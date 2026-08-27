//! Plumbing for the integration tests: a real proxy process to talk to, and
//! the smallest HTTPS client that can hold a conversation with it.
//!
//! Everything here exists so a test can assert on what actually comes back out
//! of the socket. The unit tests already cover the interceptors in isolation;
//! what they cannot see is TLS termination, the SNI the origin is deduced
//! from, hyper's framing, and the headers the TCP front end adds on the way
//! out — which is exactly where a mistake would strand a real browser.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};
use tempfile::TempDir;

/// How long to give the binary to be listening. Generous, because it is only
/// ever waited out on a genuine failure — the happy path returns in the tens
/// of milliseconds.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);

/// How many ports to try before treating a failure to start as real.
const ATTEMPTS: usize = 4;

/// A port nothing is listening on, found by letting the kernel pick one and
/// then letting go of it.
///
/// Racy in principle: anything could claim the port between the drop and the
/// proxy's bind. Fine here — a test machine is not competing for ports, and
/// the alternative is teaching the binary to accept an inherited socket for
/// the sake of the tests.
pub fn free_port() -> u16 {
	let listener = TcpListener::bind("127.0.0.1:0").expect("a free port");

	listener.local_addr().expect("bound address").port()
}

/// Start a proxy that is expected to fail, and collect why.
///
/// Separate from [`Proxy`], which retries a failed start on the assumption
/// that the port was taken from under it. Here the failure is the subject.
pub fn run_until_exit(extra: &str) -> (std::process::ExitStatus, String) {
	let dir = TempDir::new().expect("a temporary directory");
	let path = dir.path().to_path_buf();
	let config = path.join("mach5.toml");

	std::fs::write(
		&config,
		format!(
			"listen = \"127.0.0.1:0\"\n\
			 {extra}\n\
			 [paths]\n\
			 cache_dir = \"{cache}\"\n\
			 state_dir = \"{state}\"\n",
			cache = path.join("cache").display(),
			state = path.display(),
		),
	)
	.expect("write the configuration");

	let log = path.join("proxy.log");
	let out = std::fs::File::create(&log).expect("create the log");
	let err = out.try_clone().expect("share the log");

	let status = Command::new(env!("CARGO_BIN_EXE_mach5-proxy"))
		.env("MACH5_CONFIG", &config)
		.env("RUST_LOG", "info")
		.stdin(Stdio::null())
		.stdout(Stdio::from(out))
		.stderr(Stdio::from(err))
		.status()
		.expect("spawn the proxy");

	let text = std::fs::read_to_string(&log).unwrap_or_default();

	(status, text)
}

/// A running `mach5-proxy`, its configuration and state confined to a
/// temporary directory that goes away with it.
pub struct Proxy {
	child: Child,
	dir: TempDir,
	tcp_port: u16,
	alt_svc: String,
}

impl Proxy {
	/// Start a proxy with the given blocklist and wait until it answers.
	///
	/// Plugins are off: it makes startup immediate, and it keeps the tests
	/// from needing a Python interpreter to say anything about the blocklist.
	pub fn start(blocklist: &str) -> Self {
		Self::start_with(blocklist, "")
	}

	/// As [`Self::start`], with extra configuration appended — which is how a
	/// test says something the shared configuration does not.
	///
	/// Retries, because [`free_port`] is racy by construction and a dozen of
	/// these start at once: the port can be taken between being handed over and
	/// being bound, and the only symptom is a child that exits immediately. A
	/// suite that fails one run in five is worse than no suite.
	pub fn start_with(blocklist: &str, extra: &str) -> Self {
		for _ in 0..ATTEMPTS - 1 {
			let mut proxy = Self::spawn(blocklist, extra);
			if proxy.await_ready() {
				return proxy;
			}
		}

		// The last one reports properly rather than retrying, so a real failure
		// still shows its log instead of a bare "gave up".
		let mut proxy = Self::spawn(blocklist, extra);
		assert!(
			proxy.await_ready(),
			"proxy exited during startup\n{}",
			proxy.log()
		);

		proxy
	}

	fn spawn(blocklist: &str, extra: &str) -> Self {
		let dir = TempDir::new().expect("temporary directory");
		let tcp_port = free_port();
		// The QUIC listener wants a port of its own, and refuses to start
		// without one. A TCP and a UDP port of the same number never collide,
		// so it does not matter if the two probes hand back the same one.
		let udp_port = free_port();
		let alt_svc = format!(r#"h3=":{udp_port}"; ma=86400"#);

		let path = dir.path();
		std::fs::write(path.join("blocklist.txt"), blocklist).expect("write the blocklist");

		let config = path.join("mach5.toml");
		std::fs::write(
			&config,
			format!(
				"listen = \"127.0.0.1:{udp_port}\"\n\
				 listen_tcp = \"127.0.0.1:{tcp_port}\"\n\
				 \n\
				 [http]\n\
				 alt_svc = '{alt_svc}'\n\
				 \n\
				 [plugins]\n\
				 enabled = false\n\
				 \n\
				 [blocklist]\n\
				 files = [\"{blocklist_file}\"]\n\
				 \n\
				 [paths]\n\
				 cache_dir = \"{cache}\"\n\
				 state_dir = \"{state}\"\n\
				 \n\
				 [limits]\n\
				 worker_threads = 2\n\
				 max_request_body_mb = 1\n\
				 {extra}\n",
				blocklist_file = path.join("blocklist.txt").display(),
				cache = path.join("cache").display(),
				state = path.display(),
			),
		)
		.expect("write the configuration");

		// Captured to a file rather than a pipe: nothing here reads the child
		// while a test runs, and a pipe nobody drains eventually blocks the
		// process that is filling it.
		let log = std::fs::File::create(path.join("proxy.log")).expect("create the log");
		let stderr = log.try_clone().expect("share the log");

		let child = Command::new(env!("CARGO_BIN_EXE_mach5-proxy"))
			.env("MACH5_CONFIG", &config)
			.env("RUST_LOG", "info")
			.stdin(Stdio::null())
			.stdout(Stdio::from(log))
			.stderr(Stdio::from(stderr))
			.spawn()
			.expect("spawn the proxy");

		Self {
			child,
			dir,
			tcp_port,
			alt_svc,
		}
	}

	/// The `alt-svc` value this instance was configured to advertise, so a test
	/// can assert on the exact string rather than merely on its presence.
	pub fn tcp_port(&self) -> u16 {
		self.tcp_port
	}

	pub fn alt_svc(&self) -> &str {
		&self.alt_svc
	}

	/// Where the hidden-element store is mirrored to disk.
	pub fn hidden_json(&self) -> PathBuf {
		self.dir.path().join("hidden.json")
	}

	pub fn get(&self, host: &str, path: &str) -> Response {
		self.send("GET", host, path, &[], "")
	}

	pub fn post(&self, host: &str, path: &str, body: &str) -> Response {
		self.send(
			"POST",
			host,
			path,
			&[("content-type", "application/json")],
			body,
		)
	}

	/// One request over one fresh TLS connection.
	pub fn send(
		&self,
		method: &str,
		host: &str,
		path: &str,
		headers: &[(&str, &str)],
		body: &str,
	) -> Response {
		let mut connector = SslConnector::builder(SslMethod::tls()).expect("a tls client");
		// The proxy is running an ephemeral in-memory dev CA, so there is no
		// root to check its leaves against and nothing to be gained by
		// pretending otherwise. This is the *test client* being permissive; it
		// says nothing about the proxy's own upstream validation, which stays
		// strict and has its own interstitial when it fails.
		connector.set_verify(SslVerifyMode::NONE);
		// Ask for HTTP/1.1 outright: the proxy offers h2 first, and these
		// requests are written by hand.
		connector
			.set_alpn_protos(b"\x08http/1.1")
			.expect("advertise http/1.1");
		let connector = connector.build();

		let tcp = TcpStream::connect(("127.0.0.1", self.tcp_port)).expect("connect to the proxy");
		tcp.set_read_timeout(Some(Duration::from_secs(30)))
			.expect("a read timeout");

		// The SNI is how the proxy learns which origin was wanted — in a
		// transparent deployment it has no other clue — so the host under test
		// goes here, not only in the `Host` header.
		let mut stream = connector
			.configure()
			.expect("a tls configuration")
			.use_server_name_indication(true)
			.verify_hostname(false)
			.connect(host, tcp)
			.expect("tls handshake");

		let mut request =
			format!("{method} {path} HTTP/1.1\r\nhost: {host}\r\nconnection: close\r\n");
		for (name, value) in headers {
			request.push_str(&format!("{name}: {value}\r\n"));
		}
		request.push_str(&format!("content-length: {}\r\n\r\n{body}", body.len()));

		// A short write is not a failure here. The proxy answers a blocked
		// upload without reading the rest of it, so a client still pushing the
		// body gets a broken pipe — which is the point, and which a real client
		// handles by going on to read the response it was already sent.
		match stream.write_all(request.as_bytes()) {
			Ok(()) => {
				let _ = stream.flush();
			}
			Err(e) if matches!(e.kind(), ErrorKind::BrokenPipe | ErrorKind::ConnectionReset) => {}
			Err(e) => panic!("write the request: {e}"),
		}

		// A HEAD's response carries the length of the body a GET would have
		// returned and none of the bytes. Reading to that length would wait for
		// bytes that are never coming — which is exactly what a client that
		// ignores the rule does.
		read_response(&mut stream, method.eq_ignore_ascii_case("HEAD"))
	}

	/// Whether it came up. `false` means the child died before listening,
	/// which with a dozen of these starting at once is nearly always the port
	/// having been taken between `free_port` handing it over and the bind.
	///
	/// Readiness is our child's own log saying it bound, and not merely that
	/// something answers on the port. Those are different questions when two
	/// tests are handed the same recently-freed ephemeral port: one binds it,
	/// the other's child dies of `AddrInUse`, and the dead one's probe connects
	/// happily — to the *other* test's proxy. It then runs against a process it
	/// does not own until that test's `Drop` kills it, and whatever it does
	/// next fails with `ConnectionRefused` somewhere unrelated. That is one
	/// failure in roughly fifteen full-suite runs under load, landing on a
	/// different test each time.
	///
	/// The log file is per-instance, inside this proxy's own temporary
	/// directory, so nothing else can write the line we are waiting for.
	fn await_ready(&mut self) -> bool {
		let deadline = Instant::now() + STARTUP_TIMEOUT;
		let bound = format!("listening on 127.0.0.1:{}", self.tcp_port);

		while Instant::now() < deadline {
			if self.log().contains(&bound) && TcpStream::connect(("127.0.0.1", self.tcp_port)).is_ok() {
				return true;
			}

			if let Ok(Some(_)) = self.child.try_wait() {
				return false;
			}

			std::thread::sleep(Duration::from_millis(25));
		}

		panic!(
			"proxy never listened on 127.0.0.1:{}\n{}",
			self.tcp_port,
			self.log()
		);
	}

	pub fn log(&self) -> String {
		std::fs::read_to_string(self.dir.path().join("proxy.log")).unwrap_or_default()
	}

	/// Wait for something to appear in the proxy's log, or give up.
	///
	/// The log is the only way a test can tell *why* mach5 refused a
	/// connection: on the wire a refusal it chose and a refusal BoringSSL
	/// arrived at on its own are the same fatal alert.
	pub fn logged(&self, needle: &str, within: std::time::Duration) -> bool {
		let deadline = std::time::Instant::now() + within;
		while std::time::Instant::now() < deadline {
			if self.log().contains(needle) {
				return true;
			}
			std::thread::sleep(std::time::Duration::from_millis(20));
		}

		false
	}
}

impl Drop for Proxy {
	/// Kill the child here rather than at the end of each test: a failing
	/// assertion unwinds, and a proxy left holding its ports would outlive the
	/// run that started it.
	fn drop(&mut self) {
		let _ = self.child.kill();
		let _ = self.child.wait();
	}
}

pub struct Response {
	pub status: u16,
	pub headers: Vec<(String, String)>,
	pub body: Vec<u8>,
}

impl Response {
	/// Every value for a header, in the order they arrived.
	///
	/// [`Self::header`] answers with the first, which for a long time was the
	/// only thing this harness could see — so no test could tell a header sent
	/// once from the same header sent twice, which is the whole subject of the
	/// proxy's own multi-value handling.
	pub fn values(&self, name: &str) -> Vec<&str> {
		self.headers
			.iter()
			.filter(|(header, _)| header == name)
			.map(|(_, value)| value.as_str())
			.collect()
	}

	/// Header names are lowercased on the way in, so callers ask in lowercase.
	pub fn header(&self, name: &str) -> Option<&str> {
		self.headers
			.iter()
			.find(|(header, _)| header == name)
			.map(|(_, value)| value.as_str())
	}

	pub fn text(&self) -> String {
		String::from_utf8(self.body.clone()).expect("a textual response")
	}
}

struct Head {
	status: u16,
	headers: Vec<(String, String)>,
	/// Bytes of the buffer the head consumed; the rest is already body.
	len: usize,
}

fn read_response(stream: &mut impl Read, head_only: bool) -> Response {
	let mut buf = Vec::new();
	let mut chunk = [0u8; 4096];

	let head = loop {
		if let Some(head) = parse_head(&buf) {
			break head;
		}

		let read = stream.read(&mut chunk).expect("read the response");
		assert!(read > 0, "connection closed before the response head");
		buf.extend_from_slice(&chunk[..read]);
	};

	// Read to the end of the connection rather than to `content-length`, and do
	// not truncate. Every request here sends `connection: close`, so the end of
	// the stream is the end of the body.
	//
	// This used to stop at the declared length, which made a whole class of
	// assertion unfalsifiable: a HEAD was read as zero bytes whatever arrived,
	// and so was any response with no `content-length` — every 204 in the
	// suite. `assert!(body.is_empty())` then held even when the proxy had sent
	// a body, which is exactly the framing bug those tests exist to catch.
	let mut body = buf[head.len..].to_vec();
	loop {
		match stream.read(&mut chunk) {
			Ok(0) => break,
			Ok(read) => body.extend_from_slice(&chunk[..read]),
			// A TLS peer that closes without a close_notify. The bytes already
			// read are still the response.
			Err(_) => break,
		}
	}

	let declared: Option<usize> = head
		.headers
		.iter()
		.find(|(name, _)| name == "content-length")
		.map(|(_, value)| value.parse().expect("a numeric content-length"));

	// A HEAD's `content-length` describes the body a GET would have returned,
	// so it is deliberately not a claim about these bytes.
	if let Some(declared) = declared.filter(|_| !head_only) {
		assert_eq!(
			body.len(),
			declared,
			"the body is not the length the response declared"
		);
	}

	Response {
		status: head.status,
		headers: head.headers,
		body,
	}
}

/// `None` while the blank line ending the head has not arrived yet.
fn parse_head(buf: &[u8]) -> Option<Head> {
	let mut headers = [httparse::EMPTY_HEADER; 64];
	let mut response = httparse::Response::new(&mut headers);

	let httparse::Status::Complete(len) = response.parse(buf).expect("a well-formed response")
	else {
		return None;
	};

	Some(Head {
		status: response.code.expect("a complete response has a status"),
		headers: response
			.headers
			.iter()
			.map(|header| {
				(
					header.name.to_ascii_lowercase(),
					String::from_utf8_lossy(header.value).into_owned(),
				)
			})
			.collect(),
		len,
	})
}

/// A minimal TLS ClientHello carrying one server name.
///
/// Hand-built because the point is to control exactly what mach5 reads: a real
/// TLS client would be doing a handshake, and a passed-through connection never
/// completes one with mach5 at all.
pub fn client_hello(host: &[u8]) -> Vec<u8> {
	padded_client_hello(host, 0)
}

/// The same, plus `pad` bytes of a padding extension.
///
/// A real ClientHello is not the sixty bytes the minimal one above comes to. A
/// browser offering a post-quantum key share sends around two kilobytes, which
/// is two TCP segments — and that is the case the passthrough peek has to
/// survive, so a test needs to be able to build one.
pub fn padded_client_hello(host: &[u8], pad: usize) -> Vec<u8> {
	let mut names = vec![0u8];
	names.extend_from_slice(&(host.len() as u16).to_be_bytes());
	names.extend_from_slice(host);

	let mut server_name = Vec::new();
	server_name.extend_from_slice(&(names.len() as u16).to_be_bytes());
	server_name.extend_from_slice(&names);

	let mut extensions = Vec::new();
	extensions.extend_from_slice(&0u16.to_be_bytes());
	extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
	extensions.extend_from_slice(&server_name);

	if pad > 0 {
		// Extension 21 is `padding` (RFC 7685) and is exactly this: bytes that
		// mean nothing, placed after the name so the parser has to walk past
		// the interesting part to find the end.
		extensions.extend_from_slice(&21u16.to_be_bytes());
		extensions.extend_from_slice(&(pad as u16).to_be_bytes());
		extensions.extend(std::iter::repeat_n(0u8, pad));
	}

	let mut hello = vec![0x03, 0x03];
	hello.extend_from_slice(&[0u8; 32]);
	hello.push(0);
	hello.extend_from_slice(&2u16.to_be_bytes());
	hello.extend_from_slice(&[0x13, 0x01]);
	hello.push(1);
	hello.push(0);
	hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
	hello.extend_from_slice(&extensions);

	let mut handshake = vec![0x01];
	handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
	handshake.extend_from_slice(&hello);

	let mut record = vec![0x16, 0x03, 0x01];
	record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
	record.extend_from_slice(&handshake);

	record
}
