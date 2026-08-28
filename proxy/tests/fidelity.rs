//! What went in against what came out.
//!
//! A recording origin behind mach5, driven by a client that speaks h2, so a
//! request can be compared with the bytes that actually reached the far side.
//! Request direction only.
//!
//! The bug this exists for: `upstream::call` used ureq's `set`, which
//! *replaces*, so a header the client sent twice arrived at the origin once
//! carrying only the last line. HTTP/2 and HTTP/3 clients split `cookie` across
//! several fields as a matter of course (RFC 9113 §8.2.3) and browsers do it
//! routinely, so browsers behind mach5 lost most of their cookies. Nothing in
//! the existing suite could *express* that input: `common::Proxy::send` is a
//! hand-rolled HTTP/1.1 client, and over HTTP/1.1 nobody splits `cookie`.
//!
//! mach5 is a rewriting proxy, so a byte-diff of the whole request fails on the
//! first run and says nothing. The artifact that carries the value is
//! [`allowance`]: the list of what mach5 is *allowed* to change. Everything not
//! on it must arrive byte-identical. Widening that list to make a test pass is
//! the failure this file exists to prevent.

// Every test binary compiles the whole of `common`, and this one uses the
// proxy but none of the hand-rolled HTTP/1.1 client beside it.
#[allow(dead_code)]
mod common;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};

/// The name the recording origin answers to.
///
/// It has to resolve, because mach5 resolves origins itself, and the port
/// cannot be chosen: mach5 takes the origin from the SNI, which carries no
/// port, so the upstream URL is always `https://<name>/…` and always 443.
const ORIGIN: &str = "localhost";

/// Serialises the whole file. The origin has to be on 443 — see [`ORIGIN`] —
/// which is a single machine-wide address, so two of these cannot run at once.
fn one_at_a_time() -> MutexGuard<'static, ()> {
	static LOCK: OnceLock<Mutex<()>> = OnceLock::new();

	LOCK.get_or_init(|| Mutex::new(()))
		.lock()
		.unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

/// One h2 request over one fresh TLS connection to mach5.
///
/// `headers` is a list rather than a map on purpose: the same name may appear
/// more than once, which is the input the cookie bug turned on.
struct Sent {
	status: u16,
	body: Vec<u8>,
}

fn send(
	port: u16,
	method: &str,
	path: &str,
	headers: &[(&str, &str)],
	body: &[u8],
) -> Sent {
	let runtime = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.expect("a runtime");

	runtime.block_on(async move {
		use boring::ssl::{SslConnector, SslMethod, SslVerifyMode};

		let mut connector = SslConnector::builder(SslMethod::tls()).expect("a tls client");
		// The proxy runs an ephemeral in-memory dev CA, so there is no root to
		// check its leaves against. This is the test client being permissive
		// and says nothing about mach5's own upstream validation.
		connector.set_verify(SslVerifyMode::NONE);
		// h2 and nothing else. A silent fall back to HTTP/1.1 would take the
		// duplicate field lines away and the harness would report a fidelity
		// that was never tested.
		connector.set_alpn_protos(b"\x02h2").expect("advertise h2");

		let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
			.await
			.expect("reach mach5");
		let config = connector
			.build()
			.configure()
			.expect("a tls configuration")
			.use_server_name_indication(true)
			.verify_hostname(false);

		// The SNI is how mach5 learns which origin was wanted; in a transparent
		// deployment it has no other clue.
		let stream = tokio_boring::connect(config, ORIGIN, tcp)
			.await
			.expect("tls handshake");
		assert_eq!(
			stream.ssl().selected_alpn_protocol(),
			Some(&b"h2"[..]),
			"the harness is worthless over HTTP/1.1: it is where duplicate \
			 field lines stop existing"
		);

		let (mut sender, connection) =
			hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
				.await
				.expect("h2 handshake");
		tokio::spawn(connection);

		let mut request = Request::builder()
			.method(method)
			.uri(format!("https://{ORIGIN}{path}"))
			.body(Full::new(Bytes::copy_from_slice(body)))
			.expect("a request");
		for (name, value) in headers {
			// `append`, never `insert`: insert replaces, which is the very
			// mistake being tested for.
			request
				.headers_mut()
				.append(
					hyper::header::HeaderName::from_bytes(name.as_bytes()).expect("a field name"),
					value.parse().expect("a field value"),
				);
		}

		let response = sender.send_request(request).await.expect("a response");
		let status = response.status().as_u16();
		let body = response.collect().await.expect("a body").to_bytes().to_vec();

		Sent { status, body }
	})
}

// ---------------------------------------------------------------------------
// The origin
// ---------------------------------------------------------------------------

/// A TLS origin that keeps the raw bytes of everything it is sent.
///
/// Raw bytes rather than a parsed echo: header order and framing are part of
/// fidelity, and parsing normalises exactly the differences worth catching.
struct Origin {
	seen: Arc<Mutex<Vec<Vec<u8>>>>,
	stop: Arc<AtomicBool>,
	thread: Option<std::thread::JoinHandle<()>>,
}

impl Origin {
	fn start() -> Self {
		let listener = std::net::TcpListener::bind(("127.0.0.1", 443)).unwrap_or_else(|e| {
			panic!(
				"the fidelity harness needs 127.0.0.1:443, because mach5 takes \
				 the origin from the SNI and an SNI carries no port: {e}"
			)
		});
		listener.set_nonblocking(true).expect("a polling listener");

		let acceptor = Arc::new(acceptor());
		let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
		let stop = Arc::new(AtomicBool::new(false));

		let thread = {
			let seen = Arc::clone(&seen);
			let stop = Arc::clone(&stop);

			std::thread::spawn(move || {
				while !stop.load(Ordering::Relaxed) {
					match listener.accept() {
						Ok((socket, _)) => {
							let acceptor = Arc::clone(&acceptor);
							let seen = Arc::clone(&seen);
							std::thread::spawn(move || serve(&acceptor, socket, &seen));
						}
						Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
							std::thread::sleep(Duration::from_millis(5));
						}
						Err(_) => break,
					}
				}
			})
		};

		Self {
			seen,
			stop,
			thread: Some(thread),
		}
	}

	/// The request whose target is `path`, once it has arrived.
	///
	/// Keyed on the path rather than on arrival order so that mach5's own
	/// traffic — the certificate warning's failed fetch, say — cannot be
	/// mistaken for the request under test.
	fn bytes_for(&self, path: &str) -> Vec<u8> {
		let deadline = Instant::now() + Duration::from_secs(5);
		let target = format!(" {path} ");

		loop {
			let found = self
				.seen
				.lock()
				.expect("the recording")
				.iter()
				.find(|bytes| {
					String::from_utf8_lossy(bytes)
						.lines()
						.next()
						.is_some_and(|line| line.contains(&target))
				})
				.cloned();

			if let Some(found) = found {
				return found;
			}

			assert!(
				Instant::now() < deadline,
				"nothing carrying {path} ever reached the origin"
			);
			std::thread::sleep(Duration::from_millis(10));
		}
	}

	/// The same, as text. Only the head is ever textual, so anything reading a
	/// body has to take [`Self::bytes_for`].
	fn request_for(&self, path: &str) -> String {
		String::from_utf8_lossy(&self.bytes_for(path)).into_owned()
	}
}

impl Drop for Origin {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::Relaxed);
		if let Some(thread) = self.thread.take() {
			let _ = thread.join();
		}
	}
}

/// A self-signed certificate for [`ORIGIN`], which is all the origin needs:
/// mach5 is going to refuse it and be told to go ahead anyway.
fn acceptor() -> boring::ssl::SslAcceptor {
	use boring::pkey::PKey;
	use boring::ssl::{SslAcceptor, SslMethod};
	use boring::x509::X509;

	let key = rcgen::KeyPair::generate().expect("a key");
	let params = rcgen::CertificateParams::new(vec![ORIGIN.to_string()]).expect("parameters");
	let cert = params.self_signed(&key).expect("a certificate");

	let mut builder =
		SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("a tls server");
	builder
		.set_certificate(&X509::from_pem(cert.pem().as_bytes()).expect("the certificate"))
		.expect("install the certificate");
	builder
		.set_private_key(&PKey::private_key_from_pem(key.serialize_pem().as_bytes()).expect("the key"))
		.expect("install the key");

	builder.build()
}

/// Read one request, keep every byte of it, answer with the shortest thing that
/// is unambiguously a complete response.
fn serve(
	acceptor: &boring::ssl::SslAcceptor,
	socket: std::net::TcpStream,
	seen: &Mutex<Vec<Vec<u8>>>,
) {
	let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
	let _ = socket.set_write_timeout(Some(Duration::from_secs(10)));

	// mach5's *strict* agent refuses this certificate, so the handshake failing
	// is the expected first half of the bypass dance rather than a problem.
	let Ok(mut stream) = acceptor.accept(socket) else {
		return;
	};

	let mut raw = Vec::new();
	let mut byte = [0u8; 1];
	let head = loop {
		match stream.read(&mut byte) {
			Ok(0) | Err(_) => return,
			Ok(_) => raw.push(byte[0]),
		}

		let mut headers = [httparse::EMPTY_HEADER; 64];
		let mut request = httparse::Request::new(&mut headers);
		if let Ok(httparse::Status::Complete(len)) = request.parse(&raw) {
			break len;
		}
	};

	let length = declared_length(&raw[..head]);
	while raw.len() < head + length {
		let mut chunk = vec![0u8; head + length - raw.len()];
		match stream.read(&mut chunk) {
			Ok(0) | Err(_) => break,
			Ok(read) => raw.extend_from_slice(&chunk[..read]),
		}
	}

	seen.lock().expect("the recording").push(raw);

	// `no-store` so nothing here can be answered from mach5's own cache on a
	// later run, which would leave the origin never seeing the request at all.
	let _ = stream.write_all(
		b"HTTP/1.1 200 OK\r\n\
		  content-type: text/plain\r\n\
		  cache-control: no-store\r\n\
		  content-length: 2\r\n\
		  connection: close\r\n\
		  \r\n\
		  ok",
	);
	let _ = stream.flush();
	let _ = stream.shutdown();
}

fn declared_length(head: &[u8]) -> usize {
	String::from_utf8_lossy(head)
		.lines()
		.find_map(|line| {
			let (name, value) = line.split_once(':')?;
			name.trim()
				.eq_ignore_ascii_case("content-length")
				.then(|| value.trim().parse().ok())?
		})
		.unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

/// A proxy with everything that rewrites switched off, plus a recording origin
/// it has been told to fetch without validating.
struct Harness {
	proxy: common::Proxy,
	origin: Origin,
}

impl Harness {
	fn start() -> Self {
		let origin = Origin::start();
		// Blocking off (an empty list takes the link out of the chain),
		// injection off, images off, plugins off (the shared configuration),
		// and the origin cache off so every request has to be made for real.
		// In that state mach5 should be transparent apart from [`allowance`].
		let proxy = common::Proxy::start_with(
			"",
			"[images]\n\
			 enabled = false\n\
			 origin_cache_mb = 0\n\
			 \n\
			 [inject]\n\
			 enabled = false\n\
			 \n\
			 [upstream]\n\
			 addresses = \"prefer-ipv4\"\n",
		);

		let harness = Self { proxy, origin };
		harness.wave_the_origin_through();

		harness
	}

	/// Type the phrase, in effect.
	///
	/// The origin's certificate is self-signed, and mach5 is the only thing
	/// still validating origins once a device trusts its CA — so it refuses,
	/// and the only way past is the single-use token on the warning page. There
	/// is no configuration file route to this, by design.
	fn wave_the_origin_through(&self) {
		let refused = send(self.proxy.tcp_port(), "GET", "/", &[], b"");
		assert_eq!(
			refused.status, 526,
			"the origin's certificate should have been refused:\n{}",
			String::from_utf8_lossy(&refused.body)
		);

		let page = String::from_utf8_lossy(&refused.body).into_owned();
		let token = page
			.split_once("const token = \"")
			.and_then(|(_, rest)| rest.split_once('"'))
			.map(|(token, _)| token.to_string())
			.unwrap_or_else(|| panic!("no bypass token on the warning page:\n{page}"));

		let redeemed = send(
			self.proxy.tcp_port(),
			"POST",
			"/.mach5/bypass",
			&[("content-type", "application/json")],
			format!(r#"{{"token":"{token}"}}"#).as_bytes(),
		);
		assert_eq!(redeemed.status, 204, "the bypass was refused");
	}
}

// ---------------------------------------------------------------------------
// The allowlist
// ---------------------------------------------------------------------------

/// What mach5 is allowed to do to a request field on the way to the origin.
///
/// This is the contract. It exists nowhere else as one piece — it is spread
/// across `upstream::forwarded`, `upstream::is_hop_by_hop`,
/// `upstream::conditional` and the front end's own `to_proxy_request` — and
/// every entry names where it comes from. A field with no entry here must reach
/// the origin byte-identical.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Allowed {
	/// `host` is consumed by the front end (`tcp::to_proxy_request` keeps it
	/// out of the header list) and rebuilt by ureq from the upstream URL, which
	/// is the SNI without its port.
	Rebuilt,
	/// Meaningful on one connection only, RFC 9110 §7.6.1. Dropped by
	/// `tcp::to_proxy_request` via `upstream::is_hop_by_hop`.
	HopByHop,
	/// Framing is this hop's to decide, and the body being sent upstream may
	/// not be the body that arrived. `upstream::is_hop_by_hop` lists it;
	/// `upstream::call` puts the length back on.
	Reframed,
	/// Replaced wholesale, because relaying the client's value invites a coding
	/// the interceptors cannot decode. `upstream::forwarded` plus
	/// `encoding::negotiate`, whose answer is a subset of `br, gzip`.
	Renegotiated,
	/// The loop marker. `upstream::call` stamps it and `upstream::forwarded`
	/// drops any copy the client sent, so exactly one arrives and it is mach5's.
	Ours,
	/// Settled between the client and mach5 — hyper answers it — and never
	/// asked of the origin. `upstream::forwarded`, and only for this one value.
	SettledHere,
	/// Dropped *only* while mach5 is revalidating its own cache entry, because
	/// then the conditional request is mach5's question and not the client's
	/// (RFC 9110 §13.1.3). `upstream::conditional`.
	ConditionalWhileRevalidating,
	/// Supplied on a request the client left bare, because the HTTP client
	/// cannot be told to send nothing at all — an empty value writes an empty
	/// header.
	///
	/// This harness found these arriving as ureq's own defaults, naming the
	/// library and its exact version to every origin. `user-agent` is now
	/// chosen deliberately in `upstream::NO_AGENT_STATED`; `accept` is still
	/// the library showing through, and is semantically free (RFC 9110
	/// §12.5.1: an absent `accept` means `*/*`).
	///
	/// [`what_a_bare_request_is_given`] pins both, so neither can drift back
	/// into naming something.
	SuppliedWhenTheClientSaidNothing,
}

/// Whether mach5 has a cache entry of its own it is asking the origin about.
///
/// The only state in which the client's conditional headers may go missing, and
/// the harness is always [`Cache::Off`] — `origin_cache_mb = 0` — so under it a
/// conditional the client sent has to arrive. Phase 2, with the cache on, is
/// where the other arm gets exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cache {
	Off,
	#[allow(dead_code)]
	Revalidating,
}

/// The allowance for one field, or `None` if it has none and must arrive whole.
///
/// Takes the values as well as the name because some of these are value-scoped:
/// `expect` is only settled here when it is `100-continue`, and `user-agent`
/// and `accept` are only ureq's when the client sent none.
fn allowance(name: &str, sent: &[String], cache: Cache) -> Option<Allowed> {
	Some(match name.to_ascii_lowercase().as_str() {
		"host" => Allowed::Rebuilt,
		"connection" | "keep-alive" | "proxy-authenticate" | "proxy-authorization" | "te"
		| "trailer" | "transfer-encoding" | "upgrade" => Allowed::HopByHop,
		"content-length" => Allowed::Reframed,
		"accept-encoding" => Allowed::Renegotiated,
		"x-mach5-via" => Allowed::Ours,
		"expect"
			if !sent.is_empty()
				&& sent
					.iter()
					.all(|value| value.trim().eq_ignore_ascii_case("100-continue")) =>
		{
			Allowed::SettledHere
		}
		"if-none-match" | "if-modified-since" | "if-match" | "if-unmodified-since" | "if-range"
			if cache == Cache::Revalidating =>
		{
			Allowed::ConditionalWhileRevalidating
		}
		"user-agent" | "accept" if sent.is_empty() => Allowed::SuppliedWhenTheClientSaidNothing,
		_ => return None,
	})
}

/// Repeated field lines folded the way RFC 9113 §8.2.3 says to reassemble them:
/// `", "`, except `cookie`, which uses the separator its own grammar uses.
///
/// The test does this itself rather than asking the proxy, because it is the
/// written-down half of the contract: `upstream::joined_for_upstream` is the
/// implementation, and this is what it is supposed to produce.
fn folded(name: &str, values: &[String]) -> String {
	values.join(if name.eq_ignore_ascii_case("cookie") {
		"; "
	} else {
		", "
	})
}

/// The field lines of a recorded request, in order, lowercased by name.
fn fields(request: &str) -> Vec<(String, String)> {
	request
		.lines()
		.skip(1)
		.take_while(|line| !line.is_empty())
		.filter_map(|line| {
			let (name, value) = line.split_once(':')?;

			Some((name.trim().to_ascii_lowercase(), value.trim().to_string()))
		})
		.collect()
}

fn grouped(fields: &[(String, String)]) -> BTreeMap<String, Vec<String>> {
	let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
	for (name, value) in fields {
		grouped.entry(name.clone()).or_default().push(value.clone());
	}

	grouped
}

/// Every field of `sent` that has no allowance must arrive at the origin as one
/// line carrying exactly what was sent, and nothing may appear at the origin
/// that was neither sent nor allowed.
fn assert_faithful(sent: &[(&str, &str)], arrived: &str) {
	let mut expected: BTreeMap<String, Vec<String>> = BTreeMap::new();
	for (name, value) in sent {
		expected
			.entry(name.to_ascii_lowercase())
			.or_default()
			.push((*value).to_string());
	}

	let received = grouped(&fields(arrived));

	for (name, values) in &expected {
		if let Some(allowed) = allowance(name, values, Cache::Off) {
			println!("allowed to differ: {name} ({allowed:?})");

			continue;
		}

		assert_eq!(
			received.get(name).map(Vec::as_slice),
			Some(&[folded(name, values)][..]),
			"{name} is not on the allowlist, so it must reach the origin whole \
			 and as one line:\n{arrived}"
		);
	}

	for name in received.keys() {
		if expected.contains_key(name) || allowance(name, &[], Cache::Off).is_some() {
			continue;
		}

		panic!("the origin was sent {name}, which the client never sent and the allowlist does not explain:\n{arrived}");
	}
}

/// The relative order of the client's own fields survives the crossing.
///
/// Order is part of fidelity — it is one of the things parsing an echo would
/// normalise away — and mach5 keeps the list the front end built, so a
/// reordering would mean something had rebuilt it.
fn assert_order(sent: &[(&str, &str)], arrived: &str) {
	let mut wanted: Vec<String> = Vec::new();
	for (name, value) in sent {
		let name = name.to_ascii_lowercase();
		if allowance(&name, &[(*value).to_string()], Cache::Off).is_some()
			|| wanted.contains(&name)
		{
			continue;
		}

		wanted.push(name);
	}

	let got: Vec<String> = fields(arrived)
		.into_iter()
		.map(|(name, _)| name)
		.filter(|name| wanted.contains(name))
		.collect();

	assert_eq!(got, wanted, "the fields were reordered:\n{arrived}");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The check everything else here rests on: this client can put the same field
/// name on the wire twice.
///
/// Without it the harness would report a fidelity it never tested. An h2
/// receiver decodes one header-map entry per field line — HPACK has no notion
/// of joining — so two entries at the far end is two lines on the wire.
#[test]
fn the_client_can_send_one_field_twice_over_h2() {
	let runtime = tokio::runtime::Builder::new_multi_thread()
		.enable_all()
		.build()
		.expect("a runtime");

	let seen: Vec<String> = runtime.block_on(async {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
			.await
			.expect("a free port");
		let port = listener.local_addr().expect("bound").port();

		tokio::spawn(async move {
			let (socket, _) = listener.accept().await.expect("a connection");
			let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
				.serve_connection(
					TokioIo::new(socket),
					service_fn(|req: Request<Incoming>| async move {
						let joined = req
							.headers()
							.get_all("cookie")
							.iter()
							.map(|value| value.to_str().unwrap_or_default().to_string())
							.collect::<Vec<_>>()
							.join("|");

						Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(joined))))
					}),
				)
				.await;
		});

		let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
			.await
			.expect("connect");
		let (mut sender, connection) =
			hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
				.await
				.expect("h2 handshake");
		tokio::spawn(connection);

		let mut request = Request::builder()
			.uri("http://localhost/")
			.body(Empty::<Bytes>::new())
			.expect("a request");
		request
			.headers_mut()
			.append("cookie", "session=abc".parse().unwrap());
		request
			.headers_mut()
			.append("cookie", "csrf=xyz".parse().unwrap());

		let response = sender.send_request(request).await.expect("a response");
		let body = response.collect().await.expect("a body").to_bytes();

		String::from_utf8_lossy(&body)
			.split('|')
			.map(str::to_string)
			.collect()
	});

	assert_eq!(
		seen,
		vec!["session=abc".to_string(), "csrf=xyz".to_string()],
		"two entries at an h2 receiver is two field lines on the wire"
	);
}

/// With blocking, injection, images, compression and plugins off, mach5 should
/// be transparent apart from [`allowance`]. That is a far stronger invariant
/// than trying to characterise the rewriting, and it is the one this file
/// starts from.
#[test]
fn an_identity_proxy_relays_a_request_but_for_the_allowlist() {
	let _serial = one_at_a_time();
	let harness = Harness::start();

	let sent: &[(&str, &str)] = &[
		("accept", "text/html,application/xhtml+xml;q=0.9"),
		("accept-language", "en-GB"),
		// Sent so the allowance for it stays as narrow as it claims: ureq only
		// fills this in when it is missing.
		("user-agent", "fidelity-harness/1 (not ureq)"),
		("referer", "https://example.invalid/a?b=c&d=%20e"),
		("x-empty", ""),
		("x-long", &"a".repeat(4000)),
		("x-punctuation", "a,b; c=\"d\" e/f"),
	];
	let answered = send(harness.proxy.tcp_port(), "GET", "/identity?q=1", sent, b"");
	assert_eq!(answered.status, 200, "{}", harness.proxy.log());

	let arrived = harness.origin.request_for("/identity?q=1");
	assert_eq!(
		arrived.lines().next(),
		Some("GET /identity?q=1 HTTP/1.1"),
		"the method and the target survive; only the version is this hop's:\n{arrived}"
	);
	assert_faithful(sent, &arrived);
	assert_order(sent, &arrived);
}

/// The bug this file exists for.
///
/// `set` replaces, so the second `cookie` used to be all that arrived. HTTP/2
/// and HTTP/3 clients split `cookie` across several fields as a matter of
/// course — RFC 9113 §8.2.3 — and half of somebody's cookies going missing
/// looks to an origin exactly like a signed-out user.
#[test]
fn a_repeated_field_reaches_the_origin_whole() {
	let _serial = one_at_a_time();
	let harness = Harness::start();

	let sent: &[(&str, &str)] = &[
		("cookie", "session=abc"),
		("cookie", "csrf=xyz"),
		("cookie", "theme=dark"),
		("accept-language", "en"),
		("accept-language", "fr"),
	];
	let answered = send(harness.proxy.tcp_port(), "GET", "/repeated", sent, b"");
	assert_eq!(answered.status, 200, "{}", harness.proxy.log());

	let arrived = harness.origin.request_for("/repeated");

	// Spelled out before the allowlist check as well as covered by it, so that
	// a regression names itself rather than arriving as whichever field the
	// general comparison reached first.
	let received = grouped(&fields(&arrived));
	assert_eq!(
		received.get("cookie").map(Vec::as_slice),
		Some(&["session=abc; csrf=xyz; theme=dark".to_string()][..]),
		"every crumb, on one line, joined on the separator cookie's own grammar \
		 uses:\n{arrived}"
	);
	assert_eq!(
		received.get("accept-language").map(Vec::as_slice),
		Some(&["en, fr".to_string()][..]),
		"everything else joins on a comma:\n{arrived}"
	);

	assert_faithful(sent, &arrived);
}

/// The marker that stops mach5 fetching itself is mach5's to set.
///
/// ureq's `set` replaces a header — except one named `x-…`, which it pushes —
/// so a client sending its own was relayed to the origin beside the real one.
#[test]
fn a_client_cannot_add_its_own_loop_marker() {
	let _serial = one_at_a_time();
	let harness = Harness::start();

	let sent: &[(&str, &str)] = &[("x-mach5-via", "forged-by-the-client")];
	let answered = send(harness.proxy.tcp_port(), "GET", "/marker", sent, b"");
	assert_eq!(answered.status, 200, "{}", harness.proxy.log());

	let arrived = harness.origin.request_for("/marker");
	let received = grouped(&fields(&arrived));
	assert_eq!(
		received.get("x-mach5-via").map(Vec::len),
		Some(1),
		"exactly one, and it is mach5's:\n{arrived}"
	);
	assert!(
		!arrived.contains("forged-by-the-client"),
		"the client's copy is dropped on the way past:\n{arrived}"
	);
}

/// An upload's bytes are not the proxy's to touch, and its framing is.
#[test]
fn an_upload_reaches_the_origin_byte_for_byte() {
	let _serial = one_at_a_time();
	let harness = Harness::start();

	let body: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
	let sent: &[(&str, &str)] = &[
		("content-type", "application/octet-stream"),
		("cookie", "session=abc"),
		("cookie", "csrf=xyz"),
	];
	let answered = send(harness.proxy.tcp_port(), "POST", "/upload", sent, &body);
	assert_eq!(answered.status, 200, "{}", harness.proxy.log());

	let arrived = harness.origin.request_for("/upload");
	assert_faithful(sent, &arrived);

	let received = grouped(&fields(&arrived));
	assert_eq!(
		received.get("content-length").map(Vec::as_slice),
		Some(&[body.len().to_string()][..]),
		"framing is this hop's, and it has to describe what this hop is \
		 sending:\n{arrived}"
	);

	let raw = harness.origin.bytes_for("/upload");
	let head = raw
		.windows(4)
		.position(|window| window == b"\r\n\r\n")
		.expect("a complete head")
		+ 4;
	assert_eq!(&raw[head..], &body[..], "not one byte of the upload changed");
}

/// A finding rather than a rule: nothing in `src/` asks for either of these.
///
/// ureq puts its own `user-agent` and `accept` on a request that arrived
/// without them, so an origin is told mach5's HTTP client and version — and a
/// client that deliberately sent no `user-agent` has one invented for it. The
/// `accept` half is semantically free (RFC 9110 §12.5.1 says a missing `accept`
/// means `*/*` anyway); the `user-agent` half is a fingerprint the client did
/// not choose.
///
/// Pinned here rather than waved through, so that a change of client library or
/// version has to come past this test.
#[test]
fn what_a_bare_request_is_given() {
	let _serial = one_at_a_time();
	let harness = Harness::start();

	let answered = send(harness.proxy.tcp_port(), "GET", "/bare", &[], b"");
	assert_eq!(answered.status, 200, "{}", harness.proxy.log());

	let arrived = harness.origin.request_for("/bare");
	let received = grouped(&fields(&arrived));

	assert_eq!(
		received.get("accept").map(Vec::as_slice),
		Some(&["*/*".to_string()][..]),
		"{arrived}"
	);
	let agent = received
		.get("user-agent")
		.and_then(|values| values.first().cloned())
		.unwrap_or_default();

	// Something has to be sent, so the question is only what. Not the HTTP
	// library and its version, which is what this harness found here and which
	// tells an origin what mach5 is built from. Not mach5's own name either:
	// unique to this proxy, so every user of it becomes identifiable as one.
	// And not a browser's, which every other signal on the connection would
	// contradict.
	assert!(!agent.to_ascii_lowercase().contains("ureq"), "{arrived}");
	assert!(!agent.to_ascii_lowercase().contains("mach5"), "{arrived}");
	assert!(!agent.contains("Chrome") && !agent.contains("Safari"), "{arrived}");
	assert_eq!(agent, "Mozilla/5.0", "{arrived}");
}

/// A client's own conditional is the client's question, and mach5 has no cache
/// entry to ask about here, so it goes to the origin untouched.
///
/// `upstream::conditional` drops these — but only while mach5 is revalidating
/// something of its own. Dropping them outright would turn every conditional
/// request a browser makes into a full download.
#[test]
fn a_clients_own_conditional_reaches_the_origin() {
	let _serial = one_at_a_time();
	let harness = Harness::start();

	let sent: &[(&str, &str)] = &[
		("if-none-match", "\"v1\""),
		("if-modified-since", "Wed, 21 Oct 2026 07:28:00 GMT"),
	];
	let answered = send(harness.proxy.tcp_port(), "GET", "/conditional", sent, b"");
	assert_eq!(answered.status, 200, "{}", harness.proxy.log());

	let arrived = harness.origin.request_for("/conditional");
	assert_faithful(sent, &arrived);
}

/// Two the origin must never be asked about.
///
/// `te` is hop-by-hop (RFC 9110 §7.6.1) and `expect: 100-continue` is settled
/// between the client and mach5 — hyper answers it, and forwarding it asks the
/// origin for an interim response ureq cannot parse. Both are things an h2
/// client can genuinely put on the wire (`te: trailers` is the one connection
/// header h2 permits), so this is mach5 dropping them and not the transport.
#[test]
fn what_belongs_to_this_hop_does_not_cross_it() {
	let _serial = one_at_a_time();
	let harness = Harness::start();

	let sent: &[(&str, &str)] = &[("te", "trailers"), ("expect", "100-continue")];
	let answered = send(harness.proxy.tcp_port(), "GET", "/hop", sent, b"");
	assert_eq!(answered.status, 200, "{}", harness.proxy.log());

	let arrived = harness.origin.request_for("/hop");
	let received = grouped(&fields(&arrived));
	assert_eq!(received.get("te"), None, "{arrived}");
	assert_eq!(received.get("expect"), None, "{arrived}");

	assert_faithful(sent, &arrived);
}
