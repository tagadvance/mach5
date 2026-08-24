//! TCP front end: HTTP/1.1 over TLS.
//!
//! This exists because HTTP/3 cannot bootstrap itself. A browser opens TCP 443
//! first and only learns that h3 is available from the `Alt-Svc` header on a
//! response it received over TCP. Without this listener a browser pointed at
//! the proxy simply fails to connect.
//!
//! Deliberately synchronous: a bounded pool of threads, each owning its own
//! interceptor chain, mirroring how the QUIC side's workers already behave.
//! Every request takes the same path through the interceptors as an h3 one.

use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boring::ssl::{NameType, SslAcceptor, SslMethod, SslStream};

use crate::ca::CertAuthority;
use crate::config::Config;
use crate::interceptor::{Chain, Interceptor, ProxyRequest, ProxyResponse, ResponseHead};
use crate::upstream;

const STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// Start the listener and its worker pool. Returns once the socket is bound;
/// the threads keep running for the life of the process.
pub fn spawn(config: Arc<Config>, ca: Arc<CertAuthority>) -> std::io::Result<()> {
	let listener = TcpListener::bind(config.listen_tcp.0)?;
	let acceptor = Arc::new(build_acceptor(&ca)?);

	let (tx, rx) = std::sync::mpsc::channel::<TcpStream>();
	let rx = Arc::new(Mutex::new(rx));

	for _ in 0..config.worker_threads() {
		spawn_worker(config.clone(), acceptor.clone(), rx.clone());
	}

	log::info!("listening on {} (TCP/TLS, HTTP/1.1)", config.listen_tcp.0);

	std::thread::spawn(move || {
		for stream in listener.incoming() {
			match stream {
				Ok(stream) => {
					if tx.send(stream).is_err() {
						break;
					}
				}
				Err(e) => log::debug!("tcp accept failed: {e}"),
			}
		}
	});

	Ok(())
}

fn spawn_worker(config: Arc<Config>, acceptor: Arc<SslAcceptor>, rx: Arc<Mutex<Receiver<TcpStream>>>) {
	std::thread::spawn(move || {
		// Same rule as the QUIC workers: a thread owns its plugins outright.
		let interceptor = Chain::from_config(&config);
		let agent = upstream::agent(&config);

		loop {
			let stream = {
				let rx = rx.lock().unwrap();
				rx.recv()
			};
			let Ok(stream) = stream else {
				break;
			};

			if let Err(e) = serve(&config, &acceptor, &interceptor, &agent, stream) {
				log::debug!("tcp connection ended: {e}");
			}
		}
	});
}

/// Build the TLS acceptor, wired to the same on-the-fly certificate authority
/// the QUIC listener uses.
fn build_acceptor(ca: &Arc<CertAuthority>) -> std::io::Result<SslAcceptor> {
	let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
		.map_err(|e| std::io::Error::other(e.to_string()))?;

	let ca = ca.clone();
	builder.set_servername_callback(move |ssl, _alert| {
		if let Some(sni) = ssl.servername(NameType::HOST_NAME) {
			let sni = sni.to_string();
			if !ca.install(ssl, &sni) {
				log::warn!("serving default certificate for {sni}");
			}
		}

		Ok(())
	});

	// Only HTTP/1.1 here. h2 would be a further win, but the point of this
	// listener is to hand the client an Alt-Svc header and move it to h3.
	builder.set_alpn_protos(b"\x08http/1.1")
		.map_err(|e| std::io::Error::other(e.to_string()))?;
	builder.set_alpn_select_callback(|_ssl, protos| {
		boring::ssl::select_next_proto(b"\x08http/1.1", protos)
			.ok_or(boring::ssl::AlpnError::NOACK)
	});

	Ok(builder.build())
}

fn serve(
	config: &Config,
	acceptor: &SslAcceptor,
	interceptor: &dyn Interceptor,
	agent: &ureq::Agent,
	stream: TcpStream,
) -> std::io::Result<()> {
	let idle = Duration::from_secs(config.http.idle_timeout_seconds);
	stream.set_read_timeout(Some(idle))?;
	stream.set_nodelay(true)?;

	let tls = acceptor
		.accept(stream)
		.map_err(|e| std::io::Error::other(e.to_string()))?;

	// The SNI is the only thing telling us which origin the client wanted,
	// since a transparent deployment gives us no other clue.
	let sni = tls
		.ssl()
		.servername(NameType::HOST_NAME)
		.map(str::to_string);

	let mut conn = Connection {
		tls: BufReader::new(tls),
		sni,
	};

	// Keep-alive: serve requests until the client goes away or asks to close.
	while conn.serve_one(config, interceptor, agent)? {
		if !config.http.keep_alive {
			break;
		}
	}

	Ok(())
}

struct Connection {
	tls: BufReader<SslStream<TcpStream>>,
	sni: Option<String>,
}

impl Connection {
	/// Serve one request. Returns whether the connection may be reused.
	fn serve_one(
		&mut self,
		config: &Config,
		interceptor: &dyn Interceptor,
		agent: &ureq::Agent,
	) -> std::io::Result<bool> {
		let Some(head) = self.read_head(config.http.max_header_bytes)? else {
			// Clean EOF between requests.
			return Ok(false);
		};

		let mut request = match self.parse(&head, config)? {
			Some(request) => request,
			None => {
				self.write_simple(400, "malformed request")?;

				return Ok(false);
			}
		};

		interceptor.on_request(&mut request);
		log::info!(
			"proxying tcp {} {} ({} body bytes)",
			request.method,
			request.url,
			request.body.len()
		);

		let resp = match upstream::call(agent, &request) {
			Ok(resp) => resp,
			Err(message) => {
				self.write_simple(502, &message)?;

				return Ok(true);
			}
		};

		let mut head = ResponseHead {
			status: resp.status(),
			headers: upstream::response_headers(&resp),
		};

		if interceptor.wants_body(&request, &head) {
			let mut body = Vec::new();
			resp.into_reader().read_to_end(&mut body)?;

			let mut response = ProxyResponse {
				status: head.status,
				headers: head.headers,
				body,
			};
			interceptor.on_response(&request, &mut response);
			self.write_buffered(config, &response)?;
		} else {
			interceptor.on_response_head(&request, &mut head);
			self.write_streaming(config, &head, resp.into_reader())?;
		}

		Ok(true)
	}

	/// Read up to the end of the request head, bounded so a client cannot make
	/// us buffer forever.
	fn read_head(&mut self, limit: usize) -> std::io::Result<Option<Vec<u8>>> {
		let mut head = Vec::new();
		let mut byte = [0u8; 1];

		loop {
			match self.tls.read(&mut byte) {
				Ok(0) => {
					return if head.is_empty() {
						Ok(None)
					} else {
						Err(std::io::Error::new(ErrorKind::UnexpectedEof, "truncated head"))
					}
				}
				Ok(_) => head.push(byte[0]),
				Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
				Err(e) => return Err(e),
			}

			if head.ends_with(b"\r\n\r\n") {
				return Ok(Some(head));
			}

			if head.len() > limit {
				return Err(std::io::Error::other("request head too large"));
			}
		}
	}

	/// Turn a raw request head into a [`ProxyRequest`], reading the body if the
	/// request declares one.
	fn parse(&mut self, head: &[u8], config: &Config) -> std::io::Result<Option<ProxyRequest>> {
		let mut headers = [httparse::EMPTY_HEADER; 96];
		let mut parsed = httparse::Request::new(&mut headers);

		if parsed.parse(head).is_err() {
			return Ok(None);
		}
		let (Some(method), Some(path)) = (parsed.method, parsed.path) else {
			return Ok(None);
		};

		let mut collected = Vec::new();
		let mut host = None;
		let mut content_length = 0usize;

		for header in parsed.headers.iter() {
			let name = header.name.to_ascii_lowercase();
			let value = String::from_utf8_lossy(header.value).into_owned();

			match name.as_str() {
				"host" => host = Some(value),
				"content-length" => content_length = value.trim().parse().unwrap_or(0),
				// ureq re-derives these; forwarding them would conflict.
				_ if upstream::is_hop_by_hop(&name) => {}
				_ => collected.push((name, value)),
			}
		}

		// Prefer the SNI: in a transparent deployment it is the name the client
		// actually asked TLS for, and it cannot be spoofed by a stray Host.
		let authority = self.sni.clone().or(host);
		let Some(authority) = authority else {
			return Ok(None);
		};

		let mut body = vec![0u8; content_length.min(config.max_request_body())];
		if !body.is_empty() {
			self.tls.read_exact(&mut body)?;
		}

		Ok(Some(ProxyRequest {
			method: method.to_string(),
			url: format!("https://{}{path}", crate::authority_host(&authority)),
			headers: collected,
			body,
		}))
	}

	fn write_buffered(&mut self, config: &Config, resp: &ProxyResponse) -> std::io::Result<()> {
		let mut out = BufWriter::new(self.tls.get_mut());

		write_head(
			&mut out,
			config,
			resp.status,
			&resp.headers,
			Some(resp.body.len()),
		)?;
		out.write_all(&resp.body)?;
		out.flush()
	}

	/// Relay a body we never buffered, using chunked transfer-encoding because
	/// its length is not known up front.
	fn write_streaming(
		&mut self,
		config: &Config,
		head: &ResponseHead,
		mut body: impl Read,
	) -> std::io::Result<()> {
		let mut out = BufWriter::new(self.tls.get_mut());

		write_head(&mut out, config, head.status, &head.headers, None)?;
		out.write_all(b"transfer-encoding: chunked\r\n\r\n")?;

		let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
		loop {
			let read = match body.read(&mut buf) {
				Ok(0) => break,
				Ok(n) => n,
				Err(e) => {
					log::warn!("upstream read failed mid-stream: {e}");

					break;
				}
			};

			write!(out, "{read:x}\r\n")?;
			out.write_all(&buf[..read])?;
			out.write_all(b"\r\n")?;
		}

		out.write_all(b"0\r\n\r\n")?;
		out.flush()
	}

	fn write_simple(&mut self, status: u16, message: &str) -> std::io::Result<()> {
		let body = message.as_bytes();
		let mut out = BufWriter::new(self.tls.get_mut());

		write!(
			out,
			"HTTP/1.1 {status} {}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
			reason(status),
			body.len()
		)?;
		out.write_all(body)?;
		out.flush()
	}
}

fn write_head(
	out: &mut impl Write,
	config: &Config,
	status: u16,
	headers: &[(String, String)],
	content_length: Option<usize>,
) -> std::io::Result<()> {
	write!(out, "HTTP/1.1 {status} {}\r\n", reason(status))?;

	for (name, value) in headers {
		// Length and framing are ours to decide, and Alt-Svc is re-added below.
		if upstream::is_hop_by_hop(name) || name.eq_ignore_ascii_case("alt-svc") {
			continue;
		}
		write!(out, "{name}: {value}\r\n")?;
	}

	if let Some(length) = content_length {
		write!(out, "content-length: {length}\r\n")?;
	}

	// The whole reason this listener exists: tell the client h3 is available so
	// subsequent requests move to QUIC.
	if !config.http.alt_svc.is_empty() {
		write!(out, "alt-svc: {}\r\n", config.http.alt_svc)?;
	}

	if config.http.keep_alive {
		write!(out, "connection: keep-alive\r\n")?;
	} else {
		write!(out, "connection: close\r\n")?;
	}

	if content_length.is_some() {
		write!(out, "\r\n")?;
	}

	Ok(())
}

fn reason(status: u16) -> &'static str {
	match status {
		200 => "OK",
		204 => "No Content",
		301 => "Moved Permanently",
		302 => "Found",
		304 => "Not Modified",
		400 => "Bad Request",
		403 => "Forbidden",
		404 => "Not Found",
		500 => "Internal Server Error",
		502 => "Bad Gateway",
		_ => "",
	}
}
