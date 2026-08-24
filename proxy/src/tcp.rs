//! TCP front end: HTTP/2 and HTTP/1.1 over TLS.
//!
//! This exists because HTTP/3 cannot bootstrap itself. A browser opens TCP 443
//! first and only learns that h3 is available from the `Alt-Svc` header on a
//! response it received over TCP. Without this listener a browser pointed at
//! the proxy simply fails to connect.
//!
//! It matters that this speaks h2, not just h1.1: on a network where UDP is
//! blocked, every request falls back here permanently. Serving only h1.1 would
//! make the proxy slower than no proxy at all on exactly those networks.
//!
//! hyper drives the connection, so protocol negotiation, keep-alive and chunked
//! encoding are handled for us. The rest of the proxy is blocking (ureq,
//! plugin subprocesses), so all of that runs on `spawn_blocking` against a
//! fixed pool of interceptor chains rather than being rewritten as async.

use std::convert::Infallible;
use std::io::Read;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use boring::ssl::{AlpnError, NameType, SslAcceptor, SslMethod};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;

use crate::ca::CertAuthority;
use crate::config::Config;
use crate::interceptor::{Chain, Interceptor, ProxyRequest, ProxyResponse, ResponseHead};
use crate::interstitial;
use crate::upstream;

const STREAM_CHUNK_SIZE: usize = 64 * 1024;

type BoxBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

/// A fixed set of interceptor chains, borrowed for the duration of a request.
///
/// Each chain owns its own plugin subprocesses, so the pool size bounds how
/// many copies of every plugin are running. Blocking here is fine: callers are
/// already on a blocking thread.
struct ChainPool {
	give_back: Sender<Chain>,
	take: Mutex<Receiver<Chain>>,
}

impl ChainPool {
	fn new(size: usize, config: &Config) -> Self {
		let (give_back, take) = std::sync::mpsc::channel();
		for _ in 0..size {
			let _ = give_back.send(Chain::from_config(config));
		}

		Self {
			give_back,
			take: Mutex::new(take),
		}
	}

	fn acquire(&self) -> Option<Borrowed<'_>> {
		let chain = self.take.lock().ok()?.recv().ok()?;

		Some(Borrowed {
			pool: self,
			chain: Some(chain),
		})
	}
}

struct Borrowed<'a> {
	pool: &'a ChainPool,
	chain: Option<Chain>,
}

impl Borrowed<'_> {
	fn get(&self) -> &Chain {
		self.chain.as_ref().expect("chain is present until dropped")
	}
}

impl Drop for Borrowed<'_> {
	fn drop(&mut self) {
		if let Some(chain) = self.chain.take() {
			let _ = self.pool.give_back.send(chain);
		}
	}
}

/// Connection-level settings read before `shared` is moved into the service.
struct HttpSettings {
	keep_alive: bool,
	idle_timeout_seconds: u64,
}

/// Everything a request handler needs, shared across connections.
struct Shared {
	config: Arc<Config>,
	pool: ChainPool,
	agent: ureq::Agent,
}

/// Start the listener. Returns once its runtime thread is spawned.
pub fn spawn(config: Arc<Config>, ca: Arc<CertAuthority>) -> std::io::Result<()> {
	let acceptor = Arc::new(build_acceptor(&ca)?);
	let addr = config.listen_tcp.0;

	let shared = Arc::new(Shared {
		pool: ChainPool::new(config.worker_threads(), &config),
		agent: upstream::agent(&config),
		config,
	});

	// hyper needs a tokio runtime; the QUIC side keeps its own sync mio loop, so
	// the runtime lives on its own thread rather than taking over main.
	std::thread::spawn(move || {
		let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
			Ok(runtime) => runtime,
			Err(e) => {
				log::error!("could not start tcp runtime: {e}");

				return;
			}
		};

		runtime.block_on(async move {
			let listener = match TcpListener::bind(addr).await {
				Ok(listener) => listener,
				Err(e) => {
					log::error!("cannot bind {addr}: {e}");

					return;
				}
			};
			log::info!("listening on {addr} (TCP/TLS, HTTP/2 and HTTP/1.1)");

			loop {
				let (stream, peer) = match listener.accept().await {
					Ok(accepted) => accepted,
					Err(e) => {
						log::debug!("tcp accept failed: {e}");

						continue;
					}
				};

				let acceptor = acceptor.clone();
				let shared = shared.clone();
				tokio::spawn(async move {
					if let Err(e) = serve(acceptor, shared, stream).await {
						log::debug!("tcp connection from {peer} ended: {e}");
					}
				});
			}
		});
	});

	Ok(())
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

	// Offer h2 first so a client that supports it takes it.
	builder.set_alpn_select_callback(|_ssl, protos| {
		boring::ssl::select_next_proto(b"\x02h2\x08http/1.1", protos).ok_or(AlpnError::NOACK)
	});

	Ok(builder.build())
}

async fn serve(
	acceptor: Arc<SslAcceptor>,
	shared: Arc<Shared>,
	stream: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	stream.set_nodelay(true)?;

	let tls = tokio_boring::accept(&acceptor, stream)
		.await
		.map_err(|e| format!("tls handshake failed: {e}"))?;

	// The SNI is the only thing telling us which origin the client wanted: a
	// transparent deployment gives us no other clue.
	let sni = tls.ssl().servername(NameType::HOST_NAME).map(str::to_string);

	let shared_http = HttpSettings {
		keep_alive: shared.config.http.keep_alive,
		idle_timeout_seconds: shared.config.http.idle_timeout_seconds,
	};

	let service = service_fn(move |req: Request<Incoming>| {
		let shared = shared.clone();
		let sni = sni.clone();

		async move { Ok::<_, Infallible>(handle(shared, sni, req).await) }
	});

	// Auto-negotiates h2 or h1.1 from the connection preface, and handles
	// keep-alive and chunked framing on both.
	let mut builder = ConnBuilder::new(TokioExecutor::new());
	// header_read_timeout needs a timer; without one hyper cannot arm it and the
	// HTTP/1.1 path silently drops connections while h2 keeps working.
	builder
		.http1()
		.timer(TokioTimer::new())
		.keep_alive(shared_http.keep_alive)
		.header_read_timeout(std::time::Duration::from_secs(shared_http.idle_timeout_seconds));

	builder.serve_connection(TokioIo::new(tls), service).await?;

	Ok(())
}

async fn handle(shared: Arc<Shared>, sni: Option<String>, req: Request<Incoming>) -> Response<BoxBody> {
	let request = match to_proxy_request(&shared.config, sni, req).await {
		Ok(request) => request,
		Err(status) => return simple(status, "mach5: malformed request\n"),
	};

	// Everything past here blocks: plugin subprocesses and the upstream fetch.
	let (head_tx, head_rx) = tokio::sync::oneshot::channel();
	let chunk_capacity = shared.config.stream_buffer_chunks(STREAM_CHUNK_SIZE);
	let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(chunk_capacity);

	tokio::task::spawn_blocking(move || {
		fetch_blocking(&shared, request, head_tx, body_tx);
	});

	match head_rx.await {
		Ok(Outcome::Buffered(response)) => build_response(response),
		Ok(Outcome::Streaming(head)) => {
			let body = StreamBody::new(ReceiverStream::new(body_rx));
			let mut builder = Response::builder().status(head.status);
			for (name, value) in &head.headers {
				builder = builder.header(name, value);
			}

			builder
				.body(BodyExt::boxed(body))
				.unwrap_or_else(|_| simple(502, "mach5: malformed upstream headers\n"))
		}
		// The blocking task died without reporting; nothing else will answer.
		Err(_) => simple(502, "mach5: upstream fetch failed\n"),
	}
}

enum Outcome {
	Buffered(ProxyResponse),
	Streaming(ResponseHead),
}

/// Runs the interceptors and the upstream fetch on a blocking thread, reporting
/// the head as soon as it is known so a streaming body can start flowing.
fn fetch_blocking(
	shared: &Shared,
	mut request: ProxyRequest,
	head_tx: tokio::sync::oneshot::Sender<Outcome>,
	body_tx: tokio::sync::mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) {
	let Some(borrowed) = shared.pool.acquire() else {
		let _ = head_tx.send(Outcome::Buffered(error_body(502, "interceptor pool unavailable")));

		return;
	};
	let interceptor = borrowed.get();

	interceptor.on_request(&mut request);
	log::info!(
		"proxying tcp {} {} ({} body bytes)",
		request.method,
		request.url,
		request.body.len()
	);

	let resp = match upstream::call(&shared.agent, &request) {
		Ok(resp) => resp,
		Err(failure) => {
			let _ = head_tx.send(Outcome::Buffered(failure_page(&request, &failure)));

			return;
		}
	};

	let mut head = ResponseHead {
		status: resp.status(),
		headers: upstream::response_headers(&resp),
	};

	if interceptor.wants_body(&request, &head) {
		let mut body = Vec::new();
		if let Err(e) = resp.into_reader().read_to_end(&mut body) {
			log::warn!("failed reading upstream body for {}: {e}", request.url);
		}

		let mut response = ProxyResponse {
			status: head.status,
			headers: head.headers,
			body,
		};
		interceptor.on_response(&request, &mut response);
		apply_alt_svc(&shared.config, &mut response.headers);
		let _ = head_tx.send(Outcome::Buffered(response));

		return;
	}

	interceptor.on_response_head(&request, &mut head);
	apply_alt_svc(&shared.config, &mut head.headers);
	if head_tx.send(Outcome::Streaming(head)).is_err() {
		return;
	}

	// Relay the body. `blocking_send` is the backpressure: it parks this thread
	// when the client is not draining fast enough, rather than queueing without
	// bound.
	let mut reader = resp.into_reader();
	let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
	loop {
		let read = match reader.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => n,
			Err(e) => {
				log::warn!("upstream read failed mid-stream: {e}");

				break;
			}
		};

		let chunk = Bytes::copy_from_slice(&buf[..read]);
		if body_tx.blocking_send(Ok(Frame::data(chunk))).is_err() {
			// Client went away.
			break;
		}
	}
}

async fn to_proxy_request(
	config: &Config,
	sni: Option<String>,
	req: Request<Incoming>,
) -> Result<ProxyRequest, u16> {
	let (parts, body) = req.into_parts();

	let mut headers = Vec::new();
	let mut host = None;
	for (name, value) in parts.headers.iter() {
		let name = name.as_str().to_ascii_lowercase();
		let Ok(value) = value.to_str() else {
			continue;
		};

		match name.as_str() {
			"host" => host = Some(value.to_string()),
			_ if upstream::is_hop_by_hop(&name) => {}
			_ => headers.push((name, value.to_string())),
		}
	}

	// Prefer the SNI: it is the name the client actually asked TLS for and
	// cannot be redirected by a stray Host header. h2 carries :authority, which
	// hyper surfaces as the uri authority.
	let authority = sni
		.or_else(|| parts.uri.authority().map(|a| a.to_string()))
		.or(host)
		.ok_or(400u16)?;

	// hyper has already decoded chunked encoding by the time we see this.
	let collected = body.collect().await.map_err(|_| 400u16)?.to_bytes();
	if collected.len() > config.max_request_body() {
		return Err(413);
	}

	let path = parts
		.uri
		.path_and_query()
		.map(|p| p.as_str())
		.unwrap_or("/");

	Ok(ProxyRequest {
		method: parts.method.as_str().to_string(),
		url: format!("https://{}{path}", crate::authority_host(&authority)),
		headers,
		body: collected.to_vec(),
	})
}

fn build_response(response: ProxyResponse) -> Response<BoxBody> {
	let mut builder = Response::builder().status(response.status);
	for (name, value) in &response.headers {
		builder = builder.header(name, value);
	}

	builder
		.body(BodyExt::boxed(Full::new(Bytes::from(response.body))))
		.unwrap_or_else(|_| simple(502, "mach5: malformed upstream headers\n"))
}

/// Replace any upstream `Alt-Svc` with our own. The origin's advertisement
/// points at the origin's own h3 endpoint, which is not where the client should
/// go — and ours is the whole reason this listener exists.
fn apply_alt_svc(config: &Config, headers: &mut Vec<(String, String)>) {
	headers.retain(|(name, _)| !name.eq_ignore_ascii_case("alt-svc"));

	if !config.http.alt_svc.is_empty() {
		headers.push(("alt-svc".to_string(), config.http.alt_svc.clone()));
	}
}

/// Render an upstream failure as a page the person can actually read.
fn failure_page(request: &ProxyRequest, failure: &upstream::FetchError) -> ProxyResponse {
	let host = crate::host_of(&request.url);

	match failure {
		upstream::FetchError::Tls(detail) => {
			log::warn!("certificate validation failed for {host}: {detail}");

			interstitial::certificate_error(host, detail)
		}
		upstream::FetchError::Other(detail) => interstitial::upstream_error(host, detail),
	}
}

fn error_body(status: u16, message: &str) -> ProxyResponse {
	ProxyResponse {
		status,
		headers: vec![("content-type".to_string(), "text/plain".to_string())],
		body: message.as_bytes().to_vec(),
	}
}

fn simple(status: u16, message: &str) -> Response<BoxBody> {
	Response::builder()
		.status(status)
		.header("content-type", "text/plain")
		.body(BodyExt::boxed(Full::new(Bytes::from(
			message.as_bytes().to_vec(),
		))))
		.expect("static response is well formed")
}
