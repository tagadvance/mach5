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
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;

use crate::ca::CertAuthority;
use crate::config::Config;
use crate::encoding;
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
	fn new(size: usize, config: &Config, ca: &Arc<CertAuthority>) -> Self {
		let (give_back, take) = std::sync::mpsc::channel();
		for _ in 0..size {
			let _ = give_back.send(Chain::from_config(config, ca.clone()));
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
	passthrough: Arc<crate::passthrough::Passthrough>,
	pool: ChainPool,
	agents: upstream::Agents,
}

/// Start the listener. Returns once its runtime thread is spawned.
pub fn spawn(config: Arc<Config>, ca: Arc<CertAuthority>) -> std::io::Result<()> {
	let acceptor = Arc::new(build_acceptor(&ca)?);
	let addr = config.listen_tcp.0;

	let shared = Arc::new(Shared {
		passthrough: crate::passthrough::shared(&config),
		pool: ChainPool::new(config.worker_threads(), &config, &ca),
		agents: upstream::agents(&config),
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
	mut stream: tokio::net::TcpStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	stream.set_nodelay(true)?;

	// Before anything is answered: the name is in the ClientHello, and a listed
	// host must not be answered at all. Skipped entirely when nothing is
	// listed, so the common case does not pay for a peek it cannot use.
	if !shared.passthrough.is_empty() {
		if let Some(host) = peek_server_name(&mut stream).await {
			if shared.passthrough.covers(&host) {
				return splice(stream, &host, shared.passthrough.port()).await;
			}
		}
	}

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
	let (request, incoming, length) = match to_proxy_request(sni, req) {
		Ok(parts) => parts,
		Err(status) => return simple(status, "mach5: malformed request\n"),
	};

	// An upload is pumped into a bounded channel by this task while the worker
	// reads the other end. Nothing here awaits the whole body, so an upload is
	// never held in memory on the way past — and a worker that stops reading
	// fills the channel, which stops us taking bytes off the client.
	let upload = (!incoming.is_end_stream() && length != Some(0)).then(|| {
		let (chunks_tx, chunks_rx) = crate::body::channel();

		tokio::spawn(async move {
			let mut incoming = incoming;
			while let Some(frame) = incoming.frame().await {
				let Ok(frame) = frame else {
					// A client that dies mid-upload closes the channel by
					// dropping this sender, which the worker reads as an end.
					break;
				};
				let Ok(data) = frame.into_data() else {
					// Trailers; nothing upstream is waiting for them.
					continue;
				};
				if data.is_empty() {
					continue;
				}
				if chunks_tx.send(data.to_vec()).await.is_err() {
					// The worker is done with the body — short-circuited, or
					// the fetch failed. Stop reading the client.
					break;
				}
			}
		});

		(chunks_rx, length)
	});

	// Everything past here blocks: plugin subprocesses and the upstream fetch.
	let (head_tx, head_rx) = tokio::sync::oneshot::channel();
	let chunk_capacity = shared.config.stream_buffer_chunks(STREAM_CHUNK_SIZE);
	let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(chunk_capacity);

	tokio::task::spawn_blocking(move || {
		fetch_blocking(&shared, request, upload, head_tx, body_tx);
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
	upload: Option<(tokio::sync::mpsc::Receiver<crate::body::Chunk>, Option<u64>)>,
	head_tx: tokio::sync::oneshot::Sender<Outcome>,
	body_tx: tokio::sync::mpsc::Sender<Result<Frame<Bytes>, Infallible>>,
) {
	let metrics = crate::metrics::shared();
	metrics.requests.increment();

	let Some(borrowed) = shared.pool.acquire() else {
		let _ = head_tx.send(Outcome::Buffered(error_body(502, "interceptor pool unavailable")));

		return;
	};
	let interceptor = borrowed.get();

	// Anything that can answer without the body answers first, so a blocked
	// upload is refused rather than read.
	let resume = match interceptor.before_body(&mut request) {
		crate::interceptor::BeforeBody::Answered(response) => {
			short_circuit(shared, request, response, head_tx);

			return;
		}
		crate::interceptor::BeforeBody::Resume { from } => from,
	};

	let body = match crate::body::take(
		&shared.config,
		resume < interceptor.len(),
		&mut request,
		upload,
	) {
		Ok(body) => body,
		Err(rejected) => {
			let _ = head_tx.send(Outcome::Buffered(error_body(rejected.status, rejected.message)));

			return;
		}
	};

	if let Some(response) = interceptor.on_request_from(&mut request, resume) {
		short_circuit(shared, request, response, head_tx);

		return;
	}

	log::info!(
		"proxying tcp {} {} ({} body bytes)",
		request.method,
		crate::redact::url(&request.url),
		request.body.len()
	);

	let resp = match upstream::call(&shared.agents, &request, body) {
		Ok(resp) => resp,
		Err(failure) => {
			let page = failure_page(&shared.config, &request, &failure);
			metrics.bytes_to_client.add(page.body.len() as u64);
			let _ = head_tx.send(Outcome::Buffered(page));

			return;
		}
	};

	// A response that came off the disk has no reader; it is already whole, so
	// it takes the buffered path unconditionally and the interceptors run on it
	// exactly as they would on a fetched one.
	let resp = match resp {
		upstream::Fetched::Stored(stored) => {
			let mut head = ResponseHead {
				status: stored.status,
				headers: stored.headers,
			};
			let (body, coding) = encoding::decode(&mut head.headers, stored.body, shared.config.max_response_body());
			let mut response = ProxyResponse {
				status: head.status,
				headers: head.headers,
				body,
			};
			interceptor.on_response(&request, &mut response);
			response.body = encoding::encode(&mut response.headers, response.body, coding);
			finish_buffered(shared, &request, response, head_tx);

			return;
		}
		upstream::Fetched::Live(live) => *live,
	};

	let declared = upstream::declared_length(&resp);
	let mut head = ResponseHead {
		status: resp.status(),
		headers: upstream::response_headers(&resp),
	};

	// Buffered either because something wants to look at it, or because it is
	// worth keeping — a stylesheet nobody inspects still has to be held whole
	// to be stored.
	let worth_keeping =
		upstream::should_store(&shared.agents, &shared.config, &request, head.status, &head.headers, declared);

	let limit = shared.config.max_response_body();
	let mut reader = resp.into_reader();

	if interceptor.wants_body(&request, &head) || worth_keeping {
		// One byte past the limit is enough to know it was passed, and is all
		// that is ever held beyond it. Nothing here trusts content-length: an
		// origin is free to send more than it declared.
		let mut body = Vec::new();
		if let Err(e) = reader.by_ref().take((limit as u64).saturating_add(1)).read_to_end(&mut body) {
			log::warn!(
				"failed reading upstream body for {}: {e}",
				crate::redact::url(&request.url)
			);
		}

		if body.len() > limit {
			// Whatever wanted to look at this does not get to; the client
			// still gets the response. Refusing it outright would turn a large
			// download into a broken one over a plugin's filter being wide.
			log::warn!(
				"body for {} is over the {limit} byte buffer limit; relaying it uninspected",
				crate::redact::url(&request.url)
			);
			reader = Box::new(std::io::Cursor::new(body).chain(reader));
		} else {
			metrics.bytes_from_origin.add(body.len() as u64);
			// The origin's own bytes, before anything rewrites them.
			upstream::store(&shared.agents, &request, head.status, &head.headers, &body);

			// Interceptors rewrite plain bytes; the coding goes back on
			// afterwards.
			let (body, coding) = encoding::decode(&mut head.headers, body, limit);
			let mut response = ProxyResponse {
				status: head.status,
				headers: head.headers,
				body,
			};
			interceptor.on_response(&request, &mut response);
			response.body = encoding::encode(&mut response.headers, response.body, coding);
			finish_buffered(shared, &request, response, head_tx);

			return;
		}
	}

	// Nothing wants the body: relay it as it arrives. Deliberately not a place
	// to compress — the coding here is whatever the origin chose, and we never
	// hold enough of the body to know what a different one would cost.
	interceptor.on_response_head(&request, &mut head);
	apply_alt_svc(&shared.config, &mut head.headers);
	// Asked once, before the head is handed off: the answer holds for the whole
	// stream, and re-asking per chunk would cost a plugin round trip each time.
	let wants_chunks = interceptor.wants_chunks(&request, &head);
	// A page is rewritten on its way past rather than held whole, so the client
	// starts receiving it while the origin is still writing it.
	let mut rewriting = crate::inject::streamer_for(&shared.config, &request, &mut head);
	if head_tx.send(Outcome::Streaming(head)).is_err() {
		return;
	}

	// Relay the body. `blocking_send` is the backpressure: it parks this thread
	// when the client is not draining fast enough, rather than queueing without
	// bound.
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
		metrics.bytes_from_origin.add(read as u64);

		let mut chunk = buf[..read].to_vec();
		if wants_chunks {
			interceptor.on_response_chunk(&request, &mut chunk);
			// Emptied on purpose: an interceptor accumulating across chunks
			// flushes what it kept at the end instead.
			if chunk.is_empty() {
				continue;
			}
		}

		// Injection happens here, on the way past. A parser mid-document may
		// have nothing to emit yet, which is not the same as having nothing to
		// send later.
		if let Some(streamer) = rewriting.as_mut() {
			chunk = streamer.push(&chunk);
			if chunk.is_empty() {
				continue;
			}
		}

		metrics.bytes_to_client.add(chunk.len() as u64);

		if body_tx.blocking_send(Ok(Frame::data(Bytes::from(chunk)))).is_err() {
			// Client went away.
			break;
		}
	}

	if let Some(streamer) = rewriting.take() {
		let tail = streamer.finish();
		if !tail.is_empty() {
			metrics.bytes_to_client.add(tail.len() as u64);
			let _ = body_tx.blocking_send(Ok(Frame::data(Bytes::from(tail))));
		}
	}

	if wants_chunks {
		if let Some(tail) = interceptor.on_response_end(&request) {
			metrics.bytes_to_client.add(tail.len() as u64);
			let _ = body_tx.blocking_send(Ok(Frame::data(Bytes::from(tail))));
		}
	}
}

/// Split the incoming request into what the interceptors see and the body still
/// arriving behind it. The body is deliberately not read here: whether it is
/// held in memory at all is the worker's decision, and this is the async side.
fn to_proxy_request(
	sni: Option<String>,
	req: Request<Incoming>,
) -> Result<(ProxyRequest, Incoming, Option<u64>), u16> {
	let (parts, body) = req.into_parts();

	// Kept before the hop-by-hop filter drops it: it is how the upstream
	// request can use the same framing the client did.
	let length = parts
		.headers
		.get(hyper::header::CONTENT_LENGTH)
		.and_then(|value| value.to_str().ok())
		.and_then(|value| value.parse::<u64>().ok());

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

	let path = parts
		.uri
		.path_and_query()
		.map(|p| p.as_str())
		.unwrap_or("/");

	Ok((
		ProxyRequest {
			method: parts.method.as_str().to_string(),
			url: format!("https://{}{path}", crate::authority_host(&authority)),
			headers,
			body: Vec::new(),
		},
		body,
		length,
	))
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

/// The name the client asked for, read without answering it.
///
/// `peek` rather than `read`: the bytes stay in the socket, so whichever way
/// this goes the ClientHello is still there to be handled — by the TLS
/// acceptor, or by the origin at the far end of a splice. Nothing has to be
/// stitched back on.
async fn peek_server_name(stream: &mut tokio::net::TcpStream) -> Option<String> {
	let mut buf = [0u8; crate::passthrough::PEEK_BYTES];

	// One peek. A ClientHello arrives in the first packet in practice, and a
	// client that dribbles one out is terminated as usual — which is the safe
	// direction for this to be wrong in.
	let read = stream.peek(&mut buf).await.ok()?;

	crate::passthrough::server_name(&buf[..read])
}

/// Carry a connection to its origin without decrypting it.
///
/// mach5 is a pair of sockets here and nothing else: no certificate, no keys,
/// no plaintext, no interceptors, no plugins. The client is speaking TLS to the
/// real origin and checking the real certificate, which is the whole point —
/// and is also the only arrangement a certificate-pinning app will accept.
async fn splice(
	mut client: tokio::net::TcpStream,
	host: &str,
	port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	let arrived_at = client.local_addr()?;
	let mut origin = tokio::net::TcpStream::connect((host, port))
		.await
		.map_err(|e| format!("cannot reach {host} to pass it through: {e}"))?;

	// The wildcard DNS that points every name here would otherwise have mach5
	// splice to itself, each connection begetting the next.
	if origin.peer_addr()? == arrived_at {
		return Err(format!("{host} resolves to mach5 itself; refusing to splice").into());
	}

	origin.set_nodelay(true)?;
	let metrics = crate::metrics::shared();
	metrics.passed_through.increment();
	metrics.requests.increment();
	log::info!("passing {host} through without decrypting it");

	// Both directions until either end closes. The counts are of ciphertext:
	// what came back is exactly what went to the client, because mach5 did not
	// touch it.
	let (_uploaded, returned) = tokio::io::copy_bidirectional(&mut client, &mut origin).await?;
	metrics.bytes_from_origin.add(returned);
	metrics.bytes_to_client.add(returned);

	Ok(())
}

/// The last stretch every whole response takes: compress it if it is worth
/// compressing, advertise h3, count it, and hand it to the connection.
fn finish_buffered(
	shared: &Shared,
	request: &ProxyRequest,
	mut response: ProxyResponse,
	head_tx: tokio::sync::oneshot::Sender<Outcome>,
) {
	let metrics = crate::metrics::shared();

	if shared.config.http.compress {
		let plain = response.body.len();
		response.body = crate::encoding::ensure_compressed(
			&request.headers,
			response.status,
			&mut response.headers,
			response.body,
			None,
		);
		metrics
			.bytes_saved_by_compression
			.add(plain.saturating_sub(response.body.len()) as u64);
	}

	apply_alt_svc(&shared.config, &mut response.headers);
	metrics.bytes_to_client.add(response.body.len() as u64);
	let _ = head_tx.send(Outcome::Buffered(response));
}

/// Serve a response an interceptor produced instead of fetching the origin.
fn short_circuit(
	shared: &Shared,
	request: ProxyRequest,
	mut response: ProxyResponse,
	head_tx: tokio::sync::oneshot::Sender<Outcome>,
) {
	log::info!(
		"short-circuited {} {}",
		request.method,
		crate::redact::url(&request.url)
	);
	// A response we wrote ourselves never went near the upstream path, so this
	// is where it gets compressed. The picker is several kilobytes of
	// JavaScript on every page — by far the largest thing mach5 serves.
	if shared.config.http.compress {
		let plain = response.body.len();
		response.body = crate::encoding::ensure_compressed(
			&request.headers,
			response.status,
			&mut response.headers,
			response.body,
			None,
		);
		crate::metrics::shared()
			.bytes_saved_by_compression
			.add(plain.saturating_sub(response.body.len()) as u64);
	}
	apply_alt_svc(&shared.config, &mut response.headers);
	crate::metrics::shared()
		.bytes_to_client
		.add(response.body.len() as u64);
	let _ = head_tx.send(Outcome::Buffered(response));
}

/// Render an upstream failure as a page the person can actually read.
fn failure_page(
	config: &Config,
	request: &ProxyRequest,
	failure: &upstream::FetchError,
) -> ProxyResponse {
	let host = crate::host_of(&request.url);

	match failure {
		upstream::FetchError::Tls(detail) => {
			let logged = crate::redact::detail(detail, &request.url);
			log::warn!("certificate validation failed for {host}: {logged}");

			{
				// Offered only when the phrase is configured, and spent by the page
				// that carries it — see `insecure::Bypasses::redeem`.
				let offer = config
					.bypass_phrase()
					.map(|phrase| (phrase, crate::insecure::bypasses().offer(host)));
				let offer = offer.as_ref().map(|(phrase, token)| (*phrase, token.as_str()));

				interstitial::certificate_error(host, detail, offer)
			}
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
