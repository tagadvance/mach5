//! mach5 — QUIC/HTTP-3 intercepting proxy (skeleton).
//!
//! Terminates an HTTP/3 connection from a client with a certificate minted on
//! the fly for the requested SNI host (signed by our root CA), forwards each
//! request to the real origin through a pluggable [`Interceptor`], and streams
//! the response back. Upstream fetches run on a worker pool so a slow origin
//! never stalls the single-threaded QUIC event loop.

mod blocklist;
mod body;
mod budget;
mod ca;
mod config;
mod disk;
mod cosmetic;
mod encoding;
mod fetch;
mod httpcache;
mod imagecache;
mod images;
mod inject;
mod insecure;
mod interceptor;
mod internal;
mod interstitial;
mod metrics;
mod passthrough;
mod plugin;
mod redact;
mod resolver;
mod settings;
mod tcp;
mod upstream;

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use boring::ssl::{select_next_proto, AlpnError, SslContextBuilder, SslMethod, SslVersion};
use quiche::h3::NameValue;

use ca::CertAuthority;
use config::Config;
use interceptor::{Chain, Interceptor, ProxyRequest, ProxyResponse, ResponseHead};

const SOCKET: mio::Token = mio::Token(0);
const WAKER: mio::Token = mio::Token(1);

/// Prefix identifying an address-validation token as ours.
const TOKEN_MARKER: &[u8] = b"mach5";
/// A Retry token is answered within a round trip or two. Anything older is a
/// replay, and a replayed one mints connections for as long as it is kept.
const TOKEN_TTL_SECONDS: u64 = 30;
const EXPIRY_BYTES: usize = 8;
/// HMAC-SHA256.
const TAG_BYTES: usize = 32;

/// How much of a streaming body to relay per chunk.
const STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// A request handed off to a worker for fetching.
struct FetchJob {
	conn: quiche::ConnectionId<'static>,
	stream_id: u64,
	request: ProxyRequest,
	/// The body still arriving, when there is one, and the length the client
	/// declared for it.
	upload: Option<(
		tokio::sync::mpsc::Receiver<body::Chunk>,
		body::Ending,
		Option<u64>,
	)>,
	/// How much of the response may be in flight at once. See [`budget`].
	budget: Arc<budget::Budget>,
}

/// Why a worker stopped handing pieces of a response over.
///
/// The distinction is the difference between one dead client and a worker pool
/// that quietly shrinks: only [`Gone::Pool`] means this thread has nothing left
/// to do. A stream that goes away — a client that closed the tab mid-download —
/// ends the job and nothing else.
#[derive(Debug, PartialEq, Eq)]
enum Gone {
	Stream,
	Pool,
}

/// A fetched response on its way back to a client, in one of two shapes: a
/// whole buffered response, or the pieces of a streaming one.
struct FetchResult {
	conn: quiche::ConnectionId<'static>,
	stream_id: u64,
	payload: Payload,
	/// Carried alongside so the event loop can give room back as bytes leave,
	/// and can let a worker go when there is nobody left to give them to.
	budget: Arc<budget::Budget>,
}

enum Payload {
	/// The complete response, already through the interceptors.
	Full(ProxyResponse),
	/// Status and headers of a response whose body follows as chunks.
	Head(ResponseHead),
	Chunk(Vec<u8>),
	/// No more chunks: the body ended.
	End,
}

/// A response being written out on one h3 stream, tracking how far it got so it
/// can resume when the stream regains capacity.
struct Pending {
	stream_id: u64,
	status: u16,
	headers: Vec<(String, String)>,
	headers_sent: bool,
	/// Body chunks awaiting write. A buffered response arrives as one chunk.
	chunks: VecDeque<Vec<u8>>,
	/// How far into the front chunk we have written.
	offset: usize,
	/// True once no further chunks will arrive.
	complete: bool,
	/// True once the stream has actually been closed. Tracked separately from
	/// `complete` because upstream often finishes *after* the last chunk has
	/// already been written, leaving nothing to attach the fin to.
	fin_sent: bool,
	budget: Arc<budget::Budget>,
}

impl Pending {
	fn is_finished(&self) -> bool {
		self.headers_sent && self.fin_sent
	}
}

impl Drop for Pending {
	/// However this response ends — sent, failed, or dropped with the
	/// connection — the worker behind it must not be left parked waiting for
	/// room on a stream nobody is reading. There are only as many workers as
	/// cores.
	fn drop(&mut self) {
		self.budget.close();
	}
}

/// Per-connection state.
struct Client {
	conn: quiche::Connection,
	http3: Option<quiche::h3::Connection>,
	pending: Vec<Pending>,
	/// Bodies still arriving, keyed by stream id. The request itself went to a
	/// worker the moment its headers landed; this is the tap still running.
	uploads: HashMap<u64, Upload>,
}

/// An upload in flight, between the QUIC stream it arrives on and the worker
/// reading the other end of its channel.
struct Upload {
	chunks: tokio::sync::mpsc::Sender<body::Chunk>,
	/// Told apart from a body that simply ended, so a stream the client reset
	/// does not become a shorter but perfectly well-formed request upstream.
	ending: body::Ending,
	/// Bytes read off the stream that the channel had no room for. The event
	/// loop must never block, so a full channel parks chunks here instead —
	/// bounded, because parking without a bound is just buffering again.
	overflow: VecDeque<body::Chunk>,
	parked: usize,
	/// The client has sent everything. The sender is still held until the
	/// overflow drains, since dropping it is what tells the worker the body
	/// ended.
	finished: bool,
}

impl Upload {
	/// Whether there is room to read more off the stream. Past this, we simply
	/// stop reading and QUIC's own flow control tells the client to wait —
	/// which is the backpressure working, not a stall.
	fn has_room(&self, cap: usize) -> bool {
		self.parked < cap
	}

	fn park(&mut self, chunk: body::Chunk) {
		self.parked += chunk.len();
		self.overflow.push_back(chunk);
	}
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

/// Flush left on purpose: a `\`-continued string literal strips the leading
/// whitespace of each following line, which quietly un-indents help text.
const HELP: &str = r#"
An intercepting proxy. It is configured by a file, not by flags.

Configuration is read from the first of these that exists:

  $MACH5_CONFIG
  ./mach5.toml
  $XDG_CONFIG_HOME/mach5/mach5.toml

Every setting is documented inline in the example mach5.toml.
Set RUST_LOG=debug for handshake detail.

Read SECURITY.md before running this on a network you share with anyone.
"#;

/// Answer `--version` and `--help` and nothing else.
///
/// Deliberately hand-rolled rather than a dependency: mach5 is configured by a
/// file, so there are no options to parse — but "which build is this?" is the
/// first question on any bug report, and a binary that cannot answer it makes
/// every one of those a conversation.
///
/// Returns true when the caller should stop.
fn answered_on_the_command_line() -> bool {
	let asked: Vec<String> = std::env::args().skip(1).collect();

	if asked.iter().any(|a| a == "--version" || a == "-V") {
		println!("mach5-proxy {}", env!("CARGO_PKG_VERSION"));

		return true;
	}

	if asked.iter().any(|a| a == "--help" || a == "-h") {
		println!("mach5-proxy {}\n{HELP}", env!("CARGO_PKG_VERSION"));

		return true;
	}

	if let Some(unknown) = asked.first() {
		eprintln!("mach5-proxy: {unknown} is not an option; try --help");
		// Non-zero, so a wrapper script or a unit file notices. Silently
		// starting anyway would be worse: the operator thinks the flag did
		// something.
		std::process::exit(2);
	}

	false
}

/// Make sure a configured directory exists and can be written, with an error
/// somebody can act on rather than a bare `Permission denied`.
///
/// The unexpanded `~` is checked first and on purpose. Docker sets `HOME=/` for
/// a uid with no passwd entry, which is what happens the moment a container
/// runs as an arbitrary user — so the default `~/.cache/mach5` cannot be
/// expanded, and creating it would either fail with a path nobody recognises or
/// quietly make a directory literally named `~` in the working directory.
/// Neither is a thing to let happen silently.
fn usable_directory(path: &std::path::Path, setting: &str) -> Result<(), String> {
	if path.starts_with("~") {
		return Err(format!(
			"[paths] {setting} defaults to {} and there is no usable HOME to expand \
			 `~` against — normal in a container running as a uid with no passwd \
			 entry. Set it to an absolute path the container can write, as \
			 docker/mach5.toml does.",
			path.display()
		));
	}

	std::fs::create_dir_all(path)
		.map_err(|e| format!("cannot create [paths] {setting} at {} ({e}).", path.display()))
}

fn main() -> Result<(), Box<dyn Error>> {
	if answered_on_the_command_line() {
		return Ok(());
	}

	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

	let config = Arc::new(Config::load()?);
	// Before anything has a URL to log.
	redact::init(config.log.urls);
	// Taken here so that a machine with no usable random source refuses to
	// start, rather than panicking in the event loop on the first Retry.
	let _ = token_key();
	let listen = config.listen.0;

	// A cache mach5 cannot write is survivable — it works, just slower.
	if let Err(e) = usable_directory(&config.paths.cache_dir, "cache_dir") {
		log::warn!("no cache: {e} Nothing will be cached, so every image is re-encoded and every asset re-fetched.");
	}

	// The state directory is not survivable, and does not warn. It holds what
	// somebody typed — the elements they hid, the settings they chose — and a
	// proxy that runs happily while silently failing to keep any of it is the
	// worst of the available behaviours. Refusing to start costs one line of
	// configuration and is impossible to miss.
	if let Err(e) = usable_directory(&config.paths.state_dir, "state_dir") {
		return Err(format!(
			"{e} This is where hidden elements and settings are kept, so mach5 \
			 will not start without it."
		)
		.into());
	}

	// Before the front ends, so the first fetch of every list is already under
	// way while they come up. One refresher per kind of list, not per chain;
	// each returns as soon as its thread exists, and never waits on the network
	// here.
	blocklist::spawn_refresh(config.clone());
	cosmetic::spawn_refresh(config.clone());

	let ca = Arc::new(CertAuthority::from_config(&config)?);
	tcp::spawn(config.clone(), ca.clone())?;

	let mut quic_config = build_quic_config(ca.clone(), &config)?;
	let h3_config = quiche::h3::Config::new()?;

	let mut poll = mio::Poll::new()?;
	let mut events = mio::Events::with_capacity(1024);
	// Named, because `Os { code: 99, kind: AddrNotAvailable }` on its own tells
	// nobody which address failed — and the answer is almost always that the
	// address is not on this machine, or not inside this container's network
	// namespace, which is a thing you can only check if you know what was tried.
	let mut socket = mio::net::UdpSocket::bind(listen).map_err(|e| {
		format!(
			"cannot bind {listen} for QUIC: {e}. Check that [listen] names an \
			 address this machine actually has — inside a container that means \
			 the container's own addresses, not the host's."
		)
	})?;
	poll.registry()
		.register(&mut socket, SOCKET, mio::Interest::READABLE)?;
	let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER)?);

	let (jobs, results) = spawn_workers(config.clone(), ca, waker);
	log::info!("listening on {listen} (UDP/QUIC)");

	let park_cap = config.stream_buffer_bytes();
	let mut buf = [0u8; 65535];
	let mut out = vec![0u8; config.quic.max_datagram_size];
	let mut clients: ClientMap = HashMap::new();

	loop {
		let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();
		poll.poll(&mut events, timeout)?;

		// Drain the socket.
		'read: loop {
			if events.is_empty() {
				break 'read;
			}

			let (len, from) = match socket.recv_from(&mut buf) {
				Ok(v) => v,
				Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break 'read,
				Err(e) => return Err(e.into()),
			};

			if let Err(e) = recv_packet(
				&mut buf[..len],
				from,
				listen,
				&socket,
				&mut out,
				&mut quic_config,
				&mut clients,
			) {
				log::debug!("recv error from {from}: {e}");
			}
		}

		// Attach any fetched responses to their connections.
		drain_results(&results, &mut clients);

		for client in clients.values_mut() {
			client.conn.on_timeout();
		}

		drive_http3(&h3_config, &mut clients, &jobs, park_cap);
		flush(&socket, &mut out, &mut clients);

		clients.retain(|_, c| {
			if c.conn.is_closed() {
				log::info!("connection closed: {:?}", c.conn.stats());

				return false;
			}

			true
		});
	}
}

fn spawn_workers(
	config: Arc<Config>,
	ca: Arc<CertAuthority>,
	waker: Arc<mio::Waker>,
) -> (Sender<FetchJob>, Receiver<FetchResult>) {
	let (job_tx, job_rx) = std::sync::mpsc::channel::<FetchJob>();
	let (res_tx, res_rx) = std::sync::mpsc::channel::<FetchResult>();
	let job_rx = Arc::new(Mutex::new(job_rx));

	let agents = std::sync::Arc::new(upstream::agents(&config));

	for _ in 0..config.worker_threads() {
		let job_rx = job_rx.clone();
		let res_tx = res_tx.clone();
		let waker = waker.clone();
		let agents = agents.clone();
		let config = config.clone();
		let ca = ca.clone();

		std::thread::spawn(move || {
			// Each worker owns its own interceptor chain, so an external plugin
			// process is never a lock shared across workers.
			let interceptor = Chain::from_config(&config, ca);

			loop {
				let job = {
					let rx = job_rx.lock().unwrap();
					rx.recv()
				};
				let job = match job {
					Ok(j) => j,
					Err(_) => break, // senders dropped: shut down
				};

				// A stream that went away is this job's problem and nobody
				// else's; only the event loop disappearing ends the worker.
				if handle_job(&agents, &config, &interceptor, job, &res_tx, &waker)
					== Err(Gone::Pool)
				{
					break;
				}
			}
		});
	}

	(job_tx, res_rx)
}

/// Run the interceptors, fetch upstream and send the response back, either
/// whole or as a stream.
///
/// Whether the body is buffered is the interceptors' call: if nothing wants it,
/// it is relayed in chunks and never fully held in memory, which is what large
/// media needs. Errors are returned to the client as a 502 rather than dropped.
fn handle_job(
	agents: &upstream::Agents,
	config: &Config,
	interceptor: &Chain,
	mut job: FetchJob,
	results: &Sender<FetchResult>,
	waker: &mio::Waker,
) -> Result<(), Gone> {
	let metrics = metrics::shared();
	metrics.requests.increment();

	// All of this is ahead of `send`, which borrows the job for the rest of the
	// function. Anything that can answer without the body answers first, so a
	// blocked upload is refused rather than read.
	let early = interceptor.before_body(&mut job.request);
	let resume = match early {
		interceptor::BeforeBody::Answered(mut response) => {
			log::info!(
				"short-circuited {} {}",
				job.request.method,
				redact::url(&job.request.url)
			);
			compress_own(config, &job.request, &mut response);
			metrics.bytes_to_client.add(response.body.len() as u64);

			return send_full(results, waker, &job, response);
		}
		interceptor::BeforeBody::Resume { from } => from,
	};

	let upload = body::take(
		config,
		resume < interceptor.len(),
		&mut job.request,
		job.upload.take(),
	);
	let answer = match &upload {
		Ok(_) => interceptor.on_request_from(&mut job.request, resume),
		// A body we could not accept is answered instead of forwarded.
		Err(_) => None,
	};

	// RFC 9110 §9.3.2: a HEAD is answered with the headers a GET would carry
	// and none of the body. Enforced here, at the one place every response
	// leaves the worker, rather than at each of the half-dozen that produce
	// one — including the streamer, which would otherwise inject its tags into
	// a response that is not allowed to have a body at all.
	let head_only = job.request.method.eq_ignore_ascii_case("HEAD");

	let send = |payload| {
		let payload = if head_only { bodyless(payload) } else { payload };

		// The one place a worker can be made to wait for the client. Claiming
		// before the hand-off is what stops a stalled client turning into an
		// unbounded queue on the event loop's side; `false` means the stream
		// is gone, which reads to the caller exactly like a closed channel.
		//
		// A whole buffered body counts too. It is bounded per response by
		// `max_response_body_mb`, but nothing bounded how many of them could be
		// queued at once: a client opening its hundred streams for large images
		// and then not reading left every one of those bodies sitting in the
		// event loop's memory until the connection idled out.
		let claiming = match &payload {
			Payload::Chunk(chunk) => chunk.len(),
			Payload::Full(response) => response.body.len(),
			_ => 0,
		};
		if claiming > 0 && !job.budget.claim(claiming) {
			return Err(Gone::Stream);
		}

		results
			.send(FetchResult {
				conn: job.conn.clone(),
				stream_id: job.stream_id,
				payload,
				budget: job.budget.clone(),
			})
			.map_err(|_| Gone::Pool)?;
		let _ = waker.wake();

		Ok(())
	};

	let upload = match upload {
		Ok(upload) => upload,
		Err(rejected) => {
			let page = error_response_body(rejected.status, rejected.message);

			return send(Payload::Full(page));
		}
	};

	if let Some(mut response) = answer {
		log::info!(
			"short-circuited {} {}",
			job.request.method,
			redact::url(&job.request.url)
		);
		compress_own(config, &job.request, &mut response);
		metrics.bytes_to_client.add(response.body.len() as u64);

		return send(Payload::Full(response));
	}

	let resp = match upstream::call(agents, &job.request, upload) {
		Ok(resp) => resp,
		Err(failure) => {
			let host = host_of(&job.request.url);
			let page = match &failure {
				upstream::FetchError::Tls(detail) => {
					let logged = redact::detail(detail, &job.request.url);
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
			};
			metrics.bytes_to_client.add(page.body.len() as u64);

			return send(Payload::Full(page));
		}
	};

	// One that came off the disk is already whole, so it takes the buffered
	// path unconditionally and the interceptors run on it exactly as they would
	// on a fetched one.
	let resp = match resp {
		upstream::Fetched::Stored(stored) => {
			let mut headers = stored.headers;
			let (body, coding) = encoding::decode(&mut headers, stored.body, config.max_response_body());
			let mut response = ProxyResponse {
				status: stored.status,
				headers,
				body,
			};
			interceptor.on_response(&job.request, &mut response);
			response.body = encoding::encode(&mut response.headers, response.body, coding);
			compress_own(config, &job.request, &mut response);
			metrics.bytes_to_client.add(response.body.len() as u64);

			return send(Payload::Full(response));
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
		upstream::should_store(agents, config, &job.request, head.status, &head.headers, declared);

	let limit = config.max_response_body();
	let mut reader = resp.into_reader();

	if interceptor.wants_body(&job.request, &head) || worth_keeping {
		// One byte past the limit is enough to know it was passed, and is all
		// that is ever held beyond it. Nothing here trusts content-length: an
		// origin is free to send more than it declared.
		let mut body = Vec::new();
		if let Err(e) = reader.by_ref().take((limit as u64).saturating_add(1)).read_to_end(&mut body) {
			log::warn!(
				"failed reading upstream body for {}: {e}",
				redact::url(&job.request.url)
			);
		}

		if body.len() > limit {
			// Whatever wanted to look at this does not get to; the client
			// still gets the response. Refusing it outright would turn a large
			// download into a broken one over a plugin's filter being wide.
			log::warn!(
				"body for {} is over the {limit} byte buffer limit; relaying it uninspected",
				redact::url(&job.request.url)
			);
			reader = Box::new(std::io::Cursor::new(body).chain(reader));
		} else {
			metrics.bytes_from_origin.add(body.len() as u64);
			// The origin's own bytes, before anything rewrites them.
			upstream::store(agents, &job.request, head.status, &head.headers, &body);

			// Interceptors rewrite plain bytes; the coding goes back on afterwards.
			let (body, coding) = encoding::decode(&mut head.headers, body, limit);
			let mut response = ProxyResponse {
				status: head.status,
				headers: head.headers,
				body,
			};
			interceptor.on_response(&job.request, &mut response);
			response.body = encoding::encode(&mut response.headers, response.body, coding);
			if config.http.compress {
				let plain = response.body.len();
				response.body = encoding::ensure_compressed(
					&job.request.headers,
					response.status,
					&mut response.headers,
					response.body,
					coding,
				);
				metrics
					.bytes_saved_by_compression
					.add(plain.saturating_sub(response.body.len()) as u64);
			}
			metrics.bytes_to_client.add(response.body.len() as u64);

			return send(Payload::Full(response));
		}
	}

	// Nothing wants the body: relay it as it arrives. Deliberately not a place
	// to compress — the coding here is whatever the origin chose, and we never
	// hold enough of the body to know what a different one would cost.
	interceptor.on_response_head(&job.request, &mut head);

	if head_only {
		// The origin's own length, which is the answer a HEAD was asking for.
		// Nothing further reads the body, so nothing further can measure it.
		if let Some(length) = declared {
			declare_length(&mut head.headers, length);
		}
		send(Payload::Head(head))?;

		return send(Payload::End);
	}

	// Asked once, before the head is handed off: the answer holds for the whole
	// stream, and re-asking per chunk would cost a plugin round trip each time.
	let wants_chunks = interceptor.wants_chunks(&job.request, &head);
	// Rewritten on the way past rather than held whole, so the client starts
	// receiving a page while the origin is still writing it.
	let mut rewriting = inject::streamer_for(config, &job.request, &mut head);
	send(Payload::Head(head))?;

	let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
	loop {
		match reader.read(&mut buf) {
			Ok(0) => break,
			Ok(n) => {
				metrics.bytes_from_origin.add(n as u64);

				let mut chunk = buf[..n].to_vec();
				if wants_chunks {
					interceptor.on_response_chunk(&job.request, &mut chunk);
					// Emptied on purpose: an interceptor accumulating across
					// chunks flushes what it kept at the end instead.
					if chunk.is_empty() {
						continue;
					}
				}

				// Injection happens here, on the way past. A parser mid-document
				// may have nothing to emit yet, which is not the same as having
				// nothing to send later.
				if let Some(streamer) = rewriting.as_mut() {
					chunk = streamer.push(&chunk);
					if chunk.is_empty() {
						continue;
					}
				}

				metrics.bytes_to_client.add(chunk.len() as u64);

				send(Payload::Chunk(chunk))?;
			}
			Err(e) => {
				log::warn!(
					"upstream read failed for {}: {e}",
					redact::url(&job.request.url)
				);

				break;
			}
		}
	}

	// The plugin flushes first, and through the streamer, because its tail is
	// more body: bytes in the origin's coding, exactly like the chunks it was
	// given. Sending it after `finish()` put it outside the coding the head
	// declared and after the encoder had already been closed.
	let mut tail = if wants_chunks {
		interceptor
			.on_response_end(&job.request)
			.unwrap_or_default()
	} else {
		Vec::new()
	};

	if let Some(mut streamer) = rewriting.take() {
		let mut through = if tail.is_empty() {
			Vec::new()
		} else {
			streamer.push(&tail)
		};
		through.extend(streamer.finish());
		tail = through;
	}

	if !tail.is_empty() {
		metrics.bytes_to_client.add(tail.len() as u64);

		send(Payload::Chunk(tail))?;
	}

	send(Payload::End)
}


fn drain_results(results: &Receiver<FetchResult>, clients: &mut ClientMap) {
	while let Ok(result) = results.try_recv() {
		let Some(client) = clients.get_mut(&result.conn) else {
			// Client vanished while its fetch was in flight; drop the response.
			// Closing here and not only in `Pending::drop` because a connection
			// can go before the head arrives, leaving no `Pending` to drop and
			// a worker parked on room that will never be given back.
			log::debug!("dropping response for closed connection");
			result.budget.close();

			continue;
		};

		// One stream, one response. A second request on a stream that already
		// has one — see `poll_requests` — would otherwise queue a second
		// `Pending` beside the first, and `find_pending` answers with the
		// first: every chunk of one response is appended to the body of the
		// other, past a `content-length` already sent.
		if matches!(result.payload, Payload::Full(_) | Payload::Head(_))
			&& find_pending(client, result.stream_id).is_some()
		{
			log::warn!(
				"refusing a second response on stream {}; one is already in flight",
				result.stream_id
			);
			result.budget.close();

			continue;
		}

		match result.payload {
			Payload::Full(response) => client.pending.push(Pending {
				stream_id: result.stream_id,
				status: response.status,
				headers: response.headers,
				headers_sent: false,
				chunks: VecDeque::from([response.body]),
				offset: 0,
				complete: true,
				fin_sent: false,
				budget: result.budget,
			}),
			Payload::Head(head) => client.pending.push(Pending {
				stream_id: result.stream_id,
				status: head.status,
				headers: head.headers,
				headers_sent: false,
				chunks: VecDeque::new(),
				offset: 0,
				complete: false,
				fin_sent: false,
				budget: result.budget,
			}),
			Payload::Chunk(data) => {
				match find_pending(client, result.stream_id) {
					Some(pending) => pending.chunks.push_back(data),
					// Its stream already failed and was dropped.
					None => {
						log::debug!("chunk for unknown stream {}", result.stream_id);
						result.budget.close();
					}
				}
			}
			Payload::End => {
				if let Some(pending) = find_pending(client, result.stream_id) {
					pending.complete = true;
				}
			}
		}
	}
}

fn find_pending(client: &mut Client, stream_id: u64) -> Option<&mut Pending> {
	client
		.pending
		.iter_mut()
		.find(|p| p.stream_id == stream_id)
}

fn build_quic_config(
	ca: Arc<CertAuthority>,
	config: &Config,
) -> Result<quiche::Config, Box<dyn Error>> {
	let mut builder = SslContextBuilder::new(SslMethod::tls())?;
	builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;

	// Dynamic per-SNI certificate: mint a leaf for the requested host and install
	// it before the handshake picks a certificate.
	let passthrough = passthrough::shared(config);
	builder.set_servername_callback(move |ssl, alert| {
		if let Some(sni) = ssl.servername(boring::ssl::NameType::HOST_NAME) {
			let sni = sni.to_string();

			// A host mach5 must not decrypt cannot be served here at all. There
			// is no splicing a QUIC connection without reading its encrypted
			// Initial, so the handshake is refused instead and the client falls
			// back to TCP, where passthrough works. It will not have been told
			// about h3 for this host by us in the first place — we never see its
			// responses — so this only catches a client that learned about h3
			// somewhere else.
			if passthrough.covers(&sni) {
				log::info!("refusing h3 for {sni} so it can be passed through over tcp");
				*alert = boring::ssl::SslAlert::HANDSHAKE_FAILURE;

				return Err(boring::ssl::SniError::ALERT_FATAL);
			}

			if !ca.install(ssl, &sni) {
				log::warn!("serving default certificate for {sni}");
			}
		}

		Ok(())
	});

	// Advertise HTTP/3 via ALPN.
	builder.set_alpn_select_callback(|_ssl, client_protos| {
		// Wire format: 1-byte length prefix + "h3".
		select_next_proto(b"\x02h3", client_protos).ok_or(AlpnError::ALERT_FATAL)
	});

	let mut quic =
		quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)?;

	let q = &config.quic;
	quic.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
	quic.set_max_idle_timeout(q.max_idle_timeout_ms);
	quic.set_max_recv_udp_payload_size(q.max_datagram_size);
	quic.set_max_send_udp_payload_size(q.max_datagram_size);
	quic.set_initial_max_data(q.initial_max_data);
	quic.set_initial_max_stream_data_bidi_local(q.initial_max_stream_data);
	quic.set_initial_max_stream_data_bidi_remote(q.initial_max_stream_data);
	quic.set_initial_max_stream_data_uni(q.initial_max_stream_data);
	quic.set_initial_max_streams_bidi(q.initial_max_streams);
	quic.set_initial_max_streams_uni(q.initial_max_streams);

	Ok(quic)
}

fn recv_packet(
	pkt: &mut [u8],
	from: SocketAddr,
	local: SocketAddr,
	socket: &mio::net::UdpSocket,
	out: &mut [u8],
	config: &mut quiche::Config,
	clients: &mut ClientMap,
) -> Result<(), Box<dyn Error>> {
	let hdr = quiche::Header::from_slice(pkt, quiche::MAX_CONN_ID_LEN)?;

	// The client addresses its first Initials to a DCID it chose at random, and
	// keeps reusing it until it learns our chosen SCID. Deriving our SCID
	// deterministically from that DCID means repeated Initials map to one
	// connection instead of spawning a fresh one each time.
	let derived = derive_scid(&hdr.dcid);

	let key = find_key(clients, &hdr.dcid).or_else(|| find_key(clients, &derived));

	let key = match key {
		Some(k) => k,
		None => {
			if hdr.ty != quiche::Type::Initial {
				// Not a handshake and no known connection: drop.
				return Ok(());
			}

			if !quiche::version_is_supported(hdr.version) {
				let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, out)?;
				socket.send_to(&out[..len], from)?;

				return Ok(());
			}

			// Address validation. An Initial with no token gets a Retry
			// carrying one; only a client that actually received it can
			// answer, which stops an off-path attacker from pointing our
			// handshake bytes at a spoofed victim.
			let token = hdr.token.as_deref().unwrap_or_default();
			if token.is_empty() {
				let new_token = mint_token(&hdr.dcid, &from);
				let len = quiche::retry(
					&hdr.scid,
					&hdr.dcid,
					&derived,
					&new_token,
					hdr.version,
					out,
				)?;
				socket.send_to(&out[..len], from)?;
				log::debug!("sent retry to {from}");

				return Ok(());
			}

			let Some(odcid) = validate_token(&from, token) else {
				log::debug!("invalid address-validation token from {from}");

				return Ok(());
			};

			// Post-retry the client addresses us by the connection id we handed
			// it, so adopt that as our own rather than deriving a fresh one.
			let scid = hdr.dcid.clone().into_owned();
			let conn = quiche::accept(&scid, Some(&odcid), local, from, config)?;
			log::info!("new connection {scid:?} from {from}");

			clients.insert(
				scid.clone(),
				Client {
					conn,
					http3: None,
					pending: Vec::new(),
					uploads: HashMap::new(),
				},
			);

			scid
		}
	};

	let info = quiche::RecvInfo {
		from,
		to: local,
	};
	clients.get_mut(&key).unwrap().conn.recv(pkt, info)?;

	Ok(())
}

fn drive_http3(
	h3_config: &quiche::h3::Config,
	clients: &mut ClientMap,
	jobs: &Sender<FetchJob>,
	park_cap: usize,
) {
	let keys: Vec<_> = clients.keys().cloned().collect();

	for key in keys {
		let client = clients.get_mut(&key).unwrap();

		if (client.conn.is_in_early_data() || client.conn.is_established())
			&& client.http3.is_none()
		{
			match quiche::h3::Connection::with_transport(&mut client.conn, h3_config) {
				Ok(h3) => client.http3 = Some(h3),
				Err(e) => {
					log::error!("failed to create h3 connection: {e}");

					continue;
				}
			}
		}

		let Some(http3) = client.http3.as_mut() else {
			continue;
		};

		poll_requests(
			&key,
			&mut client.conn,
			http3,
			&mut client.uploads,
			jobs,
			park_cap,
		);
		pump_responses(&mut client.conn, http3, &mut client.pending);
	}
}

fn poll_requests(
	key: &quiche::ConnectionId<'static>,
	conn: &mut quiche::Connection,
	http3: &mut quiche::h3::Connection,
	uploads: &mut HashMap<u64, Upload>,
	jobs: &Sender<FetchJob>,
	park_cap: usize,
) {
	loop {
		match http3.poll(conn) {
			Ok((stream_id, quiche::h3::Event::Headers { list, more_frames })) => {
				// quiche allows a client two HEADERS frames on a request stream
				// — the second is meant to be trailers — and validates no
				// pseudo-headers, so a crafted one produces a whole second
				// request on a stream that already has one. Refused here, where
				// the first request's upload would otherwise be dropped
				// mid-body by the insert below.
				if uploads.contains_key(&stream_id) {
					log::warn!("stream={stream_id} sent a second request; ignoring it");

					continue;
				}

				match build_request(conn.server_name(), &list) {
					Some((request, _)) if !more_frames => {
						// No body to wait for.
						dispatch(key, stream_id, request, None, jobs, park_cap);
					}
					Some((request, length)) => {
						// A body follows. The request goes to a worker now and
						// the body follows it down a channel, so a large upload
						// is never assembled anywhere.
						let (chunks, receiver) = body::channel();
						let ending = body::Ending::default();
						uploads.insert(
							stream_id,
							Upload {
								chunks,
								ending: ending.clone(),
								overflow: VecDeque::new(),
								parked: 0,
								finished: false,
							},
						);
						dispatch(
							key,
							stream_id,
							request,
							Some((receiver, ending, length)),
							jobs,
							park_cap,
						);
					}
					None => log::warn!("stream={stream_id} missing pseudo-headers; ignoring"),
				}
			}
			// Data is drained below rather than here: the same work has to
			// happen on passes where no event fires, because a full channel
			// leaves bytes on the stream that nothing else would come back for.
			Ok((_, quiche::h3::Event::Data)) => {}
			Ok((stream_id, quiche::h3::Event::Finished)) => {
				if let Some(upload) = uploads.get_mut(&stream_id) {
					upload.finished = true;
				}
			}
			Ok((stream_id, quiche::h3::Event::Reset(code))) => {
				log::debug!("stream={stream_id} reset by peer (code {code})");
				// A reset is the client stopping, not finishing. Saying so
				// before the sender goes is what stops the worker forwarding a
				// truncated upload as a complete request.
				if let Some(upload) = uploads.remove(&stream_id) {
					upload.ending.abort();
				}
			}
			Ok((_, quiche::h3::Event::PriorityUpdate)) => {}
			Ok((_, quiche::h3::Event::GoAway)) => {}
			Err(quiche::h3::Error::Done) => break,
			Err(e) => {
				log::error!("h3 poll error: {e}");

				break;
			}
		}
	}

	pump_uploads(conn, http3, uploads, park_cap);
}

/// Move body bytes from the QUIC streams towards the workers.
///
/// Runs every pass rather than only on a `Data` event. Reading stops as soon as
/// the channel and its overflow are full, and quiche does not promise to raise
/// another event for bytes that were already readable — so waiting for one
/// would strand an upload half-sent.
fn pump_uploads(
	conn: &mut quiche::Connection,
	http3: &mut quiche::h3::Connection,
	uploads: &mut HashMap<u64, Upload>,
	park_cap: usize,
) {
	let mut buf = [0u8; 16_384];
	let mut done = Vec::new();

	for (&stream_id, upload) in uploads.iter_mut() {
		// Whatever was parked goes first, or the body would arrive reordered.
		let mut closed = false;
		while let Some(chunk) = upload.overflow.pop_front() {
			let size = chunk.len();
			match upload.chunks.try_send(chunk) {
				Ok(()) => upload.parked -= size,
				Err(tokio::sync::mpsc::error::TrySendError::Full(chunk)) => {
					upload.overflow.push_front(chunk);

					break;
				}
				Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
					closed = true;

					break;
				}
			}
		}

		if closed {
			done.push(stream_id);

			continue;
		}

		let mut drained = false;
		while upload.has_room(park_cap) {
			let read = match http3.recv_body(conn, stream_id, &mut buf) {
				Ok(0) => {
					drained = true;

					break;
				}
				Ok(n) => n,
				Err(quiche::h3::Error::Done) => {
					drained = true;

					break;
				}
				Err(e) => {
					log::debug!("recv_body on stream={stream_id} failed: {e}");
					done.push(stream_id);

					break;
				}
			};

			match upload.chunks.try_send(buf[..read].to_vec()) {
				Ok(()) => {}
				Err(tokio::sync::mpsc::error::TrySendError::Full(chunk)) => upload.park(chunk),
				Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
					// The worker is finished with this body — it short-circuited,
					// or the fetch failed. Stop carrying bytes nobody wants.
					done.push(stream_id);

					break;
				}
			}
		}

		// Only once the client has finished *and* everything it sent has been
		// handed on: dropping the sender is what ends the body.
		if upload.finished && drained && upload.overflow.is_empty() {
			done.push(stream_id);
		}
	}

	for stream_id in done {
		uploads.remove(&stream_id);
	}
}

fn dispatch(
	key: &quiche::ConnectionId<'static>,
	stream_id: u64,
	request: ProxyRequest,
	upload: Option<(
		tokio::sync::mpsc::Receiver<body::Chunk>,
		body::Ending,
		Option<u64>,
	)>,
	jobs: &Sender<FetchJob>,
	stream_cap: usize,
) {
	log::info!(
		"proxying stream={stream_id} {} {}{}",
		request.method,
		redact::url(&request.url),
		if upload.is_some() {
			" (body streaming)"
		} else {
			""
		}
	);

	let job = FetchJob {
		conn: key.clone(),
		stream_id,
		request,
		upload,
		budget: Arc::new(budget::Budget::new(stream_cap)),
	};
	if jobs.send(job).is_err() {
		log::error!("worker pool is gone; cannot dispatch request");
	}
}

/// Compress a response mach5 wrote itself.
///
/// One never went near the upstream path, which is where everything else is
/// compressed — and the picker mach5 injects into every page is the largest
/// thing it serves, so leaving these uncompressed is the one that shows up.
fn compress_own(config: &Config, request: &ProxyRequest, response: &mut ProxyResponse) {
	if !config.http.compress {
		return;
	}

	let plain = response.body.len();
	response.body = encoding::ensure_compressed(
		&request.headers,
		response.status,
		&mut response.headers,
		std::mem::take(&mut response.body),
		None,
	);
	metrics::shared()
		.bytes_saved_by_compression
		.add(plain.saturating_sub(response.body.len()) as u64);
}

/// A plain refusal, for a request that never reaches an origin.
/// Send one complete response back to the event loop. Used where the borrow of
/// the job has not yet been handed to the closure that usually does this.
fn send_full(
	results: &Sender<FetchResult>,
	waker: &mio::Waker,
	job: &FetchJob,
	response: ProxyResponse,
) -> Result<(), Gone> {
	// Through `bodyless` like everything else. This is the *other* place a
	// response leaves the worker — it exists because the borrow of the job has
	// not yet been handed to the closure that usually does this — and missing
	// it meant an h3 HEAD to a blocked host, or to any `/.mach5/` endpoint, was
	// answered with the whole body while TCP stripped it.
	let payload = Payload::Full(response);
	let payload = if job.request.method.eq_ignore_ascii_case("HEAD") {
		bodyless(payload)
	} else {
		payload
	};

	// Claimed like any other body, so the event loop's books balance: it
	// releases whatever it pops, and a release with no matching claim would
	// quietly under-count every later response on the stream.
	if let Payload::Full(response) = &payload {
		if !response.body.is_empty() && !job.budget.claim(response.body.len()) {
			return Err(Gone::Stream);
		}
	}

	results
		.send(FetchResult {
			conn: job.conn.clone(),
			stream_id: job.stream_id,
			payload,
			budget: job.budget.clone(),
		})
		.map_err(|_| Gone::Pool)?;
	let _ = waker.wake();

	Ok(())
}

fn error_response_body(status: u16, message: &str) -> ProxyResponse {
	ProxyResponse {
		status,
		headers: vec![("content-type".to_string(), "text/plain".to_string())],
		body: format!("mach5: {message}\n").into_bytes(),
	}
}


/// Send as much of each pending response as the streams will currently accept,
/// keeping whatever is left for the next pass.
fn pump_responses(
	conn: &mut quiche::Connection,
	http3: &mut quiche::h3::Connection,
	pending: &mut Vec<Pending>,
) {
	pending.retain_mut(|p| match send_pending(conn, http3, p) {
		Ok(done) => !done,
		Err(e) => {
			log::error!("failed sending response on stream={}: {e}", p.stream_id);

			false
		}
	});
}

/// Returns Ok(true) once the whole response has been handed to quiche.
fn send_pending(
	conn: &mut quiche::Connection,
	http3: &mut quiche::h3::Connection,
	p: &mut Pending,
) -> Result<bool, quiche::h3::Error> {
	if !p.headers_sent {
		let status = p.status.to_string();

		let mut headers = vec![quiche::h3::Header::new(b":status", status.as_bytes())];
		// A buffered response has a known length; a streaming one is delimited
		// by the stream ending, so it carries no content-length.
		//
		// Two responses must not be measured by what is being sent: one that
		// already declares its own length — a HEAD, whose body was stripped
		// after being measured — and a 204 or 304, which RFC 9110 §8.6 says
		// carries no content-length at all. Both would otherwise be told they
		// are zero bytes long.
		let framed = p.complete
			&& !matches!(p.status, 204 | 304)
			&& p.status >= 200
			&& !declares_length(&p.headers);
		let content_length = framed.then(|| body_len(p).to_string());
		if let Some(length) = &content_length {
			headers.push(quiche::h3::Header::new(b"content-length", length.as_bytes()));
		}
		for (name, value) in &p.headers {
			headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
		}

		// Only finish here if the body is known to be empty and complete.
		let fin = p.complete && body_len(p) == 0;
		match http3.send_response(conn, p.stream_id, &headers, fin) {
			Ok(()) => {
				p.headers_sent = true;
				p.fin_sent = fin;
			}
			Err(quiche::h3::Error::StreamBlocked) | Err(quiche::h3::Error::Done) => {
				return Ok(false)
			}
			Err(e) => return Err(e),
		}

		if fin {
			return Ok(true);
		}
	}

	while let Some(chunk) = p.chunks.front() {
		// The stream ends with the last byte of the last chunk, and only once
		// upstream has signalled it is done.
		let last = p.complete && p.chunks.len() == 1;

		match http3.send_body(conn, p.stream_id, &chunk[p.offset..], last) {
			Ok(0) => break,
			Ok(n) => {
				p.offset += n;
				if p.offset >= chunk.len() {
					// Room given back only once the bytes are quiche's problem,
					// which is what makes the bound mean anything.
					let sent = p.chunks.pop_front().map_or(0, |chunk| chunk.len());
					p.budget.release(sent);
					p.offset = 0;
					// The fin rode along only if this really was the last byte.
					p.fin_sent = last;
				}
			}
			Err(quiche::h3::Error::Done) => break,
			Err(e) => return Err(e),
		}
	}

	// Upstream finished after we had already drained every chunk, so close the
	// stream explicitly. Without this the client waits forever for a fin.
	if p.complete && p.chunks.is_empty() && !p.fin_sent {
		match http3.send_body(conn, p.stream_id, &[], true) {
			Ok(_) => p.fin_sent = true,
			Err(quiche::h3::Error::Done) => {}
			Err(e) => return Err(e),
		}
	}

	Ok(p.is_finished())
}

fn body_len(p: &Pending) -> usize {
	p.chunks.iter().map(Vec::len).sum()
}

/// Strip the body a HEAD must not carry, stating its length on the way past.
///
/// The length is worth keeping precisely because this is a HEAD: measuring a
/// body without downloading it is the whole point of the method, and the front
/// end can only ever measure the zero bytes that are actually sent.
fn bodyless(payload: Payload) -> Payload {
	match payload {
		Payload::Full(mut response) => {
			declare_length(&mut response.headers, response.body.len() as u64);
			response.body.clear();

			Payload::Full(response)
		}
		// A HEAD never reaches the streaming loop, so a chunk on one is a bug
		// somewhere else; dropping it is still better than sending it.
		Payload::Chunk(_) => Payload::Chunk(Vec::new()),
		other => other,
	}
}

fn declare_length(headers: &mut Vec<(String, String)>, length: u64) {
	headers.retain(|(name, _)| !name.eq_ignore_ascii_case("content-length"));
	headers.push(("content-length".to_string(), length.to_string()));
}

fn declares_length(headers: &[(String, String)]) -> bool {
	headers
		.iter()
		.any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
}

fn flush(socket: &mio::net::UdpSocket, out: &mut [u8], clients: &mut ClientMap) {
	for client in clients.values_mut() {
		loop {
			let (write, send_info) = match client.conn.send(out) {
				Ok(v) => v,
				Err(quiche::Error::Done) => break,
				Err(e) => {
					log::error!("send failed: {e}; closing");
					client.conn.close(false, 0x1, b"internal error").ok();

					break;
				}
			};

			if let Err(e) = socket.send_to(&out[..write], send_info.to) {
				if e.kind() == std::io::ErrorKind::WouldBlock {
					break;
				}

				log::error!("socket send failed: {e}");

				break;
			}
		}
	}
}

/// Build the upstream request from a request's pseudo-headers. Returns None if
/// the mandatory pseudo-headers are absent.
/// The request, and the body length the client declared for it — kept because
/// the hop-by-hop filter drops `content-length`, and passing it upstream is
/// what keeps an upload out of chunked encoding.
fn build_request(
	sni: Option<&str>,
	list: &[quiche::h3::Header],
) -> Option<(ProxyRequest, Option<u64>)> {
	let mut method = None;
	let mut authority = None;
	let mut path = None;
	let mut scheme = None;
	let mut length = None;
	let mut headers = Vec::new();

	for h in list {
		let value = String::from_utf8_lossy(h.value()).into_owned();
		if h.name().eq_ignore_ascii_case(b"content-length") {
			length = value.parse::<u64>().ok();
		}
		match h.name() {
			b":method" => method = Some(value),
			b":authority" => authority = Some(value),
			b":path" => path = Some(value),
			b":scheme" => scheme = Some(value),
			name if name.starts_with(b":") => {}
			name if upstream::is_hop_by_hop(&String::from_utf8_lossy(name)) => {}
			// ureq derives Host from the URL; a second one would conflict.
			b"host" => {}
			name => headers.push((String::from_utf8_lossy(name).into_owned(), value)),
		}
	}

	let scheme = scheme.unwrap_or_else(|| "https".to_string());
	// The SNI wins, exactly as it does on the TCP side: it is the name the
	// client asked TLS for, the only name this connection's certificate covers,
	// and the only one a passthrough decision was ever made against. Trusting
	// `:authority` instead meant a client could hand over any name it liked
	// after the handshake — including one on the passthrough list, whose whole
	// promise is that mach5 never holds its plaintext.
	let authority = sni.map(str::to_string).or(authority)?;
	// TODO: this drops any port in the authority and lets the scheme's default
	// apply (443 for https). Correct for the common case; a transparent
	// deployment should instead recover the real origin address via
	// SO_ORIGINAL_DST to preserve nonstandard ports.
	let url = format!("{scheme}://{}{}", authority_host(&authority), path?);

	Some((
		ProxyRequest {
			method: method?,
			url,
			headers,
			body: Vec::new(),
		},
		length,
	))
}

/// Host portion of an `:authority`, dropping any `:port` and keeping an IPv6
/// literal's brackets.
/// Host portion of an absolute URL, for reporting which origin failed.
pub(crate) fn host_of(url: &str) -> &str {
	let rest = url.split_once("://").map_or(url, |(_scheme, rest)| rest);
	let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);

	authority_host(host)
}

pub(crate) fn authority_host(authority: &str) -> &str {
	if authority.starts_with('[') {
		return authority.find(']').map_or(authority, |i| &authority[..=i]);
	}

	authority
		.split_once(':')
		.map_or(authority, |(host, _port)| host)
}

/// The secret this process signs address-validation tokens with.
///
/// Per process and never written down. A token is handed back within a round
/// trip or two, so a restart invalidating every outstanding one costs a client
/// one extra exchange and nothing else.
fn token_key() -> &'static ring::hmac::Key {
	static KEY: std::sync::OnceLock<ring::hmac::Key> = std::sync::OnceLock::new();

	KEY.get_or_init(|| {
		let mut secret = [0u8; 32];
		// Taken at startup by `main`, so this is a refusal to start rather than
		// a panic in the event loop. There is nothing to fall back to: an
		// unsigned token is the reflection attack described below.
		boring::rand::rand_bytes(&mut secret)
			.expect("no random bytes for the address-validation key");

		ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &secret)
	})
}

/// What the tag covers: who asked, until when, and which connection id.
///
/// The address is signed rather than carried. Nothing needs to read it back —
/// the check is only ever "does this token belong to the address it arrived
/// from" — and a field nobody parses is a field nobody can get wrong.
fn token_body(from: &SocketAddr, expiry: &[u8], dcid: &[u8]) -> Vec<u8> {
	let mut body = address_bytes(from);
	body.extend_from_slice(expiry);
	body.extend_from_slice(dcid);

	body
}

/// Build an address-validation token: a marker, when it stops being good for
/// anything, the connection id the client originally chose (which we must echo
/// back at handshake), and a tag over all of it.
///
/// The tag is the point. Without one every byte was derivable by whoever sent
/// the packet, so a forged token validated and `quiche::accept` was told the
/// address was verified — which lifts the 3× amplification cap. One spoofed
/// 1200-byte Initial then bought several kilobytes of server flight, leaf
/// certificate included, aimed at whatever address the attacker claimed to be.
/// Retry exists to prevent exactly that, and an unauthenticated token does not
/// prevent it at all.
fn mint_token(dcid: &quiche::ConnectionId, from: &SocketAddr) -> Vec<u8> {
	let expiry = (unix_now() + TOKEN_TTL_SECONDS).to_be_bytes();
	let tag = ring::hmac::sign(token_key(), &token_body(from, &expiry, dcid));

	let mut token = Vec::from(TOKEN_MARKER);
	token.extend_from_slice(&expiry);
	token.extend_from_slice(dcid);
	token.extend_from_slice(tag.as_ref());

	token
}

/// Recover the original connection id from a token, rejecting anything we did
/// not sign, that arrived from another address, or that has expired.
fn validate_token(from: &SocketAddr, token: &[u8]) -> Option<quiche::ConnectionId<'static>> {
	let rest = token.strip_prefix(TOKEN_MARKER)?;
	// An expiry, at least one byte of connection id, and a tag.
	if rest.len() <= EXPIRY_BYTES + TAG_BYTES {
		return None;
	}

	let (body, tag) = rest.split_at(rest.len() - TAG_BYTES);
	let (expiry, dcid) = body.split_at(EXPIRY_BYTES);

	// Constant time, and it is what binds the token to `from`: the address is
	// signed rather than carried, so a token minted for anyone else fails here.
	ring::hmac::verify(token_key(), &token_body(from, expiry, dcid), tag).ok()?;

	let until = u64::from_be_bytes(expiry.try_into().ok()?);
	if unix_now() > until {
		return None;
	}

	Some(quiche::ConnectionId::from_ref(dcid).into_owned())
}

fn unix_now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|since| since.as_secs())
		.unwrap_or(0)
}

fn address_bytes(addr: &SocketAddr) -> Vec<u8> {
	let mut bytes = match addr.ip() {
		std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
		std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
	};
	bytes.extend_from_slice(&addr.port().to_be_bytes());

	bytes
}

/// Find the map key whose bytes equal `cid`, working across the borrowed and
/// 'static connection-id lifetimes.
fn find_key(
	clients: &ClientMap,
	cid: &quiche::ConnectionId,
) -> Option<quiche::ConnectionId<'static>> {
	clients
		.keys()
		.find(|k| k.as_ref() == cid.as_ref())
		.cloned()
}

/// Deterministically derive a server-chosen connection ID from the client's.
/// Not a security boundary — it only needs to be stable per client DCID.
fn derive_scid(dcid: &quiche::ConnectionId) -> quiche::ConnectionId<'static> {
	use std::hash::{Hash, Hasher};

	let mut id = [0u8; quiche::MAX_CONN_ID_LEN];
	let mut written = 0;
	let mut round = 0u64;
	while written < id.len() {
		let mut hasher = std::collections::hash_map::DefaultHasher::new();
		round.hash(&mut hasher);
		dcid.as_ref().hash(&mut hasher);

		let bytes = hasher.finish().to_le_bytes();
		let take = (id.len() - written).min(bytes.len());
		id[written..written + take].copy_from_slice(&bytes[..take]);
		written += take;
		round += 1;
	}

	quiche::ConnectionId::from_ref(&id).into_owned()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn authority_host_strips_port() {
		assert_eq!(authority_host("example.com:4435"), "example.com");
		assert_eq!(authority_host("example.com"), "example.com");
		assert_eq!(authority_host("[::1]:8443"), "[::1]");
		assert_eq!(authority_host("[2001:db8::1]"), "[2001:db8::1]");
	}

	/// The first question on any bug report is which build, so `--version` has
	/// to answer it and has to answer it with the version that was actually
	/// compiled in — not a string somebody updates by hand and forgets.
	#[test]
	fn the_version_reported_is_the_version_built() {
		let reported = env!("CARGO_PKG_VERSION");

		assert!(!reported.is_empty());
		assert_eq!(
			reported,
			std::env::var("CARGO_PKG_VERSION").as_deref().unwrap_or(reported),
			"the compiled-in version and cargo's agree"
		);
		// Help text is worth nothing if it does not say where configuration
		// comes from, which is the only thing a flagless binary needs to
		// explain.
		assert!(HELP.contains("MACH5_CONFIG"));
		assert!(HELP.contains("SECURITY.md"));
	}

	#[test]
	fn build_request_from_pseudo_headers() {
		let list = vec![
			quiche::h3::Header::new(b":method", b"GET"),
			quiche::h3::Header::new(b":scheme", b"https"),
			quiche::h3::Header::new(b":authority", b"example.com:4435"),
			quiche::h3::Header::new(b":path", b"/index.html"),
			quiche::h3::Header::new(b"user-agent", b"curl"),
			quiche::h3::Header::new(b"host", b"example.com:4435"),
			quiche::h3::Header::new(b"connection", b"keep-alive"),
		];

		let (req, length) = build_request(None, &list).expect("should parse");

		assert_eq!(length, None, "a GET declares no body length");
		assert_eq!(req.method, "GET");
		assert_eq!(req.url, "https://example.com/index.html");
		// host (ureq sets it) and hop-by-hop headers are dropped; user-agent kept.
		assert_eq!(req.headers, vec![("user-agent".to_string(), "curl".to_string())]);
	}

	/// Minted through the real function, because the tests it replaces
	/// assembled tokens by hand and so encoded the very assumption that made
	/// them forgeable.
	fn mint(dcid: &[u8], from: &SocketAddr) -> Vec<u8> {
		mint_token(&quiche::ConnectionId::from_ref(dcid), from)
	}

	#[test]
	fn token_round_trips_the_original_connection_id() {
		let from: SocketAddr = "192.0.2.10:5555".parse().unwrap();
		let token = mint(b"originalcid", &from);

		let recovered = validate_token(&from, &token).expect("our own token must validate");

		assert_eq!(recovered.as_ref(), b"originalcid");
	}

	#[test]
	fn token_is_rejected_from_another_address() {
		let minted_for: SocketAddr = "192.0.2.10:5555".parse().unwrap();
		let token = mint(b"originalcid", &minted_for);

		for other in ["198.51.100.7:5555", "192.0.2.10:5556", "[2001:db8::a]:5555"] {
			let attacker: SocketAddr = other.parse().unwrap();

			assert!(
				validate_token(&attacker, &token).is_none(),
				"a token replayed from {other} must not validate"
			);
		}
	}

	/// The whole point of the tag. Every field of the old token was derivable
	/// by whoever sent the packet, so a token could simply be written out for
	/// any address at all — and a validated token tells quiche the address is
	/// verified, which lifts the amplification cap and turns this into a
	/// reflector.
	#[test]
	fn a_token_nobody_signed_is_rejected() {
		let victim: SocketAddr = "192.0.2.10:5555".parse().unwrap();

		// Exactly what an attacker can build unaided: our marker, a plausible
		// expiry, a connection id of its choosing.
		let mut forged = Vec::from(TOKEN_MARKER);
		forged.extend_from_slice(&(unix_now() + 10).to_be_bytes());
		forged.extend_from_slice(b"originalcid");
		forged.extend_from_slice(&[0u8; TAG_BYTES]);

		assert!(validate_token(&victim, &forged).is_none());

		// And one of ours with a single bit turned over.
		let mut tampered = mint(b"originalcid", &victim);
		let last = tampered.len() - 1;
		tampered[last] ^= 1;

		assert!(validate_token(&victim, &tampered).is_none());
	}

	#[test]
	fn an_expired_token_is_rejected() {
		let from: SocketAddr = "192.0.2.10:5555".parse().unwrap();
		let expiry = (unix_now() - 1).to_be_bytes();
		let dcid = b"originalcid";

		// Signed properly, so only the clock refuses it.
		let tag = ring::hmac::sign(token_key(), &token_body(&from, &expiry, dcid));
		let mut token = Vec::from(TOKEN_MARKER);
		token.extend_from_slice(&expiry);
		token.extend_from_slice(dcid);
		token.extend_from_slice(tag.as_ref());

		assert!(
			validate_token(&from, &token).is_none(),
			"a token kept past its expiry mints connections for as long as it is held"
		);
	}

	#[test]
	fn token_without_our_marker_is_rejected() {
		let from: SocketAddr = "192.0.2.10:5555".parse().unwrap();
		let mut token = Vec::from(b"other".as_slice());
		token.extend_from_slice(&mint(b"originalcid", &from)[5..]);

		assert!(validate_token(&from, &token).is_none());
		assert!(validate_token(&from, b"").is_none(), "empty token is invalid");
	}

	#[test]
	fn token_with_no_connection_id_is_rejected() {
		let from: SocketAddr = "192.0.2.10:5555".parse().unwrap();
		let expiry = (unix_now() + 10).to_be_bytes();
		let tag = ring::hmac::sign(token_key(), &token_body(&from, &expiry, b""));

		let mut token = Vec::from(TOKEN_MARKER);
		token.extend_from_slice(&expiry);
		token.extend_from_slice(tag.as_ref());

		assert!(
			validate_token(&from, &token).is_none(),
			"a token carrying no original id is unusable"
		);
	}

	/// The handshake decided what this connection is, including whether the
	/// host was one never to decrypt. Letting `:authority` name a different
	/// one afterwards steps around that decision entirely — and the TCP side
	/// already prefers the SNI for exactly this reason.
	#[test]
	fn the_name_asked_of_tls_wins_over_the_one_in_the_request() {
		let list = vec![
			quiche::h3::Header::new(b":method", b"GET"),
			quiche::h3::Header::new(b":scheme", b"https"),
			quiche::h3::Header::new(b":authority", b"secure.bank.example"),
			quiche::h3::Header::new(b":path", b"/account"),
		];

		let (req, _) = build_request(Some("innocent.example"), &list).expect("should parse");
		assert_eq!(req.url, "https://innocent.example/account");

		// And with no SNI at all — which no browser does, but a hand-written
		// client can — the authority is all there is.
		let (req, _) = build_request(None, &list).expect("should parse");
		assert_eq!(req.url, "https://secure.bank.example/account");
	}

	#[test]
	fn build_request_needs_authority_and_path() {
		let list = vec![quiche::h3::Header::new(b":method", b"GET")];

		assert!(build_request(None, &list).is_none());
	}
}
