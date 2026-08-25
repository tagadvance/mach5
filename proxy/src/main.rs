//! mach5 — QUIC/HTTP-3 intercepting proxy (skeleton).
//!
//! Terminates an HTTP/3 connection from a client with a certificate minted on
//! the fly for the requested SNI host (signed by our root CA), forwards each
//! request to the real origin through a pluggable [`Interceptor`], and streams
//! the response back. Upstream fetches run on a worker pool so a slow origin
//! never stalls the single-threaded QUIC event loop.

mod blocklist;
mod body;
mod ca;
mod config;
mod cosmetic;
mod encoding;
mod fetch;
mod inject;
mod insecure;
mod interceptor;
mod internal;
mod interstitial;
mod metrics;
mod plugin;
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

/// How much of a streaming body to relay per chunk.
const STREAM_CHUNK_SIZE: usize = 64 * 1024;

/// A request handed off to a worker for fetching.
struct FetchJob {
	conn: quiche::ConnectionId<'static>,
	stream_id: u64,
	request: ProxyRequest,
	/// The body still arriving, when there is one, and the length the client
	/// declared for it.
	upload: Option<(tokio::sync::mpsc::Receiver<body::Chunk>, Option<u64>)>,
}

/// A fetched response on its way back to a client, in one of two shapes: a
/// whole buffered response, or the pieces of a streaming one.
struct FetchResult {
	conn: quiche::ConnectionId<'static>,
	stream_id: u64,
	payload: Payload,
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
}

impl Pending {
	fn is_finished(&self) -> bool {
		self.headers_sent && self.fin_sent
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

fn main() -> Result<(), Box<dyn Error>> {
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

	let config = Arc::new(Config::load()?);
	let listen = config.listen.0;

	if let Err(e) = std::fs::create_dir_all(&config.paths.cache_dir) {
		log::warn!(
			"could not create cache dir {}: {e}",
			config.paths.cache_dir.display()
		);
	}

	if let Err(e) = std::fs::create_dir_all(&config.paths.state_dir) {
		log::warn!(
			"could not create state dir {}: {e}",
			config.paths.state_dir.display()
		);
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
	let mut socket = mio::net::UdpSocket::bind(listen)?;
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

				if handle_job(&agents, &config, &interceptor, job, &res_tx, &waker).is_err() {
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
) -> Result<(), ()> {
	let metrics = metrics::shared();
	metrics.requests.increment();

	// All of this is ahead of `send`, which borrows the job for the rest of the
	// function. Anything that can answer without the body answers first, so a
	// blocked upload is refused rather than read.
	let early = interceptor.before_body(&mut job.request);
	let resume = match early {
		interceptor::BeforeBody::Answered(response) => {
			log::info!(
				"short-circuited {} {}",
				job.request.method,
				job.request.url
			);
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

	let send = |payload| {
		results
			.send(FetchResult {
				conn: job.conn.clone(),
				stream_id: job.stream_id,
				payload,
			})
			.map_err(|_| ())?;
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

	if let Some(response) = answer {
		log::info!("short-circuited {} {}", job.request.method, job.request.url);
		metrics.bytes_to_client.add(response.body.len() as u64);

		return send(Payload::Full(response));
	}

	let resp = match upstream::call(agents, &job.request, upload) {
		Ok(resp) => resp,
		Err(failure) => {
			let host = host_of(&job.request.url);
			let page = match &failure {
				upstream::FetchError::Tls(detail) => {
					log::warn!("certificate validation failed for {host}: {detail}");

					interstitial::certificate_error(host, detail, config.bypass_phrase())
				}
				upstream::FetchError::Other(detail) => interstitial::upstream_error(host, detail),
			};
			metrics.bytes_to_client.add(page.body.len() as u64);

			return send(Payload::Full(page));
		}
	};

	let mut head = ResponseHead {
		status: resp.status(),
		headers: upstream::response_headers(&resp),
	};

	if interceptor.wants_body(&job.request, &head) {
		let mut body = Vec::new();
		if let Err(e) = resp.into_reader().read_to_end(&mut body) {
			log::warn!("failed reading upstream body for {}: {e}", job.request.url);
		}
		metrics.bytes_from_origin.add(body.len() as u64);

		// Interceptors rewrite plain bytes; the coding goes back on afterwards.
		let (body, coding) = encoding::decode(&mut head.headers, body);
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

	// Nothing wants the body: relay it as it arrives. Deliberately not a place
	// to compress — the coding here is whatever the origin chose, and we never
	// hold enough of the body to know what a different one would cost.
	interceptor.on_response_head(&job.request, &mut head);
	// Asked once, before the head is handed off: the answer holds for the whole
	// stream, and re-asking per chunk would cost a plugin round trip each time.
	let wants_chunks = interceptor.wants_chunks(&job.request, &head);
	send(Payload::Head(head))?;

	let mut reader = resp.into_reader();
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
				metrics.bytes_to_client.add(chunk.len() as u64);

				send(Payload::Chunk(chunk))?;
			}
			Err(e) => {
				log::warn!("upstream read failed for {}: {e}", job.request.url);

				break;
			}
		}
	}

	if wants_chunks {
		if let Some(tail) = interceptor.on_response_end(&job.request) {
			metrics.bytes_to_client.add(tail.len() as u64);

			send(Payload::Chunk(tail))?;
		}
	}

	send(Payload::End)
}


fn drain_results(results: &Receiver<FetchResult>, clients: &mut ClientMap) {
	while let Ok(result) = results.try_recv() {
		let Some(client) = clients.get_mut(&result.conn) else {
			// Client vanished while its fetch was in flight; drop the response.
			log::debug!("dropping response for closed connection");

			continue;
		};

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
			}),
			Payload::Chunk(data) => {
				match find_pending(client, result.stream_id) {
					Some(pending) => pending.chunks.push_back(data),
					// Its stream already failed and was dropped.
					None => log::debug!("chunk for unknown stream {}", result.stream_id),
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
	builder.set_servername_callback(move |ssl, _alert| {
		if let Some(sni) = ssl.servername(boring::ssl::NameType::HOST_NAME) {
			let sni = sni.to_string();
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
				let new_token = mint_token(&hdr, &from);
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
				match build_request(&list) {
					Some((request, _)) if !more_frames => {
						// No body to wait for.
						dispatch(key, stream_id, request, None, jobs);
					}
					Some((request, length)) => {
						// A body follows. The request goes to a worker now and
						// the body follows it down a channel, so a large upload
						// is never assembled anywhere.
						let (chunks, receiver) = body::channel();
						uploads.insert(
							stream_id,
							Upload {
								chunks,
								overflow: VecDeque::new(),
								parked: 0,
								finished: false,
							},
						);
						dispatch(key, stream_id, request, Some((receiver, length)), jobs);
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
				// Dropping the sender ends the worker's body early, which is
				// the truth: the client stopped sending.
				uploads.remove(&stream_id);
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
	upload: Option<(tokio::sync::mpsc::Receiver<body::Chunk>, Option<u64>)>,
	jobs: &Sender<FetchJob>,
) {
	log::info!(
		"proxying stream={stream_id} {} {}{}",
		request.method,
		request.url,
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
	};
	if jobs.send(job).is_err() {
		log::error!("worker pool is gone; cannot dispatch request");
	}
}

/// A plain refusal, for a request that never reaches an origin.
/// Send one complete response back to the event loop. Used where the borrow of
/// the job has not yet been handed to the closure that usually does this.
fn send_full(
	results: &Sender<FetchResult>,
	waker: &mio::Waker,
	job: &FetchJob,
	response: ProxyResponse,
) -> Result<(), ()> {
	results
		.send(FetchResult {
			conn: job.conn.clone(),
			stream_id: job.stream_id,
			payload: Payload::Full(response),
		})
		.map_err(|_| ())?;
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
		let content_length = p.complete.then(|| body_len(p).to_string());
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
					p.chunks.pop_front();
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
fn build_request(list: &[quiche::h3::Header]) -> Option<(ProxyRequest, Option<u64>)> {
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
	// TODO: this drops any port in :authority and lets the scheme's default
	// apply (443 for https). Correct for the common case; a transparent
	// deployment should instead recover the real origin address via
	// SO_ORIGINAL_DST to preserve nonstandard ports.
	let url = format!("{scheme}://{}{}", authority_host(&authority?), path?);

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

/// Build an address-validation token: a marker, the client's address, and the
/// connection id it originally chose (which we must echo back at handshake).
///
/// The token is not authenticated, so it proves only that the bearer received
/// our Retry at this address — which is exactly the amplification defence we
/// want. It is not a substitute for a signed token if this ever faces a
/// hostile network.
fn mint_token(hdr: &quiche::Header, from: &SocketAddr) -> Vec<u8> {
	let mut token = Vec::from(TOKEN_MARKER);
	token.extend_from_slice(&address_bytes(from));
	token.extend_from_slice(&hdr.dcid);

	token
}

/// Recover the original connection id from a token, rejecting anything that did
/// not come from us or arrived from a different address.
fn validate_token(from: &SocketAddr, token: &[u8]) -> Option<quiche::ConnectionId<'static>> {
	let rest = token.strip_prefix(TOKEN_MARKER)?;

	let addr = address_bytes(from);
	let rest = rest.strip_prefix(addr.as_slice())?;
	if rest.is_empty() {
		return None;
	}

	Some(quiche::ConnectionId::from_ref(rest).into_owned())
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

		let (req, length) = build_request(&list).expect("should parse");

		assert_eq!(length, None, "a GET declares no body length");
		assert_eq!(req.method, "GET");
		assert_eq!(req.url, "https://example.com/index.html");
		// host (ureq sets it) and hop-by-hop headers are dropped; user-agent kept.
		assert_eq!(req.headers, vec![("user-agent".to_string(), "curl".to_string())]);
	}

	#[test]
	fn token_round_trips_the_original_connection_id() {
		let from: SocketAddr = "192.0.2.10:5555".parse().unwrap();
		let odcid = quiche::ConnectionId::from_ref(b"originalcid");

		let mut token = Vec::from(TOKEN_MARKER);
		token.extend_from_slice(&address_bytes(&from));
		token.extend_from_slice(&odcid);

		let recovered = validate_token(&from, &token).expect("our own token must validate");

		assert_eq!(recovered.as_ref(), odcid.as_ref());
	}

	#[test]
	fn token_is_rejected_from_another_address() {
		let minted_for: SocketAddr = "192.0.2.10:5555".parse().unwrap();
		let attacker: SocketAddr = "198.51.100.7:5555".parse().unwrap();

		let mut token = Vec::from(TOKEN_MARKER);
		token.extend_from_slice(&address_bytes(&minted_for));
		token.extend_from_slice(b"originalcid");

		assert!(
			validate_token(&attacker, &token).is_none(),
			"a token replayed from a different address must not validate"
		);
	}

	#[test]
	fn token_without_our_marker_is_rejected() {
		let from: SocketAddr = "192.0.2.10:5555".parse().unwrap();
		let mut token = Vec::from(b"other".as_slice());
		token.extend_from_slice(&address_bytes(&from));
		token.extend_from_slice(b"originalcid");

		assert!(validate_token(&from, &token).is_none());
		assert!(validate_token(&from, b"").is_none(), "empty token is invalid");
	}

	#[test]
	fn token_with_no_connection_id_is_rejected() {
		let from: SocketAddr = "192.0.2.10:5555".parse().unwrap();
		let mut token = Vec::from(TOKEN_MARKER);
		token.extend_from_slice(&address_bytes(&from));

		assert!(
			validate_token(&from, &token).is_none(),
			"a token carrying no original id is unusable"
		);
	}

	#[test]
	fn build_request_needs_authority_and_path() {
		let list = vec![quiche::h3::Header::new(b":method", b"GET")];

		assert!(build_request(&list).is_none());
	}
}
