//! mach5 — QUIC/HTTP-3 intercepting proxy (skeleton).
//!
//! Terminates an HTTP/3 connection from a client with a certificate minted on
//! the fly for the requested SNI host (signed by our root CA), forwards each
//! request to the real origin through a pluggable [`Interceptor`], and streams
//! the response back. Upstream fetches run on a worker pool so a slow origin
//! never stalls the single-threaded QUIC event loop.

mod ca;
mod interceptor;

use std::collections::HashMap;
use std::error::Error;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boring::ssl::{select_next_proto, AlpnError, SslContextBuilder, SslMethod, SslVersion};
use quiche::h3::NameValue;

use ca::CertAuthority;
use interceptor::{Interceptor, PassThrough, ProxyRequest, ProxyResponse, Stamp};

const MAX_DATAGRAM_SIZE: usize = 1350;
const SOCKET: mio::Token = mio::Token(0);
const WAKER: mio::Token = mio::Token(1);

/// A request handed off to a worker for fetching.
struct FetchJob {
	conn: quiche::ConnectionId<'static>,
	stream_id: u64,
	request: ProxyRequest,
}

/// A fetched (and intercepted) response on its way back to a client.
struct FetchResult {
	conn: quiche::ConnectionId<'static>,
	stream_id: u64,
	response: ProxyResponse,
}

/// A response being streamed out on one h3 stream, tracking how far it got so
/// it can resume when the stream regains capacity.
struct Pending {
	stream_id: u64,
	response: ProxyResponse,
	headers_sent: bool,
	body_offset: usize,
}

/// Per-connection state.
struct Client {
	conn: quiche::Connection,
	http3: Option<quiche::h3::Connection>,
	pending: Vec<Pending>,
}

type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;

fn main() -> Result<(), Box<dyn Error>> {
	env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

	let listen: SocketAddr = std::env::var("MACH5_LISTEN")
		.unwrap_or_else(|_| "0.0.0.0:4433".to_string())
		.parse()?;

	let ca = Arc::new(load_ca()?);
	let mut config = build_config(ca)?;
	let h3_config = quiche::h3::Config::new()?;

	let mut poll = mio::Poll::new()?;
	let mut events = mio::Events::with_capacity(1024);
	let mut socket = mio::net::UdpSocket::bind(listen)?;
	poll.registry()
		.register(&mut socket, SOCKET, mio::Interest::READABLE)?;
	let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER)?);

	let (jobs, results) = spawn_workers(select_interceptor(), waker);
	log::info!("listening on {listen} (UDP/QUIC)");

	let mut buf = [0u8; 65535];
	let mut out = [0u8; MAX_DATAGRAM_SIZE];
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

			if let Err(e) = recv_packet(&mut buf[..len], from, listen, &mut config, &mut clients) {
				log::debug!("recv error from {from}: {e}");
			}
		}

		// Attach any fetched responses to their connections.
		drain_results(&results, &mut clients);

		for client in clients.values_mut() {
			client.conn.on_timeout();
		}

		drive_http3(&h3_config, &mut clients, &jobs);
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

fn select_interceptor() -> Arc<dyn Interceptor> {
	match std::env::var("MACH5_INTERCEPT").as_deref() {
		Ok("passthrough") => Arc::new(PassThrough),
		_ => Arc::new(Stamp),
	}
}

fn spawn_workers(
	interceptor: Arc<dyn Interceptor>,
	waker: Arc<mio::Waker>,
) -> (Sender<FetchJob>, Receiver<FetchResult>) {
	let (job_tx, job_rx) = std::sync::mpsc::channel::<FetchJob>();
	let (res_tx, res_rx) = std::sync::mpsc::channel::<FetchResult>();
	let job_rx = Arc::new(Mutex::new(job_rx));

	let agent = ureq::AgentBuilder::new()
		.redirects(0) // pass 3xx through to the client; it re-requests and we intercept again
		.timeout_connect(Duration::from_secs(10))
		.timeout_read(Duration::from_secs(30))
		.build();

	let count = std::thread::available_parallelism()
		.map(|n| n.get())
		.unwrap_or(4);

	for _ in 0..count {
		let job_rx = job_rx.clone();
		let res_tx = res_tx.clone();
		let waker = waker.clone();
		let agent = agent.clone();
		let interceptor = interceptor.clone();

		std::thread::spawn(move || loop {
			let job = {
				let rx = job_rx.lock().unwrap();
				rx.recv()
			};
			let mut job = match job {
				Ok(j) => j,
				Err(_) => break, // senders dropped: shut down
			};

			interceptor.on_request(&mut job.request);
			let mut response = fetch(&agent, &job.request);
			interceptor.on_response(&job.request, &mut response);

			let sent = res_tx.send(FetchResult {
				conn: job.conn,
				stream_id: job.stream_id,
				response,
			});
			if sent.is_err() {
				break;
			}

			let _ = waker.wake();
		});
	}

	(job_tx, res_rx)
}

/// Blocking upstream fetch. Any transport failure becomes a 502 so the client
/// always gets a well-formed response.
fn fetch(agent: &ureq::Agent, req: &ProxyRequest) -> ProxyResponse {
	let mut request = agent.request(&req.method, &req.url);
	for (name, value) in &req.headers {
		request = request.set(name, value);
	}

	let resp = match request.call() {
		Ok(resp) => resp,
		Err(ureq::Error::Status(_, resp)) => resp,
		Err(ureq::Error::Transport(t)) => {
			let body = format!("mach5: upstream fetch failed: {t}\n").into_bytes();

			return ProxyResponse {
				status: 502,
				headers: vec![("content-type".to_string(), "text/plain".to_string())],
				body,
			};
		}
	};

	let status = resp.status();
	let mut headers = Vec::new();
	for name in resp.headers_names() {
		if is_hop_by_hop(&name) {
			continue;
		}
		if let Some(value) = resp.header(&name) {
			headers.push((name.clone(), value.to_string()));
		}
	}

	let mut body = Vec::new();
	if let Err(e) = resp.into_reader().read_to_end(&mut body) {
		log::warn!("failed reading upstream body for {}: {e}", req.url);
	}

	ProxyResponse {
		status,
		headers,
		body,
	}
}

fn drain_results(results: &Receiver<FetchResult>, clients: &mut ClientMap) {
	while let Ok(result) = results.try_recv() {
		match clients.get_mut(&result.conn) {
			Some(client) => client.pending.push(Pending {
				stream_id: result.stream_id,
				response: result.response,
				headers_sent: false,
				body_offset: 0,
			}),
			// Client vanished while its fetch was in flight; drop the response.
			None => log::debug!("dropping response for closed connection"),
		}
	}
}

fn load_ca() -> Result<CertAuthority, Box<dyn Error>> {
	match (std::env::var("MACH5_CA_CERT"), std::env::var("MACH5_CA_KEY")) {
		(Ok(cert_path), Ok(key_path)) => {
			let cert_pem = std::fs::read_to_string(&cert_path)?;
			let key_pem = std::fs::read_to_string(&key_path)?;
			log::info!("loaded root CA from {cert_path}");

			CertAuthority::from_pem(&cert_pem, &key_pem)
		}
		_ => {
			log::warn!(
				"MACH5_CA_CERT / MACH5_CA_KEY unset — generating an ephemeral dev CA. \
				 Minted certs will NOT be trusted by any browser."
			);

			CertAuthority::generate_dev()
		}
	}
}

fn build_config(ca: Arc<CertAuthority>) -> Result<quiche::Config, Box<dyn Error>> {
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

	let mut config = quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, builder)?;

	config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
	config.set_max_idle_timeout(30_000);
	config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
	config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
	config.set_initial_max_data(10_000_000);
	config.set_initial_max_stream_data_bidi_local(1_000_000);
	config.set_initial_max_stream_data_bidi_remote(1_000_000);
	config.set_initial_max_stream_data_uni(1_000_000);
	config.set_initial_max_streams_bidi(100);
	config.set_initial_max_streams_uni(100);

	Ok(config)
}

fn recv_packet(
	pkt: &mut [u8],
	from: SocketAddr,
	local: SocketAddr,
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

			// TODO: stateless Retry + version negotiation before accepting, to
			// harden against spoofed-source amplification.
			let conn = quiche::accept(&derived, None, local, from, config)?;
			log::info!("new connection {derived:?} from {from}");

			clients.insert(
				derived.clone(),
				Client {
					conn,
					http3: None,
					pending: Vec::new(),
				},
			);

			derived
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

		poll_requests(&key, &mut client.conn, http3, jobs);
		pump_responses(&mut client.conn, http3, &mut client.pending);
	}
}

fn poll_requests(
	key: &quiche::ConnectionId<'static>,
	conn: &mut quiche::Connection,
	http3: &mut quiche::h3::Connection,
	jobs: &Sender<FetchJob>,
) {
	loop {
		match http3.poll(conn) {
			Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
				match build_request(&list) {
					Some(request) => {
						log::info!("proxying stream={stream_id} {} {}", request.method, request.url);

						// TODO: forward request bodies (POST/PUT) — read them from
						// the stream's Data events before dispatching.
						let job = FetchJob {
							conn: key.clone(),
							stream_id,
							request,
						};
						if jobs.send(job).is_err() {
							log::error!("worker pool is gone; cannot dispatch request");
						}
					}
					None => log::warn!("stream={stream_id} missing pseudo-headers; ignoring"),
				}
			}
			Ok((_, quiche::h3::Event::Data)) => {}
			Ok((_, quiche::h3::Event::Finished)) => {}
			Ok((_, quiche::h3::Event::Reset(_))) => {}
			Ok((_, quiche::h3::Event::PriorityUpdate)) => {}
			Ok((_, quiche::h3::Event::GoAway)) => {}
			Err(quiche::h3::Error::Done) => break,
			Err(e) => {
				log::error!("h3 poll error: {e}");

				break;
			}
		}
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
		let status = p.response.status.to_string();
		let content_length = p.response.body.len().to_string();

		let mut headers = vec![
			quiche::h3::Header::new(b":status", status.as_bytes()),
			quiche::h3::Header::new(b"content-length", content_length.as_bytes()),
		];
		for (name, value) in &p.response.headers {
			headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
		}

		let fin = p.response.body.is_empty();
		match http3.send_response(conn, p.stream_id, &headers, fin) {
			Ok(()) => p.headers_sent = true,
			Err(quiche::h3::Error::StreamBlocked) | Err(quiche::h3::Error::Done) => {
				return Ok(false)
			}
			Err(e) => return Err(e),
		}

		if fin {
			return Ok(true);
		}
	}

	while p.body_offset < p.response.body.len() {
		match http3.send_body(conn, p.stream_id, &p.response.body[p.body_offset..], true) {
			Ok(0) => break,
			Ok(n) => p.body_offset += n,
			Err(quiche::h3::Error::Done) => break,
			Err(e) => return Err(e),
		}
	}

	Ok(p.headers_sent && p.body_offset >= p.response.body.len())
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
fn build_request(list: &[quiche::h3::Header]) -> Option<ProxyRequest> {
	let mut method = None;
	let mut authority = None;
	let mut path = None;
	let mut scheme = None;
	let mut headers = Vec::new();

	for h in list {
		let value = String::from_utf8_lossy(h.value()).into_owned();
		match h.name() {
			b":method" => method = Some(value),
			b":authority" => authority = Some(value),
			b":path" => path = Some(value),
			b":scheme" => scheme = Some(value),
			name if name.starts_with(b":") => {}
			name if is_hop_by_hop(&String::from_utf8_lossy(name)) => {}
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

	Some(ProxyRequest {
		method: method?,
		url,
		headers,
	})
}

/// Host portion of an `:authority`, dropping any `:port` and keeping an IPv6
/// literal's brackets.
fn authority_host(authority: &str) -> &str {
	if authority.starts_with('[') {
		return authority.find(']').map_or(authority, |i| &authority[..=i]);
	}

	authority
		.split_once(':')
		.map_or(authority, |(host, _port)| host)
}

/// Hop-by-hop headers are meaningful only on a single connection and must not be
/// forwarded across the proxy (RFC 9110 §7.6.1), plus framing headers we set
/// ourselves.
fn is_hop_by_hop(name: &str) -> bool {
	matches!(
		name.to_ascii_lowercase().as_str(),
		"connection"
			| "keep-alive"
			| "proxy-authenticate"
			| "proxy-authorization"
			| "te" | "trailer"
			| "transfer-encoding"
			| "upgrade"
			| "content-length"
	)
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

		let req = build_request(&list).expect("should parse");

		assert_eq!(req.method, "GET");
		assert_eq!(req.url, "https://example.com/index.html");
		// host (ureq sets it) and hop-by-hop headers are dropped; user-agent kept.
		assert_eq!(req.headers, vec![("user-agent".to_string(), "curl".to_string())]);
	}

	#[test]
	fn build_request_needs_authority_and_path() {
		let list = vec![quiche::h3::Header::new(b":method", b"GET")];

		assert!(build_request(&list).is_none());
	}
}
