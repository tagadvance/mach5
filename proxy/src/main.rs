//! mach5 — QUIC/HTTP-3 intercepting proxy (skeleton).
//!
//! This proves the load-bearing feature: terminate an HTTP/3 connection from a
//! client using a certificate minted on the fly for the requested SNI host and
//! signed by our root CA. It currently answers every request with a small
//! diagnostic page. Proxying the request upstream and running it through a
//! pluggable interception layer is the next layer of work — see the TODOs in
//! `handle_h3`.

mod ca;

use std::collections::HashMap;
use std::error::Error;
use std::net::SocketAddr;
use std::sync::Arc;

use boring::ssl::{select_next_proto, AlpnError, SslContextBuilder, SslMethod, SslVersion};
use quiche::h3::NameValue;

use ca::CertAuthority;

const MAX_DATAGRAM_SIZE: usize = 1350;

/// Per-connection state.
struct Client {
	conn: quiche::Connection,
	http3: Option<quiche::h3::Connection>,
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
		.register(&mut socket, mio::Token(0), mio::Interest::READABLE)?;
	log::info!("listening on {listen} (UDP/QUIC)");

	let mut buf = [0u8; 65535];
	let mut out = [0u8; MAX_DATAGRAM_SIZE];
	let mut clients: ClientMap = HashMap::new();

	loop {
		let timeout = clients.values().filter_map(|c| c.conn.timeout()).min();
		poll.poll(&mut events, timeout)?;

		// Read every datagram currently queued on the socket.
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
				&mut config,
				&mut clients,
			) {
				log::debug!("recv error from {from}: {e}");
			}
		}

		// Fire idle/loss timers.
		for client in clients.values_mut() {
			client.conn.on_timeout();
		}

		drive_http3(&h3_config, &mut clients);
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
	socket: &mio::net::UdpSocket,
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

	let _ = socket;

	Ok(())
}

fn drive_http3(h3_config: &quiche::h3::Config, clients: &mut ClientMap) {
	for client in clients.values_mut() {
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

		if let Some(http3) = client.http3.as_mut() {
			handle_h3(&mut client.conn, http3);
		}
	}
}

fn handle_h3(conn: &mut quiche::Connection, http3: &mut quiche::h3::Connection) {
	loop {
		match http3.poll(conn) {
			Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
				let host = header_value(&list, b":authority");
				let path = header_value(&list, b":path");
				log::info!("h3 request stream={stream_id} authority={host} path={path}");

				// TODO: instead of answering here, forward this request upstream
				// (h2/h1.1 to origins that don't speak h3), run request/response
				// through the pluggable interception layer, then stream it back.
				respond(conn, http3, stream_id, &host, &path);
			}
			Ok((_stream_id, quiche::h3::Event::Data)) => {}
			Ok((_stream_id, quiche::h3::Event::Finished)) => {}
			Ok((_stream_id, quiche::h3::Event::Reset(_))) => {}
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

fn respond(
	conn: &mut quiche::Connection,
	http3: &mut quiche::h3::Connection,
	stream_id: u64,
	host: &str,
	path: &str,
) {
	let body = format!(
		"mach5 proxy skeleton\nintercepted {host}{path}\nTLS terminated with a minted certificate.\n"
	);

	let headers = [
		quiche::h3::Header::new(b":status", b"200"),
		quiche::h3::Header::new(b"content-type", b"text/plain"),
		quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
		quiche::h3::Header::new(b"server", b"mach5"),
	];

	if let Err(e) = http3.send_response(conn, stream_id, &headers, false) {
		log::error!("send_response failed: {e}");

		return;
	}

	if let Err(e) = http3.send_body(conn, stream_id, body.as_bytes(), true) {
		log::error!("send_body failed: {e}");
	}
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

fn header_value(list: &[quiche::h3::Header], name: &[u8]) -> String {
	list.iter()
		.find(|h| h.name() == name)
		.map(|h| String::from_utf8_lossy(h.value()).into_owned())
		.unwrap_or_default()
}
