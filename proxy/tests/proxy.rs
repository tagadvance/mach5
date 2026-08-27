//! End-to-end tests against the real binary, over real TLS.
//!
//! Deliberately limited to what the proxy answers by itself — the blocklist
//! and the endpoints under `/.mach5/`. Both are short-circuited in
//! `on_request`, so nothing here touches the network and no test can fail
//! because someone else's site is down.

mod common;

use common::Proxy;

/// Every proxy in this file blocks the same domain, so the blocked host and
/// the unlisted one are the same in each.
const BLOCKLIST: &str = "0.0.0.0 ads.example.com\n";

#[test]
fn a_blocked_host_is_answered_without_the_origin() {
	let proxy = Proxy::start(BLOCKLIST);

	let response = proxy.send(
		"GET",
		"ads.example.com",
		"/frame.html",
		&[("accept", "text/html")],
		"",
	);

	assert_eq!(response.status, 204);
	assert!(response.body.is_empty());
	assert_eq!(response.header("x-mach5"), Some("blocked"));
	assert_eq!(response.header("cache-control"), Some("no-store"));
	// A blocked response is still a response served over TCP: leave the
	// advertisement off it and a client never discovers h3 at all.
	assert_eq!(response.header("alt-svc"), Some(proxy.alt_svc()));
}

#[test]
fn a_blocked_image_gets_a_pixel() {
	let proxy = Proxy::start(BLOCKLIST);

	let response = proxy.send(
		"GET",
		"ads.example.com",
		"/pixel.gif",
		&[("accept", "image/webp,*/*")],
		"",
	);

	assert_eq!(response.status, 200);
	assert_eq!(response.header("content-type"), Some("image/gif"));
	assert_eq!(response.header("x-mach5"), Some("blocked"));
	assert_eq!(response.header("alt-svc"), Some(proxy.alt_svc()));
	assert!(
		response.body.starts_with(b"GIF89a"),
		"a broken-image icon is not an improvement on the ad"
	);
}

/// RFC 9110 §9.3.2: a HEAD carries the headers a GET would, and no body. The
/// interesting case is a response mach5 makes up rather than fetches — a
/// blocked image is a real body it would have sent, so its length is knowable
/// and worth stating, and sending the bytes is a framing error the client has
/// to guess its way out of.
#[test]
fn a_head_gets_the_headers_and_none_of_the_body() {
	let proxy = Proxy::start(BLOCKLIST);

	let get = proxy.send(
		"GET",
		"ads.example.com",
		"/pixel.gif",
		&[("accept", "image/webp,*/*")],
		"",
	);
	let head = proxy.send(
		"HEAD",
		"ads.example.com",
		"/pixel.gif",
		&[("accept", "image/webp,*/*")],
		"",
	);

	assert_eq!(head.status, get.status);
	assert_eq!(head.header("content-type"), get.header("content-type"));
	assert!(head.body.is_empty(), "a HEAD must not carry a body");
	assert_eq!(
		head.header("content-length"),
		Some(get.body.len().to_string().as_str()),
		"and the length it reports is the one a GET would have sent"
	);
}

/// A 204 has no body by definition, so RFC 9110 §8.6 forbids the header that
/// says how long it is. Framing a length nobody can send is how a connection
/// ends up waiting for bytes that never come.
#[test]
fn a_204_is_not_given_a_length() {
	let proxy = Proxy::start(BLOCKLIST);

	let response = proxy.send(
		"GET",
		"ads.example.com",
		"/frame.html",
		&[("accept", "text/html")],
		"",
	);

	assert_eq!(response.status, 204);
	assert_eq!(response.header("content-length"), None);
	assert!(response.body.is_empty(), "and no body to go with it");

	// Ours replaces the origin's rather than joining it. A second one would
	// mean the strip in `apply_alt_svc` had stopped working, which nothing else
	// here would notice.
	assert_eq!(response.values("alt-svc"), [proxy.alt_svc()]);
}

#[test]
fn an_unlisted_host_is_not_answered_here() {
	let proxy = Proxy::start(BLOCKLIST);

	// `.invalid` is reserved precisely so it never resolves, so this reaches
	// the upstream fetch and fails there. What the fetch does is not the point
	// — the assertion is only that the proxy did not answer it itself.
	let response = proxy.get("unlisted.invalid", "/index.html");

	assert_ne!(response.status, 204, "an unlisted host is not blocked");
	assert_ne!(
		response.header("x-mach5"),
		Some("blocked"),
		"an unlisted host is not blocked"
	);
}

#[test]
fn a_selector_survives_the_round_trip_and_reaches_the_disk() {
	let proxy = Proxy::start(BLOCKLIST);
	let host = "example.com";

	let empty = proxy.get(host, "/.mach5/hidden");
	assert_eq!(empty.status, 200);
	assert_eq!(empty.text(), r#"{"selectors":[]}"#);
	assert_eq!(empty.header("content-type"), Some("application/json"));

	let added = proxy.post(host, "/.mach5/hidden", r##"{"selector":"#promo"}"##);
	assert_eq!(added.status, 204);
	assert!(added.body.is_empty());

	let stored = proxy.get(host, "/.mach5/hidden");
	assert_eq!(stored.text(), r##"{"selectors":["#promo"]}"##);

	// The response is only sent once the store has been written, so the file
	// is already there by the time the POST has been answered.
	let on_disk = std::fs::read_to_string(proxy.hidden_json()).expect("the store is on disk");
	assert!(
		on_disk.contains("#promo"),
		"a list built up by hand must outlive the process: {on_disk}"
	);
}

#[test]
fn one_hosts_list_does_not_reach_another() {
	let proxy = Proxy::start(BLOCKLIST);

	assert_eq!(
		proxy
			.post("example.com", "/.mach5/hidden", r##"{"selector":"#ad"}"##)
			.status,
		204
	);

	assert_eq!(
		proxy.get("example.net", "/.mach5/hidden").text(),
		r#"{"selectors":[]}"#,
		"the SNI picks the list, so a neighbour's is out of reach"
	);
	assert_eq!(
		proxy.get("example.com", "/.mach5/hidden").text(),
		r##"{"selectors":["#ad"]}"##
	);
}

#[test]
fn the_stylesheet_applies_this_hosts_list() {
	let proxy = Proxy::start(BLOCKLIST);
	let host = "example.com";

	proxy.post(host, "/.mach5/hidden", r##"{"selector":"#promo"}"##);

	let response = proxy.get(host, "/.mach5/hidden.css");

	assert_eq!(response.status, 200);
	assert_eq!(
		response.header("content-type"),
		Some("text/css; charset=utf-8")
	);
	// One rule per selector, so a selector the browser cannot parse cannot take
	// the rest of the host's list with it.
	assert_eq!(response.text(), "#promo { display: none !important }\n");
}

#[test]
fn the_picker_is_served_as_javascript() {
	let proxy = Proxy::start(BLOCKLIST);

	let response = proxy.get("example.com", "/.mach5/mach5.js");

	assert_eq!(response.status, 200);
	assert_eq!(
		response.header("content-type"),
		Some("text/javascript; charset=utf-8")
	);
	assert!(!response.body.is_empty());
}

#[test]
fn an_unknown_endpoint_or_method_is_refused() {
	let proxy = Proxy::start(BLOCKLIST);
	let host = "example.com";

	assert_eq!(proxy.get(host, "/.mach5/nope").status, 404);
	assert_eq!(
		proxy.send("DELETE", host, "/.mach5/hidden", &[], "").status,
		405
	);
}

/// An upload only has to fit in memory when something asked to see it, and
/// `/.mach5/hidden` is the one endpoint here that does. The harness caps that
/// at a megabyte, so this is the cap doing its job rather than a limit on what
/// can be uploaded at all.
/// The link estimate has to be reportable from the device being measured —
/// that is the only place it can be checked against a real network — so both
/// the page and the JSON have to carry it.
///
/// Nothing is measured here and that is the assertion: a loopback client never
/// makes the proxy wait, so no sample is invented for it. What this pins down
/// is the shape — the counters stayed flat, the row is on the page, and an
/// unmeasured client is reported as unmeasured rather than as a fast one.
#[test]
fn the_link_estimate_is_reported_to_the_client_being_measured() {
	let proxy = Proxy::start(BLOCKLIST);

	let page = proxy.get("example.com", "/.mach5/");
	assert_eq!(page.status, 200);
	let page = String::from_utf8_lossy(&page.body);
	assert!(page.contains("This client&rsquo;s link"), "{page}");
	assert!(page.contains("not measured yet"), "{page}");

	let stats = proxy.get("example.com", "/.mach5/stats.json");
	assert_eq!(stats.status, 200);
	let stats = String::from_utf8_lossy(&stats.body);
	assert!(stats.contains("\"link_clients\""), "{stats}");
	assert!(
		!stats.contains("\"link_tier\""),
		"an unmeasured client must be absent rather than guessed at: {stats}"
	);
	// The counters are still there and still flat beside it.
	assert!(stats.contains("\"requests\""), "{stats}");
}

#[test]
fn a_body_something_wants_to_read_is_capped() {
	let proxy = Proxy::start(BLOCKLIST);
	let huge = "x".repeat(2 * 1024 * 1024);
	let body = format!("{{\"selector\":\"{huge}\"}}");

	let response = proxy.send(
		"POST",
		"example.com",
		"/.mach5/hidden",
		&[("content-type", "application/json")],
		&body,
	);

	assert_eq!(response.status, 413);
}

/// The upload nobody wants to read is the whole point: a blocked host is
/// answered without the body being assembled, and — because the blocklist runs
/// before anything that could ask for it — without being read at all.
#[test]
fn a_blocked_upload_is_refused_rather_than_read() {
	let proxy = Proxy::start(BLOCKLIST);
	let body = "x".repeat(4 * 1024 * 1024);

	let response = proxy.send(
		"POST",
		"ads.example.com",
		"/upload",
		&[("content-type", "application/octet-stream")],
		&body,
	);

	assert_eq!(
		response.status, 204,
		"four megabytes past a one megabyte cap, and still the blocklist's answer"
	);
	assert_eq!(response.header("x-mach5"), Some("blocked"));
}

/// The one guarantee that cannot be given by declining to modify a page: mach5
/// never holds the plaintext at all.
///
/// A plain TCP listener stands in for the origin. If mach5 had terminated TLS
/// it would have answered the ClientHello itself with a minted certificate and
/// this listener would never have seen those bytes; getting them back means the
/// two sockets were spliced and nothing in between read them.
#[test]
fn a_passthrough_host_is_never_decrypted() {
	use std::io::{Read, Write};
	use std::net::{TcpListener, TcpStream};

	let origin = TcpListener::bind("127.0.0.1:0").expect("an origin to splice to");
	let origin_port = origin.local_addr().unwrap().port();

	// Echoes one buffer, so the test can prove the bytes made the round trip.
	let echoing = std::thread::spawn(move || {
		let (mut peer, _) = origin.accept().expect("mach5 connects");
		let mut buf = [0u8; 512];
		let read = peer.read(&mut buf).expect("the client's bytes arrive here");
		peer.write_all(&buf[..read]).expect("echo them back");
		peer.flush().ok();

		buf[..read].to_vec()
	});

	let proxy = Proxy::start_with(
		BLOCKLIST,
		&format!("[passthrough]\nhosts = [\"localhost\"]\nport = {origin_port}"),
	);

	// Deliberately not a TLS client: whatever is written here should arrive at
	// the origin untouched, which is easier to assert on than a handshake.
	let mut client = TcpStream::connect(("127.0.0.1", proxy.tcp_port())).expect("reach mach5");
	// A ClientHello for `localhost`, which is what makes mach5 splice at all.
	client.write_all(&common::client_hello(b"localhost")).expect("send a hello");
	client.flush().unwrap();

	let mut back = [0u8; 512];
	let read = client.read(&mut back).expect("the origin's answer comes back");

	let at_origin = echoing.join().expect("the origin thread");

	assert_eq!(
		at_origin,
		common::client_hello(b"localhost"),
		"the origin sees the client's own bytes, not mach5's"
	);
	assert_eq!(
		&back[..read],
		&at_origin[..read],
		"and the client sees the origin's, both ways through the splice"
	);
}

/// The peek used to take whatever was in the socket the first time it was
/// readable. A real ClientHello no longer fits in one segment — a browser
/// offering a post-quantum key share sends about two kilobytes — so the parser
/// was handed a truncated record, refused it, and the refusal means terminate
/// it. Whether a listed bank was decrypted came down to TCP segmentation.
#[test]
fn a_hello_split_across_segments_is_still_passed_through() {
	use std::io::{Read, Write};
	use std::net::{TcpListener, TcpStream};

	let origin = TcpListener::bind("127.0.0.1:0").expect("an origin to splice to");
	let origin_port = origin.local_addr().unwrap().port();

	let hello = common::padded_client_hello(b"localhost", 1800);
	assert!(hello.len() > 1500, "the point is that it does not fit in one");

	let expected = hello.clone();
	// Reported over a channel rather than joined: when this regresses, mach5
	// terminates the connection instead of splicing it and nothing ever
	// arrives here, so a join would hang the run rather than fail it.
	let (arrived, at_origin) = std::sync::mpsc::channel();
	std::thread::spawn(move || {
		let Ok((mut peer, _)) = origin.accept() else {
			return;
		};
		let mut seen = Vec::new();
		let mut buf = [0u8; 4096];
		while seen.len() < expected.len() {
			match peer.read(&mut buf) {
				Ok(0) | Err(_) => break,
				Ok(read) => seen.extend_from_slice(&buf[..read]),
			}
		}
		let _ = arrived.send(seen);
	});

	let proxy = Proxy::start_with(
		BLOCKLIST,
		&format!("[passthrough]\nhosts = [\"localhost\"]\nport = {origin_port}"),
	);

	let mut client = TcpStream::connect(("127.0.0.1", proxy.tcp_port())).expect("reach mach5");
	let (first, rest) = hello.split_at(1400);
	client.write_all(first).expect("the first segment");
	client.flush().unwrap();
	// Long enough that mach5 has certainly been woken by the first segment and
	// had to decide what to do with a partial record.
	std::thread::sleep(std::time::Duration::from_millis(150));
	client.write_all(rest).expect("the rest of it");
	client.flush().unwrap();

	let seen = at_origin
		.recv_timeout(std::time::Duration::from_secs(10))
		.expect(
			"nothing reached the origin: mach5 decided from a partial record and \
			 terminated a host it was told never to decrypt",
		);
	assert_eq!(
		seen, hello,
		"the origin sees the whole hello, so mach5 waited for it rather than \
		 answering with a certificate of its own"
	);
}
