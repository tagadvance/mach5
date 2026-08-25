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
	assert_eq!(response.text(), "#promo { display: none !important }");
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
