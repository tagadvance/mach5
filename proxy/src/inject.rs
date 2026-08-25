//! The tags that put [`crate::internal`]'s two files on every page.
//!
//! Both are same-origin URLs, deliberately. A site whose CSP is
//! `script-src 'self'` still runs a `<script src="/…">` where an inline
//! `<script>` would be blocked outright, and wildcard DNS is what makes the
//! relative URL reach us. A nonce-only or hash-only CSP still blocks us; that
//! is a limitation we live with rather than one we fix by rewriting somebody's
//! `content-security-policy` header, which would take a real protection off a
//! real site to make a cosmetic feature work.
//!
//! Everything here works on bytes. A page is not always UTF-8 — and quite often
//! is not what its `charset` claims — so decoding one into a `String` to search
//! it would replace every byte we failed to understand and hand the client back
//! a corrupted page. Matching ASCII tags over bytes and splicing in ASCII bytes
//! leaves every other byte exactly where the origin put it, whatever it means.

use std::collections::HashSet;

use crate::config::Config;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse, ResponseHead};

/// What gets spliced in. The stylesheet first, so it is already being fetched
/// while the parser reaches the script; `defer` so the picker runs after the
/// document is parsed and never blocks it.
const TAGS: &[u8] =
	br#"<link rel="stylesheet" href="/.mach5/hidden.css"><script src="/.mach5/mach5.js" defer></script>"#;

/// Proof our tags are already there. Injecting twice would run the picker's
/// double-run guard for nothing and, worse, make a redirect chain or a
/// re-proxied page grow a tag per hop.
const MARKER: &[u8] = b"/.mach5/mach5.js";

const HEAD_END: &[u8] = b"</head>";
const BODY_START: &[u8] = b"<body";

/// Adds the tags to HTML pages.
pub struct Inject {
	exclude: HashSet<String>,
}

impl Inject {
	pub fn new(config: &Config) -> Self {
		Self {
			exclude: config
				.inject
				.exclude
				.iter()
				.map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
				.filter(|host| !host.is_empty())
				.collect(),
		}
	}

	fn excluded(&self, req: &ProxyRequest) -> bool {
		crate::blocklist::covers(&self.exclude, crate::host_of(&req.url))
	}
}

impl Interceptor for Inject {
	fn on_response(&self, req: &ProxyRequest, resp: &mut ProxyResponse) {
		// Another link in the chain may be the reason the body was buffered, so
		// the question `wants_body` answered has to be asked again here.
		if !claims(resp.status, &resp.headers) || self.excluded(req) {
			return;
		}

		if let Some(at) = insertion_point(&resp.body) {
			resp.body.splice(at..at, TAGS.iter().copied());
		}
	}

	/// The one hook that has to be exact. Anything this says yes to stops
	/// streaming and is held in memory whole, so it says yes to HTML pages and
	/// nothing else — not a 304, not a redirect, not a video.
	fn wants_body(&self, req: &ProxyRequest, head: &ResponseHead) -> bool {
		claims(head.status, &head.headers) && !self.excluded(req)
	}
}

fn claims(status: u16, headers: &[(String, String)]) -> bool {
	status == 200 && is_html(headers)
}

fn is_html(headers: &[(String, String)]) -> bool {
	headers.iter().any(|(name, value)| {
		name.eq_ignore_ascii_case("content-type")
			&& value.to_ascii_lowercase().contains("text/html")
	})
}

/// Where the tags go: just before the first `</head>`, or failing that just
/// after the opening `<body>` tag. `None` means neither is there, and a
/// document with no head and no body is not one we understand well enough to
/// edit — a fragment, a feed served as HTML, or something mislabelled.
fn insertion_point(body: &[u8]) -> Option<usize> {
	if find_ascii(body, MARKER).is_some() {
		return None;
	}

	if let Some(at) = find_ascii(body, HEAD_END) {
		return Some(at);
	}

	body_tag_end(body)
}

/// End of the opening `<body …>` tag. The first `>` after it ends the tag in
/// every document that is not already broken; a `>` inside an attribute value
/// would fool this, but a `<body>` with one is rare enough — and the cost is a
/// pair of tags landing a few bytes early, not a corrupted page.
fn body_tag_end(body: &[u8]) -> Option<usize> {
	let mut from = 0;

	while let Some(offset) = find_ascii(&body[from..], BODY_START) {
		let start = from + offset;
		let after = start + BODY_START.len();

		// `<bodyguard>` is not `<body>`: the name has to end here.
		match body.get(after) {
			Some(b'>') => return Some(after + 1),
			Some(c) if c.is_ascii_whitespace() || *c == b'/' => {
				if let Some(close) = body[after..].iter().position(|c| *c == b'>') {
					return Some(after + close + 1);
				}

				return None;
			}
			_ => from = after,
		}
	}

	None
}

/// First offset at which `needle` appears, comparing ASCII case-insensitively.
/// Tag names are ASCII, so this never has to know what encoding the rest of the
/// bytes are in.
fn find_ascii(haystack: &[u8], needle: &[u8]) -> Option<usize> {
	if needle.len() > haystack.len() {
		return None;
	}

	haystack
		.windows(needle.len())
		.position(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn inject(exclude: &[&str]) -> Inject {
		Inject {
			exclude: exclude.iter().map(|host| host.to_string()).collect(),
		}
	}

	fn request(url: &str) -> ProxyRequest {
		ProxyRequest {
			method: "GET".to_string(),
			url: url.to_string(),
			headers: Vec::new(),
			body: Vec::new(),
		}
	}

	fn html(status: u16, body: &[u8]) -> ProxyResponse {
		ProxyResponse {
			status,
			headers: vec![(
				"Content-Type".to_string(),
				"text/html; charset=utf-8".to_string(),
			)],
			body: body.to_vec(),
		}
	}

	fn run(inject: &Inject, url: &str, resp: &mut ProxyResponse) {
		inject.on_response(&request(url), resp);
	}

	fn head(status: u16, content_type: &str) -> ResponseHead {
		ResponseHead {
			status,
			headers: vec![("content-type".to_string(), content_type.to_string())],
		}
	}

	#[test]
	fn tags_land_before_the_head_closes() {
		let mut resp = html(200, b"<html><head><title>x</title></head><body>hi</body></html>");
		run(&inject(&[]), "https://example.com/", &mut resp);

		assert_eq!(
			String::from_utf8(resp.body).unwrap(),
			format!(
				"<html><head><title>x</title>{}</head><body>hi</body></html>",
				std::str::from_utf8(TAGS).unwrap()
			)
		);
	}

	#[test]
	fn a_shouted_head_tag_is_still_a_head_tag() {
		let mut resp = html(200, b"<HTML><HEAD></HEAD><BODY></BODY></HTML>");
		run(&inject(&[]), "https://example.com/", &mut resp);

		let body = String::from_utf8(resp.body).unwrap();

		assert!(body.contains(&format!(
			"{}</HEAD>",
			std::str::from_utf8(TAGS).unwrap()
		)));
	}

	#[test]
	fn a_page_with_no_head_falls_back_to_the_body_tag() {
		for page in [
			&b"<html><body>hi</body></html>"[..],
			&b"<html><body class=\"x\" id=y>hi</body></html>"[..],
			&b"<html><BODY\n>hi</body></html>"[..],
		] {
			let mut resp = html(200, page);
			run(&inject(&[]), "https://example.com/", &mut resp);

			let body = String::from_utf8(resp.body).unwrap();
			let at = body.find(std::str::from_utf8(TAGS).unwrap());

			assert!(at.is_some(), "{}", String::from_utf8_lossy(page));
			assert_eq!(
				&body[at.unwrap() - 1..at.unwrap()],
				">",
				"the tags go straight after the opening tag"
			);
		}
	}

	#[test]
	fn a_body_lookalike_is_not_the_body_tag() {
		let mut resp = html(200, b"<html><bodyguard></bodyguard><body>hi</body></html>");
		run(&inject(&[]), "https://example.com/", &mut resp);

		let body = String::from_utf8(resp.body).unwrap();

		assert!(body.starts_with("<html><bodyguard></bodyguard><body>"));
	}

	#[test]
	fn neither_tag_means_the_bytes_are_left_alone() {
		let original = b"<div>a fragment, or something mislabelled</div>".to_vec();
		let mut resp = html(200, &original);
		run(&inject(&[]), "https://example.com/", &mut resp);

		assert_eq!(resp.body, original);
	}

	#[test]
	fn a_page_that_already_has_the_script_is_untouched() {
		let mut original = Vec::from(&b"<html><head>"[..]);
		original.extend_from_slice(TAGS);
		original.extend_from_slice(b"</head><body></body></html>");

		let mut resp = html(200, &original);
		run(&inject(&[]), "https://example.com/", &mut resp);

		assert_eq!(resp.body, original);
	}

	/// A page is only ever *claimed* to be UTF-8. Splicing has to be a byte
	/// operation, or every byte the decoder gave up on comes back as U+FFFD.
	#[test]
	fn invalid_utf8_survives_the_splice() {
		let before = b"<html><head><meta name=\"x\" content=\"\xff\xfe caf\xe9\">";
		let after = b"</head><body>\x80\x81 \xc3\x28</body></html>";

		let mut original = Vec::from(&before[..]);
		original.extend_from_slice(&after[..]);

		let mut expected = Vec::from(&before[..]);
		expected.extend_from_slice(TAGS);
		expected.extend_from_slice(&after[..]);

		let mut resp = html(200, &original);
		run(&inject(&[]), "https://example.com/", &mut resp);

		assert_eq!(resp.body, expected);
		assert!(
			String::from_utf8(resp.body).is_err(),
			"the invalid bytes are still invalid, not replaced"
		);
	}

	#[test]
	fn only_a_html_page_is_claimed() {
		let inject = inject(&[]);
		let req = request("https://example.com/");

		assert!(inject.wants_body(&req, &head(200, "text/html; charset=utf-8")));
		assert!(inject.wants_body(&req, &head(200, "TEXT/HTML")));

		for content_type in [
			"application/json",
			"video/mp4",
			"text/plain",
			"application/xhtml+xml",
		] {
			assert!(
				!inject.wants_body(&req, &head(200, content_type)),
				"{content_type} must keep streaming"
			);
		}

		assert!(
			!inject.wants_body(
				&req,
				&ResponseHead {
					status: 200,
					headers: Vec::new(),
				}
			),
			"no content-type at all is not a page"
		);
	}

	#[test]
	fn only_a_200_is_claimed() {
		let inject = inject(&[]);
		let req = request("https://example.com/");

		for status in [204, 301, 304, 404, 500] {
			assert!(
				!inject.wants_body(&req, &head(status, "text/html")),
				"{status} must keep streaming"
			);
		}

		// And an error page is not rewritten even when it is buffered anyway.
		let mut resp = html(404, b"<html><head></head><body>gone</body></html>");
		run(&inject, "https://example.com/", &mut resp);

		assert_eq!(resp.body, b"<html><head></head><body>gone</body></html>");
	}

	#[test]
	fn an_excluded_host_is_left_alone() {
		let inject = inject(&["bank.example"]);
		let page = b"<html><head></head><body></body></html>";

		for url in [
			"https://bank.example/login",
			"https://secure.bank.example/login",
		] {
			let mut resp = html(200, page);
			run(&inject, url, &mut resp);

			assert_eq!(resp.body, page, "{url}");
			assert!(
				!inject.wants_body(&request(url), &head(200, "text/html")),
				"{url} should not even be buffered"
			);
		}

		let mut resp = html(200, page);
		run(&inject, "https://notbank.example/", &mut resp);

		assert_ne!(resp.body, page, "a substring is not a match");
	}
}
