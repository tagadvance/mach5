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
//! Where the tags go is decided by an HTML parser — Cloudflare's `lol_html` —
//! rather than by searching the bytes for `</head>`. Searching worked until it
//! did not: a `</head>` inside a comment, a script string or a `<textarea>` is
//! not the end of the head, and splicing there puts our tags in the middle of
//! somebody's JavaScript. A parser knows the difference, and it is the same
//! parser that makes the rest of the roadmap's HTML work possible at all.
//!
//! Encoding still matters, and is still not something to guess at. `lol_html`
//! is told the charset from the `content-type` header and works in it; when
//! that names something it cannot handle — a UTF-16 page, say — the body is
//! handed back exactly as it arrived rather than mangled into UTF-8.

use std::cell::Cell;
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;

use lol_html::html_content::ContentType;
use lol_html::{element, AsciiCompatibleEncoding, HtmlRewriter, Settings};

use crate::config::Config;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse, ResponseHead};

/// What gets spliced in. The stylesheet first, so it is already being fetched
/// while the parser reaches the script; `defer` so the picker runs after the
/// document is parsed and never blocks it.
const TAGS: &str =
	r#"<link rel="stylesheet" href="/.mach5/hidden.css"><script src="/.mach5/mach5.js" defer></script>"#;

/// Proof our tags are already there. Injecting twice would run the picker's
/// double-run guard for nothing and, worse, make a redirect chain or a
/// re-proxied page grow a tag per hop.
const MARKER: &[u8] = b"/.mach5/mach5.js";

/// Adds the tags to HTML pages.
pub struct Inject {
	exclude: HashSet<String>,
	metrics: Arc<crate::metrics::Metrics>,
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
			metrics: crate::metrics::shared(),
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

		// Counted here rather than beside `wants_body`: a page can be buffered,
		// looked at and left alone, and a count of what we considered injecting
		// would not be a count of what we injected.
		if let Some(rewritten) = rewrite(&resp.body, charset(&resp.headers)) {
			resp.body = rewritten;
			self.metrics.injected.increment();
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

/// Put the tags in the page, or hand it back unchanged.
///
/// `None` means nothing was injected: the tags are already there, the document
/// has neither a `<head>` nor a `<body>` to put them in, or its encoding is one
/// we will not risk rewriting.
fn rewrite(body: &[u8], charset: &str) -> Option<Vec<u8>> {
	if find_ascii(body, MARKER).is_some() {
		return None;
	}

	// Decided before anything is parsed: a page in an encoding the rewriter
	// cannot work in has to be left alone, not rewritten as though it were
	// UTF-8.
	let encoding = encoding_for(charset)?;

	// Shared because both handlers may run and only one may inject: `<head>`
	// closes before `<body>` opens, so by the time the fallback is reached the
	// answer is already known.
	let injected = Rc::new(Cell::new(false));
	let into_head = injected.clone();
	let into_body = injected.clone();

	let mut out = Vec::with_capacity(body.len() + TAGS.len());
	let settings = Settings::new()
		.with_encoding(encoding)
		.append_element_content_handler(element!("head", move |el| {
			// At the end of the head's content — which is what `</head>` meant,
			// back when it was the right `</head>`.
			el.append(TAGS, ContentType::Html);
			into_head.set(true);

			Ok(())
		}))
		.append_element_content_handler(element!("body", move |el| {
			if !into_body.get() {
				el.prepend(TAGS, ContentType::Html);
				into_body.set(true);
			}

			Ok(())
		}));

	let mut rewriter = HtmlRewriter::new(settings, |chunk: &[u8]| out.extend_from_slice(chunk));
	if rewriter.write(body).is_err() || rewriter.end().is_err() {
		// A document the parser refused. The origin's bytes are still correct,
		// which is more than can be said for a half-rewritten copy of them.
		log::debug!("could not parse a page as html; leaving it alone");

		return None;
	}

	injected.get().then_some(out)
}

/// The encoding to rewrite in, or `None` for one that cannot be rewritten
/// safely.
///
/// `lol_html` cannot work in UTF-16 or ISO-2022-JP, and a page declaring one of
/// those must come back untouched rather than reinterpreted. A label nobody
/// recognises is treated as UTF-8, which is what such a page almost always
/// turns out to be.
fn encoding_for(charset: &str) -> Option<AsciiCompatibleEncoding> {
	let Some(encoding) = encoding_rs::Encoding::for_label_no_replacement(charset.as_bytes()) else {
		return Some(AsciiCompatibleEncoding::utf_8());
	};

	AsciiCompatibleEncoding::new(encoding)
}

/// The charset the response declared, or UTF-8 when it declared none. Almost
/// every page is UTF-8; the ones that are not are usually explicit about it.
fn charset(headers: &[(String, String)]) -> &str {
	headers
		.iter()
		.find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
		.and_then(|(_, value)| value.split(';').find_map(|part| {
			let part = part.trim();
			part.strip_prefix("charset=")
				.or_else(|| part.strip_prefix("charset ="))
		}))
		.map(|charset| charset.trim().trim_matches('"'))
		.unwrap_or("utf-8")
}

/// First offset at which `needle` appears, comparing ASCII case-insensitively.
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
			metrics: Arc::new(crate::metrics::Metrics::default()),
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

	/// The reason this stopped being a byte search. A `</head>` inside a script
	/// string is not the end of the head, and splicing there lands the tags in
	/// the middle of somebody's JavaScript — a broken page, from a proxy whose
	/// whole job is not to break pages.
	#[test]
	fn a_head_end_inside_a_script_is_not_the_end_of_the_head() {
		let mut resp = html(
			200,
			br#"<html><head><script>var s = "</head>";</script><title>x</title></head><body>hi</body></html>"#,
		);
		run(&inject(&[]), "https://example.com/", &mut resp);

		let body = String::from_utf8(resp.body).unwrap();

		assert!(
			body.contains(&format!("<title>x</title>{TAGS}</head>")),
			"the tags belong at the real end of the head: {body}"
		);
		assert!(
			body.contains(r#"var s = "</head>";"#),
			"and the script must come through untouched: {body}"
		);
	}

	#[test]
	fn a_head_end_inside_a_comment_is_not_the_end_of_the_head() {
		let mut resp = html(
			200,
			b"<html><head><!-- </head> --><title>x</title></head><body>hi</body></html>",
		);
		run(&inject(&[]), "https://example.com/", &mut resp);

		let body = String::from_utf8(resp.body).unwrap();

		assert!(body.contains(&format!("<title>x</title>{TAGS}</head>")), "{body}");
	}

	/// The old scan looked for the first `>` after `<body`, which an attribute
	/// value can carry.
	#[test]
	fn a_body_attribute_containing_a_bracket_does_not_confuse_it() {
		let mut resp = html(200, br#"<html><body data-x="a > b">hi</body></html>"#);
		run(&inject(&[]), "https://example.com/", &mut resp);

		let body = String::from_utf8(resp.body).unwrap();

		assert!(
			body.contains(&format!(r#"<body data-x="a > b">{TAGS}hi"#)),
			"the tags go after the whole opening tag: {body}"
		);
	}

	/// A page mach5 cannot rewrite in the encoding it declares comes back
	/// exactly as it arrived. Reinterpreting it as UTF-8 would corrupt every
	/// character in it.
	#[test]
	fn a_page_in_an_encoding_we_cannot_rewrite_is_left_alone() {
		let original = b"<html><head></head><body>hi</body></html>".to_vec();
		let mut resp = ProxyResponse {
			status: 200,
			headers: vec![(
				"content-type".to_string(),
				"text/html; charset=utf-16le".to_string(),
			)],
			body: original.clone(),
		};
		run(&inject(&[]), "https://example.com/", &mut resp);

		assert_eq!(resp.body, original);
	}

	/// One that mach5 *can* rewrite: the high bytes are meaningful in this
	/// encoding and must survive being parsed and written back out.
	#[test]
	fn a_windows_1252_page_keeps_its_bytes() {
		// 0xA9 is © in windows-1252 and not valid UTF-8 on its own.
		let mut body = b"<html><head></head><body>caf\xe9 \xa9</body></html>".to_vec();
		body = body
			.iter()
			.copied()
			.flat_map(|b| if b == b'\\' { vec![] } else { vec![b] })
			.collect();
		let mut resp = ProxyResponse {
			status: 200,
			headers: vec![(
				"content-type".to_string(),
				"text/html; charset=windows-1252".to_string(),
			)],
			body,
		};
		run(&inject(&[]), "https://example.com/", &mut resp);

		assert!(
			resp.body.windows(2).any(|w| w == [0xe9, b' ']),
			"the high bytes are still the ones the origin sent"
		);
		assert!(resp.body.ends_with(b"</body></html>"));
	}

	#[test]
	fn the_declared_charset_is_read_out_of_the_content_type() {
		assert_eq!(charset(&[("content-type".to_string(), "text/html".to_string())]), "utf-8");
		assert_eq!(
			charset(&[(
				"Content-Type".to_string(),
				"text/html; charset=windows-1252".to_string()
			)]),
			"windows-1252"
		);
		assert_eq!(
			charset(&[("content-type".to_string(), "text/html;charset=\"utf-8\"".to_string())]),
			"utf-8",
			"quoted, as some origins write it"
		);
	}

	#[test]
	fn tags_land_before_the_head_closes() {
		let mut resp = html(200, b"<html><head><title>x</title></head><body>hi</body></html>");
		run(&inject(&[]), "https://example.com/", &mut resp);

		assert_eq!(
			String::from_utf8(resp.body).unwrap(),
			format!(
				"<html><head><title>x</title>{}</head><body>hi</body></html>",
				TAGS
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
			TAGS
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
			let at = body.find(TAGS);

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
		original.extend_from_slice(TAGS.as_bytes());
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
		expected.extend_from_slice(TAGS.as_bytes());
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

	/// The count is of pages that changed, so every reason not to splice — an
	/// excluded host, a page that already has the tags, a document with nowhere
	/// to put them — has to leave it alone.
	#[test]
	fn only_a_page_that_was_actually_changed_is_counted() {
		let inject = inject(&["bank.example"]);

		let mut resp = html(200, b"<html><head></head><body></body></html>");
		run(&inject, "https://example.com/", &mut resp);

		assert_eq!(inject.metrics.injected.get(), 1);

		// Already carrying the tags, so this pass changes nothing.
		run(&inject, "https://example.com/", &mut resp);

		let mut excluded = html(200, b"<html><head></head><body></body></html>");
		run(&inject, "https://bank.example/", &mut excluded);

		let mut fragment = html(200, b"<div>no head, no body</div>");
		run(&inject, "https://example.com/", &mut fragment);

		assert_eq!(inject.metrics.injected.get(), 1);
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
