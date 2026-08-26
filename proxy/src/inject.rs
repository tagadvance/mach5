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

use std::cell::{Cell, RefCell};
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

#[cfg(test)]
const MARKER_STR: &str = "/.mach5/mach5.js";

/// Adds the tags to HTML pages.
pub struct Inject {
	exclude: HashSet<String>,
	settings: Arc<crate::settings::Store>,
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
			settings: crate::settings::shared(config),
			metrics: crate::metrics::shared(),
		}
	}

	fn excluded(&self, req: &ProxyRequest) -> bool {
		// Switched off from the panel counts as excluded everywhere, which is
		// what somebody debugging a site is asking for.
		self.settings.get().inject == crate::settings::Injection::Off
			|| crate::blocklist::covers(&self.exclude, crate::host_of(&req.url))
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

	/// Nothing any more. Injection used to hold every HTML page in memory to
	/// splice into it, which cost the client the whole of the origin's
	/// generation time before it saw a byte. The rewriting now happens on the
	/// way past — see [`Streamer`] — so this claims nothing and `on_response`
	/// above only runs when something *else* wanted the body buffered.
	fn wants_body(&self, _req: &ProxyRequest, _head: &ResponseHead) -> bool {
		false
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

/// Whether this response should be rewritten as it streams, and the thing to
/// do it with.
///
/// A free function because the front ends reach it from the streaming path,
/// where they hold a configuration and not a chain. The exclusion list is
/// worked out once per process rather than per response.
pub fn streamer_for(
	config: &Config,
	req: &ProxyRequest,
	head: &mut ResponseHead,
) -> Option<Streamer> {
	if !config.inject.enabled {
		return None;
	}

	let inject = shared(config);
	if !claims(head.status, &head.headers) || inject.excluded(req) {
		return None;
	}

	// A page the origin sent in the clear is compressed on its way out, which
	// the buffered path used to do and this one has to do for itself. Decided
	// here rather than inside the streamer because the headers have to say so
	// before the head is sent, and the head goes out first.
	let output = match crate::encoding::coding_of(&head.headers) {
		Some(coding) => Some(coding),
		None if config.http.compress => {
			crate::encoding::streaming_coding(&req.headers, &head.headers)
		}
		None => None,
	};

	let streamer = Streamer::new(
		&head.headers,
		Lazy {
			enabled: config.inject.lazy_images,
			eager: config.inject.eager_images,
		},
		output,
		config.stream_buffer_bytes(),
	)?;

	if crate::encoding::coding_of(&head.headers).is_none() {
		if let Some(coding) = output {
			crate::encoding::declare_coding(&mut head.headers, coding);
		}
	}

	Some(streamer)
}

/// One set of exclusions for the process, as with everything else built per
/// chain.
pub fn shared(config: &Config) -> Arc<Inject> {
	static SHARED: std::sync::OnceLock<Arc<Inject>> = std::sync::OnceLock::new();

	SHARED.get_or_init(|| Arc::new(Inject::new(config))).clone()
}

/// How to treat a page's images.
#[derive(Debug, Clone, Copy)]
pub struct Lazy {
	pub enabled: bool,
	/// How many to leave alone at the top of the document.
	pub eager: usize,
}

/// Mark one image as deferrable, unless it is one of the first — or unless the
/// author already said what they wanted.
///
/// The reason for `eager` is that lazy-loading the image someone came to see
/// makes the page slower, not faster: it is the documented way to ruin Largest
/// Contentful Paint. A streaming parser sees elements in document order, so
/// "the first few" is simply the first few this handler is called for.
///
/// An author who wrote `loading` or `fetchpriority` has already thought about
/// this, and is not to be argued with.
fn defer(el: &mut lol_html::html_content::Element, seen: &Rc<Cell<usize>>, lazy: Lazy) {
	let nth = seen.get();
	seen.set(nth + 1);

	if !lazy.enabled || nth < lazy.eager {
		return;
	}

	if el.get_attribute("loading").is_some() || el.get_attribute("fetchpriority").is_some() {
		return;
	}

	let _ = el.set_attribute("loading", "lazy");

	// Free while we are here, and for the same reason: decoding off the main
	// thread is only ever a gain for something not being looked at yet.
	if el.get_attribute("decoding").is_none() {
		let _ = el.set_attribute("decoding", "async");
	}
}

/// Rewriting a page as it arrives, rather than after it has all arrived.
///
/// The reason this exists: buffering an HTML page means the client waits for
/// the origin to finish generating it before receiving a single byte. Measured
/// against an origin taking 1.2 seconds to produce a page, that moved
/// time-to-first-byte from 46ms to 1,258ms — the browser cannot start parsing,
/// cannot start fetching subresources, and shows nothing.
///
/// `lol_html` is a streaming parser, so the whole path can be push-based:
/// encoded bytes in, decoded, rewritten, re-encoded, out. The cost is a flush
/// per chunk on the encoder, which gives up a little ratio for the whole of the
/// latency.
pub struct Streamer {
	decoder: Option<crate::encoding::Decoder>,
	/// The most one chunk may inflate to. A compressed chunk says nothing about
	/// how much comes out of it, and a page always takes this path.
	inflate_limit: usize,
	encoder: Option<crate::encoding::Encoder>,
	rewriter: HtmlRewriter<'static, Sink>,
	out: Rc<RefCell<Vec<u8>>>,
	state: State,
}

/// What is still working.
///
/// The distinction that matters: the *rewriter* giving up is recoverable, and
/// the *decoder* giving up is not. The head has already gone out declaring a
/// coding, so every byte after it must be under that coding — which means a
/// give-up may stop rewriting but must never stop encoding.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
	Rewriting,
	/// The parser gave up. Bytes are still decoded and re-encoded, so the
	/// coding the head promised stays true; they are simply not rewritten.
	PassingThrough,
	/// The decoder gave up. Nothing further can be decoded, so nothing further
	/// can be re-encoded, so the body ends here — with the coding closed
	/// properly, which is the difference between a short page and an
	/// unreadable one.
	Stopped,
}

/// Where `lol_html` puts what it has finished with.
type Sink = Box<dyn FnMut(&[u8])>;

impl Streamer {
	/// `None` when this response is not one to rewrite on the fly, in which
	/// case the caller relays it as it always did.
	pub fn new(
		response_headers: &[(String, String)],
		lazy: Lazy,
		output: Option<crate::encoding::Coding>,
		inflate_limit: usize,
	) -> Option<Self> {
		let coding = crate::encoding::coding_of(response_headers);
		// A coding named but not understood cannot be decoded, so the bytes
		// cannot be parsed, so there is nothing to do but pass them through.
		if coding.is_none() && has_content_encoding(response_headers) {
			return None;
		}

		let encoding = encoding_for(charset(response_headers))?;
		let out = Rc::new(RefCell::new(Vec::new()));
		let injected = Rc::new(Cell::new(false));
		let into_head = injected.clone();
		let into_body = injected;

		// Counted across the document, which a streaming parser gives for free:
		// handlers fire in the order the elements appear.
		let seen = Rc::new(Cell::new(0usize));

		// Counted where it happens rather than where it was considered: the
		// buffered path counts in `on_response`, and a streamed page never goes
		// through it.
		let counted = crate::metrics::shared();
		let also_counted = counted.clone();

		let sink = out.clone();
		let settings = Settings::new()
			.with_encoding(encoding)
			.append_element_content_handler(element!("head", move |el| {
				el.append(TAGS, ContentType::Html);
				into_head.set(true);
				counted.injected.increment();

				Ok(())
			}))
			.append_element_content_handler(element!("body", move |el| {
				if !into_body.get() {
					el.prepend(TAGS, ContentType::Html);
					into_body.set(true);
					also_counted.injected.increment();
				}

				Ok(())
			}))
			.append_element_content_handler(element!("img", move |el| {
				defer(el, &seen, lazy);

				Ok(())
			}));

		Some(Self {
			// What arrived and what leaves are separate decisions: a page sent
			// in the clear is compressed on the way out, and one that arrived
			// compressed keeps the coding it came in.
			decoder: coding.map(crate::encoding::Decoder::new),
			inflate_limit,
			encoder: output.map(crate::encoding::Encoder::new),
			rewriter: HtmlRewriter::new(
				settings,
				Box::new(move |chunk: &[u8]| sink.borrow_mut().extend_from_slice(chunk)) as Sink,
			),
			out,
			state: State::Rewriting,
		})
	}

	/// One chunk in, whatever is ready to send out.
	pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
		if self.state == State::Stopped {
			return Vec::new();
		}

		let plain = match self.decoder.as_mut() {
			Some(decoder) => match decoder.push(chunk, self.inflate_limit) {
				Ok(plain) => plain,
				Err(e) => {
					log::debug!("no longer reading this page: {e}");
					self.state = State::Stopped;

					return Vec::new();
				}
			},
			None => chunk.to_vec(),
		};

		if self.state == State::Rewriting {
			if self.rewriter.write(&plain).is_err() {
				log::debug!("no longer rewriting this page: the parser refused the document");
				self.state = State::PassingThrough;
				// Whatever this chunk left in the sink is a prefix of the very
				// bytes about to be sent in full, so it goes in the bin rather
				// than out twice. What is lost is only what the parser was
				// still holding back from earlier chunks — at most a partial
				// token, and never the rest of the document.
				self.out.borrow_mut().clear();

				return self.encode(&plain);
			}

			let rewritten = std::mem::take(&mut *self.out.borrow_mut());

			return self.encode(&rewritten);
		}

		self.encode(&plain)
	}

	/// The end of the body: flush the parser and close the coding.
	pub fn finish(self) -> Vec<u8> {
		let plain = if self.state == State::Rewriting {
			let _ = self.rewriter.end();

			std::mem::take(&mut *self.out.borrow_mut())
		} else {
			Vec::new()
		};

		// Reached even when nothing is left to send: an encoder that is never
		// finished leaves the client a stream it cannot inflate, whatever the
		// reason it stopped early.
		let Some(mut encoder) = self.encoder else {
			return plain;
		};

		let mut out = encoder.push(&plain).unwrap_or_default();
		out.extend(encoder.finish().unwrap_or_default());

		out
	}

	fn encode(&mut self, plain: &[u8]) -> Vec<u8> {
		match self.encoder.as_mut() {
			Some(encoder) => encoder.push(plain).unwrap_or_default(),
			None => plain.to_vec(),
		}
	}
}

fn has_content_encoding(headers: &[(String, String)]) -> bool {
	headers
		.iter()
		.any(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn inject(exclude: &[&str]) -> Inject {
		Inject {
			exclude: exclude.iter().map(|host| host.to_string()).collect(),
			settings: Arc::new(crate::settings::Store::load(
				std::env::temp_dir().join("mach5-inject-test-settings.json"),
			)),
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

	fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
		pairs
			.iter()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect()
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

	/// Push a whole document through the streamer in one go, which is what the
	/// front ends do a chunk at a time.
	fn stream(html: &[u8], lazy: Lazy) -> String {
		let mut streamer =
			Streamer::new(&headers(&[("content-type", "text/html")]), lazy, None, NO_LIMIT)
				.expect("a page");
		let mut out = streamer.push(html);
		out.extend(streamer.finish());

		String::from_utf8(out).expect("utf-8 in, utf-8 out")
	}

	/// For the tests that are about rewriting rather than about the bomb guard.
	const NO_LIMIT: usize = usize::MAX;

	fn lazily() -> Lazy {
		Lazy {
			enabled: true,
			eager: 2,
		}
	}

	fn gzipped(plain: &[u8]) -> Vec<u8> {
		use std::io::Write;

		let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
		e.write_all(plain).expect("gzip");

		e.finish().expect("gzip")
	}

	/// One gzip stream, handed over in two pieces with a flush between them so
	/// the first piece decodes on its own — which is what arriving over a
	/// network looks like, and what two separate members would not be.
	fn gzipped_in_two(first: &[u8], rest: &[u8]) -> (Vec<u8>, Vec<u8>) {
		use std::io::Write;

		let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
		e.write_all(first).expect("gzip");
		e.flush().expect("gzip");
		let head = std::mem::take(e.get_mut());
		e.write_all(rest).expect("gzip");

		(head, e.finish().expect("gzip"))
	}

	fn gunzip(coded: &[u8]) -> Vec<u8> {
		use std::io::Read;

		let mut out = Vec::new();
		flate2::read::GzDecoder::new(coded)
			.read_to_end(&mut out)
			.expect("the client has to be able to inflate what it was sent");

		out
	}

	/// A streamer that decodes gzip in and re-encodes gzip out, which is what
	/// every real origin negotiates.
	fn coded_streamer() -> Streamer {
		Streamer::new(
			&headers(&[
				("content-type", "text/html"),
				("content-encoding", "gzip"),
			]),
			lazily(),
			Some(crate::encoding::Coding::Gzip),
			NO_LIMIT,
		)
		.expect("a page")
	}

	/// The head went out saying `content-encoding: gzip`, so every byte after
	/// it is gzip whatever happens next. Handing the client plaintext because
	/// the parser gave up is a page it cannot read at all — strictly worse than
	/// the un-injected page the give-up was trying to save.
	#[test]
	fn a_page_the_parser_gives_up_on_stays_under_the_declared_coding() {
		let mut streamer = coded_streamer();

		// `<script>` inside `<select>` is the documented case lol_html refuses
		// to guess at: it cannot tell whether what follows is markup or text.
		let (first, rest) = gzipped_in_two(
			b"<html><head></head><body><p>before</p>",
			b"<select><script>x</script></select><p>after</p></body></html>",
		);

		let mut out = streamer.push(&first);
		out.extend(streamer.push(&rest));
		out.extend(streamer.finish());

		let page = String::from_utf8(gunzip(&out)).expect("utf-8");
		assert!(
			page.contains(MARKER_STR),
			"what was injected before the give-up still stands: {page}"
		);
		assert!(
			page.contains("<p>before</p>"),
			"and so does the document up to it: {page}"
		);
		assert!(
			page.contains("<p>after</p>"),
			"the rest of the page still reaches the client: {page}"
		);
		assert_eq!(
			page.matches("<p>after</p>").count(),
			1,
			"exactly once — a give-up must not send the same bytes twice: {page}"
		);
	}

	/// A page always takes the streaming path — HTML is never cacheable — so
	/// `decode`'s ceiling never applies to one. A compressed chunk says nothing
	/// about how much comes out of it, and without a bound here a single 64KB
	/// chunk of a bomb is hundreds of megabytes, per concurrent stream.
	#[test]
	fn a_chunk_that_inflates_past_the_limit_stops_the_body() {
		let bomb = {
			use std::io::Write;

			let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
			e.write_all(&vec![b' '; 8 * 1024 * 1024]).expect("gzip");

			e.finish().expect("gzip")
		};
		assert!(bomb.len() < 64 * 1024, "the point is the ratio: {}", bomb.len());

		let mut streamer = Streamer::new(
			&headers(&[("content-type", "text/html"), ("content-encoding", "gzip")]),
			lazily(),
			Some(crate::encoding::Coding::Gzip),
			256 * 1024,
		)
		.expect("a page");

		let mut out = streamer.push(&bomb);
		out.extend(streamer.finish());

		// Refused, and the coding still closed — a client that cannot inflate
		// what it was sent throws the whole page away.
		let page = gunzip(&out);
		assert!(
			page.len() <= 256 * 1024 + 8 * 1024,
			"it stopped at the limit rather than holding all eight megabytes: {}",
			page.len()
		);
	}

	/// A body that stops decoding cannot be re-encoded, so it ends there. What
	/// it must not do is end *open*: an unfinished gzip stream is a page the
	/// client throws away entirely, rather than a short one it renders.
	#[test]
	fn a_body_that_stops_decoding_still_closes_the_coding() {
		let mut streamer = coded_streamer();

		let mut out = streamer.push(&gzipped(b"<html><head></head><body><p>all there is</p>"));
		// A second member that is not one. Trailing bytes after a complete
		// member are the real-world shape of this.
		out.extend(streamer.push(b"\x1f\x8b\x08not gzip at all"));
		out.extend(streamer.push(&gzipped(b"<p>never seen</p>")));
		out.extend(streamer.finish());

		let page = String::from_utf8(gunzip(&out)).expect("utf-8");
		assert!(
			page.contains(MARKER_STR),
			"what decoded is intact and injected: {page}"
		);
		assert!(
			page.contains("<p>all there is</p>"),
			"and complete up to the failure: {page}"
		);
		assert!(
			!page.contains("never seen"),
			"nothing after it can be trusted to be html: {page}"
		);
	}

	/// The plain case, kept honest alongside the two failure ones: nothing goes
	/// wrong, and the coding still closes.
	#[test]
	fn a_coded_page_that_parses_is_rewritten_and_re_encoded() {
		let mut streamer = coded_streamer();

		let mut out = streamer.push(&gzipped(b"<html><head></head><body><p>hi</p></body></html>"));
		out.extend(streamer.finish());

		let page = String::from_utf8(gunzip(&out)).expect("utf-8");
		assert!(page.contains(MARKER_STR), "{page}");
		assert!(page.contains("<p>hi</p>"), "{page}");
	}

	#[test]
	fn images_past_the_first_few_are_deferred() {
		let page = stream(
			b"<html><body><img src=1><img src=2><img src=3><img src=4></body></html>",
			lazily(),
		);

		assert_eq!(
			page.matches("loading=\"lazy\"").count(),
			2,
			"the first two stay eager: {page}"
		);
		assert!(
			page.contains(r#"<img src=1><img src=2><img src=3 loading="lazy""#),
			"and it is the first two, in document order: {page}"
		);
		assert!(
			page.contains("<img src=1><img src=2>"),
			"the author's own markup is left as it was written: {page}"
		);
	}

	/// Lazy-loading the image someone came to see is the documented way to ruin
	/// Largest Contentful Paint, and the top of the document is where it is.
	#[test]
	fn the_top_of_the_page_is_left_alone() {
		let page = stream(b"<html><body><img src=hero></body></html>", lazily());

		assert!(!page.contains("loading"), "{page}");
	}

	#[test]
	fn an_author_who_already_decided_is_not_argued_with() {
		let page = stream(
			br#"<html><body><img src=1><img src=2><img src=3 loading="eager"><img src=4 fetchpriority="high"></body></html>"#,
			lazily(),
		);

		assert!(page.contains(r#"loading="eager""#), "{page}");
		assert!(
			!page.contains(r#"loading="lazy""#),
			"neither of the last two is ours to change: {page}"
		);
	}

	#[test]
	fn deferring_can_be_switched_off() {
		let page = stream(
			b"<html><body><img src=1><img src=2><img src=3></body></html>",
			Lazy {
				enabled: false,
				eager: 0,
			},
		);

		assert!(!page.contains("loading"), "{page}");
	}

	#[test]
	fn a_deferred_image_also_decodes_off_the_main_thread() {
		let page = stream(
			br#"<html><body><img src=1><img src=2><img src=3><img src=4 decoding="sync"></body></html>"#,
			lazily(),
		);

		assert!(page.contains(r#"src=3 loading="lazy" decoding="async""#), "{page}");
		assert!(
			page.contains(r#"decoding="sync""#),
			"and an author's own choice survives: {page}"
		);
	}

	#[test]
	fn only_a_html_page_is_rewritten() {
		for content_type in ["text/html; charset=utf-8", "TEXT/HTML"] {
			assert!(
				Streamer::new(&headers(&[("content-type", content_type)]), lazily(), None, NO_LIMIT)
					.is_some(),
				"{content_type} is a page"
			);
		}

		// Not a raster, not a page, and in one case a document type this does
		// not claim to understand.
		for content_type in [
			"application/json",
			"video/mp4",
			"text/plain",
			"application/xhtml+xml",
		] {
			assert!(
				!claims(200, &headers(&[("content-type", content_type)])),
				"{content_type} must pass through untouched"
			);
		}

		assert!(
			!claims(200, &[]),
			"no content-type at all is not a page"
		);
	}

	/// Injection stopped holding pages in memory: that is what cost the client
	/// the origin's whole generation time before it saw a byte.
	#[test]
	fn nothing_is_held_in_memory_to_inject_into_it() {
		let inject = inject(&[]);
		let req = request("https://example.com/");

		assert!(
			!inject.wants_body(&req, &head(200, "text/html")),
			"a page is rewritten on the way past now"
		);
	}

	#[test]
	fn only_a_200_is_claimed() {
		let inject = inject(&[]);
		let req = request("https://example.com/");

		for status in [204, 301, 304, 404, 500] {
			assert!(
				!claims(status, &headers(&[("content-type", "text/html")])),
				"{status} must pass through untouched"
			);
		}
		let _ = &req;

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
