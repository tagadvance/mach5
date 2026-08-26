//! Not fetching the same image twice.
//!
//! The conversion cache is addressed by content, so the bytes have to be in
//! hand before it can help — every repeat still cost a full download. On a
//! gigabit line that is free; on a cloud container it is billed.
//!
//! What this does is **not** "cache it and stop asking". It is the ordinary
//! shared-cache behaviour of RFC 9111, restricted to images:
//!
//! - An entry still fresh by the origin's own `max-age` is served with no
//!   request at all.
//! - A stale one is revalidated with `if-none-match` / `if-modified-since`. A
//!   `304` is a couple of hundred bytes where the image was three hundred
//!   thousand, so the transfer collapses either way — and nothing is ever
//!   served staler than the origin said it could be.
//!
//! [`eligible`] is the part that matters. Anything that is not plainly a public
//! image is not cached at all, rather than cached carefully: a response that
//! sets a cookie, says `private`, or varies on anything but the two headers we
//! key on is left alone. The request half matters too — an `authorization`
//! header means this body was for one person.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::interceptor::{ProxyRequest, ProxyResponse};

/// The two request headers an entry may be keyed on, and so the only two an
/// origin may `vary` on and still be cached.
const KEYED_ON: [&str; 2] = ["accept", "accept-encoding"];

/// What is stored beside a body: enough to know whether it may still be served,
/// and how to ask the origin cheaply if it may not.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Entry {
	pub status: u16,
	pub headers: Vec<(String, String)>,
	/// Unix seconds after which this must be revalidated. Equal to `stored` for
	/// a response with a validator but no freshness of its own.
	pub fresh_until: u64,
	pub etag: Option<String>,
	pub last_modified: Option<String>,
}

impl Entry {
	pub fn is_fresh(&self, now: u64) -> bool {
		now < self.fresh_until
	}

	/// Whether the origin gave us anything to revalidate with. Without one, a
	/// stale entry is only good for throwing away.
	pub fn can_revalidate(&self) -> bool {
		self.etag.is_some() || self.last_modified.is_some()
	}
}

/// Whether this exchange may be stored at all.
///
/// Deliberately a wall of refusals. Every one of them is a way a body could
/// belong to one person rather than to everybody, and the cost of being wrong
/// is serving somebody else's bytes.
pub fn eligible(req: &ProxyRequest, status: u16, headers: &[(String, String)]) -> bool {
	if status != 200 {
		return false;
	}

	// GET or nothing. A HEAD carries the same headers as the GET it stands in
	// for — content-type, etag, a freshness lifetime — and every test below
	// passes on them, but its body is empty by definition. Stored under a key
	// that does not mention the method, that empty body is what the next GET
	// for the same URL is served. One `curl -I` was enough to blank an asset
	// for as long as the origin said to keep it.
	if !req.method.eq_ignore_ascii_case("GET") {
		return false;
	}

	// Whose request this was, rather than what came back.
	if header(&req.headers, "authorization").is_some() {
		return false;
	}

	let kind = kind(headers);
	if kind == Kind::Other {
		return false;
	}

	// The origin saying, in the plainest way it has, that this was for one
	// person.
	if header(headers, "set-cookie").is_some() {
		return false;
	}

	let control = joined(headers, "cache-control").to_ascii_lowercase();
	if ["private", "no-store", "no-cache"]
		.iter()
		.any(|forbidden| control.contains(forbidden))
	{
		return false;
	}

	// `vary: cookie` is an origin saying this differs per user — which is the
	// useful half of "is this a session", and far better than guessing from a
	// session cookie on the request, since a signed-in visitor still gets the
	// same public logo as everybody else.
	let vary = joined(headers, "vary");
	if !vary.is_empty() {
		let all_keyed = vary.split(',').all(|name| {
			let name = name.trim().to_ascii_lowercase();

			KEYED_ON.contains(&name.as_str())
		});
		// `*` is not in KEYED_ON, so this covers it too.
		if !all_keyed {
			return false;
		}
	}

	// Something to go on, in proportion to what being wrong would cost.
	//
	// Plenty of small sites set no cache headers at all — which is much of why
	// mach5 exists — so demanding a freshness lifetime everywhere would cache
	// nothing for exactly the origins that need the help. The answer is to ask
	// for more proof only where a mistake is expensive.
	let validated =
		header(headers, "etag").is_some() || header(headers, "last-modified").is_some();

	match kind {
		// Never personalised, and a mistake is the wrong picture or the wrong
		// typeface.
		Kind::Static | Kind::Style => freshness(headers).is_some() || validated,
		// The one that carries user ids and CSRF tokens. Either the origin says
		// out loud how long this is good for — which is a claim about everybody,
		// not about this request — or the filename carries a content hash,
		// which nobody puts on a file built per user.
		Kind::Script => {
			freshness(headers).is_some()
				|| (validated && looks_fingerprinted(&req.url))
		}
		Kind::Other => false,
	}
}

/// How long the origin said this stays good for, in seconds.
///
/// `s-maxage` first, since that is the one addressed to a shared cache, which
/// is what mach5 is.
pub fn freshness(headers: &[(String, String)]) -> Option<Duration> {
	let control = joined(headers, "cache-control").to_ascii_lowercase();

	for directive in ["s-maxage=", "max-age="] {
		if let Some(seconds) = control
			.split(',')
			.find_map(|part| part.trim().strip_prefix(directive))
			.and_then(|value| value.trim().parse::<u64>().ok())
		{
			return Some(Duration::from_secs(seconds));
		}
	}

	None
}

/// What may be cached at all: the static furniture of a page. Everything here
/// is something a site serves identically to everybody, or says it does.
///
/// HTML is deliberately absent and should stay absent until mach5 knows who is
/// asking. A page is where per-user content lives.
const SCRIPTS: [&str; 3] = [
	"application/javascript",
	"text/javascript",
	"application/x-javascript",
];

/// The `font/*` types are caught by prefix; these are the older spellings.
const FONTS: [&str; 3] = [
	"application/font-woff",
	"application/vnd.ms-fontobject",
	"application/x-font-ttf",
];

/// The kind of thing this is, which decides how much proof of publicness is
/// wanted before storing it.
///
/// Not all assets are equally risky, and treating them as if they were would
/// mean caching nothing for exactly the small sites that set no cache headers
/// and most need the help.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Kind {
	/// Images and fonts. Neither is ever personalised — a font is a build
	/// artifact — and the worst a mistake costs is the wrong picture.
	Static,
	/// A stylesheet. Personalised ones exist but are rare, and being wrong
	/// about one is cosmetic rather than a leaked credential.
	Style,
	/// A script. The one that carries user ids, CSRF tokens and API keys.
	Script,
	Other,
}

fn kind(headers: &[(String, String)]) -> Kind {
	let Some(value) = header(headers, "content-type") else {
		return Kind::Other;
	};

	let media = value
		.split(';')
		.next()
		.unwrap_or_default()
		.trim()
		.to_ascii_lowercase();

	if media.starts_with("image/") || media.starts_with("font/") || FONTS.contains(&media.as_str())
	{
		return Kind::Static;
	}

	if media == "text/css" {
		return Kind::Style;
	}

	if SCRIPTS.contains(&media.as_str()) {
		return Kind::Script;
	}

	Kind::Other
}

/// Whether the last path segment carries what looks like a content hash —
/// `app.a1b2c3d4.js`, `main-4f3a9c2e.css`.
///
/// A strong signal that something is a shared build artifact: the whole point
/// of fingerprinting is that the name changes when the bytes do, which is
/// nonsense for a file built per user. Nobody fingerprints `config.js`.
///
/// Deliberately narrow. A segment has to be long, has to mix letters and
/// digits, and has to be all hex or all lowercase alphanumeric — because the
/// cost of calling something a build artifact when it is somebody's session is
/// the whole point of the rules around it.
fn looks_fingerprinted(url: &str) -> bool {
	let path = url.split(['?', '#']).next().unwrap_or(url);
	let Some(file) = path.rsplit('/').next() else {
		return false;
	};

	file.split(['.', '-', '_']).any(|segment| {
		let long_enough = (8..=64).contains(&segment.len());
		let mixed = segment.chars().any(|c| c.is_ascii_digit())
			&& segment.chars().any(|c| c.is_ascii_alphabetic());
		let plausible = segment
			.chars()
			.all(|c| c.is_ascii_digit() || c.is_ascii_lowercase());

		long_enough && mixed && plausible
	})
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
	headers
		.iter()
		.find(|(header, _)| header.eq_ignore_ascii_case(name))
		.map(|(_, value)| value.as_str())
}

/// Every value for a header, combined the way RFC 9110 §5.3 says a recipient
/// may: a list-valued field sent as several lines means exactly what one line
/// with the values joined by commas would.
///
/// Reading only the first is how a second `cache-control: private` or a second
/// `vary: cookie` goes unnoticed — and this is the wall that decides whether a
/// response belongs to everybody, so it must see all of what the origin said,
/// not the part of it that happened to be sent first.
fn joined(headers: &[(String, String)], name: &str) -> String {
	headers
		.iter()
		.filter(|(header, _)| header.eq_ignore_ascii_case(name))
		.map(|(_, value)| value.trim())
		.collect::<Vec<_>>()
		.join(", ")
}

/// What the *client* asked for, which RFC 9111 gives it a say in and which
/// nothing about response freshness covers.
///
/// This is what a browser's hard refresh is: shift-reload sends
/// `cache-control: no-cache`, and older clients send `pragma: no-cache`. A
/// cache that ignores it takes away the one escape hatch everybody already
/// knows, so mach5 honours it — `no-cache` means revalidate before serving,
/// `no-store` means do not consult it at all.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ClientWants {
	Anything,
	Revalidated,
	Nothing,
}

pub fn client_wants(req: &ProxyRequest) -> ClientWants {
	let control = joined(&req.headers, "cache-control").to_ascii_lowercase();
	let pragma = joined(&req.headers, "pragma").to_ascii_lowercase();

	if control.contains("no-store") {
		return ClientWants::Nothing;
	}

	if control.contains("no-cache") || pragma.contains("no-cache") {
		return ClientWants::Revalidated;
	}

	ClientWants::Anything
}

pub fn now() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|since| since.as_secs())
		.unwrap_or(0)
}

/// What an entry is filed under: the URL, plus the request headers the origin
/// is allowed to vary on. Both, because an origin serving WebP to some clients
/// and JPEG to others is serving two different bodies from one URL.
pub fn key(req: &ProxyRequest) -> String {
	let mut material = req.url.clone();
	for name in KEYED_ON {
		material.push('\n');
		material.push_str(header(&req.headers, name).unwrap_or_default());
	}

	let digest = boring::sha::sha256(material.as_bytes());
	let mut name = String::with_capacity(64);
	for byte in digest {
		name.push_str(&format!("{byte:02x}"));
	}

	name
}

/// Bodies and their metadata on disk.
pub struct Cache {
	dir: PathBuf,
	budget: u64,
	since_sweep: std::sync::atomic::AtomicUsize,
	metrics: Arc<crate::metrics::Metrics>,
}

const SWEEP_EVERY: usize = 200;

impl Cache {
	pub fn new(config: &Config) -> Option<Self> {
		let budget = config.images.origin_cache_mb as u64 * 1024 * 1024;
		if budget == 0 {
			return None;
		}

		let dir = config.paths.cache_dir.join("origins");
		if let Err(e) = std::fs::create_dir_all(&dir) {
			log::warn!("no origin cache: cannot use {}: {e}", dir.display());

			return None;
		}

		let cache = Self {
			dir,
			budget,
			since_sweep: std::sync::atomic::AtomicUsize::new(0),
			metrics: crate::metrics::shared(),
		};
		crate::disk::sweep(&cache.dir, cache.budget);

		Some(cache)
	}

	pub fn get(&self, key: &str) -> Option<(Entry, Vec<u8>)> {
		let entry: Entry =
			serde_json::from_slice(&std::fs::read(self.dir.join(format!("{key}.meta"))).ok()?)
				.ok()?;
		let body = std::fs::read(self.dir.join(format!("{key}.body"))).ok()?;

		Some((entry, body))
	}

	pub fn put(&self, key: &str, entry: &Entry, body: &[u8]) {
		let Ok(meta) = serde_json::to_vec(entry) else {
			return;
		};

		// Written beside and renamed, both of them, because these paths are
		// live: every 304 re-puts an entry that readers on other threads may
		// be part-way through. A plain write truncates first, so a reader can
		// come back with half a stylesheet — and it would be served as a
		// well-formed 200, since the framing is recomputed from what was read.
		//
		// The body first, so a reader that finds the metadata always finds
		// something to go with it.
		if crate::disk::replace(&self.dir.join(format!("{key}.body")), body).is_err() {
			return;
		}
		if crate::disk::replace(&self.dir.join(format!("{key}.meta")), &meta).is_err() {
			let _ = std::fs::remove_file(self.dir.join(format!("{key}.body")));

			return;
		}

		use std::sync::atomic::Ordering;
		if self.since_sweep.fetch_add(1, Ordering::Relaxed) + 1 >= SWEEP_EVERY {
			self.since_sweep.store(0, Ordering::Relaxed);
			crate::disk::sweep(&self.dir, self.budget);
		}
	}

	/// Forget one entry outright.
	///
	/// The metadata goes first: an entry whose body is missing is a miss, so
	/// the window between the two removals never serves anything, while the
	/// other order would leave metadata pointing at nothing.
	pub fn forget(&self, key: &str) {
		let _ = std::fs::remove_file(self.dir.join(format!("{key}.meta")));
		let _ = std::fs::remove_file(self.dir.join(format!("{key}.body")));
	}

	pub fn metrics(&self) -> &crate::metrics::Metrics {
		&self.metrics
	}
}

/// One per process, as with everything else built per chain.
pub fn shared(config: &Config) -> Option<Arc<Cache>> {
	static SHARED: std::sync::OnceLock<Option<Arc<Cache>>> = std::sync::OnceLock::new();

	SHARED.get_or_init(|| Cache::new(config).map(Arc::new)).clone()
}

/// Build what to store from a response that [`eligible`] has already approved.
pub fn entry_for(status: u16, headers: &[(String, String)], stored: u64) -> Entry {
	// `max-age` counts from when the response was *generated*, not from when it
	// got here, and `age` is the hop count in seconds that says how far apart
	// those are (RFC 9111 §4.2.3). Ignoring it gave a CDN object that arrived
	// with `max-age=300, age=295` a fresh 300 seconds here — nearly twice the
	// life the origin allowed, and doubling again for anything downstream that
	// reads the same frozen `age` back out of the stored headers.
	let lifetime = freshness(headers)
		.map(|d| d.as_secs().saturating_sub(age(headers)))
		.unwrap_or(0);

	Entry {
		status,
		fresh_until: stored.saturating_add(lifetime),
		etag: header(headers, "etag").map(str::to_string),
		last_modified: header(headers, "last-modified").map(str::to_string),
		headers: headers.to_vec(),
	}
}

/// How long this response had already been alive when it arrived, in seconds.
fn age(headers: &[(String, String)]) -> u64 {
	header(headers, "age")
		.and_then(|value| value.trim().parse::<u64>().ok())
		.unwrap_or(0)
}

/// Fold a 304's headers into the ones already stored, as RFC 9111 §4.3.4
/// requires.
///
/// This is the only way an origin can change its mind about something it has
/// already handed out: shorten a lifetime, add a `vary`, or take back
/// permission to store it at all. Re-applying the stored headers instead — as
/// this did — meant an entry could never be withdrawn and its clock was reset
/// to a full lifetime on every revalidation, so a URL that became personal
/// went on being served to everybody, indefinitely.
///
/// A 304 carries no body, so anything describing one is not the origin's to
/// update here and would only contradict the bytes on disk.
pub fn refreshed_headers(
	stored: &[(String, String)],
	fresh: &[(String, String)],
) -> Vec<(String, String)> {
	let updating: Vec<&(String, String)> = fresh
		.iter()
		.filter(|(name, _)| !describes_the_body(name))
		.collect();

	let mut merged: Vec<(String, String)> = stored
		.iter()
		.filter(|(name, _)| {
			!updating
				.iter()
				.any(|(fresh, _)| fresh.eq_ignore_ascii_case(name))
		})
		.cloned()
		.collect();
	merged.extend(updating.into_iter().cloned());

	merged
}

fn describes_the_body(name: &str) -> bool {
	matches!(
		name.to_ascii_lowercase().as_str(),
		"content-length" | "content-encoding" | "content-range" | "content-type"
	)
}

/// The stored response, as something to serve.
pub fn as_response(entry: &Entry, body: Vec<u8>) -> ProxyResponse {
	ProxyResponse {
		status: entry.status,
		headers: entry.headers.clone(),
		body,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
		pairs
			.iter()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect()
	}

	fn request(pairs: &[(&str, &str)]) -> ProxyRequest {
		ProxyRequest {
			method: "GET".to_string(),
			url: "https://example.com/logo.png".to_string(),
			headers: headers(pairs),
			body: Vec::new(),
		}
	}

	fn public_image() -> Vec<(String, String)> {
		headers(&[
			("content-type", "image/png"),
			("cache-control", "public, max-age=3600"),
			("etag", "\"abc\""),
		])
	}

	#[test]
	fn a_plainly_public_image_is_eligible() {
		assert!(eligible(&request(&[]), 200, &public_image()));
	}

	/// A HEAD answers with the GET's headers and none of its body, and the key
	/// does not mention the method — so storing one files an empty body where
	/// the next GET will look for it. Verified against a real origin before the
	/// guard existed: `curl -I` then `curl` returned 0 bytes for a 6,868-byte
	/// stylesheet, and kept doing so.
	#[test]
	fn only_a_get_may_be_stored() {
		for method in ["HEAD", "POST", "PUT", "DELETE", "OPTIONS", "head"] {
			let mut req = request(&[]);
			req.method = method.to_string();

			assert_eq!(
				eligible(&req, 200, &public_image()),
				method.eq_ignore_ascii_case("GET"),
				"{method} must not be stored under a key that does not name it"
			);
		}

		assert!(eligible(&request(&[]), 200, &public_image()), "and GET still is");
	}

	#[test]
	fn nothing_but_an_image_is_eligible() {
		let mut head = public_image();
		head[0] = ("content-type".to_string(), "text/html".to_string());

		assert!(!eligible(&request(&[]), 200, &head));
	}

	#[test]
	fn only_a_200_is_eligible() {
		for status in [201, 204, 301, 304, 404, 500] {
			assert!(
				!eligible(&request(&[]), status, &public_image()),
				"{status} must not be stored"
			);
		}
	}

	/// Each of these is the origin, or the request, saying this body was for one
	/// person. Getting any of them wrong means serving it to another.
	#[test]
	fn anything_that_looks_personal_is_refused() {
		let with = |extra: (&str, &str)| {
			let mut head = public_image();
			head.push((extra.0.to_string(), extra.1.to_string()));

			head
		};

		assert!(!eligible(&request(&[]), 200, &with(("set-cookie", "sid=1"))));
		assert!(!eligible(&request(&[]), 200, &with(("vary", "cookie"))));
		assert!(!eligible(&request(&[]), 200, &with(("vary", "*"))));
		assert!(!eligible(
			&request(&[("authorization", "Bearer x")]),
			200,
			&public_image()
		));

		for control in ["private", "no-store", "no-cache", "public, private"] {
			let mut head = public_image();
			head[1] = ("cache-control".to_string(), control.to_string());
			assert!(!eligible(&request(&[]), 200, &head), "{control}");
		}
	}

	/// A signed-in visitor still gets the same public logo as everybody else,
	/// so a session cookie on the *request* says nothing useful.
	#[test]
	fn a_session_cookie_on_the_request_does_not_disqualify() {
		assert!(eligible(
			&request(&[("cookie", "PHPSESSID=deadbeef")]),
			200,
			&public_image()
		));
	}

	#[test]
	fn varying_on_what_we_key_on_is_still_eligible() {
		let mut head = public_image();
		head.push(("vary".to_string(), "Accept, Accept-Encoding".to_string()));

		assert!(eligible(&request(&[]), 200, &head));
	}

	#[test]
	fn something_with_no_freshness_and_no_validator_is_not_worth_storing() {
		let head = headers(&[("content-type", "image/png")]);

		assert!(!eligible(&request(&[]), 200, &head));
	}

	fn asset(kind: &str, control: &str) -> Vec<(String, String)> {
		headers(&[
			("content-type", kind),
			("cache-control", control),
			("etag", "\"abc\""),
		])
	}

	#[test]
	fn the_static_furniture_of_a_page_is_eligible() {
		for kind in [
			"text/css",
			"application/javascript",
			"text/javascript; charset=utf-8",
			"font/woff2",
			"application/vnd.ms-fontobject",
		] {
			assert!(
				eligible(&request(&[]), 200, &asset(kind, "public, max-age=600")),
				"{kind} should be cacheable"
			);
		}
	}

	/// HTML is where per-user content lives, and stays out until mach5 knows
	/// who is asking.
	#[test]
	fn a_page_is_never_eligible() {
		for kind in ["text/html", "application/json", "text/plain", "video/mp4"] {
			assert!(
				!eligible(&request(&[]), 200, &asset(kind, "public, max-age=600")),
				"{kind} must not be cached"
			);
		}
	}

	fn at(url: &str, pairs: &[(&str, &str)]) -> (ProxyRequest, Vec<(String, String)>) {
		let mut req = request(&[]);
		req.url = url.to_string();

		(req, headers(pairs))
	}

	/// The case Tag pushed back on: a small site that sets no cache headers at
	/// all is exactly the one mach5 is for, and demanding `max-age` everywhere
	/// would cache nothing for it.
	/// RFC 9110 §5.3: a list-valued header sent as several lines means what one
	/// joined line would. Reading only the first put the whole eligibility
	/// decision at the mercy of which line the origin happened to send first —
	/// and the second line is exactly where an origin puts the part that says
	/// "not for everybody".
	#[test]
	fn a_second_line_of_a_header_counts_as_much_as_the_first() {
		let public = headers(&[
			("content-type", "image/png"),
			("cache-control", "max-age=600"),
		]);
		assert!(
			eligible(&request(&[]), 200, &public),
			"the control case: this one really is public"
		);

		for late in [
			("vary", "cookie"),
			("cache-control", "private"),
			("cache-control", "no-store"),
			("vary", "*"),
		] {
			let mut refused = public.clone();
			refused.push(("vary".to_string(), "accept-encoding".to_string()));
			refused.push((late.0.to_string(), late.1.to_string()));

			assert!(
				!eligible(&request(&[]), 200, &refused),
				"a late `{}: {}` still refuses it",
				late.0,
				late.1
			);
		}

		// And the same for freshness, which decides how long rather than
		// whether: a directive on the second line has to count too.
		let split = headers(&[
			("cache-control", "public"),
			("cache-control", "max-age=42"),
		]);
		assert_eq!(freshness(&split), Some(Duration::from_secs(42)));
	}

	/// `max-age` counts from when the response was generated, not from when it
	/// arrived. A CDN object handed over with most of its life already spent
	/// was getting a full lifetime again here.
	#[test]
	fn an_entry_is_only_as_fresh_as_it_arrived() {
		let aged = headers(&[
			("content-type", "image/png"),
			("cache-control", "max-age=300"),
			("age", "295"),
		]);

		assert_eq!(entry_for(200, &aged, 1_000).fresh_until, 1_005);

		// An `age` past the lifetime is stale on arrival, not fresh forever.
		let expired = headers(&[("cache-control", "max-age=300"), ("age", "9000")]);
		assert_eq!(entry_for(200, &expired, 1_000).fresh_until, 1_000);

		let plain = headers(&[("cache-control", "max-age=300")]);
		assert_eq!(entry_for(200, &plain, 1_000).fresh_until, 1_300);
	}

	/// A 304 is the origin's chance to change its mind about something it has
	/// already handed out. Re-applying the stored headers took that away: an
	/// entry could never be withdrawn, and its clock was reset to a full
	/// lifetime every time the origin tried.
	#[test]
	fn a_304_replaces_what_was_stored_header_by_header() {
		let stored = headers(&[
			("content-type", "text/css"),
			("cache-control", "max-age=86400"),
			("etag", "\"v1\""),
			("x-origin-note", "kept"),
		]);
		let fresh = headers(&[
			("cache-control", "max-age=60"),
			("vary", "cookie"),
			("date", "then"),
		]);

		let merged = refreshed_headers(&stored, &fresh);
		let value = |name: &str| -> Option<&str> { header(&merged, name) };

		assert_eq!(value("cache-control"), Some("max-age=60"), "shortened");
		assert_eq!(value("vary"), Some("cookie"), "and newly per-user");
		assert_eq!(value("date"), Some("then"), "and added");
		assert_eq!(
			value("x-origin-note"),
			Some("kept"),
			"what the 304 did not mention survives"
		);
		assert_eq!(
			value("etag"),
			Some("\"v1\""),
			"including the validator the request was made with"
		);
		assert_eq!(
			value("content-type"),
			Some("text/css"),
			"and anything describing the body, which a 304 does not carry"
		);

		// Which is the point: the merged headers no longer pass the wall, so
		// the caller drops the entry instead of refreshing it.
		assert!(!eligible(&request(&[]), 200, &merged));
	}

	#[test]
	fn a_stylesheet_or_font_with_only_a_validator_is_still_cached() {
		for kind in ["text/css", "font/woff2", "application/vnd.ms-fontobject"] {
			let (req, head) = at(
				"https://small.example/style.css",
				&[("content-type", kind), ("last-modified", "Mon, 1 Jan 2024 00:00:00 GMT")],
			);

			assert!(
				eligible(&req, 200, &head),
				"{kind} is never personalised, and a mistake is cosmetic"
			);
		}
	}

	/// A fingerprint is a claim about everybody: the name changes when the
	/// bytes do, which is nonsense for a file built per user.
	#[test]
	fn a_fingerprinted_script_is_cached_on_a_validator() {
		let (req, head) = at(
			"https://small.example/assets/app.a1b2c3d4.js",
			&[("content-type", "application/javascript"), ("etag", "\"v1\"")],
		);

		assert!(eligible(&req, 200, &head));
	}

	#[test]
	fn a_plainly_named_script_is_not() {
		let (req, head) = at(
			"https://small.example/config.js",
			&[("content-type", "application/javascript"), ("etag", "\"v1\"")],
		);

		assert!(
			!eligible(&req, 200, &head),
			"this is what a bootstrap script full of tokens looks like"
		);
	}

	#[test]
	fn what_counts_as_a_fingerprint_is_narrow() {
		for yes in [
			"https://e/app.a1b2c3d4.js",
			"https://e/main-4f3a9c2e1b.css",
			"https://e/chunk_8a7f6e5d.js",
			"https://e/x/9f8e7d6c5b4a3f2e.js?v=2",
		] {
			assert!(looks_fingerprinted(yes), "{yes}");
		}

		for no in [
			"https://e/config.js",
			"https://e/session.js",
			"https://e/app.js",
			"https://e/jquery.min.js",
			"https://e/analytics.js?user=12345678",
			"https://e/abcdefghij.js",
		] {
			assert!(!looks_fingerprinted(no), "{no}");
		}
	}

	/// The asymmetry that matters, stated as one test: the same headers on a
	/// picture and on a plainly-named script get different answers.
	#[test]
	fn a_script_needs_more_proof_than_an_image_does() {
		let validator_only = |kind: &str| headers(&[("content-type", kind), ("etag", "\"abc\"")]);

		assert!(
			eligible(&request(&[]), 200, &validator_only("image/png")),
			"where the worst case is the wrong picture, a validator is enough"
		);
		assert!(
			!eligible(&request(&[]), 200, &validator_only("application/javascript")),
			"where it could be somebody's token, it is not"
		);
		assert!(
			eligible(
				&request(&[]),
				200,
				&asset("application/javascript", "public, max-age=31536000")
			),
			"unless the origin says out loud how long it is good for"
		);
	}

	#[test]
	fn a_validator_alone_is_enough_to_store() {
		let head = headers(&[("content-type", "image/png"), ("etag", "\"abc\"")]);

		assert!(eligible(&request(&[]), 200, &head));
		let entry = entry_for(200, &head, 1000);
		assert_eq!(entry.fresh_until, 1000, "stale at once, but revalidatable");
		assert!(entry.can_revalidate());
		assert!(!entry.is_fresh(1000));
	}

	#[test]
	fn freshness_prefers_what_was_addressed_to_a_shared_cache() {
		let head = headers(&[("cache-control", "max-age=60, s-maxage=600")]);

		assert_eq!(freshness(&head), Some(Duration::from_secs(600)));
	}

	#[test]
	fn freshness_reads_max_age_and_survives_nonsense() {
		assert_eq!(
			freshness(&headers(&[("cache-control", "public, max-age=120")])),
			Some(Duration::from_secs(120))
		);
		assert_eq!(freshness(&headers(&[("cache-control", "max-age=abc")])), None);
		assert_eq!(freshness(&headers(&[])), None);
	}

	#[test]
	fn an_entry_is_fresh_until_it_is_not() {
		let entry = entry_for(200, &public_image(), 1_000);

		assert_eq!(entry.fresh_until, 1_000 + 3600);
		assert!(entry.is_fresh(1_500));
		assert!(!entry.is_fresh(5_000));
	}

	/// A hard refresh is the escape hatch everybody already knows, and it is a
	/// request header rather than anything to do with how fresh the entry is.
	#[test]
	fn a_hard_refresh_is_honoured() {
		assert_eq!(client_wants(&request(&[])), ClientWants::Anything);
		assert_eq!(
			client_wants(&request(&[("cache-control", "no-cache")])),
			ClientWants::Revalidated,
			"shift-reload"
		);
		assert_eq!(
			client_wants(&request(&[("Pragma", "no-cache")])),
			ClientWants::Revalidated,
			"and the older spelling of it"
		);
		assert_eq!(
			client_wants(&request(&[("cache-control", "no-store")])),
			ClientWants::Nothing
		);
		assert_eq!(
			client_wants(&request(&[("cache-control", "max-age=0")])),
			ClientWants::Anything,
			"a plain reload is not a demand to ignore the cache"
		);
	}

	#[test]
	fn the_key_covers_the_url_and_what_may_vary() {
		let plain = request(&[]);
		let webp = request(&[("accept", "image/webp")]);
		let mut elsewhere = request(&[]);
		elsewhere.url = "https://example.com/other.png".to_string();

		assert_eq!(key(&plain), key(&request(&[])), "stable");
		assert_ne!(key(&plain), key(&webp), "the origin may vary on accept");
		assert_ne!(key(&plain), key(&elsewhere));
		assert_eq!(key(&plain).len(), 64);
		assert!(!key(&plain).contains('/'), "a key must never become a path");
	}
}
