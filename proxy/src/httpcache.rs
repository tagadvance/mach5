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

	// Whose request this was, rather than what came back.
	if header(&req.headers, "authorization").is_some() {
		return false;
	}

	if !is_image(headers) {
		return false;
	}

	// The origin saying, in the plainest way it has, that this was for one
	// person.
	if header(headers, "set-cookie").is_some() {
		return false;
	}

	let control = header(headers, "cache-control")
		.unwrap_or_default()
		.to_ascii_lowercase();
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
	if let Some(vary) = header(headers, "vary") {
		if vary.trim() == "*" {
			return false;
		}

		let all_keyed = vary.split(',').all(|name| {
			let name = name.trim().to_ascii_lowercase();

			KEYED_ON.contains(&name.as_str())
		});
		if !all_keyed {
			return false;
		}
	}

	// Something to go on: either it says how long it is good for, or it gives
	// us a way to ask.
	freshness(headers).is_some()
		|| header(headers, "etag").is_some()
		|| header(headers, "last-modified").is_some()
}

/// How long the origin said this stays good for, in seconds.
///
/// `s-maxage` first, since that is the one addressed to a shared cache, which
/// is what mach5 is.
pub fn freshness(headers: &[(String, String)]) -> Option<Duration> {
	let control = header(headers, "cache-control")
		.unwrap_or_default()
		.to_ascii_lowercase();

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

fn is_image(headers: &[(String, String)]) -> bool {
	header(headers, "content-type")
		.map(|value| value.trim().to_ascii_lowercase().starts_with("image/"))
		.unwrap_or(false)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
	headers
		.iter()
		.find(|(header, _)| header.eq_ignore_ascii_case(name))
		.map(|(_, value)| value.as_str())
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
	let control = header(&req.headers, "cache-control")
		.unwrap_or_default()
		.to_ascii_lowercase();
	let pragma = header(&req.headers, "pragma")
		.unwrap_or_default()
		.to_ascii_lowercase();

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

		// The body first, so a reader that finds the metadata always finds
		// something to go with it.
		if std::fs::write(self.dir.join(format!("{key}.body")), body).is_err() {
			return;
		}
		if std::fs::write(self.dir.join(format!("{key}.meta")), meta).is_err() {
			let _ = std::fs::remove_file(self.dir.join(format!("{key}.body")));

			return;
		}

		use std::sync::atomic::Ordering;
		if self.since_sweep.fetch_add(1, Ordering::Relaxed) + 1 >= SWEEP_EVERY {
			self.since_sweep.store(0, Ordering::Relaxed);
			crate::disk::sweep(&self.dir, self.budget);
		}
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
	Entry {
		status,
		fresh_until: stored + freshness(headers).map(|d| d.as_secs()).unwrap_or(0),
		etag: header(headers, "etag").map(str::to_string),
		last_modified: header(headers, "last-modified").map(str::to_string),
		headers: headers.to_vec(),
	}
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
