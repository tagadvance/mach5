//! The proxy's own endpoints, hosted on every origin at once.
//!
//! Because the deployment answers every DNS query with the proxy's own
//! address, a relative URL on *any* page reaches us. That is what lets the
//! proxy host endpoints of its own without owning a domain, and — more
//! usefully — without a page ever having to make a cross-origin request to
//! reach them.
//!
//! Everything under `/.mach5/` is answered here and never forwarded upstream.
//! The endpoints are the per-site list of CSS selectors to hide — a self-hosted
//! cosmetic filter, where the blocklist deliberately stops at domain matching —
//! plus the two files [`crate::inject`] points every page at: the stylesheet
//! that applies the list, and the picker that adds to it.
//!
//! Which list a request touches is decided by [`crate::host_of`] on the URL the
//! client asked for, never by anything in the request itself. Same-origin is
//! therefore a property of the routing rather than of a header someone could
//! talk us out of: a page on one site has no way to name another site's list.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse, ResponseHead};

/// Everything below this is ours. A leading dot keeps it out of the way of any
/// real path a site might already serve.
const PREFIX: &str = "/.mach5/";

/// Bounds on what one page can store. A selector is a handful of characters in
/// practice; these exist so a buggy — or hostile — page cannot grow the file
/// without limit.
const MAX_SELECTOR_BYTES: usize = 512;
const MAX_SELECTORS_PER_HOST: usize = 500;

/// The picker, compiled into the binary rather than read from disk. A file on
/// disk would be one more thing to mount into the container — and one more way
/// for a deployment to serve a script that does not match the proxy running it.
const SCRIPT: &str = include_str!("mach5.js");

/// Characters that would let a stored selector break out of the rule it is
/// written into: closing the block, starting an at-rule, ending the declaration,
/// escaping a character, or closing the `<style>`-shaped context a browser might
/// parse the response in if it were ever served as something other than CSS.
///
/// A selector containing one is dropped from the stylesheet rather than escaped.
/// Selectors are typed into the store by a page, so this is the boundary where a
/// hostile one has to stop; and nothing the picker generates contains any of
/// these, so there is no legitimate selector to preserve by escaping it.
const CSS_FORBIDDEN: [char; 7] = ['<', '>', '{', '}', '@', ';', '\\'];

/// The hidden-element selectors, per host, kept in memory and mirrored to disk.
///
/// `BTreeMap`/`BTreeSet` rather than the hash equivalents because both the file
/// and the `GET` response want a stable order: a set that reordered itself
/// would rewrite the whole file differently on every change for no reason, and
/// would make a diff of it useless.
pub struct Store {
	hidden: Mutex<BTreeMap<String, BTreeSet<String>>>,
	path: PathBuf,
}

impl Store {
	/// Read the store, or start empty. A missing file is the ordinary first
	/// run; an unreadable or corrupt one is worth a warning but never worth
	/// refusing to start over, since the proxy is the only way back onto the
	/// network for whoever has to fix it.
	pub fn load(path: PathBuf) -> Self {
		let hidden = match std::fs::read(&path) {
			Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
				log::warn!(
					"ignoring corrupt hidden-element store {}: {e}",
					path.display()
				);

				BTreeMap::new()
			}),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
			Err(e) => {
				log::warn!("cannot read hidden-element store {}: {e}", path.display());

				BTreeMap::new()
			}
		};

		Self {
			hidden: Mutex::new(hidden),
			path,
		}
	}

	/// This host's selectors, sorted.
	fn selectors(&self, host: &str) -> Vec<String> {
		self.lock()
			.get(host)
			.map(|set| set.iter().cloned().collect())
			.unwrap_or_default()
	}

	/// Store one selector. False means this host is already at
	/// [`MAX_SELECTORS_PER_HOST`] — the caller has already checked the selector
	/// itself.
	fn add(&self, host: &str, selector: &str) -> bool {
		let mut hidden = self.lock();
		let set = hidden.entry(host.to_string()).or_default();

		// Re-hiding something already hidden must never fail, so the cap only
		// applies to selectors that would actually grow the set.
		if !set.contains(selector) && set.len() >= MAX_SELECTORS_PER_HOST {
			return false;
		}

		if set.insert(selector.to_string()) {
			persist(&self.path, &hidden);
		}

		true
	}

	fn clear(&self, host: &str) {
		let mut hidden = self.lock();

		if hidden.remove(host).is_some() {
			persist(&self.path, &hidden);
		}
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, BTreeSet<String>>> {
		self.hidden.lock().expect("hidden-element store lock")
	}
}

/// Write the whole file on every change. These are a few kilobytes of hand-
/// picked selectors, so an append log or a database would cost more than it
/// saved; what does matter is that a crash mid-write cannot truncate a list
/// someone built up by hand, hence the write-and-rename.
fn persist(path: &Path, hidden: &BTreeMap<String, BTreeSet<String>>) {
	let json = serde_json::to_vec(hidden).expect("selectors are serializable");

	if let Err(e) = write_atomically(path, &json) {
		log::warn!("cannot save hidden elements to {}: {e}", path.display());
	}
}

fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
	let temporary = path.with_extension("json.tmp");
	let mut file = std::fs::File::create(&temporary)?;
	file.write_all(bytes)?;
	// A rename publishes the file's *name* atomically, not its contents: skip
	// this and a crash can leave the real name pointing at an empty file.
	file.sync_all()?;
	drop(file);

	std::fs::rename(&temporary, path)
}

/// Load once per process, exactly as [`crate::blocklist::shared`] does. Every
/// worker builds its own chain, and a write through one of them has to be
/// visible to all the others.
pub fn shared(config: &Config) -> Arc<Store> {
	static SHARED: OnceLock<Arc<Store>> = OnceLock::new();

	SHARED
		.get_or_init(|| Arc::new(Store::load(config.paths.state_dir.join("hidden.json"))))
		.clone()
}

/// Serves the endpoints under `/.mach5/`.
pub struct Internal {
	store: Arc<Store>,
}

impl Internal {
	pub fn new(config: &Config) -> Self {
		Self {
			store: shared(config),
		}
	}

	fn route(&self, host: &str, method: &str, path: &str, body: &[u8]) -> ProxyResponse {
		match (path, method) {
			("/.mach5/hidden", "GET") => self.hidden(host),
			("/.mach5/hidden", "POST") => self.hide(host, body),
			("/.mach5/hidden/clear", "POST") => {
				self.store.clear(host);

				empty(204)
			}
			("/.mach5/hidden.css", "GET") => self.stylesheet(host),
			("/.mach5/mach5.js", "GET") => script(),
			(
				"/.mach5/hidden"
				| "/.mach5/hidden/clear"
				| "/.mach5/hidden.css"
				| "/.mach5/mach5.js",
				_,
			) => empty(405),
			_ => empty(404),
		}
	}

	fn hidden(&self, host: &str) -> ProxyResponse {
		let hidden = Hidden {
			selectors: self.store.selectors(host),
		};
		let body = serde_json::to_vec(&hidden).expect("selectors are serializable");

		let mut response = empty(200);
		response
			.headers
			.push(("content-type".to_string(), "application/json".to_string()));
		response.body = body;

		response
	}

	/// This host's list as a stylesheet, which is how it actually takes effect:
	/// the browser applies it before first paint, so nothing flashes on screen
	/// before the script has had a chance to run. A host with nothing hidden
	/// gets an empty body rather than a 404 — it is not an error to have hidden
	/// nothing yet.
	fn stylesheet(&self, host: &str) -> ProxyResponse {
		let usable: Vec<String> = self
			.store
			.selectors(host)
			.into_iter()
			.filter(|selector| !selector.contains(CSS_FORBIDDEN))
			.collect();

		let mut response = empty(200);
		response.headers.push((
			"content-type".to_string(),
			"text/css; charset=utf-8".to_string(),
		));

		if !usable.is_empty() {
			response.body =
				format!("{} {{ display: none !important }}", usable.join(", ")).into_bytes();
		}

		response
	}

	fn hide(&self, host: &str, body: &[u8]) -> ProxyResponse {
		let Ok(request) = serde_json::from_slice::<Hide>(body) else {
			return empty(400);
		};

		let selector = request.selector.trim();
		if selector.is_empty() || selector.len() > MAX_SELECTOR_BYTES {
			return empty(400);
		}

		if !self.store.add(host, selector) {
			return empty(409);
		}

		empty(204)
	}
}

impl Interceptor for Internal {
	fn on_request(&self, req: &mut ProxyRequest) -> Option<ProxyResponse> {
		let path = path_of(&req.url);
		// `/.mach5` on its own is ours too, so that it answers 404 rather than
		// being forwarded to an origin that has never heard of it.
		if !path.starts_with(PREFIX) && path != PREFIX.trim_end_matches('/') {
			return None;
		}

		// The host is the one the client asked for, never one the request could
		// name, so a page can only ever reach its own site's list.
		let host = crate::host_of(&req.url);

		Some(self.route(host, &req.method, path, &req.body))
	}

	/// Answers its own paths and ignores every other response, so it must never
	/// be the reason a body is held in memory instead of streaming.
	fn wants_body(&self, _req: &ProxyRequest, _head: &ResponseHead) -> bool {
		false
	}
}

/// The body of a `GET /.mach5/hidden`.
#[derive(Serialize)]
struct Hidden {
	selectors: Vec<String>,
}

/// The body of a `POST /.mach5/hidden`.
#[derive(Deserialize)]
struct Hide {
	selector: String,
}

/// The picker library. The only endpoint here that is the same for every host,
/// and so the only one worth caching — briefly. Five minutes is long enough to
/// keep it off the wire for a browsing session and short enough that a
/// redeployed proxy is running its own script again almost immediately.
fn script() -> ProxyResponse {
	ProxyResponse {
		status: 200,
		headers: vec![
			(
				"content-type".to_string(),
				"text/javascript; charset=utf-8".to_string(),
			),
			("cache-control".to_string(), "max-age=300".to_string()),
		],
		body: SCRIPT.as_bytes().to_vec(),
	}
}

/// A bodyless response.
///
/// Note what is *not* here: no `access-control-allow-origin`, and no other CORS
/// header. These endpoints are reachable only from the site whose list they
/// belong to, and a permissive CORS header would hand that access to every
/// other site on the internet.
fn empty(status: u16) -> ProxyResponse {
	ProxyResponse {
		status,
		// Someone's list changes the moment they hide something; a cached copy
		// of it would be wrong immediately.
		headers: vec![("cache-control".to_string(), "no-store".to_string())],
		body: Vec::new(),
	}
}

/// Path portion of an absolute URL, without the query or fragment.
fn path_of(url: &str) -> &str {
	let rest = url.split_once("://").map_or(url, |(_scheme, rest)| rest);

	let Some(start) = rest.find('/') else {
		return "/";
	};
	let path = &rest[start..];

	path.split(['?', '#']).next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
	use super::*;

	use tempfile::TempDir;

	fn internal(dir: &TempDir) -> Internal {
		Internal {
			store: Arc::new(Store::load(dir.path().join("hidden.json"))),
		}
	}

	fn request(method: &str, url: &str, body: &str) -> ProxyRequest {
		ProxyRequest {
			method: method.to_string(),
			url: url.to_string(),
			headers: Vec::new(),
			body: body.as_bytes().to_vec(),
		}
	}

	fn call(internal: &Internal, method: &str, url: &str, body: &str) -> ProxyResponse {
		let mut req = request(method, url, body);

		internal
			.on_request(&mut req)
			.expect("an internal path is always answered")
	}

	fn body_of(response: &ProxyResponse) -> String {
		String::from_utf8(response.body.clone()).expect("responses are utf-8")
	}

	#[test]
	fn the_endpoints_never_claim_a_response_body() {
		let dir = TempDir::new().expect("temporary directory");
		let head = ResponseHead {
			status: 200,
			headers: vec![("content-type".to_string(), "video/mp4".to_string())],
		};

		assert!(
			!internal(&dir).wants_body(&request("GET", "https://example.com/clip.mp4", ""), &head),
			"a request-only link must not switch off streaming"
		);
	}

	#[test]
	fn a_store_round_trips_through_its_file() {
		let dir = TempDir::new().unwrap();
		let path = dir.path().join("hidden.json");
		let store = Store::load(path.clone());

		assert!(store.selectors("example.com").is_empty(), "starts empty");
		assert!(store.add("example.com", ".promo"));
		assert!(store.add("example.com", "#ad"));

		assert_eq!(store.selectors("example.com"), vec!["#ad", ".promo"]);

		// A fresh load sees what the first one wrote.
		let reloaded = Store::load(path.clone());
		assert_eq!(reloaded.selectors("example.com"), vec!["#ad", ".promo"]);

		store.clear("example.com");
		assert!(store.selectors("example.com").is_empty());
		assert!(Store::load(path).selectors("example.com").is_empty());
	}

	#[test]
	fn a_missing_or_corrupt_file_is_an_empty_store() {
		let dir = TempDir::new().unwrap();
		let path = dir.path().join("hidden.json");

		assert!(Store::load(path.clone())
			.selectors("example.com")
			.is_empty());

		std::fs::write(&path, b"{ this is not json").unwrap();

		assert!(Store::load(path).selectors("example.com").is_empty());
	}

	#[test]
	fn an_ordinary_path_is_left_alone() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		let mut req = request("GET", "https://example.com/index.html", "");

		assert!(internal.on_request(&mut req).is_none());

		// Nor does a path that merely looks like ours.
		let mut req = request("GET", "https://example.com/x/.mach5/hidden", "");
		assert!(internal.on_request(&mut req).is_none());
	}

	#[test]
	fn an_unknown_host_has_nothing_hidden() {
		let dir = TempDir::new().unwrap();
		let response = call(
			&internal(&dir),
			"GET",
			"https://example.com/.mach5/hidden",
			"",
		);

		assert_eq!(response.status, 200);
		assert_eq!(body_of(&response), r#"{"selectors":[]}"#);
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "content-type" && v == "application/json"));
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "cache-control" && v == "no-store"));
		assert!(
			!response
				.headers
				.iter()
				.any(|(k, _)| k.to_ascii_lowercase().starts_with("access-control-")),
			"same-origin by construction: never widen it with CORS"
		);
	}

	#[test]
	fn what_is_added_comes_back_sorted() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		for selector in [".promo", "#ad", ".promo"] {
			let added = call(
				&internal,
				"POST",
				"https://example.com/.mach5/hidden",
				&format!(r#"{{"selector":"{selector}"}}"#),
			);

			assert_eq!(added.status, 204);
			assert!(added.body.is_empty());
		}

		let response = call(&internal, "GET", "https://example.com/.mach5/hidden", "");

		assert_eq!(body_of(&response), r##"{"selectors":["#ad",".promo"]}"##);
	}

	#[test]
	fn a_query_string_does_not_hide_the_path() {
		let dir = TempDir::new().unwrap();
		let response = call(
			&internal(&dir),
			"GET",
			"https://example.com/.mach5/hidden?t=1",
			"",
		);

		assert_eq!(response.status, 200);
	}

	#[test]
	fn one_site_cannot_see_or_clear_another() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		call(
			&internal,
			"POST",
			"https://example.com/.mach5/hidden",
			r##"{"selector":"#ad"}"##,
		);
		call(
			&internal,
			"POST",
			"https://example.net/.mach5/hidden",
			r#"{"selector":".banner"}"#,
		);

		let com = call(&internal, "GET", "https://example.com/.mach5/hidden", "");
		let net = call(&internal, "GET", "https://example.net/.mach5/hidden", "");

		assert_eq!(body_of(&com), r##"{"selectors":["#ad"]}"##);
		assert_eq!(body_of(&net), r#"{"selectors":[".banner"]}"#);

		let cleared = call(
			&internal,
			"POST",
			"https://example.net/.mach5/hidden/clear",
			"",
		);
		assert_eq!(cleared.status, 204);

		let com = call(&internal, "GET", "https://example.com/.mach5/hidden", "");
		let net = call(&internal, "GET", "https://example.net/.mach5/hidden", "");

		assert_eq!(body_of(&com), r##"{"selectors":["#ad"]}"##, "untouched");
		assert_eq!(body_of(&net), r#"{"selectors":[]}"#);
	}

	#[test]
	fn a_body_that_names_no_selector_is_rejected() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		let url = "https://example.com/.mach5/hidden";

		for body in [
			"",
			"not json",
			"{}",
			r#"{"selector":""}"#,
			r#"{"selector":"   "}"#,
		] {
			assert_eq!(call(&internal, "POST", url, body).status, 400, "{body:?}");
		}
	}

	#[test]
	fn an_overlong_selector_is_rejected() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		let url = "https://example.com/.mach5/hidden";
		let longest = "#".repeat(MAX_SELECTOR_BYTES);

		let accepted = call(
			&internal,
			"POST",
			url,
			&format!(r#"{{"selector":"{longest}"}}"#),
		);
		let rejected = call(
			&internal,
			"POST",
			url,
			&format!(r#"{{"selector":"{longest}#"}}"#),
		);

		assert_eq!(accepted.status, 204);
		assert_eq!(rejected.status, 400);
	}

	#[test]
	fn a_host_cannot_grow_past_the_cap() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		let url = "https://example.com/.mach5/hidden";

		for n in 0..MAX_SELECTORS_PER_HOST {
			let response = call(
				&internal,
				"POST",
				url,
				&format!(r##"{{"selector":"#a{n}"}}"##),
			);

			assert_eq!(response.status, 204, "selector {n} should fit");
		}

		let full = call(&internal, "POST", url, r##"{"selector":"#one-too-many"}"##);
		assert_eq!(full.status, 409);

		// A selector already stored is not growth, so it still succeeds.
		let repeat = call(&internal, "POST", url, r##"{"selector":"#a0"}"##);
		assert_eq!(repeat.status, 204);
	}

	#[test]
	fn the_stylesheet_applies_this_hosts_list() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		for selector in [".promo", "#ad"] {
			call(
				&internal,
				"POST",
				"https://example.com/.mach5/hidden",
				&format!(r#"{{"selector":"{selector}"}}"#),
			);
		}

		let response = call(&internal, "GET", "https://example.com/.mach5/hidden.css", "");

		assert_eq!(response.status, 200);
		assert_eq!(
			body_of(&response),
			"#ad, .promo { display: none !important }"
		);
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "content-type" && v == "text/css; charset=utf-8"));
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "cache-control" && v == "no-store"));
	}

	#[test]
	fn a_host_with_nothing_hidden_gets_an_empty_stylesheet() {
		let dir = TempDir::new().unwrap();
		let response = call(
			&internal(&dir),
			"GET",
			"https://example.com/.mach5/hidden.css",
			"",
		);

		assert_eq!(response.status, 200);
		assert!(response.body.is_empty(), "no rule, not an empty rule");
	}

	#[test]
	fn a_hostile_selector_never_reaches_the_stylesheet() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		let url = "https://example.com/.mach5/hidden";

		for selector in [
			".x } body { display: none",
			"@import url(https://evil.example/x.css)",
			".x; color: red",
			"</style><script>alert(1)</script>",
			".x > .y",
			".x\\3c ",
		] {
			let stored = call(
				&internal,
				"POST",
				url,
				&serde_json::json!({ "selector": selector }).to_string(),
			);

			assert_eq!(stored.status, 204, "the store itself takes anything");
		}

		call(&internal, "POST", url, r##"{"selector":"#ad"}"##);

		let css = body_of(&call(
			&internal,
			"GET",
			"https://example.com/.mach5/hidden.css",
			"",
		));

		assert_eq!(
			css, "#ad { display: none !important }",
			"only the harmless selector survives"
		);
	}

	#[test]
	fn the_script_is_served_as_javascript() {
		let dir = TempDir::new().unwrap();
		let response = call(
			&internal(&dir),
			"GET",
			"https://example.com/.mach5/mach5.js",
			"",
		);

		assert_eq!(response.status, 200);
		assert_eq!(response.body, SCRIPT.as_bytes());
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "content-type" && v == "text/javascript; charset=utf-8"));
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "cache-control" && v == "max-age=300"));
	}

	#[test]
	fn an_unknown_endpoint_is_not_found() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		for url in [
			"https://example.com/.mach5",
			"https://example.com/.mach5/",
			"https://example.com/.mach5/nope",
			"https://example.com/.mach5/hidden/nope",
		] {
			assert_eq!(call(&internal, "GET", url, "").status, 404, "{url}");
		}
	}

	#[test]
	fn the_wrong_method_is_not_allowed() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		let deleted = call(&internal, "DELETE", "https://example.com/.mach5/hidden", "");
		let got = call(
			&internal,
			"GET",
			"https://example.com/.mach5/hidden/clear",
			"",
		);

		assert_eq!(deleted.status, 405);
		assert_eq!(got.status, 405);

		for url in [
			"https://example.com/.mach5/hidden.css",
			"https://example.com/.mach5/mach5.js",
		] {
			assert_eq!(call(&internal, "POST", url, "").status, 405, "{url}");
		}
	}
}
