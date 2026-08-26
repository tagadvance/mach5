//! The proxy's own endpoints, hosted on every origin at once.
//!
//! Because the deployment answers every DNS query with the proxy's own
//! address, a relative URL on *any* page reaches us. That is what lets the
//! proxy host endpoints of its own without owning a domain, and — more
//! usefully — without a page ever having to make a cross-origin request to
//! reach them.
//!
//! Everything under `/.mach5/` is answered here and never forwarded upstream.
//! The endpoints are the per-site list of CSS selectors to hide — where the
//! blocklist deliberately stops at domain matching — plus the two files
//! [`crate::inject`] points every page at: the stylesheet that applies the
//! list, and the picker that adds to it. The stylesheet is the union of that
//! list and whatever [`crate::cosmetic`]'s filter lists say about the same
//! host; everything else here is only ever about what somebody picked. The bare
//! prefix is a status page: what the proxy has counted, and what is hidden on
//! the site you are reading it from. And there is the root certificate itself —
//! the one file a device has to have before any of the rest of this works.
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

use crate::ca::CertAuthority;
use crate::config::Config;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse, ResponseHead};
use crate::interstitial::{escape, STYLE};
use crate::metrics::{self, Metrics, PluginStats, Snapshot};

/// Everything below this is ours. A leading dot keeps it out of the way of any
/// real path a site might already serve.
const PREFIX: &str = "/.mach5/";

/// Where the certificate warning page sends someone who typed the phrase.
const BYPASS: &str = "/.mach5/bypass";

/// The root certificate, and the name a device sees it saved under. A `.crt`
/// rather than a `.der`: that is the extension the install flows recognise.
const CERTIFICATE: &str = "/.mach5/ca";
const CERTIFICATE_FILENAME: &str = "mach5-root.crt";

/// Bounds on what one page can store. A selector is a handful of characters in
/// practice; these exist so a buggy — or hostile — page cannot grow the file
/// without limit.
const MAX_SELECTOR_BYTES: usize = 512;
const MAX_SELECTORS_PER_HOST: usize = 500;

/// The picker, compiled into the binary rather than read from disk. A file on
/// disk would be one more thing to mount into the container — and one more way
/// for a deployment to serve a script that does not match the proxy running it.
const SCRIPT: &str = include_str!("mach5.js");

/// Characters that would let a selector break out of the rule it is written
/// into: closing the block, starting an at-rule, ending the declaration, or
/// escaping a character. `<` is here for a different reason — it is what keeps
/// a `</style>` out of the body. The stylesheet is served as `text/css` from an
/// endpoint of its own and is never inlined into a page, so that one character
/// is the whole of the markup-shaped risk.
///
/// `>` is deliberately *not* here. It is the child combinator, which the
/// cosmetic lists use in every other rule, and on its own it can no more escape
/// a selector than a letter can.
///
/// A selector containing one of these is dropped from the stylesheet rather
/// than escaped. Selectors are typed into the store by a page and read out of
/// lists nobody here wrote, so this is the boundary where a hostile one has to
/// stop; and nothing legitimate contains any of them, so there is nothing to
/// preserve by escaping it.
const CSS_FORBIDDEN: [char; 6] = ['<', '{', '}', '@', ';', '\\'];

/// Whether a selector is safe to write into the stylesheet.
///
/// Shared with [`crate::cosmetic`], so that a selector from a list and a
/// selector from the picker are held to one standard rather than two.
pub fn usable(selector: &str) -> bool {
	!selector.is_empty() && !selector.contains(CSS_FORBIDDEN)
}

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

	/// Forget one selector. Silent about whether it was there: the page's remove
	/// control is the only caller, and a second click on a stale page is not a
	/// failure worth reporting.
	fn remove(&self, host: &str, selector: &str) {
		let mut hidden = self.lock();
		let Some(set) = hidden.get_mut(host) else {
			return;
		};

		if !set.remove(selector) {
			return;
		}

		// Removing the last one leaves the host behind as an empty set, which
		// `clear` would not have; the file should not record a difference
		// between the two ways of hiding nothing.
		if set.is_empty() {
			hidden.remove(host);
		}

		persist(&self.path, &hidden);
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
	bypasses: Arc<crate::insecure::Bypasses>,
	/// How long a typed bypass lasts, or `None` when the mechanism is off.
	bypass_ttl: Option<std::time::Duration>,
	metrics: Arc<Metrics>,
	/// The certificate authority, for the one endpoint that hands out its root
	/// certificate. Nothing here can reach the private key — see
	/// [`CertAuthority::root_certificate`].
	ca: Arc<CertAuthority>,
	/// The blocklist registry, or `None` when blocking is switched off. The
	/// status page needs to tell "nothing was blocked" apart from "there is no
	/// list", and — since a refresh replaces the list underneath us — the
	/// registry rather than the list it held when this was built.
	blocklist: Option<Arc<crate::blocklist::Blocklists>>,
	/// The cosmetic-rule registry, or `None` when those are switched off. The
	/// stylesheet merges what it holds with what the picker stored, and the
	/// status page reports on it — for the same reason, and through the same
	/// indirection, as the blocklist above.
	cosmetic: Option<Arc<crate::cosmetic::Cosmetics>>,
}

impl Internal {
	pub fn new(config: &Config, ca: Arc<CertAuthority>) -> Self {
		Self {
			store: shared(config),
			bypasses: crate::insecure::bypasses(),
			// `None` is the whole switch: no TTL, no endpoint.
			bypass_ttl: config.bypass_phrase().map(|_| config.bypass_ttl()),
			metrics: metrics::shared(),
			ca,
			// Asked for only when it is switched on: reporting on the blocklist
			// must not be the reason a disabled one is read off disk.
			blocklist: config
				.blocklist
				.enabled
				.then(|| crate::blocklist::shared(config)),
			cosmetic: config
				.cosmetic
				.enabled
				.then(|| crate::cosmetic::shared(config)),
		}
	}

	/// Record that whoever is at this host has asked to be let through its
	/// certificate failure, and send them back where they were going.
	///
	/// Nothing here checks that a failure actually happened. It does not need
	/// to: the phrase is only on the warning page, and a bypass changes nothing
	/// for a host whose certificate validates.
	fn bypass(&self, host: &str, query: &str, ttl: std::time::Duration) -> ProxyResponse {
		self.bypasses.allow(host, ttl);
		log::warn!(
			"certificate validation bypassed for {host} for the next {} minutes",
			ttl.as_secs() / 60
		);

		let mut response = empty(303);
		response
			.headers
			.push(("location".to_string(), next_path(query)));

		response
	}

	fn route(
		&self,
		host: &str,
		method: &str,
		path: &str,
		query: &str,
		body: &[u8],
	) -> ProxyResponse {
		// Handled ahead of the table so that, switched off, it is not in the
		// table at all: the warning page and this endpoint have to agree about
		// whether the mechanism exists, and a 405 would answer that question.
		if path == BYPASS {
			return match (self.bypass_ttl, method) {
				(Some(ttl), "GET") => self.bypass(host, query, ttl),
				(Some(_), _) => empty(405),
				(None, _) => empty(404),
			};
		}

		match (path, method) {
			// With and without the trailing slash: they are the same page, and a
			// redirect between them would be one more thing to get wrong.
			("/.mach5" | "/.mach5/", "GET") => self.status(host),
			("/.mach5/stats.json", "GET") => self.stats(),
			("/.mach5/hidden", "GET") => self.hidden(host),
			("/.mach5/hidden", "POST") => self.hide(host, body),
			("/.mach5/hidden/remove", "POST") => self.unhide(host, body),
			("/.mach5/hidden/clear", "POST") => {
				self.store.clear(host);

				empty(204)
			}
			("/.mach5/hidden.css", "GET") => self.stylesheet(host),
			("/.mach5/mach5.js", "GET") => script(),
			(CERTIFICATE, "GET") => self.certificate(),
			(
				"/.mach5"
				| "/.mach5/"
				| "/.mach5/stats.json"
				| "/.mach5/hidden"
				| "/.mach5/hidden/remove"
				| "/.mach5/hidden/clear"
				| "/.mach5/hidden.css"
				| "/.mach5/mach5.js"
				| CERTIFICATE,
				_,
			) => empty(405),
			_ => empty(404),
		}
	}

	/// The status page, which is about this host as much as about the process:
	/// the counters are the same everywhere, but what is hidden and whether a
	/// certificate bypass is running are answers only this origin can give.
	fn status(&self, host: &str) -> ProxyResponse {
		let page = status_page(
			host,
			&self.metrics.snapshot(),
			&self.store.selectors(host),
			self.bypasses.allows(host),
			// A list that loaded nothing is not a working list, so it must not
			// report as one.
			self.blocklist
				.as_ref()
				.map(|lists| lists.current().status())
				.filter(|list| list.domains > 0),
			self.cosmetic
				.as_ref()
				.map(|rules| rules.current().status())
				.filter(|rules| rules.rules > 0),
			self.ca.is_ephemeral(),
		);

		let mut response = empty(200);
		response.headers.push((
			"content-type".to_string(),
			"text/html; charset=utf-8".to_string(),
		));
		response.body = page.into_bytes();

		response
	}

	/// The root certificate, as a file a device will offer to install.
	///
	/// DER rather than PEM: it is what the install flow expects on Android, iOS
	/// and Windows, and the browsers that would rather have PEM accept DER here
	/// anyway. The disposition is the other half of that — without it a browser
	/// renders the bytes instead of offering to install them.
	///
	/// The public certificate and nothing else. There is deliberately no
	/// endpoint, here or anywhere, that can reach the private key.
	fn certificate(&self) -> ProxyResponse {
		let mut response = empty(200);
		response.headers.push((
			"content-type".to_string(),
			"application/x-x509-ca-cert".to_string(),
		));
		response.headers.push((
			"content-disposition".to_string(),
			format!("attachment; filename=\"{CERTIFICATE_FILENAME}\""),
		));
		response.body = self.ca.root_certificate().to_vec();

		response
	}

	/// The same numbers, for something that reads them on a schedule rather than
	/// once. Flat, because that is what every scraper wants to graph.
	fn stats(&self) -> ProxyResponse {
		let body =
			serde_json::to_vec(&self.metrics.snapshot()).expect("counters are serializable");

		let mut response = empty(200);
		response
			.headers
			.push(("content-type".to_string(), "application/json".to_string()));
		response.body = body;

		response
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
	///
	/// Two lists, in one rule: what somebody picked here, then what the cosmetic
	/// lists say about this host. The picked ones come first and win any
	/// duplicate, because they are the half of the file a person on this machine
	/// actually chose; each half is sorted already, so the whole thing is stable
	/// enough to diff between two fetches.
	fn stylesheet(&self, host: &str) -> ProxyResponse {
		let mut selectors: Vec<String> = self
			.store
			.selectors(host)
			.into_iter()
			.filter(|selector| usable(selector))
			.collect();

		// Filtered against what is already there rather than sorted together
		// afterwards: this is the deduplication as well as the ordering.
		let listed: Vec<String> = self
			.cosmetic
			.as_ref()
			.map(|rules| rules.current().selectors(host))
			.unwrap_or_default()
			.into_iter()
			.filter(|selector| !selectors.contains(selector))
			.collect();
		selectors.extend(listed);

		let mut response = empty(200);
		response.headers.push((
			"content-type".to_string(),
			"text/css; charset=utf-8".to_string(),
		));

		if !selectors.is_empty() {
			response.body =
				format!("{} {{ display: none !important }}", selectors.join(", "))
					.into_bytes();
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

	/// Stop hiding one selector. A 204 either way: the page that sends this may
	/// have been open since before somebody cleared the list, and unhiding what
	/// is already visible has produced exactly the state that was asked for.
	fn unhide(&self, host: &str, body: &[u8]) -> ProxyResponse {
		let Ok(request) = serde_json::from_slice::<Hide>(body) else {
			return empty(400);
		};

		self.store.remove(host, request.selector.trim());

		empty(204)
	}
}

impl Interceptor for Internal {
	fn on_request(&self, req: &mut ProxyRequest) -> Option<ProxyResponse> {
		let path = path_of(&req.url);
		if !is_ours(path) {
			return None;
		}

		// The host is the one the client asked for, never one the request could
		// name, so a page can only ever reach its own site's list.
		let host = crate::host_of(&req.url);
		self.metrics.internal.increment();

		Some(self.route(host, &req.method, path, query_of(&req.url), &req.body))
	}

	/// Its `POST` endpoints read what was sent, so the body has to be here
	/// before [`Self::on_request`] runs — but only for its own paths. An upload
	/// to the site itself is none of its business.
	fn wants_request_body(&self, req: &ProxyRequest) -> bool {
		is_ours(path_of(&req.url))
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

/// What the status page needs on top of [`crate::interstitial::STYLE`]: a table
/// of numbers and a list with a control on each row. Everything else — the
/// type, the colours, dark mode — is already there, and a second copy of it
/// would be a second thing to keep in step.
const EXTRA: &str = r#"<style>
body { align-items: flex-start; }
table { border-collapse: collapse; width: 100%; margin: 0 0 1rem; }
th, td { padding: .35rem 0; font-weight: 400; text-align: left; }
td { text-align: right; font-variant-numeric: tabular-nums; }
td .note { font-size: .8rem; }
h2 { font-size: 1.1rem; font-weight: 500; margin: 2rem 0 .75rem; }
ul { list-style: none; margin: 0; padding: 0; }
li { display: flex; align-items: center; justify-content: space-between;
  gap: 1rem; padding: .35rem 0; }
li button { font-size: .8rem; padding: .3rem .7rem; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .85rem; word-break: break-all; }
</style>"#;

/// The other half of the remove control. Delegated from the document so that one
/// listener covers every row, and a reload rather than a DOM edit so what the
/// page shows afterwards is what the store actually holds.
///
/// This is the one page in mach5 that is ours end to end, so an inline script is
/// safe here in a way it would not be on somebody else's site: no CSP of ours to
/// work around, and nothing on the page that a site could have written.
const REMOVE: &str = r#"<script>
addEventListener('click', (e) => {
	const control = e.target.closest('button[data-selector]');
	if (!control) {
		return;
	}

	fetch('/.mach5/hidden/remove', {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ selector: control.dataset.selector }),
	}).then(() => location.reload());
});
</script>"#;

/// Render the status page.
///
/// `list` and `rules` are `None` when nothing of that kind is loaded, which is
/// not the same thing as a list that has caught nothing: a bare zero there
/// would read as "this is working and there was nothing to catch".
fn status_page(
	host: &str,
	counted: &Snapshot,
	selectors: &[String],
	bypassed: bool,
	list: Option<crate::blocklist::Status>,
	rules: Option<crate::cosmetic::Status>,
	ephemeral: bool,
) -> String {
	let host = escape(host);
	let uptime = metrics::uptime(std::time::Duration::from_secs(counted.uptime_seconds));
	let requests = metrics::thousands(counted.requests);
	// How long ago it was refreshed, and out of how many lists, because a list
	// that quietly stopped being updated blocks less every week and says
	// nothing about it.
	let blocked = match list {
		Some(list) => format!(
			r#"<td>{} <span class="note">of {} domains, from {} {}, refreshed {} ago</span></td>"#,
			metrics::thousands(counted.blocked),
			metrics::thousands(list.domains as u64),
			list.sources,
			if list.sources == 1 { "list" } else { "lists" },
			metrics::uptime(list.age)
		),
		None => r#"<td class="note">no blocklist loaded</td>"#.to_string(),
	};
	// The same three facts as the blocklist row, for the same reason: rules that
	// stopped being refreshed hide less of the web every week and say nothing.
	let cosmetic = match rules {
		Some(rules) => format!(
			r#"<td>{} <span class="note">from {} {}, refreshed {} ago</span></td>"#,
			metrics::thousands(rules.rules as u64),
			rules.sources,
			if rules.sources == 1 { "list" } else { "lists" },
			metrics::uptime(rules.age)
		),
		None => r#"<td class="note">no cosmetic lists loaded</td>"#.to_string(),
	};
	let internal = metrics::thousands(counted.internal);
	let injected = metrics::thousands(counted.injected);
	let passed_through = metrics::thousands(counted.passed_through);
	let bypasses = metrics::thousands(counted.bypassed);
	let tls_failures = metrics::thousands(counted.tls_failures);
	let upstream_failures = metrics::thousands(counted.upstream_failures);
	let from_origin = metrics::bytes(counted.bytes_from_origin);
	let to_client = metrics::bytes(counted.bytes_to_client);
	let saved = metrics::bytes(counted.bytes_saved_by_compression);
	let plugins = plugin_table(&counted.plugins);
	let certificates = if bypassed {
		"<p>Certificate validation is <strong>bypassed</strong> for this site until \
		 the bypass expires.</p>"
	} else {
		"<p class=\"note\">This site&rsquo;s certificate is being validated normally.</p>"
	};
	let hidden = selector_list(selectors);
	// Loudly, when the root is the generated one: installing a certificate that
	// is replaced on the next restart is effort spent to be confused later.
	let authority = if ephemeral {
		"<strong>This is an ephemeral dev CA</strong>, regenerated every time mach5 \
		 restarts &mdash; installing it buys you one run."
	} else {
		"This is the configured root CA."
	};
	let certificate = format!(
		"<p class=\"note\"><a href=\"{CERTIFICATE}\">Install the mach5 root certificate</a> on \
		 a device before anything else here works &mdash; on a phone it usually lands in \
		 Settings rather than in the browser. {authority}</p>"
	);

	format!(
		r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mach5</title>
{STYLE}
{EXTRA}
</head>
<body>
<main>
  <h1>mach5</h1>
  <p class="lede">Running for {uptime}.</p>
  {certificate}
  <table>
    <tr><th>Requests</th><td>{requests}</td></tr>
    <tr><th>Blocked</th>{blocked}</tr>
    <tr><th>Cosmetic rules</th>{cosmetic}</tr>
    <tr><th>mach5 endpoints</th><td>{internal}</td></tr>
    <tr><th>Pages injected</th><td>{injected}</td></tr>
    <tr><th>Passed through undecrypted</th><td>{passed_through}</td></tr>
    <tr><th>Fetched unvalidated</th><td>{bypasses}</td></tr>
    <tr><th>Certificate failures</th><td>{tls_failures}</td></tr>
    <tr><th>Other upstream failures</th><td>{upstream_failures}</td></tr>
    <tr><th>Body bytes from origins</th><td>{from_origin}</td></tr>
    <tr><th>Body bytes to clients</th><td>{to_client}</td></tr>
    <tr><th>Bytes saved compressing</th><td>{saved}</td></tr>
  </table>
  {plugins}
  <h2>{host}</h2>
  {certificates}
  {hidden}
</main>
{REMOVE}
</body>
</html>
"#
	)
}

/// What each plugin has cost, and nothing at all when none has been called: a
/// heading over an empty table answers a question nobody asked.
///
/// The mean is what the row is for. A total only grows with traffic, so it says
/// nothing about whether a plugin is worth its place; a mean of 40ms says the
/// plugin is on every page load and everybody is paying for it.
///
/// A plugin is named after the file it was started from, and a filename can
/// hold very nearly anything, so the name reaches the markup through
/// [`escape`].
fn plugin_table(plugins: &BTreeMap<String, PluginStats>) -> String {
	if plugins.is_empty() {
		return String::new();
	}

	let rows: String = plugins
		.iter()
		.map(|(name, stats)| {
			format!(
				r#"<tr><th>{}</th><td>{} <span class="note">calls, {} each</span></td></tr>"#,
				escape(name),
				metrics::thousands(stats.calls),
				metrics::duration(std::time::Duration::from_micros(stats.mean_micros))
			)
		})
		.collect();

	format!("<h2>Plugins</h2>\n  <table>{rows}</table>")
}

/// This host's hidden elements, each with the control that stops hiding it.
///
/// A selector is a string a page put into the store, so it reaches the markup —
/// text and attribute alike — only through [`escape`].
fn selector_list(selectors: &[String]) -> String {
	if selectors.is_empty() {
		return "<p class=\"note\">Nothing is hidden on this site.</p>".to_string();
	}

	let rows: String = selectors
		.iter()
		.map(|selector| {
			let selector = escape(selector);

			format!(
				r#"<li><code>{selector}</code><button data-selector="{selector}">Remove</button></li>"#
			)
		})
		.collect();

	format!("<ul>{rows}</ul>")
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

/// Where to send someone after a bypass: back to the page they were refused,
/// and nowhere else.
///
/// This is the one place a value from the URL turns into a `location` header,
/// so it is where an open redirect would live. Decoding comes first — a
/// scheme-relative `//evil.com` written as `%2f%2fevil.com` has to be rejected
/// as the same thing — and then only a path is allowed through. A backslash is
/// treated as a slash by enough browsers to count as one here.
fn next_path(query: &str) -> String {
	const HOME: &str = "/";

	let Some(raw) = query
		.split('&')
		.find_map(|pair| pair.strip_prefix("next="))
	else {
		return HOME.to_string();
	};

	let next = percent_decode(raw);
	let mut characters = next.chars();

	match (characters.next(), characters.next()) {
		(Some('/'), Some('/' | '\\')) => HOME.to_string(),
		(Some('/'), _) => next,
		_ => HOME.to_string(),
	}
}

/// Enough percent-decoding for a path that `encodeURIComponent` produced.
/// Anything malformed is left as the literal characters it is, which cannot
/// turn a rejected value into an accepted one.
fn percent_decode(raw: &str) -> String {
	let bytes = raw.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;

	while i < bytes.len() {
		let decoded = (bytes[i] == b'%' && i + 2 < bytes.len())
			.then(|| std::str::from_utf8(&bytes[i + 1..i + 3]).ok())
			.flatten()
			.and_then(|hex| u8::from_str_radix(hex, 16).ok());

		match decoded {
			Some(byte) => {
				out.push(byte);
				i += 3;
			}
			None => {
				out.push(bytes[i]);
				i += 1;
			}
		}
	}

	String::from_utf8_lossy(&out).into_owned()
}

/// Query portion of an absolute URL, without the leading `?` or any fragment.
fn query_of(url: &str) -> &str {
	let Some((_before, rest)) = url.split_once('?') else {
		return "";
	};

	rest.split('#').next().unwrap_or("")
}

/// Whether this path belongs to the proxy. `/.mach5` on its own counts, so
/// that it answers rather than being forwarded to an origin that has never
/// heard of it.
fn is_ours(path: &str) -> bool {
	path.starts_with(PREFIX) || path == PREFIX.trim_end_matches('/')
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
		internal_with(dir, CertAuthority::generate_dev(&Config::default()).unwrap())
	}

	fn internal_with(dir: &TempDir, ca: CertAuthority) -> Internal {
		Internal {
			store: Arc::new(Store::load(dir.path().join("hidden.json"))),
			bypasses: Arc::new(crate::insecure::Bypasses::default()),
			bypass_ttl: Some(std::time::Duration::from_secs(60)),
			metrics: Arc::new(Metrics::default()),
			ca: Arc::new(ca),
			blocklist: None,
			cosmetic: None,
		}
	}

	/// A root loaded from PEM, the way a deployment with a real CA runs. Built
	/// here rather than kept as a fixture so the test carries its own root and
	/// nothing on disk is a private key.
	fn loaded_ca() -> CertAuthority {
		let key = rcgen::KeyPair::generate().unwrap();
		let mut params = rcgen::CertificateParams::default();
		params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
		let root = params.self_signed(&key).unwrap();

		CertAuthority::from_pem(&root.pem(), &key.serialize_pem(), &Config::default()).unwrap()
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
	fn typing_the_phrase_records_a_bypass_and_goes_back() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		let response = call(
			&internal,
			"GET",
			"https://staging.example.com/.mach5/bypass?next=%2Fapp%3Fid%3D7",
			"",
		);

		assert_eq!(response.status, 303);
		assert_eq!(
			response
				.headers
				.iter()
				.find(|(name, _)| name == "location")
				.map(|(_, value)| value.as_str()),
			Some("/app?id=7")
		);
		assert!(internal.bypasses.allows("staging.example.com"));
		assert!(
			!internal.bypasses.allows("other.example.com"),
			"only the host that was warned about"
		);
	}

	#[test]
	fn the_bypass_endpoint_does_not_exist_when_it_is_switched_off() {
		let dir = TempDir::new().unwrap();
		let mut internal = internal(&dir);
		internal.bypass_ttl = None;

		let response = call(&internal, "GET", "https://example.com/.mach5/bypass", "");

		assert_eq!(
			response.status, 404,
			"a 405 would tell someone the endpoint is there"
		);
		assert!(!internal.bypasses.allows("example.com"));
	}

	/// The one place a value out of the URL becomes a `location` header.
	#[test]
	fn only_a_path_survives_the_next_parameter() {
		assert_eq!(next_path("next=%2Fpath%3Fq%3D1"), "/path?q=1");
		assert_eq!(next_path("next=/path?q=1"), "/path?q=1");
		assert_eq!(next_path(""), "/");
		assert_eq!(next_path("next="), "/");
		assert_eq!(next_path("other=1"), "/");

		// Every shape of "somewhere that is not this site".
		assert_eq!(next_path("next=%2F%2Fevil.example"), "/");
		assert_eq!(next_path("next=//evil.example"), "/");
		assert_eq!(next_path("next=/\\evil.example"), "/");
		assert_eq!(next_path("next=https%3A%2F%2Fevil.example"), "/");
		assert_eq!(next_path("next=javascript%3Aalert(1)"), "/");
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

	/// A list nobody here wrote and a list somebody here picked end up in one
	/// rule. The picked half comes first and wins any duplicate, and both halves
	/// stay sorted so two fetches of this can be diffed against each other.
	#[test]
	fn the_stylesheet_merges_the_lists_with_what_was_picked() {
		let dir = TempDir::new().unwrap();
		let mut internal = internal(&dir);
		let list = dir.path().join("easylist.txt");
		std::fs::write(
			&list,
			"example.com##.cookie-banner\n\
			 example.com##.promo\n\
			 www.example.com##.newsletter\n\
			 example.com#@#.wanted\n\
			 example.com##.wanted\n\
			 other.example##.elsewhere\n",
		)
		.unwrap();
		internal.cosmetic = Some(Arc::new(crate::cosmetic::Cosmetics::new(
			crate::cosmetic::Cosmetic::load(&[list], false),
		)));

		for selector in [".promo", "#ad"] {
			call(
				&internal,
				"POST",
				"https://www.example.com/.mach5/hidden",
				&serde_json::json!({ "selector": selector }).to_string(),
			);
		}

		let css = body_of(&call(
			&internal,
			"GET",
			"https://www.example.com/.mach5/hidden.css",
			"",
		));

		assert_eq!(
			css,
			"#ad, .promo, .cookie-banner, .newsletter { display: none !important }",
			"picked first, then the lists, with the duplicate kept once"
		);
	}

	#[test]
	fn a_host_the_lists_say_nothing_about_gets_only_what_was_picked() {
		let dir = TempDir::new().unwrap();
		let mut internal = internal(&dir);
		let list = dir.path().join("easylist.txt");
		std::fs::write(&list, "example.com##.cookie-banner\n").unwrap();
		internal.cosmetic = Some(Arc::new(crate::cosmetic::Cosmetics::new(
			crate::cosmetic::Cosmetic::load(&[list], false),
		)));

		call(
			&internal,
			"POST",
			"https://other.example/.mach5/hidden",
			r##"{"selector":"#ad"}"##,
		);

		assert_eq!(
			body_of(&call(
				&internal,
				"GET",
				"https://other.example/.mach5/hidden.css",
				""
			)),
			"#ad { display: none !important }"
		);
		assert!(
			call(&internal, "GET", "https://third.example/.mach5/hidden.css", "")
				.body
				.is_empty(),
			"no rule, not an empty rule"
		);
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

	/// A `>` is a child combinator and nothing else — it cannot close a rule,
	/// open an at-rule or end a declaration — so it reaches the stylesheet. The
	/// characters that *can* still do not.
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

		for selector in ["#ad", ".x > .y"] {
			call(
				&internal,
				"POST",
				url,
				&serde_json::json!({ "selector": selector }).to_string(),
			);
		}

		let css = body_of(&call(
			&internal,
			"GET",
			"https://example.com/.mach5/hidden.css",
			"",
		));

		assert_eq!(
			css, "#ad, .x > .y { display: none !important }",
			"only the selectors that cannot break out survive"
		);
		assert!(usable(".wrap > .ad"), "a child combinator is a selector");
		assert!(!usable(".x { }"));
		assert!(!usable("</style>"));
		assert!(!usable(""), "an empty selector is not a rule");
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

	/// The endpoint that makes every other one usable: nothing this proxy mints
	/// is trusted until a device has installed what this hands back.
	#[test]
	fn the_root_certificate_is_served_ready_to_install() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		let response = call(&internal, "GET", "https://example.com/.mach5/ca", "");

		assert_eq!(response.status, 200);
		assert_eq!(response.body, internal.ca.root_certificate());
		assert_eq!(
			response.body.first(),
			Some(&0x30),
			"DER, not PEM: a certificate is a SEQUENCE"
		);

		// Both headers are load-bearing: the type is what an installer looks at,
		// and without the disposition a browser renders the bytes instead.
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "content-type" && v == "application/x-x509-ca-cert"));
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "content-disposition"
				&& v == r#"attachment; filename="mach5-root.crt""#));
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "cache-control" && v == "no-store"));
	}

	/// A regression guard on somebody later serving a "convenient" bundle: the
	/// public certificate is the only thing that may ever leave this endpoint.
	#[test]
	fn the_certificate_endpoint_never_serves_the_private_key() {
		let dir = TempDir::new().unwrap();
		let response = call(&internal(&dir), "GET", "https://example.com/.mach5/ca", "");
		let body = String::from_utf8_lossy(&response.body);

		assert!(!body.contains("PRIVATE KEY"), "the key must never be reachable");
		assert!(!body.contains("-----BEGIN"));
	}

	#[test]
	fn an_unknown_endpoint_is_not_found() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		for url in [
			"https://example.com/.mach5/nope",
			"https://example.com/.mach5/hidden/nope",
			"https://example.com/.mach5/stats",
		] {
			assert_eq!(call(&internal, "GET", url, "").status, 404, "{url}");
		}
	}

	#[test]
	fn the_status_page_is_this_host_and_what_is_hidden_on_it() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		call(
			&internal,
			"POST",
			"https://example.com/.mach5/hidden",
			r##"{"selector":"#ad"}"##,
		);
		internal.metrics.requests.add(1234);

		for url in [
			"https://example.com/.mach5/",
			"https://example.com/.mach5",
		] {
			let response = call(&internal, "GET", url, "");

			assert_eq!(response.status, 200, "{url}");
			assert!(response
				.headers
				.iter()
				.any(|(k, v)| k == "content-type" && v == "text/html; charset=utf-8"));
			assert!(response
				.headers
				.iter()
				.any(|(k, v)| k == "cache-control" && v == "no-store"));

			let page = body_of(&response);

			assert!(page.contains("example.com"), "{page}");
			assert!(page.contains("1,234"), "counts are readable: {page}");
			assert!(page.contains("#ad"), "{page}");
			assert!(
				page.contains(r##"data-selector="#ad""##),
				"each selector gets its own control: {page}"
			);
		}

		// Another site's page is about that site, not this one.
		let other = body_of(&call(&internal, "GET", "https://example.net/.mach5/", ""));

		assert!(other.contains("Nothing is hidden"), "{other}");
		assert!(!other.contains("#ad"));
	}

	#[test]
	fn the_status_page_says_whether_a_bypass_is_running_here() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		internal
			.bypasses
			.allow("staging.example.com", std::time::Duration::from_secs(60));

		let bypassed = body_of(&call(
			&internal,
			"GET",
			"https://staging.example.com/.mach5/",
			"",
		));
		let ordinary = body_of(&call(&internal, "GET", "https://example.com/.mach5/", ""));

		assert!(bypassed.contains("<strong>bypassed</strong>"), "{bypassed}");
		assert!(ordinary.contains("validated normally"), "{ordinary}");
	}

	/// Installing the root is the first thing anyone has to do, so the page has
	/// to offer it — and has to say when installing it would be wasted effort.
	#[test]
	fn the_status_page_offers_the_certificate_and_says_which_one_it_is() {
		let dir = TempDir::new().unwrap();

		let dev = body_of(&call(
			&internal(&dir),
			"GET",
			"https://example.com/.mach5/",
			"",
		));

		assert!(dev.contains(r#"href="/.mach5/ca""#), "{dev}");
		assert!(dev.contains("Settings"), "{dev}");
		assert!(dev.contains("<strong>This is an ephemeral dev CA</strong>"), "{dev}");

		let loaded = body_of(&call(
			&internal_with(&dir, loaded_ca()),
			"GET",
			"https://example.com/.mach5/",
			"",
		));

		assert!(loaded.contains(r#"href="/.mach5/ca""#), "{loaded}");
		assert!(!loaded.contains("ephemeral"), "a real root is not: {loaded}");
	}

	/// A selector is a string a page put in the store, so the page it comes back
	/// on is where a hostile one would take effect.
	#[test]
	fn a_hostile_selector_cannot_write_markup_into_the_status_page() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		let selector = r#"<script>alert(1)</script>" onclick="alert(2)"#;

		call(
			&internal,
			"POST",
			"https://example.com/.mach5/hidden",
			&serde_json::json!({ "selector": selector }).to_string(),
		);

		let page = body_of(&call(&internal, "GET", "https://example.com/.mach5/", ""));

		assert!(!page.contains("<script>alert(1)"), "{page}");
		assert!(!page.contains(r##"" onclick=""##), "{page}");
		assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "{page}");
		assert!(page.contains("&quot; onclick=&quot;"), "{page}");
	}

	/// A zero that means "nothing was blocked" and a zero that means "there is
	/// no list" are different answers, and the page must not give the first when
	/// the second is true.
	#[test]
	fn the_page_tells_a_missing_blocklist_from_a_loaded_one() {
		let dir = TempDir::new().unwrap();
		let mut internal = internal(&dir);

		let none = body_of(&call(&internal, "GET", "https://example.com/.mach5/", ""));

		assert!(none.contains("no blocklist loaded"), "{none}");

		let file = dir.path().join("hosts.txt");
		std::fs::write(&file, "0.0.0.0 ads.example.com\n0.0.0.0 ads.example.net\n").unwrap();
		internal.blocklist = Some(Arc::new(crate::blocklist::Blocklists::new(
			crate::blocklist::Blocklist::load(&[file], &[]),
		)));
		internal.metrics.blocked.add(9);

		let loaded = body_of(&call(&internal, "GET", "https://example.com/.mach5/", ""));

		assert!(loaded.contains("of 2 domains"), "{loaded}");
		assert!(loaded.contains(">9 "), "{loaded}");
		assert!(loaded.contains("from 1 list, refreshed 0s ago"), "{loaded}");
		assert!(!loaded.contains("no blocklist loaded"));
	}

	/// The same distinction the blocklist row makes: a zero because nothing was
	/// loaded reads very differently from a zero because there was nothing to
	/// hide.
	#[test]
	fn the_page_tells_missing_cosmetic_lists_from_loaded_ones() {
		let dir = TempDir::new().unwrap();
		let mut internal = internal(&dir);

		let none = body_of(&call(&internal, "GET", "https://example.com/.mach5/", ""));

		assert!(none.contains("no cosmetic lists loaded"), "{none}");

		let list = dir.path().join("easylist.txt");
		std::fs::write(&list, "example.com##.banner\nexample.com##.promo\n").unwrap();
		internal.cosmetic = Some(Arc::new(crate::cosmetic::Cosmetics::new(
			crate::cosmetic::Cosmetic::load(&[list], false),
		)));

		let loaded = body_of(&call(&internal, "GET", "https://example.com/.mach5/", ""));

		assert!(loaded.contains(">2 "), "{loaded}");
		assert!(loaded.contains("from 1 list, refreshed 0s ago"), "{loaded}");
		assert!(!loaded.contains("no cosmetic lists loaded"));
	}

	/// A plugin nobody has called has nothing to say, and a heading over an
	/// empty table is worse than no heading.
	#[test]
	fn the_page_shows_plugins_only_once_one_has_been_called() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		let quiet = body_of(&call(&internal, "GET", "https://example.com/.mach5/", ""));

		assert!(!quiet.contains("Plugins"), "{quiet}");

		internal
			.metrics
			.record_plugin_call("rewrite.py", std::time::Duration::from_micros(40_500));
		internal
			.metrics
			.record_plugin_call("rewrite.py", std::time::Duration::from_micros(39_500));

		let page = body_of(&call(&internal, "GET", "https://example.com/.mach5/", ""));

		assert!(page.contains("<h2>Plugins</h2>"), "{page}");
		assert!(page.contains("rewrite.py"), "{page}");
		assert!(page.contains("40.0 ms each"), "the mean, not the total: {page}");
	}

	/// A plugin is named after the file it was started from, and a filename can
	/// hold very nearly anything — including markup.
	#[test]
	fn a_hostile_plugin_name_cannot_write_markup_into_the_status_page() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		internal
			.metrics
			.record_plugin_call("<script>alert(1)</script>", std::time::Duration::ZERO);

		let page = body_of(&call(&internal, "GET", "https://example.com/.mach5/", ""));

		assert!(!page.contains("<script>alert(1)"), "{page}");
		assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "{page}");
	}

	#[test]
	fn the_counters_are_also_json() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		internal.metrics.blocked.add(3);
		internal.metrics.bytes_to_client.add(2048);
		internal.metrics.bytes_saved_by_compression.add(6144);
		internal
			.metrics
			.record_plugin_call("rewrite.py", std::time::Duration::from_millis(2));
		internal
			.metrics
			.record_plugin_call("rewrite.py", std::time::Duration::from_millis(1));

		let response = call(
			&internal,
			"GET",
			"https://example.com/.mach5/stats.json",
			"",
		);

		assert_eq!(response.status, 200);
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "content-type" && v == "application/json"));
		assert!(response
			.headers
			.iter()
			.any(|(k, v)| k == "cache-control" && v == "no-store"));

		let stats: serde_json::Value = serde_json::from_slice(&response.body).unwrap();

		assert_eq!(stats["blocked"], 3);
		assert_eq!(stats["bytes_to_client"], 2048);
		assert_eq!(stats["bytes_saved_by_compression"], 6144);
		assert_eq!(stats["internal"], 1, "this very request");
		assert!(stats["uptime_seconds"].is_u64());
		assert_eq!(
			stats["plugins"],
			serde_json::json!({
				"rewrite.py": { "calls": 2, "total_micros": 3000, "mean_micros": 1500 }
			}),
			"what each plugin cost, keyed by name"
		);
	}

	#[test]
	fn everything_answered_here_is_counted() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		call(&internal, "GET", "https://example.com/.mach5/hidden", "");
		call(&internal, "GET", "https://example.com/.mach5/nope", "");

		assert_eq!(
			internal.metrics.internal.get(),
			2,
			"a 404 under our prefix is still us answering"
		);

		let mut req = request("GET", "https://example.com/index.html", "");
		internal.on_request(&mut req);

		assert_eq!(
			internal.metrics.internal.get(),
			2,
			"a request we passed on is not ours"
		);
	}

	#[test]
	fn removing_takes_one_selector_out_and_leaves_the_rest() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		for selector in ["#ad", ".promo"] {
			call(
				&internal,
				"POST",
				"https://example.com/.mach5/hidden",
				&format!(r#"{{"selector":"{selector}"}}"#),
			);
		}

		let removed = call(
			&internal,
			"POST",
			"https://example.com/.mach5/hidden/remove",
			r##"{"selector":"#ad"}"##,
		);

		assert_eq!(removed.status, 204);
		assert!(removed.body.is_empty());
		assert_eq!(
			body_of(&call(&internal, "GET", "https://example.com/.mach5/hidden", "")),
			r#"{"selectors":[".promo"]}"#
		);
		// Persisted the same way adding is: a reload has to agree.
		assert_eq!(
			Store::load(dir.path().join("hidden.json")).selectors("example.com"),
			vec![".promo"]
		);
	}

	#[test]
	fn removing_something_that_is_not_hidden_is_not_an_error() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		let url = "https://example.com/.mach5/hidden/remove";

		assert_eq!(
			call(&internal, "POST", url, r##"{"selector":"#ad"}"##).status,
			204,
			"nothing hidden here at all"
		);

		call(
			&internal,
			"POST",
			"https://example.com/.mach5/hidden",
			r#"{"selector":".promo"}"#,
		);

		assert_eq!(
			call(&internal, "POST", url, r##"{"selector":"#ad"}"##).status,
			204
		);
		assert_eq!(
			call(&internal, "POST", url, r#"{"selector":".promo"}"#).status,
			204
		);
		assert_eq!(
			call(&internal, "POST", url, r#"{"selector":".promo"}"#).status,
			204,
			"removing it twice is the same answer"
		);
		assert!(internal.store.selectors("example.com").is_empty());
	}

	#[test]
	fn a_remove_that_names_no_selector_is_rejected() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);
		let url = "https://example.com/.mach5/hidden/remove";

		for body in ["", "not json", "{}", r#"{"selector":7}"#] {
			assert_eq!(call(&internal, "POST", url, body).status, 400, "{body:?}");
		}
	}

	#[test]
	fn one_site_cannot_unhide_another() {
		let dir = TempDir::new().unwrap();
		let internal = internal(&dir);

		for host in ["example.com", "example.net"] {
			call(
				&internal,
				"POST",
				&format!("https://{host}/.mach5/hidden"),
				r##"{"selector":"#ad"}"##,
			);
		}

		call(
			&internal,
			"POST",
			"https://example.net/.mach5/hidden/remove",
			r##"{"selector":"#ad"}"##,
		);

		assert_eq!(internal.store.selectors("example.com"), vec!["#ad"]);
		assert!(internal.store.selectors("example.net").is_empty());
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
			"https://example.com/.mach5/",
			"https://example.com/.mach5/stats.json",
			"https://example.com/.mach5/hidden.css",
			"https://example.com/.mach5/mach5.js",
			"https://example.com/.mach5/ca",
		] {
			assert_eq!(call(&internal, "POST", url, "").status, 405, "{url}");
		}
	}
}

