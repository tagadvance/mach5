//! The domain blocklist — first-stage ad blocking.
//!
//! This is built in rather than shipped as a plugin for two reasons: matching a
//! hundred thousand domains on every single request has no business crossing a
//! JSON pipe into another process, and blocking should keep working with
//! plugins turned off entirely.
//!
//! It is deliberately *only* a domain matcher. Real ad blockers also carry
//! URL-pattern rules, cosmetic filters and regexes; those lines are skipped
//! here rather than half-honoured, because a general-purpose filter engine is a
//! different project.
//!
//! Lists are parsed leniently and from any of the three formats in common use —
//! hosts files, bare domains, and Adblock's `||domain^` anchors — because the
//! popular lists mix them freely.
//!
//! Lists come from files on disk, from URLs, or both, and one background thread
//! rebuilds the whole set on a schedule. A hosts file downloaded once is stale a
//! month later, and staleness in a blocker is silent: things quietly stop being
//! blocked and nothing anywhere says so.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse, ResponseHead};

/// A 1×1 transparent GIF. Serving this rather than an empty body keeps a
/// blocked image from leaving a broken-image icon in the page.
const TRANSPARENT_GIF: [u8; 43] = [
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

/// Names a hosts file points at loopback for its own housekeeping. Blocking
/// them would be pointless at best and confusing at worst.
const HOUSEKEEPING: [&str; 4] = [
	"localhost",
	"localhost.localdomain",
	"local",
	"broadcasthost",
];

/// Where fetched lists are kept, under the configured cache directory.
const CACHE: crate::fetch::Cache = crate::fetch::Cache::new("blocklists", "blocklist");

/// Three sets of domains: what to block outright, what to block only when
/// something else embedded it, and what to never block.
pub struct Blocklist {
	blocked: HashSet<String>,
	/// `||host^$third-party`. The commonest option in a real filter list by a
	/// wide margin, and the one this proxy can actually answer: a browser says
	/// which it is in `sec-fetch-site`.
	blocked_embedded: HashSet<String>,
	allowed: HashSet<String>,
	/// `@@||host^$third-party`, which is how one list cancels another's
	/// third-party block.
	allowed_embedded: HashSet<String>,
	metrics: Arc<crate::metrics::Metrics>,
	/// How many of the configured sources actually gave us something.
	sources: usize,
	/// When this list was built. A refresh builds a whole new one, so this is
	/// also how long ago the last refresh ran.
	built: Instant,
}

impl Blocklist {
	fn new(allow: &[String], metrics: Arc<crate::metrics::Metrics>) -> Self {
		Self {
			blocked: HashSet::new(),
			blocked_embedded: HashSet::new(),
			allowed_embedded: HashSet::new(),
			allowed: allow
				.iter()
				.filter_map(|domain| normalize(domain))
				.collect(),
			metrics,
			sources: 0,
			built: Instant::now(),
		}
	}

	/// Read every list, skipping — with a warning — any that cannot be read. A
	/// missing list is not worth refusing to start over.
	pub fn load(files: &[PathBuf], allow: &[String]) -> Self {
		let mut list = Self::new(allow, crate::metrics::shared());

		for path in files {
			match std::fs::read_to_string(path) {
				Ok(text) => {
					list.add(&text);
					list.sources += 1;
				}
				Err(e) => log::warn!("cannot read blocklist {}: {e}", path.display()),
			}
		}

		list
	}

	fn add(&mut self, text: &str) {
		for line in text.lines() {
			for rule in parse(line) {
				match rule {
					Rule::Block(domain) => {
						self.blocked.insert(domain);
					}
					Rule::BlockEmbedded(domain) => {
						self.blocked_embedded.insert(domain);
					}
					Rule::Allow(domain) => {
						self.allowed.insert(domain);
					}
					Rule::AllowEmbedded(domain) => {
						self.allowed_embedded.insert(domain);
					}
				}
			}
		}
	}

	pub fn is_empty(&self) -> bool {
		self.blocked.is_empty() && self.blocked_embedded.is_empty()
	}

	/// How many domains are loaded. The status page reports it so that a blocked
	/// count of zero can be told apart from a list that never loaded.
	pub fn len(&self) -> usize {
		self.blocked.len() + self.blocked_embedded.len()
	}

	/// What the status page needs to tell a list that is being kept up to date
	/// from one that quietly stopped.
	pub fn status(&self) -> Status {
		Status {
			domains: self.blocked.len() + self.blocked_embedded.len(),
			sources: self.sources,
			age: self.built.elapsed(),
		}
	}

	/// Whether two builds hold the same rules. A refresh that changed nothing
	/// should say nothing, and this is the only way to know which it was.
	/// Every set, not just two of them. A refresh in which only the
	/// `$third-party` rules moved compared equal, so the new list was published
	/// with the log saying nothing had changed.
	fn same_as(&self, other: &Self) -> bool {
		self.blocked == other.blocked
			&& self.blocked_embedded == other.blocked_embedded
			&& self.allowed == other.allowed
			&& self.allowed_embedded == other.allowed_embedded
	}

	/// Whether this request is blocked, which depends on the request and not
	/// only on the host: a `$third-party` rule applies to a subresource and not
	/// to the page it is on.
	fn blocks_request(&self, req: &ProxyRequest, host: &str) -> bool {
		let embedded = embedded(req);

		// An exception cancels whatever matched, as long as its own scope
		// applies to this request.
		if covers(&self.allowed, host) || (embedded && covers(&self.allowed_embedded, host)) {
			return false;
		}

		covers(&self.blocked, host) || (embedded && covers(&self.blocked_embedded, host))
	}

	/// Whether a plain first-party request for this host is blocked.
	///
	/// A convenience for tests, and deliberately a *call* to the production
	/// predicate rather than a second implementation of it: this used to
	/// re-write the allow-beats-block rule by hand and leave the third-party
	/// sets out entirely, so nothing anywhere asserted that an exception beats
	/// a `$third-party` rule — the interaction that was being added at the
	/// time.
	#[cfg(test)]
	pub fn blocks(&self, host: &str) -> bool {
		let plain = ProxyRequest {
			method: "GET".to_string(),
			url: format!("https://{host}/"),
			headers: Vec::new(),
			body: Vec::new(),
			peer: None,
		};

		self.blocks_request(&plain, host)
	}
}

/// The list as the status page sees it.
pub struct Status {
	pub domains: usize,
	pub sources: usize,
	/// How long ago the list in force was built.
	pub age: Duration,
}

/// The list currently in force, and the one thing a refresh replaces.
///
/// The indirection exists so that a refresh can publish a new list without
/// every chain having to be rebuilt around it: the chains hold the registry,
/// and what the registry points at changes underneath them.
pub struct Blocklists {
	current: RwLock<Arc<Blocklist>>,
}

impl Blocklists {
	pub fn new(list: Blocklist) -> Self {
		Self {
			current: RwLock::new(Arc::new(list)),
		}
	}

	/// The list to match against right now.
	///
	/// The `Arc` is cloned out and the read lock dropped before the caller
	/// matches anything against it. Matching walks a host's parent domains, and
	/// holding the lock across that would put a refresh's write lock behind
	/// every request in flight — and then every later request behind the
	/// refresh. Bumping a refcount is all a request can ever block a swap for.
	pub fn current(&self) -> Arc<Blocklist> {
		let current = self.current.read().expect("blocklist registry lock");

		Arc::clone(&current)
	}

	fn replace(&self, list: Blocklist) {
		*self.current.write().expect("blocklist registry lock") = Arc::new(list);
	}
}

/// Load once per process. Every worker builds its own chain, so a list parsed
/// per chain would be held in memory a couple of dozen times over.
///
/// Only what is already on disk is read here — the configured files, and the
/// last copy of each URL. Startup must not wait on somebody else's web server.
pub fn shared(config: &Config) -> Arc<Blocklists> {
	static SHARED: OnceLock<Arc<Blocklists>> = OnceLock::new();

	SHARED
		.get_or_init(|| {
			let list = build(config, &cached(config));
			report(&list, configured(config));

			Arc::new(Blocklists::new(list))
		})
		.clone()
}

/// The chain link is the registry, not the list: every chain shares one load,
/// and a refresh reaches all of them at once.
impl Interceptor for Arc<Blocklists> {
	fn on_request(&self, req: &mut ProxyRequest) -> Option<ProxyResponse> {
		let list = self.current();
		let host = crate::host_of(&req.url);
		if !list.blocks_request(req, host) {
			return None;
		}

		log::debug!("blocked {host}");
		list.metrics.blocked.increment();

		Some(blocked(req))
	}

	/// Decides on the request alone, so it must never be the reason a response
	/// body is held in memory instead of streaming.
	fn wants_body(&self, _req: &ProxyRequest, _head: &ResponseHead) -> bool {
		false
	}
}

/// Answer a blocked request without touching the origin.
fn blocked(req: &ProxyRequest) -> ProxyResponse {
	let mut headers = vec![
		// A blocked response must never outlive the rule that produced it.
		("cache-control".to_string(), "no-store".to_string()),
		("x-mach5".to_string(), "blocked".to_string()),
	];

	if wants_image(req) {
		headers.push(("content-type".to_string(), "image/gif".to_string()));

		return ProxyResponse {
			status: 200,
			headers,
			body: TRANSPARENT_GIF.to_vec(),
		};
	}

	ProxyResponse {
		status: 204,
		headers,
		body: Vec::new(),
	}
}

fn wants_image(req: &ProxyRequest) -> bool {
	req.headers.iter().any(|(name, value)| {
		name.eq_ignore_ascii_case("accept") && value.to_ascii_lowercase().contains("image/")
	})
}

/// Whether the host, or any domain above it, is in the set. Walking the parents
/// is what makes this label-aware: `notdoubleclick.net` never reaches
/// `doubleclick.net`, where a substring test would have matched it.
///
/// Shared with [`crate::inject`], so that "a parent domain covers its
/// subdomains" means the same thing wherever a host is matched against a list.
pub fn covers(set: &HashSet<String>, host: &str) -> bool {
	if set.is_empty() {
		return false;
	}

	let host = host.trim_end_matches('.').to_ascii_lowercase();

	std::iter::successors(Some(host.as_str()), |name| {
		name.split_once('.').map(|(_label, parent)| parent)
	})
	.any(|name| set.contains(name))
}

/// How often to rebuild the list, or `None` when nothing is to be rebuilt.
///
/// Zero hours switches refreshing off deliberately: it is the old behaviour,
/// where a list is whatever it was when the proxy last started.
pub fn refresh_interval(config: &Config) -> Option<Duration> {
	let hours = config.blocklist.refresh_hours;

	(config.blocklist.enabled && hours > 0).then(|| Duration::from_secs(hours as u64 * 3600))
}

/// Start the background refresh, and say whether it started.
///
/// One thread for the process, not one per chain: the chains share a registry,
/// so a thread each would be a dozen copies of every list fetched to produce
/// the same answer. Returns immediately; the first refresh happens on the new
/// thread, so nothing here waits on the network.
pub fn spawn_refresh(config: Arc<Config>) -> bool {
	let Some(interval) = refresh_interval(&config) else {
		return false;
	};

	let lists = shared(&config);

	std::thread::spawn(move || {
		let agent = crate::fetch::agent(&config);

		loop {
			refresh(&lists, &config, &agent);
			std::thread::sleep(interval);
		}
	});

	true
}

/// Rebuild from every source and swap the result in.
///
/// The new list is built completely before it is published, so a source that
/// fails cannot empty what is already in force — the worst a refresh can do is
/// leave one list as stale as it was.
fn refresh(lists: &Blocklists, config: &Config, agent: &ureq::Agent) {
	let list = build(config, &fetched(config, agent));

	if !list.same_as(&lists.current()) {
		report(&list, configured(config));
	}

	// Swapped in even when it is identical, so that the age on the status page
	// answers "when did we last check", not "when did something last move".
	lists.replace(list);
}

/// Everything the configuration points at: the files, then the text each URL
/// most recently gave us.
fn build(config: &Config, lists: &[String]) -> Blocklist {
	let mut list = Blocklist::load(&config.blocklist.files, &config.blocklist.allow);

	for text in lists {
		list.add(text);
		list.sources += 1;
	}

	list
}

fn configured(config: &Config) -> usize {
	config.blocklist.files.len() + config.blocklist.urls.len()
}

/// Say what the list now holds. The only place a count is reported, so the log
/// says the same thing at startup as it does after a refresh.
fn report(list: &Blocklist, configured: usize) {
	if configured == 0 {
		log::info!("blocklist: no lists configured, so nothing is blocked");

		return;
	}

	if list.is_empty() {
		log::warn!("blocklist: nothing loaded from {configured} list(s); nothing is blocked");

		return;
	}

	log::info!(
		"blocklist: {} domains from {} of {configured} list(s)",
		list.len(),
		list.sources
	);
}

/// What each URL last gave us, read straight off disk. This is what makes a
/// restart without a network still a working blocker: yesterday's lists.
fn cached(config: &Config) -> Vec<String> {
	CACHE.cached(config, &config.blocklist.urls)
}

fn fetched(config: &Config, agent: &ureq::Agent) -> Vec<String> {
	CACHE.fetched(config, agent, &config.blocklist.urls)
}

enum Rule {
	Block(String),
	/// Blocked only where the page did not go looking for it itself.
	BlockEmbedded(String),
	Allow(String),
	/// Excepted only there. The whitelist half of `$third-party`, and honouring
	/// the block half without it turns a rule two lists agree on into a block
	/// where neither list meant one.
	AllowEmbedded(String),
}

fn fetch_metadata(req: &ProxyRequest, name: &str) -> Option<String> {
	req.headers
		.iter()
		.find(|(header, _)| header.eq_ignore_ascii_case(name))
		.map(|(_, value)| value.trim().to_ascii_lowercase())
}

/// Whether this request is third-party in the sense `$third-party` means it:
/// something a page pulled in from a different site than its own.
///
/// The browser answers this in `sec-fetch-site`, which is why this is the one
/// Adblock option mach5 can honour. Two details decide whether it is honoured
/// correctly, and getting either wrong blocks pages people asked for:
///
/// - **`same-site` is first-party.** Adblock compares registrable domains, and
///   `same-site` is the browser saying the registrable domains match — only
///   `cross-site` is a different one.
/// - **A top-level navigation is never third-party**, whatever it came from. A
///   link click from one site to another is `cross-site` too, and a document
///   request is its own first party, so `$third-party` must not match it. An
///   *iframe* navigation is a subresource and does match, which is why this
///   looks at `sec-fetch-dest` rather than `sec-fetch-mode`.
///
/// A client that sends no `sec-fetch-site` — curl, an app, an old browser — is
/// treated as first-party, because being wrong that way skips an advert and
/// being wrong the other way blocks a site somebody asked for.
fn embedded(req: &ProxyRequest) -> bool {
	if fetch_metadata(req, "sec-fetch-site").as_deref() != Some("cross-site") {
		return false;
	}

	fetch_metadata(req, "sec-fetch-dest").as_deref() != Some("document")
}

/// Parse one line of a list in whichever of the three formats it happens to be.
/// Anything else — cosmetic rules, URL patterns, regexes — is silently skipped.
///
/// A hosts line may name several hosts, which is why this returns a list.
fn parse(line: &str) -> Vec<Rule> {
	let line = line.trim();
	if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
		return Vec::new();
	}

	// A hosts file may put a comment after the name, and the whole line was
	// being thrown away for it — silently, in the direction of blocking less.
	// Only after whitespace: `example.com##.ad-banner` is a cosmetic rule, and
	// splitting that on `#` would turn it into a block on the site itself.
	let line = match line.find(" #").or_else(|| line.find("\t#")) {
		Some(at) => line[..at].trim(),
		None => line,
	};

	if let Some(rule) = line.strip_prefix("@@") {
		return one(match anchored(rule) {
			Anchored::Plain(domain) => normalize(domain).map(Rule::Allow),
			// Narrowed to third-party rather than dropped. Dropping it while
			// honouring the block half turns a domain the adservers list blocks
			// and the whitelist un-blocks into a block neither list meant.
			Anchored::ThirdParty(domain) => normalize(domain).map(Rule::AllowEmbedded),
			Anchored::Unreadable => None,
		});
	}

	if line.starts_with("||") {
		return one(match anchored(line) {
			Anchored::Plain(domain) => normalize(domain).map(Rule::Block),
			Anchored::ThirdParty(domain) => normalize(domain).map(Rule::BlockEmbedded),
			Anchored::Unreadable => None,
		});
	}

	// A hosts file line: an address, then the names being pointed at it — of
	// which there may be several, and dropping all but the first left the rest
	// unblocked with nothing said about it.
	if let Some((_address, rest)) = line.split_once(char::is_whitespace) {
		return rest
			.split_whitespace()
			.filter_map(normalize)
			.map(Rule::Block)
			.collect();
	}

	one(normalize(line).map(Rule::Block))
}

fn one(rule: Option<Rule>) -> Vec<Rule> {
	rule.into_iter().collect()
}

/// What an Adblock anchor rule turned out to say.
enum Anchored<'a> {
	/// `||ads.example.com^` — a plain domain match.
	Plain(&'a str),
	/// `||cdn.example^$third-party` — only where something else embedded it.
	ThirdParty(&'a str),
	/// Scoped by something this proxy cannot evaluate.
	Unreadable,
}

/// Read an Adblock anchor rule, options included.
///
/// The options after `$` are what scopes a rule, and stripping them widens it:
/// `||cdn.example^$third-party` means block that host only when something else
/// embeds it, and honouring the domain alone blocks the site you typed into the
/// address bar. The mirror case fails open — `@@||tracker.example^$document`
/// as an unconditional allowance quietly defeats a hosts-file block of the same
/// name from another list.
///
/// `$third-party` is honoured because a browser answers it directly in
/// `sec-fetch-site`; it is also much the commonest option in a real list, so
/// refusing it outright cost about two thousand domains against StevenBlack
/// plus EasyList. Everything else is refused, which is the rule `cosmetic`
/// already follows for domains it cannot fully parse: a rule whose scope cannot
/// be read is not ours to honour.
fn anchored(rule: &str) -> Anchored<'_> {
	let Some(rest) = rule.strip_prefix("||") else {
		return Anchored::Unreadable;
	};

	let (pattern, options) = match rest.split_once('$') {
		Some((pattern, options)) => (pattern, Some(options)),
		None => (rest, None),
	};

	let domain = pattern.split('^').next().unwrap_or(pattern);
	// A wildcard or a path means the rule is more than a domain match.
	if domain.contains(['*', '/']) {
		return Anchored::Unreadable;
	}

	match options {
		None => Anchored::Plain(domain),
		// Only on its own. `$third-party,script` is still scoped by something
		// unreadable, and `~third-party` is the negation.
		Some("third-party") => Anchored::ThirdParty(domain),
		Some(_) => Anchored::Unreadable,
	}
}

/// A name a hosts file points at loopback for its own sake, not to block it.
/// The `ip6-*` family are the same idea.
fn housekeeping(domain: &str) -> bool {
	HOUSEKEEPING.contains(&domain) || domain.starts_with("ip6-")
}

/// Lowercase and drop a trailing root dot. Single-label names are rejected: a
/// stray `localhost`, or the remains of a line we misread, would otherwise be a
/// parent of nothing useful — or, worse, of everything.
///
/// Shared with [`crate::cosmetic`], whose rules name domains in the same shape
/// and have the same reasons to refuse the ones that are not.
pub fn normalize(raw: &str) -> Option<String> {
	let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();

	if !domain.contains('.') || housekeeping(&domain) {
		return None;
	}

	let plausible = domain.split('.').all(|label| {
		!label.is_empty()
			&& label
				.chars()
				.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
	});

	plausible.then_some(domain)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn list(text: &str) -> Blocklist {
		let mut list = Blocklist::new(&[], Arc::new(crate::metrics::Metrics::default()));
		list.add(text);

		list
	}

	/// The chain link: a registry holding one list, with counters of its own so
	/// a test never reads the process's.
	fn registry(text: &str) -> Arc<Blocklists> {
		Arc::new(Blocklists::new(list(text)))
	}

	fn request(url: &str, accept: &str) -> ProxyRequest {
		ProxyRequest {
			method: "GET".to_string(),
			url: url.to_string(),
			headers: vec![("accept".to_string(), accept.to_string())],
			body: Vec::new(),
			peer: None,
		}
	}

	#[test]
	fn every_common_line_format_parses() {
		let list = list(
			"0.0.0.0 ads.example.com\n\
			 127.0.0.1\ttracker.example.net\n\
			 bare.example.org\n\
			 ||anchored.example.com^\n\
			 0.0.0.0 first.example.net second.example.net\n\
			 commented.example.org  # and a note about it\n",
		);

		assert!(list.blocks("ads.example.com"));
		assert!(list.blocks("tracker.example.net"));
		assert!(list.blocks("bare.example.org"));
		assert!(list.blocks("anchored.example.com"));
		assert!(
			list.blocks("first.example.net") && list.blocks("second.example.net"),
			"a hosts line may name several, and all but the first were dropped"
		);
		assert!(
			list.blocks("commented.example.org"),
			"a trailing comment lost the whole line"
		);
	}

	/// The options are what scopes an Adblock rule. Stripping them turns
	/// `||cdn.example^$third-party` — block this only when something else
	/// embeds it — into a block on the site you typed in, and turns
	/// `@@||tracker.example^$document` into a blanket allowance that quietly
	/// defeats a hosts-file block of the same name from another list. mach5
	/// cannot evaluate either scope, so it honours neither rule.
	#[test]
	fn a_rule_whose_scope_cannot_be_read_is_not_honoured() {
		let scoped = list(
			"0.0.0.0 tracker.example\n\
			 ||cdn.example^$third-party,script\n\
			 @@||tracker.example^$document\n",
		);

		assert!(
			!scoped.blocks("cdn.example"),
			"a conditional block must not become an unconditional one"
		);
		assert!(
			!scoped.blocked_embedded.contains("cdn.example"),
			"nor is `$third-party,script` a third-party rule: it is scoped by \
			 something else as well"
		);
		assert!(
			scoped.blocks("tracker.example"),
			"nor a conditional exception an unconditional one"
		);

		// Without options, both still work exactly as before.
		let plain = list("0.0.0.0 tracker.example\n@@||tracker.example^\n||cdn.example^\n");
		assert!(plain.blocks("cdn.example"));
		assert!(!plain.blocks("tracker.example"));
	}

	/// `$third-party` is the one option this proxy can answer, because a browser
	/// says which it is in `sec-fetch-site` — and it is much the commonest in a
	/// real list, so refusing it outright cost about two thousand domains
	/// against StevenBlack plus EasyList.
	#[test]
	fn a_third_party_rule_blocks_a_subresource_and_not_the_page() {
		let scoped = list("||cdn.example^$third-party\n");
		let ask = |site: Option<&str>, dest: Option<&str>| {
			let mut req = request("https://cdn.example/x.js", "*/*");
			for (name, value) in [("sec-fetch-site", site), ("sec-fetch-dest", dest)] {
				if let Some(value) = value {
					req.headers.push((name.to_string(), value.to_string()));
				}
			}

			scoped.blocks_request(&req, "cdn.example")
		};

		assert!(
			ask(Some("cross-site"), Some("script")),
			"a subresource from another site is what the rule is about"
		);
		assert!(
			ask(Some("cross-site"), Some("iframe")),
			"and so is a third-party frame"
		);
		assert!(
			!ask(Some("cross-site"), Some("document")),
			"but a link click is a navigation, and a document is its own first \
			 party — blocking it hands somebody a block page for a site they \
			 asked for by name"
		);
		assert!(
			!ask(Some("same-site"), Some("script")),
			"`same-site` means the registrable domains match, which is what \
			 `$third-party` compares — so this is first-party"
		);
		assert!(!ask(Some("none"), Some("document")), "typed into the address bar");
		assert!(!ask(Some("same-origin"), Some("script")), "its own page fetched it");
		assert!(
			!ask(None, None),
			"a client that says nothing is treated as the page itself: being \
			 wrong that way skips an advert, and being wrong the other way \
			 blocks a site somebody asked for"
		);

		// A plain rule still applies whatever the context.
		let plain = list("||cdn.example^\n");
		let mut req = request("https://cdn.example/x.js", "*/*");
		req.headers
			.push(("sec-fetch-site".to_string(), "none".to_string()));
		assert!(plain.blocks_request(&req, "cdn.example"));
	}

	/// Filter lists come in pairs: an adservers file blocks and a whitelist file
	/// cancels. Honouring the block half of `$third-party` while dropping the
	/// exception half turns a domain the two lists agree on into a block
	/// neither of them meant.
	#[test]
	fn a_third_party_exception_cancels_a_third_party_block() {
		let both = list("||tracker.example^$third-party\n@@||tracker.example^$third-party\n");

		let mut embedded = request("https://tracker.example/p.gif", "*/*");
		embedded.headers.push(("sec-fetch-site".to_string(), "cross-site".to_string()));
		embedded.headers.push(("sec-fetch-dest".to_string(), "image".to_string()));

		assert!(
			!both.blocks_request(&embedded, "tracker.example"),
			"the exception applies exactly where the block does"
		);

		// And an exception scoped to third-party does not un-block a plain
		// rule for a first-party request — there was nothing to un-block.
		let mixed = list("0.0.0.0 tracker.example\n@@||tracker.example^$third-party\n");
		let first_party = request("https://tracker.example/p.gif", "*/*");
		assert!(mixed.blocks_request(&first_party, "tracker.example"));
		assert!(
			!mixed.blocks_request(&embedded, "tracker.example"),
			"but it does cancel one for a third-party request, which is what \
			 a whitelist file is for"
		);
	}

	#[test]
	fn comments_and_blank_lines_are_ignored() {
		let list = list(
			"# a hosts file header\n\
			 \n\
			 ! an easylist header\n\
			 	\n\
			 0.0.0.0 real.example.com\n",
		);

		assert!(list.blocks("real.example.com"));
		assert!(
			!list.blocks("example.com"),
			"only the listed name is blocked"
		);
	}

	#[test]
	fn unsupported_rules_are_skipped() {
		let list = list(
			"example.com##.ad-banner\n\
			 example.com#@#.ad-banner\n\
			 ||example.com/ads/*\n\
			 ||*.example.com^\n\
			 /banner[0-9]+\\.gif/\n",
		);

		assert!(!list.blocks("example.com"));
		assert!(!list.blocks("ads.example.com"));
	}

	#[test]
	fn hosts_file_housekeeping_is_skipped() {
		let list = list(
			"127.0.0.1 localhost\n\
			 127.0.0.1 localhost.localdomain\n\
			 127.0.0.1 local\n\
			 255.255.255.255 broadcasthost\n\
			 ::1 ip6-localhost ip6-loopback\n\
			 fe00::0 ip6-localnet\n",
		);

		assert!(!list.blocks("localhost"));
		assert!(!list.blocks("localhost.localdomain"));
		assert!(!list.blocks("ip6-localhost"));
		assert!(!list.blocks("anything.example.com"));
	}

	#[test]
	fn single_label_entries_are_rejected() {
		let list = list("com\nnet\n0.0.0.0 nodot\n");

		assert!(
			!list.blocks("example.com"),
			"a bare TLD must not block a site"
		);
		assert!(!list.blocks("nodot"));
		assert_eq!(normalize("localhost"), None);
		assert_eq!(normalize("example.com."), Some("example.com".to_string()));
		assert_eq!(
			normalize("ADS.Example.COM"),
			Some("ads.example.com".to_string())
		);
	}

	#[test]
	fn parents_match_but_only_on_label_boundaries() {
		let list = list("doubleclick.net\n");

		assert!(list.blocks("doubleclick.net"));
		assert!(list.blocks("ad.g.doubleclick.net"));
		assert!(
			!list.blocks("notdoubleclick.net"),
			"substring is not a match"
		);
		assert!(!list.blocks("doubleclick.net.evil.com"));
		assert!(!list.blocks("net"));
	}

	#[test]
	fn exception_rules_win_over_a_block() {
		let list = list(
			"0.0.0.0 ads.example.com\n\
			 0.0.0.0 keep.ads.example.com\n\
			 @@||keep.ads.example.com^\n",
		);

		assert!(list.blocks("ads.example.com"));
		assert!(!list.blocks("keep.ads.example.com"));
	}

	#[test]
	fn configured_allowances_win_over_a_block() {
		let mut list = Blocklist::new(
			&["example.com".to_string()],
			Arc::new(crate::metrics::Metrics::default()),
		);
		list.add("0.0.0.0 ads.example.com\n0.0.0.0 ads.example.net\n");

		assert!(
			!list.blocks("ads.example.com"),
			"the whole domain is allowed"
		);
		assert!(list.blocks("ads.example.net"));
	}

	#[test]
	fn an_unlisted_host_is_not_answered() {
		let list = registry("0.0.0.0 ads.example.com\n");
		let mut req = request("https://example.org/index.html", "text/html");

		assert!(list.on_request(&mut req).is_none());
	}

	#[test]
	fn a_blocked_page_gets_no_content() {
		let list = registry("0.0.0.0 ads.example.com\n");
		let mut req = request("https://ads.example.com/frame.html", "text/html");

		let resp = list.on_request(&mut req).expect("listed host is blocked");

		assert_eq!(resp.status, 204);
		assert!(resp.body.is_empty());
		assert!(resp
			.headers
			.iter()
			.any(|(k, v)| k == "cache-control" && v == "no-store"));
		assert!(resp
			.headers
			.iter()
			.any(|(k, v)| k == "x-mach5" && v == "blocked"));
	}

	#[test]
	fn a_blocked_image_gets_a_pixel() {
		let list = registry("0.0.0.0 ads.example.com\n");
		let mut req = request(
			"https://ads.example.com/pixel.gif",
			"image/avif,image/webp,*/*",
		);

		let resp = list.on_request(&mut req).expect("listed host is blocked");

		assert_eq!(resp.status, 200);
		assert_eq!(resp.body, TRANSPARENT_GIF);
		assert!(resp
			.headers
			.iter()
			.any(|(k, v)| k == "content-type" && v == "image/gif"));
		assert!(resp
			.headers
			.iter()
			.any(|(k, v)| k == "x-mach5" && v == "blocked"));
	}

	#[test]
	fn only_a_blocked_request_is_counted() {
		let list = registry("0.0.0.0 ads.example.com\n");

		list.on_request(&mut request("https://example.org/index.html", "text/html"));

		assert_eq!(list.current().metrics.blocked.get(), 0);

		list.on_request(&mut request("https://ads.example.com/frame.html", "text/html"));
		list.on_request(&mut request("https://ads.example.com/pixel.gif", "image/webp"));

		assert_eq!(list.current().metrics.blocked.get(), 2);
	}

	#[test]
	fn blocking_never_claims_a_response_body() {
		let list = registry("0.0.0.0 ads.example.com\n");
		let head = ResponseHead {
			status: 200,
			headers: vec![("content-type".to_string(), "video/mp4".to_string())],
		};

		assert!(
			!list.wants_body(&request("https://example.org/clip.mp4", "*/*"), &head),
			"a request-only link must not switch off streaming"
		);
	}

	#[test]
	fn an_unreadable_file_is_not_fatal() {
		let list = Blocklist::load(&[PathBuf::from("/nonexistent/blocklist.txt")], &[]);

		assert!(list.is_empty());
		assert_eq!(list.sources, 0, "a file that could not be read is not a source");
	}

	/// Every chain holds the same registry, so a refresh has to reach all of
	/// them without any of them being rebuilt.
	#[test]
	fn a_swap_is_visible_to_everyone_holding_the_registry() {
		let lists = registry("0.0.0.0 ads.example.com\n");
		let chain = Arc::clone(&lists);

		assert!(chain.current().blocks("ads.example.com"));
		assert!(!chain.current().blocks("tracker.example.net"));

		lists.replace(list("0.0.0.0 tracker.example.net\n"));

		assert!(
			!chain.current().blocks("ads.example.com"),
			"the list that was replaced is gone"
		);
		assert!(chain.current().blocks("tracker.example.net"));
	}

	/// A request that has already taken its `Arc` matches against that list to
	/// the end, which is what makes the swap safe to do underneath it.
	#[test]
	fn a_list_taken_before_a_swap_is_still_the_old_one() {
		let lists = registry("0.0.0.0 ads.example.com\n");
		let taken = lists.current();

		lists.replace(list("0.0.0.0 tracker.example.net\n"));

		assert!(taken.blocks("ads.example.com"));
		assert!(!taken.blocks("tracker.example.net"));
		assert!(lists.current().blocks("tracker.example.net"));
	}

	#[test]
	fn the_chain_link_answers_from_the_list_in_force() {
		let lists = registry("0.0.0.0 ads.example.com\n");
		let ads = || request("https://ads.example.com/frame.html", "text/html");
		let tracker = || request("https://tracker.example.net/frame.html", "text/html");

		assert!(lists.on_request(&mut ads()).is_some());
		assert!(lists.on_request(&mut tracker()).is_none());

		lists.replace(list("0.0.0.0 tracker.example.net\n"));

		assert!(lists.on_request(&mut ads()).is_none());
		assert!(lists.on_request(&mut tracker()).is_some());
	}

	/// The link goes into the chain whether or not there is anything in it yet,
	/// because a refresh may fill it later. That costs one early return per
	/// request, and this is the test that says so.
	#[test]
	fn an_empty_list_in_the_chain_costs_one_lookup() {
		let lists = registry("");

		assert!(lists.current().is_empty());
		assert!(!covers(&lists.current().blocked, "example.com"));
		assert!(lists
			.on_request(&mut request("https://example.com/", "text/html"))
			.is_none());
	}

	#[test]
	fn zero_hours_is_what_switches_the_refresh_off() {
		let off = Config::from_str("[blocklist]\nrefresh_hours = 0\n").unwrap();
		let disabled = Config::from_str("[blocklist]\nenabled = false\n").unwrap();
		let hourly = Config::from_str("[blocklist]\nrefresh_hours = 1\n").unwrap();

		assert_eq!(refresh_interval(&off), None);
		assert_eq!(
			refresh_interval(&disabled),
			None,
			"nothing to keep fresh when nothing is blocked"
		);
		assert_eq!(refresh_interval(&hourly), Some(Duration::from_secs(3600)));
		assert_eq!(
			refresh_interval(&Config::default()),
			Some(Duration::from_secs(24 * 3600)),
			"a day by default"
		);
	}

	/// Startup reads the cache and nothing else — no network, and no waiting on
	/// one either.
	#[test]
	fn a_restart_starts_from_yesterdays_copy() {
		let dir = tempfile::tempdir().unwrap();
		let config = Config::from_str(&format!(
			"[paths]\ncache_dir = {:?}\n\n[blocklist]\nurls = [\"https://example.com/hosts\"]\n",
			dir.path()
		))
		.unwrap();
		let path = CACHE.path(&config, &config.blocklist.urls[0]);
		std::fs::create_dir_all(path.parent().unwrap()).unwrap();
		std::fs::write(&path, "0.0.0.0 ads.example.com\n").unwrap();

		let list = build(&config, &cached(&config));

		assert!(list.blocks("ads.example.com"));
		assert_eq!(list.sources, 1);
		assert_eq!(configured(&config), 1);
	}

	#[test]
	fn a_url_with_nothing_cached_contributes_nothing() {
		let dir = tempfile::tempdir().unwrap();
		let config = Config::from_str(&format!(
			"[paths]\ncache_dir = {:?}\n\n[blocklist]\nurls = [\"https://example.com/hosts\"]\n",
			dir.path()
		))
		.unwrap();

		assert!(cached(&config).is_empty());
		assert!(build(&config, &cached(&config)).is_empty());
	}

	#[test]
	fn a_rebuild_that_changed_nothing_is_the_same_list() {
		let one = list("0.0.0.0 ads.example.com\n");
		let same = list("0.0.0.0 ads.example.com\n");
		let more = list("0.0.0.0 ads.example.com\n0.0.0.0 ads.example.net\n");

		assert!(one.same_as(&same));
		assert!(!one.same_as(&more));
	}

	#[test]
	fn the_status_page_is_told_where_the_list_came_from() {
		let mut list = list("0.0.0.0 ads.example.com\n");
		list.sources = 2;
		let status = list.status();

		assert_eq!(status.domains, 1);
		assert_eq!(status.sources, 2);
		assert!(status.age < Duration::from_secs(1), "just built");
	}
}
