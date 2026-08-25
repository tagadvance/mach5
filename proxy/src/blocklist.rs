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
use std::io::Read;
use std::path::{Path, PathBuf};
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
const CACHE_DIR: &str = "blocklists";

/// Ceiling on a fetched list. The body arrives with a length nobody has
/// promised to honour and is read straight into memory, so it needs a bound;
/// generous, because the largest of the popular lists is a few megabytes.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;

/// Two sets of domains: what to block, and what to never block.
pub struct Blocklist {
	blocked: HashSet<String>,
	allowed: HashSet<String>,
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
			match parse(line) {
				Some(Rule::Block(domain)) => {
					self.blocked.insert(domain);
				}
				Some(Rule::Allow(domain)) => {
					self.allowed.insert(domain);
				}
				None => {}
			}
		}
	}

	pub fn is_empty(&self) -> bool {
		self.blocked.is_empty()
	}

	/// How many domains are loaded. The status page reports it so that a blocked
	/// count of zero can be told apart from a list that never loaded.
	pub fn len(&self) -> usize {
		self.blocked.len()
	}

	/// What the status page needs to tell a list that is being kept up to date
	/// from one that quietly stopped.
	pub fn status(&self) -> Status {
		Status {
			domains: self.blocked.len(),
			sources: self.sources,
			age: self.built.elapsed(),
		}
	}

	/// Whether two builds hold the same rules. A refresh that changed nothing
	/// should say nothing, and this is the only way to know which it was.
	fn same_as(&self, other: &Self) -> bool {
		self.blocked == other.blocked && self.allowed == other.allowed
	}

	/// True when this host, or any domain it sits under, is listed — so
	/// `doubleclick.net` covers `ad.g.doubleclick.net`. An allowance wins
	/// outright, whatever the lists say.
	pub fn blocks(&self, host: &str) -> bool {
		!covers(&self.allowed, host) && covers(&self.blocked, host)
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
		if !list.blocks(host) {
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
		let agent = agent(&config);

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
	config
		.blocklist
		.urls
		.iter()
		.filter_map(|url| std::fs::read_to_string(cache_path(config, url)).ok())
		.collect()
}

fn fetched(config: &Config, agent: &ureq::Agent) -> Vec<String> {
	config
		.blocklist
		.urls
		.iter()
		.filter_map(|url| fetch(config, agent, url))
		.collect()
}

/// The client lists are fetched with.
///
/// Certificate validation is on and there is no way to turn it off here: these
/// files decide what gets blocked, so a list served by whoever happens to be on
/// the wire is worse than no list. [`crate::insecure`] exists for one host
/// somebody typed a phrase for, and it is not reachable from this module.
///
/// Redirects are followed, where [`crate::upstream`]'s agent refuses them: the
/// obvious place to keep a list is a file in a git host, and those redirect.
fn agent(config: &Config) -> ureq::Agent {
	ureq::AgentBuilder::new()
		.timeout_connect(Duration::from_secs(config.limits.connect_timeout_seconds))
		.timeout_read(Duration::from_secs(config.limits.read_timeout_seconds))
		.build()
}

/// Fetch one list, falling back to the copy on disk.
///
/// `None` means this URL contributes nothing at all, which happens only when
/// the fetch failed and there is nothing cached to fall back to.
fn fetch(config: &Config, agent: &ureq::Agent, url: &str) -> Option<String> {
	let path = cache_path(config, url);
	let cached = std::fs::read_to_string(&path).ok();

	let mut request = agent.get(url);
	// Only worth asking "has this changed?" while we still hold the copy the
	// answer would be about.
	if cached.is_some() {
		let validators = read_validators(&meta_path(&path));

		if let Some(etag) = validators.etag {
			request = request.set("if-none-match", &etag);
		}

		if let Some(modified) = validators.last_modified {
			request = request.set("if-modified-since", &modified);
		}
	}

	match request.call() {
		Ok(response) => store(&path, url, response).or(cached),
		Err(ureq::Error::Status(304, _)) => {
			log::debug!("blocklist {url} is unchanged");

			cached
		}
		Err(e) => {
			log::warn!("cannot fetch blocklist {url}: {e}{}", fallback(&cached));

			cached
		}
	}
}

/// Which way a failed fetch fell, so a warning is never ambiguous about whether
/// anything from that list is still being blocked.
fn fallback(cached: &Option<String>) -> &'static str {
	match cached {
		Some(_) => "; keeping the cached copy",
		None => "; nothing is cached, so this list contributes nothing",
	}
}

/// Read the body and cache it, with whatever the origin gave us to revalidate
/// it with next time. A body that cannot be written to the cache is still
/// perfectly good in memory, so only the caching is lost.
fn store(path: &Path, url: &str, response: ureq::Response) -> Option<String> {
	let validators = Validators {
		etag: response.header("etag").map(str::to_string),
		last_modified: response.header("last-modified").map(str::to_string),
	};

	let mut body = Vec::new();
	if let Err(e) = response
		.into_reader()
		.take(MAX_LIST_BYTES)
		.read_to_end(&mut body)
	{
		log::warn!("cannot read blocklist {url}: {e}");

		return None;
	}

	// Lossy rather than a failure: one bad byte in a hundred thousand lines is
	// no reason to drop the other ninety-nine thousand, and a mangled line
	// fails to parse as a domain anyway.
	let text = String::from_utf8_lossy(&body).into_owned();

	match std::fs::create_dir_all(path.parent().unwrap_or(path)) {
		Ok(()) => match std::fs::write(path, &text) {
			Ok(()) => write_validators(&meta_path(path), &validators),
			Err(e) => log::warn!("cannot cache blocklist {url}: {e}"),
		},
		Err(e) => log::warn!("cannot create the blocklist cache directory: {e}"),
	}

	Some(text)
}

/// What an origin gave us to ask "has this changed?" with next time.
#[derive(Debug, Default, PartialEq)]
struct Validators {
	etag: Option<String>,
	last_modified: Option<String>,
}

/// Written beside the cached list as `name: value` lines. Named rather than
/// positional so that a file holding only one of the two cannot be read back as
/// the other — and a `last-modified` sent as an `if-none-match` is a request
/// nobody can answer sensibly.
fn write_validators(path: &Path, validators: &Validators) {
	let mut text = String::new();

	if let Some(etag) = &validators.etag {
		text.push_str(&format!("etag: {etag}\n"));
	}

	if let Some(modified) = &validators.last_modified {
		text.push_str(&format!("last-modified: {modified}\n"));
	}

	if text.is_empty() {
		// Nothing to revalidate with. Leaving the old file behind would have us
		// ask about a body we have just replaced.
		let _ = std::fs::remove_file(path);

		return;
	}

	if let Err(e) = std::fs::write(path, text) {
		log::warn!(
			"cannot record blocklist validators at {}: {e}",
			path.display()
		);
	}
}

/// Read back what [`write_validators`] wrote. Anything missing, unreadable or
/// unparsable is no validators at all: that costs one unconditional fetch,
/// where treating it as an error would cost the list.
fn read_validators(path: &Path) -> Validators {
	let mut validators = Validators::default();

	let Ok(text) = std::fs::read_to_string(path) else {
		return validators;
	};

	for line in text.lines() {
		// Only the first colon: both values are allowed to contain one.
		let Some((name, value)) = line.split_once(':') else {
			continue;
		};

		let value = value.trim();
		if value.is_empty() {
			continue;
		}

		match name.trim().to_ascii_lowercase().as_str() {
			"etag" => validators.etag = Some(value.to_string()),
			"last-modified" => validators.last_modified = Some(value.to_string()),
			_ => {}
		}
	}

	validators
}

/// Where a URL's last-fetched body is kept.
fn cache_path(config: &Config, url: &str) -> PathBuf {
	config
		.paths
		.cache_dir
		.join(CACHE_DIR)
		.join(format!("{}.txt", cache_name(url)))
}

/// The validators sit beside the list they are about, so that emptying the
/// cache directory can never leave one half without the other.
fn meta_path(cache: &Path) -> PathBuf {
	cache.with_extension("meta")
}

/// A filename for a URL: FNV-1a over its bytes, in hex.
///
/// The name has to be derived from the URL rather than taken from it — a URL is
/// not a filename, and two lists on one host must not collide. Nothing here is
/// a security decision, only a naming one, so a dozen lines beat a dependency
/// on a real hash. Hex keeps it to `[0-9a-f]`, which is a safe filename
/// everywhere and needs no escaping of its own.
fn cache_name(url: &str) -> String {
	const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
	const PRIME: u64 = 0x0000_0100_0000_01b3;

	let hash = url
		.bytes()
		.fold(OFFSET, |hash, byte| (hash ^ byte as u64).wrapping_mul(PRIME));

	format!("{hash:016x}")
}

enum Rule {
	Block(String),
	Allow(String),
}

/// Parse one line of a list in whichever of the three formats it happens to be.
/// Anything else — cosmetic rules, URL patterns, regexes — is silently skipped.
fn parse(line: &str) -> Option<Rule> {
	let line = line.trim();
	if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
		return None;
	}

	if let Some(rule) = line.strip_prefix("@@") {
		return Some(Rule::Allow(normalize(anchored(rule)?)?));
	}

	if line.starts_with("||") {
		return Some(Rule::Block(normalize(anchored(line)?)?));
	}

	// A hosts file line: an address, then the name it is being pointed at.
	if let Some((_address, rest)) = line.split_once(char::is_whitespace) {
		let name = rest.split_whitespace().next()?;

		return Some(Rule::Block(normalize(name)?));
	}

	Some(Rule::Block(normalize(line)?))
}

/// The domain of an Adblock anchor rule, `||ads.example.com^$third-party`.
/// Options after the separator are ignored; wildcards and paths mean the rule
/// is more than a domain match, so it is not ours to honour.
fn anchored(rule: &str) -> Option<&str> {
	let rest = rule.strip_prefix("||")?;
	let domain = rest.split(['^', '$']).next().unwrap_or(rest);

	(!domain.contains(['*', '/'])).then_some(domain)
}

/// A name a hosts file points at loopback for its own sake, not to block it.
/// The `ip6-*` family are the same idea.
fn housekeeping(domain: &str) -> bool {
	HOUSEKEEPING.contains(&domain) || domain.starts_with("ip6-")
}

/// Lowercase and drop a trailing root dot. Single-label names are rejected: a
/// stray `localhost`, or the remains of a line we misread, would otherwise be a
/// parent of nothing useful — or, worse, of everything.
fn normalize(raw: &str) -> Option<String> {
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
		}
	}

	#[test]
	fn every_common_line_format_parses() {
		let list = list(
			"0.0.0.0 ads.example.com\n\
			 127.0.0.1\ttracker.example.net\n\
			 bare.example.org\n\
			 ||anchored.example.com^\n\
			 ||options.example.com^$third-party\n",
		);

		assert!(list.blocks("ads.example.com"));
		assert!(list.blocks("tracker.example.net"));
		assert!(list.blocks("bare.example.org"));
		assert!(list.blocks("anchored.example.com"));
		assert!(list.blocks("options.example.com"));
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

	#[test]
	fn a_cache_name_is_stable_and_safe_to_write() {
		let hosts = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

		assert_eq!(cache_name(hosts), cache_name(hosts));
		assert_ne!(cache_name(hosts), cache_name(&format!("{hosts}2")));
		assert_ne!(
			cache_name("https://example.com/list?v=1"),
			cache_name("https://example.com/list?v=2"),
			"a query string is part of which list this is"
		);

		for url in [
			hosts,
			"https://example.com/lists/hosts?v=1&kind=ads",
			"https://例え.jp/リスト.txt",
		] {
			let name = cache_name(url);

			assert_eq!(name.len(), 16, "{name}");
			assert!(name.chars().all(|c| c.is_ascii_hexdigit()), "{name}");
		}
	}

	#[test]
	fn a_cached_list_and_its_validators_sit_together() {
		let config = Config::from_str("[paths]\ncache_dir = \"/cache\"\n").unwrap();
		let path = cache_path(&config, "https://example.com/hosts");
		let meta = meta_path(&path);

		assert_eq!(path.parent(), Some(Path::new("/cache/blocklists")));
		assert_eq!(path.extension(), Some("txt".as_ref()));
		assert_eq!(meta.extension(), Some("meta".as_ref()));
		assert_eq!(meta.parent(), path.parent());
		assert_eq!(meta.file_stem(), path.file_stem());
	}

	#[test]
	fn validators_round_trip_through_a_file() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("list.meta");
		let written = Validators {
			etag: Some(r#"W/"1a2b:3c""#.to_string()),
			last_modified: Some("Wed, 21 Oct 2015 07:28:00 GMT".to_string()),
		};

		write_validators(&path, &written);

		assert_eq!(read_validators(&path), written, "a colon is in both values");
	}

	#[test]
	fn a_validator_file_we_cannot_read_is_no_validators() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("list.meta");

		assert_eq!(read_validators(&path), Validators::default(), "no file");

		std::fs::write(&path, "\u{0}\nnonsense\netag:\nage: 3\n").unwrap();

		assert_eq!(
			read_validators(&path),
			Validators::default(),
			"a fetch we did not have to make beats a list we refused to load"
		);

		std::fs::write(&path, "ETag: \"abc\"\n").unwrap();
		let one = read_validators(&path);

		assert_eq!(one.etag.as_deref(), Some(r#""abc""#));
		assert_eq!(one.last_modified, None, "one is never read as the other");
	}

	#[test]
	fn nothing_to_revalidate_with_leaves_no_file_behind() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("list.meta");
		std::fs::write(&path, "etag: \"stale\"\n").unwrap();

		write_validators(&path, &Validators::default());

		assert!(
			!path.exists(),
			"a kept validator would ask about a body we have replaced"
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
		let path = cache_path(&config, &config.blocklist.urls[0]);
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
