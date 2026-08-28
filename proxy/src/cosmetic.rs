//! Cosmetic filter rules — hiding what the blocklist cannot refuse.
//!
//! [`crate::blocklist`] stops at domain matching, which is the right place for
//! it to stop and no help at all against a cookie banner served by the site
//! somebody actually wanted. [`crate::internal`]'s picker already answers that,
//! one element at a time and per host; these are the same answers written down
//! by other people, in the `example.com##.cookie-banner` syntax the published
//! cosmetic lists use.
//!
//! What comes out of here is CSS selectors and nothing else. This is not a
//! filter engine: network rules, scriptlet injections and the procedural
//! pseudo-classes that need one to mean anything are skipped rather than
//! half-honoured, exactly as the blocklist skips what it cannot honour. A rule
//! that survives is one a browser can carry out from a stylesheet on its own.
//!
//! The selectors reach a page through `/.mach5/hidden.css`, merged with
//! whatever the picker stored for that host. Lists come from files on disk,
//! from URLs, or both, and one background thread rebuilds the whole set on a
//! schedule — the same machinery, and for the same reason, as the blocklist's.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

use crate::config::Config;

/// Where fetched lists are kept, under the configured cache directory.
const CACHE: crate::fetch::Cache = crate::fetch::Cache::new("cosmetic", "cosmetic list");

/// Pseudo-classes that only mean something to a filter engine. A browser reads
/// one as a pseudo-class it has never heard of and drops the whole rule, so a
/// stylesheet carrying these is perfectly valid and hides nothing.
const PROCEDURAL: [&str; 6] = [
	":has-text(",
	":-abp-",
	":matches-path(",
	":upward(",
	":style(",
	":remove(",
];

/// Every selector a set of lists asks for, indexed by the domain that asked.
pub struct Cosmetic {
	/// Selectors to hide, by the domain a rule named. A domain covers its
	/// subdomains, so a host is looked up once per parent it has.
	hide: HashMap<String, BTreeSet<String>>,
	/// Selectors from rules that named no domain at all.
	generic: BTreeSet<String>,
	/// Selectors never to apply on a domain, whatever another rule says. Both
	/// `example.com#@#.x` and the `~example.com` in a rule's domain list land
	/// here: "not on this domain" is the whole of what either one means, and
	/// which rule it came from stops mattering the moment it is written down.
	unhide: HashMap<String, BTreeSet<String>>,
	/// Whether the generic rules are in play. Off by default — see
	/// [`crate::config::Cosmetic`].
	generic_enabled: bool,
	/// How many of the configured sources actually gave us something.
	sources: usize,
	/// When this set was built. A refresh builds a whole new one, so this is
	/// also how long ago the last refresh ran.
	built: Instant,
}

impl Cosmetic {
	fn new(generic_enabled: bool) -> Self {
		Self {
			hide: HashMap::new(),
			generic: BTreeSet::new(),
			unhide: HashMap::new(),
			generic_enabled,
			sources: 0,
			built: Instant::now(),
		}
	}

	/// Read every list, skipping — with a warning — any that cannot be read. A
	/// missing list is not worth refusing to start over.
	pub fn load(files: &[PathBuf], generic_enabled: bool) -> Self {
		let mut rules = Self::new(generic_enabled);

		for path in files {
			match std::fs::read_to_string(path) {
				Ok(text) => {
					rules.add(&text);
					rules.sources += 1;
				}
				Err(e) => log::warn!("cannot read cosmetic list {}: {e}", path.display()),
			}
		}

		rules
	}

	fn add(&mut self, text: &str) {
		for line in text.lines() {
			if let Some(rule) = parse(line) {
				self.insert(rule);
			}
		}
	}

	fn insert(&mut self, rule: Rule) {
		if rule.unhide {
			for domain in rule.domains {
				record(&mut self.unhide, domain, &rule.selector);
			}

			return;
		}

		// The exclusions first, because they hold whether or not anything is
		// left to hide: `~sub.example.com##.x` with no other domain is a
		// generic rule that one subdomain is carved out of.
		for domain in rule.except {
			record(&mut self.unhide, domain, &rule.selector);
		}

		if rule.domains.is_empty() {
			self.generic.insert(rule.selector);

			return;
		}

		for domain in rule.domains {
			record(&mut self.hide, domain, &rule.selector);
		}
	}

	/// Every selector this host should hide: what the lists name for it or for
	/// any domain above it, plus the generic rules when those are switched on,
	/// less anything an exception takes back.
	///
	/// Sorted, because this ends up in a stylesheet somebody may want to diff.
	pub fn selectors(&self, host: &str) -> Vec<String> {
		if self.hide.is_empty() && self.generic.is_empty() {
			return Vec::new();
		}

		let host = host.trim_end_matches('.').to_ascii_lowercase();
		let mut hidden: BTreeSet<&str> = BTreeSet::new();

		if self.generic_enabled {
			hidden.extend(self.generic.iter().map(String::as_str));
		}

		for name in parents(&host) {
			if let Some(set) = self.hide.get(name) {
				hidden.extend(set.iter().map(String::as_str));
			}
		}

		// After the hides rather than while collecting them: an exception is
		// about the selector, not about which rule put it there, so it has to
		// see everything before it can take anything back.
		for name in parents(&host) {
			let Some(set) = self.unhide.get(name) else {
				continue;
			};

			for selector in set {
				hidden.remove(selector.as_str());
			}
		}

		hidden.into_iter().map(str::to_string).collect()
	}

	pub fn is_empty(&self) -> bool {
		self.len() == 0
	}

	/// How many rules are loaded, counting a rule once per domain it named:
	/// that is the number the status page can compare against a list's own
	/// advertised size.
	pub fn len(&self) -> usize {
		let pairs = |map: &HashMap<String, BTreeSet<String>>| {
			map.values().map(BTreeSet::len).sum::<usize>()
		};

		pairs(&self.hide) + pairs(&self.unhide) + self.generic.len()
	}

	/// What the status page needs to tell a set of lists that is being kept up
	/// to date from one that quietly stopped.
	pub fn status(&self) -> Status {
		Status {
			rules: self.len(),
			sources: self.sources,
			age: self.built.elapsed(),
		}
	}

	/// Whether two builds hold the same rules. A refresh that changed nothing
	/// should say nothing, and this is the only way to know which it was.
	fn same_as(&self, other: &Self) -> bool {
		self.hide == other.hide
			&& self.generic == other.generic
			&& self.unhide == other.unhide
	}
}

/// Add one selector to whichever domain-keyed set it belongs in.
fn record(map: &mut HashMap<String, BTreeSet<String>>, domain: String, selector: &str) {
	map.entry(domain).or_default().insert(selector.to_string());
}

/// A host and every domain it sits under, longest first, so that a rule on
/// `example.com` reaches `www.example.com` without ever reaching
/// `notexample.com`.
fn parents(host: &str) -> impl Iterator<Item = &str> {
	std::iter::successors(Some(host), |name| {
		name.split_once('.').map(|(_label, parent)| parent)
	})
}

/// The rules as the status page sees them.
pub struct Status {
	pub rules: usize,
	pub sources: usize,
	/// How long ago the rules in force were built.
	pub age: Duration,
}

/// The rules currently in force, and the one thing a refresh replaces.
///
/// The indirection exists for the same reason [`crate::blocklist::Blocklists`]
/// has one: a refresh publishes a new set without every chain having to be
/// rebuilt around it.
pub struct Cosmetics {
	current: RwLock<Arc<Cosmetic>>,
}

impl Cosmetics {
	pub fn new(rules: Cosmetic) -> Self {
		Self {
			current: RwLock::new(Arc::new(rules)),
		}
	}

	/// The rules to match against right now.
	///
	/// The `Arc` is cloned out and the read lock dropped before the caller
	/// matches anything against it, so a request can never hold a refresh's
	/// write lock behind it for longer than a refcount bump.
	pub fn current(&self) -> Arc<Cosmetic> {
		let current = self.current.read().expect("cosmetic registry lock");

		Arc::clone(&current)
	}

	fn replace(&self, rules: Cosmetic) {
		*self.current.write().expect("cosmetic registry lock") = Arc::new(rules);
	}
}

/// Load once per process. Every worker builds its own chain, so lists parsed
/// per chain would be held in memory a couple of dozen times over.
///
/// Only what is already on disk is read here — the configured files, and the
/// last copy of each URL. Startup must not wait on somebody else's web server.
pub fn shared(config: &Config) -> Arc<Cosmetics> {
	static SHARED: OnceLock<Arc<Cosmetics>> = OnceLock::new();

	SHARED
		.get_or_init(|| {
			let rules = build(config, &cached(config));
			report(&rules, configured(config));

			Arc::new(Cosmetics::new(rules))
		})
		.clone()
}

/// How often to rebuild the rules, or `None` when nothing is to be rebuilt.
///
/// Zero hours switches refreshing off deliberately: the rules are then whatever
/// they were when the proxy last started.
pub fn refresh_interval(config: &Config) -> Option<Duration> {
	let hours = config.cosmetic.refresh_hours;

	(config.cosmetic.enabled && hours > 0).then(|| Duration::from_secs(hours as u64 * 3600))
}

/// Start the background refresh, and say whether it started.
///
/// One thread for the process, not one per chain. Returns immediately; the
/// first refresh happens on the new thread, so nothing here waits on the
/// network.
pub fn spawn_refresh(config: Arc<Config>) -> bool {
	let Some(interval) = refresh_interval(&config) else {
		return false;
	};

	let rules = shared(&config);

	std::thread::spawn(move || {
		let agent = crate::fetch::agent(&config);

		loop {
			refresh(&rules, &config, &agent);
			std::thread::sleep(interval);
		}
	});

	true
}

/// Rebuild from every source and swap the result in.
///
/// The new set is built completely before it is published, so a source that
/// fails cannot empty what is already in force — the worst a refresh can do is
/// leave one list as stale as it was.
fn refresh(rules: &Cosmetics, config: &Config, agent: &ureq::Agent) {
	let built = build(config, &fetched(config, agent));

	if !built.same_as(&rules.current()) {
		report(&built, configured(config));
	}

	// Swapped in even when it is identical, so that the age on the status page
	// answers "when did we last check", not "when did something last move".
	rules.replace(built);
}

/// Everything the configuration points at: the files, then the text each URL
/// most recently gave us.
fn build(config: &Config, lists: &[String]) -> Cosmetic {
	let mut rules = Cosmetic::load(&config.cosmetic.files, config.cosmetic.generic);

	for text in lists {
		rules.add(text);
		rules.sources += 1;
	}

	rules
}

fn configured(config: &Config) -> usize {
	config.cosmetic.files.len() + config.cosmetic.urls.len()
}

/// Say what is loaded. The only place a count is reported, so the log says the
/// same thing at startup as it does after a refresh.
fn report(rules: &Cosmetic, configured: usize) {
	if configured == 0 {
		log::info!("cosmetic: no lists configured, so nothing extra is hidden");

		return;
	}

	if rules.is_empty() {
		log::warn!("cosmetic: nothing loaded from {configured} list(s); nothing extra is hidden");

		return;
	}

	log::info!(
		"cosmetic: {} rules from {} of {configured} list(s)",
		rules.len(),
		rules.sources
	);
}

/// What each URL last gave us, read straight off disk. This is what makes a
/// restart without a network still hide things: yesterday's lists.
fn cached(config: &Config) -> Vec<String> {
	CACHE.cached(config, &config.cosmetic.urls)
}

fn fetched(config: &Config, agent: &ureq::Agent) -> Vec<String> {
	CACHE.fetched(config, agent, &config.cosmetic.urls)
}

/// One cosmetic rule, as far as we are willing to read one.
struct Rule {
	/// Domains it applies to. Empty means everywhere.
	domains: Vec<String>,
	/// Domains it does not apply to, whatever `domains` says.
	except: Vec<String>,
	selector: String,
	/// A `#@#` rule: the selector is not to be applied on `domains` at all.
	unhide: bool,
}

/// Parse one line, or skip it.
///
/// Only the two forms a stylesheet can carry out on its own are read — `##` to
/// hide and `#@#` to take a hide back. Everything else falls out here for want
/// of a separator it recognises: a network rule has no `#` in it, and `#$#`,
/// `#%#` and `#?#` have something else where the `##` would be.
fn parse(line: &str) -> Option<Rule> {
	let line = line.trim();
	if line.is_empty() || line.starts_with('!') {
		return None;
	}

	// A domain cannot contain a `#`, so the first one is where the separator
	// starts, whichever separator it turns out to be.
	let hash = line.find('#')?;
	let (domains, rest) = line.split_at(hash);

	let (selector, unhide) = match rest.strip_prefix("#@#") {
		Some(selector) => (selector, true),
		None => (rest.strip_prefix("##")?, false),
	};

	let selector = selector.trim();
	if !hideable(selector) {
		return None;
	}

	let mut wanted = Vec::new();
	let mut excluded = Vec::new();
	let mut named = false;

	for entry in domains.split(',') {
		let entry = entry.trim();
		if entry.is_empty() {
			continue;
		}

		named = true;

		match entry.strip_prefix('~') {
			// An unreadable exclusion is the dangerous half: honouring the rest
			// of the rule would apply it in exactly the place the list said not
			// to, so the whole rule goes.
			Some(name) => excluded.push(crate::host::normalize(name)?),
			// An unreadable inclusion only ever narrows the rule, so the rest of
			// it still stands.
			None => wanted.extend(crate::host::normalize(entry)),
		}
	}

	// A rule whose domains all fell out is not a generic rule; it is a rule we
	// failed to read, and treating it as one would apply it to every site there
	// is.
	if named && wanted.is_empty() && excluded.is_empty() {
		return None;
	}

	// `#@#` with no domain would switch a selector off everywhere from a list
	// nobody read, which is a bigger claim than a list gets to make here.
	if unhide && wanted.is_empty() {
		return None;
	}

	Some(Rule {
		domains: wanted,
		except: excluded,
		selector: selector.to_string(),
		unhide,
	})
}

/// Whether this is a selector, rather than something that only means anything
/// to a filter engine.
///
/// `+js(` is a scriptlet injection written after a `##`, the one place the
/// separator lies about what follows it. The [`PROCEDURAL`] forms are the other
/// half: they parse, they are valid CSS to write down, and they hide nothing.
/// The rest is [`crate::internal::usable`], because a selector from a list goes
/// into the same stylesheet as a selector from the picker and there is no
/// reason for two answers to the same question.
fn hideable(selector: &str) -> bool {
	!selector.starts_with("+js(")
		&& !PROCEDURAL.iter().any(|form| selector.contains(form))
		&& crate::internal::usable(selector)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn rules(text: &str) -> Cosmetic {
		let mut rules = Cosmetic::new(false);
		rules.add(text);

		rules
	}

	fn generic_rules(text: &str) -> Cosmetic {
		let mut rules = Cosmetic::new(true);
		rules.add(text);

		rules
	}

	#[test]
	fn a_domain_rule_hides_on_that_domain_and_below_it() {
		let rules = rules("example.com##.banner\n");

		assert_eq!(rules.selectors("example.com"), vec![".banner"]);
		assert_eq!(rules.selectors("www.example.com"), vec![".banner"]);
		assert_eq!(rules.selectors("a.b.example.com"), vec![".banner"]);
		assert!(rules.selectors("notexample.com").is_empty());
		assert!(rules.selectors("example.com.evil.test").is_empty());
		assert!(rules.selectors("example.net").is_empty());
	}

	#[test]
	fn one_rule_can_name_several_domains() {
		let rules = rules("example.com,other.example##.banner\n");

		assert_eq!(rules.selectors("example.com"), vec![".banner"]);
		assert_eq!(rules.selectors("deep.other.example"), vec![".banner"]);
		assert!(rules.selectors("third.example").is_empty());
	}

	#[test]
	fn a_tilde_carves_a_subdomain_out_of_the_rule() {
		let rules = rules("~sub.example.com,example.com##.banner\n");

		assert_eq!(rules.selectors("example.com"), vec![".banner"]);
		assert_eq!(rules.selectors("www.example.com"), vec![".banner"]);
		assert!(rules.selectors("sub.example.com").is_empty());
		assert!(
			rules.selectors("deeper.sub.example.com").is_empty(),
			"an exclusion covers what is under it, as a rule does"
		);
	}

	#[test]
	fn a_generic_rule_applies_only_when_it_is_switched_on() {
		let off = rules("##.ad-slot\n");
		let on = generic_rules("##.ad-slot\n");

		assert!(off.selectors("example.com").is_empty(), "off by default");
		assert!(off.selectors("anything.test").is_empty());
		assert_eq!(on.selectors("example.com"), vec![".ad-slot"]);
		assert_eq!(on.selectors("anything.test"), vec![".ad-slot"]);
	}

	#[test]
	fn a_generic_rule_can_be_carved_out_of_too() {
		let rules = generic_rules("~example.com##.ad-slot\n");

		assert_eq!(rules.selectors("other.test"), vec![".ad-slot"]);
		assert!(rules.selectors("example.com").is_empty());
		assert!(rules.selectors("www.example.com").is_empty());
	}

	#[test]
	fn an_unhide_rule_beats_a_hide() {
		let rules = rules(
			"example.com##.banner\n\
			 example.com##.promo\n\
			 example.com#@#.banner\n",
		);

		assert_eq!(rules.selectors("example.com"), vec![".promo"]);
		assert_eq!(
			rules.selectors("www.example.com"),
			vec![".promo"],
			"an unhide reaches the subdomains a hide would have"
		);
	}

	/// The order the two rules appear in must not decide the answer: an
	/// exception is not a later edit to a set, it is a statement about the
	/// selector.
	#[test]
	fn an_unhide_wins_whichever_order_it_is_read_in() {
		let after = rules("example.com##.banner\nexample.com#@#.banner\n");
		let before = rules("example.com#@#.banner\nexample.com##.banner\n");

		assert!(after.selectors("example.com").is_empty());
		assert!(before.selectors("example.com").is_empty());
	}

	/// A parent hides it, a child takes it back — which is the whole reason an
	/// unhide exists.
	#[test]
	fn an_unhide_on_a_subdomain_takes_back_a_parents_hide() {
		let rules = rules("example.com##.banner\nkeep.example.com#@#.banner\n");

		assert_eq!(rules.selectors("example.com"), vec![".banner"]);
		assert!(rules.selectors("keep.example.com").is_empty());
	}

	#[test]
	fn a_procedural_selector_is_skipped() {
		let rules = rules(
			"example.com##.item:has-text(Sponsored)\n\
			 example.com##div:-abp-contains(Ad)\n\
			 example.com##.x:matches-path(/shop)\n\
			 example.com##.y:upward(2)\n\
			 example.com##.z:style(height: 0)\n\
			 example.com##.w:remove()\n\
			 example.com##.plain\n",
		);

		assert_eq!(
			rules.selectors("example.com"),
			vec![".plain"],
			"a rule a browser would drop is not worth carrying"
		);
	}

	#[test]
	fn network_and_scriptlet_rules_are_skipped() {
		let rules = generic_rules(
			"||ads.example.com^\n\
			 @@||keep.example.com^\n\
			 ||example.com/ads/*$third-party\n\
			 example.com##+js(set-constant, x, true)\n\
			 example.com#$#body { overflow: auto }\n\
			 example.com#%#//scriptlet('abort-on-property-read', 'x')\n\
			 example.com#?#div:has(> .ad)\n\
			 0.0.0.0 ads.example.net\n\
			 example.com##.kept\n",
		);

		assert_eq!(rules.selectors("example.com"), vec![".kept"]);
		assert_eq!(rules.len(), 1, "nothing else was written down at all");
	}

	#[test]
	fn comments_and_blank_lines_are_skipped() {
		let rules = generic_rules(
			"! Title: Example List\n\
			 ! Expires: 4 days\n\
			 \n\
			 	\n\
			 [Adblock Plus 2.0]\n\
			 # a hosts file header\n\
			 example.com##.real\n",
		);

		assert_eq!(rules.selectors("example.com"), vec![".real"]);
		assert_eq!(rules.len(), 1);
	}

	/// A `>` is a child combinator, which cosmetic lists use constantly; the
	/// characters that could break out of the rule still cannot get in.
	#[test]
	fn a_selector_that_could_break_out_of_the_rule_is_skipped() {
		let rules = rules(
			"example.com##.wrap > .ad\n\
			 example.com##.x } body { display: none\n\
			 example.com##</style><script>alert(1)</script>\n\
			 example.com##.x; color: red\n\
			 example.com##@import url(https://evil.example/x.css)\n\
			 example.com##.x\\3c \n",
		);

		assert_eq!(rules.selectors("example.com"), vec![".wrap > .ad"]);
	}

	#[test]
	fn a_domain_we_cannot_read_never_widens_a_rule() {
		let rules = generic_rules(
			"example.*##.wildcard\n\
			 example.*,example.com##.narrowed\n\
			 ~example.*,other.example##.risky\n",
		);

		assert!(
			rules.selectors("example.test").is_empty(),
			"a rule whose domains all fell out is not a generic rule"
		);
		assert_eq!(rules.selectors("example.com"), vec![".narrowed"]);
		assert!(
			rules.selectors("other.example").is_empty(),
			"an unreadable exclusion takes the whole rule with it"
		);
	}

	#[test]
	fn a_domain_is_matched_case_and_root_dot_insensitively() {
		let rules = rules("EXAMPLE.com##.banner\n");

		assert_eq!(rules.selectors("WWW.Example.COM."), vec![".banner"]);
	}

	#[test]
	fn selectors_come_out_sorted_and_deduplicated() {
		let rules = generic_rules(
			"example.com##.zebra\n\
			 example.com##.apple\n\
			 www.example.com##.apple\n\
			 ##.middle\n",
		);

		assert_eq!(
			rules.selectors("www.example.com"),
			vec![".apple", ".middle", ".zebra"]
		);
	}

	#[test]
	fn an_unreadable_file_is_not_fatal() {
		let rules = Cosmetic::load(&[PathBuf::from("/nonexistent/easylist.txt")], false);

		assert!(rules.is_empty());
		assert_eq!(
			rules.sources, 0,
			"a file that could not be read is not a source"
		);
	}

	#[test]
	fn a_rebuild_that_changed_nothing_is_the_same_set() {
		let one = rules("example.com##.banner\n");
		let same = rules("example.com##.banner\n");
		let more = rules("example.com##.banner\nexample.com##.promo\n");

		assert!(one.same_as(&same));
		assert!(!one.same_as(&more));
	}

	#[test]
	fn a_swap_is_visible_to_everyone_holding_the_registry() {
		let registry = Arc::new(Cosmetics::new(rules("example.com##.banner\n")));
		let chain = Arc::clone(&registry);

		assert_eq!(chain.current().selectors("example.com"), vec![".banner"]);

		registry.replace(rules("example.com##.promo\n"));

		assert_eq!(chain.current().selectors("example.com"), vec![".promo"]);
	}

	#[test]
	fn zero_hours_is_what_switches_the_refresh_off() {
		let off = Config::from_str("[cosmetic]\nrefresh_hours = 0\n").unwrap();
		let disabled = Config::from_str("[cosmetic]\nenabled = false\n").unwrap();
		let hourly = Config::from_str("[cosmetic]\nrefresh_hours = 1\n").unwrap();

		assert_eq!(refresh_interval(&off), None);
		assert_eq!(refresh_interval(&disabled), None);
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
			"[paths]\ncache_dir = {:?}\n\n[cosmetic]\nurls = [\"https://example.com/easylist.txt\"]\n",
			dir.path()
		))
		.unwrap();
		let path = CACHE.path(&config, &config.cosmetic.urls[0]);
		std::fs::create_dir_all(path.parent().unwrap()).unwrap();
		std::fs::write(&path, "example.com##.banner\n").unwrap();

		let rules = build(&config, &cached(&config));

		assert_eq!(rules.selectors("example.com"), vec![".banner"]);
		assert_eq!(rules.sources, 1);
		assert_eq!(configured(&config), 1);
	}

	#[test]
	fn a_url_with_nothing_cached_contributes_nothing() {
		let dir = tempfile::tempdir().unwrap();
		let config = Config::from_str(&format!(
			"[paths]\ncache_dir = {:?}\n\n[cosmetic]\nurls = [\"https://example.com/easylist.txt\"]\n",
			dir.path()
		))
		.unwrap();

		assert!(cached(&config).is_empty());
		assert!(build(&config, &cached(&config)).is_empty());
	}

	#[test]
	fn the_status_page_is_told_where_the_rules_came_from() {
		let mut rules = rules("example.com,other.example##.banner\nexample.com#@#.promo\n");
		rules.sources = 2;
		let status = rules.status();

		assert_eq!(status.rules, 3, "a rule counts once per domain it named");
		assert_eq!(status.sources, 2);
		assert!(status.age < Duration::from_secs(1), "just built");
	}
}
