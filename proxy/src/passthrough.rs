//! Connections mach5 refuses to open.
//!
//! Everywhere else in this project mach5 terminates TLS, which means it holds
//! the plaintext of everything it carries. For most of the web that is the
//! point. For a bank it is the wrong guarantee entirely, and `[inject] exclude`
//! does not give the right one — it only stops mach5 *changing* a page it has
//! already decrypted.
//!
//! This is the other answer: read the name out of the ClientHello without
//! answering it, and for a listed host open a socket to the real origin and
//! copy bytes between the two. mach5 never has the keys, never sees a byte of
//! plaintext, and the client validates the origin's own certificate itself —
//! which is also the only thing that makes a certificate-pinning app work
//! through a proxy at all.
//!
//! The parser below reads exactly as much of the ClientHello as it takes to
//! find the SNI, and refuses anything it does not fully understand. A record
//! it cannot parse is not passed through: unrecognised means intercepted, the
//! same direction every other decision here fails in.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::config::Config;

/// A TLS record carries at most 2^14 bytes plus its five-byte header, so this
/// holds any single one of them whole.
///
/// It was 4096, which a real ClientHello can exceed — a browser offering a
/// post-quantum key share sends around two kilobytes, and one with a long
/// cipher list and many extensions goes further. Exceeding it meant the name
/// could not be read, and a name that cannot be read means the connection is
/// terminated rather than passed through. Sized to a maximal record, that
/// failure is gone rather than made less likely.
pub const PEEK_BYTES: usize = MAX_RECORD + RECORD_HEADER;

/// The most a single TLS record may carry, from RFC 8446 §5.1.
const MAX_RECORD: usize = 16384;

/// A legal record must never be larger than what is read, or the name in it
/// cannot be found and a listed host is decrypted. Checked at compile time
/// rather than in a test, so replacing `PEEK_BYTES` with a smaller literal
/// stops the build instead of quietly narrowing the promise.
const _: () = assert!(PEEK_BYTES >= MAX_RECORD + RECORD_HEADER);

/// How long a host learned from a challenge stays passed through.
///
/// It has to expire, and this is the only way back: once a host is passed
/// through mach5 never sees its responses again, so it can never notice that
/// the challenge stopped. A week is long enough to be useful on a trip and
/// short enough that a site which fixed itself comes back.
const LEARNED_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// Where fetched lists are kept, under the configured cache directory.
const CACHE: crate::fetch::Cache = crate::fetch::Cache::new("passthrough", "passthrough list");

/// Ceiling on how many hosts one fetched list may contribute.
///
/// A list of the hosts not to decrypt is a curated thing — a few banks, a
/// health provider, the handful of sites that fingerprint hard — and even a
/// thorough one is hundreds of names. A file with tens of thousands in it is
/// not that: it is a hosts *blocklist* pointed at the wrong setting, or a list
/// gone hostile, and either way honouring it would switch mach5 off for most of
/// the web without saying so. A list over the ceiling is refused whole rather
/// than truncated: half of a security list, chosen by whatever order the lines
/// happened to be in, is worse than none of it.
const MAX_HOSTS: usize = 10_000;

/// Labels a country-code registry sells names under, so `co.uk` and `com.au`
/// are the registry's own name and not a site.
const REGISTRY_LABELS: [&str; 18] = [
	"ac", "co", "com", "edu", "gen", "go", "gov", "govt", "id", "in", "ltd", "mil", "ne", "net",
	"nom", "or", "org", "sch",
];

const HANDSHAKE: u8 = 0x16;
/// Content type, legacy version, and the two-byte record length.
const RECORD_HEADER: usize = 5;
const CLIENT_HELLO: u8 = 0x01;
/// A handshake message header: one type byte and a 24-bit length.
const HANDSHAKE_HEADER: usize = 4;
const EXTENSION_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST: u8 = 0x00;

/// Hosts mach5 decided not to decrypt, as opposed to hosts it was told not to.
///
/// Kept apart from the configured list on purpose, and the separation is the
/// security boundary rather than tidiness:
///
/// - The **configured** list is what somebody wrote down — a bank, a health
///   provider — and nothing reachable from a web page may touch it. Removing an
///   entry from it would mean a page could make mach5 start decrypting a host
///   its operator had exempted.
/// - This list is **learned**, expires, and is only ever changed for the host
///   doing the asking, exactly as the hidden-element store is. A page on
///   `evil.example` can add or remove `evil.example` and nothing else, and the
///   worst it achieves is being decrypted, which is the default anyway.
pub struct Learned {
	path: PathBuf,
	hosts: Mutex<BTreeMap<String, Instant>>,
}

impl Learned {
	pub fn load(path: PathBuf) -> Self {
		// Only the names are persisted, not the deadlines: a restart resets the
		// clock, which is the forgiving direction — a host stays exempt a while
		// longer rather than being decrypted unexpectedly.
		let hosts = std::fs::read(&path)
			.ok()
			.and_then(|bytes| serde_json::from_slice::<Vec<String>>(&bytes).ok())
			.unwrap_or_default()
			.into_iter()
			.filter_map(|host| normalize_host(&host).map(|h| (h, Instant::now())))
			.collect();

		Self {
			path,
			hosts: Mutex::new(hosts),
		}
	}

	fn live(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, Instant>> {
		let mut hosts = self.hosts.lock().expect("learned passthrough lock");
		let now = Instant::now();
		hosts.retain(|_, at| now.duration_since(*at) < LEARNED_TTL);

		hosts
	}

	/// Whether this exact host was learned. Deliberately not the parent-domain
	/// walk `covers` does: a challenge on one host says nothing about its
	/// siblings, and widening it automatically would stop decrypting far more
	/// than was observed.
	pub fn holds(&self, host: &str) -> bool {
		let Some(host) = normalize_host(host) else {
			return false;
		};

		self.live().contains_key(&host)
	}

	/// Returns true when this is new, so the caller can say so once rather than
	/// on every request.
	pub fn add(&self, host: &str) -> bool {
		let Some(host) = normalize_host(host) else {
			return false;
		};

		let mut hosts = self.live();
		let fresh = !hosts.contains_key(&host);
		hosts.insert(host, Instant::now());
		let names: Vec<String> = hosts.keys().cloned().collect();
		drop(hosts);
		self.save(&names);

		fresh
	}

	pub fn remove(&self, host: &str) -> bool {
		let Some(host) = normalize_host(host) else {
			return false;
		};

		let mut hosts = self.live();
		let removed = hosts.remove(&host).is_some();
		let names: Vec<String> = hosts.keys().cloned().collect();
		drop(hosts);
		if removed {
			self.save(&names);
		}

		removed
	}

	/// Whether anything has been learned at all, so the front ends can skip the
	/// ClientHello peek when there is nothing either list could match.
	pub fn any(&self) -> bool {
		!self.live().is_empty()
	}

	/// Every learned host, for the status page.
	pub fn all(&self) -> Vec<String> {
		self.live().keys().cloned().collect()
	}

	fn save(&self, names: &[String]) {
		let Ok(json) = serde_json::to_vec(names) else {
			return;
		};

		if let Err(e) = crate::disk::replace(&self.path, &json) {
			log::warn!(
				"cannot save learned passthrough hosts to {}: {e}",
				self.path.display()
			);
		}
	}
}

/// Notices an origin refusing mach5, and remembers the host so the next
/// connection is spliced rather than decrypted.
///
/// It changes nothing about the response it sees — the client still gets the
/// challenge this time. There is no way to fix the current request: the
/// decision not to decrypt is made from the ClientHello, long before any of
/// this is known.
pub struct Watcher {
	learned: Arc<Learned>,
	enabled: bool,
}

impl Watcher {
	pub fn new(config: &Config) -> Self {
		Self {
			learned: learned(config),
			enabled: config.passthrough.learn_from_challenges,
		}
	}
}

impl crate::interceptor::Interceptor for Watcher {
	fn on_response_head(
		&self,
		req: &crate::interceptor::ProxyRequest,
		head: &mut crate::interceptor::ResponseHead,
	) {
		if !self.enabled || !is_a_challenge(head.status, &head.headers) {
			return;
		}

		let host = crate::host_of(&req.url);
		if self.learned.add(host) {
			log::warn!(
				"{host} answered with a bot challenge, which mach5 is the cause of — \
				 it will not be decrypted from the next connection on. Undo that at \
				 https://{host}/.mach5/ if it is wrong."
			);
		}
	}

	/// Reads the head and nothing else, so it must never be the reason a body
	/// is held in memory.
	fn wants_body(
		&self,
		_req: &crate::interceptor::ProxyRequest,
		_head: &crate::interceptor::ResponseHead,
	) -> bool {
		false
	}
}

/// Whether a response is a bot-check standing between the client and the site.
///
/// The point of noticing is that mach5 *causes* these. The origin sees mach5's
/// TLS handshake and HTTP/1.1 rather than the browser's, while the headers say
/// Chrome — a textbook automation signature — so a managed challenge fires and
/// then loops, because whatever passes the check is not what retries it.
///
/// `cf-mitigated` is Cloudflare saying so in as many words and is the signal
/// worth trusting. The rest is a deliberately narrow fallback: a challenge
/// status, from a server that says it is Cloudflare, with a challenge-platform
/// path in the body. Narrow because a false positive means quietly not
/// decrypting a site — which is safe, but also means no blocking on it, and
/// that should not happen by accident.
pub fn is_a_challenge(status: u16, headers: &[(String, String)]) -> bool {
	let header = |name: &str| {
		headers
			.iter()
			.find(|(h, _)| h.eq_ignore_ascii_case(name))
			.map(|(_, v)| v.trim().to_ascii_lowercase())
	};

	if header("cf-mitigated").as_deref() == Some("challenge") {
		return true;
	}

	if !matches!(status, 403 | 503) {
		return false;
	}

	header("server").is_some_and(|s| s.contains("cloudflare"))
		&& headers.iter().any(|(name, value)| {
			name.eq_ignore_ascii_case("set-cookie") && value.to_ascii_lowercase().contains("cf_chl")
		})
}

/// Whether this name must not be decrypted, for any of the three reasons.
///
/// The lists are checked separately and matched differently on purpose. A
/// configured entry covers its subdomains, because that is what somebody
/// writing down a bank means, and a fetched one is the same statement from a
/// file so it is matched the same way. A learned one is exact: a challenge on
/// one host says nothing about its siblings, and widening it automatically
/// would stop decrypting far more than was ever observed.
pub fn never_decrypt(configured: &Passthrough, learned: &Learned, host: &str) -> bool {
	configured.covers(host) || learned.holds(host)
}

/// One per process, beside the configured list.
pub fn learned(config: &Config) -> Arc<Learned> {
	static SHARED: std::sync::OnceLock<Arc<Learned>> = std::sync::OnceLock::new();

	SHARED
		.get_or_init(|| {
			Arc::new(Learned::load(
				config.paths.state_dir.join("passthrough.json"),
			))
		})
		.clone()
}

fn normalize_host(host: &str) -> Option<String> {
	let host = host.trim().trim_end_matches('.').to_ascii_lowercase();

	// The same rule the configured list follows: a name reaches the wire as
	// ASCII, so anything else can never match what arrives.
	(!host.is_empty() && host.contains('.') && host.is_ascii()).then_some(host)
}

/// The hosts never to decrypt.
///
/// Two sets, not one, and the split is the same kind of boundary [`Learned`]
/// draws. `hosts` is what somebody wrote in the configuration file and is
/// built once and never touched again. `fetched` is what the lists in
/// `[passthrough] urls` most recently said, and a refresh replaces it every
/// few hours. Keeping them apart makes "nothing a fetched list does can drop a
/// host somebody wrote down" true by construction rather than by care: the
/// refresh has no way to reach `hosts` at all.
///
/// For *matching* the two are the same thing — a fetched entry covers its
/// subdomains exactly as a configured one does, because it is the same kind of
/// statement, only from a file. That is the difference from `Learned`, which is
/// exact and expires.
pub struct Passthrough {
	hosts: HashSet<String>,
	/// Swapped whole by a refresh. The `Arc` is cloned out and the lock dropped
	/// before anything is matched against it, as the blocklist registry does:
	/// matching walks a host's parents, and holding a read lock across that
	/// would put the refresh's write lock behind every connection in flight.
	fetched: RwLock<Arc<HashSet<String>>>,
	port: u16,
}

impl Passthrough {
	pub fn new(config: &Config) -> Self {
		let hosts = config
			.passthrough
			.hosts
			.iter()
			.map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
			.filter(|host| !host.is_empty())
			.filter(|host| {
				// A name reaches the wire as ASCII: a browser sends the
				// punycode. So an entry written in unicode matches neither
				// what arrives nor anything else, and the host it was meant to
				// protect is quietly intercepted. Said out loud, because the
				// whole value of this list is that being on it means something.
				if !host.is_ascii() {
					log::warn!(
						"[passthrough] hosts: ignoring {host:?} — a name arrives as \
						 punycode (xn--...), so this entry can never match. Convert it, \
						 or the host is intercepted like any other."
					);

					return false;
				}

				true
			})
			.collect();

		// Only what is already on disk is read here — the last copy of each
		// URL. Startup must not wait on somebody else's web server, and a
		// restart with no network still has to come up with the same hosts
		// exempt as before it.
		let fetched: HashSet<String> = cached(config).into_iter().flatten().collect();

		if !config.passthrough.urls.is_empty() {
			report(fetched.len(), config.passthrough.urls.len());
		}

		Self {
			hosts,
			fetched: RwLock::new(Arc::new(fetched)),
			port: config.passthrough.port,
		}
	}

	/// The fetched set to match against right now.
	fn fetched(&self) -> Arc<HashSet<String>> {
		Arc::clone(&self.fetched.read().expect("passthrough fetched lock"))
	}

	fn replace_fetched(&self, hosts: HashSet<String>) {
		*self.fetched.write().expect("passthrough fetched lock") = Arc::new(hosts);
	}

	/// Where a passed-through connection is carried to.
	pub fn port(&self) -> u16 {
		self.port
	}

	/// Whether this name is one mach5 must not terminate.
	///
	/// A parent covers its subdomains, as it does in the blocklist: listing
	/// `example-bank.com` and then being handed `secure.example-bank.com`
	/// undecrypted is what anyone writing that line meant.
	pub fn covers(&self, host: &str) -> bool {
		crate::blocklist::covers(&self.hosts, host)
			|| crate::blocklist::covers(&self.fetched(), host)
	}

	/// Whether anything at all is listed, so the front ends can skip the
	/// ClientHello peek. A fetched list counts: leaving it out here would have
	/// every host on it decrypted despite `covers` saying otherwise, which is
	/// exactly the silent failure this module exists to avoid.
	pub fn is_empty(&self) -> bool {
		self.hosts.is_empty() && self.fetched().is_empty()
	}
}

pub fn shared(config: &Config) -> Arc<Passthrough> {
	static SHARED: std::sync::OnceLock<Arc<Passthrough>> = std::sync::OnceLock::new();

	SHARED
		.get_or_init(|| Arc::new(Passthrough::new(config)))
		.clone()
}

/// How often to re-fetch the lists, or `None` when there is nothing to fetch.
///
/// Zero hours switches refreshing off deliberately, as it does for the
/// blocklist: the lists are then whatever they were when the proxy last
/// started.
pub fn refresh_interval(config: &Config) -> Option<Duration> {
	let hours = config.passthrough.refresh_hours;

	(!config.passthrough.urls.is_empty() && hours > 0)
		.then(|| Duration::from_secs(hours as u64 * 3600))
}

/// Start the background refresh, and say whether it started.
///
/// One thread for the process, like the blocklist's. Returns immediately; the
/// first fetch happens on the new thread, so nothing here waits on the network.
pub fn spawn_refresh(config: Arc<Config>) -> bool {
	let Some(interval) = refresh_interval(&config) else {
		return false;
	};

	let list = shared(&config);

	std::thread::spawn(move || {
		let agent = crate::fetch::agent(&config);
		// What each URL last gave us, seeded from the copies on disk that
		// `Passthrough::new` has already matched against. The refresh carries
		// it forward rather than rebuilding it from nothing, because it is the
		// only record of which list contributed which hosts — and that is what
		// a list coming back unreadable has to fall back to.
		let mut held = cached(&config);

		loop {
			refresh(&list, &config, &agent, &mut held);
			std::thread::sleep(interval);
		}
	});

	true
}

/// Re-fetch every list and swap the union in.
fn refresh(list: &Passthrough, config: &Config, agent: &ureq::Agent, held: &mut [HashSet<String>]) {
	for (url, held) in config.passthrough.urls.iter().zip(held.iter_mut()) {
		// One URL at a time, because `fetched` drops a URL it could not get
		// anything for and a batched call would not say which one that was.
		// Losing which list a host came from loses the ability to keep it.
		let text = CACHE.fetched(config, agent, std::slice::from_ref(url)).pop();

		update(held, text.as_deref(), url);
	}

	let hosts: HashSet<String> = held.iter().flatten().cloned().collect();
	let changed = hosts != *list.fetched();

	if changed {
		report(hosts.len(), config.passthrough.urls.len());
	}

	list.replace_fetched(hosts);
}

/// What one list contributes, given whatever it gave us this time.
///
/// This is where the list fails in one direction only. A host wrongly on it is
/// a site that keeps its own TLS and loses mach5's blocking and compression; a
/// host wrongly off it is a bank being decrypted. So every way this can go
/// wrong — nothing fetched and nothing cached, a body that is an error page
/// rather than a list, a list over the ceiling — leaves what this URL gave us
/// last time exactly as it was. The only thing that replaces a contribution is
/// a list that parsed to at least one usable host.
fn update(held: &mut HashSet<String>, text: Option<&str>, url: &str) {
	let Some(text) = text else {
		// The fetch failed and nothing is cached for it either; `fetch` has
		// already warned. Whatever this URL gave us before stands.
		return;
	};

	let hosts = parse(text, url);
	if hosts.is_empty() {
		log::warn!(
			"[passthrough] {url} gave us no host we can use — keeping the {} it gave us \
			 last time rather than starting to decrypt them",
			held.len()
		);

		return;
	}

	*held = hosts;
}

/// What each URL last gave us, parsed, one entry per configured URL.
///
/// Per URL rather than merged, and read here rather than through
/// [`crate::fetch::Cache::cached`], because that drops the URLs it could not
/// read — and a refresh has to be able to say *which* list a host came from to
/// be able to keep it when that list next comes back broken.
fn cached(config: &Config) -> Vec<HashSet<String>> {
	config
		.passthrough
		.urls
		.iter()
		.map(|url| match std::fs::read_to_string(CACHE.path(config, url)) {
			Ok(text) => parse(&text, url),
			Err(_) => HashSet::new(),
		})
		.collect()
}

/// Say what the fetched lists now hold, at startup and whenever a refresh moves
/// it. Never silently: this decides what is not decrypted, and a list that
/// quietly stopped loading looks exactly like one that never had anything in
/// it.
fn report(hosts: usize, configured: usize) {
	if hosts == 0 {
		log::warn!(
			"[passthrough] nothing loaded from {configured} fetched list(s); only the \
			 hosts written down in the configuration are exempt"
		);

		return;
	}

	log::info!("[passthrough] {hosts} host(s) from {configured} fetched list(s)");
}

/// Read a fetched list: one host per line, `#` and `!` comments, blank lines,
/// and hosts-file lines (`0.0.0.0 bank.example`), because that is the shape
/// most published lists come in.
///
/// Deliberately *not* `blocklist::parse`, which reads the same files.
/// That returns Adblock rules, and a rule has a scope this list has no reading
/// for: `@@||bank.example^` is an *exception* — the list saying "do not block
/// this" — and honouring it here would turn a line that means nothing about
/// decryption into a host mach5 stops decrypting. `||cdn.example^$third-party`
/// is the same problem the other way. Only the label rules are shared, through
/// [`crate::blocklist::normalize`], so that a name means the same thing
/// wherever it was written.
fn parse(text: &str, url: &str) -> HashSet<String> {
	let mut hosts = HashSet::new();
	let mut refused = 0usize;

	for line in text.lines() {
		let line = line.trim();
		if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
			continue;
		}

		// A hosts file may put a comment after the name. Only after
		// whitespace, so a `#` inside something else does not split a line in
		// half and leave a fragment to be read as a host.
		let line = match line.find(" #").or_else(|| line.find("\t#")) {
			Some(at) => line[..at].trim(),
			None => line,
		};

		// A hosts-file line is an address and then the names pointed at it, of
		// which there may be several.
		let names = match line.split_once(char::is_whitespace) {
			Some((_address, rest)) => rest,
			None => line,
		};

		for name in names.split_whitespace() {
			match entry(name) {
				Some(host) => {
					hosts.insert(host);
				}
				None => refused += 1,
			}
		}
	}

	if hosts.len() > MAX_HOSTS {
		log::error!(
			"[passthrough] {url} names {} hosts, past the ceiling of {MAX_HOSTS}. That is \
			 not a list of hosts to leave alone, it is something else pointed at the \
			 wrong setting — refusing all of it rather than an arbitrary half",
			hosts.len()
		);

		return HashSet::new();
	}

	if refused > 0 {
		log::warn!("[passthrough] {url}: {refused} line(s) are not a host mach5 will exempt");
	}

	hosts
}

/// One line of a fetched list as a host, or `None` when it is not one this list
/// may add.
///
/// The label rules are [`crate::blocklist::normalize`]'s — lowercased, no
/// trailing root dot, at least two labels, ASCII only (a name reaches the wire
/// as punycode, so a unicode entry could never match anything). What is added
/// on top is a ceiling on *how much* one line may exempt, because these lists
/// come from wherever somebody pointed the configuration and a single line is
/// otherwise enough to switch decryption off for a whole country's registry.
fn entry(raw: &str) -> Option<String> {
	// `*.bank.example` is how some published lists spell what an entry here
	// already means, since a parent covers its subdomains. Stripping the
	// wildcard keeps the host rather than silently dropping it.
	let raw = raw.strip_prefix("*.").unwrap_or(raw);
	let host = crate::blocklist::normalize(raw)?;

	// DNS's own limits. Nothing longer can be a name that ever arrives, so a
	// longer line is filler.
	if host.len() > 253 || host.split('.').any(|label| label.len() > 63) {
		return None;
	}

	(!is_public_suffix(&host)).then_some(host)
}

/// Whether this is a registry's own name rather than a site — `com`, `co.uk`.
///
/// One such entry exempts every name beneath it, which for `co.uk` is most of
/// a country. That is not a decision to take from a file fetched over the
/// network, so it is refused and counted.
///
/// Not the full Public Suffix List: that is a megabyte of data and a dependency
/// to answer one question, and it needs its own refresh to stay right. These
/// are the two shapes that do the damage. A single label — `com`, `localhost`,
/// the remains of a line we misread — is already refused by `normalize`, so
/// what is left is a two-label name under a two-letter (country-code) TLD whose
/// first label is one a registry sells under. Anything longer is somebody's
/// name, whoever sold it to them.
fn is_public_suffix(host: &str) -> bool {
	let labels: Vec<&str> = host.split('.').collect();

	match labels.as_slice() {
		[second, tld] => tld.len() == 2 && REGISTRY_LABELS.contains(second),
		_ => false,
	}
}

/// What a caller holding the first bytes off a socket should do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Hello {
	/// Not the start of a TLS handshake record. Nothing to wait for.
	NotTls,
	/// A handshake record, and this many bytes are needed to hold all of it.
	Want(usize),
	/// The whole record is here.
	Complete,
}

/// Whether the whole first handshake record has arrived yet.
///
/// This exists because a ClientHello no longer fits in one TCP segment. A
/// modern browser offering a post-quantum key share sends about two kilobytes,
/// so it arrives in two segments — and reading whatever happened to be in the
/// socket when it was first readable gave [`server_name`] a truncated record,
/// which it correctly refused to parse. The refusal means "terminate it", so
/// whether a listed bank was decrypted came down to TCP segmentation.
pub fn have_hello(bytes: &[u8]) -> Hello {
	match bytes.first() {
		Some(&HANDSHAKE) => {}
		// Nothing yet: a client that has connected and said nothing is still
		// worth waiting a moment for.
		None => return Hello::Want(RECORD_HEADER),
		Some(_) => return Hello::NotTls,
	}

	let Some(assembled) = assemble(bytes) else {
		return Hello::NotTls;
	};

	// The handshake header is four bytes: a type and a 24-bit length. Until
	// they have all arrived there is nothing to size the wait against, so ask
	// for whatever would finish the record now arriving — or, if none has
	// started, for a header to read.
	if assembled.payload.len() < HANDSHAKE_HEADER {
		return Hello::Want(
			assembled
				.pending
				.unwrap_or(assembled.consumed + RECORD_HEADER),
		);
	}

	let declared = u32::from_be_bytes([
		0,
		assembled.payload[1],
		assembled.payload[2],
		assembled.payload[3],
	]) as usize;
	let needed = HANDSHAKE_HEADER + declared;

	if assembled.payload.len() >= needed {
		return Hello::Complete;
	}

	// A lower bound on what the socket must hold. Under-estimating only costs
	// another turn of the caller's loop; over-estimating makes it give up on a
	// hello that was still arriving, which for a listed host is the expensive
	// direction — so this stays a bound and never a guess.
	let missing = needed - assembled.payload.len();

	Hello::Want(match assembled.pending {
		// A record is already on its way and may carry all that is missing.
		Some(pending) => pending.max(assembled.consumed + missing),
		// Nothing started, so at least one more header on top of the bytes.
		None => assembled.consumed + RECORD_HEADER + missing,
	})
}

/// The handshake bytes carried by consecutive handshake records, joined.
///
/// A handshake message may be split across several TLS records — legal, and
/// what defeated reading only the first one. Whether a listed host was
/// decrypted then came down to how the client chose to frame its hello.
struct Assembled {
	payload: Vec<u8>,
	/// How much of `bytes` the complete records accounted for, so a caller can
	/// say what more it needs without recounting.
	consumed: usize,
	/// When a further record has begun arriving and its header can be read,
	/// how many bytes from the start of `bytes` would complete it.
	pending: Option<usize>,
}

fn assemble(bytes: &[u8]) -> Option<Assembled> {
	let mut payload = Vec::new();
	let mut consumed = 0;
	let mut pending = None;

	while bytes.len() - consumed >= RECORD_HEADER {
		let header = &bytes[consumed..consumed + RECORD_HEADER];
		if header[0] != HANDSHAKE {
			// Something that is not more handshake. Whatever has been gathered
			// is all the handshake there is going to be.
			break;
		}

		let length = u16::from_be_bytes([header[3], header[4]]) as usize;
		if length > MAX_RECORD {
			// Longer than a record may be, so this is not a stream we have
			// understood, and guessing at a name from it is the one thing this
			// module must never do.
			return None;
		}

		let end = consumed + RECORD_HEADER + length;
		if end > bytes.len() {
			// The record is still arriving. Stop here rather than reading a
			// partial one, and leave `consumed` on the last whole record — but
			// remember exactly what would finish this one, because that is a
			// better answer than a guess.
			pending = Some(end);

			break;
		}

		payload.extend_from_slice(&bytes[consumed + RECORD_HEADER..end]);
		consumed = end;
	}

	Some(Assembled {
		payload,
		consumed,
		pending,
	})
}

/// The server name from a TLS ClientHello, if this is one and it carries a
/// name we can read.
///
/// Deliberately strict. Every length in a TLS record is explicit, so anything
/// that does not add up is a record we have misunderstood — and a
/// misunderstanding here would mean deciding not to decrypt a connection on the
/// strength of a name we invented. `None` means "carry on and terminate it",
/// which is the safe direction to be wrong in.
pub fn server_name(bytes: &[u8]) -> Option<String> {
	// Joined across records first. A hello framed as several records is legal,
	// and parsing only the first one read a truncated message, refused it, and
	// so terminated a connection somebody had exempted.
	let joined = assemble(bytes)?;
	let mut handshake = Reader::new(&joined.payload);

	if handshake.u8()? != CLIENT_HELLO {
		return None;
	}
	let handshake_length = handshake.u24()? as usize;
	let mut hello = Reader::new(handshake.take(handshake_length)?);

	// Client version, then the 32-byte random.
	hello.skip(2 + 32)?;
	// Session id, cipher suites, compression methods: each a length then that
	// many bytes, and none of them of any interest here.
	let session = hello.u8()? as usize;
	hello.skip(session)?;
	let ciphers = hello.u16()? as usize;
	hello.skip(ciphers)?;
	let compression = hello.u8()? as usize;
	hello.skip(compression)?;

	// A ClientHello with no extensions has no SNI, which is not a failure to
	// parse — just nothing to find.
	let extensions_length = hello.u16()? as usize;
	let mut extensions = Reader::new(hello.take(extensions_length)?);

	while let Some(kind) = extensions.u16() {
		let length = extensions.u16()? as usize;
		let body = extensions.take(length)?;

		if kind == EXTENSION_SERVER_NAME {
			return first_host_name(body);
		}
	}

	None
}

/// The first `host_name` entry in a server_name extension.
fn first_host_name(body: &[u8]) -> Option<String> {
	let mut list = Reader::new(body);
	let list_length = list.u16()? as usize;
	let mut names = Reader::new(list.take(list_length)?);

	while let Some(kind) = names.u8() {
		let length = names.u16()? as usize;
		let name = names.take(length)?;

		if kind == NAME_TYPE_HOST {
			// A host name is ASCII by the time it reaches the wire; anything
			// else is not one we should be matching a list against.
			if !name.is_ascii() {
				return None;
			}

			return Some(String::from_utf8_lossy(name).to_ascii_lowercase());
		}
	}

	None
}

/// A cursor that yields `None` rather than panicking at the end of the buffer,
/// so a truncated or hostile record simply fails to parse.
struct Reader<'a> {
	bytes: &'a [u8],
	at: usize,
}

impl<'a> Reader<'a> {
	fn new(bytes: &'a [u8]) -> Self {
		Self { bytes, at: 0 }
	}

	fn take(&mut self, count: usize) -> Option<&'a [u8]> {
		let end = self.at.checked_add(count)?;
		let slice = self.bytes.get(self.at..end)?;
		self.at = end;

		Some(slice)
	}

	fn skip(&mut self, count: usize) -> Option<()> {
		self.take(count).map(|_| ())
	}

	fn u8(&mut self) -> Option<u8> {
		self.take(1).map(|b| b[0])
	}

	fn u16(&mut self) -> Option<u16> {
		self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
	}

	fn u24(&mut self) -> Option<u32> {
		self.take(3)
			.map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A name arrives as punycode, so a unicode entry matches nothing at all —
	/// and the failure is silent in the worst possible direction, since the
	/// host it was written to protect is intercepted like any other.
	#[test]
	fn a_unicode_entry_is_refused_rather_than_kept_useless() {
		let config = Config::from_str(
			"[passthrough]\nhosts = [\"münchen-bank.de\", \"xn--mnchen-bank-zhb.de\"]\n",
		)
		.unwrap();
		let passthrough = Passthrough::new(&config);

		assert!(
			!passthrough.covers("münchen-bank.de"),
			"an SNI is never unicode either"
		);
		assert!(
			passthrough.covers("xn--mnchen-bank-zhb.de"),
			"the punycode entry is the one that works"
		);
		assert_eq!(passthrough.hosts.len(), 1);
	}

	/// The signal has to be narrow. A false positive means quietly not
	/// decrypting a site — safe, but it also means no blocking on it, and that
	/// should never happen by accident.
	#[test]
	fn only_an_actual_challenge_counts_as_one() {
		let h = |pairs: &[(&str, &str)]| -> Vec<(String, String)> {
			pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
		};

		// Cloudflare saying so in as many words.
		assert!(is_a_challenge(403, &h(&[("cf-mitigated", "challenge")])));
		assert!(is_a_challenge(200, &h(&[("CF-Mitigated", "Challenge")])));

		// The narrow fallback: challenge status, cloudflare, challenge cookie.
		assert!(is_a_challenge(
			403,
			&h(&[("server", "cloudflare"), ("set-cookie", "cf_chl_2=abc; Path=/")])
		));

		// And everything that must not count.
		assert!(!is_a_challenge(403, &h(&[("server", "cloudflare")])), "a plain 403 is just a 403");
		assert!(
			!is_a_challenge(403, &h(&[("set-cookie", "cf_chl_2=abc")])),
			"a challenge cookie from something that is not cloudflare"
		);
		assert!(
			!is_a_challenge(200, &h(&[("server", "cloudflare"), ("set-cookie", "cf_chl_2=abc")])),
			"a 200 is a page, whatever cookies came with it"
		);
		assert!(!is_a_challenge(404, &h(&[])), "an ordinary error");
		assert!(!is_a_challenge(200, &h(&[])));
	}

	/// The learned list is exact where the configured one covers subdomains. A
	/// challenge on one host says nothing about its siblings, and widening it
	/// automatically would stop decrypting far more than was ever observed.
	#[test]
	fn a_learned_host_does_not_drag_its_subdomains_with_it() {
		let dir = tempfile::TempDir::new().unwrap();
		let learned = Learned::load(dir.path().join("p.json"));

		assert!(learned.add("www.merriam-webster.com"));
		assert!(!learned.add("www.merriam-webster.com"), "already there, so not new");

		assert!(learned.holds("www.merriam-webster.com"));
		assert!(learned.holds("WWW.Merriam-Webster.COM."), "however it is spelled");
		assert!(!learned.holds("merriam-webster.com"), "the parent is a different host");
		assert!(!learned.holds("other.merriam-webster.com"));

		// Whereas the configured list deliberately does cover them.
		let configured = listing(&["example-bank.com"]);
		assert!(configured.covers("secure.example-bank.com"));
	}

	/// The security boundary. `/.mach5/` is same-origin on every site, so if a
	/// page could reach the *configured* list it could make mach5 start
	/// decrypting a host somebody had written down. Only the learned list is
	/// reachable, and `never_decrypt` still honours both.
	#[test]
	fn removing_a_learned_host_cannot_reach_the_configured_one() {
		let dir = tempfile::TempDir::new().unwrap();
		let learned = Learned::load(dir.path().join("p.json"));
		let configured = listing(&["example-bank.com"]);

		assert!(never_decrypt(&configured, &learned, "secure.example-bank.com"));

		// Whatever a page does to the learned list, the configured entry stands.
		learned.add("secure.example-bank.com");
		learned.remove("secure.example-bank.com");
		assert!(
			never_decrypt(&configured, &learned, "secure.example-bank.com"),
			"the configured list is not reachable from anything a page can call"
		);
	}

	/// It has to survive a restart, or every trip re-learns the same hosts.
	#[test]
	fn learned_hosts_come_back_after_a_restart() {
		let dir = tempfile::TempDir::new().unwrap();
		let path = dir.path().join("p.json");

		let first = Learned::load(path.clone());
		first.add("news.example");
		first.add("shop.example");
		first.remove("shop.example");
		drop(first);

		let second = Learned::load(path);
		assert!(second.holds("news.example"));
		assert!(!second.holds("shop.example"), "a removal has to persist too");
		assert_eq!(second.all(), vec!["news.example".to_string()]);
	}

	/// Whether the whole record has arrived is the question the caller has to
	/// answer before parsing, because refusing a truncated one means "decrypt
	/// it" — and a hello that spans two segments is now the ordinary case.
	/// Re-frame a hello as several TLS records, which is legal and which
	/// browsers do not do — but "the client happened not to" is not a security
	/// argument, and reading only the first record meant a listed host was
	/// decrypted whenever one did.
	fn split_across_records(hello: &[u8], at: usize) -> Vec<u8> {
		let body = &hello[RECORD_HEADER..];
		let (first, second) = body.split_at(at);

		let mut out = Vec::new();
		for part in [first, second] {
			out.extend_from_slice(&[HANDSHAKE, 0x03, 0x01]);
			out.extend_from_slice(&(part.len() as u16).to_be_bytes());
			out.extend_from_slice(part);
		}

		out
	}

	#[test]
	fn a_hello_framed_as_several_records_still_gives_up_its_name() {
		let hello = client_hello(b"bank.example");
		let body = hello.len() - RECORD_HEADER;

		// Every split point, including ones that cut the handshake header, the
		// length, and the name itself in half.
		for at in 1..body {
			let split = split_across_records(&hello, at);

			assert_eq!(
				have_hello(&split),
				Hello::Complete,
				"split at {at} was not recognised as whole"
			);
			assert_eq!(
				server_name(&split).as_deref(),
				Some("bank.example"),
				"split at {at} lost the name, so a listed host would be decrypted"
			);
		}
	}

	#[test]
	fn a_second_record_still_arriving_is_waited_for() {
		let hello = client_hello(b"bank.example");
		let split = split_across_records(&hello, 20);

		// Everything but the last byte of the second record.
		let short = &split[..split.len() - 1];

		match have_hello(short) {
			Hello::Want(wanted) => assert!(
				wanted <= split.len(),
				"asking for {wanted} of a {} byte hello would make the caller \
				 give up on one that was still arriving",
				split.len()
			),
			other => panic!("a partial second record must be waited for, not {other:?}"),
		}

		assert_eq!(
			server_name(short),
			None,
			"and it must not be parsed while incomplete"
		);
	}

	#[test]
	fn a_record_longer_than_a_record_may_be_is_refused() {
		// 2^14 is the ceiling in RFC 8446 section 5.1. Anything claiming more
		// is a stream we have not understood, and inventing a name from one is
		// the single thing this module must never do.
		let mut absurd = vec![HANDSHAKE, 0x03, 0x01];
		absurd.extend_from_slice(&((MAX_RECORD + 1) as u16).to_be_bytes());
		absurd.extend(std::iter::repeat_n(0u8, 64));

		assert_eq!(have_hello(&absurd), Hello::NotTls);
		assert_eq!(server_name(&absurd), None);
	}

	#[test]
	fn a_truncated_hello_asks_for_the_rest_of_itself() {
		let hello = client_hello(b"bank.example");

		assert_eq!(have_hello(&hello), Hello::Complete);
		assert_eq!(
			have_hello(&hello[..hello.len() - 1]),
			Hello::Want(hello.len()),
			"one byte short, and it says exactly how many it wants"
		);
		assert_eq!(have_hello(&hello[..3]), Hello::Want(5), "not even the header");
		assert_eq!(have_hello(&[]), Hello::Want(5), "nothing at all yet");

		// Nothing to wait for: this is not a handshake record, so no amount of
		// patience turns it into one.
		assert_eq!(have_hello(b"GET / HTTP/1.1\r\n"), Hello::NotTls);

		// And what the caller does with the answer: the truncated record still
		// parses to nothing, which is why it must not be parsed yet.
		assert_eq!(server_name(&hello[..hello.len() - 1]), None);
		assert_eq!(server_name(&hello).as_deref(), Some("bank.example"));
	}

	/// A real ClientHello, assembled rather than pasted so the shape of one is
	/// visible in the test that depends on it.
	fn client_hello(host: &[u8]) -> Vec<u8> {
		let mut names = vec![NAME_TYPE_HOST];
		names.extend_from_slice(&(host.len() as u16).to_be_bytes());
		names.extend_from_slice(host);

		let mut server_name = Vec::new();
		server_name.extend_from_slice(&(names.len() as u16).to_be_bytes());
		server_name.extend_from_slice(&names);

		let mut extensions = Vec::new();
		extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
		extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
		extensions.extend_from_slice(&server_name);

		let mut hello = vec![0x03, 0x03];
		hello.extend_from_slice(&[0u8; 32]);
		hello.push(0); // no session id
		hello.extend_from_slice(&2u16.to_be_bytes());
		hello.extend_from_slice(&[0x13, 0x01]); // one cipher suite
		hello.push(1); // one compression method
		hello.push(0);
		hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
		hello.extend_from_slice(&extensions);

		let mut handshake = vec![CLIENT_HELLO];
		handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
		handshake.extend_from_slice(&hello);

		let mut record = vec![HANDSHAKE, 0x03, 0x01];
		record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
		record.extend_from_slice(&handshake);

		record
	}

	#[test]
	fn the_name_comes_out_of_a_client_hello() {
		let hello = client_hello(b"secure.example-bank.com");

		assert_eq!(
			server_name(&hello).as_deref(),
			Some("secure.example-bank.com")
		);
	}

	#[test]
	fn a_shouted_name_is_the_same_name() {
		let hello = client_hello(b"Secure.Example-Bank.COM");

		assert_eq!(
			server_name(&hello).as_deref(),
			Some("secure.example-bank.com"),
			"the list is matched in lowercase"
		);
	}

	/// Every one of these used to be a way to read past the end of a buffer.
	/// None of them may be a way to produce a name.
	#[test]
	fn nothing_malformed_yields_a_name() {
		let hello = client_hello(b"example.com");

		for cut in 0..hello.len() {
			assert_eq!(
				server_name(&hello[..cut]),
				None,
				"a hello truncated at {cut} bytes is not one we understand"
			);
		}

		assert_eq!(server_name(&[]), None);
		assert_eq!(server_name(&[HANDSHAKE]), None);
		assert_eq!(server_name(b"GET / HTTP/1.1\r\n\r\n"), None, "not TLS at all");
	}

	#[test]
	fn a_record_that_is_not_a_handshake_is_not_read() {
		let mut hello = client_hello(b"example.com");
		hello[0] = 0x17; // application data

		assert_eq!(server_name(&hello), None);
	}

	#[test]
	fn a_lie_about_a_length_does_not_get_a_name() {
		let mut hello = client_hello(b"example.com");
		// Claim the record is far longer than what follows.
		hello[3] = 0xff;
		hello[4] = 0xff;

		assert_eq!(
			server_name(&hello),
			None,
			"a length past the end of the buffer is a record we misread"
		);
	}

	#[test]
	fn a_hello_without_the_extension_has_no_name() {
		let mut hello = client_hello(b"example.com");
		// Blank the extension type, so nothing matches server_name.
		let at = hello.len() - 20;
		hello[at] = 0xff;

		assert_eq!(server_name(&hello), None);
	}

	fn listing(hosts: &[&str]) -> Passthrough {
		Passthrough {
			hosts: hosts.iter().map(|h| h.to_string()).collect(),
			fetched: RwLock::new(Arc::new(HashSet::new())),
			port: 443,
		}
	}

	#[test]
	fn a_listed_host_and_its_subdomains_are_covered() {
		let list = listing(&["example-bank.com"]);

		assert!(list.covers("example-bank.com"));
		assert!(
			list.covers("secure.example-bank.com"),
			"listing the bank means the whole bank"
		);
		assert!(!list.covers("example-bank.com.evil.example"));
		assert!(!list.covers("example.com"));
	}

	#[test]
	fn an_empty_list_covers_nothing() {
		assert!(!listing(&[]).covers("example.com"));
		assert!(listing(&[]).is_empty());
	}

	/// A config with a cache directory of its own and whatever URLs the test
	/// wants, so nothing here can read or write the real one.
	fn configured(dir: &std::path::Path, hosts: &[&str], urls: &[String]) -> Config {
		let list = |values: &[String]| {
			values
				.iter()
				.map(|value| format!("{value:?}"))
				.collect::<Vec<_>>()
				.join(", ")
		};
		let hosts: Vec<String> = hosts.iter().map(|h| h.to_string()).collect();

		Config::from_str(&format!(
			"[paths]\ncache_dir = {:?}\n\n[passthrough]\nhosts = [{}]\nurls = [{}]\n",
			dir,
			list(&hosts),
			list(urls)
		))
		.unwrap()
	}

	/// Leave a copy on disk where a fetch would have left one.
	fn cache(config: &Config, url: &str, text: &str) -> std::path::PathBuf {
		let path = CACHE.path(config, url);
		std::fs::create_dir_all(path.parent().unwrap()).unwrap();
		std::fs::write(&path, text).unwrap();

		path
	}

	/// A URL nothing is listening on, so a fetch of it fails for real rather
	/// than being simulated. Bound and dropped so the port is one the kernel
	/// just said was free.
	fn nowhere() -> String {
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let addr = listener.local_addr().unwrap();
		drop(listener);

		format!("http://{addr}/list.txt")
	}

	/// A one-shot HTTP server on loopback.
	///
	/// The interesting failure is a list that *downloads perfectly* and is not
	/// a list — a 404 page served as 200, a captive portal — because that is
	/// the one the cache cannot save us from: the good copy on disk has already
	/// been overwritten by the time anything notices. Proving that needs a
	/// fetch that succeeds, and there is no network here to succeed against.
	fn serving(body: &'static str) -> (String, std::thread::JoinHandle<()>) {
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let url = format!("http://{}/list.txt", listener.local_addr().unwrap());

		let handle = std::thread::spawn(move || {
			let Ok((mut stream, _)) = listener.accept() else {
				return;
			};

			// Read the request before answering it, so the client is not
			// writing into a socket that has already gone away.
			let mut request = [0u8; 1024];
			let _ = std::io::Read::read(&mut stream, &mut request);

			let response = format!(
				"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\
				 content-length: {}\r\nconnection: close\r\n\r\n{body}",
				body.len()
			);
			let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
		});

		(url, handle)
	}

	/// A fetched entry is the same statement as a configured one, only from a
	/// file, so it is matched the same way — and it has to count towards
	/// `is_empty`, which is what decides whether the ClientHello is peeked at
	/// all. A fetched list that did not count there would match in `covers`
	/// and be decrypted anyway.
	#[test]
	fn a_fetched_host_covers_its_subdomains_and_counts_as_listed() {
		let dir = tempfile::tempdir().unwrap();
		let url = nowhere();
		let config = configured(dir.path(), &[], std::slice::from_ref(&url));
		cache(&config, &url, "example-bank.com\n");

		let list = Passthrough::new(&config);

		assert!(list.covers("example-bank.com"));
		assert!(
			list.covers("secure.example-bank.com"),
			"a fetched entry covers its subdomains exactly as a written one does"
		);
		assert!(!list.covers("example-bank.com.evil.example"), "label-aware");
		assert!(!list.covers("notexample-bank.com"));
		assert!(
			!list.is_empty(),
			"nothing is peeked at when this says empty, so a fetched list that did \
			 not count here would never match anything"
		);
	}

	/// The seam between a fetched list and the two places that act on it.
	///
	/// `covers` being right is not enough on its own: the TCP front end splices
	/// on `never_decrypt`, and the acceptor refuses the handshake on the same
	/// call when the ClientHello peek did not manage to. A fetched host that
	/// reached one of those and not the other would be decrypted by whichever
	/// it missed.
	#[test]
	fn a_fetched_host_reaches_never_decrypt_like_any_other() {
		let dir = tempfile::tempdir().unwrap();
		let url = nowhere();
		let config = configured(dir.path(), &[], std::slice::from_ref(&url));
		cache(&config, &url, "example-bank.com\n");

		let list = Passthrough::new(&config);
		let learned = Learned::load(dir.path().join("learned.json"));

		assert!(never_decrypt(&list, &learned, "example-bank.com"));
		assert!(
			never_decrypt(&list, &learned, "secure.example-bank.com"),
			"subdomains too, or the splice and the refusal disagree with covers"
		);
		assert!(!never_decrypt(&list, &learned, "somewhere.else.example"));
	}

	/// The direction this list is allowed to fail in. A download that goes
	/// wrong must leave the same hosts exempt as before it, because the other
	/// way is a bank being decrypted — and the configured hosts are not the
	/// refresh's to touch at all.
	#[test]
	fn a_failed_fetch_keeps_the_list_it_had() {
		let dir = tempfile::tempdir().unwrap();
		let url = nowhere();
		let config = configured(dir.path(), &["written-down.example"], std::slice::from_ref(&url));
		cache(&config, &url, "example-bank.com\n");

		let list = Passthrough::new(&config);
		let mut held = cached(&config);
		refresh(&list, &config, &crate::fetch::agent(&config), &mut held);

		assert!(
			list.covers("secure.example-bank.com"),
			"the fetch failed, so yesterday's copy is still what is in force"
		);
		assert!(
			list.covers("written-down.example"),
			"and a failing list is never a reason to stop honouring a configured host"
		);
	}

	/// A fetch that fails with nothing cached behind it either. There is
	/// nothing to fall back to on disk, so what the list gave us last time —
	/// held in memory since startup — is what stands.
	#[test]
	fn a_fetch_with_nothing_behind_it_still_keeps_what_it_had() {
		let mut held: HashSet<String> = ["example-bank.com".to_string()].into_iter().collect();

		update(&mut held, None, "https://example.com/list.txt");

		assert!(held.contains("example-bank.com"));
	}

	/// The case the cache cannot save us from: a list that downloads perfectly
	/// and is an error page. The good copy on disk is overwritten before
	/// anything can notice, so keeping the parsed hosts in memory is the only
	/// thing between that and a decrypted bank.
	#[test]
	fn a_list_that_comes_back_unreadable_keeps_its_hosts() {
		let dir = tempfile::tempdir().unwrap();
		let (url, server) = serving("<html><head><title>404 Not Found</title></head></html>");
		let config = configured(dir.path(), &[], std::slice::from_ref(&url));
		let path = cache(&config, &url, "example-bank.com\n");

		let list = Passthrough::new(&config);
		let mut held = cached(&config);
		refresh(&list, &config, &crate::fetch::agent(&config), &mut held);
		server.join().unwrap();

		assert!(
			std::fs::read_to_string(&path).unwrap().contains("<html>"),
			"the fetch really did succeed, so the cache no longer holds the good copy"
		);
		assert!(
			list.covers("secure.example-bank.com"),
			"and the hosts it gave us last time are still exempt"
		);
	}

	/// A list far too long to be a list of hosts to leave alone — a hosts
	/// blocklist pointed at the wrong setting, or a list gone hostile. Either
	/// way honouring it would switch decryption off for most of the web.
	#[test]
	fn a_list_past_the_ceiling_is_refused_whole() {
		let huge: String = (0..=MAX_HOSTS)
			.map(|n| format!("host{n}.example\n"))
			.collect();
		let url = "https://example.com/list.txt";

		assert!(
			parse(&huge, url).is_empty(),
			"refused whole, not truncated: half of a security list chosen by line \
			 order is worse than none of it"
		);

		// And refusing it is not a way to shrink what is already in force.
		let mut held: HashSet<String> = ["example-bank.com".to_string()].into_iter().collect();
		update(&mut held, Some(&huge), url);

		assert!(held.contains("example-bank.com"));

		// One under the ceiling is an ordinary list.
		let big: String = (0..MAX_HOSTS)
			.map(|n| format!("host{n}.example\n"))
			.collect();
		assert_eq!(parse(&big, url).len(), MAX_HOSTS);
	}

	/// One line is otherwise enough to exempt a whole registry. These lists
	/// come from wherever somebody pointed the configuration, so that is not a
	/// decision to accept from one.
	#[test]
	fn an_entry_that_covers_the_world_is_refused() {
		let hosts = parse(
			"co.uk\ncom.au\nne.jp\norg.uk\ncom\nuk\n*\nlocalhost\n\
			 münchen-bank.de\nhttps://bank.example/\nbank.example:443\n\
			 real-bank.co.uk\nexample-bank.com\n",
			"https://example.com/list.txt",
		);

		for refused in [
			"co.uk", "com.au", "ne.jp", "org.uk", "com", "uk", "*", "localhost",
		] {
			assert!(!hosts.contains(refused), "{refused} exempts far too much");
		}
		assert!(!hosts.contains("münchen-bank.de"), "a name arrives as punycode");
		assert!(
			!hosts.iter().any(|h| h.contains('/') || h.contains(':')),
			"a URL or a port is not a host, and half of one is not either"
		);

		assert_eq!(
			hosts,
			["real-bank.co.uk".to_string(), "example-bank.com".to_string()]
				.into_iter()
				.collect::<HashSet<_>>(),
			"a name under a public suffix is somebody's site, and is kept"
		);
	}

	/// The formats published lists actually come in. A host silently dropped
	/// here is a host that starts being decrypted, so every shape matters.
	#[test]
	fn every_shape_a_published_list_comes_in_parses() {
		let hosts = parse(
			"# a comment\n\
			 ! and the other kind\n\
			 \n\
			 bank.example\n\
			 0.0.0.0 hosts-style.example\n\
			 127.0.0.1\ttabbed.example\n\
			 0.0.0.0 first.example second.example\n\
			 trailing.example  # why it is here\n\
			 *.wildcard.example\n\
			 UPPER.example.\n",
			"https://example.com/list.txt",
		);

		let expected: HashSet<String> = [
			"bank.example",
			"hosts-style.example",
			"tabbed.example",
			"first.example",
			"second.example",
			"trailing.example",
			"wildcard.example",
			"upper.example",
		]
		.into_iter()
		.map(str::to_string)
		.collect();

		assert_eq!(hosts, expected);
	}

	/// Nothing configured means no thread and no fetching, and zero hours is
	/// the deliberate way to freeze the lists where they are.
	#[test]
	fn refreshing_only_runs_when_there_is_something_to_fetch() {
		let dir = tempfile::tempdir().unwrap();
		let url = nowhere();

		assert_eq!(
			refresh_interval(&configured(dir.path(), &[], &[])),
			None,
			"no urls, nothing to refresh"
		);
		assert_eq!(
			refresh_interval(&configured(dir.path(), &[], std::slice::from_ref(&url))),
			Some(Duration::from_secs(24 * 3600)),
			"daily by default"
		);

		let frozen = Config::from_str(&format!(
			"[passthrough]\nurls = [{url:?}]\nrefresh_hours = 0\n"
		))
		.unwrap();
		assert_eq!(refresh_interval(&frozen), None);
	}
}
