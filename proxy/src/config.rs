//! Configuration.
//!
//! Every tunable lives here rather than as a literal in the code. Values come
//! from a TOML file (the idiomatic Rust equivalent of a `.properties` file);
//! anything absent falls back to the defaults below, so an empty or missing
//! file still yields a working proxy.
//!
//! Lookup order: `$MACH5_CONFIG`, then `./mach5.toml`, then
//! `$XDG_CONFIG_HOME/mach5/mach5.toml` (`~/.config/mach5/mach5.toml`).

use std::error::Error;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use time::Duration;

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
	/// Address to listen on for QUIC (UDP).
	pub listen: Listen,
	/// TCP address for HTTP/2 and HTTP/1.1 over TLS. Browsers connect here
	/// first — HTTP/3 is only discovered afterwards, via `[http] alt_svc`.
	pub listen_tcp: ListenTcp,
	pub ca: Ca,
	pub http: Http,
	pub paths: Paths,
	pub plugins: Plugins,
	pub blocklist: Blocklist,
	pub log: Log,
	pub images: Images,
	pub upstream: Upstream,
	pub passthrough: Passthrough,
	pub cosmetic: Cosmetic,
	pub internal: Internal,
	pub inject: Inject,
	pub tls: Tls,
	pub limits: Limits,
	pub quic: Quic,
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct Listen(pub SocketAddr);

impl Default for Listen {
	fn default() -> Self {
		Self("0.0.0.0:4433".parse().expect("valid default listen addr"))
	}
}

#[derive(Debug, Deserialize)]
#[serde(transparent)]
pub struct ListenTcp(pub SocketAddr);

impl Default for ListenTcp {
	fn default() -> Self {
		Self("0.0.0.0:4443".parse().expect("valid default tcp addr"))
	}
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Http {
	/// Value of the `Alt-Svc` header advertising HTTP/3, added to every
	/// response served over TCP. This is how a browser learns to switch to
	/// QUIC at all. Empty disables the advertisement.
	pub alt_svc: String,
	/// Keep TCP connections open for reuse between requests.
	pub keep_alive: bool,
	/// How long to wait for a request on an idle kept-alive connection.
	pub idle_timeout_seconds: u64,
	/// Compress a buffered body the origin sent uncompressed, when the client
	/// accepts a coding we can produce. Free bytes on the one hop we control.
	pub compress: bool,
}

impl Default for Http {
	fn default() -> Self {
		Self {
			alt_svc: r#"h3=":4433"; ma=86400"#.to_string(),
			keep_alive: true,
			idle_timeout_seconds: 60,
			compress: true,
		}
	}
}

/// Which of an origin's addresses to try first.
///
/// mach5 resolves origins on its own host, so this is independent of what the
/// clients can do — a client with IPv6 switched off still reaches IPv6-only
/// origins through mach5.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AddressPolicy {
	/// Whatever the resolver returns, in its order. RFC 6724 usually means
	/// IPv6 first.
	#[default]
	System,
	/// A records first, AAAA after. For a host whose IPv6 is a 6rd tunnel and
	/// slower than the IPv4 it rides on. Nothing is dropped, so an AAAA-only
	/// origin is still reached.
	PreferIpv4,
	PreferIpv6,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Upstream {
	pub addresses: AddressPolicy,
}

/// Re-encoding images to WebP on the way past.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Images {
	pub enabled: bool,
	/// How much disk the re-encoded images may take. 0 switches the cache off
	/// and pays the conversion on every request.
	pub cache_mb: u32,
	/// How much disk the origins' own bytes may take, so a repeat does not have
	/// to be downloaded again. Freshness and revalidation are the origin's to
	/// decide; see `httpcache.rs`.
	pub origin_cache_mb: u32,
	/// The largest response worth holding whole in order to cache it. A
	/// stylesheet would otherwise stream past untouched, so caching one means
	/// buffering it — and a bundle of many megabytes is not worth the memory.
	pub max_cacheable_mb: u32,
	/// WebP quality, 0-100. 80 is the usual "indistinguishable at a glance"
	/// setting and is what the measurements behind this were taken at.
	pub quality: u8,
	/// The most pixels an image may have before it is passed through rather
	/// than converted.
	///
	/// The bound has to be on pixels, not on bytes: a decoded frame costs
	/// width × height × 4 whatever the file compressed to, so two megabytes of
	/// flat-colour PNG is nearly half a gigabyte of memory and several seconds
	/// of a worker. 16 is a 4000×4000 image, which is past anything anyone puts
	/// on a page.
	pub max_megapixels: u32,
}

impl Default for Images {
	fn default() -> Self {
		Self {
			enabled: true,
			quality: 80,
			max_megapixels: 16,
			cache_mb: 512,
			origin_cache_mb: 256,
			max_cacheable_mb: 8,
		}
	}
}

/// Hosts mach5 must not decrypt at all.
///
/// Distinct from `[inject] exclude`, which only stops mach5 changing a page it
/// has already read. This stops it reading one.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Passthrough {
	pub hosts: Vec<String>,
	/// The port a passed-through connection is carried to. 443 unless mach5 is
	/// listening somewhere unusual — a transparent deployment cannot recover a
	/// nonstandard port without `SO_ORIGINAL_DST`, so this is the one knob.
	pub port: u16,
}

impl Default for Passthrough {
	fn default() -> Self {
		Self {
			hosts: Vec::new(),
			port: 443,
		}
	}
}

/// How much of a URL is written to the log.
///
/// mach5 sees every request every device makes, so its log is a record of all
/// of it. The query string is the part that carries tokens and session ids, and
/// a log is kept long after they should have been forgotten.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UrlLogging {
	/// Scheme, host and path. The default: enough to tell which page, without
	/// the part that is usually a credential.
	#[default]
	Path,
	/// Scheme and host only, for when even a path is too much — a magic link
	/// carries its secret there.
	Host,
	/// Everything, including the query string. For debugging, not for a proxy
	/// carrying real traffic.
	Full,
}

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Log {
	pub urls: UrlLogging,
}

/// Root certificate authority used to sign minted leaves. When either path is
/// absent the proxy generates an ephemeral in-memory CA (development only).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Ca {
	pub cert: Option<PathBuf>,
	pub key: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Paths {
	/// Scratch space for cached artifacts (re-encoded assets and the like).
	pub cache_dir: PathBuf,
	/// Where data someone actually typed is kept — the hidden-element
	/// selectors, so far. Deliberately not under `cache_dir`: a cache may be
	/// wiped at any moment, and losing a list built up by hand is not the same
	/// kind of loss as re-encoding an image again.
	pub state_dir: PathBuf,
}

impl Default for Paths {
	fn default() -> Self {
		Self {
			cache_dir: default_cache_dir(),
			state_dir: default_state_dir(),
		}
	}
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Plugins {
	/// Directory of executable interceptor plugins, run in filename order.
	pub dir: PathBuf,
	pub enabled: bool,
	/// Add an `x-mach5` header to every response. A debugging aid that makes
	/// interception visible without writing a plugin.
	pub stamp_responses: bool,
}

impl Default for Plugins {
	fn default() -> Self {
		Self {
			dir: default_plugin_dir(),
			enabled: true,
			stamp_responses: false,
		}
	}
}

/// Domains answered locally instead of being fetched — the first-stage ad
/// blocker. Lists are hosts files or Adblock-style domain lists, in any mix.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Blocklist {
	/// With no lists loaded this is a no-op, so it costs nothing to leave on.
	pub enabled: bool,
	pub files: Vec<PathBuf>,
	/// Lists to fetch rather than read. Each is cached under `cache_dir`, so a
	/// restart without a network still starts with yesterday's copy.
	pub urls: Vec<String>,
	/// Domains never blocked, whatever the lists say.
	pub allow: Vec<String>,
	/// How often to re-read the files and re-fetch the URLs. Zero switches
	/// refreshing off, which leaves every list as stale as the last restart.
	pub refresh_hours: u32,
}

impl Default for Blocklist {
	fn default() -> Self {
		Self {
			enabled: true,
			files: Vec::new(),
			urls: Vec::new(),
			allow: Vec::new(),
			refresh_hours: 24,
		}
	}
}

/// Cosmetic filter lists — the second stage, where the blocklist stops. Rules
/// are `example.com##.selector` lines, merged into the per-host stylesheet
/// alongside whatever the picker was used to hide by hand.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Cosmetic {
	/// With no lists loaded this is a no-op, so it costs nothing to leave on.
	pub enabled: bool,
	pub files: Vec<PathBuf>,
	/// Lists to fetch rather than read. Each is cached under `cache_dir`, so a
	/// restart without a network still starts with yesterday's copy.
	pub urls: Vec<String>,
	/// How often to re-read the files and re-fetch the URLs. Zero switches
	/// refreshing off, which leaves every list as stale as the last restart.
	pub refresh_hours: u32,
	/// Whether to apply the rules that name no domain.
	///
	/// Off, because a generic rule fires on every site in the world. When one is
	/// wrong it breaks a page that has nothing to do with the list it came from,
	/// and nothing on the broken page connects it back to a file nobody read —
	/// which is a bad trade for a class of rule the domain-specific ones already
	/// cover on the sites that matter.
	pub generic: bool,
}

impl Default for Cosmetic {
	fn default() -> Self {
		Self {
			enabled: true,
			files: Vec::new(),
			urls: Vec::new(),
			refresh_hours: 24,
			generic: false,
		}
	}
}

/// The proxy's own endpoints, served under `/.mach5/` on every origin at once.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Internal {
	pub enabled: bool,
}

impl Default for Internal {
	fn default() -> Self {
		Self { enabled: true }
	}
}

/// The tags added to every HTML page: the stylesheet that applies this host's
/// hidden-element list, and the picker that adds to it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Inject {
	pub enabled: bool,
	/// Hosts left exactly as the origin sent them. A parent domain covers its
	/// subdomains, as in the blocklist.
	pub exclude: Vec<String>,
	/// Mark off-screen images `loading="lazy"`, so a browser fetches them when
	/// they are needed rather than all at once. On a high-latency link the win
	/// is round trips, not bytes.
	pub lazy_images: bool,
	/// How many images to leave alone at the top of a page.
	///
	/// Lazy-loading the image someone actually came to see makes the page
	/// *slower* — it is the documented way to ruin Largest Contentful Paint —
	/// and the first images in a document are the ones most likely to be it.
	pub eager_images: usize,
}

impl Default for Inject {
	fn default() -> Self {
		Self {
			enabled: true,
			exclude: Vec::new(),
			lazy_images: true,
			eager_images: 3,
		}
	}
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Tls {
	/// How long a minted leaf stays valid. Minted certs have no revocation
	/// path, so expiry is the only bound on a leaked key — keep it short.
	pub leaf_ttl_hours: u32,
	/// Backdate `notBefore` to tolerate clients whose clocks run behind.
	pub clock_skew_minutes: u32,
	/// Re-mint a cached leaf once less than this remains, so the cache never
	/// serves a cert that expires mid-connection.
	pub refresh_margin_minutes: u32,
	/// Whether the certificate warning page can be typed past at all. Turning
	/// this off removes the mechanism entirely: the page says nothing about it
	/// and `/.mach5/bypass` stops existing.
	pub allow_bypass: bool,
	/// How long one host stays waved through. Bypasses are in memory only, so
	/// this is a ceiling on top of "until the proxy restarts".
	pub bypass_ttl_minutes: u32,
	/// What has to be typed on the warning page. Chrome's phrase by default,
	/// because it is the one muscle memory already has.
	pub bypass_phrase: String,
}

impl Default for Tls {
	fn default() -> Self {
		Self {
			leaf_ttl_hours: 24,
			clock_skew_minutes: 60,
			refresh_margin_minutes: 60,
			allow_bypass: true,
			bypass_ttl_minutes: 60,
			bypass_phrase: "thisisunsafe".to_string(),
		}
	}
}

/// A thread count, either absolute or relative to the core count using Maven's
/// `-T` convention: `"1C"` is one per core, `"2C"` two per core, `"0.5C"` half.
#[derive(Debug, Deserialize, Clone)]
#[serde(untagged)]
pub enum Threads {
	Count(usize),
	PerCore(String),
}

impl Default for Threads {
	fn default() -> Self {
		Self::PerCore("1C".to_string())
	}
}

impl Threads {
	/// Resolve to a concrete count, never less than one.
	pub fn resolve(&self) -> usize {
		let cores = available_cores();

		let count = match self {
			// 0 has always meant "decide for me".
			Self::Count(0) => cores,
			Self::Count(n) => *n,
			Self::PerCore(spec) => parse_threads(spec, cores).unwrap_or_else(|| {
				log::warn!("unparsable worker_threads {spec:?}; using one per core");

				cores
			}),
		};

		count.max(1)
	}
}

/// Parse `"2C"`, `"0.5C"` or a plain `"8"`.
fn parse_threads(spec: &str, cores: usize) -> Option<usize> {
	let spec = spec.trim();

	let Some(multiplier) = spec.strip_suffix(['C', 'c']) else {
		return spec.parse::<usize>().ok();
	};

	let multiplier: f64 = multiplier.trim().parse().ok()?;
	if !multiplier.is_finite() || multiplier <= 0.0 {
		return None;
	}

	Some((multiplier * cores as f64).round() as usize)
}

/// Parallelism available to this process. Deliberately not the physical core
/// count: this respects cgroup CPU limits and affinity masks, so it stays
/// correct inside a container.
fn available_cores() -> usize {
	std::thread::available_parallelism()
		.map(|n| n.get())
		.unwrap_or(4)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
	/// Cap on a buffered request body; bounds what one stream can allocate.
	pub max_request_body_mb: usize,
	/// Cap on a buffered *response* body, applied both to what is read off the
	/// wire and to what it inflates to. A compressed body's size says nothing
	/// about the plain one's, so without this a couple of megabytes of gzip
	/// becomes a couple of gigabytes of resident memory. A response over the
	/// cap is relayed to the client rather than refused; what it loses is
	/// being looked at.
	pub max_response_body_mb: usize,
	/// Upstream fetch workers, absolute (`8`) or per-core (`"1C"`, `"2C"`).
	pub worker_threads: Threads,
	pub connect_timeout_seconds: u64,
	pub read_timeout_seconds: u64,
	/// How long a plugin may take per hook before it is abandoned.
	pub plugin_timeout_seconds: u64,
	/// How much of *one* streaming response may sit in memory waiting for a
	/// slow client before the upstream read pauses. The backpressure bound on
	/// both front ends — a bounded channel per response on TCP, a
	/// [`crate::budget::Budget`] per stream on QUIC. Generous by design, since
	/// the box has RAM to spare; `streams_parked` says whether it is ever
	/// actually reached.
	pub stream_buffer_mb: usize,
}

impl Default for Limits {
	fn default() -> Self {
		Self {
			max_request_body_mb: 10,
			max_response_body_mb: 64,
			worker_threads: Threads::default(),
			connect_timeout_seconds: 10,
			read_timeout_seconds: 30,
			plugin_timeout_seconds: 10,
			stream_buffer_mb: 32,
		}
	}
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Quic {
	pub max_datagram_size: usize,
	pub max_idle_timeout_ms: u64,
	pub initial_max_data: u64,
	pub initial_max_stream_data: u64,
	pub initial_max_streams: u64,
}

impl Default for Quic {
	fn default() -> Self {
		Self {
			max_datagram_size: 1350,
			max_idle_timeout_ms: 30_000,
			initial_max_data: 10_000_000,
			initial_max_stream_data: 1_000_000,
			initial_max_streams: 100,
		}
	}
}

impl Config {
	/// Load configuration, falling back to defaults when no file is found.
	pub fn load() -> Result<Self, Box<dyn Error>> {
		match Self::locate() {
			Some(path) => {
				let text = std::fs::read_to_string(&path)?;
				let mut config: Config = toml::from_str(&text)?;
				config.normalize();
				log::info!("loaded configuration from {}", path.display());

				Ok(config)
			}
			None => {
				log::info!("no configuration file found; using defaults");

				Ok(Self::default())
			}
		}
	}

	#[cfg(test)]
	pub fn from_str(text: &str) -> Result<Self, Box<dyn Error>> {
		let mut config: Config = toml::from_str(text)?;
		config.normalize();

		Ok(config)
	}

	fn locate() -> Option<PathBuf> {
		if let Some(path) = std::env::var_os("MACH5_CONFIG") {
			return Some(PathBuf::from(path));
		}

		let local = PathBuf::from("mach5.toml");
		if local.is_file() {
			return Some(local);
		}

		let user = config_home().join("mach5").join("mach5.toml");
		if user.is_file() {
			return Some(user);
		}

		None
	}

	/// Expand `~` in every path so the rest of the code never has to.
	fn normalize(&mut self) {
		self.ca.cert = self.ca.cert.take().map(|p| expand_tilde(&p));
		self.ca.key = self.ca.key.take().map(|p| expand_tilde(&p));
		self.paths.cache_dir = expand_tilde(&self.paths.cache_dir);
		self.paths.state_dir = expand_tilde(&self.paths.state_dir);
		self.plugins.dir = expand_tilde(&self.plugins.dir);
		for file in &mut self.blocklist.files {
			*file = expand_tilde(file);
		}
		for file in &mut self.cosmetic.files {
			*file = expand_tilde(file);
		}
	}

	pub fn leaf_ttl(&self) -> Duration {
		Duration::hours(self.tls.leaf_ttl_hours as i64)
	}

	pub fn clock_skew(&self) -> Duration {
		Duration::minutes(self.tls.clock_skew_minutes as i64)
	}

	pub fn refresh_margin(&self) -> Duration {
		Duration::minutes(self.tls.refresh_margin_minutes as i64)
	}

	/// How long a typed bypass lasts.
	pub fn bypass_ttl(&self) -> std::time::Duration {
		std::time::Duration::from_secs(self.tls.bypass_ttl_minutes as u64 * 60)
	}

	/// The phrase to type past a certificate warning, or `None` when the
	/// mechanism is switched off. An empty phrase switches it off too — an
	/// interstitial that any keystroke walks past is not a warning.
	pub fn bypass_phrase(&self) -> Option<&str> {
		let phrase = self.tls.bypass_phrase.trim();

		(self.tls.allow_bypass && !phrase.is_empty()).then_some(phrase)
	}

	pub fn max_request_body(&self) -> usize {
		self.limits.max_request_body_mb * 1024 * 1024
	}

	/// The most a response body may occupy while it is being held whole, in
	/// bytes — both as it arrives and after it inflates.
	pub fn max_response_body(&self) -> usize {
		self.limits.max_response_body_mb * 1024 * 1024
	}

	pub fn worker_threads(&self) -> usize {
		self.limits.worker_threads.resolve()
	}

	/// The backpressure bound in bytes: how much of a body may sit in memory
	/// between the wire and whatever is consuming it.
	pub fn stream_buffer_bytes(&self) -> usize {
		self.limits.stream_buffer_mb * 1024 * 1024
	}

	/// Streaming backpressure expressed as a number of in-flight chunks.
	pub fn stream_buffer_chunks(&self, chunk_size: usize) -> usize {
		((self.limits.stream_buffer_mb * 1024 * 1024) / chunk_size).max(1)
	}
}

/// The home directory, or `None` when there is not a usable one.
///
/// Docker sets `HOME=/` for a uid with no passwd entry, which is what happens
/// the moment a container is told to run as an arbitrary user. `~/.cache/mach5`
/// then expands to `/.cache/mach5`, which that uid cannot create — so mach5
/// came up with no cache, no state, and two warnings nobody was watching for.
/// `/` and the empty string are therefore treated as "no home" rather than
/// expanded into nonsense.
fn home() -> Option<PathBuf> {
	let home = std::env::var_os("HOME").map(PathBuf::from)?;

	if home.as_os_str().is_empty() || home == Path::new("/") {
		return None;
	}

	Some(home)
}

fn config_home() -> PathBuf {
	std::env::var_os("XDG_CONFIG_HOME")
		.map(PathBuf::from)
		.unwrap_or_else(|| home().unwrap_or_else(|| PathBuf::from(".")).join(".config"))
}

/// `<home>/<rest>`, or a literal `~/<rest>` when there is no usable home.
///
/// Keeping the tilde is deliberate: the path then fails to create under the
/// name it was written as, so the error is about the default rather than about
/// `/.cache/mach5`, which nobody recognises as theirs.
fn tilde_or(home: Option<PathBuf>, rest: &str) -> PathBuf {
	match home {
		Some(home) => home.join(rest),
		None => PathBuf::from("~").join(rest),
	}
}

fn default_cache_dir() -> PathBuf {
	std::env::var_os("XDG_CACHE_HOME")
		.map(PathBuf::from)
		.unwrap_or_else(|| tilde_or(home(), ".cache"))
		.join("mach5")
}

/// Where the XDG base directory spec puts data that is not a cache and not
/// configuration.
fn default_state_dir() -> PathBuf {
	std::env::var_os("XDG_DATA_HOME")
		.map(PathBuf::from)
		.unwrap_or_else(|| tilde_or(home(), ".local").join("share"))
		.join("mach5")
}

fn default_plugin_dir() -> PathBuf {
	config_home().join("mach5").join("plugins")
}

fn expand_tilde(path: &Path) -> PathBuf {
	let Ok(rest) = path.strip_prefix("~") else {
		return path.to_path_buf();
	};

	// With no usable home the path stays as it was written. It will fail to
	// create, and the caller says why — which beats expanding to `/` and
	// failing with a path nobody recognises.
	match home() {
		Some(home) => home.join(rest),
		None => path.to_path_buf(),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// These tests are about `~` being expanded, so they need something to
	/// expand it to. A machine with no usable HOME is a real situation — it is
	/// what a container gives you — but it is covered by
	/// `a_path_that_cannot_be_expanded_keeps_its_tilde` below, which needs no
	/// environment at all.
	fn a_home() -> PathBuf {
		home().expect("these tests assume a usable HOME; see tilde_or for the other case")
	}

	/// Docker sets `HOME=/` for a uid with no passwd entry, so `~/.cache/mach5`
	/// became `/.cache/mach5` — a path the container could not create, named
	/// after nothing the operator wrote. Keeping the tilde means the failure
	/// names the default itself, and `usable_directory` refuses it outright
	/// rather than creating a directory called `~` next to wherever it started.
	#[test]
	fn a_path_that_cannot_be_expanded_keeps_its_tilde() {
		assert_eq!(
			tilde_or(None, ".cache"),
			PathBuf::from("~/.cache"),
			"no home, so the tilde stays and the error can say so"
		);
		assert_eq!(
			tilde_or(Some(PathBuf::from("/home/someone")), ".cache"),
			PathBuf::from("/home/someone/.cache")
		);

		// And the two values Docker actually hands out are both refused.
		for unusable in ["", "/"] {
			assert_eq!(
				tilde_or(Some(PathBuf::from(unusable)).filter(|h| {
					!h.as_os_str().is_empty() && h != Path::new("/")
				}), ".cache"),
				PathBuf::from("~/.cache"),
				"HOME={unusable:?} is not a home"
			);
		}
	}

	#[test]
	fn defaults_apply_to_an_empty_file() {
		let config = Config::from_str("").expect("empty config should be valid");

		assert_eq!(config.listen.0.port(), 4433);
		assert_eq!(config.tls.leaf_ttl_hours, 24);
		assert_eq!(config.max_request_body(), 10 * 1024 * 1024);
		assert!(config.ca.cert.is_none(), "no CA configured means dev CA");
	}

	#[test]
	fn partial_file_keeps_other_defaults() {
		let config = Config::from_str(
			r#"
			listen = "127.0.0.1:9443"

			[tls]
			leaf_ttl_hours = 2
			"#,
		)
		.expect("partial config should be valid");

		assert_eq!(config.listen.0.port(), 9443);
		assert_eq!(config.tls.leaf_ttl_hours, 2);
		// Untouched fields keep their defaults.
		assert_eq!(config.tls.clock_skew_minutes, 60);
		assert_eq!(config.limits.max_request_body_mb, 10);
		assert_eq!(config.limits.max_response_body_mb, 64);
	}

	#[test]
	fn unknown_keys_are_rejected() {
		// A typo should fail loudly rather than silently doing nothing.
		let err = Config::from_str("[tls]\nleaf_ttl_hrs = 2\n");

		assert!(err.is_err(), "unknown key must be an error");
	}

	#[test]
	fn tilde_expands_to_home() {
		let expanded = expand_tilde(Path::new("~/.cache/mach5"));

		assert_eq!(expanded, a_home().join(".cache/mach5"));
		assert_eq!(expand_tilde(Path::new("/abs/path")), Path::new("/abs/path"));
	}

	#[test]
	fn blocklist_paths_expand_like_every_other_path() {
		let config = Config::from_str("[blocklist]\nfiles = [\"~/lists/hosts\"]\n").unwrap();

		assert_eq!(config.blocklist.files, vec![a_home().join("lists/hosts")]);
		assert!(config.blocklist.enabled, "a list with no files is a no-op");
		assert!(config.blocklist.urls.is_empty(), "nothing is fetched unasked");
		assert_eq!(config.blocklist.refresh_hours, 24, "daily by default");
	}

	#[test]
	fn a_blocklist_can_be_fetched_as_well_as_read() {
		let config = Config::from_str(
			r#"
			[blocklist]
			urls = ["https://example.com/hosts"]
			refresh_hours = 6
			"#,
		)
		.unwrap();

		assert_eq!(
			config.blocklist.urls,
			vec!["https://example.com/hosts".to_string()]
		);
		assert_eq!(config.blocklist.refresh_hours, 6);
		assert!(config.blocklist.files.is_empty(), "files stay optional");
	}

	#[test]
	fn cosmetic_lists_are_off_the_shelf_but_generic_rules_are_not() {
		let config = Config::from_str(
			r#"
			[cosmetic]
			files = ["~/lists/easylist.txt"]
			urls = ["https://example.com/annoyances.txt"]
			"#,
		)
		.unwrap();

		assert_eq!(config.cosmetic.files, vec![a_home().join("lists/easylist.txt")]);
		assert_eq!(
			config.cosmetic.urls,
			vec!["https://example.com/annoyances.txt".to_string()]
		);
		assert!(config.cosmetic.enabled, "a list with no files is a no-op");
		assert_eq!(config.cosmetic.refresh_hours, 24, "daily by default");
		assert!(
			!config.cosmetic.generic,
			"a rule that fires everywhere has to be asked for"
		);
		assert!(Config::from_str("[cosmetic]\ngeneric = true\n")
			.unwrap()
			.cosmetic
			.generic);
	}

	#[test]
	fn state_is_kept_apart_from_the_cache() {
		let config = Config::from_str("[paths]\nstate_dir = \"~/state\"\n").unwrap();

		assert_eq!(config.paths.state_dir, a_home().join("state"));
		assert_ne!(
			Config::default().paths.state_dir,
			Config::default().paths.cache_dir,
			"a wiped cache must not take someone's selectors with it"
		);
		assert!(config.internal.enabled, "the endpoints are on by default");
	}

	#[test]
	fn compression_is_on_unless_it_is_turned_off() {
		assert!(Config::default().http.compress);
		assert!(Config::from_str("").unwrap().http.compress);

		let off = Config::from_str("[http]\ncompress = false\n").unwrap();

		assert!(!off.http.compress);
		assert!(off.http.keep_alive, "an unrelated default is untouched");
	}

	#[test]
	fn injection_is_on_with_nothing_excluded() {
		let config = Config::from_str("[inject]\nexclude = [\"bank.example\"]\n").unwrap();

		assert!(config.inject.enabled);
		assert_eq!(config.inject.exclude, vec!["bank.example".to_string()]);
		assert!(Config::default().inject.enabled);
		assert!(Config::default().inject.exclude.is_empty());
	}

	#[test]
	fn threads_follow_the_maven_per_core_convention() {
		assert_eq!(parse_threads("1C", 8), Some(8));
		assert_eq!(parse_threads("2C", 8), Some(16));
		assert_eq!(parse_threads("0.5C", 8), Some(4));
		assert_eq!(parse_threads("2c", 8), Some(16), "lowercase suffix works");
		assert_eq!(parse_threads(" 2C ", 8), Some(16), "surrounding space is fine");
		// A bare number is an absolute count, not a multiplier.
		assert_eq!(parse_threads("6", 8), Some(6));
	}

	#[test]
	fn nonsense_thread_specs_are_rejected() {
		assert_eq!(parse_threads("C", 8), None);
		assert_eq!(parse_threads("xC", 8), None);
		assert_eq!(parse_threads("-2C", 8), None);
		assert_eq!(parse_threads("0C", 8), None);
	}

	#[test]
	fn thread_count_parses_from_either_toml_form() {
		let per_core = Config::from_str("[limits]\nworker_threads = \"2C\"\n").unwrap();
		let absolute = Config::from_str("[limits]\nworker_threads = 3\n").unwrap();

		assert_eq!(absolute.worker_threads(), 3);
		assert_eq!(per_core.worker_threads(), 2 * available_cores());
		// Default is one per core.
		assert_eq!(Config::default().worker_threads(), available_cores());
	}

	#[test]
	fn durations_derive_from_units() {
		let config = Config::from_str(
			r#"
			[tls]
			leaf_ttl_hours = 6
			clock_skew_minutes = 15
			"#,
		)
		.unwrap();

		assert_eq!(config.leaf_ttl(), Duration::hours(6));
		assert_eq!(config.clock_skew(), Duration::minutes(15));
	}
	/// The configs shipped in this repo are parsed by the same `deny_unknown_fields`
	/// deserializer the binary uses, so a key added to one and not the other —
	/// or to neither struct — is a container that will not start. Nothing else
	/// reads these files until then.
	#[test]
	fn the_configs_in_this_repo_parse() {
		let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
			.parent()
			.expect("the crate sits under the repo root");

		for name in ["mach5.toml", "docker/mach5.toml"] {
			let path = root.join(name);
			let text = std::fs::read_to_string(&path)
				.unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));

			Config::from_str(&text)
				.unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()));
		}
	}

}

