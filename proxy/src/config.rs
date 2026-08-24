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
	pub ca: Ca,
	pub paths: Paths,
	pub plugins: Plugins,
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
}

impl Default for Paths {
	fn default() -> Self {
		Self {
			cache_dir: default_cache_dir(),
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
}

impl Default for Tls {
	fn default() -> Self {
		Self {
			leaf_ttl_hours: 24,
			clock_skew_minutes: 60,
			refresh_margin_minutes: 60,
		}
	}
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
	/// Cap on a buffered request body; bounds what one stream can allocate.
	pub max_request_body_mb: usize,
	/// Upstream fetch workers. 0 means one per available core.
	pub worker_threads: usize,
	pub connect_timeout_seconds: u64,
	pub read_timeout_seconds: u64,
	/// How long a plugin may take per hook before it is abandoned.
	pub plugin_timeout_seconds: u64,
}

impl Default for Limits {
	fn default() -> Self {
		Self {
			max_request_body_mb: 10,
			worker_threads: 0,
			connect_timeout_seconds: 10,
			read_timeout_seconds: 30,
			plugin_timeout_seconds: 10,
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
		self.plugins.dir = expand_tilde(&self.plugins.dir);
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

	pub fn max_request_body(&self) -> usize {
		self.limits.max_request_body_mb * 1024 * 1024
	}

	pub fn worker_threads(&self) -> usize {
		if self.limits.worker_threads > 0 {
			return self.limits.worker_threads;
		}

		std::thread::available_parallelism()
			.map(|n| n.get())
			.unwrap_or(4)
	}
}

fn home() -> PathBuf {
	std::env::var_os("HOME")
		.map(PathBuf::from)
		.unwrap_or_else(|| PathBuf::from("."))
}

fn config_home() -> PathBuf {
	std::env::var_os("XDG_CONFIG_HOME")
		.map(PathBuf::from)
		.unwrap_or_else(|| home().join(".config"))
}

fn default_cache_dir() -> PathBuf {
	std::env::var_os("XDG_CACHE_HOME")
		.map(PathBuf::from)
		.unwrap_or_else(|| home().join(".cache"))
		.join("mach5")
}

fn default_plugin_dir() -> PathBuf {
	config_home().join("mach5").join("plugins")
}

fn expand_tilde(path: &Path) -> PathBuf {
	let Ok(rest) = path.strip_prefix("~") else {
		return path.to_path_buf();
	};

	home().join(rest)
}

#[cfg(test)]
mod tests {
	use super::*;

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

		assert_eq!(expanded, home().join(".cache/mach5"));
		assert_eq!(expand_tilde(Path::new("/abs/path")), Path::new("/abs/path"));
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
}
