//! Fetching a list somebody else maintains, and keeping the last copy on disk.
//!
//! [`crate::blocklist`] and [`crate::cosmetic`] both want the same thing of a
//! URL — a text file, revalidated rather than re-downloaded, cached so that a
//! restart without a network still comes up with yesterday's copy, and never
//! allowed to fail in a way that empties a list that was working. That is one
//! set of rules, so it is written once here rather than twice over there.
//!
//! What differs between the two is only where the copies are kept and what to
//! call them in a log line, which is what a [`Cache`] carries.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::config::Config;

/// Ceiling on a fetched list. The body arrives with a length nobody has
/// promised to honour and is read straight into memory, so it needs a bound;
/// generous, because the largest of the popular lists is a few megabytes.
const MAX_LIST_BYTES: u64 = 64 * 1024 * 1024;

/// Where one kind of list is cached, and what a log line calls it.
pub struct Cache {
	/// Directory under `cache_dir` holding this kind of list.
	dir: &'static str,
	/// The word a warning uses, so "cannot fetch" names which list failed.
	kind: &'static str,
}

impl Cache {
	pub const fn new(dir: &'static str, kind: &'static str) -> Self {
		Self { dir, kind }
	}

	/// Where a URL's last-fetched body is kept.
	pub fn path(&self, config: &Config, url: &str) -> PathBuf {
		config
			.paths
			.cache_dir
			.join(self.dir)
			.join(format!("{}.txt", cache_name(url)))
	}

	/// What each URL last gave us, read straight off disk. This is what makes a
	/// restart without a network still a working list: yesterday's copy.
	pub fn cached(&self, config: &Config, urls: &[String]) -> Vec<String> {
		urls.iter()
			.filter_map(|url| std::fs::read_to_string(self.path(config, url)).ok())
			.collect()
	}

	pub fn fetched(&self, config: &Config, agent: &ureq::Agent, urls: &[String]) -> Vec<String> {
		urls.iter()
			.filter_map(|url| self.fetch(config, agent, url))
			.collect()
	}

	/// Fetch one list, falling back to the copy on disk.
	///
	/// `None` means this URL contributes nothing at all, which happens only when
	/// the fetch failed and there is nothing cached to fall back to.
	fn fetch(&self, config: &Config, agent: &ureq::Agent, url: &str) -> Option<String> {
		let path = self.path(config, url);
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
			Ok(response) => self.store(&path, url, response).or(cached),
			Err(ureq::Error::Status(304, _)) => {
				log::debug!("{} {url} is unchanged", self.kind);

				cached
			}
			Err(e) => {
				log::warn!(
					"cannot fetch {} {url}: {e}{}",
					self.kind,
					fallback(&cached)
				);

				cached
			}
		}
	}

	/// Read the body and cache it, with whatever the origin gave us to
	/// revalidate it with next time. A body that cannot be written to the cache
	/// is still perfectly good in memory, so only the caching is lost.
	fn store(&self, path: &Path, url: &str, response: ureq::Response) -> Option<String> {
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
			log::warn!("cannot read {} {url}: {e}", self.kind);

			return None;
		}

		// Lossy rather than a failure: one bad byte in a hundred thousand lines
		// is no reason to drop the other ninety-nine thousand, and a mangled
		// line fails to parse as a rule anyway.
		let text = String::from_utf8_lossy(&body).into_owned();

		match std::fs::create_dir_all(path.parent().unwrap_or(path)) {
			Ok(()) => match std::fs::write(path, &text) {
				Ok(()) => write_validators(&meta_path(path), &validators),
				Err(e) => log::warn!("cannot cache {} {url}: {e}", self.kind),
			},
			Err(e) => log::warn!("cannot create the {} cache directory: {e}", self.kind),
		}

		Some(text)
	}
}

/// The client lists are fetched with.
///
/// Certificate validation is on and there is no way to turn it off here: these
/// files decide what gets blocked and what gets hidden, so a list served by
/// whoever happens to be on the wire is worse than no list. [`crate::insecure`]
/// exists for one host somebody typed a phrase for, and it is not reachable
/// from this module.
///
/// Redirects are followed, where [`crate::upstream`]'s agent refuses them: the
/// obvious place to keep a list is a file in a git host, and those redirect.
pub fn agent(config: &Config) -> ureq::Agent {
	ureq::AgentBuilder::new()
		.timeout_connect(Duration::from_secs(config.limits.connect_timeout_seconds))
		.timeout_read(Duration::from_secs(config.limits.read_timeout_seconds))
		.build()
}

/// Which way a failed fetch fell, so a warning is never ambiguous about whether
/// anything from that list is still in force.
fn fallback(cached: &Option<String>) -> &'static str {
	match cached {
		Some(_) => "; keeping the cached copy",
		None => "; nothing is cached, so this list contributes nothing",
	}
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
		log::warn!("cannot record list validators at {}: {e}", path.display());
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

#[cfg(test)]
mod tests {
	use super::*;

	const BLOCKLISTS: Cache = Cache::new("blocklists", "blocklist");
	const COSMETIC: Cache = Cache::new("cosmetic", "cosmetic list");

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
		let path = BLOCKLISTS.path(&config, "https://example.com/hosts");
		let meta = meta_path(&path);

		assert_eq!(path.parent(), Some(Path::new("/cache/blocklists")));
		assert_eq!(path.extension(), Some("txt".as_ref()));
		assert_eq!(meta.extension(), Some("meta".as_ref()));
		assert_eq!(meta.parent(), path.parent());
		assert_eq!(meta.file_stem(), path.file_stem());
	}

	/// The two kinds of list never share a file, even for the same URL: one is
	/// domains and the other is selectors, and reading either as the other
	/// would quietly load nothing.
	#[test]
	fn each_kind_of_list_has_its_own_directory() {
		let config = Config::from_str("[paths]\ncache_dir = \"/cache\"\n").unwrap();
		let url = "https://example.com/list.txt";

		assert_eq!(
			COSMETIC.path(&config, url).parent(),
			Some(Path::new("/cache/cosmetic"))
		);
		assert_ne!(BLOCKLISTS.path(&config, url), COSMETIC.path(&config, url));
		assert_eq!(
			BLOCKLISTS.path(&config, url).file_name(),
			COSMETIC.path(&config, url).file_name(),
			"the same URL still names the same file within its own directory"
		);
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
	fn a_url_reads_back_the_copy_left_on_disk() {
		let dir = tempfile::tempdir().unwrap();
		let config =
			Config::from_str(&format!("[paths]\ncache_dir = {:?}\n", dir.path())).unwrap();
		let urls = vec!["https://example.com/hosts".to_string()];

		assert!(
			BLOCKLISTS.cached(&config, &urls).is_empty(),
			"nothing cached yet"
		);

		let path = BLOCKLISTS.path(&config, &urls[0]);
		std::fs::create_dir_all(path.parent().unwrap()).unwrap();
		std::fs::write(&path, "0.0.0.0 ads.example.com\n").unwrap();

		assert_eq!(
			BLOCKLISTS.cached(&config, &urls),
			vec!["0.0.0.0 ads.example.com\n".to_string()]
		);
	}
}
