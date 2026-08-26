//! Re-encoded images, kept so the work is done once.
//!
//! Converting an image costs about twelve milliseconds, and without this it was
//! paid on every request for the same picture forever. This does not save a
//! byte of bandwidth — the original is still fetched from the origin — it saves
//! the CPU, which was the actual weakness.
//!
//! **Entries are addressed by the content they came from**: the key is the
//! SHA-256 of the original bytes and the quality asked for. That is worth
//! spelling out, because it is what makes this cache safe to build before mach5
//! has any notion of who is asking:
//!
//! - There is no invalidation problem. If an origin changes an image the bytes
//!   change, so the key changes, so the old entry is simply never asked for
//!   again.
//! - There is nothing to go stale, for the same reason.
//! - A hit can only ever return the re-encoding of exactly the bytes just
//!   fetched. One person's image cannot be served to another, because the only
//!   way to reach an entry is to already be holding its input.
//!
//! A general response cache has none of those properties, which is why the
//! roadmap keeps it behind the user-session work and this is not.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use crate::config::Config;

/// How many inserts before checking whether the budget has been passed.
///
/// Sweeping means listing the directory, so doing it per insert would trade the
/// CPU this exists to save for I/O. Images average a few tens of kilobytes, so
/// the overshoot between sweeps is a rounding error against any sane budget.
const SWEEP_EVERY: usize = 200;

pub struct Cache {
	dir: PathBuf,
	budget: u64,
	since_sweep: AtomicUsize,
	metrics: Arc<crate::metrics::Metrics>,
}

impl Cache {
	pub fn new(config: &Config) -> Option<Self> {
		let budget = config.images.cache_mb as u64 * 1024 * 1024;
		if budget == 0 {
			return None;
		}

		let dir = config.paths.cache_dir.join("images");
		if let Err(e) = std::fs::create_dir_all(&dir) {
			log::warn!("no image cache: cannot use {}: {e}", dir.display());

			return None;
		}

		let cache = Self {
			dir,
			budget,
			since_sweep: AtomicUsize::new(0),
			metrics: crate::metrics::shared(),
		};
		// Once at startup, so a budget lowered between runs takes effect
		// without waiting for enough traffic to trigger a sweep.
		cache.sweep();

		Some(cache)
	}

	/// The re-encoding of these bytes at this quality, if it has been done
	/// before.
	pub fn get(&self, original: &[u8], quality: u8) -> Option<Vec<u8>> {
		let found = std::fs::read(self.path_for(original, quality)).ok();

		if found.is_some() {
			self.metrics.image_cache_hits.increment();
		} else {
			self.metrics.image_cache_misses.increment();
		}

		found
	}

	pub fn put(&self, original: &[u8], quality: u8, encoded: &[u8]) {
		let path = self.path_for(original, quality);

		// Written beside and renamed, so a reader never sees a half-written
		// image — the same reason the other stores here do it.
		let temporary = path.with_extension("tmp");
		let written = std::fs::write(&temporary, encoded).and_then(|()| {
			std::fs::rename(&temporary, &path)
		});
		if let Err(e) = written {
			log::debug!("cannot cache a re-encoded image: {e}");
			let _ = std::fs::remove_file(&temporary);

			return;
		}

		if self.since_sweep.fetch_add(1, Ordering::Relaxed) + 1 >= SWEEP_EVERY {
			self.since_sweep.store(0, Ordering::Relaxed);
			self.sweep();
		}
	}

	fn path_for(&self, original: &[u8], quality: u8) -> PathBuf {
		self.dir.join(name_for(original, quality))
	}

	/// Delete the least recently used entries until the budget is met.
	///
	/// Least recently *used* rather than written, which needs the filesystem to
	/// be updating access times — many are mounted `relatime` and will not.
	/// Modification time is the honest fallback and, for files that are never
	/// modified after they are written, means oldest-first.
	fn sweep(&self) {
		let Ok(entries) = std::fs::read_dir(&self.dir) else {
			return;
		};

		let mut files: Vec<(std::time::SystemTime, u64, PathBuf)> = entries
			.filter_map(|entry| {
				let entry = entry.ok()?;
				let meta = entry.metadata().ok()?;
				let used = meta.accessed().or_else(|_| meta.modified()).ok()?;

				Some((used, meta.len(), entry.path()))
			})
			.collect();

		let total: u64 = files.iter().map(|(_, size, _)| size).sum();
		if total <= self.budget {
			return;
		}

		files.sort_by_key(|(used, _, _)| *used);

		let mut freed = 0;
		for (_, size, path) in files {
			if total - freed <= self.budget {
				break;
			}

			if std::fs::remove_file(&path).is_ok() {
				freed += size;
			}
		}

		log::info!(
			"image cache swept: {} freed to stay under {}",
			crate::metrics::bytes(freed),
			crate::metrics::bytes(self.budget)
		);
	}
}

/// The filename for a given input. SHA-256 rather than something cheaper
/// because a collision would mean serving one image in place of another, and a
/// hash an attacker can collide deliberately is a way to do exactly that.
fn name_for(original: &[u8], quality: u8) -> String {
	let digest = boring::sha::sha256(original);

	let mut name = String::with_capacity(64 + 8);
	for byte in digest {
		name.push_str(&format!("{byte:02x}"));
	}
	name.push_str(&format!("-q{quality}.webp"));

	name
}

/// One cache for the process. Every worker builds its own chain, and sixteen
/// of these would mean sixteen startup sweeps of the same directory.
pub fn shared(config: &Config) -> Option<Arc<Cache>> {
	static SHARED: std::sync::OnceLock<Option<Arc<Cache>>> = std::sync::OnceLock::new();

	SHARED.get_or_init(|| Cache::new(config).map(Arc::new)).clone()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn cache(dir: &tempfile::TempDir, budget: u64) -> Cache {
		std::fs::create_dir_all(dir.path().join("images")).unwrap();

		Cache {
			dir: dir.path().join("images"),
			budget,
			since_sweep: AtomicUsize::new(0),
			metrics: Arc::new(crate::metrics::Metrics::default()),
		}
	}

	#[test]
	fn what_went_in_comes_back_out() {
		let dir = tempfile::TempDir::new().unwrap();
		let cache = cache(&dir, 1024 * 1024);

		assert_eq!(cache.get(b"original bytes", 80), None);
		cache.put(b"original bytes", 80, b"re-encoded");

		assert_eq!(cache.get(b"original bytes", 80).as_deref(), Some(&b"re-encoded"[..]));
		assert_eq!(cache.metrics.image_cache_hits.get(), 1);
		assert_eq!(cache.metrics.image_cache_misses.get(), 1);
	}

	/// The property the whole design rests on: an entry is reachable only by
	/// holding the bytes it was made from.
	#[test]
	fn different_input_is_a_different_entry() {
		let dir = tempfile::TempDir::new().unwrap();
		let cache = cache(&dir, 1024 * 1024);
		cache.put(b"one image", 80, b"encoded one");

		assert_eq!(cache.get(b"another image", 80), None);
	}

	#[test]
	fn quality_is_part_of_the_key() {
		let dir = tempfile::TempDir::new().unwrap();
		let cache = cache(&dir, 1024 * 1024);
		cache.put(b"same bytes", 80, b"at eighty");

		assert_eq!(
			cache.get(b"same bytes", 40),
			None,
			"a panel set to low must not be handed the high-quality copy"
		);
		assert_eq!(cache.get(b"same bytes", 80).as_deref(), Some(&b"at eighty"[..]));
	}

	#[test]
	fn a_name_is_stable_and_says_what_it_is() {
		let first = name_for(b"bytes", 80);

		assert_eq!(first, name_for(b"bytes", 80));
		assert!(first.ends_with("-q80.webp"));
		assert_eq!(first.len(), 64 + "-q80.webp".len());
		assert!(
			!first.contains('/') && !first.contains(".."),
			"a key derived from content must never become a path"
		);
	}

	#[test]
	fn sweeping_brings_it_back_under_budget() {
		let dir = tempfile::TempDir::new().unwrap();
		let cache = cache(&dir, 100);

		for i in 0..10u8 {
			cache.put(&[i; 32], 80, &[0u8; 40]);
			// Distinct timestamps, so "oldest first" has something to sort on.
			std::thread::sleep(std::time::Duration::from_millis(5));
		}
		cache.sweep();

		let left: u64 = std::fs::read_dir(&cache.dir)
			.unwrap()
			.filter_map(|e| e.ok()?.metadata().ok())
			.map(|m| m.len())
			.sum();

		assert!(left <= 100, "{left} bytes is over the budget");
		assert!(left > 0, "and it must not simply empty itself");
	}

	#[test]
	fn a_budget_of_zero_means_no_cache_at_all() {
		let dir = tempfile::TempDir::new().unwrap();
		let config = Config::from_str(&format!(
			"[images]\ncache_mb = 0\n[paths]\ncache_dir = \"{}\"\n",
			dir.path().display()
		))
		.unwrap();

		assert!(Cache::new(&config).is_none());
	}
}
