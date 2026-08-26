//! Keeping a cache directory under its budget.
//!
//! Shared by the two on-disk caches, which want the same thing: delete the
//! least recently used files until the total fits again.

use std::path::{Path, PathBuf};

/// Delete oldest-first until `budget` is met.
///
/// Least recently *used* where the filesystem tracks it, and modification time
/// where it does not — many are mounted `relatime` and will not update atime
/// for a read. For files never written twice, that means oldest-first, which is
/// the honest fallback.
pub fn sweep(dir: &Path, budget: u64) {
	let Ok(entries) = std::fs::read_dir(dir) else {
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
	if total <= budget {
		return;
	}

	files.sort_by_key(|(used, _, _)| *used);

	let mut freed = 0;
	for (_, size, path) in files {
		if total - freed <= budget {
			break;
		}

		if std::fs::remove_file(&path).is_ok() {
			freed += size;
		}
	}

	log::info!(
		"{} swept: {} freed to stay under {}",
		dir.display(),
		crate::metrics::bytes(freed),
		crate::metrics::bytes(budget)
	);
}

/// Delete everything in a cache directory, leaving the directory itself.
///
/// The blunt instrument for when something is cached that should not be. It
/// cannot make mach5 less safe — the worst it does is cost a re-download — so
/// unlike most controls it is safe to expose.
pub fn empty(dir: &Path) -> usize {
	let Ok(entries) = std::fs::read_dir(dir) else {
		return 0;
	};

	entries
		.filter_map(|entry| entry.ok())
		.filter(|entry| std::fs::remove_file(entry.path()).is_ok())
		.count()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn sweeping_brings_a_directory_back_under_budget() {
		let dir = tempfile::TempDir::new().unwrap();

		for i in 0..10u8 {
			std::fs::write(dir.path().join(format!("{i}.bin")), [0u8; 40]).unwrap();
			// Distinct timestamps, so oldest-first has something to sort on.
			std::thread::sleep(std::time::Duration::from_millis(5));
		}
		sweep(dir.path(), 100);

		let left: u64 = std::fs::read_dir(dir.path())
			.unwrap()
			.filter_map(|e| e.ok()?.metadata().ok())
			.map(|m| m.len())
			.sum();

		assert!(left <= 100, "{left} bytes is over the budget");
		assert!(left > 0, "and it must not simply empty itself");
	}

	#[test]
	fn emptying_removes_everything_and_keeps_the_directory() {
		let dir = tempfile::TempDir::new().unwrap();
		std::fs::write(dir.path().join("a.bin"), [0u8; 4]).unwrap();
		std::fs::write(dir.path().join("b.bin"), [0u8; 4]).unwrap();

		assert_eq!(empty(dir.path()), 2);
		assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
		assert!(dir.path().exists(), "the cache can still be written to");
	}

	#[test]
	fn a_directory_inside_its_budget_is_left_alone() {
		let dir = tempfile::TempDir::new().unwrap();
		std::fs::write(dir.path().join("small.bin"), [0u8; 10]).unwrap();

		sweep(dir.path(), 1024);

		assert!(dir.path().join("small.bin").exists());
	}
}
