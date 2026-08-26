//! Files under a budget, and files replaced without a reader seeing a tear.
//!
//! Shared by the two on-disk caches and the list fetcher, which want the same
//! two things: delete the least recently used files until the total fits
//! again, and never leave a half-written file where something will read it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Delete oldest-first until `budget` is met.
///
/// Least recently *used* where the filesystem tracks it, and modification time
/// where it does not — many are mounted `relatime` and will not update atime
/// for a read. For files never written twice, that means oldest-first, which is
/// the honest fallback.
/// Put `bytes` at `path` without any reader ever seeing a partial file.
///
/// The temporary has to be unique per *write*, not per process. Workers here
/// are threads, so a process id is the same for all of them, and two of them
/// replacing one path shared a temporary: the second `create` truncated the
/// first mid-write, and — because `rename` moves the name and not the open
/// file — the loser then went on writing into the *published* file. A reader
/// gets half a stylesheet or a clipped image, and it is served as a
/// well-formed 200, since the framing is recomputed from what was read.
///
/// The counter is what makes them distinct; the pid is kept for the other
/// case, two processes over one directory.
pub fn replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
	static WRITES: AtomicU64 = AtomicU64::new(0);

	let nth = WRITES.fetch_add(1, Ordering::Relaxed);
	let temporary = path.with_extension(format!("tmp{}.{nth}", std::process::id()));

	std::fs::write(&temporary, bytes).inspect_err(|_| {
		let _ = std::fs::remove_file(&temporary);
	})?;

	std::fs::rename(&temporary, path).inspect_err(|_| {
		let _ = std::fs::remove_file(&temporary);
	})
}

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

	/// The property the whole point rests on: at no instant does the published
	/// path hold anything but a complete previous version or a complete new
	/// one — even with several threads replacing it at once with different
	/// contents.
	#[test]
	fn a_reader_never_sees_a_half_written_file() {
		let dir = tempfile::TempDir::new().unwrap();
		let path = dir.path().join("body");
		let sizes = [1_000usize, 200_000, 40_000, 900_000];

		replace(&path, &vec![b'0'; sizes[0]]).unwrap();

		let writers: Vec<_> = sizes
			.iter()
			.enumerate()
			.map(|(n, size)| {
				let path = path.clone();
				let byte = b'a' + n as u8;
				let size = *size;

				std::thread::spawn(move || {
					for _ in 0..25 {
						replace(&path, &vec![byte; size]).unwrap();
					}
				})
			})
			.collect();

		for _ in 0..500 {
			// Whatever is there must be one writer's bytes, all of them, and
			// the right number of them. A tear shows up as a mixture or as a
			// length nobody wrote.
			if let Ok(read) = std::fs::read(&path) {
				let byte = read[0];
				assert!(
					read.iter().all(|b| *b == byte),
					"a mixture of two writers' bytes"
				);

				let wrote = match byte {
					b'0' => sizes[0],
					other => sizes[(other - b'a') as usize],
				};
				assert_eq!(read.len(), wrote, "the file is a length nobody wrote");
			}
			std::thread::yield_now();
		}

		for writer in writers {
			writer.join().unwrap();
		}

		// And nothing is left behind.
		let leftovers: Vec<_> = std::fs::read_dir(dir.path())
			.unwrap()
			.filter_map(|e| e.ok())
			.map(|e| e.file_name().to_string_lossy().to_string())
			.filter(|name| name != "body")
			.collect();
		assert!(leftovers.is_empty(), "temporaries left behind: {leftovers:?}");
	}

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
