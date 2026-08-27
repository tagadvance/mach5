//! What the control panel is allowed to change.
//!
//! Everything under `/.mach5/` is same-origin on every site — that is what
//! makes it reachable at all, and it means any page you visit can POST here.
//! The hidden-element endpoints survive that because they are host-scoped: a
//! page can only touch its own list. Settings are global, so they cannot lean
//! on the same defence.
//!
//! The line drawn instead is in the shape of this type. **Everything settable
//! here can make the web look worse and none of it can make mach5 less safe.**
//! Blocking, passthrough, certificate validation and the bypass are absent on
//! purpose and belong in the configuration file, where a web page cannot reach
//! them. The worst a hostile site can do through this endpoint is force your
//! images ugly, which is annoying rather than dangerous.
//!
//! If something genuinely dangerous ever needs a switch, the way to do it is a
//! reserved hostname mach5 answers and refuses these writes from anywhere else
//! — enforceable, because mach5 sees the SNI. Nothing needs it yet.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::config::Config;

/// How hard mach5 should work on images, when somebody would rather decide for
/// themselves than let it decide.
///
/// The point of `Low` is a connection flapping between good and useless, which
/// is exactly when an automatic measurement is least worth trusting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Quality {
	/// Whatever the configuration says.
	#[default]
	Auto,
	/// Better than configured, for when the link is fine and the eyes are not.
	High,
	/// Worse on purpose. Half the bytes of `Auto`, give or take.
	Low,
	/// Leave images exactly as the origin sent them. The *highest* quality
	/// there is, and not to be confused with `None` below: both skip the
	/// encoder, and only `None` skips the origin.
	Off,
	/// Do not fetch them at all. Every image request is answered on the spot
	/// with a transparent pixel, so the bytes are never paid for — which is
	/// the whole point, and why this is a tier rather than a stronger `Low`.
	None,
}

impl Quality {
	/// The WebP quality this asks for, given what the configuration wanted.
	pub fn applied_to(self, configured: u8) -> Option<u8> {
		match self {
			Self::Auto => Some(configured),
			Self::High => Some(configured.saturating_add(12).min(95)),
			Self::Low => Some(configured.saturating_sub(35).max(20)),
			Self::Off => None,
			Self::None => None,
		}
	}
}

/// Everything the panel may set. Adding a field here is a decision about what
/// a web page is allowed to do to mach5 — see the note at the top of the file.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Settings {
	pub image_quality: Quality,
	/// Stop putting the picker and the stylesheet into pages. Someone
	/// debugging a site wants this, and it is theirs to turn back on.
	pub inject: Injection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Injection {
	#[default]
	On,
	Off,
}

/// The live settings, on disk and in memory.
pub struct Store {
	settings: Mutex<Settings>,
	path: PathBuf,
}

impl Store {
	pub fn load(path: PathBuf) -> Self {
		let settings = match std::fs::read(&path) {
			Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
				log::warn!("ignoring unreadable settings at {}: {e}", path.display());

				Settings::default()
			}),
			Err(e) if e.kind() == std::io::ErrorKind::NotFound => Settings::default(),
			Err(e) => {
				log::warn!("cannot read settings at {}: {e}", path.display());

				Settings::default()
			}
		};

		Self {
			settings: Mutex::new(settings),
			path,
		}
	}

	pub fn get(&self) -> Settings {
		*self.lock()
	}

	/// Replace the settings and write them out. Logged, because a change made
	/// from a web page should be visible to whoever runs the proxy.
	pub fn set(&self, settings: Settings) {
		let mut held = self.lock();
		if *held == settings {
			return;
		}

		*held = settings;
		log::info!("settings changed: {settings:?}");
		persist(&self.path, &settings);
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, Settings> {
		self.settings.lock().expect("settings lock")
	}
}

fn persist(path: &Path, settings: &Settings) {
	let Ok(json) = serde_json::to_vec(settings) else {
		return;
	};

	// Write-and-rename, as the hidden-element store does: a crash mid-write
	// must not leave an empty file where the settings were.
	let temporary = path.with_extension("json.tmp");
	let written = std::fs::File::create(&temporary).and_then(|mut file| {
		file.write_all(&json)?;
		file.sync_all()?;
		drop(file);

		std::fs::rename(&temporary, path)
	});

	if let Err(e) = written {
		log::warn!("cannot save settings to {}: {e}", path.display());
	}
}

pub fn shared(config: &Config) -> Arc<Store> {
	static SHARED: OnceLock<Arc<Store>> = OnceLock::new();

	SHARED
		.get_or_init(|| Arc::new(Store::load(config.paths.state_dir.join("settings.json"))))
		.clone()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn quality_moves_around_what_was_configured() {
		assert_eq!(Quality::Auto.applied_to(80), Some(80));
		assert!(Quality::High.applied_to(80) > Quality::Auto.applied_to(80));
		assert!(Quality::Low.applied_to(80) < Quality::Auto.applied_to(80));
		assert_eq!(Quality::Off.applied_to(80), None, "off means untouched");
	}

	#[test]
	fn quality_stays_inside_what_webp_accepts() {
		assert_eq!(Quality::High.applied_to(95), Some(95), "never past 95");
		assert_eq!(Quality::Low.applied_to(10), Some(20), "never below 20");
	}

	#[test]
	fn settings_round_trip_through_disk() {
		let dir = tempfile::TempDir::new().unwrap();
		let path = dir.path().join("settings.json");

		let store = Store::load(path.clone());
		assert_eq!(store.get(), Settings::default());

		store.set(Settings {
			image_quality: Quality::Low,
			inject: Injection::Off,
		});

		let reopened = Store::load(path);
		assert_eq!(reopened.get().image_quality, Quality::Low);
		assert_eq!(reopened.get().inject, Injection::Off);
	}

	#[test]
	fn nonsense_on_disk_is_ignored_rather_than_fatal() {
		let dir = tempfile::TempDir::new().unwrap();
		let path = dir.path().join("settings.json");
		std::fs::write(&path, b"{ not json").unwrap();

		assert_eq!(Store::load(path).get(), Settings::default());
	}

	/// The whole point of the type. If this test has to change, the change
	/// needs an argument attached to it.
	#[test]
	fn nothing_dangerous_is_settable() {
		let json = serde_json::to_string(&Settings::default()).unwrap();

		for forbidden in ["blocklist", "passthrough", "bypass", "verify", "ca", "plugin"] {
			assert!(
				!json.contains(forbidden),
				"a web page must not be able to set {forbidden}: {json}"
			);
		}
	}
}
