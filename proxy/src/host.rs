//! What a hostname is, and when one name covers another.
//!
//! Neither question is about blocking, which is only where they were first
//! asked. The answers are shared by the blocklist, the cosmetic filters, the
//! injection exclusions and the passthrough list, and they live here so that a
//! host means the same thing in all of them.
//!
//! [`covers`] in particular is load-bearing for [`crate::passthrough`], the
//! never-decrypt list, where being too broad is not a wasted advert but a
//! connection nobody meant to leave alone. It walks label boundaries for that
//! reason: the obvious substring test would have `example-bank.com` matching
//! `notexample-bank.com`.

use std::collections::HashSet;

/// Names a hosts file points at loopback for its own housekeeping. Taking them
/// for domains would be pointless at best and confusing at worst.
const HOUSEKEEPING: [&str; 4] = [
	"localhost",
	"localhost.localdomain",
	"local",
	"broadcasthost",
];

/// Whether the host, or any domain above it, is in the set. Walking the parents
/// is what makes this label-aware: `notdoubleclick.net` never reaches
/// `doubleclick.net`, where a substring test would have matched it.
///
/// Shared by the blocklist, [`crate::inject`] and [`crate::passthrough`], so
/// that "a parent domain covers its subdomains" means the same thing wherever a
/// host is matched against a list.
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

/// A name a hosts file points at loopback for its own sake, not to block it.
/// The `ip6-*` family are the same idea.
fn housekeeping(domain: &str) -> bool {
	HOUSEKEEPING.contains(&domain) || domain.starts_with("ip6-")
}

/// Lowercase and drop a trailing root dot. Single-label names are rejected: a
/// stray `localhost`, or the remains of a line we misread, would otherwise be a
/// parent of nothing useful — or, worse, of everything.
///
/// Shared by the blocklist, [`crate::cosmetic`] and [`crate::passthrough`],
/// whose lists all name domains in the same shape and have the same reasons to
/// refuse the ones that are not.
pub fn normalize(raw: &str) -> Option<String> {
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

	fn set(hosts: &[&str]) -> HashSet<String> {
		hosts.iter().map(|host| host.to_string()).collect()
	}

	/// The walk itself, rather than one caller's use of it: every list in the
	/// proxy inherits this, and the passthrough list inherits it as a security
	/// boundary.
	#[test]
	fn parents_match_but_only_on_label_boundaries() {
		let set = set(&["doubleclick.net"]);

		assert!(covers(&set, "doubleclick.net"));
		assert!(covers(&set, "ad.g.doubleclick.net"));
		assert!(
			!covers(&set, "notdoubleclick.net"),
			"substring is not a match"
		);
		assert!(!covers(&set, "doubleclick.net.evil.com"));
		assert!(!covers(&set, "net"));
	}

	#[test]
	fn a_name_is_lowercased_and_a_single_label_rejected() {
		assert_eq!(normalize("localhost"), None);
		assert_eq!(normalize("localhost.localdomain"), None);
		assert_eq!(normalize("example.com."), Some("example.com".to_string()));
		assert_eq!(
			normalize("ADS.Example.COM"),
			Some("ads.example.com".to_string())
		);
	}
}
