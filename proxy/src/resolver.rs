//! Which of an origin's addresses mach5 tries first.
//!
//! mach5 resolves origins itself, on its own host, which has a consequence
//! worth stating plainly: **a client does not need IPv6 to reach an IPv6-only
//! site through mach5.** The client speaks to the proxy over whatever it has,
//! and the proxy speaks to the origin over whatever *it* has. Turning IPv6 off
//! on a laptop stops that laptop reaching v6-only origins; going through mach5
//! does not.
//!
//! What this module adds is the other half: choosing which family to try first
//! when an origin has both. A 6rd tunnel is IPv6 that arrives over IPv4 with a
//! relay in the middle, and is frequently far slower than the IPv4 path it is
//! riding on — so preferring A records avoids the tunnel while leaving
//! AAAA-only origins reachable, because the list still contains them.
//!
//! ureq tries the addresses handed back in order until one connects, so
//! ordering is all that is needed here. Nothing is filtered out: a policy that
//! dropped addresses would turn "slower" into "unreachable".

use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::AddressPolicy;

pub struct Ordered {
	policy: AddressPolicy,
	metrics: Arc<crate::metrics::Metrics>,
}

impl Ordered {
	pub fn new(policy: AddressPolicy) -> Self {
		Self {
			policy,
			metrics: crate::metrics::shared(),
		}
	}
}

impl ureq::Resolver for Ordered {
	fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
		use std::net::ToSocketAddrs;

		let mut addresses: Vec<SocketAddr> = netloc.to_socket_addrs()?.collect();
		count(&self.metrics, &addresses);
		order(&mut addresses, self.policy);

		Ok(addresses)
	}
}

/// What each family a lookup came back with, which is the honest version of
/// "IPv4 against IPv6 usage".
///
/// mach5 hands ureq a list and does not learn which entry actually connected,
/// so counting this as *utilisation* would be a guess. What it can say for
/// certain is how much of what it looks up is reachable each way — which is
/// the more interesting number anyway.
fn count(metrics: &crate::metrics::Metrics, addresses: &[SocketAddr]) {
	let v4 = addresses.iter().any(SocketAddr::is_ipv4);
	let v6 = addresses.iter().any(SocketAddr::is_ipv6);

	match (v4, v6) {
		(true, true) => metrics.lookups_dual.increment(),
		(true, false) => metrics.lookups_ipv4_only.increment(),
		(false, true) => metrics.lookups_ipv6_only.increment(),
		(false, false) => {}
	}
}

/// A stable sort, so whatever order the resolver put the addresses of one
/// family in — which is where its own latency and round-robin knowledge lives
/// — survives being grouped.
fn order(addresses: &mut [SocketAddr], policy: AddressPolicy) {
	match policy {
		AddressPolicy::System => {}
		AddressPolicy::PreferIpv4 => addresses.sort_by_key(|address| !address.is_ipv4()),
		AddressPolicy::PreferIpv6 => addresses.sort_by_key(|address| !address.is_ipv6()),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn addresses(specs: &[&str]) -> Vec<SocketAddr> {
		specs.iter().map(|s| s.parse().unwrap()).collect()
	}

	#[test]
	fn preferring_one_family_puts_it_first_and_keeps_the_other() {
		let mut got = addresses(&["[2001:db8::1]:443", "192.0.2.1:443", "[2001:db8::2]:443"]);
		order(&mut got, AddressPolicy::PreferIpv4);

		assert!(got[0].is_ipv4());
		assert_eq!(
			got.len(),
			3,
			"nothing is dropped: a preference must not become a refusal"
		);
		assert!(got[1..].iter().all(SocketAddr::is_ipv6));
	}

	#[test]
	fn preferring_the_other_way_round_works_the_same() {
		let mut got = addresses(&["192.0.2.1:443", "[2001:db8::1]:443"]);
		order(&mut got, AddressPolicy::PreferIpv6);

		assert!(got[0].is_ipv6());
		assert!(got[1].is_ipv4());
	}

	#[test]
	fn an_origin_with_only_one_family_is_untouched() {
		let only_v6 = addresses(&["[2001:db8::1]:443", "[2001:db8::2]:443"]);

		let mut got = only_v6.clone();
		order(&mut got, AddressPolicy::PreferIpv4);

		assert_eq!(
			got, only_v6,
			"an AAAA-only origin stays reachable, which is the whole point"
		);
	}

	#[test]
	fn the_resolvers_own_ordering_survives_within_a_family() {
		let mut got = addresses(&["192.0.2.9:443", "[2001:db8::1]:443", "192.0.2.1:443"]);
		order(&mut got, AddressPolicy::PreferIpv4);

		assert_eq!(
			got[..2].to_vec(),
			addresses(&["192.0.2.9:443", "192.0.2.1:443"]),
			"a stable sort keeps what the resolver knew about these two"
		);
	}

	#[test]
	fn the_system_policy_changes_nothing() {
		let original = addresses(&["[2001:db8::1]:443", "192.0.2.1:443"]);

		let mut got = original.clone();
		order(&mut got, AddressPolicy::System);

		assert_eq!(got, original);
	}

	#[test]
	fn what_a_lookup_offered_is_counted_by_family() {
		let metrics = crate::metrics::Metrics::default();

		count(&metrics, &addresses(&["192.0.2.1:443"]));
		count(&metrics, &addresses(&["[2001:db8::1]:443"]));
		count(&metrics, &addresses(&["192.0.2.1:443", "[2001:db8::1]:443"]));

		assert_eq!(metrics.lookups_ipv4_only.get(), 1);
		assert_eq!(metrics.lookups_ipv6_only.get(), 1);
		assert_eq!(metrics.lookups_dual.get(), 1);
	}
}
