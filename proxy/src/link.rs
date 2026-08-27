//! How fast the client on the other side of a connection is.
//!
//! mach5 sits between two links and only one of them is worth reacting to. A
//! CDN having a bad minute is not a reason to serve somebody grey boxes; their
//! phone having one bar is. So nothing here is allowed to observe the origin:
//! both entry points take a measurement that could only have come from the
//! client — the congestion controller's own estimate of what the client
//! acknowledged on the QUIC side, and time spent *parked waiting for the client
//! to drain* on the TCP side. Neither can be produced by a slow origin, which
//! is the property the rest of the design rests on.
//!
//! What comes out is a [`Tier`], deliberately coarse. Nothing here decides what
//! a tier means for an image, a compression level or an injection: this module
//! measures, and its consumers choose.
//!
//! Identity is the peer address and nothing more. That is wrong in both
//! directions — a NAT'd household shares one, and a phone changes its own when
//! it moves — and it is wrong cheaply: the cost of confusing two clients is
//! that one of them gets pictures chosen for the other. There is deliberately
//! no session, no cookie and nothing written to disk, because the moment this
//! could tell two people apart it would be worth far more scrutiny than a
//! quality heuristic deserves.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::Config;

/// What to serve a client, coarsest first.
///
/// The ladder is ordered by how much it takes away, so [`Tier::degradation`] is
/// the only comparison anything should make. `Ord` is deliberately *not*
/// derived: "greater" would mean "worse", and every use site would have to
/// remember that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
	/// Whatever was configured. The link is not the constraint.
	Full,
	/// Same pictures, fewer bytes.
	Reduced,
	/// Colour is the first thing worth spending, and greyscale compresses far
	/// harder than a quality drop does.
	Grey,
	/// A solid block of the image's own dimensions. The page still lays out
	/// correctly; the bytes are gone.
	Placeholder,
	/// Not fetched at all.
	#[serde(rename = "none")]
	Nothing,
}

/// What a client nothing has measured yet is assumed to be.
///
/// Optimistic, and the argument for it is narrow enough to write down:
///
/// - The first thing a connection carries is a document, not an image, and
///   carrying it is itself a measurement. Both front ends have a sample before
///   the images on that page are requested, so the cold window is one document
///   long rather than one page long.
/// - An entry outlives the connection that produced it — it is keyed by
///   address and expires on a timer — so a genuinely slow client is cold once,
///   not once per connection.
/// - The two mistakes are not symmetric. Guessing *pessimistically* is wrong
///   for every fast client on the network, on their first page, visibly:
///   greyscale that arrives on a link that never needed it reads as a broken
///   proxy. Guessing optimistically is wrong for one document's worth of images
///   on a slow link, and corrects itself immediately afterwards.
///
/// It is the wrong guess for the case the project cares most about — the one
/// bar on the mountainside — for exactly one page load. That is the trade being
/// made, and it is only defensible because of the two points above it.
const COLD_START: Tier = Tier::Full;

/// Consecutive samples that must all argue for a better tier before one is
/// served. Downgrades need none of this: they apply as soon as the smoothed
/// estimate crosses.
const UPGRADE_SAMPLES: u8 = 3;

/// Ignore a window this short, so one unlucky moment cannot decide anything.
const MIN_WINDOW: Duration = Duration::from_millis(250);

/// And ignore a window this small even if it was slow, so one unlucky chunk
/// cannot decide anything.
const MIN_BYTES: u64 = 16 * 1024;

/// How much a QUIC connection must have sent before its delivery rate means
/// anything. Below this the number is slow start ramping up, which would read
/// as a slow client on the fastest link in the world.
const MIN_DELIVERED_BYTES: u64 = 32 * 1024;

impl Tier {
	/// How far down the ladder this is: 0 is untouched, and larger is less to
	/// carry. The only ordering this type has.
	pub fn degradation(self) -> u8 {
		match self {
			Self::Full => 0,
			Self::Reduced => 1,
			Self::Grey => 2,
			Self::Placeholder => 3,
			Self::Nothing => 4,
		}
	}

	pub fn label(self) -> &'static str {
		match self {
			Self::Full => "full quality",
			Self::Reduced => "reduced quality",
			Self::Grey => "greyscale",
			Self::Placeholder => "placeholders",
			Self::Nothing => "no images",
		}
	}
}

/// The ladder, best first. Parallel to [`Thresholds::floors`]; `Nothing` has no
/// floor because it is what is left when nothing else matches.
const LADDER: [Tier; 4] = [Tier::Full, Tier::Reduced, Tier::Grey, Tier::Placeholder];

/// What has been measured about one client, for something that wants to show it
/// rather than act on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Estimate {
	pub tier: Tier,
	pub kbps: u32,
	pub age: Duration,
}

/// The lowest speed that still earns each tier.
struct Thresholds {
	floors: [u32; 4],
}

impl Thresholds {
	fn from_config(config: &Config) -> Self {
		// Clamped rather than validated: the ladder only means anything if it
		// descends, and a configuration file that says otherwise should get a
		// working proxy and a slightly odd ladder rather than a refusal to
		// start over a picture-quality heuristic.
		let mut floors = [
			config.link.full_kbps,
			config.link.reduced_kbps,
			config.link.grey_kbps,
			config.link.placeholder_kbps,
		];
		for i in 1..floors.len() {
			floors[i] = floors[i].min(floors[i - 1]);
		}

		Self { floors }
	}

	fn tier_for(&self, kbps: u32) -> Tier {
		for (tier, floor) in LADDER.iter().zip(self.floors) {
			if kbps >= floor {
				return *tier;
			}
		}

		Tier::Nothing
	}
}

struct Entry {
	/// Smoothed, not raw — see [`blend`].
	kbps: u32,
	tier: Tier,
	/// How many samples in a row have argued for something better than `tier`.
	upgrades: u8,
	seen: Instant,
}

/// Every client mach5 has measured lately.
pub struct Links {
	/// Off means every accessor answers [`COLD_START`] and nothing is stored,
	/// so switching this off costs a comparison rather than a lock.
	enabled: bool,
	thresholds: Thresholds,
	ttl: Duration,
	max: usize,
	clients: Mutex<HashMap<IpAddr, Entry>>,
}

impl Links {
	pub fn new(config: &Config) -> Self {
		Self {
			enabled: config.link.enabled,
			thresholds: Thresholds::from_config(config),
			ttl: Duration::from_secs(u64::from(config.link.ttl_minutes) * 60),
			// A store keyed by peer address that never forgets is a slow leak
			// on a process that runs for months.
			max: config.link.max_clients.max(1),
			clients: Mutex::new(HashMap::new()),
		}
	}

	/// Take one measurement **of the client link**.
	///
	/// Callers must not pass anything an origin could have caused. There are
	/// only two ways to get a value that qualifies, and both are in this
	/// module: [`from_drain`] and [`from_delivery_rate`].
	pub fn record(&self, peer: IpAddr, kbps: u32) {
		self.record_at(peer, kbps, Instant::now());
	}

	/// What to serve this client. Answers even for a client never seen, which
	/// is the whole point of [`COLD_START`].
	///
	/// What a tier *means* is not decided here: [`crate::images`] is the one
	/// consumer so far, and it weighs this against what the panel asked for.
	pub fn tier(&self, peer: IpAddr) -> Tier {
		self.tier_at(peer, Instant::now())
	}

	/// The same, with the number behind it, for the status page. `None` means
	/// nothing has been measured — which is not the same as a slow client.
	pub fn estimate(&self, peer: IpAddr) -> Option<Estimate> {
		self.estimate_at(peer, Instant::now())
	}

	/// How many clients are being tracked, for the status page.
	pub fn tracked(&self) -> usize {
		self.clients.lock().expect("link lock").len()
	}

	fn record_at(&self, peer: IpAddr, kbps: u32, now: Instant) {
		if !self.enabled || kbps == 0 {
			return;
		}

		let mut clients = self.clients.lock().expect("link lock");

		match clients.get_mut(&peer) {
			// Expired is the same as never seen: an old measurement of a
			// different network on the same address is worse than no
			// measurement at all.
			Some(entry) if now.duration_since(entry.seen) < self.ttl => {
				entry.kbps = blend(entry.kbps, kbps);
				entry.seen = now;

				let candidate = self.thresholds.tier_for(entry.kbps);
				// The tier this speed would still earn if the link were a fifth
				// worse than it currently measures. Upgrading to *this* rather
				// than to `candidate` is the margin: a link that has only just
				// crossed a threshold is not yet a link on the other side of it.
				let confident = self.thresholds.tier_for(entry.kbps / 5 * 4);

				if candidate.degradation() >= entry.tier.degradation() {
					// Worse, or no better. Applied at once: a page that is
					// still loading when the link collapses should finish
					// loading.
					entry.tier = candidate;
					entry.upgrades = 0;
				} else if confident.degradation() < entry.tier.degradation() {
					entry.upgrades = entry.upgrades.saturating_add(1);
					if entry.upgrades >= UPGRADE_SAMPLES {
						entry.tier = confident;
						entry.upgrades = 0;
					}
				} else {
					entry.upgrades = 0;
				}
			}
			_ => {
				// Nothing is being served to this client yet, so there is no
				// tier to be sticky about: the first sample is taken at face
				// value in both directions.
				let entry = Entry {
					kbps,
					tier: self.thresholds.tier_for(kbps),
					upgrades: 0,
					seen: now,
				};
				clients.insert(peer, entry);
				self.bound(&mut clients, now);
			}
		}
	}

	fn tier_at(&self, peer: IpAddr, now: Instant) -> Tier {
		self.estimate_at(peer, now)
			.map(|estimate| estimate.tier)
			.unwrap_or(COLD_START)
	}

	fn estimate_at(&self, peer: IpAddr, now: Instant) -> Option<Estimate> {
		if !self.enabled {
			return None;
		}

		let clients = self.clients.lock().expect("link lock");
		let entry = clients.get(&peer)?;
		let age = now.duration_since(entry.seen);
		if age >= self.ttl {
			return None;
		}

		Some(Estimate {
			tier: entry.tier,
			kbps: entry.kbps,
			age,
		})
	}

	/// Keep the map inside `max`, cheaply: expired entries first, and only if
	/// that was not enough, whichever client has gone longest without being
	/// measured. Called on insert, so the sweep happens once per new client
	/// rather than on every sample.
	fn bound(&self, clients: &mut HashMap<IpAddr, Entry>, now: Instant) {
		if clients.len() <= self.max {
			return;
		}

		clients.retain(|_, entry| now.duration_since(entry.seen) < self.ttl);

		while clients.len() > self.max {
			let Some(oldest) = clients
				.iter()
				.min_by_key(|(_, entry)| entry.seen)
				.map(|(peer, _)| *peer)
			else {
				break;
			};
			clients.remove(&oldest);
		}
	}
}

/// Half weight to a sample saying the link got worse, a quarter to one saying
/// it got better. Asymmetric on purpose: this is half of the stickiness, and
/// the half that stops a single stall from being ignored while still refusing
/// to believe one good chunk.
fn blend(previous: u32, sample: u32) -> u32 {
	let (previous, sample) = (u64::from(previous), u64::from(sample));

	let blended = if sample < previous {
		(previous + sample) / 2
	} else {
		(previous * 3 + sample) / 4
	};

	blended as u32
}

/// A measurement from the TCP front end: bytes the client actually took off our
/// hands, and the wall time it took to do it.
///
/// **The caller owes the origin-versus-client distinction.** This number is only
/// about the client if the client was the slower half — the caller establishes
/// that by only offering windows in which its send channel never fell empty, and
/// `tcp.rs` says how. Timing the origin read instead would have been easier and
/// would have measured entirely the wrong link: a slow CDN would look exactly
/// like a slow phone, and every client behind mach5 would get grey boxes because
/// one origin was having a bad minute.
///
/// `None` when the window is too small to divide by.
pub fn from_drain(bytes: u64, elapsed: Duration) -> Option<u32> {
	if elapsed < MIN_WINDOW || bytes < MIN_BYTES {
		return None;
	}

	let kbps = bytes.saturating_mul(8) / elapsed.as_millis().max(1) as u64;

	u32::try_from(kbps).ok().filter(|kbps| *kbps > 0)
}

/// A measurement from the QUIC front end: the congestion controller's delivery
/// rate, in bytes per second.
///
/// This is a client-link measurement by construction — it is derived from what
/// the *client* acknowledged, and the origin is not on this path at all — which
/// is why the QUIC side needs no equivalent of the care [`from_drain`] and its
/// caller take.
///
/// `None` until enough has been sent for the number to be about the link rather
/// than about slow start.
pub fn from_delivery_rate(bytes_per_second: u64, sent_bytes: u64) -> Option<u32> {
	if sent_bytes < MIN_DELIVERED_BYTES {
		return None;
	}

	u32::try_from(bytes_per_second.saturating_mul(8) / 1000)
		.ok()
		.filter(|kbps| *kbps > 0)
}

/// A speed in the largest unit that leaves a number worth reading.
pub fn speed(kbps: u32) -> String {
	if kbps >= 1000 {
		format!("{:.1} Mbps", f64::from(kbps) / 1000.0)
	} else {
		format!("{kbps} kbps")
	}
}

/// One store per process, exactly as [`crate::settings::shared`] does it: both
/// front ends measure into the same one, because they are two ways of reaching
/// the same phone.
pub fn shared(config: &Config) -> Arc<Links> {
	static SHARED: OnceLock<Arc<Links>> = OnceLock::new();

	SHARED.get_or_init(|| Arc::new(Links::new(config))).clone()
}

#[cfg(test)]
mod tests {
	use super::*;

	fn links(extra: &str) -> Links {
		Links::new(&Config::from_str(&format!("[link]\n{extra}")).unwrap())
	}

	fn peer() -> IpAddr {
		"192.0.2.10".parse().unwrap()
	}

	/// Feed `kbps` in until the tier stops being `from`, and say how many it
	/// took. `None` if it never moved.
	fn samples_to_leave(store: &Links, start: Instant, from: Tier, kbps: u32) -> Option<u8> {
		let mut at = start;
		for taken in 1..=50u8 {
			at += Duration::from_millis(200);
			store.record_at(peer(), kbps, at);
			if store.tier_at(peer(), at) != from {
				return Some(taken);
			}
		}

		None
	}

	#[test]
	fn a_client_nobody_has_measured_is_assumed_fast() {
		let store = links("");

		assert_eq!(store.tier(peer()), Tier::Full);
		assert_eq!(store.estimate(peer()), None, "assumed is not measured");
	}

	#[test]
	fn the_ladder_descends_with_the_link() {
		let store = links("");
		let ladder = &store.thresholds;

		assert_eq!(ladder.tier_for(50_000), Tier::Full);
		assert_eq!(ladder.tier_for(2_000), Tier::Full);
		assert_eq!(ladder.tier_for(1_999), Tier::Reduced);
		assert_eq!(ladder.tier_for(700), Tier::Reduced);
		assert_eq!(ladder.tier_for(699), Tier::Grey);
		assert_eq!(ladder.tier_for(250), Tier::Grey);
		assert_eq!(ladder.tier_for(249), Tier::Placeholder);
		assert_eq!(ladder.tier_for(80), Tier::Placeholder);
		assert_eq!(ladder.tier_for(79), Tier::Nothing);
		assert_eq!(ladder.tier_for(0), Tier::Nothing);
	}

	/// A ladder that does not descend is not a ladder. Clamped rather than
	/// rejected, so a typo cannot stop the proxy starting.
	#[test]
	fn a_ladder_written_out_of_order_is_clamped_back_into_one() {
		let store = links("full_kbps = 500\nreduced_kbps = 4000\ngrey_kbps = 3000\n");
		let floors = store.thresholds.floors;

		assert!(
			floors.windows(2).all(|pair| pair[0] >= pair[1]),
			"floors must descend: {floors:?}"
		);
		assert_eq!(store.thresholds.tier_for(600), Tier::Full);
	}

	#[test]
	fn the_first_measurement_is_taken_at_face_value() {
		let store = links("");
		let now = Instant::now();

		store.record_at(peer(), 120, now);

		assert_eq!(store.tier_at(peer(), now), Tier::Placeholder);
		assert_eq!(store.estimate_at(peer(), now).unwrap().kbps, 120);
	}

	/// The property the whole design rests on: falling is cheap, climbing is
	/// not. A page half in colour and half in grey looks broken, so the tier
	/// has to be reluctant to change — and reluctant asymmetrically, or a
	/// flapping link would spend half its time in the wrong place.
	///
	/// The same threshold and the same factor of two in each direction, so the
	/// only thing the two counts differ by is the reluctance being measured.
	#[test]
	fn a_tier_falls_faster_than_it_climbs() {
		let now = Instant::now();
		let (slow, fast) = (1_000, 4_000);

		let falling = links("");
		falling.record_at(peer(), fast, now);
		assert_eq!(falling.tier_at(peer(), now), Tier::Full);
		let down = samples_to_leave(&falling, now, Tier::Full, slow).expect("must fall");

		let climbing = links("");
		climbing.record_at(peer(), slow, now);
		assert_eq!(climbing.tier_at(peer(), now), Tier::Reduced);
		let up = samples_to_leave(&climbing, now, Tier::Reduced, fast).expect("must climb");

		assert!(
			up > down,
			"climbing took {up} samples and falling took {down}; \
			 climbing must need more evidence"
		);
	}

	/// The other half of the asymmetry, and the half the tier counts cannot
	/// show: a link that has collapsed should be believed sooner than one
	/// claiming to have recovered, so the same distance in each direction must
	/// not move the estimate by the same amount.
	#[test]
	fn a_worse_sample_moves_the_estimate_further_than_a_better_one() {
		let settled = 1_000;
		let fell = settled - blend(settled, 500);
		let rose = blend(settled, 1_500) - settled;

		assert!(fell > rose, "fell by {fell}, rose by only {rose}");
	}

	/// The other half of stickiness. One good sample on a link that has been
	/// bad is a lull, not a recovery.
	#[test]
	fn one_good_sample_never_upgrades() {
		let store = links("");
		let mut at = Instant::now();
		store.record_at(peer(), 100, at);

		at += Duration::from_millis(200);
		store.record_at(peer(), 100_000, at);

		assert_eq!(
			store.tier_at(peer(), at),
			Tier::Placeholder,
			"a single fast sample must not repaint the page"
		);
	}

	/// And having climbed, it must actually arrive: a tier that could never
	/// improve would be a one-way ratchet down.
	#[test]
	fn a_link_that_stays_good_does_climb_back() {
		let store = links("");
		let mut at = Instant::now();
		store.record_at(peer(), 100, at);

		for _ in 0..10 {
			at += Duration::from_millis(200);
			store.record_at(peer(), 20_000, at);
		}

		assert_eq!(store.tier_at(peer(), at), Tier::Full);
	}

	/// A sample arriving after the entry went stale starts again rather than
	/// being blended with it: the address may well be a different phone by now.
	#[test]
	fn an_entry_expires() {
		let store = links("ttl_minutes = 1\n");
		let now = Instant::now();
		store.record_at(peer(), 100, now);

		let later = now + Duration::from_secs(61);

		assert_eq!(store.estimate_at(peer(), later), None);
		assert_eq!(
			store.tier_at(peer(), later),
			COLD_START,
			"a forgotten client is a new client"
		);

		store.record_at(peer(), 20_000, later);
		assert_eq!(
			store.tier_at(peer(), later),
			Tier::Full,
			"the first sample after expiry is a first sample"
		);
	}

	#[test]
	fn the_store_is_bounded() {
		let store = links("max_clients = 8\n");
		let now = Instant::now();

		for n in 0..200u32 {
			let peer = IpAddr::from(std::net::Ipv4Addr::from(n.to_be_bytes()));
			store.record_at(peer, 1_000, now + Duration::from_millis(u64::from(n)));
		}

		assert!(store.tracked() <= 8, "tracked {} clients", store.tracked());
	}

	/// Expiry alone must not be what keeps the map small: a thousand clients
	/// all measured a moment ago are still a thousand entries.
	#[test]
	fn the_bound_holds_even_when_nothing_has_expired() {
		let store = links("max_clients = 4\nttl_minutes = 600\n");
		let now = Instant::now();

		for n in 0..50u32 {
			let peer = IpAddr::from(std::net::Ipv4Addr::from(n.to_be_bytes()));
			store.record_at(peer, 1_000, now);
		}

		assert!(store.tracked() <= 4, "tracked {} clients", store.tracked());
	}

	#[test]
	fn switched_off_it_measures_nothing_and_assumes_the_best() {
		let store = links("enabled = false\n");
		let now = Instant::now();

		store.record_at(peer(), 30, now);

		assert_eq!(store.tier_at(peer(), now), Tier::Full);
		assert_eq!(store.estimate_at(peer(), now), None);
		assert_eq!(store.tracked(), 0, "nothing is stored when it is off");
	}

	#[test]
	fn a_window_too_small_to_divide_by_is_not_a_measurement() {
		assert_eq!(
			from_drain(64 * 1024 * 1024, Duration::ZERO),
			None,
			"no elapsed time to divide by"
		);
		assert_eq!(
			from_drain(64 * 1024, Duration::from_millis(249)),
			None,
			"too short a window to mean anything"
		);
		assert_eq!(
			from_drain(1024, Duration::from_secs(30)),
			None,
			"too few bytes to divide by"
		);
	}

	#[test]
	fn a_drain_the_client_paced_is_a_measurement() {
		// 256KiB the client took a quarter of a second to accept.
		assert_eq!(
			from_drain(256 * 1024, Duration::from_millis(250)),
			Some(8388)
		);
		// 64KiB over ten seconds: a phone with one bar.
		assert_eq!(from_drain(64 * 1024, Duration::from_secs(10)), Some(52));
	}

	#[test]
	fn a_delivery_rate_is_ignored_until_slow_start_is_over() {
		assert_eq!(
			from_delivery_rate(125_000, 1024),
			None,
			"a connection this young has only measured its own ramp"
		);
		assert_eq!(from_delivery_rate(125_000, 1024 * 1024), Some(1000));
		assert_eq!(from_delivery_rate(0, 1024 * 1024), None);
	}

	#[test]
	fn speeds_read_in_the_unit_they_belong_in() {
		assert_eq!(speed(52), "52 kbps");
		assert_eq!(speed(999), "999 kbps");
		assert_eq!(speed(5242), "5.2 Mbps");
	}
}
