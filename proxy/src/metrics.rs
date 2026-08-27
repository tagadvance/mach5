//! What the proxy has actually been doing.
//!
//! Counters, and nothing but counters. Every one of them is `Relaxed`: nothing
//! in the proxy branches on a count, so the alternative is paying for ordering
//! on every request to protect a number that is only ever read by a person
//! looking at a page. A lost increment costs one off a total.
//!
//! There is one set per process rather than one per chain. Every worker builds
//! its own [`crate::interceptor::Chain`], so per-chain counters would answer
//! "what did this worker do", which is a question nobody is asking.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::Serialize;

const KB: u64 = 1024;
const MB: u64 = KB * 1024;
const GB: u64 = MB * 1024;

/// One number that only ever goes up.
///
/// A newtype rather than a bare `AtomicU64` so that every call site is one
/// unambiguous line, instead of repeating a `fetch_add` and an ordering
/// argument at each of the places a count is taken — where a wrong ordering
/// would be easy to write and impossible to notice.
#[derive(Default)]
pub struct Counter(AtomicU64);

impl Counter {
	pub fn increment(&self) {
		self.0.fetch_add(1, Relaxed);
	}

	pub fn add(&self, n: u64) {
		self.0.fetch_add(n, Relaxed);
	}

	pub fn get(&self) -> u64 {
		self.0.load(Relaxed)
	}
}

/// What one plugin has cost so far.
#[derive(Default)]
pub struct PluginTime {
	pub calls: u64,
	pub total: Duration,
	/// Responses this plugin asked to see and was not shown. There is exactly
	/// one way that happens — a chunk plugin whose response was buffered for
	/// the cache — and the whole reason it is counted is that the symptom
	/// otherwise is "my plugin does not run" with nothing to look at.
	pub skipped: u64,
}

/// Every counter the proxy keeps, plus the moment it started.
pub struct Metrics {
	/// Taken when the metrics are first asked for, which is during startup.
	started: Instant,
	/// Every request that reached a front end and was about to be handled.
	pub requests: Counter,
	/// Requests the blocklist answered instead of the origin.
	pub blocked: Counter,
	/// Connections spliced to the origin without ever being decrypted.
	pub passed_through: Counter,
	/// Requests answered by the proxy's own endpoints under `/.mach5/`.
	pub internal: Counter,
	/// Pages that actually had the tags spliced into them.
	pub injected: Counter,
	/// Fetches made without validating the origin's certificate.
	pub bypassed: Counter,
	/// Fetches refused because the origin's certificate did not validate.
	pub tls_failures: Counter,
	/// Fetches that failed for any other reason.
	pub upstream_failures: Counter,
	/// Response body bytes read from origins, as they arrived on the wire.
	pub bytes_from_origin: Counter,
	/// Response body bytes sent to clients. Differs from the above whenever an
	/// interceptor rewrote a body — which is the point of counting both.
	pub bytes_to_client: Counter,
	/// Bytes `bytes_to_client` does not contain because we compressed a body
	/// the origin left in the clear: what the client would have had to read
	/// otherwise.
	pub bytes_saved_by_compression: Counter,
	/// Bytes not sent because an image was re-encoded.
	pub bytes_saved_by_images: Counter,
	/// Images answered with a pixel instead of being fetched, in text-only
	/// mode. Counted rather than measured in bytes: the origin was never
	/// asked, so what it would have sent is not known.
	pub images_stripped: Counter,
	/// Upstream lookups by the families they came back with. Not utilisation —
	/// see `resolver.rs` for why that would be a guess.
	/// Re-encodings that did not have to be done again, and those that did.
	/// Images served without asking the origin, and stale ones the origin
	/// confirmed with a 304 instead of a download.
	pub origin_cache_hits: Counter,
	pub origin_cache_revalidated: Counter,
	pub origin_cache_misses: Counter,
	pub bytes_saved_by_origin_cache: Counter,
	pub image_cache_hits: Counter,
	pub image_cache_misses: Counter,
	/// Times a worker had to wait for a client to catch up before it could hand
	/// over the next chunk of an h3 response. Zero means the backpressure bound
	/// has never been reached and `stream_buffer_mb` could come down; a number
	/// that climbs with no slow clients about means it is too low.
	pub streams_parked: Counter,
	pub lookups_ipv4_only: Counter,
	pub lookups_ipv6_only: Counter,
	pub lookups_dual: Counter,
	/// Time spent waiting on each plugin, by plugin name.
	///
	/// A locked map rather than the atomics above, because the keys are plugin
	/// names discovered at startup rather than fields known at compile time —
	/// and `BTreeMap` because the status page's rows should not reorder
	/// themselves between two refreshes. The lock costs nothing in context: it
	/// is held for a few nanoseconds either side of a subprocess round trip
	/// that already costs milliseconds.
	plugins: Mutex<BTreeMap<String, PluginTime>>,
}

/// `Instant::now` is why this is written out rather than derived.
impl Default for Metrics {
	fn default() -> Self {
		Self {
			started: Instant::now(),
			requests: Counter::default(),
			blocked: Counter::default(),
			passed_through: Counter::default(),
			internal: Counter::default(),
			injected: Counter::default(),
			bypassed: Counter::default(),
			tls_failures: Counter::default(),
			upstream_failures: Counter::default(),
			bytes_from_origin: Counter::default(),
			bytes_to_client: Counter::default(),
			bytes_saved_by_compression: Counter::default(),
			bytes_saved_by_images: Counter::default(),
			images_stripped: Counter::default(),
			origin_cache_hits: Counter::default(),
			origin_cache_revalidated: Counter::default(),
			origin_cache_misses: Counter::default(),
			bytes_saved_by_origin_cache: Counter::default(),
			image_cache_hits: Counter::default(),
			image_cache_misses: Counter::default(),
			streams_parked: Counter::default(),
			lookups_ipv4_only: Counter::default(),
			lookups_ipv6_only: Counter::default(),
			lookups_dual: Counter::default(),
			plugins: Mutex::new(BTreeMap::new()),
		}
	}
}

impl Metrics {
	pub fn uptime(&self) -> Duration {
		self.started.elapsed()
	}

	/// Record one hook call and what waiting for it cost.
	pub fn record_plugin_call(&self, name: &str, elapsed: Duration) {
		let mut plugins = self.plugins.lock().expect("plugin timing lock");
		let time = plugins.entry(name.to_string()).or_default();

		time.calls += 1;
		time.total += elapsed;
	}

	/// A response this plugin wanted and did not get. Returns how many times it
	/// has now happened, so the caller can say it loudly the first time and
	/// quietly afterwards.
	pub fn record_plugin_skip(&self, name: &str) -> u64 {
		let mut plugins = self.plugins.lock().expect("plugin timing lock");
		let time = plugins.entry(name.to_string()).or_default();
		time.skipped += 1;

		time.skipped
	}

	/// Read every counter once.
	///
	/// The page and the JSON are both rendered from one of these rather than
	/// from the atomics directly, so that a request served halfway through
	/// rendering cannot leave the page saying two different things.
	pub fn snapshot(&self) -> Snapshot {
		Snapshot {
			uptime_seconds: self.uptime().as_secs(),
			requests: self.requests.get(),
			blocked: self.blocked.get(),
			passed_through: self.passed_through.get(),
			internal: self.internal.get(),
			injected: self.injected.get(),
			bypassed: self.bypassed.get(),
			tls_failures: self.tls_failures.get(),
			upstream_failures: self.upstream_failures.get(),
			bytes_from_origin: self.bytes_from_origin.get(),
			bytes_to_client: self.bytes_to_client.get(),
			bytes_saved_by_compression: self.bytes_saved_by_compression.get(),
			bytes_saved_by_images: self.bytes_saved_by_images.get(),
			images_stripped: self.images_stripped.get(),
			origin_cache_hits: self.origin_cache_hits.get(),
			origin_cache_revalidated: self.origin_cache_revalidated.get(),
			origin_cache_misses: self.origin_cache_misses.get(),
			bytes_saved_by_origin_cache: self.bytes_saved_by_origin_cache.get(),
			image_cache_hits: self.image_cache_hits.get(),
			image_cache_misses: self.image_cache_misses.get(),
			streams_parked: self.streams_parked.get(),
			lookups_ipv4_only: self.lookups_ipv4_only.get(),
			lookups_ipv6_only: self.lookups_ipv6_only.get(),
			lookups_dual: self.lookups_dual.get(),
			plugins: self
				.plugins
				.lock()
				.expect("plugin timing lock")
				.iter()
				.map(|(name, time)| (name.clone(), PluginStats::of(time)))
				.collect(),
		}
	}
}

/// What one plugin cost, at one moment.
///
/// Microseconds rather than a [`Duration`], which serialises as a struct of
/// seconds and nanoseconds that nothing wants to graph. The mean is carried
/// rather than left to the reader: it is the number that says whether a plugin
/// is worth its place, and a total only ever grows with traffic.
#[derive(Serialize)]
pub struct PluginStats {
	pub calls: u64,
	pub total_micros: u64,
	pub mean_micros: u64,
	pub skipped: u64,
}

impl PluginStats {
	fn of(time: &PluginTime) -> Self {
		let total_micros = time.total.as_micros() as u64;

		Self {
			calls: time.calls,
			total_micros,
			// A recorded plugin has been called at least once, so the guard is
			// only here to keep a division from depending on that.
			mean_micros: total_micros / time.calls.max(1),
			skipped: time.skipped,
		}
	}
}

/// Every counter at one moment, flat, which is also the shape `stats.json`
/// serves: anything scraping it wants numbers it can graph, not structure.
#[derive(Serialize)]
pub struct Snapshot {
	pub uptime_seconds: u64,
	pub requests: u64,
	pub blocked: u64,
	pub passed_through: u64,
	pub internal: u64,
	pub injected: u64,
	pub bypassed: u64,
	pub tls_failures: u64,
	pub upstream_failures: u64,
	pub bytes_from_origin: u64,
	pub bytes_to_client: u64,
	pub bytes_saved_by_compression: u64,
	pub bytes_saved_by_images: u64,
	pub images_stripped: u64,
	pub origin_cache_hits: u64,
	pub origin_cache_revalidated: u64,
	pub origin_cache_misses: u64,
	pub bytes_saved_by_origin_cache: u64,
	pub image_cache_hits: u64,
	pub image_cache_misses: u64,
	/// Times a worker had to wait for a client before it could hand over the
	/// next chunk. See [`Metrics::streams_parked`].
	pub streams_parked: u64,
	pub lookups_ipv4_only: u64,
	pub lookups_ipv6_only: u64,
	pub lookups_dual: u64,
	/// Keyed by plugin name — the one part of the JSON that is not flat,
	/// because the set of plugins is not known until they are loaded.
	pub plugins: BTreeMap<String, PluginStats>,
}

/// One set per process, exactly as [`crate::blocklist::shared`] does it. Both
/// front ends and every chain count into the same numbers.
pub fn shared() -> Arc<Metrics> {
	static SHARED: OnceLock<Arc<Metrics>> = OnceLock::new();

	SHARED.get_or_init(|| Arc::new(Metrics::default())).clone()
}

/// A count with thousands separated, because the difference between 10000 and
/// 100000 is not something anyone should have to count digits to see.
pub fn thousands(n: u64) -> String {
	let digits = n.to_string();
	let mut out = String::with_capacity(digits.len() + digits.len() / 3);

	for (i, digit) in digits.char_indices() {
		if i > 0 && (digits.len() - i).is_multiple_of(3) {
			out.push(',');
		}

		out.push(digit);
	}

	out
}

/// A byte count in the largest unit that leaves a number below 1024. Powers of
/// two, since these are buffer sizes rather than disk-vendor megabytes.
pub fn bytes(n: u64) -> String {
	for (unit, suffix) in [(GB, "GB"), (MB, "MB"), (KB, "KB")] {
		if n >= unit {
			return format!("{:.1} {suffix}", n as f64 / unit as f64);
		}
	}

	format!("{} B", thousands(n))
}

/// How long a plugin took, in the unit that leaves a number worth reading:
/// microseconds below a millisecond, milliseconds above. One decimal place,
/// since the difference between 0.4ms and 0.9ms per call is the whole point.
pub fn duration(elapsed: Duration) -> String {
	let micros = elapsed.as_micros() as f64;

	if micros < 1000.0 {
		format!("{micros:.1} µs")
	} else {
		format!("{:.1} ms", micros / 1000.0)
	}
}

/// How long the process has been up, largest unit first.
///
/// Zero units are dropped only from the front: "1d 0h 5m" has to keep its
/// hours, or it reads as five minutes of uptime rather than a day of it.
pub fn uptime(elapsed: Duration) -> String {
	let seconds = elapsed.as_secs();
	let mut out = String::new();

	for (value, unit) in [
		(seconds / 86_400, "d"),
		(seconds / 3_600 % 24, "h"),
		(seconds / 60 % 60, "m"),
		(seconds % 60, "s"),
	] {
		if value == 0 && out.is_empty() && unit != "s" {
			continue;
		}

		if !out.is_empty() {
			out.push(' ');
		}

		out.push_str(&format!("{value}{unit}"));
	}

	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_counter_starts_at_zero_and_only_goes_up() {
		let metrics = Metrics::default();

		assert_eq!(metrics.requests.get(), 0);

		metrics.requests.increment();
		metrics.requests.increment();
		metrics.bytes_to_client.add(4096);

		assert_eq!(metrics.requests.get(), 2);
		assert_eq!(metrics.bytes_to_client.get(), 4096);
		assert_eq!(metrics.blocked.get(), 0, "counters are independent");
	}

	#[test]
	fn a_snapshot_reports_every_counter() {
		let metrics = Metrics::default();

		metrics.requests.add(7);
		metrics.blocked.add(6);
		metrics.internal.add(5);
		metrics.injected.add(4);
		metrics.bypassed.add(3);
		metrics.tls_failures.add(2);
		metrics.upstream_failures.add(1);
		metrics.bytes_from_origin.add(1000);
		metrics.bytes_to_client.add(1200);
		metrics.bytes_saved_by_compression.add(800);

		let json = serde_json::to_value(metrics.snapshot()).unwrap();

		assert_eq!(json["requests"], 7);
		assert_eq!(json["blocked"], 6);
		assert_eq!(json["internal"], 5);
		assert_eq!(json["injected"], 4);
		assert_eq!(json["bypassed"], 3);
		assert_eq!(json["tls_failures"], 2);
		assert_eq!(json["upstream_failures"], 1);
		assert_eq!(json["bytes_from_origin"], 1000);
		assert_eq!(json["bytes_to_client"], 1200);
		assert_eq!(json["bytes_saved_by_compression"], 800);
		assert!(json["uptime_seconds"].is_u64());
		assert!(json["plugins"].is_object(), "no plugins is an empty object");
	}

	#[test]
	fn saved_bytes_are_the_difference_compression_made() {
		let metrics = Metrics::default();
		let plain = 4096u64;
		let compressed = 1024u64;

		metrics.bytes_to_client.add(compressed);
		metrics.bytes_saved_by_compression.add(plain - compressed);

		assert_eq!(metrics.bytes_saved_by_compression.get(), 3072);
		assert_eq!(
			metrics.bytes_to_client.get() + metrics.bytes_saved_by_compression.get(),
			plain,
			"the two together are what the origin gave us"
		);
		assert_eq!(bytes(metrics.bytes_saved_by_compression.get()), "3.0 KB");
	}

	#[test]
	fn every_worker_counts_into_the_same_numbers() {
		let metrics = shared();
		let before = metrics.requests.get();

		metrics.requests.increment();

		assert_eq!(
			shared().requests.get(),
			before + 1,
			"a second handle is the same counters"
		);
	}

	#[test]
	fn bytes_are_shown_in_the_largest_unit_that_fits() {
		assert_eq!(bytes(0), "0 B");
		assert_eq!(bytes(999), "999 B");
		assert_eq!(bytes(1023), "1,023 B");
		assert_eq!(bytes(1024), "1.0 KB");
		assert_eq!(bytes(1024 * 1024), "1.0 MB");
		assert_eq!(bytes(1024 * 1024 * 1024), "1.0 GB");
		assert_eq!(bytes(1536), "1.5 KB");
	}

	#[test]
	fn counts_are_grouped_in_threes() {
		assert_eq!(thousands(0), "0");
		assert_eq!(thousands(999), "999");
		assert_eq!(thousands(1000), "1,000");
		assert_eq!(thousands(1234567), "1,234,567");
	}

	#[test]
	fn a_plugin_s_calls_are_summed_and_averaged() {
		let metrics = Metrics::default();

		metrics.record_plugin_call("slow.py", Duration::from_millis(30));
		metrics.record_plugin_call("slow.py", Duration::from_millis(10));

		let snapshot = metrics.snapshot();
		let slow = &snapshot.plugins["slow.py"];

		assert_eq!(slow.calls, 2);
		assert_eq!(slow.total_micros, 40_000);
		assert_eq!(slow.mean_micros, 20_000, "the mean is per call, not per hook");
	}

	#[test]
	fn plugins_are_kept_apart_and_come_back_in_name_order() {
		let metrics = Metrics::default();

		metrics.record_plugin_call("zebra.py", Duration::from_millis(5));
		metrics.record_plugin_call("alpha.sh", Duration::from_millis(1));

		let snapshot = metrics.snapshot();
		let names: Vec<&str> = snapshot.plugins.keys().map(String::as_str).collect();

		assert_eq!(names, ["alpha.sh", "zebra.py"], "stable rows on the page");
		assert_eq!(snapshot.plugins["alpha.sh"].total_micros, 1_000);
		assert_eq!(snapshot.plugins["zebra.py"].total_micros, 5_000);
	}

	#[test]
	fn plugin_times_are_shown_in_the_unit_that_fits() {
		assert_eq!(duration(Duration::ZERO), "0.0 µs");
		assert_eq!(duration(Duration::from_micros(250)), "250.0 µs");
		assert_eq!(duration(Duration::from_micros(999)), "999.0 µs");
		assert_eq!(duration(Duration::from_millis(1)), "1.0 ms");
		assert_eq!(duration(Duration::from_micros(40_500)), "40.5 ms");
	}

	#[test]
	fn uptime_keeps_the_units_that_change_its_meaning() {
		assert_eq!(uptime(Duration::ZERO), "0s");
		assert_eq!(uptime(Duration::from_secs(59)), "59s");
		assert_eq!(uptime(Duration::from_secs(61)), "1m 1s");
		assert_eq!(uptime(Duration::from_secs(3661)), "1h 1m 1s");
		assert_eq!(
			uptime(Duration::from_secs(86_400 + 300)),
			"1d 0h 5m 0s",
			"a zero in the middle is not noise"
		);
	}
}
