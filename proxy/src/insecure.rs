//! Where certificate verification is switched off — and the only place it is.
//!
//! Once a device trusts mach5's certificate authority, mach5 is the only thing
//! still checking that an origin is who it says it is. Everything in this file
//! exists to take that check away, so it is deliberately confined:
//!
//! - The permissive agent is only ever handed a request whose exact host is in
//!   [`Bypasses`], and a host only gets in there when somebody typed the phrase
//!   on the warning page for it.
//! - A bypass expires, and the registry is in memory only, so restarting the
//!   proxy forgets every one of them. That is a feature: the failure mode of a
//!   forgotten bypass is silent, so it must not be able to outlive the process.
//! - Every request that takes this path is logged as a warning, by
//!   [`crate::upstream::call`], every single time.
//!
//! Nothing else may use [`Unverified`]. If you are looking for the reason a
//! certificate was not checked, it is here or it did not happen.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use boring::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
use ureq::{ReadWrite, TlsConnector};

/// How long an offered token stays redeemable. Long enough to read a warning
/// page and decide, short enough that one left open in a background tab is not
/// a standing invitation.
const OFFER_TTL: Duration = Duration::from_secs(600);

/// The hosts currently waved through, and the moment each stops being — plus
/// the tokens offered to hosts whose warning page is currently on screen.
///
/// The tokens are what stop `/.mach5/bypass` being a URL any page can point an
/// `<img>` at. They are minted here rather than anywhere else because this is
/// the only place that knows what a bypass is, and because a token is only
/// meaningful next to the registry it unlocks.
pub struct Bypasses {
	hosts: Mutex<HashMap<String, Instant>>,
	offered: Mutex<HashMap<String, (String, Instant)>>,
}

impl Default for Bypasses {
	fn default() -> Self {
		Self {
			hosts: Mutex::new(HashMap::new()),
			offered: Mutex::new(HashMap::new()),
		}
	}
}

impl Bypasses {
	/// Wave this host through for `ttl`.
	pub fn allow(&self, host: &str, ttl: Duration) {
		let expiry = Instant::now() + ttl;
		self.lock().insert(key(host), expiry);
	}

	/// Whether this host is currently waved through, dropping anything that has
	/// expired on the way past.
	///
	/// The host must match exactly. Everywhere else in mach5 a parent domain
	/// covers its subdomains — that is right for a blocklist, where being too
	/// broad costs you an advert, and wrong here, where it would silently take
	/// the check off hosts nobody looked at.
	pub fn allows(&self, host: &str) -> bool {
		let now = Instant::now();
		let mut hosts = self.lock();
		hosts.retain(|_, expiry| *expiry > now);

		hosts.contains_key(&key(host))
	}

	/// Mint a token for this host and put it on the warning page.
	///
	/// One per page: a second warning for the same host replaces the first,
	/// which is what you want when the earlier tab has been abandoned.
	pub fn offer(&self, host: &str) -> String {
		let token = token();
		let now = Instant::now();

		let mut offered = self.offered.lock().expect("bypass offers lock");
		// Pruned here as well as in `redeem`, because an offer nobody takes up
		// is the *common* case: every failed validation mints one, and if the
		// phrase is never typed then `redeem` never runs and nothing was ever
		// dropped, `OFFER_TTL` or no. A page fetching a few hundred thousand
		// subdomains of a host with a bad certificate grew this without end.
		offered.retain(|_, (_, expiry)| *expiry > now);
		offered.insert(key(host), (token.clone(), now + OFFER_TTL));

		token
	}

	/// Spend a token: wave the host through if it matches, and never twice.
	///
	/// Consuming it is the point. Without that, a token read out of one page
	/// keeps working, and the thing being protected against is precisely a
	/// request that arrives without anyone having seen a warning.
	pub fn redeem(&self, host: &str, token: &str, ttl: Duration) -> bool {
		let host = key(host);
		let now = Instant::now();

		let mut offered = self.offered.lock().expect("bypass offers lock");
		offered.retain(|_, (_, expiry)| *expiry > now);

		let Some((expected, _)) = offered.get(&host) else {
			return false;
		};
		if !same(expected.as_bytes(), token.as_bytes()) {
			return false;
		}

		offered.remove(&host);
		drop(offered);

		self.allow(&host, ttl);

		true
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Instant>> {
		self.hosts.lock().expect("bypass registry lock")
	}
}

/// 256 bits from the CSPRNG BoringSSL is already here for, as hex.
///
/// An empty string on failure rather than a panic, and `redeem` refuses one:
/// a proxy that cannot reach its random source should stop offering bypasses,
/// not stop.
fn token() -> String {
	let mut bytes = [0u8; 32];
	if boring::rand::rand_bytes(&mut bytes).is_err() {
		log::error!("no random bytes for a bypass token; the warning page cannot be dismissed");

		return String::new();
	}

	bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Constant time, and never true for an empty expectation.
fn same(expected: &[u8], given: &[u8]) -> bool {
	if expected.is_empty() || expected.len() != given.len() {
		return false;
	}

	expected
		.iter()
		.zip(given)
		.fold(0u8, |differences, (a, b)| differences | (a ^ b))
		== 0
}

fn key(host: &str) -> String {
	host.trim_end_matches('.').to_ascii_lowercase()
}

/// The one registry, shared by every worker: a bypass recorded by whichever
/// chain served the warning page has to apply to the fetch that follows it,
/// which will be on another thread entirely.
pub fn bypasses() -> Arc<Bypasses> {
	static SHARED: OnceLock<Arc<Bypasses>> = OnceLock::new();

	SHARED.get_or_init(|| Arc::new(Bypasses::default())).clone()
}

/// A TLS client that accepts any certificate at all — expired, self-signed,
/// issued to another name, or issued by nobody.
///
/// BoringSSL rather than a second rustls configuration because quiche already
/// links it: one TLS stack in the binary, and no `dangerous_configuration` in
/// the dependency tree for somebody to reach for later.
pub struct Unverified {
	connector: SslConnector,
}

impl Unverified {
	pub fn new() -> Result<Self, boring::error::ErrorStack> {
		let mut builder = SslConnector::builder(SslMethod::tls())?;
		builder.set_verify(SslVerifyMode::NONE);

		Ok(Self {
			connector: builder.build(),
		})
	}
}

impl TlsConnector for Unverified {
	fn connect(
		&self,
		dns_name: &str,
		io: Box<dyn ReadWrite>,
	) -> Result<Box<dyn ReadWrite>, ureq::Error> {
		let config = self
			.connector
			.configure()
			.map_err(|e| std::io::Error::other(format!("tls setup failed: {e}")))?
			// The name check is separate from the chain check, and both have to
			// go: connecting to a staging box by IP fails on the name alone.
			.verify_hostname(false);

		let stream = config
			.connect(dns_name, io)
			.map_err(|e| std::io::Error::other(format!("tls handshake failed: {e}")))?;

		Ok(Box::new(Unchecked(stream)))
	}
}

/// The handshaken stream, wearing the trait ureq hands its body reads and
/// writes through.
#[derive(Debug)]
struct Unchecked(SslStream<Box<dyn ReadWrite>>);

impl Read for Unchecked {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		self.0.read(buf)
	}
}

impl Write for Unchecked {
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		self.0.write(buf)
	}

	fn flush(&mut self) -> std::io::Result<()> {
		self.0.flush()
	}
}

impl ReadWrite for Unchecked {
	/// ureq wants the socket underneath to set its own timeouts on it, so the
	/// question has to travel through the TLS layer to whatever it wrapped.
	fn socket(&self) -> Option<&TcpStream> {
		self.0.get_ref().socket()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const TTL: Duration = Duration::from_secs(60);

	/// An offer nobody takes up is the common case — every failed validation
	/// mints one — and `redeem` is the only thing that used to prune them, so
	/// nothing was dropped until somebody typed the phrase. A page fetching
	/// subdomains of a host with a bad certificate grew the map for free.
	#[test]
	fn offers_nobody_redeems_do_not_pile_up() {
		let bypasses = Bypasses::default();

		for n in 0..500 {
			bypasses.offer(&format!("n{n}.bad.example"));
		}
		assert_eq!(
			bypasses.offered.lock().unwrap().len(),
			500,
			"none of these has expired yet, so all of them are still live"
		);

		// Wind every one of them into the past, then offer once more.
		for (_, expiry) in bypasses.offered.lock().unwrap().values_mut() {
			*expiry = Instant::now() - Duration::from_secs(1);
		}
		bypasses.offer("one.more.example");

		let offered = bypasses.offered.lock().unwrap();
		assert_eq!(offered.len(), 1, "the expired ones go when the next is made");
		assert!(offered.contains_key("one.more.example"));
	}

	#[test]
	fn a_bypass_applies_to_the_host_it_was_given() {
		let bypasses = Bypasses::default();
		bypasses.allow("staging.example.com", TTL);

		assert!(bypasses.allows("staging.example.com"));
		assert!(bypasses.allows("STAGING.example.com"), "host case is not data");
		assert!(bypasses.allows("staging.example.com."), "nor is a root dot");
	}

	#[test]
	fn a_bypass_covers_neither_a_parent_nor_a_child() {
		let bypasses = Bypasses::default();
		bypasses.allow("staging.example.com", TTL);

		assert!(
			!bypasses.allows("api.staging.example.com"),
			"a subdomain was never looked at by whoever bypassed the parent"
		);
		assert!(!bypasses.allows("example.com"));
	}

	#[test]
	fn an_unknown_host_is_never_allowed() {
		let bypasses = Bypasses::default();

		assert!(!bypasses.allows("example.com"));

		bypasses.allow("other.example.com", TTL);

		assert!(!bypasses.allows("example.com"));
	}

	#[test]
	fn a_bypass_stops_applying_once_it_expires() {
		let bypasses = Bypasses::default();
		// Expiring immediately rather than sleeping out a real TTL.
		bypasses.allow("staging.example.com", Duration::ZERO);

		assert!(!bypasses.allows("staging.example.com"));
		assert!(
			bypasses.lock().is_empty(),
			"an expired bypass is dropped, not merely ignored"
		);
	}
}
