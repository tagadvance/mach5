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

/// The hosts currently waved through, and the moment each stops being.
pub struct Bypasses {
	hosts: Mutex<HashMap<String, Instant>>,
}

impl Default for Bypasses {
	fn default() -> Self {
		Self {
			hosts: Mutex::new(HashMap::new()),
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

	fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Instant>> {
		self.hosts.lock().expect("bypass registry lock")
	}
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
