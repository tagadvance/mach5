//! On-the-fly certificate authority.
//!
//! Mints a leaf certificate per SNI hostname, signed by a root CA, and installs
//! it on the live TLS handshake. The root CA is either loaded from disk (the
//! real one, whose private key you keep off-repo) or generated ephemerally for
//! local development so the skeleton runs self-contained.

use std::collections::HashMap;
use std::error::Error;
use std::path::Path;
use std::sync::Mutex;
use std::time::Instant;

use boring::pkey::{PKey, Private};
use boring::x509::X509;
use rcgen::{
	BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
	KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};

use crate::config::Config;

/// A minted leaf, in the boring types the TLS stack consumes.
#[derive(Clone)]
struct Leaf {
	cert: X509,
	key: PKey<Private>,
	not_after: OffsetDateTime,
}

/// How many minted leaves to keep.
///
/// It has to be bounded, and the bound has to be small enough to matter. mach5
/// is deployed behind a resolver that answers every name with its own address,
/// so a page can ask for `a1.attacker.test`, `a2.attacker.test` and onwards for
/// as long as it likes — and each one used to cost a keypair, a signature and a
/// permanent entry holding both. A thousand is far more distinct hosts than a
/// browsing session touches, and the cost of being wrong is one re-mint.
const MAX_LEAVES: usize = 1_024;

/// A cached leaf and when it was last handed out, which is what decides who
/// goes when the cache is full.
struct Held {
	leaf: Leaf,
	used: Instant,
}

/// How long minted leaves stay valid, and when to re-mint them.
struct Validity {
	ttl: Duration,
	clock_skew: Duration,
	refresh_margin: Duration,
}

pub struct CertAuthority {
	issuer: Issuer<'static, KeyPair>,
	/// The root's own certificate, DER-encoded. Kept from construction because
	/// every device that has to trust this proxy needs a copy, and the encoding
	/// never changes for the life of the process.
	root: Vec<u8>,
	/// Whether the root was generated at startup rather than loaded from disk.
	ephemeral: bool,
	cache: Mutex<HashMap<String, Held>>,
	validity: Validity,
}

impl CertAuthority {
	/// Read one of the `[ca]` files, saying what is actually wrong with it.
	///
	/// Both mistakes here are ones a person makes once and then spends an hour
	/// on, because the underlying errors describe bytes rather than intent:
	/// pointing at a DER file surfaces as "invalid UTF-8", and pointing at the
	/// wrong PEM surfaces much later as a parse failure.
	fn read_pem(path: &Path, what: &str) -> Result<String, Box<dyn Error>> {
		// Name the file: "No such file or directory" with no path is a
		// miserable thing to debug inside a container.
		let bytes = std::fs::read(path)
			.map_err(|e| format!("cannot read [ca] {what} {}: {e}", path.display()))?;

		// A DER file starts with the SEQUENCE tag; PEM starts with '-'.
		if bytes.first() == Some(&0x30) {
			return Err(format!(
				"[ca] {what} {} is DER, and PEM is what is wanted. Convert it: \
				 openssl x509 -inform DER -in {0} -out {0}.pem",
				path.display()
			)
			.into());
		}

		let text = String::from_utf8(bytes)
			.map_err(|_| format!("[ca] {what} {} is not text, so not PEM", path.display()))?;

		// openssl writes a "Bag Attributes" preamble ahead of the PEM block when
		// it exports from a keystore, and rcgen refuses the file outright rather
		// than skipping to the block. Anyone converting a p12 hits this, so take
		// the PEM from wherever it starts.
		let Some(start) = text.find("-----BEGIN") else {
			return Err(format!("[ca] {what} {} contains no PEM block", path.display()).into());
		};

		Ok(text[start..].to_string())
	}

	/// Load the CA named by the configuration, or generate an ephemeral one
	/// when no CA is configured.
	pub fn from_config(config: &Config) -> Result<Self, Box<dyn Error>> {
		match (&config.ca.cert, &config.ca.key) {
			(Some(cert_path), Some(key_path)) => {
				let cert_pem = Self::read_pem(cert_path, "cert")?;
				let key_pem = Self::read_pem(key_path, "key")?;

				if !key_pem.contains("PRIVATE KEY") {
					return Err(format!(
						"[ca] key {} holds no private key{}",
						key_path.display(),
						if key_pem.contains("BEGIN CERTIFICATE") {
							" — it is a certificate. The key is a separate file; \
							 security/init.sh writes both."
						} else {
							""
						}
					)
					.into());
				}

				log::info!("loaded root CA from {}", cert_path.display());

				Self::from_pem(&cert_pem, &key_pem, config)
			}
			_ => {
				log::warn!(
					"no [ca] cert/key configured — generating an ephemeral dev CA. \
					 Minted certs will NOT be trusted by any browser."
				);

				Self::generate_dev(config)
			}
		}
	}

	/// Load a CA from PEM cert + PEM private key.
	pub fn from_pem(cert_pem: &str, key_pem: &str, config: &Config) -> Result<Self, Box<dyn Error>> {
		// rcgen says only "CouldNotParseKeyPair", and by far the likeliest cause
		// is a PKCS#8 EC key with no public-key point in it — which is exactly
		// what `keytool` exports and what `openssl pkey` preserves. security/
		// init.sh round-trips through SEC1 to put the point back.
		let key = KeyPair::from_pem(key_pem).map_err(|e| {
			format!(
				"[ca] key could not be parsed ({e}). If it came out of a Java \
				 keystore, re-export it with security/init.sh: an EC key with no \
				 public-key point in it is rejected."
			)
		})?;
		// Through boring rather than rcgen: this is the same PEM the issuer is
		// built from, and boring is already here to hand it back as DER.
		let root = X509::from_pem(cert_pem.as_bytes())?.to_der()?;
		let issuer = Issuer::from_ca_cert_pem(cert_pem, key)?;

		Ok(Self::new(issuer, root, false, config))
	}

	/// Generate a throwaway self-signed CA. Development only: nothing signed by
	/// it is trusted by any browser, and the key lives only in memory.
	pub fn generate_dev(config: &Config) -> Result<Self, Box<dyn Error>> {
		let key = KeyPair::generate()?;

		let mut params = CertificateParams::default();
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
		let mut dn = DistinguishedName::new();
		dn.push(DnType::CommonName, "mach5 dev CA");
		params.distinguished_name = dn;

		// Self-signed first, because an issuer alone is a signing identity with
		// no certificate to hand anyone: nothing could be installed to trust it.
		let root = params.self_signed(&key)?.der().to_vec();
		let issuer = Issuer::new(params, key);

		Ok(Self::new(issuer, root, true, config))
	}

	fn new(
		issuer: Issuer<'static, KeyPair>,
		root: Vec<u8>,
		ephemeral: bool,
		config: &Config,
	) -> Self {
		Self {
			issuer,
			root,
			ephemeral,
			cache: Mutex::new(HashMap::new()),
			validity: Validity {
				ttl: config.leaf_ttl(),
				clock_skew: config.clock_skew(),
				refresh_margin: config.refresh_margin(),
			},
		}
	}

	/// The root's certificate, DER-encoded.
	///
	/// This is the public certificate and only ever that. The private key stays
	/// inside `issuer`, where nothing in the endpoint layer can reach it, and
	/// must never be given a way out of this type. Handing the certificate to
	/// whoever asks is not a leak: it is a public certificate whose entire
	/// purpose is to be installed on the devices that have to trust what this
	/// proxy mints.
	pub fn root_certificate(&self) -> &[u8] {
		&self.root
	}

	/// Whether the root was generated at startup instead of loaded from disk.
	/// Worth saying out loud before somebody installs it: the next restart mints
	/// a different root, and every device that trusted this one stops working.
	pub fn is_ephemeral(&self) -> bool {
		self.ephemeral
	}

	/// Return a leaf for `sni`, minting and caching on first request and
	/// re-minting once a cached leaf nears expiry.
	fn leaf_for(&self, sni: &str) -> Result<Leaf, Box<dyn Error>> {
		// A name is a name whatever it was capitalised as, and the same one
		// twice should not cost two keypairs.
		let key = sni.trim_end_matches('.').to_ascii_lowercase();

		if let Some(leaf) = self.cached(&key) {
			return Ok(leaf);
		}

		// Minted with the lock *not* held. A keygen, a signature and two PEM
		// round trips take long enough that holding it would put every other
		// handshake on the process behind this one — and one of the threads
		// waiting is the QUIC event loop, which is every connection at once.
		// Two callers racing on one name mint twice and one of them throws its
		// leaf away, which is far cheaper than the alternative.
		// Minted from the *normalised* name, not the raw SNI. They used to
		// disagree: a client sending `example.com.` had the cache keyed on
		// `example.com` but the leaf's only SAN written as `example.com.`,
		// which no client accepts — and it was then served for the whole TTL.
		let leaf = self.mint(&key)?;
		self.remember(key, leaf.clone());

		Ok(leaf)
	}

	fn cached(&self, key: &str) -> Option<Leaf> {
		let mut cache = self.cache.lock().unwrap();
		let leaf = cache.get_mut(key)?;

		if leaf.leaf.not_after - self.validity.refresh_margin <= OffsetDateTime::now_utc() {
			return None;
		}

		leaf.used = Instant::now();

		Some(leaf.leaf.clone())
	}

	fn remember(&self, key: String, leaf: Leaf) {
		let mut cache = self.cache.lock().unwrap();

		if cache.len() >= MAX_LEAVES && !cache.contains_key(&key) {
			// Expired first, since nothing wants those. An O(n) scan over a
			// thousand entries is nothing beside the keygen that got us here.
			let now = OffsetDateTime::now_utc();
			cache.retain(|_, held| held.leaf.not_after > now);

			while cache.len() >= MAX_LEAVES {
				let Some(oldest) = cache
					.iter()
					.min_by_key(|(_, held)| held.used)
					.map(|(name, _)| name.clone())
				else {
					break;
				};
				cache.remove(&oldest);
			}
		}

		cache.insert(
			key,
			Held {
				leaf,
				used: Instant::now(),
			},
		);
	}

	fn mint(&self, sni: &str) -> Result<Leaf, Box<dyn Error>> {
		let key = KeyPair::generate()?;

		let mut params = CertificateParams::new(vec![sni.to_string()])?;
		let mut dn = DistinguishedName::new();
		dn.push(DnType::CommonName, sni);
		params.distinguished_name = dn;

		let now = OffsetDateTime::now_utc();
		let not_after = now + self.validity.ttl;
		params.not_before = now - self.validity.clock_skew;
		params.not_after = not_after;

		let cert = params.signed_by(&key, &self.issuer)?;

		let x509 = X509::from_pem(cert.pem().as_bytes())?;
		let pkey = PKey::private_key_from_pem(key.serialize_pem().as_bytes())?;

		Ok(Leaf {
			cert: x509,
			key: pkey,
			not_after,
		})
	}

	/// Install the leaf for `sni` onto a live connection. Returns false when the
	/// client sent no SNI (nothing to key on) or minting failed; the caller then
	/// falls back to the context's default certificate.
	pub fn install(&self, ssl: &mut boring::ssl::SslRef, sni: &str) -> bool {
		match self.leaf_for(sni) {
			Ok(leaf) => {
				ssl.set_certificate(&leaf.cert).is_ok() && ssl.set_private_key(&leaf.key).is_ok()
			}
			Err(e) => {
				log::warn!("failed to mint cert for {sni}: {e}");

				false
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The two ways of pointing `[ca]` at the wrong file, both of which used to
	/// surface as something about bytes rather than about the mistake.
	#[test]
	fn a_der_file_is_named_as_der() {
		let dir = std::env::temp_dir().join("mach5-ca-der-test");
		std::fs::create_dir_all(&dir).unwrap();
		let path = dir.join("root.crt");
		std::fs::write(&path, [0x30u8, 0x82, 0x01, 0x02]).unwrap();

		let err = CertAuthority::read_pem(&path, "cert").unwrap_err().to_string();

		assert!(err.contains("is DER"), "{err}");
		assert!(err.contains("openssl x509 -inform DER"), "it must say how to fix it: {err}");
	}

	#[test]
	fn a_bag_attributes_preamble_is_skipped() {
		let dir = std::env::temp_dir().join("mach5-ca-preamble-test");
		std::fs::create_dir_all(&dir).unwrap();
		let path = dir.join("root.pem");
		std::fs::write(
			&path,
			"Bag Attributes\n    friendlyName: mach5_root\n-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
		)
		.unwrap();

		let pem = CertAuthority::read_pem(&path, "key").unwrap();

		assert!(
			pem.starts_with("-----BEGIN PRIVATE KEY-----"),
			"openssl writes this preamble when exporting from a keystore: {pem}"
		);
	}

	#[test]
	fn a_file_with_no_pem_block_is_rejected() {
		let dir = std::env::temp_dir().join("mach5-ca-nopem-test");
		std::fs::create_dir_all(&dir).unwrap();
		let path = dir.join("notes.txt");
		std::fs::write(&path, "just some words\n").unwrap();

		assert!(CertAuthority::read_pem(&path, "key").is_err());
	}

	#[test]
	fn mints_leaf_with_sni_in_san() {
		let ca = CertAuthority::generate_dev(&Config::default()).unwrap();
		let leaf = ca.mint("example.com").unwrap();

		let san = leaf
			.cert
			.subject_alt_names()
			.expect("leaf should carry a SAN");
		let has_host = san
			.iter()
			.filter_map(|n| n.dnsname())
			.any(|n| n == "example.com");

		assert!(has_host, "SAN should contain the requested SNI host");
	}

	#[test]
	fn leaf_validity_is_bounded() {
		let ca = CertAuthority::generate_dev(&Config::default()).unwrap();
		let leaf = ca.mint("example.com").unwrap();

		let config = Config::default();
		let now = OffsetDateTime::now_utc();
		let expected = now + config.leaf_ttl();

		assert!(leaf.not_after > now, "leaf must be valid now");
		assert!(
			(leaf.not_after - expected).abs() < Duration::minutes(1),
			"leaf should expire at the configured TTL, not rcgen's default"
		);
	}

	#[test]
	fn validity_follows_configuration() {
		let config = Config::from_str("[tls]\nleaf_ttl_hours = 2\n").unwrap();
		let ca = CertAuthority::generate_dev(&config).unwrap();
		let leaf = ca.mint("example.com").unwrap();

		let expected = OffsetDateTime::now_utc() + Duration::hours(2);

		assert!(
			(leaf.not_after - expected).abs() < Duration::minutes(1),
			"configured TTL should override the default"
		);
	}

	/// The certificate the proxy hands out has to be the one that actually
	/// signed what it mints, or installing it changes nothing.
	#[test]
	fn the_root_certificate_signs_the_leaves() {
		let ca = CertAuthority::generate_dev(&Config::default()).unwrap();
		let root = X509::from_der(ca.root_certificate()).unwrap();
		let leaf = ca.mint("example.com").unwrap();

		assert!(leaf.cert.verify(&root.public_key().unwrap()).unwrap());
		assert!(ca.is_ephemeral(), "generated, so nothing should trust it long");
	}

	#[test]
	fn a_loaded_root_is_served_as_loaded() {
		let key = KeyPair::generate().unwrap();
		let mut params = CertificateParams::default();
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		let root = params.self_signed(&key).unwrap();

		let ca =
			CertAuthority::from_pem(&root.pem(), &key.serialize_pem(), &Config::default()).unwrap();

		assert_eq!(ca.root_certificate(), root.der().as_ref());
		assert!(!ca.is_ephemeral(), "loaded from disk, so it survives a restart");
	}

	#[test]
	fn caches_repeated_sni() {
		let ca = CertAuthority::generate_dev(&Config::default()).unwrap();
		let first = ca.leaf_for("example.com").unwrap();
		let second = ca.leaf_for("example.com").unwrap();

		// Same cached leaf, so the DER encodings match; a re-mint would differ
		// because each carries a freshly generated key.
		assert_eq!(
			first.cert.to_der().unwrap(),
			second.cert.to_der().unwrap()
		);

		// And a name is a name however it was capitalised, or the same host
		// costs two keypairs and two permanent entries.
		let shouted = ca.leaf_for("EXAMPLE.COM.").unwrap();
		assert_eq!(first.cert.to_der().unwrap(), shouted.cert.to_der().unwrap());
		assert_eq!(ca.cache.lock().unwrap().len(), 1);
	}

	/// The order matters, and hid a defect: minting `example.com` first made
	/// the odd spelling a pure cache hit, so the raw name never reached `mint`.
	/// Asked the other way round, the leaf's only SAN was written verbatim —
	/// trailing dot and all — and no client accepts that, for the whole TTL.
	#[test]
	fn a_leaf_carries_the_name_a_client_will_check() {
		let ca = CertAuthority::generate_dev(&Config::default()).unwrap();
		let leaf = ca.leaf_for("EXAMPLE.COM.").unwrap();

		let names: Vec<String> = leaf
			.cert
			.subject_alt_names()
			.expect("a leaf has a SAN")
			.iter()
			.filter_map(|name| name.dnsname().map(str::to_string))
			.collect();

		assert_eq!(names, ["example.com"], "the name as a client will send it");
	}

	/// mach5 sits behind a resolver that answers every name with its own
	/// address, so a page can ask for a new hostname as fast as it can write
	/// one down — and each used to cost a keypair, a signature and a permanent
	/// entry holding both, with nothing ever removing one.
	#[test]
	fn the_leaf_cache_cannot_grow_without_end() {
		let ca = CertAuthority::generate_dev(&Config::default()).unwrap();

		// The one to keep: minted first, and used again at the end.
		ca.leaf_for("wanted.example").unwrap();

		for n in 0..MAX_LEAVES + 32 {
			ca.leaf_for(&format!("n{n}.attacker.test")).unwrap();
			// Touched so it is never the least recently used.
			ca.leaf_for("wanted.example").unwrap();
		}

		let held = ca.cache.lock().unwrap();
		assert!(
			held.len() <= MAX_LEAVES,
			"{} leaves held against a cap of {MAX_LEAVES}",
			held.len()
		);
		assert!(
			held.contains_key("wanted.example"),
			"the name still in use is not the one to throw away"
		);
	}
}
