//! On-the-fly certificate authority.
//!
//! Mints a leaf certificate per SNI hostname, signed by a root CA, and installs
//! it on the live TLS handshake. The root CA is either loaded from disk (the
//! real one, whose private key you keep off-repo) or generated ephemerally for
//! local development so the skeleton runs self-contained.

use std::collections::HashMap;
use std::error::Error;
use std::sync::Mutex;

use boring::pkey::{PKey, Private};
use boring::x509::X509;
use rcgen::{
	BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
	KeyUsagePurpose,
};

/// A minted leaf, in the boring types the TLS stack consumes.
#[derive(Clone)]
struct Leaf {
	cert: X509,
	key: PKey<Private>,
}

pub struct CertAuthority {
	issuer: Issuer<'static, KeyPair>,
	cache: Mutex<HashMap<String, Leaf>>,
}

impl CertAuthority {
	/// Load a CA from PEM cert + PEM private key.
	pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Self, Box<dyn Error>> {
		let key = KeyPair::from_pem(key_pem)?;
		let issuer = Issuer::from_ca_cert_pem(cert_pem, key)?;

		Ok(Self {
			issuer,
			cache: Mutex::new(HashMap::new()),
		})
	}

	/// Generate a throwaway self-signed CA. Development only: nothing signed by
	/// it is trusted by any browser, and the key lives only in memory.
	pub fn generate_dev() -> Result<Self, Box<dyn Error>> {
		let key = KeyPair::generate()?;

		let mut params = CertificateParams::default();
		params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
		params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
		let mut dn = DistinguishedName::new();
		dn.push(DnType::CommonName, "mach5 dev CA");
		params.distinguished_name = dn;

		let issuer = Issuer::new(params, key);

		Ok(Self {
			issuer,
			cache: Mutex::new(HashMap::new()),
		})
	}

	/// Return a leaf for `sni`, minting and caching on first request.
	fn leaf_for(&self, sni: &str) -> Result<Leaf, Box<dyn Error>> {
		if let Some(leaf) = self.cache.lock().unwrap().get(sni) {
			return Ok(leaf.clone());
		}

		let leaf = self.mint(sni)?;
		self.cache
			.lock()
			.unwrap()
			.insert(sni.to_string(), leaf.clone());

		Ok(leaf)
	}

	fn mint(&self, sni: &str) -> Result<Leaf, Box<dyn Error>> {
		let key = KeyPair::generate()?;

		let mut params = CertificateParams::new(vec![sni.to_string()])?;
		let mut dn = DistinguishedName::new();
		dn.push(DnType::CommonName, sni);
		params.distinguished_name = dn;

		let cert = params.signed_by(&key, &self.issuer)?;

		let x509 = X509::from_pem(cert.pem().as_bytes())?;
		let pkey = PKey::private_key_from_pem(key.serialize_pem().as_bytes())?;

		Ok(Leaf {
			cert: x509,
			key: pkey,
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

	#[test]
	fn mints_leaf_with_sni_in_san() {
		let ca = CertAuthority::generate_dev().unwrap();
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
	fn caches_repeated_sni() {
		let ca = CertAuthority::generate_dev().unwrap();
		let first = ca.leaf_for("example.com").unwrap();
		let second = ca.leaf_for("example.com").unwrap();

		// Same cached leaf, so the DER encodings match; a re-mint would differ
		// because each carries a freshly generated key.
		assert_eq!(
			first.cert.to_der().unwrap(),
			second.cert.to_der().unwrap()
		);
	}
}
