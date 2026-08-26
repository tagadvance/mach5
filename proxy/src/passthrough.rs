//! Connections mach5 refuses to open.
//!
//! Everywhere else in this project mach5 terminates TLS, which means it holds
//! the plaintext of everything it carries. For most of the web that is the
//! point. For a bank it is the wrong guarantee entirely, and `[inject] exclude`
//! does not give the right one — it only stops mach5 *changing* a page it has
//! already decrypted.
//!
//! This is the other answer: read the name out of the ClientHello without
//! answering it, and for a listed host open a socket to the real origin and
//! copy bytes between the two. mach5 never has the keys, never sees a byte of
//! plaintext, and the client validates the origin's own certificate itself —
//! which is also the only thing that makes a certificate-pinning app work
//! through a proxy at all.
//!
//! The parser below reads exactly as much of the ClientHello as it takes to
//! find the SNI, and refuses anything it does not fully understand. A record
//! it cannot parse is not passed through: unrecognised means intercepted, the
//! same direction every other decision here fails in.

use std::collections::HashSet;
use std::sync::Arc;

use crate::config::Config;

/// A ClientHello is the first thing a client sends and is comfortably inside
/// this; anything larger is not one we need to read the start of.
pub const PEEK_BYTES: usize = 4096;

const HANDSHAKE: u8 = 0x16;
/// Content type, legacy version, and the two-byte record length.
const RECORD_HEADER: usize = 5;
const CLIENT_HELLO: u8 = 0x01;
const EXTENSION_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST: u8 = 0x00;

/// The hosts never to decrypt.
pub struct Passthrough {
	hosts: HashSet<String>,
	port: u16,
}

impl Passthrough {
	pub fn new(config: &Config) -> Self {
		let hosts = config
			.passthrough
			.hosts
			.iter()
			.map(|host| host.trim().trim_end_matches('.').to_ascii_lowercase())
			.filter(|host| !host.is_empty())
			.filter(|host| {
				// A name reaches the wire as ASCII: a browser sends the
				// punycode. So an entry written in unicode matches neither
				// what arrives nor anything else, and the host it was meant to
				// protect is quietly intercepted. Said out loud, because the
				// whole value of this list is that being on it means something.
				if !host.is_ascii() {
					log::warn!(
						"[passthrough] hosts: ignoring {host:?} — a name arrives as \
						 punycode (xn--...), so this entry can never match. Convert it, \
						 or the host is intercepted like any other."
					);

					return false;
				}

				true
			})
			.collect();

		Self {
			hosts,
			port: config.passthrough.port,
		}
	}

	/// Where a passed-through connection is carried to.
	pub fn port(&self) -> u16 {
		self.port
	}

	/// Whether this name is one mach5 must not terminate.
	///
	/// A parent covers its subdomains, as it does in the blocklist: listing
	/// `example-bank.com` and then being handed `secure.example-bank.com`
	/// undecrypted is what anyone writing that line meant.
	pub fn covers(&self, host: &str) -> bool {
		crate::blocklist::covers(&self.hosts, host)
	}

	pub fn is_empty(&self) -> bool {
		self.hosts.is_empty()
	}
}

pub fn shared(config: &Config) -> Arc<Passthrough> {
	static SHARED: std::sync::OnceLock<Arc<Passthrough>> = std::sync::OnceLock::new();

	SHARED
		.get_or_init(|| Arc::new(Passthrough::new(config)))
		.clone()
}

/// What a caller holding the first bytes off a socket should do next.
#[derive(Debug, PartialEq, Eq)]
pub enum Hello {
	/// Not the start of a TLS handshake record. Nothing to wait for.
	NotTls,
	/// A handshake record, and this many bytes are needed to hold all of it.
	Want(usize),
	/// The whole record is here.
	Complete,
}

/// Whether the whole first handshake record has arrived yet.
///
/// This exists because a ClientHello no longer fits in one TCP segment. A
/// modern browser offering a post-quantum key share sends about two kilobytes,
/// so it arrives in two segments — and reading whatever happened to be in the
/// socket when it was first readable gave [`server_name`] a truncated record,
/// which it correctly refused to parse. The refusal means "terminate it", so
/// whether a listed bank was decrypted came down to TCP segmentation.
pub fn have_hello(bytes: &[u8]) -> Hello {
	match bytes.first() {
		Some(&HANDSHAKE) => {}
		// Nothing yet: a client that has connected and said nothing is still
		// worth waiting a moment for.
		None => return Hello::Want(RECORD_HEADER),
		Some(_) => return Hello::NotTls,
	}

	if bytes.len() < RECORD_HEADER {
		return Hello::Want(RECORD_HEADER);
	}

	let length = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
	let whole = RECORD_HEADER + length;

	if bytes.len() >= whole {
		Hello::Complete
	} else {
		Hello::Want(whole)
	}
}

/// The server name from a TLS ClientHello, if this is one and it carries a
/// name we can read.
///
/// Deliberately strict. Every length in a TLS record is explicit, so anything
/// that does not add up is a record we have misunderstood — and a
/// misunderstanding here would mean deciding not to decrypt a connection on the
/// strength of a name we invented. `None` means "carry on and terminate it",
/// which is the safe direction to be wrong in.
pub fn server_name(bytes: &[u8]) -> Option<String> {
	let mut record = Reader::new(bytes);

	if record.u8()? != HANDSHAKE {
		return None;
	}
	// Legacy record version, then the record length.
	record.skip(2)?;
	let record_length = record.u16()? as usize;
	let mut handshake = Reader::new(record.take(record_length)?);

	if handshake.u8()? != CLIENT_HELLO {
		return None;
	}
	let handshake_length = handshake.u24()? as usize;
	let mut hello = Reader::new(handshake.take(handshake_length)?);

	// Client version, then the 32-byte random.
	hello.skip(2 + 32)?;
	// Session id, cipher suites, compression methods: each a length then that
	// many bytes, and none of them of any interest here.
	let session = hello.u8()? as usize;
	hello.skip(session)?;
	let ciphers = hello.u16()? as usize;
	hello.skip(ciphers)?;
	let compression = hello.u8()? as usize;
	hello.skip(compression)?;

	// A ClientHello with no extensions has no SNI, which is not a failure to
	// parse — just nothing to find.
	let extensions_length = hello.u16()? as usize;
	let mut extensions = Reader::new(hello.take(extensions_length)?);

	while let Some(kind) = extensions.u16() {
		let length = extensions.u16()? as usize;
		let body = extensions.take(length)?;

		if kind == EXTENSION_SERVER_NAME {
			return first_host_name(body);
		}
	}

	None
}

/// The first `host_name` entry in a server_name extension.
fn first_host_name(body: &[u8]) -> Option<String> {
	let mut list = Reader::new(body);
	let list_length = list.u16()? as usize;
	let mut names = Reader::new(list.take(list_length)?);

	while let Some(kind) = names.u8() {
		let length = names.u16()? as usize;
		let name = names.take(length)?;

		if kind == NAME_TYPE_HOST {
			// A host name is ASCII by the time it reaches the wire; anything
			// else is not one we should be matching a list against.
			if !name.is_ascii() {
				return None;
			}

			return Some(String::from_utf8_lossy(name).to_ascii_lowercase());
		}
	}

	None
}

/// A cursor that yields `None` rather than panicking at the end of the buffer,
/// so a truncated or hostile record simply fails to parse.
struct Reader<'a> {
	bytes: &'a [u8],
	at: usize,
}

impl<'a> Reader<'a> {
	fn new(bytes: &'a [u8]) -> Self {
		Self { bytes, at: 0 }
	}

	fn take(&mut self, count: usize) -> Option<&'a [u8]> {
		let end = self.at.checked_add(count)?;
		let slice = self.bytes.get(self.at..end)?;
		self.at = end;

		Some(slice)
	}

	fn skip(&mut self, count: usize) -> Option<()> {
		self.take(count).map(|_| ())
	}

	fn u8(&mut self) -> Option<u8> {
		self.take(1).map(|b| b[0])
	}

	fn u16(&mut self) -> Option<u16> {
		self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
	}

	fn u24(&mut self) -> Option<u32> {
		self.take(3)
			.map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A name arrives as punycode, so a unicode entry matches nothing at all —
	/// and the failure is silent in the worst possible direction, since the
	/// host it was written to protect is intercepted like any other.
	#[test]
	fn a_unicode_entry_is_refused_rather_than_kept_useless() {
		let config = Config::from_str(
			"[passthrough]\nhosts = [\"münchen-bank.de\", \"xn--mnchen-bank-zhb.de\"]\n",
		)
		.unwrap();
		let passthrough = Passthrough::new(&config);

		assert!(
			!passthrough.covers("münchen-bank.de"),
			"an SNI is never unicode either"
		);
		assert!(
			passthrough.covers("xn--mnchen-bank-zhb.de"),
			"the punycode entry is the one that works"
		);
		assert_eq!(passthrough.hosts.len(), 1);
	}

	/// Whether the whole record has arrived is the question the caller has to
	/// answer before parsing, because refusing a truncated one means "decrypt
	/// it" — and a hello that spans two segments is now the ordinary case.
	#[test]
	fn a_truncated_hello_asks_for_the_rest_of_itself() {
		let hello = client_hello(b"bank.example");

		assert_eq!(have_hello(&hello), Hello::Complete);
		assert_eq!(
			have_hello(&hello[..hello.len() - 1]),
			Hello::Want(hello.len()),
			"one byte short, and it says exactly how many it wants"
		);
		assert_eq!(have_hello(&hello[..3]), Hello::Want(5), "not even the header");
		assert_eq!(have_hello(&[]), Hello::Want(5), "nothing at all yet");

		// Nothing to wait for: this is not a handshake record, so no amount of
		// patience turns it into one.
		assert_eq!(have_hello(b"GET / HTTP/1.1\r\n"), Hello::NotTls);

		// And what the caller does with the answer: the truncated record still
		// parses to nothing, which is why it must not be parsed yet.
		assert_eq!(server_name(&hello[..hello.len() - 1]), None);
		assert_eq!(server_name(&hello).as_deref(), Some("bank.example"));
	}

	/// A real ClientHello, assembled rather than pasted so the shape of one is
	/// visible in the test that depends on it.
	fn client_hello(host: &[u8]) -> Vec<u8> {
		let mut names = vec![NAME_TYPE_HOST];
		names.extend_from_slice(&(host.len() as u16).to_be_bytes());
		names.extend_from_slice(host);

		let mut server_name = Vec::new();
		server_name.extend_from_slice(&(names.len() as u16).to_be_bytes());
		server_name.extend_from_slice(&names);

		let mut extensions = Vec::new();
		extensions.extend_from_slice(&EXTENSION_SERVER_NAME.to_be_bytes());
		extensions.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
		extensions.extend_from_slice(&server_name);

		let mut hello = vec![0x03, 0x03];
		hello.extend_from_slice(&[0u8; 32]);
		hello.push(0); // no session id
		hello.extend_from_slice(&2u16.to_be_bytes());
		hello.extend_from_slice(&[0x13, 0x01]); // one cipher suite
		hello.push(1); // one compression method
		hello.push(0);
		hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
		hello.extend_from_slice(&extensions);

		let mut handshake = vec![CLIENT_HELLO];
		handshake.extend_from_slice(&(hello.len() as u32).to_be_bytes()[1..]);
		handshake.extend_from_slice(&hello);

		let mut record = vec![HANDSHAKE, 0x03, 0x01];
		record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
		record.extend_from_slice(&handshake);

		record
	}

	#[test]
	fn the_name_comes_out_of_a_client_hello() {
		let hello = client_hello(b"secure.example-bank.com");

		assert_eq!(
			server_name(&hello).as_deref(),
			Some("secure.example-bank.com")
		);
	}

	#[test]
	fn a_shouted_name_is_the_same_name() {
		let hello = client_hello(b"Secure.Example-Bank.COM");

		assert_eq!(
			server_name(&hello).as_deref(),
			Some("secure.example-bank.com"),
			"the list is matched in lowercase"
		);
	}

	/// Every one of these used to be a way to read past the end of a buffer.
	/// None of them may be a way to produce a name.
	#[test]
	fn nothing_malformed_yields_a_name() {
		let hello = client_hello(b"example.com");

		for cut in 0..hello.len() {
			assert_eq!(
				server_name(&hello[..cut]),
				None,
				"a hello truncated at {cut} bytes is not one we understand"
			);
		}

		assert_eq!(server_name(&[]), None);
		assert_eq!(server_name(&[HANDSHAKE]), None);
		assert_eq!(server_name(b"GET / HTTP/1.1\r\n\r\n"), None, "not TLS at all");
	}

	#[test]
	fn a_record_that_is_not_a_handshake_is_not_read() {
		let mut hello = client_hello(b"example.com");
		hello[0] = 0x17; // application data

		assert_eq!(server_name(&hello), None);
	}

	#[test]
	fn a_lie_about_a_length_does_not_get_a_name() {
		let mut hello = client_hello(b"example.com");
		// Claim the record is far longer than what follows.
		hello[3] = 0xff;
		hello[4] = 0xff;

		assert_eq!(
			server_name(&hello),
			None,
			"a length past the end of the buffer is a record we misread"
		);
	}

	#[test]
	fn a_hello_without_the_extension_has_no_name() {
		let mut hello = client_hello(b"example.com");
		// Blank the extension type, so nothing matches server_name.
		let at = hello.len() - 20;
		hello[at] = 0xff;

		assert_eq!(server_name(&hello), None);
	}

	fn listing(hosts: &[&str]) -> Passthrough {
		Passthrough {
			hosts: hosts.iter().map(|h| h.to_string()).collect(),
			port: 443,
		}
	}

	#[test]
	fn a_listed_host_and_its_subdomains_are_covered() {
		let list = listing(&["example-bank.com"]);

		assert!(list.covers("example-bank.com"));
		assert!(
			list.covers("secure.example-bank.com"),
			"listing the bank means the whole bank"
		);
		assert!(!list.covers("example-bank.com.evil.example"));
		assert!(!list.covers("example.com"));
	}

	#[test]
	fn an_empty_list_covers_nothing() {
		assert!(!listing(&[]).covers("example.com"));
		assert!(listing(&[]).is_empty());
	}
}
