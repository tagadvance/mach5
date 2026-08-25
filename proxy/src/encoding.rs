//! Content codings, made explicit.
//!
//! Origins compress almost everything, so an interceptor that rewrites a body
//! would otherwise be handed brotli bytes and corrupt the page by editing them.
//! Rather than trust the HTTP client to decode selectively, we do it ourselves:
//! ask upstream only for codings we can decode *and* the client accepts, then
//! decode before the interceptors run and re-encode after. The streaming path
//! never buffers a body, so it relays whatever the origin sent untouched.
//!
//! The other direction is [`ensure_compressed`]: an origin that skipped
//! compression altogether is leaving bytes on the hop we control, so we apply a
//! coding it did not bother with.

use std::io::{Read, Write};

const ACCEPT_ENCODING: &str = "accept-encoding";
const CONTENT_ENCODING: &str = "content-encoding";
const CONTENT_TYPE: &str = "content-type";
const IDENTITY: &str = "identity";
const VARY: &str = "vary";

/// Bodies below this are left alone: the framing and the CPU cost more than the
/// coding saves, and the compressed form is routinely the larger of the two.
const MIN_COMPRESSIBLE: usize = 1024;

/// Media types worth the CPU, alongside anything `text/*`. Everything absent
/// here — images, video, archives, fonts — carries its own compression already,
/// so a second pass only makes it bigger and slower.
const COMPRESSIBLE_TYPES: [&str; 8] = [
	"application/json",
	"application/javascript",
	"application/xml",
	"application/xhtml+xml",
	"application/rss+xml",
	"application/atom+xml",
	"application/manifest+json",
	"image/svg+xml",
];

const BUFFER_SIZE: usize = 8192;
/// Cheap enough to sit in the request path; we are re-compressing for one hop
/// on the local network, not for a CDN cache.
const QUALITY: u32 = 5;
const WINDOW_BITS: u32 = 22;

/// The codings we can both decode and produce, in the order we prefer them.
const SUPPORTED: [Coding; 2] = [Coding::Brotli, Coding::Gzip];

/// A content coding we understand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coding {
	Gzip,
	Brotli,
}

impl Coding {
	fn parse(token: &str) -> Option<Self> {
		match token.trim().to_ascii_lowercase().as_str() {
			// x-gzip is the pre-RFC spelling some origins still emit.
			"gzip" | "x-gzip" => Some(Self::Gzip),
			"br" => Some(Self::Brotli),
			_ => None,
		}
	}

	fn token(self) -> &'static str {
		match self {
			Self::Gzip => "gzip",
			Self::Brotli => "br",
		}
	}
}

/// The `accept-encoding` value to send upstream: the intersection of what we
/// can decode with what the client said it accepts.
///
/// This is the invariant that makes re-encoding safe — we can never end up
/// holding a coding the client cannot read. A client that asked for nothing, or
/// only for codings we do not implement, gets `identity`.
pub fn negotiate(headers: &[(String, String)]) -> String {
	let Some((_, value)) = headers
		.iter()
		.find(|(name, _)| name.eq_ignore_ascii_case(ACCEPT_ENCODING))
	else {
		return IDENTITY.to_string();
	};

	let offered: Vec<(String, bool)> = value.split(',').filter_map(parse_offer).collect();
	let accepted: Vec<&str> = SUPPORTED
		.iter()
		.filter(|coding| accepts(&offered, coding.token()))
		.map(|coding| coding.token())
		.collect();

	if accepted.is_empty() {
		IDENTITY.to_string()
	} else {
		accepted.join(", ")
	}
}

/// One `accept-encoding` entry as its coding name and whether it is wanted at
/// all. Only `q=0` matters — an explicit refusal — so the remaining quality
/// values are deliberately not ranked.
fn parse_offer(entry: &str) -> Option<(String, bool)> {
	let mut parts = entry.split(';');
	let name = parts.next()?.trim().to_ascii_lowercase();
	if name.is_empty() {
		return None;
	}

	let refused = parts.any(|param| {
		let mut kv = param.splitn(2, '=');
		let key = kv.next().unwrap_or_default().trim();
		let value = kv.next().unwrap_or_default().trim();

		key.eq_ignore_ascii_case("q") && value.parse::<f32>().is_ok_and(|q| q <= 0.0)
	});

	Some((name, !refused))
}

fn accepts(offered: &[(String, bool)], coding: &str) -> bool {
	if let Some((_, wanted)) = offered.iter().find(|(name, _)| name == coding) {
		return *wanted;
	}

	offered
		.iter()
		.find(|(name, _)| name == "*")
		.is_some_and(|(_, wanted)| *wanted)
}

/// Decompress the body and strip `content-encoding`, returning the coding so it
/// can be put back afterwards.
///
/// A coding we do not implement, or a body that will not decompress, is left
/// exactly as it arrived: a truncated response should reach the client as the
/// origin sent it rather than becoming a crash.
pub fn decode(headers: &mut Vec<(String, String)>, body: Vec<u8>) -> (Vec<u8>, Option<Coding>) {
	let Some(value) = headers
		.iter()
		.find(|(name, _)| name.eq_ignore_ascii_case(CONTENT_ENCODING))
		.map(|(_, value)| value.clone())
	else {
		return (body, None);
	};

	let Some(coding) = Coding::parse(&value) else {
		return (body, None);
	};

	match decompress(coding, &body) {
		Ok(decoded) => {
			headers.retain(|(name, _)| !name.eq_ignore_ascii_case(CONTENT_ENCODING));

			(decoded, Some(coding))
		}
		Err(e) => {
			log::warn!("failed decoding {} body: {e}", coding.token());

			(body, None)
		}
	}
}

/// Re-compress with the coding [`decode`] removed, restoring the header.
/// `None` hands the body straight back.
pub fn encode(
	headers: &mut Vec<(String, String)>,
	body: Vec<u8>,
	coding: Option<Coding>,
) -> Vec<u8> {
	let Some(coding) = coding else {
		return body;
	};

	match compress(coding, &body) {
		Ok(encoded) => {
			headers.push((CONTENT_ENCODING.to_string(), coding.token().to_string()));

			encoded
		}
		// Sending it uncompressed is still correct; the header stays off.
		Err(e) => {
			log::warn!("failed re-encoding body as {}: {e}", coding.token());

			body
		}
	}
}

/// Compress a body the origin sent in the clear.
///
/// Only ever a body that arrived unencoded, which is why `coding` alone is not
/// the test: an origin sending a coding we do not implement decodes to `None`
/// too, and compressing *that* would wrap zstd bytes in brotli. The header
/// still being present is what tells the two apart.
///
/// Nothing here changes what the body means, so a body we decline to compress —
/// too small, the wrong type, a client that asked for none, or a coding that
/// came out larger than what went in — is handed straight back with the headers
/// untouched.
pub fn ensure_compressed(
	request: &[(String, String)],
	status: u16,
	headers: &mut Vec<(String, String)>,
	body: Vec<u8>,
	coding: Option<Coding>,
) -> Vec<u8> {
	// 204 and 304 carry no body to compress, whatever length we are holding.
	if coding.is_some()
		|| has_content_encoding(headers)
		|| body.len() < MIN_COMPRESSIBLE
		|| matches!(status, 204 | 304)
		|| !compressible(headers)
	{
		return body;
	}

	// `negotiate` already computes the intersection with what we can produce,
	// in preference order; its first name is the best coding available to us.
	let accepted = negotiate(request);
	let Some(coding) = accepted.split(',').next().and_then(Coding::parse) else {
		return body;
	};

	match compress(coding, &body) {
		Ok(encoded) if encoded.len() < body.len() => {
			headers.push((CONTENT_ENCODING.to_string(), coding.token().to_string()));
			vary_on_accept_encoding(headers);

			encoded
		}
		// Incompressible input, and rarer than it sounds. Shipping the larger
		// of the two bodies would be absurd.
		Ok(_) => body,
		Err(e) => {
			log::warn!("failed compressing body as {}: {e}", coding.token());

			body
		}
	}
}

fn has_content_encoding(headers: &[(String, String)]) -> bool {
	headers
		.iter()
		.any(|(name, _)| name.eq_ignore_ascii_case(CONTENT_ENCODING))
}

/// Whether the `content-type` is one that gets smaller. A response without one
/// is not compressed: we would be guessing at the bytes.
fn compressible(headers: &[(String, String)]) -> bool {
	let Some((_, value)) = headers
		.iter()
		.find(|(name, _)| name.eq_ignore_ascii_case(CONTENT_TYPE))
	else {
		return false;
	};

	// The charset and any other parameter say nothing about compressibility.
	let media = value
		.split(';')
		.next()
		.unwrap_or_default()
		.trim()
		.to_ascii_lowercase();

	media.starts_with("text/") || COMPRESSIBLE_TYPES.contains(&media.as_str())
}

/// What we served now depends on a request header, and a shared cache has to
/// know that before it hands this body to a client that cannot read it.
fn vary_on_accept_encoding(headers: &mut Vec<(String, String)>) {
	let Some((_, value)) = headers
		.iter_mut()
		.find(|(name, _)| name.eq_ignore_ascii_case(VARY))
	else {
		headers.push((VARY.to_string(), ACCEPT_ENCODING.to_string()));

		return;
	};

	// Whatever else the origin varies on has to survive; we are adding to its
	// list, not replacing it.
	if value
		.split(',')
		.any(|token| token.trim().eq_ignore_ascii_case(ACCEPT_ENCODING))
	{
		return;
	}

	value.push_str(", ");
	value.push_str(ACCEPT_ENCODING);
}

fn decompress(coding: Coding, body: &[u8]) -> std::io::Result<Vec<u8>> {
	let mut out = Vec::new();
	match coding {
		Coding::Gzip => flate2::read::GzDecoder::new(body).read_to_end(&mut out)?,
		Coding::Brotli => brotli::Decompressor::new(body, BUFFER_SIZE).read_to_end(&mut out)?,
	};

	Ok(out)
}

fn compress(coding: Coding, body: &[u8]) -> std::io::Result<Vec<u8>> {
	match coding {
		Coding::Gzip => {
			let mut encoder =
				flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
			encoder.write_all(body)?;

			encoder.finish()
		}
		Coding::Brotli => {
			let mut encoder =
				brotli::CompressorWriter::new(Vec::new(), BUFFER_SIZE, QUALITY, WINDOW_BITS);
			encoder.write_all(body)?;

			Ok(encoder.into_inner())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn accept(value: &str) -> Vec<(String, String)> {
		vec![("Accept-Encoding".to_string(), value.to_string())]
	}

	fn encoded(value: &str) -> Vec<(String, String)> {
		vec![
			("Content-Type".to_string(), "text/html".to_string()),
			("Content-Encoding".to_string(), value.to_string()),
		]
	}

	/// A body big enough to clear the threshold and repetitive enough that any
	/// coding will shrink it.
	fn page() -> Vec<u8> {
		b"<html><body>hello, mach5</body></html>".repeat(64)
	}

	fn plain(content_type: &str) -> Vec<(String, String)> {
		vec![("Content-Type".to_string(), content_type.to_string())]
	}

	fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
		headers
			.iter()
			.find(|(key, _)| key.eq_ignore_ascii_case(name))
			.map(|(_, value)| value.as_str())
	}

	fn round_trip(coding: Coding) {
		let original = b"<html><body>hello, mach5</body></html>".repeat(16);
		let mut headers = encoded(coding.token());

		let compressed = compress(coding, &original).expect("compresses");
		let (body, found) = decode(&mut headers, compressed);

		assert_eq!(found, Some(coding));
		assert_eq!(body, original, "interceptors must see the plain body");
		assert!(
			!has_content_encoding(&headers),
			"content-encoding must be stripped while decoded"
		);

		let body = encode(&mut headers, body, found);

		assert_eq!(
			headers
				.iter()
				.find(|(name, _)| name.eq_ignore_ascii_case(CONTENT_ENCODING))
				.map(|(_, value)| value.as_str()),
			Some(coding.token()),
			"and restored afterwards"
		);
		assert_eq!(
			decompress(coding, &body).expect("decompresses"),
			original,
			"what the client receives must decode to the same bytes"
		);
	}

	#[test]
	fn gzip_survives_a_round_trip() {
		round_trip(Coding::Gzip);
	}

	#[test]
	fn brotli_survives_a_round_trip() {
		round_trip(Coding::Brotli);
	}

	#[test]
	fn an_unknown_coding_is_left_alone() {
		let mut headers = encoded("zstd");
		let original = b"compressed with something we do not speak".to_vec();

		let (body, coding) = decode(&mut headers, original.clone());

		assert_eq!(coding, None);
		assert_eq!(body, original);
		assert!(
			has_content_encoding(&headers),
			"the header must survive so the client can decode it"
		);
		assert_eq!(encode(&mut headers, body, coding), original);
	}

	#[test]
	fn a_body_that_will_not_decompress_is_passed_through() {
		let mut headers = encoded("gzip");
		let garbage = b"this is not gzip".to_vec();

		let (body, coding) = decode(&mut headers, garbage.clone());

		assert_eq!(coding, None);
		assert_eq!(body, garbage);
		assert!(has_content_encoding(&headers));
	}

	#[test]
	fn negotiation_keeps_only_what_we_can_decode() {
		assert_eq!(negotiate(&accept("gzip, deflate, br, zstd")), "br, gzip");
	}

	#[test]
	fn negotiation_narrows_to_what_the_client_asked_for() {
		assert_eq!(negotiate(&accept("gzip")), "gzip");
	}

	#[test]
	fn negotiation_falls_back_to_identity() {
		assert_eq!(negotiate(&accept("identity")), IDENTITY);
		assert_eq!(negotiate(&[]), IDENTITY);
	}

	#[test]
	fn negotiation_honours_an_explicit_refusal() {
		assert_eq!(negotiate(&accept("br;q=0, gzip")), "gzip");
	}

	#[test]
	fn negotiation_reads_a_wildcard_as_anything_we_have() {
		assert_eq!(negotiate(&accept("*")), "br, gzip");
	}

	#[test]
	fn a_body_the_origin_left_plain_is_compressed() {
		let original = page();
		let mut headers = plain("text/html; charset=utf-8");

		let body =
			ensure_compressed(&accept("gzip, br"), 200, &mut headers, original.clone(), None);

		assert!(body.len() < original.len(), "it has to be worth doing");
		assert_eq!(
			header(&headers, CONTENT_ENCODING),
			Some("br"),
			"the first coding negotiate names is the one we prefer"
		);
		assert_eq!(
			decompress(Coding::Brotli, &body).expect("decompresses"),
			original,
			"the client must get back exactly what the interceptors produced"
		);
	}

	#[test]
	fn only_the_coding_the_client_can_read_is_used() {
		let mut headers = plain("application/json");

		let body = ensure_compressed(&accept("gzip"), 200, &mut headers, page(), None);

		assert_eq!(header(&headers, CONTENT_ENCODING), Some("gzip"));
		assert_eq!(decompress(Coding::Gzip, &body).expect("decompresses"), page());
	}

	/// The one that matters most: a coding we cannot decode still leaves the
	/// body encoded, and compressing it again would corrupt the response.
	#[test]
	fn a_body_we_could_not_decode_is_never_compressed_again() {
		let original = page();
		let mut headers = encoded("zstd");

		let (body, coding) = decode(&mut headers, original.clone());

		assert_eq!(coding, None, "we do not speak zstd");

		let body = ensure_compressed(&accept("br"), 200, &mut headers, body, coding);

		assert_eq!(body, original);
		assert_eq!(
			header(&headers, CONTENT_ENCODING),
			Some("zstd"),
			"the origin's coding must be all the client is told about"
		);
		assert!(header(&headers, VARY).is_none());
	}

	#[test]
	fn a_body_we_decoded_and_re_encoded_is_not_compressed_twice() {
		let mut headers = plain("text/html");
		let body = encode(&mut headers, page(), Some(Coding::Gzip));

		let served =
			ensure_compressed(&accept("br"), 200, &mut headers, body.clone(), Some(Coding::Gzip));

		assert_eq!(served, body);
		assert_eq!(header(&headers, CONTENT_ENCODING), Some("gzip"));
	}

	#[test]
	fn a_small_body_is_left_alone() {
		let original = b"<html>tiny</html>".to_vec();
		let mut headers = plain("text/html");

		assert!(original.len() < MIN_COMPRESSIBLE);
		assert_eq!(
			ensure_compressed(&accept("br"), 200, &mut headers, original.clone(), None),
			original
		);
		assert!(header(&headers, CONTENT_ENCODING).is_none());
	}

	#[test]
	fn an_already_compressed_type_is_left_alone() {
		let mut headers = plain("image/jpeg");

		assert_eq!(
			ensure_compressed(&accept("br"), 200, &mut headers, page(), None),
			page()
		);
		assert!(header(&headers, CONTENT_ENCODING).is_none());
		assert!(
			ensure_compressed(&accept("br"), 200, &mut plain("image/svg+xml"), page(), None).len()
				< page().len(),
			"an svg is text wearing an image type"
		);
	}

	#[test]
	fn a_client_that_wants_no_coding_gets_none() {
		let mut headers = plain("text/html");

		assert_eq!(
			ensure_compressed(&accept(IDENTITY), 200, &mut headers, page(), None),
			page()
		);
		assert_eq!(
			ensure_compressed(&[], 200, &mut headers, page(), None),
			page(),
			"no accept-encoding at all is the same answer"
		);
		assert!(header(&headers, CONTENT_ENCODING).is_none());
	}

	#[test]
	fn a_status_with_nothing_to_compress_is_left_alone() {
		let mut headers = plain("text/html");

		assert_eq!(
			ensure_compressed(&accept("br"), 304, &mut headers, page(), None),
			page()
		);
		assert!(header(&headers, CONTENT_ENCODING).is_none());
	}

	#[test]
	fn a_body_that_grows_is_sent_as_it_was() {
		// Xorshift output: no structure for brotli to find, so all it can add
		// is its own framing.
		let mut state = 0x2545_f491_4f6c_dd1du64;
		let original: Vec<u8> = (0..MIN_COMPRESSIBLE + 64)
			.map(|_| {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;

				(state >> 24) as u8
			})
			.collect();
		let mut headers = plain("text/plain");

		let body = ensure_compressed(&accept("br"), 200, &mut headers, original.clone(), None);

		assert_eq!(body, original);
		assert!(
			header(&headers, CONTENT_ENCODING).is_none(),
			"the header must not claim a coding we did not apply"
		);
	}

	#[test]
	fn compressing_tells_caches_what_it_depends_on() {
		let mut headers = plain("text/html");

		ensure_compressed(&accept("br"), 200, &mut headers, page(), None);

		assert_eq!(header(&headers, VARY), Some(ACCEPT_ENCODING));
	}

	#[test]
	fn an_existing_vary_is_added_to_rather_than_replaced() {
		let mut headers = plain("text/html");
		headers.push(("Vary".to_string(), "Cookie".to_string()));

		ensure_compressed(&accept("br"), 200, &mut headers, page(), None);

		assert_eq!(header(&headers, VARY), Some("Cookie, accept-encoding"));

		let mut headers = plain("text/html");
		headers.push(("Vary".to_string(), "Cookie, Accept-Encoding".to_string()));

		ensure_compressed(&accept("gzip"), 200, &mut headers, page(), None);

		assert_eq!(
			header(&headers, VARY),
			Some("Cookie, Accept-Encoding"),
			"a token already there must not be listed twice"
		);
	}
}
