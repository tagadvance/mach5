//! Content codings, made explicit.
//!
//! Origins compress almost everything, so an interceptor that rewrites a body
//! would otherwise be handed brotli bytes and corrupt the page by editing them.
//! Rather than trust the HTTP client to decode selectively, we do it ourselves:
//! ask upstream only for codings we can decode *and* the client accepts, then
//! decode before the interceptors run and re-encode after. The streaming path
//! never buffers a body, so it relays whatever the origin sent untouched.

use std::io::{Read, Write};

const ACCEPT_ENCODING: &str = "accept-encoding";
const CONTENT_ENCODING: &str = "content-encoding";
const IDENTITY: &str = "identity";

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

	fn has_content_encoding(headers: &[(String, String)]) -> bool {
		headers
			.iter()
			.any(|(name, _)| name.eq_ignore_ascii_case(CONTENT_ENCODING))
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
}
