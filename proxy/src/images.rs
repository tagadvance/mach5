//! Re-encoding images on the way past.
//!
//! The first thing in mach5 that earns the word "accelerator". Text compression
//! wins a few percent; images are half the weight of a page, and measured
//! across twenty real ones from Wikipedia and the BBC, WebP at quality 80 took
//! 674KB down to 352KB — with none of them coming out larger. A 232KB PNG
//! became 24KB.
//!
//! What that costs is CPU: about twelve milliseconds per image to decode and
//! re-encode, on a worker thread rather than any event loop. That is worth
//! paying once and not per request, which is what `[paths] cache_dir` is for
//! and is not yet wired up — see the roadmap.
//!
//! Three rules keep this from ever making a page worse:
//!
//! - Only when the client said it takes WebP. Every current browser does, but
//!   `curl` does not, and neither does whatever is fetching an image into a
//!   script.
//! - Only formats worth converting. An image that is already WebP or AVIF is
//!   left alone; so is an SVG, which is text and not a raster image at all.
//! - Only if the result is actually smaller. It nearly always is, and when it
//!   is not the original goes out untouched.

use std::io::Cursor;
use std::sync::Arc;

use crate::config::Config;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse, ResponseHead};

/// What we can decode, and what is worth the attempt. Anything else — WebP,
/// AVIF, SVG, an icon — is either already better than we would manage or not a
/// raster image.
const CONVERTIBLE: [&str; 4] = ["image/jpeg", "image/jpg", "image/png", "image/bmp"];

/// Below this there is nothing to win, and the WebP container has overheads of
/// its own. Tracking pixels and spacers live down here.
const MIN_BYTES: usize = 3 * 1024;

pub struct Images {
	/// What the configuration asked for. The panel moves around this rather
	/// than replacing it, so the config stays the thing that sets the house
	/// style.
	configured: u8,
	settings: Arc<crate::settings::Store>,
	/// Absent when switched off, and then every request pays the conversion.
	cache: Option<Arc<crate::imagecache::Cache>>,
	metrics: Arc<crate::metrics::Metrics>,
}

impl Images {
	pub fn new(config: &Config) -> Self {
		Self {
			configured: config.images.quality,
			settings: crate::settings::shared(config),
			cache: crate::imagecache::shared(config),
			metrics: crate::metrics::shared(),
		}
	}
}

impl Interceptor for Images {
	fn on_response(&self, req: &ProxyRequest, resp: &mut ProxyResponse) {
		// Asked again here because another link may be the reason the body was
		// buffered at all.
		if !claims(req, resp.status, &resp.headers) || resp.body.len() < MIN_BYTES {
			return;
		}

		// Asked per response rather than held, so a change from the panel takes
		// effect on the next image and not the next restart.
		let Some(quality) = self
			.settings
			.get()
			.image_quality
			.applied_to(self.configured)
		else {
			return;
		};

		// Keyed on the bytes in hand, so a hit is by definition the
		// re-encoding of exactly this image.
		let cached = self
			.cache
			.as_ref()
			.and_then(|cache| cache.get(&resp.body, quality));

		let webp = match cached {
			Some(webp) => webp,
			None => {
				let Some(webp) = to_webp(&resp.body, quality as f32) else {
					return;
				};

				if let Some(cache) = self.cache.as_ref() {
					cache.put(&resp.body, quality, &webp);
				}

				webp
			}
		};

		// Larger is a real outcome, just a rare one, and shipping it would be
		// absurd.
		if webp.len() >= resp.body.len() {
			return;
		}

		self.metrics
			.bytes_saved_by_images
			.add((resp.body.len() - webp.len()) as u64);
		set_content_type(&mut resp.headers);
		crate::encoding::vary_on_accept(&mut resp.headers);
		resp.body = webp;
	}

	/// Exact, as ever: anything this claims is held in memory whole instead of
	/// streaming, so it claims images it can convert for a client that wants
	/// them and nothing else.
	fn wants_body(&self, req: &ProxyRequest, head: &ResponseHead) -> bool {
		claims(req, head.status, &head.headers)
	}
}

fn claims(req: &ProxyRequest, status: u16, headers: &[(String, String)]) -> bool {
	status == 200 && accepts_webp(&req.headers) && is_convertible(headers)
}

/// Whether the client said it takes WebP. Browsers have for years; the point of
/// asking is everything that is not a browser.
fn accepts_webp(headers: &[(String, String)]) -> bool {
	headers.iter().any(|(name, value)| {
		name.eq_ignore_ascii_case("accept") && value.to_ascii_lowercase().contains("image/webp")
	})
}

fn is_convertible(headers: &[(String, String)]) -> bool {
	headers.iter().any(|(name, value)| {
		if !name.eq_ignore_ascii_case("content-type") {
			return false;
		}

		let value = value.to_ascii_lowercase();
		let kind = value.split(';').next().unwrap_or(&value).trim().to_string();

		CONVERTIBLE.contains(&kind.as_str())
	})
}

fn set_content_type(headers: &mut Vec<(String, String)>) {
	headers.retain(|(name, _)| !name.eq_ignore_ascii_case("content-type"));
	headers.push(("content-type".to_string(), "image/webp".to_string()));
}

/// Decode and re-encode, or `None` when the bytes are not an image we can read.
///
/// A body that will not decode is not an error worth reporting: an origin may
/// have mislabelled it, or truncated it, and either way the right thing is to
/// pass on exactly what arrived.
fn to_webp(body: &[u8], quality: f32) -> Option<Vec<u8>> {
	let decoded = image::ImageReader::new(Cursor::new(body))
		.with_guessed_format()
		.ok()?
		.decode()
		.ok()?;

	// Transparency has to survive, or a logo comes out on a black square.
	let encoded = if decoded.color().has_alpha() {
		webp::Encoder::from_rgba(&decoded.to_rgba8(), decoded.width(), decoded.height())
			.encode(quality)
	} else {
		webp::Encoder::from_rgb(&decoded.to_rgb8(), decoded.width(), decoded.height())
			.encode(quality)
	};

	Some(encoded.to_vec())
}

#[cfg(test)]
mod tests {
	use super::*;

	fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
		pairs
			.iter()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect()
	}

	fn request(accept: &str) -> ProxyRequest {
		ProxyRequest {
			method: "GET".to_string(),
			url: "https://example.com/photo.jpg".to_string(),
			headers: headers(&[("accept", accept)]),
			body: Vec::new(),
		}
	}

	/// A PNG with enough going on to be a realistic payload: a flat gradient
	/// compresses to almost nothing and would sit under the size floor, which
	/// is not the case this is meant to exercise.
	fn png(width: u32, height: u32) -> Vec<u8> {
		let mut buffer = image::RgbImage::new(width, height);
		for (x, y, pixel) in buffer.enumerate_pixels_mut() {
			let swirl = ((x * x + y * y) % 251) as u8;
			*pixel = image::Rgb([swirl, (x % 256) as u8 ^ swirl, (y % 256) as u8]);
		}

		let mut out = Vec::new();
		image::DynamicImage::ImageRgb8(buffer)
			.write_to(&mut Cursor::new(&mut out), image::ImageFormat::Png)
			.expect("a png");

		out
	}

	fn response(body: Vec<u8>, content_type: &str) -> ProxyResponse {
		ProxyResponse {
			status: 200,
			headers: headers(&[("content-type", content_type)]),
			body,
		}
	}

	fn images() -> Images {
		Images {
			configured: 80,
			settings: Arc::new(crate::settings::Store::load(
				std::env::temp_dir().join("mach5-images-test-settings.json"),
			)),
			cache: None,
			metrics: Arc::new(crate::metrics::Metrics::default()),
		}
	}

	#[test]
	fn a_png_comes_back_smaller_and_as_webp() {
		let original = png(200, 200);
		let mut resp = response(original.clone(), "image/png");

		images().on_response(&request("image/webp,*/*"), &mut resp);

		assert!(
			resp.body.len() < original.len(),
			"{} bytes was not an improvement on {}",
			resp.body.len(),
			original.len()
		);
		assert!(resp.body.starts_with(b"RIFF"), "and it is a webp container");
		assert_eq!(
			resp.headers
				.iter()
				.find(|(name, _)| name == "content-type")
				.map(|(_, value)| value.as_str()),
			Some("image/webp")
		);
	}

	/// What was served now depends on a request header, and a cache in front of
	/// mach5 has to know that.
	#[test]
	fn a_converted_image_varies_on_accept() {
		let mut resp = response(png(200, 200), "image/png");

		images().on_response(&request("image/webp,*/*"), &mut resp);

		assert!(resp
			.headers
			.iter()
			.any(|(name, value)| name.eq_ignore_ascii_case("vary")
				&& value.to_ascii_lowercase().contains("accept")));
	}

	#[test]
	fn a_client_that_did_not_ask_for_webp_gets_what_the_origin_sent() {
		let original = png(200, 200);
		let mut resp = response(original.clone(), "image/png");

		images().on_response(&request("image/png,*/*"), &mut resp);

		assert_eq!(resp.body, original);
		assert!(!images().wants_body(
			&request("image/png,*/*"),
			&ResponseHead {
				status: 200,
				headers: headers(&[("content-type", "image/png")]),
			}
		));
	}

	#[test]
	fn what_we_cannot_improve_is_not_claimed() {
		let head = |kind: &str| ResponseHead {
			status: 200,
			headers: headers(&[("content-type", kind)]),
		};
		let asking = request("image/webp,*/*");

		assert!(images().wants_body(&asking, &head("image/jpeg")));
		assert!(images().wants_body(&asking, &head("image/png")));
		assert!(
			!images().wants_body(&asking, &head("image/webp")),
			"already webp"
		);
		assert!(!images().wants_body(&asking, &head("image/avif")), "already better");
		assert!(!images().wants_body(&asking, &head("image/svg+xml")), "not a raster");
		assert!(!images().wants_body(&asking, &head("text/html")));
	}

	#[test]
	fn a_tiny_image_is_left_alone() {
		let original = png(4, 4);
		assert!(original.len() < MIN_BYTES, "the fixture must be tiny");
		let mut resp = response(original.clone(), "image/png");

		images().on_response(&request("image/webp,*/*"), &mut resp);

		assert_eq!(resp.body, original, "nothing to win down here");
	}

	#[test]
	fn something_that_is_not_an_image_is_passed_on_untouched() {
		let original = vec![b'x'; MIN_BYTES + 1];
		let mut resp = response(original.clone(), "image/png");

		images().on_response(&request("image/webp,*/*"), &mut resp);

		assert_eq!(
			resp.body, original,
			"a mislabelled body is the origin's business, not ours to mangle"
		);
	}

	#[test]
	fn a_404_is_not_an_image_worth_converting() {
		let mut resp = response(png(200, 200), "image/png");
		resp.status = 404;
		let original = resp.body.clone();

		images().on_response(&request("image/webp,*/*"), &mut resp);

		assert_eq!(resp.body, original);
	}

	#[test]
	fn transparency_survives() {
		let mut buffer = image::RgbaImage::new(100, 100);
		for (x, _y, pixel) in buffer.enumerate_pixels_mut() {
			*pixel = image::Rgba([255, 0, 0, if x < 50 { 0 } else { 255 }]);
		}
		let mut original = Vec::new();
		image::DynamicImage::ImageRgba8(buffer)
			.write_to(&mut Cursor::new(&mut original), image::ImageFormat::Png)
			.expect("a png");

		let converted = to_webp(&original, 80.0).expect("it converts");
		let features = webp::BitstreamFeatures::new(&converted).expect("a webp");

		assert!(
			features.has_alpha(),
			"a logo must not come back on a black square"
		);
		assert_eq!((features.width(), features.height()), (100, 100));
	}
}
