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
/// Exactly what the `image` dependency is built to decode — see its `features`
/// in Cargo.toml. `image/bmp` was listed here and is not among them, so a BMP
/// was buffered whole in memory and then always failed to convert: the cost of
/// claiming it with none of the benefit.
const CONVERTIBLE: [&str; 3] = ["image/jpeg", "image/jpg", "image/png"];

/// Below this there is nothing to win, and the WebP container has overheads of
/// its own. Tracking pixels and spacers live down here.
const MIN_BYTES: usize = 3 * 1024;

/// A 1x1 transparent GIF, the same one the blocklist serves. An image request
/// answered with an empty body leaves a broken-image icon; answered with this,
/// the page merely has a very small image in it.
const TRANSPARENT_GIF: [u8; 43] = [
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

pub struct Images {
	/// What the configuration asked for. The panel moves around this rather
	/// than replacing it, so the config stays the thing that sets the house
	/// style.
	configured: u8,
	settings: Arc<crate::settings::Store>,
	/// Absent when switched off, and then every request pays the conversion.
	cache: Option<Arc<crate::imagecache::Cache>>,
	/// What `[images] max_megapixels` comes to, in pixels.
	max_pixels: u64,
	metrics: Arc<crate::metrics::Metrics>,
}

impl Images {
	pub fn new(config: &Config) -> Self {
		Self {
			configured: config.images.quality,
			settings: crate::settings::shared(config),
			cache: crate::imagecache::shared(config),
			max_pixels: u64::from(config.images.max_megapixels) * 1_000_000,
			metrics: crate::metrics::shared(),
		}
	}
}

impl Interceptor for Images {
	/// Text-only mode, decided on the request where that is possible so the image is never
	/// fetched. Every other tier is a trade between bytes and how the picture
	/// looks; this one is the only place the bytes stop entirely.
	fn on_request(&self, req: &mut ProxyRequest) -> Option<ProxyResponse> {
		if !self.settings.get().image_quality.strips_images() || !is_image_request(req) {
			return None;
		}

		self.metrics.images_stripped.increment();

		Some(ProxyResponse {
			status: 200,
			headers: vec![
				("content-type".to_string(), "image/gif".to_string()),
				// Must not outlive the setting. Without this, turning images
				// back on leaves every page the browser cached showing blanks
				// until the entries expire, which reads as mach5 being broken.
				("cache-control".to_string(), "no-store".to_string()),
				("x-mach5".to_string(), "no-images".to_string()),
			],
			body: TRANSPARENT_GIF.to_vec(),
		})
	}

	fn on_response(&self, req: &ProxyRequest, resp: &mut ProxyResponse) {
		// The other half of text-only mode, for images the request did not
		// announce. An image fetched by script arrives as `sec-fetch-dest:
		// empty` and is indistinguishable from any other XHR until the origin
		// says what it sent, so this is the only place it can be caught.
		//
		// The bytes have already been paid for by the time we are here, which
		// looks like it defeats the point — and would, if the constrained link
		// were the one to the origin. It is not: mach5 sits on a home
		// connection and the client reaches it over a tunnel from a phone.
		// What this saves is every byte on the half that is actually metered.
		if self.settings.get().image_quality.strips_images()
			&& is_image_response(&resp.headers)
		{
			self.metrics.images_stripped.increment();
			self.metrics
				.bytes_saved_by_images
				.add(resp.body.len().saturating_sub(TRANSPARENT_GIF.len()) as u64);
			strip(resp);

			return;
		}

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
				let Some(webp) = to_webp(&resp.body, quality as f32, self.max_pixels) else {
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
		// Including whether converting is switched on at all. Without this,
		// `image_quality: "off"` still bought every JPEG a trip through memory
		// up to `max_response_body_mb` — the whole cost of the feature, and
		// none of it, since `on_response` then hands the bytes straight back.
		let quality = self.settings.get().image_quality;

		// Text-only wants the body precisely so it can throw it away. Only for
		// what is actually an image: claiming anything else here would take the
		// whole proxy off streaming.
		if quality.strips_images() {
			return is_image_response(&head.headers);
		}

		if quality.applied_to(self.configured).is_none() {
			return false;
		}

		claims(req, head.status, &head.headers)
	}
}

/// Whether this request is a browser asking for an image, as opposed to asking
/// for something that would merely accept one.
///
/// Stricter than it looks like it needs to be, and deliberately: a top-level
/// navigation's `accept` also contains `image/` further down the list, so a
/// looser test turns text-only mode into blank-page mode.
fn is_image_request(req: &ProxyRequest) -> bool {
	let header = |wanted: &str| {
		req.headers
			.iter()
			.find(|(name, _)| name.eq_ignore_ascii_case(wanted))
			.map(|(_, value)| value.to_ascii_lowercase())
	};

	// What the browser says the fetch is for. Definitive where it is sent,
	// which is every browser current enough to be worth proxying.
	if let Some(dest) = header("sec-fetch-dest") {
		return dest.trim() == "image";
	}

	// Otherwise the *first* type offered, which is `image/...` for an <img>
	// and `text/html` for a page.
	header("accept").is_some_and(|accept| {
		accept
			.split(',')
			.next()
			.unwrap_or_default()
			.trim()
			.starts_with("image/")
	})
}

/// Whether the origin says it sent an image, whatever the request looked like.
fn is_image_response(headers: &[(String, String)]) -> bool {
	headers.iter().any(|(name, value)| {
		name.eq_ignore_ascii_case("content-type")
			&& value
				.trim_start()
				.to_ascii_lowercase()
				.starts_with("image/")
	})
}

/// Replace a response body with the pixel, in place.
fn strip(resp: &mut ProxyResponse) {
	resp.headers.retain(|(name, _)| {
		!name.eq_ignore_ascii_case("content-type")
			&& !name.eq_ignore_ascii_case("content-length")
			&& !name.eq_ignore_ascii_case("cache-control")
			&& !name.eq_ignore_ascii_case("etag")
			&& !name.eq_ignore_ascii_case("last-modified")
			// Whatever the origin used is gone with the body it described.
			&& !name.eq_ignore_ascii_case("content-encoding")
	});

	resp.headers
		.push(("content-type".to_string(), "image/gif".to_string()));
	// Same reasoning as the request side: this must not outlive the setting,
	// and a validator kept from the real image would let the browser
	// revalidate its way back to a pixel.
	resp.headers
		.push(("cache-control".to_string(), "no-store".to_string()));
	resp.headers
		.push(("x-mach5".to_string(), "no-images".to_string()));

	resp.body = TRANSPARENT_GIF.to_vec();
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

/// What libwebp will accept in either direction (`WEBP_MAX_DIMENSION`).
const MAX_DIMENSION: u32 = 16383;

/// Decode and re-encode, or `None` when the bytes are not an image we can read.
///
/// A body that will not decode is not an error worth reporting: an origin may
/// have mislabelled it, or truncated it, and either way the right thing is to
/// pass on exactly what arrived.
fn to_webp(body: &[u8], quality: f32, max_pixels: u64) -> Option<Vec<u8>> {
	// The header, before anything is decoded. A decoded frame costs
	// width × height × 4 bytes whatever the file compressed to, so the bytes
	// that arrived are no bound at all: two megabytes of flat-colour PNG is
	// 11000×11000, which is 484MB of pixels — and there are two worker pools of
	// these, so a page of twenty such images asks for more memory than the box
	// has. Deciding from the dimensions costs one pass over the header.
	let (width, height) = image::ImageReader::new(Cursor::new(body))
		.with_guessed_format()
		.ok()?
		.into_dimensions()
		.ok()?;

	// libwebp refuses either dimension above this, and the `webp` crate's
	// `encode` unwraps that refusal — inside an h3 worker, which is a bare
	// spawned thread with nothing supervising it, so one panorama would take a
	// worker down for the lifetime of the process and the listener would
	// quietly answer fewer and fewer connections. A picture too big to convert
	// is just a picture we pass through.
	if width > MAX_DIMENSION || height > MAX_DIMENSION {
		log::debug!("not re-encoding a {width}x{height} image: past what webp can hold");

		return None;
	}

	if u64::from(width) * u64::from(height) > max_pixels {
		log::debug!(
			"not re-encoding a {width}x{height} image: more pixels than [images] \
			 max_megapixels allows"
		);

		return None;
	}

	let decoded = image::ImageReader::new(Cursor::new(body))
		.with_guessed_format()
		.ok()?
		.decode()
		.ok()?;

	// Read before the conversion below consumes it.
	let has_alpha = decoded.color().has_alpha();

	// Transparency has to survive, or a logo comes out on a black square.
	//
	// `into_` rather than `to_`, so the pixels are moved where the layout
	// already matches instead of copied — the copy doubled the peak for every
	// image, and the peak is the thing being bounded.
	//
	// `encode_simple` rather than `encode` for the same reason as the guard
	// above: it hands back an error where `encode` unwraps one.
	let encoded = if has_alpha {
		webp::Encoder::from_rgba(&decoded.into_rgba8(), width, height)
			.encode_simple(false, quality)
	} else {
		webp::Encoder::from_rgb(&decoded.into_rgb8(), width, height)
			.encode_simple(false, quality)
	}
	.ok()?;

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
			peer: None,
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

	/// A fresh settings file per call. It used to be a fixed name under the
	/// system temp directory, so anything another checkout — or another user —
	/// left there was deserialised into these tests: an `image_quality: "off"`
	/// in that file turns every assertion below red with no code change.
	/// For the tests that are about something other than the pixel budget.
	const NO_PIXEL_LIMIT: u64 = u64::MAX;

	fn images() -> Images {
		let dir = tempfile::TempDir::new().expect("a settings directory");
		let store = crate::settings::Store::load(dir.path().join("settings.json"));
		// The directory only has to outlive the load; the store keeps the path
		// and writes to it only when something is set, which no test here does.
		drop(dir);

		Images {
			configured: 80,
			settings: Arc::new(store),
			cache: None,
			max_pixels: u64::from(crate::config::Images::default().max_megapixels) * 1_000_000,
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

		let converted = to_webp(&original, 80.0, NO_PIXEL_LIMIT).expect("it converts");
		let features = webp::BitstreamFeatures::new(&converted).expect("a webp");

		assert!(
			features.has_alpha(),
			"a logo must not come back on a black square"
		);
		assert_eq!((features.width(), features.height()), (100, 100));
	}

	/// libwebp refuses anything past `WEBP_MAX_DIMENSION`, and the `webp`
	/// crate's `encode` unwraps that refusal. Before the guard this test did
	/// not fail, it panicked — which in an h3 worker means the thread is gone
	/// for good and the listener answers one fewer connection from then on.
	#[test]
	fn an_image_too_wide_for_webp_is_passed_through() {
		let wide = png(MAX_DIMENSION + 1, 2);

		assert_eq!(
			to_webp(&wide, 80.0, NO_PIXEL_LIMIT),
			None,
			"too wide to convert is not a reason to crash"
		);
	}

	/// A decoded frame is width × height × 4 bytes whatever the file compressed
	/// to, so the bytes that arrived bound nothing: this is a couple of hundred
	/// kilobytes of flat-colour PNG and forty megabytes of pixels, and there
	/// are two worker pools that would each hold one.
	#[test]
	fn a_picture_with_more_pixels_than_allowed_is_passed_through() {
		let big = png(1_000, 1_000);

		assert_eq!(
			to_webp(&big, 80.0, 500_000),
			None,
			"a megapixel against a half-megapixel limit"
		);
		assert!(
			to_webp(&big, 80.0, 2 * 1_000_000).is_some(),
			"and it converts when the limit allows it, so the refusal is the \
			 limit and not the image"
		);
	}

	#[test]
	fn an_image_at_the_limit_still_converts() {
		let edge = png(MAX_DIMENSION, 2);

		assert!(
			to_webp(&edge, 80.0, NO_PIXEL_LIMIT).is_some(),
			"16383 is allowed, and must stay allowed"
		);
	}

	/// The `accept` a browser sends for a top-level navigation. It contains
	/// `image/` further down the list, which is why the looser test the
	/// blocklist uses is not good enough here.
	const NAVIGATION: &str =
		"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8";

	/// What Chrome sends for an `<img>`.
	const IMG: &str = "image/avif,image/webp,image/apng,image/*,*/*;q=0.8";

	/// `Images` with a settings store of its own.
	///
	/// `settings::shared` is a process-global `OnceLock`, so two tests moving
	/// the quality tier at once see each other's writes. Giving each its own
	/// store on a temporary path is what keeps them independent.
	fn at_tier(tier: crate::settings::Quality) -> (Images, tempfile::TempDir) {
		let dir = tempfile::TempDir::new().unwrap();
		let store = crate::settings::Store::load(dir.path().join("settings.json"));
		store.set(crate::settings::Settings {
			image_quality: tier,
			..Default::default()
		});

		let mut images = Images::new(&Config::default());
		images.settings = Arc::new(store);

		(images, dir)
	}

	fn with(pairs: &[(&str, &str)]) -> ProxyRequest {
		ProxyRequest {
			method: "GET".to_string(),
			url: "https://example.com/photo.jpg".to_string(),
			headers: headers(pairs),
			body: Vec::new(),
			peer: None,
		}
	}

	#[test]
	fn an_image_request_is_told_apart_from_a_page_that_would_accept_one() {
		assert!(is_image_request(&with(&[("accept", IMG)])));
		assert!(
			!is_image_request(&with(&[("accept", NAVIGATION)])),
			"a navigation lists image/ too; stripping it would blank the page"
		);

		// Where the browser says outright, that is what is believed — even
		// when `accept` disagrees, which it does on exactly this fetch.
		assert!(is_image_request(&with(&[
			("sec-fetch-dest", "image"),
			("accept", "*/*"),
		])));
		assert!(!is_image_request(&with(&[
			("sec-fetch-dest", "document"),
			("accept", IMG),
		])));

		// And a request that says nothing is left alone rather than guessed at.
		assert!(!is_image_request(&with(&[("user-agent", "curl/8")])));
	}

	#[test]
	fn text_only_answers_the_image_without_asking_the_origin() {
		let (images, _dir) = at_tier(crate::settings::Quality::None);

		let answer = images
			.on_request(&mut with(&[("sec-fetch-dest", "image")]))
			.expect("answered on the spot");

		assert_eq!(answer.status, 200);
		assert_eq!(answer.body, TRANSPARENT_GIF.to_vec());
		assert!(answer
			.headers
			.iter()
			.any(|(n, v)| n == "content-type" && v == "image/gif"));

		// The setting can change at any moment from a phone, so nothing this
		// produced may outlive it.
		assert!(
			answer
				.headers
				.iter()
				.any(|(n, v)| n == "cache-control" && v == "no-store"),
			"a cached pixel would leave blanks after switching back"
		);

		// The page itself must still be fetched.
		assert!(images
			.on_request(&mut with(&[("accept", NAVIGATION)]))
			.is_none());
	}

	#[test]
	fn every_other_tier_still_fetches_the_image() {
		for tier in [
			crate::settings::Quality::Auto,
			crate::settings::Quality::High,
			crate::settings::Quality::Low,
			// `Off` is the one worth naming: it means "do not re-encode", not
			// "do not fetch", and confusing the two is what this tier exists
			// to stop.
			crate::settings::Quality::Off,
		] {
			let (images, _dir) = at_tier(tier);

			assert!(
				images
					.on_request(&mut with(&[("sec-fetch-dest", "image")]))
					.is_none(),
				"{tier:?} must still go to the origin"
			);
		}
	}

	fn image_head(kind: &str) -> ResponseHead {
		ResponseHead {
			status: 200,
			headers: headers(&[("content-type", kind)]),
		}
	}

	#[test]
	fn text_only_strips_an_image_the_request_did_not_announce() {
		// What a script-fetched image looks like: nothing in the request says
		// image, so only the origin's answer gives it away.
		let (images, _dir) = at_tier(crate::settings::Quality::None);
		let req = with(&[("sec-fetch-dest", "empty"), ("accept", "*/*")]);

		assert!(
			images
				.on_request(&mut with(&[("sec-fetch-dest", "empty"), ("accept", "*/*")]))
				.is_none(),
			"not caught on the request"
		);
		assert!(
			images.wants_body(&req, &image_head("image/jpeg")),
			"so the body has to be claimed in order to throw it away"
		);

		let mut resp = ProxyResponse {
			status: 200,
			headers: headers(&[
				("content-type", "image/jpeg"),
				("content-length", "72790"),
				("etag", "\"abc\""),
				("cache-control", "public, max-age=31536000"),
			]),
			body: vec![0u8; 72_790],
		};
		images.on_response(&req, &mut resp);

		assert_eq!(resp.body, TRANSPARENT_GIF.to_vec());
		assert!(resp.headers.iter().any(|(n, v)| n == "content-type" && v == "image/gif"));
		assert!(
			resp.headers.iter().any(|(n, v)| n == "cache-control" && v == "no-store"),
			"the origin's year-long max-age must not survive the swap"
		);
		assert!(
			!resp.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("etag")),
			"a validator from the real image would revalidate back to a pixel"
		);
		assert!(
			!resp.headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("content-length")),
			"the length described a body that is gone"
		);
	}

	#[test]
	fn text_only_leaves_everything_that_is_not_an_image_alone() {
		let (images, _dir) = at_tier(crate::settings::Quality::None);
		let req = with(&[("sec-fetch-dest", "empty"), ("accept", "*/*")]);

		for kind in ["text/html", "application/json", "text/css", "font/woff2"] {
			assert!(
				!images.wants_body(&req, &image_head(kind)),
				"{kind} must keep streaming"
			);

			let mut resp = ProxyResponse {
				status: 200,
				headers: headers(&[("content-type", kind)]),
				body: b"the page itself".to_vec(),
			};
			images.on_response(&req, &mut resp);
			assert_eq!(resp.body, b"the page itself", "{kind} was rewritten");
		}
	}

	#[test]
	fn no_other_tier_claims_a_body_it_only_means_to_discard() {
		// `wants_body` taking a response off streaming is the expensive
		// mistake in this file, so every tier is asked directly.
		let req = with(&[("accept", "text/html")]);

		for tier in [
			crate::settings::Quality::Auto,
			crate::settings::Quality::High,
			crate::settings::Quality::Low,
			crate::settings::Quality::Off,
		] {
			let (images, _dir) = at_tier(tier);
			assert!(
				!images.wants_body(&req, &image_head("image/jpeg")),
				"{tier:?} claimed a body for a client that never asked for webp"
			);
		}
	}
}
