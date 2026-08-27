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
//!
//! # Two axes, one answer
//!
//! What is served is decided by two things that are not the same question. The
//! panel's [`Quality`](crate::settings::Quality) is what the *person* asked
//! for; [`crate::link`]'s [`Tier`] is what their *connection* can carry. They
//! meet in exactly one place — [`Images::serving`] — and they meet by taking
//! whichever asks for less. Neither can talk the other up: asking for `High` on
//! a link measured at 2G still gets greyscale, and asking for no images at all
//! still gets no images however fast the link turns out to be.

use std::io::Cursor;
use std::sync::Arc;

use crate::config::Config;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse, ResponseHead};
use crate::link::{Links, Tier};
use crate::settings::Quality;

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

/// What a re-encoding *is*, past the quality number.
///
/// Part of the cache key, because the number does not imply it: greyscale at
/// quality 35 and colour at quality 35 are different pictures rather than
/// different sizes of the same one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Form {
	Colour,
	Grey,
	Placeholder,
}

impl Form {
	pub fn tag(self) -> &'static str {
		match self {
			Self::Colour => "colour",
			Self::Grey => "grey",
			Self::Placeholder => "placeholder",
		}
	}
}

/// What one image is served as, once the panel and the link have both had their
/// say. Produced only by [`Images::serving`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Serving {
	/// Exactly what the origin sent, byte for byte.
	Untouched,
	/// Re-encoded to WebP at this quality, in this form.
	Encoded(u8, Form),
	/// Not fetched at all — a transparent pixel, answered on the request where
	/// that is possible.
	Nothing,
}

/// Quality for a placeholder.
///
/// Higher than it looks like it should be, because at these dimensions the
/// number barely matters: what a placeholder costs is one frame's worth of
/// macroblock overhead, not detail it does not have. Measured on a 1200x800
/// frame, quality 5 came to 3172 bytes and quality 40 to 3612 — twelve percent
/// for the difference between a banded blur and a smooth one.
const PLACEHOLDER_QUALITY: u8 = 40;

/// The longest edge of the copy a placeholder is built from. Small enough that
/// only colour and gross composition survive and never anything readable, which
/// is as much a privacy property as a size one: a placeholder is served over a
/// link that could not carry the picture, and it should not be able to.
const PLACEHOLDER_EDGE: u32 = 16;

pub struct Images {
	/// What the configuration asked for. The panel moves around this rather
	/// than replacing it, so the config stays the thing that sets the house
	/// style.
	configured: u8,
	/// The most quality the `reduced` and `grey` link tiers may be served.
	/// Ceilings, not settings: see [`Images::serving`].
	reduced_quality: u8,
	grey_quality: u8,
	settings: Arc<crate::settings::Store>,
	/// How fast each client's own link is. Read per response, because a phone
	/// that walks out of range mid-page should finish the page differently.
	links: Arc<Links>,
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
			reduced_quality: config.images.reduced_quality,
			grey_quality: config.images.grey_quality,
			settings: crate::settings::shared(config),
			links: crate::link::shared(config),
			cache: crate::imagecache::shared(config),
			max_pixels: u64::from(config.images.max_megapixels) * 1_000_000,
			metrics: crate::metrics::shared(),
		}
	}

	/// **The one place the two axes meet.**
	///
	/// The panel says what the person wants and the link says what the wire can
	/// carry, and what is served is whichever of the two asks for less. That is
	/// the whole rule, and it has to be one rule rather than two checks in two
	/// places, because both directions are a bug: an upgrade past `Quality::None`
	/// puts pictures in front of somebody who asked for none, and a link tier
	/// ignored puts a full-quality photograph on a link that cannot carry it.
	fn serving(&self, quality: Quality, tier: Tier) -> Serving {
		// The panel's own rung on the link's ladder, so that the two can be
		// compared at all. `None` is the one setting that is a rung rather than
		// a number; the rest are numbers, and `wanted` below is where they have
		// their say. `Off` sits with `Auto` and `High` at `Full` because it is
		// the *highest* quality there is — "do not re-encode" — and is not to
		// be confused with `None`, which is no images at all.
		let asked = match quality {
			Quality::None => Tier::Nothing,
			Quality::Auto | Quality::High | Quality::Low | Quality::Off => Tier::Full,
		};

		let worse = if tier.degradation() >= asked.degradation() {
			tier
		} else {
			asked
		};

		// Below `Full` there is no way to honour `Off` — a link that cannot
		// carry the origin's bytes cannot carry them whatever the panel says —
		// so it falls back to the configured quality and the rung takes it from
		// there. Every other setting has a number of its own already.
		let wanted = quality.applied_to(self.configured).unwrap_or(self.configured);

		match worse {
			Tier::Full => match quality.applied_to(self.configured) {
				Some(quality) => Serving::Encoded(quality, Form::Colour),
				None => Serving::Untouched,
			},
			Tier::Reduced => Serving::Encoded(wanted.min(self.reduced_quality), Form::Colour),
			Tier::Grey => Serving::Encoded(wanted.min(self.grey_quality), Form::Grey),
			Tier::Placeholder => Serving::Encoded(PLACEHOLDER_QUALITY, Form::Placeholder),
			Tier::Nothing => Serving::Nothing,
		}
	}

	/// What this request is served as, panel and link together.
	fn serving_for(&self, req: &ProxyRequest) -> Serving {
		// No address is no measurement, which is not the same as a slow client:
		// a request that did not come from a connection must not be degraded on
		// the strength of not having one.
		let tier = req.peer.map_or(Tier::Full, |peer| self.links.tier(peer.ip()));

		self.serving(self.settings.get().image_quality, tier)
	}
}

impl Interceptor for Images {
	/// Text-only mode, decided on the request where that is possible so the image is never
	/// fetched. Every other tier is a trade between bytes and how the picture
	/// looks; this one is the only place the bytes stop entirely.
	///
	/// Reached either by asking for it from the panel or by having a link too
	/// slow to carry an image at all — the same answer, for the same reason.
	fn on_request(&self, req: &mut ProxyRequest) -> Option<ProxyResponse> {
		// The header scan first, because it is the cheap half and it is false
		// for almost every request. Asking what to serve takes two locks, and
		// only images are worth taking them for.
		if !is_image_request(req) || self.serving_for(req) != Serving::Nothing {
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
		let serving = self.serving_for(req);

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
		if serving == Serving::Nothing && is_image_response(&resp.headers) {
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

		// `Untouched` is the panel's `Off` on a link with nothing to say about
		// it; `Nothing` for something that was not an image after all.
		let Serving::Encoded(quality, form) = serving else {
			return;
		};

		// Keyed on the bytes in hand, so a hit is by definition the
		// re-encoding of exactly this image.
		let cached = self
			.cache
			.as_ref()
			.and_then(|cache| cache.get(&resp.body, quality, form));

		let webp = match cached {
			Some(webp) => webp,
			None => {
				let Some(webp) = to_webp(&resp.body, quality as f32, form, self.max_pixels)
				else {
					return;
				};

				if let Some(cache) = self.cache.as_ref() {
					cache.put(&resp.body, quality, form, &webp);
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

		// A reduced-quality copy is still the picture, and caching it normally
		// is the point. The two rungs below that are not: they are what one
		// link could carry at one moment, and the origin's year-long max-age
		// would keep a blur on the page long after the phone found wifi again.
		// `vary: accept` cannot help — nothing in the request changes when the
		// link does.
		if matches!(form, Form::Grey | Form::Placeholder) {
			stop_caching(&mut resp.headers);
		}

		resp.body = webp;
	}

	/// Exact, as ever: anything this claims is held in memory whole instead of
	/// streaming, so it claims images it can convert for a client that wants
	/// them and nothing else.
	fn wants_body(&self, req: &ProxyRequest, head: &ResponseHead) -> bool {
		match self.serving_for(req) {
			// Text-only wants the body precisely so it can throw it away. Only
			// for what is actually an image: claiming anything else here would
			// take the whole proxy off streaming.
			Serving::Nothing => is_image_response(&head.headers),
			// Nothing to do to it, so nothing to buffer for. Without this,
			// `image_quality: "off"` still bought every JPEG a trip through
			// memory up to `max_response_body_mb` — the whole cost of the
			// feature and none of it, since `on_response` then hands the bytes
			// straight back.
			Serving::Untouched => false,
			Serving::Encoded(..) => claims(req, head.status, &head.headers),
		}
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
			// Whatever the origin used is gone with the body it described.
			&& !name.eq_ignore_ascii_case("content-encoding")
	});

	resp.headers
		.push(("content-type".to_string(), "image/gif".to_string()));
	// Same reasoning as the request side: this must not outlive the setting,
	// and a validator kept from the real image would let the browser
	// revalidate its way back to a pixel.
	stop_caching(&mut resp.headers);
	resp.headers
		.push(("x-mach5".to_string(), "no-images".to_string()));

	resp.body = TRANSPARENT_GIF.to_vec();
}

/// Take a body out of every cache between here and the screen.
///
/// The validators go with the freshness: keeping the origin's `etag` would let
/// the browser revalidate, be told 304, and go on using the stand-in it already
/// has — which is exactly the outcome the `no-store` is there to prevent.
fn stop_caching(headers: &mut Vec<(String, String)>) {
	headers.retain(|(name, _)| {
		!name.eq_ignore_ascii_case("cache-control")
			&& !name.eq_ignore_ascii_case("expires")
			&& !name.eq_ignore_ascii_case("etag")
			&& !name.eq_ignore_ascii_case("last-modified")
	});

	headers.push(("cache-control".to_string(), "no-store".to_string()));
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
fn to_webp(body: &[u8], quality: f32, form: Form, max_pixels: u64) -> Option<Vec<u8>> {
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

	let decoded = match form {
		Form::Colour => decoded,
		// `DynamicImage::grayscale` keeps the alpha channel where there was one
		// — it answers `LumaA` for an `Rgba` input — so a transparent logo does
		// not come back on a black square. WebP has no greyscale mode of its
		// own; what makes this small is that the chroma planes come out flat,
		// and flat is what the encoder is best at.
		Form::Grey => decoded.grayscale(),
		Form::Placeholder => placeholder(&decoded, width, height),
	};

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

/// A stand-in for an image, at the image's own dimensions.
///
/// The obvious thing is a rectangle of one flat colour, and it would lay the
/// page out just as correctly. This does the LQIP trick instead: scale the
/// picture down until nothing but its gross composition survives, then scale
/// that back up to where it started. It costs two passes over a frame that is
/// already decoded and in hand, and what comes back still reads as *this*
/// picture — sky above, a dark mass in the middle, the right colours in the
/// right places.
///
/// What that is worth is measurable and is not free. On a 1200x800 frame the
/// flat rectangle came to 1788 bytes and this to 3612, because at full
/// dimensions almost all of either number is per-macroblock overhead that no
/// amount of smoothness removes. Against the 5610 bytes the same picture cost
/// at full quality, the choice is between spending a third of the budget on
/// something recognisable and spending a sixth of it on a beige box.
///
/// The dimensions are the point. Whatever this returns is the size the origin's
/// image was, so a page that sized nothing explicitly still lays out as though
/// the picture had arrived, and nothing reflows.
fn placeholder(decoded: &image::DynamicImage, width: u32, height: u32) -> image::DynamicImage {
	// At least one pixel each way: an image far wider than it is tall would
	// otherwise take its short side to zero, and a zero-sized resize is a
	// panic rather than an error.
	let scale = width.max(height).div_ceil(PLACEHOLDER_EDGE).max(1);
	let tiny = decoded.resize_exact(
		(width / scale).max(1),
		(height / scale).max(1),
		image::imageops::FilterType::Triangle,
	);

	// Gaussian on the way back up rather than the Triangle used on the way
	// down: bilinear from sixteen pixels leaves visible facets where the
	// gradients meet. It is not a size decision — the two came out two bytes
	// apart on the fixture — it is that one of them looks like a blur and the
	// other looks like a bug.
	tiny.resize_exact(width, height, image::imageops::FilterType::Gaussian)
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
			reduced_quality: crate::config::Images::default().reduced_quality,
			grey_quality: crate::config::Images::default().grey_quality,
			settings: Arc::new(store),
			links: Arc::new(Links::new(&Config::default())),
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

		let converted = to_webp(&original, 80.0, Form::Colour, NO_PIXEL_LIMIT).expect("it converts");
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
			to_webp(&wide, 80.0, Form::Colour, NO_PIXEL_LIMIT),
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
			to_webp(&big, 80.0, Form::Colour, 500_000),
			None,
			"a megapixel against a half-megapixel limit"
		);
		assert!(
			to_webp(&big, 80.0, Form::Colour, 2 * 1_000_000).is_some(),
			"and it converts when the limit allows it, so the refusal is the \
			 limit and not the image"
		);
	}

	#[test]
	fn an_image_at_the_limit_still_converts() {
		let edge = png(MAX_DIMENSION, 2);

		assert!(
			to_webp(&edge, 80.0, Form::Colour, NO_PIXEL_LIMIT).is_some(),
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

	/// The client the link tests measure. Every one of them builds its own
	/// `Links`, so they cannot see each other's measurements.
	const CLIENT: &str = "192.0.2.10:44321";

	/// A speed that lands a client squarely on each rung, well clear of the
	/// floors in `[link]`.
	fn kbps_for(tier: Tier) -> Option<u32> {
		match tier {
			// Nothing recorded at all, which is also how a real client starts.
			Tier::Full => None,
			Tier::Reduced => Some(1_000),
			Tier::Grey => Some(400),
			Tier::Placeholder => Some(120),
			Tier::Nothing => Some(20),
		}
	}

	/// `Images` with a settings store and a link store of its own, the panel
	/// set to `quality` and the client at `CLIENT` measured onto `tier`.
	fn at(quality: Quality, tier: Tier) -> Images {
		let dir = tempfile::TempDir::new().expect("a settings directory");
		let store = crate::settings::Store::load(dir.path().join("settings.json"));
		store.set(crate::settings::Settings {
			image_quality: quality,
			..Default::default()
		});
		drop(dir);

		let links = Links::new(&Config::default());
		if let Some(kbps) = kbps_for(tier) {
			// The first sample is taken at face value, so one places a client
			// anywhere on the ladder.
			links.record(from(CLIENT).ip(), kbps);
		}

		let mut images = images();
		images.settings = Arc::new(store);
		images.links = Arc::new(links);
		assert_eq!(
			images.links.tier(from(CLIENT).ip()),
			tier,
			"the fixture must actually put the client where it says"
		);

		images
	}

	fn from(peer: &str) -> std::net::SocketAddr {
		peer.parse().expect("an address")
	}

	/// A request from a measured client, as opposed to the address-less ones
	/// the rest of this file uses.
	fn by(accept: &str) -> ProxyRequest {
		ProxyRequest {
			peer: Some(from(CLIENT)),
			..request(accept)
		}
	}

	/// **The rule the whole feature rests on**, written out in both directions:
	/// the panel is a ceiling and the link is a ceiling, and what is served is
	/// under both of them.
	#[test]
	fn what_is_served_is_the_worse_of_the_two_axes() {
		let images = images();
		let (reduced, grey) = (images.reduced_quality, images.grey_quality);

		// Neither constrains the other: what the panel asked for is what it gets.
		assert_eq!(
			images.serving(Quality::Auto, Tier::Full),
			Serving::Encoded(80, Form::Colour)
		);
		assert_eq!(
			images.serving(Quality::High, Tier::Full),
			Serving::Encoded(92, Form::Colour)
		);
		assert_eq!(
			images.serving(Quality::Off, Tier::Full),
			Serving::Untouched,
			"off means untouched, which is the best there is"
		);

		// The link is the worse of the two. The panel cannot buy its way past it.
		assert_eq!(
			images.serving(Quality::High, Tier::Reduced),
			Serving::Encoded(reduced, Form::Colour),
			"asking for high on a link that cannot carry it does not carry it"
		);
		assert_eq!(images.serving(Quality::High, Tier::Grey), Serving::Encoded(grey, Form::Grey));
		assert_eq!(
			images.serving(Quality::Off, Tier::Grey),
			Serving::Encoded(grey, Form::Grey),
			"and off is a request not to re-encode, not a licence to skip the ladder"
		);
		assert_eq!(
			images.serving(Quality::High, Tier::Nothing),
			Serving::Nothing
		);

		// The panel is the worse of the two. A fast link cannot undo it.
		let low = Quality::Low.applied_to(80).unwrap();
		assert_eq!(
			images.serving(Quality::Low, Tier::Full),
			Serving::Encoded(low, Form::Colour),
			"low on a fast link is still low"
		);
		assert!(low < 80, "and low is below what the configuration asked for");
		assert_eq!(
			images.serving(Quality::Low, Tier::Reduced),
			Serving::Encoded(low.min(reduced), Form::Colour),
			"and on a reduced link it is whichever of the two is lower"
		);
		assert_eq!(
			images.serving(Quality::None, Tier::Full),
			Serving::Nothing,
			"nobody who asked for no images is handed one because the wire is quick"
		);
	}

	/// The trap named in `settings.rs`: `Off` is the *highest* quality and
	/// `None` is no images, and a ladder that confused them would answer the
	/// wrong one with a pixel.
	#[test]
	fn off_and_none_are_not_the_same_end_of_the_ladder() {
		let images = images();

		for tier in [Tier::Full, Tier::Reduced, Tier::Grey, Tier::Placeholder] {
			assert_ne!(
				images.serving(Quality::Off, tier),
				Serving::Nothing,
				"off at {tier:?} must still be a picture"
			);
			assert_eq!(
				images.serving(Quality::None, tier),
				Serving::Nothing,
				"none at {tier:?} must still be no picture"
			);
		}
	}

	/// The ceiling has to hold where it is acted on and not only where it is
	/// computed, so both directions are asked again through the hooks.
	#[test]
	fn the_ceiling_holds_through_the_hooks_in_both_directions() {
		// A fast link never fetches an image for somebody who asked for none.
		let fast = at(Quality::None, Tier::Full);
		assert!(
			fast.on_request(&mut by(IMG)).is_some(),
			"answered with the pixel, not fetched"
		);

		// And a link with nothing to spare degrades the highest setting there is.
		let original = png(300, 300);
		let mut best = response(original.clone(), "image/png");
		at(Quality::High, Tier::Full).on_response(&by("image/webp,*/*"), &mut best);

		let mut worst = response(original, "image/png");
		at(Quality::High, Tier::Grey).on_response(&by("image/webp,*/*"), &mut worst);

		assert!(
			worst.body.len() < best.body.len(),
			"high on a slow link took {} bytes against {} on a fast one",
			worst.body.len(),
			best.body.len()
		);
	}

	/// A client too slow for a picture is answered exactly as the panel's
	/// `None` is — the same pixel, through the same code.
	#[test]
	fn a_link_that_cannot_carry_an_image_is_answered_with_the_pixel() {
		let images = at(Quality::Auto, Tier::Nothing);

		let answer = images
			.on_request(&mut by(IMG))
			.expect("answered on the spot");

		assert_eq!(answer.body, TRANSPARENT_GIF.to_vec());
		assert!(answer
			.headers
			.iter()
			.any(|(n, v)| n == "cache-control" && v == "no-store"));

		// And the page itself is still fetched, however slow the link is.
		assert!(images.on_request(&mut by(NAVIGATION)).is_none());
	}

	/// Every rung has to be worth having: one that does not actually take bytes
	/// off the wire is a picture made worse for nothing.
	///
	/// The fixture is the noisy one on purpose, because it is the case the
	/// ladder is for. The ordering is *not* a property of every image: a nearly
	/// flat one compresses in greyscale to less than its own blur costs at full
	/// dimensions, and then the last two rungs cross over. What is left at that
	/// point is a few hundred bytes either way, on an image that was never the
	/// problem.
	#[test]
	fn every_rung_carries_fewer_bytes_than_the_one_above_it() {
		let original = png(600, 400);
		let mut measured = Vec::new();

		for tier in [Tier::Full, Tier::Reduced, Tier::Grey, Tier::Placeholder] {
			let mut resp = response(original.clone(), "image/png");
			at(Quality::Auto, tier).on_response(&by("image/webp,*/*"), &mut resp);
			measured.push((tier, resp.body.len()));
		}
		// The bottom rung is not fetched at all, so what reaches the client is
		// the pixel and nothing else.
		measured.push((Tier::Nothing, TRANSPARENT_GIF.len()));

		println!("original png: {} bytes", original.len());
		for (tier, bytes) in &measured {
			println!("{:>12}: {bytes} bytes", tier.label());
		}

		assert!(
			measured[0].1 < original.len(),
			"the top rung must still beat the origin"
		);
		for pair in measured.windows(2) {
			let ((above, larger), (below, smaller)) = (pair[0], pair[1]);
			assert!(
				smaller < larger,
				"{} took {smaller} bytes and {} took {larger}: the ladder does not descend",
				below.label(),
				above.label()
			);
		}
	}

	/// The point of a placeholder rather than nothing at all: the page lays out
	/// as though the picture had arrived, so nothing reflows when it has not.
	#[test]
	fn a_placeholder_keeps_the_image_its_own_dimensions() {
		let original = png(640, 360);
		let mut resp = response(original, "image/png");

		at(Quality::Auto, Tier::Placeholder).on_response(&by("image/webp,*/*"), &mut resp);

		let features = webp::BitstreamFeatures::new(&resp.body).expect("a webp");

		assert_eq!((features.width(), features.height()), (640, 360));
	}

	/// And more than a rectangle: what comes back has to still be *this*
	/// picture, or the argument for building one at all is gone.
	#[test]
	fn a_placeholder_is_a_blur_of_the_image_and_not_one_flat_colour() {
		let mut buffer = image::RgbImage::new(200, 200);
		for (x, _y, pixel) in buffer.enumerate_pixels_mut() {
			// Red down the left, blue down the right. An average colour would
			// come back purple everywhere; a downscaled copy keeps the halves.
			*pixel = if x < 100 {
				image::Rgb([220, 20, 20])
			} else {
				image::Rgb([20, 20, 220])
			};
		}
		let mut original = Vec::new();
		image::DynamicImage::ImageRgb8(buffer)
			.write_to(&mut Cursor::new(&mut original), image::ImageFormat::Png)
			.expect("a png");

		let blurred = to_webp(
			&original,
			f32::from(PLACEHOLDER_QUALITY),
			Form::Placeholder,
			NO_PIXEL_LIMIT,
		)
		.expect("it converts");

		let left = pixel_at(&blurred, 20, 100);
		let right = pixel_at(&blurred, 180, 100);

		assert!(
			left[0] > left[2] + 60,
			"the left half must still read as red, not as an average: {left:?}"
		);
		assert!(
			right[2] > right[0] + 60,
			"and the right half as blue: {right:?}"
		);
	}

	/// The argument for having a greyscale rung at all: the colour is worth
	/// bytes on its own, so taking it is not the same trade as taking quality.
	///
	/// How *much* it is worth depends entirely on the picture, and this fixture
	/// is the unflattering case. On its high-frequency noise, grey at 50 came
	/// to 92054 bytes against 91604 for colour at 35 — the same trade, near
	/// enough. On a smooth photograph the gap is far wider. The rung earns its
	/// place either way, but "greyscale compresses far harder than a quality
	/// drop" is not true of every image, and the assertion below is only the
	/// part that is.
	#[test]
	fn dropping_the_colour_takes_bytes_off_at_the_same_quality() {
		let original = png(600, 400);

		let colour = to_webp(&original, 50.0, Form::Colour, NO_PIXEL_LIMIT).expect("converts");
		let grey = to_webp(&original, 50.0, Form::Grey, NO_PIXEL_LIMIT).expect("converts");

		assert!(
			grey.len() < colour.len(),
			"grey took {} bytes against {} in colour at the same quality",
			grey.len(),
			colour.len()
		);
	}

	/// Greyscale means greyscale: a chroma channel that survived would be the
	/// whole saving gone.
	#[test]
	fn grey_has_no_colour_left_in_it() {
		let original = png(200, 200);

		let grey = to_webp(&original, 35.0, Form::Grey, NO_PIXEL_LIMIT).expect("it converts");

		for x in (0..200).step_by(7) {
			for y in (0..200).step_by(7) {
				let [r, g, b] = pixel_at(&grey, x, y);
				let spread = r.max(g).max(b) - r.min(g).min(b);
				// Not zero: WebP is lossy, and it reconstructs even a flat
				// chroma plane with a little noise in it.
				assert!(spread <= 12, "({x}, {y}) is [{r}, {g}, {b}], which has colour in it");
			}
		}
	}

	/// One pixel of an encoded WebP. The `webp` crate's `image` integration is
	/// switched off in Cargo.toml, so the decoded frame arrives as a flat RGB
	/// buffer and the indexing is ours to do.
	fn pixel_at(encoded: &[u8], x: u32, y: u32) -> [u8; 3] {
		let decoded = webp::Decoder::new(encoded).decode().expect("a webp");
		assert!(!decoded.is_alpha(), "three channels, not four");

		let at = ((y * decoded.width() + x) * 3) as usize;

		[decoded[at], decoded[at + 1], decoded[at + 2]]
	}

	/// The half of the cache key the quality number cannot carry.
	///
	/// The rungs are deliberately configured to land on the *same* quality
	/// here, which a configuration file is free to do. That is the only
	/// arrangement in which the bug shows: with the shipped numbers the three
	/// forms come out at 50, 35 and 40, so the quality alone happens to keep
	/// them apart and a key missing the form would pass unnoticed until
	/// somebody edited `[images]`.
	#[test]
	fn a_cached_copy_is_never_served_to_a_different_tier() {
		let dir = tempfile::TempDir::new().unwrap();
		let config = Config::from_str(&format!(
			"[paths]\ncache_dir = \"{}\"\n",
			dir.path().display()
		))
		.unwrap();
		let cache = Arc::new(crate::imagecache::Cache::new(&config).expect("a cache"));

		let original = png(300, 300);
		let mut served = Vec::new();

		for tier in [Tier::Reduced, Tier::Grey, Tier::Placeholder, Tier::Reduced] {
			let mut images = at(Quality::Auto, tier);
			images.cache = Some(cache.clone());
			images.reduced_quality = PLACEHOLDER_QUALITY;
			images.grey_quality = PLACEHOLDER_QUALITY;
			assert_eq!(
				images.serving(Quality::Auto, tier),
				Serving::Encoded(PLACEHOLDER_QUALITY, form_of(tier)),
				"the fixture must put all three rungs on one quality"
			);

			let mut resp = response(original.clone(), "image/png");
			images.on_response(&by("image/webp,*/*"), &mut resp);
			served.push(resp.body);
		}

		assert_ne!(served[0], served[1], "the grey client got the colour copy");
		assert_ne!(served[1], served[2], "the placeholder client got the grey copy");
		assert_ne!(served[0], served[2], "the placeholder client got the colour copy");
		assert_eq!(
			served[0], served[3],
			"and the second reduced-quality client must still hit the entry the first one wrote"
		);
	}

	fn form_of(tier: Tier) -> Form {
		match tier {
			Tier::Grey => Form::Grey,
			Tier::Placeholder => Form::Placeholder,
			_ => Form::Colour,
		}
	}

	/// A rung the *link* chose is true of one moment, and the origin's
	/// year-long max-age is not. Without this a phone that found wifi again
	/// keeps the blurs it was served on the train.
	#[test]
	fn what_the_link_degraded_is_not_left_in_the_browsers_cache() {
		let cached = |tier| {
			let mut resp = ProxyResponse {
				status: 200,
				headers: headers(&[
					("content-type", "image/png"),
					("cache-control", "public, max-age=31536000"),
					("etag", "\"abc\""),
				]),
				body: png(300, 300),
			};
			at(Quality::Auto, tier).on_response(&by("image/webp,*/*"), &mut resp);

			resp.headers
		};

		for tier in [Tier::Grey, Tier::Placeholder] {
			let headers = cached(tier);

			assert!(
				headers
					.iter()
					.any(|(n, v)| n.eq_ignore_ascii_case("cache-control") && v == "no-store"),
				"{tier:?} kept the origin's freshness"
			);
			assert!(
				!headers.iter().any(|(n, _)| n.eq_ignore_ascii_case("etag")),
				"{tier:?} kept a validator that revalidates straight back to it"
			);
		}

		// A reduced-quality copy is still the picture, and caching it normally
		// is the whole point of having a cache.
		assert!(
			cached(Tier::Reduced)
				.iter()
				.any(|(n, v)| n.eq_ignore_ascii_case("cache-control") && v.contains("max-age")),
			"a reduced copy must still be cacheable"
		);
	}

	/// `wants_body` is where an interceptor takes the whole proxy off
	/// streaming, so what the link does to it is worth asking directly.
	#[test]
	fn a_slow_link_claims_a_body_and_a_stopped_one_claims_only_what_it_discards() {
		let asking = by("image/webp,*/*");

		for tier in [Tier::Reduced, Tier::Grey, Tier::Placeholder] {
			assert!(
				at(Quality::Auto, tier).wants_body(&asking, &image_head("image/jpeg")),
				"{tier:?} has to see the body in order to shrink it"
			);
		}

		// Nothing wants an image only so it can throw it away, and wants
		// nothing else at all.
		let stopped = at(Quality::Auto, Tier::Nothing);
		assert!(stopped.wants_body(&asking, &image_head("image/jpeg")));
		assert!(!stopped.wants_body(&asking, &image_head("text/html")));

		// And `off` on a link with nothing to say still streams straight past.
		assert!(!at(Quality::Off, Tier::Full).wants_body(&asking, &image_head("image/jpeg")));
	}

	/// A request that never came from a connection has no address, and no
	/// address is no measurement — which is not the same as a slow client.
	#[test]
	fn a_request_without_an_address_is_not_treated_as_slow() {
		let images = at(Quality::Auto, Tier::Nothing);
		let mut anonymous = request(IMG);
		assert!(anonymous.peer.is_none());

		assert!(
			images.on_request(&mut anonymous).is_none(),
			"a request with nobody behind it must not be answered with a pixel"
		);
	}
}
