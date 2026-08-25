//! The domain blocklist — first-stage ad blocking.
//!
//! This is built in rather than shipped as a plugin for two reasons: matching a
//! hundred thousand domains on every single request has no business crossing a
//! JSON pipe into another process, and blocking should keep working with
//! plugins turned off entirely.
//!
//! It is deliberately *only* a domain matcher. Real ad blockers also carry
//! URL-pattern rules, cosmetic filters and regexes; those lines are skipped
//! here rather than half-honoured, because a general-purpose filter engine is a
//! different project.
//!
//! Lists are parsed leniently and from any of the three formats in common use —
//! hosts files, bare domains, and Adblock's `||domain^` anchors — because the
//! popular lists mix them freely.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::config::Config;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse, ResponseHead};

/// A 1×1 transparent GIF. Serving this rather than an empty body keeps a
/// blocked image from leaving a broken-image icon in the page.
const TRANSPARENT_GIF: [u8; 43] = [
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
];

/// Names a hosts file points at loopback for its own housekeeping. Blocking
/// them would be pointless at best and confusing at worst.
const HOUSEKEEPING: [&str; 4] = [
	"localhost",
	"localhost.localdomain",
	"local",
	"broadcasthost",
];

/// Two sets of domains: what to block, and what to never block.
pub struct Blocklist {
	blocked: HashSet<String>,
	allowed: HashSet<String>,
}

impl Blocklist {
	fn new(allow: &[String]) -> Self {
		Self {
			blocked: HashSet::new(),
			allowed: allow
				.iter()
				.filter_map(|domain| normalize(domain))
				.collect(),
		}
	}

	/// Read every list, skipping — with a warning — any that cannot be read. A
	/// missing list is not worth refusing to start over.
	pub fn load(files: &[PathBuf], allow: &[String]) -> Self {
		let mut list = Self::new(allow);
		let mut read = 0;

		for path in files {
			match std::fs::read_to_string(path) {
				Ok(text) => {
					list.add(&text);
					read += 1;
				}
				Err(e) => log::warn!("cannot read blocklist {}: {e}", path.display()),
			}
		}

		log::info!(
			"blocklist: {} domains from {read} of {} file(s)",
			list.blocked.len(),
			files.len()
		);

		list
	}

	fn add(&mut self, text: &str) {
		for line in text.lines() {
			match parse(line) {
				Some(Rule::Block(domain)) => {
					self.blocked.insert(domain);
				}
				Some(Rule::Allow(domain)) => {
					self.allowed.insert(domain);
				}
				None => {}
			}
		}
	}

	pub fn is_empty(&self) -> bool {
		self.blocked.is_empty()
	}

	/// True when this host, or any domain it sits under, is listed — so
	/// `doubleclick.net` covers `ad.g.doubleclick.net`. An allowance wins
	/// outright, whatever the lists say.
	pub fn blocks(&self, host: &str) -> bool {
		!covers(&self.allowed, host) && covers(&self.blocked, host)
	}
}

/// Load once per process. Every worker builds its own chain, so a list parsed
/// per chain would be held in memory a couple of dozen times over.
pub fn shared(config: &Config) -> Arc<Blocklist> {
	static SHARED: OnceLock<Arc<Blocklist>> = OnceLock::new();

	SHARED
		.get_or_init(|| {
			Arc::new(Blocklist::load(
				&config.blocklist.files,
				&config.blocklist.allow,
			))
		})
		.clone()
}

/// The chain link is the `Arc`, not the list: every chain shares one load.
impl Interceptor for Arc<Blocklist> {
	fn on_request(&self, req: &mut ProxyRequest) -> Option<ProxyResponse> {
		let host = crate::host_of(&req.url);
		if !self.blocks(host) {
			return None;
		}

		log::debug!("blocked {host}");

		Some(blocked(req))
	}

	/// Decides on the request alone, so it must never be the reason a response
	/// body is held in memory instead of streaming.
	fn wants_body(&self, _req: &ProxyRequest, _head: &ResponseHead) -> bool {
		false
	}
}

/// Answer a blocked request without touching the origin.
fn blocked(req: &ProxyRequest) -> ProxyResponse {
	let mut headers = vec![
		// A blocked response must never outlive the rule that produced it.
		("cache-control".to_string(), "no-store".to_string()),
		("x-mach5".to_string(), "blocked".to_string()),
	];

	if wants_image(req) {
		headers.push(("content-type".to_string(), "image/gif".to_string()));

		return ProxyResponse {
			status: 200,
			headers,
			body: TRANSPARENT_GIF.to_vec(),
		};
	}

	ProxyResponse {
		status: 204,
		headers,
		body: Vec::new(),
	}
}

fn wants_image(req: &ProxyRequest) -> bool {
	req.headers.iter().any(|(name, value)| {
		name.eq_ignore_ascii_case("accept") && value.to_ascii_lowercase().contains("image/")
	})
}

/// Whether the host, or any domain above it, is in the set. Walking the parents
/// is what makes this label-aware: `notdoubleclick.net` never reaches
/// `doubleclick.net`, where a substring test would have matched it.
fn covers(set: &HashSet<String>, host: &str) -> bool {
	if set.is_empty() {
		return false;
	}

	let host = host.trim_end_matches('.').to_ascii_lowercase();

	std::iter::successors(Some(host.as_str()), |name| {
		name.split_once('.').map(|(_label, parent)| parent)
	})
	.any(|name| set.contains(name))
}

enum Rule {
	Block(String),
	Allow(String),
}

/// Parse one line of a list in whichever of the three formats it happens to be.
/// Anything else — cosmetic rules, URL patterns, regexes — is silently skipped.
fn parse(line: &str) -> Option<Rule> {
	let line = line.trim();
	if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
		return None;
	}

	if let Some(rule) = line.strip_prefix("@@") {
		return Some(Rule::Allow(normalize(anchored(rule)?)?));
	}

	if line.starts_with("||") {
		return Some(Rule::Block(normalize(anchored(line)?)?));
	}

	// A hosts file line: an address, then the name it is being pointed at.
	if let Some((_address, rest)) = line.split_once(char::is_whitespace) {
		let name = rest.split_whitespace().next()?;

		return Some(Rule::Block(normalize(name)?));
	}

	Some(Rule::Block(normalize(line)?))
}

/// The domain of an Adblock anchor rule, `||ads.example.com^$third-party`.
/// Options after the separator are ignored; wildcards and paths mean the rule
/// is more than a domain match, so it is not ours to honour.
fn anchored(rule: &str) -> Option<&str> {
	let rest = rule.strip_prefix("||")?;
	let domain = rest.split(['^', '$']).next().unwrap_or(rest);

	(!domain.contains(['*', '/'])).then_some(domain)
}

/// A name a hosts file points at loopback for its own sake, not to block it.
/// The `ip6-*` family are the same idea.
fn housekeeping(domain: &str) -> bool {
	HOUSEKEEPING.contains(&domain) || domain.starts_with("ip6-")
}

/// Lowercase and drop a trailing root dot. Single-label names are rejected: a
/// stray `localhost`, or the remains of a line we misread, would otherwise be a
/// parent of nothing useful — or, worse, of everything.
fn normalize(raw: &str) -> Option<String> {
	let domain = raw.trim().trim_end_matches('.').to_ascii_lowercase();

	if !domain.contains('.') || housekeeping(&domain) {
		return None;
	}

	let plausible = domain.split('.').all(|label| {
		!label.is_empty()
			&& label
				.chars()
				.all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
	});

	plausible.then_some(domain)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn list(text: &str) -> Blocklist {
		let mut list = Blocklist::new(&[]);
		list.add(text);

		list
	}

	fn request(url: &str, accept: &str) -> ProxyRequest {
		ProxyRequest {
			method: "GET".to_string(),
			url: url.to_string(),
			headers: vec![("accept".to_string(), accept.to_string())],
			body: Vec::new(),
		}
	}

	#[test]
	fn every_common_line_format_parses() {
		let list = list(
			"0.0.0.0 ads.example.com\n\
			 127.0.0.1\ttracker.example.net\n\
			 bare.example.org\n\
			 ||anchored.example.com^\n\
			 ||options.example.com^$third-party\n",
		);

		assert!(list.blocks("ads.example.com"));
		assert!(list.blocks("tracker.example.net"));
		assert!(list.blocks("bare.example.org"));
		assert!(list.blocks("anchored.example.com"));
		assert!(list.blocks("options.example.com"));
	}

	#[test]
	fn comments_and_blank_lines_are_ignored() {
		let list = list(
			"# a hosts file header\n\
			 \n\
			 ! an easylist header\n\
			 	\n\
			 0.0.0.0 real.example.com\n",
		);

		assert!(list.blocks("real.example.com"));
		assert!(
			!list.blocks("example.com"),
			"only the listed name is blocked"
		);
	}

	#[test]
	fn unsupported_rules_are_skipped() {
		let list = list(
			"example.com##.ad-banner\n\
			 example.com#@#.ad-banner\n\
			 ||example.com/ads/*\n\
			 ||*.example.com^\n\
			 /banner[0-9]+\\.gif/\n",
		);

		assert!(!list.blocks("example.com"));
		assert!(!list.blocks("ads.example.com"));
	}

	#[test]
	fn hosts_file_housekeeping_is_skipped() {
		let list = list(
			"127.0.0.1 localhost\n\
			 127.0.0.1 localhost.localdomain\n\
			 127.0.0.1 local\n\
			 255.255.255.255 broadcasthost\n\
			 ::1 ip6-localhost ip6-loopback\n\
			 fe00::0 ip6-localnet\n",
		);

		assert!(!list.blocks("localhost"));
		assert!(!list.blocks("localhost.localdomain"));
		assert!(!list.blocks("ip6-localhost"));
		assert!(!list.blocks("anything.example.com"));
	}

	#[test]
	fn single_label_entries_are_rejected() {
		let list = list("com\nnet\n0.0.0.0 nodot\n");

		assert!(
			!list.blocks("example.com"),
			"a bare TLD must not block a site"
		);
		assert!(!list.blocks("nodot"));
		assert_eq!(normalize("localhost"), None);
		assert_eq!(normalize("example.com."), Some("example.com".to_string()));
		assert_eq!(
			normalize("ADS.Example.COM"),
			Some("ads.example.com".to_string())
		);
	}

	#[test]
	fn parents_match_but_only_on_label_boundaries() {
		let list = list("doubleclick.net\n");

		assert!(list.blocks("doubleclick.net"));
		assert!(list.blocks("ad.g.doubleclick.net"));
		assert!(
			!list.blocks("notdoubleclick.net"),
			"substring is not a match"
		);
		assert!(!list.blocks("doubleclick.net.evil.com"));
		assert!(!list.blocks("net"));
	}

	#[test]
	fn exception_rules_win_over_a_block() {
		let list = list(
			"0.0.0.0 ads.example.com\n\
			 0.0.0.0 keep.ads.example.com\n\
			 @@||keep.ads.example.com^\n",
		);

		assert!(list.blocks("ads.example.com"));
		assert!(!list.blocks("keep.ads.example.com"));
	}

	#[test]
	fn configured_allowances_win_over_a_block() {
		let mut list = Blocklist::new(&["example.com".to_string()]);
		list.add("0.0.0.0 ads.example.com\n0.0.0.0 ads.example.net\n");

		assert!(
			!list.blocks("ads.example.com"),
			"the whole domain is allowed"
		);
		assert!(list.blocks("ads.example.net"));
	}

	#[test]
	fn an_unlisted_host_is_not_answered() {
		let list = Arc::new(list("0.0.0.0 ads.example.com\n"));
		let mut req = request("https://example.org/index.html", "text/html");

		assert!(list.on_request(&mut req).is_none());
	}

	#[test]
	fn a_blocked_page_gets_no_content() {
		let list = Arc::new(list("0.0.0.0 ads.example.com\n"));
		let mut req = request("https://ads.example.com/frame.html", "text/html");

		let resp = list.on_request(&mut req).expect("listed host is blocked");

		assert_eq!(resp.status, 204);
		assert!(resp.body.is_empty());
		assert!(resp
			.headers
			.iter()
			.any(|(k, v)| k == "cache-control" && v == "no-store"));
		assert!(resp
			.headers
			.iter()
			.any(|(k, v)| k == "x-mach5" && v == "blocked"));
	}

	#[test]
	fn a_blocked_image_gets_a_pixel() {
		let list = Arc::new(list("0.0.0.0 ads.example.com\n"));
		let mut req = request(
			"https://ads.example.com/pixel.gif",
			"image/avif,image/webp,*/*",
		);

		let resp = list.on_request(&mut req).expect("listed host is blocked");

		assert_eq!(resp.status, 200);
		assert_eq!(resp.body, TRANSPARENT_GIF);
		assert!(resp
			.headers
			.iter()
			.any(|(k, v)| k == "content-type" && v == "image/gif"));
		assert!(resp
			.headers
			.iter()
			.any(|(k, v)| k == "x-mach5" && v == "blocked"));
	}

	#[test]
	fn blocking_never_claims_a_response_body() {
		let list = Arc::new(list("0.0.0.0 ads.example.com\n"));
		let head = ResponseHead {
			status: 200,
			headers: vec![("content-type".to_string(), "video/mp4".to_string())],
		};

		assert!(
			!list.wants_body(&request("https://example.org/clip.mp4", "*/*"), &head),
			"a request-only link must not switch off streaming"
		);
	}

	#[test]
	fn an_unreadable_file_is_not_fatal() {
		let list = Blocklist::load(&[PathBuf::from("/nonexistent/blocklist.txt")], &[]);

		assert!(list.is_empty());
	}
}
