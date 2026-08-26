//! Talking to the real origin.
//!
//! Shared by both front ends: the QUIC/HTTP-3 listener and the TCP/HTTP-1.1
//! one. Upstream is always HTTP/1.1 or HTTP/2 over TLS, and its certificate is
//! validated — once a client installs our CA we are the only thing left
//! performing that check, so this must never be relaxed globally.

use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::encoding;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse, ResponseHead};

/// Marks a request as one this proxy issued. Set on the way out and checked on
/// the way in, so both halves of the arrangement live in one file: nothing
/// stamps this header but [`call`], and nothing reads it but [`LoopGuard`].
const VIA: &str = "x-mach5-via";

/// This process's value for [`VIA`], derived once from the process id and the
/// nanosecond it was first asked for. That is all the uniqueness the job needs:
/// two proxies on one box get different values, and an outsider cannot
/// practically guess one. Guessing it buys nothing either — the forged header
/// only gets the guesser's own request refused.
fn via_id() -> &'static str {
	static ID: OnceLock<String> = OnceLock::new();

	ID.get_or_init(|| {
		let nanos = SystemTime::now()
			.duration_since(UNIX_EPOCH)
			.map_or(0, |since| since.as_nanos());

		format!("{:x}{nanos:x}", std::process::id())
	})
}

/// Refuses a request this proxy sent to itself.
///
/// The deployment answers every DNS query with the proxy's own address, so the
/// proxy has to resolve through a different server to fetch anything for real.
/// When that is misconfigured every origin resolves back here and a fetch
/// becomes a fetch of ourselves, recursing until the machine gives up — with no
/// error anywhere to say why. [`VIA`] is what makes the second lap visible.
pub struct LoopGuard;

impl Interceptor for LoopGuard {
	fn on_request(&self, req: &mut ProxyRequest) -> Option<ProxyResponse> {
		if !is_own_request(&req.headers) {
			return None;
		}

		let host = crate::host_of(&req.url);
		log::error!("fetch loop: {host} resolves back to mach5; check the proxy's own resolver");

		Some(crate::interstitial::fetch_loop(host))
	}

	/// Decides on the request alone, so it must never be the reason a response
	/// body is held in memory instead of streaming.
	fn wants_body(&self, _req: &ProxyRequest, _head: &ResponseHead) -> bool {
		false
	}
}

/// True only for *our* marker. Another proxy's value means we are one hop in
/// somebody's chain, which is legitimate; only our own means a loop.
fn is_own_request(headers: &[(String, String)]) -> bool {
	headers
		.iter()
		.any(|(name, value)| name.eq_ignore_ascii_case(VIA) && value == via_id())
}

/// The two upstream HTTP agents, identical but for what they make of a
/// certificate.
///
/// They are a pair rather than one agent with a switch because ureq decides its
/// TLS configuration when the agent is built. Keeping the strict one as the
/// only thing [`call`] reaches for by default means the permissive one cannot
/// be selected by forgetting something.
pub struct Agents {
	strict: ureq::Agent,
	/// Used only for a host in [`crate::insecure::bypasses`]. See that module.
	permissive: ureq::Agent,
	bypasses: std::sync::Arc<crate::insecure::Bypasses>,
	cache: Option<std::sync::Arc<crate::httpcache::Cache>>,
	metrics: std::sync::Arc<crate::metrics::Metrics>,
}

/// Builds the shared upstream HTTP agents.
pub fn agents(config: &Config) -> Agents {
	let builder = || {
		ureq::AgentBuilder::new()
			// Ours, so which family an origin is reached over is a decision
			// rather than an accident of whatever the resolver felt like.
			.resolver(crate::resolver::Ordered::new(config.upstream.addresses))
			// Pass 3xx through to the client; it re-requests and we intercept again.
			.redirects(0)
			.timeout_connect(Duration::from_secs(config.limits.connect_timeout_seconds))
			.timeout_read(Duration::from_secs(config.limits.read_timeout_seconds))
	};

	// A failure to build the permissive one is not fatal: falling back to a
	// second strict agent means a bypass simply does not work, which is the
	// safe direction to fail in.
	let permissive = match crate::insecure::Unverified::new() {
		Ok(connector) => builder().tls_connector(std::sync::Arc::new(connector)).build(),
		Err(e) => {
			log::error!("cannot build the bypass TLS client, so bypasses will not work: {e}");

			builder().build()
		}
	};

	Agents {
		strict: builder().build(),
		permissive,
		bypasses: crate::insecure::bypasses(),
		cache: crate::httpcache::shared(config),
		metrics: crate::metrics::shared(),
	}
}

impl Agents {
	/// The agent to fetch this host with. Anything not explicitly waved through
	/// gets the one that validates.
	fn for_host(&self, host: &str) -> &ureq::Agent {
		if !self.bypasses.allows(host) {
			return &self.strict;
		}

		// Once per request, not once per bypass: a bypass that has been left on
		// should be impossible to miss in the log.
		log::warn!("fetching {host} WITHOUT certificate validation (bypassed)");
		self.metrics.bypassed.increment();

		&self.permissive
	}
}

/// Why an upstream fetch failed.
pub enum FetchError {
	/// The origin's certificate did not validate. Distinguished from other
	/// failures because it is the one the user must be shown and must decide
	/// about, rather than a transient network problem.
	Tls(String),
	Other(String),
}

/// Does this transport failure look like certificate validation rejecting the
/// origin? ureq collapses TLS errors into a generic transport error, so the
/// message is all there is to go on.
fn is_tls_failure(message: &str) -> bool {
	let message = message.to_ascii_lowercase();

	message.contains("invalid peer certificate")
		|| message.contains("certificate expired")
		|| message.contains("unknownissuer")
		|| message.contains("notvalidforname")
		|| message.contains("certificate not valid")
		|| message.contains("tls connection init failed")
		|| message.contains("certificate verify failed")
}

/// Perform the upstream request, mapping transport failures to a message.
///
/// `body` is how an upload gets forwarded without ever being held whole:
/// [`RequestBody::Streaming`] hands ureq a reader the front end is still
/// filling. When the client told us how long it would be, that length goes back
/// on — ureq falls back to chunked encoding without it, and enough origins
/// refuse a chunked upload that it is worth carrying through.
/// What a fetch produced: a live response to read, or one that never left the
/// disk.
///
/// A cached body still goes through the interceptors exactly as a fetched one
/// does — the cache is in the fetch, not in the chain, so a plugin cannot tell
/// the difference and does not have to.
pub enum Fetched {
	/// Boxed only to keep the two variants a similar size: a `ureq::Response`
	/// is several hundred bytes and every caller matches on this immediately.
	Live(Box<ureq::Response>),
	Stored(ProxyResponse),
}

pub fn call(
	agents: &Agents,
	req: &ProxyRequest,
	body: crate::body::RequestBody,
) -> Result<Fetched, FetchError> {
	// Only a body-less request can be answered from disk: anything carrying an
	// upload is not a repeat of something.
	let cached = match &body {
		crate::body::RequestBody::None if req.body.is_empty() => lookup(agents, req),
		_ => None,
	};

	if let Some(Cached::Fresh(response)) = cached {
		return Ok(Fetched::Stored(response));
	}

	let agent = agents.for_host(crate::host_of(&req.url));
	let mut request = agent.request(&req.method, &req.url);
	// A stale entry means the conditional request about to be sent is *ours*,
	// asking about the copy on disk.
	let revalidating = matches!(cached, Some(Cached::Stale(..)));

	for (name, value) in &req.headers {
		if !forwarded(name, value) {
			continue;
		}

		// The client's own validators ask a different question, and RFC 9110
		// §13.1.3 says a server presented with `if-none-match` must ignore
		// `if-modified-since` — so a client sending `if-none-match: *` against
		// an entry we hold on a `last-modified` alone gets a 304 for *its*
		// question, which the code below then reads as the origin confirming
		// what mach5 had stored. That is a stale asset pinned in a shared cache
		// by anyone who asks for it.
		if revalidating && conditional(name) {
			continue;
		}

		request = request.set(name, value);
	}
	request = request.set("accept-encoding", &encoding::negotiate(&req.headers));
	// Last, and with `set` rather than a push: this must be our value even when
	// the client sent one of its own, or a client could talk us out of the loop
	// check by forging it.
	request = request.set(VIA, via_id());

	// A stale entry is worth an `if-none-match` rather than a download: the
	// origin answers 304 in a couple of hundred bytes, and nothing is served
	// staler than it allowed.
	if let Some(Cached::Stale(entry, _)) = &cached {
		if let Some(etag) = &entry.etag {
			request = request.set("if-none-match", etag);
		}
		if let Some(modified) = &entry.last_modified {
			request = request.set("if-modified-since", modified);
		}
	}

	let result = match body {
		crate::body::RequestBody::Streaming { reader, length } => {
			if let Some(length) = length {
				request = request.set("content-length", &length.to_string());
			}

			request.send(reader)
		}
		// ureq derives Content-Length from the payload.
		crate::body::RequestBody::None if !req.body.is_empty() => request.send_bytes(&req.body),
		crate::body::RequestBody::None => request.call(),
	};

	let response = match result {
		Ok(resp) => resp,
		// An HTTP error status is a perfectly good response to relay.
		Err(ureq::Error::Status(_, resp)) => resp,
		Err(ureq::Error::Transport(t)) => return Err(failure(&agents.metrics, t.to_string())),
	};

	// "Nothing has changed" — so what we already had is the answer, and only a
	// few hundred bytes crossed the wire to establish it.
	if response.status() == 304 {
		if let Some(Cached::Stale(entry, body)) = cached {
			// RFC 9111 §4.3.4: what the origin said *this* time replaces what
			// was stored, header by header. Re-applying the stored ones left
			// the origin no way to shorten a lifetime, add a `vary`, or take
			// back permission to store this at all — and reset the clock to a
			// full lifetime every time it tried.
			let headers =
				crate::httpcache::refreshed_headers(&entry.headers, &response_headers(&response));

			if let Some(cache) = agents.cache.as_ref() {
				cache.metrics().origin_cache_revalidated.increment();
				cache.metrics().bytes_saved_by_origin_cache.add(body.len() as u64);

				let key = crate::httpcache::key(req);
				if crate::httpcache::eligible(req, entry.status, &headers) {
					let refreshed = crate::httpcache::entry_for(
						entry.status,
						&headers,
						crate::httpcache::now(),
					);
					cache.put(&key, &refreshed, &body);
				} else {
					// It was public when it was stored and the origin has just
					// said it is not. Keeping it would mean handing it to the
					// next person who asks.
					log::info!(
						"dropping {} from the cache: the origin no longer says it is public",
						crate::redact::url(&req.url)
					);
					cache.forget(&key);
				}
			}

			let refreshed = crate::httpcache::Entry {
				headers,
				..entry
			};

			return Ok(Fetched::Stored(crate::httpcache::as_response(
				&refreshed, body,
			)));
		}
	}

	Ok(Fetched::Live(Box::new(response)))
}

/// A stored answer, and whether it may be served without asking.
enum Cached {
	Fresh(ProxyResponse),
	Stale(crate::httpcache::Entry, Vec<u8>),
}

fn lookup(agents: &Agents, req: &ProxyRequest) -> Option<Cached> {
	let cache = agents.cache.as_ref()?;

	// The other half of the rule in `httpcache::eligible`: nothing but a GET
	// stores, and nothing but a GET is served from what was stored. Answering
	// a HEAD out of the cache would attach a body to a response that must not
	// have one.
	if !req.method.eq_ignore_ascii_case("GET") {
		return None;
	}

	// RFC 9111 §3.5. `eligible` refuses to *store* one of these; refusing to
	// serve one is the other half, or a signed-in visitor is handed the public
	// answer an anonymous one caused to be stored.
	if crate::httpcache::carries_credentials(req) {
		return None;
	}

	// A hard refresh is a client saying it does not trust what anyone has
	// stored, and it is right to be able to say so.
	let wants = crate::httpcache::client_wants(req);
	if wants == crate::httpcache::ClientWants::Nothing {
		return None;
	}
	let Some((entry, body)) = cache.get(&crate::httpcache::key(req)) else {
		cache.metrics().origin_cache_misses.increment();

		return None;
	};

	if entry.is_fresh(crate::httpcache::now())
		&& wants == crate::httpcache::ClientWants::Anything
	{
		cache.metrics().origin_cache_hits.increment();
		cache.metrics().bytes_saved_by_origin_cache.add(body.len() as u64);

		return Some(Cached::Fresh(crate::httpcache::as_response(&entry, body)));
	}

	if entry.can_revalidate() {
		return Some(Cached::Stale(entry, body));
	}

	// Stale and nothing to ask with: no better than not having it.
	cache.metrics().origin_cache_misses.increment();

	None
}

/// Whether this response is worth holding whole so it can be cached.
///
/// Nothing else buffers a stylesheet — injection claims HTML and the re-encoder
/// claims images, so an asset would otherwise stream past and never be offered
/// to the cache at all. Caching one therefore means choosing to buffer it,
/// which is only worth doing when it is going to be stored and is small enough
/// to be worth the memory.
pub fn should_store(
	agents: &Agents,
	config: &crate::config::Config,
	req: &ProxyRequest,
	status: u16,
	headers: &[(String, String)],
	declared: Option<u64>,
) -> bool {
	if agents.cache.is_none() || !crate::httpcache::eligible(req, status, headers) {
		return false;
	}

	// An unknown length means a chunked response of unknown size, which is not
	// something to take a chance on holding. It has to be passed in:
	// `content-length` is hop-by-hop and `response_headers` has already dropped
	// it by the time a caller has a header list.
	let Some(length) = declared else {
		return false;
	};

	length <= config.images.max_cacheable_mb as u64 * 1024 * 1024
}

/// Keep a response, if it is one that may be kept. Called by the front ends
/// once the origin's own bytes are in hand and before anything has rewritten
/// them.
pub fn store(agents: &Agents, req: &ProxyRequest, status: u16, headers: &[(String, String)], body: &[u8]) {
	let Some(cache) = agents.cache.as_ref() else {
		return;
	};

	if !crate::httpcache::eligible(req, status, headers) {
		return;
	}

	let entry = crate::httpcache::entry_for(status, headers, crate::httpcache::now());
	cache.put(&crate::httpcache::key(req), &entry, body);
}

/// Sort one transport failure into the two kinds, counting it on the way past.
/// Counted here rather than at the two call sites because both front ends turn
/// a [`FetchError`] into a page and neither should have to remember to.
fn failure(metrics: &crate::metrics::Metrics, message: String) -> FetchError {
	if is_tls_failure(&message) {
		metrics.tls_failures.increment();

		return FetchError::Tls(message);
	}

	metrics.upstream_failures.increment();

	FetchError::Other(message)
}

/// What the origin said the body's length was, before that header is dropped
/// for being hop-by-hop.
pub fn declared_length(resp: &ureq::Response) -> Option<u64> {
	resp.header("content-length")
		.and_then(|value| value.trim().parse::<u64>().ok())
}

/// Every header the origin sent that is ours to relay, values included.
///
/// `headers_names` yields one entry per header *line*, so a header sent twice
/// appears twice — but `header` finds only the first value, so taking one per
/// name both duplicated the first value and dropped the second entirely. That
/// is not a tidiness point: two `set-cookie` lines are how a login sets a session
/// and a CSRF token, and one of them was being thrown away. A second
/// `cache-control: private` or `vary: cookie` was invisible to the cache's
/// eligibility check for the same reason, which is how a private response ends
/// up in a shared cache.
pub fn response_headers(resp: &ureq::Response) -> Vec<(String, String)> {
	let mut seen = std::collections::HashSet::new();
	let mut headers = Vec::new();

	for name in resp.headers_names() {
		// `headers_names` lowercases, so the set is already case-folded — and
		// ureq matches names case-insensitively, so `all` finds every line
		// whatever the origin capitalised.
		if is_hop_by_hop(&name) || !seen.insert(name.clone()) {
			continue;
		}

		headers.extend(
			resp.all(&name)
				.into_iter()
				.map(|value| (name.clone(), value.to_string())),
		);
	}

	headers
}

/// Headers that make a request conditional, and therefore belong to whoever is
/// doing the conditioning.
fn conditional(name: &str) -> bool {
	matches!(
		name.to_ascii_lowercase().as_str(),
		"if-none-match" | "if-modified-since" | "if-match" | "if-unmodified-since" | "if-range"
	)
}

/// Whether a header the client sent goes to the origin as it stands.
///
/// Two do not, for unrelated reasons:
///
/// - `accept-encoding` is renegotiated, because relaying the client's value
///   verbatim invites a coding the interceptors cannot decode.
/// - `expect: 100-continue` is settled between the client and this proxy before
///   anything goes upstream — hyper answers it itself. Forwarding it asks the
///   origin for an interim response ureq does not know about: it parses the
///   `100 Continue` as *the* response and hands back a 100 with the real one
///   still on the socket. Any other expectation is passed on, so an origin can
///   refuse what it does not understand.
fn forwarded(name: &str, value: &str) -> bool {
	if name.eq_ignore_ascii_case("accept-encoding") {
		return false;
	}

	!(name.eq_ignore_ascii_case("expect") && value.trim().eq_ignore_ascii_case("100-continue"))
}

/// Hop-by-hop headers are meaningful only on a single connection and must not
/// be forwarded across the proxy (RFC 9110 §7.6.1), plus framing headers each
/// front end sets for itself.
pub fn is_hop_by_hop(name: &str) -> bool {
	matches!(
		name.to_ascii_lowercase().as_str(),
		"connection"
			| "keep-alive"
			| "proxy-authenticate"
			| "proxy-authorization"
			| "te" | "trailer"
			| "transfer-encoding"
			| "upgrade"
			| "content-length"
	)
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A conditional request mach5 sends is about the copy on *its* disk. RFC
	/// 9110 §13.1.3 says a server given `if-none-match` must ignore
	/// `if-modified-since`, so a client's `if-none-match: *` against an entry
	/// held on a `last-modified` alone got a 304 for the client's question —
	/// which the 304 handler then read as the origin confirming what mach5 had
	/// stored, and refreshed a stale body to a full lifetime for everybody.
	#[test]
	fn a_clients_own_validators_do_not_go_with_our_revalidation() {
		for name in [
			"if-none-match",
			"If-Modified-Since",
			"if-match",
			"if-unmodified-since",
			"if-range",
		] {
			assert!(conditional(name), "{name} conditions a request");
		}

		// Not conditionals, and a proxy that dropped these would break ranges
		// and content negotiation.
		for name in ["range", "if-none-matches", "accept", "etag"] {
			assert!(!conditional(name), "{name} is not a conditional");
		}
	}

	/// A header sent more than once is not a curiosity: two `set-cookie` lines
	/// are how a login hands out a session and a CSRF token in one response.
	/// Taking one value per name sent the first cookie twice and threw the
	/// second away, so signing in through the proxy quietly half-worked.
	#[test]
	fn a_header_sent_twice_arrives_twice() {
		let resp: ureq::Response = "HTTP/1.1 200 OK\r\n\
			 content-type: text/html\r\n\
			 Set-Cookie: session=abc; HttpOnly\r\n\
			 set-cookie: csrf=xyz\r\n\
			 Vary: Accept-Encoding\r\n\
			 vary: Cookie\r\n\
			 content-length: 0\r\n\
			 \r\n"
			.parse()
			.expect("a well-formed response");

		let headers = response_headers(&resp);
		let values = |name: &str| -> Vec<&str> {
			headers
				.iter()
				.filter(|(header, _)| header == name)
				.map(|(_, value)| value.as_str())
				.collect()
		};

		assert_eq!(values("set-cookie"), ["session=abc; HttpOnly", "csrf=xyz"]);
		assert_eq!(
			values("vary"),
			["Accept-Encoding", "Cookie"],
			"and the second is what tells the cache this is per-user"
		);
		assert_eq!(values("content-type"), ["text/html"]);
		assert!(
			values("content-length").is_empty(),
			"framing is still each front end's own"
		);
	}

	fn request(headers: Vec<(String, String)>) -> ProxyRequest {
		ProxyRequest {
			method: "GET".to_string(),
			url: "https://example.com/index.html".to_string(),
			headers,
			body: Vec::new(),
		}
	}

	fn via(value: &str) -> Vec<(String, String)> {
		vec![(VIA.to_string(), value.to_string())]
	}

	/// Built by hand rather than through [`agents`], so the registry and the
	/// counters belong to this test instead of to the process.
	fn agents(bypasses: std::sync::Arc<crate::insecure::Bypasses>) -> Agents {
		Agents {
			strict: ureq::AgentBuilder::new().build(),
			permissive: ureq::AgentBuilder::new().build(),
			bypasses,
			metrics: std::sync::Arc::new(crate::metrics::Metrics::default()),
			cache: None,
		}
	}

	#[test]
	fn only_a_bypassed_host_counts_as_bypassed() {
		let bypasses = std::sync::Arc::new(crate::insecure::Bypasses::default());
		bypasses.allow("staging.example.com", Duration::from_secs(60));
		let agents = agents(bypasses);

		agents.for_host("example.com");

		assert_eq!(
			agents.metrics.bypassed.get(),
			0,
			"a fetch that was validated is not a bypass"
		);

		agents.for_host("staging.example.com");

		assert_eq!(agents.metrics.bypassed.get(), 1);
	}

	#[test]
	fn a_failure_is_counted_as_the_kind_it_is() {
		let metrics = crate::metrics::Metrics::default();

		let tls = failure(&metrics, "invalid peer certificate: Expired".to_string());
		let other = failure(&metrics, "connection refused".to_string());

		assert!(matches!(tls, FetchError::Tls(_)));
		assert!(matches!(other, FetchError::Other(_)));
		assert_eq!(metrics.tls_failures.get(), 1);
		assert_eq!(metrics.upstream_failures.get(), 1);
	}

	#[test]
	fn the_marker_is_stable_within_a_process() {
		assert!(!via_id().is_empty());
		assert_eq!(via_id(), via_id());
	}

	#[test]
	fn our_own_marker_is_a_loop() {
		let mut req = request(via(via_id()));

		let resp = LoopGuard
			.on_request(&mut req)
			.expect("our own marker means we are fetching ourselves");

		assert_eq!(resp.status, 508);
	}

	#[test]
	fn another_proxys_marker_is_not_a_loop() {
		let mut req = request(via("2a1f9c00deadbeef"));

		assert!(
			LoopGuard.on_request(&mut req).is_none(),
			"another proxy in the chain is not a loop"
		);
	}

	#[test]
	fn an_unmarked_request_is_not_a_loop() {
		let mut req = request(vec![("accept".to_string(), "*/*".to_string())]);

		assert!(LoopGuard.on_request(&mut req).is_none());
	}

	#[test]
	fn the_marker_is_recognised_whatever_its_case() {
		let mut req = request(vec![("X-Mach5-Via".to_string(), via_id().to_string())]);

		assert!(LoopGuard.on_request(&mut req).is_some());
	}

	#[test]
	fn the_guard_never_claims_a_response_body() {
		let head = ResponseHead {
			status: 200,
			headers: vec![("content-type".to_string(), "video/mp4".to_string())],
		};

		assert!(
			!LoopGuard.wants_body(&request(Vec::new()), &head),
			"a request-only link must not switch off streaming"
		);
	}

	#[test]
	fn hop_by_hop_headers_are_recognised_case_insensitively() {
		assert!(is_hop_by_hop("Connection"));
		assert!(is_hop_by_hop("transfer-encoding"));
		assert!(is_hop_by_hop("Content-Length"));
		assert!(!is_hop_by_hop("content-type"));
		assert!(!is_hop_by_hop("x-custom"));
	}

	/// ureq has no notion of an interim response: it reads the `100 Continue`
	/// an origin sends back as the response itself, and the real one is left on
	/// the socket. The expectation was answered by this proxy anyway.
	#[test]
	fn a_100_continue_expectation_is_not_forwarded() {
		assert!(!forwarded("expect", "100-continue"));
		assert!(!forwarded("Expect", " 100-Continue "));

		// Anything else is the origin's to refuse.
		assert!(forwarded("expect", "some-future-thing"));
		assert!(forwarded("expect-ct", "max-age=0"));

		// The other one that never goes as it came.
		assert!(!forwarded("accept-encoding", "zstd"));
		assert!(forwarded("accept", "text/html"));
	}
}
