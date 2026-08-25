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

/// Builds the shared upstream HTTP agent.
pub fn agent(config: &Config) -> ureq::Agent {
	ureq::AgentBuilder::new()
		// Pass 3xx through to the client; it re-requests and we intercept again.
		.redirects(0)
		.timeout_connect(Duration::from_secs(config.limits.connect_timeout_seconds))
		.timeout_read(Duration::from_secs(config.limits.read_timeout_seconds))
		.build()
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
pub fn call(agent: &ureq::Agent, req: &ProxyRequest) -> Result<ureq::Response, FetchError> {
	let mut request = agent.request(&req.method, &req.url);
	for (name, value) in &req.headers {
		// Negotiated below instead: relaying the client's value verbatim invites
		// a coding the interceptors cannot decode.
		if name.eq_ignore_ascii_case("accept-encoding") {
			continue;
		}

		request = request.set(name, value);
	}
	request = request.set("accept-encoding", &encoding::negotiate(&req.headers));
	// Last, and with `set` rather than a push: this must be our value even when
	// the client sent one of its own, or a client could talk us out of the loop
	// check by forging it.
	request = request.set(VIA, via_id());

	let result = if req.body.is_empty() {
		request.call()
	} else {
		// ureq derives Content-Length from the payload.
		request.send_bytes(&req.body)
	};

	match result {
		Ok(resp) => Ok(resp),
		// An HTTP error status is a perfectly good response to relay.
		Err(ureq::Error::Status(_, resp)) => Ok(resp),
		Err(ureq::Error::Transport(t)) => {
			let message = t.to_string();

			Err(if is_tls_failure(&message) {
				FetchError::Tls(message)
			} else {
				FetchError::Other(message)
			})
		}
	}
}

pub fn response_headers(resp: &ureq::Response) -> Vec<(String, String)> {
	resp.headers_names()
		.into_iter()
		.filter(|name| !is_hop_by_hop(name))
		.filter_map(|name| {
			resp.header(&name)
				.map(|value| (name.clone(), value.to_string()))
		})
		.collect()
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
}
