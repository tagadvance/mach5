//! Talking to the real origin.
//!
//! Shared by both front ends: the QUIC/HTTP-3 listener and the TCP/HTTP-1.1
//! one. Upstream is always HTTP/1.1 or HTTP/2 over TLS, and its certificate is
//! validated — once a client installs our CA we are the only thing left
//! performing that check, so this must never be relaxed globally.

use std::time::Duration;

use crate::config::Config;
use crate::interceptor::ProxyRequest;

/// Builds the shared upstream HTTP agent.
pub fn agent(config: &Config) -> ureq::Agent {
	ureq::AgentBuilder::new()
		// Pass 3xx through to the client; it re-requests and we intercept again.
		.redirects(0)
		.timeout_connect(Duration::from_secs(config.limits.connect_timeout_seconds))
		.timeout_read(Duration::from_secs(config.limits.read_timeout_seconds))
		.build()
}

/// Perform the upstream request, mapping transport failures to a message.
pub fn call(agent: &ureq::Agent, req: &ProxyRequest) -> Result<ureq::Response, String> {
	let mut request = agent.request(&req.method, &req.url);
	for (name, value) in &req.headers {
		request = request.set(name, value);
	}

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
		// TODO: distinguish TLS validation failures and render a proper
		// interstitial with a per-host bypass instead of a plain 502.
		Err(ureq::Error::Transport(t)) => Err(format!("mach5: upstream fetch failed: {t}\n")),
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

	#[test]
	fn hop_by_hop_headers_are_recognised_case_insensitively() {
		assert!(is_hop_by_hop("Connection"));
		assert!(is_hop_by_hop("transfer-encoding"));
		assert!(is_hop_by_hop("Content-Length"));
		assert!(!is_hop_by_hop("content-type"));
		assert!(!is_hop_by_hop("x-custom"));
	}
}
