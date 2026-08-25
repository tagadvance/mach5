//! The pluggable interception seam.
//!
//! Every intercepted request passes through an [`Interceptor`] before it is
//! fetched upstream, and every response passes through on the way back. This is
//! the boundary a future out-of-process plugin layer (Python, Node, WASM) plugs
//! into — for now the hooks are in-process Rust.

/// A request about to be forwarded upstream.
pub struct ProxyRequest {
	pub method: String,
	pub url: String,
	pub headers: Vec<(String, String)>,
	pub body: Vec<u8>,
}

/// A response coming back from upstream.
pub struct ProxyResponse {
	pub status: u16,
	pub headers: Vec<(String, String)>,
	pub body: Vec<u8>,
}

/// A response's status and headers, known before its body has been read.
pub struct ResponseHead {
	pub status: u16,
	pub headers: Vec<(String, String)>,
}

/// Hooks run on the worker thread, off the QUIC event loop, so an expensive
/// interceptor cannot stall unrelated connections.
pub trait Interceptor: Send + Sync {
	/// Called before the request is forwarded. Returning `Some` short-circuits
	/// it: that response is served and the origin is never contacted, which is
	/// what a blocker or an internal proxy endpoint needs.
	///
	/// A short-circuited response is served exactly as returned. Links after the
	/// one that answered never see the request, and no
	/// [`on_response`](Self::on_response) or
	/// [`on_response_head`](Self::on_response_head) hook runs on it. That is
	/// deliberate: a blocked request should not then be rewritten by an
	/// injection plugin.
	fn on_request(&self, _req: &mut ProxyRequest) -> Option<ProxyResponse> {
		None
	}

	/// Called with the whole response once its body has been buffered — which
	/// only happens when [`wants_body`](Self::wants_body) asked for it.
	fn on_response(&self, _req: &ProxyRequest, _resp: &mut ProxyResponse) {}

	/// Called instead of [`on_response`](Self::on_response) when the body is
	/// streaming past unbuffered. Status and headers may still be changed; the
	/// body is not available.
	fn on_response_head(&self, _req: &ProxyRequest, _head: &mut ResponseHead) {}

	/// Whether this interceptor needs the whole body in memory. Returning false
	/// lets the body stream straight through, which is what large media wants.
	/// Defaults to true so an interceptor that forgets to answer still works.
	fn wants_body(&self, _req: &ProxyRequest, _head: &ResponseHead) -> bool {
		true
	}
}

/// An ordered list of interceptors, applied in sequence. Requests run through
/// in order — until one of them answers the request itself — and responses run
/// through in the same order.
pub struct Chain {
	links: Vec<Box<dyn Interceptor>>,
}

impl Chain {
	/// Build the chain described by the configuration: the loop guard, the
	/// blocklist, the proxy's own endpoints, the page injection, then the
	/// external plugins in the plugin directory, plus the optional response
	/// stamp.
	pub fn from_config(config: &crate::config::Config) -> Self {
		let mut links: Vec<Box<dyn Interceptor>> = Vec::new();

		// Ahead of everything, and not configurable: a request carrying our own
		// marker is this proxy fetching itself, and fetching it again is how the
		// box falls over.
		links.push(Box::new(crate::upstream::LoopGuard));

		// First, so a blocked request never reaches a plugin at all.
		if config.blocklist.enabled {
			let blocklist = crate::blocklist::shared(config);
			if !blocklist.is_empty() {
				links.push(Box::new(blocklist));
			}
		}

		// Before the plugins: a plugin has no business seeing — or answering —
		// the proxy's own endpoints.
		if config.internal.enabled {
			links.push(Box::new(crate::internal::Internal::new(config)));
		}

		// Before the plugins: a plugin should see the page as the origin wrote
		// it, not with our tags already spliced into it.
		if config.inject.enabled {
			links.push(Box::new(crate::inject::Inject::new(config)));
		}

		if config.plugins.enabled {
			for plugin in crate::plugin::load_all(config) {
				links.push(Box::new(plugin));
			}
		}

		if config.plugins.stamp_responses {
			links.push(Box::new(Stamp));
		}

		Self { links }
	}
}

impl Interceptor for Chain {
	/// Stops at the first link that answers, and hands that response straight
	/// back untouched by the rest of the chain.
	fn on_request(&self, req: &mut ProxyRequest) -> Option<ProxyResponse> {
		self.links.iter().find_map(|link| link.on_request(req))
	}

	fn on_response(&self, req: &ProxyRequest, resp: &mut ProxyResponse) {
		for link in &self.links {
			link.on_response(req, resp);
		}
	}

	fn on_response_head(&self, req: &ProxyRequest, head: &mut ResponseHead) {
		for link in &self.links {
			link.on_response_head(req, head);
		}
	}

	/// Buffer only if something in the chain actually wants the body.
	fn wants_body(&self, req: &ProxyRequest, head: &ResponseHead) -> bool {
		self.links.iter().any(|link| link.wants_body(req, head))
	}
}

/// Stamps every response with a marker header. Its only job is to make
/// interception observable end-to-end; it stands in for the real request/
/// response rewriting (ad blocking, injection, re-encoding) to come.
pub struct Stamp;

impl Interceptor for Stamp {
	fn on_response(&self, _req: &ProxyRequest, resp: &mut ProxyResponse) {
		stamp(&mut resp.headers);
	}

	fn on_response_head(&self, _req: &ProxyRequest, head: &mut ResponseHead) {
		stamp(&mut head.headers);
	}

	/// Touches headers only, so it never forces a body to be buffered.
	fn wants_body(&self, _req: &ProxyRequest, _head: &ResponseHead) -> bool {
		false
	}
}

fn stamp(headers: &mut Vec<(String, String)>) {
	headers.retain(|(k, _)| !k.eq_ignore_ascii_case("x-mach5"));
	headers.push(("x-mach5".to_string(), "intercepted".to_string()));
}

#[cfg(test)]
mod tests {
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::Arc;

	use super::*;

	/// Answers every request with the given status, so a chain can be tested
	/// without a live plugin.
	struct Answer(u16);

	impl Interceptor for Answer {
		fn on_request(&self, _req: &mut ProxyRequest) -> Option<ProxyResponse> {
			Some(ProxyResponse {
				status: self.0,
				headers: Vec::new(),
				body: Vec::new(),
			})
		}
	}

	/// Records that it ran and rewrites the URL, so both "was it reached" and
	/// "did rewrites still apply" are observable.
	struct Recorder {
		called: Arc<AtomicBool>,
	}

	impl Interceptor for Recorder {
		fn on_request(&self, req: &mut ProxyRequest) -> Option<ProxyResponse> {
			self.called.store(true, Ordering::SeqCst);
			req.url.push_str("?seen");

			None
		}
	}

	fn request() -> ProxyRequest {
		ProxyRequest {
			method: "GET".to_string(),
			url: "https://example.com/".to_string(),
			headers: Vec::new(),
			body: Vec::new(),
		}
	}

	fn response() -> ProxyResponse {
		ProxyResponse {
			status: 200,
			headers: vec![("content-type".to_string(), "text/html".to_string())],
			body: Vec::new(),
		}
	}

	#[test]
	fn stamp_marks_response_once() {
		let req = ProxyRequest {
			method: "GET".to_string(),
			url: "https://example.com/".to_string(),
			headers: Vec::new(),
			body: Vec::new(),
		};
		let mut resp = response();

		Stamp.on_response(&req, &mut resp);
		Stamp.on_response(&req, &mut resp);

		let stamps: Vec<_> = resp
			.headers
			.iter()
			.filter(|(k, _)| k.eq_ignore_ascii_case("x-mach5"))
			.collect();

		assert_eq!(stamps.len(), 1, "marker must not accumulate on re-run");
		assert_eq!(stamps[0].1, "intercepted");
	}

	#[test]
	fn short_circuit_stops_the_chain() {
		let called = Arc::new(AtomicBool::new(false));
		let chain = Chain {
			links: vec![
				Box::new(Answer(403)),
				Box::new(Recorder {
					called: called.clone(),
				}),
			],
		};
		let mut req = request();

		let response = chain.on_request(&mut req).expect("first link answers");

		assert_eq!(response.status, 403);
		assert!(
			!called.load(Ordering::SeqCst),
			"links after the one that answered must not run"
		);
		assert_eq!(req.url, "https://example.com/", "and must not rewrite it");
	}

	/// The default is deliberately "buffer", so a link that forgets to answer
	/// still works. The cost is that every request-only link must opt out by
	/// hand or it switches off streaming for the whole proxy.
	#[test]
	fn a_link_that_forgets_to_answer_still_buffers() {
		let chain = Chain {
			links: vec![Box::new(Recorder {
				called: Arc::new(AtomicBool::new(false)),
			})],
		};
		let head = ResponseHead {
			status: 200,
			headers: vec![("content-type".to_string(), "video/mp4".to_string())],
		};

		assert!(
			chain.wants_body(&request(), &head),
			"a link that forgets to answer still buffers, by design"
		);
	}

	#[test]
	fn a_chain_that_answers_nothing_still_rewrites() {
		let chain = Chain {
			links: vec![
				Box::new(Recorder {
					called: Arc::new(AtomicBool::new(false)),
				}),
				Box::new(Recorder {
					called: Arc::new(AtomicBool::new(false)),
				}),
			],
		};
		let mut req = request();

		assert!(chain.on_request(&mut req).is_none());
		assert_eq!(req.url, "https://example.com/?seen?seen", "both links ran");
	}
}
