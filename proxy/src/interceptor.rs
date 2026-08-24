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
	fn on_request(&self, _req: &mut ProxyRequest) {}

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
/// in order and responses run through in the same order.
pub struct Chain {
	links: Vec<Box<dyn Interceptor>>,
}

impl Chain {
	/// Build the chain described by the configuration: the external plugins in
	/// the plugin directory, plus the optional response stamp.
	pub fn from_config(config: &crate::config::Config) -> Self {
		let mut links: Vec<Box<dyn Interceptor>> = Vec::new();

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
	fn on_request(&self, req: &mut ProxyRequest) {
		for link in &self.links {
			link.on_request(req);
		}
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
	use super::*;

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
}
