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

/// Hooks run on the worker thread, off the QUIC event loop, so an expensive
/// interceptor cannot stall unrelated connections.
pub trait Interceptor: Send + Sync {
	fn on_request(&self, _req: &mut ProxyRequest) {}

	fn on_response(&self, _req: &ProxyRequest, _resp: &mut ProxyResponse) {}
}

/// Forwards everything unchanged.
pub struct PassThrough;

impl Interceptor for PassThrough {}

/// Stamps every response with a marker header. Its only job is to make
/// interception observable end-to-end; it stands in for the real request/
/// response rewriting (ad blocking, injection, re-encoding) to come.
pub struct Stamp;

impl Interceptor for Stamp {
	fn on_response(&self, _req: &ProxyRequest, resp: &mut ProxyResponse) {
		resp.headers
			.retain(|(k, _)| !k.eq_ignore_ascii_case("x-mach5"));
		resp.headers
			.push(("x-mach5".to_string(), "intercepted".to_string()));
	}
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
