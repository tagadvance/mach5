//! External interceptor plugins.
//!
//! A plugin is any executable in the plugin directory. It is started once and
//! kept running, and speaks newline-delimited JSON on stdin/stdout — one JSON
//! object per line in, one per line out — so it can be written in Python, Node,
//! Go, or anything else that can read a line and print a line.
//!
//! Request hook, sent to the plugin:
//! ```json
//! {"hook":"request","method":"GET","url":"https://…","headers":[["a","b"]],"body_b64":""}
//! ```
//! Response hook:
//! ```json
//! {"hook":"response","method":"GET","url":"https://…","status":200,
//!  "headers":[["a","b"]],"body_b64":"…"}
//! ```
//!
//! The plugin replies with one JSON object carrying whichever fields it wants
//! to change; anything it omits is left alone. Replying `{}` means "no change".
//! Bodies are base64 so arbitrary binary survives the text protocol.
//!
//! A `status` on a reply to the *request* hook is special: it means the plugin
//! is answering the request itself, and the origin is never contacted. The
//! reply's `headers` and `body_b64` become the response — both default to empty
//! — and `method`/`url` are ignored. Nothing downstream sees it: later plugins
//! do not get the request, and no response hook runs on what is served.
//!
//! Chunk hook, sent only to a plugin whose `init` reply set `"chunks": true`,
//! once per chunk of a body streaming past unbuffered:
//! ```json
//! {"hook":"chunk","method":"GET","url":"https://…","body_b64":"…"}
//! ```
//! The reply's `body_b64` replaces that chunk; `{}` leaves it alone; an empty
//! `body_b64` drops it, which is how a plugin accumulating across chunks says
//! "not yet". The stream ends with one more:
//! ```json
//! {"hook":"chunk","method":"GET","url":"https://…","final":true}
//! ```
//! carrying no `body_b64`. A `body_b64` in *that* reply is appended after the
//! last chunk, which is how the accumulated state gets flushed.
//!
//! Chunks and buffering are exclusive: a plugin that asks for chunks never
//! claims the body, since buffering it whole is what the chunk hook exists to
//! avoid. A plugin that declares both gets chunks.
//!
//! **A streaming body still carries the origin's `content-encoding`.** Only
//! buffered bodies are decoded and re-encoded (see `encoding.rs`), so a
//! chunk hook sees the bytes exactly as the origin sent them — usually brotli
//! or gzip, and split at arbitrary byte boundaries. A plugin that wants plain
//! text should claim the body instead.
//!
//! Chunks are not free: they cost a base64 round trip per 64KB chunk per
//! plugin. Ask for them only when seeing the body progressively is the point.
//!
//! A plugin that dies, times out, or emits nonsense is abandoned — the proxy
//! logs it and forwards traffic unmodified rather than failing the request.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse, ResponseHead};
use crate::metrics::Metrics;

/// What the proxy sends to a plugin.
#[derive(Serialize)]
struct Hook<'a> {
	hook: &'a str,
	method: &'a str,
	url: &'a str,
	#[serde(skip_serializing_if = "Option::is_none")]
	status: Option<u16>,
	/// Absent on the chunk hook, which is about bytes rather than metadata.
	#[serde(skip_serializing_if = "Option::is_none")]
	headers: Option<&'a [(String, String)]>,
	/// Absent when the body is streaming past unbuffered.
	#[serde(skip_serializing_if = "Option::is_none")]
	body_b64: Option<String>,
	/// True when the body is not included and cannot be changed.
	#[serde(skip_serializing_if = "std::ops::Not::not")]
	streaming: bool,
	/// True on the one chunk hook that marks the end of a streaming body.
	#[serde(rename = "final", skip_serializing_if = "std::ops::Not::not")]
	is_final: bool,
}

/// What a plugin may send back. Every field is optional: omitted means unchanged.
#[derive(Deserialize, Default)]
#[serde(default)]
struct Reply {
	method: Option<String>,
	url: Option<String>,
	status: Option<u16>,
	headers: Option<Vec<(String, String)>>,
	body_b64: Option<String>,
}

/// A plugin's answer to the `init` hook, declaring what it wants to see.
#[derive(Deserialize, Default)]
#[serde(default)]
struct InitReply {
	#[serde(rename = "match")]
	filter: Filter,
	/// Whether the request hook should carry the uploaded body.
	request_body: bool,
	/// Ask for the body a chunk at a time instead of whole. Exclusive with
	/// claiming the body: see [`Plugin::wants_body`].
	chunks: bool,
}

/// Header constraints deciding whether a plugin sees a given exchange. Every
/// named header must match — they are ANDed — so a plugin can require, say,
/// both an `accept` on the request and a `content-type` on the response. Any
/// header works, including custom `x-*` ones. An empty filter matches
/// everything.
#[derive(Deserialize, Default, Debug)]
#[serde(default)]
struct Filter {
	request: BTreeMap<String, String>,
	response: BTreeMap<String, String>,
}

impl Filter {
	fn is_empty(&self) -> bool {
		self.request.is_empty() && self.response.is_empty()
	}
}

/// Does every constraint find a matching header? Names compare
/// case-insensitively and values match as a case-insensitive substring, so
/// `text/html` matches `text/html; charset=utf-8`.
fn headers_match(constraints: &BTreeMap<String, String>, headers: &[(String, String)]) -> bool {
	constraints.iter().all(|(name, needle)| {
		let needle = needle.to_ascii_lowercase();

		headers.iter().any(|(header, value)| {
			header.eq_ignore_ascii_case(name)
				&& value.to_ascii_lowercase().contains(needle.as_str())
		})
	})
}

pub struct Plugin {
	name: String,
	/// Declared at `init`: this plugin wants uploads in memory rather than
	/// streaming past it.
	request_body: bool,
	timeout: Duration,
	filter: Filter,
	/// Declared once at `init`: this plugin takes streaming bodies a chunk at a
	/// time.
	chunks: bool,
	/// Whether the response currently streaming past is one this plugin asked
	/// for chunks of. The chunk hooks carry no [`ResponseHead`] to re-test the
	/// filter against, so the answer is recorded when `wants_chunks` is asked.
	/// A chain is owned by one worker and relays one response at a time, so a
	/// single flag is enough.
	chunking: AtomicBool,
	io: Mutex<Option<Io>>,
	/// Where each hook call's cost is recorded, so the status page can say
	/// which plugin is the expensive one.
	metrics: Arc<Metrics>,
}

/// The live channels to a running plugin. Replaced with `None` once the plugin
/// is abandoned.
struct Io {
	child: Child,
	stdin: ChildStdin,
	/// Lines read by a dedicated thread, so a hung plugin hits a timeout instead
	/// of blocking a worker forever.
	lines: Receiver<String>,
}

/// Start every executable in the configured plugin directory, in filename order.
pub fn load_all(config: &Config) -> Vec<Plugin> {
	let dir = &config.plugins.dir;
	let timeout = Duration::from_secs(config.limits.plugin_timeout_seconds);

	let mut paths = match executables_in(dir) {
		Ok(paths) => paths,
		Err(e) => {
			// A missing plugin directory is normal, not an error.
			if e.kind() != std::io::ErrorKind::NotFound {
				log::warn!("cannot read plugin dir {}: {e}", dir.display());
			}

			return Vec::new();
		}
	};
	paths.sort();

	paths
		.iter()
		.filter_map(|path| match Plugin::start(path, timeout) {
			Ok(plugin) => Some(plugin),
			Err(e) => {
				log::error!("failed to start plugin {}: {e}", path.display());

				None
			}
		})
		.collect()
}

fn executables_in(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
	use std::os::unix::fs::PermissionsExt;

	let mut out = Vec::new();
	for entry in std::fs::read_dir(dir)? {
		let entry = entry?;
		let path = entry.path();
		let meta = entry.metadata()?;

		if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
			out.push(path);
		}
	}

	Ok(out)
}

impl Plugin {
	fn start(path: &Path, timeout: Duration) -> std::io::Result<Self> {
		let mut child = Command::new(path)
			.stdin(Stdio::piped())
			.stdout(Stdio::piped())
			// Leave stderr attached so a plugin's own logging reaches the console.
			.stderr(Stdio::inherit())
			.spawn()?;

		let stdin = child.stdin.take().expect("stdin was piped");
		let stdout = child.stdout.take().expect("stdout was piped");

		let (tx, lines) = std::sync::mpsc::channel();
		std::thread::spawn(move || {
			for line in BufReader::new(stdout).lines() {
				let Ok(line) = line else {
					break;
				};
				if tx.send(line).is_err() {
					break;
				}
			}
		});

		let name = path
			.file_name()
			.map(|n| n.to_string_lossy().into_owned())
			.unwrap_or_else(|| path.display().to_string());

		let mut plugin = Self {
			name,
			timeout,
			filter: Filter::default(),
			request_body: false,
			chunks: false,
			chunking: AtomicBool::new(false),
			io: Mutex::new(Some(Io {
				child,
				stdin,
				lines,
			})),
			metrics: crate::metrics::shared(),
		};

		// Ask what it wants to see. A plugin that ignores the init hook keeps
		// the empty filter and therefore sees everything.
		let init = plugin
			.call::<_, InitReply>(&serde_json::json!({ "hook": "init" }))
			.unwrap_or_default();
		let filter = init.filter;

		if filter.is_empty() {
			log::info!("started plugin {} (sees all traffic)", plugin.name);
		} else {
			log::info!("started plugin {} matching {filter:?}", plugin.name);
		}
		if init.chunks {
			log::info!("plugin {} takes streaming bodies a chunk at a time", plugin.name);
		}
		if init.request_body {
			log::info!("plugin {} takes uploaded request bodies", plugin.name);
		}

		plugin.filter = filter;
		plugin.chunks = init.chunks;
		plugin.request_body = init.request_body;

		Ok(plugin)
	}

	fn matches_request(&self, req: &ProxyRequest) -> bool {
		headers_match(&self.filter.request, &req.headers)
	}

	fn matches_response(&self, req: &ProxyRequest, head: &ResponseHead) -> bool {
		self.matches_request(req) && headers_match(&self.filter.response, &head.headers)
	}

	/// Send one hook and await the reply. Returns None when the plugin is gone
	/// or misbehaved, in which case it has been abandoned.
	fn call<T: Serialize, R: serde::de::DeserializeOwned>(&self, hook: &T) -> Option<R> {
		let mut guard = self.io.lock().unwrap();
		let io = guard.as_mut()?;

		let mut line = match serde_json::to_string(hook) {
			Ok(line) => line,
			Err(e) => {
				log::error!("plugin {}: cannot encode hook: {e}", self.name);

				return None;
			}
		};
		line.push('\n');

		// Started here, after the lock and the encoding, so that what is
		// measured is the plugin's own round trip rather than our bookkeeping.
		let started = Instant::now();

		if let Err(e) = io.stdin.write_all(line.as_bytes()).and_then(|()| io.stdin.flush()) {
			log::error!("plugin {} stdin closed: {e}", self.name);
			self.abandon(&mut guard);

			return None;
		}

		let reply = match io.lines.recv_timeout(self.timeout) {
			Ok(reply) => {
				self.metrics.record_plugin_call(&self.name, started.elapsed());

				reply
			}
			Err(RecvTimeoutError::Timeout) => {
				// A plugin that hangs is precisely the one worth seeing on the
				// status page, so the whole wait counts as time it cost.
				self.metrics.record_plugin_call(&self.name, started.elapsed());
				log::error!(
					"plugin {} did not reply within {:?}; abandoning it",
					self.name,
					self.timeout
				);
				self.abandon(&mut guard);

				return None;
			}
			Err(RecvTimeoutError::Disconnected) => {
				log::error!("plugin {} exited", self.name);
				self.abandon(&mut guard);

				return None;
			}
		};

		match serde_json::from_str(&reply) {
			Ok(reply) => Some(reply),
			Err(e) => {
				// One bad line is not fatal; the plugin stays up.
				log::warn!("plugin {}: ignoring unparsable reply: {e}", self.name);

				None
			}
		}
	}

	/// Stop talking to a plugin for good, killing the process.
	fn abandon(&self, guard: &mut Option<Io>) {
		if let Some(mut io) = guard.take() {
			let _ = io.child.kill();
			let _ = io.child.wait();
		}
	}
}

impl Interceptor for Plugin {
	/// Only when it asked at `init`. A plugin that did not is not being denied
	/// anything it expects: it is told the body is streaming and gets on with
	/// the headers, which is what nearly every plugin actually wants.
	fn wants_request_body(&self, req: &ProxyRequest) -> bool {
		self.request_body && self.matches_request(req)
	}

	fn on_request(&self, req: &mut ProxyRequest) -> Option<ProxyResponse> {
		if !self.matches_request(req) {
			return None;
		}

		// A body we were never given is absent rather than empty, and flagged,
		// so a plugin can tell "nothing was uploaded" from "it went past you".
		let carries_body = self.wants_request_body(req);
		let hook = Hook {
			hook: "request",
			method: &req.method,
			url: &req.url,
			status: None,
			headers: Some(&req.headers),
			body_b64: carries_body.then(|| BASE64.encode(&req.body)),
			streaming: !carries_body,
			is_final: false,
		};

		// A plugin that has gone away neither rewrites nor answers.
		let reply = self.call::<_, Reply>(&hook)?;

		if let Some(response) = short_circuit(&self.name, &reply) {
			return Some(response);
		}

		if let Some(method) = reply.method {
			req.method = method;
		}
		if let Some(url) = reply.url {
			req.url = url;
		}
		if let Some(headers) = reply.headers {
			req.headers = headers;
		}
		if let Some(body) = decode_body(&self.name, reply.body_b64) {
			req.body = body;
		}

		None
	}

	fn on_response(&self, req: &ProxyRequest, resp: &mut ProxyResponse) {
		let head = ResponseHead {
			status: resp.status,
			headers: std::mem::take(&mut resp.headers),
		};
		let matched = self.matches_response(req, &head);
		resp.headers = head.headers;

		if !matched {
			return;
		}

		let hook = Hook {
			hook: "response",
			method: &req.method,
			url: &req.url,
			status: Some(resp.status),
			headers: Some(&resp.headers),
			body_b64: Some(BASE64.encode(&resp.body)),
			streaming: false,
			is_final: false,
		};

		let Some(reply) = self.call::<_, Reply>(&hook) else {
			return;
		};

		if let Some(status) = reply.status {
			resp.status = status;
		}
		if let Some(headers) = reply.headers {
			resp.headers = headers;
		}
		if let Some(body) = decode_body(&self.name, reply.body_b64) {
			resp.body = body;
		}
	}

	fn on_response_head(&self, req: &ProxyRequest, head: &mut ResponseHead) {
		if !self.matches_response(req, head) {
			return;
		}

		let hook = Hook {
			hook: "response",
			method: &req.method,
			url: &req.url,
			status: Some(head.status),
			headers: Some(&head.headers),
			body_b64: None,
			streaming: true,
			is_final: false,
		};

		let Some(reply) = self.call::<_, Reply>(&hook) else {
			return;
		};

		if let Some(status) = reply.status {
			head.status = status;
		}
		if let Some(headers) = reply.headers {
			head.headers = headers;
		}
		if reply.body_b64.is_some() {
			log::warn!(
				"plugin {}: ignoring body returned for a streaming response",
				self.name
			);
		}
	}

	/// Only claim bodies this plugin's filter actually selects, so unmatched
	/// responses (large media, most notably) stream straight through.
	///
	/// A plugin that asked for chunks never claims the body: buffering it whole
	/// is precisely what the chunk hook exists to avoid, so if a plugin somehow
	/// declares both, chunks win.
	fn wants_body(&self, req: &ProxyRequest, head: &ResponseHead) -> bool {
		!self.chunks && self.matches_response(req, head)
	}

	fn wants_chunks(&self, req: &ProxyRequest, head: &ResponseHead) -> bool {
		let wanted = self.chunks && self.matches_response(req, head);
		// Remembered for the chunk hooks, which never see the head again.
		self.chunking.store(wanted, Ordering::Relaxed);

		wanted
	}

	fn on_response_chunk(&self, req: &ProxyRequest, chunk: &mut Vec<u8>) {
		if !self.chunking.load(Ordering::Relaxed) {
			return;
		}

		let hook = Hook {
			hook: "chunk",
			method: &req.method,
			url: &req.url,
			status: None,
			headers: None,
			body_b64: Some(BASE64.encode(&chunk)),
			streaming: false,
			is_final: false,
		};

		let Some(reply) = self.call::<_, Reply>(&hook) else {
			return;
		};

		// An empty `body_b64` decodes to no bytes, which drops the chunk. That
		// is how a plugin accumulating across the stream says "not yet".
		if let Some(body) = decode_body(&self.name, reply.body_b64) {
			*chunk = body;
		}
	}

	fn on_response_end(&self, req: &ProxyRequest) -> Option<Vec<u8>> {
		// Cleared as it is read, so a stream that ends cannot leak its answer
		// into the next response this plugin is asked about.
		if !self.chunking.swap(false, Ordering::Relaxed) {
			return None;
		}

		let hook = Hook {
			hook: "chunk",
			method: &req.method,
			url: &req.url,
			status: None,
			headers: None,
			body_b64: None,
			streaming: false,
			is_final: true,
		};

		let reply = self.call::<_, Reply>(&hook)?;

		decode_body(&self.name, reply.body_b64).filter(|tail| !tail.is_empty())
	}
}

impl Drop for Plugin {
	fn drop(&mut self) {
		let mut guard = self.io.lock().unwrap();
		self.abandon(&mut guard);
	}
}

/// A reply to the request hook that carries a `status` is the plugin answering
/// the request itself. Everything else it may have sent about the request —
/// `method`, `url` — is moot, since the request is never made.
fn short_circuit(name: &str, reply: &Reply) -> Option<ProxyResponse> {
	let status = reply.status?;

	Some(ProxyResponse {
		status,
		headers: reply.headers.clone().unwrap_or_default(),
		body: decode_body(name, reply.body_b64.clone()).unwrap_or_default(),
	})
}

fn decode_body(name: &str, body_b64: Option<String>) -> Option<Vec<u8>> {
	let encoded = body_b64?;

	match BASE64.decode(encoded) {
		Ok(bytes) => Some(bytes),
		Err(e) => {
			log::warn!("plugin {name}: body_b64 is not valid base64: {e}");

			None
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn missing_plugin_dir_yields_no_plugins() {
		let config = Config::from_str("[plugins]\ndir = \"/nonexistent/mach5-plugins\"\n").unwrap();

		assert!(load_all(&config).is_empty());
	}

	#[test]
	fn disabled_plugins_are_not_loaded() {
		let config = Config::from_str("[plugins]\nenabled = false\n").unwrap();
		let ca = std::sync::Arc::new(crate::ca::CertAuthority::generate_dev(&config).unwrap());
		let chain = crate::interceptor::Chain::from_config(&config, ca);

		// Nothing configured and plugins off: the chain must be a no-op.
		let mut req = ProxyRequest {
			method: "GET".to_string(),
			url: "https://example.com/".to_string(),
			headers: Vec::new(),
			body: Vec::new(),
		};
		assert!(chain.on_request(&mut req).is_none());
		assert_eq!(req.url, "https://example.com/");
	}

	fn constraints(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
		pairs
			.iter()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect()
	}

	fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
		pairs
			.iter()
			.map(|(k, v)| (k.to_string(), v.to_string()))
			.collect()
	}

	#[test]
	fn empty_filter_matches_everything() {
		assert!(headers_match(&BTreeMap::new(), &[]));
		assert!(headers_match(&BTreeMap::new(), &headers(&[("a", "b")])));
	}

	#[test]
	fn constraints_are_anded() {
		let filter = constraints(&[("accept", "text/html"), ("x-qos", "high")]);

		assert!(headers_match(
			&filter,
			&headers(&[("accept", "text/html"), ("x-qos", "high")])
		));
		// Only one of the two present: must not match.
		assert!(!headers_match(&filter, &headers(&[("accept", "text/html")])));
	}

	#[test]
	fn values_match_as_case_insensitive_substrings() {
		let filter = constraints(&[("content-type", "text/html")]);

		assert!(
			headers_match(
				&filter,
				&headers(&[("Content-Type", "text/html; charset=utf-8")])
			),
			"a parameterised content-type should still match"
		);
		assert!(!headers_match(
			&filter,
			&headers(&[("content-type", "application/json")])
		));
	}

	#[test]
	fn filter_parses_from_an_init_reply() {
		let reply: InitReply = serde_json::from_str(
			r#"{"match":{"request":{"accept":"text/html"},"response":{"content-type":"text/html"}}}"#,
		)
		.unwrap();

		assert_eq!(reply.filter.request.get("accept").unwrap(), "text/html");
		assert_eq!(
			reply.filter.response.get("content-type").unwrap(),
			"text/html"
		);
		assert!(!reply.filter.is_empty());
	}

	#[test]
	fn an_init_reply_may_ask_for_chunks() {
		let reply: InitReply =
			serde_json::from_str(r#"{"chunks":true,"match":{"response":{"content-type":"text/"}}}"#)
				.unwrap();

		assert!(reply.chunks);
		assert_eq!(reply.filter.response.get("content-type").unwrap(), "text/");
	}

	#[test]
	fn the_chunk_hooks_go_out_in_the_documented_shape() {
		let chunk = Hook {
			hook: "chunk",
			method: "GET",
			url: "https://example.com/big",
			status: None,
			headers: None,
			body_b64: Some(BASE64.encode(b"hello")),
			streaming: false,
			is_final: false,
		};
		let end = Hook {
			body_b64: None,
			is_final: true,
			..chunk
		};

		assert_eq!(
			serde_json::to_string(&chunk).unwrap(),
			r#"{"hook":"chunk","method":"GET","url":"https://example.com/big","body_b64":"aGVsbG8="}"#
		);
		assert_eq!(
			serde_json::to_string(&end).unwrap(),
			r#"{"hook":"chunk","method":"GET","url":"https://example.com/big","final":true}"#
		);
	}

	#[test]
	fn a_chunk_reply_replaces_the_chunk() {
		let reply: Reply = serde_json::from_str(&format!(
			r#"{{"body_b64":"{}"}}"#,
			BASE64.encode(b"rewritten")
		))
		.unwrap();

		assert_eq!(
			decode_body("t", reply.body_b64),
			Some(b"rewritten".to_vec())
		);
	}

	#[test]
	fn an_empty_chunk_reply_drops_the_chunk() {
		let reply: Reply = serde_json::from_str(r#"{"body_b64":""}"#).unwrap();

		assert_eq!(
			decode_body("t", reply.body_b64),
			Some(Vec::new()),
			"an empty body is a decision, not an omission"
		);
	}

	#[test]
	fn an_empty_chunk_reply_object_leaves_it_alone() {
		let reply: Reply = serde_json::from_str("{}").unwrap();

		assert!(reply.body_b64.is_none());
		assert!(decode_body("t", reply.body_b64).is_none(), "unchanged");
	}

	#[test]
	fn plugin_ignoring_init_sees_everything() {
		// A plugin that replies `{}` declares no constraints.
		let reply: InitReply = serde_json::from_str("{}").unwrap();

		assert!(reply.filter.is_empty());
	}

	#[test]
	fn an_init_reply_may_ask_for_request_bodies() {
		let asked: InitReply = serde_json::from_str(r#"{"request_body":true}"#).unwrap();
		let silent: InitReply = serde_json::from_str("{}").unwrap();

		assert!(asked.request_body);
		assert!(
			!silent.request_body,
			"a plugin that says nothing lets uploads stream past it"
		);
	}

	#[test]
	fn a_status_on_the_request_hook_answers_the_request() {
		let reply: Reply = serde_json::from_str(&format!(
			r#"{{"status":403,"headers":[["content-type","text/plain"]],"body_b64":"{}"}}"#,
			BASE64.encode(b"blocked\n")
		))
		.unwrap();

		let response = short_circuit("t", &reply).expect("status means short-circuit");

		assert_eq!(response.status, 403);
		assert_eq!(
			response.headers,
			vec![("content-type".to_string(), "text/plain".to_string())]
		);
		assert_eq!(response.body, b"blocked\n");
	}

	#[test]
	fn a_short_circuit_may_omit_headers_and_body() {
		let reply: Reply = serde_json::from_str(r#"{"status":204}"#).unwrap();
		let response = short_circuit("t", &reply).unwrap();

		assert_eq!(response.status, 204);
		assert!(response.headers.is_empty());
		assert!(response.body.is_empty());
	}

	#[test]
	fn a_reply_without_a_status_only_rewrites() {
		let reply: Reply = serde_json::from_str(r#"{"url":"https://example.org/"}"#).unwrap();

		assert!(short_circuit("t", &reply).is_none());
	}

	#[test]
	fn decode_body_rejects_bad_base64() {
		assert!(decode_body("t", Some("!!!not base64!!!".to_string())).is_none());
		assert_eq!(decode_body("t", Some(BASE64.encode(b"hi"))), Some(b"hi".to_vec()));
		assert!(decode_body("t", None).is_none(), "absent means unchanged");
	}
}
