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
//! A plugin that dies, times out, or emits nonsense is abandoned — the proxy
//! logs it and forwards traffic unmodified rather than failing the request.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Mutex;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::interceptor::{Interceptor, ProxyRequest, ProxyResponse};

/// What the proxy sends to a plugin.
#[derive(Serialize)]
struct Hook<'a> {
	hook: &'a str,
	method: &'a str,
	url: &'a str,
	#[serde(skip_serializing_if = "Option::is_none")]
	status: Option<u16>,
	headers: &'a [(String, String)],
	body_b64: String,
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

pub struct Plugin {
	name: String,
	timeout: Duration,
	io: Mutex<Option<Io>>,
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
		log::info!("started plugin {name}");

		Ok(Self {
			name,
			timeout,
			io: Mutex::new(Some(Io {
				child,
				stdin,
				lines,
			})),
		})
	}

	/// Send one hook and await the reply. Returns None when the plugin is gone
	/// or misbehaved, in which case it has been abandoned.
	fn call(&self, hook: &Hook) -> Option<Reply> {
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

		if let Err(e) = io.stdin.write_all(line.as_bytes()).and_then(|()| io.stdin.flush()) {
			log::error!("plugin {} stdin closed: {e}", self.name);
			self.abandon(&mut guard);

			return None;
		}

		let reply = match io.lines.recv_timeout(self.timeout) {
			Ok(reply) => reply,
			Err(RecvTimeoutError::Timeout) => {
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
	fn on_request(&self, req: &mut ProxyRequest) {
		let hook = Hook {
			hook: "request",
			method: &req.method,
			url: &req.url,
			status: None,
			headers: &req.headers,
			body_b64: BASE64.encode(&req.body),
		};

		let Some(reply) = self.call(&hook) else {
			return;
		};

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
	}

	fn on_response(&self, req: &ProxyRequest, resp: &mut ProxyResponse) {
		let hook = Hook {
			hook: "response",
			method: &req.method,
			url: &req.url,
			status: Some(resp.status),
			headers: &resp.headers,
			body_b64: BASE64.encode(&resp.body),
		};

		let Some(reply) = self.call(&hook) else {
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
}

impl Drop for Plugin {
	fn drop(&mut self) {
		let mut guard = self.io.lock().unwrap();
		self.abandon(&mut guard);
	}
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
		let chain = crate::interceptor::Chain::from_config(&config);

		// Nothing configured and plugins off: the chain must be a no-op.
		let mut req = ProxyRequest {
			method: "GET".to_string(),
			url: "https://example.com/".to_string(),
			headers: Vec::new(),
			body: Vec::new(),
		};
		chain.on_request(&mut req);

		assert_eq!(req.url, "https://example.com/");
	}

	#[test]
	fn decode_body_rejects_bad_base64() {
		assert!(decode_body("t", Some("!!!not base64!!!".to_string())).is_none());
		assert_eq!(decode_body("t", Some(BASE64.encode(b"hi"))), Some(b"hi".to_vec()));
		assert!(decode_body("t", None).is_none(), "absent means unchanged");
	}
}
