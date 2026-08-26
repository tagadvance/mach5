//! What of a URL is allowed to reach the log.
//!
//! mach5 terminates TLS for every device pointed at it, so its log is a record
//! of everything those devices did. A query string is where the dangerous part
//! of that lives: OAuth codes, password-reset tokens, session ids, presigned
//! signatures, search terms. Written at the default level, into a container log
//! that is kept until the container is removed, those are credentials sitting
//! on disk in plain text long after they were used.
//!
//! So the default is to log the path and drop the query. A path can carry a
//! secret too — an invite link, a magic URL — and `host` exists for anyone who
//! would rather not risk it, at the cost of a log that can no longer tell you
//! which page misbehaved.
//!
//! The policy is process-wide rather than threaded through every call site: it
//! is set once at startup and read from the QUIC event loop, where there is no
//! configuration to hand.

use std::sync::OnceLock;

use crate::config::UrlLogging;

static POLICY: OnceLock<UrlLogging> = OnceLock::new();

/// Fix the policy for the life of the process. Later calls are ignored, which
/// only happens in tests.
pub fn init(policy: UrlLogging) {
	let _ = POLICY.set(policy);
}

fn policy() -> UrlLogging {
	POLICY.get().copied().unwrap_or_default()
}

/// The part of `url` that may be logged.
///
/// Always a prefix of the original, so this never allocates and never invents
/// a URL that was not asked for.
pub fn url(url: &str) -> &str {
	trim(url, policy())
}

fn trim(url: &str, policy: UrlLogging) -> &str {
	match policy {
		UrlLogging::Full => url,
		UrlLogging::Path => {
			let cut = url.find(['?', '#']).unwrap_or(url.len());

			&url[..cut]
		}
		UrlLogging::Host => {
			// Past the scheme, then to the end of the authority.
			let after_scheme = url.find("://").map(|at| at + 3).unwrap_or(0);
			let cut = url[after_scheme..]
				.find(['/', '?', '#'])
				.map(|at| after_scheme + at)
				.unwrap_or(url.len());

			&url[..cut]
		}
	}
}

/// A library's error message with the URL it embedded trimmed to what may be
/// logged.
///
/// ureq builds its transport errors as `<the whole url>: what went wrong`, so
/// logging one verbatim reintroduces every query string the rest of this module
/// exists to keep out. The URL is known exactly, so this is a substitution
/// rather than a guess at what looks like a URL.
pub fn detail(detail: &str, full_url: &str) -> String {
	let safe = url(full_url);
	if safe == full_url {
		return detail.to_string();
	}

	detail.replace(full_url, safe)
}

#[cfg(test)]
mod tests {
	use super::*;

	const TOKENED: &str = "https://accounts.example.com/reset?token=abc123&next=/x";

	#[test]
	fn a_query_string_is_dropped_by_default() {
		assert_eq!(
			trim(TOKENED, UrlLogging::Path),
			"https://accounts.example.com/reset",
			"the token is the whole reason this module exists"
		);
	}

	#[test]
	fn a_fragment_is_dropped_too() {
		assert_eq!(
			trim("https://example.com/page#section", UrlLogging::Path),
			"https://example.com/page"
		);
	}

	#[test]
	fn a_url_with_nothing_to_hide_is_untouched() {
		let plain = "https://example.com/index.html";

		assert_eq!(trim(plain, UrlLogging::Path), plain);
		assert_eq!(trim(plain, UrlLogging::Host), "https://example.com");
	}

	#[test]
	fn host_keeps_only_the_origin() {
		assert_eq!(trim(TOKENED, UrlLogging::Host), "https://accounts.example.com");
		assert_eq!(
			trim("https://example.com", UrlLogging::Host),
			"https://example.com",
			"a bare origin has nothing to cut"
		);
	}

	#[test]
	fn full_is_exactly_what_was_asked_for() {
		assert_eq!(trim(TOKENED, UrlLogging::Full), TOKENED);
	}

	#[test]
	fn an_error_message_loses_the_query_it_quoted() {
		init(UrlLogging::Path);
		let message = format!("{TOKENED}: Connection Failed: tls handshake failed");

		let logged = detail(&message, TOKENED);

		assert!(!logged.contains("token=abc123"), "{logged}");
		assert!(logged.contains("tls handshake failed"), "{logged}");
		assert!(logged.contains("accounts.example.com/reset"), "{logged}");
	}
}
