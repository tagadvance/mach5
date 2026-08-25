//! The interstitials.
//!
//! Pages the proxy serves in place of one it could not or would not fetch. The
//! first of them, and the reason the module exists:
//!
//! When an origin's certificate fails validation the client cannot be told the
//! truth by the usual means: it has already completed a perfectly good TLS
//! handshake with *us*, using a certificate we minted, so its own warning UI
//! will never fire. Once a device installs our root CA we are the only thing
//! still checking, which makes showing this page part of the security model
//! rather than a nicety.

use crate::interceptor::ProxyResponse;

/// Cloudflare's de-facto status for "the origin's certificate is invalid".
/// Browsers render our body regardless; this just makes logs honest.
const STATUS_INVALID_CERT: u16 = 526;

/// RFC 5842's "the server terminated an operation because it encountered an
/// infinite loop".
const STATUS_LOOP_DETECTED: u16 = 508;

/// Build the interstitial shown in place of a page whose origin failed
/// certificate validation.
///
/// `bypass_phrase` is what someone may type on this page to be let through
/// anyway, or `None` when that is switched off — in which case the page carries
/// no trace of the mechanism at all.
pub fn certificate_error(host: &str, detail: &str, bypass_phrase: Option<&str>) -> ProxyResponse {
	let body = page(host, detail, bypass_phrase);

	ProxyResponse {
		status: STATUS_INVALID_CERT,
		headers: vec![
			(
				"content-type".to_string(),
				"text/html; charset=utf-8".to_string(),
			),
			// Never let a warning page be cached in place of the real site.
			("cache-control".to_string(), "no-store".to_string()),
		],
		body: body.into_bytes(),
	}
}

/// A plain-text failure, for everything that is not a certificate problem.
pub fn upstream_error(host: &str, detail: &str) -> ProxyResponse {
	ProxyResponse {
		status: 502,
		headers: vec![
			(
				"content-type".to_string(),
				"text/html; charset=utf-8".to_string(),
			),
			("cache-control".to_string(), "no-store".to_string()),
		],
		body: unreachable_page(host, detail).into_bytes(),
	}
}

/// Build the interstitial shown when the proxy's own request came back to it,
/// which means the origin's name resolved to the proxy itself.
pub fn fetch_loop(host: &str) -> ProxyResponse {
	ProxyResponse {
		status: STATUS_LOOP_DETECTED,
		headers: vec![
			(
				"content-type".to_string(),
				"text/html; charset=utf-8".to_string(),
			),
			("cache-control".to_string(), "no-store".to_string()),
		],
		body: loop_page(host).into_bytes(),
	}
}

fn page(host: &str, detail: &str, bypass_phrase: Option<&str>) -> String {
	let host = escape(host);
	let detail = escape(detail);
	let explanation = explain(&detail);
	let bypass = bypass_phrase.map(listener).unwrap_or_default();

	format!(
		r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your connection is not private</title>
{STYLE}
</head>
<body>
<main>
  <div class="mark" aria-hidden="true">&#9888;</div>
  <h1>Your connection is not private</h1>
  <p class="lede">
    <strong>{host}</strong> presented a certificate that mach5 could not verify,
    so the connection was refused before any data was sent.
  </p>
  <p>{explanation}</p>
  <details>
    <summary>Technical details</summary>
    <p class="detail">{detail}</p>
    <p class="note">
      mach5 is intercepting this connection, so your browser cannot check this
      certificate itself &mdash; it trusts mach5&rsquo;s own certificate
      authority. That makes mach5 the only thing still validating the origin,
      which is why it stopped here rather than letting the page load.
    </p>
  </details>
  <p class="actions"><button onclick="location.reload()">Try again</button></p>
</main>
{bypass}
</body>
</html>
"#
	)
}

/// The way past this page: type the phrase.
///
/// Chrome's `thisisunsafe`, and Chrome's reasoning with it — a warning with a
/// button on it is a warning people click through without reading, where
/// something you have to already know and type is not something anyone does by
/// accident. It is also why the markup above says nothing about it: the page
/// has to remain a refusal, and this is the whole of the mechanism.
fn listener(phrase: &str) -> String {
	// Through a JSON string, so a phrase carrying a quote or a backslash cannot
	// end the literal and become code.
	let phrase = serde_json::to_string(phrase).unwrap_or_else(|_| "\"\"".to_string());

	format!(
		r#"<script>
(() => {{
	const want = {phrase};
	let typed = '';
	addEventListener('keypress', (e) => {{
		typed = (typed + String.fromCharCode(e.charCode || e.keyCode)).slice(-want.length);
		if (typed !== want) {{
			return;
		}}

		const next = encodeURIComponent(location.pathname + location.search);
		location.href = '/.mach5/bypass?next=' + next;
	}});
}})();
</script>"#
	)
}

fn unreachable_page(host: &str, detail: &str) -> String {
	let host = escape(host);
	let detail = escape(detail);

	format!(
		r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>This site can't be reached</title>
{STYLE}
</head>
<body>
<main>
  <div class="mark" aria-hidden="true">&#8709;</div>
  <h1>This site can&rsquo;t be reached</h1>
  <p class="lede">mach5 could not fetch <strong>{host}</strong>.</p>
  <details>
    <summary>Technical details</summary>
    <p class="detail">{detail}</p>
  </details>
  <p class="actions"><button onclick="location.reload()">Try again</button></p>
</main>
</body>
</html>
"#
	)
}

/// No "try again" here, unlike the other two: this one never clears up on a
/// reload, and a retry only costs another lap.
fn loop_page(host: &str) -> String {
	let host = escape(host);

	format!(
		r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mach5 reached itself</title>
{STYLE}
</head>
<body>
<main>
  <div class="mark" aria-hidden="true">&#8634;</div>
  <h1>mach5 reached itself</h1>
  <p class="lede">
    Fetching <strong>{host}</strong> came back to mach5 instead of the real
    site, so the request was stopped rather than repeated until the machine
    ran out.
  </p>
  <p>
    That means mach5 resolved this name to its own address. Almost always it is
    resolving through the DNS server that answers every query with mach5 &mdash;
    the one the clients use &mdash; instead of a resolver that returns the real
    address of the origin.
  </p>
  <details>
    <summary>What to check</summary>
    <p class="detail">dns: &mdash; the proxy container&rsquo;s resolver in compose.yaml</p>
    <p class="detail">/etc/resolv.conf &mdash; if the proxy is not in a container</p>
    <p class="note">
      Whichever applies must point at a resolver with real answers, never at the
      wildcard server that points every name at mach5.
    </p>
  </details>
</main>
</body>
</html>
"#
	)
}

/// Turn the underlying library message into something a person can act on.
fn explain(detail: &str) -> &'static str {
	let detail = detail.to_ascii_lowercase();

	if detail.contains("expired") {
		"The certificate has expired. That usually means the site let it lapse, \
		 but it can also mean your device's clock is wrong."
	} else if detail.contains("unknownissuer") || detail.contains("unknown issuer") {
		"The certificate was not issued by an authority mach5 trusts. It may be \
		 self-signed, or something may be intercepting the connection between \
		 mach5 and the site."
	} else if detail.contains("notvalidforname") || detail.contains("not valid for") {
		"The certificate is valid, but it was issued for a different hostname. \
		 The request may have been redirected somewhere unintended."
	} else {
		"The certificate could not be validated, so mach5 refused to continue."
	}
}

pub(crate) const STYLE: &str = r#"<style>
:root { color-scheme: light dark; }
body {
  margin: 0; min-height: 100vh; display: flex; align-items: center;
  justify-content: center; padding: 2rem;
  font: 16px/1.6 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background: #fff; color: #202124;
}
main { max-width: 42rem; }
.mark { font-size: 3.5rem; line-height: 1; color: #b0b3b8; margin-bottom: 1rem; }
h1 { font-size: 1.65rem; font-weight: 500; margin: 0 0 1rem; }
.lede { font-size: 1.05rem; }
p { margin: 0 0 1rem; }
details { margin: 1.5rem 0; }
summary { cursor: pointer; color: #1a73e8; }
.detail { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: .85rem; word-break: break-word; margin-top: .75rem; }
.note { font-size: .9rem; color: #5f6368; }
.actions { margin-top: 2rem; }
button {
  font: inherit; font-size: .95rem; padding: .55rem 1.1rem; border: 0;
  border-radius: 4px; background: #1a73e8; color: #fff; cursor: pointer;
}
button:hover { background: #1867cf; }
@media (prefers-color-scheme: dark) {
  body { background: #202124; color: #e8eaed; }
  .note { color: #9aa0a6; }
  summary { color: #8ab4f8; }
  button { background: #8ab4f8; color: #202124; }
  button:hover { background: #aecbfa; }
}
</style>"#;

/// Minimal HTML escaping. The host and the library's message both reach this
/// page from outside, so neither is trusted markup — nor is a stored selector,
/// which is why [`crate::internal`] escapes through this one too.
pub(crate) fn escape(raw: &str) -> String {
	let mut out = String::with_capacity(raw.len());
	for c in raw.chars() {
		match c {
			'&' => out.push_str("&amp;"),
			'<' => out.push_str("&lt;"),
			'>' => out.push_str("&gt;"),
			'"' => out.push_str("&quot;"),
			'\'' => out.push_str("&#39;"),
			_ => out.push(c),
		}
	}

	out
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The mechanism has to be invisible when it is on and absent when it is
	/// off. A page that hinted at it would be a page people click through.
	#[test]
	fn the_bypass_is_invisible_on_the_page_and_absent_when_off() {
		let with = certificate_error("example.com", "expired", Some("thisisunsafe"));
		let body = String::from_utf8(with.body).unwrap();

		assert!(body.contains("/.mach5/bypass"), "the listener has to be there");
		assert!(
			!body.contains("thisisunsafe</") && !body.contains("Proceed") && !body.contains("Advanced"),
			"but nothing readable may announce it"
		);

		let without = certificate_error("example.com", "expired", None);
		let body = String::from_utf8(without.body).unwrap();

		assert!(
			!body.contains("mach5/bypass") && !body.contains("<script>"),
			"switched off, the page carries no trace of the mechanism"
		);
	}

	/// A phrase is configurable, so it reaches the page as data rather than as
	/// code — a quote in it must not be able to close the literal.
	#[test]
	fn a_phrase_cannot_break_out_of_the_script() {
		let resp = certificate_error("example.com", "expired", Some("a\"; alert(1); //"));
		let body = String::from_utf8(resp.body).unwrap();

		assert!(body.contains(r#"const want = "a\"; alert(1); //";"#), "{body}");
	}


	#[test]
	fn host_and_detail_are_escaped() {
		let resp = certificate_error("<script>alert(1)</script>", "\"quoted\"", None);
		let body = String::from_utf8(resp.body).unwrap();

		assert!(!body.contains("<script>alert(1)</script>"));
		assert!(body.contains("&lt;script&gt;"));
		assert!(body.contains("&quot;quoted&quot;"));
	}

	#[test]
	fn expiry_gets_its_own_explanation() {
		let resp = certificate_error("example.com", "certificate expired", None);
		let body = String::from_utf8(resp.body).unwrap();

		assert!(body.contains("has expired"));
		assert!(body.contains("clock is wrong"), "clock skew is worth naming");
	}

	#[test]
	fn wrong_host_and_unknown_issuer_differ() {
		let issuer = certificate_error("example.com", "invalid peer certificate: UnknownIssuer", None);
		let name = certificate_error("example.com", "certificate not valid for name", None);

		let issuer = String::from_utf8(issuer.body).unwrap();
		let name = String::from_utf8(name.body).unwrap();

		assert!(issuer.contains("not issued by an authority"));
		assert!(name.contains("issued for a different hostname"));
	}

	#[test]
	fn the_loop_page_names_the_host_and_the_thing_to_check() {
		let resp = fetch_loop("example.com");

		assert_eq!(resp.status, 508);
		assert!(resp
			.headers
			.iter()
			.any(|(k, v)| k == "cache-control" && v == "no-store"));

		let body = String::from_utf8(resp.body).unwrap();

		assert!(body.contains("example.com"));
		assert!(body.contains("DNS"), "the cause is worth naming");
		assert!(body.contains("resolv.conf"));
	}

	#[test]
	fn the_loop_page_escapes_its_host() {
		let resp = fetch_loop("<script>alert(1)</script>");
		let body = String::from_utf8(resp.body).unwrap();

		assert!(!body.contains("<script>alert(1)</script>"));
		assert!(body.contains("&lt;script&gt;"));
	}

	#[test]
	fn interstitial_is_never_cached() {
		let resp = certificate_error("example.com", "whatever", None);

		assert_eq!(resp.status, 526);
		assert!(resp
			.headers
			.iter()
			.any(|(k, v)| k == "cache-control" && v == "no-store"));
	}
}
