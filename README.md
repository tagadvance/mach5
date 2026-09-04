# mach5

[![CI](https://github.com/tagadvance/mach5/actions/workflows/ci.yml/badge.svg)](https://github.com/tagadvance/mach5/actions/workflows/ci.yml)
[![Audit](https://github.com/tagadvance/mach5/actions/workflows/audit.yml/badge.svg)](https://github.com/tagadvance/mach5/actions/workflows/audit.yml)
[![Licence](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE)

**TL;DR** — mach5 is a self-hosted web accelerator: a proxy you run on your own
network that shrinks pages on their way to your devices. It is a hobby project,
built for one person on hardware they own, and it is not a product. Opera Mini
and Google's Chrome Data Saver were this exact idea with real money behind it;
Google retired theirs in 2022 citing cheap mobile data, and Opera's still ships
in the markets where bytes are not cheap. Which is the honest pitch: run it
where bandwidth still costs you something.

---

An intercepting proxy that makes the web lighter on slow connections, blocks
what you tell it to, and lets you rewrite pages with a plugin in any language.

It does that by terminating your TLS connections with certificates it mints on
the fly, signed by a root certificate authority you generate and install on your
own devices. **That means it can read everything.** Start with the next section.

## Read this before you run it

mach5 holds the cleartext of every page every device sends through it. That is
not a side effect, it is the mechanism — none of the features below are possible
without it. It is the same technique corporate TLS-inspection appliances use,
and the same one you have been warned about your whole career. The only thing
separating those two is who is running it and why.

Three rules, and none of them is optional:

- **Do not expose it to the internet.** It binds 443 and answers for every
  hostname it is asked about. On a public address it is an open proxy and it
  will be found.
- **The root private key is total authority** over every device that trusts it.
  Anyone holding it can impersonate any website to any of those devices, on any
  network. Generate your own, keep it mode 600, never commit it, never copy it
  into an image.
- **Put anything that matters in `[passthrough] hosts`** — banking, health,
  work. Listed hosts are never decrypted: mach5 reads the name out of the
  ClientHello without answering it and splices the two sockets, so it holds no
  key and sees no plaintext, and your client checks the real certificate itself.
  `[passthrough] urls` takes lists to fetch and keep up to date, so the list
  need not be only what you thought to type.

[`SECURITY.md`](SECURITY.md) has the full threat model, what mach5 does and does
not defend against, and where to send a finding.

## When this is worth running

**Bandwidth-constrained and high-latency links.** Hotel and aeroplane wifi, a
phone on one bar, public wifi, anything metered or capped. This is what it is
for and where the numbers are real.

**Sites nobody optimised.** Plenty of the web still serves uncompressed HTML and
full-size JPEGs. mach5 compresses what the origin left plain, re-encodes images
to WebP, and defers off-screen ones. Benchmarked across a mixed set of pages:
**−10.2% bytes and −27.2% wall time**, with one uncompressed site at −66%.

**The things that are not about speed at all.** Blocking, cosmetic filtering,
hiding an element permanently on a site that will not stop showing it to you,
and rewriting any page with a plugin.

## When it is not worth running

**A modern site behind a CDN.** It is already brotli-compressed, already serving
WebP or AVIF, already lazy-loading. There is nothing left for mach5 to win and it
adds a hop. Most of the web is now this.

**A fast wired connection.** Here mach5 is *negative* value: measurable latency
in exchange for savings you cannot perceive. Fewer bytes over a local hop is not
the same as faster, and the benchmark reports both columns for that reason.

**Sites that fingerprint their clients.** Sites with serious bot detection may
challenge you, because from their side the connection *does* look like
automation. See below for what they see, and what to do about it.

**Anywhere you cannot accept the trust model.** See above. If installing a root
CA on your devices makes you uneasy, that instinct is correct and this is not
the tool for you.

## If a site challenges you

When mach5 fetches a page on your behalf, the connection the origin sees is
**mach5's, not your browser's**. Modern bot detection fingerprints exactly that
connection, and mach5's does not match the browser whose name is in the headers:

| What they see | |
| --- | --- |
| TLS handshake | rustls, via ureq — not Chrome's. The JA3/JA4 fingerprint contradicts the `user-agent`. |
| HTTP version | 1.1. Chrome has not spoken HTTP/1.1 to Google in years. |
| `accept-encoding` | `gzip, br` — clamped to what mach5 can decode and rewrite. Chrome sends `gzip, deflate, br, zstd`. |
| Header order | ureq's, which is itself a fingerprint. |
| Source address | one, shared by every device behind the proxy. |

A Chrome user-agent over a non-Chrome TLS handshake on HTTP/1.1 is close to a
textbook automation signature. The sites are not wrong; that really is a proxy.
How much this costs in day-to-day use is not known — the mechanism is certain,
its frequency is not.

**This is not fixable in any honest way.** Matching Chrome's fingerprint means a
uTLS-style spoofing layer, maintained against a moving target, so that mach5 can
claim to be something it is not. That is an arms race, and losing it looks like
this; winning it is worse.

**Where it does happen, the answer is `[passthrough]`.** A listed host is never
decrypted, so your browser's own handshake reaches it and the fingerprint
matches, because it is genuinely your browser talking.

Add hosts because you met a problem on them, or because you would not want them
decrypted in the first place — not pre-emptively against a problem you have not
seen:

```toml
[passthrough]
hosts = [
  # Everything you would not want decrypted regardless. This is the reason
  # that does not depend on any of the above being true.
  "your-bank.example",
  "your-health-provider.example",
]
```

`urls` takes lists to fetch instead, cached on disk and refreshed on a schedule
like the blocklist's. A fetched entry covers its subdomains exactly as one typed
here does, and it is kept apart from what you wrote: a list that fails to
download, or comes back as an error page, leaves the hosts it gave you last time
exempt rather than quietly starting to decrypt them.

What you give up on a listed host is blocking, cosmetic filtering, the picker
and compression. For a bank that is nothing you wanted anyway. For a site you
listed because it challenged you, weigh it against the site working at all.

## Alongside pi-hole, not instead of it

Run both. They block different things and neither replaces the other.

**DNS blocks by name.** Earlier, cheaper, for every protocol and every device on
the network, whether or not it goes through the proxy. If you are only blocking
domains, pi-hole is the better tool and mach5 has nothing to add.

**A proxy blocks by request.** It sees which page asked, the path, the type and
the `accept` header — so it can honour a rule scoped to third-party context,
which DNS structurally cannot. Of the Adblock rules mach5 reads from EasyList,
1,661 carry `$third-party`: block this host, but only when another site embedded
it. A resolver must either apply those unconditionally, which blocks the site you
typed into the address bar, or ignore them.

It also means a blocked image can be answered with a transparent pixel instead
of a connection error, so pages are not visibly broken.

Point mach5's blocklist at Adblock-style lists and leave the hosts files to
pi-hole. Two copies of the same list is work for nothing.

## What it does

- **Three protocols.** HTTP/3 over QUIC, plus HTTP/2 and HTTP/1.1 over TCP. The
  TCP listener is not optional: HTTP/3 cannot bootstrap itself, so a browser
  starts there and moves itself across once it sees the `Alt-Svc` header.
- **Blocks domains.** hosts files, bare domain lists and Adblock `||domain^`
  anchors, fetched on a schedule and cached so a restart without network still
  blocks. `$third-party` is honoured; a rule scoped by anything else mach5
  cannot evaluate is skipped rather than applied more widely than it was written.
- **Hides elements.** Adblock cosmetic rules (`domain##selector`) from filter
  lists, plus anything hidden by hand: press `Ctrl+Shift+H` on a page, click an
  element, and it stays hidden on the next visit. Both are served back as a
  stylesheet that applies before first paint, so nothing flashes.
- **Re-encodes images** to WebP when the client accepts it and the result is
  smaller, cached by content hash so each conversion is paid once.
- **Compresses what the origin didn't**, and relays what it did untouched.
- **Caches static assets** — stylesheets, scripts, fonts, images. HTML is
  deliberately absent and stays absent until mach5 knows who is asking.
- **Rewrites pages.** Plugins are ordinary executables speaking newline-delimited
  JSON on stdin/stdout, in any language. They can rewrite a request, answer it
  themselves, rewrite a buffered response, or watch a body stream past a chunk
  at a time.
- **Validates what your browser no longer can.** Once a device trusts mach5, it
  is the only thing left checking the origin's certificate. A failure gets a page
  explaining which failure it was, not a blank 502.
- **Never decrypts what you tell it not to.** `[passthrough] hosts`.

## Running it

```sh
cd proxy && cargo build --release
```

Generate a root CA and point the configuration at it:

```sh
MACH5_CA_SUBJECT="/CN=my mach5 root/O=My Homelab/C=GB" bash security/init.sh
```

Then run it:

```sh
MACH5_CONFIG=mach5.toml ./proxy/target/release/mach5-proxy
```

`mach5.toml` documents every setting inline and everything in it is optional.
`docker compose up --build` runs the same thing on port 443.

Point a client at it by making the host you want resolve to the proxy — mach5
reads the SNI to learn which origin was meant:

```sh
curl -sS -k --resolve example.com:4443:127.0.0.1 https://example.com:4443/
```

With no `[ca]` configured it generates a throwaway root at startup and says so
on the status page. Nothing will trust it and the next restart mints a different
one; it exists so you can have a look around, not to deploy.

For real use, install the certificate on each device — mach5 serves it at
`/.mach5/ca.crt` for exactly that — the `.crt` matters, because a phone decides
what a download is from its filename.

## Its own endpoints

Because every name resolves to the proxy, `/.mach5/` is reachable on any host:

| Path | |
| --- | --- |
| `/.mach5/` | status: counters, this host's hidden elements, the CA link |
| `/.mach5/ca.crt` | the root certificate, as a `.crt` download |
| `/.mach5/stats.json` | the same counters, for scraping |
| `/.mach5/hidden.css` | this host's hidden elements, as a stylesheet |
| `/.mach5/mach5.js` | the element picker |

## Documentation

| | |
| --- | --- |
| [`SECURITY.md`](SECURITY.md) | the threat model, and the rules for running it |
| [`docs/architecture.md`](docs/architecture.md) | how it works: the life of a request, the chain order, backpressure |
| [`docs/running.md`](docs/running.md) | what it costs in memory, CPU and disk — measured |
| [`plugins/README.md`](plugins/README.md) | the plugin protocol |
| `mach5.toml` | every setting, documented inline |

## Building

Rust, on Cloudflare's [quiche](https://github.com/cloudflare/quiche). BoringSSL
is compiled from source as part of it: that needs cmake, a C compiler, perl and
libclang at build time, and nothing at runtime.

Plugins live in `plugins/`; [`plugins/README.md`](plugins/README.md) is the
protocol.

## Licence

Apache-2.0. See [`LICENSE`](LICENSE), and note that it disclaims warranty and
limits liability — this is one person's homelab project, it has not been
independently audited, and you should judge it accordingly before putting it
between yourself and the web.
