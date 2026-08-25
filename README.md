# mach5

An intercepting proxy that terminates a client's TLS with a certificate minted
on the fly for whatever host the client asked for, signed by a root CA installed
on the device. That gives it every byte of every page, which is the point: ad
blocking, cosmetic filtering, JavaScript injection, and on-the-fly rewriting.

`proxy/` is the live implementation, in Rust on Cloudflare's quiche. `app/` is an
abandoned Java prototype, kept only for reference.

## What it does

- **Three protocols.** HTTP/3 over QUIC, plus HTTP/2 and HTTP/1.1 over TCP. The
  TCP listener is not optional: HTTP/3 cannot bootstrap itself, so a browser
  starts there and moves itself over once it sees the `Alt-Svc` header.
- **Blocks domains.** hosts files, bare domain lists and Adblock `||domain^`
  anchors, fetched on a schedule and cached. A blocked request is answered
  locally — 204, or a transparent pixel if an image was expected.
- **Hides elements.** Adblock cosmetic rules (`domain##selector`) from filter
  lists, plus anything hidden by hand: press `Ctrl+Shift+H` on a page, click an
  element, and it stays hidden on the next visit. Both are served back as a
  stylesheet that applies before first paint.
- **Rewrites pages.** Plugins are ordinary executables speaking newline-delimited
  JSON on stdin/stdout, in any language. They can rewrite a request, answer it
  themselves, rewrite a buffered response, or watch a body stream past a chunk
  at a time.
- **Validates what your browser no longer can.** Once a device trusts mach5, it
  is the only thing left checking the origin's certificate. A failure gets a
  page explaining which failure it was, not a blank 502.
- **Compresses what the origin didn't**, and relays what it did untouched.

## Running it

```sh
cd proxy && cargo build
cd .. && MACH5_CONFIG=mach5.toml ./proxy/target/debug/mach5-proxy
```

`mach5.toml` documents every setting inline; everything in it is optional.
`docker compose up --build` runs the same thing on port 443.

Point a client at it by making the host you want resolve to the proxy — mach5
reads the SNI to learn which origin was meant:

```sh
curl -sS -k --resolve example.com:4443:127.0.0.1 https://example.com:4443/
```

With no `[ca]` configured it generates a throwaway CA on startup, so `-k` is
required and no browser will trust it. For real use, generate a root, point
`[ca]` at it, and install the certificate on each device — the proxy serves it
at `/.mach5/ca` for exactly that.

## Its own endpoints

Because every name resolves to the proxy, `/.mach5/` is reachable on any host:

| Path | |
| --- | --- |
| `/.mach5/` | status: counters, this host's hidden elements, the CA link |
| `/.mach5/ca` | the root certificate, as a `.crt` download |
| `/.mach5/stats.json` | the same counters, for scraping |
| `/.mach5/hidden.css` | this host's hidden elements, as a stylesheet |
| `/.mach5/mach5.js` | the element picker |

## Building

BoringSSL is compiled from source as part of quiche: it needs cmake, a C
compiler, perl and libclang at build time, and nothing at runtime.

Plugins live in `plugins/`; `plugins/README.md` is the protocol.
