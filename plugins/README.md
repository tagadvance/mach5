# Interceptor plugins

Any executable file in this directory is started once when the proxy starts and
kept running. Plugins run in filename order, which is why the examples are
numbered.

Because the protocol is newline-delimited JSON on stdin/stdout, a plugin can be
written in any language that can read a line and print a line.

## Protocol

One JSON object per line in, one per line out.

### `init` — register what you want to see

Sent once at startup. Reply with header constraints; the proxy then only sends
you exchanges that match, and only buffers bodies you actually asked for.

```json
{"hook":"init"}
```

```json
{"match":{"request":{"accept":"text/html"},"response":{"content-type":"text/html"}}}
```

- Constraints are **ANDed** — every header named must match.
- Names compare case-insensitively; values match as a **case-insensitive
  substring**, so `text/html` matches `text/html; charset=utf-8`.
- Any header works, including custom `x-*` ones.
- `request` constraints apply to both hooks; `response` constraints apply only
  to the response hook.
- Reply `{}` (or ignore the hook) to see everything.
- Add `"chunks": true` to take streaming bodies a chunk at a time instead of
  whole — see [Chunk hooks](#chunk-hooks).
- Add `"request_body": true` to be given what was **uploaded** — see
  [Uploaded bodies](#uploaded-bodies).

**This is also how you avoid buffering large media.** A response whose body no
plugin has claimed streams straight through to the client, never held whole in
memory. Declaring a narrow filter is therefore a performance decision, not just
a convenience.

### `request` / `response`

The proxy sends:

```json
{"hook":"request","method":"GET","url":"https://example.com/","headers":[["accept","*/*"]],"body_b64":""}
```

```json
{"hook":"response","method":"GET","url":"https://example.com/","status":200,"headers":[["content-type","text/html"]],"body_b64":"PGh0bWw+"}
```

Reply with a single JSON object containing only the fields you want to change.
Anything you omit is left as-is, so `{}` means "no change":

```json
{"status":403,"body_b64":"YmxvY2tlZAo="}
```

| Field | Hook | Meaning |
| --- | --- | --- |
| `method` | request | Replace the HTTP method |
| `url` | request | Replace the upstream URL — this is how you redirect |
| `status` | request | **Answer the request yourself** — see below |
| `status` | response | Replace the status code |
| `headers` | both | Replace the whole header list |
| `body_b64` | both | Replace the body (base64, so binary is safe) |

Framing headers in `headers` are dropped: `content-length`,
`transfer-encoding`, `connection` and the rest of the hop-by-hop set belong to
whichever front end is speaking to the client, and it recomputes them from the
body actually sent. A `content-length` of your own would simply be a lie about
a body only mach5 knows the size of.

**One reply per hook, and it must parse.** There is no request id in the
protocol — replies are matched to hooks by order — so a line that is not a
reply puts the two sides permanently out of step. mach5 abandons a plugin that
sends one, rather than applying every later answer to the wrong hook. In
practice this means: do not print anything to **stdout** except replies. Use
stderr for logging; it is left attached and goes to mach5's own log.

### Uploaded bodies

By default an upload streams past you: the `request` hook still fires, with the
method, URL and headers, but no `body_b64` and `"streaming": true`.

```json
{"hook":"request","method":"PUT","url":"https://example.com/f","headers":[],"streaming":true}
```

That default exists because an upload has no size limit — someone putting a
2GB file through the proxy is not something to hold in memory on the chance a
plugin is interested. Ask for it and you get it:

```json
{"request_body": true}
```

Then the body arrives as `body_b64` like any other, and `max_request_body_mb`
applies: an upload past that is refused with a `413` rather than buffered. So
narrow your `match` if you ask for this — a filter of `{}` means every upload
through the proxy is held in memory for you, and anything over the limit stops
working.

> A request the proxy answers itself — a blocked host, or one of its own
> `/.mach5/` endpoints — is refused *before* the body is read, so you will not
> see a hook for it at all. That ordering is deliberate: it is what lets a
> blocked upload be turned away after a few kilobytes instead of after all of
> it.

### Answering a request yourself

Return a `status` on the **request** hook and the origin is never contacted:
your reply becomes the response. This is how you block an ad, or serve an
internal page from the proxy itself.

```json
{"status":403,"headers":[["content-type","text/plain"]],"body_b64":"YmxvY2tlZAo="}
```

`headers` and `body_b64` default to empty; `method` and `url` are ignored, since
no request is made. Nothing downstream runs: plugins after yours never see the
request, and no response hook — not even your own — touches what is served. A
blocked request must not then be rewritten by an injection plugin.

### Streaming responses

A response hook can arrive with `"streaming": true` and **no** `body_b64`. That
means the body is being relayed straight to the client and is not available. You
may still change `status` and `headers`; a `body_b64` you return is ignored.

To see that body anyway, without it ever being held whole in memory, ask for
chunks.

### Chunk hooks

Set `"chunks": true` on your `init` reply and you get a `chunk` hook for every
chunk of a **streaming** body whose response matches your filter, instead of one
`response` hook with the whole thing:

```json
{"hook":"chunk","method":"GET","url":"https://example.com/big.txt","body_b64":"aGVsbG8="}
```

Reply with a `body_b64` to replace that chunk, `{}` to leave it alone, or an
empty `body_b64` to **drop** it — which is how a plugin that is accumulating
across chunks says "not yet". When the body ends you get one final hook, with no
`body_b64`:

```json
{"hook":"chunk","method":"GET","url":"https://example.com/big.txt","final":true}
```

A `body_b64` you return on *that* one is appended after the last chunk, which is
how you flush whatever you were holding.

> **The bytes are still `content-encoding`d.** Only *buffered* bodies are
> decoded and re-encoded by the proxy. A chunk hook sees exactly what the origin
> put on the wire — usually brotli or gzip, split at arbitrary byte boundaries
> that fall wherever the socket happened to fill. If you want plain text, do not
> ask for chunks: claim the body instead and use the `response` hook. This is
> the single easiest thing to get wrong here.

Asking for chunks means you never get the body buffered — the two are exclusive,
and chunks win if you somehow declare both. Buffering the whole body is exactly
what a chunk hook exists to avoid.

Chunks are not free: every 64KB chunk is a base64 round trip through your
process, per plugin. Ask for them only when watching the body go past is
genuinely the point — progressive rewriting, re-encoding, scanning a body too
large to hold.

## Rules

- **Always print exactly one line per line you receive**, and flush it. A plugin
  that goes quiet is abandoned after `plugin_timeout_seconds`.
- Bodies are base64-encoded. Decode before inspecting, encode after modifying.
- Write debug output to **stderr**, never stdout — stdout is the protocol. Note
  that stderr *is* the proxy's log: mach5 keeps query strings out of its own
  lines by default, and a plugin printing URLs or bodies undoes that on a
  machine that sees every request every device makes.
- A plugin that crashes, hangs, or prints nonsense is dropped and traffic keeps
  flowing unmodified. Check the proxy log if a plugin stops taking effect.
- Each proxy worker thread starts its own copy of every plugin, so a plugin may
  run as several processes. Keep per-process state to a minimum, or put shared
  state somewhere external.
