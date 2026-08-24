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
| `url` | request | Replace the upstream URL — this is how you block or redirect |
| `status` | response | Replace the status code |
| `headers` | both | Replace the whole header list |
| `body_b64` | both | Replace the body (base64, so binary is safe) |

### Streaming responses

A response hook can arrive with `"streaming": true` and **no** `body_b64`. That
means the body is being relayed straight to the client and is not available. You
may still change `status` and `headers`; a `body_b64` you return is ignored.

## Rules

- **Always print exactly one line per line you receive**, and flush it. A plugin
  that goes quiet is abandoned after `plugin_timeout_seconds`.
- Bodies are base64-encoded. Decode before inspecting, encode after modifying.
- Write debug output to **stderr**, never stdout — stdout is the protocol.
- A plugin that crashes, hangs, or prints nonsense is dropped and traffic keeps
  flowing unmodified. Check the proxy log if a plugin stops taking effect.
- Each proxy worker thread starts its own copy of every plugin, so a plugin may
  run as several processes. Keep per-process state to a minimum, or put shared
  state somewhere external.
