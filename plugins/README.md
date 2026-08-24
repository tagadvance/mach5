# Interceptor plugins

Any executable file in this directory is started once when the proxy starts and
kept running. Plugins run in filename order, which is why the examples are
numbered.

Because the protocol is newline-delimited JSON on stdin/stdout, a plugin can be
written in any language that can read a line and print a line.

## Protocol

One JSON object per line in, one per line out. The proxy sends:

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
