#!/usr/bin/env python3
"""Example mach5 interceptor plugin.

Demonstrates both hooks: blocking a host on the request side, and rewriting the
body on the response side. Copy this as a starting point.

`on_chunk` below sketches the third option — seeing a streaming body a piece at
a time — but this plugin does not ask for it. See README.md for the protocol.
"""

import base64
import json
import sys

# Requests to these hosts never reach the network.
BLOCKED = frozenset({"ads.example.com", "tracker.example.com"})

BANNER = (
    b'<div style="position:fixed;top:0;left:0;right:0;z-index:99999;'
    b'background:#111;color:#0f0;font:12px monospace;padding:4px 8px">'
    b"mach5 intercepted this page</div>"
)


def log(message):
    """Debug output goes to stderr; stdout carries the protocol."""
    print(f"[10-example] {message}", file=sys.stderr, flush=True)


def on_init(_msg):
    """Register what this plugin wants to see.

    Constraints are ANDed, matched case-insensitively as substrings, and can
    name any header including custom `x-*` ones. Declaring a response
    content-type means images and video are never buffered for us — they stream
    straight through to the client.

    Adding `"chunks": True` here would swap the buffered `response` hook for the
    per-chunk one below. We do not, because this plugin rewrites HTML and a
    chunk arrives still `content-encoding`d.
    """
    return {"match": {"response": {"content-type": "text/html"}}}


def on_request(msg):
    url = msg.get("url", "")
    host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]

    if host in BLOCKED:
        log(f"blocking {host}")
        # A status on the request hook answers it here: the origin is never
        # contacted and nothing downstream sees the request.
        return {"status": 204}

    return {}


def on_response(msg):
    # The proxy only routes matching responses here, but a body is still absent
    # when it is streaming past unbuffered — nothing to rewrite in that case.
    if msg.get("streaming"):
        return {}

    body = base64.b64decode(msg.get("body_b64", ""))
    if b"<body" not in body.lower():
        return {}

    # Insert the banner immediately after the opening <body> tag.
    lowered = body.lower()
    start = lowered.index(b"<body")
    insert_at = body.find(b">", start) + 1
    patched = body[:insert_at] + BANNER + body[insert_at:]

    log(f"injected banner into {msg.get('url')}")

    return {"body_b64": base64.b64encode(patched).decode()}


def on_chunk(msg):
    """One chunk of a streaming body — only sent if `init` asked for chunks.

    NOT WIRED UP: `on_init` above does not request chunks, so this never runs.
    It is here to show the shape.

    The bytes are exactly what the origin sent, still compressed (brotli or
    gzip) and split at arbitrary boundaries — so a chunk is not text and not a
    whole anything. Claim the body instead if you want plain text.

    Return `{"body_b64": ...}` to replace this chunk, `{}` to pass it through,
    or an empty `body_b64` to drop it while you accumulate. On the final hook
    there is no body to read, and whatever you return is appended after the
    last chunk.
    """
    if msg.get("final"):
        log(f"stream ended for {msg.get('url')}")
        # Nothing held back, so nothing to flush.
        return {}

    chunk = base64.b64decode(msg.get("body_b64", ""))
    log(f"{len(chunk)} bytes from {msg.get('url')}")

    return {}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            msg = json.loads(line)
            handler = {
                "init": on_init,
                "request": on_request,
                "response": on_response,
                "chunk": on_chunk,
            }.get(msg.get("hook"), lambda _msg: {})
            reply = handler(msg)
        except Exception as e:  # never die: a broken plugin should not break browsing
            log(f"error: {e}")
            reply = {}

        print(json.dumps(reply), flush=True)


if __name__ == "__main__":
    main()
