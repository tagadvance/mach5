#!/usr/bin/env python3
"""Example mach5 interceptor plugin.

Demonstrates both hooks: blocking a host on the request side, and rewriting the
body on the response side. Copy this as a starting point.

See README.md for the protocol.
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
    """
    return {"match": {"response": {"content-type": "text/html"}}}


def on_request(msg):
    url = msg.get("url", "")
    host = url.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]

    if host in BLOCKED:
        log(f"blocking {host}")
        # Point the fetch at something harmless. Returning a body here would be
        # nicer, but the request hook cannot short-circuit the fetch yet.
        return {"url": "https://example.com/"}

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
            }.get(msg.get("hook"), lambda _msg: {})
            reply = handler(msg)
        except Exception as e:  # never die: a broken plugin should not break browsing
            log(f"error: {e}")
            reply = {}

        print(json.dumps(reply), flush=True)


if __name__ == "__main__":
    main()
