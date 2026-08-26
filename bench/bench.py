#!/usr/bin/env python3
"""Measure what mach5 costs and what it saves.

Fetches each page twice — once straight at the origin, once through a running
proxy — and reports bytes on the wire and wall time for each. With
`--subresources` it also pulls what the page references, which is closer to
what a browser actually does and is where blocking and compression show up.

Nothing here is a page-load benchmark in the browser sense: there is no
renderer, so no paint, no layout, no JavaScript. What it does measure is the
part mach5 can change — how many bytes cross the wire, and how long the
transfers take — which is enough to tell whether an optimisation was worth
having.

    ./bench/bench.py --ca security/mach5_root_cert.pem --port 4443

Bytes are counted with `--raw`, so what is reported is what crossed the wire,
compressed as it was sent, not what the client had after decoding it.

Two things to hold in mind when reading the result:

- **The injected picker is not counted.** It is the cost of a feature, not
  proxy overhead, and including it would compare a page against a different
  page. Both columns fetch the same URLs.
- **A saving is not a speed-up.** Fewer bytes over a local hop can still take
  longer than more bytes direct, and the time column will say so.
"""

import argparse
import json
import pathlib
import re
import statistics
import subprocess
import sys
import tempfile
import urllib.parse

# Enough of a spread to be worth reading: a heavy news page carrying adverts, a
# text-first page that is already lean, a big documentation page, and a site
# that serves no compression at all.
DEFAULT_PAGES = [
    "https://www.theguardian.com/international",
    "https://danluu.com/",
    "https://sqlite.org/index.html",
    "https://info.cern.ch/",
]

ASSET = re.compile(
    rb"""<(?:script|link|img)\b[^>]*?\b(?:src|href)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# A browser's, so origins answer the way they would in real use.
ACCEPT_ENCODING = "gzip, deflate, br, zstd"


def curl(url, *, ca=None, resolve=None, decode=False, timeout=30):
    """One fetch. Returns (wire_bytes, seconds, status, body), or None.

    The body goes to a file rather than sharing stdout with the measurements:
    a page contains newlines and spaces, so anything that tries to pick the
    numbers back out of the same stream is guessing.

    By default the body is left encoded as it arrived, so `size_download` is
    the number that matters — what crossed the wire. `decode=True` is for the
    one case that needs to read the HTML rather than weigh it, and its byte
    count is the decoded size instead.
    """
    with tempfile.NamedTemporaryFile() as body_file:
        command = [
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            str(timeout),
            "--write-out",
            "%{size_download} %{time_total} %{http_code}",
            "--output",
            body_file.name,
        ]
        if decode:
            # Ask for, and undo, whatever coding the origin offers.
            command.append("--compressed")
        else:
            command += ["--header", f"accept-encoding: {ACCEPT_ENCODING}", "--raw"]
        if ca:
            command += ["--cacert", ca]
        if resolve:
            command += ["--resolve", resolve]
        command.append(url)

        done = subprocess.run(command, capture_output=True, text=True)
        if done.returncode != 0:
            return None

        parts = done.stdout.split()
        if len(parts) != 3:
            return None

        body = pathlib.Path(body_file.name).read_bytes()

    return int(parts[0]), float(parts[1]), int(parts[2]), body


def through_proxy(url, host, port, ca, decode=False):
    """The same fetch, but resolved at the proxy.

    `--resolve` is what stands in for the wildcard DNS a real deployment uses:
    the name is unchanged, so the proxy still learns the origin from SNI.
    """
    origin = urllib.parse.urlsplit(url)
    proxied = url.replace(f"//{origin.netloc}", f"//{origin.netloc}:{port}", 1)

    return curl(
        proxied,
        ca=ca,
        resolve=f"{origin.hostname}:{port}:{host}",
        decode=decode,
    )


def subresources(page_url, body, limit):
    """Absolute URLs for what the page references, in document order."""
    found = []
    for raw in ASSET.findall(body):
        url = urllib.parse.urljoin(page_url, raw.decode("utf-8", "replace"))
        if not url.startswith("https://") or url in found:
            continue
        found.append(url)
        if len(found) >= limit:
            break

    return found


def median_of(runs):
    return statistics.median(runs) if runs else 0


def measure(direct_urls, proxied_urls, host, port, ca, repeat):
    """Bytes and seconds for what each side fetches.

    Both sides fetch the same list. The picker mach5 injects is not in it: it
    buys a feature, and weighing a feature against its own absence says nothing
    about whether the proxy makes the web lighter. What is measured here is the
    same bytes, fetched both ways.
    """
    direct_bytes = direct_time = 0
    proxied_bytes = proxied_time = 0
    failures = []

    for url in direct_urls:
        runs = [curl(url) for _ in range(repeat)]
        if any(r is None for r in runs):
            failures.append(url)
            continue

        direct_bytes += int(median_of([r[0] for r in runs]))
        direct_time += median_of([r[1] for r in runs])

    for url in proxied_urls:
        runs = [through_proxy(url, host, port, ca) for _ in range(repeat)]
        if any(r is None for r in runs):
            failures.append(url)
            continue

        proxied_bytes += int(median_of([r[0] for r in runs]))
        proxied_time += median_of([r[1] for r in runs])

    return direct_bytes, direct_time, proxied_bytes, proxied_time, failures


def stats(host, port, ca):
    """The proxy's own counters, so a run can say what it thinks it did."""
    got = curl(
        f"https://localhost:{port}/.mach5/stats.json",
        ca=ca,
        resolve=f"localhost:{port}:{host}",
        decode=True,
    )
    if not got or got[2] != 200:
        return {}

    try:
        return json.loads(got[3])
    except json.JSONDecodeError:
        return {}


def human(count):
    for unit in ("B", "KB", "MB"):
        if abs(count) < 1024 or unit == "MB":
            return f"{count:,.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1024


def delta(before, after):
    if not before:
        return "     —"
    return f"{(after - before) / before * 100:+6.1f}%"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="where the proxy is listening")
    parser.add_argument("--port", type=int, default=4443, help="its TCP port")
    parser.add_argument("--ca", help="its root certificate, so TLS verifies properly")
    parser.add_argument("--pages", help="a file of URLs, one per line; otherwise a built-in set")
    parser.add_argument("--repeat", type=int, default=3, help="fetches per URL; the median is kept")
    parser.add_argument(
        "--subresources",
        type=int,
        default=0,
        metavar="N",
        help="also fetch up to N things each page references",
    )
    args = parser.parse_args()

    if args.pages:
        with open(args.pages) as f:
            pages = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    else:
        pages = DEFAULT_PAGES

    before = stats(args.host, args.port, args.ca)
    if not before:
        print(f"warning: no proxy answering on {args.host}:{args.port}", file=sys.stderr)

    print(f"{'page':<44}{'direct':>12}{'proxied':>12}{'bytes':>8}{'time':>8}")
    print("-" * 84)

    totals = [0, 0.0, 0, 0.0]
    for page in pages:
        direct_urls = [page]
        proxied_urls = [page]

        if args.subresources:
            # The baseline comes from the page as the origin wrote it. Taking
            # it from the proxied copy instead would collect mach5's own
            # injected tags and compare them against a 404 — which is how this
            # was wrong the first time.
            plain = curl(page, decode=True)
            if plain:
                shared = subresources(page, plain[3], args.subresources)
                direct_urls += shared
                proxied_urls += shared

        d_bytes, d_time, p_bytes, p_time, failed = measure(
            direct_urls, proxied_urls, args.host, args.port, args.ca, args.repeat
        )
        if failed and len(failed) >= len(direct_urls):
            print(f"{page[:43]:<44}{'unreachable':>12}")
            continue

        label = page[:43] + (f" +{len(direct_urls) - 1}" if len(direct_urls) > 1 else "")
        print(
            f"{label[:43]:<44}{human(d_bytes):>12}{human(p_bytes):>12}"
            f"{delta(d_bytes, p_bytes):>8}{delta(d_time, p_time):>8}"
        )

        totals[0] += d_bytes
        totals[1] += d_time
        totals[2] += p_bytes
        totals[3] += p_time

    print("-" * 84)
    print(
        f"{'total':<44}{human(totals[0]):>12}{human(totals[2]):>12}"
        f"{delta(totals[0], totals[2]):>8}{delta(totals[1], totals[3]):>8}"
    )

    after = stats(args.host, args.port, args.ca)
    if before and after:
        moved = {k: after.get(k, 0) - before.get(k, 0) for k in after if isinstance(after[k], int)}
        print(
            f"\nthe proxy's own account: {moved.get('requests', 0)} requests, "
            f"{moved.get('blocked', 0)} blocked, {moved.get('injected', 0)} pages injected, "
            f"{human(moved.get('bytes_saved_by_compression', 0))} saved by compressing"
        )


if __name__ == "__main__":
    main()
