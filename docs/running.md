# What it costs to run

Measured, not estimated. Every number below came off a release build on the
machine described at the bottom; where hardware changes the answer, it says so.

## The short version

mach5 is small at rest and spiky under image conversion. If you size it for the
spikes you will never think about it again.

| | |
| --- | --- |
| **Minimum that works** | 1 core, 512 MB RAM, 2 GB disk |
| **Comfortable** | 2 cores, 1 GB RAM, 4 GB disk |
| **The thing that actually costs** | re-encoding images |
| **The thing that costs nothing** | idling, blocking, cosmetic filtering |

## Memory

| | Resident |
| --- | --- |
| Idle: no lists, no plugins | **9.5 MB** |
| With 127,871 blocklist domains (StevenBlack + EasyList) | **31.4 MB** |
| Peak while converting a 1280px photograph | **25.3 MB** |
| One example plugin, `worker_threads = 4` | **9.9 MB** + the plugin processes |

Blocklists are the predictable cost: roughly **170 bytes of resident memory per
domain**, held for the life of the process. 4.4 MB of list text becomes about
22 MB in memory, because it is a hash set of owned strings rather than the file.

The unpredictable cost is image conversion, and it is worth understanding
because it is the only thing here that can surprise you.

**A decoded image costs `width × height × 4` bytes, whatever the file
compressed to.** A two-megabyte PNG of a flat colour can be 11000×11000, which
is 484 MB of pixels. That is why `[images] max_megapixels` exists and defaults
to 16 — a 4000×4000 image, past anything anyone puts on a page. At that cap one
conversion peaks around 64 MB.

Conversions can overlap. There are two interceptor chains — the QUIC worker pool
and the TCP one — so up to `worker_threads × 2` can be in flight. On a four-core
box at the default `1C`, that is eight, and the worst case is
`8 × max_megapixels × 4 bytes` ≈ 512 MB.

**On a small box, turn `max_megapixels` down before anything else.** At 4 it is
64 MB worst case across all workers, and you lose only images larger than
2000×2000, which are rare and were never going to convert quickly anyway.

## CPU

Idle is genuinely idle — an event loop and some parked threads.

Image conversion is the only CPU-bound work, and it scales with pixels rather
than with bytes. Measured end to end against a real photograph:

| | Bytes | Time |
| --- | --- | --- |
| Direct from the origin | 72,790 | 0.165 s |
| Through mach5, first time | 25,658 | 0.233 s |
| Through mach5, cached | 25,658 | **0.033 s** |

**−65% bytes.** The first fetch is ~70 ms slower — that is the conversion, paid
once — and every fetch after it is five times faster than going to the origin at
all, because the answer is already on disk.

That table is the whole product in miniature: mach5 costs you something the
first time and pays it back on repeats, which is why it is worth more on a
connection where bytes are expensive than on one where they are not.

Blocking, cosmetic filtering and header rewriting do not register. HTML
rewriting is a streaming parse and does not either.

## Startup

| | |
| --- | --- |
| Bare | **11 ms** |
| With 127,871 blocklist domains | **78 ms** |
| One plugin, `worker_threads = 1` | 25 ms, 2 plugin processes |
| One plugin, `worker_threads = 4` | 79 ms, 8 plugin processes |

Plugins are launched **`worker_threads × 2` times** — once per chain, and both
pools build their own — so the process count is the number to watch if your
plugins are heavy. Sixteen Python interpreters on an eight-core box is the
default, and it is deliberate: no lock contention between workers.

If a script talks to the proxy immediately after starting it, retry the first
connection. Two false bug reports have come from exactly that.

## Disk

Bounded by configuration, so it cannot run away:

| | Default |
| --- | --- |
| `[images] cache_mb` — WebP re-encodings | 512 MB |
| `[images] origin_cache_mb` — origins' own bytes | 256 MB |
| Blocklists and cosmetic lists, cached | size of the lists, ~5 MB |
| State — hidden selectors, settings | kilobytes |

Measured: one 72 KB photograph occupies **40 KB** across both caches, since the
converted copy is smaller than the original and both are kept.

Set either `*_mb` to 0 to switch that cache off. Switching off the image cache
means paying the conversion on every request, which on a small box is worse than
the disk it saves.

## Network

One upstream connection per in-flight request; mach5 does not multiplex to
origins. Response bodies stream in 64 KB chunks, and no more than
`[limits] stream_buffer_mb` of any one response is ever held in memory — 32 MB
by default, per response, on both front ends.

`[limits] max_response_body_mb` bounds what a buffered body may allocate, 64 MB
by default, applied both to what arrives and to what it inflates to.

## What was measured, and on what

A release build (`cargo build --release`), on x86-64 with 32 cores and 64 GB,
inside a container. Startup and memory sampled at the moment the listener
accepts; the image figures are `curl` against a real Wikimedia photograph
through a real proxy.

**On slower hardware, scale the conversion time and leave the rest alone.**
Memory and startup are dominated by list parsing and process launches, which are
not sensitive to core count. Image conversion is proportional to pixels and to
single-core speed — a Raspberry Pi will take several times longer per image,
which is the argument for keeping `[images] cache_mb` generous there rather than
turning it off.
