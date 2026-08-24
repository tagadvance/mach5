# mach5 proxy.
#
# BoringSSL is compiled from source as part of quiche, which needs cmake, a C
# compiler and perl at build time — but nothing at runtime, so the final image
# stays slim. libclang is needed too: boring-sys generates its bindings with
# bindgen, which loads libclang at build time.

FROM rust:1.90-trixie AS builder

RUN apt-get update \
	&& apt-get install --yes --no-install-recommends cmake libclang-dev \
	&& rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Prime the dependency cache first. BoringSSL alone takes minutes to compile and
# only needs redoing when the manifests change, so keep it off the edit loop.
COPY proxy/Cargo.toml proxy/Cargo.lock ./
RUN mkdir src \
	&& echo 'fn main() {}' > src/main.rs \
	&& cargo build --release \
	&& rm -rf src

COPY proxy/src ./src
# cargo decides by mtime, and COPY can preserve an older one, so make sure the
# real sources look newer than the placeholder build above.
RUN touch src/main.rs && cargo build --release


FROM debian:trixie-slim

# ca-certificates is not optional: it is what lets the proxy validate the
# certificates of the origins it fetches. python3 is here only for the example
# plugin — drop it if your plugins are compiled or written in another language.
RUN apt-get update \
	&& apt-get install --yes --no-install-recommends ca-certificates python3 \
	&& rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --uid 10001 mach5

# Owned up front so the unprivileged user can write here even when no volume is
# mounted over it.
RUN mkdir -p /var/cache/mach5 && chown mach5:mach5 /var/cache/mach5

COPY --from=builder /build/target/release/mach5-proxy /usr/local/bin/mach5-proxy

# Config, plugins and the CA are mounted under here. Paths in mach5.toml are
# resolved relative to this directory.
WORKDIR /etc/mach5

USER mach5
ENV MACH5_CONFIG=/etc/mach5/mach5.toml

# TCP first (browsers start there), then QUIC once Alt-Svc has moved them over.
EXPOSE 443/tcp
EXPOSE 443/udp

ENTRYPOINT ["mach5-proxy"]
