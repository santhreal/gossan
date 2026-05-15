# syntax=docker/dockerfile:1
# Gossan — attack-surface discovery CLI
#
# Multi-stage build:
#   1. `builder` compiles the cli binary against the pinned workspace.
#   2. `runtime` is a slim debian image carrying just the binary and
#      its runtime deps (TLS roots + libssl).

ARG RUST_VERSION=1.85
FROM rust:${RUST_VERSION} AS builder

WORKDIR /build

# Copy the whole tree. We don't bother with the dummy-lib trick because
# this image is meant to produce a release binary; iterative dev should
# happen on the host with `cargo build` and the host's incremental cache.
COPY . .

# Build the cli binary. Bin name is `gossan` (see crates/cli/Cargo.toml).
RUN cargo build --release -p gossan

# ── Runtime stage ─────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Non-root execution by default. Engine mode (raw SYN scanning) needs
# CAP_NET_RAW — grant it explicitly via `docker run --cap-add=NET_RAW`
# rather than running the container as root.
RUN groupadd -r gossan && useradd -r -g gossan -m -d /home/gossan gossan
USER gossan
WORKDIR /home/gossan

COPY --from=builder /build/target/release/gossan /usr/local/bin/gossan

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD gossan --version > /dev/null || exit 1

ENTRYPOINT ["gossan"]
