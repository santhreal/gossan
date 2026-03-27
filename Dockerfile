# syntax=docker/dockerfile:1
# Gossan - Web reconnaissance and crawling toolkit

FROM rust:1.85 AS builder

WORKDIR /build

# Copy workspace manifest first for dependency caching
COPY Cargo.toml Cargo.lock ./
COPY crates/cli/Cargo.toml ./crates/cli/
COPY crates/core/Cargo.toml ./crates/core/
COPY crates/crawl/Cargo.toml ./crates/crawl/
COPY crates/dns/Cargo.toml ./crates/dns/
COPY crates/subdomain/Cargo.toml ./crates/subdomain/
COPY crates/portscan/Cargo.toml ./crates/portscan/
COPY crates/techstack/Cargo.toml ./crates/techstack/
COPY crates/cloud/Cargo.toml ./crates/cloud/
COPY crates/js/Cargo.toml ./crates/js/
COPY crates/hidden/Cargo.toml ./crates/hidden/
COPY crates/origin/Cargo.toml ./crates/origin/
COPY crates/synscan/Cargo.toml ./crates/synscan/
COPY crates/headless/Cargo.toml ./crates/headless/
COPY crates/checkpoint/Cargo.toml ./crates/checkpoint/
COPY crates/correlation/Cargo.toml ./crates/correlation/

# Create dummy lib files for dependency caching
RUN mkdir -p crates/core/src crates/cli/src crates/crawl/src crates/dns/src \
    crates/subdomain/src crates/portscan/src crates/techstack/src \
    crates/cloud/src crates/js/src crates/hidden/src crates/origin/src \
    crates/synscan/src crates/headless/src crates/checkpoint/src crates/correlation/src && \
    echo "fn main() {}" > crates/cli/src/main.rs && \
    touch crates/core/src/lib.rs crates/crawl/src/lib.rs crates/dns/src/lib.rs \
    crates/subdomain/src/lib.rs crates/portscan/src/lib.rs crates/techstack/src/lib.rs \
    crates/cloud/src/lib.rs crates/js/src/lib.rs crates/hidden/src/lib.rs \
    crates/origin/src/lib.rs crates/synscan/src/lib.rs crates/headless/src/lib.rs \
    crates/checkpoint/src/lib.rs crates/correlation/src/lib.rs

# Build dependencies first
RUN cargo build --release -p gossan-cli 2>/dev/null || true

# Copy actual source code
COPY . .

# Build the actual binary
RUN cargo build --release -p gossan-cli

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r nonroot && useradd -r -g nonroot nonroot

# Copy binary from builder
COPY --from=builder /build/target/release/gossan /usr/local/bin/gossan

# Set up permissions
RUN chmod +x /usr/local/bin/gossan

USER nonroot

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD gossan --help > /dev/null || exit 1

ENTRYPOINT ["gossan"]
