> Part of the [Santh](https://santh.io) security research ecosystem.

# gossan

[![CI](https://github.com/santhsecurity/gossan/actions/workflows/ci.yml/badge.svg)](https://github.com/santhsecurity/gossan/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Crates.io](https://img.shields.io/crates/v/gossan)](https://crates.io/crates/gossan)

**Fast, modular attack surface discovery.** Subdomains, ports, tech stack, hidden paths, cloud assets, DNS security, origin IP — all in one scan.

## Install

```bash
cargo install gossan
```

## Usage

```bash
# Full recon scan
gossan scan example.com

# Specific modules
gossan scan example.com --modules subdomain,portscan,hidden

# Custom ports
gossan scan example.com --ports 80,443,8080,8443

# JSON output
gossan scan example.com --format json -o results.json
```

## Architecture

Gossan is a workspace of independent, reusable crates. Each crate is a standalone scanner that can be used independently or composed through the `gossan` CLI.

| Crate | Description |
|-------|-------------|
| `gossan-core` | Core types, traits, config, rate limiting |
| `gossan-subdomain` | Subdomain enumeration (CT logs, Wayback, DNS brute) |
| `gossan-portscan` | TCP port scanning with TLS inspection and banner grabbing |
| `gossan-techstack` | Technology fingerprinting (headers, cookies, HTML patterns) |
| `gossan-dns` | DNS security auditing (SPF, DMARC, DKIM, CAA, zone transfer) |
| `gossan-hidden` | Hidden endpoint discovery (dirbusting, sitemap, robots.txt, swagger) |
| `gossan-cloud` | Cloud asset discovery (S3, GCS, Azure blobs) |
| `gossan-js` | JavaScript analysis (secrets, API endpoints, WASM) |
| `gossan-origin` | Origin IP discovery (bypass CDN/WAF) |
| `gossan-crawl` | Authenticated web crawler with form/parameter extraction |
| `gossan-correlation` | Cross-module finding correlation |
| `gossan-checkpoint` | Scan checkpoint and resume |
| `gossan-synscan` | Raw socket SYN scanning (requires root) |
| `gossan-headless` | Headless browser integration |

## As a Library

```rust
use gossan_portscan::PortScanner;
use gossan_core::{Config, Scanner, ScanInput, Target};

let scanner = PortScanner;
let config = Config::default();
let input = ScanInput { targets: vec![/* ... */] };
let output = scanner.run(input, &config).await?;
```

## License

MIT — [Santh Security](https://santh.io)
