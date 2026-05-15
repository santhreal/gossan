> Part of the [Santh](https://santh.dev) security research ecosystem.

# gossan

[![CI](https://github.com/santhsecurity/gossan/actions/workflows/ci.yml/badge.svg)](https://github.com/santhsecurity/gossan/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Crates.io](https://img.shields.io/crates/v/gossan)](https://crates.io/crates/gossan)

**Fast, modular attack surface discovery.** Subdomains, ports, tech stack, hidden paths, cloud assets, DNS security, origin IP: all in one scan.

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

# Probe which packet I/O backend the SYN engine would select
gossan probe-engine

# Adaptive (AIMD) rate control — halves on TX-drop bursts, recovers slowly
gossan scan example.com --adaptive-rate

# Other formats: SARIF (security-tool integration), nmap-xml (-oX),
# masscan-grep (-oG), graphml (Gephi/Cytoscape/yEd).
gossan scan example.com --format sarif -o report.sarif
gossan scan example.com --format nmap-xml -o scan.xml
```

## Output formats

| `--format`       | aliases             | use case |
|------------------|---------------------|----------|
| `text`           | (default)           | human terminal |
| `json`           | —                   | scripting / pipeline (top-level array of `Finding`) |
| `jsonl`          | `ndjson`            | streaming / log shippers |
| `sarif`          | —                   | GitHub code-scanning, sarif-multitool |
| `markdown`       | `md`                | issue body / wiki |
| `nmap-xml`       | `nmap`, `xml`, `-oX`| drop-in for nmap consumers |
| `masscan-grep`   | `grepable`, `-oG`   | drop-in for masscan consumers |
| `graphml`        | `graph-ml`          | Gephi / Cytoscape / yEd |

## Environment variables

| var                                        | effect |
|--------------------------------------------|--------|
| `GOSSAN_LOG_JSON=1`                        | structured JSON logs (Loki/CloudWatch/Datadog) |
| `GOSSAN_ALLOW_UNSAFE_PATHS=1`              | override `--out` path-traversal guard |
| `GITHUB_TOKEN`                             | scm GitHub org enumeration |
| `GITLAB_TOKEN`                             | scm GitLab group enumeration |
| `CENSYS_API_ID` + `CENSYS_API_SECRET`      | origin Censys integration |
| `SHODAN_API_KEY`                           | origin favicon-hash cross-reference |
| `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` | cloud inside-out discovery |


## Screenshots

```
+-------------------------------------------------------------+
| gossan scan example.com                                     |
+-------------------------------------------------------------+
| [✓] Subdomain Enum      : 124 found                         |
| [✓] Port Scanning       : 12 open ports                     |
| [✓] Tech Fingerprinting : React, Nginx, PHP                 |
| [✓] Cloud Assets        : 1 S3 bucket found (public!)       |
|                                                             |
| Findings:                                                   |
| - [HIGH] S3 Bucket 'example-backup' is publicly readable.   |
| - [MED]  Exposed .git directory at dev.example.com/.git/    |
| - [LOW]  Missing DMARC record on mail.example.com           |
+-------------------------------------------------------------+
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
| `gossan-engine` | Stateless masscan-class SYN engine (netforge, requires root) |
| `gossan-headless` | Headless browser integration |
| `gossan-horizontal` | Horizontal discovery (ASN/BGP mapping + ownership) |
| `gossan-graph` | Graph-based Attack Surface Management (ASM) |
| `gossan-scm` | Source Control Mapping (GitHub/GitLab discovery) |
| `gossan-intel` | Global Passive Intel (Local bulk dataset indexing) |
| `gossan-fleet` | Distributed Master/Worker orchestration |

## Conservative Campaign Mapper

When `--conservative` is set, Gossan runs a **zero-false-positive horizontal asset validator** that confirms whether candidate domains/IPs truly belong to the same organization or campaign before feeding them downstream into Warpscan (static rule scanning) and Sear (URL detonation).

**Every candidate is tested pairwise against the seed using multiple independent signals:**

| Signal | Weight | Description |
|--------|--------|-------------|
| TLS Certificate Serial | High | Same leaf cert = same deployment |
| SSH Host Key | High | Same key exchange fingerprint |
| Shared GA/GTM Trackers | High | Same analytics property = same operator |
| WHOIS Registrant Match | Medium | Ownership-level correlation |
| Favicon Hash (mmh3) | Medium | Shodan-compatible favicon fingerprint |
| Content Hash | Medium | Identical page content |
| Error Page Structure | Medium | Hash DOM structure of 404 page (survives content rotation) |
| HTTP/2 SETTINGS Fingerprint | Low | Server SETTINGS frame = deployment config |
| Header Ordering | Low | Response header sequence = middleware stack |
| JARM TLS Fingerprint | Low | TLS stack fingerprint (high ambient noise from CDNs) |
| DNS Resolution IP | Low | Shared hosting makes this noisy alone |

**Scoring rules:**
- Known CDN/shared-hosting values (Cloudflare JARM, default favicons, AWS ELB IPs) are **blocklisted** and receive zero weight.
- A candidate must exceed a **multi-signal threshold**: no single weak signal can produce a match.
- Each emitted match carries a **confidence tier** (High/Medium/Low) so downstream consumers can decide their own risk tolerance.

```bash
# Conservative mode for safe downstream feeding
gossan scan example.com --conservative

# Pairs with:
warpscan scan ./campaign-assets --rules-dir ./rules   # Static rule matching
sear analyze "https://candidate.evil.tk" --depth full  # URL detonation
```

## Legendary Accuracy: Differential Signal Intelligence

Gossan is the only scanner designed to survive the **"Mirror Maze"**: environments where thousands of subdomains or paths alias to a single root asset.

- **Response Baselining**: Every new host is interrogated with randomized "garbage" paths to establish a structural baseline (DOM tree, fuzzy hashes, and header signatures).
- **Structural Delta Engine**: Subsequent discoveries are compared against this baseline. Assets with >98% structural similarity are flagged as **Mirror Assets** and automatically **braked** to save bandwidth.
- **Signal Sniping**: Outliers that break the pattern (e.g., a single `openapi.json` hidden in a sea of mirrors) are promoted as **Signal Assets** for deep analysis.
- **Response Bomb Shield**: Hard-killing TCP connections that exceed safe `Content-Length` thresholds (5MB HTML / 10MB JS) to prevent OOM attacks.

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

MIT: [Santh Security](https://santh.dev)
