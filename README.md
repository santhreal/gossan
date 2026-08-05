> Part of the [Santh](https://santh.dev) security research ecosystem.

# gossan

[![CI](https://github.com/santhreal/gossan/actions/workflows/ci.yml/badge.svg)](https://github.com/santhreal/gossan/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Crates.io](https://img.shields.io/crates/v/gossan)](https://crates.io/crates/gossan)

**Fast, modular attack surface discovery.** Subdomains, ports, tech stack, hidden paths, cloud assets, DNS security, origin IP: all in one scan.

## Install

Prefer a **GitHub Release binary**. `cargo install` works, but release archives are what we test for day-one speed and reliability.

### One-liner (recommended)

**Linux / macOS**

```bash
curl -sSfL https://raw.githubusercontent.com/santhreal/gossan/main/scripts/install.sh | bash
```

**Windows (PowerShell)**

```powershell
irm https://raw.githubusercontent.com/santhreal/gossan/main/scripts/install.ps1 | iex
```

The installer downloads the matching release asset, verifies the SHA-256 sidecar when present, copies `gossan` into a durable directory (not a symlink into `/tmp`), checks `--version`, and prints PATH instructions when needed.

### Copy-paste: download + PATH (every OS)

Asset names are stable under [`/releases/latest/download/`](https://github.com/santhreal/gossan/releases/latest) so these URLs do not need a version pin.

#### Linux x86_64

```bash
mkdir -p "$HOME/.local/bin"
curl -fsSL -o /tmp/gossan.tgz \
  https://github.com/santhreal/gossan/releases/latest/download/gossan-x86_64-unknown-linux-gnu.tar.gz
tar -xzf /tmp/gossan.tgz -C /tmp
install -m 0755 /tmp/gossan-x86_64-unknown-linux-gnu/gossan "$HOME/.local/bin/gossan"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
gossan --version
```

#### Linux aarch64 (ARM64)

```bash
mkdir -p "$HOME/.local/bin"
curl -fsSL -o /tmp/gossan.tgz \
  https://github.com/santhreal/gossan/releases/latest/download/gossan-aarch64-unknown-linux-gnu.tar.gz
tar -xzf /tmp/gossan.tgz -C /tmp
install -m 0755 /tmp/gossan-aarch64-unknown-linux-gnu/gossan "$HOME/.local/bin/gossan"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
gossan --version
```

#### macOS Apple Silicon (aarch64)

```bash
mkdir -p "$HOME/.local/bin"
curl -fsSL -o /tmp/gossan.tgz \
  https://github.com/santhreal/gossan/releases/latest/download/gossan-aarch64-apple-darwin.tar.gz
tar -xzf /tmp/gossan.tgz -C /tmp
install -m 0755 /tmp/gossan-aarch64-apple-darwin/gossan "$HOME/.local/bin/gossan"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
gossan --version
```

#### macOS Intel (x86_64)

```bash
mkdir -p "$HOME/.local/bin"
curl -fsSL -o /tmp/gossan.tgz \
  https://github.com/santhreal/gossan/releases/latest/download/gossan-x86_64-apple-darwin.tar.gz
tar -xzf /tmp/gossan.tgz -C /tmp
install -m 0755 /tmp/gossan-x86_64-apple-darwin/gossan "$HOME/.local/bin/gossan"
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
gossan --version
```

#### Windows x86_64 (PowerShell)

```powershell
$dir = Join-Path $env:LOCALAPPDATA "gossan\bin"
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$zip = Join-Path $env:TEMP "gossan.zip"
Invoke-WebRequest -Uri "https://github.com/santhreal/gossan/releases/latest/download/gossan-x86_64-pc-windows-msvc.zip" -OutFile $zip
Expand-Archive -Force $zip $env:TEMP
Copy-Item -Force (Join-Path $env:TEMP "gossan-x86_64-pc-windows-msvc\gossan.exe") (Join-Path $dir "gossan.exe")
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($userPath -split ";" | Where-Object { $_ -eq $dir })) {
  [Environment]::SetEnvironmentVariable("Path", "$dir;$userPath", "User")
}
$env:Path = "$dir;$env:Path"
gossan --version
```

#### Verify checksums (optional but recommended)

Each asset ships a `.sha256` sidecar:

```bash
curl -fsSL -O https://github.com/santhreal/gossan/releases/latest/download/gossan-x86_64-unknown-linux-gnu.tar.gz
curl -fsSL -O https://github.com/santhreal/gossan/releases/latest/download/gossan-x86_64-unknown-linux-gnu.tar.gz.sha256
sha256sum -c gossan-x86_64-unknown-linux-gnu.tar.gz.sha256
```

Pin a version by swapping `latest/download` for `download/v0.3.3` (or set `GOSSAN_VERSION=0.3.3` for the install scripts).

### From crates.io / source

Every `v*.*.*` tag also publishes **all** workspace crates to crates.io
(`scripts/publish.sh` via the release workflow). Prefer the GitHub Release
binary above for day-one speed; use crates.io when you want `cargo install`.

```bash
# crates.io (needs a recent Rust toolchain + protoc for fleet)
cargo install gossan --locked

# from a local checkout
cargo install --path crates/cli --locked
```

Add Cargo's bin dir to PATH if needed:

```bash
# Linux / macOS
echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc

# Windows PowerShell
[Environment]::SetEnvironmentVariable("Path", "$env:USERPROFILE\.cargo\bin;$([Environment]::GetEnvironmentVariable('Path','User'))", "User")
```

### Docker

```bash
docker build -t gossan .
docker run --rm gossan --version
# SYN engine needs CAP_NET_RAW:
docker run --rm --cap-add=NET_RAW gossan probe-engine
```

### After install

```bash
gossan --version
gossan probe-engine   # which packet backend the SYN engine would pick
gossan scan example.com --no-subdomain --no-js --no-hidden --no-cloud --no-headless --no-crawl --no-origin --no-horizontal --no-graph --no-scm --no-intel --no-fleet
```

## Usage

```bash
# Full recon scan
gossan scan example.com

# Specific modules (skip heavy ones, or invoke a single module)
gossan scan example.com --no-js --no-cloud --no-headless --no-crawl --no-origin --no-horizontal --no-graph --no-scm --no-intel --no-fleet
gossan subdomain example.com
gossan ports example.com
gossan hidden example.com
gossan tech example.com

# Custom ports
gossan scan example.com --ports 80,443,8080,8443

# JSON output
gossan scan example.com --format json -o results.json

# Probe which packet I/O backend the SYN engine would select
gossan probe-engine

# Adaptive (AIMD) rate control, halves on TX-drop bursts, recovers slowly
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
| `json`           | | scripting / pipeline (top-level array of `Finding`) |
| `jsonl`          | `ndjson`            | streaming / log shippers |
| `sarif`          | | GitHub code-scanning, sarif-multitool |
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

## Oneshot Accuracy: Differential Signal Intelligence

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
