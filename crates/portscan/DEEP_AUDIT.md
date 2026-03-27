# Deep Audit: gossan-portscan

**Date:** 2026-03-26  
**LOC:** ~1,734 lines (including tests)  
**Crates:** Single crate with 6 modules  

---

## 1. Does It Actually Scan Ports Correctly?

### ✅ YES - Core scanning is functional and well-implemented

**How it works:**
- Uses `tokio::net::TcpStream` with `futures::stream::iter().buffer_unordered()` for concurrent connections
- Hardcoded 800ms timeout for banner reading (line 408 in `lib.rs`)
- Supports SOCKS5 proxy via `gossan_core::net::connect_tcp()`
- Concurrency is configurable via `Config.concurrency` (default: 200)

**Port probing flow (`probe_port()`):**
1. TCP connect with timeout
2. Grab banner (first 512 bytes, printable ASCII only)
3. Check if port is in TLS list (443, 8443, 465, 993, 636)
4. For TLS ports: probe certificate, check expiry, detect self-signed, run JARM fingerprint
5. For legacy TLS: probe TLS 1.0/1.1 support via raw ClientHello
6. Banner identification and CVE correlation

**Limitations:**
- **TCP connect only** - No SYN stealth scanning (requires root)
- **Banner grabbing is passive** - Doesn't send protocol-specific probes (e.g., no HTTP request sent)
- **Fixed 800ms read timeout** - May miss slow banners
- **No UDP scanning** - Only TCP supported

**Test coverage:** Good unit tests for banner identification, CVE correlation, TLS parsing

---

## 2. What Protocols Does It Detect?

### Protocol Detection Summary

| Protocol | Detection Method | Accuracy | Notes |
|----------|-----------------|----------|-------|
| **SSH** | Banner prefix `SSH-` | ✅ High | Version parsed, old versions flagged |
| **FTP** | Port 21 + `220`/`230` response | ⚠️ Medium | Basic banner only |
| **SMTP** | Port 25/465/587 + `220` response | ⚠️ Medium | Basic banner only |
| **HTTP** | Banner prefix `http/` + Server header | ⚠️ Medium | Passive only, no active probe |
| **Redis** | Port 6379 + `+` or `-` response | ✅ High | Detects unauthenticated access |
| **MongoDB** | Port 27017 + `MongoDB`/`ismaster` | ✅ High | Detects unauthenticated access |
| **Telnet** | Port 23 + any response | ✅ High | Critical severity flagged |
| **TLS/HTTPS** | Port-based (443, 8443, etc) + cert inspection | ✅ High | Full cert parsing, SAN extraction |

### TLS Inspection Capabilities

**Certificate extraction:**
- Subject, Issuer, SANs
- Expiry checking (alerts at 30/14/0 days)
- Self-signed detection
- SAN domains added as new targets for pipeline

**Legacy TLS detection:**
- Raw ClientHello probing for TLS 1.0/1.1
- Detects BEAST/POODLE vulnerable configurations

**JARM Fingerprinting:**
- 10-probe suite with varying cipher orders, TLS versions, ALPN
- Known fingerprints for: Cobalt Strike, Metasploit, Sliver, Havoc, BruteRatel
- Also fingerprints legit servers (nginx, Apache, IIS, Cloudflare)

### What's Missing

- **No service version probing** - Doesn't send version queries
- **No protocol negotiation** - SSH, SMTP, FTP detection is banner-only
- **No HTTP主动探测** - Only reads initial response, doesn't send HTTP request
- **No UDP services** - DNS, SNMP, NTP not detected
- **No database protocol deep inspection** - MySQL, PostgreSQL, MSSQL banners not parsed

---

## 3. Is It Faster Than nmap for Basic Scans?

### Performance Comparison

| Metric | gossan-portscan | nmap (default) | Notes |
|--------|-----------------|----------------|-------|
| **Scan type** | TCP connect | SYN stealth | nmap requires root for SYN |
| **Concurrency** | Async tokio (200 default) | Adaptive | Both highly concurrent |
| **Default ports** | 52 high-risk | 1000 common | gossan more targeted |
| **Banner grabbing** | 800ms timeout per port | Configurable | Similar |
| **TLS inspection** | ~10 probes per TLS port | Limited | gossan more thorough |

### Benchmark Estimates (hypothetical)

**Single host, default ports (52 ports):**
- gossan: ~1-3 seconds (including TLS inspection on ~5-10 ports)
- nmap: ~2-5 seconds (with service detection `-sV`)

**Single host, top 1000 ports:**
- gossan: ~10-30 seconds
- nmap: ~30-60 seconds (with service detection)

### Speed Advantages

1. **Async/await throughout** - No thread per connection overhead
2. **Targeted port list** - Default 52 ports vs nmap's 1000
3. **Parallel TLS inspection** - JARM + cert + legacy TLS all concurrent
4. **Built-in banner correlation** - No post-processing needed

### Speed Disadvantages

1. **TCP connect only** - nmap SYN scan is faster and stealthier (requires root)
2. **JARM adds overhead** - 10 probes per TLS port
3. **No host discovery** - nmap has optimized ping sweeps
4. **Rust compile time** - Development iteration slower than nmap

### Verdict

**For the specific use case (security scanning, finding exposures):**  
✅ **Yes, competitive with nmap** for targeted scans with service detection enabled (`-sV`)

**For network reconnaissance:**  
❌ **No, nmap is more versatile** - SYN stealth, UDP, OS detection, script engine

---

## 4. What's Coupled to gossan-core vs What's Generic?

### Tight Coupling to gossan-core

| Component | Core Dependency | Standalone Blocker |
|-----------|-----------------|-------------------|
| `PortScanner` struct | `Scanner` trait from core | HIGH - Core abstraction |
| `probe_port()` returns | `ServiceTarget`, `Finding`, `Target` | HIGH - Core types |
| `identify_banner()` | `Finding`, `Severity`, `Evidence` | HIGH - Core types |
| `make_finding()` helper | `gossan_core::make_finding()` | HIGH - Finding construction |
| `FindingExt` trait | `gossan_core::FindingExt` | MEDIUM - Builder methods |
| `Config` struct | `PortMode`, `timeout()`, `proxy` | MEDIUM - Configuration |
| `connect_tcp()` | `gossan_core::net::connect_tcp` | LOW - Can be inlined |

### Generic/Standalone Components

| Component | Standalone Ready | Notes |
|-----------|-----------------|-------|
| `top_ports.rs` | ✅ YES | Pure data tables |
| `jarm.rs` | ✅ YES | Only needs `connect_tcp` |
| `tls.rs` | ⚠️ PARTIAL | Needs `connect_tcp`, returns custom types |
| `cve.rs` | ⚠️ PARTIAL | Uses `Finding`, `ServiceTarget` from core |
| Banner grabbing logic | ✅ YES | Pure tokio code |
| Protocol detection patterns | ✅ YES | String matching only |

### Dependency Graph

```
gossan-portscan
├── gossan-core (required)
│   ├── Config (port_mode, timeout, proxy, concurrency)
│   ├── Scanner trait (async_trait)
│   ├── Target enum (Domain, Host, Service)
│   ├── Finding, Severity, Evidence
│   ├── FindingExt trait
│   └── net::connect_tcp
├── tokio (async runtime)
├── tokio-rustls + rustls (TLS)
├── x509-cert (cert parsing)
├── sha2 (JARM hashing)
├── serde + toml (CVE rules)
└── async-trait, futures, chrono, tracing, anyhow
```

---

## 5. Could This Be Published as a Standalone Crate?

### ✅ YES - With Moderate Refactoring

**Estimated effort:** 2-3 days of focused work

### Required Changes

#### 1. Extract Generic Types (1 day)

Create new types in the standalone crate:

```rust
// New standalone types
pub struct PortScanResult {
    pub host: String,
    pub port: u16,
    pub state: PortState,  // Open, Closed, Filtered
    pub banner: Option<String>,
    pub tls_info: Option<TlsInfo>,
    pub jarm_fingerprint: Option<String>,
    pub findings: Vec<SecurityFinding>,  // Generic finding type
}

pub struct TlsInfo {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    pub not_after: DateTime<Utc>,
    pub is_self_signed: bool,
    pub supports_tls10: bool,
    pub supports_tls11: bool,
}
```

#### 2. Decouple from Scanner Trait (2-3 hours)

Replace trait implementation with standalone API:

```rust
pub struct PortScanner {
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub concurrency: usize,
    pub proxy: Option<String>,
    pub enable_tls_inspection: bool,
    pub enable_jarm: bool,
}

impl PortScanner {
    pub async fn scan(&self, target: &str) -> Result<Vec<PortScanResult>> {
        // Current logic, adapted
    }
}
```

#### 3. Conditional gossan-core Integration (2-3 hours)

Add feature flag for gossan integration:

```toml
[features]
default = ["standalone"]
gossan-integration = ["gossan-core"]
standalone = []
```

```rust
#[cfg(feature = "gossan-integration")]
mod gossan_adapter {
    // Convert PortScanResult -> gossan_core::Finding
}
```

#### 4. Inline connect_tcp (30 min)

Copy the 13-line function from `gossan_core::net`:

```rust
async fn connect_tcp(addr: &str, port: u16, proxy: Option<&str>) -> io::Result<TcpStream> {
    // Same implementation
}
```

### Standalone Crate Structure

```
gossan-portscan/
├── Cargo.toml
├── src/
│   ├── lib.rs           # Public API
│   ├── scanner.rs       # Core scanning logic (from lib.rs)
│   ├── tls.rs           # TLS inspection (as-is)
│   ├── jarm.rs          # JARM fingerprinting (as-is)
│   ├── banner.rs        # Banner grabbing + protocol ID
│   ├── ports.rs         # Port lists (from top_ports.rs)
│   ├── cve.rs           # CVE correlation (generic findings)
│   └── gossan.rs        # Optional: gossan-core adapter
├── examples/
│   ├── simple_scan.rs
│   └── tls_inspection.rs
└── tests/
```

### Public API Proposal

```rust
use gossan_portscan::{PortScanner, PortMode, TlsConfig};

#[tokio::main]
async fn main() -> Result<()> {
    let scanner = PortScanner::builder()
        .ports(PortMode::Top100)
        .timeout(Duration::from_secs(5))
        .concurrency(500)
        .tls_inspection(true)
        .jarm_fingerprinting(true)
        .build();
    
    let results = scanner.scan("example.com").await?;
    
    for result in results {
        println!("{}:{} - {:?}", result.host, result.port, result.state);
        if let Some(tls) = result.tls_info {
            println!("  Subject: {}", tls.subject);
            println!("  Expires: {}", tls.not_after);
        }
        for finding in result.findings {
            println!("  [!] {}: {}", finding.severity, finding.title);
        }
    }
    
    Ok(())
}
```

### Verdict

| Criterion | Assessment |
|-----------|------------|
| **Code quality** | ✅ Good - Well structured, tested |
| **Dependencies** | ⚠️ Moderate - Need to feature-gate core |
| **API design** | ⚠️ Needs work - Currently tied to trait |
| **Documentation** | ⚠️ Needs expansion - Examples, README |
| **Publish ready** | ❌ No - Refactoring required |

**Recommendation:**  
✅ **Publishable as standalone** after the refactoring outlined above. The core scanning logic is solid and the JARM/TLS inspection features are genuinely valuable additions over basic port scanners.

---

## Summary

| Question | Answer |
|----------|--------|
| Does it scan correctly? | ✅ Yes - TCP connect + banner grab, TLS inspection |
| Protocol detection? | 7 protocols via banner matching, extensive TLS features |
| Faster than nmap? | ⚠️ Competitive for targeted scans, nmap wins on stealth/features |
| Coupling to core? | Tight - uses Scanner trait, Finding, Target types |
| Standalone viable? | ✅ Yes - ~2-3 days refactoring needed |

**Unique strengths:**
- JARM fingerprinting for C2 detection
- Built-in CVE correlation from banners
- Certificate SAN extraction for domain discovery
- Legacy TLS version detection
- Redis/MongoDB unauthenticated access detection

**Unique weaknesses:**
- No SYN stealth scanning
- Passive banner grabbing only (no active probes)
- No UDP support
- Hardcoded 800ms banner timeout
