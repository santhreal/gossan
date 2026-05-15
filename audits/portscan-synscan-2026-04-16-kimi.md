# Deep Audit: `crates/portscan/` + `crates/synscan/`

**Auditor:** Kimi  
**Date:** 2026-04-16  
**Scope:** Read-only source review. Findings written to this file only.  
**Bars:** Zero false negatives. Zero host damage. Comparable to nmap/masscan/zmap/rustscan/naabu.

---

## Executive Summary

| Crate | Lines | Verdict |
|-------|-------|---------|
| `portscan` | ~3,200 | **Does not compile** (fatal reference to undefined variable `out`). Extensive correctness gaps in rate limiting, service probing, TLS depth, and IPv6 coverage. |
| `synscan` | ~319 | **Severely incomplete.** IPv4-only stub scanner with no banner grab, no TLS, no SYN-cookie awareness, and mocked port lists (`Top100` → `[80, 443]`). |

**Combined maturity:** Alpha at best. `synscan` is not production-ready under any definition. `portscan` has useful TLS/JARM logic but is undermined by a compilation failure and architectural choices that guarantee false negatives at scale.

---

## 1. `portscan` — Critical Findings

### 1.1 COMPILATION FAILURE — `out` is undefined
**File:** `crates/portscan/src/lib.rs`  
**Line:** 275

```rust
tracing::info!(open = out.targets.len(), "port scan complete");
```

`out` does not exist in this scope. The `Scanner::run` signature returns `anyhow::Result<()>` and results are emitted via `input.emit_target()`. This line is dead code from a prior refactor.

**Fix:** Delete the line or replace with a counter collected during result iteration.

---

### 1.2 INTEGRATION TEST DOES NOT COMPILE
**File:** `crates/portscan/src/integration_tests.rs`  
**Line:** 34–43

```rust
let output = scanner.run(input, &config).await.unwrap();
assert!(!output.targets.is_empty(), ...);
```

`Scanner::run` returns `anyhow::Result<()>`, not a struct with a `.targets` field. The test suite will fail at compile time.

**Fix:** Rewrite the test to use a mock `ScanInput` with channels and receive emitted targets asynchronously.

---

### 1.3 FALSE NEGATIVE GUARANTEE IS IMPOSSIBLE — No Retry, No Rate-Limit Integration
**File:** `crates/portscan/src/lib.rs`  
**Lines:** 238–247

The scan loop uses `futures::stream::iter(pairs).map(...).buffer_unordered(config.concurrency)`.  

- **No retry on timeout:** `tokio::time::timeout(..., connect_tcp(...)).await.ok()?.ok()?` — any timeout or connection failure immediately drops the port. It is never retried.
- **No per-IP/CIDR/ASN rate limiting:** `config.rate_limit`, `config.host_delay_ms`, and the `HostRateLimiter` in `gossan_core::ratelimit` are completely unused. A scan of a /16 network will hammer individual hosts as fast as the tokio scheduler allows.
- **No connection-pool reuse:** Every port opens a fresh TCP connection. For TLS ports this means repeated handshakes and no session resumption.

**Impact:** Under any packet loss, host overload, or aggressive firewall rate-limiting, open ports are silently discarded. This directly violates the "zero false negatives" mandate.

**Fix:**
1. Implement a retry queue with exponential backoff for ports that time out or receive RST.
2. Integrate `HostRateLimiter` or a token-bucket per destination IP/CIDR.
3. Reuse TLS sessions where possible (tokio-rustls session cache).

---

### 1.4 BANNER GRAB IS SERIAL INSIDE THE ASYNC TASK — Cumulative Timeout Explosion
**File:** `crates/portscan/src/lib.rs`  
**Lines:** 280–446 (`probe_port`)

Inside a single `probe_port` call:
1. Connect + timeout
2. `grab_banner(stream, timeout)`
3. If TLS port → `tls::probe_tls()` (new connection + handshake)
4. `tls::probe_legacy()` (new raw connection)
5. `jarm::fingerprint()` (10 new connections)

Each step is sequential. While `buffer_unordered` allows *other* ports to run concurrently, a single TLS port can occupy its task slot for:

```
timeout + banner_timeout + tls_timeout + legacy_timeout + (10 × jarm_timeout)
```

With default `timeout_secs = 10`, one task can live for well over 30 seconds. At `concurrency = 200`, the entire scan pipeline can stall if even a modest fraction of targets are slow TLS responders.

**Fix:**
- Run banner grab, TLS cert probe, legacy TLS probe, and JARM in parallel with an **overall per-port deadline** (e.g. `tokio::time::timeout(total_deadline, tokio::join!(...))`).
- Make JARM optional/configurable; it is massively expensive (10 full handshakes per port).

---

### 1.5 TLS EXTRACTION IS SHALLOW — Missing JA3, JA3S, Cert Chain, Cipher Details
**File:** `crates/portscan/src/tls.rs`

`probe_tls` extracts:
- Subject, Issuer, SANs, `not_after`, `is_self_signed`

It does **not** extract:
- **JA3 / JA3S** — Modern WAFs and threat intel rely on these. The crate builds raw ClientHellos in `jarm.rs` but never computes JA3.
- **Full certificate chain** — Only the first `peer_certificates()` entry is parsed. Intermediates are ignored.
- **Signature algorithm** — Not parsed from `tbs_certificate`.
- **`not_before`** — Only `not_after` is captured.
- **TLS version negotiated** — `probe_legacy` detects whether 1.0/1.1 are *accepted*, but the actual handshake version from `rustls` is not recorded.
- **ALPN advertised / selected** — Not captured from the rustls connection.
- **Weak cipher detection** — No analysis for 3DES, RC4, null, or CBC-mode MAC-then-encrypt.

**Impact:** Incomplete TLS fingerprint = incomplete fingerprint. This is explicitly called out in the task brief as a bug class.

**Fix:** Expand `TlsCertInfo` to include `ja3`, `ja3s`, `chain: Vec<ChainEntry>`, `signature_alg`, `not_before_unix`, `negotiated_version`, `alpn`. Compute JA3 from the ClientHello bytes already constructed in `jarm.rs`.

---

### 1.6 SERVICE DETECTION IS PASSIVE AND MINIMAL — No Active Probes
**File:** `crates/portscan/src/lib.rs`  
**Lines:** 448–669 (`identify_banner`)

After a TCP connect succeeds, the scanner:
1. Reads whatever the server sends first (up to 512 bytes).
2. Matches a handful of hard-coded string prefixes.

There are **no active probes** comparable to nmap's `nmap-service-probes` (hundreds of payloads). Services that require a trigger (e.g. `HTTP GET /`, `SMTP EHLO`, `AMQP 0.9.1`, `DNS version.bind`, `SNMP sysDescr`) are invisible unless they spontaneously banner.

**Missing probes:**
- HTTP/1.1 `GET / HTTP/1.1\r\nHost: ...\r\n\r\n`
- SMTP `EHLO scanner\r\n`
- SSH is passive (ok, SSH banners first).
- No Telnet option negotiation probe.
- No TLS `ClientHello` on STARTTLS ports (25, 587, 110, 143).

**Fix:** Implement a TOML-driven `service_probes.toml` with `probe_name`, `payload_bytes`, `match_regex`, and `fallback_probe` — exactly like nmap's service-probes file. Send the probe after connection if the service does not banner within 200ms.

---

### 1.7 PORT MODE PARSING IS STRUCTURAL — No Human-Readable Strings
**File:** `crates/core/src/config.rs`  
**Lines:** 20–34

`PortMode` is an enum:

```rust
pub enum PortMode {
    Default, Top100, Top1000, Full, Custom(Vec<u16>),
}
```

There is **no parser** for user-facing strings like:
- `top-1000`
- `1-65535`
- `80,443,8080`
- `-` (all ports)
- `U:53,T:80` (UDP vs TCP)

This is a massive UX gap versus nmap, rustscan, and naabu.

**Fix:** Implement `FromStr for PortMode` (or a dedicated parser) supporting ranges, commas, `U:`, `T:`, and `-` as shorthand for `Full`.

---

### 1.8 CDN MODULE IS DEAD CODE
**File:** `crates/portscan/src/cdn.rs`

`cdn.rs` exports `load_ranges`, `is_cdn_ip`, and `ptr_heuristic`. It is **never imported or called** in `lib.rs`. CDN detection does not influence port skipping, rate limiting, or SAN filtering.

**Fix:** Either wire it into the scan pipeline (skip CDN-covered ports when `--skip-cdn` is set) or delete it per Law 1.

---

### 1.9 SAN FILTERING IS BRITTLE AND ROOT-DOMAIN EXTRACTION IS INCOMPLETE
**File:** `crates/portscan/src/lib.rs`  
**Lines:** 249–272, 744–761

The SAN filter compares `extract_root_domain(san)` against `extract_root_domain(seed)`. The root extractor hard-codes a tiny list of two-part TLDs:

```rust
let two_part_tlds = ["co.uk", "com.au", "co.jp", "com.br", "co.in", "org.uk", "net.au", "co.za"];
```

This misses hundreds of public suffixes (`.ac.uk`, `.gov.uk`, `.co.nz`, `.com.mx`, `.nom.br`, etc.). A valid SAN like `api.ac.uk` will be incorrectly truncated to `ac.uk` and may be filtered out.

**Fix:** Use the `publicsuffix` crate or the Mozilla Public Suffix List. Do not hand-roll TLD logic.

---

### 1.10 RISKY SERVICE RULES ARE ONLY BY PORT NUMBER — No Banner Confirmation
**File:** `crates/portscan/src/lib.rs`  
**Line:** 312–321

```rust
if let Some(r) = rules::risky_services().iter().find(|r| r.port == port) { ... }
```

A service on port 6379 is flagged as "Redis exposed" even if the banner is a generic TCP proxy, a honeypot, or `Connection refused` (the code only reaches here after connect succeeds, but the service could be anything).

**Fix:** Require banner confirmation for risky-service findings. If banner grab returns `None`, downgrade severity or flag as "unknown service on risky port".

---

### 1.11 CVE CORRELATION USES SUBSTRING MATCHING — No Version Parsing
**File:** `crates/portscan/src/cve.rs`  
**Lines:** 329–360

```rust
if lower.contains(&rule.pattern) { ... }
```

`apache/2.4.49` will match `Server: Apache/2.4.49`, but it will also match `This server runs Apache/2.4.49-mod_security` or a blog post about the CVE in the HTTP body. There is no structured version comparison (`>`, `<`, `==`).

**Fix:** Replace substring rules with semantic version matchers (e.g. `product = "apache", min_version = "2.4.49", max_version = "2.4.49"`).

---

### 1.12 OOM RISK IN JARM — Fixed 8 KiB Buffer, But 10 Parallel Connections Per Port
**File:** `crates/portscan/src/jarm.rs`  
**Line:** 542

`let mut buf = vec![0u8; 8192];` — this is fine per probe, but JARM sends 10 probes **serially** per TLS port. For a large scan (e.g. top-1000 on 10,000 hosts = 10M ports), JARM alone opens 100M connections. Memory is not the bottleneck; **time and file descriptors** are.

More critically, there is no limit on concurrent JARM handshakes. The OS will exhaust ephemeral ports (`ECONNREFUSED` / `EMFILE`).

**Fix:** Make JARM opt-in. If enabled, cap concurrent JARM probes to a separate semaphore.

---

### 1.13 TESTS ARE NOT ADVERSARIAL
**Files:** `crates/portscan/src/tests.rs`, `crates/portscan/src/integration_tests.rs`

- No fake tarpit server that accepts connections and sends 1 byte per minute.
- No test for TCP retransmit scenarios (packet loss simulation).
- No test for a server that sends SYN-ACK then immediately RST (IDS behavior).
- No property-based test for malformed TLS ServerHello (only `proptest` in `synscan` for seq calculation).
- The banner sanitization test manually re-implements the sanitization logic instead of calling `grab_banner` with a mock stream.

**Fix:** Add a `tokio::net::TcpListener` adversarial harness that simulates slow-loris, immediate-RST, and megabyte-banner behaviors.

---

## 2. `synscan` — Critical Findings

### 2.1 SYN SCAN IS A 319-LINE STUB
**File:** `crates/synscan/src/lib.rs`

The entire crate is a single file with:
- No banner grabbing.
- No TLS inspection.
- No service detection.
- No IPv6 support.
- No checkpoint / resume state.
- No retry on packet loss.

**Verdict:** This is not a production SYN scanner. It is a proof-of-concept that happens to send raw packets.

---

### 2.2 MOCKED PORT LISTS — `Top100` and `Top1000` ARE HARDCODED TO `[80, 443]`
**File:** `crates/synscan/src/lib.rs`  
**Lines:** 129–135

```rust
PortMode::Default => &[80, 443, 22, ...], // 20 ports
PortMode::Top100 => &[80, 443],
PortMode::Top1000 => &[80, 443],
```

`Top100` scans **two ports**. `Top1000` scans **two ports**. This is a guaranteed false-negative factory.

**Fix:** Import the actual port lists from `gossan_portscan::rules` or share them via `gossan_core`.

---

### 2.3 IPv6 IS COMPLETELY ABSENT
**File:** `crates/synscan/src/lib.rs`  
**Lines:** 95–144

Every IP is cast to `Ipv4Addr`. `TransportProtocol::Ipv4` is hard-coded. IPv6 targets in `input.targets` are silently dropped.

At internet scale, IPv6 is no longer optional. Major CDNs and cloud providers are IPv6-first.

**Fix:** Implement raw IPv6 sockets (`socket(AF_INET6, SOCK_RAW, IPPROTO_TCP)`) or use `pnet`'s IPv6 transport channel. Duplicate the packet-building logic for IPv6 (larger addresses, different pseudo-header checksum).

---

### 2.4 NO PROPER TCP SEQUENCE RANDOMIZATION — Predictable Stateless Cookie
**File:** `crates/synscan/src/lib.rs`  
**Lines:** 41–47

```rust
fn calculate_stateless_seq(target_ip: &Ipv4Addr, target_port: u16, seed: u64) -> u32 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    target_ip.hash(&mut hasher);
    target_port.hash(&mut hasher);
    (hasher.finish() & 0xFFFFFFFF) as u32
}
```

`DefaultHasher` is **not a cryptographic PRNG**. An observer can fingerprint the scanner by seeing correlated sequence numbers across probes. Worse, the sequence space is only 32 bits and derived from a predictable hash.

**Fix:** Use `rand::thread_rng().gen::<u32>()` or `fastrand::u32(..)` (already in deps) for true randomization. Store the (ip, port, seq) mapping in a `DashMap` or similar for validation instead of stateless cookies.

---

### 2.5 NOT SYN-COOKIE-AWARE
**File:** `crates/synscan/src/lib.rs`  
**Lines:** 163–183

The listener validates responses with:

```rust
if tcp.get_acknowledgement() == expected_seq + 1 { ... }
```

Linux SYN cookies encode the MSS and other connection details into the ACK number. A server with SYN cookies enabled will **not** return `seq + 1`. The scanner will drop legitimate SYN-ACKs from high-load Linux servers.

**Fix:** Accept a window of valid ACK values or implement SYN-cookie decoding. At minimum, accept `ack >= expected_seq && ack <= expected_seq + 64000`.

---

### 2.6 PACKET LISTENER IS A BLOCKING `std::thread` WITH `std::sync::mpsc`
**File:** `crates/synscan/src/lib.rs`  
**Lines:** 154–183

The RX path spawns a `std::thread` that blocks on `pnet::transport::tcp_packet_iter`. It uses `std::sync::mpsc::sync_channel(100_000)`.  

- This thread will **pin a kernel thread** for the entire scan duration.
- The `stop_flag` is polled with `Relaxed` ordering; there is no `_wakeup` mechanism, so the thread may hang until the next packet arrives after the scan should have ended.
- `pnet` iterators are not async-aware.

**Fix:** Use `tokio::task::spawn_blocking` and an async-aware stop signal (e.g. `tokio::sync::Notify` or a timeout on `recv`). Better yet, use a raw socket with `tokio::net::UdpSocket` or `async-pnet` if available.

---

### 2.7 NO IP CHECKSUM — Only TCP Checksum
**File:** `crates/synscan/src/lib.rs`  
**Line:** 204

```rust
tcp.set_checksum(ipv4_checksum(&tcp.to_immutable(), &source_ip, &target_ip));
```

This computes the **TCP checksum** (which includes the IPv4 pseudo-header). It does **not** compute the **IPv4 header checksum**. `pnet` at Layer4 does not build the IP header; the kernel does. However, if the crate ever moves to Layer3 (to support IP options, fragmentation, or custom TTL), the IP checksum must be calculated.

More importantly, **the TTL is never set**. The kernel default TTL is used, which limits OS fingerprinting accuracy.

**Fix:** If staying at Layer4, explicitly set `IP_TTL` via socket options. If moving to Layer3 (required for IPv6 and advanced features), compute the full IPv4 header checksum.

---

### 2.8 SOURCE PORT SELECTION IS COLLISION-PRONE
**File:** `crates/synscan/src/lib.rs`  
**Line:** 98

```rust
let source_port = 49152 + (std::process::id() as u16 % 16383);
```

A single source port is used for **all** probes. This means:
- If scanning multiple hosts concurrently, responses from different hosts arrive on the same source port and must be disambiguated by `(src_ip, src_port, dst_port)`.
- If scanning 65,535 ports on one host, the source port is identical for every probe. The only differentiator is the destination port, which is fine for IPv4 but can confuse some NATs and firewalls.
- Running two `synscan` processes on the same machine will use the **same source port** and steal each other's packets.

**Fix:** Randomize the source port per probe or per host, and track them in a lookup table.

---

### 2.9 FIXED WAIT TIME AFTER TRANSMIT — No Adaptive RTT
**File:** `crates/synscan/src/lib.rs`  
**Line:** 213

```rust
sleep(timeout).await;
```

After sending all SYNs, the scanner sleeps for `config.timeout()` (default 10s) and then stops listening.  

- If the network RTT is 500ms and the target has 100 open ports, 10s is wasteful.
- If the network RTT is 2s and there is packet loss, 10s may be insufficient.
- There is **no retransmission**. A single dropped SYN packet = false negative.

**Fix:** Implement a sliding window with RTT estimation (Jacobson's algorithm) and at least one SYN retransmit.

---

### 2.10 OS FINGERPRINTING IS A TOY
**File:** `crates/synscan/src/lib.rs`  
**Lines:** 50–63

```rust
fn identify_os(ttl: u8, window: u16) -> Option<OsFingerprint> {
    match (ttl, window) {
        (64, _) | (63, _) | (62, _) => Some(OsFingerprint { name: "Linux/Unix" }),
        (128, _) | (127, _) | (126, _) => Some(OsFingerprint { name: "Windows" }),
        ...
    }
}
```

TTL is **hardcoded to 64** in the response struct (`ttl: 64` at line 176). The actual TTL from the IP header is never extracted because `pnet`'s Layer4 transport channel does not expose it. The OS fingerprint is therefore always "Linux/Unix" regardless of the target.

**Fix:** Move to Layer3 (`pnet::transport::TransportChannelType::Layer3`) to read the IP header TTL and options. Or remove `identify_os` entirely.

---

### 2.11 NO BANNER, NO TLS, NO SERVICE DETECTION
**File:** `crates/synscan/src/lib.rs`  
**Lines:** 228–249

When a SYN-ACK is received, the scanner emits:

```rust
ServiceTarget {
    host: HostTarget { ip: IpAddr::V4(ip), domain },
    port,
    protocol: Protocol::Tcp,
    banner: None,           // always None
    tls: port == 443 || port == 8443, // hard-coded guess
}
```

There is no banner grab, no TLS handshake, no cert extraction, no JARM, no legacy TLS probe.

**Fix:** After SYN discovery, hand off open ports to the `portscan` crate's `probe_port` logic for full service enumeration. `synscan` should be the fast discovery layer; `portscan` should be the deep inspection layer. Currently they do not integrate at all.

---

## 3. Cross-Cutting Architectural Gaps

### 3.1 No Checkpoint / Resume Integration
The task brief asks about scan resumability. Neither crate references the `checkpoint` crate. There is no serialization of `(target_ip, port, state)` to disk. A killed scan restarts from zero.

**Fix:** After every N ports (or every T seconds), serialize the pending and completed port sets to a SQLite or flat file. On startup, skip completed ports.

### 3.2 No UDP Scanning
Despite `Protocol::Udp` existing in `gossan_core`, neither crate scans UDP ports. `U:53` parsing is therefore moot.

**Fix:** Implement UDP scanning with protocol-specific payload probes (DNS, SNMP, NTP) and ICMP unreachable detection.

### 3.3 No Connection to `gossan_core::ratelimit`
`gossan_core` has a `HostRateLimiter`, `get_with_backoff`, and `send_with_backoff`. `portscan` and `synscan` ignore all of it.

---

## 4. Comparison to Industry Scanners

| Feature | nmap | masscan | rustscan | naabu | gossan portscan | gossan synscan |
|---------|------|---------|----------|-------|-----------------|----------------|
| SYN scan | Yes | Yes | No | Yes | No | **Partial (IPv4 only)** |
| Connect scan | Yes | No | Yes | Yes | Yes | No |
| IPv6 | Yes | No | Yes | Yes | Yes | **No** |
| Service probes (active) | ~1,000+ | No | No | No | **~15 passive** | No |
| TLS cert parsing | Yes (NSE) | No | No | Basic | **Basic** | No |
| JA3 / JA3S | Via scripts | No | No | No | **No** | No |
| JARM | No | No | No | No | **Yes** | No |
| Rate limit per host | Yes | Yes | Yes | Yes | **No** | No |
| Retry on packet loss | Yes | Yes | No | No | **No** | No |
| Top100/Top1000/Full | Yes | Yes | Yes | Yes | Yes | **Top100→2 ports** |
| Resume state | Yes | No | No | No | **No** | No |

---

## 5. Actionable Remediation Plan

### Immediate (Blocks Release)
1. **Fix compilation error** in `portscan/src/lib.rs` line 275.
2. **Fix integration test** in `portscan/src/integration_tests.rs`.
3. **Delete or wire up `cdn.rs`** — dead code violates Law 1.

### Short Term (Correctness)
4. **Integrate rate limiting** into `portscan::run`: use `HostRateLimiter` and respect `config.host_delay_ms`.
5. **Add retry logic** for `connect_tcp` timeouts (exponential backoff, max 3 attempts).
6. **Parallelize `probe_port`** sub-tasks under a single per-port deadline.
7. **Make JARM opt-in** — default off.
8. **Replace `synscan` port lists** with real `top_100` / `top_1000` / `default` lists shared from `gossan_core` or `gossan_portscan::rules`.

### Medium Term (Depth)
9. **Expand TLS extraction** to include JA3, JA3S, full chain, signature algorithm, negotiated version, ALPN, and weak-cipher flags.
10. **Implement active service probes** as TOML rules (`service_probes.toml`).
11. **Fix SYN-cookie validation** in `synscan` with an ACK window.
12. **Add IPv6 raw socket support** to `synscan`.
13. **Add checkpoint/resume** serialization to both scanners.

### Long Term (Architecture)
14. **Merge `synscan` discovery with `portscan` inspection**: `synscan` finds open ports quickly, then spawns `portscan::probe_port` for deep analysis.
15. **Add adversarial integration tests** (tarpit, RST-after-SYN-ACK, slow TLS, megabyte banner).

---

## 6. Severity Ratings

| Finding | Severity |
|---------|----------|
| `portscan` compilation failure (`out` undefined) | **Critical** |
| `portscan` integration test compilation failure | **Critical** |
| `synscan` Top100/Top1000 hardcoded to 2 ports | **Critical** |
| No retry on timeout / packet loss (portscan) | **Critical** |
| No rate limiting per host/CIDR (portscan) | **Critical** |
| SYN scan lacks SYN-cookie awareness | **High** |
| TLS extraction missing JA3/JA3S/chain/version | **High** |
| No active service probes (only 15 passive banners) | **High** |
| `synscan` IPv6 completely absent | **High** |
| Predictable TCP sequence numbers | **High** |
| JARM is 10× connection overhead with no concurrency cap | **Medium** |
| CDN module is dead code | **Medium** |
| SAN root-domain extraction misses public suffixes | **Medium** |
| CVE correlation uses naive substring matching | **Medium** |
| OS fingerprinting in synscan is broken (fixed TTL) | **Low** |
| No checkpoint / resume state | **Low** |

---

*End of audit.*
