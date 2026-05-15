# Deep Audit: `crates/subdomain/`

**Date:** 2026-04-16  
**Auditor:** Kimi (deep read-only)  
**Scope:** `crates/subdomain/src/**/*.rs` + `tests/`  
**Commit:** Working tree (uncommitted breakage present)

---

## Executive Summary

The `gossan-subdomain` crate is **currently uncompilable** due to a botched migration from a batched `ScanOutput` pattern to a streaming `emit_target` pattern. Multiple source files contain syntax errors, undefined types, and non-existent method calls. Even if the syntax were repaired, the crate suffers from severe correctness gaps: no per-source rate limiting, missing wildcard filtering in permutation and root-level brute-force, 7 dead source modules, no response size limits (OOM vector), and a passive-source design that blocks all streaming until the slowest source returns. **At internet scale, every bug class here translates directly to missed attack surface or burned API keys.**

| Category | Status | Severity |
|----------|--------|----------|
| Compilation | 🔴 Broken | Critical |
| Source coverage | 🟡 27 of 80+ | Critical |
| Wildcard handling | 🟡 Partial | Critical |
| Rate limiting | 🔴 Missing per-source | Critical |
| Failure isolation | 🟡 Functional but anti-pattern | High |
| Deduplication / normalization | 🟡 Basic | High |
| CT parsing robustness | 🟡 Fragile | High |
| Security (key leakage) | 🔴 Keys in URLs | Critical |
| OOM safety | 🔴 No size limits | Critical |
| Tests | 🔴 Broken / absent | Critical |

---

## 1. Source Inventory

### 1.1 Implemented & Wired (`mod` in `lib.rs`)

| # | Source | File | Key? | Notes |
|---|--------|------|------|-------|
| 1 | crt.sh | `ct.rs` | No | CT JSON API |
| 2 | CertSpotter | `certspotter.rs` | No | CT API (100 req/hr free) |
| 3 | Wayback Machine | `wayback.rs` | No | CDX API |
| 4 | HackerTarget | `hackertarget.rs` | No | hostsearch API |
| 5 | RapidDNS | `rapiddns.rs` | No | HTML scrape |
| 6 | AlienVault OTX | `alienvault.rs` | No | Passive DNS API |
| 7 | Urlscan.io | `urlscan.rs` | No | Search API |
| 8 | CommonCrawl | `commoncrawl.rs` | No | Hardcoded `CC-MAIN-2024-51` index |
| 9 | DNSdumpster | `dnsdumpster.rs` | No | CSRF-scraped HTML table |
| 10 | VirusTotal | `virustotal.rs` | Yes | 4 req/min, 500/day |
| 11 | SecurityTrails | `securitytrails.rs` | Yes | Paid |
| 12 | Shodan | `shodan.rs` | Yes | Paid |
| 13 | Censys | `censys.rs` | Yes | `api_id:api_secret` format |
| 14 | BinaryEdge | `binaryedge.rs` | Yes | Paid |
| 15 | FullHunt | `fullhunt.rs` | Yes | Paid |
| 16 | GitHub | `github.rs` | Yes | Code search |
| 17 | Chaos (ProjectDiscovery) | `chaos.rs` | Yes | Paid |
| 18 | Bevigil | `bevigil.rs` | Yes | Paid |
| 19 | FOFA | `fofa.rs` | Yes | `email:key` format |
| 20 | Hunter.io | `hunter.rs` | Yes | Paid |
| 21 | Netlas | `netlas.rs` | Yes | Paid |
| 22 | ZoomEye | `zoomeye.rs` | Yes | Paid |
| 23 | C99.nl | `c99.rs` | Yes | Paid |
| 24 | Quake (360) | `quake.rs` | Yes | Paid |
| 25 | ThreatBook | `threatbook.rs` | Yes | Paid |
| 26 | Anubis | `anubis.rs` | No | `jldc.me` endpoint |
| 27 | DNS Brute-force | `bruteforce.rs` | N/A | 491-word compiled-in wordlist |
| — | Permutation engine | `permutations.rs` | N/A | Markov + dictionary |

**Total wired passive sources:** 26 (plus brute-force / permutation).

### 1.2 Dead Code (Files on Disk but **NOT** `mod`'d in `lib.rs`)

These modules are completely ignored by the compiler and never executed:

| Source | File | Why It Matters |
|--------|------|----------------|
| BufferOver | `bufferover.rs` | Free forward/reverse DNS dataset |
| DNSRepo | `dnsrepo.rs` | Free historical DNS scraper |
| IntelX | `intelx.rs` | Premium intel source |
| LeakIX | `leakix.rs` | Free/premium leak intel |
| Robtex | `robtex.rs` | Free passive DNS (NDJSON) |
| WhoisXML | `whoisxml.rs` | Subdomains lookup API |
| ASN lookup | `asn.rs` | Network enrichment |

**Finding:** 7 implemented files are orphaned. They are maintained (some have recent-looking code) but never compiled, meaning bit-rot is guaranteed.

### 1.3 Major Missing Sources (vs. Amass 80+, Subfinder 55+)

Every missing source is a **false-negative vector** — real subdomains that will never be discovered.

*Certificate Transparency (only 2 of ~10+ major logs covered):*
- Google CT
- Facebook CT
- Apple CT
- Cloudflare CT
- DigiCert CT
- Sectigo / IdenTrust / Entrust / GoDaddy / Amazon CT

*Passive DNS / OSINT:*
- PassiveTotal (IBM / RiskIQ)
- Spyse
- DNSlytics
- ThreatMiner
- PTRarchive
- Riddler
- SiteDossier
- SonarSearch (Rapid7 FDNS)
- CIRCL pDNS
- Mnemonic pDNS
- Farsight DNSDB
- Pastebin
- HackerOne / Bugcrowd / Intigriti scope parsing

*Search Engine scraping (completely absent):*
- Bing
- Baidu
- DuckDuckGo
- Yahoo
- Exalead
- Ask

*Other:*
- Sublist3r API
- Omnisint
- Digitorus
- Facebook Certificate Transparency
- Active DNS zone-walking

**Fix:** Implement a source plugin system (TOML-driven where possible) so the community can add sources without touching core code. Wire the 7 dead modules immediately.

---

## 2. Critical Correctness Findings

### 2.1 The Crate Does Not Compile — Broken Migration Artifact

**Severity: Critical**

`crates/subdomain/src/lib.rs` contains multiple syntax errors that make the crate uncompilable. Root cause: a partial migration from `ScanOutput { targets, findings }` to streaming `input.emit_target()`.

**Evidence:**

```rust
// lib.rs:252 — broken function signature
fn emit_and_push(input: &ScanInput, out: &mut t: Target) {
    input.emit_target(t.clone());
    input.emit_target(t);
}

// lib.rs:257 — broken function signature
fn take_targets(
    source: &'static str,
    domain: &str,
    out: &mut input: &ScanInput,   // "out: &mut input: &ScanInput" is invalid Rust
    result: anyhow::Result<Vec<Target>>,
) -> Vec<Target> { ... }
```

Inside `run()`, the variable `out` is referenced 50+ times but **never declared**:

```rust
// lib.rs:136
for t in take_targets("ct", &d.domain, &mut out, &input, ct) { ... }
//                        ^^^^^^^ out does not exist in this scope
```

The unit tests in `lib.rs` also reference `out`:

```rust
emit_and_push(&input, &mut out, target.clone());
assert_eq!(out.targets.len(), 1);
```

There is no `ScanOutput` struct in the current codebase (only found in a backup file). The `.audits/fix_empty.py` script was clearly intended to strip this pattern but failed for `subdomain/src/lib.rs`.

**Impact:** The entire scanner is dead code. No subdomain enumeration happens at all.

**Fix:** Complete the migration. Remove `out` references. Change `emit_and_push` to push into an accumulator or stream directly. Rewrite `take_targets` to accept `&ScanInput` only and return filtered targets. Rewrite tests to use a local `Vec<Target>` accumulator.

---

### 2.2 Additional Compilation Errors in Orphaned Modules

**Severity: Critical**

Three of the dead-code files reference `config.api_keys.extra`, which does not exist. `gossan_core::config::ApiKeys` is a type alias:

```rust
pub type ApiKeys = std::collections::HashMap<String, String>;
```

**Files affected:**
- `intelx.rs:19` — `config.api_keys.extra.get("intelx")`
- `leakix.rs:18` — `config.api_keys.extra.get("leakix")`
- `whoisxml.rs:18` — `config.api_keys.extra.get("whoisxml")`

These files also call `rate_limiter.wait_for_host(...)`, but `HostRateLimiter` only exposes `until_ready`:

```rust
// intelx.rs:27
rate_limiter.wait_for_host("2.intelx.io").await;
// leakix.rs:31
rate_limiter.wait_for_host("leakix.net").await;
// whoisxml.rs:31
rate_limiter.wait_for_host("whoisxmlapi.com").await;
```

**Impact:** Even if these modules were wired into `lib.rs`, they would fail to compile.

**Fix:** Replace `config.api_keys.extra.get(...)` with `config.api_keys.get(...)`. Replace `wait_for_host` with `until_ready`.

---

### 2.3 Wildcard Detection Is Incomplete and Not Applied to Root Brute-Force

**Severity: Critical**

`lib.rs` runs a single wildcard probe:

```rust
async fn detect_wildcard(domain: &str, resolver: &TokioAsyncResolver) -> Option<IpAddr> {
    let probe = format!("this-label-should-not-exist-gossan-probe-{}. {}", fastrand::u32(..), domain);
    if let Ok(lookup) = resolver.lookup_ip(probe.as_str()).await {
        lookup.iter().next()
    } else {
        None
    }
}
```

**Deficiencies:**
1. **Single IP returned** — Many wildcard setups return multiple A-records (round-robin CDN). Only the first IP is checked, so wildcard answers with additional IPs slip through.
2. **No CNAME wildcard detection** — If `*.target.com` CNAMEs to another domain, `lookup_ip` will follow the CNAME and return the final IPs. The code does not detect this pattern.
3. **Root-level brute-force ignores the detected wildcard** — `bruteforce::scan` is called with `wildcard_ip = None` at the top level:
   ```rust
   recursive_scan(..., 0, 2, None).await
   ```
   The wildcard is detected in `lib.rs` but **never passed down**.
4. **Permutation engine has zero wildcard filtering** — `permutations.rs` resolves candidates and returns them unconditionally. If the root domain has a wildcard, every permutation will "resolve" and pollute results.

**Impact:** For wildcard-enabled domains, brute-force and permutation emit hundreds or thousands of false positives, drowning real signal in noise.

**Fix:**
- Pass the wildcard `HashSet<IpAddr>` (not `Option<IpAddr>`) into `bruteforce::scan`.
- Build the wildcard set by probing multiple random labels (e.g., 5 probes) and collecting all returned IPs + CNAME chains.
- Apply the same wildcard filter in `permutations::expand`.

---

### 2.4 No Per-Source Rate Limiting — Global Cap Will Burn API Keys

**Severity: Critical**

All 26 passive sources share a single `HostRateLimiter` instantiated with `config.rate_limit` (default 300 req/sec):

```rust
let passive_rate_limiter = HostRateLimiter::new(config.rate_limit);
```

**Why this is catastrophic:**

| Source | Documented Limit | Global 300 rps Impact |
|--------|------------------|-----------------------|
| VirusTotal | 4 req/min | 75× over limit → instant key ban |
| CertSpotter (free) | 100 req/hr | 180× over limit → IP ban |
| GitHub | 10 req/min (unauth) / 30 (auth) | 30–180× over limit → account suspension |
| Censys | 0.2 req/sec (free) | 1,500× over limit |
| Shodan | 1 req/sec (free) | 300× over limit |

**Impact:** One scan of a few domains can permanently exhaust daily quotas or trigger account bans, creating a **permanent blind spot**.

**Fix:** Give every source its own `HostRateLimiter` constructed with documented limits. Store limits in a TOML table (e.g., `config.subdomain_source_limits.virustotal = 4`) and default to conservative values. Do not rely on 429 backoff as primary rate limiting; backoff is a failure-recovery mechanism, not a quota guard.

---

### 2.5 API Keys Leaked in URL Query Parameters

**Severity: Critical**

Multiple sources embed secrets directly in the request URL:

- `c99.rs:30` — `https://api.c99.nl/subdomainfinder?key={}&domain={}&json`
- `shodan.rs:29` — `https://api.shodan.io/dns/domain/{}?key={}`
- `whoisxml.rs:28` — `https://subdomains.whoisxmlapi.com/api/v1?apiKey={key}&domainName={domain}`
- `hunter.rs:50` — `https://api.hunter.io/v2/domain-search?domain={}&api_key={}`

**Impact:** API keys appear in proxy logs, server access logs, shell history, and CI output. Key exposure leads to abuse, quota exhaustion, and account termination.

**Fix:** Move keys to headers or POST bodies where the API supports it. For sources that *require* query parameters (none of the above do), warn the user at startup and document the risk.

---

### 2.6 No Response Size Limits — OOM on Large CT / CommonCrawl Responses

**Severity: Critical**

Every passive source uses `get_text()` or `get_json()`, which call `resp.text().await?` or `resp.json().await?` without any size guard:

```rust
pub(crate) async fn get_json<T: serde::de::DeserializeOwned>(
    client: &reqwest::Client,
    url: &str,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<T> {
    send_with_backoff(url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(client.get(url).send().await?)
    })
    .await?
    .json()   // <-- unbounded allocation
    .await
    .map_err(Into::into)
}
```

`gossan_core` provides `read_response_limited(resp, max_size)` specifically to prevent this, but it is **never used** in the subdomain crate.

**Impact:** A popular domain like `google.com` on crt.sh can return multi-megabyte JSON. An attacker-controlled DNS zone with thousands of CT entries could cause the scanner OOM and crash the process.

**Fix:** Use `read_response_limited` with a sane cap (e.g., 8 MiB) before deserializing. For NDJSON sources (CommonCrawl, Robtex), stream lines and enforce a per-line limit plus a total parsed-item limit.

---

### 2.7 `tokio::join!` Blocks Streaming Until the Slowest Source Finishes

**Severity: High**

All 26 passive sources are awaited with `tokio::join!`:

```rust
let (ct, cs, wb, ht, rd, av, us, cc, dd, vt, st, sd, cn, be, fh, gh, ch, bv, ff, hu, nl, ze, c9, qk, tb, anubis, brute) = tokio::join!(...);
```

Results are only iterated **after** every future completes. If one source (e.g., Wayback) takes 30 seconds, every fast source (crt.sh, HackerTarget) sits idle while the port scanner downstream starves for targets.

The doc comment claims:

> "Every confirmed target is emitted via `input.emit_target()` immediately so the port scanner can start while subdomain discovery is still running."

That promise is broken for all passive sources. Only `bruteforce::scan` emits internally via `target_tx`.

**Impact:** Attack surface discovery is gated by the slowest or hung upstream API, violating the streaming architecture and extending scan time by orders of magnitude.

**Fix:** Replace `tokio::join!` with `tokio::spawn` per source, attaching a `mpsc` channel or directly calling `input.emit_target()` inside each source task as results arrive. Aggregate with ` FuturesUnordered` or a select loop.

---

### 2.8 Deduplication Lacks Normalization

**Severity: High**

Deduplication happens in two places (pre-permutation and final) using a `HashSet<String>` of the raw domain string:

```rust
let mut seen: HashSet<String> = HashSet::new();
out.targets.retain(|t| {
    t.domain()
        .map(|d| seen.insert(d.to_string()))
        .unwrap_or(true)
});
```

Only `to_lowercase()` is applied. Missing:
- **Trailing dot normalization** — `sub.example.com.` vs `sub.example.com`
- **Punycode normalization** — `münchen.example.com` vs `xn--mnchen-3ya.example.com`
- **www-stripping** — some sources return `www.example.com` and `example.com` interchangeably
- **Duplicate SAN entries within a single source** — crt.sh often returns the same subdomain dozens of times per certificate. This is only deduped globally, wasting memory during parsing.

**Impact:** Duplicate targets propagate downstream, causing redundant port scans, HTTP probes, and inflated output.

**Fix:** Normalize with `url::Host::parse` or `idna` crate before inserting into the HashSet. Strip trailing dots. Store domains in punycode (ACE) form consistently.

---

### 2.9 CT Parsing Fragility (crt.sh)

**Severity: High**

`ct.rs` assumes a flat JSON array:

```rust
#[derive(Deserialize)]
struct Entry {
    name_value: String,
}
```

crt.sh returns entries where:
- `name_value` can contain `\n` delimited SANs (handled by `.lines()`)
- `name_value` can contain `*.` wildcards (handled by `trim_start_matches("*.")`)
- **But** it can also contain raw IPs, email addresses, or unrelated domains when a cert covers a multi-domain SAN list. The `is_subdomain_of` filter catches most of this, but the code does not handle:
  - Duplicate entries per certificate (memory bloat)
  - Missing `name_value` field (will panic on deserialization if crt.sh ever changes shape — though `get_json` returns `anyhow::Error`, so it just fails the whole source)
  - HTML error pages masquerading as JSON (crt.sh occasionally returns Cloudflare challenge pages). `get_json` will return a deserialization error and abort the source entirely.

**Fix:**
- Parse crt.sh with `serde_json::Value` first, defensively extract fields.
- Deduplicate inside `ct.rs` before returning.
- Handle non-JSON responses gracefully (return empty vec instead of error).

---

### 2.10 Source Error Misclassified as `InfoDisclosure` Finding

**Severity: Medium-High**

When a passive source fails, `take_targets` emits a `Finding`:

```rust
if let Some(finding) = Finding::builder("subdomain", domain, Severity::Low)
    .title(format!("Subdomain source failed: {source}"))
    .kind(secfinding::FindingKind::InfoDisclosure)
    .tag("source-error")
    ...
```

A timeout or 500 from a third-party API is **not** an information disclosure vulnerability. Misclassified findings pollute the output and train users to ignore scanner results.

**Fix:** Change `FindingKind` to `OperationalError` or `EnumerationLimitation`. Elevate severity to `Medium` or `High` when a key-gated source fails (because it represents a real blind spot).

---

## 3. Security & Robustness Findings

### 3.1 Regex in GitHub Source Built Dynamically

`github.rs` builds a regex from the target domain:

```rust
let pattern = format!(r"([a-zA-Z0-9_-]+\.{})", regex::escape(domain));
let re = Regex::new(&pattern)?;
```

While `regex::escape` prevents injection, the regex is compiled fresh for every domain scan. For large GitHub code fragments, `captures_iter` on unbounded input can be CPU-intensive. There is no length cap on `text_matches` fragments.

**Fix:** Compile the regex once per scan (acceptable), but cap the total bytes scanned per fragment to prevent regex DoS on megabyte-sized files.

### 3.2 DNSdumpster Scraping Is Brittle

`dnsdumpster.rs` extracts subdomains by scanning every `<td>` tag in the HTML response:

```rust
if line_lower.contains("<td>") && line_lower.contains(domain) {
    if let Some(subdomain) = extract_text_from_td(line) { ... }
}
```

If DNSdumpster changes its layout, adds pagination, or returns a Cloudflare challenge, the source silently returns zero results. No fallback. No adversarial test for HTML error pages.

**Fix:** Add a health-check probe. If CSRF extraction fails, log a clear error rather than returning an empty vector that looks like "no subdomains found."

### 3.3 CommonCrawl Index Is Stale

`commoncrawl.rs` hardcodes:

```rust
"https://index.commoncrawl.org/CC-MAIN-2024-51-index?url=*.{}&output=json&fl=url&limit=5000"
```

As of 2026-04, `2024-51` is ~16 months old. Newer crawls exist. Using a stale index means missing recently discovered subdomains.

**Fix:** Query `https://index.commoncrawl.org/collinfo.json` to discover the latest index ID at runtime, or fall back through the last N indices.

---

## 4. Test Coverage

### 4.1 Broken Tests

| Test File | Status | Why |
|-----------|--------|-----|
| `lib.rs` (unit tests) | 🔴 Broken | References undefined `out`, `mpsc` not imported, `build_resolver` not in scope |
| `tests/streaming_audit.rs` | 🔴 Broken | Imports `TokioAsyncResolver` from `gossan_core` (not re-exported) |
| `tests/bench_streaming.rs` | 🔴 Broken | Same import error + `build_resolver` not in scope |

### 4.2 Missing Adversarial Tests

No tests exist for:
- **Wildcard DNS** — e.g., a mock resolver where `*.example.com` → `1.2.3.4`
- **Malformed JSON** — HTML error page returned instead of JSON
- **Rate-limit responses** — 429 with/without `Retry-After`
- **Empty / giant responses** — 0 bytes vs 100 MB payload
- **Source timeout** — one source hanging, others finishing
- **Concurrent deduplication** — two sources returning the same subdomain
- **Punycode / IDN** — mixed unicode and ACE forms

**Fix:** Add a `tests/adversarial.rs` suite using a local `wiremock` or `tokio::net::TcpListener` mock server to exercise every source against crafted responses. Test the wildcard resolver with a fake `hickory_resolver` or a custom stub resolver.

---

## 5. Action Plan (Priority Order)

1. **Fix compilation immediately.**
   - Repair `lib.rs` function signatures and `out` references.
   - Repair `intelx.rs`, `leakix.rs`, `whoisxml.rs` (`api_keys.extra` → `api_keys.get`, `wait_for_host` → `until_ready`).
   - Repair test file imports.

2. **Wire dead modules.**
   - Add `mod` declarations for `asn`, `bufferover`, `dnsrepo`, `intelx`, `leakix`, `robtex`, `whoisxml`.
   - Include them in the `tokio::join!` (or better, the spawned task loop).

3. **Implement per-source rate limiting.**
   - Add a `SubdomainSourceConfig` TOML section with `req_per_sec` and `daily_quota` per source.
   - Enforce before request, not just after 429.

4. **Fix wildcard handling.**
   - Collect multi-probe wildcard IP sets.
   - Pass wildcard set into `bruteforce::scan` root level.
   - Filter permutations against wildcards.

5. **Add response size limits.**
   - Use `read_response_limited` for all passive sources.

6. **Restore streaming semantics.**
   - Spawn each source in its own task and emit targets as they arrive.

7. **Add adversarial tests.**
   - Mock every source. Test wildcards, malformation, OOM, timeout, dedup.

---

## 6. Conclusion

`gossan-subdomain` is a **high-risk crate in its current state**. The most immediate threat is that it **does not compile**, meaning the entire attack-surface management pipeline is blind to subdomains. Once compilation is restored, the next tier of risks — missing per-source rate limits, wildcard pollution, blocked streaming, and OOM exposure — will cause real production harm: burned API keys, false negatives, and garbage findings. Every item in this audit is actionable and should be treated as blocking for any release.
