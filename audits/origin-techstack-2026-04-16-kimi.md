# Deep Audit: `crates/origin/` + `crates/techstack/`

**Auditor:** Kimi  
**Date:** 2026-04-16  
**Scope:** Read-only source review. Actionable findings only. No band-aids.

---

## Part A — `crates/origin/` (Origin IP Discovery)

### A.1 Architecture Overview

| File | Responsibility |
|------|----------------|
| `Cargo.toml` | 5 feature-gated scanners (`dns_misconfig`, `ssl_cert`, `http_header`, `favicon`, `dns_history`) |
| `src/lib.rs` | Entry point `discover_origin(domain, _config)` — spawns enabled scanners in parallel, aggregates, sorts by confidence, dedupes by IP |
| `src/types.rs` | `OriginCandidate { ip, method, confidence }` |
| `src/scanners/dns_misconfig.rs` | MX → A, SPF `ip4:` parsing, 5 hardcoded bypass subdomains |
| `src/scanners/ssl_cert.rs` | `crt.sh` CT query → hostname extraction → DNS resolution |
| `src/scanners/http_header.rs` | HTTP+HTTPS probes, inspects `rules/leak_headers.toml` for leaked IPs |
| `src/scanners/favicon.rs` | Fetches `/favicon.ico`, computes Shodan-compatible MurmurHash3, optional Shodan API query |
| `src/scanners/dns_history.rs` | SecurityTrails API (v1) + ViewDNS HTML scraping for historical A records |
| `rules/leak_headers.toml` | 13 header definitions with confidence scores |

### A.2 Techniques Inventory vs. State-of-the-Art

| Technique | Status | Finding |
|-----------|--------|---------|
| Historical DNS — SecurityTrails | ✅ | `dns_history.rs` uses `/v1/history/{}/dns/a` |
| Historical DNS — Censys | ❌ **MISSING** | **Finding:** No Censys host or cert search. CloudFail uses Censys IPv4 history. |
| Historical DNS — DNSDB | ❌ **MISSING** | **Finding:** No Farsight DNSDB integration. |
| Historical DNS — CIRCL PDNS | ❌ **MISSING** | **Finding:** No CIRCL passive DNS. |
| Historical DNS — PassiveTotal | ❌ **MISSING** | **Finding:** No RiskIQ/PassiveTotal historical resolution. |
| Certificate Transparency — `crt.sh` | ✅ | `ssl_cert.rs` queries `crt.sh` JSON API. |
| Certificate Transparency — other feeds (Google, Facebook, Cloudflare Nimbus) | ❌ **MISSING** | **Finding:** `crt.sh` only. No direct log ingestion. No SAN-to-IP correlation beyond simple A-record resolution. |
| Email SPF | ✅ | `dns_misconfig.rs` parses `ip4:` tokens from TXT records. |
| Email MX | ✅ | `dns_misconfig.rs` resolves MX to A records. |
| Email DMARC | ❌ **MISSING** | **Finding:** DMARC TXT records are not parsed for RUA domains or origin infra leakage. |
| Subdomain heuristics | ⚠️ PARTIAL | **Finding:** Only 5 hardcoded subs (`direct`, `origin`, `mail`, `ftp`, `cpanel`). OnionOrigin / gotator style dictionaries (hundreds of CDN-bypass subdomains) are absent. |
| Shodan cert search / `ssl:"target"` | ❌ **MISSING** | **Finding:** No Shodan cert-based IP search. Only favicon hash search is implemented. |
| ZoomEye | ❌ **MISSING** | **Finding:** No ZoomEye cert or host search. |
| Favicon hash search (Shodan `http.favicon.hash`) | ✅ | `favicon.rs` computes MurmurHash3 x86/32 and optionally queries Shodan. |
| Favicon search — Censys | ❌ **MISSING** | **Finding:** No Censys favicon hash search. |
| 404 behavior comparison | ❌ **MISSING** | **Finding:** No active fingerprinting comparing CDN 404 page vs. origin 404 page. |
| HTTP header leakage | ✅ | `http_header.rs` + `rules/leak_headers.toml` covers 13 headers. |

### A.3 The Validation Gap — CRITICAL

**Status: COMPLETELY ABSENT.**

`discover_origin(domain, _config)` returns candidates immediately after passive/heuristic aggregation. There is **zero active confirmation**.

What is missing:
1. **Host-header swap:** For each candidate IP, the scanner should open a TCP/TLS connection directly to the IP, send the original `Host` header, and fetch the response.
2. **Response comparison:** Compare body hash, `<title>`, `ETag`, `Content-Length`, or a stable content fingerprint between the CDN-routed response and the direct-to-IP response.
3. **Confirmation scoring:** If the direct-to-IP response matches the CDN response, confidence should jump to `CONFIRMED` (e.g., 100). Without this step, every candidate is speculative.

**Finding:** Without validation, this crate is a *candidate generator*, not an origin discovery engine. A discovered origin IP is a high-value finding only if it is **confirmed**. The lack of confirmation logic is the single most critical defect in this crate.

### A.4 Safety, Robustness, and DoS Surface

#### Unsafe Code
- `#![forbid(unsafe_code)]` is present in `lib.rs`. ✅ No unsafe blocks in production code.

#### Panics
- `#[cfg(not(test)), deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` enforces panic-free production code. ✅
- The only `unwrap`-like call in scanner code is `dns_misconfig.rs:35` — `split(...).next().unwrap_or("")`, which is safe due to the fallback.

#### Regex Backtracking
- **No regex usage anywhere.** ✅ No regex backtracking vulnerabilities.

#### OOM / DoS — MULTIPLE FINDINGS

1. **Unbounded `response.bytes().await` in `favicon.rs:120`**
   - **Fix:** Cap favicon download to a reasonable max (e.g., 5 MB) before hashing. A malicious server can stream an infinite response and exhaust memory.
   - The gap test (`test_legendary_gap.rs`) attempts a 10MB payload, but because `favicon.rs` hardcodes `https://`, it does not actually hit the HTTP-only WireMock server. The vulnerability remains unaddressed.

2. **Unbounded JSON deserialization in `ssl_cert.rs`**
   - `response.json().await` on `crt.sh` will allocate arbitrarily large vectors if the API returns a malformed/huge response. No size limit or streaming parser is used.
   - **Fix:** Use `response.text().await` with a length cap, then parse with `serde_json::from_str` on the bounded string.

3. **Unbounded HTML text in `dns_history.rs`**
   - `response.text().await` loads the full ViewDNS HTML page into memory unbounded.
   - **Fix:** Stream the response or cap the accepted body size.

4. **Hostname amplification in `ssl_cert.rs`**
   - Extracts **all** hostnames from CT logs into a `HashSet` with no upper bound, then sequentially resolves every single one. A domain with thousands of SAN entries could trigger excessive DNS queries and slow execution significantly.
   - **Fix:** Cap the number of hostnames resolved to a reasonable limit (e.g., 500).

### A.5 IP Filtering Inconsistency

- `http_header.rs` filters `is_loopback()` but **misses `is_private()`**.
- `dns_misconfig.rs`, `ssl_cert.rs`, and `dns_history.rs` filter **neither** loopback nor private IPs.
- **Finding:** Private IP leakage (e.g., `10.0.0.1`, `192.168.1.1`) is not consistently suppressed. At internet scale, this pollutes results and may leak internal topology.
- **Fix:** Apply a unified filter function to **all** scanners that rejects loopback, private, link-local, and multicast ranges.

### A.6 Configuration Plumbing — Dead Code

The `_config` parameter in `discover_origin(domain, _config)` is **completely ignored**. API keys are hardcoded as `None` with comments stating they "would come from config in a real integration."

**Finding:** This is dead-code-by-design. The scanner cannot be configured at runtime. SecurityTrails and Shodan integrations are effectively disabled in any real deployment unless the crate is recompiled.

### A.7 Test Analysis

| Test File | Verdict |
|-----------|---------|
| `test_legendary_adversarial.rs` | Good input sanitization (1MB domain, null bytes, zalgo, path traversal, CRLF). **Does NOT test WAFed vs. origin response differences** because no such logic exists. |
| `test_legendary_gap.rs` | Checks localhost/private-IP filtering (acknowledges known gap). Favicon large-payload test is **ineffective** due to HTTPS hardcoding. |
| `test_legendary_property.rs` | Good `proptest` coverage for `Ord` and deduplication invariants. |
| `test_legendary_unit.rs` | Basic smoke tests. |

**Finding:** There are **no adversarial networking tests** (no mock WAF vs. mock origin behavior tests) and **no tests for validation logic** because validation does not exist.

### A.8 Minor Findings

- **`danger_accept_invalid_certs(true)`** is used in `http_header.rs` and `favicon.rs`. While sometimes necessary for origin discovery, it is applied globally without opt-out or warning surface. **Fix:** Make this a configurable flag, defaulting to `false`, with explicit logging when enabled.
- **SPF parser drops CIDR ranges:** `ip4:1.2.3.0/24` is split on `/` and only the prefix is kept. Network range information is lost. **Fix:** Parse CIDR ranges and either expand them or store them as ranges.
- **ViewDNS parser is brittle:** It strips literal `<td>` / `</td>` strings with `replace`. Any HTML attribute change or whitespace variation will break it. **Fix:** Use a minimal HTML parser or stricter substring extraction.

---

## Part B — `crates/techstack/` (Technology Fingerprinting)

### B.1 Architecture Overview

`crates/techstack/` is an **extremely thin integration wrapper** (~124 LOC) around the standalone **`truestack`** crate located at `../../../truestack`. All fingerprinting, security-header auditing, favicon hashing, and version extraction logic lives in `truestack`, not in this crate.

| Component | Lines | Responsibility |
|-----------|-------|----------------|
| `crates/techstack/src/lib.rs` | 124 | `TechStackScanner` implementing `gossan_core::Scanner` |
| `crates/techstack/src/bridge.rs` | 110 | Adapts `truestack` types into `gossan_core` types |
| `truestack/src/fingerprints.rs` | 357 | Core rule engine: parses `rules.toml`, `detect()`, `extract_version()` |
| `truestack/src/rules.toml` | 2,505 | **Embedded TOML signature database** — 185 rules |
| `truestack/src/postprocess.rs` | 186 | Excludes/requires logic, dedup, implied-tech expansion, SPA catch-all |
| `truestack/src/implied.rs` | 227 | Hardcoded implication graph (React → Node.js/webpack, etc.) |
| `truestack/src/behavior.rs` | 129 | Behavioral fingerprinting (malformed HTTP probes) |
| `truestack/src/version_intel.rs` | 601 | Backport-aware version reliability assessment |
| `truestack/src/security_headers.rs` | 393 | Security header audit (HSTS, CSP deep analysis, leaky headers) |
| `truestack/src/favicon.rs` | 132 | Shodan-compatible MurmurHash3 favicon hashing |
| `truestack/src/waf.rs` | 72 | Thin wrapper around `wafrift_detect` crate |

### B.2 Wrapper vs. Reimplementation

**This is 100% a wrapper around `truestack`.** The `Cargo.toml` description literally says *"powered by truestack"*. There is zero fingerprinting logic in `crates/techstack/` itself.

### B.3 Critical Integration Gap — Unused `truestack` Features

The wrapper calls `truestack::fingerprints::detect()` directly and **bypasses** several advanced `truestack` features:

| Feature | Status in Wrapper | Impact |
|---------|-------------------|--------|
| `postprocess::apply()` | ❌ **NOT CALLED** | Duplicates, excludes, requires, and deduplication never run. |
| `implied::expand()` | ❌ **NOT CALLED** | Inferred technologies (Node.js, webpack, etc.) never added. |
| `behavior::identify()` | ❌ **NOT CALLED** | Behavioral probes (malformed method / overlong URI) never executed. |
| `version_intel::assess()` | ❌ **NOT CALLED** | Backport-aware version reliability never computed. |
| `waf::detect()` | ❌ **NOT CALLED** | WAF detection never invoked. |

**Finding:** The `gossan` pipeline receives **raw, unprocessed** fingerprint results. This means:
- Duplicate technologies are emitted (see B.4).
- Conflicting or excluded technologies are not filtered out.
- Implied technologies (e.g., React implies Node.js) are lost.
- Behavioral fingerprints (e.g., nginx vs. Apache error pages) are never collected.
- Version strings are returned without reliability assessment.

**Fix:** The wrapper must call the full `truestack` pipeline:
```rust
let mut technologies = detect(...);
behavior::identify(&client, url, &mut technologies).await.ok();
postprocess::apply(&mut technologies);
implied::expand(&mut technologies);
version_intel::assess(&mut technologies);
```

### B.4 Signature Source: TOML-Based but Duplicated

- **TOML-driven:** `rules.toml` is embedded at compile time via `include_str!`. Runtime custom rules are supported via `RuleEngine::from_directory(path)`.
- **Rule count:** **185** rules.
- **Duplicate rules:** **28 duplicate rule names** in `rules.toml`. Examples: `Akamai`, `Astro`, `AWS CloudFront`, `Caddy`, `Cloudflare WAF`, `Gatsby`, `Ghost`, `Joomla`, `Magento`, `Remix`, `SvelteKit`, `Vercel`, `WooCommerce`.

**Finding:** Because `detect()` iterates over all rules and the wrapper bypasses `postprocess::apply()` (which deduplicates), the same technology can be emitted multiple times with overlapping signals. At internet scale, this corrupts downstream CVE mapping and patch-signature correlation.

**Fix:** 
1. Deduplicate `rules.toml` (remove or merge the 28 duplicates).
2. Ensure the wrapper calls `postprocess::apply()`.

### B.5 Confidence Scoring — Primitive

| Aspect | Implementation | Verdict |
|--------|----------------|---------|
| Pattern-match confidence | Hardcoded to **`80`** for *every* rule match in `fingerprints.rs:169` | 🔴 Weak |
| Source weight | None. A `Server: nginx` header and a buried `<script>nginx</script>` body hit get the same `80` | 🔴 Missing |
| Version extraction confidence | No separate confidence score. `extract_version()` returns `Some(String)` or `None` with no indication of parsing certainty | 🔴 Missing |
| Signal accumulation | `min_signals` field exists on `Rule` but defaults to `1`. No scoring based on how many signals matched | 🔴 Missing |
| Implied tech confidence | `tech.confidence / 2` with a floor of `20` in `implied.rs:161` | 🟡 Acceptable (but unused by wrapper) |
| Behavioral confidence | `(matches / total_probes) * 100`, clamped to `100` in `behavior.rs:90` | 🟢 Reasonable (but unused by wrapper) |

**Finding:** Dynamic confidence scoring is absent. Every match is exactly `80`, regardless of signal strength or source. This makes it impossible to prioritize high-confidence findings (e.g., a `Server` header) over low-confidence ones (e.g., a generic body substring).

**Fix:** Implement source-weighted confidence:
- `header` exact match: 95
- `cookie` exact match: 90
- `favicon` hash match: 90
- `body` substring match: 60–80 (scaled by rarity)
- `script` src match: 70

### B.6 Modern Stack Detection

| Technology | Detected? | Evidence in `rules.toml` |
|------------|-----------|--------------------------|
| **Next.js** | ✅ | `__NEXT_DATA__`, `/_next/static`, `x-powered-by: next.js` |
| **Nuxt** | ✅ | `__NUXT__`, `/_nuxt/`, `id="__nuxt"` |
| **Remix** | ✅ | `x-remix-route`, `window.__remixContext` |
| **Astro** | ✅ | `x-astro-page`, `data-astro-cid-` |
| **SvelteKit** | ✅ | `__sveltekit_`, `x-sveltekit-page` |
| **React Server Components** | ❌ **No** | **Finding:** No `__RSC`, `react-server`, or flight data signatures. |
| **Vite** | ✅ | `vite`, `x-vite` |
| **Turbopack** | ❌ **No** | **Finding:** No `turbopack`, `__turbopack_load`, or related signatures. |

**Fix:** Add rules for React Server Components (`__RSC`, `react-server`, `x-rsc`) and Turbopack (`__turbopack_load`, `turbopack`, `x-turbopack`).

### B.7 Backend Detection

#### Cookie Names

| Cookie | Present? | Finding / Fix |
|--------|----------|---------------|
| `PHPSESSID` | ✅ | PHP rule |
| `JSESSIONID` | ✅ | Tomcat, Spring rules |
| `ASP.NET_SessionId` | ✅ | ASP.NET rule |
| `connect.sid` | ✅ | Express rule |
| `_ga` (Google Analytics) | ❌ **No** | **Finding:** No Google Analytics cookie detection. **Fix:** Add `cookie: _ga` → Google Analytics. |
| `express:sess` | ✅ | Express rule |
| `laravel_session` | ✅ | Laravel rule |
| `ci_session` | ✅ | CodeIgniter rule |

#### Header Leaks

Checked in `security_headers.rs`:
- ✅ `X-Powered-By`
- ✅ `Server`
- ✅ `X-AspNet-Version`
- ✅ `X-AspNetMvc-Version`
- ✅ `X-Generator`
- ✅ `Via`
- ✅ `X-Version`

**Missing:**
- `X-Backend` — not checked as a generic leak.
- `X-Served-By` — only checked for Fastly CDN, not as a generic leak.
- `X-Cache-Key` — not checked.
- `X-Real-Ip` — not checked.

#### Error Page Signatures

Present in `behavior.rs` but **very limited** (only 8 signatures):
- nginx 405 / 414 / 400
- Apache 501 / 414 / 400
- IIS 405
- Express 404 ("Cannot XYZMETHOD")
- Caddy 405 (empty body)

**Finding:** There is **no general error-page body parsing** in the main fingerprint engine for framework-specific error templates (e.g., Django yellow page, ASP.NET error details, Spring Whitelabel, Laravel debug page).

**Fix:** Add error-page body signatures to `rules.toml` for major frameworks.

### B.8 Version Extraction

| Source | Supported? | Notes |
|--------|------------|-------|
| `X-Generator` | ✅ | Drupal, Joomla, Ghost, TYPO3, Webflow |
| `meta generator` tag | ⚠️ Partial | Only if raw HTML contains `<meta name="generator" content="...` as a substring. No structured DOM parsing specifically for this tag. |
| Framework routes | ✅ | `/wp-json/`, `/wp-content/`, `/sites/default/`, `/static/admin/`, `/_next/static`, `/_nuxt/` |

**Extraction Logic Quality:**
- Located in `fingerprints::extract_version()`.
- Does basic string splitting: looks for `tech_name/version`, falls back to first whitespace token starting with a digit, or `split('/').nth(1)`.
- **No regex** (avoids backtracking, but lacks precision).
- **No extraction confidence** returned.
- Fails on complex banners like `Apache/2.4.41 (Unix) OpenSSL/1.1.1d PHP/7.4.3` — it returns `2.4.41` for Apache (correct) but misses secondary versions.

**Fix:** Return a `VersionExtraction { version: String, confidence: u8 }` struct instead of `Option<String>`. Use more precise parsing for compound banners.

### B.9 Safety, Robustness, and DoS Surface

#### Unsafe Code
- `truestack` crate root has `#![forbid(unsafe_code)]`.
- **BUT** `truestack/src/favicon.rs:44` contains:
  ```rust
  formatted.push_str(unsafe { std::str::from_utf8_unchecked(chunk) });
  ```
  This is inside a regular `fn`, not an `unsafe fn`.

**Finding:** The `unsafe` block in `favicon.rs` **directly contradicts** `#![forbid(unsafe_code)]` in `lib.rs`. This code likely **does not compile** with that attribute, or the attribute is being silently overridden. This is a direct violation of the crate's own safety policy.

**Fix:** Remove the `unsafe` block. Use `std::str::from_utf8(chunk).unwrap_or("")` — the chunk comes from base64 ASCII output, so it is guaranteed valid UTF-8. The `unsafe` optimization is unnecessary.

#### Panics
- `fingerprints.rs:110`: Compile-time panic on malformed embedded `rules.toml`:
  ```rust
  toml::from_str(toml).unwrap_or_else(|e| panic!("failed to parse embedded rules.toml: {}", e))
  ```
  This is acceptable because it fails at build time, not runtime.
- Tests use `.unwrap()` extensively (acceptable in test code).

#### Regex Backtracking
- **No `regex` crate dependency.**
- **Zero regex usage.**
- Substring matching is done via a custom `contains_ignore_case()` function that does a naive O(n·m) byte scan.
- ✅ No backtracking risks.

#### OOM / DoS — FINDINGS

1. **`bridge.rs:19`: `resp.text().await`** loads the **entire response body** into a `String`. No size limit.
   - **Fix:** Cap body download to a configurable max (e.g., 2 MB).

2. **`truestack/src/favicon.rs:16-20`:** Fetches arbitrary-size favicon bytes with `resp.bytes().await`. No limit.
   - **Fix:** Cap favicon download to 5 MB.

3. **`contains_ignore_case()` is a naive O(n·m) byte scan.** With 185 rules on a 1 MB body, this is ~185 MB of scanning per request. No Boyer-Moore or Aho-Corasick optimization.
   - **Fix:** For large bodies, consider using `memchr` or Aho-Corasick for multi-pattern matching.

4. **`behavior.rs:123`:** Probes generate an **8,192-character path** (`"A".repeat(8192)`). Some middleware may log this, causing disk exhaustion.
   - **Fix:** Ensure probes are rate-limited and logged responsibly.

### B.10 Test Analysis

| Test File | Verdict |
|-----------|---------|
| `truestack/tests/adversarial.rs` (257 lines) | Good edge-case tests: empty inputs, unicode, malformed HTML, case-insensitive headers, version extraction edge cases, concurrent usage (10 threads). |
| `truestack/tests/integration.rs` (91 lines) | Two WireMock tests: WordPress full pipeline, CSP bypass detection. |
| `truestack/fuzz/fuzz_targets/fuzz_rule_engine.rs` | Basic `libfuzzer` target for `detect_with_engine()`. |

**What's Missing:**
- ❌ **No test for a target that spoofs multiple frameworks simultaneously.**
- ❌ **No test for negative signals** at the integration level.
- ❌ **No test for excludes/requires** interaction.
- ❌ **No test for duplicate rule suppression.**
- ❌ **No adversarial test with very large bodies** (OOM/DoS).
- ❌ **No test for behavioral probing** — the module exists but has zero integration tests.
- ❌ **No test verifying the wrapper calls `postprocess::apply()` or `implied::expand()`**.

### B.11 Wrapper-Specific Findings

- **`bridge.rs` uses `v.to_str().unwrap_or("")`** on headers. If a header contains non-UTF8 bytes, it silently drops them rather than using raw bytes. **Fix:** Use `to_str()` lossy conversion or document the UTF-8 requirement.
- **The wrapper only makes a single HTTP GET request to `/`.** No secondary probes for `/robots.txt`, `/sitemap.xml`, `/favicon.ico` (except for hash), or framework-specific routes like `/wp-json/`. **Fix:** Add secondary route probing for higher-confidence detection.

---

## Part C — Cross-Cutting Findings (Both Crates)

### C.1 Panics, Casts, OOM, Regex Backtracking — Summary

| Risk | `origin` | `techstack` |
|------|----------|-------------|
| Panics (production) | Low (strict lints) | Low (strict lints) |
| Unsafe code | None ✅ | **Violation in `favicon.rs`** 🔴 |
| Regex backtracking | None ✅ | None ✅ |
| OOM / DoS | **Unbounded response buffering** 🔴 | **Unbounded body/favicon buffering** 🔴 |
| Casts | None significant | None significant |

### C.2 Test Philosophy Gap

Neither crate has tests that simulate an **adversarial target**:
- A target that returns different responses for CDN vs. direct-IP requests (origin-specific test).
- A target that intentionally spoofs multiple framework signatures to pollute techstack results.
- A target that returns multi-gigabyte responses to test DoS resistance.

**Finding:** The test suites are "happy path + input sanitization" rather than "adversarial networking." At internet scale, every scanner will encounter malicious or pathological endpoints.

---

## Part D — Actionable Recommendations (Prioritized)

### Immediate (Do Not Postpone)

1. **`origin` — Implement validation logic.** For every candidate IP, perform a direct TCP/TLS connection with the original `Host` header. Compare body hash / `<title>` / `ETag` against the CDN-routed response. Without this, the crate is incomplete.
2. **`origin` — Add missing historical DNS sources.** Censys, DNSDB, CIRCL PDNS, PassiveTotal.
3. **`techstack` — Fix the wrapper to use the full `truestack` pipeline.** Call `postprocess::apply()`, `implied::expand()`, `behavior::identify()`, `version_intel::assess()`.
4. **`techstack` — Remove duplicate rules from `rules.toml`.**
5. **Both crates — Cap all response body sizes.** Favicon ≤ 5 MB, HTML ≤ 2 MB, JSON ≤ 10 MB.
6. **`techstack` — Remove the `unsafe` block in `favicon.rs` or remove `#![forbid(unsafe_code)]`.** Do not leave contradictory policies in place.

### Short-Term

7. **`origin` — Unify private/loopback IP filtering across all scanners.**
8. **`origin` — Expand bypass subdomain dictionary** from 5 to hundreds (OnionOrigin / gotator style).
9. **`origin` — Parse DMARC records** for RUA domains and infrastructure leakage.
10. **`origin` — Add 404 behavior fingerprinting.**
11. **`techstack` — Implement source-weighted confidence scoring.**
12. **`techstack` — Add missing modern framework signatures:** React Server Components, Turbopack.
13. **`techstack` — Add missing backend signals:** `_ga` cookie, `X-Backend` header leak, framework-specific error pages.
14. **`techstack` — Return version extraction confidence**, not just `Option<String>`.
15. **Both crates — Add adversarial networking tests:** multi-GB responses, spoofed frameworks, WAF vs. origin behavior divergence.

---

## Part E — Verdict

| Crate | Grade | Rationale |
|-------|-------|-----------|
| `origin` | **C-** | Good scaffolding, clean parallelism, safe Rust. Fatally undermined by **complete absence of origin confirmation logic** and **missing major historical DNS sources**. Unbounded memory consumption is a secondary critical issue. |
| `techstack` | **C+** | Thin wrapper around a competent engine (`truestack`), but the wrapper **discards half the engine's features** (post-processing, behavioral probes, version intel, WAF detection). 185 rules is adequate but not comprehensive. Confidence scoring is primitive. Duplicate rules and an `unsafe` block under `forbid(unsafe_code)` are concrete bugs. |
| **Combined** | **C** | Both crates need deep refactors, not band-aids. The origin crate needs validation logic (the core value proposition). The techstack crate needs to stop bypassing the advanced features of its own engine. |
