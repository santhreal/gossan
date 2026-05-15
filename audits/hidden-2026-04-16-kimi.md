# Deep Audit: `crates/hidden/` — Hidden Endpoint Scanner

**Auditor:** Kimi Code CLI  
**Date:** 2026-04-16  
**Scope:** `crates/hidden/src/` and tests (read-only audit)  
**Output:** `audits/hidden-2026-04-16-kimi.md`

---

## Executive Summary

`gossan-hidden` contains a mix of well-intentioned probes and **critical structural failures**. Most alarmingly, **three entire subsystems are dead code** (never linked into `lib.rs`), the main scanner loop contains a **syntax error that prevents compilation**, and **multiple test files reference a non-existent `dependency_confusion` module**. At internet scale, these bugs guarantee false negatives on OAuth endpoints, 403-bypass opportunities, and directory-brute discoveries.

**Severity distribution:**
- **CRITICAL:** 8 findings (dead code, compilation blocker, missing soft-404 logic, missing introspection bypasses, path traversal in output, unbounded response reads)
- **HIGH:** 7 findings (missing techniques vs. industry tools, weak concurrency controls, missing `.well-known` coverage, missing GraphQL tricks)
- **MEDIUM:** 6 findings (wordlist gaps, test coverage holes, TOML loading edge cases)

---

## 1. File-by-File Technique Enumeration

| File | Technique | Status |
|------|-----------|--------|
| `lib.rs` | Scanner orchestration, per-host rate limiter, catch-all detection | **BROKEN — syntax error on line 390; dead modules not wired** |
| `directory_brute.rs` | Dirbusting with wordlist + extensions + baseline fingerprinting | **DEAD CODE — not declared in `lib.rs`** |
| `robots.rs` | robots.txt parsing (Disallow, Sitemap) | Active |
| `sitemap.rs` | sitemap.xml/sitemap_index.xml parsing, gzip support, recursive index follow | Active |
| `swagger.rs` | OpenAPI/Swagger path list, JSON parsing, unauth endpoint analysis | Active |
| `graphql.rs` | Introspection, field suggestion, batching, alias amplification | Active |
| `git_env/mod.rs` | Orchestrator for `.git`/`.env`/config exposure probes | Active |
| `git_env/detect.rs` | Catch-all detection (`is_catch_all`) | Active |
| `git_env/extract.rs` | Response → finding conversion with content validation | Active |
| `git_env/rules.rs` | Compiled-in `CHECKS` array + TOML loader | Active |
| `backup_files.rs` | Backup/swap/config file probes with 404 baseline + magic bytes | Active |
| `bypass403.rs` | 403 bypass via headers, path mutations, method switching | **DEAD CODE — not declared in `lib.rs`** |
| `cookies.rs` | Set-Cookie security flag analysis | Active |
| `cors.rs` | CORS origin reflection, null origin, prefix bypass, HTTP downgrade, methods | Active |
| `csp.rs` | CSP directive parsing (`unsafe-inline`, `unsafe-eval`, `*`, `data:`, missing `frame-ancestors`) | Active |
| `debug_endpoints.rs` | Framework debug endpoint probes (Spring Boot, Django, Go pprof, etc.) | Active |
| `error_disclosure.rs` | Trigger errors and detect stack traces, SQL errors, SSTI, debug headers | Active |
| `favicon.rs` | Favicon hash fingerprinting (murmurhash3) | Active |
| `methods.rs` | HTTP method enumeration (OPTIONS → PUT/DELETE/TRACE) | Active |
| `oauth.rs` | OAuth/OIDC discovery, open redirect in `redirect_uri`, JWKS analysis, token endpoint auth | **DEAD CODE — not declared in `lib.rs`** |
| `rate_limit.rs` | Burst login requests to detect rate limiting absence | Active |
| `security_headers.rs` | HSTS, X-Frame-Options, X-Content-Type-Options checks | Active |
| `tech_probes.rs` | WordPress, Drupal, Laravel, Joomla, Strapi targeted checks | Active |
| `waf.rs` | WAF fingerprinting via `wafrift-detect` | Active |

### 1.1 Missing Modules vs. Advertised Capabilities

The crate-level doc comment in `lib.rs` (lines 20–27) claims the scanner probes for:
- **h2c upgrade bypass** → *No module implements this.*
- **host header injection** → *No module implements this.*
- **open redirect** → *Only partially covered inside the dead `oauth.rs` module.*
- **SSRF** → *No module implements this.*
- **dependency confusion** → *Referenced in tests, but no source module exists.*

**Fix:** Either implement these modules or remove the false claims from the documentation.

---

## 2. Comparison to Industry Tools — Technique Gaps

### 2.1 vs. ffuf / dirsearch / gobuster / feroxbuster

| Capability | Tool Standard | `gossan-hidden` Status | Finding |
|------------|---------------|------------------------|---------|
| **Soft-404 detection** | Baseline multiple random paths, compare body hash/length/ratio | Partial (`directory_brute.rs` and `backup_files.rs` have baselines, but `git_env` uses a *different* catch-all check and most other probes have **no** baseline) | **HIGH** |
| **Recursive directory brute** | feroxbuster-style recursive fuzzing on discovered 200 dirs | Not implemented | **HIGH** |
| **File extension mutations** | `.bak`, `.old`, `.zip`, `.tar.gz`, `.sql` | Only `directory_brute.rs` has a hardcoded 10-extension list; dead code means it never runs | **CRITICAL** |
| **Spider / link extraction** | katana-style passive crawling, JavaScript parsing | No JS rendering, no link extraction from HTML | **HIGH** |
| **Wordlist size** | SecLists `raft-large-directories.txt` (~62k entries) | Built-in wordlist is ~480 lines; no automatic SecLists integration | **MEDIUM** |
| **Response-time filtering** | ffuf can filter by response time | Not implemented | LOW |
| **Replay / proxy integration** | Burp/OWASP ZAP proxy support | Not visible in this crate | INFO |

### 2.2 vs. katana

| Capability | katana | `gossan-hidden` | Finding |
|------------|--------|-----------------|---------|
| **JavaScript endpoint extraction** | Yes (AST-based) | No | **HIGH** |
| **Automatic form submission** | Yes | No | MEDIUM |
| **Custom headers / cookies** | Yes | Delegated to `gossan-core` client builder | — |
| **Headless browser** | Yes (optional) | No | MEDIUM |

### 2.3 vs. Specialized GraphQL Tools (graphql-cop, clairvoyance)

| Capability | `gossan-hidden` | Finding |
|------------|-----------------|---------|
| **Introspection via `__schema`** | Yes | — |
| **Introspection via `__Type` / `__Field` fragments** | No | **HIGH** |
| **Introspection disabled bypass (alias trick)** | No | **HIGH** |
| **Introspection disabled bypass (fragment spreading)** | No | **HIGH** |
| **GraphQL subscription abuse** | No | MEDIUM |
| **Directive-based DoS (`@include`/`@skip` amplification)** | No | MEDIUM |

### 2.4 vs. Swagger/OpenAPI Discovery

| Capability | `gossan-hidden` | Finding |
|------------|-----------------|---------|
| **Path list** | 28 paths (`swagger.rs` lines 12–52); covers common locations | — |
| **Parse spec and emit every endpoint** | Partial — emits *unauthenticated* endpoints and API-key params, but **does not emit every endpoint as a standalone finding** | **HIGH** |
| **YAML parsing** | No YAML parser dependency; falls back to weak text heuristics (`analyze_spec_text`) | **MEDIUM** |
| **Versioned variants** | `/v1/swagger.json`, `/v2/swagger.json`, `/v3/openapi.json`, `/api/v1/swagger.json`, `/api/v2/openapi.json` | — |
| **`.well-known/openapi.json`** | Present | — |
| **Missing paths:** `/swagger-resources`, `/swagger-ui/springfox.js`, `/api/swagger-ui.html`, `/api/v3/api-docs`, `/rest/v1/swagger.json` | Missing | MEDIUM |

---

## 3. Soft-404 Detection

### 3.1 Where Baselines Exist

- **`directory_brute.rs`** (`establish_baseline` / `looks_like_404`):
  - Uses **one** random probe (`fastrand::u64(..)`).
  - Compares status, body prefix (256 bytes), and length similarity (`< 100` bytes or `< 20%`).
  - **Weakness:** A single probe is fragile. Servers with dynamic ads or timestamps will produce a different prefix on every request. Length-only similarity allows false negatives on SPAs that serve `index.html` with slightly different content lengths.

- **`backup_files.rs`** (`establish_404_baseline` / `is_likely_404_response`):
  - Uses **3** random probe paths (better than `directory_brute.rs`).
  - Compares status, 512-byte prefix match, and length similarity.
  - **Weakness:** Still no hashing. A SPA with inline CSP nonces or CSRF tokens will fail prefix matching. Length check can be bypassed by servers that pad responses.

### 3.2 Where Baselines Are Missing

- **`git_env/extract.rs`**: Uses `detect::is_catch_all` (a single 200 probe) and HTML rejection, but **no length/hash baseline**.
- **`debug_endpoints.rs`**: No baseline at all. A catch-all SPA serving `index.html` for all paths will trigger findings on `/actuator/env`, `/__debug__/`, etc.
- **`swagger.rs`**: No baseline. If `/swagger.json` returns the SPA shell as HTML 200, the `is_spec` check (`body.contains("openapi")`) will fail, which is fine, but if the SPA shell *happens* to contain those strings (e.g., from an OpenAPI documentation widget), it will false-positive.
- **`graphql.rs`**: No baseline. A catch-all server returning 200 + `{"data":null}` for all paths will false-positive as a GraphQL endpoint.
- **`robots.rs`**, **`sitemap.rs`**, **`methods.rs`**, **`api_versions.rs`**, **`tech_probes.rs`**, **`oauth.rs` (dead)**, **`bypass403.rs` (dead)**: **No soft-404 logic whatsoever.**

### 3.3 Comparison to Best Practice

**Best practice** (feroxbuster, ffuf):
1. Request 3–5 guaranteed-nonexistent paths.
2. Record status, body length, and a perceptual hash or ratio-hash of the body.
3. For every candidate response, compute the same hash and compare.
4. If the server returns 200 for nonexistent paths, **require content validation** (magic bytes, specific substrings, or content-type mismatch rejection).

**Gap:** `gossan-hidden` does not share a **single, robust baseline** across all probes for a given target. Each subsystem reinvents its own partial check.

**Fix:** Extract a unified `Soft404Baseline` struct that computes status + body hash (e.g., xxhash or simhash of normalized HTML) and share it across every probe module.

---

## 4. Swagger / OpenAPI Discovery

### 4.1 Path Coverage

`swagger.rs` defines 28 paths. This is **adequate but not exhaustive**.

**Missing common paths:**
- `/swagger-resources` (Spring Boot)
- `/swagger-ui/springfox.js`
- `/api/swagger-ui.html`
- `/api/v3/api-docs`
- `/rest/v1/swagger.json`
- `/api/swagger/v1/swagger.json`

### 4.2 Parsing Depth

- **JSON specs:** Parsed with `serde_json`. Unauthenticated endpoints and API-key parameters are surfaced. **However, the spec does not emit *every* endpoint as a finding** — it only emits aggregated statistics. An operator cannot feed these findings directly into a path scanner.
- **YAML specs:** No YAML parser. Falls back to `analyze_spec_text`, which does crude `http://` detection and path-count estimation. If a YAML spec is large and complex, this heuristic is nearly useless.

### 4.3 Critical Gap: No Baseline

If the target is a catch-all SPA, `/swagger.json` may return 200 with the SPA shell. The `is_spec` check relies on substring matching (`"openapi"`, `"swagger"`), which a generic HTML page might accidentally pass if it includes a documentation widget or marketing copy.

**Fix:** Before parsing, verify the response `Content-Type` is `application/json` or `text/yaml`, and reject HTML responses.

---

## 5. GraphQL

### 5.1 What Works

- Endpoint discovery via `__typename` probe across 11 common paths.
- Introspection query (`__schema { queryType { name } types { name kind fields { name } } }`).
- Field suggestion leakage (typo probe `__typenme`).
- Batching detection (array of 10 queries).
- Alias amplification (20 aliases).

### 5.2 Critical Gaps

**Missing introspection bypass techniques:**
1. **Alias trick:** `query { __schema { queryType { name } } }` sent as an aliased field to bypass simple regex filters.
2. **Fragment spreading:** `query { ... on __Schema { queryType { name } } }` to bypass field-name blacklists.
3. **Double underscore mutation:** Some WAFs block `__schema` but not `__Schema` or encoded variants.
4. **Introspection via `__type(name: "User")`:** A more targeted query that some servers allow even when full introspection is disabled.

**Missing batching depth tests:**
- The batch probe uses exactly 10 queries. A robust test should vary batch size (50, 100, 500) to detect rate-limit bypass scaling.

**Missing subscription abuse:**
- No WebSocket upgrade probe for GraphQL subscriptions (common on `/graphql` with `subscription` messages).

### 5.3 False Positive Risk

The endpoint discovery phase accepts any 200 response containing `__typename` or `"data"`. A catch-all SPA returning `{"data":null}` or a page containing the string `data` will false-positive.

**Fix:** Require the response to be valid JSON with a `data.__typename` field, and implement soft-404 baseline rejection.

---

## 6. `.git` / `.env` / Backup Discovery

### 6.1 `git_env` Module

`git_env/rules.rs` defines an excellent compiled-in checklist (90+ entries) covering:
- `.git/HEAD`, `.git/config`, `.git/COMMIT_EDITMSG`, `.git/logs/HEAD`
- `.svn/entries`, `.hg/hgrc`, `.bzr/branch/format`
- SSH keys, cloud credentials (AWS, GCP, K8s)
- `.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.backup`, `.env.old`, `.env.example`
- Config files (`config.php`, `wp-config.php.bak`, `settings.py`, `web.config`)
- Backups (`backup.zip`, `dump.sql`, `db.sql`, `database.sql`)
- Debug endpoints, admin panels, API docs

**Strengths:**
- TOML-driven extensibility (`data/checks.toml` or `./data/*.toml`).
- Content validation (`content_probe`) for most critical checks.
- Catch-all rejection (HTML responses are discarded on catch-all servers).

**Weaknesses:**
- **Missing `.git/objects/` traversal:** An exposed `.git/HEAD` is flagged, but the scanner does not attempt to enumerate `.git/objects/xx/xxxx...` to verify full repository reconstructability.
- **Missing `.git/index`:** Not in the check list. `.git/index` is critical for source reconstruction.
- **Missing `.env.development`, `.env.test`:** Only `.env.local`, `.env.production`, `.env.staging` are covered.
- **Missing `backup.sql`, `data.sql` in compiled checks but present in TOML:** The compiled `CHECKS` array and `data/checks.toml` are **not perfectly synchronized**. For example, `data/checks.toml` includes `/backup.sql` and `/data.sql`, but the compiled `CHECKS` in `rules.rs` also includes them. However, `/config.php` has `content_probe = None` in `CHECKS` but no TOML override — this allows false positives.

### 6.2 `backup_files.rs`

A parallel, **redundant** subsystem that probes many of the same paths (`/.env`, `/.env.production`, `/dump.sql`, `/backup.zip`, etc.) but with different validation logic (magic bytes for binaries, `body_confirms` for text).

**Critical Finding:** `backup_files.rs` is **active** (called from `lib.rs`), while `git_env` is also active. This means the same paths are probed **twice** with overlapping coverage, wasting requests. Worse, `backup_files.rs` has its own 404 baseline, but `git_env` uses `is_catch_all` — the two subsystems do not share state.

**Fix:** Merge `backup_files.rs` into `git_env` or delete it. Having two overlapping backup scanners violates the DRY principle and doubles request volume.

### 6.3 Path Safety

When a finding is created, the **URL path is embedded directly into the finding title and detail strings**. There is no path sanitization before emitting. If the scanner later writes findings to disk using the URL as a filename (this logic lives outside `crates/hidden/`, in the emitter), a malicious server could theoretically influence the output path.

However, **within `crates/hidden/` itself**, no filesystem writes are performed. The risk is indirect. Still, `gossan-hidden` should sanitize or encode paths before embedding them in `Finding` structs to prevent downstream traversal if the consumer uses these strings as filenames.

**Fix:** Percent-encode or strip path separators from any server-controlled string before placing it in a `Finding`.

---

## 7. Wordlist Quality

### 7.1 Directory Wordlist

`directory_wordlist.txt` contains ~480 entries. Categories covered: admin, APIs, dev/CI, config, source control, databases, files, logs, mail, network, CMS, help, apps, e-commerce, security, misc.

**Comparison:**
- SecLists `raft-large-directories.txt`: ~62,000 entries.
- SecLists `common.txt`: ~4,700 entries.
- `gossan-hidden`: ~480 entries.

**Verdict:** The built-in wordlist is **tiny** compared to industry standard. It will miss niche applications and custom admin panels.

**Fix:** Load from an external TOML/file by default (community extensible, per LAW 6). The built-in list should be a minimal fallback, not the primary source.

### 7.2 Extension List

`directory_brute.rs` defines:
```rust
const DEFAULT_EXTENSIONS: &[&str] = &["", ".php", ".js", ".json", ".bak", ".txt", ".zip", ".tar.gz", ".sql", ".xml"];
```

**Missing extensions:** `.old`, `.save`, `.swp`, `.~`, `.orig`, `.copy`, `.rar`, `.7z`, `.gz`, `.tgz`, `.bz2`, `.tar`, `.log`, `.config`, `.yml`, `.yaml`, `.cfg`, `.ini`, `.db`, `.sqlite`, `.sqlite3`, `.mdb`, `.dbf`, `.csv`, `.xls`, `.xlsx`, `.pdf`, `.doc`, `.docx`.

**Fix:** Make the extension list TOML-driven and default to a much broader SecLists-based set.

---

## 8. Concurrency Safety

### 8.1 Rate Limiting

`lib.rs` implements `HostRateLimiter`:
- Simple per-host `HashMap<String, Instant>` protected by `tokio::RwLock`.
- Enforces `config.host_delay_ms` between requests **to the same host**.

**Strengths:**
- Prevents unbounded hammering of a single target.
- Different hosts are not throttled against each other.

**Weaknesses:**
1. **No exponential backoff on 429/503.** The scanner continues at the same fixed delay even if the server is clearly struggling.
2. **No global concurrency limit per host.** `buffer_unordered(config.concurrency)` limits total concurrent targets, but a single target still receives **all probes simultaneously** via `FuturesUnordered` inside the target loop. With 20+ probes, a target gets 20 concurrent requests at once, then is gated by `host_delay_ms` only for subsequent waves.
3. **Rate limiter is not shared across `client_no_redir` and `client_follow` probes.** Although the same `Arc<HostRateLimiter>` is cloned, the probes are spawned into the same `FuturesUnordered`, so they race. The first to call `wait_for_host` wins; the rest sleep. This is correct, but the **burst size** is equal to the number of probes (~20), which is large.

### 8.2 Request Amplification

For a single `Target::Web`, the scanner spawns:
- git_env
- swagger
- cookies
- graphql
- cors
- csp
- api_versions
- methods
- rate_limit
- security_headers
- debug_endpoints
- error_disclosure
- robots
- sitemap
- favicon
- waf
- debug_endpoints_follow
- backup_files
- tech_probes (conditional)

That is **18–19** concurrent requests to the same host, followed by internal concurrency within subsystems like `git_env` (buffer_unordered(25)) and `backup_files` (sequential but each request is independent).

**Fix:** Cap per-host in-flight requests to a small number (e.g., 3–5) and implement exponential backoff on 429/503/ConnectionRefused.

---

## 9. Path Safety (Directory Traversal in Output)

### 9.1 Direct File Writes in `crates/hidden/`

None. `gossan-hidden` only creates `Finding` structs and emits them via `input.emit(f)`. It does not write to disk.

### 9.2 Indirect Risk

The `Finding` structs contain:
- `title`
- `detail`
- `evidence` (which may contain `body_excerpt` with server-controlled content)

If a downstream consumer uses the target URL or path from a finding as a filename (e.g., `output_dir/{finding.title}.json`), a malicious server returning `../../../../etc/passwd` as a "discovered URL" could influence the path.

**Specific instances where server-controlled strings are embedded unsanitized:**
- `directory_brute.rs` line 146: `title(format!("Hidden path discovered: {}{}", path, ext))` — `path` comes from the wordlist, which is trusted. Safe.
- `swagger.rs` line 86–88: `detail` contains `url`, which is constructed from `base + PATHS[i]`. Safe (client-controlled).
- `graphql.rs` line 99: `detail` contains `ep`, which is the server-responding URL. Safe (client-controlled).
- `backup_files.rs` line 529: `detail` contains `url`, which is `base + p.path`. Safe.
- `git_env/extract.rs` line 62: `title` and `detail` come from `OwnedCheck`, which is client-controlled. Safe.

**However:** `error_disclosure.rs` embeds arbitrary server response lines into `excerpt` and `detail` (line 260). If a server returns a path like `../../../etc/shadow` in an error message, it is placed verbatim into the finding. Downstream consumers must sanitize this.

**Verdict:** Low direct risk, but `gossan-hidden` should percent-encode or strip `..` and path separators from any `body_excerpt` before embedding it in a finding to protect downstream consumers.

---

## 10. Panics, Casts, OOM, Regex Backtracking

### 10.1 Panic Sources

`lib.rs` uses `#![cfg_attr(not(test), deny(clippy::panic))]`, which is good.

**Found issues:**

1. **`lib.rs` line 390 — Syntax Error (Compilation Blocker)**
   ```rust
   for f in batch) { input.emit(f); }
   ```
   This is invalid Rust. The crate **cannot compile**.
   **Severity: CRITICAL**

2. **`favicon.rs` line 57 — Casting panic risk:**
   ```rust
   i32::try_from(hash).unwrap_or(0)
   ```
   This is safe (`try_from` + `unwrap_or`), but the comment above says `murmurhash3_x86_32` returns `u32`, and `i32::try_from(u32)` will return `Err` for any hash > `i32::MAX`. This means half of all hashes are silently truncated to `0` in the Shodan query detail string.
   **Severity: MEDIUM** (informational truncation, not a panic).

3. **`sitemap.rs` — OOM risk on gzip bomb:**
   `extract_sitemap_urls_recursive` reads the full response into memory (`resp.bytes().await`), then decompresses gzip via `flate2::read::GzDecoder` into a `String`. A malicious server could send a gzip bomb (e.g., 10MB compressed → 10GB uncompressed). There is **no size limit** during decompression.
   **Severity: CRITICAL**

4. **`cors.rs` — Regex? No regex used.** The CORS probe uses simple string comparisons. Good.

5. **`backup_files.rs` — OOM on large binary responses:**
   `resp.bytes().await` reads the entire response into memory. A server could return a multi-GB "backup.zip" that exhausts RAM. No streaming or size limit.
   **Severity: CRITICAL**

6. **`graphql.rs` — OOM on large introspection response:**
   `resp.text().await` reads the entire body. GraphQL introspection on a large schema can produce 100MB+ responses.
   **Severity: HIGH**

### 10.2 Regex Usage

Regex is imported as a workspace dependency, but **no regex is used anywhere in `crates/hidden/src/`**. This is a dead dependency.

**Fix:** Remove `regex` from `Cargo.toml`.

---

## 11. Tests Analysis

### 11.1 Unit Tests (Inside Source Modules)

Most modules have `#[cfg(test)]` blocks with basic structural tests:
- `directory_brute.rs`: None.
- `robots.rs`: Two tests for disallow parsing.
- `sitemap.rs`: 8 tests for URL extraction, whitespace, malformed XML, limits.
- `swagger.rs`: 7 tests for spec analysis (HTTP-only, unauth endpoints, API keys, YAML heuristics).
- `graphql.rs`: None.
- `git_env/rules.rs`: None.
- `backup_files.rs`: 10 tests for magic bytes, baselines, probe structure.
- `bypass403.rs`: None.
- `cookies.rs`: None.
- `cors.rs`: 3 tests for evidence helpers.
- `csp.rs`: 4 tests for directive parsing.
- `debug_endpoints.rs`: 4 tests for path validity.
- `error_disclosure.rs`: 3 tests for payload presence and pattern coverage.
- `api_versions.rs`: 6 tests for status/body classification.
- `favicon.rs`: None.
- `methods.rs`: None.
- `oauth.rs`: None.
- `rate_limit.rs`: None.
- `security_headers.rs`: None.
- `tech_probes.rs`: None.
- `waf.rs`: None.

**Observation:** Many critical modules have **zero unit tests** (`graphql`, `bypass403`, `oauth`, `methods`, `rate_limit`, `security_headers`, `favicon`, `tech_probes`, `waf`).

### 11.2 Integration Tests (`tests/`)

| File | Content | Status |
|------|---------|--------|
| `test_legendary_adversarial.rs` | CORS huge body (1MB) and invalid headers | **Compiles? References `gossan_hidden::cors` (public). OK.** |
| `test_legendary_gap.rs` | `dependency_confusion` gap test + CORS suffix gap test | **BROKEN — `dependency_confusion` module does not exist. Also `cors` suffix test fails by design (gap demonstration).** |
| `test_legendary_property.rs` | Proptest for CORS with random headers | **Compiles? References `gossan_hidden::cors` (public). OK.** |
| `test_legendary_unit.rs` | CORS reflection/null tests + `dependency_confusion` test | **BROKEN — `dependency_confusion` module does not exist.** |

### 11.3 Missing Adversarial Tests

The following adversarial scenarios are **not tested**:
1. **Soft-404 server returning 200 for all paths** → No test for `directory_brute.rs`, `git_env`, `backup_files`.
2. **Server returning 301 redirect loops** → `client_follow` would hang or recurse; `reqwest` handles this, but no test verifies the behavior.
3. **Server returning 500MB HTML response** → No OOM protection test.
4. **Gzip bomb sitemap** → No test.
5. **GraphQL endpoint that returns 200 for every query** → No catch-all test.
6. **Rate limiter with concurrent access from multiple tasks** → `HostRateLimiter` tests are sequential.

### 11.4 Broken Tests — `dependency_confusion`

Both `test_legendary_gap.rs` and `test_legendary_unit.rs` contain:
```rust
use gossan_hidden::dependency_confusion;
```

There is **no `mod dependency_confusion;` in `lib.rs`** and **no `dependency_confusion.rs` file**. These tests are compilation errors waiting to happen.

**Fix:** Either implement `dependency_confusion.rs` and declare it in `lib.rs`, or delete the broken tests.

---

## 12. TOML Extensibility (LAW 6)

### 12.1 What Is TOML-Driven

- `git_env/rules.rs`: Loads `*.toml` from `exe_dir/data/` or `./data/`. Falls back to compiled `CHECKS`.
- `backup_files.rs`: Claims TOML loading in comments (`backup_probes.toml` exists), but **the TOML file is never actually loaded at runtime**. The probe list is hardcoded as `const PROBES: &[BackupProbe]`.
- `debug_endpoints.rs`: Same issue — `debug_probes.toml` exists but is **never loaded**. `PROBES` is hardcoded.
- `directory_brute.rs`: Wordlist is `include_str!("directory_wordlist.txt")` with optional custom path. Not TOML-driven.

### 12.2 Gap

`backup_probes.toml` and `debug_probes.toml` are **orphan artifacts**. They are maintained in parallel with the compiled code but never used. This is a maintenance trap — they will drift out of sync and mislead users who edit them expecting runtime changes.

**Fix:** Either wire the TOML loaders into `backup_files.rs` and `debug_endpoints.rs`, or delete the TOML files and remove the misleading comments.

---

## 13. Detailed Critical Findings

### Finding C1: `lib.rs` Syntax Error — Crate Will Not Compile

**Location:** `crates/hidden/src/lib.rs:390`
```rust
for f in batch) { input.emit(f); }
```
**Issue:** `batch)` is a syntax error.
**Fix:** Change to `for f in batch { input.emit(f); }`.

### Finding C2: `directory_brute.rs` Is Dead Code

**Location:** `crates/hidden/src/directory_brute.rs`
**Issue:** The module is not declared in `lib.rs`. None of the directory brute-force logic, wordlist, or extension brute is ever executed.
**Fix:** Add `mod directory_brute;` to `lib.rs` and call `directory_brute::probe()` in the scanner loop.

### Finding C3: `bypass403.rs` Is Dead Code

**Location:** `crates/hidden/src/bypass403.rs`
**Issue:** Not declared in `lib.rs`. The entire 403 bypass suite (header spoofing, path mutations, method switching) is unreachable.
**Fix:** Add `mod bypass403;` to `lib.rs` and integrate the probe. Note: the `client_no_redir` comment in `lib.rs` already references `bypass403`, suggesting the author intended to wire it.

### Finding C4: `oauth.rs` Is Dead Code

**Location:** `crates/hidden/src/oauth.rs`
**Issue:** Not declared in `lib.rs`. OAuth/OIDC discovery, open redirect tests, and JWKS analysis are completely absent from scans.
**Fix:** Add `mod oauth;` to `lib.rs` and call `oauth::probe()` in the scanner loop.

### Finding C5: Unbounded Response Reads → OOM

**Locations:**
- `sitemap.rs` (`resp.bytes().await` + `GzDecoder` without size cap)
- `backup_files.rs` (`resp.bytes().await` on potentially multi-GB archives)
- `graphql.rs` (`resp.text().await` on potentially massive introspection responses)
- `favicon.rs` (`resp.bytes().await`)

**Fix:** Apply a `content-length` cap (e.g., reject responses > 10MB) or stream responses. For gzip, use a bounded decoder (e.g., `flate2` with a manual byte counter).

### Finding C6: Gzip Bomb in Sitemap Parser

**Location:** `sitemap.rs:140–234`
**Issue:** `decompress_gzip` reads all bytes into a `String` with no limit. A 10MB gzip file can expand to 10GB+.
**Fix:** Reject gzip payloads over a threshold (e.g., 5MB compressed, 50MB uncompressed) or use a streaming parser.

### Finding C7: Missing Global Soft-404 Baseline

**Issue:** Each subsystem implements its own partial catch-all detection. There is no shared, robust baseline (multiple probes + hash comparison) used across all modules.
**Fix:** Create a `BaselineFingerprint` struct shared by all probes. Compute it once per target using 3–5 random paths and a body hash. Reject any probe response that matches the baseline.

### Finding C8: Tests Reference Non-Existent `dependency_confusion` Module

**Locations:**
- `crates/hidden/tests/test_legendary_gap.rs:5`
- `crates/hidden/tests/test_legendary_unit.rs:7`
**Issue:** Compilation will fail because the module does not exist.
**Fix:** Implement `dependency_confusion.rs` (probe for `package.json`, `composer.json`, `requirements.txt`, `Gemfile`, `go.mod` with scope analysis) or delete the broken tests.

---

## 14. Detailed High Findings

### Finding H1: GraphQL Missing Introspection Bypasses

**Issue:** Modern GraphQL servers disable introspection. The scanner does not try alias tricks, fragment spreading, or `__type(name:...)` probing.
**Fix:** Add alias-wrapped introspection queries and fragment-based probes.

### Finding H2: Swagger Does Not Emit Every Endpoint

**Issue:** `analyze_spec` only reports aggregate statistics ("X endpoints with no auth"). It does not create a finding per endpoint, which limits downstream exploitation.
**Fix:** Emit one finding per unauthenticated endpoint (capped at a limit, e.g., 50).

### Finding H3: No Recursive Directory Brute

**Issue:** `directory_brute.rs` (already dead) is also non-recursive. If `/admin/` is discovered, it does not fuzz `/admin/FUZZ`.
**Fix:** Add recursive depth option to `directory_brute.rs` (or its replacement).

### Finding H4: Wordlist Too Small

**Issue:** ~480 entries vs. SecLists ~62k.
**Fix:** Default to loading an external wordlist. Keep the 480-entry list as an emergency fallback only.

### Finding H5: Per-Target Request Burst Is Too Large

**Issue:** ~18 probes spawn simultaneously for each target before the rate limiter kicks in.
**Fix:** Add a per-host semaphore (e.g., `tokio::sync::Semaphore(3)`) to cap concurrent in-flight requests.

### Finding H6: No Exponential Backoff on 429/503

**Issue:** `HostRateLimiter` uses a fixed delay regardless of server feedback.
**Fix:** Parse `Retry-After` headers and double the delay on 429/503.

### Finding H7: Missing `.well-known/` Discovery

**Issue:** The scanner probes `/.well-known/openapi.json` and `/.well-known/security.txt`, but misses:
- `/.well-known/apple-app-site-association`
- `/.well-known/assetlinks.json`
- `/.well-known/change-password`
- `/.well-known/jwks.json`
- `/.well-known/oauth-authorization-server` (only in `oauth.rs`, which is dead)
- `/.well-known/openid-configuration` (only in `oauth.rs`, which is dead)
- `/.well-known/robots.txt` (non-standard but seen in the wild)
- `/.well-known/traffic-advice`

**Fix:** Add a dedicated `.well-known/` enumeration probe with a comprehensive path list.

---

## 15. Actionable Fix List (Prioritized)

1. **Fix `lib.rs:390` syntax error.** (1 line)
2. **Wire dead modules into `lib.rs`:** `mod directory_brute;`, `mod bypass403;`, `mod oauth;`. Add their `probe()` calls to the scanner loop. (10 lines)
3. **Delete or implement `dependency_confusion.rs`.** If deleting, also remove broken test imports. (2 files)
4. **Add response size limits.** Cap `resp.bytes().await` to 10MB across all probes. Reject larger responses. (Touch ~6 files)
5. **Fix gzip bomb in `sitemap.rs`.** Add a 50MB uncompressed limit. (1 function)
6. **Merge or delete `backup_files.rs`.** It overlaps `git_env`. Prefer merging its magic-byte validation into `git_env/extract.rs`. (1 file deletion + small refactor)
7. **Extract unified `Soft404Baseline`.** Use it in `directory_brute`, `git_env`, `backup_files`, `swagger`, `graphql`, `debug_endpoints`. (New module)
8. **Add GraphQL introspection bypass probes.** Alias + fragment tricks. (1 function in `graphql.rs`)
9. **Add per-host concurrency semaphore.** Prevent 18-request bursts. (1 semaphore in `lib.rs`)
10. **Add `.well-known/` enumeration.** (New probe or expand `git_env/rules.rs`)
11. **Remove unused `regex` dependency.** (1 line in `Cargo.toml`)
12. **Sync TOML files or delete them.** Either load `backup_probes.toml`/`debug_probes.toml` at runtime, or delete them. (2 files)

---

## 16. Conclusion

`gossan-hidden` has **solid individual probe implementations** (especially `git_env`, `cors`, `csp`, `error_disclosure`), but it is **structurally compromised** by dead modules, a compilation-blocking syntax error, and missing industry-standard techniques. The most dangerous issues are:

1. **False negatives guaranteed** by dead `directory_brute`, `bypass403`, and `oauth` modules.
2. **OOM/DoS vulnerabilities** from unbounded response reads and gzip bomb handling.
3. **Soft-404 fragility** leading to both false positives and false negatives on modern SPAs.

Until the dead code is wired, the syntax error is fixed, and response limits are added, this scanner should **not** be used against production targets at scale.

---
*End of Audit*
