# Deep Audit: `correlation`, `graph`, `intel`

**Auditor:** Kimi  
**Date:** 2026-04-16  
**Scope:** `crates/correlation/`, `crates/graph/`, `crates/intel/`  
**Mandate:** Read-only source review. Write-only this file. These three crates are the semantic core that distinguishes gossan from "five tools glued together."

---

## Executive Summary

| Crate | Grade | Verdict |
|-------|-------|---------|
| `correlation` | **D+** | Three fully-implemented rules are dead code (never registered). No deduplication, no confidence scoring, no streaming, no relationship graph. |
| `graph` | **C-** | A SQLite persistence wrapper with temporal diffing. Zero query API, zero graph algorithms, no schema versioning, brittle heuristic ID mapping that silently drops edges. |
| `intel` | **F** | **Zero online sources implemented.** Tests are completely broken (reference a non-existent `ScanInput` shape). Async blocking bug. Port truncation bug. No caching, no rate limiting, no API key handling. |

**Bottom line:** The attack-surface graph and unified correlation engine are, at this moment, largely aspirational. The `intel` crate is an offline SQLite passthrough with a misleading description. If these crates ship as-is, gossan will indeed be "five tools glued together" — with glue that misses seams.

---

## Part A — `crates/correlation/`

### A.1 What it actually does
`CorrelationEngine` runs a fixed list of hard-coded `CorrelationRule` implementations over a completed `Vec<Finding>` + `Vec<Target>`. Each rule returns `Vec<Finding>` (new "chain" findings). The engine concatenates them and returns the flat list.

### A.2 Dedup Logic — FINDING: Nonexistent

**There is no centralized deduplication.**

```rust
// src/lib.rs:73-87
pub fn run(&self, findings: &[Finding], targets: &[Target]) -> Vec<Finding> {
    let mut chains = Vec::new();
    for rule in &self.rules {
        let new = rule.check(findings, targets);
        chains.extend(new);   // <- no dedup whatsoever
    }
    chains
}
```

Per-rule dedup is inconsistent:
- `TlsWeaknessRule` deduplicates **issue titles** per host with a `HashSet<String>`.
- `ShadowInfrastructureRule` deduplicates discovered domains via `sort()` + `dedup()` after normalization.
- **All other rules emit one finding per matching intersection with no dedup.**

**Case folding / trailing dot:**
- Only `ShadowInfrastructureRule` calls `.to_lowercase()` and strips `*.` prefix.
- **No rule strips trailing dots.** `example.com.` and `example.com` are different hosts everywhere else.
- `src/utils.rs` defines `normalize_host()` that strips schemes, ports, and paths — but **it is dead code** (never imported by any rule). As a result:
  - `http://admin.example.com` and `https://admin.example.com:443` are treated as **different hosts** by `AdminExposedRule`, `ApiAuthRule`, and `TlsWeaknessRule`.
  - The gap test `gap_admin_exposed_should_correlate_across_http_and_https` documents this as a known bug.

**Wildcard handling:**
- Only `ShadowInfrastructureRule` strips `*.` prefix. No other rule understands wildcard DNS. If `*.example.com` and `www.example.com` both appear, they are treated as unrelated strings.

### A.3 Cross-Source Confidence — FINDING: None

**Confidence is not scored.** Every rule hard-codes severity:

| Rule | Severity |
|------|----------|
| AdminExposedRule | `Critical` |
| ApiAuthRule | `Critical` |
| CorsSecretChainRule | `Critical` |
| DebugRceRule | `Critical` |
| ShadowInfrastructureRule | `High` |
| SourceCodeSecretsRule | `Critical` |
| SsrfInternalRule | `Critical` |
| TlsWeaknessRule | `High` |
| WildcardTakeoverRule | `Critical` |

A subdomain from 5 independent sources and a subdomain from 1 source produce the exact same chain finding with the exact same severity. There is no cardinality bonus, no source-provenance tracking, and no uncertainty quantification.

### A.4 Finding Relationships — FINDING: Flat List, Not a Graph

The correlation engine emits a **flat `Vec<Finding>`**. There is no machine-readable graph structure like:

```
subdomain -> RESOLVES_TO -> IP -> HOSTS -> Service -> RUNS -> Tech -> EXPOSES -> Endpoint
```

The closest thing to structured linkage is an ad-hoc `Evidence::Raw(format!("Admin finding id: {}", evidence_id))` in `AdminExposedRule`. This is a human-readable string, not a traversable edge.

**Consequence:** Downstream consumers (Karyx, Soleno, or any graph analytics) cannot walk from a chain finding back to its constituents programmatically. They must parse English prose in `detail` strings.

### A.5 Stream vs Batch — FINDING: Strictly Batch

The `CorrelationRule` trait signature makes streaming impossible:

```rust
pub trait CorrelationRule: Send + Sync {
    fn check(&self, findings: &[Finding], targets: &[Target]) -> Vec<Finding>;
}
```

There is no `Stream`, no `Sink`, no callback, and no incremental partial-results API. The engine must wait for **all** scanner stages to finish before it emits anything.

### A.6 Critical Correctness Bugs

#### 🔴 CRITICAL: Three implemented rules are never registered

`src/rules/mod.rs` exports 9 rule structs. `src/lib.rs` re-exports only 6. `CorrelationEngine::new()` registers only 6.

**Dead code:**
- `WildcardTakeoverRule`
- `DebugRceRule`
- `CorsSecretChainRule`

These rules compile, have dedicated source files, have doc comments — but they will **never execute** in production because they are omitted from the engine constructor.

```rust
// src/lib.rs:58-68
pub fn new() -> Self {
    Self {
        rules: vec![
            Box::new(TlsWeaknessRule),
            Box::new(AdminExposedRule),
            Box::new(ApiAuthRule),
            Box::new(SsrfInternalRule),
            Box::new(SourceCodeSecretsRule),
            Box::new(ShadowInfrastructureRule),
            // MISSING: WildcardTakeoverRule, DebugRceRule, CorsSecretChainRule
        ],
    }
}
```

#### 🔴 CRITICAL: `AdminExposedRule` evidence construction is broken

The rule captures only the **first** `hidden` finding ID:

```rust
let evidence_id = findings
    .iter()
    .filter(|f| f.scanner == "hidden" && Some(f.target.as_str()) == Some(host.as_str()))
    .map(|f| f.id.to_string())
    .next()
    .unwrap_or_default();
```

The adversarial test `test_evidence_chain_construction` expects **both** finding IDs to be present:

```rust
match &ev[0] {
    secfinding::Evidence::Raw(s) => {
        assert!(s.contains(&f1.id.to_string()));
        assert!(s.contains(&f2.id.to_string())); // f2 uses scanner="techstack", filtered out above
    }
}
```

This test will fail because the filter requires `scanner == "hidden"`, but `f2` is from the `techstack` scanner.

#### 🔴 HIGH: Host-agnostic target selection in chain findings

Several rules pick the target of the **first** matching finding for the chain, even when correlated findings occur on different hosts:

- `SsrfInternalRule` — `target = internal_services.first().unwrap().target`
- `SourceCodeSecretsRule` — `target = source_exposures.first().unwrap().target`
- `DebugRceRule` — `target = critical_debug.first().unwrap().target`
- `CorsSecretChainRule` — `target = secret_findings.first().unwrap().target`

There is no logic ensuring the chain components belong to the same host or domain.

#### 🔴 HIGH: `ShadowInfrastructureRule` is IPv6-blind

```rust
if !f.target.chars().next().is_some_and(|c| c.is_ascii_digit()) { continue; }
```

IPv6 addresses start with `[` or hex characters, so IPv6 TLS targets are silently skipped.

### A.7 Additional Findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | No trailing-dot normalization; `example.com.` != `example.com` | Medium |
| 2 | `SourceCodeSecretsRule` calls `.take(3)` before dedup, so duplicate titles can hide distinct exposure types | Medium |
| 3 | Repeated `.to_lowercase()` inside hot filter closures is O(n·m·len) wasteful | Low |
| 4 | `README.md` documents `engine.correlate(&all_findings)` but the actual method is `engine.run(&findings, &targets)` | Low |
| 5 | `AdminExposedRule` uses redundant `Option` wrapping: `Some(f.target.as_str()) == Some(host.as_str())` | Low |

### A.8 Actionable Fixes

1. **Register the missing rules** in `CorrelationEngine::new()` and `lib.rs` re-exports.
2. **Use `normalize_host`** (or a better canonicalizer) in every rule that matches by target string. Add trailing-dot stripping and scheme/port normalization.
3. **Implement source-count confidence scoring:** a `HashMap<NormalizedTarget, Vec<Source>>` that feeds into chain severity or a dedicated `confidence` field.
4. **Change the API to emit structured relationships**, not just flat findings. Add `Evidence::Relationship { from, to, rel_type }` or emit graph edges directly.
5. **Add a streaming correlation API** (e.g., `check_incremental(&mut state, finding) -> Vec<Finding>`) so the pipeline does not have to buffer everything.
6. **Fix `AdminExposedRule` evidence** to collect *all* relevant finding IDs, not just the first `hidden` one.

---

## Part B — `crates/graph/`

### B.1 What it actually does
`GraphStore` is a SQLite-backed persistence layer. It stores `Target` and `Finding` records as JSON blobs, maintains a `relationships` table for inferred edges, and can compute temporal diffs (`ScanDiff`) between the current database state and a new batch.

**Important:** The entire crate is a single 419-line file (`src/lib.rs`). There are no sub-modules.

### B.2 Schema — FINDING: Not Versioned, Incomplete

**Node types** (stored in `targets` table, mapped from `gossan_core::Target`):

| Variant | `target_id` prefix | `target_kind` |
|---------|-------------------|---------------|
| `Domain` | `domain:` | `domain` |
| `Host` | `host:` | `host` |
| `Service` | `service:{ip}:` | `service` |
| `Web` | `web:` | `web` |
| `Network` | `network:` | `network` |
| `Repository` | `repo:` | `repository` |
| `InternalPackage` | `pkg:` | `package` |

**Edge types** (stored in `relationships` table):

| `rel_type` | Semantics |
|------------|-----------|
| `HAS_FINDING` | Auto-inserted between target and every linked finding |
| `RESOLVES_TO` | `Domain -> Host` (when `Host.domain` is `Some`) |
| `HAS_SERVICE` | `Host -> Service` and `Domain -> Service` |
| `HAS_WEB_ASSET` | `Service -> Web` |

**Missing edge types from the spec:**
- `RUNS` (Service -> Tech)
- `EXPOSES` (Service -> Endpoint)
- `LEAKS` (Endpoint -> Secret)
- `MISCONFIGURED` (any -> Finding)

**Schema versioning:**
**There is none.** `init_schema()` runs a handful of primitive `ALTER TABLE ... ADD COLUMN` migrations and **silently swallows all errors**:

```rust
let _ = self.conn.execute("ALTER TABLE targets ADD COLUMN first_seen ...", []);
let _ = self.conn.execute("ALTER TABLE targets ADD COLUMN last_seen ...", []);
// ...
```

There is no `schema_version` table, no migration registry, and no rollback. A genuine failure (locked table, disk full) leaves the database in an unknown state.

### B.3 Storage — FINDING: SQLite Only, No Export Formats

- **Backend:** SQLite via `rusqlite` (bundled). WAL mode, `synchronous = NORMAL`, `foreign_keys = ON`, `busy_timeout = 5000`.
- **Serialization:** `serde_json` for internal `data` columns only.
- **Export formats:** None. No JSON, Parquet, GraphML, CSV, or protobuf export.
- **Streaming:** No. `persist_scan` takes `&[Target]` and `&[Finding]` slices, so the caller must materialize the entire batch in memory.

### B.4 Query Layer — FINDING: Does Not Exist

The public API exposes **only** write/diff operations:

```rust
pub struct GraphStore { conn: Connection }

impl GraphStore {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self>
    pub fn persist_scan(&mut self, targets: &[Target], findings: &[Finding]) -> Result<()>
    pub fn compute_diff(&self, targets: &[Target], findings: &[Finding], removed_threshold: Duration) -> Result<ScanDiff>
    pub fn target_id(target: &Target) -> String
    pub fn conn(&self) -> &Connection   // raw SQL escape hatch
}
```

There are **zero** read/query helpers. You cannot ask:
- *"What are the neighbors of target X?"*
- *"What are all HTTP services on subdomains of target X?"*
- *"Find all findings with severity High."*

The only way to answer these is to drop down to raw SQL via `conn()`.

### B.5 Size / Scalability — FINDING: All-or-Nothing Diff

- A test persists 10,000 domains and asserts it finishes in < 30 seconds. The threshold is loose, but it shows the crate does not fall over at 10K rows.
- However, `compute_diff` eagerly clones **every** added/changed/removed target and finding into owned `Vec`s. If 10K assets are removed, all 10K are deserialized and cloned into RAM at once.
- **No streaming or lazy iterator support** exists for reads or diffs.

### B.6 Pyrograph / GPU Graph — FINDING: No Integration, No Graph Algorithms

**There is no `pyrograph` crate in this workspace.** Zero references in any `Cargo.toml` or `.rs` file.

Consequently, `gossan-graph`:
- Does **not** use GPU acceleration.
- Does **not** implement BFS, DFS, connected-components, reachability, shortest-path, or cycle detection.

It is purely a SQLite persistence wrapper with manual edge insertion. Tests that mention "cycle detection" simply insert rows via raw SQL and count them.

### B.7 Critical Correctness Bugs

#### 🔴 HIGH: `target_id_from_finding` heuristic silently drops edges

```rust
fn target_id_from_finding(finding: &Finding) -> String {
    let t = finding.target();
    if t.starts_with("http") {
        format!("web:{}", t)
    } else if t.contains(':') && t.chars().filter(|&c| c == ':').count() == 1 {
        format!("service:{}", t)
    } else if t.parse::<std::net::IpAddr>().is_ok() {
        format!("host:{}", t)
    } else {
        format!("domain:{}", t)
    }
}
```

**Problems:**
1. **IPv6** addresses contain multiple colons, so they fall through the `IpAddr` parse path (because the `contains(':') && count == 1` check fails first) and become `domain:` IDs — **wrong**.
2. A domain like `example.com:443` has exactly one colon, so it becomes `service:example.com:443`, but the actual service ID scheme is `service:{ip}:{port}`. This ID mismatch means the `HAS_FINDING` edge insert references a non-existent `target_id`. Because the insert uses `INSERT OR IGNORE`, the edge is **silently dropped**.
3. URLs starting with `ftp://`, `sftp://`, etc. are mishandled.

#### 🔴 HIGH: Test asserts impossible FK behavior

`test_edge_creation_missing_target_finding` (`tests/test_legendary_more.rs:155-163`) calls:

```rust
store.persist_scan(&[], &[finding]).unwrap();
```

and then asserts `COUNT(*) FROM targets == 1`.

The library code **does not** auto-insert missing targets when persisting findings. With `PRAGMA foreign_keys = ON`, inserting a finding whose `target_id` does not exist in `targets` should trigger a **foreign-key constraint violation**. If this test passes in CI, it implies FK enforcement is not actually active — a serious data-integrity gap.

#### 🔴 MEDIUM: `compute_diff` crashes on large `Duration`

```rust
let threshold_secs = removed_threshold.as_secs();
// ...
"SELECT data FROM targets WHERE last_seen < datetime('now', '-' || ?1 || ' seconds')"
```

For `Duration::MAX` (or any value exceeding SQLite's date parser limits), this throws a `Sqlite` error. The gap test explicitly documents this as a known failure.

### B.8 Actionable Fixes

1. **Add schema versioning.** Create a `schema_version` table and a numbered migration registry. Stop swallowing migration errors.
2. **Fix `target_id_from_finding`.** Parse URLs properly with `url::Url`, handle IPv6 brackets, and validate service IDs against the `service:{ip}:{port}` scheme. Fail loudly instead of silently dropping edges.
3. **Implement a query layer.** Expose methods like `neighbors_of(&target_id)`, `findings_for(&target_id)`, `targets_by_kind(&str)`, and a typed path traversal API.
4. **Add export formats.** At minimum: JSONL and GraphML. Parquet for analytics.
5. **Add streaming diff.** Return iterators or a `ScanDiff` that lazily yields pages instead of cloning everything into RAM.
6. **Decide on pyrograph.** Either wire this crate to a GPU graph backend for large-scale reachability / SCC, or rename the crate to avoid implying it is a graph compute engine.

---

## Part C — `crates/intel/`

### C.1 What it actually does
`IntelScanner` is an **offline-only** scanner. It queries a local SQLite database of pre-ingested bulk data and emits generic `Finding`s. It makes **zero network requests**.

### C.2 Threat-Intel Sources — FINDING: Massive Gaps

**Implemented online sources:** **None.**

| Source | Status |
|--------|--------|
| GreyNoise | ❌ Not implemented |
| Censys host context v2 (API) | ❌ Not implemented |
| Shodan host lookup (API) | ❌ Not implemented |
| AbuseIPDB | ❌ Not implemented |
| VirusTotal | ❌ Not implemented |
| URLScan | ❌ Not implemented |
| ASN lookup (MaxMind GeoIP2 / ipinfo) | ❌ Not implemented |
| Passive DNS (API) | ❌ Not implemented |

**Documented intent vs. reality:**
- `lib.rs` doc comment: *"Queries a local SQLite database of pre-ingested Shodan/Censys/BinaryEdge data"*
- `ingest.rs` doc comment: *"Bulk dataset ingester — imports Project Sonar, Censys, and crt.sh dumps"*

**Reality:** The only ingestion path is `Ingester::ingest_jsonl`, which deserializes lines into a fixed-schema `IntelRecord`. There are **no adapters** for Shodan, Censys v2, Project Sonar, or crt.sh JSON schemas. Real dumps from those providers will fail on every line due to field-name mismatches and missing `#[serde(default)]` annotations.

### C.3 Caching — FINDING: None

- Every target triggers a direct SQLite `SELECT`.
- No in-memory cache, no TTL, no keyed eviction by IP/domain.
- The SQLite DB is persistent storage, not a cache layer.

### C.4 API Key Handling — FINDING: None

- `gossan-intel` does not read environment variables or `Config::api_keys`.
- `Config::api_keys` exists in `gossan-core` (`HashMap<String, String>`) but is **never accessed** by this crate.
- Because there are no online sources, keys are moot — but the crate also does not gracefully skip or configure anything.

### C.5 Rate Limiting — FINDING: None

- No `HostRateLimiter`, no `governor`, no token bucket.
- No concurrency control beyond a `std::sync::Mutex` on the SQLite connection.

### C.6 Enrichment Contract — FINDING: Ad-Hoc String Soup

**No `IntelEnrichment` struct exists anywhere in the workspace.**

`query.rs` manually builds a generic `Finding` with string formatting:

```rust
fn process_record(input: &gossan_core::ScanInput, r: IntelRecord) -> anyhow::Result<()> {
    let title = format!("Passive Intel: {}/{} open", r.port, r.protocol);
    let mut detail = format!("IP: {}\nPort: {}\nProtocol: {}", r.ip, r.port, r.protocol);
    if let Some(ref b) = r.banner {
        detail.push_str(&format!("\nBanner: {}", b));
    }

    let mut f = Finding::builder("intel", &r.ip, Severity::Info)
        .title(title)
        .detail(detail)
        .kind(secfinding::FindingKind::InfoDisclosure)
        .tag("passive")
        .tag("intel")
        .build()
        .map_err(|e| anyhow::anyhow!("Fix: valid intel finding fields required: {}", e))?;
    // ...
}
```

- `FindingKind` is hard-coded to `InfoDisclosure` for every record.
- `last_seen` and `tech_stack` are squashed into tags or detail strings.
- There is no typed enrichment attachment, no structured JSON payload, and no per-source provenance.

### C.7 Critical Correctness Bugs

#### 🔴 CRITICAL: Tests are completely broken and will not compile

`tests/adversarial.rs` and `tests/intel_tests.rs` construct a **fictional** `ScanInput`:

```rust
fn get_test_scan_input(targets: Vec<Target>) -> ScanInput {
    ScanInput {
        seed: "test".to_string(),
        targets,                 // ❌ does not exist in real ScanInput
        live_tx: None,           // ❌ real ScanInput requires UnboundedSender, not Option
        target_tx: None,         // ❌ same
        resolver: Arc::new(...),
        cancel: CancellationToken::new(), // ❌ does not exist in real ScanInput
    }
}
```

The real `ScanInput` (from `crates/core/src/scanner.rs`) is:

```rust
pub struct ScanInput {
    pub seed: String,
    pub target_rx: tokio::sync::Mutex<UnboundedReceiver<Target>>,
    pub live_tx: UnboundedSender<Finding>,
    pub target_tx: UnboundedSender<Target>,
    pub resolver: Arc<TokioAsyncResolver>,
}
```

And `Scanner::run` returns `anyhow::Result<()>` — **not** a result with `.findings`. The test suite references `.findings` on the return value and expects `live_tx: Option<...>`.

**Conclusion:** The test suite cannot compile against the real `gossan-core`.

#### 🔴 CRITICAL: Blocking async runtime

`IntelScanner::run` is `async`, yet it performs synchronous SQLite I/O while holding a `std::sync::Mutex` inside the async context:

```rust
// crates/intel/src/query.rs:12-18
if let Some(ip_addr) = ip {
    let ip_str = ip_addr.to_string();
    let records = db.query_by_ip(&ip_str)?;  // blocks the Tokio worker
    for r in records {
        process_record(input, r)?;
    }
}
```

`query_by_ip` locks `std::sync::Mutex<Connection>` and executes SQL. Under load, this will block the async executor and stall the entire pipeline.

**Fix:** Use `tokio::task::spawn_blocking` or switch to `tokio-rusqlite`.

#### 🔴 HIGH: Port truncation bug

```rust
// crates/intel/src/db.rs:96
port: row.get::<_, i32>(2)? as u16,
```

Rust's `as` truncates modulo `2^16`. A malformed record with port `-1` or `70000` will silently wrap to `65535` or `4464`.

#### 🔴 HIGH: Unused dependency with external path

`Cargo.toml` declares:

```toml
hashkit = { version = "0.1", path = "../../../../libs/performance/indexing/hashkit" }
```

It is **never imported or used** in any source file. This path also reaches outside the workspace.

#### 🔴 HIGH: `process_record` aborts the scan on builder errors

```rust
.map_err(|e| anyhow::anyhow!("Fix: valid intel finding fields required: {}", e))?;
```

If `Finding::builder(...).build()` fails (e.g., title too long), the error bubbles up and **aborts the entire target scan** instead of skipping the malformed finding.

### C.8 Actionable Fixes

1. **Either implement the online sources** (GreyNoise, Censys v2, Shodan, AbuseIPDB, VT, URLScan, MaxMind) **or rewrite the crate description** to stop claiming support for them.
2. **Add source-specific JSONL adapters** for Censys, Project Sonar, Shodan, and crt.sh dumps, with `#[serde(default)]` and field remapping.
3. **Fix the test suite.** Rewrite `adversarial.rs` and `intel_tests.rs` to use the real `ScanInput` shape (`target_rx` channel, non-optional `live_tx`/`target_tx`).
4. **Eliminate async blocking.** Move all SQLite I/O into `spawn_blocking` or adopt `tokio-rusqlite`.
5. **Fix port truncation.** Validate `i32` range before converting to `u16`:
   ```rust
   let port_i32: i32 = row.get(2)?;
   let port: u16 = port_i32.try_into().context("invalid port in intel db")?;
   ```
6. **Add caching.** An LRU keyed by `(source, ip_or_host)` with a configurable TTL (e.g., 24h) would prevent repeated lookups for the same asset.
7. **Add rate limiting.** Per-service token buckets are mandatory for any online enrichment.
8. **Add API key handling.** Read from `Config::api_keys` or environment, and gracefully skip services when keys are absent.
9. **Define a typed `IntelEnrichment` struct** and attach it to findings as structured data (e.g., a JSON metadata field or a dedicated evidence variant).
10. **Remove or fix the `hashkit` dependency.**

---

## Part D — Cross-Cutting Architectural Gaps

### D.1 No unified relationship model
The three crates do not share a relationship representation:
- `correlation` emits flat findings with string evidence.
- `graph` stores edges in SQLite but has no query API.
- `intel` has no concept of relationships at all.

**Recommendation:** Define a single `gossan_core::Relationship` enum and ensure all three crates can produce/consume it.

### D.2 No streaming anywhere
- `correlation` is batch-only.
- `graph` persists full batches.
- `intel` reads targets from a channel but does not stream findings incrementally.

For a 10K-subdomain target, every stage materializes full vectors in memory.

### D.3 `gossan-core` does not define graph semantics
The core crate defines `Target` and `Finding`, but there is no `EdgeType` or `Relationship` type that downstream crates can rely on. This forces each crate to invent its own ad-hoc linkage.

---

## Appendix: File Inventory

### `crates/correlation/`
```
Cargo.toml
README.md
src/lib.rs
src/utils.rs
src/rules/mod.rs
src/rules/admin_exposed.rs
src/rules/api_auth.rs
src/rules/cors_secret_chain.rs
src/rules/debug_rce.rs
src/rules/shadow_infra.rs
src/rules/source_secrets.rs
src/rules/ssrf_internal.rs
src/rules/tls_weakness.rs
src/rules/wildcard_takeover.rs
tests/adversarial/mod.rs
tests/gap/mod.rs
tests/property/mod.rs
tests/unit/mod.rs
```

### `crates/graph/`
```
Cargo.toml
src/lib.rs
tests/ (adversarial, concurrent, integration, unit, plus legendary test files)
```

### `crates/intel/`
```
Cargo.toml
src/lib.rs
src/db.rs
src/ingest.rs
src/query.rs
tests/adversarial.rs
tests/adversarial.rs.diff
tests/adversarial.rs.patch
tests/intel_tests.rs
tests/test_single.rs
```

---

*End of audit.*
