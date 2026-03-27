# Gossan Subcrate Standalone Compilation Check

**Date:** 2026-03-26  
**Command:** `cargo check --manifest-path Cargo.toml` for each crate  
**Goal:** Verify each subcrate can compile standalone (publishable to crates.io)

---

## Summary

| Crate | Compiles | gossan-core Dependency | Publishable | Notes |
|-------|----------|------------------------|-------------|-------|
| **gossan-core** | ✅ Yes | N/A (root) | ⚠️ Partial | No internal deps, but has path dep on `secfinding` |
| gossan-checkpoint | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-cloud | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-correlation | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-crawl | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-dns | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-headless | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-hidden | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-js | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-origin | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-portscan | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-subdomain | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-synscan | ✅ Yes | `path = "../core"` | ❌ No | Depends on gossan-core |
| gossan-techstack | ✅ Yes | `path = "../core"` + `truestack` | ❌ No | **Double blocker**: gossan-core + local truestack path |

---

## Detailed Results

### ✅ FULLY STANDALONE

#### `gossan-core`
- **Status:** ✅ Compiles standalone
- **Dependencies:** No internal gossan deps
- **Blockers for crates.io:** Depends on `secfinding` via workspace path
- **Action needed:** Publish `secfinding` to crates.io, then update dependency

```toml
[dependencies]
# Current (blocks publishing)
secfinding = { workspace = true }  # Points to local path

# Required for crates.io
secfinding = "0.2"
```

---

### ❌ DEPENDS ON gossan-core

All the following crates compile successfully but depend on `gossan-core` via local path:

#### Scanner Crates (10 crates)
1. **gossan-checkpoint** - Scan checkpoint and resume (SQLite persistence)
2. **gossan-cloud** - Cloud asset discovery (S3, GCS, Azure Blob, DO Spaces)
3. **gossan-correlation** - Cross-module finding correlation (attack chain detection)
4. **gossan-crawl** - Authenticated web crawler
5. **gossan-dns** - DNS security scanner (SPF, DMARC, DKIM, CAA, zone transfer)
6. **gossan-headless** - Headless Chromium browser engine
7. **gossan-hidden** - Hidden endpoint scanner (CORS, SSRF, JWT, Swagger)
8. **gossan-js** - JavaScript analysis (secrets, prototype pollution, WASM)
9. **gossan-origin** - Origin IP discovery (CDN/WAF bypass)
10. **gossan-portscan** - TCP port scanner with TLS inspection

#### Recon Crates (2 crates)
11. **gossan-subdomain** - Subdomain discovery (CT logs, Wayback, permutations)
12. **gossan-synscan** - Raw socket SYN port scanner

#### Analysis Crates (1 crate)
13. **gossan-techstack** - Tech stack fingerprinting

---

### 🔴 SPECIAL CASE: gossan-techstack

**Most problematic crate for standalone publishing:**

```toml
[dependencies]
gossan-core = { path = "../core" }      # Internal dependency
truestack   = { path = "../../../truestack" }  # External local dependency!
```

This crate has **two path dependencies**:
1. `gossan-core` (same workspace - fixable)
2. `truestack` (external project - major blocker)

**To make publishable:**
1. Publish `gossan-core` to crates.io
2. Publish `truestack` to crates.io (separate project!)
3. Update both to versioned dependencies

---

## Dependency Chain Analysis

```
                    ┌─────────────────────────────────────┐
                    │           secfinding                │
                    │      (external workspace dep)       │
                    └──────────────┬──────────────────────┘
                                   │
                    ┌──────────────▼──────────────────────┐
                    │           gossan-core               │
                    │         (0 internal deps)           │
                    └──────┬──────────────────┬───────────┘
                           │                  │
        ┌──────────────────┼──────────────────┼──────────────────┐
        │                  │                  │                  │
   ┌────▼────┐    ┌───────▼───────┐  ┌───────▼───────┐  ┌──────▼──────┐
   │ scanners│    │    recon      │  │   network     │  │   analysis  │
   │  (5)    │    │    (2)        │  │    (2)        │  │    (1)      │
   └─────────┘    └───────────────┘  └───────────────┘  └─────────────┘
   checkpoint     subdomain          portscan            techstack ⚠️
   cloud          synscan            origin                ↑
   correlation                       hidden                │
   crawl                             js                    │
   dns                               headless              │
                                                         │
                                            ┌─────────────┘
                                            │
                                    ┌───────▼────────┐
                                    │   truestack    │
                                    │ (external!!)   │
                                    └────────────────┘
```

---

## Path to Full Decoupling

### Phase 1: Publish External Dependencies
1. **secfinding** - Publish to crates.io first
2. **truestack** - Separate project, needs its own publishing

### Phase 2: Update gossan-core
```toml
[dependencies]
# BEFORE
secfinding = { workspace = true }

# AFTER
secfinding = "0.2"  # Version from crates.io
```

### Phase 3: Publish gossan-core
```bash
cd crates/core
cargo publish --dry-run  # Verify
cargo publish
```

### Phase 4: Update All Dependent Crates
For each of the 13 dependent crates, update:
```toml
[dependencies]
# BEFORE
gossan-core = { path = "../core" }

# AFTER
gossan-core = "0.2"  # Version from crates.io
```

### Phase 5: Special Handling for techstack
```toml
[dependencies]
# BEFORE
gossan-core = { path = "../core" }
truestack   = { path = "../../../truestack" }

# AFTER
gossan-core = "0.2"
truestack   = "0.1"  # Must be published separately
```

---

## Current Compilation Warnings

### gossan-correlation
- Unused imports: `DiscoverySource`, `DomainTarget`
- Unused import: `Severity`

### gossan-portscan
- Dead code: `CveRulesFile` struct
- Unused function: `load_community_rules`
- Unused function: `all_rules`

These are non-blocking but should be cleaned up before publishing.

---

## Conclusion

**Current State:** All 14 subcrates compile successfully with `cargo check`.

**Standalone Publishable:** 0 crates (technically)
- `gossan-core` is closest but blocked by `secfinding` path dependency
- All other crates depend on `gossan-core` via path
- `gossan-techstack` has an additional external dependency

**Recommended Priority:**
1. ✅ Fix compilation warnings in `correlation` and `portscan`
2. 🔴 Publish `secfinding` to crates.io
3. 🔴 Publish `truestack` to crates.io (separate repo)
4. 🟡 Update `gossan-core` to use versioned `secfinding`
5. 🟡 Publish `gossan-core` to crates.io
6. 🟢 Update all 13 dependent crates to use versioned `gossan-core`
7. 🟢 Publish all crates to crates.io

---

*Generated by standalone compilation check*
