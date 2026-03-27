# Probe Audit Report

This report details the findings of a manual audit of the Probe codebase for publication readiness. The audit was performed without the ability to run `cargo clippy`, so the code quality section is based on manual review and may be incomplete.

## 1. Hardcoded Values

Numerous hardcoded values were found throughout the codebase. While some are acceptable as part of a probe's knowledge base, many should be made configurable or defined as constants.

**High-Priority:**

*   **Port Scan List:**
    *   **File:** `crates/portscan/src/lib.rs:25`
    *   **Issue:** The list of TCP ports to scan is hardcoded. This is a major limitation for a port scanner.
    *   **Recommendation:** Make the port list configurable. Options could include "top N ports", a custom list, or all 65535 ports. This should be driven from the central `Config`.

*   **Timeouts:**
    *   **File:** `crates/portscan/src/lib.rs:90` - `let timeout = Duration::from_secs(3);`
    *   **File:** `crates/dns/src/lib.rs:320` - `let timeout = std::time::Duration::from_secs(5);`
    *   **File:** `crates/dns/src/lib.rs:322` - `tokio::time::timeout(timeout, ...)`
    *   **File:** `crates/portscan/src/jarm.rs:321` - `tokio::time::timeout(Duration::from_millis(1500), ...)`
    *   **Issue:** Several modules use their own hardcoded timeouts instead of the globally configured timeout from `config.timeout()`.
    *   **Recommendation:** Replace all hardcoded request/probe timeouts with the value from the central `Config`.

*   **Public Suffix Parsing:**
    *   **File:** `crates/cloud/src/lib.rs:88`
    *   **Issue:** The `org_name_from_domain` function uses a weak heuristic to parse the TLD, which will fail for many common TLDs (e.g., `.co.uk`).
    *   **Recommendation:** Use a proper public suffix list library (e.g., `psl`) to accurately parse domain names.

**Medium-Priority:**

*   **Service URLs:**
    *   **Files:** `crates/subdomain/src/wayback.rs`, `hackertarget.rs`, `ct.rs`, `certspotter.rs`
    *   **Issue:** URLs for external services like Wayback Machine, HackerTarget, etc., are hardcoded.
    *   **Recommendation:** Define these URLs as constants at the top of their respective modules for clarity and easier maintenance.

*   **Cloud Provider URL Formats:**
    *   **Files:** `crates/cloud/src/s3.rs`, `gcs.rs`, `azure.rs`, `do_spaces.rs`
    *   **Issue:** URL format strings for cloud providers are hardcoded inside `format!` macros.
    *   **Recommendation:** Define these as constants.

*   **User Agent:**
    *   **File:** `crates/core/src/config.rs:44` - `user_agent: "gossan/0.1 (+https://santh.io)".into()`
    *   **Issue:** The user agent contains a hardcoded version number. The project name is `gossan`, which is inconsistent.
    *   **Recommendation:** The version should be dynamically inserted, possibly from `env!("CARGO_PKG_VERSION")`. The project name should be consistent.

*   **Tuning Parameters:**
    *   **File:** `crates/hidden/src/lib.rs:56`, `crates/hidden/src/lib.rs:67` - `pool_idle_timeout`
    *   **File:** `crates/js/src/lib.rs` - `buffer_unordered(20)` and `buffer_unordered(10)`
    *   **Issue:** Various hardcoded concurrency limits and pool timeouts.
    *   **Recommendation:** For clarity, define these as constants. For flexibility, consider making them part of the `Config`.

## 2. Code Quality

*   **Error Handling:**
    *   **Issue:** The codebase makes extensive use of `unwrap_or_default()` when calling probe modules (e.g., in `crates/hidden/src/lib.rs`). This pattern is dangerous as it silently ignores any `Err` returned by a probe, effectively hiding bugs.
    *   **Recommendation:** Replace `unwrap_or_default()` with proper error handling. At a minimum, errors from probes should be logged.

*   **Static Analysis:**
    *   **Issue:** The audit was performed without `cargo clippy`. It is highly likely that `clippy` would find many more issues related to style, performance, and correctness.
    *   **Recommendation:** Run `cargo clippy --all-targets --all-features -- -D warnings` and fix all reported issues.

## 3. Probe Quality

The overall quality of the probes is very high. The tool employs many advanced and effective techniques.

*   **Strengths:**
    *   **Comprehensive DNS scanner:** AXFR, SPF/DMARC/DKIM, and subdomain takeover checks are excellent.
    *   **Powerful JS scanner:** Source map analysis with secret scanning in original source code is a standout feature.
    *   **Extensive `hidden` scanner:** A huge number of high-quality checks for a wide range of web vulnerabilities.
    *   **Smart Cloud scanner:** The use of organization name permutations to find buckets is very effective.
    *   **Advanced Port scanner:** JARM fingerprinting and CVE correlation are powerful features.

*   **Weaknesses:**
    *   **Cloud domain parsing:** As mentioned, the TLD parsing is a significant weakness.
    *   **Port scan list:** The hardcoded port list is a major limitation.
    *   **Banner grabbing logic:** The banner identification logic in the port scanner is basic and could be improved with more sophisticated pattern matching.

## 4. API/Public Surface

*   **Documentation:**
    *   **Issue:** This is the most significant issue in this category. There are almost no doc comments (`///`) on public structs and functions, including the main `Scanner` implementations (`SubdomainScanner`, `PortScanner`, etc.) and the core data structures in `gossan-core`.
    *   **Recommendation:** Add comprehensive doc comments to every public item in all `lib.rs` files. Explain what each module, struct, and function does, its parameters, and what it returns.

*   **Exports:**
    *   The `gossan-core` crate does a good job of cleanly exporting its public API via `pub use`.

## 5. Cargo.toml

*   **Missing Metadata:**
    *   **Issue:** All `Cargo.toml` files are missing essential metadata for publishing to `crates.io`.
    *   **Recommendation:** Add a `[workspace.package]` section to the root `Cargo.toml` with `authors`, `description`, `license`, `repository`, `keywords`, and `categories`. Ensure all crates inherit this metadata or define their own.

*   **Inconsistent Naming:**
    *   **Issue:** The project is named `probe` in the filesystem, but the crates are named `gossan` and `gossan-*`.
    *   **Recommendation:** Choose a single, consistent name for the project and use it everywhere.

## 6. README/DOCS

*   **Missing README:**
    *   **Issue:** There is no `README.md` file in the project root. This is a critical omission for an open-source project.
    *   **Recommendation:** Create a `README.md` file that includes:
        *   A description of what the project does.
        *   Installation instructions.
        *   Usage examples (basic and advanced).
        *   A description of the different scanners and what they check for.
        *   Instructions on how to contribute.
        *   License information.

## 7. Architecture

*   **Strengths:**
    *   The scanner plugin architecture based on the `Scanner` trait is clean, modular, and extensible.
    *   The use of a central `Config` struct is good.
    *   The use of `async`/`await` and `futures` for concurrency is well-suited for an I/O-bound application like this.
    *   The separation of concerns between the different crates is logical.

*   **Weaknesses:**
    *   The error handling strategy of silencing errors from probes is a significant architectural flaw. A better strategy would be to collect and report probe-level errors.
    *   The configuration is driven entirely by command-line arguments. For a tool this complex, supporting a configuration file (e.g., `config.toml`) would be a valuable addition.
