//! KeyHog-powered secret detection in JavaScript source code.
//!
//! Integrates the full `keyhog-scanner` engine to identify hardcoded
//! secrets using hundreds of high-confidence patterns, SIMD pre-filtering,
//! and ML-based scoring.

use gossan_core::Target;
use gossan_keyhog_lite::{Chunk, ChunkMetadata, CompiledScanner};
use secfinding::{Evidence, Finding, Severity};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::RwLock;

static KEYHOG_SCANNER: OnceLock<CompiledScanner> = OnceLock::new();

// In-memory, process-local store mapping credential-hash -> raw credential.
// This avoids placing raw secrets into Finding tags/serialized reports while
// still allowing the verification engine to access raw values securely in-memory.
static RAW_STORE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

pub(crate) fn store_raw_secret(hash: &str, secret: &str) {
    let map = RAW_STORE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(mut w) = map.write() {
        w.insert(hash.to_string(), secret.to_string());
    }
}

/// Peek a raw credential without consuming it. Prefer this when multiple
/// findings may share one hash and all need verification in one batch.
pub fn get_raw_secret(hash: &str) -> Option<String> {
    RAW_STORE
        .get()
        .and_then(|map| map.read().ok().and_then(|r| r.get(hash).cloned()))
}

/// Recover (and consume) a raw credential by hash.
pub fn take_raw_secret(hash: &str) -> Option<String> {
    RAW_STORE
        .get()
        .and_then(|map| map.write().ok().and_then(|mut w| w.remove(hash)))
}

/// Drop a raw credential after a verification batch finishes.
pub fn clear_raw_secret(hash: &str) {
    let _ = take_raw_secret(hash);
}

/// Initialize the KeyHog scanner by loading and compiling all detectors.
///
/// Sources detectors from `gossan_keyhog_lite::embedded_detectors()` —
/// the curated corpus baked into the published `gossan-keyhog-lite`
/// crate. This guarantees a working scanner under `cargo install`
/// without depending on any sibling-checkout filesystem path.
///
/// Fail closed: empty corpus or compile failure panics (same contract as
/// `gossan_scm::git_scanner::get_scanner`). Never return a path that makes
/// `scan()` look like a successful empty result.
fn get_scanner() -> &'static CompiledScanner {
    KEYHOG_SCANNER.get_or_init(|| {
        let detectors = gossan_keyhog_lite::embedded_detectors();
        assert!(
            !detectors.is_empty(),
            "embedded KeyHog detector corpus is empty; refusing to disable JS secret detection"
        );
        CompiledScanner::compile(detectors).unwrap_or_else(|e| {
            panic!("failed to compile embedded KeyHog detector corpus: {e}")
        })
    })
}

use sha2::{Digest, Sha256};

/// Scan JS source for hardcoded secrets using the KeyHog engine.
pub fn scan(js_url: &str, body: &str, target: &Target) -> Vec<Finding> {
    let scanner = get_scanner();

    let mut findings = Vec::new();

    // Create a KeyHog chunk for the JS body
    let chunk = Chunk {
        data: body.to_string(),
        metadata: ChunkMetadata {
            source_type: "js".into(),
            path: Some(js_url.to_string()),
            ..Default::default()
        },
    };

    // Perform the scan
    let matches = scanner.scan(&chunk);

    for m in matches {
        // Map KeyHog severity to secfinding severity
        let severity = map_severity(m.severity);

        let mut hasher = Sha256::new();
        hasher.update(m.credential.as_bytes());
        let hash = hex::encode(hasher.finalize());

        // Store the raw credential in a process-local secure store for later verification.
        // Do NOT serialize or log this value.
        store_raw_secret(&hash, &m.credential);

        let builder = Finding::builder("js", target.domain().unwrap_or("?"), severity)
            .title(format!("Hardcoded {} identified", m.detector_name))
            .detail(format!(
                "A potential {} was found in {}. Verified credentials represent a high risk of account takeover.",
                m.detector_name, js_url
            ))
            .evidence(Evidence::JsSnippet {
                url: std::sync::Arc::from(js_url),
                line: m.location.line.unwrap_or(0),
                snippet: std::sync::Arc::from(
                    gossan_keyhog_lite::redact(&m.credential).as_str(),
                ),
            })
            .tag("secret")
            .tag("keyhog")
            .tag(format!("det:{}", m.detector_id))
            .tag(format!("hash:{}", hash))
            // raw credential intentionally NOT stored in tags, would leak secrets
            // into reports, logs, and downstream systems. Use hash tag for correlation.
            .tag(m.service.to_string())
            .kind(secfinding::FindingKind::SecretLeak);

        if let Some(f) = builder.build_or_log() {
            findings.push(f);
        }
    }

    findings
}

fn map_severity(s: gossan_keyhog_lite::Severity) -> Severity {
    match s {
        gossan_keyhog_lite::Severity::Info => Severity::Info,
        gossan_keyhog_lite::Severity::Low => Severity::Low,
        gossan_keyhog_lite::Severity::Medium => Severity::Medium,
        gossan_keyhog_lite::Severity::High => Severity::High,
        gossan_keyhog_lite::Severity::Critical => Severity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{HostTarget, Target};

    fn dummy_target() -> Target {
        Target::Host(HostTarget {
            ip: "127.0.0.1".parse().unwrap(),
            domain: Some("example.com".into()),
        })
    }

    #[test]
    fn get_scanner_compiles_embedded_corpus() {
        // Regression: `get_scanner` used to return None / empty-success on
        // empty corpus or compile failure. It must return a compiled
        // non-empty scanner (fail closed), matching scm get_scanner.
        let scanner = get_scanner();
        assert!(
            !scanner.is_empty(),
            "embedded KeyHog scanner must expose at least one detector"
        );
    }

    #[test]
    fn scan_empty_body_returns_empty() {
        let target = dummy_target();
        let findings = scan("https://example.com/app.js", "", &target);
        assert!(findings.is_empty());
    }

    #[test]
    fn scan_very_long_body_does_not_panic() {
        let target = dummy_target();
        let body = "x".repeat(1_000_000);
        let findings = scan("https://example.com/app.js", &body, &target);
        // Should return without panicking; exact count depends on KeyHog corpus.
        let _ = findings.len();
    }

    #[test]
    fn scan_multiline_body_does_not_panic() {
        let target = dummy_target();
        let body = "\n".repeat(100_000);
        let findings = scan("https://example.com/app.js", &body, &target);
        assert!(findings.is_empty());
    }

    #[test]
    fn get_raw_secret_does_not_consume() {
        store_raw_secret("peek-hash", "super-secret");
        assert_eq!(get_raw_secret("peek-hash").as_deref(), Some("super-secret"));
        assert_eq!(get_raw_secret("peek-hash").as_deref(), Some("super-secret"));
        clear_raw_secret("peek-hash");
        assert_eq!(get_raw_secret("peek-hash"), None);
    }

    // ── proptest property tests ───────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn scan_never_panics(body in "\\PC{0,4096}") {
            let target = dummy_target();
            let _ = scan("https://example.com/app.js", &body, &target);
        }

        #[test]
        fn scan_never_panics_on_arbitrary_url(js_url in "\\PC{0,256}", body in "\\PC{0,4096}") {
            let target = dummy_target();
            let _ = scan(&js_url, &body, &target);
        }

        #[test]
        fn store_and_take_raw_secret_roundtrips(secret in "\\PC{1,128}") {
            let hash = format!("hash_{}", secret.len());
            store_raw_secret(&hash, &secret);
            let taken = take_raw_secret(&hash);
            prop_assert_eq!(taken, Some(secret));
        }
    }
}
