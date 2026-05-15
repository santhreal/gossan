//! KeyHog-powered secret detection in JavaScript source code.
//!
//! Integrates the legendary `keyhog-scanner` engine to identify hardcoded
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

pub fn take_raw_secret(hash: &str) -> Option<String> {
    RAW_STORE
        .get()
        .and_then(|map| map.write().ok().and_then(|mut w| w.remove(hash)))
}

/// Initialize the KeyHog scanner by loading and compiling all detectors.
///
/// Sources detectors from `gossan_keyhog_lite::embedded_detectors()` —
/// the curated corpus baked into the published `gossan-keyhog-lite`
/// crate. This guarantees a working scanner under `cargo install`
/// without depending on any sibling-checkout filesystem path.
fn get_scanner() -> Option<&'static CompiledScanner> {
    KEYHOG_SCANNER.get_or_init(|| {
        let empty_fallback = || -> CompiledScanner {
            // Compile with zero detectors — a no-op scanner that matches nothing.
            // This compile call with an empty vec genuinely cannot fail,
            // but we log defensively if it somehow does.
            match CompiledScanner::compile(Vec::new()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("failed to compile empty keyhog scanner: {e}");
                    CompiledScanner::compile(Vec::new()).unwrap_or_else(|e2| {
                        tracing::error!(
                            "keyhog scanner cannot compile even with zero detectors: {e2}"
                        );
                        std::process::exit(1);
                    })
                }
            }
        };

        let detectors = gossan_keyhog_lite::embedded_detectors();
        if detectors.is_empty() {
            tracing::warn!(
                "embedded KeyHog detector corpus is empty; secret detection will be skipped"
            );
            return empty_fallback();
        }

        match CompiledScanner::compile(detectors) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to compile KeyHog scanner: {e}");
                empty_fallback()
            }
        }
    });
    KEYHOG_SCANNER.get()
}

use sha2::{Digest, Sha256};

/// Scan JS source for hardcoded secrets using the KeyHog engine.
pub fn scan(js_url: &str, body: &str, target: &Target) -> Vec<Finding> {
    let Some(scanner) = get_scanner() else {
        return Vec::new();
    };

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
            // raw credential intentionally NOT stored in tags — would leak secrets
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
