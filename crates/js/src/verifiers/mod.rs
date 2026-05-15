//! Live verification stage for JavaScript-discovered secrets.
//!
//! In gossan we wire the `gossan-keyhog-lite` verification engine,
//! which is intentionally a stub (returns `Unknown` for every match).
//! When the upstream `keyhog-verifier` HTTP probe set lands in the
//! lite crate, the call shape here doesn't change.

use gossan_keyhog_lite::{
    dedup_matches, DedupScope, MatchLocation, RawMatch, Severity as KhSeverity, VerificationEngine,
    VerificationResult, VerifyConfig,
};
use secfinding::{Finding, Severity};
use std::collections::HashMap;
use std::sync::Arc;

/// Engine that runs verification over a batch of secret findings.
pub struct VerifierEngine {
    engine: Arc<VerificationEngine>,
}

impl Default for VerifierEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifierEngine {
    /// Build the verifier. Detector loading is best-effort — a missing
    /// directory or malformed file degrades the engine to "no-op" but
    /// never panics or blocks initialization.
    #[must_use]
    pub fn new() -> Self {
        let detector_dir = std::path::Path::new("../../../../software/keyhog/detectors");
        let detectors = if detector_dir.exists() {
            gossan_keyhog_lite::load_detectors(detector_dir).unwrap_or_default()
        } else {
            tracing::warn!(
                "KeyHog detectors directory not found at {:?}, live verification will be limited",
                detector_dir
            );
            Vec::new()
        };

        let engine = VerificationEngine::new(&detectors, VerifyConfig::default())
            // VerificationEngine::new is infallible (returns Infallible),
            // so this `Ok` arm is always taken; the match is here only
            // to mirror upstream's `Result`-returning signature.
            .unwrap_or_else(|_| unreachable!("VerificationEngine::new is infallible"));

        Self {
            engine: Arc::new(engine),
        }
    }

    /// Walk `findings`, collect every entry tagged `secret`, recover
    /// the raw credential via [`crate::secrets::take_raw_secret`], run
    /// dedup, send the batch through the engine, and stamp each
    /// finding with the verification result.
    pub async fn verify_all(&self, findings: &mut [Finding]) {
        if findings.is_empty() {
            return;
        }

        // 1. Collect raw matches.
        let mut raw_matches: Vec<RawMatch> = Vec::new();
        for f in findings.iter() {
            if !f.tags().iter().any(|t| t.as_ref() == "secret") {
                continue;
            }
            let detector_id = f
                .tags()
                .iter()
                .find(|t| t.starts_with("det:"))
                .map(|t| t[4..].to_string());
            let hash = f
                .tags()
                .iter()
                .find(|t| t.starts_with("hash:"))
                .map(|t| t[5..].to_string());
            let (Some(detector_id), Some(hash)) = (detector_id, hash) else {
                continue;
            };
            let Some(secret) = crate::secrets::take_raw_secret(&hash) else {
                continue;
            };
            if raw_matches
                .iter()
                .any(|m| m.detector_id == detector_id && m.credential == secret)
            {
                continue;
            }
            raw_matches.push(RawMatch {
                detector_id: detector_id.clone(),
                detector_name: f.title().to_string(),
                service: detector_id,
                severity: map_severity(f.severity()),
                credential: secret,
                credential_hash: hash,
                companions: HashMap::new(),
                location: MatchLocation {
                    source: "js".into(),
                    file_path: Some(f.target().to_string()),
                    line: Some(0),
                    offset: 0,
                    commit: None,
                    author: None,
                    date: None,
                },
                entropy: None,
                confidence: Some(1.0),
            });
        }

        if raw_matches.is_empty() {
            return;
        }

        // 2. Dedup.
        let deduped = dedup_matches(raw_matches, &DedupScope::Credential);

        // 3. Verify.
        let verified = self.engine.verify_all(deduped).await;

        // 4. Re-stamp matching findings via the rebuild-from-builder
        // path. `Finding` fields are not directly mutable through the
        // public API, so we drop and rebuild the affected entries.
        // This intentionally tolerates the stub `Unknown` case by
        // leaving the original finding untouched — the slice never
        // elevates severity on "we don't know".
        for vf in verified {
            let hash_tag = format!("hash:{}", vf.credential_hash);
            for slot in findings.iter_mut() {
                let is_match = slot.tags().iter().any(|t| t.as_ref() == hash_tag.as_str());
                if !is_match {
                    continue;
                }
                match &vf.verification {
                    VerificationResult::Live => {
                        let new_detail = format!(
                            "{}\n\n[Verification]: This credential was successfully verified as active.",
                            slot.detail()
                        );
                        if let Some(new_f) = rebuild_with(slot, Some(Severity::Critical), |b| {
                            b.tag("verified-live").detail(new_detail)
                        }) {
                            *slot = new_f;
                        }
                    }
                    VerificationResult::Dead => {
                        let new_detail = format!(
                            "{}\n\n[Verification]: This credential appears to be inactive or revoked.",
                            slot.detail()
                        );
                        if let Some(new_f) =
                            rebuild_with(slot, None, |b| b.tag("verified-dead").detail(new_detail))
                        {
                            *slot = new_f;
                        }
                    }
                    VerificationResult::Error(e) => {
                        let new_detail =
                            format!("{}\n\n[Verification Error]: {}", slot.detail(), e);
                        if let Some(new_f) =
                            rebuild_with(slot, None, |b| b.tag("verified-error").detail(new_detail))
                        {
                            *slot = new_f;
                        }
                    }
                    VerificationResult::Unknown => {}
                }
            }
        }
    }
}

fn rebuild_with<F>(
    orig: &Finding,
    severity_override: Option<Severity>,
    decorate: F,
) -> Option<Finding>
where
    F: FnOnce(secfinding::FindingBuilder) -> secfinding::FindingBuilder,
{
    let severity = severity_override.unwrap_or_else(|| orig.severity());
    let mut b = Finding::builder(
        orig.scanner().to_string(),
        orig.target().to_string(),
        severity,
    )
    .title(orig.title().to_string())
    .detail(orig.detail().to_string())
    .kind(orig.kind());
    for ev in orig.evidence() {
        b = b.evidence(ev.clone());
    }
    for tag in orig.tags() {
        // Strip the internal correlation tags so they don't survive
        // into the post-verification finding.
        let s = tag.as_ref();
        if s.starts_with("raw:") || s.starts_with("det:") || s.starts_with("hash:") {
            continue;
        }
        b = b.tag(s.to_string());
    }
    for cve in orig.cve_ids() {
        b = b.cve(cve.to_string());
    }
    if let Some(hint) = orig.exploit_hint() {
        b = b.exploit_hint(hint.to_string());
    }
    decorate(b).build().ok()
}

fn map_severity(s: Severity) -> KhSeverity {
    match s {
        Severity::Info => KhSeverity::Info,
        Severity::Low => KhSeverity::Low,
        Severity::Medium => KhSeverity::Medium,
        Severity::High => KhSeverity::High,
        Severity::Critical => KhSeverity::Critical,
        // secfinding::Severity is `#[non_exhaustive]`; future variants
        // must not silently change the verification scope. Treat
        // anything new as a high-impact secret until the mapping is
        // explicitly updated.
        _ => KhSeverity::High,
    }
}
