#![forbid(unsafe_code)]
//! Shared secret-verification orchestration.
//!
//! One home for the security-sensitive glue every secret-emitting
//! gossan scanner needs:
//!
//! * a **process-local raw-credential store** keyed by SHA-256 hash, so
//!   the raw secret is recoverable in-memory for verification but is
//!   NEVER serialised into a `Finding` (it would re-leak through the
//!   report);
//! * the `Finding` → `RawMatch` → `VerifiedFinding` → re-stamp pipeline
//!   that runs the real, data-driven `gossan-keyhog-lite`
//!   [`VerificationEngine`].
//!
//! `gossan-js` and `gossan-scm` both call this  -  identically  -  instead
//! of duplicating a path that handles live credentials. Live
//! verification is opt-in ([`VerifierEngine::with_enabled`]); the
//! default leaves every finding untouched (`Unknown` never elevates).

use gossan_keyhog_lite::{
    dedup_matches, DedupScope, MatchLocation, RawMatch, Severity as KhSeverity,
    VerificationEngine, VerificationResult, VerifyConfig,
};
use secfinding::{Finding, Severity};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};

use sha2::{Digest, Sha256};

/// In-memory, process-local `credential-hash -> raw credential` map.
/// Raw secrets live here ONLY long enough for verification; they are
/// removed on read (`take`) and never serialised.
static RAW_STORE: OnceLock<RwLock<HashMap<String, String>>> = OnceLock::new();

/// Stable SHA-256 hex id for a raw credential  -  the correlation key
/// shared by the `hash:` finding tag and the raw store.
#[must_use]
pub fn hash_secret(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    hex::encode(h.finalize())
}

/// Record a raw credential for later in-memory verification.
pub fn store_raw_secret(hash: &str, secret: &str) {
    let map = RAW_STORE.get_or_init(|| RwLock::new(HashMap::new()));
    if let Ok(mut w) = map.write() {
        w.insert(hash.to_string(), secret.to_string());
    }
}

/// Recover (and consume) a raw credential by hash.
#[must_use]
pub fn take_raw_secret(hash: &str) -> Option<String> {
    RAW_STORE
        .get()
        .and_then(|map| map.write().ok().and_then(|mut w| w.remove(hash)))
}

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
    /// Passive engine (live verification OFF).
    #[must_use]
    pub fn new() -> Self {
        Self::with_enabled(false)
    }

    /// Engine with live verification explicitly on/off. `enabled`
    /// comes from `Config::verify_secrets` (the `--verify-secrets`
    /// opt-in). When `false` every secret resolves to `Unknown` and no
    /// credential leaves the host.
    #[must_use]
    pub fn with_enabled(enabled: bool) -> Self {
        let detectors = gossan_keyhog_lite::embedded_detectors();
        let cfg = VerifyConfig {
            enabled,
            ..VerifyConfig::default()
        };
        let engine = VerificationEngine::new(&detectors, cfg)
            // VerificationEngine::new is infallible (Infallible error).
            .unwrap_or_else(|_| unreachable!("VerificationEngine::new is infallible"));
        Self {
            engine: Arc::new(engine),
        }
    }

    /// Walk `findings`, collect every entry tagged `secret`, recover
    /// the raw credential from the store, dedup, verify, and re-stamp
    /// each finding with the outcome. `Unknown` (disabled / no recipe)
    /// leaves the finding untouched  -  verification never *lowers*
    /// signal, only confirms it.
    pub async fn verify_all(&self, findings: &mut [Finding]) {
        if findings.is_empty() {
            return;
        }

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
            let Some(secret) = take_raw_secret(&hash) else {
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
                    source: "gossan".into(),
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

        let deduped = dedup_matches(raw_matches, &DedupScope::Credential);
        let verified = self.engine.verify_all(deduped).await;

        for vf in verified {
            let hash_tag = format!("hash:{}", vf.credential_hash);
            for slot in findings.iter_mut() {
                if !slot.tags().iter().any(|t| t.as_ref() == hash_tag.as_str()) {
                    continue;
                }
                match &vf.verification {
                    VerificationResult::Live => {
                        let new_detail = format!(
                            "{}\n\n[Verification]: This credential was successfully \
                             verified as ACTIVE against the provider.",
                            slot.detail()
                        );
                        if let Some(nf) = rebuild_with(slot, Some(Severity::Critical), |b| {
                            b.tag("verified-live").detail(new_detail)
                        }) {
                            *slot = nf;
                        }
                    }
                    VerificationResult::Dead => {
                        let new_detail = format!(
                            "{}\n\n[Verification]: This credential appears inactive \
                             or revoked.",
                            slot.detail()
                        );
                        if let Some(nf) =
                            rebuild_with(slot, None, |b| b.tag("verified-dead").detail(new_detail))
                        {
                            *slot = nf;
                        }
                    }
                    VerificationResult::Error(e) => {
                        let nd = format!("{}\n\n[Verification Error]: {e}", slot.detail());
                        if let Some(nf) =
                            rebuild_with(slot, None, |b| b.tag("verified-error").detail(nd))
                        {
                            *slot = nf;
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
        // Drop the internal correlation tags so they don't survive
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
        // secfinding::Severity is `#[non_exhaustive]`; treat any new
        // variant as high-impact until the mapping is updated.
        _ => KhSeverity::High,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secfinding::FindingKind;

    fn secret_finding(detector_id: &str, raw: &str) -> Finding {
        let hash = hash_secret(raw);
        store_raw_secret(&hash, raw);
        Finding::builder("scm", "https://t/r.git", Severity::High)
            .title("Hardcoded GitHub PAT committed")
            .detail("base detail")
            .kind(FindingKind::SecretLeak)
            .tag("secret")
            .tag("keyhog")
            .tag(format!("det:{detector_id}"))
            .tag(format!("hash:{hash}"))
            .build()
            .expect("finding")
    }

    /// PROVING: round-trip raw store by hash.
    #[test]
    fn raw_store_round_trips_then_consumes() {
        let h = hash_secret("ghp_abc");
        store_raw_secret(&h, "ghp_abc");
        assert_eq!(take_raw_secret(&h).as_deref(), Some("ghp_abc"));
        assert_eq!(take_raw_secret(&h), None, "consumed on read");
    }

    /// PRECISION / SAFETY: disabled (default) verification leaves the
    /// finding byte-identical  -  never elevates, no raw secret in the
    /// rebuilt finding, internal det:/hash: tags would only be stripped
    /// on an actual re-stamp (which does not happen here).
    #[tokio::test(flavor = "current_thread")]
    async fn disabled_engine_does_not_mutate_findings() {
        let mut f = vec![secret_finding("github-classic-pat", "ghp_x")];
        let before_sev = f[0].severity();
        VerifierEngine::with_enabled(false).verify_all(&mut f).await;
        assert_eq!(f[0].severity(), before_sev, "must not elevate when disabled");
        assert!(
            !f[0].tags().iter().any(|t| t.as_ref().starts_with("verified-")),
            "no verification tag when disabled"
        );
        // The raw secret must NEVER appear in the serialised finding.
        let blob = format!("{:?}", f[0]);
        assert!(!blob.contains("ghp_x"), "raw credential leaked into finding");
    }

    /// PROVING: a non-secret finding, or one missing the det:/hash:
    /// tags, is ignored (no panic, untouched).
    #[tokio::test(flavor = "current_thread")]
    async fn non_secret_and_untagged_findings_are_ignored() {
        let mut v = vec![
            Finding::builder("hidden", "t", Severity::Low)
                .title("missing header")
                .detail("d")
                .kind(FindingKind::Misconfiguration)
                .build()
                .expect("f"),
        ];
        VerifierEngine::with_enabled(true).verify_all(&mut v).await;
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].title(), "missing header");
    }
}
