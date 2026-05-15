//! Verification engine — honest stub.
//!
//! Live verification (HTTP probes against AWS / Stripe / GitHub /
//! etc.) lives in upstream `keyhog-verifier` and pulls in `tokio` +
//! provider SDKs that we keep out of gossan's build graph. Instead of
//! claiming to verify, every match comes back as
//! [`VerificationResult::Unknown`] — gossan-js + gossan-scm callers
//! treat "unknown" as "do not elevate severity", which is the
//! conservative default.

use crate::scanner::MatchLocation;
use crate::Detector;
use crate::Severity;
use std::collections::HashMap;

/// A match prepared for the verification stage. Mirrors upstream's
/// `RawMatch` shape so gossan-js's verifiers module can construct
/// these unchanged.
#[derive(Debug, Clone)]
pub struct RawMatch {
    /// Detector id.
    pub detector_id: String,
    /// Detector human name.
    pub detector_name: String,
    /// Service label.
    pub service: String,
    /// Severity carried from the detector.
    pub severity: Severity,
    /// Raw credential — keep out of serialized outputs.
    pub credential: String,
    /// SHA-256 hex hash of the credential. Stable ID for correlation.
    pub credential_hash: String,
    /// Companion values pulled out by the detector (e.g. AWS secret
    /// key co-located with the access key).
    pub companions: HashMap<String, String>,
    /// Where the match lives.
    pub location: MatchLocation,
    /// Shannon entropy of the credential, if the scanner computed it.
    pub entropy: Option<f32>,
    /// Confidence score in `[0.0, 1.0]`. `None` = no prior; treat as
    /// neutral.
    pub confidence: Option<f32>,
}

/// Outcome of a single verification attempt.
#[derive(Debug, Clone)]
pub enum VerificationResult {
    /// The credential was confirmed active against the provider.
    Live,
    /// The credential was rejected by the provider (revoked / wrong
    /// account / format mismatch).
    Dead,
    /// The provider returned an error response that we couldn't
    /// classify (5xx / network / rate-limit).
    Error(String),
    /// No live check was performed. This is the only result this slice
    /// returns; downstream callers treat it as "do not elevate".
    Unknown,
}

/// A verified finding — the input `RawMatch` paired with whatever
/// outcome we landed on. `metadata` is provider-specific extra context
/// (account id, key prefix, region) — empty in this slice.
#[derive(Debug, Clone)]
pub struct VerifiedFinding {
    /// Original credential hash (so callers can correlate against
    /// emitted `Finding`s).
    pub credential_hash: String,
    /// What happened.
    pub verification: VerificationResult,
    /// Provider-supplied metadata when verification ran. Empty in
    /// keyhog-lite because we don't run live checks.
    pub metadata: HashMap<String, String>,
}

/// Knobs for the verification engine.
#[derive(Debug, Clone, Default)]
pub struct VerifyConfig {
    /// Per-provider request timeout (seconds). Ignored in this slice;
    /// kept on the struct so upstream config files still deserialize.
    pub timeout_secs: u64,
    /// Maximum concurrent provider probes. Ignored here.
    pub max_concurrent: usize,
}

/// Verification engine handle. Construction is infallible — the
/// underlying state is just the detector list passed in. We carry it
/// around so future feature-gated live verification can read per-
/// detector verify URLs without changing call sites.
pub struct VerificationEngine {
    #[allow(dead_code)]
    detectors_known: usize,
}

impl VerificationEngine {
    /// Build a verification engine. Never fails; mirrors upstream's
    /// `Result` return so call sites can stay identical when this
    /// slice is swapped for the upstream crate.
    ///
    /// # Errors
    ///
    /// Returns `Err` only if upstream's `Result` shape grows a
    /// failure mode — at the moment, none is reachable in this slice.
    pub fn new(
        detectors: &[Detector],
        _config: VerifyConfig,
    ) -> Result<Self, std::convert::Infallible> {
        Ok(Self {
            detectors_known: detectors.len(),
        })
    }

    /// Verify a batch. This slice returns one `VerifiedFinding` per
    /// input with `VerificationResult::Unknown`. Async signature is
    /// kept to match upstream so call sites don't need a `cfg`-swap.
    #[allow(clippy::unused_async)] // shape-compat with upstream — must stay async
    pub async fn verify_all(&self, matches: Vec<RawMatch>) -> Vec<VerifiedFinding> {
        matches
            .into_iter()
            .map(|m| VerifiedFinding {
                credential_hash: m.credential_hash,
                verification: VerificationResult::Unknown,
                metadata: HashMap::new(),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw(hash: &str) -> RawMatch {
        RawMatch {
            detector_id: "x".into(),
            detector_name: "X".into(),
            service: "x".into(),
            severity: Severity::Info,
            credential: "raw".into(),
            credential_hash: hash.into(),
            companions: HashMap::new(),
            location: MatchLocation::default(),
            entropy: None,
            confidence: None,
        }
    }

    #[test]
    fn verifier_new_is_infallible() {
        let _e = VerificationEngine::new(&[], VerifyConfig::default()).expect("infallible");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_all_returns_unknown_for_every_input() {
        let e = VerificationEngine::new(&[], VerifyConfig::default()).expect("ok");
        let out = e.verify_all(vec![raw("hashA"), raw("hashB")]).await;
        assert_eq!(out.len(), 2);
        for v in out {
            assert!(matches!(v.verification, VerificationResult::Unknown));
            assert!(v.metadata.is_empty());
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn verify_all_empty_input_returns_empty() {
        let e = VerificationEngine::new(&[], VerifyConfig::default()).expect("ok");
        let out = e.verify_all(Vec::new()).await;
        assert!(out.is_empty());
    }
}
