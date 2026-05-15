//! Pure-CPU vendor slice of the keyhog secret-detection engine.
//!
//! See the crate-level README for the rationale and surface boundary.
//! This module ties together the four sub-modules (detector / scanner /
//! dedup / verifier) into a single public API matching upstream
//! `keyhog-core` + `keyhog-scanner` + `keyhog-verifier`.

#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]

mod dedup;
mod detector;
mod scanner;
mod verifier;

pub use dedup::{dedup_matches, DedupScope};
pub use detector::{
    embedded_detectors, load_detectors, Companion, Detector, DetectorError, DetectorMeta, Pattern,
};
pub use scanner::{Chunk, ChunkMetadata, CompiledScanner, Match, MatchLocation, ScannerError};
pub use verifier::{
    RawMatch, VerificationEngine, VerificationResult, VerifiedFinding, VerifyConfig,
};

use serde::{Deserialize, Serialize};

/// Severity grades. Matches the upstream `keyhog_core::Severity` shape
/// so `From` / `Into` between gossan-js's `secfinding::Severity` and
/// this enum is a 5-arm match.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Discovery-only signal; not a confirmed secret.
    Info,
    /// Low-impact / low-confidence match.
    Low,
    /// Medium-impact / medium-confidence match.
    #[default]
    Medium,
    /// High-impact match (provider with auth APIs).
    High,
    /// Critical: cloud root keys, PII tokens, payments keys.
    Critical,
}

/// Redact a credential for display in logs / findings / reports.
///
/// Keeps the first 4 and last 4 chars when the input is ≥ 12 chars,
/// otherwise asterisks the whole thing. Avoids placing raw secrets in
/// downstream sinks while preserving enough fingerprint that two
/// findings on the same secret correlate visually.
#[must_use]
pub fn redact(credential: &str) -> String {
    let n = credential.chars().count();
    if n >= 12 {
        let chars: Vec<char> = credential.chars().collect();
        let prefix: String = chars.iter().take(4).collect();
        let suffix: String = chars.iter().skip(n - 4).collect();
        format!("{prefix}…{suffix}")
    } else if n == 0 {
        String::new()
    } else {
        "*".repeat(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_keeps_first4_last4_for_long_secrets() {
        assert_eq!(redact("AKIAIOSFODNN7EXAMPLE"), "AKIA…MPLE");
    }

    #[test]
    fn redact_asterisks_short_secrets() {
        assert_eq!(redact("abcdef"), "******");
    }

    #[test]
    fn redact_handles_empty() {
        assert_eq!(redact(""), "");
    }

    #[test]
    fn redact_handles_unicode_grapheme_boundaries() {
        // Multi-byte chars must not panic the slice.
        let s = "ñoñoñoñoñoño";
        let r = redact(s);
        assert!(!r.is_empty());
    }

    #[test]
    fn severity_ordering_matches_expected_risk_progression() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn severity_default_is_medium() {
        assert_eq!(Severity::default(), Severity::Medium);
    }
}
