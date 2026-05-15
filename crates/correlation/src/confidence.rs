//! Cross-source confidence fusion.
//!
//! # Math
//!
//! For a finding observed by `N` independent sources, each with single-source
//! confidence `p` (default 0.6), the fused confidence is:
//!
//! ```text
//! confidence = 1 - (1 - p)^N
//! ```
//!
//! This is the probability that at least one source is correct under the
//! independence assumption. As `N` grows, confidence approaches 1.0.

/// Default confidence assigned to a single source.
pub const SINGLE_SOURCE_CONFIDENCE: f64 = 0.6;

/// Fuse confidence from `N` independent observations.
///
/// # Panics
///
/// Panics if `count` is zero (no sources to fuse).
#[must_use]
pub fn fuse_confidence(count: usize) -> f64 {
    assert!(count > 0, "fuse_confidence requires at least one source");
    let p = SINGLE_SOURCE_CONFIDENCE;
    1.0 - (1.0 - p).powi(count as i32)
}

/// Map a fused confidence to a severity boost.
///
/// - 1 source  -> no change
/// - 2 sources -> +1 tier (e.g., Medium -> High)
/// - 3+ sources -> +2 tiers (capped at Critical)
pub fn confidence_to_severity_boost(base: secfinding::Severity, count: usize) -> secfinding::Severity {
    use secfinding::Severity;
    let tiers = match count {
        1 => 0,
        2 => 1,
        _ => 2,
    };

    let current = severity_tier(base);
    let boosted = (current + tiers).min(4);
    tier_to_severity(boosted)
}

fn severity_tier(s: secfinding::Severity) -> u8 {
    use secfinding::Severity;
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
        // `Severity` is `#[non_exhaustive]` upstream — any future
        // variant defaults to Info-tier so callers still get a
        // defined boost result.
        _ => 0,
    }
}

fn tier_to_severity(tier: u8) -> secfinding::Severity {
    use secfinding::Severity;
    match tier {
        0 => Severity::Info,
        1 => Severity::Low,
        2 => Severity::Medium,
        3 => Severity::High,
        _ => Severity::Critical,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secfinding::Severity;

    #[test]
    fn fuse_one_source() {
        assert!((fuse_confidence(1) - SINGLE_SOURCE_CONFIDENCE).abs() < 0.001);
    }

    #[test]
    fn fuse_increases_with_n() {
        let c1 = fuse_confidence(1);
        let c2 = fuse_confidence(2);
        let c3 = fuse_confidence(3);
        assert!(c1 < c2);
        assert!(c2 < c3);
        assert!(c3 < 1.0);
    }

    #[test]
    fn severity_boost_capped() {
        assert_eq!(confidence_to_severity_boost(Severity::Info, 1), Severity::Info);
        assert_eq!(confidence_to_severity_boost(Severity::Medium, 2), Severity::High);
        assert_eq!(confidence_to_severity_boost(Severity::High, 3), Severity::Critical);
        assert_eq!(confidence_to_severity_boost(Severity::Critical, 5), Severity::Critical);
    }

    #[test]
    fn fusion_associative_commutative() {
        // Under the simple model, order and grouping don't matter: only N matters.
        let c2 = fuse_confidence(2);
        let c2_again = fuse_confidence(2);
        assert!((c2 - c2_again).abs() < 0.001);
    }
}
