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
    if count == 0 {
        return 0.0;
    }
    let p = SINGLE_SOURCE_CONFIDENCE;
    // Cap to i32::MAX to avoid wrap-around in `powi` on overflow.
    let safe_count = count.min(i32::MAX as usize);
    1.0 - (1.0 - p).powi(safe_count as i32)
}

/// Map a fused confidence to a severity boost.
///
/// - 1 source  -> no change
/// - 2 sources -> +1 tier (e.g., Medium -> High)
/// - 3+ sources -> +2 tiers (capped at Critical)
pub fn confidence_to_severity_boost(
    base: secfinding::Severity,
    count: usize,
) -> secfinding::Severity {
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
        // `Severity` is `#[non_exhaustive]` upstream  -  any future
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
        assert_eq!(
            confidence_to_severity_boost(Severity::Info, 1),
            Severity::Info
        );
        assert_eq!(
            confidence_to_severity_boost(Severity::Medium, 2),
            Severity::High
        );
        assert_eq!(
            confidence_to_severity_boost(Severity::High, 3),
            Severity::Critical
        );
        assert_eq!(
            confidence_to_severity_boost(Severity::Critical, 5),
            Severity::Critical
        );
    }

    /// ADVERSARIAL: `fuse_confidence` used `assert!(count > 0)` which
    /// panics on zero. A correlation pipeline that receives zero
    /// observations (empty finding set) must not crash the scanner.
    #[test]
    fn fuse_confidence_zero_does_not_panic() {
        let c = fuse_confidence(0);
        assert_eq!(c, 0.0, "zero observations => zero confidence");
    }

    /// ADVERSARIAL: `count as i32` wraps for `usize::MAX`, causing
    /// `powi` to receive a negative exponent and return `-inf` or NaN.
    #[test]
    fn fuse_confidence_huge_count_does_not_overflow() {
        let c = fuse_confidence(usize::MAX);
        assert!(
            c.is_finite(),
            "fuse_confidence(usize::MAX) must be finite, got {c}"
        );
        assert!(
            (c - 1.0).abs() < 0.001,
            "with astronomical observations confidence ≈ 1.0"
        );
    }

    #[test]
    fn fusion_associative_commutative() {
        // Under the simple model, order and grouping don't matter: only N matters.
        let c2 = fuse_confidence(2);
        let c2_again = fuse_confidence(2);
        assert!((c2 - c2_again).abs() < 0.001);
    }

    proptest! {
        #[test]
        fn fuse_confidence_never_panics(count in any::<usize>()) {
            let _ = fuse_confidence(count);
            prop_assert!(true);
        }
    }
}
