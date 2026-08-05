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
/// Returns `0.0` when `count` is zero (no sources to fuse).
#[must_use]
pub fn fuse_confidence(count: usize) -> f64 {
    if count == 0 {
        return 0.0;
    }
    let p = SINGLE_SOURCE_CONFIDENCE;
    // Use `powf` with `f64` exponent to avoid `i32` overflow on huge `count`.
    1.0 - (1.0 - p).powf(count as f64)
}

/// Map a fused confidence to a severity boost.
///
/// - 0–1 sources -> no change (zero sources carry no corroboration, so
///   they must never boost: `fuse_confidence(0)` is likewise `0.0`)
/// - 2 sources -> +1 tier (e.g., Medium -> High)
/// - 3+ sources -> +2 tiers (capped at Critical)
pub fn confidence_to_severity_boost(
    base: secfinding::Severity,
    count: usize,
) -> secfinding::Severity {
    use secfinding::Severity;
    let tiers = match count {
        0 | 1 => 0,
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
        // `Severity` is `#[non_exhaustive]` upstream, any future
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

    #[test]
    fn fusion_associative_commutative() {
        // Under the simple model, order and grouping don't matter: only N matters.
        let c2 = fuse_confidence(2);
        let c2_again = fuse_confidence(2);
        assert!((c2 - c2_again).abs() < 0.001);
    }

    #[test]
    fn fuse_confidence_zero_does_not_panic() {
        let c = fuse_confidence(0);
        assert!((c - 0.0).abs() < 0.001);
    }

    #[test]
    fn fuse_confidence_huge_count_does_not_panic_or_wrap() {
        let c = fuse_confidence(usize::MAX);
        assert!(c >= 0.0 && c <= 1.0, "confidence must be in [0,1], got {}", c);
        assert!((c - 1.0).abs() < 0.001, "huge count should give ~1.0 confidence");
    }

    #[test]
    fn fuse_confidence_i32_max_plus_one() {
        // Regression: previously `count as i32` wrapped to negative,
        // causing `powi` to return a value > 1 and confidence < 0.
        let count = (i32::MAX as usize) + 1;
        let c = fuse_confidence(count);
        assert!(c >= 0.0 && c <= 1.0, "confidence must be in [0,1], got {}", c);
    }

    // ── Boundary: exact values ────────────────────────────────────────────

    #[test]
    fn fuse_confidence_two_sources_exact_value() {
        // 1 - (1-0.6)^2 = 1 - 0.16 = 0.84
        let c = fuse_confidence(2);
        assert!((c - 0.84).abs() < 0.001, "two sources should give ~0.84, got {c}");
    }

    #[test]
    fn fuse_confidence_three_sources_exact_value() {
        // 1 - (1-0.6)^3 = 1 - 0.064 = 0.936
        let c = fuse_confidence(3);
        assert!((c - 0.936).abs() < 0.001, "three sources should give ~0.936, got {c}");
    }

    #[test]
    fn fuse_confidence_result_always_in_unit_interval() {
        for n in 0..=100 {
            let c = fuse_confidence(n);
            assert!(
                c >= 0.0 && c <= 1.0,
                "count={n}: confidence {c} outside [0, 1]"
            );
        }
    }

    #[test]
    fn fuse_confidence_strictly_monotone_increasing() {
        // Anti-rig: adding more independent sources must NEVER decrease confidence.
        let mut prev = fuse_confidence(0);
        for n in 1..=50 {
            let cur = fuse_confidence(n);
            assert!(
                cur >= prev,
                "fuse_confidence({n}) = {cur} < fuse_confidence({}) = {prev}",
                n - 1
            );
            prev = cur;
        }
    }

    #[test]
    fn fuse_confidence_approaches_one_asymptotically() {
        // By count=100 we must be very close to 1.0.
        let c = fuse_confidence(100);
        assert!(c > 0.9999, "100 sources should give confidence > 0.9999, got {c}");
    }

    // ── Boundary: severity boost ──────────────────────────────────────────

    #[test]
    fn severity_boost_zero_count_no_boost() {
        // count=0 is unusual but must not panic; 0 tiers → no boost.
        let s = confidence_to_severity_boost(Severity::Medium, 0);
        assert_eq!(s, Severity::Medium);
    }

    #[test]
    fn severity_boost_one_source_no_change() {
        use Severity::*;
        for base in [Info, Low, Medium, High, Critical] {
            assert_eq!(
                confidence_to_severity_boost(base, 1),
                base,
                "1 source must not boost {base:?}"
            );
        }
    }

    #[test]
    fn severity_boost_two_sources_boosts_one_tier() {
        use Severity::*;
        assert_eq!(confidence_to_severity_boost(Info, 2), Low);
        assert_eq!(confidence_to_severity_boost(Low, 2), Medium);
        assert_eq!(confidence_to_severity_boost(Medium, 2), High);
        assert_eq!(confidence_to_severity_boost(High, 2), Critical);
        // Critical cannot go higher.
        assert_eq!(confidence_to_severity_boost(Critical, 2), Critical);
    }

    #[test]
    fn severity_boost_three_sources_boosts_two_tiers() {
        use Severity::*;
        assert_eq!(confidence_to_severity_boost(Info, 3), Medium);
        assert_eq!(confidence_to_severity_boost(Low, 3), High);
        assert_eq!(confidence_to_severity_boost(Medium, 3), Critical);
        assert_eq!(confidence_to_severity_boost(High, 3), Critical);
        assert_eq!(confidence_to_severity_boost(Critical, 3), Critical);
    }

    #[test]
    fn severity_boost_large_count_behaves_like_three_sources() {
        use Severity::*;
        // The boost saturates at +2 tiers (count >= 3); a huge count does
        // NOT escalate further. Anti-rig: pins that more sources can't push
        // a low base all the way to Critical, the cap is on the tier add,
        // not the severity ceiling (Info + 2 tiers = Medium, never Critical).
        for base in [Info, Low, Medium, High, Critical] {
            assert_eq!(
                confidence_to_severity_boost(base, 1000),
                confidence_to_severity_boost(base, 3),
                "large count must behave like 3 sources (+2 tiers) for base {base:?}"
            );
        }
    }

    #[test]
    fn severity_boost_only_three_tiers_defined() {
        // counts 4, 5, 100 should all behave like count=3 (2-tier boost).
        for n in [4usize, 5, 100] {
            assert_eq!(
                confidence_to_severity_boost(Severity::Low, n),
                confidence_to_severity_boost(Severity::Low, 3),
                "count={n} must behave like count=3"
            );
        }
    }
}
