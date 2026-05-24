//! Utility helpers for correlation rule evaluation.

/// Normalise a finding target for cross-host clustering.
///
/// Now delegates to the single canonical `gossan_core::domain`
/// implementation (formerly this crate carried *two* divergent
/// `normalize_host` copies  -  this conservative one used by the rules
/// and a richer one in `dedup`). Unifying on the rich version is an
/// intentional behaviour change: clustering is now case-, trailing-dot-
/// and IDN-insensitive everywhere, which removes a class of cross-host
/// correlation false positives/negatives.
pub(crate) fn normalize_host(target: &str) -> String {
    gossan_core::domain::normalize_host(target)
}
