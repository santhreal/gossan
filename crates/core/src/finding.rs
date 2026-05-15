//! Finding types for gossan.
//!
//! Re-exports the shared [`Finding`] from `secfinding`.

pub use secfinding::{Evidence, Finding, FindingBuilder, FindingKind, Severity};

use crate::Target;
/// A helper function to create a `Finding` seamlessly using gossan's `Target` type.
/// The `Target` is converted into a string domain for `secfinding::Finding`.
///
/// # Errors
/// Returns an error if the internal builder fails to guarantee required fields are set.
#[allow(clippy::needless_pass_by_value)]
pub fn make_finding(
    scanner: impl Into<String>,
    target: Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> anyhow::Result<Finding> {
    Finding::builder(
        scanner.into(),
        target.domain().unwrap_or("?").to_string(),
        severity,
    )
    .title(title)
    .detail(detail)
    .build()
    .map_err(|e| anyhow::anyhow!(e))
}

/// Helper to build a finding and push it to a vector, logging and continuing on error.
/// This prevents scanner panics if finding validation (like length limits) fails.
pub fn try_push_finding(builder: FindingBuilder, findings: &mut Vec<Finding>) {
    match builder.build() {
        Ok(f) => findings.push(f),
        Err(e) => tracing::warn!(error = %e, "finding builder failed; skipping finding"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DiscoverySource, DomainTarget};

    #[test]
    fn test_make_finding_sets_required_fields() {
        let target = Target::Domain(DomainTarget {
            domain: "example.com".into(),
            source: DiscoverySource::Seed,
        });
        let finding = make_finding(
            "test-scanner",
            target,
            Severity::High,
            "Test Title",
            "Test Detail",
        )
        .unwrap();

        assert_eq!(finding.scanner(), "test-scanner");
        assert_eq!(finding.target(), "example.com");
        assert_eq!(finding.severity(), Severity::High);
        assert_eq!(finding.title(), "Test Title");
        assert_eq!(finding.detail(), "Test Detail");
    }

    #[test]
    fn severity_ordering_matches_expected_risk_progression() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }
}
