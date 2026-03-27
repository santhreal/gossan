//! Finding types for gossan.
//!
//! Re-exports the shared [`Finding`] from `secfinding`.

pub use secfinding::{Evidence, Finding, FindingBuilder, FindingKind, Severity};

use crate::Target;

/// A helper function to create a `Finding` seamlessly using gossan's `Target` type.
/// The `Target` is converted into a string domain for `secfinding::Finding`.
///
/// # Panics
/// Panics if the internal builder fails to guarantee required fields are set.
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn make_finding(
    scanner: impl Into<String>,
    target: Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> Finding {
    Finding::builder(
        scanner.into(),
        target.domain().unwrap_or("?").to_string(),
        severity,
    )
    .title(title)
    .detail(detail)
    .build()
    .expect("finding builder: required fields are set")
}

pub trait FindingExt {
    #[must_use]
    fn with_evidence(self, ev: Evidence) -> Self;
    #[must_use]
    fn with_tag(self, tag: impl Into<String>) -> Self;
    #[must_use]
    fn with_exploit_hint(self, hint: impl Into<String>) -> Self;
}

impl FindingExt for Finding {
    fn with_evidence(mut self, ev: Evidence) -> Self {
        self.evidence.push(ev);
        self
    }

    fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    fn with_exploit_hint(mut self, hint: impl Into<String>) -> Self {
        self.exploit_hint = Some(hint.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DiscoverySource, DomainTarget, Target};
    use serde_json::json;

    fn dummy_target() -> Target {
        Target::Domain(DomainTarget {
            domain: "example.com".into(),
            source: DiscoverySource::Seed,
        })
    }

    #[test]
    fn make_finding_creates_finding() {
        let f = make_finding(
            "portscan",
            dummy_target(),
            Severity::High,
            "title",
            "detail",
        );
        assert_eq!(f.scanner, "portscan");
        assert_eq!(f.target, "example.com");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.title, "title");
        assert_eq!(f.detail, "detail");
    }

    #[test]
    fn make_finding_falls_back_to_placeholder_when_target_has_no_domain() {
        let target = Target::Host(crate::HostTarget {
            ip: "127.0.0.1".parse().unwrap(),
            domain: None,
        });
        let finding = make_finding("dns", target, Severity::Low, "title", "detail");
        assert_eq!(finding.target, "?");
    }

    #[test]
    fn finding_ext_appends_evidence_tags_and_exploit_hint() {
        let finding = make_finding(
            "hidden",
            dummy_target(),
            Severity::Medium,
            "title",
            "detail",
        )
        .with_evidence(Evidence::Raw("stack trace".into()))
        .with_tag("debug")
        .with_tag("exposure")
        .with_exploit_hint("curl https://example.com");

        assert_eq!(finding.evidence, vec![Evidence::Raw("stack trace".into())]);
        assert_eq!(finding.tags, vec!["debug", "exposure"]);
        assert_eq!(
            finding.exploit_hint.as_deref(),
            Some("curl https://example.com")
        );
    }

    #[test]
    fn severity_ordering_matches_expected_risk_progression() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn finding_builder_deduplicates_and_sorts_tags() {
        let finding = Finding::builder("core", "example.com", Severity::Info)
            .title("tag test")
            .tag("zeta")
            .tag("alpha")
            .tag("alpha")
            .build()
            .expect("finding builder: required fields are set");

        assert_eq!(finding.tags, vec!["alpha", "zeta"]);
    }

    #[test]
    fn finding_builder_serializes_kind_as_type_field() {
        let finding = Finding::builder("core", "example.com", Severity::High)
            .title("serialized")
            .kind(FindingKind::Exposure)
            .build()
            .expect("finding builder: required fields are set");

        let value = serde_json::to_value(&finding).unwrap();
        assert_eq!(value["type"], json!("exposure"));
    }

    #[test]
    fn finding_round_trips_through_json() {
        let finding = make_finding(
            "portscan",
            dummy_target(),
            Severity::Critical,
            "open redis",
            "detail",
        )
        .with_tag("redis")
        .with_evidence(Evidence::DnsRecord {
            record_type: "TXT".into(),
            value: "v=spf1 -all".into(),
        });

        let encoded = serde_json::to_string(&finding).unwrap();
        let decoded: Finding = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded.scanner, "portscan");
        assert_eq!(decoded.target, "example.com");
        assert_eq!(decoded.severity, Severity::Critical);
        assert_eq!(decoded.tags, vec!["redis"]);
        assert_eq!(decoded.evidence.len(), 1);
    }

    #[test]
    fn finding_try_into_json_value_preserves_core_fields() {
        let finding = make_finding(
            "subdomain",
            dummy_target(),
            Severity::Info,
            "title",
            "detail",
        );
        let value = serde_json::Value::try_from(finding).unwrap();

        assert_eq!(value["scanner"], json!("subdomain"));
        assert_eq!(value["target"], json!("example.com"));
        assert_eq!(value["severity"], json!("info"));
    }
}
