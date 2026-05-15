//! Correlates wildcard DNS with subdomain takeover for mass hijack detection.
//!
//! When a domain has:
//!   1. A wildcard DNS record (*.example.com resolves)
//!   2. Any dangling CNAME/NS takeover finding
//!
//! The attacker doesn't just capture one subdomain — they capture ALL
//! subdomains, including future ones. This is a domain-wide compromise.

use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

const WILDCARD_SIGNALS: &[&str] = &["wildcard", "catch-all", "*."];
const TAKEOVER_SIGNALS: &[&str] = &["takeover", "dangling", "unclaimed"];

pub struct WildcardTakeoverRule;

impl super::super::CorrelationRule for WildcardTakeoverRule {
    fn name(&self) -> &'static str {
        "wildcard_takeover"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        let has_wildcard = findings.iter().any(|f| {
            let lower = f.title().to_lowercase();
            WILDCARD_SIGNALS.iter().any(|sig| lower.contains(sig))
        });

        let takeover_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                let lower = f.title().to_lowercase();
                TAKEOVER_SIGNALS.iter().any(|sig| lower.contains(sig))
            })
            .collect();

        if !has_wildcard || takeover_findings.is_empty() {
            return vec![];
        }

        let chain = Finding::builder(
            "correlation",
            takeover_findings
                .first()
                .map(|f| f.target())
                .unwrap_or("unknown"),
            Severity::Critical,
        )
        .title("Wildcard DNS + Subdomain Takeover = Mass Domain Hijack")
        .detail(format!(
            "A wildcard DNS record exists alongside {} takeover-vulnerable subdomain(s).              Because the wildcard resolves ALL subdomains, an attacker who completes              the takeover captures not just the dangling subdomain but EVERY possible              subdomain — including future ones that don't exist yet. This enables              mass phishing, cookie theft across the entire domain, and bypass of              same-site cookie protections.",
            takeover_findings.len()
        ))
        .kind(FindingKind::Vulnerability)
        .tag("chain")
        .tag("wildcard")
        .tag("takeover")
        .tag("critical")
        .build_or_log();

        chain.into_iter().collect()
    }
}
