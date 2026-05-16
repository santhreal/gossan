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

use crate::utils::normalize_host;

const WILDCARD_SIGNALS: &[&str] = &["wildcard", "catch-all", "*."];
const TAKEOVER_SIGNALS: &[&str] = &["takeover", "dangling", "unclaimed"];

pub struct WildcardTakeoverRule;

impl super::super::CorrelationRule for WildcardTakeoverRule {
    fn name(&self) -> &'static str {
        "wildcard_takeover"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        // Collect wildcard-bearing findings as their parent-domain
        // strings (stripped of the leading "*."). The chain only fires
        // when a takeover-vulnerable host lives UNDER one of those
        // parents — otherwise a wildcard on example.com and a
        // dangling subdomain on totally-different.com would emit a
        // false-positive "mass domain hijack" chain.
        let wildcard_parents: Vec<String> = findings
            .iter()
            .filter(|f| {
                let lower = f.title().to_lowercase();
                WILDCARD_SIGNALS.iter().any(|sig| lower.contains(sig))
            })
            .map(|f| {
                normalize_host(f.target())
                    .trim_start_matches("*.")
                    .to_string()
            })
            .filter(|p| !p.is_empty())
            .collect();

        if wildcard_parents.is_empty() {
            return vec![];
        }

        let takeover_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                let lower = f.title().to_lowercase();
                if !TAKEOVER_SIGNALS.iter().any(|sig| lower.contains(sig)) {
                    return false;
                }
                let host = normalize_host(f.target());
                // Same-domain test: takeover host must equal the parent
                // OR end with `.<parent>` (true subdomain). Apex match
                // is included because a wildcard at the apex still
                // shadows a takeover on the apex itself.
                wildcard_parents
                    .iter()
                    .any(|p| host == *p || host.ends_with(&format!(".{p}")))
            })
            .collect();

        if takeover_findings.is_empty() {
            return vec![];
        }

        let chain = Finding::builder(
            "correlation",
            takeover_findings[0].target(),
            Severity::Critical,
        )
        .title("Wildcard DNS + Subdomain Takeover = Mass Domain Hijack")
        .detail(format!(
            "A wildcard DNS record exists alongside {} takeover-vulnerable subdomain(s) under \
             the same parent domain. Because the wildcard resolves ALL subdomains, an attacker \
             who completes the takeover captures not just the dangling subdomain but EVERY \
             possible subdomain — including future ones that don't exist yet. This enables mass \
             phishing, cookie theft across the entire domain, and bypass of same-site cookie \
             protections.",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CorrelationRule;

    fn finding(scanner: &str, target: &str, title: &str) -> Finding {
        Finding::builder(scanner, target, Severity::High)
            .title(title)
            .build()
            .expect("test finding")
    }

    /// Adversarial: a wildcard on example.com + a dangling subdomain
    /// on unrelated-target.com MUST NOT chain. Pre-fix, the rule
    /// matched the takeover *anywhere* in the scan once a wildcard
    /// existed *anywhere*, producing a false-positive Critical chain.
    #[test]
    fn wildcard_takeover_does_not_fire_across_unrelated_domains() {
        let rule = WildcardTakeoverRule;
        let findings = vec![
            finding("dns", "*.example.com", "Wildcard DNS catch-all detected"),
            finding(
                "subdomain",
                "leftover.unrelated-target.com",
                "Subdomain takeover on dangling CNAME",
            ),
        ];
        assert!(
            rule.check(&findings, &[]).is_empty(),
            "cross-domain wildcard+takeover chain emitted as a false positive"
        );
    }

    #[test]
    fn wildcard_takeover_fires_when_takeover_lives_under_wildcard_parent() {
        let rule = WildcardTakeoverRule;
        let findings = vec![
            finding("dns", "*.example.com", "Wildcard DNS catch-all detected"),
            finding(
                "subdomain",
                "leftover.example.com",
                "Subdomain takeover on dangling CNAME",
            ),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].title().contains("Mass Domain Hijack"));
    }
}
