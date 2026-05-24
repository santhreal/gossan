//! Correlates wildcard DNS with subdomain takeover for mass hijack detection.
//!
//! When a domain has:
//!   1. A wildcard DNS record (*.example.com resolves to a fixed set of IPs)
//!   2. Any dangling CNAME/NS takeover finding under the same parent
//!
//! The attacker doesn't just capture one subdomain  -  they capture ALL
//! subdomains, including future ones. This is a domain-wide compromise.
//!
//! Wildcard signal: tag `dns-wildcard` on a subdomain/dns finding (the
//! authoritative emission point is `gossan_subdomain` after
//! `detect_wildcards`), OR a finding whose target starts with `*.`.
//! Title-substring matching was the prior approach and false-fired on
//! unrelated `wildcard` findings (CORS `Access-Control-Allow-Origin: *`,
//! CSP `wildcard * in script-src`, `wildcard Access-Control-Allow-Methods`)
//! while the rule's only "wildcard DNS" emitter never produced a finding
//! at all  -  so on real data the rule was simultaneously unreachable on
//! its real signal and a false-positive Critical generator on every
//! target with a wildcard CORS/CSP misconfig.

use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

use crate::correlation::utils::normalize_host;

const TAKEOVER_SIGNALS: &[&str] = &["takeover", "dangling", "unclaimed"];
const WILDCARD_TAG: &str = "dns-wildcard";

fn is_dns_wildcard(f: &Finding) -> bool {
    if f.tags().iter().any(|t| t.as_ref() == WILDCARD_TAG) {
        return true;
    }
    // Fallback: an emitter that stamps the wildcard's own host as the
    // target (e.g. a DNS scanner using `*.example.com`) is still
    // accepted. Confines fallback to a structural target shape  -  not a
    // title-substring scan  -  so CORS/CSP "wildcard" findings (whose
    // target is the scanned host, never a `*.`-prefixed apex) cannot
    // trip it.
    normalize_host(f.target()).starts_with("*.")
}

fn wildcard_parent_of(f: &Finding) -> String {
    // Tagged wildcard findings are emitted on the apex (no leading `*.`),
    // structural `*.host` fallbacks must strip the leading label.
    normalize_host(f.target())
        .trim_start_matches("*.")
        .to_string()
}

pub struct WildcardTakeoverRule;

impl super::super::CorrelationRule for WildcardTakeoverRule {
    fn name(&self) -> &'static str {
        "wildcard_takeover"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        // Collect wildcard parents (one per affected apex, after dedup
        // by parent string so the same wildcard reported twice doesn't
        // skew the chain count).
        let mut wildcard_parents: Vec<String> = findings
            .iter()
            .filter(|f| is_dns_wildcard(f))
            .map(wildcard_parent_of)
            .filter(|p| !p.is_empty())
            .collect();
        wildcard_parents.sort();
        wildcard_parents.dedup();

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
             possible subdomain  -  including future ones that don't exist yet. This enables mass \
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
    use crate::correlation::CorrelationRule;

    fn finding(scanner: &str, target: &str, title: &str) -> Finding {
        Finding::builder(scanner, target, Severity::High)
            .title(title)
            .build()
            .expect("test finding")
    }

    fn wildcard_finding(apex: &str) -> Finding {
        Finding::builder("subdomain", apex, Severity::Info)
            .title(format!("Wildcard DNS detected on {apex}"))
            .tag("subdomain")
            .tag(WILDCARD_TAG)
            .build()
            .expect("test wildcard finding")
    }

    /// Adversarial: a wildcard on example.com + a dangling subdomain
    /// on unrelated-target.com MUST NOT chain. Pre-fix, the rule
    /// matched the takeover *anywhere* in the scan once a wildcard
    /// existed *anywhere*, producing a false-positive Critical chain.
    #[test]
    fn wildcard_takeover_does_not_fire_across_unrelated_domains() {
        let rule = WildcardTakeoverRule;
        let findings = vec![
            wildcard_finding("example.com"),
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
            wildcard_finding("example.com"),
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

    /// PRECISION (the real defect  -  pre-2026-05-22 every CORS wildcard
    /// finding on a target with any dangling subdomain produced a false
    /// Critical "Mass Domain Hijack"). The CORS / CSP "wildcard"
    /// findings have nothing to do with DNS wildcards and MUST NOT
    /// trigger the chain.
    #[test]
    fn wildcard_takeover_ignores_cors_wildcard_origin_finding() {
        let rule = WildcardTakeoverRule;
        let findings = vec![
            // Exact title emitted by hidden::cors when the origin
            // reflects `Access-Control-Allow-Origin: *`. Target is the
            // scanned web host, not a `*.`-prefixed apex.
            finding(
                "hidden",
                "example.com",
                "CORS: wildcard origin (Access-Control-Allow-Origin: *)",
            ),
            finding(
                "subdomain",
                "leftover.example.com",
                "Subdomain takeover on dangling CNAME",
            ),
        ];
        assert!(
            rule.check(&findings, &[]).is_empty(),
            "CORS wildcard origin finding wrongly triggered DNS wildcard+takeover chain"
        );
    }

    /// PRECISION: same for the CSP `wildcard * in script-src` finding.
    #[test]
    fn wildcard_takeover_ignores_csp_wildcard_script_src_finding() {
        let rule = WildcardTakeoverRule;
        let findings = vec![
            finding("hidden", "example.com", "CSP: wildcard * in script-src"),
            finding(
                "subdomain",
                "leftover.example.com",
                "Subdomain takeover on dangling CNAME",
            ),
        ];
        assert!(
            rule.check(&findings, &[]).is_empty(),
            "CSP wildcard finding wrongly triggered DNS wildcard+takeover chain"
        );
    }

    /// PRECISION: CORS wildcard credentials variant must also be inert.
    #[test]
    fn wildcard_takeover_ignores_cors_wildcard_with_credentials_finding() {
        let rule = WildcardTakeoverRule;
        let findings = vec![
            finding(
                "hidden",
                "example.com",
                "CORS: wildcard origin with credentials",
            ),
            finding(
                "subdomain",
                "leftover.example.com",
                "Subdomain takeover on dangling CNAME",
            ),
        ];
        assert!(
            rule.check(&findings, &[]).is_empty(),
            "CORS wildcard+credentials finding wrongly triggered DNS wildcard+takeover chain"
        );
    }

    /// Structural fallback: a finding whose target is literally
    /// `*.example.com` still chains (e.g. a hand-emitted dns scanner
    /// finding that hasn't been switched to the tag).
    #[test]
    fn wildcard_takeover_fires_via_starred_target_fallback() {
        let rule = WildcardTakeoverRule;
        let findings = vec![
            // Untagged, but target carries the literal `*.` form.
            Finding::builder("dns", "*.example.com", Severity::Info)
                .title("zone observed")
                .build()
                .expect("starred target finding"),
            finding(
                "subdomain",
                "leftover.example.com",
                "Subdomain takeover on dangling CNAME",
            ),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
    }

    /// Adversarial: a wildcard finding alone (no takeover) MUST NOT
    /// fabricate the chain.
    #[test]
    fn wildcard_alone_does_not_chain() {
        let rule = WildcardTakeoverRule;
        let findings = vec![wildcard_finding("example.com")];
        assert!(rule.check(&findings, &[]).is_empty());
    }

    /// Adversarial: takeover alone (no wildcard) MUST NOT chain.
    #[test]
    fn takeover_alone_does_not_chain() {
        let rule = WildcardTakeoverRule;
        let findings = vec![finding(
            "subdomain",
            "leftover.example.com",
            "Subdomain takeover on dangling CNAME",
        )];
        assert!(rule.check(&findings, &[]).is_empty());
    }

    /// Adversarial: duplicate wildcard findings on the same apex must
    /// not multiply the chain count (parent dedup invariant).
    #[test]
    fn duplicate_wildcard_findings_emit_one_chain() {
        let rule = WildcardTakeoverRule;
        let findings = vec![
            wildcard_finding("example.com"),
            wildcard_finding("example.com"),
            finding(
                "subdomain",
                "leftover.example.com",
                "Subdomain takeover on dangling CNAME",
            ),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
    }

    /// Hierarchical match: wildcard on `*.api.example.com` (target form
    /// `api.example.com` post-trim) must chain a takeover on
    /// `dev.api.example.com` but NOT one on `apex.example.com`.
    #[test]
    fn wildcard_takeover_matches_one_subdomain_level_below_the_wildcard() {
        let rule = WildcardTakeoverRule;
        let findings = vec![
            wildcard_finding("api.example.com"),
            finding(
                "subdomain",
                "dev.api.example.com",
                "Dangling CNAME under api.example.com",
            ),
            finding(
                "subdomain",
                "apex.example.com",
                "Dangling CNAME on sibling apex",
            ),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert!(
            chains[0].detail().contains("1 takeover-vulnerable"),
            "chain must include only the under-wildcard takeover, got {}",
            chains[0].detail()
        );
    }
}
