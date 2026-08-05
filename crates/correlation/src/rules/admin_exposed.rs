//! Correlates an exposed admin panel with a missing authentication header finding.
//! Admin UI reachable without auth controls = immediate privilege escalation.

use gossan_core::Target;
use secfinding::{Evidence, Finding, FindingKind, Severity};

use crate::utils::normalize_host;
use crate::CorrelationRule;
/// AdminExposedRule correlation rule (detects multi-signal attack chains).
pub struct AdminExposedRule;

impl CorrelationRule for AdminExposedRule {
    fn name(&self) -> &'static str {
        "admin-no-auth-chain"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        let mut chains = Vec::new();

        // Hosts with admin panel exposure
        let admin_hosts: std::collections::HashSet<String> = findings
            .iter()
            .filter(|f| {
                f.scanner() == "hidden"
                    && (f.title().to_lowercase().contains("admin")
                        || f.title().to_lowercase().contains("dashboard")
                        || f.title().to_lowercase().contains("console"))
            })
            .filter_map(|f| Some(f.target()).map(|d| normalize_host(d)))
            .collect();

        if admin_hosts.is_empty() {
            return chains;
        }

        // Same hosts missing WWW-Authenticate / auth headers. The
        // filter is deliberately auth-specific: a generic "Missing"
        // substring (e.g. "Missing HSTS header") would chain with any
        // admin panel finding and emit a false-positive Critical
        // "admin without auth" chain. Match only titles that name
        // authentication directly.
        let is_unauth_finding = |f: &Finding| -> bool {
            let scanner_ok = f.scanner() == "techstack" || f.scanner() == "hidden";
            if !scanner_ok {
                return false;
            }
            let t = f.title().to_lowercase();
            t.contains("no authentication")
                || t.contains("missing authentication")
                || t.contains("authentication missing")
                || t.contains("authentication required")
                || t.contains("auth bypass")
                || t.contains("auth-bypass")
                || t.contains("www-authenticate")
                || t.contains("unauthenticated")
                || f.tags().iter().any(|tag| {
                    let ts = tag.as_ref();
                    ts == "auth-bypass" || ts == "no-auth" || ts == "unauthenticated"
                })
        };
        let unauth_hosts: std::collections::HashSet<String> = findings
            .iter()
            .filter(|f| is_unauth_finding(f))
            .filter_map(|f| Some(f.target()).map(|d| normalize_host(d)))
            .collect();

        for host in admin_hosts.intersection(&unauth_hosts) {
            // Find all relevant findings for evidence
            let is_admin = |f: &Finding| {
                f.scanner() == "hidden"
                    && normalize_host(f.target()) == *host
                    && {
                        let t = f.title().to_lowercase();
                        t.contains("admin") || t.contains("dashboard") || t.contains("console")
                    }
            };
            let admin_findings: Vec<&Finding> = findings
                .iter()
                .filter(|f| is_admin(f))
                .collect();

            let auth_findings: Vec<&Finding> = findings
                .iter()
                .filter(|f| normalize_host(f.target()) == *host && is_unauth_finding(f))
                .collect();

            // Self-chain guard: require two *distinct* findings. A single
            // finding whose title matches both predicates (e.g. "Admin
            // console accessible, no authentication required") is one
            // finding already reported by its own scanner; re-emitting it
            // as a Critical correlation is a duplicate, not a correlation.
            let has_distinct_pair = {
                let a = admin_findings.iter().copied().next();
                let b = auth_findings.iter().copied().next();
                match (a, b) {
                    (Some(fa), Some(fb)) if !std::ptr::eq(fa, fb) => true,
                    (Some(fa), Some(fb)) => {
                        let a2 = admin_findings.iter().copied().find(|f| !std::ptr::eq(*f, fb));
                        let b2 = auth_findings.iter().copied().find(|f| !std::ptr::eq(*f, fa));
                        a2.is_some() || b2.is_some()
                    }
                    _ => false,
                }
            };
            if !has_distinct_pair {
                continue;
            }

            let mut evidence_ids = Vec::new();
            for finding in admin_findings.iter().chain(auth_findings.iter()) {
                evidence_ids.push(finding.id().to_string());
            }
            let evidence_string = evidence_ids.join(", ");

            // The chain output preserves the *original* target (path,
            // unicode, port) of the contributing admin finding, only
            // grouping uses the normalized form. Tests assert the chain
            // target round-trips the original verbatim.
            let display_target = admin_findings
                .first()
                .map(|f| f.target().to_string())
                .unwrap_or_else(|| host.clone());

            if let Some(finding) =
                Finding::builder("correlation", display_target, Severity::Critical)
                    .title(format!(
                        "Admin panel exposed without authentication: {}",
                        host
                    ))
                    .detail(format!(
                        "An admin/dashboard panel is accessible on {} and no authentication \
                         mechanism (WWW-Authenticate, login redirect, auth headers) was detected. \
                         Immediate privilege escalation and full application compromise likely.",
                        host
                    ))
                    .kind(FindingKind::Vulnerability)
                    .tag("chain")
                    .tag("admin")
                    .tag("auth-bypass")
                    .evidence(Evidence::raw(format!("Finding IDs: {}", evidence_string)))
                    .build_or_log()
            {
                chains.push(finding);
            }
        }

        chains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn finding(scanner: &str, target: &str, title: &str) -> Finding {
        Finding::builder(scanner, target, Severity::High)
            .title(title)
            .build()
            .expect("test finding")
    }

    #[test]
    fn admin_exposed_rule_requires_matching_targets() {
        let findings = vec![
            finding("hidden", "admin.example.com", "Admin dashboard exposed"),
            finding("hidden", "api.example.com", "No authentication required"),
        ];
        assert!(AdminExposedRule.check(&findings, &[]).is_empty());
    }

    #[test]
    fn admin_exposed_rule_emits_critical_chain_for_matching_host() {
        let findings = vec![
            finding("hidden", "admin.example.com", "Admin dashboard exposed"),
            finding("hidden", "admin.example.com", "No authentication required"),
        ];
        let chains = AdminExposedRule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].severity(), Severity::Critical);
        assert!(chains[0].title().contains("without authentication"));
    }

    /// Adversarial: a host with an admin panel finding *and* a
    /// generic "Missing X header" finding (HSTS, CSP, X-Frame-Options)
    /// MUST NOT trigger the auth-bypass chain. Pre-fix, the substring
    /// match `.contains("missing")` fired on every security-headers
    /// finding and produced false-positive Critical chains.
    #[test]
    fn admin_exposed_rule_does_not_chain_on_unrelated_missing_header() {
        let findings = vec![
            finding("hidden", "admin.example.com", "Admin dashboard exposed"),
            finding("hidden", "admin.example.com", "Missing HSTS header"),
            finding(
                "hidden",
                "admin.example.com",
                "Missing X-Frame-Options header",
            ),
            finding(
                "hidden",
                "admin.example.com",
                "Missing Content-Security-Policy header",
            ),
        ];
        let chains = AdminExposedRule.check(&findings, &[]);
        assert!(
            chains.is_empty(),
            "missing-header findings produced a false-positive admin-no-auth chain: {:?}",
            chains.iter().map(Finding::title).collect::<Vec<_>>()
        );
    }

    /// The auth-bypass chain still fires for a real auth-related
    /// title (proving the tightened filter didn't over-correct).
    #[test]
    fn admin_exposed_rule_chains_on_explicit_auth_bypass_signal() {
        let findings = vec![
            finding("hidden", "admin.example.com", "Admin dashboard exposed"),
            finding(
                "hidden",
                "admin.example.com",
                "Authentication missing on /admin",
            ),
        ];
        let chains = AdminExposedRule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
    }

    /// ADVERSARIAL: one hidden-scanner finding that already states both
    /// halves ("Admin console accessible, no authentication required")
    /// must NOT self-chain. It is a single finding already reported by
    /// its own scanner; re-emitting it as a Critical correlation is a
    /// duplicate, not a correlation of two independent signals.
    #[test]
    fn admin_exposed_rule_does_not_self_chain_single_combined_finding() {
        for title in [
            "Admin console accessible, no authentication required",
            "Unauthenticated admin dashboard exposed",
            "Admin panel reachable, authentication missing",
        ] {
            let findings = vec![finding("hidden", "admin.example.com", title)];
            let chains = AdminExposedRule.check(&findings, &[]);
            assert!(
                chains.is_empty(),
                "single combined finding {title:?} self-chained: {:?}",
                chains.iter().map(Finding::title).collect::<Vec<_>>()
            );
        }
    }

    /// PROVING (regression twin): the combined dual-signal finding,
    /// when accompanied by a *distinct* second admin finding on the
    /// same host, must still chain.
    #[test]
    fn admin_exposed_rule_chains_combined_finding_with_distinct_partner() {
        let findings = vec![
            finding(
                "hidden",
                "admin.example.com",
                "Admin console accessible, no authentication required",
            ),
            finding("hidden", "admin.example.com", "Admin login panel discovered"),
        ];
        let chains = AdminExposedRule.check(&findings, &[]);
        assert_eq!(
            chains.len(),
            1,
            "combined finding + distinct admin finding must still chain"
        );
        assert_eq!(chains[0].severity(), Severity::Critical);
    }
}
