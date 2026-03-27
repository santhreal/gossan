//! Correlates an exposed admin panel with a missing authentication header finding.
//! Admin UI reachable without auth controls = immediate privilege escalation.

use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

use crate::CorrelationRule;

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
                f.scanner == "hidden"
                    && (f.title.to_lowercase().contains("admin")
                        || f.title.to_lowercase().contains("dashboard")
                        || f.title.to_lowercase().contains("console"))
            })
            .filter_map(|f| Some(f.target.as_str()).map(|d| d.to_string()))
            .collect();

        if admin_hosts.is_empty() {
            return chains;
        }

        // Same hosts missing WWW-Authenticate / auth headers
        let unauth_hosts: std::collections::HashSet<String> = findings
            .iter()
            .filter(|f| {
                (f.scanner == "techstack" || f.scanner == "hidden")
                    && (f.title.to_lowercase().contains("missing")
                        || f.title.to_lowercase().contains("no authentication"))
            })
            .filter_map(|f| Some(f.target.as_str()).map(|d| d.to_string()))
            .collect();

        for host in admin_hosts.intersection(&unauth_hosts) {
            // Find the original admin finding for evidence
            let evidence_id = findings
                .iter()
                .filter(|f| f.scanner == "hidden" && Some(f.target.as_str()) == Some(host.as_str()))
                .map(|f| f.id.to_string())
                .next()
                .unwrap_or_default();

            chains.push(
                Finding::builder("correlation", host.clone(), Severity::Critical)
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
                    .tag("chain")
                    .tag("admin")
                    .tag("auth-bypass")
                    .evidence(Evidence::Raw(format!("Admin finding id: {}", evidence_id)))
                    .build()
                    .expect("finding builder: required fields are set"),
            );
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
            .expect("finding builder: required fields are set")
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
        assert_eq!(chains[0].severity, Severity::Critical);
        assert!(chains[0].title.contains("without authentication"));
    }
}
