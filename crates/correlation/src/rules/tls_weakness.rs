//! Correlates multiple TLS/crypto weaknesses on the same host into a chain finding.
//! Self-signed cert + expired cert + missing HSTS = "defence in depth completely absent."

use gossan_core::Target;
use secfinding::{Finding, Severity};

use crate::CorrelationRule;

pub struct TlsWeaknessRule;

impl CorrelationRule for TlsWeaknessRule {
    fn name(&self) -> &'static str {
        "tls-weakness-chain"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        // Group TLS/header findings by host
        let mut host_issues: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();

        for f in findings {
            let title_lc = f.title.to_lowercase();
            let is_tls = title_lc.contains("self-signed")
                || title_lc.contains("expired")
                || title_lc.contains("hsts")
                || title_lc.contains("certificate")
                || title_lc.contains("tls");
            if !is_tls {
                continue;
            }
            let Some(host) = Some(f.target.as_str()) else {
                continue;
            };
            host_issues
                .entry(host.to_string())
                .or_default()
                .push(f.title.clone());
        }

        host_issues
            .into_iter()
            .filter_map(|(host, issues)| {
                // Deduplicate issue titles — same finding fires on multiple targets (http/https/ports)
                let mut seen = std::collections::HashSet::new();
                let unique: Vec<String> = issues
                    .into_iter()
                    .filter(|t| seen.insert(t.clone()))
                    .collect();
                if unique.len() < 2 {
                    return None;
                }
                Some(
                    Finding::builder("correlation", host.clone(), Severity::High)
                        .title(format!("Multiple TLS weaknesses on {}", host))
                        .detail(format!(
                            "{} has {} distinct TLS/transport-security issues: {}. \
                         Combined, these indicate complete absence of transport security hygiene \
                         and make MitM attacks highly feasible.",
                            host,
                            unique.len(),
                            unique.join("; ")
                        ))
                        .tag("chain")
                        .tag("tls")
                        .tag("transport")
                        .build()
                        .expect("finding builder: required fields are set"),
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn finding(target: &str, title: &str) -> Finding {
        Finding::builder("portscan", target, Severity::High)
            .title(title)
            .build()
            .expect("finding builder: required fields are set")
    }

    #[test]
    fn tls_weakness_rule_requires_multiple_distinct_issues() {
        let findings = vec![finding("example.com", "TLS certificate expired")];
        assert!(TlsWeaknessRule.check(&findings, &[]).is_empty());
    }

    #[test]
    fn tls_weakness_rule_deduplicates_repeated_titles() {
        let findings = vec![
            finding("example.com", "TLS certificate expired"),
            finding("example.com", "TLS certificate expired"),
            finding("example.com", "Self-signed TLS certificate"),
        ];
        let chains = TlsWeaknessRule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0]
            .detail
            .contains("2 distinct TLS/transport-security issues"));
    }
}
