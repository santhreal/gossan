//! Correlates multiple TLS/crypto weaknesses on the same host into a chain finding.
//! Self-signed cert + expired cert + missing HSTS = "defence in depth completely absent."

use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

use crate::correlation::utils::normalize_host;
use crate::correlation::CorrelationRule;
/// TlsWeaknessRule correlation rule  -  detects multi-signal attack chains.
pub struct TlsWeaknessRule;

impl CorrelationRule for TlsWeaknessRule {
    fn name(&self) -> &'static str {
        "tls-weakness-chain"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        // Group TLS/header findings by host, tracking both normalized and original targets
        let mut host_issues: std::collections::HashMap<String, (Vec<String>, String)> =
            std::collections::HashMap::new();

        for f in findings {
            let title_lc = f.title().to_lowercase();
            // `expired` must be qualified by a cert/TLS context  -  a
            // bare "expired" matched unrelated findings ("Domain
            // registration expired", "Session token expired") and
            // counted them as TLS weaknesses, both mislabeling them in
            // the chain detail and padding the ≥2-distinct threshold
            // with non-TLS noise.
            let is_tls = title_lc.contains("self-signed")
                || title_lc.contains("hsts")
                || title_lc.contains("tls")
                || title_lc.contains("certificate")
                || (title_lc.contains("expired") && title_lc.contains("cert"));
            if !is_tls {
                continue;
            }
            let Some(host) = Some(f.target()) else {
                continue;
            };
            let normalized_host = normalize_host(host);
            let entry = host_issues
                .entry(normalized_host)
                .or_insert((Vec::new(), host.to_string()));
            entry.0.push(f.title().to_string());
        }

        host_issues
            .into_iter()
            .filter_map(|(normalized_host, (issues, original_target))| {
                // Deduplicate issue titles  -  same finding fires on multiple targets (http/https/ports)
                let mut seen = std::collections::HashSet::new();
                let unique: Vec<String> = issues
                    .into_iter()
                    .filter(|t| seen.insert(t.clone()))
                    .collect();
                if unique.len() < 2 {
                    return None;
                }
                // Use normalized host if original target had ports/schemes, otherwise use original
                let target_for_chain =
                    if original_target.contains(':') || original_target.starts_with("http") {
                        normalized_host.clone()
                    } else {
                        original_target.clone()
                    };
                Finding::builder("correlation", target_for_chain, Severity::High)
                    .title(format!("Multiple TLS weaknesses on {}", normalized_host))
                    .detail(format!(
                        "{} has {} distinct TLS/transport-security issues: {}. \
                         Combined, these indicate complete absence of transport security hygiene \
                         and make MitM attacks highly feasible.",
                        normalized_host,
                        unique.len(),
                        unique.join("; ")
                    ))
                    .kind(FindingKind::Vulnerability)
                    .tag("chain")
                    .tag("tls")
                    .tag("transport")
                    .build_or_log()
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
            .expect("test finding")
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
            .detail()
            .contains("2 distinct TLS/transport-security issues"));
    }

    /// ADVERSARIAL: non-TLS findings whose titles merely contain
    /// "expired" must NOT be counted as TLS weaknesses. Pre-fix, two
    /// such unrelated findings on a host produced a false "Multiple
    /// TLS weaknesses" chain.
    #[test]
    fn tls_weakness_rule_ignores_non_cert_expired_findings() {
        let findings = vec![
            finding("example.com", "Domain registration expired"),
            finding("example.com", "Session token expired"),
        ];
        assert!(
            TlsWeaknessRule.check(&findings, &[]).is_empty(),
            "non-TLS 'expired' findings were miscounted as TLS weaknesses"
        );
    }

    /// ADVERSARIAL (negative twin): a real TLS weakness padded by a
    /// non-TLS "expired" finding must NOT reach the chain  -  only one
    /// genuine TLS issue is present, which is not a "multiple
    /// weaknesses" chain.
    #[test]
    fn tls_weakness_rule_does_not_let_non_tls_expired_pad_the_threshold() {
        let findings = vec![
            finding("example.com", "Domain registration expired"),
            finding("example.com", "Self-signed certificate"),
        ];
        assert!(
            TlsWeaknessRule.check(&findings, &[]).is_empty(),
            "a non-TLS 'expired' finding padded the >=2 distinct threshold"
        );
    }

    /// PROVING: genuine multiple TLS weaknesses (including the
    /// "expired cert" phrasing without the word "certificate") still
    /// chain  -  the tightened filter didn't over-correct.
    #[test]
    fn tls_weakness_rule_still_chains_real_multiple_weaknesses() {
        let findings = vec![
            finding("example.com", "Self-signed certificate"),
            finding("example.com", "Missing HSTS header"),
            finding("example.com", "Expired cert on port 8443"),
        ];
        let chains = TlsWeaknessRule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0]
            .detail()
            .contains("3 distinct TLS/transport-security issues"));
    }
}
