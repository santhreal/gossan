//! Correlates CORS misconfiguration with exposed secrets for credential theft.
//!
//! When both are present:
//!   1. CORS allows arbitrary origins (origin reflection with credentials)
//!   2. Secrets found in JavaScript source code
//!
//! An attacker on any domain can make authenticated cross-origin requests
//! AND the application already has secrets in client-side code. This is a
//! direct path to credential theft.

use gossan_core::Target;
use secfinding::{Finding, FindingKind, Severity};

use crate::utils::normalize_host;

pub struct CorsSecretChainRule;

impl super::super::CorrelationRule for CorsSecretChainRule {
    fn name(&self) -> &'static str {
        "cors_secret_chain"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        let is_cors_with_creds = |f: &&Finding| -> bool {
            let lower = f.title().to_lowercase();
            lower.contains("cors") && lower.contains("credential")
        };
        let is_secret = |f: &&Finding| -> bool {
            f.tags()
                .iter()
                .any(|t| t.as_ref() == "secret" || t.as_ref() == "keyhog")
        };

        // Group by normalized host. The chain only fires when both
        // signals are on the SAME target — otherwise unrelated
        // findings (CORS misconfig on app.example.com + secret on
        // unrelated.com) would emit a false-positive Critical chain
        // claiming attacker movement between them.
        let mut by_host: std::collections::HashMap<String, Vec<&Finding>> =
            std::collections::HashMap::new();
        for f in findings {
            by_host
                .entry(normalize_host(f.target()))
                .or_default()
                .push(f);
        }

        let mut chains = Vec::new();
        for (_host, group) in by_host {
            let has_cors_with_creds = group.iter().any(is_cors_with_creds);
            let secret_findings: Vec<&Finding> = group.iter().copied().filter(is_secret).collect();

            if !has_cors_with_creds || secret_findings.is_empty() {
                continue;
            }

            let chain = Finding::builder(
                "correlation",
                secret_findings[0].target(),
                Severity::Critical,
            )
            .title("CORS Origin Reflection + JS Secrets = Credential Theft")
            .detail(format!(
                "CORS allows arbitrary origins with credentials AND {} secret(s) found in \
                 JavaScript on the same target. An attacker on any domain can: (1) make \
                 authenticated cross-origin requests to steal user session data, (2) access API \
                 endpoints using the leaked credentials from JS. Combined, this enables full \
                 account takeover without any user interaction beyond visiting a page.",
                secret_findings.len()
            ))
            .kind(FindingKind::Vulnerability)
            .tag("chain")
            .tag("cors")
            .tag("secret")
            .build_or_log();

            chains.extend(chain);
        }
        chains
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CorrelationRule;

    fn finding(scanner: &str, target: &str, title: &str, tags: &[&str]) -> Finding {
        let mut b = Finding::builder(scanner, target, Severity::High).title(title);
        for t in tags {
            b = b.tag(*t);
        }
        b.build().expect("test finding")
    }

    /// Adversarial: CORS misconfig on host A and secret on unrelated
    /// host B MUST NOT chain. Pre-fix the rule fired any time both
    /// signals existed anywhere in the same scan.
    #[test]
    fn cors_secret_chain_does_not_fire_across_unrelated_hosts() {
        let rule = CorsSecretChainRule;
        let findings = vec![
            finding(
                "hidden",
                "app.example.com",
                "CORS allows arbitrary origin with credentials",
                &[],
            ),
            finding(
                "js",
                "unrelated-target.com",
                "AWS Access Key in JS",
                &["secret"],
            ),
        ];
        assert!(
            rule.check(&findings, &[]).is_empty(),
            "cross-host cors+secret chain emitted as a false positive"
        );
    }

    #[test]
    fn cors_secret_chain_fires_when_both_on_same_host() {
        let rule = CorsSecretChainRule;
        let findings = vec![
            finding(
                "hidden",
                "app.example.com",
                "CORS allows arbitrary origin with credentials",
                &[],
            ),
            finding("js", "app.example.com", "AWS Access Key in JS", &["secret"]),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].target(), "app.example.com");
    }
}
