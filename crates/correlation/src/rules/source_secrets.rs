//! Correlates source code exposure with hardcoded secret detection.
//!
//! When a scanner detects:
//!   1. Source code exposure (.git, .env, source maps, swagger/openapi, debug endpoints)
//!   2. Hardcoded secrets in JavaScript or debug output
//!
//! This chain means the attacker has a direct path from discoverable source code
//! to extractable credentials. The severity is always Critical because the
//! attack chain is: discover source → extract secret → authenticate as app.

use gossan_core::Target;
use secfinding::{Finding, Severity};

/// Patterns indicating source code has been exposed.
const SOURCE_SIGNALS: &[&str] = &[
    ".git",
    ".env",
    "source map",
    "sourcemap",
    "swagger",
    "openapi",
    "directory listing",
    "backup file",
    "debug",
    "profiler",
    "phpinfo",
    "actuator",
];

/// Patterns indicating hardcoded secrets were found.
const SECRET_SIGNALS: &[&str] = &[
    "secret",
    "api key",
    "access key",
    "private key",
    "token",
    "credential",
    "password",
    "aws",
    "stripe",
    "github pat",
    "jwt",
];

/// Correlates source code exposure with hardcoded secret findings.
pub struct SourceCodeSecretsRule;

impl super::super::CorrelationRule for SourceCodeSecretsRule {
    fn name(&self) -> &'static str {
        "source_code_secrets"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        let source_exposures: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                let lower = f.title.to_lowercase();
                SOURCE_SIGNALS.iter().any(|sig| lower.contains(sig))
            })
            .collect();

        let secret_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                let lower = f.title.to_lowercase();
                SECRET_SIGNALS.iter().any(|sig| lower.contains(sig))
            })
            .collect();

        if source_exposures.is_empty() || secret_findings.is_empty() {
            return vec![];
        }

        let source_types: Vec<String> = source_exposures
            .iter()
            .map(|f| f.title.clone())
            .take(3)
            .collect();
        let secret_types: Vec<String> = secret_findings
            .iter()
            .map(|f| f.title.clone())
            .take(3)
            .collect();

        let chain = Finding::builder(
            "correlation",
            source_exposures
                .first()
                .map(|f| f.target.as_str())
                .unwrap_or("unknown"),
            Severity::Critical,
        )
        .title("Source Code Exposure → Credential Extraction Chain")
        .detail(format!(
            "Source code is exposed ({}) and contains hardcoded secrets ({}). \
             An attacker can follow this chain: discover exposed source → \
             extract credentials → authenticate as the application. \
             This is a direct path to compromise. \
             Fix: remove source code from production AND rotate all exposed credentials.",
            source_types.join(", "),
            secret_types.join(", "),
        ))
        .tag("chain")
        .tag("source-exposure")
        .tag("credential-leak")
        .build()
        .expect("finding builder: required fields are set");

        vec![chain]
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
            .expect("finding builder: required fields are set")
    }

    #[test]
    fn fires_when_source_and_secrets_present() {
        let rule = SourceCodeSecretsRule;
        let findings = vec![
            finding("hidden", "example.com", ".git/config exposed"),
            finding("js", "example.com", "AWS Access Key in JavaScript"),
        ];
        let chains = rule.check(&findings, &[]);
        assert_eq!(chains.len(), 1);
        assert!(chains[0].title.contains("Source Code Exposure"));
    }

    #[test]
    fn does_not_fire_with_only_source_exposure() {
        let rule = SourceCodeSecretsRule;
        let findings = vec![finding("hidden", "example.com", ".git/config exposed")];
        assert!(rule.check(&findings, &[]).is_empty());
    }

    #[test]
    fn does_not_fire_with_only_secrets() {
        let rule = SourceCodeSecretsRule;
        let findings = vec![finding("js", "example.com", "AWS Access Key in JavaScript")];
        assert!(rule.check(&findings, &[]).is_empty());
    }
}
