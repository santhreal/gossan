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

pub struct CorsSecretChainRule;

impl super::super::CorrelationRule for CorsSecretChainRule {
    fn name(&self) -> &'static str {
        "cors_secret_chain"
    }

    fn check(&self, findings: &[Finding], _targets: &[Target]) -> Vec<Finding> {
        let has_cors_with_creds = findings.iter().any(|f| {
            let lower = f.title().to_lowercase();
            lower.contains("cors") && lower.contains("credential")
        });

        let secret_findings: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                f.tags()
                    .iter()
                    .any(|t| t.as_ref() == "secret" || t.as_ref() == "keyhog")
            })
            .collect();

        if !has_cors_with_creds || secret_findings.is_empty() {
            return vec![];
        }

        let chain = Finding::builder(
            "correlation",
            secret_findings
                .first()
                .map(|f| f.target())
                .unwrap_or("unknown"),
            Severity::Critical,
        )
        .title("CORS Origin Reflection + JS Secrets = Credential Theft")
        .detail(format!(
            "CORS allows arbitrary origins with credentials AND {} secret(s) found              in JavaScript. An attacker on any domain can: (1) make authenticated              cross-origin requests to steal user session data, (2) access API endpoints              using the leaked credentials from JS. Combined, this enables full              account takeover without any user interaction beyond visiting a page.",
            secret_findings.len()
        ))
        .kind(FindingKind::Vulnerability)
        .tag("chain")
        .tag("cors")
        .tag("secret")
        .build_or_log();

        chain.into_iter().collect()
    }
}
