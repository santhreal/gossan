#![forbid(unsafe_code)]
// pedantic moved to workspace [lints.clippy] in root Cargo.toml
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

//! Cross-module finding correlation engine.
//!
//! Runs after all scanner stages complete. Applies a set of [`CorrelationRule`]s
//! that look for patterns spanning multiple scanners — e.g., SSRF + Redis, or
//! source-code exposure + hardcoded secrets — and emits new **chain findings**.
//!
//! # Adding a new rule
//! 1. Create `src/rules/{rule}.rs` and implement [`CorrelationRule`].
//! 2. Register it in [`CorrelationEngine::default()`].
//!    That's the only change needed.

pub mod confidence;
pub mod dedup;
pub mod relationship;
mod rules;
mod utils;

use gossan_core::Target;
#[allow(unused_imports)] // Severity is used by tests via `use super::*`
use secfinding::{Finding, Severity};

pub use rules::{
    AdminExposedRule, ApiAuthRule, CorsSecretChainRule, DebugRceRule, ShadowInfrastructureRule,
    SourceCodeSecretsRule, SsrfInternalRule, TlsWeaknessRule, WildcardTakeoverRule,
};

/// A correlation rule inspects the full finding + target set and returns
/// zero or more new "chain" findings.
pub trait CorrelationRule: Send + Sync {
    /// Short identifier for logging.
    fn name(&self) -> &'static str;
    /// Analyse findings and targets; return any newly synthesised chain findings.
    fn check(&self, findings: &[Finding], targets: &[Target]) -> Vec<Finding>;
}

/// The correlation engine holds an ordered list of rules and runs them all.
pub struct CorrelationEngine {
    rules: Vec<Box<dyn CorrelationRule>>,
}

impl CorrelationEngine {
    /// Construct an engine with all built-in rules registered.
    ///
    /// Includes 9 cross-finding correlation rules:
    /// TLS weakness, AdminExposed, ApiAuth, SsrfInternal,
    /// SourceCodeSecrets, ShadowInfrastructure, WildcardTakeover,
    /// DebugRce, CorsSecretChain.
    pub fn new() -> Self {
        Self {
            rules: vec![
                Box::new(TlsWeaknessRule),
                Box::new(AdminExposedRule),
                Box::new(ApiAuthRule),
                Box::new(SsrfInternalRule),
                Box::new(SourceCodeSecretsRule),
                Box::new(ShadowInfrastructureRule),
                Box::new(WildcardTakeoverRule),
                Box::new(DebugRceRule),
                Box::new(CorsSecretChainRule),
            ],
        }
    }

    /// Run all rules against the completed scan results.
    /// Returns a (potentially empty) list of new chain findings.
    pub fn run(&self, findings: &[Finding], targets: &[Target]) -> Vec<Finding> {
        let mut chains = Vec::new();
        for rule in &self.rules {
            let new = rule.check(findings, targets);
            if !new.is_empty() {
                tracing::info!(
                    rule = rule.name(),
                    count = new.len(),
                    "correlation rule fired"
                );
            }
            chains.extend(new);
        }
        chains
    }
}

impl Default for CorrelationEngine {
    fn default() -> Self {
        Self::new()
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

    /// Same as `finding()` but with one extra tag pre-applied. Replaces
    /// the previous `v1.tags.push(...)` mutation that no longer
    /// compiles since `Finding.tags` became a private field with no
    /// public mutator.
    fn finding_with_tag(scanner: &str, target: &str, title: &str, tag: &str) -> Finding {
        Finding::builder(scanner, target, Severity::High)
            .title(title)
            .tag(tag)
            .build()
            .expect("finding builder: required fields are set")
    }

    #[test]
    fn engine_empty_input_produces_no_chains() {
        let engine = CorrelationEngine::new();
        assert!(engine.run(&[], &[]).is_empty());
    }

    #[test]
    fn correlation_engine_runs_all_rules() {
        let engine = CorrelationEngine::new();
        assert_eq!(engine.rules.len(), 9, "all 9 rules should be registered");
    }

    #[test]
    fn engine_returns_tls_chain_when_multiple_tls_issues_exist() {
        let engine = CorrelationEngine::new();
        let findings = vec![
            finding("portscan", "example.com", "Self-signed TLS certificate"),
            finding("hidden", "example.com", "Missing HSTS header"),
        ];
        let chains = engine.run(&findings, &[]);
        assert!(chains
            .iter()
            .any(|f| f.title().contains("Multiple TLS weaknesses")));
    }

    #[test]
    fn engine_returns_admin_chain_when_admin_and_auth_findings_align() {
        let engine = CorrelationEngine::new();
        let findings = vec![
            finding("hidden", "admin.example.com", "Admin panel exposed"),
            finding("hidden", "admin.example.com", "No authentication required"),
        ];
        let chains = engine.run(&findings, &[]);
        assert!(chains.iter().any(|f| f
            .title()
            .contains("Admin panel exposed without authentication")));
    }

    #[test]
    fn engine_returns_api_auth_chain() {
        let engine = CorrelationEngine::new();
        // Pre-tag instead of mutating after build (Finding.tags is now private).
        let v1 = finding_with_tag(
            "hidden",
            "api.example.com",
            "API version enumeration",
            "api-version",
        );
        let auth = finding("hidden", "api.example.com", "No authentication required");

        let chains = engine.run(&[v1, auth], &[]);
        assert!(chains
            .iter()
            .any(|f| f.title().contains("Unauthenticated legacy API")));
    }
}
