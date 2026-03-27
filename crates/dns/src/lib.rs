//! DNS security scanner — modular, feature-gated auditing engine.
//!
//! Four independent modules, each compilable in isolation via Cargo features:
//!
//! | Feature     | Module       | What it checks |
//! |-------------|-------------|----------------|
//! | `email`     | [`email`]   | SPF (recursive include resolution), DMARC (policy + report URI), DKIM (13 selectors) |
//! | `axfr`      | [`axfr`]    | Zone transfer over raw DNS-over-TCP wire protocol |
//! | `takeover`  | [`takeover`]| Dangling CNAME → 60+ service fingerprints |
//! | `posture`   | [`posture`] | CAA cert restrictions, NS resilience, MX enumeration |
//!
//! # Quick start
//!
//! ```toml
//! # Everything (default)
//! gossan-dns = "0.2"
//!
//! # Just email authentication auditing
//! gossan-dns = { version = "0.2", default-features = false, features = ["email"] }
//! ```

#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "axfr")]
pub mod axfr;
#[cfg(feature = "takeover")]
pub mod takeover;
#[cfg(feature = "posture")]
pub mod posture;

mod resolver;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{Config, ScanInput, ScanOutput, Scanner, Target};
use secfinding::Finding;

pub use resolver::build_resolver;

/// DNS security scanner. Runs all enabled feature modules against each domain target.
pub struct DnsScanner;

#[async_trait]
impl Scanner for DnsScanner {
    fn name(&self) -> &'static str {
        "dns"
    }
    fn tags(&self) -> &'static [&'static str] {
        &["active", "dns", "email"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Domain(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();
        let dns = build_resolver(config)?;

        let owned: Vec<Target> = input
            .targets
            .into_iter()
            .filter(|t| self.accepts(t))
            .collect();

        let timeout = config.timeout();
        let proxy_opt = config.proxy.clone();

        let findings: Vec<Vec<Finding>> = futures::stream::iter(owned)
            .map(|target| {
                let dns = dns.clone();
                let proxy = proxy_opt.clone();
                async move {
                    let domain = target.domain().unwrap_or("").to_string();
                    audit_domain(&dns, &domain, &target, timeout, proxy.as_deref()).await
                }
            })
            .buffer_unordered(config.concurrency)
            .collect()
            .await;

        for batch in findings {
            out.findings.extend(batch);
        }
        Ok(out)
    }
}

/// Run all enabled modules against a single domain.
async fn audit_domain(
    dns: &hickory_resolver::TokioAsyncResolver,
    domain: &str,
    target: &Target,
    timeout: std::time::Duration,
    proxy: Option<&str>,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    #[cfg(feature = "axfr")]
    {
        findings.extend(axfr::check(dns, domain, target, timeout, proxy).await);
    }

    #[cfg(feature = "email")]
    {
        findings.extend(email::check(dns, domain, target).await);
    }

    #[cfg(feature = "posture")]
    {
        findings.extend(posture::check(dns, domain, target).await);
    }

    #[cfg(feature = "takeover")]
    {
        findings.extend(takeover::check(dns, domain, target).await);
    }

    findings
}
