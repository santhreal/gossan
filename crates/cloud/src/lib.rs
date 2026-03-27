//! Cloud asset discovery scanner.
//!
//! Derives candidate bucket/account names from the target domain via the
//! Mozilla Public Suffix List, generates permutations, then probes every
//! registered [`CloudProvider`] in parallel.
//!
//! # Adding a new cloud provider
//! 1. Create `src/{provider}.rs` and implement [`CloudProvider`].
//! 2. Add it to [`providers()`] — that's the only change needed in this file.

extern crate self as reqwest;
pub use upstream_reqwest::{header, redirect, Client, Method, Proxy, Request, Response, StatusCode, Url};

mod azure;
mod common;
mod do_spaces;
mod gcs;
mod permutations;
mod provider;
mod s3;

use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{build_client, Config, ScanInput, ScanOutput, Scanner, Target};
use secfinding::{Finding, FindingBuilder, Severity};

use common::make_target;
use provider::CloudProvider;

pub struct CloudScanner;

pub(crate) fn finding_builder(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    Finding::builder("cloud", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
}

#[async_trait]
impl Scanner for CloudScanner {
    fn name(&self) -> &'static str {
        "cloud"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "cloud", "exposure"]
    }

    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Domain(_) | Target::Web(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();

        // Cloud scanner never follows redirects (we need exact 3xx/403 status codes)
        let client = build_client(config, false)?;

        // Derive unique org names from all targets using the PSL
        let mut org_names: Vec<String> = input
            .targets
            .iter()
            .filter(|t| self.accepts(t))
            .filter_map(|t| t.domain())
            .map(org_name)
            .filter(|n| !n.is_empty())
            .collect();
        org_names.dedup();

        let seed_org = org_name(&input.seed);
        if !seed_org.is_empty() && !org_names.contains(&seed_org) {
            org_names.push(seed_org);
        }

        let providers: Arc<Vec<Box<dyn CloudProvider>>> = Arc::new(providers());
        let seed_target = make_target(&input.seed);

        for org in &org_names {
            let candidates = permutations::generate(org);
            tracing::info!(
                org = %org,
                buckets = candidates.len(),
                "cloud scan — probing {} providers",
                providers.len()
            );

            let findings: Vec<Finding> = futures::stream::iter(candidates)
                .map(|name| {
                    let client = client.clone();
                    let target = seed_target.clone();
                    let providers = providers.clone();
                    async move {
                        let futs: Vec<_> = providers
                            .iter()
                            .map(|p| p.probe(&client, &name, &target))
                            .collect();
                        let results = futures::future::join_all(futs).await;
                        let mut f = Vec::new();
                        for (provider, result) in providers.iter().zip(results) {
                            match result {
                                Ok(v) => f.extend(v),
                                Err(e) => tracing::warn!(
                                    provider = provider.name(),
                                    bucket   = %name,
                                    err      = %e,
                                    "cloud probe error"
                                ),
                            }
                        }
                        f
                    }
                })
                .buffer_unordered(config.concurrency)
                .flat_map(futures::stream::iter)
                .collect()
                .await;

            out.findings.extend(findings);
        }

        Ok(out)
    }
}

/// Return all registered cloud storage providers.
///
/// To add a new provider: implement [`CloudProvider`] and append it here.
fn providers() -> Vec<Box<dyn CloudProvider>> {
    vec![
        Box::new(s3::S3Provider),
        Box::new(gcs::GcsProvider),
        Box::new(azure::AzureProvider),
        Box::new(do_spaces::DoSpacesProvider),
    ]
}

/// Extract the organisation name from a domain using the Mozilla Public Suffix List.
///
/// Examples:
/// - `"example.com"`        → `"example"`
/// - `"shop.example.co.uk"` → `"example"`
/// - `"api.example.com.br"` → `"example"`
/// - `"localhost"`           → `"localhost"`
fn org_name(input: &str) -> String {
    // Strip scheme and port
    let host = input
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/')
        .split(':')
        .next()
        .unwrap_or(input);

    if host.parse::<std::net::IpAddr>().is_ok() {
        return host.to_lowercase();
    }

    // Use PSL to find the registrable domain
    if let Some(domain) = psl::domain(host.as_bytes()) {
        // domain.as_bytes() = "example.co.uk" — first label is always the org name
        let registrable = std::str::from_utf8(domain.as_bytes()).unwrap_or(host);
        registrable.split('.').next().unwrap_or(host).to_lowercase()
    } else {
        // IP address, localhost, or unrecognised TLD — use first label as-is
        host.split('.').next().unwrap_or(host).to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::{org_name, providers};

    #[test]
    fn simple() {
        assert_eq!(org_name("example.com"), "example");
    }
    #[test]
    fn subdomain() {
        assert_eq!(org_name("sub.example.com"), "example");
    }
    #[test]
    fn co_uk() {
        assert_eq!(org_name("shop.example.co.uk"), "example");
    }
    #[test]
    fn com_br() {
        assert_eq!(org_name("api.example.com.br"), "example");
    }
    #[test]
    fn gov_au() {
        assert_eq!(org_name("www.agency.gov.au"), "agency");
    }
    #[test]
    fn https_scheme() {
        assert_eq!(org_name("https://example.com"), "example");
    }
    #[test]
    fn with_port() {
        assert_eq!(org_name("example.com:8080"), "example");
    }
    #[test]
    fn localhost() {
        assert_eq!(org_name("localhost"), "localhost");
    }
    #[test]
    fn deep_sub() {
        assert_eq!(org_name("a.b.c.example.io"), "example");
    }
    #[test]
    fn ip_address() {
        assert_eq!(org_name("192.0.2.10"), "192.0.2.10");
    }
    #[test]
    fn hyphenated() {
        assert_eq!(org_name("cdn.example-site.com"), "example-site");
    }
    #[test]
    fn trailing_slash() {
        assert_eq!(org_name("https://example.com/"), "example");
    }
    #[test]
    fn providers_registered() {
        assert_eq!(providers().len(), 4);
    }
}
