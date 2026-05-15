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

//! Cloud asset discovery scanner.
//!
//! Derives candidate bucket/account names from the target domain via the
//! Mozilla Public Suffix List, generates permutations, then probes every
//! registered [`CloudProvider`] in parallel.
//!
//! # Adding a new cloud provider
//! 1. Create `src/{provider}.rs` and implement [`CloudProvider`].
//! 2. Add it to the `providers()` constructor in this file — the only change needed.

pub mod azure;
pub mod common;
pub mod do_spaces;
pub mod gcs;
pub mod inside_out;
pub mod permutations;
pub mod provider;
pub mod s3;
// AWS-service-specific probes implementing `provider::CloudProvider`.
// These were committed as orphan files (no `mod` declaration) when
// the workspace was last reorganised; re-exporting so the integration
// test in `tests/test_cloud_adversarial_network.rs` can drive each
// provider's adversarial-network behaviour directly. Each module is
// safe to import independently.
pub mod apigateway;
pub mod cloudfront;
pub mod lambda;

#[cfg(test)]
mod integration_tests;

use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{Config, ScanClient, ScanInput, Scanner, Target};
use secfinding::{Finding, FindingBuilder, Severity};

use common::make_target;
use provider::CloudProvider;
/// Cloud storage asset scanner — discovers open buckets and containers.
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
        .kind(secfinding::FindingKind::Exposure)
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

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        // SSRF Protection: Early exit on metadata service and private IPs
        if is_ssrf_protected_target(&input.seed) {
            tracing::warn!("SSRF protection triggered for seed: {}", input.seed);
            return Ok(());
        }

        // Drain inbound targets up-front. Cloud bucket-permutation
        // and inside-out discovery both need the full domain set to
        // deduplicate org names + seed the AWS API enumeration; this
        // is not the kind of stage that benefits from incremental
        // processing.
        let (inbound, has_ssrf_targets): (Vec<Target>, bool) = {
            let mut rx = input.target_rx.lock().await;
            let mut buf = Vec::new();
            let mut ssrf_detected = false;
            while let Ok(t) = rx.try_recv() {
                // SSRF Protection: Filter out metadata service and private IPs
                if !is_ssrf_protected_target_obj(&t) {
                    buf.push(t);
                } else {
                    tracing::warn!("SSRF protection triggered for target: {:?}", t);
                    ssrf_detected = true;
                }
            }
            (buf, ssrf_detected)
        };

        #[cfg(feature = "cloud")]
        {
            // Inside-Out Discovery: use credentials to find unmapped
            // assets (S3, EC2, Route53, RDS). Emits directly via
            // input.emit_target — no separate buffer parameter.
            // Skip if we detected SSRF-protected targets to avoid hanging.
            if !has_ssrf_targets {
                if let Err(e) = crate::inside_out::discover_aws(&input).await {
                    tracing::error!("AWS inside-out discovery failed: {}", e);
                }
            } else {
                tracing::warn!("Skipping AWS inside-out discovery due to SSRF protection");
            }
        }

        // Cloud scanner never follows redirects (we need exact 3xx/403 status codes)
        let client = ScanClient::from_config_no_redirect(config, Arc::clone(&input.resolver))?;

        // Derive unique org names from all targets using the PSL
        let mut org_names: Vec<String> = inbound
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

        // Early exit if we detected SSRF targets and have no inbound targets
        if has_ssrf_targets && inbound.is_empty() {
            tracing::info!("SSRF protection: All targets filtered out, exiting early");
            return Ok(());
        }

        // Early exit if no valid organizations to scan
        if org_names.is_empty() {
            tracing::info!("No valid organizations to scan, exiting early");
            return Ok(());
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

            for f in findings {
                input.emit(f);
            }
        }

        Ok(())
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
mod ssrf_tests {
    use super::{is_ssrf_protected_ip, is_ssrf_protected_target};
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn aws_metadata_blocked() {
        assert!(is_ssrf_protected_ip(&ip("169.254.169.254")));
        assert!(is_ssrf_protected_target("169.254.169.254"));
        assert!(is_ssrf_protected_target("metadata.google.internal"));
    }

    #[test]
    fn rfc1918_blocked() {
        assert!(is_ssrf_protected_ip(&ip("10.0.0.1")));
        assert!(is_ssrf_protected_ip(&ip("10.255.255.255")));
        assert!(is_ssrf_protected_ip(&ip("172.16.0.1")));
        assert!(is_ssrf_protected_ip(&ip("172.31.255.255")));
        assert!(is_ssrf_protected_ip(&ip("192.168.0.1")));
    }

    #[test]
    fn loopback_blocked() {
        assert!(is_ssrf_protected_ip(&ip("127.0.0.1")));
        assert!(is_ssrf_protected_ip(&ip("127.255.255.254")));
    }

    #[test]
    fn link_local_blocked() {
        assert!(is_ssrf_protected_ip(&ip("169.254.0.1")));
        assert!(is_ssrf_protected_ip(&ip("169.254.255.254")));
    }

    #[test]
    fn ipv6_loopback_and_link_local_blocked() {
        assert!(is_ssrf_protected_ip(&ip("::1")));
        assert!(is_ssrf_protected_ip(&ip("fe80::1")));
        assert!(is_ssrf_protected_ip(&ip("fe80::dead:beef")));
    }

    #[test]
    fn public_ips_allowed() {
        assert!(!is_ssrf_protected_ip(&ip("1.1.1.1")));
        assert!(!is_ssrf_protected_ip(&ip("8.8.8.8")));
        assert!(!is_ssrf_protected_ip(&ip("172.32.0.1"))); // outside 172.16-31
        assert!(!is_ssrf_protected_ip(&ip("169.253.0.1"))); // adjacent /16
        assert!(!is_ssrf_protected_ip(&ip("2606:4700:4700::1111")));
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

/// Check if a string target (seed) should be blocked due to SSRF protection.
fn is_ssrf_protected_target(target: &str) -> bool {
    // Try to parse as IP address
    if let Ok(ip) = target.parse::<IpAddr>() {
        return is_ssrf_protected_ip(&ip);
    }

    // Check if it's a hostname that resolves to a protected IP
    // For simplicity, check known metadata service hostname patterns
    if target == "metadata.google.internal" || target == "169.254.169.254" {
        return true;
    }

    false
}

/// Check if a Target object should be blocked due to SSRF protection.
fn is_ssrf_protected_target_obj(target: &Target) -> bool {
    match target {
        Target::Host(host_target) => is_ssrf_protected_ip(&host_target.ip),
        Target::Domain(domain_target) => is_ssrf_protected_target(&domain_target.domain),
        _ => false,
    }
}

/// Check if an IP address should be blocked due to SSRF protection.
fn is_ssrf_protected_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // AWS metadata service
            if octets == [169, 254, 169, 254] {
                return true;
            }
            // RFC1918 private ranges
            if octets[0] == 10 {
                return true;
            }
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // Loopback
            if octets[0] == 127 {
                return true;
            }
            // Link-local (169.254.0.0/16)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
        }
        IpAddr::V6(ipv6) => {
            // IPv6 loopback
            if *ipv6 == std::net::Ipv6Addr::LOCALHOST {
                return true;
            }
            // IPv6 link-local (fe80::/10)
            let segments = ipv6.segments();
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
        }
    }
    false
}
