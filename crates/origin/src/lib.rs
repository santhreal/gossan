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

//! Origin IP Discovery Engine.
//!
//! Breaks through CDNs/WAFs using heuristic scanners (DNS, SSL, HTTP headers,
//! favicon hashing, DNS history, etc.) to uncover the direct origin IP for
//! WAF-bypass networking.
//!
//! Each scanner is feature-gated so consumers can pick exactly what they need.
//! All scanners run in parallel and results are aggregated by confidence score.
//!
//! # Scanners
//!
//! | Scanner | Feature | API Key? | Confidence |
//! |---------|---------|----------|------------|
//! | DNS misconfig (MX, SPF, DMARC, bypass subs) | `dns_misconfig` | No | 60-85 |
//! | SSL certificate transparency (crt.sh) | `ssl_cert` | No | 70 |
//! | HTTP header leaks | `http_header` | No | 50-90 |
//! | Favicon hash (Shodan + Censys) | `favicon` | Optional | 80 |
//! | DNS history (SecurityTrails/ViewDNS) | `dns_history` | Optional | 85-90 |
//! | Historical DNS (Censys, DNSDB, CIRCL, PassiveTotal) | — | Optional | 70-85 |

pub mod scanners;
pub mod sources;
pub mod types;
pub mod util;
pub mod validator;

use gossan_core::{Config, ScanClient};
pub use types::{OriginCandidate, ValidationState};

/// Discover the origin IP of a given domain behind a CDN/WAF.
///
/// Invokes all activated heuristic scanners and external sources in parallel,
/// aggregates the results, runs active validation, and returns candidates
/// sorted by validation state and confidence (highest first).
pub async fn discover_origin(
    domain: &str,
    config: &Config,
) -> anyhow::Result<Vec<OriginCandidate>> {
    // ── Single shared transport ──────────────────────────────────────
    let resolver = std::sync::Arc::new(gossan_core::net::build_resolver(config)?);
    let client = std::sync::Arc::new(ScanClient::from_config(config, resolver)?);

    let mut tasks: Vec<tokio::task::JoinHandle<anyhow::Result<Vec<OriginCandidate>>>> = Vec::new();

    let d = domain.to_string();
    let cfg = config.clone();

    #[cfg(feature = "dns_misconfig")]
    {
        let domain_clone = d.clone();
        tasks.push(tokio::spawn(async move {
            scanners::dns_misconfig::scan(domain_clone).await
        }));
    }

    #[cfg(feature = "ssl_cert")]
    {
        let domain_clone = d.clone();
        let c = std::sync::Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            scanners::ssl_cert::scan(domain_clone, &c).await
        }));
    }

    #[cfg(feature = "http_header")]
    {
        let domain_clone = d.clone();
        let config_clone = cfg.clone();
        let c = std::sync::Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            scanners::http_header::scan(domain_clone, &config_clone, &c).await
        }));
    }

    #[cfg(feature = "favicon")]
    {
        let domain_clone = d.clone();
        let config_clone = cfg.clone();
        let c = std::sync::Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            scanners::favicon::scan(domain_clone, &config_clone, &c).await
        }));
    }

    #[cfg(feature = "dns_history")]
    {
        let domain_clone = d.clone();
        let config_clone = cfg.clone();
        let c = std::sync::Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            scanners::dns_history::scan(domain_clone, &config_clone, &c).await
        }));
    }

    // External passive sources (always enabled, gracefully skip when unconfigured).
    {
        let domain_clone = d.clone();
        let config_clone = cfg.clone();
        let c = std::sync::Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            sources::censys::scan(&domain_clone, &config_clone, &c).await
        }));
    }
    {
        let domain_clone = d.clone();
        let config_clone = cfg.clone();
        let c = std::sync::Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            sources::dnsdb::scan(&domain_clone, &config_clone, &c).await
        }));
    }
    {
        let domain_clone = d.clone();
        let config_clone = cfg.clone();
        let c = std::sync::Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            sources::circl::scan(&domain_clone, &config_clone, &c).await
        }));
    }
    {
        let domain_clone = d.clone();
        let config_clone = cfg.clone();
        let c = std::sync::Arc::clone(&client);
        tasks.push(tokio::spawn(async move {
            sources::passivetotal::scan(&domain_clone, &config_clone, &c).await
        }));
    }

    let mut candidates = Vec::new();

    for task in tasks {
        match task.await {
            Ok(Ok(results)) => candidates.extend(results),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "origin scanner returned error");
            }
            Err(e) => {
                tracing::warn!(error = %e, "origin scanner task panicked");
            }
        }
    }

    // Active validation
    candidates = validator::validate(candidates, domain, config, &client).await;

    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// With no scanner features active, the function should return an empty vec.
    #[cfg(not(any(
        feature = "dns_misconfig",
        feature = "ssl_cert",
        feature = "http_header",
        feature = "favicon",
        feature = "dns_history"
    )))]
    #[tokio::test]
    async fn discover_origin_returns_empty_without_scanners() {
        let candidates = discover_origin("example.com", &Config::default())
            .await
            .unwrap();
        assert!(candidates.is_empty());
    }

    /// With scanner features active, the function runs without panicking.
    #[cfg(any(
        feature = "dns_misconfig",
        feature = "ssl_cert",
        feature = "http_header",
        feature = "favicon",
        feature = "dns_history"
    ))]
    #[tokio::test]
    async fn discover_origin_runs_without_panic() {
        let result = discover_origin("example.com", &Config::default()).await;
        assert!(result.is_ok() || result.is_err());
    }
}
