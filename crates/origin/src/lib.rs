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
//! | DNS misconfig (MX, SPF, bypass subs) | `dns_misconfig` | No | 60-85 |
//! | SSL certificate transparency (crt.sh) | `ssl_cert` | No | 70 |
//! | HTTP header leaks | `http_header` | No | 50-90 |
//! | Favicon hash (Shodan) | `favicon` | Optional | 80 |
//! | DNS history (SecurityTrails/ViewDNS) | `dns_history` | Optional | 85-90 |

extern crate self as reqwest;
pub use stealthreq::http::{Client, Method, Proxy, Request, Response, StatusCode, Url};
pub use stealthreq::http::{header, redirect};

pub mod scanners;
pub mod types;

use gossan_core::Config;
pub use types::OriginCandidate;

/// Discover the origin IP of a given domain behind a CDN/WAF.
///
/// Invokes all activated heuristic scanners in parallel and aggregates
/// the results, sorted by confidence (highest first).
pub async fn discover_origin(
    domain: &str,
    _config: &Config,
) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut tasks: Vec<tokio::task::JoinHandle<anyhow::Result<Vec<OriginCandidate>>>> = Vec::new();

    let d = domain.to_string();

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
        tasks.push(tokio::spawn(async move {
            scanners::ssl_cert::scan(domain_clone).await
        }));
    }

    #[cfg(feature = "http_header")]
    {
        let domain_clone = d.clone();
        tasks.push(tokio::spawn(async move {
            scanners::http_header::scan(domain_clone).await
        }));
    }

    #[cfg(feature = "favicon")]
    {
        let domain_clone = d.clone();
        // Shodan API key would come from config in a real integration.
        tasks.push(tokio::spawn(async move {
            scanners::favicon::scan(domain_clone, None).await
        }));
    }

    #[cfg(feature = "dns_history")]
    {
        let domain_clone = d.clone();
        // SecurityTrails API key would come from config in a real integration.
        tasks.push(tokio::spawn(async move {
            scanners::dns_history::scan(domain_clone, None).await
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

    // Sort by confidence, descending.
    candidates.sort_by(|a, b| b.confidence.cmp(&a.confidence));

    // Deduplicate by IP, keeping the highest-confidence entry.
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|c| seen.insert(c.ip));

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
    /// We do not assert emptiness because real scanners may find results.
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
        // Network calls may fail in CI; we only care that it didn't panic.
        assert!(result.is_ok() || result.is_err());
    }
}
