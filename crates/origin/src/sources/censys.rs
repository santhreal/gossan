//! Censys host search for origin IP discovery.
//!
//! Queries Censys v2 hosts API for historical A records and certificates
//! tied to the target domain. Requires Censys API ID + Secret.

use crate::util::{bounded_json, is_routable_ip};
use crate::OriginCandidate;
use gossan_core::{Config, ScanClient};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// Scan Censys for origin candidates.
pub async fn scan(domain: &str, config: &Config, client: &ScanClient) -> anyhow::Result<Vec<OriginCandidate>> {
    let api_id = match config.api_keys.get("censys_id") {
        Some(k) => k,
        None => {
            tracing::debug!(source = "censys", "skipping: no censys_id API key");
            return Ok(vec![]);
        }
    };
    let api_secret = match config.api_keys.get("censys_secret") {
        Some(k) => k,
        None => {
            tracing::debug!(source = "censys", "skipping: no censys_secret API key");
            return Ok(vec![]);
        }
    };

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    // 1. Certificate search — find IPs in certs for this domain
    let cert_url = format!(
        "https://search.censys.io/api/v2/certificates/search?q=names:{}&per_page=100",
        urlencoding::encode(domain)
    );

    let req = client
        .inner()
        .get(&cert_url)
        .basic_auth(api_id, Some(api_secret))
        .build()?;

    match client.execute(req).await {
        Ok(resp) => {
            if resp.status().is_success() {
                let limit = config.max_response_size.min(10 * 1024 * 1024);
                if let Ok(json) = bounded_json::<serde_json::Value>(resp, limit).await {
                    if let Some(results) = json
                        .get("result")
                        .and_then(|r| r.get("hits"))
                        .and_then(|h| h.as_array())
                    {
                        for hit in results {
                            if let Some(ips) = hit.get("ip").and_then(|v| v.as_str()) {
                                if let Ok(ip) = IpAddr::from_str(ips) {
                                    if is_routable_ip(ip) && seen.insert(ip) {
                                        candidates.push(OriginCandidate::new(
                                            ip,
                                            "censys_cert",
                                            75,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                tracing::warn!(source = "censys", status = %resp.status(), "Censys cert search failed");
            }
        }
        Err(e) => {
            tracing::warn!(source = "censys", error = %e, "Censys cert request failed");
        }
    }

    tokio::time::sleep(std::time::Duration::from_millis(config.host_delay_ms)).await;

    // 2. Host search — find hosts presenting this domain
    let host_url = format!(
        "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf.names:{}&per_page=100",
        urlencoding::encode(domain)
    );

    let req = client
        .inner()
        .get(&host_url)
        .basic_auth(api_id, Some(api_secret))
        .build()?;

    match client.execute(req).await {
        Ok(resp) => {
            if resp.status().is_success() {
                let limit = config.max_response_size.min(10 * 1024 * 1024);
                if let Ok(json) = bounded_json::<serde_json::Value>(resp, limit).await {
                    if let Some(results) = json
                        .get("result")
                        .and_then(|r| r.get("hits"))
                        .and_then(|h| h.as_array())
                    {
                        for hit in results {
                            if let Some(ip_str) = hit.get("ip").and_then(|v| v.as_str()) {
                                if let Ok(ip) = IpAddr::from_str(ip_str) {
                                    if is_routable_ip(ip) && seen.insert(ip) {
                                        candidates.push(OriginCandidate::new(
                                            ip,
                                            "censys_host_tls",
                                            80,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                tracing::warn!(source = "censys", status = %resp.status(), "Censys host search failed");
            }
        }
        Err(e) => {
            tracing::warn!(source = "censys", error = %e, "Censys host request failed");
        }
    }

    Ok(candidates)
}
