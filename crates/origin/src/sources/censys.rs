//! Censys host search for origin IP discovery.
//!
//! Queries Censys v2 certificates + hosts APIs for IPs tied to the
//! target domain. Certificate search yields fingerprints (not IPs);
//! those fingerprints are resolved via the hosts API. Requires Censys
//! API ID + Secret.

use crate::util::{bounded_json, is_routable_ip};
use crate::OriginCandidate;
use gossan_core::{Config, ScanClient};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// Cap follow-up host lookups per certificate fingerprint to bound
/// API spend when a domain has a large cert corpus.
const MAX_CERT_FINGERPRINTS: usize = 10;

/// Scan Censys for origin candidates.
pub async fn scan(
    domain: &str,
    config: &Config,
    client: &ScanClient,
) -> anyhow::Result<Vec<OriginCandidate>> {
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

    // 1. Certificate search → fingerprints (certs have no root `ip` field).
    let cert_url = format!(
        "https://search.censys.io/api/v2/certificates/search?q=names:{}&per_page=100",
        urlencoding::encode(domain)
    );

    let mut fingerprints: Vec<String> = Vec::new();

    let req = client
        .inner()
        .get(&cert_url)
        .basic_auth(api_id, Some(api_secret))
        .build()?;

    match client.execute(req).await {
        Ok(resp) => {
            if resp.status().is_success() {
                let limit = config.max_response_size.min(crate::MAX_ORIGIN_JSON_BYTES);
                let json = bounded_json::<serde_json::Value>(resp, limit).await?;
                if let Some(results) = json
                    .get("result")
                    .and_then(|r| r.get("hits"))
                    .and_then(|h| h.as_array())
                {
                    for hit in results {
                        // Prefer explicit sha256 fingerprint fields used by Censys v2.
                        let fp = hit
                            .get("fingerprint_sha256")
                            .or_else(|| hit.get("parsed").and_then(|p| p.get("fingerprint_sha256")))
                            .and_then(|v| v.as_str());
                        if let Some(fp) = fp {
                            if fingerprints.len() < MAX_CERT_FINGERPRINTS
                                && !fingerprints.iter().any(|f| f == fp)
                            {
                                fingerprints.push(fp.to_string());
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

    // Resolve each cert fingerprint to hosts that present it.
    for fp in &fingerprints {
        tokio::time::sleep(std::time::Duration::from_millis(config.host_delay_ms)).await;

        let host_by_fp = format!(
            "https://search.censys.io/api/v2/hosts/search?q=services.tls.certificates.leaf.fingerprint:{}&per_page=100",
            urlencoding::encode(fp)
        );

        let req = client
            .inner()
            .get(&host_by_fp)
            .basic_auth(api_id, Some(api_secret))
            .build()?;

        match client.execute(req).await {
            Ok(resp) => {
                if resp.status().is_success() {
                    let limit = config.max_response_size.min(crate::MAX_ORIGIN_JSON_BYTES);
                    match bounded_json::<serde_json::Value>(resp, limit).await {
                        Ok(json) => {
                            collect_host_ips(
                                &json,
                                &mut candidates,
                                &mut seen,
                                "censys_cert_fp",
                                75,
                            );
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "body/JSON read failed; skipping source response");
                        }
                    }
                } else {
                    tracing::warn!(
                        source = "censys",
                        status = %resp.status(),
                        fingerprint = %fp,
                        "Censys host-by-fingerprint search failed"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    source = "censys",
                    error = %e,
                    fingerprint = %fp,
                    "Censys host-by-fingerprint request failed"
                );
            }
        }
    }

    tokio::time::sleep(std::time::Duration::from_millis(config.host_delay_ms)).await;

    // 2. Host search, find hosts presenting this domain on TLS.
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
                let limit = config.max_response_size.min(crate::MAX_ORIGIN_JSON_BYTES);
                let json = bounded_json::<serde_json::Value>(resp, limit).await?;
                collect_host_ips(&json, &mut candidates, &mut seen, "censys_host_tls", 80);
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

fn collect_host_ips(
    json: &serde_json::Value,
    candidates: &mut Vec<OriginCandidate>,
    seen: &mut HashSet<IpAddr>,
    source: &'static str,
    confidence: u8,
) {
    let Some(results) = json
        .get("result")
        .and_then(|r| r.get("hits"))
        .and_then(|h| h.as_array())
    else {
        return;
    };

    for hit in results {
        let Some(ip_str) = hit.get("ip").and_then(|v| v.as_str()) else {
            continue;
        };
        let Ok(ip) = IpAddr::from_str(ip_str) else {
            continue;
        };
        if is_routable_ip(ip) && seen.insert(ip) {
            candidates.push(OriginCandidate::new(ip, source, confidence));
        }
    }
}
