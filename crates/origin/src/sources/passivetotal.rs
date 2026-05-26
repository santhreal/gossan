//! RiskIQ PassiveTotal historical DNS and subdomain enrichment.
//!
//! Queries PassiveTotal for historical A records and discovered subdomains.
//! Requires a PassiveTotal username and API key.

use crate::util::{bounded_json, is_routable_ip};
use crate::OriginCandidate;
use base64::Engine as _;
use gossan_core::{Config, ScanClient};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// Scan PassiveTotal for origin candidates.
pub async fn scan(
    domain: &str,
    config: &Config,
    client: &ScanClient,
) -> anyhow::Result<Vec<OriginCandidate>> {
    let username = match config.api_keys.get("passivetotal_user") {
        Some(k) => k,
        None => {
            tracing::debug!(
                source = "passivetotal",
                "skipping: no passivetotal_user API key"
            );
            return Ok(vec![]);
        }
    };
    let api_key = match config.api_keys.get("passivetotal_key") {
        Some(k) => k,
        None => {
            tracing::debug!(
                source = "passivetotal",
                "skipping: no passivetotal_key API key"
            );
            return Ok(vec![]);
        }
    };

    let auth =
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", username, api_key));

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    // 1. DNS history
    let history_url = format!(
        "https://api.passivetotal.org/v2/dns/history/{}",
        urlencoding::encode(domain)
    );

    let req = client
        .inner()
        .get(&history_url)
        .header("Authorization", format!("Basic {}", auth))
        .build()?;

    match client.execute(req).await {
        Ok(resp) => {
            if resp.status().is_success() {
                let limit = config.max_response_size.min(10 * 1024 * 1024);
                if let Ok(json) = bounded_json::<serde_json::Value>(resp, limit).await {
                    if let Some(records) = json.get("results").and_then(|v| v.as_array()) {
                        for record in records {
                            if let Some(resolve) = record.get("resolve") {
                                if let Some(ip_str) = resolve.as_str() {
                                    if let Ok(ip) = IpAddr::from_str(ip_str) {
                                        if is_routable_ip(ip) && seen.insert(ip) {
                                            candidates.push(OriginCandidate::new(
                                                ip,
                                                "passivetotal_dns_history",
                                                85,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                tracing::warn!(source = "passivetotal", status = %resp.status(), "PassiveTotal DNS history failed");
            }
        }
        Err(e) => {
            tracing::warn!(source = "passivetotal", error = %e, "PassiveTotal DNS history request failed");
        }
    }

    tokio::time::sleep(std::time::Duration::from_millis(config.host_delay_ms)).await;

    // 2. Subdomain enrichment — resolve each subdomain.
    let sub_url = format!(
        "https://api.passivetotal.org/v2/enrichment/subdomains/{}",
        urlencoding::encode(domain)
    );

    let req = client
        .inner()
        .get(&sub_url)
        .header("Authorization", format!("Basic {}", auth))
        .build()?;

    match client.execute(req).await {
        Ok(resp) => {
            if resp.status().is_success() {
                let limit = config.max_response_size.min(10 * 1024 * 1024);
                if let Ok(json) = bounded_json::<serde_json::Value>(resp, limit).await {
                    if let Some(subs) = json.get("subdomains").and_then(|v| v.as_array()) {
                        let resolver = hickory_resolver::TokioResolver::builder_with_config(
                            hickory_resolver::config::ResolverConfig::default(),
                            hickory_resolver::name_server::TokioConnectionProvider::default(),
                        )
                        .with_options(hickory_resolver::config::ResolverOpts::default())
                        .build();
                        for sub_val in subs {
                            if let Some(sub) = sub_val.as_str() {
                                let fqdn = format!("{}.{}", sub, domain);
                                if let Ok(lookup) = resolver.ipv4_lookup(&fqdn).await {
                                    for ip in lookup {
                                        let addr = IpAddr::V4(ip.0);
                                        if is_routable_ip(addr) && seen.insert(addr) {
                                            candidates.push(OriginCandidate::new(
                                                addr,
                                                format!("passivetotal_subdomain ({fqdn})"),
                                                70,
                                            ));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                tracing::warn!(source = "passivetotal", status = %resp.status(), "PassiveTotal subdomain enrichment failed");
            }
        }
        Err(e) => {
            tracing::warn!(source = "passivetotal", error = %e, "PassiveTotal subdomain request failed");
        }
    }

    Ok(candidates)
}
