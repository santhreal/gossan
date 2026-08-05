//! RiskIQ PassiveTotal historical DNS and subdomain enrichment.
//!
//! Queries PassiveTotal for historical A records and discovered subdomains.
//! Requires a PassiveTotal username and API key.

use crate::util::{bounded_json, is_routable_ip};
use crate::OriginCandidate;
use base64::Engine as _;
use futures::future::join_all;
use gossan_core::{Config, ScanClient};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// Maximum number of PassiveTotal subdomains to resolve per target.
const MAX_SUBDOMAIN_RESOLUTIONS: usize = 500;

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
                let limit = config.max_response_size.min(crate::MAX_ORIGIN_JSON_BYTES);
                match bounded_json::<serde_json::Value>(resp, limit).await {
                    Ok(json) => {
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
                    Err(e) => {
                        tracing::warn!(error = %e, "body/JSON read failed; skipping source response");
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

    // 2. Subdomain enrichment (resolve each subdomain).
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
                let limit = config.max_response_size.min(crate::MAX_ORIGIN_JSON_BYTES);
                match bounded_json::<serde_json::Value>(resp, limit).await {
                    Ok(json) => {
                        if let Some(subs) = json.get("subdomains").and_then(|v| v.as_array()) {
                            let resolver = hickory_resolver::TokioResolver::builder_with_config(
                                hickory_resolver::config::ResolverConfig::default(),
                                hickory_resolver::name_server::TokioConnectionProvider::default(),
                            )
                            .with_options(hickory_resolver::config::ResolverOpts::default())
                            .build();

                            let to_resolve: Vec<String> = subs
                                .iter()
                                .take(MAX_SUBDOMAIN_RESOLUTIONS)
                                .filter_map(|sub_val| {
                                    sub_val
                                        .as_str()
                                        .map(|sub| format!("{}.{}", sub, domain))
                                })
                                .collect();

                            let lookups: Vec<_> = to_resolve
                                .iter()
                                .map(|fqdn| {
                                    let resolver = resolver.clone();
                                    let fqdn = fqdn.clone();
                                    async move {
                                        match resolver.ipv4_lookup(&fqdn).await {
                                            Ok(lookup) => Some(lookup),
                                            Err(e) => {
                                                if !(e.is_nx_domain() || e.is_no_records_found()) {
                                                    tracing::warn!(
                                                        fqdn = %fqdn,
                                                        error = %e,
                                                        "passivetotal subdomain A lookup failed; skipping"
                                                    );
                                                }
                                                None
                                            }
                                        }
                                    }
                                })
                                .collect();

                            for (fqdn, lookup) in to_resolve
                                .into_iter()
                                .zip(join_all(lookups).await)
                            {
                                if let Some(lookup) = lookup {
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
                    Err(e) => {
                        tracing::warn!(error = %e, "body/JSON read failed; skipping source response");
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
