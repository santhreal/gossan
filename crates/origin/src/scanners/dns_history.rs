//! DNS history scanner.
//!
//! Queries public DNS history services to find old A records from
//! before the domain was moved behind a CDN. The pre-CDN IP is
//! almost certainly the origin server.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::util::{bounded_json, bounded_text, is_routable_ip};
use crate::OriginCandidate;
use gossan_core::{Config, ScanClient};

/// Query SecurityTrails API for historical DNS A records.
/// Requires a SecurityTrails API key (free tier available: 50 queries/month).
async fn query_securitytrails(
    domain: &str,
    api_key: &str,
    client: &ScanClient,
    limit: usize,
) -> anyhow::Result<Vec<(IpAddr, String)>> {
    let url = format!("https://api.securitytrails.com/v1/history/{}/dns/a", domain);

    let req = client.inner().get(&url).header("APIKEY", api_key).build()?;

    let response = client.execute(req).await?;

    if !response.status().is_success() {
        tracing::warn!(
            scanner = "dns_history",
            source = "securitytrails",
            status = %response.status(),
            "SecurityTrails query failed"
        );
        return Ok(Vec::new());
    }

    let body: serde_json::Value = bounded_json(response, limit).await?;
    let mut results = Vec::new();

    if let Some(records) = body.get("records").and_then(|r| r.as_array()) {
        for record in records {
            if let Some(values) = record.get("values").and_then(|v| v.as_array()) {
                for value in values {
                    if let Some(ip_str) = value.get("ip").and_then(|v| v.as_str()) {
                        if let Ok(ip) = IpAddr::from_str(ip_str) {
                            let first_seen = record
                                .get("first_seen")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            results
                                .push((ip, format!("securitytrails (first_seen: {})", first_seen)));
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Query ViewDNS.info for historical DNS records (free, no API key for basic usage).
async fn query_viewdns(
    domain: &str,
    client: &ScanClient,
    limit: usize,
) -> anyhow::Result<Vec<(IpAddr, String)>> {
    let url = format!(
        "https://viewdns.info/iphistory/?domain={}",
        urlencoding::encode(domain)
    );

    let response = match client.get(&url).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(scanner = "dns_history", source = "viewdns", error = %e, "request failed");
            return Ok(Vec::new());
        }
    };

    if !response.status().is_success() {
        return Ok(Vec::new());
    }

    let body = bounded_text(response, limit).await.unwrap_or_default();
    let mut results = Vec::new();

    // Parse IP addresses from the HTML table.
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.contains("<td>") {
            // Use a more robust substring extraction than naive replace.
            let start = trimmed.find("<td>").map(|i| i + 4);
            let end = trimmed.find("</td>");
            if let (Some(s), Some(e)) = (start, end) {
                if e > s {
                    let clean = trimmed[s..e].trim();
                    if let Ok(ip) = IpAddr::from_str(clean) {
                        results.push((ip, "viewdns_ip_history".to_string()));
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Scan DNS history services for the domain's pre-CDN IP addresses.
pub async fn scan(
    domain: String,
    config: &Config,
    client: &ScanClient,
) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut candidates = Vec::new();
    let mut seen_ips = HashSet::new();

    let limit = config.max_response_size.min(10 * 1024 * 1024).max(1024);

    // Query SecurityTrails if API key is available.
    if let Some(api_key) = config.api_keys.get("securitytrails") {
        match query_securitytrails(&domain, api_key, client, limit).await {
            Ok(results) => {
                for (ip, source) in results {
                    if is_routable_ip(ip) && seen_ips.insert(ip) {
                        candidates.push(OriginCandidate::new(
                            ip,
                            format!("dns_history_{}", source),
                            90,
                        ));
                    }
                }
            }
            Err(e) => {
                tracing::warn!(scanner = "dns_history", error = %e, "SecurityTrails query error");
            }
        }
    }

    // Query ViewDNS (no API key required).
    match query_viewdns(&domain, client, limit).await {
        Ok(results) => {
            for (ip, source) in results {
                if is_routable_ip(ip) && seen_ips.insert(ip) {
                    candidates.push(OriginCandidate::new(
                        ip,
                        format!("dns_history_{}", source),
                        85,
                    ));
                }
            }
        }
        Err(e) => {
            tracing::warn!(scanner = "dns_history", error = %e, "ViewDNS query error");
        }
    }

    Ok(candidates)
}
