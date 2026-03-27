//! DNS history scanner.
//!
//! Queries public DNS history services to find old A records from
//! before the domain was moved behind a CDN. The pre-CDN IP is
//! almost certainly the origin server.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::OriginCandidate;

/// Query SecurityTrails API for historical DNS A records.
/// Requires a SecurityTrails API key (free tier available: 50 queries/month).
async fn query_securitytrails(
    domain: &str,
    api_key: &str,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<(IpAddr, String)>> {
    let url = format!("https://api.securitytrails.com/v1/history/{}/dns/a", domain);

    let response = client.get(&url).header("APIKEY", api_key).send().await?;

    if !response.status().is_success() {
        tracing::warn!(
            scanner = "dns_history",
            source = "securitytrails",
            status = %response.status(),
            "SecurityTrails query failed"
        );
        return Ok(Vec::new());
    }

    let body: serde_json::Value = response.json().await?;
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
    client: &reqwest::Client,
) -> anyhow::Result<Vec<(IpAddr, String)>> {
    let url = format!(
        "https://viewdns.info/iphistory/?domain={}",
        urlencoding::encode(domain)
    );

    let response = match client
        .get(&url)
        .header("User-Agent", "Mozilla/5.0")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(scanner = "dns_history", source = "viewdns", error = %e, "request failed");
            return Ok(Vec::new());
        }
    };

    if !response.status().is_success() {
        return Ok(Vec::new());
    }

    let body = response.text().await.unwrap_or_default();
    let mut results = Vec::new();

    // Parse IP addresses from the HTML table. ViewDNS returns a simple HTML page
    // with a table containing IP history. We extract IPs with a simple regex-free scan.
    for line in body.lines() {
        let trimmed = line.trim();
        // Look for table cells containing IP-like strings.
        if trimmed.contains("<td>") {
            let stripped = trimmed.replace("<td>", "").replace("</td>", "");
            let clean = stripped.trim();
            if let Ok(ip) = IpAddr::from_str(clean) {
                results.push((ip, "viewdns_ip_history".to_string()));
            }
        }
    }

    Ok(results)
}

/// Scan DNS history services for the domain's pre-CDN IP addresses.
pub async fn scan(
    domain: String,
    securitytrails_key: Option<&str>,
) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut candidates = Vec::new();
    let mut seen_ips = HashSet::new();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    // Query SecurityTrails if API key is available.
    if let Some(api_key) = securitytrails_key {
        match query_securitytrails(&domain, api_key, &client).await {
            Ok(results) => {
                for (ip, source) in results {
                    if seen_ips.insert(ip) {
                        candidates.push(OriginCandidate {
                            ip,
                            method: format!("dns_history_{}", source),
                            confidence: 90, // Historical A records are very high confidence.
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!(scanner = "dns_history", error = %e, "SecurityTrails query error");
            }
        }
    }

    // Query ViewDNS (no API key required).
    match query_viewdns(&domain, &client).await {
        Ok(results) => {
            for (ip, source) in results {
                if seen_ips.insert(ip) {
                    candidates.push(OriginCandidate {
                        ip,
                        method: format!("dns_history_{}", source),
                        confidence: 85,
                    });
                }
            }
        }
        Err(e) => {
            tracing::warn!(scanner = "dns_history", error = %e, "ViewDNS query error");
        }
    }

    Ok(candidates)
}
