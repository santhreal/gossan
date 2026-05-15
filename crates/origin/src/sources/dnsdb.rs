//! Farsight DNSDB passive DNS.
//!
//! Queries DNSDB for historical A records associated with the target domain.
//! Requires a DNSDB API key.

use crate::util::{bounded_text, is_routable_ip};
use crate::OriginCandidate;
use gossan_core::{Config, ScanClient};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// Scan DNSDB for origin candidates.
pub async fn scan(domain: &str, config: &Config, client: &ScanClient) -> anyhow::Result<Vec<OriginCandidate>> {
    let api_key = match config.api_keys.get("dnsdb") {
        Some(k) => k,
        None => {
            tracing::debug!(source = "dnsdb", "skipping: no dnsdb API key");
            return Ok(vec![]);
        }
    };

    let url = format!(
        "https://api.dnsdb.info/lookup/rrset/name/{}/A",
        urlencoding::encode(domain)
    );

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    let req = client
        .inner()
        .get(&url)
        .header("X-API-Key", api_key)
        .header("Accept", "application/json")
        .build()?;

    match client.execute(req).await {
        Ok(resp) => {
            if resp.status().is_success() {
                let limit = config.max_response_size.min(10 * 1024 * 1024);
                // DNSDB NDJSON: one JSON object per line.
                let text = bounded_text(resp, limit).await.unwrap_or_default();
                for line in text.lines() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) {
                        if let Some(rdata) = obj.get("rdata").and_then(|v| v.as_array()) {
                            for entry in rdata {
                                if let Some(ip_str) = entry.as_str() {
                                    // DNSDB A records are quoted JSON strings: "1.2.3.4"
                                    let clean = ip_str.trim_matches('"');
                                    if let Ok(ip) = IpAddr::from_str(clean) {
                                        if is_routable_ip(ip) && seen.insert(ip) {
                                            candidates.push(OriginCandidate::new(
                                                ip,
                                                "dnsdb_historical_a",
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
                tracing::warn!(source = "dnsdb", status = %resp.status(), "DNSDB query failed");
            }
        }
        Err(e) => {
            tracing::warn!(source = "dnsdb", error = %e, "DNSDB request failed");
        }
    }

    Ok(candidates)
}
