//! CIRCL Passive DNS (PDNS).
//!
//! Queries CIRCL.lu for historical DNS resolutions.
//! Requires a CIRCL username and password.

use crate::util::{bounded_json, is_routable_ip};
use crate::OriginCandidate;
use gossan_core::{Config, ScanClient};
use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

/// Scan CIRCL PDNS for origin candidates.
pub async fn scan(
    domain: &str,
    config: &Config,
    client: &ScanClient,
) -> anyhow::Result<Vec<OriginCandidate>> {
    let username = match config.api_keys.get("circl_user") {
        Some(k) => k,
        None => {
            tracing::debug!(source = "circl", "skipping: no circl_user API key");
            return Ok(vec![]);
        }
    };
    let password = match config.api_keys.get("circl_pass") {
        Some(k) => k,
        None => {
            tracing::debug!(source = "circl", "skipping: no circl_pass API key");
            return Ok(vec![]);
        }
    };

    let url = format!(
        "https://www.circl.lu/v2b/query/{}",
        urlencoding::encode(domain)
    );

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    let req = client
        .inner()
        .get(&url)
        .basic_auth(username, Some(password))
        .build()?;

    match client.execute(req).await {
        Ok(resp) => {
            if resp.status().is_success() {
                let limit = config.max_response_size.min(10 * 1024 * 1024);
                if let Ok(arr) = bounded_json::<Vec<serde_json::Value>>(resp, limit).await {
                    for entry in arr {
                        // CIRCL PDNS v2b returns objects with `rrtype` and `rdata`.
                        if let Some(rdata) = entry.get("rdata").and_then(|v| v.as_str()) {
                            if entry
                                .get("rrtype")
                                .and_then(|v| v.as_str())
                                .map(|t| t == "A" || t == "AAAA")
                                .unwrap_or(false)
                            {
                                if let Ok(ip) = IpAddr::from_str(rdata) {
                                    if is_routable_ip(ip) && seen.insert(ip) {
                                        candidates.push(OriginCandidate::new(ip, "circl_pdns", 85));
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                tracing::warn!(source = "circl", status = %resp.status(), "CIRCL query failed");
            }
        }
        Err(e) => {
            tracing::warn!(source = "circl", error = %e, "CIRCL request failed");
        }
    }

    Ok(candidates)
}
