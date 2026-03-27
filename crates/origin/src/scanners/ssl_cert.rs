//! SSL Certificate Transparency scanner.
//!
//! Queries the crt.sh public CT log API to find historical certificates
//! for the target domain, then resolves the associated hostnames to find
//! IPs that may belong to the origin server (pre-CDN migration).

use std::collections::HashSet;
use std::net::IpAddr;

use crate::OriginCandidate;

/// JSON shape returned by crt.sh API.
#[derive(serde::Deserialize)]
struct CrtShEntry {
    /// Common name or SAN value.
    name_value: String,
}

/// Query crt.sh for certificate transparency logs, extract hostnames,
/// resolve them, and return candidate origin IPs.
///
/// crt.sh is free, requires no API key, and indexes the full CT log
/// ecosystem (Google Argon, Cloudflare Nimbus, Let's Encrypt Oak, etc.).
pub async fn scan(domain: String) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut candidates = Vec::new();

    let url = format!(
        "https://crt.sh/?q=%.{}&output=json",
        urlencoding::encode(&domain)
    );

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let response = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(scanner = "ssl_cert", error = %e, "crt.sh request failed");
            return Ok(candidates);
        }
    };

    if !response.status().is_success() {
        tracing::warn!(
            scanner = "ssl_cert",
            status = %response.status(),
            "crt.sh returned non-200"
        );
        return Ok(candidates);
    }

    let entries: Vec<CrtShEntry> = match response.json().await {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(scanner = "ssl_cert", error = %e, "failed to parse crt.sh response");
            return Ok(candidates);
        }
    };

    // Extract unique hostnames from certificate CN/SAN fields.
    let mut hostnames = HashSet::new();
    for entry in &entries {
        // name_value can contain newline-separated SANs.
        for name in entry.name_value.split('\n') {
            let clean = name.trim().to_lowercase();
            // Skip wildcard-only entries — they don't resolve.
            if let Some(base) = clean.strip_prefix("*.") {
                // Try the base domain (strip the wildcard).
                if !base.is_empty() {
                    hostnames.insert(base.to_string());
                }
            } else if !clean.is_empty() {
                hostnames.insert(clean);
            }
        }
    }

    tracing::info!(
        scanner = "ssl_cert",
        unique_hostnames = hostnames.len(),
        "extracted hostnames from CT logs"
    );

    // Resolve each hostname to find non-CDN IPs.
    let resolver = hickory_resolver::TokioAsyncResolver::tokio(
        hickory_resolver::config::ResolverConfig::default(),
        hickory_resolver::config::ResolverOpts::default(),
    );

    let mut seen_ips = HashSet::new();

    for hostname in &hostnames {
        if let Ok(lookup) = resolver.ipv4_lookup(hostname.as_str()).await {
            for ip in lookup {
                let addr = IpAddr::V4(ip.0);
                if seen_ips.insert(addr) {
                    candidates.push(OriginCandidate {
                        ip: addr,
                        method: format!("ssl_cert_ct_log ({})", hostname),
                        confidence: 70,
                    });
                }
            }
        }
    }

    Ok(candidates)
}
