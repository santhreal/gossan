//! SSL Certificate Transparency scanner.
//!
//! Queries the crt.sh public CT log API to find historical certificates
//! for the target domain, then resolves the associated hostnames to find
//! IPs that may belong to the origin server (pre-CDN migration).

use std::collections::HashSet;
use std::net::IpAddr;

use crate::util::{bounded_json, is_routable_ip};
use crate::OriginCandidate;

/// JSON shape returned by crt.sh API.
#[derive(serde::Deserialize)]
struct CrtShEntry {
    /// Common name or SAN value.
    name_value: String,
}

/// Maximum number of unique hostnames to resolve from CT logs.
const MAX_HOSTNAMES: usize = 500;

/// Query crt.sh for certificate transparency logs, extract hostnames,
/// resolve them, and return candidate origin IPs.
///
/// crt.sh is free, requires no API key, and indexes the full CT log
/// ecosystem (Google Argon, Cloudflare Nimbus, Let's Encrypt Oak, etc.).
/// Query crt.sh for certificate transparency logs, extract hostnames,
/// resolve them, and return candidate origin IPs.
///
/// crt.sh is free, requires no API key, and indexes the full CT log
/// ecosystem (Google Argon, Cloudflare Nimbus, Let's Encrypt Oak, etc.).
pub async fn scan(domain: String, client: &gossan_core::ScanClient) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut candidates = Vec::new();

    let url = format!(
        "https://crt.sh/?q=%.{}&output=json",
        urlencoding::encode(&domain)
    );

    let response = match client.get(&url).await {
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

    let entries: Vec<CrtShEntry> = match bounded_json(response, 10 * 1024 * 1024).await {
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
                if !base.is_empty() {
                    hostnames.insert(base.to_string());
                }
            } else if !clean.is_empty() {
                hostnames.insert(clean);
            }
        }
    }

    if hostnames.len() > MAX_HOSTNAMES {
        tracing::warn!(
            scanner = "ssl_cert",
            total = hostnames.len(),
            max = MAX_HOSTNAMES,
            "truncating hostname list to avoid excessive DNS queries"
        );
    }

    tracing::info!(
        scanner = "ssl_cert",
        unique_hostnames = hostnames.len().min(MAX_HOSTNAMES),
        "extracted hostnames from CT logs"
    );

    // Resolve each hostname to find non-CDN IPs.
    let resolver = hickory_resolver::TokioAsyncResolver::tokio(
        hickory_resolver::config::ResolverConfig::default(),
        hickory_resolver::config::ResolverOpts::default(),
    );

    let mut seen_ips = HashSet::new();

    for hostname in hostnames.iter().take(MAX_HOSTNAMES) {
        if let Ok(lookup) = resolver.ipv4_lookup(hostname.as_str()).await {
            for ip in lookup {
                let addr = IpAddr::V4(ip.0);
                if is_routable_ip(addr) && seen_ips.insert(addr) {
                    candidates.push(OriginCandidate::new(
                        addr,
                        format!("ssl_cert_ct_log ({hostname})"),
                        70,
                    ));
                }
            }
        }
    }

    Ok(candidates)
}
