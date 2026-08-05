//! SSL Certificate Transparency scanner.
//!
//! Queries the crt.sh public CT log API to find historical certificates
//! for the target domain, then resolves the associated hostnames to find
//! IPs that may belong to the origin server (pre-CDN migration).

use std::collections::HashSet;
use std::net::IpAddr;

use crate::util::{bounded_text, is_routable_ip};
use crate::OriginCandidate;
use futures::future::join_all;

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
pub async fn scan(
    domain: String,
    client: &gossan_core::ScanClient,
) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut candidates = Vec::new();

    let url = ctlog::crtsh_query_url(&domain);

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

    let body = match bounded_text(response, crate::MAX_ORIGIN_JSON_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(scanner = "ssl_cert", error = %e, "failed to read crt.sh response");
            return Ok(candidates);
        }
    };

    // Extract unique hostnames (CN + SANs, apex included) via the canonical
    // crt.sh parser, which applies the shared normalization: newline split,
    // `*.` wildcard strip, lowercase, empty/wildcard drop, and dedup.
    let hostnames: HashSet<String> = match ctlog::parse_crtsh_hostnames(&body) {
        Ok(names) => names.into_iter().collect(),
        Err(e) => {
            tracing::warn!(scanner = "ssl_cert", error = %e, "failed to parse crt.sh response");
            return Ok(candidates);
        }
    };

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

    // Resolve each hostname concurrently to find non-CDN IPs.
    let resolver = hickory_resolver::TokioResolver::builder_with_config(
        hickory_resolver::config::ResolverConfig::default(),
        hickory_resolver::name_server::TokioConnectionProvider::default(),
    )
    .with_options(hickory_resolver::config::ResolverOpts::default())
    .build();

    let mut seen_ips = HashSet::new();

    let hostnames: Vec<&String> = hostnames.iter().take(MAX_HOSTNAMES).collect();
    let lookups: Vec<_> = hostnames
        .iter()
        .map(|hostname| async {
            let result = resolver.ipv4_lookup(hostname.as_str()).await;
            (*hostname, result)
        })
        .collect();

    for (hostname, lookup) in join_all(lookups).await {
        match lookup {
            Ok(lookup) => {
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
            Err(e) if e.is_nx_domain() || e.is_no_records_found() => {}
            Err(e) => {
                tracing::warn!(
                    %hostname,
                    error = %e,
                    "ssl_cert CT hostname A lookup failed; skipping host"
                );
            }
        }
    }

    Ok(candidates)
}
