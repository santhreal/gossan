//! Certificate Transparency log query via crt.sh public JSON API.
//! Every cert ever issued for a domain's SANs is a subdomain inventory.

use gossan_core::{Config, DiscoverySource, DomainTarget, HostRateLimiter, Target};
use serde::Deserialize;

use crate::{get_json, is_subdomain_of};

#[derive(Deserialize)]
struct Entry {
    name_value: String,
}

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    let entries: Vec<Entry> = get_json(client, &url, rate_limiter).await?;

    let targets = entries
        .into_iter()
        .flat_map(|e| {
            e.name_value
                .lines()
                .map(|n| n.trim().trim_start_matches("*.").to_lowercase())
                .filter(|n| !n.contains('*') && is_subdomain_of(n, domain))
                .map(|name| {
                    Target::Domain(DomainTarget {
                        domain: name,
                        source: DiscoverySource::CertificateTransparency,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    Ok(targets)
}
