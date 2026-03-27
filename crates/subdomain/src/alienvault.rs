//! AlienVault OTX passive DNS — free, no API key required.
//! https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns

use gossan_core::{Config, DiscoverySource, DomainTarget, HostRateLimiter, Target};
use serde::Deserialize;

use crate::{get_json, is_subdomain_of};

#[derive(Deserialize)]
struct Response {
    passive_dns: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    hostname: String,
}

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let url = format!(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns",
        domain
    );
    let resp: Response = get_json(client, &url, rate_limiter).await?;

    let targets = resp
        .passive_dns
        .into_iter()
        .map(|e| e.hostname.trim().to_lowercase())
        .filter(|h| is_subdomain_of(h, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::AlienVault,
            })
        })
        .collect();

    Ok(targets)
}
