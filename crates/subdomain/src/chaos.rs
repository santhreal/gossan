//! Chaos (ProjectDiscovery) subdomain enumeration.
//! Requires a Chaos API key.
//! Set via $CHAOS_API_KEY env var or config.api_keys.chaos.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    subdomains: Vec<String>,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.chaos.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!("https://dns.projectdiscovery.io/dns/{}/subdomains", domain);
    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .get(&url)
                .header("Authorization", api_key)
                .send()
                .await?,
        )
    })
    .await?
    .json()
    .await?;

    // Chaos returns bare labels (e.g. "www", "mail") — append the root domain
    let targets = resp
        .subdomains
        .into_iter()
        .map(|sub| format!("{}.{}", sub.trim().to_lowercase(), domain))
        .filter(|d| is_subdomain_of(d, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::Chaos,
            })
        })
        .collect();

    Ok(targets)
}
