//! FullHunt subdomain enumeration.
//! Requires a FullHunt API key.
//! Set via $FULLHUNT_API_KEY env var or config.api_keys.fullhunt.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    hosts: Vec<HostEntry>,
}

#[derive(Deserialize)]
struct HostEntry {
    domain: String,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.fullhunt.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!("https://fullhunt.io/api/v1/domain/{}/details", domain);
    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .get(&url)
                .header("X-Api-Key", api_key)
                .send()
                .await?,
        )
    })
    .await?
    .json()
    .await?;

    let targets = resp
        .hosts
        .into_iter()
        .map(|h| h.domain.trim().to_lowercase())
        .filter(|d| is_subdomain_of(d, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::FullHunt,
            })
        })
        .collect();

    Ok(targets)
}
