//! Netlas subdomain enumeration.
//! Requires a Netlas API key.
//! Set via $NETLAS_API_KEY env var or config.api_keys.netlas.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    domain: String,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.netlas.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!(
        "https://app.netlas.io/api/domains/?q=domain:{}*&source_type=include&fields=*&size=100",
        domain
    );

    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .get(&url)
                .header("X-API-Key", api_key)
                .send()
                .await?,
        )
    })
    .await?
    .json()
    .await?;

    let targets = resp
        .items
        .into_iter()
        .map(|item| item.domain.trim().to_lowercase())
        .filter(|d| is_subdomain_of(d, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::Netlas,
            })
        })
        .collect();

    Ok(targets)
}
