//! ZoomEye subdomain enumeration.
//! Requires a ZoomEye API key.
//! Set via $ZOOMEYE_API_KEY env var or config.api_keys.zoomeye.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    list: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    name: String,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.zoomeye.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!(
        "https://api.zoomeye.org/domain/search?q={}&type=1",
        domain
    );

    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .get(&url)
                .header("API-KEY", api_key)
                .send()
                .await?,
        )
    })
    .await?
    .json()
    .await?;

    let targets = resp
        .list
        .into_iter()
        .map(|entry| entry.name.trim().to_lowercase())
        .filter(|name| is_subdomain_of(name, domain))
        .map(|name| {
            Target::Domain(DomainTarget {
                domain: name,
                source: DiscoverySource::ZoomEye,
            })
        })
        .collect();

    Ok(targets)
}
