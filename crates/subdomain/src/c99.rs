//! C99.nl subdomain finder API.
//! Requires a C99 API key.
//! Set via $C99_API_KEY env var or config.api_keys.c99.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    subdomains: Vec<String>,
    #[allow(dead_code)]
    success: bool,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.c99.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!(
        "https://api.c99.nl/subdomainfinder?key={}&domain={}&json",
        api_key, domain
    );

    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(client.get(&url).send().await?)
    })
    .await?
    .json()
    .await?;

    let targets = resp
        .subdomains
        .into_iter()
        .map(|s| s.trim().to_lowercase())
        .filter(|d| is_subdomain_of(d, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::C99,
            })
        })
        .collect();

    Ok(targets)
}
