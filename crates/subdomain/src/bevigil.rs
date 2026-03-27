//! Bevigil subdomain enumeration.
//! Requires a Bevigil API key.
//! Set via $BEVIGIL_API_KEY env var or config.api_keys.bevigil.

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
    let Some(api_key) = config.api_keys.bevigil.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!("https://osint.bevigil.com/api/{}/subdomains/", domain);
    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .get(&url)
                .header("X-Access-Token", api_key)
                .send()
                .await?,
        )
    })
    .await?
    .json()
    .await?;

    let targets = resp
        .subdomains
        .into_iter()
        .map(|sub| sub.trim().to_lowercase())
        .filter(|d| is_subdomain_of(d, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::Bevigil,
            })
        })
        .collect();

    Ok(targets)
}
