//! Shodan subdomain enumeration.
//! Requires a Shodan API key.
//! Set via $SHODAN_API_KEY env var or config.api_keys.shodan.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    domain: String,
    subdomains: Vec<String>,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.shodan.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!(
        "https://api.shodan.io/dns/domain/{}?key={}",
        domain, api_key
    );

    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(client.get(&url).send().await?)
    })
    .await?
    .json()
    .await?;

    // Shodan returns bare labels (e.g. "www", "mail") — append the root domain
    let root = resp.domain.trim_end_matches('.').to_string();
    let root = if root.is_empty() {
        domain.to_string()
    } else {
        root
    };

    let targets = resp
        .subdomains
        .into_iter()
        .map(|sub| format!("{}.{}", sub.trim().to_lowercase(), root))
        .filter(|d| is_subdomain_of(d, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::Shodan,
            })
        })
        .collect();

    Ok(targets)
}
