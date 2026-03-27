//! BinaryEdge subdomain enumeration.
//! Requires a BinaryEdge API key.
//! Set via $BINARYEDGE_API_KEY env var or config.api_keys.binaryedge.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    events: Vec<String>,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.binaryedge.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!(
        "https://api.binaryedge.io/v2/query/domains/subdomain/{}",
        domain
    );
    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .get(&url)
                .header("X-Key", api_key)
                .send()
                .await?,
        )
    })
    .await?
    .json()
    .await?;

    let targets = resp
        .events
        .into_iter()
        .map(|e| e.trim().to_lowercase())
        .filter(|d| is_subdomain_of(d, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::BinaryEdge,
            })
        })
        .collect();

    Ok(targets)
}
