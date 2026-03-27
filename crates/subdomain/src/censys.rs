//! Censys certificate search subdomain enumeration.
//! Requires a Censys API key in format "api_id:api_secret".
//! Set via $CENSYS_API_KEY env var or config.api_keys.censys.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    result: ResultData,
}

#[derive(Deserialize)]
struct ResultData {
    hits: Vec<Hit>,
}

#[derive(Deserialize)]
struct Hit {
    names: Vec<String>,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.censys.as_deref() else {
        return Ok(vec![]);
    };

    // Parse api_id:api_secret format
    let (api_id, api_secret) = api_key
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("CENSYS_API_KEY must be in format 'api_id:api_secret'"))?;

    let url = format!(
        "https://search.censys.io/api/v2/certificates/search?q=names:{}",
        domain
    );

    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .get(&url)
                .basic_auth(api_id, Some(api_secret))
                .send()
                .await?,
        )
    })
    .await?
    .json()
    .await?;

    let targets = resp
        .result
        .hits
        .into_iter()
        .flat_map(|hit| hit.names)
        .map(|name| name.trim().trim_start_matches("*.").to_lowercase())
        .filter(|name| !name.contains('*') && is_subdomain_of(name, domain))
        .map(|name| {
            Target::Domain(DomainTarget {
                domain: name,
                source: DiscoverySource::Censys,
            })
        })
        .collect();

    Ok(targets)
}
