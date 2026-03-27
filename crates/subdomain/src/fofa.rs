//! FOFA subdomain enumeration.
//! Requires a FOFA API key in format "email:key".
//! Set via $FOFA_API_KEY env var or config.api_keys.fofa.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    results: Vec<Vec<String>>,
    #[serde(rename = "size")]
    _size: Option<i64>,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.fofa.as_deref() else {
        return Ok(vec![]);
    };

    // Parse email:key format
    let (email, key) = api_key
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("FOFA_API_KEY must be in format 'email:key'"))?;

    // Build FOFA query: domain="example.com"
    let fofa_query = format!("domain=\"{}\"", domain);
    let b64_query = BASE64_STANDARD.encode(fofa_query);

    let url = format!(
        "https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&size=10000",
        email, key, b64_query
    );

    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(client.get(&url).send().await?)
    })
    .await?
    .json()
    .await?;

    let targets = resp
        .results
        .into_iter()
        .filter_map(|row| row.first().cloned())
        .map(|host| host.trim().to_lowercase())
        .filter(|host| is_subdomain_of(host, domain))
        .map(|host| {
            Target::Domain(DomainTarget {
                domain: host,
                source: DiscoverySource::Fofa,
            })
        })
        .collect();

    Ok(targets)
}
