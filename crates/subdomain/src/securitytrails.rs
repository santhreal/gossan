//! SecurityTrails subdomain enumeration.
//! Requires a SecurityTrails API key.
//! Set via $ST_API_KEY env var or config.api_keys.securitytrails.

use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use serde::Deserialize;

#[derive(Deserialize)]
struct Response {
    subdomains: Vec<String>,
    endpoint: String,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.securitytrails.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!("https://api.securitytrails.com/v1/domain/{}/subdomains?children_only=false&include_inactive=true", domain);
    let resp: Response = client
        .get(&url)
        .header("apikey", api_key)
        .send()
        .await?
        .json()
        .await?;

    // SecurityTrails returns bare labels (e.g. "www", "mail") — append the root domain
    let apex = resp.endpoint.trim_end_matches('.').to_string();
    let root = if apex.is_empty() {
        domain.to_string()
    } else {
        apex
    };

    let targets = resp
        .subdomains
        .into_iter()
        .map(|sub| format!("{}.{}", sub.trim().to_lowercase(), root))
        .filter(|d| d.ends_with(domain) && d.len() > domain.len())
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::SecurityTrails,
            })
        })
        .collect();

    Ok(targets)
}
