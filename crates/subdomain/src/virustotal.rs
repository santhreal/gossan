//! VirusTotal passive DNS subdomain enumeration.
//! Requires a free VirusTotal API key (500 req/day, 4 req/min).
//! Set via $VT_API_KEY env var or config.api_keys.virustotal.

use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use serde::Deserialize;

#[derive(Deserialize)]
struct Response {
    data: Vec<Entry>,
}

#[derive(Deserialize)]
struct Entry {
    id: String,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.virustotal.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!(
        "https://www.virustotal.com/api/v3/domains/{}/subdomains?limit=1000",
        domain
    );
    let resp: Response = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await?
        .json()
        .await?;

    let targets = resp
        .data
        .into_iter()
        .map(|e| e.id.trim().to_lowercase())
        .filter(|d| d.ends_with(domain) && d.len() > domain.len())
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::VirusTotal,
            })
        })
        .collect();

    Ok(targets)
}
