//! Urlscan.io passive subdomain discovery — free, no API key for basic queries.
//! https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000

use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use serde::Deserialize;

#[derive(Deserialize)]
struct Response {
    results: Vec<Result_>,
}

#[derive(Deserialize)]
struct Result_ {
    page: Page,
}

#[derive(Deserialize)]
struct Page {
    domain: String,
}

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<Target>> {
    let url = format!(
        "https://urlscan.io/api/v1/search/?q=domain:{}&size=10000",
        domain
    );
    let resp: Response = client.get(&url).send().await?.json().await?;

    let targets = resp
        .results
        .into_iter()
        .map(|r| r.page.domain.trim().to_lowercase())
        .filter(|d| d.ends_with(domain) && d.len() > domain.len())
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::UrlScan,
            })
        })
        .collect();

    Ok(targets)
}
