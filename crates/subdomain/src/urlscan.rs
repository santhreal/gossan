//! Urlscan.io passive subdomain discovery — free, no API key for basic queries.
//! https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000

use gossan_core::{Config, DiscoverySource, DomainTarget, HostRateLimiter, Target};
use serde::Deserialize;

use crate::{get_json, is_subdomain_of};

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
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let url = format!(
        "https://urlscan.io/api/v1/search/?q=domain:{}&size=10000",
        domain
    );
    let resp: Response = get_json(client, &url, rate_limiter).await?;

    let targets = resp
        .results
        .into_iter()
        .map(|r| r.page.domain.trim().to_lowercase())
        .filter(|d| is_subdomain_of(d, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::UrlScan,
            })
        })
        .collect();

    Ok(targets)
}
