//! CommonCrawl CDX API — free, no API key required.
//! Queries the latest CommonCrawl index for URLs matching *.{domain}
//! and extracts unique hostnames.

use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use serde::Deserialize;

#[derive(Deserialize)]
struct CdxRecord {
    url: String,
}

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<Target>> {
    // Query the latest available index; fl=url limits response to URL field only
    let url = format!(
        "https://index.commoncrawl.org/CC-MAIN-2024-51-index?url=*.{}&output=json&fl=url&limit=5000",
        domain
    );

    let text = client.get(&url).send().await?.text().await?;

    // Response is NDJSON (one JSON object per line)
    let mut targets = Vec::new();
    for line in text.lines() {
        let Ok(record) = serde_json::from_str::<CdxRecord>(line) else {
            continue;
        };
        let Ok(parsed) = url::Url::parse(&record.url) else {
            continue;
        };
        let Some(host) = parsed.host_str() else {
            continue;
        };
        let host = host.trim().to_lowercase();
        if host.ends_with(domain) && host.len() > domain.len() {
            targets.push(Target::Domain(DomainTarget {
                domain: host,
                source: DiscoverySource::CommonCrawl,
            }));
        }
    }

    Ok(targets)
}
