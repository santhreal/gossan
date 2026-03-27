//! RapidDNS.io passive subdomain enumeration.
//! Free, no API key required. Returns a plain-text list of subdomains.

use gossan_core::{Config, DiscoverySource, DomainTarget, Target};

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<Target>> {
    let url = format!("https://rapiddns.io/subdomain/{}?full=1&down=1", domain);
    let text = client.get(&url).send().await?.text().await?;

    let targets = text
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|s| {
            !s.is_empty() && !s.starts_with('#') && s.ends_with(domain) && s.len() > domain.len()
        })
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::RapidDns,
            })
        })
        .collect();

    Ok(targets)
}
