//! Certificate Transparency log query via crt.sh public JSON API.
//! Every cert ever issued for a domain's SANs is a subdomain inventory.

use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use serde::Deserialize;

#[derive(Deserialize)]
struct Entry {
    name_value: String,
}

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<Target>> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);
    let entries: Vec<Entry> = client.get(&url).send().await?.json().await?;

    let targets = entries
        .into_iter()
        .flat_map(|e| {
            e.name_value
                .lines()
                .map(|n| n.trim().trim_start_matches("*.").to_lowercase())
                .filter(|n| !n.contains('*') && n.ends_with(domain) && n.len() > domain.len())
                .map(|name| {
                    Target::Domain(DomainTarget {
                        domain: name,
                        source: DiscoverySource::CertificateTransparency,
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect();

    Ok(targets)
}
