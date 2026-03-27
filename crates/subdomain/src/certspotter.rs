//! CertSpotter CT log query — complementary to crt.sh, different backend.
//! API: https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names
//! No key required (100 req/hr unauthenticated). Surfaces certs that crt.sh may miss.

use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use serde::Deserialize;

#[derive(Deserialize)]
struct Issuance {
    dns_names: Vec<String>,
}

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<Target>> {
    let url = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names&after=0",
        domain
    );

    let resp = client.get(&url).send().await?;
    if !resp.status().is_success() {
        anyhow::bail!("Certspotter API returned status {:?}", resp.status());
    }

    let issuances: Vec<Issuance> = resp.json().await?;

    let targets = issuances
        .into_iter()
        .flat_map(|i| i.dns_names)
        .map(|n| n.trim().trim_start_matches("*.").to_lowercase())
        .filter(|n| !n.contains('*') && n.ends_with(domain) && n.len() > domain.len())
        .map(|name| {
            Target::Domain(DomainTarget {
                domain: name,
                source: DiscoverySource::CertificateTransparency,
            })
        })
        .collect();

    Ok(targets)
}
