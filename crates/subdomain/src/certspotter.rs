//! CertSpotter CT log query — complementary to crt.sh, different backend.
//! API: https://api.certspotter.com/v1/issuances?domain=<domain>&include_subdomains=true&expand=dns_names
//! No key required (100 req/hr unauthenticated). Surfaces certs that crt.sh may miss.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Issuance {
    dns_names: Vec<String>,
}

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let url = format!(
        "https://api.certspotter.com/v1/issuances?domain={}&include_subdomains=true&expand=dns_names&after=0",
        domain
    );

    let resp = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(client.get(&url).send().await?)
    })
    .await?;
    if !resp.status().is_success() {
        anyhow::bail!("Certspotter API returned status {:?}", resp.status());
    }

    let issuances: Vec<Issuance> = resp.json().await?;

    let targets = issuances
        .into_iter()
        .flat_map(|i| i.dns_names)
        .map(|n| n.trim().trim_start_matches("*.").to_lowercase())
        .filter(|n| !n.contains('*') && is_subdomain_of(n, domain))
        .map(|name| {
            Target::Domain(DomainTarget {
                domain: name,
                source: DiscoverySource::CertificateTransparency,
            })
        })
        .collect();

    Ok(targets)
}
