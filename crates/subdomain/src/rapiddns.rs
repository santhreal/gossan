//! RapidDNS.io passive subdomain enumeration.
//! Free, no API key required. Returns a plain-text list of subdomains.

use gossan_core::{Config, DiscoverySource, DomainTarget, HostRateLimiter, Target};

use crate::{get_text, is_subdomain_of};

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let url = format!("https://rapiddns.io/subdomain/{}?full=1&down=1", domain);
    let text = get_text(client, &url, rate_limiter).await?;

    let targets = text
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|s| !s.is_empty() && !s.starts_with('#') && is_subdomain_of(s, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::RapidDns,
            })
        })
        .collect();

    Ok(targets)
}
