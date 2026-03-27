//! HackerTarget hostsearch API — free passive subdomain enumeration.
//! https://api.hackertarget.com/hostsearch/?q=example.com

use gossan_core::{Config, DiscoverySource, DomainTarget, HostRateLimiter, Target};

use crate::{get_text, is_subdomain_of};

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={}", domain);
    let text = get_text(client, &url, rate_limiter).await?;

    // Each line: "subdomain.example.com,1.2.3.4"
    // Error responses start with "error" — skip them
    if text.trim_start().starts_with("error") {
        return Ok(vec![]);
    }

    let targets = text
        .lines()
        .filter_map(|line| {
            let host = line.split(',').next()?.trim().to_lowercase();
            if !host.is_empty() && is_subdomain_of(&host, domain) {
                Some(Target::Domain(DomainTarget {
                    domain: host,
                    source: DiscoverySource::PassiveDns,
                }))
            } else {
                None
            }
        })
        .collect();

    Ok(targets)
}
