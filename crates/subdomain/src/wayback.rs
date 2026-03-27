// Wayback Machine CDX API — free passive subdomain source.
// Queries https://web.archive.org/cdx/search/cdx?url=*.domain&output=text&fl=original&collapse=urlkey

use gossan_core::{Config, DiscoverySource, DomainTarget, HostRateLimiter, Target};
use url::Url;

use crate::{get_text, is_subdomain_of};

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url=*.{}&output=text&fl=original&collapse=urlkey&limit=5000",
        domain
    );

    let text = get_text(client, &url, rate_limiter).await?;

    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        if let Ok(parsed) = Url::parse(line.trim()) {
            if let Some(host) = parsed.host_str() {
                let h = host.to_lowercase();
                if is_subdomain_of(&h, domain) && seen.insert(h.clone()) {
                    targets.push(Target::Domain(DomainTarget {
                        domain: h,
                        source: DiscoverySource::PassiveDns,
                    }));
                }
            }
        }
    }

    Ok(targets)
}
