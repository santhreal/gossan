// Wayback Machine CDX API — free passive subdomain source.
// Queries https://web.archive.org/cdx/search/cdx?url=*.domain&output=text&fl=original&collapse=urlkey

use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use url::Url;

pub async fn query(
    domain: &str,
    _config: &Config,
    client: &reqwest::Client,
) -> anyhow::Result<Vec<Target>> {
    let url = format!(
        "https://web.archive.org/cdx/search/cdx?url=*.{}&output=text&fl=original&collapse=urlkey&limit=5000",
        domain
    );

    let text = client.get(&url).send().await?.text().await?;

    let mut targets = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for line in text.lines() {
        if let Ok(parsed) = Url::parse(line.trim()) {
            if let Some(host) = parsed.host_str() {
                let h = host.to_lowercase();
                if h.ends_with(&format!(".{}", domain)) && seen.insert(h.clone()) {
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
