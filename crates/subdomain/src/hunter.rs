//! Hunter.io subdomain enumeration.
//! Requires a Hunter.io API key.
//! Set via $HUNTER_API_KEY env var or config.api_keys.hunter.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    data: Data,
}

#[derive(Deserialize)]
struct Data {
    emails: Vec<Email>,
    #[allow(dead_code)]
    domain: Option<String>,
}

#[derive(Deserialize)]
struct Email {
    #[allow(dead_code)]
    value: Option<String>,
    sources: Option<Vec<Source>>,
}

#[derive(Deserialize)]
struct Source {
    #[allow(dead_code)]
    domain: Option<String>,
    #[allow(dead_code)]
    uri: Option<String>,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.hunter.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!(
        "https://api.hunter.io/v2/domain-search?domain={}&api_key={}",
        domain, api_key
    );

    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(client.get(&url).send().await?)
    })
    .await?
    .json()
    .await?;

    // Collect subdomains from email sources
    let mut subdomains: std::collections::HashSet<String> = std::collections::HashSet::new();

    for email in resp.data.emails {
        // Extract domains from sources
        if let Some(sources) = email.sources {
            for source in sources {
                if let Some(source_domain) = source.domain {
                    let source_domain = source_domain.trim().to_lowercase();
                    if is_subdomain_of(&source_domain, domain) {
                        subdomains.insert(source_domain);
                    }
                }
            }
        }

        // Also extract domain from email address itself
        if let Some(email_value) = email.value {
            if let Some(at_pos) = email_value.find('@') {
                let email_domain = email_value[at_pos + 1..].trim().to_lowercase();
                if is_subdomain_of(&email_domain, domain) {
                    subdomains.insert(email_domain);
                }
            }
        }
    }

    let targets = subdomains
        .into_iter()
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::HunterIo,
            })
        })
        .collect();

    Ok(targets)
}
