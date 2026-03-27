//! GitHub code search subdomain enumeration.
//! Requires a GitHub personal access token.
//! Set via $GITHUB_TOKEN env var or config.api_keys.github.

use gossan_core::{
    send_with_backoff, Config, DiscoverySource, DomainTarget, HostRateLimiter, Target,
};
use regex::Regex;
use serde::Deserialize;

use crate::is_subdomain_of;

#[derive(Deserialize)]
struct Response {
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    path: String,
    #[serde(rename = "text_matches")]
    text_matches: Option<Vec<TextMatch>>,
}

#[derive(Deserialize)]
struct TextMatch {
    fragment: String,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.github.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!(
        "https://api.github.com/search/code?q=\"{}\"&per_page=100",
        domain
    );

    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .get(&url)
                .header("Authorization", format!("Bearer {}", api_key))
                .header("Accept", "application/vnd.github.v3+json")
                .send()
                .await?,
        )
    })
    .await?
    .json()
    .await?;

    // Build regex to find subdomains: matches labels ending with .{domain}
    let pattern = format!(r"([a-zA-Z0-9_-]+\.{})", regex::escape(domain));
    let re = Regex::new(&pattern)?;

    let mut found = std::collections::HashSet::new();

    for item in resp.items {
        // Check the file path for subdomains
        for cap in re.captures_iter(&item.path) {
            if let Some(m) = cap.get(0) {
                found.insert(m.as_str().to_lowercase());
            }
        }

        // Check text matches (code fragments) for subdomains
        if let Some(matches) = item.text_matches {
            for tm in matches {
                for cap in re.captures_iter(&tm.fragment) {
                    if let Some(m) = cap.get(0) {
                        found.insert(m.as_str().to_lowercase());
                    }
                }
            }
        }
    }

    let targets = found
        .into_iter()
        .filter(|d| is_subdomain_of(d, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::GitHub,
            })
        })
        .collect();

    Ok(targets)
}
