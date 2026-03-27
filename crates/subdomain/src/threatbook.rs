//! ThreatBook subdomain enumeration.
//! Requires a ThreatBook API key.
//! Set via $THREATBOOK_API_KEY env var or config.api_keys.threatbook.

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
    #[serde(rename = "sub_domains")]
    sub_domains: Vec<String>,
}

pub async fn query(
    domain: &str,
    config: &Config,
    client: &reqwest::Client,
    rate_limiter: &HostRateLimiter,
) -> anyhow::Result<Vec<Target>> {
    let Some(api_key) = config.api_keys.threatbook.as_deref() else {
        return Ok(vec![]);
    };

    let url = format!(
        "https://api.threatbook.io/v3/domain/sub_domains?resource={}",
        domain
    );
    let resp: Response = send_with_backoff(&url, Some(rate_limiter), || async {
        Ok::<reqwest::Response, anyhow::Error>(
            client
                .get(&url)
                .header("X-Api-Key", api_key)
                .send()
                .await?,
        )
    })
    .await?
    .json()
    .await?;

    let targets = resp
        .data
        .sub_domains
        .into_iter()
        .map(|d| d.trim().to_lowercase())
        .filter(|d| is_subdomain_of(d, domain))
        .map(|d| {
            Target::Domain(DomainTarget {
                domain: d,
                source: DiscoverySource::ThreatBook,
            })
        })
        .collect();

    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_deserialization() {
        let json = r#"{
            "data": {
                "sub_domains": ["api.example.com", "www.example.com", "mail.example.com"]
            }
        }"#;
        let resp: Response = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(resp.data.sub_domains.len(), 3);
        assert_eq!(resp.data.sub_domains[0], "api.example.com");
        assert_eq!(resp.data.sub_domains[1], "www.example.com");
        assert_eq!(resp.data.sub_domains[2], "mail.example.com");
    }

    #[test]
    fn response_deserialization_empty() {
        let json = r#"{"data": {"sub_domains": []}}"#;
        let resp: Response = serde_json::from_str(json).expect("valid JSON");
        assert!(resp.data.sub_domains.is_empty());
    }
}
