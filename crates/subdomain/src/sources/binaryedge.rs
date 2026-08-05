//! Binaryedge subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Binaryedge;

#[async_trait]
impl SubdomainSource for Binaryedge {
    fn name(&self) -> &'static str { "binaryedge" }
    fn requires_api_key(&self) -> bool { true }
    fn api_key_name(&self) -> &'static str { "BINARYEDGE_API_KEY" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::BinaryEdge }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        
        let Some(key) = crate::sources::get_api_key(config, "binaryedge", "BINARYEDGE_API_KEY") else {
            return Ok(vec![]);
        };

        let url = format!("https://api.binaryedge.io/v2/query/domains/subdomain/{}?page=1", domain);
        limiter.until_ready().await;
        let resp = client
            .get(&url)
            .header("X-Key", key)
            .send()
            .await?
            .error_for_status()?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(arr) = json.get("events").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(v) = item.as_str() {
                    let candidate = v.trim().trim_start_matches("*.").to_lowercase();
                    if !candidate.contains('*') && crate::is_subdomain_of(&candidate, &domain_lower) {
                        seen.insert(candidate);
                    }
                }
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::BinaryEdge,
        })).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_x_key_header_and_query_url() {
        let client = reqwest::Client::new();
        let url = format!("https://api.binaryedge.io/v2/query/domains/subdomain/{}?page=1", "example.com");
        let req = client.get(&url).header("X-Key", "secret").build().unwrap();
        assert_eq!(req.url().as_str(), "https://api.binaryedge.io/v2/query/domains/subdomain/example.com?page=1");
        assert_eq!(req.headers().get("X-Key").unwrap(), "secret");
    }
}
