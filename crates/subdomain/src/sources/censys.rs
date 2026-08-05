//! Censys subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Censys;

#[async_trait]
impl SubdomainSource for Censys {
    fn name(&self) -> &'static str { "censys" }
    fn requires_api_key(&self) -> bool { true }
    fn api_key_name(&self) -> &'static str { "CENSYS_API_KEY" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(0) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::Censys }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        
        let Some(credentials) = crate::sources::get_api_key(config, "censys", "CENSYS_API_KEY") else {
            return Ok(vec![]);
        };
        let Some((api_id, api_secret)) = credentials.split_once(':') else {
            return Err(anyhow::anyhow!("CENSYS_API_KEY must be in format api_id:api_secret"));
        };

        let url = format!("https://search.censys.io/api/v2/certificates/search?q=names:%20{}&per_page=100", domain);
        limiter.until_ready().await;
        let resp = client
            .get(&url)
            .basic_auth(api_id, Some(api_secret))
            .send()
            .await?
            .error_for_status()?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(arr) = json.get("result").and_then(|v| v.get("hits")).and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(v) = item.get("names").and_then(|v| v.as_str()) {
                    let candidate = v.trim().trim_start_matches("*.").to_lowercase();
                    if !candidate.contains('*') && crate::is_subdomain_of(&candidate, &domain_lower) {
                        seen.insert(candidate);
                    }
                }
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::Censys,
        })).collect())
    }
}
