
//! CommonCrawl subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct CommonCrawl;

#[async_trait]
impl SubdomainSource for CommonCrawl {
    fn name(&self) -> &'static str { "commoncrawl" }
    fn requires_api_key(&self) -> bool { false }
    fn api_key_name(&self) -> &'static str { "" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::CommonCrawl }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        let mut indices: Vec<String> = vec!["CC-MAIN-2025-08".into(), "CC-MAIN-2024-51".into(), "CC-MAIN-2024-42".into()];
        
        // Try to discover latest index
        limiter.until_ready().await;
        let collinfo = client.get("https://index.commoncrawl.org/collinfo.json").send().await;
        if let Ok(resp) = collinfo {
            let max_size = config.max_response_size;
            if let Ok(bytes) = gossan_core::read_response_limited(resp, max_size).await {
                if let Ok(arr) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    if let Some(list) = arr.as_array() {
                        indices.clear();
                        for item in list.iter().take(3) {
                            if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                                indices.push(id.to_string());
                            }
                        }
                    }
                }
            }
        }

        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        let max_size = config.max_response_size;

        for index in &indices {
            let url = format!(
                "https://index.commoncrawl.org/{index}-index?url=*.{}&output=json&fl=url&limit=5000",
                domain
            );
            limiter.until_ready().await;
            let resp = client.get(&url).send().await?;
            let text = String::from_utf8(gossan_core::read_response_limited(resp, max_size).await?)?;
            for line in text.lines() {
                if line.is_empty() { continue; }
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(line) {
                    if let Some(u) = json.get("url").and_then(|v| v.as_str()) {
                        if let Ok(parsed) = url::Url::parse(u) {
                            if let Some(host) = parsed.host_str() {
                                let host = host.to_lowercase();
                                if crate::is_subdomain_of(&host, &domain_lower) {
                                    seen.insert(host);
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::CommonCrawl,
        })).collect())
    }
}
