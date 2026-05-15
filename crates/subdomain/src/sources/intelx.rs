
//! IntelX (Intelligence X) subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct IntelX;

#[async_trait]
impl SubdomainSource for IntelX {
    fn name(&self) -> &'static str { "intelx" }
    fn requires_api_key(&self) -> bool { true }
    fn api_key_name(&self) -> &'static str { "INTELX_API_KEY" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::PassiveDns }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        let Some(key) = crate::sources::get_api_key(config, "intelx", "INTELX_API_KEY") else {
            return Ok(vec![]);
        };

        let search_body = serde_json::json!({
            "term": domain,
            "maxresults": 10000,
            "media": 0,
            "target": 1,
            "terminate": []
        });

        limiter.until_ready().await;
        let search_resp = client
            .post("https://2.intelx.io/phonebook/search")
            .header("x-key", &key)
            .header("Content-Type", "application/json")
            .json(&search_body)
            .send()
            .await?;

        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(search_resp, max_size).await?;
        let search_json: serde_json::Value = serde_json::from_slice(&bytes)?;
        let Some(search_id) = search_json.get("id").and_then(|v| v.as_str()) else {
            return Ok(vec![]);
        };

        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();

        for _ in 0..3 {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            limiter.until_ready().await;
            let result_url = format!("https://2.intelx.io/phonebook/search/result?id={search_id}&limit=10000&offset=0");
            let result_resp = client
                .get(&result_url)
                .header("x-key", &key)
                .send()
                .await?;
            let bytes = gossan_core::read_response_limited(result_resp, max_size).await?;
            let result_json: serde_json::Value = serde_json::from_slice(&bytes)?;
            if let Some(selectors) = result_json.get("selectors").and_then(|v| v.as_array()) {
                for selector in selectors {
                    if let Some(svalue) = selector.get("selectorvalue").and_then(|v| v.as_str()) {
                        let candidate = svalue.trim().to_lowercase();
                        if crate::is_subdomain_of(&candidate, &domain_lower) {
                            seen.insert(candidate);
                        }
                    }
                }
            }
            if result_json.get("status").and_then(|v| v.as_u64()).unwrap_or(0) == 2 {
                break;
            }
        }

        Ok(seen.into_iter().map(|d| Target::Domain(DomainTarget {
            domain: d,
            source: DiscoverySource::PassiveDns,
        })).collect())
    }
}
