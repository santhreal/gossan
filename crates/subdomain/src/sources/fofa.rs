//! Fofa subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct Fofa;

#[async_trait]
impl SubdomainSource for Fofa {
    fn name(&self) -> &'static str { "fofa" }
    fn requires_api_key(&self) -> bool { true }
    fn api_key_name(&self) -> &'static str { "FOFA_API_KEY" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(0) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::Fofa }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        
        let Some(credentials) = crate::sources::get_api_key(config, "fofa", "FOFA_API_KEY") else {
            return Ok(vec![]);
        };
        let Some((email, key)) = credentials.split_once(':') else {
            return Err(anyhow::anyhow!("FOFA_API_KEY must be in format email:key"));
        };
        if email.is_empty() {
            return Err(anyhow::anyhow!("FOFA_API_KEY missing email"));
        }

        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(format!("domain={domain}"));
        let base = "https://fofa.info/api/v1/search/all";
        limiter.until_ready().await;
        let resp = client
            .get(base)
            .query(&[
                ("qbase64", b64.as_str()),
                ("email", email),
                ("key", key),
                ("size", "10000"),
            ])
            .send()
            .await?
            .error_for_status()?;
        let max_size = config.max_response_size;
        let bytes = gossan_core::read_response_limited(resp, max_size).await?;
        let mut seen = std::collections::HashSet::new();
        let domain_lower = domain.to_lowercase();
        
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;
        if let Some(arr) = json.get("results").and_then(|v| v.as_array()) {
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
            source: DiscoverySource::Fofa,
        })).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn fofa_url_includes_email_and_key() {
        let domain = "example.com";
        let email = "user@example.com";
        let key = "secret";
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(format!("domain={domain}"));
        let url = reqwest::Url::parse_with_params(
            "https://fofa.info/api/v1/search/all",
            &[("qbase64", b64.as_str()), ("email", email), ("key", key), ("size", "10000")],
        )
        .unwrap();
        assert_eq!(url.host_str().unwrap(), "fofa.info");
        assert!(url.query().unwrap().contains("email=user%40example.com"));
        assert!(url.query().unwrap().contains("key=secret"));
        assert!(url.query().unwrap().contains("qbase64="));
    }

    #[test]
    fn fofa_credentials_split_requires_email() {
        let creds = "user@example.com:secret";
        let (email, key) = creds.split_once(':').unwrap();
        assert_eq!(email, "user@example.com");
        assert_eq!(key, "secret");
    }
}
