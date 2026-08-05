//! FacebookCt Certificate Transparency log source.
use gossan_core::{Config, DiscoverySource, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct FacebookCt;

#[async_trait]
impl SubdomainSource for FacebookCt {
    fn name(&self) -> &'static str { "facebook_ct" }
    fn requires_api_key(&self) -> bool { false }
    fn api_key_name(&self) -> &'static str { "" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::CertificateTransparency }

    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        let url = format!("https://graph.facebook.com/certificates?query={}&fields=subjects", domain);
        crate::sources::common::ct_get_entries(domain, &url, config, client, limiter).await
    }
}
