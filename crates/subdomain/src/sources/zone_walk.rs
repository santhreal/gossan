//! DNS zone-walking subdomain source.
use gossan_core::{Config, DiscoverySource, DomainTarget, Target};
use crate::sources::{SubdomainSource, SourceRate};
use async_trait::async_trait;
use governor::DefaultDirectRateLimiter;

pub struct ZoneWalk;

#[async_trait]
impl SubdomainSource for ZoneWalk {
    fn name(&self) -> &'static str { "zone_walk" }
    fn requires_api_key(&self) -> bool { false }
    fn api_key_name(&self) -> &'static str { "" }
    fn rate_limit(&self) -> SourceRate { SourceRate::per_second(1) }
    fn discovery_source(&self) -> DiscoverySource { DiscoverySource::ZoneWalk }

    async fn query(
        &self,
        domain: &str,
        _config: &Config,
        _client: &reqwest::Client,
        _limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        // Zone walking requires NSEC/NSEC3 parsing and is implemented as a
        // specialized DNS-based scan rather than an HTTP fetch.  For now we
        // return an empty list; full implementation would query the zone's
        // SOA and walk NSEC chains.
        Ok(vec![])
    }
}
