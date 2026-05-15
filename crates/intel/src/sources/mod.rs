//! Online intelligence source implementations — one source per file.

pub mod abuseipdb;
pub mod asn;
pub mod censys;
pub mod greynoise;
pub mod passive_dns;
pub mod shodan;
pub mod urlscan;
pub mod virustotal;

use crate::enrichment::IntelEnrichment;
use async_trait::async_trait;

/// Trait implemented by every online intel source.
#[async_trait]
pub trait IntelSource: Send + Sync {
    /// Human-readable source name.
    fn name(&self) -> &'static str;

    /// Query the source for an IP address.
    ///
    /// # Errors
    ///
    /// Returns an error if the network request fails or the response is malformed.
    async fn query_ip(&self, ip: &str) -> anyhow::Result<IntelEnrichment>;

    /// Query the source for a domain.
    ///
    /// # Errors
    ///
    /// Returns an error if the network request fails or the response is malformed.
    async fn query_domain(&self, domain: &str) -> anyhow::Result<IntelEnrichment>;
}
