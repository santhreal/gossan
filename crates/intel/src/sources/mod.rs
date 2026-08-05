//! Online intelligence source implementations (one source per file).

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

/// Maximum bytes to read from an intel source JSON response.
/// 8 MiB is large enough for Shodan host records (potentially hundreds of
/// services) and VirusTotal/URLScan result sets while guarding against
/// unbounded reads from adversarial or misconfigured endpoints.
pub(crate) const MAX_INTEL_JSON_BYTES: usize = 8 * 1024 * 1024;

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
