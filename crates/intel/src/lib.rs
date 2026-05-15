#![forbid(unsafe_code)]
// pedantic moved to workspace [lints.clippy] in root Cargo.toml
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

//! Intelligence scanner — online enrichment + offline bulk datasets.
//!
//! # Sources
//! - GreyNoise
//! - Censys host context v2
//! - Shodan
//! - AbuseIPDB
//! - VirusTotal
//! - URLScan
//! - ASN (ipinfo.io)
//! - Passive DNS
//!
//! # Caching
//! All enrichment is cached in a SQLite-backed TTL cache keyed by
//! `(source, target_type, target_value)`.

use async_trait::async_trait;
use gossan_core::{Config, ScanClient, ScanInput, Scanner, Target};
use std::sync::Arc;

pub mod cache;
pub mod db;
pub mod enrichment;
pub mod ingest;
pub mod query;
pub mod ratelimit;
pub mod sources;

use cache::IntelCache;
use sources::IntelSource;

/// Intel scanner configuration.
pub struct IntelScanner {
    /// HTTP client shared across all sources.
    pub client: ScanClient,
    /// Online enrichment sources.
    pub sources: Vec<Arc<dyn IntelSource>>,
    /// Persistent TTL cache.
    pub cache: Option<Arc<IntelCache>>,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Optional offline bulk database.
    pub db: Option<Arc<db::IntelDb>>,
    /// Per-service rate limiter.
    pub limiter: Option<Arc<ratelimit::ServiceRateLimiter>>,
}

impl IntelScanner {
    /// Build an intel scanner from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache database cannot be opened.
    pub fn from_config(config: &Config) -> anyhow::Result<Self> {
        let client = ScanClient::default_client();
        let inner = client.inner().clone();

        let mut sources: Vec<Arc<dyn IntelSource>> = Vec::new();

        let greynoise_key = config.api_keys.get("greynoise").cloned();
        sources.push(Arc::new(sources::greynoise::GreyNoiseSource::new(
            inner.clone(),
            greynoise_key,
        )));

        let censys_id = config.api_keys.get("censys_id").cloned();
        let censys_secret = config.api_keys.get("censys_secret").cloned();
        sources.push(Arc::new(sources::censys::CensysSource::new(
            inner.clone(),
            censys_id,
            censys_secret,
        )));

        let shodan_key = config.api_keys.get("shodan").cloned();
        sources.push(Arc::new(sources::shodan::ShodanSource::new(
            inner.clone(),
            shodan_key,
        )));

        let abuseipdb_key = config.api_keys.get("abuseipdb").cloned();
        sources.push(Arc::new(sources::abuseipdb::AbuseIpdbSource::new(
            inner.clone(),
            abuseipdb_key,
        )));

        let vt_key = config.api_keys.get("virustotal").cloned();
        sources.push(Arc::new(sources::virustotal::VirusTotalSource::new(
            inner.clone(),
            vt_key,
        )));

        let urlscan_key = config.api_keys.get("urlscan").cloned();
        sources.push(Arc::new(sources::urlscan::UrlScanSource::new(
            inner.clone(),
            urlscan_key,
        )));

        let asn_token = config.api_keys.get("ipinfo").cloned();
        sources.push(Arc::new(sources::asn::AsnSource::new(
            inner.clone(),
            asn_token,
        )));

        let pdns_key = config.api_keys.get("passive_dns").cloned();
        let pdns_endpoint = config
            .api_keys
            .get("passive_dns_endpoint")
            .cloned()
            .unwrap_or_else(|| "https://api.dnsdb.info".to_string());
        sources.push(Arc::new(sources::passive_dns::PassiveDnsSource::new(
            inner.clone(),
            pdns_key,
            pdns_endpoint,
        )));

        let cache = if let Some(ref path) = config.intel_db_path {
            Some(Arc::new(IntelCache::open(path)?))
        } else {
            None
        };

        let db = if let Some(ref path) = config.intel_db_path {
            Some(Arc::new(db::IntelDb::open(path)?))
        } else {
            None
        };

        let limiter = Some(ratelimit::build_limiter(config.rate_limit.max(1)));

        Ok(Self {
            client,
            sources,
            cache,
            cache_ttl_secs: 86_400, // 24h default
            db,
            limiter,
        })
    }

    /// Create a scanner with only the offline bulk database (legacy mode).
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let db = Arc::new(db::IntelDb::open(path)?);
        Ok(Self {
            client: ScanClient::default_client(),
            sources: Vec::new(),
            cache: None,
            cache_ttl_secs: 86_400,
            db: Some(db),
            limiter: None,
        })
    }

    /// Enrich a single target using all configured sources.
    ///
    /// Emits findings via `input.emit()` and returns the number of enrichments.
    pub async fn enrich_target(&self, target: &Target, input: &ScanInput) -> anyhow::Result<usize> {
        let mut emitted = 0usize;

        // 1. Offline bulk lookup (legacy)
        if let Some(ref db) = self.db {
            let db = Arc::clone(db);
            let target = target.clone();
            let live_tx = input.live_tx.clone();
            let count = tokio::task::spawn_blocking(move || {
                let mut count = 0usize;
                let records_by_ip = if let Some(ip_addr) = target.ip() {
                    db.query_by_ip(&ip_addr.to_string()).unwrap_or_default()
                } else {
                    vec![]
                };
                let records_by_host = if let Some(host) = target.domain() {
                    db.query_by_host(host).unwrap_or_default()
                } else {
                    vec![]
                };
                for r in records_by_ip.iter().chain(records_by_host.iter()) {
                    if let Some(finding) = query::record_to_finding(r) {
                        let _ = live_tx.send(finding);
                        count += 1;
                    }
                }
                count
            })
            .await?;
            emitted += count;
        }

        // 2. Online enrichment
        let ip = target.ip().map(|i| i.to_string());
        let domain = target.domain().map(|s| s.to_string());

        for source in &self.sources {
            if let Some(ref limiter) = self.limiter {
                ratelimit::acquire(limiter, source.name()).await;
            }

            let enrichment = if let Some(ref ip) = ip {
                if let Some(ref cache) = self.cache {
                    if let Some(cached) = cache.get(source.name(), "ip", ip, self.cache_ttl_secs)? {
                        Ok(cached)
                    } else {
                        let result = source.query_ip(ip).await;
                        if let Ok(ref e) = result {
                            let _ = cache.put(e);
                        }
                        result
                    }
                } else {
                    source.query_ip(ip).await
                }
            } else if let Some(ref domain) = domain {
                if let Some(ref cache) = self.cache {
                    if let Some(cached) =
                        cache.get(source.name(), "domain", domain, self.cache_ttl_secs)?
                    {
                        Ok(cached)
                    } else {
                        let result = source.query_domain(domain).await;
                        if let Ok(ref e) = result {
                            let _ = cache.put(e);
                        }
                        result
                    }
                } else {
                    source.query_domain(domain).await
                }
            } else {
                continue;
            };

            match enrichment {
                Ok(e) => {
                    if let Some(finding) = query::enrichment_to_finding(&e) {
                        input.emit(finding);
                        emitted += 1;
                    }
                }
                Err(e) => {
                    tracing::warn!(source = source.name(), error = %e, "intel source failed");
                }
            }
        }

        Ok(emitted)
    }
}

#[async_trait]
impl Scanner for IntelScanner {
    fn name(&self) -> &'static str {
        "intel"
    }
    fn tags(&self) -> &[&'static str] {
        &["passive", "active", "intel", "enrichment"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Domain(_) | Target::Host(_))
    }

    async fn run(&self, input: ScanInput, _config: &Config) -> anyhow::Result<()> {
        let mut rx = input.target_rx.lock().await;
        while let Some(target) = rx.recv().await {
            if let Err(e) = self.enrich_target(&target, &input).await {
                tracing::warn!(error = %e, "intel enrichment failed for target");
            }
        }
        Ok(())
    }
}
