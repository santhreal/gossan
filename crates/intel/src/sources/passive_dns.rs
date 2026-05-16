//! Passive DNS source — CIRCL/PassiveTotal/DNSDB style.
//!
//! This implementation uses a generic pdns endpoint shape common to many
//! providers. In production it can be wired to a specific backend via config.

use async_trait::async_trait;
use serde::Deserialize;

use crate::enrichment::{DnsRecord, IntelEnrichment};
use crate::sources::IntelSource;

/// Passive DNS API client.
pub struct PassiveDnsSource {
    client: reqwest::Client,
    api_key: Option<String>,
    endpoint: String,
}

impl PassiveDnsSource {
    /// Create a new Passive DNS source.
    pub fn new(client: reqwest::Client, api_key: Option<String>, endpoint: String) -> Self {
        Self {
            client,
            api_key,
            endpoint,
        }
    }
}

#[async_trait]
impl IntelSource for PassiveDnsSource {
    fn name(&self) -> &'static str {
        "passive_dns"
    }

    async fn query_ip(&self, ip: &str) -> anyhow::Result<IntelEnrichment> {
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Passive DNS requires an API key"))?;
        let url = format!("{}/lookup/rdata/{ip}", self.endpoint);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(api_key)
            .send()
            .await?
            .error_for_status()?;
        // Passive-DNS history for a busy hostname can run into many
        // thousand records; cap at 8 MiB to bound the worst case.
        let body: PdnsResp = gossan_core::net::bounded_json(resp, 8 * 1024 * 1024).await?;

        let mut enrichment = IntelEnrichment::new("passive_dns", "ip", ip);
        for rec in body.records {
            enrichment.passive_dns.push(DnsRecord {
                record_type: rec.rrtype,
                value: rec.rdata,
                first_seen: rec.time_first.map(|t| t.to_string()),
                last_seen: rec.time_last.map(|t| t.to_string()),
            });
        }

        Ok(enrichment)
    }

    async fn query_domain(&self, domain: &str) -> anyhow::Result<IntelEnrichment> {
        let api_key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Passive DNS requires an API key"))?;
        let url = format!("{}/lookup/rrset/name/{domain}", self.endpoint);
        let resp = self
            .client
            .get(&url)
            .bearer_auth(api_key)
            .send()
            .await?
            .error_for_status()?;
        // Passive-DNS history for a busy hostname can run into many
        // thousand records; cap at 8 MiB to bound the worst case.
        let body: PdnsResp = gossan_core::net::bounded_json(resp, 8 * 1024 * 1024).await?;

        let mut enrichment = IntelEnrichment::new("passive_dns", "domain", domain);
        for rec in body.records {
            enrichment.passive_dns.push(DnsRecord {
                record_type: rec.rrtype,
                value: rec.rdata,
                first_seen: rec.time_first.map(|t| t.to_string()),
                last_seen: rec.time_last.map(|t| t.to_string()),
            });
        }

        Ok(enrichment)
    }
}

#[derive(Debug, Deserialize)]
struct PdnsResp {
    #[serde(default)]
    records: Vec<PdnsRecord>,
}

#[derive(Debug, Deserialize)]
struct PdnsRecord {
    rrtype: String,
    rdata: String,
    #[serde(default)]
    time_first: Option<u64>,
    #[serde(default)]
    time_last: Option<u64>,
}
