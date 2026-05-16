//! AbuseIPDB source — IP reputation and abuse reports.

use async_trait::async_trait;
use serde::Deserialize;

use crate::enrichment::{IntelEnrichment, ServiceInfo};
use crate::sources::IntelSource;

const BASE_URL: &str = "https://api.abuseipdb.com/api/v2/check";

/// AbuseIPDB API client.
pub struct AbuseIpdbSource {
    client: reqwest::Client,
    api_key: Option<String>,
}

impl AbuseIpdbSource {
    /// Create a new AbuseIPDB source.
    pub fn new(client: reqwest::Client, api_key: Option<String>) -> Self {
        Self { client, api_key }
    }
}

#[async_trait]
impl IntelSource for AbuseIpdbSource {
    fn name(&self) -> &'static str {
        "abuseipdb"
    }

    async fn query_ip(&self, ip: &str) -> anyhow::Result<IntelEnrichment> {
        let key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("AbuseIPDB requires an API key"))?;
        let resp = self
            .client
            .get(BASE_URL)
            .header("Key", key)
            .header("Accept", "application/json")
            .query(&[("ipAddress", ip), ("maxAgeInDays", "90")])
            .send()
            .await?
            .error_for_status()?;
        // 256 KiB is well above the largest legitimate AbuseIPDB
        // response observed in production; bounding here protects
        // against a hostile MITM injecting a giant body.
        let body: AbuseIpdbResp = gossan_core::net::bounded_json(resp, 256 * 1024).await?;

        let mut enrichment = IntelEnrichment::new("abuseipdb", "ip", ip);
        enrichment.classification = if body.data.abuse_confidence_score > 75 {
            Some("malicious".to_string())
        } else if body.data.abuse_confidence_score > 25 {
            Some("suspicious".to_string())
        } else {
            Some("benign".to_string())
        };

        if let Some(country) = body.data.country_code {
            enrichment.geo = Some(crate::enrichment::GeoInfo {
                country: Some(country),
                city: None,
                region: None,
            });
        }

        enrichment.services.push(ServiceInfo {
            port: 0,
            protocol: "tcp".to_string(),
            banner: None,
            product: body.data.usage_type,
        });

        enrichment.raw.insert(
            "abuse_confidence_score".to_string(),
            serde_json::to_value(body.data.abuse_confidence_score)?,
        );
        enrichment.raw.insert(
            "total_reports".to_string(),
            serde_json::to_value(body.data.total_reports)?,
        );

        Ok(enrichment)
    }

    async fn query_domain(&self, _domain: &str) -> anyhow::Result<IntelEnrichment> {
        anyhow::bail!("AbuseIPDB does not support domain enrichment")
    }
}

#[derive(Debug, Deserialize)]
struct AbuseIpdbResp {
    data: AbuseIpdbData,
}

#[derive(Debug, Deserialize)]
struct AbuseIpdbData {
    ip_address: String,
    abuse_confidence_score: u8,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    usage_type: Option<String>,
    #[serde(default)]
    total_reports: Option<u32>,
}
