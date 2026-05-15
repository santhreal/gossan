//! VirusTotal source — IP and domain reputation.

use async_trait::async_trait;
use serde::Deserialize;

use crate::enrichment::{IntelEnrichment, ServiceInfo};
use crate::sources::IntelSource;

const BASE_URL: &str = "https://www.virustotal.com/api/v3";

/// VirusTotal API client.
pub struct VirusTotalSource {
    client: reqwest::Client,
    api_key: Option<String>,
}

impl VirusTotalSource {
    /// Create a new VirusTotal source.
    pub fn new(client: reqwest::Client, api_key: Option<String>) -> Self {
        Self { client, api_key }
    }
}

#[async_trait]
impl IntelSource for VirusTotalSource {
    fn name(&self) -> &'static str {
        "virustotal"
    }

    async fn query_ip(&self, ip: &str) -> anyhow::Result<IntelEnrichment> {
        let key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("VirusTotal requires an API key"))?;
        let url = format!("{BASE_URL}/ip_addresses/{ip}");
        let resp = self
            .client
            .get(&url)
            .header("x-apikey", key)
            .send()
            .await?;
        let body: VtResp = resp.error_for_status()?.json().await?;

        let mut enrichment = IntelEnrichment::new("virustotal", "ip", ip);
        if let Some(stats) = body.data.attributes.last_analysis_stats {
            let malicious = stats.malicious.unwrap_or(0);
            let suspicious = stats.suspicious.unwrap_or(0);
            let harmless = stats.harmless.unwrap_or(0);
            enrichment.classification = if malicious > 0 {
                Some("malicious".to_string())
            } else if suspicious > 0 {
                Some("suspicious".to_string())
            } else if harmless > 0 {
                Some("benign".to_string())
            } else {
                Some("unknown".to_string())
            };
            enrichment.raw.insert(
                "last_analysis_stats".to_string(),
                serde_json::to_value(stats)?,
            );
        }

        if let Some(ref asn) = body.data.attributes.asn {
            enrichment.asn = Some(crate::enrichment::AsnInfo {
                asn: asn.to_string(),
                org: body.data.attributes.as_owner.clone(),
                domain: None,
            });
        }

        if let Some(country) = body.data.attributes.country {
            enrichment.geo = Some(crate::enrichment::GeoInfo {
                country: Some(country),
                city: None,
                region: None,
            });
        }

        Ok(enrichment)
    }

    async fn query_domain(&self, domain: &str) -> anyhow::Result<IntelEnrichment> {
        let key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("VirusTotal requires an API key"))?;
        let url = format!("{BASE_URL}/domains/{domain}");
        let resp = self
            .client
            .get(&url)
            .header("x-apikey", key)
            .send()
            .await?;
        let body: VtResp = resp.error_for_status()?.json().await?;

        let mut enrichment = IntelEnrichment::new("virustotal", "domain", domain);
        if let Some(stats) = body.data.attributes.last_analysis_stats {
            let malicious = stats.malicious.unwrap_or(0);
            let suspicious = stats.suspicious.unwrap_or(0);
            enrichment.classification = if malicious > 0 {
                Some("malicious".to_string())
            } else if suspicious > 0 {
                Some("suspicious".to_string())
            } else {
                Some("benign".to_string())
            };
            enrichment.raw.insert(
                "last_analysis_stats".to_string(),
                serde_json::to_value(stats)?,
            );
        }

        Ok(enrichment)
    }
}

#[derive(Debug, Deserialize)]
struct VtResp {
    data: VtData,
}

#[derive(Debug, Deserialize)]
struct VtData {
    attributes: VtAttributes,
}

#[derive(Debug, Deserialize)]
struct VtAttributes {
    #[serde(default)]
    last_analysis_stats: Option<VtStats>,
    #[serde(default)]
    asn: Option<u64>,
    #[serde(default)]
    as_owner: Option<String>,
    #[serde(default)]
    country: Option<String>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct VtStats {
    #[serde(default)]
    malicious: Option<u32>,
    #[serde(default)]
    suspicious: Option<u32>,
    #[serde(default)]
    harmless: Option<u32>,
    #[serde(default)]
    undetected: Option<u32>,
}
