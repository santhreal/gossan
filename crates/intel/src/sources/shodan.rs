//! Shodan host lookup source.

use async_trait::async_trait;
use serde::Deserialize;

use crate::enrichment::{AsnInfo, GeoInfo, IntelEnrichment, ServiceInfo};
use crate::sources::IntelSource;

const BASE_URL: &str = "https://api.shodan.io";

/// Shodan API client.
pub struct ShodanSource {
    client: reqwest::Client,
    api_key: Option<String>,
}

impl ShodanSource {
    /// Create a new Shodan source.
    pub fn new(client: reqwest::Client, api_key: Option<String>) -> Self {
        Self { client, api_key }
    }
}

#[async_trait]
impl IntelSource for ShodanSource {
    fn name(&self) -> &'static str {
        "shodan"
    }

    async fn query_ip(&self, ip: &str) -> anyhow::Result<IntelEnrichment> {
        let key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Shodan requires an API key"))?;
        let url = format!("{BASE_URL}/shodan/host/{ip}?key={key}");
        let resp = self.client.get(&url).send().await?;
        let body: ShodanResp = resp.error_for_status()?.json().await?;

        let mut enrichment = IntelEnrichment::new("shodan", "ip", ip);

        if let Some(ports) = body.ports {
            for port in ports {
                enrichment.services.push(ServiceInfo {
                    port,
                    protocol: "tcp".to_string(),
                    banner: None,
                    product: None,
                });
            }
        }

        if let (Some(asn), Some(ref org)) = (body.asn, &body.org) {
            enrichment.asn = Some(AsnInfo {
                asn: asn.to_string(),
                org: Some(org.clone()),
                domain: None,
            });
        }

        if let (Some(country_name), Some(city)) = (body.country_name, body.city) {
            enrichment.geo = Some(GeoInfo {
                country: Some(country_name),
                city: Some(city),
                region: None,
            });
        }

        if let Some(tags) = body.tags {
            enrichment.tags = tags;
        }

        enrichment.raw.insert("os".to_string(), serde_json::to_value(body.os)?);
        enrichment.raw.insert("isp".to_string(), serde_json::to_value(body.isp)?);

        Ok(enrichment)
    }

    async fn query_domain(&self, domain: &str) -> anyhow::Result<IntelEnrichment> {
        let key = self
            .api_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Shodan requires an API key"))?;
        let url = format!("{BASE_URL}/dns/domain/{domain}?key={key}");
        let resp = self.client.get(&url).send().await?;
        let body: ShodanDnsResp = resp.error_for_status()?.json().await?;

        let mut enrichment = IntelEnrichment::new("shodan", "domain", domain);
        for sub in body.subdomains.unwrap_or_default() {
            enrichment.passive_dns.push(crate::enrichment::DnsRecord {
                record_type: "A".to_string(),
                value: format!("{sub}.{domain}"),
                first_seen: None,
                last_seen: None,
            });
        }

        Ok(enrichment)
    }
}

#[derive(Debug, Deserialize)]
struct ShodanResp {
    #[serde(default)]
    ports: Option<Vec<u16>>,
    #[serde(default)]
    asn: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    country_name: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    isp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ShodanDnsResp {
    #[serde(default)]
    subdomains: Option<Vec<String>>,
}
