//! Censys host context v2 source.

use async_trait::async_trait;
use serde::Deserialize;

use crate::enrichment::{AsnInfo, IntelEnrichment, ServiceInfo};
use crate::sources::IntelSource;

const BASE_URL: &str = "https://search.censys.io/api/v2/hosts";

/// Censys API client.
pub struct CensysSource {
    client: reqwest::Client,
    api_id: Option<String>,
    api_secret: Option<String>,
}

impl CensysSource {
    /// Create a new Censys source.
    pub fn new(
        client: reqwest::Client,
        api_id: Option<String>,
        api_secret: Option<String>,
    ) -> Self {
        Self {
            client,
            api_id,
            api_secret,
        }
    }
}

#[async_trait]
impl IntelSource for CensysSource {
    fn name(&self) -> &'static str {
        "censys"
    }

    async fn query_ip(&self, ip: &str) -> anyhow::Result<IntelEnrichment> {
        let api_id = self
            .api_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Censys requires API ID"))?;
        let api_secret = self
            .api_secret
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Censys requires API secret"))?;
        let url = format!("{BASE_URL}/{ip}");
        let resp = self
            .client
            .get(&url)
            .basic_auth(api_id, Some(api_secret))
            .send()
            .await?;
        let body: CensysResp = resp.error_for_status()?.json().await?;

        let mut enrichment = IntelEnrichment::new("censys", "ip", ip);

        if let Some(services) = body.result.services {
            for svc in services {
                enrichment.services.push(ServiceInfo {
                    port: svc.port,
                    protocol: svc.transport_protocol.unwrap_or_else(|| "tcp".to_string()),
                    banner: svc.banner,
                    product: svc.service_name.clone(),
                });
                if let Some(software) = svc.software {
                    for sw in software {
                        if let Some(name) = sw.product {
                            enrichment.technologies.push(name);
                        }
                    }
                }
            }
        }

        if let Some(ref asn) = body.result.asn {
            enrichment.asn = Some(AsnInfo {
                asn: asn.asn.clone(),
                org: asn.name.clone(),
                domain: None,
            });
        }

        enrichment.raw.insert("censys_code".to_string(), serde_json::to_value(body.code)?);

        Ok(enrichment)
    }

    async fn query_domain(&self, _domain: &str) -> anyhow::Result<IntelEnrichment> {
        anyhow::bail!("Censys host context v2 does not support domain enrichment")
    }
}

#[derive(Debug, Deserialize)]
struct CensysResp {
    code: i32,
    result: CensysResult,
}

#[derive(Debug, Deserialize)]
struct CensysResult {
    #[serde(default)]
    services: Option<Vec<CensysService>>,
    #[serde(default)]
    asn: Option<CensysAsn>,
}

#[derive(Debug, Deserialize)]
struct CensysService {
    port: u16,
    #[serde(default)]
    transport_protocol: Option<String>,
    #[serde(default)]
    banner: Option<String>,
    #[serde(default)]
    service_name: Option<String>,
    #[serde(default)]
    software: Option<Vec<CensysSoftware>>,
}

#[derive(Debug, Deserialize)]
struct CensysSoftware {
    #[serde(default)]
    product: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CensysAsn {
    asn: String,
    name: Option<String>,
}
