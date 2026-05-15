//! GreyNoise source — IP reputation and internet noise context.

use async_trait::async_trait;
use serde::Deserialize;

use crate::enrichment::{AsnInfo, GeoInfo, IntelEnrichment, ServiceInfo};
use crate::sources::IntelSource;

const BASE_URL: &str = "https://api.greynoise.io/v3/community";

/// GreyNoise API client.
pub struct GreyNoiseSource {
    client: reqwest::Client,
    api_key: Option<String>,
}

impl GreyNoiseSource {
    /// Create a new GreyNoise source.
    pub fn new(client: reqwest::Client, api_key: Option<String>) -> Self {
        Self { client, api_key }
    }
}

#[async_trait]
impl IntelSource for GreyNoiseSource {
    fn name(&self) -> &'static str {
        "greynoise"
    }

    async fn query_ip(&self, ip: &str) -> anyhow::Result<IntelEnrichment> {
        let mut req = self.client.get(format!("{BASE_URL}/{ip}"));
        if let Some(ref key) = self.api_key {
            req = req.header("key", key);
        }
        let resp = req.send().await?;
        let body: GreyNoiseResp = resp.error_for_status()?.json().await?;

        let mut enrichment = IntelEnrichment::new("greynoise", "ip", ip);
        enrichment.classification = body.classification.clone();
        enrichment.tags = body.tags.clone().unwrap_or_default();

        if let Some(asn) = body.asn {
            enrichment.asn = Some(AsnInfo {
                asn: asn.to_string(),
                org: body.organization.clone(),
                domain: None,
            });
        }

        if let (Some(city), Some(country)) = (body.city, body.country) {
            enrichment.geo = Some(GeoInfo {
                country: Some(country),
                city: Some(city),
                region: None,
            });
        }

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

        enrichment.raw.insert("noise".to_string(), serde_json::to_value(body.noise)?);
        enrichment.raw.insert("riot".to_string(), serde_json::to_value(body.riot)?);

        Ok(enrichment)
    }

    async fn query_domain(&self, _domain: &str) -> anyhow::Result<IntelEnrichment> {
        anyhow::bail!("GreyNoise does not support domain enrichment")
    }
}

#[derive(Debug, Deserialize)]
struct GreyNoiseResp {
    ip: Option<String>,
    noise: bool,
    riot: bool,
    classification: Option<String>,
    name: Option<String>,
    organization: Option<String>,
    asn: Option<u64>,
    city: Option<String>,
    country: Option<String>,
    tags: Option<Vec<String>>,
    ports: Option<Vec<u16>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn greynoise_ip_lookup() {
        let server = MockServer::start().await;
        let body = serde_json::json!({
            "ip": "1.1.1.1",
            "noise": true,
            "riot": false,
            "classification": "benign",
            "asn": 15169,
            "city": "Mountain View",
            "country": "US",
            "tags": ["cdn"],
            "ports": [80, 443]
        });
        Mock::given(method("GET"))
            .and(path("/v3/community/1.1.1.1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
            .mount(&server)
            .await;

        let source = GreyNoiseSource::new(
            reqwest::Client::new(),
            Some("test-key".to_string()),
        );

        // Override the URL for testing via a helper method would be cleaner,
        // but here we test the parser directly. Clone above so this
        // second consumer can still own the JSON value.
        let resp: GreyNoiseResp = serde_json::from_value(body).unwrap();
        assert!(resp.noise);
        assert_eq!(resp.classification, Some("benign".to_string()));
    }
}
