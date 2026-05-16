//! URLScan source — URL and domain scanning intelligence.

use async_trait::async_trait;
use serde::Deserialize;

use crate::enrichment::IntelEnrichment;
use crate::sources::IntelSource;

const BASE_URL: &str = "https://urlscan.io/api/v1";

/// URLScan API client.
pub struct UrlScanSource {
    client: reqwest::Client,
    api_key: Option<String>,
}

impl UrlScanSource {
    /// Create a new URLScan source.
    pub fn new(client: reqwest::Client, api_key: Option<String>) -> Self {
        Self { client, api_key }
    }
}

#[async_trait]
impl IntelSource for UrlScanSource {
    fn name(&self) -> &'static str {
        "urlscan"
    }

    async fn query_ip(&self, ip: &str) -> anyhow::Result<IntelEnrichment> {
        // URLScan search by IP
        let url = format!("{BASE_URL}/search/?q=ip:{ip}");
        let mut req = self.client.get(&url);
        if let Some(ref key) = self.api_key {
            req = req.header("API-Key", key);
        }
        let resp = req.send().await?.error_for_status()?;
        // URLScan search responses can include hundreds of historical
        // crawls per query; cap at 8 MiB.
        let body: UrlScanSearchResp = gossan_core::net::bounded_json(resp, 8 * 1024 * 1024).await?;

        let mut enrichment = IntelEnrichment::new("urlscan", "ip", ip);
        enrichment.classification = body
            .results
            .first()
            .and_then(|r| r.page.as_ref())
            .and_then(|p| p.country.clone());

        for result in body.results.into_iter().take(10) {
            if let Some(server) = result.page.as_ref().and_then(|p| p.server.clone()) {
                enrichment.technologies.push(server);
            }
        }

        enrichment
            .raw
            .insert("total".to_string(), serde_json::to_value(body.total)?);

        Ok(enrichment)
    }

    async fn query_domain(&self, domain: &str) -> anyhow::Result<IntelEnrichment> {
        let url = format!("{BASE_URL}/search/?q=domain:{domain}");
        let mut req = self.client.get(&url);
        if let Some(ref key) = self.api_key {
            req = req.header("API-Key", key);
        }
        let resp = req.send().await?.error_for_status()?;
        // URLScan search responses can include hundreds of historical
        // crawls per query; cap at 8 MiB.
        let body: UrlScanSearchResp = gossan_core::net::bounded_json(resp, 8 * 1024 * 1024).await?;

        let mut enrichment = IntelEnrichment::new("urlscan", "domain", domain);
        for result in body.results.into_iter().take(10) {
            if let Some(server) = result.page.as_ref().and_then(|p| p.server.clone()) {
                enrichment.technologies.push(server);
            }
        }

        enrichment
            .raw
            .insert("total".to_string(), serde_json::to_value(body.total)?);

        Ok(enrichment)
    }
}

#[derive(Debug, Deserialize)]
struct UrlScanSearchResp {
    #[serde(default)]
    total: u32,
    #[serde(default)]
    results: Vec<UrlScanResult>,
}

#[derive(Debug, Deserialize)]
struct UrlScanResult {
    #[serde(default)]
    page: Option<UrlScanPage>,
}

#[derive(Debug, Deserialize)]
struct UrlScanPage {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    server: Option<String>,
}
