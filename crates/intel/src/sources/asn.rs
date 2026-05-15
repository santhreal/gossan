//! ASN source — ipinfo.io (free tier) or MaxMind fallback.

use async_trait::async_trait;
use serde::Deserialize;

use crate::enrichment::{AsnInfo, GeoInfo, IntelEnrichment};
use crate::sources::IntelSource;

const BASE_URL: &str = "https://ipinfo.io";

/// ASN / GeoIP source.
pub struct AsnSource {
    client: reqwest::Client,
    token: Option<String>,
}

impl AsnSource {
    /// Create a new ASN source.
    pub fn new(client: reqwest::Client, token: Option<String>) -> Self {
        Self { client, token }
    }
}

#[async_trait]
impl IntelSource for AsnSource {
    fn name(&self) -> &'static str {
        "asn"
    }

    async fn query_ip(&self, ip: &str) -> anyhow::Result<IntelEnrichment> {
        let mut url = format!("{BASE_URL}/{ip}/json");
        if let Some(ref token) = self.token {
            url.push_str(&format!("?token={token}"));
        }
        let resp = self.client.get(&url).send().await?;
        let body: IpInfoResp = resp.error_for_status()?.json().await?;

        let mut enrichment = IntelEnrichment::new("asn", "ip", ip);
        enrichment.asn = Some(AsnInfo {
            asn: body.asn.clone().unwrap_or_default(),
            org: body.org.clone(),
            domain: None,
        });
        enrichment.geo = Some(GeoInfo {
            country: body.country.clone(),
            city: body.city.clone(),
            region: body.region.clone(),
        });

        enrichment
            .raw
            .insert("loc".to_string(), serde_json::to_value(body.loc)?);

        Ok(enrichment)
    }

    async fn query_domain(&self, domain: &str) -> anyhow::Result<IntelEnrichment> {
        // ipinfo.io supports domain lookup as well
        let mut url = format!("{BASE_URL}/{domain}/json");
        if let Some(ref token) = self.token {
            url.push_str(&format!("?token={token}"));
        }
        let resp = self.client.get(&url).send().await?;
        let body: IpInfoResp = resp.error_for_status()?.json().await?;

        let mut enrichment = IntelEnrichment::new("asn", "domain", domain);
        enrichment.asn = Some(AsnInfo {
            asn: body.asn.clone().unwrap_or_default(),
            org: body.org.clone(),
            domain: None,
        });
        enrichment.geo = Some(GeoInfo {
            country: body.country.clone(),
            city: body.city.clone(),
            region: body.region.clone(),
        });

        Ok(enrichment)
    }
}

#[derive(Debug, Deserialize)]
struct IpInfoResp {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    region: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    loc: Option<String>,
    #[serde(default)]
    org: Option<String>,
    #[serde(default)]
    asn: Option<String>,
}
