//! DigitalOcean Spaces probe.
//!
//! URL format: `https://{bucket}.{region}.digitaloceanspaces.com/`
//!
//! DO Spaces is S3-compatible, so the same listing and write probes apply.
//! Regions are tried in order; scan stops at first confirmed result.

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};
use serde::Deserialize;
use std::sync::OnceLock;

use crate::common::is_xml_listing;
use crate::provider::CloudProvider;

/// DO Spaces region definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct DoRegion {
    id: String,
    #[allow(dead_code)]
    location: String,
    #[allow(dead_code)]
    country: String,
}

/// TOML file containing DO Spaces region definitions.
#[derive(Debug, Deserialize)]
struct DoRegionsFile {
    region: Vec<DoRegion>,
}

/// Built-in do_spaces.toml content (embedded at compile time).
const BUILTIN_DO_SPACES: &str = include_str!("../rules/do_spaces.toml");

/// Global cache for built-in DO regions.
static DO_REGIONS: OnceLock<Vec<DoRegion>> = OnceLock::new();

/// Initialize and return the built-in DO Spaces regions.
fn builtin_do_regions() -> &'static Vec<DoRegion> {
    DO_REGIONS.get_or_init(|| {
        match toml::from_str::<DoRegionsFile>(BUILTIN_DO_SPACES) {
            Ok(file) => file.region,
            Err(e) => {
                tracing::error!(error = %e, "failed to parse built-in do_spaces.toml");
                // Fallback to minimal hardcoded list only on parse failure
                vec![
                    DoRegion {
                        id: "nyc3".to_string(),
                        location: "New York City".to_string(),
                        country: "US".to_string(),
                    },
                    DoRegion {
                        id: "ams3".to_string(),
                        location: "Amsterdam".to_string(),
                        country: "NL".to_string(),
                    },
                ]
            }
        }
    })
}

/// Get region IDs from TOML configuration.
fn region_ids() -> &'static [DoRegion] {
    builtin_do_regions()
}

pub struct DoSpacesProvider;

#[async_trait]
impl CloudProvider for DoSpacesProvider {
    fn name(&self) -> &'static str {
        "spaces"
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        name: &str,
        target: &Target,
    ) -> anyhow::Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for region in region_ids() {
            let url = format!("https://{}.{}.digitaloceanspaces.com/", name, region.id);

            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let status = resp.status().as_u16();

            match status {
                200 => {
                    let body = resp.text().await.unwrap_or_default();
                    let listed = is_xml_listing(&body);
                    findings.push(
                        crate::finding_builder(
                            target,
                            if listed {
                                Severity::Critical
                            } else {
                                Severity::High
                            },
                            format!("Public DO Spaces bucket: {} ({})", name, region.id),
                            if listed {
                                format!(
                                    "DO Spaces bucket '{}' ({}) is publicly listable — \
                                     all object keys enumerable.",
                                    name, region.id
                                )
                            } else {
                                format!(
                                    "DO Spaces bucket '{}' ({}) returns 200 — publicly accessible.",
                                    name, region.id
                                )
                            },
                        )
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("url".into(), url.clone())],
                            body_excerpt: Some(body.chars().take(200).collect()),
                        })
                        .tag("cloud")
                        .tag("storage")
                        .tag("do-spaces")
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                    try_write(client, name, &region.id, &url, target, &mut findings).await;
                    break;
                }
                403 => {
                    findings.push(
                        crate::finding_builder(
                            target,
                            Severity::Low,
                            format!("DO Spaces bucket exists (private): {} ({})", name, region.id),
                            format!(
                                "DO Spaces bucket '{}' ({}) exists but is private (HTTP 403). \
                                 Verify ownership.",
                                name, region.id
                            ),
                        )
                        .tag("cloud")
                        .tag("storage")
                        .tag("do-spaces")
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                    try_write(client, name, &region.id, &url, target, &mut findings).await;
                    break;
                }
                _ => {}
            }
        }

        Ok(findings)
    }
}

/// Attempt an unauthenticated S3-compatible PUT. On success: Critical finding + cleanup.
async fn try_write(
    client: &reqwest::Client,
    bucket: &str,
    region: &str,
    _base_url: &str,
    target: &Target,
    findings: &mut Vec<Finding>,
) {
    const PROBE_KEY: &str = "gossan-write-probe-delete-me.txt";
    let put_url = format!(
        "https://{}.{}.digitaloceanspaces.com/{}",
        bucket, region, PROBE_KEY
    );

    let Ok(resp) = client
        .put(&put_url)
        .header("content-type", "text/plain")
        .body("gossan-security-probe — safe to delete")
        .send()
        .await
    else {
        return;
    };

    let status = resp.status().as_u16();
    if matches!(status, 200 | 204) {
        let _ = client.delete(&put_url).send().await;
        findings.push(
            crate::finding_builder(
                target,
                Severity::Critical,
                format!(
                    "DO Spaces bucket writable without authentication: {} ({})",
                    bucket, region
                ),
                format!(
                    "An unauthenticated PUT to '{}/{}' succeeded (HTTP {}). \
                     Probe object deleted immediately after confirmation.",
                    put_url.trim_end_matches(PROBE_KEY),
                    PROBE_KEY,
                    status
                ),
            )
            .evidence(Evidence::HttpResponse {
                status,
                headers: vec![("url".into(), put_url.clone())],
                body_excerpt: None,
            })
            .tag("cloud")
            .tag("storage")
            .tag("do-spaces")
            .tag("file-upload")
            .build()
            .expect("finding builder: required fields are set"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn do_regions_load_from_toml() {
        let regions = region_ids();
        assert!(!regions.is_empty(), "should have DO regions from TOML");
        
        // Check for expected regions
        assert!(
            regions.iter().any(|r| r.id == "nyc3"),
            "should include nyc3 region"
        );
        assert!(
            regions.iter().any(|r| r.id == "ams3"),
            "should include ams3 region"
        );
    }

    #[test]
    fn do_regions_have_required_fields() {
        for region in region_ids() {
            assert!(!region.id.is_empty(), "region id should not be empty");
            assert!(!region.location.is_empty(), "location should not be empty");
            assert!(!region.country.is_empty(), "country should not be empty");
        }
    }

    #[test]
    fn do_regions_cover_major_geographies() {
        let ids: Vec<_> = region_ids().iter().map(|r| r.id.clone()).collect();
        for expected in ["nyc3", "ams3", "sgp1", "fra1"] {
            assert!(ids.contains(&expected.to_string()), "missing region: {}", expected);
        }
    }
}
