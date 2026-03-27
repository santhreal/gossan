//! DigitalOcean Spaces probe.
//!
//! URL format: `https://{bucket}.{region}.digitaloceanspaces.com/`
//!
//! DO Spaces is S3-compatible, so the same listing and write probes apply.
//! Regions are tried in order; scan stops at first confirmed result.

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

use crate::common::is_xml_listing;
use crate::provider::CloudProvider;

const REGIONS: &[&str] = &[
    "nyc3", "sgp1", "ams3", "fra1", "sfo2", "sfo3", "lon1", "blr1",
];

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

        for region in REGIONS {
            let url = format!("https://{}.{}.digitaloceanspaces.com/", name, region);

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
                            format!("Public DO Spaces bucket: {} ({})", name, region),
                            if listed {
                                format!(
                                    "DO Spaces bucket '{}' ({}) is publicly listable — \
                                     all object keys enumerable.",
                                    name, region
                                )
                            } else {
                                format!(
                                    "DO Spaces bucket '{}' ({}) returns 200 — publicly accessible.",
                                    name, region
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
                    try_write(client, name, region, &url, target, &mut findings).await;
                    break;
                }
                403 => {
                    findings.push(
                        crate::finding_builder(
                            target,
                            Severity::Low,
                            format!("DO Spaces bucket exists (private): {} ({})", name, region),
                            format!(
                                "DO Spaces bucket '{}' ({}) exists but is private (HTTP 403). \
                                 Verify ownership.",
                                name, region
                            ),
                        )
                        .tag("cloud")
                        .tag("storage")
                        .tag("do-spaces")
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                    try_write(client, name, region, &url, target, &mut findings).await;
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
                headers: vec![("url".into(), put_url)],
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
