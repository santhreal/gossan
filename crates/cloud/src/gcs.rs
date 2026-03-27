//! Google Cloud Storage bucket probe.
//!
//! Two URL forms are tried:
//!   - `https://storage.googleapis.com/{name}/`  (path-style)
//!   - `https://{name}.storage.googleapis.com/`  (vhost-style)
//!
//! Also probes for unauthenticated write access via an unsigned PUT,
//! matching the depth of the S3 probe.

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

use crate::common::is_xml_listing;
use crate::provider::CloudProvider;

pub struct GcsProvider;

#[async_trait]
impl CloudProvider for GcsProvider {
    fn name(&self) -> &'static str {
        "gcs"
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        name: &str,
        target: &Target,
    ) -> anyhow::Result<Vec<Finding>> {
        let urls = [
            format!("https://storage.googleapis.com/{}/", name),
            format!("https://{}.storage.googleapis.com/", name),
        ];

        let mut findings = Vec::new();

        for url in &urls {
            let resp = match client.get(url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let status = resp.status().as_u16();

            match status {
                200 => {
                    let body = resp.text().await.unwrap_or_default();
                    findings.push(
                        crate::finding_builder(
                            target,
                            Severity::Critical,
                            format!("GCS bucket publicly listed: {}", name),
                            format!(
                                "gs://{} is publicly accessible and allows directory listing. \
                                 Use `gsutil ls gs://{}` to enumerate objects without credentials.",
                                name, name
                            ),
                        )
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("url".into(), url.clone())],
                            body_excerpt: if is_xml_listing(&body) {
                                Some(body.chars().take(300).collect())
                            } else {
                                None
                            },
                        })
                        .tag("gcs")
                        .tag("cloud")
                        .tag("exposure")
                        .exploit_hint(format!(
                            "# List objects:\ngsutil ls gs://{}\n\
                             # Download everything:\ngsutil -m cp -r gs://{}/* .",
                            name, name
                        ))
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                    try_write(client, name, url, target, &mut findings).await;
                    break; // found — no need to try second URL form
                }
                403 => {
                    findings.push(
                        crate::finding_builder(
                            target,
                            Severity::Low,
                            format!("GCS bucket exists (access denied): {}", name),
                            format!(
                                "gs://{} exists but is not publicly accessible (HTTP 403).",
                                name
                            ),
                        )
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("url".into(), url.clone())],
                            body_excerpt: None,
                        })
                        .tag("gcs")
                        .tag("cloud")
                        .build()
                        .expect("finding builder: required fields are set"),
                    );
                    try_write(client, name, url, target, &mut findings).await;
                    break;
                }
                _ => {}
            }
        }

        Ok(findings)
    }
}

/// Attempt an unauthenticated PUT to GCS. On success: Critical finding + cleanup.
async fn try_write(
    client: &reqwest::Client,
    bucket: &str,
    base_url: &str,
    target: &Target,
    findings: &mut Vec<Finding>,
) {
    const PROBE_KEY: &str = "gossan-write-probe-delete-me.txt";
    // GCS simple upload via XML API
    let put_url = if base_url.contains("storage.googleapis.com/")
        && !base_url.starts_with("https://storage")
    {
        format!("https://{}.storage.googleapis.com/{}", bucket, PROBE_KEY)
    } else {
        format!("https://storage.googleapis.com/{}/{}", bucket, PROBE_KEY)
    };

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
                format!("GCS bucket writable without authentication: {}", bucket),
                format!(
                    "An unauthenticated PUT to gs://{}/{} succeeded (HTTP {}). \
                     The `allUsers: WRITER` IAM binding is set — any attacker can upload files. \
                     Probe object deleted immediately after confirmation.",
                    bucket, PROBE_KEY, status
                ),
            )
            .evidence(Evidence::HttpResponse {
                status,
                headers: vec![("url".into(), put_url)],
                body_excerpt: None,
            })
            .tag("gcs")
            .tag("cloud")
            .tag("file-upload")
            .tag("exposure")
            .build()
            .expect("finding builder: required fields are set"),
        );
    }
}
