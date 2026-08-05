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
/// Google Cloud Storage bucket discovery.
pub struct GcsProvider {
    /// Optional endpoint override for testing.
    pub(crate) endpoint_override: Option<String>,
}

impl GcsProvider {
    /// Create a new GCS provider with the default Google endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self { endpoint_override: None }
    }

    /// Create a GCS provider with a custom endpoint (for tests).
    #[must_use]
    pub fn with_endpoint(url: impl Into<String>) -> Self {
        Self { endpoint_override: Some(url.into()) }
    }
}

impl Default for GcsProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CloudProvider for GcsProvider {
    fn name(&self) -> &'static str {
        "gcs"
    }

    fn endpoint(&self, name: &str) -> String {
        if let Some(ref url) = self.endpoint_override {
            return url.clone();
        }
        format!("https://{}.storage.googleapis.com/", name)
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        name: &str,
        target: &Target,
    ) -> anyhow::Result<Vec<Finding>> {
        let vhost = self.endpoint(name);
        let path = format!("https://storage.googleapis.com/{}/", name);

        let mut urls = vec![vhost.clone()];
        if vhost.contains("googleapis.com") {
            urls.push(path);
        }

        let mut findings = Vec::new();

        for url in &urls {
            let resp = match client.get(url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        bucket = %name,
                        url = %url,
                        error = %e,
                        "GCS probe send failed"
                    );
                    continue;
                }
            };
            let status = resp.status().as_u16();

            match status {
                200 => {
                    let body = match gossan_core::net::bounded_text(
                        resp,
                        crate::MAX_CLOUD_RESPONSE_BYTES,
                    )
                    .await
                    {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                bucket = %name,
                                url = %url,
                                error = %e,
                                "GCS body read failed"
                            );
                            continue;
                        }
                    };
                    gossan_core::try_push_finding(
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
                            headers: vec![("url".into(), url.clone().into())],
                            body_excerpt: if is_xml_listing(&body) {
                                Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into())
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
                        )),
                        &mut findings,
                    );
                    try_write(client, name, url, target, &mut findings).await;
                    break; // found, no need to try second URL form
                }
                403 => {
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
    let put_url = if !base_url.contains("googleapis.com") {
        // Custom endpoint (e.g. test mock) (append probe key directly).
        format!("{}/{}", base_url.trim_end_matches('/'), PROBE_KEY)
    } else if base_url.contains("storage.googleapis.com/")
        && !base_url.starts_with("https://storage")
    {
        format!("https://{}.storage.googleapis.com/{}", bucket, PROBE_KEY)
    } else {
        format!("https://storage.googleapis.com/{}/{}", bucket, PROBE_KEY)
    };

    let Ok(resp) = client
        .put(&put_url)
        .header("content-type", "text/plain")
        .body("gossan-security-probe, safe to delete")
        .send()
        .await
    else {
        return;
    };

    let status = resp.status().as_u16();
    if matches!(status, 200 | 204) {
        if let Err(e) = client.delete(&put_url).send().await {
            tracing::error!(bucket = %bucket, err = %e, "probe cleanup failed");
        }
        gossan_core::try_push_finding(
            crate::finding_builder(
                target,
                Severity::Critical,
                format!("GCS bucket writable without authentication: {}", bucket),
                format!(
                    "An unauthenticated PUT to gs://{}/{} succeeded (HTTP {}). \
                     The `allUsers: WRITER` IAM binding is set, any attacker can upload files. \
                     Probe object deleted immediately after confirmation.",
                    bucket, PROBE_KEY, status
                ),
            )
            .evidence(Evidence::HttpResponse {
                status,
                headers: vec![("url".into(), put_url.into())],
                body_excerpt: None,
            })
            .tag("gcs")
            .tag("cloud")
            .tag("file-upload")
            .tag("exposure"),
            findings,
        );
    }
}
