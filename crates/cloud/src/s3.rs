//! AWS S3 bucket probe.
//!
//! Three-stage test per candidate:
//!   1. GET `/`  — 200 + XML listing = public (Critical)
//!   2. PUT canary object — succeeds = unauthenticated write (Critical)
//!   3. GET `/` + 403 — bucket confirmed, listing denied (Low)
//!
//! Both vhost-style (`{name}.s3.amazonaws.com`) and path-style
//! (`s3.amazonaws.com/{name}`) URLs are tried; some older regions only
//! accept path-style.

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

use crate::common::is_xml_listing;
use crate::provider::CloudProvider;
/// AWS S3 bucket discovery and permission enumeration.
pub struct S3Provider;

#[async_trait]
impl CloudProvider for S3Provider {
    fn name(&self) -> &'static str {
        "s3"
    }

    fn endpoint(&self, name: &str) -> String {
        let encoded_name = urlencoding::encode(name);
        format!("https://{}.s3.amazonaws.com/", encoded_name)
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        name: &str,
        target: &Target,
    ) -> anyhow::Result<Vec<Finding>> {
        let vhost = self.endpoint(name);
        let encoded_name = urlencoding::encode(name);
        let path = format!("https://s3.amazonaws.com/{}/", encoded_name);
        let mut findings = Vec::new();

        // Stage 1: directory listing probe
        let (status, body, effective_url) = {
            let mut status = 0u16;
            let mut body = String::new();
            let mut eff = vhost.clone();

            if let Ok(resp) = client.get(&vhost).send().await {
                status = resp.status().as_u16();
                body = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024)
                    .await
                    .unwrap_or_default();
            }
            // Retry path-style ONLY if we are using the real AWS endpoint
            if (status == 0 || status == 301) && vhost.contains("amazonaws.com") {
                if let Ok(resp) = client.get(&path).send().await {
                    status = resp.status().as_u16();
                    body = gossan_core::net::bounded_text(resp, 4 * 1024 * 1024)
                        .await
                        .unwrap_or_default();
                    eff = path.clone();
                }
            }
            (status, body, eff)
        };

        match status {
            200 => {
                gossan_core::try_push_finding(crate::finding_builder(target, Severity::Critical,
                        format!("S3 bucket publicly listed: {}", name),
                        format!(
                            "s3://{} is publicly accessible and allows directory listing. \
                             All object keys are enumerable; use \
                             `aws s3 ls s3://{} --no-sign-request` to download without credentials.",
                            name, name
                        ))
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: vec![("url".into(), effective_url.clone().into())],
                        body_excerpt: if is_xml_listing(&body) {
                            Some(body.chars().take(400).collect::<String>().into())
                        } else {
                            None
                        },
                    })
                    .tag("s3").tag("cloud").tag("exposure")
                    .exploit_hint(format!(
                        "# List all objects:\naws s3 ls s3://{} --no-sign-request\n\
                         # Download everything:\naws s3 sync s3://{} . --no-sign-request",
                        name, name
                    )), &mut findings);
                // Stage 2: write-access check
                try_write(client, name, &effective_url, target, &mut findings).await;
            }
            403 => {
                gossan_core::try_push_finding(
                    crate::finding_builder(
                        target,
                        Severity::Low,
                        format!("S3 bucket exists (access denied): {}", name),
                        format!(
                            "s3://{} exists but public listing is blocked (HTTP 403). \
                             Probe for write access and per-object ACL misconfigurations.",
                            name
                        ),
                    )
                    .evidence(Evidence::HttpResponse {
                        status,
                        headers: vec![("url".into(), effective_url.clone().into())],
                        body_excerpt: None,
                    })
                    .tag("s3")
                    .tag("cloud"),
                    &mut findings,
                );
                // A 403 on GET / doesn't mean PUT is blocked — common misconfiguration
                try_write(client, name, &effective_url, target, &mut findings).await;
            }
            _ => {} // 404 = doesn't exist; skip
        }

        Ok(findings)
    }
}

/// Attempt an unauthenticated PUT. On success: Critical finding + immediate cleanup.
async fn try_write(
    client: &reqwest::Client,
    bucket: &str,
    base_url: &str,
    target: &Target,
    findings: &mut Vec<Finding>,
) {
    const PROBE_KEY: &str = "gossan-write-probe-delete-me.txt";
    let encoded_bucket = urlencoding::encode(bucket);
    let put_url = if base_url.contains(".s3.amazonaws.com") {
        format!("https://{}.s3.amazonaws.com/{}", encoded_bucket, PROBE_KEY)
    } else {
        format!("https://s3.amazonaws.com/{}/{}", encoded_bucket, PROBE_KEY)
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
        let _ = client.delete(&put_url).send().await; // best-effort cleanup
        gossan_core::try_push_finding(crate::finding_builder(target, Severity::Critical,
                format!("S3 bucket writable without authentication: {}", bucket),
                format!(
                    "An unauthenticated PUT to s3://{}/{} succeeded (HTTP {}). \
                     Any attacker can upload arbitrary files including web shells. \
                     The probe object was deleted immediately after confirmation.",
                    bucket, PROBE_KEY, status
                ))
            .evidence(Evidence::HttpResponse {
                status,
                headers: vec![("url".into(), put_url.clone().into())],
                body_excerpt: None,
            })
            .tag("s3").tag("cloud").tag("file-upload").tag("exposure")
            .exploit_hint(format!(
                "# Upload a malicious file:\naws s3 cp malware.html s3://{}/malware.html --no-sign-request\n\
                 # Via curl:\ncurl -s -X PUT '{}' --upload-file payload.bin",
                bucket,
                put_url.replace(PROBE_KEY, "payload.bin")
            )), findings);
    }
}
