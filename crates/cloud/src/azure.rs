//! Azure Blob Storage probe.
//!
//! Azure storage account names are 3–24 lowercase alphanumeric chars (no hyphens).
//! Containers are probed by name — common names and the special `$web` container
//! (used for static website hosting) are checked.
//!
//! URL format: `https://{account}.blob.core.windows.net/{container}/`

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::{Evidence, Finding, Severity};

use crate::provider::CloudProvider;

/// Common container names in Azure Blob Storage accounts.
const CONTAINERS: &[&str] = &[
    "$web", // static website hosting — highest-value target
    "public", "assets", "static", "files", "uploads", "media", "images", "docs", "backup", "data",
];

pub struct AzureProvider;

#[async_trait]
impl CloudProvider for AzureProvider {
    fn name(&self) -> &'static str {
        "azure"
    }

    async fn probe(
        &self,
        client: &reqwest::Client,
        name: &str,
        target: &Target,
    ) -> anyhow::Result<Vec<Finding>> {
        // Azure account names: 3–24 lowercase alphanumeric only
        let account: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>()
            .to_lowercase();
        if account.len() < 3 || account.len() > 24 {
            return Ok(vec![]);
        }

        let mut findings = Vec::new();
        let mut account_confirmed = false;

        for container in CONTAINERS {
            let url = format!("https://{}.blob.core.windows.net/{}/", account, container);
            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let status = resp.status().as_u16();

            match status {
                200 => {
                    let body = resp.text().await.unwrap_or_default();
                    let is_web = *container == "$web";
                    findings.push(
                        crate::finding_builder(target, Severity::Critical,
                            format!("Azure Blob container public: {}/{}", account, container),
                            if is_web {
                                format!(
                                    "https://{}.blob.core.windows.net/$web is the static website \
                                     hosting container and is publicly readable — all files accessible.",
                                    account
                                )
                            } else {
                                format!(
                                    "https://{}.blob.core.windows.net/{} is publicly accessible \
                                     and returns a directory listing.",
                                    account, container
                                )
                            })
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("url".into(), url)],
                            body_excerpt: Some(body.chars().take(300).collect()),
                        })
                        .tag("azure").tag("cloud").tag("exposure")
                        .build().expect("finding builder: required fields are set"),
                    );
                    return Ok(findings); // one public container is enough to report
                }
                403 | 404 if !account_confirmed => {
                    // 403 = container exists but private; 404 on a valid account
                    // still confirms the account exists
                    if status == 403 {
                        account_confirmed = true;
                        findings.push(
                            crate::finding_builder(target, Severity::Low,
                                format!("Azure storage account exists: {}", account),
                                format!(
                                    "https://{}.blob.core.windows.net exists — account name confirmed \
                                     via HTTP 403 on container probe.",
                                    account
                                ))
                            .evidence(Evidence::HttpResponse {
                                status,
                                headers: vec![("url".into(), url)],
                                body_excerpt: None,
                            })
                            .tag("azure").tag("cloud")
                            .build().expect("finding builder: required fields are set"),
                        );
                    }
                }
                _ => {}
            }
        }

        Ok(findings)
    }
}
