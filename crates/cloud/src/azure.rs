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
use serde::Deserialize;
use std::sync::OnceLock;

use crate::provider::CloudProvider;

/// Azure container definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct AzureContainer {
    name: String,
    #[allow(dead_code)]
    description: String,
    #[allow(dead_code)]
    #[serde(rename = "severity_if_exposed")]
    severity: String,
}

/// TOML file containing Azure container definitions.
#[derive(Debug, Deserialize)]
struct AzureContainersFile {
    container: Vec<AzureContainer>,
}

/// Built-in azure.toml content (embedded at compile time).
const BUILTIN_AZURE: &str = include_str!("../rules/azure.toml");

/// Global cache for built-in Azure containers.
static AZURE_CONTAINERS: OnceLock<Vec<AzureContainer>> = OnceLock::new();

/// Initialize and return the built-in Azure containers.
fn builtin_azure_containers() -> &'static Vec<AzureContainer> {
    AZURE_CONTAINERS.get_or_init(|| {
        match toml::from_str::<AzureContainersFile>(BUILTIN_AZURE) {
            Ok(file) => file.container,
            Err(e) => {
                tracing::error!(error = %e, "failed to parse built-in azure.toml");
                // Fallback to minimal hardcoded list only on parse failure
                vec![
                    AzureContainer {
                        name: "$web".to_string(),
                        description: "static website hosting".to_string(),
                        severity: "critical".to_string(),
                    },
                ]
            }
        }
    })
}

/// Get container names from TOML configuration.
fn container_names() -> &'static [AzureContainer] {
    builtin_azure_containers()
}

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

        for container in container_names() {
            let container_name = &container.name;
            let url = format!(
                "https://{}.blob.core.windows.net/{}/",
                account, container_name
            );
            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(_) => continue,
            };
            let status = resp.status().as_u16();

            match status {
                200 => {
                    let body = resp.text().await.unwrap_or_default();
                    let is_web = container_name == "$web";
                    findings.push(
                        crate::finding_builder(target, Severity::Critical,
                            format!("Azure Blob container public: {}/{}", account, container_name),
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
                                    account, container_name
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn azure_containers_load_from_toml() {
        let containers = container_names();
        assert!(!containers.is_empty(), "should have Azure containers from TOML");
        
        // Check for critical $web container
        assert!(
            containers.iter().any(|c| c.name == "$web"),
            "should include $web container"
        );
    }

    #[test]
    fn azure_containers_have_required_fields() {
        for container in container_names() {
            assert!(!container.name.is_empty(), "container name should not be empty");
            assert!(!container.severity.is_empty(), "severity should not be empty");
        }
    }

    #[test]
    fn azure_containers_include_common_names() {
        let names: Vec<_> = container_names().iter().map(|c| c.name.clone()).collect();
        for expected in ["$web", "public", "assets", "backup"] {
            assert!(names.contains(&expected.to_string()), "missing container: {}", expected);
        }
    }
}
