//! Azure Blob Storage probe.
//!
//! Azure storage account names are 3–24 lowercase alphanumeric chars (no hyphens).
//! Containers are probed by name, common names and the special `$web` container
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
    description: String,
    #[serde(rename = "severity_if_exposed")]
    severity: String,
}

impl AzureContainer {
    /// Parse the TOML severity string into a `Severity` variant.
    /// Unknown strings default to `High` (conservative but not silent).
    fn severity(&self) -> Severity {
        match self.severity.to_ascii_lowercase().as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => {
                tracing::warn!(
                    container = %self.name,
                    raw = %self.severity,
                    "unknown severity in azure.toml; defaulting to High"
                );
                Severity::High
            }
        }
    }
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
            Err(e) => panic!("gossan-cloud: built-in azure.toml is malformed: {e}")
        }
    })
}

/// Get container names from TOML configuration.
fn container_names() -> &'static [AzureContainer] {
    builtin_azure_containers()
}
/// Azure Blob Storage container enumeration.
pub struct AzureProvider {
    /// Optional endpoint override for testing.
    pub(crate) endpoint_override: Option<String>,
}

impl AzureProvider {
    /// Create a new Azure provider with the default Microsoft endpoint.
    #[must_use]
    pub fn new() -> Self {
        Self { endpoint_override: None }
    }

    /// Create an Azure provider with a custom endpoint (for tests).
    #[must_use]
    pub fn with_endpoint(url: impl Into<String>) -> Self {
        Self { endpoint_override: Some(url.into()) }
    }
}

impl Default for AzureProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CloudProvider for AzureProvider {
    fn name(&self) -> &'static str {
        "azure"
    }

    fn endpoint(&self, name: &str) -> String {
        if let Some(ref url) = self.endpoint_override {
            return url.clone();
        }
        format!("https://{}.blob.core.windows.net/", name)
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

        let base_endpoint = self.endpoint(&account);
        let mut findings = Vec::new();
        let mut account_confirmed = false;

        for container in container_names() {
            let container_name = &container.name;
            let url = format!("{}{}/", base_endpoint, container_name);
            let resp = match client.get(&url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        account = %account,
                        container = %container_name,
                        url = %url,
                        error = %e,
                        "Azure blob probe send failed"
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
                                account = %account,
                                container = %container_name,
                                url = %url,
                                error = %e,
                                "Azure blob body read failed"
                            );
                            continue;
                        }
                    };
                    let is_web = container_name == "$web";
                    gossan_core::try_push_finding(crate::finding_builder(target, container.severity(),
                            format!("Azure Blob container public: {}/{}", account, container_name),
                            if is_web {
                                format!(
                                    "https://{}.blob.core.windows.net/$web is the static website \
                                     hosting container ({}) and is publicly readable, all files accessible.",
                                    account, container.description
                                )
                            } else {
                                format!(
                                    "https://{}.blob.core.windows.net/{} ({}) is publicly accessible \
                                     and returns a directory listing.",
                                    account, container_name, container.description
                                )
                            })
                        .evidence(Evidence::HttpResponse {
                            status,
                            headers: vec![("url".into(), url.clone().into())],
                            body_excerpt: Some(body.chars().take(crate::MAX_BODY_EXCERPT_CHARS).collect::<String>().into()),
                        })
                        .tag("azure").tag("cloud").tag("exposure"), &mut findings);
                    return Ok(findings); // one public container is enough to report
                }
                403 | 404 if !account_confirmed => {
                    // 403 = container exists but private; 404 on a valid account
                    // still confirms the account exists
                    if status == 403 {
                        account_confirmed = true;
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
        assert!(
            !containers.is_empty(),
            "should have Azure containers from TOML"
        );

        // Check for critical $web container
        assert!(
            containers.iter().any(|c| c.name == "$web"),
            "should include $web container"
        );
    }

    #[test]
    fn azure_containers_have_required_fields() {
        for container in container_names() {
            assert!(
                !container.name.is_empty(),
                "container name should not be empty"
            );
            assert!(
                !container.severity.is_empty(),
                "severity should not be empty"
            );
        }
    }

    #[test]
    fn azure_containers_include_common_names() {
        let names: Vec<_> = container_names().iter().map(|c| c.name.clone()).collect();
        for expected in ["$web", "public", "assets", "backup"] {
            assert!(
                names.contains(&expected.to_string()),
                "missing container: {}",
                expected
            );
        }
    }
}
