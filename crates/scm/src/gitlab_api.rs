//! GitLab API integration — group and project discovery.
//!
//! Mirrors the github.rs surface: given a domain, treat the leading
//! label as the candidate group path, look it up at gitlab.com, and
//! emit each project's clone URL as a `Target::Repository`.
//!
//! Token resolution order: `Config::api_keys["gitlab"]` → env
//! `GITLAB_TOKEN` → unauthenticated. Unauthenticated calls still work
//! against public projects but rate-limit harder.
//!
//! Self-managed GitLab is supported via `Config::api_keys["gitlab_url"]`
//! (e.g. `https://gitlab.example.com`); defaults to `https://gitlab.com`.

use gossan_core::target::{RepositoryTarget, ScmService};
use gossan_core::{Config, DiscoverySource, ScanInput, Target};
use serde::Deserialize;
use tracing::{info, warn};
use url::Url;

const DEFAULT_BASE: &str = "https://gitlab.com";
const PAGE_LIMIT: u32 = 10;
const PER_PAGE: u32 = 100;

#[derive(Debug, Deserialize)]
struct GitlabGroup {
    id: u64,
    #[serde(default)]
    full_path: String,
}

#[derive(Debug, Deserialize)]
struct GitlabProject {
    #[serde(default)]
    http_url_to_repo: Option<String>,
    #[serde(default)]
    web_url: Option<String>,
    #[serde(default)]
    default_branch: Option<String>,
}

fn base_url(config: &Config) -> String {
    config
        .api_keys
        .get("gitlab_url")
        .cloned()
        .unwrap_or_else(|| DEFAULT_BASE.to_string())
}

fn token(config: &Config) -> Option<String> {
    if let Some(t) = config.api_keys.get("gitlab") {
        return Some(t.clone());
    }
    std::env::var("GITLAB_TOKEN").ok()
}

/// Discover GitLab repositories belonging to the group named after
/// the seed domain's leading label.
///
/// Streams each repository back through `ScanInput::emit_target`. Soft
/// errors (404, transient HTTP failures) are logged but do not abort
/// the scan — gitlab discovery is best-effort enrichment.
pub async fn discover_org_assets(
    domain: &str,
    config: &Config,
    input: &ScanInput,
) -> anyhow::Result<()> {
    let base = base_url(config);
    let group_name = domain.split('.').next().unwrap_or(domain);
    if group_name.is_empty() {
        return Ok(());
    }

    let client = reqwest::Client::builder()
        .user_agent("gossan-scm/0.2")
        .timeout(std::time::Duration::from_secs(15))
        .build()?;

    let mut req = client.get(format!(
        "{}/api/v4/groups/{}",
        base.trim_end_matches('/'),
        urlencoding(group_name)
    ));
    if let Some(t) = token(config) {
        req = req.header("PRIVATE-TOKEN", t);
    }

    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            warn!(group = group_name, err = %e, "gitlab: group lookup failed");
            return Ok(());
        }
    };

    if !resp.status().is_success() {
        warn!(
            group = group_name,
            status = %resp.status(),
            "gitlab: group not found or inaccessible"
        );
        return Ok(());
    }

    // Bound the JSON read — GitLab.com group payloads are <100 KiB
    // even for huge orgs; capping at 4 MiB protects against a hostile
    // self-hosted GitLab instance streaming gigabytes from /groups/.
    let group: GitlabGroup = match gossan_core::net::bounded_json(resp, 4 * 1024 * 1024).await {
        Ok(g) => g,
        Err(e) => {
            warn!(group = group_name, err = %e, "gitlab: group json decode failed");
            return Ok(());
        }
    };

    info!(
        group_id = group.id,
        full_path = %group.full_path,
        "gitlab: enumerating projects"
    );

    let mut page = 1u32;
    let mut total_emitted = 0usize;
    while page <= PAGE_LIMIT {
        let mut req = client.get(format!(
            "{}/api/v4/groups/{}/projects?per_page={}&page={}&include_subgroups=true",
            base.trim_end_matches('/'),
            urlencoding(group_name),
            PER_PAGE,
            page,
        ));
        if let Some(t) = token(config) {
            req = req.header("PRIVATE-TOKEN", t);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                warn!(page, err = %e, "gitlab: projects page fetch failed");
                break;
            }
        };

        if !resp.status().is_success() {
            warn!(page, status = %resp.status(), "gitlab: projects page non-2xx");
            break;
        }

        // Same bound reasoning as the group call above. PER_PAGE caps
        // the count, but a hostile server could pad each project entry
        // arbitrarily — cap the response itself.
        let projects: Vec<GitlabProject> =
            match gossan_core::net::bounded_json(resp, 8 * 1024 * 1024).await {
                Ok(p) => p,
                Err(e) => {
                    warn!(page, err = %e, "gitlab: projects json decode failed");
                    break;
                }
            };

        if projects.is_empty() {
            break;
        }

        for p in &projects {
            let raw = p.http_url_to_repo.clone().or_else(|| p.web_url.clone());
            let Some(raw) = raw else {
                continue;
            };
            let Ok(url) = Url::parse(&raw) else {
                continue;
            };
            input.emit_target(Target::Repository(RepositoryTarget {
                url,
                service: ScmService::GitLab,
                source: DiscoverySource::ScmMapping,
                branch: p.default_branch.clone(),
            }));
            total_emitted += 1;
        }

        if projects.len() < PER_PAGE as usize {
            break;
        }
        page += 1;
    }

    info!(
        group = group_name,
        emitted = total_emitted,
        "gitlab: discovery complete"
    );
    Ok(())
}

fn urlencoding(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_encoding_handles_subgroup_paths() {
        assert_eq!(urlencoding("acme/inner"), "acme%2Finner");
        assert_eq!(urlencoding("plain"), "plain");
        assert_eq!(urlencoding("a b"), "a%20b");
    }

    #[test]
    fn base_url_default_is_gitlab_com() {
        let cfg = Config::default();
        assert_eq!(base_url(&cfg), "https://gitlab.com");
    }

    #[test]
    fn base_url_overridable_for_self_managed() {
        let mut cfg = Config::default();
        cfg.api_keys
            .insert("gitlab_url".into(), "https://gitlab.acme.io".into());
        assert_eq!(base_url(&cfg), "https://gitlab.acme.io");
    }
}
