//! GitHub API integration — organization enumeration and repo discovery.

use gossan_core::target::{RepositoryTarget, ScmService};
use gossan_core::{Config, DiscoverySource, ScanInput, Target};
use octocrab::Octocrab;
use tracing::{info, warn};
use url::Url;

pub async fn discover_org_assets(
    domain: &str,
    config: &Config,
    input: &ScanInput,
) -> anyhow::Result<()> {
    // `api_keys` is a `HashMap<String, String>` keyed by provider name.
    // Fall back to the GITHUB_TOKEN env var for parity with CLI flags.
    let token = if let Some(t) = config.api_keys.get("github") {
        t.clone()
    } else if let Ok(t) = std::env::var("GITHUB_TOKEN") {
        t
    } else {
        return Ok(());
    };

    let octo = Octocrab::builder().personal_token(token).build()?;

    // 1. Search for organizations matching the domain (e.g. email domain or name)
    // Heuristic: take the root domain name
    let org_name = domain.split('.').next().unwrap_or(domain);

    info!(org_name, "searching GitHub for organization");

    // In a real scenario, we'd use search API or direct Org lookup
    match octo.orgs(org_name).get().await {
        Ok(org) => {
            info!(org_id = org.id.0, "found organization on GitHub");

            // 2. List repositories
            let mut page = 1u32;
            loop {
                // Use the correct octocrab method for list repositories
                let repos = octo
                    .orgs(org_name)
                    .list_repos()
                    .per_page(100)
                    .page(page)
                    .send()
                    .await?;

                if repos.items.is_empty() {
                    break;
                }

                for r in repos {
                    let repo_url_str = r
                        .clone_url
                        .map(|u| u.to_string())
                        .unwrap_or_else(|| r.html_url.map(|u| u.to_string()).unwrap_or_default());
                    if repo_url_str.is_empty() {
                        continue;
                    }

                    if let Ok(url) = Url::parse(&repo_url_str) {
                        input.emit_target(Target::Repository(RepositoryTarget {
                            url,
                            service: ScmService::GitHub,
                            source: DiscoverySource::ScmMapping,
                            branch: None,
                        }));
                    }
                }

                page += 1;
                if page > 10 {
                    break;
                } // Safety limit
            }
        }
        Err(e) => {
            warn!(org_name, err = %e, "GitHub organization not found");
        }
    }

    Ok(())
}
