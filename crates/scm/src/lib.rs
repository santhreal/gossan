#![forbid(unsafe_code)]
// pedantic moved to workspace [lints.clippy] in root Cargo.toml
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

//! Source code management discovery — GitHub/GitLab organization mapping.
//!
//! Discovers repositories, scans for secrets, and identifies dependency
//! manifests for supply-chain analysis.

use async_trait::async_trait;
use gossan_core::{Config, ScanInput, Scanner, Target};

pub mod git_scanner;
pub mod github;
pub mod gitlab_api; // named to avoid conflict with crate name
/// Source control mapping — discovers GitHub/GitLab organizations and repos.
pub struct ScmScanner;

#[async_trait]
impl Scanner for ScmScanner {
    fn name(&self) -> &'static str {
        "scm"
    }
    fn tags(&self) -> &[&'static str] {
        &["osint", "secret", "supply-chain"]
    }
    fn accepts(&self, target: &Target) -> bool {
        // We accept domains (to find orgs) or explicit Repo targets
        matches!(target, Target::Domain(_) | Target::Repository(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        // Drain the inbound channel — `targets: Vec<Target>` has been
        // retired in favor of the streaming `target_rx`.
        let mut owned: Vec<Target> = Vec::new();
        {
            let mut rx = input.target_rx.lock().await;
            while let Some(t) = rx.recv().await {
                if self.accepts(&t) {
                    owned.push(t);
                }
            }
        }

        for target in &owned {
            match target {
                Target::Domain(d) => {
                    let (gh, gl) = tokio::join!(
                        github::discover_org_assets(&d.domain, config, &input),
                        gitlab_api::discover_org_assets(&d.domain, config, &input),
                    );
                    if let Err(e) = gh {
                        tracing::warn!(domain = %d.domain, err = %e, "scm: github org discovery failed");
                    }
                    if let Err(e) = gl {
                        tracing::warn!(domain = %d.domain, err = %e, "scm: gitlab org discovery failed");
                    }
                }
                Target::Repository(repo) => {
                    if let Err(e) = git_scanner::scan_repo(repo, config, &input).await {
                        tracing::warn!(url = %repo.url, err = %e, "scm: repo scan failed");
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}
