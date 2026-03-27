//! Hidden endpoint/file probe scanner.
//!
//! Probes each web asset for:
//!   .git/.env/backup exposure · GraphQL introspection + batching · Swagger/OpenAPI ·
//!   CORS misconfiguration · h2c upgrade bypass · WAF fingerprint · favicon hash ·
//!   robots.txt/sitemap harvest · host header injection · open redirect · SSRF ·
//!   OAuth/OIDC misconfiguration · API version enumeration · rate limit absence ·
//!   cookie security flags · dependency confusion · tech-specific CMS probes

mod api_versions;
mod cookies;
mod cors;
mod csp;
mod error_disclosure;
mod favicon;
mod git_env;
mod graphql;
mod methods;
mod rate_limit;
mod robots;
mod sitemap;
mod swagger;
mod tech_probes;
mod waf;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{build_client, Config, ScanInput, ScanOutput, Scanner, Target};
use secfinding::{Finding, FindingBuilder, Severity};

pub struct HiddenScanner;

pub(crate) fn finding_builder(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    Finding::builder("hidden", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
}

#[async_trait]
impl Scanner for HiddenScanner {
    fn name(&self) -> &'static str {
        "hidden"
    }
    fn tags(&self) -> &[&'static str] {
        &["active", "web", "hidden"]
    }
    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Web(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<ScanOutput> {
        let mut out = ScanOutput::empty();

        // client_no_redir: used where we need to see 3xx exactly (open redirect, bypass403)
        let client_no_redir = build_client(config, false)?;
        // client_follow: used for discovery probes that should chase redirects
        let client_follow = build_client(config, true)?;

        let owned: Vec<Target> = input
            .targets
            .into_iter()
            .filter(|t| self.accepts(t))
            .collect();

        let findings: Vec<Vec<Finding>> = futures::stream::iter(owned)
            .map(|target| {
                let cn = client_no_redir.clone();
                let cf = client_follow.clone();
                async move {
                    let mut f = Vec::new();

                    macro_rules! run_probe {
                        ($name:expr, $fut:expr) => {
                            match $fut.await {
                                Ok(v)  => f.extend(v),
                                Err(e) => tracing::warn!(probe = $name, err = %e, "probe error"),
                            }
                        };
                    }

                    // ── Exposure probes ───────────────────────────────────────────
                    run_probe!("git_env", git_env::probe(&cn, &target));
                    run_probe!("swagger", swagger::probe(&cn, &target));
                    run_probe!("cookies", cookies::probe(&cn, &target));

                    // ── Protocol / injection probes ───────────────────────────────
                    run_probe!("graphql", graphql::probe(&cn, &target));

                    // ── Security header probes ─────────────────────────────────
                    run_probe!("cors", cors::probe(&cn, &target));
                    run_probe!("csp", csp::probe(&cn, &target));

                    // ── API surface enumeration ───────────────────────────────────
                    run_probe!("api_versions", api_versions::probe(&cn, &target));
                    run_probe!("methods", methods::probe(&cn, &target));
                    run_probe!("rate_limit", rate_limit::probe(&cn, &target));
                    run_probe!("error_disclosure", error_disclosure::probe(&cn, &target));

                    // ── Crawl-assisted probes ─────────────────────────────────────
                    run_probe!("robots", robots::probe(&cf, &target));
                    run_probe!("sitemap", sitemap::probe(&cf, &target));
                    run_probe!("favicon", favicon::probe(&cf, &target));
                    run_probe!("waf", waf::probe(&cf, &target));

                    // ── Tech-specific CMS/framework probes ────────────────────────
                    if let Target::Web(asset) = &target {
                        f.extend(tech_probes::probe(&cf, asset, &target).await);
                    }

                    f
                }
            })
            .buffer_unordered(config.concurrency)
            .collect()
            .await;

        for batch in findings {
            out.findings.extend(batch);
        }
        Ok(out)
    }
}
