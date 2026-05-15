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

//! Hidden endpoint/file probe scanner.
//!
//! Probes each web asset for:
//!   .git/.env/backup exposure · GraphQL introspection + batching · Swagger/OpenAPI ·
//!   CORS misconfiguration · WAF fingerprint · favicon hash ·
//!   robots.txt/sitemap harvest · OAuth/OIDC misconfiguration · API version enumeration ·
//!   rate limit absence · cookie security flags · tech-specific CMS probes ·
//!   dependency confusion · 403 bypass · directory brute-force

mod api_versions;
pub mod backup_files;
mod bypass403;
mod cookies;
pub mod cors;
pub mod csp;
mod debug_endpoints;
pub mod dependency_confusion;
pub mod directory_brute;
mod error_disclosure;
mod favicon;
pub mod git_env;
pub mod graphql;
mod methods;
mod oauth;
mod path_sanitize;
mod rate_limit;
pub mod robots;
mod security_headers;
mod sitemap;
mod soft404;
pub mod swagger;
mod tech_probes;
mod waf;

use async_trait::async_trait;
use futures::StreamExt;
use gossan_core::{Config, ScanClient, ScanInput, Scanner, Target};
use secfinding::{Evidence, Finding, FindingBuilder, Severity};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};

/// Maximum concurrent in-flight requests to a single host.
const PER_HOST_CONCURRENCY: usize = 4;

/// Maximum response body size to read into memory (10 MiB).
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// Per-host rate limiter that enforces a minimum delay between requests
/// and exponential backoff on 429/503.
pub struct HostRateLimiter {
    /// Map of hostname to last request time.
    last_request: RwLock<HashMap<String, Instant>>,
    /// Minimum delay between requests to the same host.
    delay: Duration,
    /// Current backoff multiplier per host.
    backoff: RwLock<HashMap<String, Duration>>,
}

impl HostRateLimiter {
    /// Create a new rate limiter with the specified delay between requests.
    #[must_use]
    pub fn new(delay_ms: u64) -> Self {
        Self {
            last_request: RwLock::new(HashMap::new()),
            delay: Duration::from_millis(delay_ms),
            backoff: RwLock::new(HashMap::new()),
        }
    }

    /// Wait until it's safe to send a request to the given host.
    pub async fn wait_for_host(&self, host: &str) {
        if self.delay.is_zero() {
            return;
        }

        let now = Instant::now();
        let should_sleep = {
            let read_guard = self.last_request.read().await;
            let backoff_guard = self.backoff.read().await;
            let effective_delay = self.delay + backoff_guard.get(host).copied().unwrap_or_default();
            if let Some(last) = read_guard.get(host) {
                let elapsed = now.duration_since(*last);
                if elapsed < effective_delay {
                    Some(effective_delay - elapsed)
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(sleep_duration) = should_sleep {
            tokio::time::sleep(sleep_duration).await;
        }

        let mut write_guard = self.last_request.write().await;
        write_guard.insert(host.to_string(), Instant::now());
    }

    /// Increase backoff on 429/503 responses.
    pub async fn observe_status(&self, host: &str, status: u16) {
        if status == 429 || status == 503 {
            let mut backoff_guard = self.backoff.write().await;
            let current = backoff_guard.get(host).copied().unwrap_or_default();
            let next = if current.is_zero() {
                self.delay
            } else {
                current * 2
            };
            // Cap at 60 seconds
            let capped = next.min(Duration::from_secs(60));
            backoff_guard.insert(host.to_string(), capped);
        }
    }

    /// Decay backoff after a successful request.
    pub async fn decay_backoff(&self, host: &str) {
        let mut backoff_guard = self.backoff.write().await;
        if let Some(current) = backoff_guard.get(host).copied() {
            let next = current / 2;
            if next < self.delay {
                backoff_guard.remove(host);
            } else {
                backoff_guard.insert(host.to_string(), next);
            }
        }
    }

    /// Get the configured base delay.
    #[must_use]
    pub fn delay(&self) -> Duration {
        self.delay
    }
}

/// `HiddenScanner`.
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

/// Build a finding with an explicit [`FindingKind`].
pub(crate) fn finding_builder_typed(
    target: &Target,
    severity: Severity,
    kind: secfinding::FindingKind,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    Finding::builder("hidden", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
        .kind(kind)
}

/// Vulnerability finding (confirmed exploit path).
pub(crate) fn vulnerability_finding(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    finding_builder_typed(
        target,
        severity,
        secfinding::FindingKind::Vulnerability,
        title,
        detail,
    )
}

/// Misconfiguration finding (CORS, CSP, headers).
pub(crate) fn misconfig_finding(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    finding_builder_typed(
        target,
        severity,
        secfinding::FindingKind::Misconfiguration,
        title,
        detail,
    )
}

/// Exposure finding (open endpoints, admin panels).
pub(crate) fn exposure_finding(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    finding_builder_typed(
        target,
        severity,
        secfinding::FindingKind::Exposure,
        title,
        detail,
    )
}

/// File discovery finding (backup files, .git, .env).
pub(crate) fn file_finding(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    finding_builder_typed(
        target,
        severity,
        secfinding::FindingKind::FileDiscovery,
        title,
        detail,
    )
}

/// Info disclosure finding (stack traces, server versions).
pub(crate) fn info_finding(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    finding_builder_typed(
        target,
        severity,
        secfinding::FindingKind::InfoDisclosure,
        title,
        detail,
    )
}

/// Tech detect finding (framework/language fingerprint).
pub(crate) fn tech_finding(
    target: &Target,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    finding_builder_typed(
        target,
        Severity::Info,
        secfinding::FindingKind::TechDetect,
        title,
        detail,
    )
}

/// Supply chain finding (dependency confusion, typosquat).
pub(crate) fn supply_chain_finding(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    finding_builder_typed(
        target,
        severity,
        secfinding::FindingKind::SupplyChain,
        title,
        detail,
    )
}

/// Secret leak finding (exposed API keys, tokens).
pub(crate) fn secret_finding(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    finding_builder_typed(
        target,
        severity,
        secfinding::FindingKind::SecretLeak,
        title,
        detail,
    )
}

/// Build a finding from a FindingBuilder and push it into the provided findings
/// vector. Any build error is logged and the finding is skipped instead of
/// panicking; probes should be resilient to builder failures.
pub(crate) fn try_push_finding(builder: FindingBuilder, findings: &mut Vec<Finding>) {
    match builder.build() {
        Ok(f) => findings.push(f),
        Err(e) => tracing::warn!(error = %e, "finding builder failed; skipping finding"),
    }
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

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        let client_no_redir =
            ScanClient::from_config_no_redirect(config, Arc::clone(&input.resolver))?;
        let client_follow = ScanClient::from_config(config, Arc::clone(&input.resolver))?;
        let rate_limiter = Arc::new(HostRateLimiter::new(config.host_delay_ms));

        // Drain the streaming target receiver into a Vec. Hidden's per-host
        // probe layout (futures::stream::iter + buffer_unordered + per-host
        // semaphore) is batch-shaped, not incremental — collect first, then
        // fan out probes per accepted Web target.
        let owned: Vec<Target> = {
            let mut rx = input.target_rx.lock().await;
            let mut buf = Vec::new();
            while let Ok(t) = rx.try_recv() {
                if self.accepts(&t) {
                    buf.push(t);
                }
            }
            buf
        };

        let findings: Vec<Vec<Finding>> = futures::stream::iter(owned)
            .map(|target| {
                let cn = client_no_redir.clone();
                let cf = client_follow.clone();
                let rl = Arc::clone(&rate_limiter);
                async move {
                    let mut f = Vec::new();
                    let host = target.domain().unwrap_or("").to_string();
                    let semaphore = Arc::new(Semaphore::new(PER_HOST_CONCURRENCY));

                    // Establish a shared soft-404 baseline for this target
                    let baseline = if let Target::Web(asset) = &target {
                        let base = asset.url.as_str().trim_end_matches('/');
                        soft404::establish(&cn, base).await
                    } else {
                        None
                    };
                    let baseline = Arc::new(baseline);

                    let mut probes = futures::stream::FuturesUnordered::new();

                    macro_rules! spawn_probe {
                        ($name:expr, $client:expr, $target:expr) => {
                            {
                                let rl_inner = Arc::clone(&rl);
                                let host_inner = host.clone();
                                let target_inner = $target.clone();
                                let client_inner = $client.clone();
                                let sem_inner = Arc::clone(&semaphore);
                                let baseline_inner = Arc::clone(&baseline);
                                probes.push(tokio::spawn(async move {
                                    let _permit = sem_inner.acquire().await;
                                    rl_inner.wait_for_host(&host_inner).await;
                                    let result = match $name {
                                        "git_env" => git_env::probe(&client_inner, &target_inner).await,
                                        "swagger" => swagger::probe(&client_inner, &target_inner, baseline_inner.as_ref().as_ref()).await,
                                        "cookies" => cookies::probe(&client_inner, &target_inner).await,
                                        "graphql" => graphql::probe(&client_inner, &target_inner, baseline_inner.as_ref().as_ref()).await,
                                        "cors" => cors::probe(&client_inner, &target_inner).await,
                                        "csp" => csp::probe(&client_inner, &target_inner).await,
                                        "api_versions" => api_versions::probe(&client_inner, &target_inner).await,
                                        "methods" => methods::probe(&client_inner, &target_inner).await,
                                        "rate_limit" => rate_limit::probe(&client_inner, &target_inner).await,
                                        "security_headers" => security_headers::probe(&client_inner, &target_inner).await,
                                        "debug_endpoints" => debug_endpoints::probe(&client_inner, &target_inner).await,
                                        "error_disclosure" => error_disclosure::probe(&client_inner, &target_inner).await,
                                        "robots" => robots::probe(&client_inner, &target_inner).await,
                                        "sitemap" => sitemap::probe(&client_inner, &target_inner).await,
                                        "favicon" => favicon::probe(&client_inner, &target_inner).await,
                                        "waf" => waf::probe(&client_inner, &target_inner).await,
                                        "tech_probes" => {
                                            // tech_probes::probe returns
                                            // Vec<Finding> directly (no Result),
                                            // unlike the other probes. Wrap so
                                            // the match arms agree on
                                            // anyhow::Result<Vec<Finding>>.
                                            if let Target::Web(asset) = &target_inner {
                                                Ok(tech_probes::probe(&client_inner, asset, &target_inner).await)
                                            } else {
                                                Ok::<Vec<Finding>, anyhow::Error>(Vec::new())
                                            }
                                        }
                                        "debug_endpoints_follow" => debug_endpoints::probe(&client_inner, &target_inner).await,
                                        "directory_brute" => {
                                            let words = directory_brute::load_wordlist(None);
                                            let exts = directory_brute::extensions(&[]);
                                            let codes = directory_brute::status_codes(&[]);
                                            Ok(directory_brute::probe(&client_inner, &target_inner, &words, &exts, &codes, baseline_inner.as_ref().as_ref()).await)
                                        }
                                        "bypass403" => bypass403::probe(&client_inner, &target_inner).await,
                                        "oauth" => oauth::probe(&client_inner, &target_inner).await,
                                        "dependency_confusion" => dependency_confusion::probe(&client_inner, &target_inner).await,
                                        "backup_files" => backup_files::probe(&client_inner, &target_inner).await,
                                        _ => Ok(Vec::new()),
                                    };
                                    // Update rate-limiter state based on response evidence
                                    if let Ok(ref findings) = result {
                                        for finding in findings {
                                            for ev in finding.evidence() {
                                                if let Evidence::HttpResponse { status, .. } = ev {
                                                    rl_inner.observe_status(&host_inner, *status).await;
                                                }
                                            }
                                        }
                                    }
                                    result.unwrap_or_else(|e| {
                                        tracing::warn!(probe = $name, err = %e, "probe error");
                                        Vec::new()
                                    })
                                }));
                            }
                        };
                    }

                    spawn_probe!("git_env", cn, target);
                    spawn_probe!("swagger", cn, target);
                    spawn_probe!("cookies", cn, target);
                    spawn_probe!("graphql", cn, target);
                    spawn_probe!("cors", cn, target);
                    spawn_probe!("csp", cn, target);
                    spawn_probe!("api_versions", cn, target);
                    spawn_probe!("methods", cn, target);
                    spawn_probe!("rate_limit", cn, target);
                    spawn_probe!("security_headers", cn, target);
                    spawn_probe!("debug_endpoints", cn, target);
                    spawn_probe!("error_disclosure", cn, target);
                    spawn_probe!("robots", cf, target);
                    spawn_probe!("sitemap", cf, target);
                    spawn_probe!("favicon", cf, target);
                    spawn_probe!("waf", cf, target);
                    spawn_probe!("tech_probes", cf, target);
                    spawn_probe!("debug_endpoints_follow", cf, target);
                    spawn_probe!("directory_brute", cf, target);
                    spawn_probe!("bypass403", cn, target);
                    spawn_probe!("oauth", cn, target);
                    spawn_probe!("dependency_confusion", cn, target);
                    spawn_probe!("backup_files", cn, target);

                    while let Some(res) = probes.next().await {
                        if let Ok(mut probe_findings) = res {
                            f.append(&mut probe_findings);
                        }
                    }

                    f
                }
            })
            .buffer_unordered(config.concurrency)
            .collect()
            .await;

        for batch in findings {
            for finding in batch {
                input.emit(finding);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn host_rate_limiter_respects_delay() {
        let limiter = HostRateLimiter::new(100); // 100ms delay
        let _start = Instant::now();
        limiter.wait_for_host("example.com").await;
        let first = Instant::now();
        limiter.wait_for_host("example.com").await;
        let second = Instant::now();
        let elapsed = second.duration_since(first);
        assert!(
            elapsed >= Duration::from_millis(100),
            "Rate limiter did not enforce delay"
        );

        let third_start = Instant::now();
        limiter.wait_for_host("other.com").await;
        let third_elapsed = Instant::now().duration_since(third_start);
        assert!(
            third_elapsed < Duration::from_millis(50),
            "Different host was incorrectly delayed"
        );
    }

    #[tokio::test]
    async fn host_rate_limiter_zero_delay_no_wait() {
        let limiter = HostRateLimiter::new(0);
        let start = Instant::now();
        limiter.wait_for_host("example.com").await;
        limiter.wait_for_host("example.com").await;
        limiter.wait_for_host("example.com").await;
        let elapsed = Instant::now().duration_since(start);
        assert!(
            elapsed < Duration::from_millis(50),
            "Zero delay should not wait"
        );
    }

    #[tokio::test]
    async fn host_rate_limiter_exponential_backoff() {
        let limiter = HostRateLimiter::new(100);
        limiter.observe_status("example.com", 429).await;
        let start = Instant::now();
        limiter.wait_for_host("example.com").await;
        limiter.wait_for_host("example.com").await;
        let elapsed = Instant::now().duration_since(start);
        // base 100ms + backoff 100ms = 200ms effective, so two requests should be >= 200ms apart
        assert!(elapsed >= Duration::from_millis(200), "Backoff not applied");
    }
}
