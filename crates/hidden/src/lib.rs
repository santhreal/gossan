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
pub mod debug_endpoints;
pub mod dependency_confusion;
pub mod directory_brute;
pub mod error_disclosure;
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
pub mod soft404;
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
use tokio::sync::Semaphore;

/// Maximum concurrent in-flight requests to a single host.
const PER_HOST_CONCURRENCY: usize = 4;

/// Maximum response body size to read into memory (10 MiB).
pub const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

struct HostRateLimiterState {
    /// Map of hostname to last request time.
    last_request: HashMap<String, Instant>,
    /// Current backoff multiplier per host.
    backoff: HashMap<String, Duration>,
}

/// Per-host rate limiter that enforces a minimum delay between requests
/// and exponential backoff on 429/503.
pub struct HostRateLimiter {
    state: std::sync::Mutex<HostRateLimiterState>,
    /// Minimum delay between requests to the same host.
    delay: Duration,
}

impl HostRateLimiter {
    /// Create a new rate limiter with the specified delay between requests.
    #[must_use]
    pub fn new(delay_ms: u64) -> Self {
        Self {
            state: std::sync::Mutex::new(HostRateLimiterState {
                last_request: HashMap::new(),
                backoff: HashMap::new(),
            }),
            delay: Duration::from_millis(delay_ms),
        }
    }

    /// Wait until it's safe to send a request to the given host.
    pub async fn wait_for_host(&self, host: &str) {
        if self.delay.is_zero() {
            return;
        }

        let now = Instant::now();
        let sleep_duration = {
            let mut state = self.state.lock().expect("lock poisoned");
            let backoff_dur = state.backoff.get(host).copied().unwrap_or_default();
            let effective_delay = self.delay + backoff_dur;

            let last = state.last_request.get(host).copied();
            let next_allowed = last
                .map(|l| l + effective_delay)
                .unwrap_or(now)
                .max(now);

            // Pre-reserve the slot by setting the last request time to next_allowed
            state.last_request.insert(host.to_string(), next_allowed);

            if next_allowed > now {
                Some(next_allowed - now)
            } else {
                None
            }
        };

        if let Some(sleep_duration) = sleep_duration {
            tokio::time::sleep(sleep_duration).await;
        }
    }

    /// Increase backoff on 429/503 responses.
    pub async fn observe_status(&self, host: &str, status: u16) {
        if status == 429 || status == 503 {
            let mut state = self.state.lock().expect("lock poisoned");
            let current = state.backoff.get(host).copied().unwrap_or_default();
            let next = if current.is_zero() {
                self.delay
            } else {
                current * 2
            };
            // Cap at 60 seconds
            let capped = next.min(Duration::from_secs(60));
            state.backoff.insert(host.to_string(), capped);
        } else {
            self.decay_backoff(host).await;
        }
    }

    /// Decay backoff after a successful request.
    pub async fn decay_backoff(&self, host: &str) {
        let mut state = self.state.lock().expect("lock poisoned");
        if let Some(current) = state.backoff.get(host).copied() {
            let next = current / 2;
            if next < self.delay {
                state.backoff.remove(host);
            } else {
                state.backoff.insert(host.to_string(), next);
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

        let semaphore = Arc::new(Semaphore::new(config.concurrency));
        let mut rx = input.target_rx.lock().await;
        let mut workers = futures::stream::FuturesUnordered::new();
        let live_tx = input.live_tx.clone();

        loop {
            tokio::select! {
                opt_target = rx.recv() => {
                    match opt_target {
                        Some(target) => {
                            if !self.accepts(&target) {
                                continue;
                            }
                            let permit = Arc::clone(&semaphore).acquire_owned().await;
                            let Ok(permit) = permit else {
                                break;
                            };
                            let cn = client_no_redir.clone();
                            let cf = client_follow.clone();
                            let rl = Arc::clone(&rate_limiter);
                            let live_tx = live_tx.clone();
                            workers.push(tokio::spawn(async move {
                                let _permit = permit;
                                let mut f = Vec::new();
                                let host = target.domain().unwrap_or("").to_string();
                                let host_clone = host.clone();
                                let per_host_semaphore = Arc::new(Semaphore::new(PER_HOST_CONCURRENCY));

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
                                    ($name:expr, $client:expr, $target_inner:expr) => {
                                        {
                                            let rl_inner = Arc::clone(&rl);
                                            let host_inner = host_clone.clone();
                                            let target_inner2 = $target_inner.clone();
                                            let client_inner = $client.clone();
                                            let sem_inner = Arc::clone(&per_host_semaphore);
                                            let baseline_inner = Arc::clone(&baseline);
                                            probes.push(tokio::spawn(async move {
                                                let _permit = sem_inner.acquire().await;
                                                rl_inner.wait_for_host(&host_inner).await;
                                                let result = match $name {
                                                    "git_env" => git_env::probe(&client_inner, &target_inner2, &rl_inner, &host_inner).await,
                                                    "swagger" => swagger::probe(&client_inner, &target_inner2, baseline_inner.as_ref().as_ref()).await,
                                                    "cookies" => cookies::probe(&client_inner, &target_inner2).await,
                                                    "graphql" => graphql::probe(&client_inner, &target_inner2, baseline_inner.as_ref().as_ref()).await,
                                                    "cors" => cors::probe(&client_inner, &target_inner2).await,
                                                    "csp" => csp::probe(&client_inner, &target_inner2).await,
                                                    "api_versions" => api_versions::probe(&client_inner, &target_inner2).await,
                                                    "methods" => methods::probe(&client_inner, &target_inner2).await,
                                                    "rate_limit" => rate_limit::probe(&client_inner, &target_inner2).await,
                                                    "security_headers" => security_headers::probe(&client_inner, &target_inner2).await,
                                                    "debug_endpoints" => debug_endpoints::probe(&client_inner, &target_inner2).await,
                                                    "error_disclosure" => error_disclosure::probe(&client_inner, &target_inner2).await,
                                                    "robots" => robots::probe(&client_inner, &target_inner2).await,
                                                    "sitemap" => sitemap::probe(&client_inner, &target_inner2).await,
                                                    "favicon" => favicon::probe(&client_inner, &target_inner2).await,
                                                    "waf" => waf::probe(&client_inner, &target_inner2).await,
                                                    "tech_probes" => {
                                                        if let Target::Web(asset) = &target_inner2 {
                                                            Ok(tech_probes::probe(&client_inner, asset, &target_inner2, &rl_inner, &host_inner).await)
                                                        } else {
                                                            Ok::<Vec<Finding>, anyhow::Error>(Vec::new())
                                                        }
                                                    }
                                                    "debug_endpoints_follow" => debug_endpoints::probe(&client_inner, &target_inner2).await,
                                                    "directory_brute" => {
                                                        let words = directory_brute::load_wordlist(None);
                                                        let exts = directory_brute::extensions(&[]);
                                                        let codes = directory_brute::status_codes(&[]);
                                                        Ok(directory_brute::probe(&client_inner, &target_inner2, &words, &exts, &codes, baseline_inner.as_ref().as_ref(), &rl_inner, &host_inner).await)
                                                    }
                                                    "bypass403" => bypass403::probe(&client_inner, &target_inner2).await,
                                                    "oauth" => oauth::probe(&client_inner, &target_inner2).await,
                                                    "dependency_confusion" => dependency_confusion::probe(&client_inner, &target_inner2).await,
                                                    "backup_files" => backup_files::probe(&client_inner, &target_inner2, &rl_inner, &host_inner).await,
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

                                // Emit findings for this target directly
                                for finding in f {
                                    let _ = live_tx.send(finding);
                                }
                            }));
                        }
                        None => {
                            break;
                        }
                    }
                }
                Some(worker_res) = workers.next() => {
                    if let Err(e) = worker_res {
                        tracing::error!(err = %e, "worker task panicked");
                    }
                }
            }
        }

        while let Some(worker_res) = workers.next().await {
            if let Err(e) = worker_res {
                tracing::error!(err = %e, "worker task panicked");
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
