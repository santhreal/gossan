//! Per-host rate limiter with automatic 429 / backoff handling.
//!
//! `Config::rate_limit` caps total RPS across all hosts. This module adds a
//! second layer: independent per-hostname token-bucket governors so that a
//! burst against one host doesn't consume the global budget and block scanning
//! of others.
//!
//! # Usage
//! ```ignore
//! let rl = HostRateLimiter::new(20); // 20 req/s per hostname
//! rl.until_ready("example.com").await;
//! // now safe to send a request
//! ```

use std::collections::HashMap;
use std::future::Future;
use std::num::NonZeroU32;
use std::time::Instant;
use std::sync::Arc;

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use hickory_resolver::TokioResolver;
use scanclient::reqwest;
pub use guise_pacing::{BackoffKind, BackoffPolicy};
use tokio::sync::RwLock;

use crate::config::MAX_HTTP_REDIRECTS;
use crate::scanclient_bridge;
use crate::Config;

fn is_timeout_error(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<reqwest::Error>()
        .is_some_and(reqwest::Error::is_timeout)
}

/// Per-hostname rate limiter.  Creates an independent token-bucket governor for
/// each unique hostname the first time it is seen; subsequent calls reuse it.
pub struct HostRateLimiter {
    limiters: RwLock<HashMap<String, (Arc<DefaultDirectRateLimiter>, Instant)>>,
    /// `None` means per-host limiting is disabled (unthrottled).
    rps: Option<NonZeroU32>,
}

/// Cap on retained per-host governors. Beyond this, idle entries are pruned.
const HOST_LIMITER_CAP: usize = 10_000;

impl HostRateLimiter {
    /// `rps_per_host`: max requests per second per unique hostname.
    ///
    /// Pass `0` to disable per-host limiting entirely (unthrottled). A zero
    /// value must NOT collapse to 1 RPS.
    #[must_use]
    pub fn new(rps_per_host: u32) -> Self {
        Self {
            limiters: RwLock::new(HashMap::new()),
            rps: NonZeroU32::new(rps_per_host),
        }
    }

    /// Derive a per-host RPS from `Config::host_delay_ms`, capped by the
    /// global `rate_limit`. `host_delay_ms == 0` disables per-host limiting.
    #[must_use]
    pub fn from_config(config: &Config) -> Self {
        if config.host_delay_ms == 0 {
            return Self::new(0);
        }
        let from_delay = (1000 / config.host_delay_ms.max(1)).max(1) as u32;
        let capped = from_delay.min(config.rate_limit.max(1));
        Self::new(capped)
    }

    /// Async-wait until a request to `host` is within the rate budget.
    pub async fn until_ready(&self, host: &str) {
        let Some(_) = self.rps else {
            return;
        };
        let limiter = self.get_or_create(host).await;
        limiter.until_ready().await;
    }

    async fn get_or_create(&self, host: &str) -> Arc<DefaultDirectRateLimiter> {
        let rps = self.rps.expect("get_or_create only called when rps is Some");
        {
            let read = self.limiters.read().await;
            if let Some((l, _)) = read.get(host) {
                return Arc::clone(l);
            }
        }
        let mut write = self.limiters.write().await;
        if let Some((l, last)) = write.get_mut(host) {
            *last = Instant::now();
            return Arc::clone(l);
        }
        if write.len() >= HOST_LIMITER_CAP {
            // Drop the oldest half to bound memory on million-host scans.
            let mut entries: Vec<(String, Instant)> = write
                .iter()
                .map(|(k, (_, t))| (k.clone(), *t))
                .collect();
            entries.sort_by_key(|(_, t)| *t);
            let drop_n = entries.len() / 2;
            for (k, _) in entries.into_iter().take(drop_n) {
                write.remove(&k);
            }
        }
        let quota = Quota::per_second(rps);
        let limiter = Arc::new(RateLimiter::direct(quota));
        write.insert(host.to_string(), (Arc::clone(&limiter), Instant::now()));
        limiter
    }
}

/// Build a shared `reqwest::Client` from scan `Config` via scanclient's pool.
pub fn build_client(
    config: &Config,
    follow_redirects: bool,
    resolver: Arc<TokioResolver>,
) -> anyhow::Result<reqwest::Client> {
    crate::transport::warn_insecure_tls_once(config.insecure_tls);
    let redirect_policy = if follow_redirects {
        reqwest::redirect::Policy::limited(MAX_HTTP_REDIRECTS)
    } else {
        reqwest::redirect::Policy::none()
    };
    scanclient_bridge::build_http_client(config, resolver, redirect_policy)
        .map_err(|e| anyhow::anyhow!("scanclient pool: {e}"))
}

pub use guise_pacing::{BACKOFF_429_BASE_MS, BACKOFF_MAX_RETRIES, BACKOFF_TIMEOUT_BASE_MS};

/// Retry an HTTP GET request, backing off exponentially on 429 responses.
///
/// Backoff schedule: `BACKOFF_429_BASE_MS` × 2^attempt until
/// `BACKOFF_MAX_RETRIES` are exhausted.
///
/// # Errors
/// Returns an error if all retries are exhausted or a non-retryable error occurs.
pub async fn get_with_backoff(
    client: &reqwest::Client,
    url: &str,
    rate_limiter: Option<&HostRateLimiter>,
) -> anyhow::Result<reqwest::Response> {
    send_with_backoff(url, rate_limiter, || async {
        Ok::<reqwest::Response, anyhow::Error>(client.get(url).send().await?)
    })
    .await
}

use futures::StreamExt;

/// Reads the entire response body while enforcing a size limit.
///
/// If the body exceeds `max_size`, returns an error and stops reading.
/// This is the 'Response Bomb Shield' designed to prevent OOM from malicious servers.
pub async fn read_response_limited(
    resp: reqwest::Response,
    max_size: usize,
) -> anyhow::Result<Vec<u8>> {
    // Check Content-Length header first, bail early when the server
    // declares the body is over limit, and capture the length for
    // pre-allocation below.
    let content_length = resp.content_length();
    if let Some(cl) = content_length {
        if cl > max_size as u64 {
            anyhow::bail!(
                "Response body exceeds max size (header check): {} > {}",
                cl,
                max_size
            );
        }
    }

    // Pre-allocate with the declared size (capped at max_size) so the
    // common case, small responses with a Content-Length header, pays
    // one allocation instead of O(log n) doubling reallocations while streaming.
    let initial_capacity = content_length
        .map(|cl| (cl as usize).min(max_size))
        .unwrap_or(0);
    let mut body = Vec::with_capacity(initial_capacity);
    let mut total_read = 0;

    let mut stream = resp.bytes_stream();
    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res?;
        total_read += chunk.len();
        if total_read > max_size {
            anyhow::bail!(
                "Response body exceeds max size (stream check): {} > {}",
                total_read,
                max_size
            );
        }
        body.extend_from_slice(&chunk);
    }

    Ok(body)
}

/// Retry an HTTP request, backing off exponentially on 429 responses.
///
/// # Errors
/// Returns an error if all retries are exhausted or a non-retryable error occurs.
pub async fn send_with_backoff<F, Fut>(
    url: &str,
    rate_limiter: Option<&HostRateLimiter>,
    mut send_request: F,
) -> anyhow::Result<reqwest::Response>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<reqwest::Response>>,
{
    let host = {
        let parsed = url::Url::parse(url)?;
        parsed.host_str().unwrap_or(url).to_string()
    };

    let backoff = BackoffPolicy::gossan_compatible();

    for attempt in 0..backoff.max_retries() {
        if let Some(rl) = rate_limiter {
            rl.until_ready(&host).await;
        }

        match send_request().await {
            Ok(resp) if resp.status().as_u16() == 429 => {
                let delay = backoff.delay(BackoffKind::RateLimited, attempt);
                tracing::debug!(
                    url,
                    attempt,
                    delay_ms = delay.as_millis(),
                    "429, backing off"
                );
                tokio::time::sleep(delay).await;
            }
            Ok(resp) => return Ok(resp),
            Err(e) if backoff.should_retry_after(attempt) && is_timeout_error(&e) => {
                let delay = backoff.delay(BackoffKind::Timeout, attempt);
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
    anyhow::bail!("max retries exceeded for {url}")
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn zero_rps_is_unthrottled_not_one() {
        let rl = HostRateLimiter::new(0);
        // Must return immediately without creating governors.
        rl.until_ready("example.com").await;
        assert!(rl.rps.is_none());
        let guard = rl.limiters.read().await;
        assert!(guard.is_empty(), "unthrottled limiter must not allocate per-host governors");
    }

    #[test]
    fn from_config_maps_host_delay_to_rps() {
        let mut cfg = Config::default();
        cfg.host_delay_ms = 100; // 10 rps
        cfg.rate_limit = 300;
        let rl = HostRateLimiter::from_config(&cfg);
        assert_eq!(rl.rps.map(|n| n.get()), Some(10));
    }

    #[test]
    fn from_config_zero_delay_disables() {
        let mut cfg = Config::default();
        cfg.host_delay_ms = 0;
        let rl = HostRateLimiter::from_config(&cfg);
        assert!(rl.rps.is_none());
    }
}
