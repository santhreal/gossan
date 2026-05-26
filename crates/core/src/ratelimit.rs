//! Per-host rate limiter with automatic 429 / backoff handling.
//!
//! The global `governor` rate limiter in `Config` caps total RPS across all hosts.
//! This module adds a second layer: independent per-hostname buckets so that a burst
//! against one host doesn't consume the global budget and block scanning of others.
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
use std::sync::Arc;
use std::time::Duration;

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use hickory_resolver::TokioAsyncResolver;
use scanclient::reqwest;
use tokio::sync::RwLock;

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
    limiters: RwLock<HashMap<String, Arc<DefaultDirectRateLimiter>>>,
    rps: NonZeroU32,
}

impl HostRateLimiter {
    /// `rps_per_host`: max requests per second per unique hostname.
    #[must_use]
    pub fn new(rps_per_host: u32) -> Self {
        Self {
            limiters: RwLock::new(HashMap::new()),
            rps: NonZeroU32::new(rps_per_host).unwrap_or(NonZeroU32::MIN),
        }
    }

    /// Async-wait until a request to `host` is within the rate budget.
    pub async fn until_ready(&self, host: &str) {
        let limiter = self.get_or_create(host).await;
        limiter.until_ready().await;
    }

    async fn get_or_create(&self, host: &str) -> Arc<DefaultDirectRateLimiter> {
        {
            let read = self.limiters.read().await;
            if let Some(l) = read.get(host) {
                return Arc::clone(l);
            }
        }
        // Not yet seen — insert under write lock
        let mut write = self.limiters.write().await;
        // Double-check after acquiring write lock
        if let Some(l) = write.get(host) {
            return Arc::clone(l);
        }
        let quota = Quota::per_second(self.rps);
        let limiter = Arc::new(RateLimiter::direct(quota));
        write.insert(host.to_string(), Arc::clone(&limiter));
        limiter
    }
}

/// Build a shared `reqwest::Client` from scan `Config` via scanclient's pool.
pub fn build_client(
    config: &Config,
    follow_redirects: bool,
    resolver: Arc<TokioAsyncResolver>,
) -> anyhow::Result<reqwest::Client> {
    crate::transport::warn_insecure_tls_once(config.insecure_tls);
    let redirect_policy = if follow_redirects {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };
    scanclient_bridge::build_http_client(config, resolver, redirect_policy)
        .map_err(|e| anyhow::anyhow!("scanclient pool: {e}"))
}

/// Retry an HTTP GET request, backing off exponentially on 429 responses.
///
/// Backoff schedule: 500 ms → 1 s → 2 s → 4 s → give up.
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
    let mut body = Vec::new();
    let mut total_read = 0;

    // Check Content-Length header first if available
    if let Some(cl) = resp.content_length() {
        if cl > max_size as u64 {
            anyhow::bail!(
                "Response body exceeds max size (header check): {} > {}",
                cl,
                max_size
            );
        }
    }

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
    const MAX_RETRIES: u32 = 4;

    let host = {
        let parsed = url::Url::parse(url)?;
        parsed.host_str().unwrap_or(url).to_string()
    };

    for attempt in 0..MAX_RETRIES {
        if let Some(rl) = rate_limiter {
            rl.until_ready(&host).await;
        }

        match send_request().await {
            Ok(resp) if resp.status().as_u16() == 429 => {
                let delay = Duration::from_millis(500 * 2u64.pow(attempt));
                tracing::debug!(
                    url,
                    attempt,
                    delay_ms = delay.as_millis(),
                    "429 — backing off"
                );
                tokio::time::sleep(delay).await;
            }
            Ok(resp) => return Ok(resp),
            Err(e) if attempt + 1 < MAX_RETRIES && is_timeout_error(&e) => {
                let delay = Duration::from_millis(200 * 2u64.pow(attempt));
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e),
        }
    }
    anyhow::bail!("max retries exceeded for {url}")
}
