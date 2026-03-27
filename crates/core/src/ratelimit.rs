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
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use tokio::sync::RwLock;

use crate::Config;

/// Per-hostname rate limiter.  Creates an independent token-bucket governor for
/// each unique hostname the first time it is seen; subsequent calls reuse it.
pub struct HostRateLimiter {
    limiters: RwLock<HashMap<String, Arc<DefaultDirectRateLimiter>>>,
    rps: u32,
}

impl HostRateLimiter {
    /// `rps_per_host`: max requests per second per unique hostname.
    pub fn new(rps_per_host: u32) -> Self {
        Self {
            limiters: RwLock::new(HashMap::new()),
            rps: rps_per_host.max(1),
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
        let quota = Quota::per_second(
            NonZeroU32::new(self.rps).expect("rps is clamped to >= 1 at construction"),
        );
        let limiter = Arc::new(RateLimiter::direct(quota));
        write.insert(host.to_string(), Arc::clone(&limiter));
        limiter
    }
}

/// Build a shared `reqwest::Client` from scan `Config`.
///
/// All scanners should call this rather than constructing their own client, so
/// proxy, timeout, user-agent, and TLS settings are applied consistently.
///
/// `follow_redirects`: pass `true` for normal probing; `false` where you need to
/// see `3xx` responses directly (e.g. open-redirect detection, 403-bypass).
pub fn build_client(config: &Config, follow_redirects: bool) -> anyhow::Result<reqwest::Client> {
    let redirect_policy = if follow_redirects {
        reqwest::redirect::Policy::limited(10)
    } else {
        reqwest::redirect::Policy::none()
    };

    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(cookie_val) = &config.cookie {
        if let Ok(hv) = reqwest::header::HeaderValue::from_str(cookie_val) {
            headers.insert(reqwest::header::COOKIE, hv);
        }
    }

    let mut builder = reqwest::Client::builder()
        .timeout(config.timeout())
        .user_agent(&config.user_agent)
        .default_headers(headers)
        .danger_accept_invalid_certs(true)
        .redirect(redirect_policy)
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30));

    if let Some(proxy_url) = &config.proxy {
        builder = builder.proxy(reqwest::Proxy::all(proxy_url)?);
    }

    Ok(builder.build()?)
}

/// Retry an HTTP GET request, backing off exponentially on 429 responses.
///
/// Backoff schedule: 500 ms → 1 s → 2 s → 4 s → give up.
///
/// Returns the first non-429 response, or an error if all retries are exhausted
/// or a non-retryable error occurs.
pub async fn get_with_backoff(
    client: &reqwest::Client,
    url: &str,
    rate_limiter: Option<&HostRateLimiter>,
) -> anyhow::Result<reqwest::Response> {
    let host = {
        let parsed = url::Url::parse(url)?;
        parsed.host_str().unwrap_or(url).to_string()
    };

    const MAX_RETRIES: u32 = 4;
    for attempt in 0..MAX_RETRIES {
        if let Some(rl) = rate_limiter {
            rl.until_ready(&host).await;
        }

        match client.get(url).send().await {
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
            Err(e) if attempt + 1 < MAX_RETRIES && e.is_timeout() => {
                let delay = Duration::from_millis(200 * 2u64.pow(attempt));
                tokio::time::sleep(delay).await;
            }
            Err(e) => return Err(e.into()),
        }
    }
    anyhow::bail!("max retries exceeded for {}", url)
}
