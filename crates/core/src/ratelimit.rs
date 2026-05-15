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

use hickory_resolver::TokioAsyncResolver;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use tokio::sync::RwLock;

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

/// Build a shared `reqwest::Client` from scan `Config`.
pub fn build_client(
    config: &Config,
    follow_redirects: bool,
    resolver: Arc<TokioAsyncResolver>,
) -> anyhow::Result<reqwest::Client> {
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
        .dns_resolver(Arc::new(HickoryResolver(resolver)))
        .timeout(config.timeout())
        .user_agent(&config.user_agent)
        .default_headers(headers)
        .danger_accept_invalid_certs(config.insecure_tls)
        .redirect(redirect_policy)
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30));

    // Optional proxy
    if let Some(proxy_url) = &config.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| anyhow::anyhow!("invalid proxy: {e}"))?;
        builder = builder.proxy(proxy);
    }

    Ok(builder.build()?)
}

struct HickoryResolver(Arc<TokioAsyncResolver>);

impl reqwest::dns::Resolve for HickoryResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<Box<dyn Iterator<Item = std::net::SocketAddr> + Send>, Box<dyn std::error::Error + Send + Sync>>> + Send>> {
        let resolver = Arc::clone(&self.0);
        Box::pin(async move {
            let lookup = resolver.lookup_ip(name.as_str()).await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let addrs: Box<dyn Iterator<Item = std::net::SocketAddr> + Send> = Box::new(
                lookup.into_iter().map(|ip| std::net::SocketAddr::new(ip, 0))
            );
            Ok(addrs)
        })
    }
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
pub async fn read_response_limited(resp: reqwest::Response, max_size: usize) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut total_read = 0;

    // Check Content-Length header first if available
    if let Some(cl) = resp.content_length() {
        if cl > max_size as u64 {
            anyhow::bail!("Response body exceeds max size (header check): {} > {}", cl, max_size);
        }
    }

    let mut stream = resp.bytes_stream();
    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res?;
        total_read += chunk.len();
        if total_read > max_size {
            anyhow::bail!("Response body exceeds max size (stream check): {} > {}", total_read, max_size);
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
