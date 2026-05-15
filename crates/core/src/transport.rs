//! Unified transport layer for all Gossan scanner modules.
//!
//! [`ScanClient`] wraps a single pooled `reqwest::Client` with:
//!
//! - **Per-host rate limiting** via [`HostRateLimiter`]
//! - **Automatic 429 / timeout backoff** (exponential, 4 retries)
//! - **Response size limiting** (OOM protection)
//! - **Config-driven defaults** (UA, proxy, TLS, timeouts)
//!
//! # Usage
//!
//! ```ignore
//! let client = ScanClient::from_config(&config, resolver)?;
//! let resp = client.get("https://example.com/api").await?;
//! let json: serde_json::Value = client.get_json("https://example.com/api").await?;
//! ```
//!
//! No scanner module should ever import `reqwest` directly or call
//! `reqwest::Client::builder()`. This is the single source of truth.

use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::TokioAsyncResolver;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::config::Config;
use crate::ratelimit::HostRateLimiter;

/// Unified HTTP client for all scanner modules.
///
/// Encapsulates connection pooling, rate limiting, backoff, and response
/// safety. Constructed once per scan and shared (via `Arc<ScanClient>` or
/// `&ScanClient`) across all scanner stages.
#[derive(Clone)]
pub struct ScanClient {
    /// The underlying pooled HTTP client.
    http: reqwest::Client,
    /// Per-host rate limiter.
    rate_limiter: Arc<HostRateLimiter>,
    /// Max response body size in bytes.
    max_response_size: usize,
}

/// DNS resolver bridge for reqwest.
struct HickoryResolver(Arc<TokioAsyncResolver>);

impl reqwest::dns::Resolve for HickoryResolver {
    fn resolve(
        &self,
        name: reqwest::dns::Name,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = std::result::Result<
                        Box<dyn Iterator<Item = std::net::SocketAddr> + Send>,
                        Box<dyn std::error::Error + Send + Sync>,
                    >,
                > + Send,
        >,
    > {
        let resolver = Arc::clone(&self.0);
        Box::pin(async move {
            let lookup = resolver
                .lookup_ip(name.as_str())
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
            let addrs: Box<dyn Iterator<Item = std::net::SocketAddr> + Send> =
                Box::new(lookup.into_iter().map(|ip| std::net::SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}

impl ScanClient {
    /// Build a `ScanClient` from scan configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying reqwest client cannot be constructed
    /// (e.g. invalid proxy URL).
    pub fn from_config(
        config: &Config,
        resolver: Arc<TokioAsyncResolver>,
    ) -> anyhow::Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(cookie_val) = &config.cookie {
            if let Ok(hv) = reqwest::header::HeaderValue::from_str(cookie_val) {
                headers.insert(reqwest::header::COOKIE, hv);
            }
        }

        let mut builder = reqwest::Client::builder()
            .dns_resolver(Arc::new(HickoryResolver(resolver)))
            .timeout(config.timeout())
            .connect_timeout(Duration::from_secs(config.timeout_secs.min(5)))
            .user_agent(&config.user_agent)
            .default_headers(headers)
            .danger_accept_invalid_certs(config.insecure_tls)
            .redirect(reqwest::redirect::Policy::limited(10))
            .pool_max_idle_per_host(32)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30));

        if let Some(proxy_url) = &config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| anyhow::anyhow!("invalid proxy: {e}"))?;
            builder = builder.proxy(proxy);
        }

        let http = builder.build()?;

        let rate_limiter = Arc::new(HostRateLimiter::new(config.rate_limit.max(1)));

        Ok(Self {
            http,
            rate_limiter,
            max_response_size: config.max_response_size,
        })
    }

    /// Build a `ScanClient` that does NOT follow HTTP redirects.
    ///
    /// Useful for scanners that inspect 3xx responses (origin leaks,
    /// header analysis, CORS misconfiguration checks).
    pub fn from_config_no_redirect(
        config: &Config,
        resolver: Arc<TokioAsyncResolver>,
    ) -> anyhow::Result<Self> {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(cookie_val) = &config.cookie {
            if let Ok(hv) = reqwest::header::HeaderValue::from_str(cookie_val) {
                headers.insert(reqwest::header::COOKIE, hv);
            }
        }

        let mut builder = reqwest::Client::builder()
            .dns_resolver(Arc::new(HickoryResolver(resolver)))
            .timeout(config.timeout())
            .connect_timeout(Duration::from_secs(config.timeout_secs.min(5)))
            .user_agent(&config.user_agent)
            .default_headers(headers)
            .danger_accept_invalid_certs(config.insecure_tls)
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(32)
            .pool_idle_timeout(Duration::from_secs(90))
            .tcp_keepalive(Duration::from_secs(30));

        if let Some(proxy_url) = &config.proxy {
            let proxy = reqwest::Proxy::all(proxy_url)
                .map_err(|e| anyhow::anyhow!("invalid proxy: {e}"))?;
            builder = builder.proxy(proxy);
        }

        let http = builder.build()?;
        let rate_limiter = Arc::new(HostRateLimiter::new(config.rate_limit.max(1)));

        Ok(Self {
            http,
            rate_limiter,
            max_response_size: config.max_response_size,
        })
    }

    /// Build a minimal `ScanClient` without DNS resolver or config.
    /// Useful for tests and one-off requests.
    #[must_use]
    pub fn default_client() -> Self {
        Self {
            http: reqwest::Client::new(),
            rate_limiter: Arc::new(HostRateLimiter::new(50)),
            max_response_size: 10 * 1024 * 1024,
        }
    }

    /// Access the underlying `reqwest::Client` for advanced usage.
    ///
    /// Prefer the convenience methods (`get`, `get_json`, `post_json`) where
    /// possible. Direct access is provided for multipart uploads, streaming,
    /// or custom header requirements.
    #[must_use]
    pub fn inner(&self) -> &reqwest::Client {
        &self.http
    }

    // ── Core request methods ─────────────────────────────────────────

    /// Send a GET request with automatic rate limiting and backoff.
    ///
    /// # Errors
    ///
    /// Returns an error if all retries are exhausted.
    pub async fn get(&self, url: &str) -> anyhow::Result<reqwest::Response> {
        self.request_with_backoff(url, || self.http.get(url).send())
            .await
    }

    /// Send a GET and deserialize the JSON response body.
    ///
    /// Enforces `max_response_size` before deserialization.
    ///
    /// # Errors
    ///
    /// Returns an error on network failure, size limit, or JSON parse error.
    pub async fn get_json<T: DeserializeOwned>(&self, url: &str) -> anyhow::Result<T> {
        let resp = self.get(url).await?;
        let bytes = self.read_body(resp).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Send a GET and return the response body as bytes (size-limited).
    pub async fn get_bytes(&self, url: &str) -> anyhow::Result<Vec<u8>> {
        let resp = self.get(url).await?;
        self.read_body(resp).await
    }

    /// Send a POST with a JSON body. Returns the raw response.
    pub async fn post_json<T: Serialize>(
        &self,
        url: &str,
        body: &T,
    ) -> anyhow::Result<reqwest::Response> {
        self.request_with_backoff(url, || self.http.post(url).json(body).send())
            .await
    }

    /// Send a request built via the `reqwest::RequestBuilder` API.
    ///
    /// Rate limiting and backoff are still applied.
    pub async fn execute(
        &self,
        request: reqwest::Request,
    ) -> anyhow::Result<reqwest::Response> {
        let url = request.url().as_str().to_string();
        let host = request
            .url()
            .host_str()
            .unwrap_or("")
            .to_string();
        self.rate_limiter.until_ready(&host).await;
        let resp = self.http.execute(request).await?;
        if resp.status().as_u16() == 429 {
            anyhow::bail!("429 Too Many Requests for {url}");
        }
        Ok(resp)
    }

    // ── Response handling ────────────────────────────────────────────

    /// Read the response body with size limiting (OOM protection).
    ///
    /// # Errors
    ///
    /// Returns an error if the body exceeds `max_response_size`.
    pub async fn read_body(&self, resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
        crate::read_response_limited(resp, self.max_response_size).await
    }

    /// Read the response body and deserialize as JSON.
    pub async fn read_json<T: DeserializeOwned>(
        &self,
        resp: reqwest::Response,
    ) -> anyhow::Result<T> {
        let bytes = self.read_body(resp).await?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    // ── Internal ─────────────────────────────────────────────────────

    /// Retry loop with per-host rate limiting and exponential backoff.
    async fn request_with_backoff<F, Fut>(
        &self,
        url: &str,
        mut send: F,
    ) -> anyhow::Result<reqwest::Response>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
    {
        const MAX_RETRIES: u32 = 4;

        let host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(String::from))
            .unwrap_or_default();

        for attempt in 0..MAX_RETRIES {
            self.rate_limiter.until_ready(&host).await;

            match send().await {
                Ok(resp) if resp.status().as_u16() == 429 => {
                    let delay = Duration::from_millis(500 * 2u64.pow(attempt));
                    tracing::debug!(url, attempt, delay_ms = delay.as_millis(), "429 — backing off");
                    tokio::time::sleep(delay).await;
                }
                Ok(resp) => return Ok(resp),
                Err(e) if attempt + 1 < MAX_RETRIES && e.is_timeout() => {
                    let delay = Duration::from_millis(200 * 2u64.pow(attempt));
                    tracing::debug!(url, attempt, "timeout — retrying in {}ms", delay.as_millis());
                    tokio::time::sleep(delay).await;
                }
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("max retries exceeded for {url}")
    }
}

impl std::ops::Deref for ScanClient {
    type Target = reqwest::Client;

    fn deref(&self) -> &reqwest::Client {
        &self.http
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_client_builds() {
        let client = ScanClient::default_client();
        assert!(client.max_response_size > 0);
    }

    #[test]
    fn from_config_builds() {
        let config = Config::default();
        let resolver = Arc::new(crate::net::build_resolver(&config).unwrap());
        let client = ScanClient::from_config(&config, resolver);
        assert!(client.is_ok());
    }
}
