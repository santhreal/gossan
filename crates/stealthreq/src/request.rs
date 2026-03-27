//! Stealth HTTP client with request jitter and header rotation.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;

use crate::{random_user_agent, sleep_jitter, stealth_headers};

// Re-export reqwest types for convenience
pub use upstream_reqwest::Client;

/// Configuration for stealth request behavior.
#[derive(Debug, Clone)]
pub struct StealthConfig {
    /// Base delay between requests (milliseconds)
    pub base_delay_ms: u64,
    /// Jitter factor (0.0-1.0) for randomizing delays
    pub jitter_factor: f64,
    /// Request timeout
    pub timeout: Duration,
    /// Follow redirects
    pub follow_redirects: bool,
    /// Maximum redirects to follow
    pub max_redirects: usize,
    /// Proxy URL (optional)
    pub proxy: Option<String>,
    /// Default headers to include with every request
    pub default_headers: HashMap<String, String>,
    /// Accept invalid TLS certificates
    pub insecure_tls: bool,
}

impl Default for StealthConfig {
    fn default() -> Self {
        Self {
            base_delay_ms: 1000,
            jitter_factor: 0.2,
            timeout: Duration::from_secs(30),
            follow_redirects: true,
            max_redirects: 10,
            proxy: None,
            default_headers: HashMap::new(),
            insecure_tls: false,
        }
    }
}

impl StealthConfig {
    /// Create a new config with aggressive stealth (higher delays, more jitter).
    pub fn aggressive() -> Self {
        Self {
            base_delay_ms: 2000,
            jitter_factor: 0.4,
            ..Default::default()
        }
    }

    /// Create a new config with minimal stealth (lower delays, less jitter).
    pub fn minimal() -> Self {
        Self {
            base_delay_ms: 500,
            jitter_factor: 0.1,
            ..Default::default()
        }
    }

    /// Set base delay.
    pub fn with_delay(mut self, ms: u64) -> Self {
        self.base_delay_ms = ms;
        self
    }

    /// Set jitter factor.
    pub fn with_jitter(mut self, factor: f64) -> Self {
        self.jitter_factor = factor.clamp(0.0, 1.0);
        self
    }

    /// Set proxy.
    pub fn with_proxy(mut self, proxy: impl Into<String>) -> Self {
        self.proxy = Some(proxy.into());
        self
    }

    /// Set timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// HTTP client with stealth capabilities.
///
/// Automatically rotates User-Agents and varies headers per request.
/// Adds jittered delays between requests to avoid rate limiting.
pub struct StealthClient {
    inner: upstream_reqwest::Client,
    config: StealthConfig,
}

impl StealthClient {
    /// Create a new stealth client with the given configuration.
    pub fn new(config: StealthConfig) -> Result<Self> {
        let client = build_inner_client(&config)?;
        Ok(Self {
            inner: client,
            config,
        })
    }

    /// Create a GET request with stealth headers.
    pub fn get(&self, url: impl AsRef<str>) -> StealthRequestBuilder {
        self.request(upstream_reqwest::Method::GET, url)
    }

    /// Create a POST request with stealth headers.
    pub fn post(&self, url: impl AsRef<str>) -> StealthRequestBuilder {
        self.request(upstream_reqwest::Method::POST, url)
    }

    /// Create a PUT request with stealth headers.
    pub fn put(&self, url: impl AsRef<str>) -> StealthRequestBuilder {
        self.request(upstream_reqwest::Method::PUT, url)
    }

    /// Create a DELETE request with stealth headers.
    pub fn delete(&self, url: impl AsRef<str>) -> StealthRequestBuilder {
        self.request(upstream_reqwest::Method::DELETE, url)
    }

    /// Create a request with the given method and stealth headers.
    pub fn request(&self, method: upstream_reqwest::Method, url: impl AsRef<str>) -> StealthRequestBuilder {
        let url = url.as_ref().to_string();
        let mut builder = self.inner.request(method, &url);
        
        // Add stealth headers
        let headers = stealth_headers();
        for (key, value) in &headers {
            if let Ok(header_value) = upstream_reqwest::header::HeaderValue::from_str(value) {
                if let Ok(header_name) = upstream_reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
                    builder = builder.header(header_name, header_value);
                }
            }
        }
        
        // Add random User-Agent
        let ua = random_user_agent();
        if let Ok(ua_value) = upstream_reqwest::header::HeaderValue::from_str(&ua) {
            builder = builder.header(upstream_reqwest::header::USER_AGENT, ua_value);
        }
        
        StealthRequestBuilder {
            inner: builder,
            config: self.config.clone(),
            applied_jitter: false,
        }
    }

    /// Get a reference to the inner reqwest client.
    pub fn inner(&self) -> &upstream_reqwest::Client {
        &self.inner
    }

    /// Get the configuration.
    pub fn config(&self) -> &StealthConfig {
        &self.config
    }
}

/// Builder for stealth HTTP requests.
pub struct StealthRequestBuilder {
    inner: upstream_reqwest::RequestBuilder,
    config: StealthConfig,
    applied_jitter: bool,
}

impl StealthRequestBuilder {
    /// Add a header to the request.
    pub fn header(mut self, key: impl AsRef<str>, value: impl AsRef<str>) -> Self {
        if let Ok(name) = upstream_reqwest::header::HeaderName::from_bytes(key.as_ref().as_bytes()) {
            if let Ok(val) = upstream_reqwest::header::HeaderValue::from_str(value.as_ref()) {
                self.inner = self.inner.header(name, val);
            }
        }
        self
    }

    /// Set the request body.
    pub fn body(mut self, body: impl Into<upstream_reqwest::Body>) -> Self {
        self.inner = self.inner.body(body);
        self
    }

    /// Set JSON body.
    pub fn json<T: serde::Serialize>(mut self, json: &T) -> Self {
        self.inner = self.inner.json(json);
        self
    }

    /// Set form body.
    pub fn form<T: serde::Serialize>(mut self, form: &T) -> Self {
        self.inner = self.inner.form(form);
        self
    }

    /// Disable jitter for this request.
    pub fn no_jitter(mut self) -> Self {
        self.applied_jitter = true; // Mark as applied so we skip it
        self
    }

    /// Send the request with jitter.
    pub async fn send(self) -> Result<upstream_reqwest::Response> {
        // Apply jitter before request
        if !self.applied_jitter {
            sleep_jitter(self.config.base_delay_ms, self.config.jitter_factor).await;
        }
        
        let response = self.inner.send().await?;
        Ok(response)
    }
}

/// Build the inner reqwest client from config.
fn build_inner_client(config: &StealthConfig) -> Result<upstream_reqwest::Client> {
    let redirect_policy = if config.follow_redirects {
        upstream_reqwest::redirect::Policy::limited(config.max_redirects)
    } else {
        upstream_reqwest::redirect::Policy::none()
    };

    let mut builder = upstream_reqwest::Client::builder()
        .timeout(config.timeout)
        .danger_accept_invalid_certs(config.insecure_tls)
        .redirect(redirect_policy)
        .pool_max_idle_per_host(20)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Duration::from_secs(30));

    // Add default headers
    let mut default_headers = upstream_reqwest::header::HeaderMap::new();
    for (key, value) in &config.default_headers {
        if let Ok(name) = upstream_reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
            if let Ok(val) = upstream_reqwest::header::HeaderValue::from_str(value) {
                default_headers.insert(name, val);
            }
        }
    }
    if !default_headers.is_empty() {
        builder = builder.default_headers(default_headers);
    }

    // Add proxy if configured
    if let Some(proxy_url) = &config.proxy {
        builder = builder.proxy(upstream_reqwest::Proxy::all(proxy_url)?);
    }

    Ok(builder.build()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stealth_config_default() {
        let config = StealthConfig::default();
        assert_eq!(config.base_delay_ms, 1000);
        assert_eq!(config.jitter_factor, 0.2);
        assert!(config.follow_redirects);
    }

    #[test]
    fn stealth_config_aggressive() {
        let config = StealthConfig::aggressive();
        assert_eq!(config.base_delay_ms, 2000);
        assert_eq!(config.jitter_factor, 0.4);
    }

    #[test]
    fn stealth_config_minimal() {
        let config = StealthConfig::minimal();
        assert_eq!(config.base_delay_ms, 500);
        assert_eq!(config.jitter_factor, 0.1);
    }

    #[test]
    fn stealth_config_builder() {
        let config = StealthConfig::default()
            .with_delay(1500)
            .with_jitter(0.3)
            .with_proxy("http://127.0.0.1:8080");
        
        assert_eq!(config.base_delay_ms, 1500);
        assert_eq!(config.jitter_factor, 0.3);
        assert_eq!(config.proxy, Some("http://127.0.0.1:8080".to_string()));
    }

    #[test]
    fn stealth_client_creation() {
        let config = StealthConfig::minimal();
        let client = StealthClient::new(config);
        assert!(client.is_ok());
    }

    #[test]
    fn stealth_request_builder_chaining() {
        let config = StealthConfig::default();
        let client = StealthClient::new(config).unwrap();
        
        let builder = client
            .get("https://example.com")
            .header("X-Custom", "value")
            .no_jitter();
        
        // Should compile without errors
        drop(builder);
    }
}
