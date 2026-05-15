//! Proxy-aware TCP connection primitives.
//!
//! Delegates all proxy protocol handling to [`proxywire`] — supports SOCKS4,
//! SOCKS5, SOCKS5h, and HTTP CONNECT tunneling with optional authentication.
//!
//! Scanners should use [`connect_tcp`] for raw TCP (e.g. AXFR) and
//! [`build_proxy_route`] when they need to pass a route to reqwest.

use tokio::net::TcpStream;
use hickory_resolver::{
    config::{NameServerConfigGroup, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use crate::Config;

/// Build a high-performance, async DNS resolver.
///
/// If `config.resolvers` is empty, uses Cloudflare's public DNS.
/// # Errors
///
/// Returns an error if the resolver configuration is invalid.
pub fn build_resolver(config: &Config) -> anyhow::Result<TokioAsyncResolver> {
    let servers = if config.resolvers.is_empty() {
        NameServerConfigGroup::cloudflare()
    } else {
        NameServerConfigGroup::from_ips_clear(&config.resolvers, 53, true)
    };
    let rc = ResolverConfig::from_parts(None, vec![], servers);
    let mut opts = ResolverOpts::default();
    opts.timeout = config.timeout();
    opts.attempts = 1;
    // DNS rebinding mitigation: hold the first positive resolution for
    // a long minimum TTL so the same hostname does not silently
    // re-resolve to a different IP mid-scan. An attacker's authoritative
    // server can otherwise hand back a private/loopback IP after the
    // initial public-facing answer and trick a follow-up probe into
    // hitting an internal asset. We pin to 1 hour — long enough for any
    // single scan to finish, short enough that a real IP change is
    // picked up on the next process invocation.
    opts.positive_min_ttl =
        Some(std::time::Duration::from_secs(3600));
    // Cap negative caching so a transient NXDOMAIN doesn't permanently
    // poison the resolver for the rest of the process.
    opts.negative_min_ttl = Some(std::time::Duration::from_secs(60));
    opts.cache_size = 8192;
    Ok(TokioAsyncResolver::tokio(rc, opts))
}

/// Create a TCP connection, optionally routing through a proxy.
///
/// Supports:
/// - `socks5://host:port` — SOCKS5 (proxy resolves DNS)
/// - `socks5h://host:port` — SOCKS5 with local DNS resolution
/// - `socks4://host:port` — SOCKS4
/// - `http://host:port` — HTTP CONNECT tunnel
///
/// # Errors
///
/// Returns an I/O error if the connection or proxy handshake fails.
pub async fn connect_tcp(addr: &str, port: u16, proxy: Option<&str>) -> std::io::Result<TcpStream> {
    let Some(proxy_url) = proxy else {
        return TcpStream::connect((addr, port)).await;
    };

    let target = proxywire::ProxyTarget::new(addr.to_string(), port);
    let route = parse_proxy_route(proxy_url)
        .map_err(|e| std::io::Error::other(format!("invalid proxy URL: {e}")))?;

    proxywire::connect_via_route(&route, &target)
        .await
        .map_err(|e| std::io::Error::other(format!("proxy connection failed: {e}")))
}

/// Build a [`proxywire::ProxyRoute`] from a proxy URL string.
///
/// Returns `ProxyRoute::Direct` if the proxy string is `None`.
///
/// # Errors
///
/// Returns an error if the proxy URL scheme is not recognized.
pub fn build_proxy_route(proxy: Option<&str>) -> Result<proxywire::ProxyRoute, String> {
    match proxy {
        None => Ok(proxywire::ProxyRoute::Direct),
        Some(url) => parse_proxy_route(url).map_err(|e| e.to_string()),
    }
}

/// Parse a proxy URL string into a single-hop [`ProxyRoute`].
fn parse_proxy_route(url: &str) -> Result<proxywire::ProxyRoute, proxywire::Error> {
    let (protocol, host_port) = if let Some(rest) = url.strip_prefix("socks5h://") {
        (proxywire::ProxyProtocol::Socks5LocalDns, rest)
    } else if let Some(rest) = url.strip_prefix("socks5://") {
        (proxywire::ProxyProtocol::Socks5, rest)
    } else if let Some(rest) = url.strip_prefix("socks4://") {
        (proxywire::ProxyProtocol::Socks4, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (proxywire::ProxyProtocol::HttpConnect, rest)
    } else {
        // Default to SOCKS5 for bare host:port
        (proxywire::ProxyProtocol::Socks5, url)
    };

    let (host, port) = parse_host_port(host_port)?;
    let endpoint = proxywire::ProxyEndpoint::new(protocol, host, port);
    Ok(proxywire::ProxyRoute::Chain(vec![endpoint]))
}

/// Extract host and port from `host:port` string.
fn parse_host_port(s: &str) -> Result<(&str, u16), proxywire::Error> {
    let (host, port_str) = s.rsplit_once(':').ok_or_else(|| proxywire::Error::InvalidConfig {
        message: format!("proxy URL missing port: {s}"),
        fix: "use format scheme://host:port (e.g. socks5://127.0.0.1:9050)".to_string(),
    })?;
    let port = port_str.parse::<u16>().map_err(|_| proxywire::Error::InvalidConfig {
        message: format!("invalid port number: {port_str}"),
        fix: "port must be a number between 1 and 65535".to_string(),
    })?;
    Ok((host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_socks5_proxy() {
        let route = parse_proxy_route("socks5://127.0.0.1:9050").unwrap();
        match route {
            proxywire::ProxyRoute::Chain(hops) => {
                assert_eq!(hops.len(), 1);
                assert_eq!(hops[0].protocol, proxywire::ProxyProtocol::Socks5);
            }
            proxywire::ProxyRoute::Direct => panic!("expected chain, got direct"),
            // ProxyRoute is `#[non_exhaustive]`; future variants must
            // not silently swallow data — panic loudly so we notice
            // when proxywire grows a new transport.
            _ => panic!("unhandled ProxyRoute variant"),
        }
    }

    #[test]
    fn parse_http_connect_proxy() {
        let route = parse_proxy_route("http://proxy.corp:8080").unwrap();
        match route {
            proxywire::ProxyRoute::Chain(hops) => {
                assert_eq!(hops[0].protocol, proxywire::ProxyProtocol::HttpConnect);
            }
            proxywire::ProxyRoute::Direct => panic!("expected chain"),
            _ => panic!("unhandled ProxyRoute variant"),
        }
    }

    #[test]
    fn parse_socks5h_proxy() {
        let route = parse_proxy_route("socks5h://tor:9050").unwrap();
        match route {
            proxywire::ProxyRoute::Chain(hops) => {
                assert_eq!(hops[0].protocol, proxywire::ProxyProtocol::Socks5LocalDns);
            }
            proxywire::ProxyRoute::Direct => panic!("expected chain"),
            _ => panic!("unhandled ProxyRoute variant"),
        }
    }

    #[test]
    fn build_proxy_route_returns_direct_for_none() {
        let route = build_proxy_route(None).unwrap();
        assert!(matches!(route, proxywire::ProxyRoute::Direct));
    }

    #[test]
    fn parse_rejects_missing_port() {
        assert!(parse_proxy_route("socks5://localhost").is_err());
    }
}

/// Read up to `limit` bytes from a reqwest response and return as a `String`.
///
/// Bounds the response body before any caller calls `.text()` or
/// `.bytes()`. Without this, a malicious endpoint can return a 10 GB
/// body and OOM the scanner. Every HTTP-consuming scanner should
/// route through this helper or `bounded_bytes`.
///
/// # Errors
///
/// Returns the underlying reqwest error if the stream fails mid-read.
pub async fn bounded_text(resp: reqwest::Response, limit: usize) -> anyhow::Result<String> {
    use futures::StreamExt;
    let mut buf = Vec::with_capacity(limit.min(4096));
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let remaining = limit.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        buf.extend_from_slice(&chunk[..take]);
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

/// Read up to `limit` bytes from a reqwest response and return as raw bytes.
///
/// # Errors
///
/// Returns the underlying reqwest error if the stream fails mid-read.
pub async fn bounded_bytes(resp: reqwest::Response, limit: usize) -> anyhow::Result<Vec<u8>> {
    use futures::StreamExt;
    let mut buf = Vec::with_capacity(limit.min(4096));
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let remaining = limit.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        buf.extend_from_slice(&chunk[..take]);
    }
    Ok(buf)
}

/// Read up to `limit` bytes from a reqwest response and deserialize as JSON.
///
/// # Errors
///
/// Returns an error on stream failure or JSON parse failure.
pub async fn bounded_json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    limit: usize,
) -> anyhow::Result<T> {
    let text = bounded_text(resp, limit).await?;
    serde_json::from_str(&text).map_err(Into::into)
}

#[cfg(test)]
mod bounded_tests {
    use super::*;

    #[tokio::test]
    async fn bounded_text_caps_at_limit() {
        // Spin up a tiny tokio listener that writes 100 KiB.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut s, _) = listener.accept().await.unwrap();
            let body = "x".repeat(100 * 1024);
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.shutdown().await;
        });
        let url = format!("http://{addr}/");
        let resp = reqwest::get(&url).await.unwrap();
        let body = bounded_text(resp, 4096).await.unwrap();
        assert_eq!(body.len(), 4096, "must clamp to limit, got {}", body.len());
    }

    #[tokio::test]
    async fn bounded_text_returns_full_body_when_smaller_than_limit() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut s, _) = listener.accept().await.unwrap();
            let body = "hello";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = s.write_all(resp.as_bytes()).await;
            let _ = s.shutdown().await;
        });
        let url = format!("http://{addr}/");
        let resp = reqwest::get(&url).await.unwrap();
        let body = bounded_text(resp, 1024 * 1024).await.unwrap();
        assert_eq!(body, "hello");
    }
}
