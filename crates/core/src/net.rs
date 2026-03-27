//! Proxy-aware TCP connection primitives.
//!
//! Delegates all proxy protocol handling to [`proxywire`] — supports SOCKS4,
//! SOCKS5, SOCKS5h, and HTTP CONNECT tunneling with optional authentication.
//!
//! Scanners should use [`connect_tcp`] for raw TCP (e.g. AXFR) and
//! [`build_proxy_route`] when they need to pass a route to reqwest.

use tokio::net::TcpStream;

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
