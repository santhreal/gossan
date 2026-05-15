//! Shared utilities for origin discovery — IP filtering, bounded I/O, etc.

use std::net::IpAddr;

/// Returns `true` only for globally routable IPs.
/// Rejects loopback, private, link-local, multicast, broadcast, and unspecified.
pub fn is_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // Unique local addresses (fc00::/7)
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // Link-local (fe80::/10)
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Read up to `limit` bytes from a response and return as a `String`.
pub async fn bounded_text(resp: reqwest::Response, limit: usize) -> anyhow::Result<String> {
    let mut buf = Vec::with_capacity(limit.min(4096));
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
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

/// Read up to `limit` bytes from a response and return as raw bytes.
pub async fn bounded_bytes(resp: reqwest::Response, limit: usize) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(limit.min(4096));
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = futures::StreamExt::next(&mut stream).await {
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

/// Read up to `limit` bytes from a response and deserialize as JSON.
pub async fn bounded_json<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
    limit: usize,
) -> anyhow::Result<T> {
    let text = bounded_text(resp, limit).await?;
    serde_json::from_str(&text).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routable_ip_accepts_public() {
        assert!(is_routable_ip("1.1.1.1".parse().unwrap()));
        assert!(is_routable_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn routable_ip_rejects_private() {
        assert!(!is_routable_ip("10.0.0.1".parse().unwrap()));
        assert!(!is_routable_ip("192.168.1.1".parse().unwrap()));
        assert!(!is_routable_ip("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn routable_ip_rejects_loopback() {
        assert!(!is_routable_ip("127.0.0.1".parse().unwrap()));
        assert!(!is_routable_ip("::1".parse().unwrap()));
    }

    #[test]
    fn routable_ip_rejects_link_local() {
        assert!(!is_routable_ip("169.254.0.1".parse().unwrap()));
        assert!(!is_routable_ip("fe80::1".parse().unwrap()));
    }

    #[test]
    fn routable_ip_rejects_multicast() {
        assert!(!is_routable_ip("224.0.0.1".parse().unwrap()));
        assert!(!is_routable_ip("ff02::1".parse().unwrap()));
    }
}
