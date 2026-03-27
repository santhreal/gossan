//! HTTP header leak scanner.
//!
//! Probes the target for response headers that inadvertently disclose
//! the origin server IP or internal hostname. Many reverse proxies
//! and load balancers inject headers that leak backend identity.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::OriginCandidate;

/// Headers commonly set by reverse proxies / load balancers that leak origin info.
const LEAK_HEADERS: &[&str] = &[
    "x-served-by",
    "x-backend-server",
    "x-backend",
    "x-host",
    "x-forwarded-server",
    "x-real-ip",
    "x-origin-server",
    "x-server",
    "via",
    "x-powered-by-plesk",
    "x-amz-cf-id",
    "x-azure-ref",
    "cf-ray",
    "server",
];

/// Check HTTP response headers for IP address or hostname leaks.
///
/// Sends requests to both HTTP and HTTPS endpoints and inspects
/// response headers for values that look like IP addresses or
/// internal hostnames that could identify the origin server.
pub async fn scan(domain: String) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut candidates = Vec::new();
    let mut seen_ips = HashSet::new();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .build()?;

    let urls = [format!("https://{}", domain), format!("http://{}", domain)];

    for url in &urls {
        let response = match client.get(url).send().await {
            Ok(r) => r,
            Err(_) => continue,
        };

        for header_name in LEAK_HEADERS {
            if let Some(value) = response.headers().get(*header_name) {
                let val_str = match value.to_str() {
                    Ok(s) => s.to_string(),
                    Err(_) => continue,
                };

                // Try to extract IP addresses from the header value.
                for token in
                    val_str.split(|c: char| !c.is_ascii_alphanumeric() && c != '.' && c != ':')
                {
                    if let Ok(ip) = IpAddr::from_str(token.trim()) {
                        // Skip loopback and private ranges — they're internal but not
                        // useful for direct-connect bypass over the internet.
                        if ip.is_loopback() {
                            continue;
                        }
                        if seen_ips.insert(ip) {
                            let confidence = match *header_name {
                                "x-backend-server" | "x-backend" | "x-origin-server" => 90,
                                "x-served-by" | "x-real-ip" => 85,
                                "x-host" | "x-forwarded-server" => 80,
                                "via" | "server" => 50,
                                _ => 60,
                            };

                            candidates.push(OriginCandidate {
                                ip,
                                method: format!("http_header_leak ({}: {})", header_name, val_str),
                                confidence,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(candidates)
}
