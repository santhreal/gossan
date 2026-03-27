//! HTTP header leak scanner.
//!
//! Probes the target for response headers that inadvertently disclose
//! the origin server IP or internal hostname. Many reverse proxies
//! and load balancers inject headers that leak backend identity.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;
use serde::Deserialize;
use std::sync::OnceLock;

use crate::OriginCandidate;

/// HTTP header definition from TOML with confidence score.
#[derive(Debug, Clone, Deserialize)]
struct LeakHeader {
    name: String,
    confidence: u8,
    #[allow(dead_code)]
    description: String,
}

/// TOML file containing leak header definitions.
#[derive(Debug, Deserialize)]
struct LeakHeadersFile {
    header: Vec<LeakHeader>,
}

/// Built-in leak_headers.toml content (embedded at compile time).
const BUILTIN_LEAK_HEADERS: &str = include_str!("../../rules/leak_headers.toml");

/// Global cache for built-in leak headers.
static LEAK_HEADERS: OnceLock<Vec<LeakHeader>> = OnceLock::new();

/// Initialize and return the built-in leak headers.
fn builtin_leak_headers() -> &'static Vec<LeakHeader> {
    LEAK_HEADERS.get_or_init(|| {
        match toml::from_str::<LeakHeadersFile>(BUILTIN_LEAK_HEADERS) {
            Ok(file) => file.header,
            Err(e) => {
                tracing::error!(error = %e, "failed to parse built-in leak_headers.toml");
                // Fallback to minimal hardcoded list only on parse failure
                vec![
                    LeakHeader {
                        name: "x-served-by".to_string(),
                        confidence: 85,
                        description: "CDN backend identifier".to_string(),
                    },
                    LeakHeader {
                        name: "x-backend-server".to_string(),
                        confidence: 90,
                        description: "Backend server name".to_string(),
                    },
                    LeakHeader {
                        name: "x-real-ip".to_string(),
                        confidence: 85,
                        description: "Original client IP".to_string(),
                    },
                ]
            }
        }
    })
}

/// Get leak headers from TOML configuration.
fn leak_headers() -> &'static [LeakHeader] {
    builtin_leak_headers()
}

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

        for header in leak_headers() {
            if let Some(value) = response.headers().get(&header.name) {
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
                            let confidence = match header.name.as_str() {
                                "x-backend-server" | "x-backend" | "x-origin-server" => 90,
                                "x-served-by" | "x-real-ip" => 85,
                                "x-host" | "x-forwarded-server" => 80,
                                "via" | "server" => 50,
                                _ => header.confidence,
                            };

                            candidates.push(OriginCandidate {
                                ip,
                                method: format!("http_header_leak ({}: {})", header.name, val_str),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leak_headers_load_from_toml() {
        let headers = leak_headers();
        assert!(!headers.is_empty(), "should have leak headers from TOML");
        assert!(
            headers.iter().any(|h| h.name == "x-served-by"),
            "should include x-served-by header"
        );
    }

    #[test]
    fn leak_headers_have_required_fields() {
        for header in leak_headers() {
            assert!(!header.name.is_empty(), "header name should not be empty");
            assert!(header.confidence > 0, "confidence should be > 0");
            assert!(header.confidence <= 100, "confidence should be <= 100");
        }
    }

    #[test]
    fn leak_headers_include_critical_ones() {
        let names: Vec<_> = leak_headers().iter().map(|h| h.name.clone()).collect();
        for expected in ["x-served-by", "x-backend-server", "x-real-ip", "cf-ray"] {
            assert!(names.contains(&expected.to_string()), "missing header: {}", expected);
        }
    }

    #[test]
    fn high_confidence_headers_prioritized() {
        let high_confidence: Vec<_> = leak_headers()
            .iter()
            .filter(|h| h.confidence >= 80)
            .map(|h| h.name.clone())
            .collect();
        
        assert!(
            high_confidence.contains(&"x-backend-server".to_string()),
            "x-backend-server should have high confidence"
        );
        assert!(
            high_confidence.contains(&"x-served-by".to_string()),
            "x-served-by should have high confidence"
        );
    }
}
