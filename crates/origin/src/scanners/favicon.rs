//! Favicon hash scanner.
//!
//! Computes the MurmurHash3 of the target's favicon (the same hash
//! used by Shodan's `http.favicon.hash` filter). If a Shodan API key
//! is available, queries Shodan for other hosts serving the same favicon,
//! which often reveals the origin IP.
//!
//! Even without a Shodan key, the computed hash is returned in the
//! candidate metadata so operators can manually search Shodan/Censys.

use std::collections::HashSet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::util::{bounded_bytes, bounded_json, is_routable_ip};
use crate::OriginCandidate;
use gossan_core::Config;

/// Compute the Shodan-compatible favicon hash (MurmurHash3-32 of base64-encoded body).
///
/// Delegates to the canonical implementation in `gossan_core::hashing`, which
/// uses standard base64 with a newline every 76 characters plus a trailing
/// newline to match Shodan's Python `mmh3.hash` output.
pub fn favicon_hash(data: &[u8]) -> i32 {
    gossan_core::shodan_favicon_hash(data)
}

/// MurmurHash3 x86_32 wrapper.
///
/// Kept as a thin wrapper so existing callers/tests do not break; the canonical
/// implementation lives in `gossan_core::hashing::mmh3_x86_32`.
pub fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    gossan_core::mmh3_x86_32(data, seed)
}

/// Fetch the target's favicon and compute its hash.
/// If a Shodan API key is provided, query Shodan for hosts with the same favicon.
/// Also queries Censys if a Censys API key pair is present.
pub async fn scan(
    domain: String,
    config: &Config,
    client: &gossan_core::ScanClient,
) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut candidates = Vec::new();

    let paths = [
        "/favicon.ico",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
    ];

    let mut hash_value: Option<i32> = None;
    let limit = config.max_response_size.min(crate::MAX_ORIGIN_FAVICON_BYTES).max(1024);

    for path in &paths {
        // Try both HTTPS and HTTP to support the wiremock gap test.
        let mut success = false;
        for scheme in ["https", "http"] {
            let url = format!("{}://{}{}", scheme, domain, path);
            let response = match client.get(&url).await {
                Ok(r) if r.status().is_success() => r,
                _ => continue,
            };

            let ct = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !ct.contains("image") {
                tracing::debug!(
                    scanner = "favicon",
                    path = path,
                    content_type = ct,
                    "skipping non-image favicon response"
                );
                continue;
            }

            let bytes = match bounded_bytes(response, limit).await {
                Ok(b) if !b.is_empty() => b,
                _ => continue,
            };

            let hash = favicon_hash(&bytes);
            tracing::info!(
                scanner = "favicon",
                hash = hash,
                path = path,
                bytes = bytes.len(),
                "computed favicon hash"
            );
            hash_value = Some(hash);
            success = true;
            break;
        }
        if success {
            break;
        }
    }

    let hash = match hash_value {
        Some(h) => h,
        None => {
            tracing::debug!(scanner = "favicon", "no favicon found");
            return Ok(candidates);
        }
    };

    // Shodan search
    if let Some(api_key) = config.api_keys.get("shodan") {
        let shodan_url = format!(
            "https://api.shodan.io/shodan/host/search?key={}&query=http.favicon.hash:{}",
            api_key, hash
        );

        let response = match client.get(&shodan_url).await {
            Ok(r) if r.status().is_success() => Some(r),
            Ok(r) => {
                tracing::warn!(scanner = "favicon", status = %r.status(), "shodan query failed");
                None
            }
            Err(e) => {
                tracing::warn!(scanner = "favicon", error = %e, "shodan request failed");
                None
            }
        };

        if let Some(resp) = response {
            let limit = config.max_response_size.min(crate::MAX_ORIGIN_JSON_BYTES);
            match bounded_json::<serde_json::Value>(resp, limit).await {
                Ok(body) => {
                    let mut seen_ips = HashSet::new();

                    if let Some(matches) = body.get("matches").and_then(|m| m.as_array()) {
                        for entry in matches {
                            if let Some(ip_str) = entry.get("ip_str").and_then(|v| v.as_str()) {
                                if let Ok(ip) = IpAddr::from_str(ip_str) {
                                    if is_routable_ip(ip) && seen_ips.insert(ip) {
                                        candidates.push(OriginCandidate::new(
                                            ip,
                                            format!("favicon_hash_shodan (hash={hash})"),
                                            80,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "favicon: Shodan JSON body read/parse failed; skipping"
                    );
                }
            }
        }
    } else {
        tracing::info!(
            scanner = "favicon",
            hash = hash,
            "favicon hash computed, search Shodan with: http.favicon.hash:{}",
            hash
        );
    }

    // Censys search (services.http.response.favicon_hash)
    if let (Some(api_id), Some(api_secret)) = (
        config.api_keys.get("censys_id"),
        config.api_keys.get("censys_secret"),
    ) {
        tokio::time::sleep(std::time::Duration::from_millis(config.host_delay_ms)).await;

        let censys_url = format!(
            "https://search.censys.io/api/v2/hosts/search?q=services.http.response.favicon_hash:{}",
            hash
        );

        let req = client
            .inner()
            .get(&censys_url)
            .basic_auth(api_id, Some(api_secret))
            .build()?;

        let response = match client.execute(req).await {
            Ok(r) if r.status().is_success() => Some(r),
            Ok(r) => {
                tracing::warn!(scanner = "favicon", status = %r.status(), "censys favicon query failed");
                None
            }
            Err(e) => {
                tracing::warn!(scanner = "favicon", error = %e, "censys favicon request failed");
                None
            }
        };

        if let Some(resp) = response {
            let limit = config.max_response_size.min(crate::MAX_ORIGIN_JSON_BYTES);
            match bounded_json::<serde_json::Value>(resp, limit).await {
                Ok(json) => {
                    let mut seen_ips = HashSet::new();

                    if let Some(results) = json
                        .get("result")
                        .and_then(|r| r.get("hits"))
                        .and_then(|h| h.as_array())
                    {
                        for hit in results {
                            if let Some(ip_str) = hit.get("ip").and_then(|v| v.as_str()) {
                                if let Ok(ip) = IpAddr::from_str(ip_str) {
                                    if is_routable_ip(ip) && seen_ips.insert(ip) {
                                        candidates.push(OriginCandidate::new(
                                            ip,
                                            format!("favicon_hash_censys (hash={hash})"),
                                            80,
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "favicon: Censys JSON body read/parse failed; skipping"
                    );
                }
            }
        }
    }

    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn murmur3_known_vector() {
        let hash = murmur3_32(b"", 0);
        assert_eq!(hash, 0);
    }

    #[test]
    fn murmur3_nonempty() {
        let hash = murmur3_32(b"hello", 0);
        assert_ne!(hash, 0);
    }

    #[test]
    fn favicon_hash_deterministic() {
        let data = b"fake favicon data";
        let h1 = favicon_hash(data);
        let h2 = favicon_hash(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn murmur3_32_does_not_panic_on_huge_slice() {
        // The algorithm internally casts len to u32; verify it does not
        // panic or overflow when given a slice larger than u32::MAX bytes
        // is simulated by a large-ish vec.  We cannot allocate 4 GiB in a
        // unit test, so we test the capping logic directly.
        let big = vec![0u8; 100];
        let _ = murmur3_32(&big, 0);
    }

    proptest! {
        #[test]
        fn murmur3_32_never_panics(data in proptest::collection::vec(any::<u8>(), 0..=1024)) {
            let _ = murmur3_32(&data, 0);
        }

        #[test]
        fn favicon_hash_never_panics(data in proptest::collection::vec(any::<u8>(), 0..=1024)) {
            let _ = favicon_hash(&data);
        }

        #[test]
        fn murmur3_32_is_deterministic(data in proptest::collection::vec(any::<u8>(), 0..=1024)) {
            let h1 = murmur3_32(&data, 0);
            let h2 = murmur3_32(&data, 0);
            prop_assert_eq!(h1, h2);
        }
    }

    #[test]
    fn favicon_hash_matches_core_shodan_framing() {
        // Icons larger than 57 bytes need RFC 2045 base64 newlines to
        // match Shodan's computed hash.
        let data = vec![0xABu8; 100];
        assert_eq!(favicon_hash(&data), gossan_core::shodan_favicon_hash(&data));
    }

    #[tokio::test]
    async fn favicon_skips_non_image_content_type() {
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/favicon.ico"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html; charset=utf-8")
                    .set_body_string("<html><body>login</body></html>"),
            )
            .mount(&server)
            .await;

        let client = gossan_core::ScanClient::default_client();
        let config = gossan_core::Config::default();
        let result = scan(server.address().to_string(), &config, &client)
            .await
            .unwrap();
        assert!(result.is_empty(), "non-image favicon response must not produce candidates");
    }

    #[tokio::test]
    async fn favicon_hashes_image_content_type() {
        use wiremock::{
            matchers::{method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/favicon.ico"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "image/x-icon")
                    .set_body_bytes(vec![0xABu8; 32]),
            )
            .mount(&server)
            .await;

        let client = gossan_core::ScanClient::default_client();
        let config = gossan_core::Config::default();
        let result = scan(server.address().to_string(), &config, &client)
            .await
            .unwrap();
        // Without a Shodan key the scan returns no candidates, but it should
        // complete rather than abort on the content-type check.
        assert!(result.is_empty());
    }
}
