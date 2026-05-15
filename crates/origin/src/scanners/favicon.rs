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
/// Shodan's favicon hash is: `mmh3(base64(favicon_bytes))` using the standard
/// MurmurHash3 32-bit variant with seed 0.
fn favicon_hash(data: &[u8]) -> i32 {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    murmur3_32(encoded.as_bytes(), 0) as i32
}

/// MurmurHash3 32-bit implementation (seed 0, standard constants).
/// Matches the Python `mmh3.hash()` used by Shodan.
fn murmur3_32(data: &[u8], seed: u32) -> u32 {
    let c1: u32 = 0xcc9e_2d51;
    let c2: u32 = 0x1b87_3593;
    let len = data.len() as u32;
    let mut h1 = seed;

    let n_blocks = data.len() / 4;
    for i in 0..n_blocks {
        let offset = i * 4;
        let k1 = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        let k1 = k1.wrapping_mul(c1);
        let k1 = k1.rotate_left(15);
        let k1 = k1.wrapping_mul(c2);

        h1 ^= k1;
        h1 = h1.rotate_left(13);
        h1 = h1.wrapping_mul(5).wrapping_add(0xe654_6b64);
    }

    let tail = &data[n_blocks * 4..];
    let mut k1: u32 = 0;
    match tail.len() {
        3 => {
            k1 ^= u32::from(tail[2]) << 16;
            k1 ^= u32::from(tail[1]) << 8;
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);
            h1 ^= k1;
        }
        2 => {
            k1 ^= u32::from(tail[1]) << 8;
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);
            h1 ^= k1;
        }
        1 => {
            k1 ^= u32::from(tail[0]);
            k1 = k1.wrapping_mul(c1).rotate_left(15).wrapping_mul(c2);
            h1 ^= k1;
        }
        _ => {}
    }

    h1 ^= len;
    h1 ^= h1 >> 16;
    h1 = h1.wrapping_mul(0x85eb_ca6b);
    h1 ^= h1 >> 13;
    h1 = h1.wrapping_mul(0xc2b2_ae35);
    h1 ^= h1 >> 16;

    h1
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
    let limit = config.max_response_size.min(5 * 1024 * 1024).max(1024);

    for path in &paths {
        // Try both HTTPS and HTTP to support the wiremock gap test.
        let mut success = false;
        for scheme in ["https", "http"] {
            let url = format!("{}://{}{}", scheme, domain, path);
            let response = match client.get(&url).await {
                Ok(r) if r.status().is_success() => r,
                _ => continue,
            };

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
            let limit = config.max_response_size.min(10 * 1024 * 1024);
            let body: serde_json::Value = match bounded_json(resp, limit).await {
                Ok(v) => v,
                Err(_) => serde_json::Value::Null,
            };

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
    } else {
        tracing::info!(
            scanner = "favicon",
            hash = hash,
            "favicon hash computed — search Shodan with: http.favicon.hash:{}",
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
            let limit = config.max_response_size.min(10 * 1024 * 1024);
            let json: serde_json::Value = match bounded_json(resp, limit).await {
                Ok(v) => v,
                Err(_) => serde_json::Value::Null,
            };

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
    }

    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
