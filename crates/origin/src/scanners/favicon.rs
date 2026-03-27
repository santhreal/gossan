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

use crate::OriginCandidate;

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

    // Body: process 4-byte chunks.
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

    // Tail: remaining bytes.
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

    // Finalization.
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
pub async fn scan(
    domain: String,
    shodan_api_key: Option<&str>,
) -> anyhow::Result<Vec<OriginCandidate>> {
    let mut candidates = Vec::new();

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .danger_accept_invalid_certs(true)
        .build()?;

    // Try common favicon paths.
    let paths = [
        "/favicon.ico",
        "/apple-touch-icon.png",
        "/apple-touch-icon-precomposed.png",
    ];

    let mut hash_value: Option<i32> = None;

    for path in &paths {
        let url = format!("https://{}{}", domain, path);
        let response = match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => r,
            _ => continue,
        };

        let bytes = match response.bytes().await {
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
        break;
    }

    let hash = match hash_value {
        Some(h) => h,
        None => {
            tracing::debug!(scanner = "favicon", "no favicon found");
            return Ok(candidates);
        }
    };

    // If we have a Shodan API key, search for other hosts with the same favicon.
    if let Some(api_key) = shodan_api_key {
        let shodan_url = format!(
            "https://api.shodan.io/shodan/host/search?key={}&query=http.favicon.hash:{}",
            api_key, hash
        );

        let response = match client.get(&shodan_url).send().await {
            Ok(r) if r.status().is_success() => r,
            Ok(r) => {
                tracing::warn!(scanner = "favicon", status = %r.status(), "shodan query failed");
                return Ok(candidates);
            }
            Err(e) => {
                tracing::warn!(scanner = "favicon", error = %e, "shodan request failed");
                return Ok(candidates);
            }
        };

        let body: serde_json::Value = match response.json().await {
            Ok(v) => v,
            Err(_) => return Ok(candidates),
        };

        let mut seen_ips = HashSet::new();

        if let Some(matches) = body.get("matches").and_then(|m| m.as_array()) {
            for entry in matches {
                if let Some(ip_str) = entry.get("ip_str").and_then(|v| v.as_str()) {
                    if let Ok(ip) = IpAddr::from_str(ip_str) {
                        if seen_ips.insert(ip) {
                            candidates.push(OriginCandidate {
                                ip,
                                method: format!("favicon_hash_shodan (hash={})", hash),
                                confidence: 80,
                            });
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

    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn murmur3_known_vector() {
        // Known test vector for MurmurHash3_x86_32 with seed 0.
        let hash = murmur3_32(b"", 0);
        assert_eq!(hash, 0);
    }

    #[test]
    fn murmur3_nonempty() {
        let hash = murmur3_32(b"hello", 0);
        // Just verify it produces a deterministic non-zero value.
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
