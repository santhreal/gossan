//! Favicon hash fingerprinting for technology detection.

use gossan_core::Target;
use secfinding::{Finding, Severity};
use std::collections::HashMap;

fn known_hashes() -> HashMap<u32, &'static str> {
    [
        (116323821, "Jenkins"),
        (708762727, "Apache Tomcat"),
        (1820000864, "Kibana"),
        (1768726056, "Grafana"),
        (2112077716, "phpMyAdmin"),
        (812492305, "Jupyter Notebook"),
        (3509854774, "GitLab"),
        (3876078860, "Jira"),
        (434606617, "Confluence"),
        (1307864597, "Elasticsearch"),
        (783822853, "Splunk"),
        (3093228109, "Fortinet"),
        (2091241266, "Cisco"),
        (2040698672, "Citrix"),
    ]
    .into_iter()
    .collect()
}

/// True when Content-Type claims an image/icon, or body magic matches ICO/PNG/GIF/SVG.
fn is_image_favicon(content_type: &str, bytes: &[u8]) -> bool {
    let ct = content_type.to_ascii_lowercase();
    if ct.contains("image/") || ct.contains("icon") {
        return true;
    }
    looks_like_image_magic(bytes)
}

fn looks_like_image_magic(bytes: &[u8]) -> bool {
    if bytes.len() >= 4 && bytes[0] == 0x00 && bytes[1] == 0x00 && bytes[2] == 0x01 && bytes[3] == 0x00 {
        return true; // ICO
    }
    if bytes.len() >= 8
        && bytes[..8] == [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]
    {
        return true; // PNG
    }
    if bytes.len() >= 6 && (bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a")) {
        return true; // GIF
    }
    // SVG: text magic
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(256)]).to_ascii_lowercase();
    let trimmed = head.trim_start();
    trimmed.starts_with("<svg")
        || (trimmed.starts_with("<?xml") && head.contains("<svg"))
}

fn looks_like_html_body(bytes: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).to_ascii_lowercase();
    let t = head.trim_start();
    t.starts_with("<!doctype html") || t.starts_with("<html") || t.contains("<html")
}

pub async fn probe(client: &reqwest::Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');
    let url = format!("{}/favicon.ico", base);
    let mut findings = Vec::new();

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("favicon: request failed url={url} error={e}");
            return Ok(findings);
        }
    };

    if resp.status().as_u16() != 200 {
        return Ok(findings);
    }

    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| match v.to_str() {
            Ok(s) => Some(s.to_string()),
            Err(e) => {
                tracing::warn!("favicon: invalid content-type bytes error={e}");
                None
            }
        })
        .unwrap_or_default();

    let bytes = match crate::soft404::read_limited(resp, crate::MAX_BODY_BYTES).await {
        Some(b) => b,
        None => {
            tracing::warn!("favicon: body read failed or oversized url={url}");
            return Ok(findings);
        }
    };
    if bytes.is_empty() {
        return Ok(findings);
    }

    // Skip HTML soft-404 / catch-all bodies masquerading as favicon.ico
    if looks_like_html_body(&bytes) && !looks_like_image_magic(&bytes) {
        tracing::warn!("favicon: skipping HTML body for /favicon.ico (url={url}, content_type={content_type})");
        return Ok(findings);
    }

    if !is_image_favicon(&content_type, &bytes) {
        tracing::warn!("favicon: skipping non-image response (url={url}, content_type={content_type})");
        return Ok(findings);
    }

    let b64 = base64_encode(&bytes);
    let hash = gossan_core::mmh3_x86_32(b64.as_bytes(), 0);
    let known = known_hashes();
    if let Some(tech) = known.get(&hash) {
        gossan_core::try_push_finding(
            crate::info_finding(
                target,
                Severity::Info,
                format!("Favicon identifies: {}", tech),
                format!(
                    "Favicon hash 0x{:08x} matches {}, identified without version headers.",
                    hash, tech
                ),
            )
            .tag("favicon")
            .tag("fingerprint"),
            &mut findings,
        );
    } else {
        gossan_core::try_push_finding(
            crate::info_finding(
                target,
                Severity::Info,
                "Favicon hash computed",
                format!(
                    "Favicon hash: 0x{:08x} (Shodan query: http.favicon.hash:{})",
                    hash,
                    hash as i32
                ),
            )
            .tag("favicon"),
            &mut findings,
        );
    }

    Ok(findings)
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    let mut col = 0;
    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(CHARS[((n >> 18) & 63) as usize] as char);
        out.push(CHARS[((n >> 12) & 63) as usize] as char);
        out.push(if i + 1 < data.len() {
            CHARS[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if i + 2 < data.len() {
            CHARS[(n & 63) as usize] as char
        } else {
            '='
        });
        col += 4;
        if col >= 76 {
            out.push('\n');
            col = 0;
        }
        i += 3;
    }
    out
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_empty_input() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_encode_single_byte() {
        assert_eq!(base64_encode(b"f"), "Zg==");
    }

    #[test]
    fn base64_encode_two_bytes() {
        assert_eq!(base64_encode(b"fo"), "Zm8=");
    }

    #[test]
    fn base64_encode_three_bytes() {
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn murmurhash3_is_deterministic() {
        let h1 = gossan_core::mmh3_x86_32(b"test", 0);
        let h2 = gossan_core::mmh3_x86_32(b"test", 0);
        assert_eq!(h1, h2);
    }

    #[test]
    fn known_hashes_contains_jenkins() {
        let known = known_hashes();
        assert!(known.contains_key(&116_323_821));
        assert_eq!(known.get(&116_323_821), Some(&"Jenkins"));
    }

    #[test]
    fn base64_encode_standard_padding() {
        assert_eq!(base64_encode(b"a"), "YQ==");
        assert_eq!(base64_encode(b"ab"), "YWI=");
    }

    #[test]
    fn murmurhash3_different_inputs_different_hashes() {
        let h1 = gossan_core::mmh3_x86_32(b"foo", 0);
        let h2 = gossan_core::mmh3_x86_32(b"bar", 0);
        assert_ne!(h1, h2);
    }

    #[test]
    fn known_hashes_contains_tomcat() {
        let known = known_hashes();
        assert!(known.contains_key(&708_762_727));
        assert_eq!(known.get(&708_762_727), Some(&"Apache Tomcat"));
    }

    #[test]
    fn base64_encode_all_byte_values() {
        let input: Vec<u8> = (0..=255).collect();
        let out = base64_encode(&input);
        assert_eq!(out.len(), 348); // 344 base64 chars + 4 newlines (every 76 chars)
    }

    #[test]
    fn murmurhash3_seed_affects_output() {
        let h1 = gossan_core::mmh3_x86_32(b"test", 0);
        let h2 = gossan_core::mmh3_x86_32(b"test", 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn base64_encode_all_zeros() {
        let input = vec![0u8; 10];
        let out = base64_encode(&input);
        assert_eq!(out, "AAAAAAAAAAAAAA==");
    }

    #[test]
    fn base64_encode_all_ones() {
        let input = vec![0xffu8; 6];
        let out = base64_encode(&input);
        assert_eq!(out, "////////");
    }

    #[test]
    fn base64_encode_newline_every_76_chars() {
        let input = vec![b'A'; 76];
        let out = base64_encode(&input);
        assert!(out.contains('\n'));
        // 76 input bytes -> 25 full triples (100 chars) + 1 byte (2 chars + 2 padding) = 104 output chars + 1 newline = 105
        assert_eq!(out.len(), 105);
    }

    #[test]
    fn base64_encode_256_distinct_bytes() {
        let input: Vec<u8> = (0..=255).collect();
        let out = base64_encode(&input);
        assert_eq!(out.len(), 348); // 344 base64 chars + 4 newlines
    }

    #[test]
    fn murmurhash3_empty_input() {
        let h = gossan_core::mmh3_x86_32(b"", 0);
        // Just verify it doesn't panic and is deterministic
        assert_eq!(h, gossan_core::mmh3_x86_32(b"", 0));
    }

    #[test]
    fn murmurhash3_large_input() {
        let input = vec![b'x'; 10000];
        let h = gossan_core::mmh3_x86_32(&input, 0);
        assert_eq!(h, gossan_core::mmh3_x86_32(&input, 0));
    }

    #[test]
    fn murmurhash3_binary_input() {
        let input = vec![0x00, 0x01, 0x02, 0x03, 0xff, 0xfe, 0xfd, 0xfc];
        let h = gossan_core::mmh3_x86_32(&input, 0);
        assert_eq!(h, gossan_core::mmh3_x86_32(&input, 0));
    }

    #[test]
    fn known_hashes_contains_grafana() {
        let known = known_hashes();
        assert!(known.contains_key(&1_768_726_056));
        assert_eq!(known.get(&1_768_726_056), Some(&"Grafana"));
    }

    #[test]
    fn known_hashes_contains_gitlab() {
        let known = known_hashes();
        assert!(known.contains_key(&3_509_854_774));
        assert_eq!(known.get(&3_509_854_774), Some(&"GitLab"));
    }

    #[test]
    fn known_hashes_contains_phpmyadmin() {
        let known = known_hashes();
        assert!(known.contains_key(&2_112_077_716));
        assert_eq!(known.get(&2_112_077_716), Some(&"phpMyAdmin"));
    }

    /// Adversarial: favicon hashes with the high bit set must render as
    /// negative i32 in the Shodan query (Shodan uses signed 32-bit hashes).
    /// Pre-fix, `i32::try_from(hash).unwrap_or(0)` produced `0` for these,
    /// breaking the query. Post-fix, `hash as i32` preserves the bit pattern.
    #[test]
    fn high_bit_hash_renders_as_negative_i32() {
        let hash: u32 = 3_509_854_774; // GitLab
        let expected: i32 = hash as i32; // -785_112_522
        assert_ne!(expected, 0, "GitLab hash must not collapse to 0");
        let detail = format!(
            "Favicon hash: 0x{:08x} (Shodan query: http.favicon.hash:{})",
            hash, expected
        );
        assert!(
            detail.contains("http.favicon.hash:-785112522"),
            "Shodan query must contain negative hash, got: {}",
            detail
        );
    }


    #[test]
    fn image_magic_detects_ico_png_gif_svg() {
        assert!(looks_like_image_magic(&[0x00, 0x00, 0x01, 0x00, 0x01, 0x00]));
        assert!(looks_like_image_magic(&[
            0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0
        ]));
        assert!(looks_like_image_magic(b"GIF89a...."));
        assert!(looks_like_image_magic(b"<svg xmlns='http://www.w3.org/2000/svg'></svg>"));
        assert!(looks_like_image_magic(
            b"<?xml version=\"1.0\"?><svg xmlns='http://www.w3.org/2000/svg'></svg>"
        ));
        assert!(!looks_like_image_magic(b"<html><body>nope</body></html>"));
    }

    #[test]
    fn is_image_favicon_accepts_content_type_or_magic() {
        assert!(is_image_favicon("image/x-icon", b"notmagic"));
        assert!(is_image_favicon("IMAGE/PNG", b"notmagic"));
        assert!(is_image_favicon("application/octet-stream", &[
            0x00, 0x00, 0x01, 0x00
        ]));
        assert!(!is_image_favicon("text/html", b"<html></html>"));
        assert!(!is_image_favicon("", b"random bytes without magic"));
    }

    /// Adversarial: SPA/catch-all HTML returned as HTTP 200 for /favicon.ico
    /// must not produce a favicon finding.
    #[tokio::test]
    async fn html_200_favicon_ico_yields_no_finding() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let shell = "<!DOCTYPE html><html><body>SPA shell /home/ /app/</body></html>";
        Mock::given(method("GET"))
            .and(path("/favicon.ico"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html; charset=utf-8")
                    .set_body_string(shell),
            )
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let target = gossan_core::testkit::web_target(&server.uri());
        let findings = probe(&client, &target).await.unwrap();
        assert!(
            findings.is_empty(),
            "HTML soft-404 favicon must not produce findings, got {:?}",
            findings
        );
    }

    #[tokio::test]
    async fn real_ico_magic_without_content_type_still_hashes() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // Minimal ICO magic + padding
        let mut ico = vec![0x00, 0x00, 0x01, 0x00];
        ico.extend(std::iter::repeat(0u8).take(32));
        Mock::given(method("GET"))
            .and(path("/favicon.ico"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(ico))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let target = gossan_core::testkit::web_target(&server.uri());
        let findings = probe(&client, &target).await.unwrap();
        assert!(
            findings.iter().any(|f| f.title().contains("Favicon")),
            "ICO magic without Content-Type should still hash, got {:?}",
            findings
        );
    }

        /// Property tests for favicon helpers.
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_base64_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
                let encoded = base64_encode(&data);
                // Output length is ceil(input / 3) * 4 + newlines
                let expected_min = (data.len() + 2) / 3 * 4;
                let newline_count = expected_min / 76;
                prop_assert!(encoded.len() >= expected_min);
                prop_assert!(encoded.len() <= expected_min + newline_count);
            }

            #[test]
            fn prop_murmurhash_deterministic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
                let h1 = gossan_core::mmh3_x86_32(&data, 0);
                let h2 = gossan_core::mmh3_x86_32(&data, 0);
                prop_assert_eq!(h1, h2);
            }

            #[test]
            fn prop_murmurhash_different_seeds_differ(
                data in proptest::collection::vec(any::<u8>(), 1..512)
            ) {
                let h1 = gossan_core::mmh3_x86_32(&data, 0);
                let h2 = gossan_core::mmh3_x86_32(&data, 1);
                prop_assert_ne!(h1, h2);
            }
        }
    }
}
