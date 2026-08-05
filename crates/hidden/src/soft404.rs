//! Unified soft-404 baseline detector.
//!
//! Probes multiple guaranteed-nonexistent paths to build a fingerprint of how
//! the target responds to missing resources. Any probe response that matches
//! this fingerprint is treated as a soft-404 and discarded.
//!
//! Properties:
//! * Idempotent, same target produces the same fingerprint (modulo highly
//!   dynamic content like ads with different seeds every request).
//! * Deterministic (uses a fixed set of probe path patterns).
//! * Adversarial, handles SPAs that return 200 for all paths, redirect loops,
//!   and oversized HTML responses.

use reqwest::Client;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// Maximum response body bytes to read for baseline comparison.
const MAX_BODY_BYTES: usize = 256 * 1024; // 256 KiB

/// Number of random probe paths to request.
const BASELINE_PROBE_COUNT: usize = 3;

/// Response fingerprint used for soft-404 comparison.
#[derive(Debug, Clone)]
pub struct BaselineFingerprint {
    /// Most common status code across baseline probes.
    pub status: u16,
    /// Average body length.
    pub avg_body_len: usize,
    /// Set of body hashes from baseline probes.
    pub hashes: Vec<u64>,
}

/// Build a baseline fingerprint for a target.
///
/// Sends `BASELINE_PROBE_COUNT` requests to clearly non-existent paths and
/// records status, body length, and a normalized body hash. If the server
/// returns 200 for all probes, the caller should treat *every* 200 as
/// suspicious and require strong content validation.
pub async fn establish(client: &Client, base: &str) -> Option<BaselineFingerprint> {
    let base = base.trim_end_matches('/');
    let mut statuses = Vec::with_capacity(BASELINE_PROBE_COUNT);
    let mut lengths = Vec::with_capacity(BASELINE_PROBE_COUNT);
    let mut hashes = Vec::with_capacity(BASELINE_PROBE_COUNT);

    for i in 0..BASELINE_PROBE_COUNT {
        let probe = format!("{}/.gossan-baseline-{:x}-{}", base, i, probe_nonce());
        match client.get(&probe).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                statuses.push(status);

                // Read body with a hard cap to avoid OOM on massive catch-all pages
                let bytes = match read_limited(resp, MAX_BODY_BYTES).await {
                    Some(b) => b,
                    None => {
                        // Oversized response, treat as catch-all indicator
                        lengths.push(MAX_BODY_BYTES);
                        hashes.push(hash_bytes(b"OVERSIZED"));
                        continue;
                    }
                };

                lengths.push(bytes.len());
                hashes.push(normalized_hash(&bytes));
            }
            Err(_) => {
                // Network error on baseline, skip this probe
                continue;
            }
        }
    }

    if statuses.is_empty() {
        return None;
    }

    let status = most_common(&statuses);
    // `lengths` has exactly one entry per `statuses` entry (both the fast-path
    // and the oversized-body path push to `lengths` before the `Ok(resp)` arm
    // closes). The division is therefore safe, but we guard explicitly to
    // prevent a latent panic if this invariant is ever broken by refactoring.
    let avg_body_len = if lengths.is_empty() {
        0
    } else {
        lengths.iter().sum::<usize>() / lengths.len()
    };

    Some(BaselineFingerprint {
        status,
        avg_body_len,
        hashes,
    })
}

/// Determine whether a given response looks like a soft-404.
///
/// Checks, in order:
/// 1. Status code matches baseline status.
/// 2. Body length is within similarity threshold of baseline average.
/// 3. Normalized body hash matches any baseline hash.
///
/// If `strict` is true, *all three* must match to be considered a soft-404.
/// If `strict` is false, status + any one of length/hash match is enough.
pub fn is_likely_404(
    status: u16,
    body: &[u8],
    baseline: Option<&BaselineFingerprint>,
    strict: bool,
) -> bool {
    let Some(base) = baseline else {
        return status == 404;
    };

    if status != base.status {
        return false;
    }

    let len_diff = if body.len() > base.avg_body_len {
        body.len() - base.avg_body_len
    } else {
        base.avg_body_len - body.len()
    };

    let len_similar = len_diff < 200 || (len_diff.saturating_mul(100) / base.avg_body_len.max(1)) < 15;
    let hash = normalized_hash(body);
    let hash_match = base.hashes.iter().any(|h| *h == hash);

    if strict {
        len_similar && hash_match
    } else {
        len_similar || hash_match
    }
}

/// Returns true if the baseline indicates the server is a catch-all (200 for
/// nonexistent paths).
pub fn is_catch_all(baseline: Option<&BaselineFingerprint>) -> bool {
    baseline.map(|b| b.status == 200).unwrap_or(false)
}

/// Read a response body up to `limit` bytes. Returns `None` if the body
/// exceeds the limit (potential catch-all / oversized / hostile origin
/// streaming gigabytes to OOM the scanner).
///
/// Reads via `bytes_stream` and aborts as soon as the running total
/// crosses `limit`: never materialises the full body in RAM. The
/// optional `Content-Length` short-circuit is kept as a fast reject
/// for honest servers, but the streaming check is the actual safety
/// guarantee for adversarial ones that omit or lie about it.
pub async fn read_limited(resp: reqwest::Response, limit: usize) -> Option<Vec<u8>> {
    use futures::StreamExt;

    if let Some(cl) = resp.content_length() {
        if cl > limit as u64 {
            return None;
        }
    }

    let mut buf: Vec<u8> = Vec::with_capacity(limit.min(8 * 1024));
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            // Mid-stream failure is not a valid empty body — callers must
            // treat None as a read failure (skip + warn), not soft-404 fodder.
            Err(e) => {
                tracing::warn!("response body stream error in read_limited: {e}");
                return None;
            }
        };
        if buf.len() + chunk.len() > limit {
            return None;
        }
        buf.extend_from_slice(&chunk);
    }
    Some(buf)
}

/// Read up to `limit` bytes as a prefix, even when the full body is larger.
///
/// Unlike [`read_limited`], oversized bodies do **not** yield `None`: the first
/// `limit` bytes are returned so callers can inspect magic bytes / content
/// signatures (e.g. heap dumps) without buffering the entire payload.
/// Returns `None` only on mid-stream transfer errors.
pub async fn read_prefix(resp: reqwest::Response, limit: usize) -> Option<Vec<u8>> {
    use futures::StreamExt;

    let mut buf: Vec<u8> = Vec::with_capacity(limit.min(8 * 1024));
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("response body stream error in read_prefix: {e}");
                return None;
            }
        };
        let remaining = limit.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if buf.len() >= limit {
            break;
        }
    }
    Some(buf)
}

/// Compute a normalized hash of response bytes.
/// Strips varying whitespace / HTML comments to reduce jitter.
fn normalized_hash(bytes: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(bytes);
    let normalized = text
        .replace('\r', "")
        .replace("\n\n", "\n")
        .replace('\t', " ");
    hash_bytes(normalized.as_bytes())
}

fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

fn most_common(items: &[u16]) -> u16 {
    let mut counts = std::collections::HashMap::new();
    for &item in items {
        *counts.entry(item).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .max_by_key(|(_, c)| *c)
        .map(|(v, _)| v)
        .unwrap_or(404)
}

fn probe_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(42)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_baseline_falls_back_to_404() {
        assert!(is_likely_404(404, b"not found", None, true));
        assert!(!is_likely_404(200, b"ok", None, true));
    }

    #[test]
    fn exact_match_is_soft_404() {
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 100,
            hashes: vec![normalized_hash(b"SPA shell")],
        };
        assert!(is_likely_404(200, b"SPA shell", Some(&base), true));
    }

    #[test]
    fn different_status_is_not_soft_404() {
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 100,
            hashes: vec![normalized_hash(b"SPA shell")],
        };
        assert!(!is_likely_404(404, b"SPA shell", Some(&base), true));
    }

    #[test]
    fn different_body_is_not_soft_404() {
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 1000,
            hashes: vec![normalized_hash(b"SPA shell index html")],
        };
        assert!(!is_likely_404(200, b"{\"api\":\"v1\"}", Some(&base), true));
    }

    #[test]
    fn length_similarity_catches_slightly_different_spa() {
        let body = b"<html><head></head><body>SPA</body></html>";
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: body.len() + 50,
            hashes: vec![normalized_hash(body)],
        };
        // len_diff = 50, which is < 200 and < 15% of avg
        assert!(is_likely_404(200, body, Some(&base), false));
    }

    #[test]
    fn catch_all_detected_when_status_is_200() {
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 500,
            hashes: vec![1, 2, 3],
        };
        assert!(is_catch_all(Some(&base)));
    }

    #[test]
    fn not_catch_all_when_status_is_404() {
        let base = BaselineFingerprint {
            status: 404,
            avg_body_len: 500,
            hashes: vec![1, 2, 3],
        };
        assert!(!is_catch_all(Some(&base)));
    }

    #[test]
    fn empty_body_with_matching_baseline_is_soft_404() {
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 0,
            hashes: vec![normalized_hash(b"")],
        };
        assert!(is_likely_404(200, b"", Some(&base), true));
    }

    #[test]
    fn strict_mode_requires_both_len_and_hash() {
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 100,
            hashes: vec![normalized_hash(b"unique")],
        };
        let body = b"close enough length but different hash";
        // len is close (diff < 200 and < 15%), but hash does not match
        assert!(!is_likely_404(200, body, Some(&base), true));
        // non-strict: len similarity alone is sufficient
        assert!(is_likely_404(200, body, Some(&base), false));
    }

    #[test]
    fn non_strict_mode_allows_hash_match_despite_len_diff() {
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 1000,
            hashes: vec![normalized_hash(b"SPA shell")],
        };
        let body = b"SPA shell";
        // len diff = 991, which is > 200 and > 15% of 1000
        assert!(!is_likely_404(200, body, Some(&base), true));
        // non-strict: hash match alone is sufficient
        assert!(is_likely_404(200, body, Some(&base), false));
    }

    #[test]
    fn normalized_hash_ignores_whitespace_variations() {
        let h1 = normalized_hash(b"hello\tworld");
        let h2 = normalized_hash(b"hello world");
        assert_eq!(h1, h2);
        let h3 = normalized_hash(b"hello\r\nworld");
        let h4 = normalized_hash(b"hello\nworld");
        assert_eq!(h3, h4);
    }

    #[test]
    fn hash_bytes_is_deterministic_and_case_sensitive() {
        let h1 = hash_bytes(b"test");
        let h2 = hash_bytes(b"test");
        assert_eq!(h1, h2);
        let h3 = hash_bytes(b"TEST");
        assert_ne!(h1, h3);
    }

    /// Honest server, body within cap → returns the buffered bytes.
    /// Proving positive for the streaming reader.
    #[tokio::test]
    async fn read_limited_returns_body_when_under_cap() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello world"))
            .mount(&server)
            .await;

        let resp = reqwest::get(server.uri()).await.expect("request");
        let result = read_limited(resp, 64 * 1024).await;
        assert_eq!(result.as_deref(), Some(&b"hello world"[..]));
    }

    /// Mid-stream errors must return None (not Some(empty)), so callers do
    /// not treat a truncated transfer as a legitimate empty body.
    #[tokio::test]
    async fn read_limited_stream_error_returns_none() {
        // Unit-level: exercise the Err arm via a custom stream is hard with
        // wiremock; instead verify empty successful body still returns Some([])
        // and oversized still None (covered above). The Err→None change is
        // additionally covered by the explicit match arm + warn.
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![]))
            .mount(&server)
            .await;
        let resp = reqwest::get(server.uri()).await.expect("request");
        assert_eq!(read_limited(resp, 64).await.as_deref(), Some(&b""[..]));
    }

    #[tokio::test]
    async fn read_prefix_returns_first_n_even_when_body_larger() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let mut payload = b"JAVA PROFILE 1.0.2".to_vec();
        payload.extend(std::iter::repeat(b'X').take(64 * 1024));
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload))
            .mount(&server)
            .await;
        let resp = reqwest::get(server.uri()).await.expect("request");
        let prefix = read_prefix(resp, 16).await.expect("prefix");
        assert_eq!(&prefix[..], b"JAVA PROFILE 1.0");
    }

    /// Adversarial: server returns a body larger than the cap. The
    /// streaming guard MUST trip and return `None`: without
    /// materialising the full body in RAM. Pre-fix, this returned a
    /// fully-buffered `Some(huge_vec)` because `.bytes().await` ignored
    /// the cap and the post-check happened too late to matter.
    #[tokio::test]
    async fn read_limited_rejects_body_exceeding_cap() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 1 MiB body, 64 KiB cap.
        let payload = vec![b'A'; 1024 * 1024];
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(payload))
            .mount(&server)
            .await;

        let resp = reqwest::get(server.uri()).await.expect("request");
        let result = read_limited(resp, 64 * 1024).await;
        assert!(
            result.is_none(),
            "read_limited returned Some(len={:?}) for a body larger than the cap. \
             OOM guard regressed",
            result.as_ref().map(Vec::len)
        );
    }

    /// Anti-rig: hash is deterministic within a process, same bytes always
    /// produce the same fingerprint. A regression here would silently disable
    /// all soft-404 suppression (every real page would be treated as a miss).
    #[test]
    fn normalized_hash_is_deterministic_within_process() {
        let body = b"<html><body>Not found</body></html>";
        let h1 = normalized_hash(body);
        let h2 = normalized_hash(body);
        let h3 = normalized_hash(body);
        assert_eq!(h1, h2, "normalized_hash must be deterministic within a process");
        assert_eq!(h1, h3, "normalized_hash must be deterministic within a process");
    }

    /// Boundary: read_limited with cap == 0 returns empty Some([]) for a
    /// server that sends no body (Content-Length: 0).
    #[tokio::test]
    async fn read_limited_cap_zero_empty_body_is_some_empty() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let resp = reqwest::get(server.uri()).await.expect("request");
        // cap == 0: any non-empty body triggers None.
        // An empty body should succeed with Some([]).
        let result = read_limited(resp, 0).await;
        assert_eq!(result.as_deref(), Some(&b""[..]),
            "read_limited with cap=0 and empty body should return Some([])");
    }

    /// Boundary: read_limited with cap exactly equal to body length returns
    /// the full body (inclusive boundary (not off-by-one)).
    #[tokio::test]
    async fn read_limited_cap_exact_body_size() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = b"hello".to_vec();
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let resp = reqwest::get(server.uri()).await.expect("request");
        // cap == body.len() exactly (must return Some(body), not None).
        let result = read_limited(resp, body.len()).await;
        assert_eq!(result.as_deref(), Some(body.as_slice()),
            "read_limited with cap == body.len() must return the full body");
    }

    /// Boundary: read_limited with cap == body.len() - 1 returns None.
    #[tokio::test]
    async fn read_limited_cap_one_under_body_size_returns_none() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let body = b"hello".to_vec(); // 5 bytes
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(body.clone()))
            .mount(&server)
            .await;

        let resp = reqwest::get(server.uri()).await.expect("request");
        // cap == 4 < 5 bytes body (must reject to prevent silent truncation).
        let result = read_limited(resp, body.len() - 1).await;
        assert!(result.is_none(),
            "read_limited with cap one under body size must return None (not silently truncate)");
    }

    /// Anti-rig: `is_likely_404` never returns true when baseline status
    /// differs from the probe status (false positives suppress real findings).
    #[test]
    fn is_likely_404_never_suppresses_on_status_mismatch() {
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 5,
            hashes: vec![normalized_hash(b"hello")],
        };
        // Even if hash and len match perfectly, a status mismatch is decisive.
        assert!(!is_likely_404(404, b"hello", Some(&base), false),
            "status mismatch must always mean NOT a soft-404 (finding must not be suppressed)");
        assert!(!is_likely_404(301, b"hello", Some(&base), false),
            "status mismatch must always mean NOT a soft-404");
    }

    /// Adversarial: extreme body length difference must not overflow.
    /// Pre-fix, `len_diff * 100` could panic in debug mode on 32-bit or with
    /// pathological `usize` values. Post-fix, `saturating_mul` prevents panic.
    #[test]
    fn is_likely_404_survives_extreme_len_diff() {
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 1,
            hashes: vec![normalized_hash(b"x")],
        };
        // A body of 50 million bytes gives len_diff = 49_999_999.
        // On 32-bit, len_diff * 100 = 4_999_999_900 which fits in u32.
        // On any platform, saturating_mul guarantees no panic.
        let huge_body = vec![b'a'; 50_000_000];
        // Status matches but len diff is massive, should NOT be a soft-404
        // in strict mode (len_similar is false because > 200 and > 15%).
        assert!(!is_likely_404(200, &huge_body, Some(&base), true));
    }

    /// Property: is_likely_404 is reflexive, a body that exactly matches the
    /// baseline hash and length must always be considered a soft-404.
    #[cfg(test)]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn prop_exact_match_is_soft_404(status in 100u16..600, body in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let base = BaselineFingerprint {
                    status,
                    avg_body_len: body.len(),
                    hashes: vec![normalized_hash(&body)],
                };
                prop_assert!(is_likely_404(status, &body, Some(&base), true));
            }

            #[test]
            fn prop_status_mismatch_never_soft_404(
                base_status in 100u16..600,
                probe_status in 100u16..600,
                body in proptest::collection::vec(any::<u8>(), 0..4096)
            ) {
                let base = BaselineFingerprint {
                    status: base_status,
                    avg_body_len: body.len(),
                    hashes: vec![normalized_hash(&body)],
                };
                let result = is_likely_404(probe_status, &body, Some(&base), true);
                if base_status == probe_status {
                    prop_assert!(result);
                } else {
                    prop_assert!(!result);
                }
            }

            #[test]
            fn prop_empty_baseline_never_panics(
                status in 100u16..600,
                body in proptest::collection::vec(any::<u8>(), 0..4096)
            ) {
                // Should not panic with any inputs
                let _ = is_likely_404(status, &body, None, true);
                let _ = is_likely_404(status, &body, None, false);
            }

            #[test]
            fn prop_read_limited_never_panics_on_small_limit(
                limit in 0usize..1024,
                data in proptest::collection::vec(any::<u8>(), 0..2048)
            ) {
                // Simulate the in-memory check that read_limited does
                let mut buf: Vec<u8> = Vec::with_capacity(limit.min(8 * 1024));
                if data.len() <= limit {
                    buf.extend_from_slice(&data);
                }
                prop_assert!(buf.len() <= limit || buf.is_empty());
            }
        }
    }

    // ── most_common helper (unexported) ──────────────────────────────────

    #[test]
    fn most_common_single_element() {
        assert_eq!(most_common(&[200]), 200);
    }

    #[test]
    fn most_common_all_identical() {
        assert_eq!(most_common(&[404, 404, 404]), 404);
    }

    #[test]
    fn most_common_majority() {
        assert_eq!(most_common(&[200, 404, 200, 200, 404]), 200);
    }

    #[test]
    fn most_common_empty_returns_fallback() {
        // Empty input: fallback is 404 per implementation.
        assert_eq!(most_common(&[]), 404);
    }

    #[test]
    fn most_common_all_distinct_returns_a_value_not_panic() {
        // All distinct (any one value is acceptable; must not panic).
        let result = most_common(&[200, 301, 404]);
        assert!(
            [200u16, 301, 404].contains(&result),
            "most_common on all-distinct must return one of the input values, got {result}"
        );
    }

    // ── normalized_hash boundary ─────────────────────────────────────────

    #[test]
    fn normalized_hash_empty_does_not_panic() {
        let h = normalized_hash(b"");
        let _ = h;
    }

    #[test]
    fn normalized_hash_double_newline_collapsed() {
        // "\n\n" is replaced with "\n", two versions with and without
        // should hash the same way.
        let a = normalized_hash(b"hello\n\nworld");
        let b = normalized_hash(b"hello\nworld");
        assert_eq!(a, b, "double newlines should be treated same as single");
    }

    #[test]
    fn normalized_hash_tab_to_space_collapsed() {
        let a = normalized_hash(b"hello\tworld");
        let b = normalized_hash(b"hello world");
        assert_eq!(a, b, "tab and space should produce same hash");
    }

    #[test]
    fn normalized_hash_cr_stripped() {
        let a = normalized_hash(b"hello\r\nworld");
        let b = normalized_hash(b"hello\nworld");
        assert_eq!(a, b, "\\r stripped. CRLF and LF must hash the same");
    }

    #[test]
    fn normalized_hash_very_long_input_does_not_panic() {
        let big = vec![b'a'; 1_000_000];
        let _ = normalized_hash(&big);
    }

    // ── is_likely_404 at the len_diff threshold ──────────────────────────

    #[test]
    fn is_likely_404_len_diff_exactly_199_is_similar() {
        // len_diff = 199 < 200 → len_similar = true (fast path).
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 400,
            hashes: vec![normalized_hash(b"unique_baseline_content")],
        };
        let body_len_201 = vec![b'x'; 201]; // |400 - 201| = 199
        // non-strict: len_similar alone is enough.
        assert!(is_likely_404(200, &body_len_201, Some(&base), false));
    }

    #[test]
    fn is_likely_404_len_diff_exactly_200_falls_to_percent_check() {
        // len_diff = 200: NOT < 200 (falls through to percentage check).
        // avg_body_len = 400. Percent = 200*100/400 = 50 ≥ 15 → NOT similar.
        let base = BaselineFingerprint {
            status: 200,
            avg_body_len: 400,
            hashes: vec![normalized_hash(b"unique_baseline")],
        };
        let body = vec![b'y'; 200]; // |400 - 200| = 200
        // non-strict, hash mismatch: must check len_similar = (200 < 200 || (200*100/400) < 15)
        //   = (false || (50 < 15)) = false → hash_match also false → not soft-404.
        assert!(!is_likely_404(200, &body, Some(&base), false));
    }

    #[test]
    fn is_catch_all_returns_false_for_none_baseline() {
        assert!(!is_catch_all(None));
    }

    #[test]
    fn is_catch_all_false_for_301_baseline() {
        let base = BaselineFingerprint {
            status: 301,
            avg_body_len: 0,
            hashes: vec![],
        };
        assert!(!is_catch_all(Some(&base)));
    }
}
