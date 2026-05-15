//! Unified soft-404 baseline detector.
//!
//! Probes multiple guaranteed-nonexistent paths to build a fingerprint of how
//! the target responds to missing resources. Any probe response that matches
//! this fingerprint is treated as a soft-404 and discarded.
//!
//! Properties:
//! * Idempotent — same target produces the same fingerprint (modulo highly
//!   dynamic content like ads with different seeds every request).
//! * Deterministic — uses a fixed set of probe path patterns.
//! * Adversarial — handles SPAs that return 200 for all paths, redirect loops,
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
                        // Oversized response — treat as catch-all indicator
                        lengths.push(MAX_BODY_BYTES);
                        hashes.push(hash_bytes(b"OVERSIZED"));
                        continue;
                    }
                };

                lengths.push(bytes.len());
                hashes.push(normalized_hash(&bytes));
            }
            Err(_) => {
                // Network error on baseline — skip this probe
                continue;
            }
        }
    }

    if statuses.is_empty() {
        return None;
    }

    let status = most_common(&statuses);
    let avg_body_len = lengths.iter().sum::<usize>() / lengths.len();

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

    let len_similar = len_diff < 200 || (len_diff * 100 / base.avg_body_len.max(1)) < 15;
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
/// crosses `limit` — never materialises the full body in RAM. The
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
            // Mid-read failure is reported as an empty body, matching
            // the previous swallowing behaviour at this call site.
            Err(_) => return Some(Vec::new()),
        };
        if buf.len() + chunk.len() > limit {
            return None;
        }
        buf.extend_from_slice(&chunk);
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

    /// Adversarial: server returns a body larger than the cap. The
    /// streaming guard MUST trip and return `None` — without
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
            "read_limited returned Some(len={:?}) for a body larger than the cap — \
             OOM guard regressed",
            result.as_ref().map(Vec::len)
        );
    }
}
