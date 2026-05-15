//! Active origin validation — host-header swap and 404 fingerprinting.
//!
//! Every candidate IP discovered by passive/heuristic scanners is validated
//! by opening a direct connection with the original `Host` header and
//! comparing the response fingerprint to the CDN-routed baseline.

use crate::util::{bounded_text, is_routable_ip};
use crate::{OriginCandidate, ValidationState};
use gossan_core::{Config, ScanClient};
use std::collections::HashSet;
use std::net::IpAddr;

/// Fingerprint of an HTTP response used for comparison.
#[derive(Debug, Clone)]
struct Fingerprint {
    status: u16,
    body_hash: String,
    title: Option<String>,
    etag: Option<String>,
}

/// Result of comparing a direct-IP response to the CDN baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    /// At least two stable attributes match — origin confirmed.
    Match,
    /// Direct IP serves a generic default page (nginx/Apache welcome).
    FalsePositive,
    /// No meaningful similarity — candidate is speculative at best.
    NoMatch,
}

/// Extract `<title>` from HTML without regex.
fn extract_title(body: &str) -> Option<String> {
    let lower = body.to_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = lower[start..].find("</title>")?;
    Some(body[start..start + end].trim().to_string())
}

/// Compute a stable SHA-256 hex hash of the (possibly truncated) body.
fn body_hash(body: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(body.as_bytes()))
}

/// Fetch the CDN-routed baseline for a domain.
/// Tries HTTPS first, then HTTP.
async fn fetch_baseline(client: &ScanClient, domain: &str, limit: usize) -> Option<Fingerprint> {
    for scheme in ["https", "http"] {
        let url = format!("{}://{}/", scheme, domain);
        if let Ok(resp) = client.get(&url).await {
            let status = resp.status().as_u16();
            let etag = resp
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            if let Ok(body) = bounded_text(resp, limit).await {
                return Some(Fingerprint {
                    status,
                    body_hash: body_hash(&body),
                    title: extract_title(&body),
                    etag,
                });
            }
        }
    }
    None
}

/// Format an authority component for an IP+optional-port. IPv6
/// addresses get bracketed per RFC 3986 so the URL parser doesn't
/// confuse the colon in `::1` with the port separator.
fn ip_authority(ip: IpAddr, port: Option<u16>) -> String {
    let host = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{}]", v6),
    };
    match port {
        Some(p) => format!("{}:{}", host, p),
        None => host,
    }
}

/// Fetch the direct-IP response with the original `Host` header.
async fn fetch_direct(
    client: &ScanClient,
    domain: &str,
    ip: IpAddr,
    port: Option<u16>,
    limit: usize,
) -> Option<Fingerprint> {
    let authority = ip_authority(ip, port);
    for scheme in ["https", "http"] {
        let url = format!("{}://{}/", scheme, authority);
        let req = client
            .inner()
            .get(&url)
            .header("Host", domain)
            .build()
            .ok()?;
        if let Ok(resp) = client.execute(req).await {
            let status = resp.status().as_u16();
            let etag = resp
                .headers()
                .get("etag")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            if let Ok(body) = bounded_text(resp, limit).await {
                return Some(Fingerprint {
                    status,
                    body_hash: body_hash(&body),
                    title: extract_title(&body),
                    etag,
                });
            }
        }
    }
    None
}

/// Compare baseline and direct fingerprints.
fn compare(baseline: &Fingerprint, direct: &Fingerprint) -> Comparison {
    // If the direct IP returns a generic default page, it's a false positive.
    if direct.status == 200 {
        // Common default page markers.
        let markers = [
            "Welcome to nginx",
            "It works!",
            "Apache2 Ubuntu Default Page",
            "IIS Windows Server",
        ];
        // We don't have the raw body here, but we can infer from title/body hash
        // if the title matches known defaults.
        if let Some(ref title) = direct.title {
            for marker in &markers {
                if title.contains(marker) {
                    // Only reject if the baseline does NOT share this title.
                    if baseline.title.as_ref() != Some(title) {
                        return Comparison::FalsePositive;
                    }
                }
            }
        }
    }

    let mut matches = 0;
    if direct.status == baseline.status {
        matches += 1;
    }
    if direct.body_hash == baseline.body_hash {
        matches += 1;
    }
    if direct.etag.is_some() && direct.etag == baseline.etag {
        matches += 1;
    }
    if direct.title.is_some() && direct.title == baseline.title {
        matches += 1;
    }

    if matches >= 2 {
        Comparison::Match
    } else {
        Comparison::NoMatch
    }
}

/// Fetch a 404 page fingerprint for the given target authority
/// (`host` or `host:port`, IPv6 already bracketed).
async fn fetch_404(
    client: &ScanClient,
    domain: &str,
    target: &str,
    limit: usize,
) -> Option<(u16, String)> {
    let path = format!("/nonexistent-{}", uuid::Uuid::new_v4());
    // Try HTTPS first
    let https_url = format!("https://{}{}", target, path);
    let req = client
        .inner()
        .get(&https_url)
        .header("Host", domain)
        .build()
        .ok()?;
    if let Ok(resp) = client.execute(req).await {
        let status = resp.status().as_u16();
        if let Ok(body) = bounded_text(resp, limit).await {
            return Some((status, body_hash(&body)));
        }
    }
    // Fall back to HTTP
    let http_url = format!("http://{}{}", target, path);
    let req = client
        .inner()
        .get(&http_url)
        .header("Host", domain)
        .build()
        .ok()?;
    if let Ok(resp) = client.execute(req).await {
        let status = resp.status().as_u16();
        if let Ok(body) = bounded_text(resp, limit).await {
            return Some((status, body_hash(&body)));
        }
    }
    None
}

/// Compare 404 behaviour between CDN and direct IP.
/// Returns `true` if the 404 pages differ (strong origin signal).
async fn fingerprint_404(
    client: &ScanClient,
    domain: &str,
    ip: IpAddr,
    port: Option<u16>,
    limit: usize,
) -> bool {
    let cdn_404 = fetch_404(client, domain, domain, limit).await;
    let direct_404 = fetch_404(client, domain, &ip_authority(ip, port), limit).await;
    match (cdn_404, direct_404) {
        (Some((cdn_status, cdn_hash)), Some((direct_status, direct_hash))) => {
            cdn_status == direct_status && cdn_hash != direct_hash
        }
        _ => false,
    }
}

/// Validate a list of origin candidates.
///
/// Confirmed candidates receive `confidence = 100` and `validated = Confirmed`.
/// Candidates that fail validation keep their original confidence and are marked
/// `Rejected` (consumers may choose to drop them).
pub async fn validate(
    candidates: Vec<OriginCandidate>,
    domain: &str,
    _config: &Config,
    client: &ScanClient,
) -> Vec<OriginCandidate> {
    let limit = _config.max_response_size.min(2 * 1024 * 1024).max(1024);

    let baseline = fetch_baseline(client, domain, limit).await;
    if baseline.is_none() {
        tracing::warn!(domain = %domain, "validator could not fetch baseline");
    }

    let mut validated = Vec::with_capacity(candidates.len());

    for mut candidate in candidates {
        // An explicit port on the candidate signals operator intent —
        // wiremock harnesses bind to ephemeral 127.0.0.1:N, and Censys/
        // Shodan-derived candidates may legitimately point at private
        // ranges in pentest contexts. The unguarded discovery path
        // (no port set) keeps the global-routability gate.
        let allow_non_routable = candidate.port.is_some();
        if !allow_non_routable && !is_routable_ip(candidate.ip) {
            candidate.validated = ValidationState::Rejected;
            validated.push(candidate);
            continue;
        }

        let Some(ref baseline_fp) = baseline else {
            // No baseline — keep speculative.
            validated.push(candidate);
            continue;
        };

        let Some(direct_fp) =
            fetch_direct(client, domain, candidate.ip, candidate.port, limit).await
        else {
            validated.push(candidate);
            continue;
        };

        match compare(baseline_fp, &direct_fp) {
            Comparison::Match => {
                candidate.confidence = 100;
                candidate.validated = ValidationState::Confirmed;
                candidate.method = "validated_origin".to_string();
                tracing::info!(ip = %candidate.ip, "origin confirmed by host-header swap");
            }
            Comparison::FalsePositive => {
                candidate.validated = ValidationState::Rejected;
                tracing::info!(ip = %candidate.ip, "origin candidate rejected (generic default page)");
            }
            Comparison::NoMatch => {
                // 404 divergence can rescue a speculative candidate.
                if fingerprint_404(client, domain, candidate.ip, candidate.port, limit).await {
                    candidate.confidence = 95;
                    candidate.validated = ValidationState::Confirmed;
                    candidate.method = "validated_origin_404".to_string();
                    tracing::info!(ip = %candidate.ip, "origin confirmed by 404 divergence");
                } else {
                    candidate.validated = ValidationState::Speculative;
                }
            }
        }

        validated.push(candidate);
    }

    // Sort: Confirmed first, then by confidence descending.
    validated.sort_by(|a, b| {
        let a_ord = match a.validated {
            ValidationState::Confirmed => 2,
            ValidationState::Speculative => 1,
            ValidationState::Rejected => 0,
        };
        let b_ord = match b.validated {
            ValidationState::Confirmed => 2,
            ValidationState::Speculative => 1,
            ValidationState::Rejected => 0,
        };
        b_ord
            .cmp(&a_ord)
            .then_with(|| b.confidence.cmp(&a.confidence))
    });

    // Deduplicate by IP, keeping the best validation state + highest confidence.
    let mut seen = HashSet::new();
    validated.retain(|c| seen.insert(c.ip));

    validated
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_title_finds_simple_title() {
        let body = "<html><head><title>Hello World</title></head></html>";
        assert_eq!(extract_title(body), Some("Hello World".to_string()));
    }

    #[test]
    fn body_hash_is_deterministic() {
        let h1 = body_hash("test");
        let h2 = body_hash("test");
        assert_eq!(h1, h2);
        assert_ne!(h1, body_hash("different"));
    }

    #[test]
    fn comparison_match_with_body_and_title() {
        let baseline = Fingerprint {
            status: 200,
            body_hash: "abc".into(),
            title: Some("Home".into()),
            etag: Some("e1".into()),
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "abc".into(),
            title: Some("Home".into()),
            etag: Some("e2".into()),
        };
        assert_eq!(compare(&baseline, &direct), Comparison::Match);
    }

    #[test]
    fn comparison_false_positive_for_welcome_nginx() {
        let baseline = Fingerprint {
            status: 200,
            body_hash: "base".into(),
            title: Some("Real Site".into()),
            etag: None,
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "direct".into(),
            title: Some("Welcome to nginx!".into()),
            etag: None,
        };
        assert_eq!(compare(&baseline, &direct), Comparison::FalsePositive);
    }

    #[test]
    fn comparison_no_match_when_different() {
        let baseline = Fingerprint {
            status: 200,
            body_hash: "base".into(),
            title: Some("Home".into()),
            etag: None,
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "other".into(),
            title: Some("Other".into()),
            etag: None,
        };
        assert_eq!(compare(&baseline, &direct), Comparison::NoMatch);
    }
}
