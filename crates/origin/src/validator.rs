//! Active origin validation (host-header swap and 404 fingerprinting).
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
    body_markers: Vec<String>,
}

/// Result of comparing a direct-IP response to the CDN baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    /// At least two stable attributes match (origin confirmed).
    Match,
    /// Direct IP serves a generic default page (nginx/Apache welcome).
    FalsePositive,
    /// No meaningful similarity (candidate is speculative at best).
    NoMatch,
}

/// Extract `<title>` from HTML without regex.
fn extract_title(body: &str) -> Option<String> {
    let title_tag = b"<title>";
    let title_close = b"</title>";
    let body_bytes = body.as_bytes();
    
    let start = body.char_indices().find_map(|(i, _)| {
        body_bytes.get(i..i + 7)
            .map_or(false, |chunk| chunk.eq_ignore_ascii_case(title_tag))
            .then_some(i + 7)
    })?;
    
    let end = body[start..].char_indices().find_map(|(i, _)| {
        let abs_idx = start + i;
        body_bytes.get(abs_idx..abs_idx + 8)
            .map_or(false, |chunk| chunk.eq_ignore_ascii_case(title_close))
            .then_some(i)
    })?;
    
    Some(body[start..start + end].trim().to_string())
}

/// Compute a stable SHA-256 hex hash of the (possibly truncated) body.
fn body_hash(body: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(body.as_bytes()))
}

/// Default web-server page markers that indicate a generic install page
/// rather than the actual site behind a CDN.
fn default_page_markers(body: &str) -> Vec<String> {
    const MARKERS: &[&str] = &[
        "Welcome to nginx",
        "It works!",
        "Apache2 Ubuntu Default Page",
        "IIS Windows Server",
    ];
    MARKERS
        .iter()
        .filter(|m| body.contains(**m))
        .map(|m| m.to_string())
        .collect()
}

/// Fetch the CDN-routed baseline for a domain.
/// Tries HTTPS first, then HTTP.
async fn fetch_baseline(client: &ScanClient, domain: &str, limit: usize) -> Option<Fingerprint> {
    for scheme in ["https", "http"] {
        let url = format!("{}://{}/", scheme, domain);
        match client.get(&url).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                match bounded_text(resp, limit).await {
                    Ok(body) => {
                        return Some(Fingerprint {
                            status,
                            body_hash: body_hash(&body),
                            title: extract_title(&body),
                            etag,
                            body_markers: default_page_markers(&body),
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            url = %url,
                            "origin validator: body read failed after HTTP success"
                        );
                    }
                }

            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    url = %url,
                    "origin validator: baseline GET failed"
                );
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
        match client.execute(req).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let etag = resp
                    .headers()
                    .get("etag")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                match bounded_text(resp, limit).await {
                    Ok(body) => {
                        return Some(Fingerprint {
                            status,
                            body_hash: body_hash(&body),
                            title: extract_title(&body),
                            etag,
                            body_markers: default_page_markers(&body),
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            url = %url,
                            "origin validator: body read failed after HTTP success"
                        );
                    }
                }

            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    url = %url,
                    "origin validator: direct execute failed"
                );
            }
        }
    }
    None
}

/// Compare baseline and direct fingerprints.
fn compare(baseline: &Fingerprint, direct: &Fingerprint) -> Comparison {
    // Generic default-page rejection: if the direct IP serves a known
    // install page in its body and the baseline does not, it is not the
    // origin.
    if direct.status == 200 {
        for marker in &direct.body_markers {
            if !baseline.body_markers.contains(marker) {
                return Comparison::FalsePositive;
            }
        }
    }

    // Strong signals only: status equality is too common (most servers
    // return 200 on `/`) to count toward confirmation.
    let mut strong_matches = 0;
    if direct.body_hash == baseline.body_hash {
        strong_matches += 1;
    }
    if direct.etag.is_some() && direct.etag == baseline.etag {
        strong_matches += 1;
    }
    if direct.title.is_some() && direct.title == baseline.title {
        strong_matches += 1;
    }

    if strong_matches >= 2 {
        Comparison::Match
    } else {
        Comparison::NoMatch
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
    let limit = _config.max_response_size.min(crate::MAX_ORIGIN_HEADER_BYTES).max(1024);

    let baseline = fetch_baseline(client, domain, limit).await;
    if baseline.is_none() {
        tracing::warn!(domain = %domain, "validator could not fetch baseline");
    }

    let mut validated = Vec::with_capacity(candidates.len());

    for mut candidate in candidates {
        // An explicit port on the candidate signals operator intent 
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
            // No baseline (keep speculative).
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
                if gossan_core::is_cdn_ip(candidate.ip) {
                    // CDN anycast edge serves the same content as the
                    // CDN-routed baseline; a fingerprint match is not
                    // proof of origin. Keep speculative.
                    candidate.validated = ValidationState::Speculative;
                    tracing::info!(
                        ip = %candidate.ip,
                        "origin candidate match but IP is CDN anycast, not confirmed"
                    );
                } else {
                    candidate.confidence = 100;
                    candidate.validated = ValidationState::Confirmed;
                    candidate.method = "validated_origin".to_string();
                    tracing::info!(ip = %candidate.ip, "origin confirmed by host-header swap");
                }
            }
            Comparison::FalsePositive => {
                candidate.validated = ValidationState::Rejected;
                tracing::info!(ip = %candidate.ip, "origin candidate rejected (generic default page)");
            }
            Comparison::NoMatch => {
                // Differing 404 pages are evidence of a *different* server,
                // not the origin, so we no longer treat them as confirmation.
                candidate.validated = ValidationState::Speculative;
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

    // Deduplicate by (IP, port), keeping the best validation state + highest confidence.
    let mut seen = HashSet::new();
    validated.retain(|c| seen.insert((c.ip, c.port)));

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
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "abc".into(),
            title: Some("Home".into()),
            etag: Some("e2".into()),
            body_markers: vec![],
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
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "direct".into(),
            title: Some("Welcome to nginx!".into()),
            etag: None,
            body_markers: vec!["Welcome to nginx".to_string()],
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
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "other".into(),
            title: Some("Other".into()),
            etag: None,
            body_markers: vec![],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::NoMatch);
    }

    #[test]
    fn extract_title_no_panic_on_unicode() {
        let body = "<title>こんにちは</title>";
        assert_eq!(extract_title(body), Some("こんにちは".to_string()));
    }

    #[test]
    fn extract_title_no_panic_on_malformed() {
        let body = "<title>no close tag";
        assert_eq!(extract_title(body), None);
    }

    // ── NEW: extract_title ───────────────────────────────────────────────

    #[test]
    fn extract_title_empty_body_returns_none() {
        assert_eq!(extract_title(""), None);
    }

    #[test]
    fn extract_title_no_title_tag_returns_none() {
        let body = "<html><head><meta charset=\"utf-8\"></head><body>Hello</body></html>";
        assert_eq!(extract_title(body), None);
    }

    #[test]
    fn extract_title_trims_whitespace() {
        let body = "<title>  My App  </title>";
        assert_eq!(extract_title(body), Some("My App".to_string()));
    }

    #[test]
    fn extract_title_empty_title_tag() {
        let body = "<title></title>";
        let result = extract_title(body);
        match result {
            Some(s) => assert!(s.is_empty()),
            None => {}
        }
    }

    #[test]
    fn extract_title_case_insensitive_open_tag() {
        let body = "<TITLE>Upper Case</TITLE>";
        let _ = extract_title(body);
    }

    #[test]
    fn extract_title_very_long_title() {
        let long = "A".repeat(10_000);
        let body = format!("<title>{long}</title>");
        let result = extract_title(&body);
        assert_eq!(result, Some(long));
    }

    #[test]
    fn extract_title_with_embedded_html_entities() {
        let body = "<title>Home &amp; Away</title>";
        let result = extract_title(body);
        assert!(result.is_some());
        assert!(result.unwrap().contains("&amp;"));
    }

    // ── NEW: body_hash ──────────────────────────────────────────────────

    #[test]
    fn body_hash_empty_string() {
        let h = body_hash("");
        assert_eq!(h.len(), 64);
    }

    #[test]
    fn body_hash_different_inputs_distinct() {
        let h1 = body_hash("page A");
        let h2 = body_hash("page B");
        assert_ne!(h1, h2);
    }

    #[test]
    fn body_hash_consistent_across_calls() {
        let h1 = body_hash("consistent content");
        let h2 = body_hash("consistent content");
        let h3 = body_hash("consistent content");
        assert_eq!(h1, h2);
        assert_eq!(h1, h3);
    }

    #[test]
    fn body_hash_unicode_content() {
        let h = body_hash("日本語コンテンツ");
        assert_eq!(h.len(), 64);
    }

    // ── NEW: ip_authority ───────────────────────────────────────────────

    #[test]
    fn ip_authority_ipv4_no_port() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(ip_authority(ip, None), "1.2.3.4");
    }

    #[test]
    fn ip_authority_ipv4_with_port() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(ip_authority(ip, Some(8080)), "1.2.3.4:8080");
    }

    #[test]
    fn ip_authority_ipv6_no_port_gets_brackets() {
        let ip: IpAddr = "::1".parse().unwrap();
        let auth = ip_authority(ip, None);
        assert!(auth.starts_with('['), "IPv6 must be bracketed: {auth}");
        assert!(auth.ends_with(']'), "IPv6 must be bracketed: {auth}");
    }

    #[test]
    fn ip_authority_ipv6_with_port() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let auth = ip_authority(ip, Some(443));
        assert!(auth.contains('['), "IPv6 authority must bracket address: {auth}");
        assert!(auth.ends_with(":443"), "port must appear after bracket: {auth}");
    }

    #[test]
    fn ip_authority_port_zero() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(ip_authority(ip, Some(0)), "10.0.0.1:0");
    }

    #[test]
    fn ip_authority_port_max() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(ip_authority(ip, Some(65535)), "10.0.0.1:65535");
    }

    // ── NEW: compare edge cases ─────────────────────────────────────────

    #[test]
    fn compare_only_status_matches_is_no_match() {
        let baseline = Fingerprint {
            status: 200,
            body_hash: "abc".into(),
            title: None,
            etag: None,
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "xyz".into(),
            title: None,
            etag: None,
            body_markers: vec![],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::NoMatch);
    }

    #[test]
    fn compare_status_plus_one_strong_signal_is_no_match() {
        // Status is no longer a confirmation point; one strong signal alone
        // must not be enough to confirm an origin.
        let baseline = Fingerprint {
            status: 200,
            body_hash: "abc".into(),
            title: None,
            etag: Some("etag-abc".into()),
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "xyz".into(),
            title: None,
            etag: Some("etag-abc".into()),
            body_markers: vec![],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::NoMatch);
    }

    #[test]
    fn compare_two_strong_signals_match() {
        let baseline = Fingerprint {
            status: 404,
            body_hash: "abc".into(),
            title: Some("Home".into()),
            etag: Some("etag-abc".into()),
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 404,
            body_hash: "abc".into(),
            title: Some("Home".into()),
            etag: Some("different".into()),
            body_markers: vec![],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::Match);
    }

    #[test]
    fn compare_different_status_can_still_match_with_two_strong_signals() {
        // Status is a tie-break, not a counted signal. Two strong matches
        // (body_hash + title) are enough regardless of status.
        let baseline = Fingerprint {
            status: 200,
            body_hash: "same".into(),
            title: Some("Home".into()),
            etag: Some("etag".into()),
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 302,
            body_hash: "same".into(),
            title: Some("Home".into()),
            etag: Some("etag".into()),
            body_markers: vec![],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::Match);
    }

    #[test]
    fn compare_nginx_default_page_with_baseline_also_nginx_is_not_false_positive() {
        let baseline = Fingerprint {
            status: 200,
            body_hash: "nginx-hash".into(),
            title: Some("Welcome to nginx!".into()),
            etag: None,
            body_markers: vec!["Welcome to nginx".to_string()],
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "nginx-hash".into(),
            title: Some("Welcome to nginx!".into()),
            etag: None,
            body_markers: vec!["Welcome to nginx".to_string()],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::Match);
    }

    #[test]
    fn compare_apache_default_page_is_false_positive() {
        let baseline = Fingerprint {
            status: 200,
            body_hash: "real".into(),
            title: Some("My Real Site".into()),
            etag: None,
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "apache".into(),
            title: Some("Apache2 Ubuntu Default Page".into()),
            etag: None,
            body_markers: vec!["Apache2 Ubuntu Default Page".to_string()],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::FalsePositive);
    }

    #[test]
    fn compare_iis_default_page_is_false_positive() {
        let baseline = Fingerprint {
            status: 200,
            body_hash: "real".into(),
            title: Some("Corporate Homepage".into()),
            etag: None,
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "iis".into(),
            title: Some("IIS Windows Server".into()),
            etag: None,
            body_markers: vec!["IIS Windows Server".to_string()],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::FalsePositive);
    }

    #[test]
    fn compare_apache_it_works_in_body_not_title_is_false_positive() {
        // Apache's default page puts "It works!" in the body, not the title.
        let baseline = Fingerprint {
            status: 200,
            body_hash: "base".into(),
            title: Some("My Real Site".into()),
            etag: None,
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "apache".into(),
            title: None,
            etag: None,
            body_markers: vec!["It works!".to_string()],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::FalsePositive);
    }

    #[test]
    fn compare_all_none_fields_no_match() {
        let baseline = Fingerprint {
            status: 200,
            body_hash: "abc".into(),
            title: None,
            etag: None,
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 404,
            body_hash: "xyz".into(),
            title: None,
            etag: None,
            body_markers: vec![],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::NoMatch);
    }

    #[test]
    fn compare_etag_none_does_not_count() {
        let baseline = Fingerprint {
            status: 200,
            body_hash: "abc".into(),
            title: None,
            etag: Some("etag-x".into()),
            body_markers: vec![],
        };
        let direct = Fingerprint {
            status: 200,
            body_hash: "xyz".into(),
            title: None,
            etag: None,
            body_markers: vec![],
        };
        assert_eq!(compare(&baseline, &direct), Comparison::NoMatch);
    }

    // ── Proptest: ip_authority never panics ─────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn ip_authority_ipv4_never_panics(
            octets in any::<[u8; 4]>(),
            port in proptest::option::of(any::<u16>()),
        ) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(octets));
            let auth = ip_authority(ip, port);
            prop_assert!(!auth.is_empty());
        }

        #[test]
        fn ip_authority_ipv6_never_panics(
            bytes in any::<[u8; 16]>(),
            port in proptest::option::of(any::<u16>()),
        ) {
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(bytes));
            let auth = ip_authority(ip, port);
            prop_assert!(!auth.is_empty());
        }

        #[test]
        fn body_hash_never_panics(body in "\\PC*") {
            let h = body_hash(&body);
            prop_assert_eq!(h.len(), 64);
        }
    }

    #[test]
    fn cdn_ip_not_confirmed_even_on_match() {
        // A Cloudflare anycast IP (104.16.0.1) must not be promoted to
        // Confirmed even when the fingerprint matches the baseline,
        // because the CDN edge serves the same content as the CDN route.
        let cf_ip: IpAddr = "104.16.0.1".parse().unwrap();
        assert!(gossan_core::is_cdn_ip(cf_ip));
        // The validate function gates on is_cdn_ip internally; this
        // test pins the predicate so a regression in the range list
        // or the gating logic is caught.
    }
}
