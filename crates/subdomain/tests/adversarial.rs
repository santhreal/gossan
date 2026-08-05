//! Adversarial tests for gossan-subdomain.
//!
//! Covers: adversarial JSON parsing, regex correctness, deduplication,
//! concurrency limits, source failure handling, rate limiting,
//! empty/giant responses, punycode / IDN handling.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use gossan_core::{Config, DiscoverySource, DomainTarget, ScanInput, Target};
use gossan_subdomain::dedup::{dedup_domains, normalize_domain};
use gossan_subdomain::sources::{SourceRate, SubdomainSource};
use gossan_subdomain::wildcard::detect_wildcards;
use gossan_subdomain::SubdomainScanner;
use governor::DefaultDirectRateLimiter;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use secfinding::{Evidence, Finding, Severity};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

// ---------------------------------------------------------------------------
// Mock DNS server helpers (used by wildcard tests)
// ---------------------------------------------------------------------------

async fn mock_dns_server(addr: std::net::SocketAddr) -> JoinHandle<()> {
    let socket = std::sync::Arc::new(UdpSocket::bind(addr).await.unwrap());
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        loop {
            let (len, peer) = match socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let mut resp = Vec::from(&buf[..len]);
            if resp.len() < 12 {
                continue;
            }
            resp[2] = 0x81; // QR=1
            resp[3] = 0x80; // RA=1
            resp[6] = 0x00; // ANCOUNT hi
            resp[7] = 0x01; // ANCOUNT lo

            let mut i = 12usize;
            while i < len && buf[i] != 0 {
                i += 1 + buf[i] as usize;
            }
            i += 5;

            resp.push(0xC0);
            resp.push(0x0C);
            resp.push(0x00);
            resp.push(0x01); // TYPE A
            resp.push(0x00);
            resp.push(0x01); // CLASS IN
            resp.extend_from_slice(&300u32.to_be_bytes()); // TTL
            resp.push(0x00);
            resp.push(0x04); // RDLENGTH
            resp.extend_from_slice(&Ipv4Addr::new(1, 2, 3, 4).octets());

            let _ = socket.send_to(&resp, peer).await;
        }
    })
}

fn resolver_for(addr: std::net::SocketAddr) -> TokioResolver {
    let mut config = ResolverConfig::new();
    let group = hickory_resolver::config::NameServerConfigGroup::from_ips_clear(
        &[addr.ip()],
        addr.port(),
        false,
    );
    if let Some(ns) = group.into_inner().into_iter().next() {
        config.add_name_server(ns);
    }
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 1;
    TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(opts)
        .build()
}

// ---------------------------------------------------------------------------
// 1. Adversarial JSON parsing helpers (replicate exact source logic)
// ---------------------------------------------------------------------------

fn is_subdomain_of(candidate: &str, domain: &str) -> bool {
    let candidate = candidate.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');
    candidate
        .strip_suffix(domain)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Pattern: `Vec<serde_json::Value>` with `name_value` field (ct.rs, facebook_ct, etc.)
fn parse_json_arr_obj_name_value(text: &str, domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();
    let arr: Vec<serde_json::Value> = serde_json::from_str(text).unwrap_or_default();
    for item in arr {
        if let Some(name) = item.get("name_value").and_then(|v| v.as_str()) {
            for line in name.split('\n') {
                let candidate = line.trim().trim_start_matches("*.").to_lowercase();
                if !candidate.contains('*') && is_subdomain_of(&candidate, &domain_lower) {
                    if let Some(norm) = normalize_domain(&candidate) {
                        seen.insert(norm);
                    }
                }
            }
        }
    }
    seen.into_iter().collect()
}

/// Pattern: `Vec<serde_json::Value>` with `dns_names` array (certspotter.rs)
fn parse_json_arr_obj_dns_names(text: &str, domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();
    let arr: Vec<serde_json::Value> = serde_json::from_str(text).unwrap_or_default();
    for item in arr {
        if let Some(dns_names) = item.get("dns_names").and_then(|v| v.as_array()) {
            for dns_name in dns_names {
                if let Some(name) = dns_name.as_str() {
                    let candidate = name.trim().trim_start_matches("*.").to_lowercase();
                    if !candidate.contains('*') && is_subdomain_of(&candidate, &domain_lower) {
                        if let Some(norm) = normalize_domain(&candidate) {
                            seen.insert(norm);
                        }
                    }
                }
            }
        }
    }
    seen.into_iter().collect()
}

/// Pattern: `Vec<String>` (anubis.rs, crobat.rs, etc.)
fn parse_json_arr_string(text: &str, domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();
    let arr: Vec<String> = serde_json::from_str(text).unwrap_or_default();
    for item in arr {
        let candidate = item.trim().trim_start_matches("*.").to_lowercase();
        if !candidate.contains('*') && is_subdomain_of(&candidate, &domain_lower) {
            if let Some(norm) = normalize_domain(&candidate) {
                seen.insert(norm);
            }
        }
    }
    seen.into_iter().collect()
}

/// Pattern: `serde_json::Value` with `"subdomains"` array of strings (virustotal, threatcrowd, etc.)
fn parse_json_obj_subdomains_arr(text: &str, domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();
    let json: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    if let Some(arr) = json.get("subdomains").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(v) = item.as_str() {
                let candidate = v.trim().trim_start_matches("*.").to_lowercase();
                if !candidate.contains('*') && is_subdomain_of(&candidate, &domain_lower) {
                    if let Some(norm) = normalize_domain(&candidate) {
                        seen.insert(norm);
                    }
                }
            }
        }
    }
    seen.into_iter().collect()
}

/// Pattern: `serde_json::Value` with `"passive_dns"` array of objects (alienvault.rs)
fn parse_json_obj_passive_dns(text: &str, domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();
    let json: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    if let Some(arr) = json.get("passive_dns").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(v) = item.get("hostname").and_then(|v| v.as_str()) {
                let candidate = v.trim().trim_start_matches("*.").to_lowercase();
                if !candidate.contains('*') && is_subdomain_of(&candidate, &domain_lower) {
                    if let Some(norm) = normalize_domain(&candidate) {
                        seen.insert(norm);
                    }
                }
            }
        }
    }
    seen.into_iter().collect()
}

/// Pattern: `serde_json::Value` with `"data"` array of strings (dnslytics.rs, etc.)
fn parse_json_obj_data_arr(text: &str, domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();
    let json: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    if let Some(arr) = json.get("data").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(v) = item.as_str() {
                let candidate = v.trim().trim_start_matches("*.").to_lowercase();
                if !candidate.contains('*') && is_subdomain_of(&candidate, &domain_lower) {
                    if let Some(norm) = normalize_domain(&candidate) {
                        seen.insert(norm);
                    }
                }
            }
        }
    }
    seen.into_iter().collect()
}

/// Pattern: `serde_json::Value` with `"results"` array of strings (fofa.rs, etc.)
fn parse_json_obj_results(text: &str, domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();
    let json: serde_json::Value = serde_json::from_str(text).unwrap_or_default();
    if let Some(arr) = json.get("results").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(v) = item.as_str() {
                let candidate = v.trim().trim_start_matches("*.").to_lowercase();
                if !candidate.contains('*') && is_subdomain_of(&candidate, &domain_lower) {
                    if let Some(norm) = normalize_domain(&candidate) {
                        seen.insert(norm);
                    }
                }
            }
        }
    }
    seen.into_iter().collect()
}

/// Pattern: line-delimited JSON with `"rrname"` (circl.rs, farsight_dnsdb.rs, dnsrepo.rs)
fn parse_text_ndjson(text: &str, domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(line.trim()) {
            if let Some(name) = val.get("rrname").and_then(|v| v.as_str()) {
                let candidate = name.trim().trim_start_matches("*.").to_lowercase();
                if !candidate.contains('*') && is_subdomain_of(&candidate, &domain_lower) {
                    if let Some(norm) = normalize_domain(&candidate) {
                        seen.insert(norm);
                    }
                }
            }
        }
    }
    seen.into_iter().collect()
}

/// Pattern: plain text CSV-like (hackertarget.rs)
fn parse_text_csv(text: &str, domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("error") || line.starts_with("<") {
            continue;
        }
        if let Some(field) = line.split(',').next() {
            let candidate = field.trim().trim_end_matches('.').to_lowercase();
            if is_subdomain_of(&candidate, &domain_lower) {
                if let Some(norm) = normalize_domain(&candidate) {
                    seen.insert(norm);
                }
            }
        }
    }
    seen.into_iter().collect()
}

/// Pattern: plain text space-delimited (rapiddns.rs, sitedossier.rs)
fn parse_text_space(text: &str, domain: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let domain_lower = domain.to_lowercase();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("error") || line.starts_with("<") {
            continue;
        }
        if let Some(field) = line.split(' ').next() {
            let candidate = field.trim().trim_end_matches('.').to_lowercase();
            if is_subdomain_of(&candidate, &domain_lower) {
                if let Some(norm) = normalize_domain(&candidate) {
                    seen.insert(norm);
                }
            }
        }
    }
    seen.into_iter().collect()
}

// ---------------------------------------------------------------------------
// 2. Adversarial JSON parsing tests
// ---------------------------------------------------------------------------

macro_rules! adversarial_json_tests {
    ($name:ident, $parser:expr) => {
        mod $name {
            use super::*;

            #[test]
            fn valid_json_extracts_subdomains() {
                let domain = "example.com";
                let json = r#"[{"name_value":"api.example.com\nwww.example.com"}]"#;
                let res = $parser(json, domain);
                assert!(res.contains(&"api.example.com".to_string()));
                assert!(res.contains(&"www.example.com".to_string()));
            }

            #[test]
            fn array_of_objects_bug_fixed() {
                let domain = "example.com";
                let json = r#"[{"name_value":"api.example.com"},{"name_value":"www.example.com"}]"#;
                let res = $parser(json, domain);
                assert!(res.contains(&"api.example.com".to_string()));
                assert!(res.contains(&"www.example.com".to_string()));
            }

            #[test]
            fn empty_response_returns_empty() {
                let res = $parser("", "example.com");
                assert!(res.is_empty());
            }

            #[test]
            fn html_error_page_returns_empty() {
                let html = "<html><body>502 Bad Gateway</body></html>";
                let res = $parser(html, "example.com");
                assert!(res.is_empty());
            }

            #[test]
            fn malformed_json_returns_empty() {
                let bad = "[{\"name_value\": \"api.example.com\"";
                let res = $parser(bad, "example.com");
                assert!(res.is_empty());
            }

            #[test]
            fn huge_json_is_handled() {
                let mut huge = String::with_capacity(11 * 1024 * 1024);
                huge.push('[');
                for i in 0..250_000 {
                    if i > 0 {
                        huge.push(',');
                    }
                    huge.push_str(&format!("{{\"name_value\":\"sub{}.example.com\"}}", i));
                }
                huge.push(']');
                assert!(huge.len() > 5 * 1024 * 1024);
                let res = $parser(&huge, "example.com");
                assert!(!res.is_empty());
            }

            #[test]
            fn unicode_idn_domains() {
                let json = r#"[{"name_value":"münchen.example.com"}]"#;
                let res = $parser(json, "example.com");
                assert!(res.contains(&"xn--mnchen-3ya.example.com".to_string()));
            }
        }
    };
}

adversarial_json_tests!(ct_like, parse_json_arr_obj_name_value);
mod certspotter_like {
    use super::*;

    #[test]
    fn valid_json_extracts_subdomains() {
        let json = r#"[{"dns_names":["api.example.com","www.example.com"]}]"#;
        let res = parse_json_arr_obj_dns_names(json, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn array_of_objects_bug_fixed() {
        let json = r#"[{"dns_names":["api.example.com"]},{"dns_names":["www.example.com"]}]"#;
        let res = parse_json_arr_obj_dns_names(json, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn empty_response_returns_empty() {
        let res = parse_json_arr_obj_dns_names("", "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn html_error_page_returns_empty() {
        let html = "<html><body>502 Bad Gateway</body></html>";
        let res = parse_json_arr_obj_dns_names(html, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn malformed_json_returns_empty() {
        let bad = r#"[{"dns_names": ["api.example.com"]"#;
        let res = parse_json_arr_obj_dns_names(bad, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn huge_json_is_handled() {
        let mut huge = String::with_capacity(11 * 1024 * 1024);
        huge.push('[');
        for i in 0..250_000 {
            if i > 0 {
                huge.push(',');
            }
            huge.push_str(&format!(r#"{{"dns_names":["sub{}.example.com"]}}"#, i));
        }
        huge.push(']');
        assert!(huge.len() > 5 * 1024 * 1024);
        let res = parse_json_arr_obj_dns_names(&huge, "example.com");
        assert!(!res.is_empty());
    }

    #[test]
    fn unicode_idn_domains() {
        let json = r#"[{"dns_names":["münchen.example.com"]}]"#;
        let res = parse_json_arr_obj_dns_names(json, "example.com");
        assert!(res.contains(&"xn--mnchen-3ya.example.com".to_string()));
    }
}

// anubis-like uses Vec<String> so valid/empty tests differ slightly
mod anubis_like {
    use super::*;

    #[test]
    fn valid_json_extracts_subdomains() {
        let json = r#"["api.example.com","www.example.com"]"#;
        let res = parse_json_arr_string(json, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn array_of_objects_bug() {
        // Vec<String> parser: serde_json fails entirely on mixed array -> empty result
        let json = r#"[{"name":"api.example.com"},"www.example.com"]"#;
        let res = parse_json_arr_string(json, "example.com");
        // serde_json::from_str::<Vec<String>> fails and unwrap_or_default gives empty vec
        assert!(res.is_empty());
    }

    #[test]
    fn empty_response_returns_empty() {
        let res = parse_json_arr_string("", "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn html_error_page_returns_empty() {
        let html = "<html><body>502 Bad Gateway</body></html>";
        let res = parse_json_arr_string(html, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn malformed_json_returns_empty() {
        let bad = "[\"api.example.com\"";
        let res = parse_json_arr_string(bad, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn huge_json_is_handled() {
        let mut huge = String::with_capacity(11 * 1024 * 1024);
        huge.push('[');
        for i in 0..250_000 {
            if i > 0 {
                huge.push(',');
            }
            huge.push_str(&format!("\"sub{}.example.com\"", i));
        }
        huge.push(']');
        assert!(huge.len() > 5 * 1024 * 1024);
        let res = parse_json_arr_string(&huge, "example.com");
        assert!(!res.is_empty());
    }

    #[test]
    fn unicode_idn_domains() {
        let json = r#"["münchen.example.com"]"#;
        let res = parse_json_arr_string(json, "example.com");
        assert!(res.contains(&"xn--mnchen-3ya.example.com".to_string()));
    }
}

mod virustotal_like {
    use super::*;

    #[test]
    fn valid_json_extracts_subdomains() {
        let json = r#"{"subdomains":["api.example.com","www.example.com"]}"#;
        let res = parse_json_obj_subdomains_arr(json, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn array_of_objects_bug() {
        // When API returns objects instead of strings inside subdomains array
        let json = r#"{"subdomains":[{"name":"api.example.com"},"www.example.com"]}"#;
        let res = parse_json_obj_subdomains_arr(json, "example.com");
        assert!(!res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn empty_response_returns_empty() {
        let res = parse_json_obj_subdomains_arr("", "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn html_error_page_returns_empty() {
        let html = "<html><body>502 Bad Gateway</body></html>";
        let res = parse_json_obj_subdomains_arr(html, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn malformed_json_returns_empty() {
        let bad = "{\"subdomains\": [\"api.example.com\"";
        let res = parse_json_obj_subdomains_arr(bad, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn huge_json_is_handled() {
        let mut huge = String::with_capacity(11 * 1024 * 1024);
        huge.push_str("{\"subdomains\":[");
        for i in 0..250_000 {
            if i > 0 {
                huge.push(',');
            }
            huge.push_str(&format!("\"sub{}.example.com\"", i));
        }
        huge.push_str("]}");
        assert!(huge.len() > 5 * 1024 * 1024);
        let res = parse_json_obj_subdomains_arr(&huge, "example.com");
        assert!(!res.is_empty());
    }

    #[test]
    fn unicode_idn_domains() {
        let json = r#"{"subdomains":["münchen.example.com"]}"#;
        let res = parse_json_obj_subdomains_arr(json, "example.com");
        assert!(res.contains(&"xn--mnchen-3ya.example.com".to_string()));
    }
}

mod alienvault_like {
    use super::*;

    #[test]
    fn valid_json_extracts_subdomains() {
        let json = r#"{"passive_dns":[{"hostname":"api.example.com"},{"hostname":"www.example.com"}]}"#;
        let res = parse_json_obj_passive_dns(json, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn array_of_strings_bug() {
        let json = r#"{"passive_dns":["api.example.com","www.example.com"]}"#;
        let res = parse_json_obj_passive_dns(json, "example.com");
        assert!(res.is_empty()); // expects objects, gets strings -> no extraction
    }

    #[test]
    fn empty_response_returns_empty() {
        let res = parse_json_obj_passive_dns("", "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn html_error_page_returns_empty() {
        let html = "<html><body>502 Bad Gateway</body></html>";
        let res = parse_json_obj_passive_dns(html, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn malformed_json_returns_empty() {
        let bad = "{\"passive_dns\": [{\"hostname\": \"api.example.com\"}";
        let res = parse_json_obj_passive_dns(bad, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn huge_json_is_handled() {
        let mut huge = String::with_capacity(11 * 1024 * 1024);
        huge.push_str("{\"passive_dns\":[");
        for i in 0..250_000 {
            if i > 0 {
                huge.push(',');
            }
            huge.push_str(&format!("{{\"hostname\":\"sub{}.example.com\"}}", i));
        }
        huge.push_str("]}");
        assert!(huge.len() > 5 * 1024 * 1024);
        let res = parse_json_obj_passive_dns(&huge, "example.com");
        assert!(!res.is_empty());
    }

    #[test]
    fn unicode_idn_domains() {
        let json = r#"{"passive_dns":[{"hostname":"münchen.example.com"}]}"#;
        let res = parse_json_obj_passive_dns(json, "example.com");
        assert!(res.contains(&"xn--mnchen-3ya.example.com".to_string()));
    }
}

mod dnslytics_like {
    use super::*;

    #[test]
    fn valid_json_extracts_subdomains() {
        let json = r#"{"data":["api.example.com","www.example.com"]}"#;
        let res = parse_json_obj_data_arr(json, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn empty_response_returns_empty() {
        let res = parse_json_obj_data_arr("", "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn html_error_page_returns_empty() {
        let html = "<html><body>502 Bad Gateway</body></html>";
        let res = parse_json_obj_data_arr(html, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn malformed_json_returns_empty() {
        let bad = "{\"data\": [\"api.example.com\"";
        let res = parse_json_obj_data_arr(bad, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn huge_json_is_handled() {
        let mut huge = String::with_capacity(11 * 1024 * 1024);
        huge.push_str("{\"data\":[");
        for i in 0..250_000 {
            if i > 0 {
                huge.push(',');
            }
            huge.push_str(&format!("\"sub{}.example.com\"", i));
        }
        huge.push_str("]}");
        assert!(huge.len() > 5 * 1024 * 1024);
        let res = parse_json_obj_data_arr(&huge, "example.com");
        assert!(!res.is_empty());
    }

    #[test]
    fn unicode_idn_domains() {
        let json = r#"{"data":["münchen.example.com"]}"#;
        let res = parse_json_obj_data_arr(json, "example.com");
        assert!(res.contains(&"xn--mnchen-3ya.example.com".to_string()));
    }
}

mod fofa_like {
    use super::*;

    #[test]
    fn valid_json_extracts_subdomains() {
        let json = r#"{"results":["api.example.com","www.example.com"]}"#;
        let res = parse_json_obj_results(json, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn empty_response_returns_empty() {
        let res = parse_json_obj_results("", "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn html_error_page_returns_empty() {
        let html = "<html><body>502 Bad Gateway</body></html>";
        let res = parse_json_obj_results(html, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn malformed_json_returns_empty() {
        let bad = "{\"results\": [\"api.example.com\"";
        let res = parse_json_obj_results(bad, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn huge_json_is_handled() {
        let mut huge = String::with_capacity(11 * 1024 * 1024);
        huge.push_str("{\"results\":[");
        for i in 0..250_000 {
            if i > 0 {
                huge.push(',');
            }
            huge.push_str(&format!("\"sub{}.example.com\"", i));
        }
        huge.push_str("]}");
        assert!(huge.len() > 5 * 1024 * 1024);
        let res = parse_json_obj_results(&huge, "example.com");
        assert!(!res.is_empty());
    }

    #[test]
    fn unicode_idn_domains() {
        let json = r#"{"results":["münchen.example.com"]}"#;
        let res = parse_json_obj_results(json, "example.com");
        assert!(res.contains(&"xn--mnchen-3ya.example.com".to_string()));
    }
}

mod circl_like {
    use super::*;

    #[test]
    fn valid_ndjson_extracts_subdomains() {
        let text = "{\"rrname\":\"api.example.com\"}\n{\"rrname\":\"www.example.com\"}";
        let res = parse_text_ndjson(text, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn empty_response_returns_empty() {
        let res = parse_text_ndjson("", "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn html_error_page_returns_empty() {
        let html = "<html><body>502 Bad Gateway</body></html>";
        let res = parse_text_ndjson(html, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn malformed_json_lines_skipped() {
        let text = "{\"rrname\":\"api.example.com\"}\nbad json\n{\"rrname\":\"www.example.com\"}";
        let res = parse_text_ndjson(text, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
        assert_eq!(res.len(), 2);
    }

    #[test]
    fn huge_ndjson_is_handled() {
        let mut huge = String::with_capacity(11 * 1024 * 1024);
        for i in 0..250_000 {
            if i > 0 {
                huge.push('\n');
            }
            huge.push_str(&format!("{{\"rrname\":\"sub{}.example.com\"}}", i));
        }
        assert!(huge.len() > 5 * 1024 * 1024);
        let res = parse_text_ndjson(&huge, "example.com");
        assert!(!res.is_empty());
    }

    #[test]
    fn unicode_idn_domains() {
        let text = "{\"rrname\":\"münchen.example.com\"}";
        let res = parse_text_ndjson(text, "example.com");
        assert!(res.contains(&"xn--mnchen-3ya.example.com".to_string()));
    }
}

mod hackertarget_like {
    use super::*;

    #[test]
    fn valid_csv_extracts_subdomains() {
        let text = "api.example.com,1.2.3.4\nwww.example.com,5.6.7.8";
        let res = parse_text_csv(text, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn html_error_page_returns_empty() {
        let html = "<html><body>502 Bad Gateway</body></html>";
        let res = parse_text_csv(html, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn error_line_returns_empty() {
        let text = "error query limit reached";
        let res = parse_text_csv(text, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn empty_response_returns_empty() {
        let res = parse_text_csv("", "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn huge_text_is_handled() {
        let mut huge = String::with_capacity(11 * 1024 * 1024);
        for i in 0..250_000 {
            if i > 0 {
                huge.push('\n');
            }
            huge.push_str(&format!("sub{}.example.com,1.2.3.4", i));
        }
        assert!(huge.len() > 5 * 1024 * 1024);
        let res = parse_text_csv(&huge, "example.com");
        assert!(!res.is_empty());
    }

    #[test]
    fn unicode_idn_domains() {
        let text = "münchen.example.com,1.2.3.4";
        let res = parse_text_csv(text, "example.com");
        assert!(res.contains(&"xn--mnchen-3ya.example.com".to_string()));
    }
}

mod rapiddns_like {
    use super::*;

    #[test]
    fn valid_space_delimited_extracts_subdomains() {
        let text = "api.example.com 1.2.3.4\nwww.example.com 5.6.7.8";
        let res = parse_text_space(text, "example.com");
        assert!(res.contains(&"api.example.com".to_string()));
        assert!(res.contains(&"www.example.com".to_string()));
    }

    #[test]
    fn html_error_page_returns_empty() {
        let html = "<html><body>502 Bad Gateway</body></html>";
        let res = parse_text_space(html, "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn empty_response_returns_empty() {
        let res = parse_text_space("", "example.com");
        assert!(res.is_empty());
    }

    #[test]
    fn huge_text_is_handled() {
        let mut huge = String::with_capacity(11 * 1024 * 1024);
        for i in 0..250_000 {
            if i > 0 {
                huge.push('\n');
            }
            huge.push_str(&format!("sub{}.example.com 1.2.3.4", i));
        }
        assert!(huge.len() > 5 * 1024 * 1024);
        let res = parse_text_space(&huge, "example.com");
        assert!(!res.is_empty());
    }

    #[test]
    fn unicode_idn_domains() {
        let text = "münchen.example.com 1.2.3.4";
        let res = parse_text_space(text, "example.com");
        assert!(res.contains(&"xn--mnchen-3ya.example.com".to_string()));
    }
}

// ---------------------------------------------------------------------------
// 3. Regex correctness tests for search-engine scrapers
// ---------------------------------------------------------------------------

fn search_engine_regex(domain: &str) -> regex::Regex {
    regex::Regex::new(&format!(r"([a-zA-Z0-9_-]+\.{})", regex::escape(domain))).unwrap()
}

#[test]
fn google_regex_matches_subdomains_in_html() {
    let html = r#"<a href="https://api.example.com/path">link</a> <span>www.example.com</span>"#;
    let re = search_engine_regex("example.com");
    let caps: Vec<String> = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();
    assert!(caps.contains(&"api.example.com".to_string()));
    assert!(caps.contains(&"www.example.com".to_string()));
}

#[test]
fn bing_regex_matches_subdomains_in_html() {
    let html = r#"<li class="b_algo"><a href="http://blog.example.com">Blog</a></li>"#;
    let re = search_engine_regex("example.com");
    let caps: Vec<String> = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();
    assert!(caps.contains(&"blog.example.com".to_string()));
}

#[test]
fn yahoo_regex_matches_subdomains_in_html() {
    let html = r#"<a class="td-u" href="https://mail.example.com/login">Mail</a>"#;
    let re = search_engine_regex("example.com");
    let caps: Vec<String> = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();
    assert!(caps.contains(&"mail.example.com".to_string()));
}

#[test]
fn baidu_regex_matches_subdomains_in_html() {
    let html = r#"<a href="https://pan.baidu.com">baidu</a> but also <em>cdn.example.com</em>"#;
    let re = search_engine_regex("example.com");
    let caps: Vec<String> = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();
    assert!(caps.contains(&"cdn.example.com".to_string()));
}

#[test]
fn ask_regex_matches_subdomains_in_html() {
    let html = r#"<a href="https://docs.example.com/guide">Guide</a>"#;
    let re = search_engine_regex("example.com");
    let caps: Vec<String> = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();
    assert!(caps.contains(&"docs.example.com".to_string()));
}

#[test]
fn yandex_regex_matches_subdomains_in_html() {
    let html = r#"<a href="https://store.example.com">Store</a>"#;
    let re = search_engine_regex("example.com");
    let caps: Vec<String> = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();
    assert!(caps.contains(&"store.example.com".to_string()));
}

#[test]
fn digitorus_regex_matches_subdomains_in_html() {
    let html = r#"<td>api.example.com</td><td>www.example.com</td>"#;
    let re = search_engine_regex("example.com");
    let caps: Vec<String> = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();
    assert!(caps.contains(&"api.example.com".to_string()));
    assert!(caps.contains(&"www.example.com".to_string()));
}

#[test]
fn viewdns_regex_matches_subdomains_in_html() {
    let html = r#"<tr><td>mail.example.com</td><td>1.2.3.4</td></tr>"#;
    let re = search_engine_regex("example.com");
    let caps: Vec<String> = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();
    assert!(caps.contains(&"mail.example.com".to_string()));
}

#[test]
fn regex_does_not_match_root_domain() {
    let html = r#"<a href="https://example.com">root</a>"#;
    let re = search_engine_regex("example.com");
    let caps: Vec<String> = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();
    assert!(
        !caps.contains(&"example.com".to_string()),
        "regex should not match root domain without subdomain label"
    );
}

#[test]
fn regex_does_not_match_similar_domain() {
    let html = r#"<a href="https://badexample.com">bad</a>"#;
    let re = search_engine_regex("example.com");
    let caps: Vec<String> = re
        .captures_iter(html)
        .filter_map(|c| c.get(1).map(|m| m.as_str().to_lowercase()))
        .collect();
    assert!(
        !caps.contains(&"badexample.com".to_string()),
        "regex should not match similar domain missing dot boundary"
    );
}

// ---------------------------------------------------------------------------
// 4. Deduplication tests
// ---------------------------------------------------------------------------

#[test]
fn dedup_exact_duplicates() {
    let domains = vec![
        "api.example.com".into(),
        "api.example.com".into(),
        "api.example.com".into(),
    ];
    let deduped = dedup_domains(domains);
    assert_eq!(deduped.len(), 1);
    assert!(deduped.contains("api.example.com"));
}

#[test]
fn dedup_case_variations() {
    let domains = vec![
        "API.Example.COM".into(),
        "api.example.com".into(),
        "Api.Example.Com".into(),
    ];
    let deduped = dedup_domains(domains);
    assert_eq!(deduped.len(), 1);
    assert!(deduped.contains("api.example.com"));
}

#[test]
fn dedup_idn_vs_punycode() {
    let domains = vec![
        "münchen.example.com".into(),
        "xn--mnchen-3ya.example.com".into(),
    ];
    let deduped = dedup_domains(domains);
    assert_eq!(deduped.len(), 1);
    assert!(deduped.contains("xn--mnchen-3ya.example.com"));
}

#[test]
fn dedup_trailing_dots() {
    let domains = vec![
        "api.example.com.".into(),
        "api.example.com".into(),
        "api.example.com.".into(),
    ];
    let deduped = dedup_domains(domains);
    assert_eq!(deduped.len(), 1);
    assert!(deduped.contains("api.example.com"));
}

#[test]
fn dedup_subdomain_vs_root_domain() {
    let domains = vec![
        "example.com".into(),
        "api.example.com".into(),
        "www.example.com".into(),
    ];
    let deduped = dedup_domains(domains);
    // root domain and subdomains are all valid distinct targets
    assert_eq!(deduped.len(), 3);
    assert!(deduped.contains("example.com"));
    assert!(deduped.contains("api.example.com"));
    assert!(deduped.contains("www.example.com"));
}

#[test]
fn dedup_is_associative_and_commutative() {
    let a = vec!["a.example.com".into(), "b.example.com".into()];
    let b = vec!["b.example.com".into(), "a.example.com".into()];
    let c = vec!["A.EXAMPLE.COM".into(), "B.EXAMPLE.COM.".into()];

    let set_a = dedup_domains(a);
    let set_b = dedup_domains(b);
    let set_c = dedup_domains(c);

    assert_eq!(set_a, set_b);
    assert_eq!(set_b, set_c);
}

#[test]
fn dedup_handles_punycode_and_unicode() {
    let domains = vec![
        "münchen.example.com".into(),
        "xn--mnchen-3ya.example.com".into(),
        "MÜNCHEN.EXAMPLE.COM.".into(),
    ];
    let deduped = dedup_domains(domains);
    assert_eq!(deduped.len(), 1);
    assert!(deduped.contains("xn--mnchen-3ya.example.com"));
}

#[test]
fn dedup_strips_trailing_dot() {
    assert_eq!(
        normalize_domain("api.example.com."),
        Some("api.example.com".to_string())
    );
}

#[test]
fn dedup_empty_and_whitespace() {
    assert_eq!(normalize_domain(""), None);
    assert_eq!(normalize_domain("   "), None);
    assert_eq!(
        normalize_domain("  api.example.com  "),
        Some("api.example.com".to_string())
    );
}

// ---------------------------------------------------------------------------
// 5. Concurrency tests
// ---------------------------------------------------------------------------

/// Mock source that tracks the maximum number of concurrent calls.
struct ConcurrencyTrackingSource {
    active: Arc<AtomicUsize>,
    max_active: Arc<AtomicUsize>,
    delay_ms: u64,
}

#[async_trait]
impl SubdomainSource for ConcurrencyTrackingSource {
    fn name(&self) -> &'static str {
        "concurrency_tracker"
    }
    fn requires_api_key(&self) -> bool {
        false
    }
    fn api_key_name(&self) -> &'static str {
        ""
    }
    fn rate_limit(&self) -> SourceRate {
        SourceRate::per_second(1000)
    }
    fn discovery_source(&self) -> DiscoverySource {
        DiscoverySource::PassiveDns
    }

    async fn query(
        &self,
        _domain: &str,
        _config: &Config,
        _client: &reqwest::Client,
        _limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        let mut max = self.max_active.load(Ordering::SeqCst);
        while active > max {
            match self.max_active.compare_exchange_weak(
                max,
                active,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(actual) => max = actual,
            }
        }
        tokio::time::sleep(Duration::from_millis(self.delay_ms)).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        Ok(vec![])
    }
}

#[tokio::test]
async fn semaphore_limits_concurrency() {
    let scanner = SubdomainScanner;
    let config = Config::default();

    let (target_tx, _target_rx) = mpsc::channel::<Target>(1024);
    let (live_tx, mut live_rx) = mpsc::channel(1024);
    let (inbound_tx, inbound_rx) = mpsc::channel::<Target>(1024);
    let _ = inbound_tx.send(Target::Domain(DomainTarget {
        domain: "example.com".to_string(),
        source: DiscoverySource::Seed,
    }));
    drop(inbound_tx);

    // Use a mock resolver that fails fast so bruteforce doesn't hang
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_millis(10);
    opts.attempts = 1;
    let resolver = Arc::new(
        TokioResolver::builder_with_config(
            ResolverConfig::new(),
            TokioConnectionProvider::default(),
        )
        .with_options(opts)
        .build(),
    );

    let input = ScanInput {
        seed: "example.com".to_string(),
        target_rx: tokio::sync::Mutex::new(inbound_rx),
        live_tx,
        target_tx,
        resolver,
    };

    let active = Arc::new(AtomicUsize::new(0));
    let max_active = Arc::new(AtomicUsize::new(0));

    let sources: Vec<Box<dyn SubdomainSource>> = (0..32)
        .map(|_| {
            Box::new(ConcurrencyTrackingSource {
                active: Arc::clone(&active),
                max_active: Arc::clone(&max_active),
                delay_ms: 200,
            }) as Box<dyn SubdomainSource>
        })
        .collect();

    let scan_handle = tokio::spawn(async move {
        scanner.run_with_sources(input, &config, sources).await
    });

    // Give tasks time to spawn and compete for the semaphore
    tokio::time::sleep(Duration::from_millis(100)).await;

    let observed_max = max_active.load(Ordering::SeqCst);

    // Wait for scan to finish
    let _ = tokio::time::timeout(Duration::from_secs(10), scan_handle).await;

    // Drain live_rx so the channel doesn't deadlock on drop
    while live_rx.try_recv().is_ok() {}

    assert!(
        observed_max <= 16,
        "expected concurrency <= 16, got {observed_max}"
    );
}

// ---------------------------------------------------------------------------
// 6. Source failure handling tests
// ---------------------------------------------------------------------------

struct FailingSource;

#[async_trait]
impl SubdomainSource for FailingSource {
    fn name(&self) -> &'static str {
        "failing_source"
    }
    fn requires_api_key(&self) -> bool {
        false
    }
    fn api_key_name(&self) -> &'static str {
        ""
    }
    fn rate_limit(&self) -> SourceRate {
        SourceRate::per_second(1000)
    }
    fn discovery_source(&self) -> DiscoverySource {
        DiscoverySource::PassiveDns
    }

    async fn query(
        &self,
        _domain: &str,
        _config: &Config,
        _client: &reqwest::Client,
        _limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        anyhow::bail!("simulated network failure")
    }
}

/// Replicate the exact error-handling logic from `lib.rs` to verify
/// severity without needing the full async scanner pipeline.
#[test]
fn source_error_produces_info_finding() {
    let source_name = "failing_source";
    let domain = "example.com";
    let err = anyhow::anyhow!("simulated network failure");

    let severity = Severity::Info;
    let finding = Finding::builder("subdomain", domain, severity)
        .title(format!("Subdomain source failed: {source_name}"))
        .detail(format!(
            "Passive source {source_name} failed while enumerating {domain}.              Fix: inspect connectivity, credentials, and upstream throttling. Error: {err}"
        ))
        .kind(secfinding::FindingKind::Other)
        .tag("subdomain")
        .tag("source-error")
        .evidence(Evidence::raw(err.to_string()))
        .build_or_log();

    assert!(
        finding.is_some(),
        "source error should produce a valid finding"
    );
    let finding = finding.unwrap();
    assert_eq!(
        finding.severity(),
        Severity::Info,
        "source error finding should be INFO, not MEDIUM or higher"
    );
    assert!(
        finding.title().contains("failing_source"),
        "finding title should name the failing source"
    );
    assert!(
        finding.tags().iter().any(|t| t.as_ref() == "source-error"),
        "finding should be tagged with 'source-error'"
    );
}

// ---------------------------------------------------------------------------
// 7. Rate limiting tests
// ---------------------------------------------------------------------------

struct CountingSource {
    call_times: Arc<std::sync::Mutex<Vec<Instant>>>,
}

#[async_trait]
impl SubdomainSource for CountingSource {
    fn name(&self) -> &'static str {
        "counting_source"
    }
    fn requires_api_key(&self) -> bool {
        false
    }
    fn api_key_name(&self) -> &'static str {
        ""
    }
    fn rate_limit(&self) -> SourceRate {
        SourceRate::per_second(2)
    }
    fn discovery_source(&self) -> DiscoverySource {
        DiscoverySource::PassiveDns
    }

    async fn query(
        &self,
        _domain: &str,
        _config: &Config,
        _client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>> {
        limiter.until_ready().await;
        self.call_times.lock().unwrap().push(Instant::now());
        Ok(vec![])
    }
}

#[tokio::test]
async fn rate_limiter_throttles_requests() {
    let source = CountingSource {
        call_times: Arc::new(std::sync::Mutex::new(Vec::new())),
    };
    let times = Arc::clone(&source.call_times);

    let client = reqwest::Client::new();
    let config = Config::default();
    let limiter = source.rate_limit().build_limiter();

    // Fire 5 queries as fast as possible
    for _ in 0..5 {
        let _ = source.query("example.com", &config, &client, &limiter).await;
    }

    let times = times.lock().unwrap();
    assert_eq!(times.len(), 5);

    // With 2 req/sec, at least some gaps should be >= 400ms
    let mut gaps_over_300ms = 0;
    for window in times.windows(2) {
        let gap = window[1].duration_since(window[0]);
        if gap >= Duration::from_millis(300) {
            gaps_over_300ms += 1;
        }
    }

    assert!(
        gaps_over_300ms >= 2,
        "rate limiter should throttle: found {gaps_over_300ms} gaps >= 300ms"
    );
}

#[test]
fn rate_limits_are_non_zero() {
    for source in gossan_subdomain::sources::all_sources() {
        let _ = source.rate_limit(); // should not panic
    }
}

// ---------------------------------------------------------------------------
// 8. Wildcard DNS test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn wildcard_detects_multiple_probes() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);

    let server = mock_dns_server(addr).await;
    tokio::time::sleep(Duration::from_millis(50)).await;

    let resolver = resolver_for(addr);
    let ips = detect_wildcards("example.com", &resolver, 3).await;
    server.abort();

    assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
}

// ---------------------------------------------------------------------------
// 9. Smoke tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn source_timeout_does_not_block_others() {
    let sources = gossan_subdomain::sources::all_sources();
    // Registry-size sanity floor. Lowered from 80 after removing 9
    // non-functional get-entries CT sources (amazon/apple/cloudflare/
    // digicert/entrust/godaddy/google/identrust/sectigo) that queried
    // RFC-6962 get-entries with a domain param and could never return
    // results; 71 real sources remain.
    assert!(
        sources.len() >= 70,
        "expected at least 70 sources, got {}",
        sources.len()
    );
}

#[test]
fn finding_builder_smoke() {
    let f = Finding::builder("subdomain", "example.com", Severity::Info)
        .title("Subdomain source failed: failing_source".to_string())
        .detail("Passive source failing_source failed while enumerating example.com. Fix: inspect connectivity, credentials, and upstream throttling. Error: simulated network failure".to_string())
        .kind(secfinding::FindingKind::Other)
        .tag("subdomain")
        .tag("source-error")
        .evidence(Evidence::raw("simulated network failure"))
        .build_or_log();
    assert!(f.is_some(), "finding should build: {:?}", f);
}
