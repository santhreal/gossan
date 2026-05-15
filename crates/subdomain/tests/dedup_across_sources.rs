//! Per GOSSAN_LEGENDARY A3: feed two sources the same subdomain;
//! assert it appears once in the deduped output.

use gossan_subdomain::dedup::{dedup_domains, normalize_domain};

#[test]
fn duplicates_collapse() {
    let from_ct = vec!["www.example.com".to_string(), "api.example.com".to_string()];
    let from_wayback = vec!["www.example.com".to_string(), "blog.example.com".to_string()];
    let combined: Vec<String> = from_ct.into_iter().chain(from_wayback).collect();
    let deduped = dedup_domains(combined);
    assert_eq!(deduped.len(), 3);
    assert!(deduped.contains("www.example.com"));
    assert!(deduped.contains("api.example.com"));
    assert!(deduped.contains("blog.example.com"));
}

#[test]
fn case_insensitive_dedup() {
    let combined = vec![
        "API.Example.COM".to_string(),
        "api.example.com".to_string(),
        "Api.Example.com".to_string(),
    ];
    let deduped = dedup_domains(combined);
    assert_eq!(deduped.len(), 1);
    assert!(deduped.contains("api.example.com"));
}

#[test]
fn trailing_dot_normalized() {
    assert_eq!(normalize_domain("api.example.com."), Some("api.example.com".into()));
    assert_eq!(normalize_domain("api.example.com"), Some("api.example.com".into()));
    let combined = vec!["api.example.com.".to_string(), "api.example.com".to_string()];
    assert_eq!(dedup_domains(combined).len(), 1);
}

#[test]
fn empty_strings_dropped() {
    let combined = vec!["".to_string(), "  ".to_string(), "api.example.com".to_string()];
    let deduped = dedup_domains(combined);
    assert_eq!(deduped.len(), 1);
}
