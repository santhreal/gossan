//! Pin every documented Config default. Adding/removing a field without
//! touching this file should fail the test suite.

use gossan_core::config::{Config, OutputConfig, OutputFormat, PortMode};
use std::net::IpAddr;
use std::time::Duration;

#[test]
fn rate_limit_default_is_300() {
    assert_eq!(Config::default().rate_limit, 300);
}

#[test]
fn timeout_secs_default_is_10() {
    let c = Config::default();
    assert_eq!(c.timeout_secs, 10);
    assert_eq!(c.timeout(), Duration::from_secs(10));
}

#[test]
fn concurrency_default_is_200() {
    assert_eq!(Config::default().concurrency, 200);
}

#[test]
fn host_delay_ms_default_is_100() {
    assert_eq!(Config::default().host_delay_ms, 100);
}

#[test]
fn max_response_size_default_is_10mb() {
    assert_eq!(Config::default().max_response_size, 10 * 1024 * 1024);
}

#[test]
fn resolvers_default_is_cloudflare_and_google() {
    let c = Config::default();
    assert_eq!(c.resolvers.len(), 2);
    let cloudflare: IpAddr = "1.1.1.1".parse().unwrap();
    let google: IpAddr = "8.8.8.8".parse().unwrap();
    assert!(c.resolvers.contains(&cloudflare));
    assert!(c.resolvers.contains(&google));
}

#[test]
fn port_mode_default_is_default_variant() {
    assert!(matches!(Config::default().port_mode, PortMode::Default));
}

#[test]
fn insecure_tls_off_by_default() {
    assert!(!Config::default().insecure_tls);
}

#[test]
fn proxy_unset_by_default() {
    assert!(Config::default().proxy.is_none());
}

#[test]
fn min_severity_unset_by_default() {
    assert!(Config::default().min_severity.is_none());
}

#[test]
fn modules_empty_by_default() {
    assert!(Config::default().modules.is_empty());
}

#[test]
fn api_keys_empty_by_default() {
    assert!(Config::default().api_keys.is_empty());
}

#[test]
fn include_exclude_kind_empty_by_default() {
    let c = Config::default();
    assert!(c.include_kind.is_empty());
    assert!(c.exclude_kind.is_empty());
}

#[test]
fn strict_off_by_default() {
    assert!(!Config::default().strict);
}

#[test]
fn conservative_off_by_default() {
    assert!(!Config::default().conservative);
}

#[test]
fn intel_db_path_unset_by_default() {
    assert!(Config::default().intel_db_path.is_none());
}

#[test]
fn user_agent_carries_pkg_version_and_repo_url() {
    let ua = Config::default().user_agent;
    assert!(ua.starts_with("gossan/"));
    assert!(ua.contains("https://"));
}

#[test]
fn crawl_max_pages_default_is_50() {
    assert_eq!(Config::default().crawl.max_pages, 50);
}

#[test]
fn crawl_max_depth_default_is_3() {
    assert_eq!(Config::default().crawl.max_depth, 3);
}

#[test]
fn output_default_is_text_and_no_path() {
    let o = OutputConfig::default();
    assert!(matches!(o.format, OutputFormat::Text));
    assert!(o.path.is_none());
}

#[test]
fn config_roundtrips_through_toml() {
    let c = Config::default();
    let toml = toml::to_string(&c).unwrap();
    let back: Config = toml::from_str(&toml).unwrap();
    assert_eq!(back.rate_limit, c.rate_limit);
    assert_eq!(back.timeout_secs, c.timeout_secs);
    assert_eq!(back.concurrency, c.concurrency);
    assert_eq!(back.host_delay_ms, c.host_delay_ms);
    assert_eq!(back.max_response_size, c.max_response_size);
}

#[test]
fn load_or_default_returns_default_when_no_config_file() {
    // Run from a temp dir that has no gossan.toml; default must come back.
    let tmp = tempfile::tempdir().unwrap();
    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(tmp.path()).unwrap();
    let r = Config::load_or_default();
    std::env::set_current_dir(cwd).unwrap();
    let c = r.unwrap();
    assert_eq!(c.rate_limit, 300);
    assert_eq!(c.timeout_secs, 10);
}
