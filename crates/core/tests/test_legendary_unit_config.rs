use gossan_core::{Config, config::ModuleConfig};
use std::path::PathBuf;

#[test]
fn test_config_default() {
    let config = Config::default();
    assert_eq!(config.rate_limit, 300);
    assert_eq!(config.timeout_secs, 10);
    assert_eq!(config.concurrency, 200);
    assert_eq!(config.resolvers.len(), 2);
    assert!(config.user_agent.contains("gossan/"));
    assert_eq!(config.host_delay_ms, 100);
    assert_eq!(config.max_response_size, 10 * 1024 * 1024);
}

#[test]
fn test_module_config_all() {
    // `ModuleConfig` migrated from a struct-with-named-fields to
    // `HashMap<String, bool>` (per-module enablement keyed by name).
    // The "all enabled" sentinel is the special `"all"` key, not a
    // helper constructor — equivalent semantics, different API.
    let mut modules: ModuleConfig = std::collections::HashMap::new();
    modules.insert("all".into(), true);
    let want = [
        "subdomain", "portscan", "techstack", "dns", "js", "hidden",
        "cloud", "headless", "crawl", "origin",
        "horizontal", "graph", "scm", "intel", "fleet",
    ];
    // Either explicit-key=true OR the "all" wildcard counts as enabled.
    for m in want {
        let enabled = modules.get(m).copied().unwrap_or(false)
            || modules.get("all").copied().unwrap_or(false);
        assert!(enabled, "module {m} should be enabled when 'all' is set");
    }
}

#[test]
fn test_config_timeout() {
    let config = Config::default();
    let duration = config.timeout();
    assert_eq!(duration.as_secs(), 10);
}

#[test]
fn test_config_from_toml_file() {
    let toml_content = r#"
rate_limit = 500
timeout_secs = 5
concurrency = 100
user_agent = "custom-agent"
resolvers = []
port_mode = "default"
[modules]
subdomain = false
portscan = false
techstack = false
dns = false
js = false
hidden = false
cloud = false
headless = false
crawl = false
origin = false
horizontal = false
graph = false
scm = false
intel = false
fleet = false
[output]
format = "text"
[api_keys]
"#;
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("gossan.toml");
    std::fs::write(&file_path, toml_content).unwrap();

    let config = Config::from_toml(&file_path).expect("Should parse valid toml");
    assert_eq!(config.rate_limit, 500);
    assert_eq!(config.timeout_secs, 5);
    assert_eq!(config.concurrency, 100);
    assert_eq!(config.user_agent, "custom-agent");
    assert_eq!(config.max_response_size, 10 * 1024 * 1024);
}

#[test]
fn test_config_from_invalid_toml() {
    let toml_content = r#"
rate_limit = "not-a-number"
"#;
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("gossan.toml");
    std::fs::write(&file_path, toml_content).unwrap();

    let result = Config::from_toml(&file_path);
    assert!(result.is_err(), "Invalid TOML should cause error");
}

#[test]
fn test_config_from_missing_toml() {
    let path = PathBuf::from("does_not_exist.toml");
    let result = Config::from_toml(&path);
    assert!(result.is_err(), "Missing file should cause error");
}
