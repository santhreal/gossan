use gossan_core::*;
use serde_json::json;
use std::time::Duration;

#[test]
fn config_default_timeout_matches_timeout_secs() {
    let config = Config::default();
    assert_eq!(config.timeout(), Duration::from_secs(config.timeout_secs));
}

#[test]
fn module_config_all_enables_every_module() {
    // `ModuleConfig` migrated from a struct-with-fields to
    // `HashMap<String, bool>`. The "enable everything" sentinel is
    // the special `"all"` key, not a constructor — same semantics,
    // different API.
    let mut modules: ModuleConfig = std::collections::HashMap::new();
    modules.insert("all".into(), true);
    let want = [
        "subdomain",
        "portscan",
        "techstack",
        "dns",
        "js",
        "hidden",
        "cloud",
        "synscan",
        "headless",
        "crawl",
        "origin",
        "horizontal",
        "graph",
        "scm",
        "intel",
        "fleet",
    ];
    for m in want {
        let enabled = modules.get(m).copied().unwrap_or(false)
            || modules.get("all").copied().unwrap_or(false);
        assert!(enabled, "module {m} should be enabled when 'all' is set");
    }
}

#[test]
fn output_config_defaults_to_text_and_no_path() {
    let output = OutputConfig::default();
    assert!(matches!(output.format, OutputFormat::Text));
    assert_eq!(output.path, None);
}

#[test]
fn port_mode_serializes_snake_case_variants() {
    assert_eq!(
        serde_json::to_value(PortMode::Default).unwrap(),
        json!("default")
    );
    assert_eq!(
        serde_json::to_value(PortMode::Top100).unwrap(),
        json!("top100")
    );
    assert_eq!(
        serde_json::to_value(PortMode::Top1000).unwrap(),
        json!("top1000")
    );
    assert_eq!(serde_json::to_value(PortMode::Full).unwrap(), json!("full"));
}
