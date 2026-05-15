use gossan_core::Config;
use std::path::PathBuf;

#[test]
fn test_config_adversarial_huge_values() {
    // Intentionally huge values causing overflow if incorrectly sized
    let toml_content = r#"
rate_limit = 4294967295
timeout_secs = 18446744073709551615
concurrency = 18446744073709551615
user_agent = "x"
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

    let result = Config::from_toml(&file_path);
    match result {
        Ok(config) => {
            assert_eq!(
                config.rate_limit, 4294967295,
                "Rate limit should parse to exactly u32 max"
            );
            assert_eq!(
                config.timeout_secs, 18446744073709551615,
                "Timeout should parse to exactly u64 max"
            );
        }
        Err(e) => {
            assert!(
                e.contains("parse error"),
                "Should return a parse error string if it fails to parse"
            );
        }
    }
}

#[test]
fn test_config_adversarial_null_bytes_in_path() {
    // On Unix, null bytes in path are invalid. On Rust it should result in an error reading
    // rather than panic.
    let path = PathBuf::from("does_not_exist\0.toml");
    let result = Config::from_toml(&path);
    assert!(result.is_err(), "Null byte path should cause error");
}

#[test]
fn test_config_adversarial_malformed_toml() {
    let toml_content = r#"
[unclosed_section
"#;
    let temp_dir = tempfile::tempdir().unwrap();
    let file_path = temp_dir.path().join("gossan.toml");
    std::fs::write(&file_path, toml_content).unwrap();

    let result = Config::from_toml(&file_path);
    assert!(result.is_err(), "Malformed TOML should error gracefully");
}
