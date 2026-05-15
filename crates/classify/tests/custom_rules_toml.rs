//! `gossan-classify` accepts community-contributed service rules
//! from a TOML file at runtime. This test proves:
//!
//! 1. The loader returns the parsed rules.
//! 2. Custom rules + builtin rules combine via `builtin_plus(path)`,
//!    custom-first so a higher-priority custom rule wins ties.
//! 3. A custom rule actually fires on a matching banner.
//! 4. Garbage TOML returns an error, not a panic.

use gossan_classify::matcher::CpuMatcher;
use gossan_classify::rules::{builtin_plus, builtin_rules, load_from_toml};

fn fixture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("custom_rules.toml")
}

#[test]
fn loader_parses_two_custom_rules() {
    let parsed = load_from_toml(fixture_path()).expect("load ok");
    assert_eq!(parsed.len(), 2);
    let ids: Vec<_> = parsed.iter().map(|r| r.id.clone()).collect();
    assert!(ids.contains(&"custom-acme-api".to_string()));
    assert!(ids.contains(&"custom-foobar-rpc".to_string()));
}

#[test]
fn builtin_plus_combines_custom_and_builtin() {
    let combined = builtin_plus(fixture_path());
    let baseline = builtin_rules().len();
    assert_eq!(
        combined.len(),
        baseline + 2,
        "combined = builtin ({baseline}) + 2 custom"
    );
    // Custom rules are first so a tied-priority custom wins ordering.
    assert_eq!(combined[0].id, "custom-acme-api");
    assert_eq!(combined[1].id, "custom-foobar-rpc");
}

#[test]
fn custom_rule_actually_matches_a_banner() {
    let m = CpuMatcher::new(builtin_plus(fixture_path()));
    let hits = m.match_banner("HTTP/1.1 200 OK\r\nX-Acme-Version: 3.1.4\r\nServer: AcmeAPI\r\n");
    assert!(
        hits.iter().any(|h| h.service == "AcmeAPI"),
        "expected AcmeAPI to fire on its custom banner; got {:?}",
        hits.iter().map(|h| &h.service).collect::<Vec<_>>()
    );
    let acme = hits.iter().find(|h| h.service == "AcmeAPI").unwrap();
    assert_eq!(acme.version.as_deref(), Some("3.1.4"));
}

#[test]
fn loader_errors_on_garbage_not_panic() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), b"this is { not toml = ! ;").unwrap();
    let r = load_from_toml(tmp.path());
    assert!(r.is_err(), "expected parse error on garbage input");
}

#[test]
fn loader_errors_on_missing_file() {
    let r = load_from_toml("/nonexistent/path/that/does/not/exist.toml");
    assert!(r.is_err());
}
