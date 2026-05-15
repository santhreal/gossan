//! SARIF schema-shape validation test.
//!
//! Per GOSSAN_LEGENDARY B5: ensure the JSON gossan emits with
//! `--format sarif` is structurally a valid SARIF 2.1.0 document.
//!
//! We don't need a full JSON-Schema validator (that's a separate
//! cargo dep + ~100KB of dependencies). The structural checks here
//! cover the SARIF 2.1.0 requirements that downstream tools
//! (GitHub code-scanning, Microsoft sarif-multitool, JFrog Xray,
//! Sonarqube) actually enforce on import:
//!
//!  * top-level `$schema` URL is the SARIF 2.1.0 schema
//!  * top-level `version` == "2.1.0"
//!  * `runs` is a non-empty array
//!  * each run has `tool.driver.name` (rule provenance)
//!  * each run has `results: []` (the findings array)
//!  * each result has `ruleId` + `level` + `message.text`
//!
//! This test feeds 3 fixture findings of varying severity through
//! the santh_output renderer and validates the emitted JSON.

use secfinding::{Evidence, Finding, Severity};
use santh_output::format::Format;

fn fixture_findings() -> Vec<Finding> {
    let make = |sev: Severity, title: &str| {
        Finding::builder("test-tool", "example.com", sev)
            .title(title)
            .detail(format!("detail for {title}"))
            .evidence(Evidence::Banner {
                raw: format!("ev for {title}").into(),
            })
            .build()
            .expect("build finding")
    };
    vec![
        make(Severity::Critical, "critical thing"),
        make(Severity::High, "high thing"),
        make(Severity::Info, "info thing"),
    ]
}

fn render_sarif(findings: &[Finding]) -> serde_json::Value {
    let s = santh_output::render::render(findings, Format::Sarif, "gossan")
        .expect("render");
    serde_json::from_str(&s).expect("emitted SARIF must be valid JSON")
}

#[test]
fn sarif_top_level_shape() {
    let v = render_sarif(&fixture_findings());
    assert_eq!(
        v.get("$schema").and_then(|s| s.as_str()),
        Some("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"),
    );
    assert_eq!(v.get("version").and_then(|s| s.as_str()), Some("2.1.0"));
    let runs = v.get("runs").and_then(|s| s.as_array()).expect("runs[]");
    assert!(!runs.is_empty(), "runs array must be non-empty");
}

#[test]
fn sarif_run_has_tool_driver_name() {
    let v = render_sarif(&fixture_findings());
    let run = &v["runs"][0];
    let name = run["tool"]["driver"]["name"]
        .as_str()
        .expect("tool.driver.name");
    assert_eq!(name, "gossan");
}

#[test]
fn sarif_run_has_results_array() {
    let v = render_sarif(&fixture_findings());
    let results = v["runs"][0]["results"]
        .as_array()
        .expect("runs[0].results[]");
    assert_eq!(results.len(), 3, "3 input findings → 3 SARIF results");
}

#[test]
fn sarif_each_result_has_required_fields() {
    let v = render_sarif(&fixture_findings());
    let results = v["runs"][0]["results"].as_array().unwrap();
    for (i, r) in results.iter().enumerate() {
        assert!(
            r.get("ruleId").and_then(|x| x.as_str()).is_some(),
            "result {i} missing ruleId"
        );
        // SARIF requires either `level` (with values warning|error|note|none)
        // OR a kind="pass" — gossan emits level on every finding.
        let level = r
            .get("level")
            .and_then(|x| x.as_str())
            .unwrap_or_else(|| panic!("result {i} missing level"));
        assert!(
            matches!(level, "error" | "warning" | "note" | "none"),
            "result {i} has invalid level `{level}`"
        );
        let text = r["message"]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("result {i} missing message.text"));
        assert!(!text.is_empty(), "result {i} message.text is empty");
    }
}

#[test]
fn sarif_empty_input_still_valid_shape() {
    let v = render_sarif(&[]);
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["results"].as_array().map(|a| a.len()), Some(0));
}
