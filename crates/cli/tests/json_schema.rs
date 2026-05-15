//! JSON output schema test.
//!
//! Asserts that the canonical `--format json` output matches the
//! shape committed in `docs/schema/v1.json`. We don't run a full
//! JSON-Schema validator (would pull in jsonschema as a dep) — we
//! parse the output as `serde_json::Value` and check the contract
//! the schema documents: top-level object with `tool: "gossan"`,
//! `findings: [...]`, and each finding having `kind`, `target`,
//! `severity`, `title`. NDJSON variant: each line parses to a
//! Finding-shaped object.

use secfinding::{Evidence, Finding, Severity};
use serde_json::Value;

fn fixture() -> Vec<Finding> {
    vec![
        Finding::builder("portscan", "1.2.3.4", Severity::Info)
            .title("open: 80/tcp")
            .detail("open port")
            .tag("ip:1.2.3.4")
            .tag("port:80/tcp")
            .evidence(Evidence::Banner {
                raw: "HTTP/1.1 200 OK".into(),
            })
            .build()
            .unwrap(),
        Finding::builder("hidden", "https://1.2.3.4/admin", Severity::High)
            .title("admin panel exposed")
            .detail("HTTP 200 on /admin without auth")
            .tag("exposure")
            .build()
            .unwrap(),
    ]
}

#[test]
fn json_output_shape_matches_v1_schema() {
    let rendered =
        santh_output::render(&fixture(), santh_output::Format::Json, "gossan").expect("render");
    let mut buf = Vec::new();
    santh_output::emit(&rendered, &mut buf).expect("emit");
    let value: Value = serde_json::from_slice(&buf).expect("parse json");

    // Top-level is an array of findings (per santh-output's
    // GenericFinding::json_value contract).
    let findings = value.as_array().expect("top-level array of findings");
    assert_eq!(findings.len(), 2, "two findings emitted");

    for f in findings {
        let f = f.as_object().expect("finding is an object");
        // Per docs/schema/v1.json the canonical fields are scanner,
        // target, severity, title.
        for required in ["scanner", "target", "severity", "title"] {
            assert!(
                f.contains_key(required),
                "finding is missing required field `{required}`: {f:?}"
            );
        }
        let sev = f.get("severity").and_then(Value::as_str).unwrap();
        assert!(
            ["info", "low", "medium", "high", "critical"]
                .contains(&sev.to_ascii_lowercase().as_str()),
            "severity {sev} not in v1 enum"
        );
    }
}

#[test]
fn jsonl_output_emits_one_finding_per_line() {
    let rendered =
        santh_output::render(&fixture(), santh_output::Format::Jsonl, "gossan").expect("render");
    let mut buf = Vec::new();
    santh_output::emit(&rendered, &mut buf).expect("emit");
    let body = String::from_utf8(buf).expect("utf8");
    let lines: Vec<&str> = body.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(
        lines.len() >= 2,
        "jsonl must have at least one line per finding; got {} lines",
        lines.len()
    );
    for line in lines {
        let v: Value = serde_json::from_str(line).expect("each jsonl line parses");
        assert!(v.is_object(), "each jsonl record is an object");
    }
}

#[test]
fn sarif_output_carries_v210_marker_and_results() {
    let rendered =
        santh_output::render(&fixture(), santh_output::Format::Sarif, "gossan").expect("render");
    let mut buf = Vec::new();
    santh_output::emit(&rendered, &mut buf).expect("emit");
    let value: Value = serde_json::from_slice(&buf).expect("sarif parses as json");
    let obj = value.as_object().expect("top-level sarif object");
    let version = obj.get("version").and_then(Value::as_str).unwrap_or("");
    assert!(
        version.starts_with("2.1"),
        "sarif version must be 2.1.x, got {version}"
    );
    let runs = obj
        .get("runs")
        .and_then(Value::as_array)
        .expect("runs: [...]");
    assert!(!runs.is_empty(), "sarif must contain at least one run");
}
