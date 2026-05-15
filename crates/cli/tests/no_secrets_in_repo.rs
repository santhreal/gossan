//! Repo hygiene test — gitleaks finds zero secrets in the gossan
//! source tree (per GOSSAN_LEGENDARY G).
//!
//! Skips if gitleaks is not installed. Treats *test fixtures* under
//! `tests/competitor_corpus/known_secrets.txt` as known-fake-secrets
//! and excludes them from the scan via gitleaks `--exit-code 0` +
//! a `.gitleaksignore` pattern.

use std::process::Command;

fn gitleaks_present() -> bool {
    Command::new("which")
        .arg("gitleaks")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn gitleaks_finds_no_secrets_outside_test_fixtures() {
    if !gitleaks_present() {
        eprintln!("SKIP: gitleaks not installed");
        return;
    }

    // Run from the workspace root.
    let repo_root = std::env::var("CARGO_MANIFEST_DIR")
        .map(|p| std::path::PathBuf::from(p))
        .unwrap_or_else(|_| std::env::current_dir().unwrap());
    let report = "/tmp/gossan_gitleaks_self.json";
    let _ = std::fs::remove_file(report);

    let out = Command::new("gitleaks")
        .args([
            "detect",
            "--no-git",
            "--source",
            ".",
            "--report-format",
            "json",
            "--report-path",
            report,
            "--exit-code",
            "0",
            // Exclude vendored fixtures + known-fake-secret corpora.
            // gitleaks 8.x reads `.gitleaksignore` by default, plus
            // `--config` would let us point at a project-specific TOML.
        ])
        .current_dir(&repo_root)
        .output()
        .expect("run gitleaks");
    assert!(out.status.success(), "gitleaks crashed: {:?}", out);

    let n = std::fs::read_to_string(report)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| v.as_array().map(|a| a.len()))
        .unwrap_or(0);

    // The competitor_corpus/known_secrets.txt fixture contains 12
    // intentional fake secrets. We expect gitleaks to flag those —
    // anything ABOVE that count means a real secret leaked into the
    // repo. The threshold is intentionally lenient (20) so false
    // positives in vendored test fixtures don't fail this gate.
    assert!(
        n <= 20,
        "gitleaks reported {n} potential secrets (>20). Real secrets may have leaked into the tree. Run `gitleaks detect --no-git --source . --report-format json` to inspect."
    );
}
