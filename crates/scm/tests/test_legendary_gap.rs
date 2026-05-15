//! Real git-clone path on `git_scanner::scan_repo`.
//!
//! Builds a tiny local repo, points the scanner at it, and asserts the
//! function returns Ok. The pre-streaming `ScanInput { targets:
//! Vec<_>, live_tx: Option<...>, target_tx: Option<...> }` form is
//! retired; the streaming `ScanInput` carries a `target_rx` channel
//! and concrete (not optional) live/target senders.

use gossan_core::{
    target::{DiscoverySource, RepositoryTarget, ScmService},
    Config, ScanInput,
};
use gossan_scm::git_scanner;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use tempfile::tempdir;
use tokio::sync::mpsc;
use url::Url;

fn dummy_resolver() -> Arc<hickory_resolver::TokioAsyncResolver> {
    let (config, opts) = hickory_resolver::system_conf::read_system_conf().unwrap();
    Arc::new(hickory_resolver::TokioAsyncResolver::tokio(config, opts))
}

#[tokio::test]
async fn test_gap_scan_repo_runs_to_completion_on_local_repo() {
    let dir = tempdir().unwrap();

    // Skip if git isn't on PATH (e.g. minimal CI image). Asserting on
    // git's presence makes the test environment-aware; otherwise the
    // `git init` shell-out errors propagate as panics from `.unwrap()`.
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("skipping: git binary not on PATH");
        return;
    }

    Command::new("git")
        .arg("init")
        .current_dir(dir.path())
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    fs::write(
        dir.path().join("package.json"),
        r#"{ "name": "example", "dependencies": { "@internal/package": "1.0.0" } }"#,
    )
    .unwrap();
    fs::write(
        dir.path().join("main.rs"),
        "let aws_key = \"AKIAIOSFODNN7EXAMPLE\";",
    )
    .unwrap();

    Command::new("git")
        .args(["add", "."])
        .current_dir(dir.path())
        .output()
        .unwrap();
    Command::new("git")
        .args(["commit", "-m", "Initial commit"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let target = RepositoryTarget {
        url: Url::from_file_path(dir.path()).unwrap(),
        service: ScmService::GitHub,
        source: DiscoverySource::ScmMapping,
        branch: None,
    };

    let config = Config::default();

    // Streaming ScanInput: inbound rx is empty (scan_repo doesn't read
    // from it), live + target senders carry whatever the scanner
    // emits, resolver is a real (config-derived) handle.
    let (_in_tx, in_rx) = mpsc::unbounded_channel();
    let (live_tx, mut live_rx) = mpsc::unbounded_channel();
    let (target_tx, mut target_rx) = mpsc::unbounded_channel();
    let input = ScanInput {
        seed: "dummy_seed".into(),
        target_rx: tokio::sync::Mutex::new(in_rx),
        live_tx,
        target_tx,
        resolver: dummy_resolver(),
    };

    let result = git_scanner::scan_repo(&target, &config, &input).await;
    assert!(result.is_ok(), "scan_repo returned error: {result:?}");

    // Drain any emitted findings / targets so the test surfaces what
    // the current implementation actually produces (rather than
    // asserting on the pre-streaming `out.findings.is_empty()` API
    // that no longer exists).
    let mut findings_emitted = 0usize;
    while live_rx.try_recv().is_ok() {
        findings_emitted += 1;
    }
    let mut targets_emitted = 0usize;
    while target_rx.try_recv().is_ok() {
        targets_emitted += 1;
    }
    // Smoke check: the contract is "scan completes without panic".
    // The current implementation (see `git_scanner.rs`) walks the
    // tree but does not yet emit findings — the secret-detection
    // hook is open, see GOSSAN_LEGENDARY.md A19. Both counts may be
    // zero; the assertion above is the load-bearing one.
    let _ = (findings_emitted, targets_emitted);
}
