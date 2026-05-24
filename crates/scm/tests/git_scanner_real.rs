//! Real e2e for `gossan_scm::git_scanner::scan_repo`.
//!
//! Before this, `scan_repo` cloned the repo, built a `Chunk` per blob,
//! then THREW IT AWAY (`let _chunk` + `// Skip scan for now`): the
//! entire git-repo secret-scanning capability emitted zero findings,
//! ever  -  every credential committed to a scanned repository was
//! silently missed (a NO-STUBS-law violation: a stub disguised as a
//! scanner). This drives the now-real engine against an actual local
//! git repository with a planted secret and a clean control, and
//! enforces the redaction invariant (the raw credential must never
//! reach the serialized finding).

use std::process::Command;
use std::sync::Arc;

use gossan_core::target::{DiscoverySource, RepositoryTarget, ScmService};
use gossan_core::{Config, Finding, ScanInput, Target};
use gossan_scm::git_scanner::scan_repo;
use tokio::sync::mpsc::unbounded_channel;

// Real-shaped, NON-placeholder AWS key (the canonical AWS docs key
// `AKIAIOSFODNN7EXAMPLE` is deliberately filtered by keyhog; this one
// is detected  -  verified in the gossan-js deep-test work).
const LEAK: &str = "AKIA1234567890ABCDEF";

fn git(args: &[&str], cwd: &std::path::Path) {
    let ok = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_TERMINAL_PROMPT", "0")
        .status()
        .expect("git available")
        .success();
    assert!(ok, "git {args:?} failed");
}

/// Create a local git repo containing `files`, return a `file://` URL.
fn make_repo(dir: &std::path::Path, files: &[(&str, &str)]) -> String {
    git(&["init", "-q", "-b", "main"], dir);
    for (name, body) in files {
        std::fs::write(dir.join(name), body).expect("write fixture file");
    }
    git(&["add", "-A"], dir);
    git(
        &[
            "-c",
            "user.email=t@t.test",
            "-c",
            "user.name=tester",
            "commit",
            "-q",
            "-m",
            "fixture",
        ],
        dir,
    );
    format!("file://{}", dir.display())
}

fn scan_input(seed: &str) -> (ScanInput, tokio::sync::mpsc::UnboundedReceiver<Finding>) {
    let (live_tx, live_rx) = unbounded_channel::<Finding>();
    let (target_tx, _t_rx) = unbounded_channel::<Target>();
    let (_in_tx, in_rx) = unbounded_channel::<Target>();
    let resolver = Arc::new(
        gossan_core::net::build_resolver(&Config::default()).expect("resolver"),
    );
    (
        ScanInput {
            seed: seed.to_string(),
            target_rx: tokio::sync::Mutex::new(in_rx),
            live_tx,
            target_tx,
            resolver,
        },
        live_rx,
    )
}

fn repo_target(url: &str) -> RepositoryTarget {
    RepositoryTarget {
        url: url::Url::parse(url).expect("repo url"),
        service: ScmService::GitHub,
        source: DiscoverySource::Seed,
        branch: None,
    }
}

/// PROVING: a secret committed to the repo is found, classified
/// SecretLeak, and the raw credential is NEVER serialized (only the
/// keyhog-redacted form + detector id).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_repo_finds_committed_secret_and_redacts_it() {
    let tmp = tempfile::tempdir().unwrap();
    let url = make_repo(
        tmp.path(),
        &[
            ("config.py", &format!("AWS_ACCESS_KEY_ID = \"{LEAK}\"\n")),
            ("README.md", "# clean project\nno secrets here\n"),
        ],
    );

    let (input, mut rx) = scan_input(&url);
    scan_repo(&repo_target(&url), &Config::default(), &input)
        .await
        .expect("scan_repo must succeed on a clonable local repo");
    drop(input); // close live_tx so the channel drains cleanly

    let mut findings = Vec::new();
    while let Ok(f) = rx.try_recv() {
        findings.push(f);
    }
    assert!(
        !findings.is_empty(),
        "the committed AWS key MUST be detected  -  scan_repo is no longer a stub"
    );

    let redacted = gossan_keyhog_lite::redact(LEAK);
    assert_ne!(redacted, LEAK, "redact must transform the secret");

    let mut saw_secret_leak = false;
    for f in &findings {
        let j = serde_json::to_string(f).expect("Finding: Serialize");
        assert!(
            !j.contains(LEAK),
            "RAW SECRET LEAKED into serialized finding  -  critical: {j}"
        );
        if j.contains("secret-leak") {
            saw_secret_leak = true;
            assert!(j.contains(&redacted), "evidence must carry the redacted secret; {j}");
            assert!(j.contains("det:"), "must carry a det:<detector> tag; {j}");
            assert!(j.contains("config.py"), "must locate the leaky file; {j}");
        }
    }
    assert!(
        saw_secret_leak,
        "at least one finding must be kind=secret-leak, got {findings:?}"
    );
}

/// NEGATIVE twin: a repo with no secrets yields no findings (precision
///  -  the fix must not turn into noise).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scan_repo_clean_repo_yields_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let url = make_repo(
        tmp.path(),
        &[
            ("main.rs", "fn main() { println!(\"hello\"); }\n"),
            ("notes.txt", "just some prose, a uuid 550e8400-e29b-41d4-a716-446655440000\n"),
        ],
    );

    let (input, mut rx) = scan_input(&url);
    scan_repo(&repo_target(&url), &Config::default(), &input)
        .await
        .expect("scan_repo must succeed on a clean local repo");
    drop(input);

    let mut n = 0;
    while rx.try_recv().is_ok() {
        n += 1;
    }
    assert_eq!(n, 0, "a clean repo must yield zero secret findings");
}
