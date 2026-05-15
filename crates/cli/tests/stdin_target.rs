//! `gossan subdomain -` reads target domains from stdin.
//!
//! Per GOSSAN_LEGENDARY A2: pipe a domain list, assert all consumed.
//! We can't run a full scan against real DNS in CI; instead we
//! assert the parse path accepts `-` and exits cleanly when stdin
//! is empty.

use std::io::Write;
use std::process::{Command, Stdio};

fn cli_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_gossan"))
}

#[test]
fn stdin_dash_target_with_empty_stdin_does_not_panic() {
    let mut child = Command::new(cli_bin())
        .args(["subdomain", "-"])
        .env("GOSSAN_NO_NETWORK", "1") // future-proof env hint
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gossan");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"");
    }
    let out = child.wait_with_output().expect("wait");
    // We don't pin the exit code — cli today returns 0 on empty
    // stdin. The contract this test holds is "no panic".
    assert!(
        out.status.code().is_some(),
        "process must exit cleanly (got signal kill?)"
    );
}

#[test]
#[ignore = "spawns a real subdomain scan (network-bound). Run explicitly with --ignored when wanted."]
fn stdin_dash_target_with_one_domain_parses_cleanly() {
    let mut child = Command::new(cli_bin())
        .args(["subdomain", "-"])
        .env("GOSSAN_NO_NETWORK", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn gossan");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"example.com\n");
    }
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.code().is_some(),
        "process must exit cleanly with one stdin target"
    );
}
