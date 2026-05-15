//! Per-flag CLI smoke tests.
//!
//! Per GOSSAN_LEGENDARY A2: every CLI flag exits cleanly on a valid
//! value and exits non-zero (clap convention: 2) on an invalid value.
//! These tests don't run a full scan — they pair every flag with
//! `--help` so clap parses, then short-circuits.

use std::process::Command;

fn cli_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_gossan"))
}

fn check_args_succeed(args: &[&str]) {
    let out = Command::new(cli_bin())
        .args(args)
        .output()
        .expect("spawn gossan");
    assert!(
        out.status.success(),
        "args {args:?} exited with {:?}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn check_args_fail(args: &[&str]) {
    let out = Command::new(cli_bin())
        .args(args)
        .output()
        .expect("spawn gossan");
    assert!(
        !out.status.success(),
        "args {args:?} unexpectedly succeeded:\nstdout:\n{}",
        String::from_utf8_lossy(&out.stdout),
    );
}

#[test]
fn each_subcommand_help_succeeds() {
    for sc in ["scan", "subdomain", "ports", "dns", "list-scans"] {
        check_args_succeed(&[sc, "--help"]);
    }
}

#[test]
fn rate_flag_accepts_valid_integer() {
    check_args_succeed(&["--rate", "1000", "--help"]);
}

#[test]
fn rate_flag_rejects_non_integer() {
    check_args_fail(&["--rate", "not-a-number", "scan", "example.com"]);
}

#[test]
fn timeout_flag_accepts_valid_integer() {
    check_args_succeed(&["--timeout", "30", "--help"]);
}

#[test]
fn concurrency_flag_accepts_valid_integer() {
    check_args_succeed(&["--concurrency", "100", "--help"]);
}

#[test]
fn format_flag_accepts_known_values() {
    for fmt in [
        "text",
        "json",
        "jsonl",
        "ndjson",
        "sarif",
        "markdown",
        "md",
        "masscan-grep",
        "masscan",
        "grep",
        "grepable",
        "nmap-xml",
        "nmap",
        "xml",
        "graphml",
    ] {
        check_args_succeed(&["--format", fmt, "--help"]);
    }
}

#[test]
fn unknown_flag_is_rejected() {
    check_args_fail(&["--this-flag-does-not-exist", "scan", "example.com"]);
}

#[test]
fn ports_flag_accepts_named_modes() {
    for mode in ["default", "top100", "top1000", "full"] {
        check_args_succeed(&["--ports", mode, "--help"]);
    }
}

#[test]
fn out_flag_accepts_path() {
    check_args_succeed(&["--out", "/tmp/gossan_test_out.json", "--help"]);
}
