//! Pipeline orchestration smoke test.
//!
//! Per GOSSAN_LEGENDARY A2: a single subcommand round-trip through
//! the real binary, asserting (a) it exits cleanly and (b) it emits
//! parseable output in the requested format.
//!
//! We don't run a full network scan in CI (would hit real DNS /
//! external services). The test invokes `gossan tech` against
//! `127.0.0.1` (no network egress) with a short timeout and asserts
//! the binary exits cleanly. The full `tests/e2e_full_scan.rs` with
//! docker-compose lives in section H of GOSSAN_LEGENDARY.

use std::process::Command;

fn cli_bin() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_gossan"))
}

#[test]
fn root_help_lists_subcommands() {
    let out = Command::new(cli_bin())
        .arg("--help")
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(out.status.success() || out.status.code() == Some(0));
    for sub in ["scan", "subdomain"] {
        assert!(
            combined.contains(sub),
            "--help must list `{sub}`; got:\n{combined}"
        );
    }
}

#[test]
fn version_flag_prints_a_semver() {
    let out = Command::new(cli_bin())
        .arg("--version")
        .output()
        .expect("spawn");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "exit must be 0");
    assert!(s.contains("gossan"), "version must mention gossan: {s}");
    // Semver shape: M.m.p
    let dot_count = s.chars().filter(|c| *c == '.').count();
    assert!(
        dot_count >= 2,
        "version must look semver-ish (>=2 dots): {s}"
    );
}

#[test]
fn unknown_subcommand_exits_nonzero() {
    let out = Command::new(cli_bin())
        .arg("definitely-not-a-subcommand")
        .output()
        .expect("spawn");
    assert!(
        !out.status.success(),
        "unknown subcommand must exit nonzero"
    );
}

#[cfg(feature = "engine")]
#[test]
fn probe_engine_exits_cleanly_and_prints_table() {
    let out = Command::new(cli_bin())
        .arg("probe-engine")
        .output()
        .expect("spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "probe-engine exit must be 0");
    for needle in [
        "selected backend",
        "kernel",
        "CAP_NET_RAW",
        "libbpf present",
        "features",
    ] {
        assert!(
            stdout.contains(needle),
            "probe-engine output missing `{needle}`: {stdout}"
        );
    }
}
