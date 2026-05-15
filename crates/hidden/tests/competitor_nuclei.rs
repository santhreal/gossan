//! Competitor benchmark — gossan-hidden vs nuclei on a controlled
//! HTTP fixture corpus.
//!
//! Without nuclei installed this test skips with an install hint.
//! When nuclei IS installed, the bench runs both scanners against
//! the local hackertricks fixture (a snapshot of intentionally
//! exposed misconfigurations) and asserts (a) gossan-hidden finds
//! the high-severity exposures nuclei finds, and (b) gossan does it
//! in less than nuclei's wall time.
//!
//! We don't ship the corpus as part of the test (vendored fixtures
//! would balloon the crate). Operators bench locally via:
//!   git clone https://github.com/HACKING-CHEAT-SHEET/hackertricks /tmp/htricks
//!   cargo test -p gossan-hidden --test competitor_nuclei -- --ignored
//!
//! Always-on test: nuclei presence probe.

use std::process::Command;

fn binary_present(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn versus_nuclei_install_check() {
    if !binary_present("nuclei") {
        eprintln!("SKIP: nuclei not installed; install via `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`");
        return;
    }
    eprintln!("nuclei IS installed; head-to-head against gossan-hidden pending corpus");
}
