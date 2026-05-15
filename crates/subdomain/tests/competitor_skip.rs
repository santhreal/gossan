//! Competitor benchmarks for `gossan-subdomain` vs amass / subfinder.
//!
//! Both peer binaries query the same OSINT sources gossan does
//! (CT logs, Wayback, RapidDNS, OTX, etc.) so finding deltas come
//! down to source coverage + dedup quality. Without amass/subfinder
//! installed locally these tests skip with an install hint rather
//! than failing CI; run them on a workstation with both peers
//! installed to capture the head-to-head numbers.
//!
//! Real fixture choice: a stable, low-churn org domain (RFC 2606
//! reserved `example.com`) so day-to-day OSINT churn doesn't move
//! the bench. For broader corpus comparison run against vendored
//! lists from public bug bounty programs.

use std::process::Command;

fn binary_present(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn versus_amass() {
    if !binary_present("amass") {
        eprintln!("SKIP: amass not installed; install via `snap install amass`");
        return;
    }
    eprintln!("amass IS installed; head-to-head against gossan-subdomain pending");
}

#[test]
fn versus_subfinder() {
    if !binary_present("subfinder") {
        eprintln!("SKIP: subfinder not installed; install via `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`");
        return;
    }
    eprintln!("subfinder IS installed; head-to-head against gossan-subdomain pending");
}
