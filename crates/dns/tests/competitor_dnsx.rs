//! Competitor benchmark — gossan-dns vs projectdiscovery/dnsx and
//! blechschmidt/massdns.
//!
//! Both peers do bulk DNS resolution (massdns is the speed leader,
//! dnsx adds DNS-record-type filters). gossan-dns adds posture
//! audit (SPF/DMARC/DKIM/CAA) on top of resolution; head-to-head on
//! pure resolution speed is one comparison, head-to-head on
//! audit-finding count is the other.

use std::process::Command;

fn binary_present(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn versus_dnsx() {
    if !binary_present("dnsx") {
        eprintln!(
            "SKIP: dnsx not installed; go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        );
        return;
    }
    eprintln!("dnsx IS installed; head-to-head against gossan-dns pending corpus");
}

#[test]
fn versus_massdns() {
    if !binary_present("massdns") {
        eprintln!("SKIP: massdns not installed; build from github.com/blechschmidt/massdns");
        return;
    }
    eprintln!("massdns IS installed; head-to-head against gossan-dns pending corpus");
}
