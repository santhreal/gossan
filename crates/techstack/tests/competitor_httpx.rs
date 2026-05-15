//! Competitor benchmark — gossan-techstack vs projectdiscovery/httpx
//! and webanalyze.
//!
//! Both peer tools fingerprint the tech stack of an HTTP target.
//! We can't legitimately run head-to-head without a live HTTP
//! fixture (which would require a docker-compose with N stack
//! variants). For this test we (a) verify peer binary presence and
//! (b) skip the actual run with a clear install hint.
//!
//! Note: the python `httpx` (HTTP client library) is unrelated to
//! projectdiscovery's Go `httpx` and shadows the binary on most
//! systems. We resolve the Go binary explicitly via `~/go/bin/httpx`.

use std::path::Path;
use std::process::Command;

fn pd_httpx_path() -> Option<String> {
    let candidates = [
        format!(
            "{}/go/bin/httpx",
            std::env::var("HOME").unwrap_or_default()
        ),
        "/usr/local/bin/httpx-pd".into(),
    ];
    candidates.into_iter().find(|c| Path::new(c).exists())
}

fn binary_present(name: &str) -> bool {
    Command::new("which").arg(name).output().map(|o| o.status.success()).unwrap_or(false)
}

#[test]
fn versus_pd_httpx() {
    let Some(p) = pd_httpx_path() else {
        eprintln!("SKIP: projectdiscovery httpx not at ~/go/bin/httpx (the python httpx in PATH is the wrong binary). Install: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest");
        return;
    };
    eprintln!("pd-httpx at {p}; head-to-head against gossan-techstack pending fixture corpus");
}

#[test]
fn versus_webanalyze() {
    if !binary_present("webanalyze") {
        eprintln!("SKIP: webanalyze not installed; go install github.com/rverton/webanalyze/cmd/webanalyze@latest");
        return;
    }
    eprintln!("webanalyze IS installed; head-to-head against gossan-techstack pending");
}
