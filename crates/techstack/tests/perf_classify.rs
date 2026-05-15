//! Per GOSSAN_LEGENDARY A7: classify a 1 MB HTML in <50 ms.
//!
//! Drives `truestack::fingerprints::detect` against a synthetic
//! 1 MiB HTML body and asserts the run completes under 50 ms.
//! Release-only because debug builds linearize regex compilation.

use std::time::{Duration, Instant};

const ONE_MB: usize = 1024 * 1024;

fn synth_html(target: usize) -> String {
    let pad = "x".repeat(64);
    let mut buf = String::with_capacity(target + 1024);
    buf.push_str("<!DOCTYPE html><html><head><title>perf</title></head><body>");
    while buf.len() < target {
        buf.push_str("<p>");
        buf.push_str(&pad);
        buf.push_str("</p>");
    }
    buf.push_str("</body></html>");
    buf
}

#[test]
#[cfg(not(debug_assertions))]
fn classify_1mb_html_under_50ms() {
    let body = synth_html(ONE_MB);
    let headers: &[(&str, &str)] = &[];
    let start = Instant::now();
    let _ = truestack::fingerprints::detect(headers, &body);
    let elapsed = start.elapsed();
    eprintln!("techstack classify 1 MiB HTML: {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(50),
        "techstack classify took {elapsed:?} on 1 MiB HTML, > 50 ms gate"
    );
}

#[test]
fn classify_perf_gate_is_release_only() {
    let _ = synth_html(1024);
}
