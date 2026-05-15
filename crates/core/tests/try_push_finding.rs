//! `try_push_finding` must reject every input the secfinding builder rejects
//! (null bytes, U+FFFD, oversize fields) without panicking, and must NOT push
//! the rejected finding into the destination vector.

use gossan_core::finding::{try_push_finding, Finding};
use gossan_core::Severity;

fn ok_builder(scanner: &str) -> secfinding::FindingBuilder {
    Finding::builder(scanner, "example.com", Severity::Info)
        .title("ok title")
        .detail("ok detail")
}

#[test]
fn pushes_a_valid_finding() {
    let mut v: Vec<Finding> = Vec::new();
    try_push_finding(ok_builder("scanner-a"), &mut v);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].scanner(), "scanner-a");
}

#[test]
fn rejects_null_bytes_in_title() {
    let mut v: Vec<Finding> = Vec::new();
    let b = Finding::builder("scanner", "example.com", Severity::Info)
        .title("with\0null")
        .detail("ok");
    try_push_finding(b, &mut v);
    assert!(v.is_empty(), "null byte in title must be rejected");
}

#[test]
fn rejects_null_bytes_in_detail() {
    let mut v: Vec<Finding> = Vec::new();
    let b = Finding::builder("scanner", "example.com", Severity::Info)
        .title("ok")
        .detail("with\0null");
    try_push_finding(b, &mut v);
    assert!(v.is_empty(), "null byte in detail must be rejected");
}

#[test]
fn rejects_null_bytes_in_target() {
    let mut v: Vec<Finding> = Vec::new();
    let b = Finding::builder("scanner", "exa\0mple.com", Severity::Info)
        .title("ok")
        .detail("ok");
    try_push_finding(b, &mut v);
    assert!(v.is_empty(), "null byte in target must be rejected");
}

#[test]
fn rejects_replacement_char_in_title() {
    let mut v: Vec<Finding> = Vec::new();
    let b = Finding::builder("scanner", "example.com", Severity::Info)
        .title("invalid\u{FFFD}utf8-marker")
        .detail("ok");
    try_push_finding(b, &mut v);
    assert!(v.is_empty(), "U+FFFD in title must be rejected");
}

#[test]
fn rejects_replacement_char_in_detail() {
    let mut v: Vec<Finding> = Vec::new();
    let b = Finding::builder("scanner", "example.com", Severity::Info)
        .title("ok")
        .detail("d\u{FFFD}etail");
    try_push_finding(b, &mut v);
    assert!(v.is_empty(), "U+FFFD in detail must be rejected");
}

#[test]
fn rejects_oversize_title() {
    let mut v: Vec<Finding> = Vec::new();
    // Default max_title_len is 10_240; go a hair past.
    let title = "x".repeat(10_241);
    let b = Finding::builder("scanner", "example.com", Severity::Info)
        .title(title)
        .detail("ok");
    try_push_finding(b, &mut v);
    assert!(v.is_empty(), "oversize title must be rejected");
}

#[test]
fn rejects_oversize_detail() {
    let mut v: Vec<Finding> = Vec::new();
    // Default max_detail_len is 1 MiB; cross by one byte.
    let detail = "x".repeat(1_048_577);
    let b = Finding::builder("scanner", "example.com", Severity::Info)
        .title("ok")
        .detail(detail);
    try_push_finding(b, &mut v);
    assert!(v.is_empty(), "oversize detail must be rejected");
}

#[test]
fn good_after_bad_still_pushes() {
    let mut v: Vec<Finding> = Vec::new();
    let bad = Finding::builder("scanner", "example.com", Severity::Info)
        .title("bad\0title")
        .detail("ok");
    try_push_finding(bad, &mut v);
    try_push_finding(ok_builder("scanner-good"), &mut v);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].scanner(), "scanner-good");
}
