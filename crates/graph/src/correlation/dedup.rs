//! Deduplication logic for findings.
//!
//! Thin re-export of the canonical implementation in
//! [`gossan_core::dedup`]. Used to be a 268-line copy that lived in
//! this module — the corrected version after `gossan_correlation::dedup`
//! shipped a wildcard-bucket key bug that collapsed the apex host
//! into the wildcard and silently dropped distinct apex findings.
//! Both copies now delegate to one canonical implementation in
//! gossan_core, which is the corrected version and carries the
//! apex-RCE adversarial regression test.
//!
//! Kept as a re-export instead of removed so consumers of
//! `gossan_graph::correlation::dedup` continue to compile
//! (LAW 2 — backwards-compatible API surface).

pub use gossan_core::dedup::{
    dedup_findings, is_wildcard_covered, normalize_host, strip_wildcard,
};
