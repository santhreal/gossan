//! Deduplication logic for findings.
//!
//! Thin re-export of the canonical implementation in
//! [`gossan_core::dedup`]. Used to be a 220-line copy that lived in
//! this crate alongside a *separate* 268-line copy in
//! `gossan_graph::correlation::dedup`. The two had silently diverged
//! on the security-critical wildcard-bucket key — the copy here
//! keyed the wildcard bucket on the stripped parent, which collided
//! with the apex host and silently dropped distinct apex findings
//! (e.g. a Critical RCE on `example.com` swallowed by `*.example.com`).
//! The canonical implementation is now the corrected one from the
//! graph copy and carries the apex-RCE adversarial regression test.
//!
//! Kept as a re-export instead of removed so consumers of
//! `gossan_correlation::dedup` continue to compile (LAW 2 —
//! backwards-compatible API surface).

pub use gossan_core::dedup::{
    dedup_findings, is_wildcard_covered, normalize_host, strip_wildcard,
};
