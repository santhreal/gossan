#![forbid(unsafe_code)]
// pedantic moved to workspace [lints.clippy] in root Cargo.toml
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc
)]

//! Core types and traits for the Gossan attack surface scanner.
//!
//! This crate defines the foundational pipeline architecture:
//!
//! - **[`Target`]**: the tagged enum flowing through the pipeline
//!   (`Domain → Host → Service → Web`)
//! - **[`Scanner`]**: the async trait every scanner module implements
//! - **[`Config`]**: global scan configuration (timeouts, concurrency, modules)
//! - **[`Finding`]** / **[`Evidence`]**: security findings (via [`secfinding`])
//!
//! All 14 scanner crates depend on `gossan-core` for these shared types.

pub mod accuracy;
pub mod config;
pub mod ports;
pub use ports::{resolve_ports, EPHEMERAL_PORT_COUNT, EPHEMERAL_PORT_START};
/// Canonical MurmurHash3 x86_32 + Shodan favicon-hash. Three scanners
/// (hidden, horizontal, origin) previously had private copies of this
/// algorithm. This module is the single canonical source; callers should
/// migrate their private copies to `gossan_core::hashing::mmh3_x86_32`.
pub mod hashing;
// Canonical host normalisation used by dedup, target-classification,
// and scanner output. Previously a stray sibling file alongside
// `domain.rs` whose contents nobody could reach because the module
// wasn't declared; promoted so the canonical dedup path
// (`crate::dedup`) and external callers (gossan correlation /
// graph) can share one normaliser.
pub mod domain;
pub mod error;
pub mod finding;
pub mod net;
pub mod ratelimit;
pub(crate) mod scanclient_bridge;
pub mod scanner;
pub mod target;
pub mod testkit;
pub mod text;
pub mod transport;

// Canonical finding deduplication. Used to live in two places
// (`gossan::correlation::dedup` and
// `gossan::graph::correlation::dedup`) that had silently diverged
// on the security-critical wildcard-bucket key. See `dedup.rs` for
// the apex-RCE adversarial test that pins the correct behaviour.
pub mod dedup;

pub use accuracy::{calculate_fuzzy_hash, generate_dom_fingerprint, ResponseBaseline};
pub use config::{
    ApiKeys, Config, CrawlConfig, ModuleConfig, OutputConfig, OutputFormat, PortMode,
};
pub use error::Error;
pub use finding::{make_finding, try_push_finding, Evidence, Finding, FindingKind, Severity};
pub use hashing::{mmh3_x86_32, shodan_favicon_hash};
pub use net::connect_tcp;
pub use ratelimit::{
    build_client, get_with_backoff, read_response_limited, send_with_backoff, HostRateLimiter,
};
pub use scanclient::reqwest;
pub use scanner::{ScanInput, Scanner};
pub use target::{
    DiscoveredForm, DiscoveredParam, DiscoverySource, DomainTarget, HostTarget, NetworkTarget,
    ParamLocation, ParamSource, Protocol, ServiceTarget, Target, TechCategory, Technology,
    WebAssetTarget,
};
pub use text::{xml_escape, xml_unescape};
pub use transport::ScanClient;
