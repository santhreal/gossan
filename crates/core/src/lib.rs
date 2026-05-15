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
//! - **[`Target`]** — the tagged enum flowing through the pipeline
//!   (`Domain → Host → Service → Web`)
//! - **[`Scanner`]** — the async trait every scanner module implements
//! - **[`Config`]** — global scan configuration (timeouts, concurrency, modules)
//! - **[`Finding`]** / **[`Evidence`]** — security findings (via [`secfinding`])
//!
//! All 14 scanner crates depend on `gossan-core` for these shared types.

pub mod accuracy;
pub mod config;
pub mod error;
pub mod finding;
pub mod net;
pub mod ratelimit;
pub mod scanner;
pub mod target;
pub mod transport;

pub use accuracy::{calculate_fuzzy_hash, generate_dom_fingerprint, ResponseBaseline};
pub use config::{
    ApiKeys, Config, CrawlConfig, ModuleConfig, OutputConfig, OutputFormat, PortMode,
};
pub use error::Error;
pub use finding::{make_finding, try_push_finding, Evidence, Finding, FindingKind, Severity};
pub use net::connect_tcp;
pub use ratelimit::{
    build_client, get_with_backoff, read_response_limited, send_with_backoff, HostRateLimiter,
};
pub use reqwest;
pub use scanner::{ScanInput, Scanner};
pub use target::{
    DiscoveredForm, DiscoveredParam, DiscoverySource, DomainTarget, HostTarget, NetworkTarget,
    ParamLocation, ParamSource, Protocol, ServiceTarget, Target, TechCategory, Technology,
    WebAssetTarget,
};
pub use transport::ScanClient;
