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

extern crate self as reqwest;
pub use stealthreq::http::{header, redirect};
pub use stealthreq::http::{Client, Method, Proxy, Request, Response, StatusCode, Url};

pub mod config;
pub mod error;
pub mod finding;
pub mod net;
pub mod ratelimit;
pub mod scanner;
pub mod target;

pub use config::{
    ApiKeys, Config, CrawlConfig, ModuleConfig, OutputConfig, OutputFormat, PortMode,
};
pub use error::Error;
pub use finding::{make_finding, Evidence, Finding, FindingExt, Severity};
pub use net::connect_tcp;
pub use ratelimit::{build_client, get_with_backoff, send_with_backoff, HostRateLimiter};
pub use scanner::{ScanInput, ScanOutput, Scanner};
pub use target::{
    DiscoveredForm, DiscoveredParam, DiscoverySource, DomainTarget, HostTarget, ParamLocation,
    ParamSource, Protocol, ServiceTarget, Target, TechCategory, Technology, WebAssetTarget,
};
