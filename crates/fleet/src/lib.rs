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

//! Distributed gossan scanning — master/worker fleet coordination.
//!
//! The master distributes targets across workers and aggregates findings.

pub mod master;
pub mod observability;
pub mod worker;

pub mod proto {
    tonic::include_proto!("gossan.fleet");
}
