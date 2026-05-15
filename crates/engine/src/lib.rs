//! # gossan-engine
//!
//! High-performance stateless SYN scanner and banner grabber.
//!
//! Replaces `gossan-synscan` with an architecture designed to beat masscan:
//!
//! - **Stateless SYN scanning** via [`netforge::SeqEncoder`] (zero per-connection state)
//! - **Randomized scan order** via [`schedule::BlackrockPermutation`] (IDS evasion)
//! - **Batch packet I/O** via [`netforge::PacketEngine`] (sendmmsg / AF_XDP)
//! - **Lock-free result pipeline** via crossbeam SPSC channels
//! - **Token-bucket rate control** with sub-microsecond precision
//!
//! ## Usage as a Gossan Scanner
//!
//! ```rust,ignore
//! use gossan_engine::EngineScanner;
//! let scanner = EngineScanner::default();
//! scanner.run(input, &config).await?;
//! ```

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

pub mod icmp_backoff;
pub mod probe;
pub mod rate;
pub mod scan;
pub mod schedule;

pub use probe::{probe, Backend, ProbeReport};
pub use scan::EngineScanner;
