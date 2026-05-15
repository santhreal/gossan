//! # gossan-classify
//!
//! Banner classification and service fingerprinting engine.
//!
//! Takes raw TCP banner responses and classifies them into:
//! - Service type (HTTP, SSH, FTP, MySQL, Redis, etc.)
//! - Version extraction (Apache 2.4.52, OpenSSH 8.9, etc.)
//! - OS hints from protocol behavior
//! - Security posture signals (default creds, debug mode, info leaks)
//!
//! Classification rules are TOML-defined for community contribution.
//! The engine supports both CPU (regex) and optional GPU (Vyre) backends.

#![allow(clippy::module_name_repetitions)]

pub mod rules;
pub mod matcher;
pub mod classifier;

pub use classifier::BannerClassifier;
pub use rules::{ServiceMatch, ServiceRule};
