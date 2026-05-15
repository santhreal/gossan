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
    clippy::missing_errors_doc,
)]

//! Attack-surface graph — typed schema, multiple backends, and query layer.
//!
//! # Backends
//! - [`store::sqlite::SqliteBackend`] — persistent SQLite with temporal diffing.
//! - [`store::json::JsonBackend`] — JSON/JSONL export, auto-streams past 10K nodes.
//! - [`store::graphml::GraphMlBackend`] — GraphML for network-analysis tools.
//!
//! # Query layer
//! - [`query::find_all`] — nodes by type.
//! - [`query::neighbors`] — outgoing edges from a node.
//! - [`query::path`] — BFS shortest path between two nodes.

pub mod edge;
pub mod node;
pub mod query;
pub mod schema;
pub mod store;

pub use edge::Edge;
pub use node::Node;

// Re-export schema types
pub use schema::{EdgeType, GraphSchema, NodeType, SchemaError, SCHEMA_VERSION};

// Re-export store backends and traits
pub use store::graphml::GraphMlBackend;
pub use store::json::JsonBackend;
pub use store::sqlite::{ScanDiff, SqliteBackend};
pub use store::GraphBackend;

// Re-export query helpers
pub use query::{find_all, neighbors, path};

// Re-export legacy compatibility items from the sqlite backend.
pub use store::sqlite::target_id_from_finding;
// Public deterministic ID for a `Target` — see `store::sqlite::target_id`
// for shape (`domain:<host>` / `host:<ip>` / etc.). Re-exported at
// crate root so callers can call it without spelling the backend
// path; legendary unit test depends on this for ID-format pinning.
pub use store::sqlite::target_id;
