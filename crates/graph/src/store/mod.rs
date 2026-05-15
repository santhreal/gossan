//! Storage backends for the attack-surface graph.

pub mod graphml;
pub mod json;
pub mod memory;
pub mod sqlite;

use crate::{schema::EdgeType, Edge, Node};

/// Abstract storage backend for graph operations.
pub trait GraphBackend {
    /// Error type returned by this backend.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Initialize the backend (create tables/files, run migrations).
    fn init(&mut self) -> Result<(), Self::Error>;

    /// Persist a batch of nodes.
    fn write_nodes(&mut self, nodes: &[Node]) -> Result<(), Self::Error>;

    /// Persist a batch of edges.
    fn write_edges(&mut self, edges: &[Edge]) -> Result<(), Self::Error>;

    /// Read all nodes.
    fn read_nodes(&self) -> Result<Vec<Node>, Self::Error>;

    /// Read all edges.
    fn read_edges(&self) -> Result<Vec<Edge>, Self::Error>;

    /// Find nodes by type.
    fn find_nodes_by_type(&self, kind: crate::schema::NodeType) -> Result<Vec<Node>, Self::Error>;

    /// Find outgoing edges from a node, optionally filtered by edge type.
    fn neighbors(
        &self,
        node_id: &str,
        edge_type: Option<EdgeType>,
    ) -> Result<Vec<Edge>, Self::Error>;

    /// Clear all data.
    fn clear(&mut self) -> Result<(), Self::Error>;
}
