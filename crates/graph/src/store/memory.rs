//! In-memory graph backend.
//!
//! Holds nodes + edges in `Vec`s. Useful for short-lived scans where
//! the persistence cost of sqlite/graphml/json isn't justified, and as
//! the simplest implementation against which the
//! [`GraphBackend`] trait shape can be verified.

use crate::schema::{EdgeType, NodeType};
use crate::{Edge, Node};

use super::GraphBackend;

/// Errors returned by the in-memory backend.
#[derive(Debug)]
pub struct MemoryError(String);

impl std::fmt::Display for MemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for MemoryError {}

/// In-memory store of nodes and edges.
#[derive(Debug, Default, Clone)]
pub struct MemoryStore {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
}

impl MemoryStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl GraphBackend for MemoryStore {
    type Error = MemoryError;

    fn init(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn write_nodes(&mut self, nodes: &[Node]) -> Result<(), Self::Error> {
        self.nodes.extend_from_slice(nodes);
        Ok(())
    }

    fn write_edges(&mut self, edges: &[Edge]) -> Result<(), Self::Error> {
        self.edges.extend_from_slice(edges);
        Ok(())
    }

    fn read_nodes(&self) -> Result<Vec<Node>, Self::Error> {
        Ok(self.nodes.clone())
    }

    fn read_edges(&self) -> Result<Vec<Edge>, Self::Error> {
        Ok(self.edges.clone())
    }

    fn find_nodes_by_type(&self, kind: NodeType) -> Result<Vec<Node>, Self::Error> {
        Ok(self
            .nodes
            .iter()
            .filter(|n| n.kind == kind)
            .cloned()
            .collect())
    }

    fn neighbors(
        &self,
        node_id: &str,
        edge_type: Option<EdgeType>,
    ) -> Result<Vec<Edge>, Self::Error> {
        Ok(self
            .edges
            .iter()
            .filter(|e| e.source_id == node_id)
            .filter(|e| edge_type.map_or(true, |t| e.kind == t))
            .cloned()
            .collect())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.nodes.clear();
        self.edges.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EdgeType, NodeType};

    fn sample_node(id: &str, kind: NodeType) -> Node {
        Node::new(id, kind, id)
    }

    fn sample_edge(src: &str, dst: &str, kind: EdgeType) -> Edge {
        Edge::new(src, dst, kind)
    }

    #[test]
    fn memory_store_roundtrip() {
        let mut s = MemoryStore::new();
        s.init().expect("init");
        let nodes = vec![
            sample_node("d1", NodeType::Domain),
            sample_node("h1", NodeType::Ip),
        ];
        let edges = vec![sample_edge("d1", "h1", EdgeType::ResolvesTo)];
        s.write_nodes(&nodes).unwrap();
        s.write_edges(&edges).unwrap();

        let read_nodes = s.read_nodes().unwrap();
        let read_edges = s.read_edges().unwrap();
        assert_eq!(read_nodes.len(), 2);
        assert_eq!(read_edges.len(), 1);
    }

    #[test]
    fn memory_find_by_type_and_neighbors() {
        let mut s = MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[
            sample_node("d1", NodeType::Domain),
            sample_node("d2", NodeType::Domain),
            sample_node("h1", NodeType::Ip),
        ])
        .unwrap();
        s.write_edges(&[
            sample_edge("d1", "h1", EdgeType::ResolvesTo),
            sample_edge("d2", "h1", EdgeType::ResolvesTo),
        ])
        .unwrap();

        let domains = s.find_nodes_by_type(NodeType::Domain).unwrap();
        assert_eq!(domains.len(), 2);
        let hosts = s.find_nodes_by_type(NodeType::Ip).unwrap();
        assert_eq!(hosts.len(), 1);

        let from_d1 = s.neighbors("d1", None).unwrap();
        assert_eq!(from_d1.len(), 1);
        assert_eq!(from_d1[0].target_id, "h1");
    }

    #[test]
    fn memory_clear_resets_state() {
        let mut s = MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[sample_node("d1", NodeType::Domain)])
            .unwrap();
        assert_eq!(s.read_nodes().unwrap().len(), 1);
        s.clear().unwrap();
        assert!(s.read_nodes().unwrap().is_empty());
    }
}
