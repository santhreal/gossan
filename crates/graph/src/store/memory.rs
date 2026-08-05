//! In-memory graph backend.
//!
//! Holds nodes + edges in `Vec`s. Useful for short-lived scans where
//! the persistence cost of sqlite/graphml/json isn't justified, and as
//! the simplest implementation against which the
//! [`GraphBackend`] trait shape can be verified.

use std::collections::HashMap;

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
    nodes: HashMap<String, Node>,
    adjacency: HashMap<String, Vec<Edge>>,
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
        for node in nodes {
            if let Some(existing) = self.nodes.get_mut(&node.id) {
                existing.kind = node.kind;
                existing.label = node.label.clone();
                existing.payload = node.payload.clone();
                existing.last_seen_ms = node.last_seen_ms;
            } else {
                self.nodes.insert(node.id.clone(), node.clone());
            }
        }
        Ok(())
    }

    fn write_edges(&mut self, edges: &[Edge]) -> Result<(), Self::Error> {
        for edge in edges {
            let out = self.adjacency.entry(edge.source_id.clone()).or_default();
            if let Some(existing) = out
                .iter_mut()
                .find(|e| e.target_id == edge.target_id && e.kind == edge.kind)
            {
                existing.payload = edge.payload.clone();
                existing.last_seen_ms = edge.last_seen_ms;
            } else {
                out.push(edge.clone());
            }
        }
        Ok(())
    }

    fn read_nodes(&self) -> Result<Vec<Node>, Self::Error> {
        Ok(self.nodes.values().cloned().collect())
    }

    fn read_edges(&self) -> Result<Vec<Edge>, Self::Error> {
        Ok(self.adjacency.values().flatten().cloned().collect())
    }

    fn find_nodes_by_type(&self, kind: NodeType) -> Result<Vec<Node>, Self::Error> {
        Ok(self
            .nodes
            .values()
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
            .adjacency
            .get(node_id)
            .map_or_else(Vec::new, |out| {
                out.iter()
                    .filter(|e| edge_type.map_or(true, |t| e.kind == t))
                    .cloned()
                    .collect()
            }))
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.nodes.clear();
        self.adjacency.clear();
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
    fn deduplicates_nodes_by_id() {
        let mut s = MemoryStore::new();
        let mut first = sample_node("d1", NodeType::Domain);
        first.label = "first".to_string();
        s.write_nodes(&[first]).unwrap();

        let mut second = sample_node("d1", NodeType::Ip);
        second.label = "second".to_string();
        s.write_nodes(&[second]).unwrap();

        let nodes = s.read_nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].label, "second");
        assert_eq!(nodes[0].kind, NodeType::Ip);
    }

    #[test]
    fn deduplicates_edges_by_triple() {
        let mut s = MemoryStore::new();
        s.write_edges(&[sample_edge("d1", "h1", EdgeType::ResolvesTo)])
            .unwrap();
        s.write_edges(&[sample_edge("d1", "h1", EdgeType::ResolvesTo)])
            .unwrap();
        assert_eq!(s.read_edges().unwrap().len(), 1);
    }

    #[test]
    fn neighbors_uses_adjacency_map() {
        let mut s = MemoryStore::new();
        s.write_edges(&[
            sample_edge("d1", "h1", EdgeType::ResolvesTo),
            sample_edge("d1", "h2", EdgeType::ResolvesTo),
            sample_edge("h1", "p1", EdgeType::Exposes),
        ])
        .unwrap();

        let all = s.neighbors("d1", None).unwrap();
        assert_eq!(all.len(), 2);

        let typed = s.neighbors("d1", Some(EdgeType::ResolvesTo)).unwrap();
        assert_eq!(typed.len(), 2);

        let other = s.neighbors("h1", None).unwrap();
        assert_eq!(other.len(), 1);
    }

    #[test]
    fn first_seen_preserved_on_rewrite() {
        let mut s = MemoryStore::new();
        let mut first = sample_node("d1", NodeType::Domain);
        first.first_seen_ms = 42;
        first.last_seen_ms = 42;
        s.write_nodes(&[first]).unwrap();

        let mut second = sample_node("d1", NodeType::Domain);
        second.first_seen_ms = 100;
        second.last_seen_ms = 100;
        s.write_nodes(&[second]).unwrap();

        let nodes = s.read_nodes().unwrap();
        assert_eq!(nodes[0].first_seen_ms, 42);
        assert_eq!(nodes[0].last_seen_ms, 100);
    }
}
