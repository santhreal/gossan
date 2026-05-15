//! Query layer for graph traversal.

use crate::store::GraphBackend;
use crate::{schema::EdgeType, Edge, Node};
use std::collections::{HashSet, VecDeque};

/// Find all nodes of a given type.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn find_all<B: GraphBackend>(
    backend: &B,
    kind: crate::schema::NodeType,
) -> Result<Vec<Node>, B::Error> {
    backend.find_nodes_by_type(kind)
}

/// Find outgoing edges from a node, optionally filtered by edge type.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn neighbors<B: GraphBackend>(
    backend: &B,
    node_id: &str,
    edge_type: Option<EdgeType>,
) -> Result<Vec<Edge>, B::Error> {
    backend.neighbors(node_id, edge_type)
}

/// Find a path from `start` to `goal` using BFS over edges.
///
/// Returns the list of node ids forming the path, or `None` if unreachable.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn path<B: GraphBackend>(
    backend: &B,
    start: &str,
    goal: &str,
) -> Result<Option<Vec<String>>, B::Error> {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    let mut parents: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    visited.insert(start.to_string());
    queue.push_back(start.to_string());

    while let Some(current) = queue.pop_front() {
        if current == goal {
            let mut path = vec![goal.to_string()];
            let mut cursor = goal.to_string();
            while let Some(parent) = parents.get(&cursor) {
                path.push(parent.clone());
                cursor = parent.clone();
            }
            path.reverse();
            return Ok(Some(path));
        }

        for edge in backend.neighbors(&current, None)? {
            if visited.insert(edge.target_id.clone()) {
                parents.insert(edge.target_id.clone(), current.clone());
                queue.push_back(edge.target_id.clone());
            }
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::NodeType;
    use crate::store::sqlite::SqliteBackend;

    #[test]
    fn find_all_filters_by_type() {
        let mut backend = SqliteBackend::open_in_memory().unwrap();
        backend
            .write_nodes(&[
                Node::new("d1", NodeType::Domain, "example.com"),
                Node::new("s1", NodeType::Subdomain, "sub.example.com"),
            ])
            .unwrap();

        let domains = find_all(&backend, NodeType::Domain).unwrap();
        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].id, "d1");
    }

    #[test]
    fn neighbors_returns_only_matching_edges() {
        let mut backend = SqliteBackend::open_in_memory().unwrap();
        backend
            .write_edges(&[
                Edge::new("a", "b", EdgeType::ResolvesTo),
                Edge::new("a", "c", EdgeType::Hosts),
                Edge::new("b", "d", EdgeType::ResolvesTo),
            ])
            .unwrap();

        let all = neighbors(&backend, "a", None).unwrap();
        assert_eq!(all.len(), 2);

        let hosts_only = neighbors(&backend, "a", Some(EdgeType::Hosts)).unwrap();
        assert_eq!(hosts_only.len(), 1);
        assert_eq!(hosts_only[0].target_id, "c");
    }

    #[test]
    fn path_finds_shortest_route() {
        let mut backend = SqliteBackend::open_in_memory().unwrap();
        backend
            .write_edges(&[
                Edge::new("a", "b", EdgeType::ResolvesTo),
                Edge::new("b", "c", EdgeType::Hosts),
                Edge::new("c", "d", EdgeType::Exposes),
                // Longer route a -> e -> d
                Edge::new("a", "e", EdgeType::ResolvesTo),
                Edge::new("e", "d", EdgeType::Exposes),
            ])
            .unwrap();

        let p = path(&backend, "a", "d").unwrap();
        assert_eq!(
            p,
            Some(vec!["a".to_string(), "e".to_string(), "d".to_string()])
        );
    }

    #[test]
    fn path_none_when_disconnected() {
        let mut backend = SqliteBackend::open_in_memory().unwrap();
        backend
            .write_edges(&[Edge::new("a", "b", EdgeType::ResolvesTo)])
            .unwrap();

        let p = path(&backend, "a", "z").unwrap();
        assert_eq!(p, None);
    }
}
