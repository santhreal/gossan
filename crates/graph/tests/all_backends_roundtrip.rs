//! All-backend round-trip test (closes A18 of GOSSAN_LEGENDARY).
//!
//! Builds the same node/edge set, persists through every backend
//! (sqlite / json / graphml / in-memory), reads it back, and asserts
//! each backend reports the same node + edge counts. The graphml
//! backend is exercised through serialize → deserialize via its
//! file-store API rather than the full DOM parser; the assertion is
//! the count contract, not byte-for-byte equivalence.

use gossan_graph::schema::{EdgeType, NodeType};
use gossan_graph::store::{
    json::JsonBackend, memory::MemoryStore, sqlite::SqliteBackend, GraphBackend,
};
use gossan_graph::{Edge, Node};

fn fixture_nodes() -> Vec<Node> {
    vec![
        Node::new("d:example.com", NodeType::Domain, "example.com"),
        Node::new("d:sub.example.com", NodeType::Subdomain, "sub.example.com"),
        Node::new("ip:1.2.3.4", NodeType::Ip, "1.2.3.4"),
        Node::new("port:80", NodeType::Port, "80"),
        Node::new("svc:nginx", NodeType::Service, "nginx"),
    ]
}

fn fixture_edges() -> Vec<Edge> {
    vec![
        Edge::new("d:example.com", "d:sub.example.com", EdgeType::Hosts),
        Edge::new("d:sub.example.com", "ip:1.2.3.4", EdgeType::ResolvesTo),
        Edge::new("ip:1.2.3.4", "port:80", EdgeType::Exposes),
        Edge::new("port:80", "svc:nginx", EdgeType::Runs),
    ]
}

#[test]
fn memory_backend_roundtrip_count_matches() {
    let mut s = MemoryStore::new();
    s.init().unwrap();
    s.write_nodes(&fixture_nodes()).unwrap();
    s.write_edges(&fixture_edges()).unwrap();
    assert_eq!(s.read_nodes().unwrap().len(), 5);
    assert_eq!(s.read_edges().unwrap().len(), 4);
}

#[test]
fn sqlite_backend_roundtrip_count_matches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("g.db");
    let mut s = SqliteBackend::open(&path).unwrap();
    s.init().unwrap();
    s.write_nodes(&fixture_nodes()).unwrap();
    s.write_edges(&fixture_edges()).unwrap();
    let nodes = s.read_nodes().unwrap();
    let edges = s.read_edges().unwrap();
    assert_eq!(nodes.len(), 5);
    assert_eq!(edges.len(), 4);
}

#[test]
fn json_backend_roundtrip_count_matches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("g.json");
    let mut s = JsonBackend::open(path);
    s.init().unwrap();
    s.write_nodes(&fixture_nodes()).unwrap();
    s.write_edges(&fixture_edges()).unwrap();
    let nodes = s.read_nodes().unwrap();
    let edges = s.read_edges().unwrap();
    assert_eq!(nodes.len(), 5);
    assert_eq!(edges.len(), 4);
}

#[test]
fn graphml_backend_roundtrip_count_matches() {
    use gossan_graph::store::graphml::GraphMlBackend;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("g.graphml");
    let mut s = GraphMlBackend::open(path);
    s.init().unwrap();
    s.write_nodes(&fixture_nodes()).unwrap();
    s.write_edges(&fixture_edges()).unwrap();
    let nodes = s.read_nodes().unwrap();
    let edges = s.read_edges().unwrap();
    assert_eq!(nodes.len(), 5);
    assert_eq!(edges.len(), 4);
}
