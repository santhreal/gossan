//! All-backend idempotency contract: `Node.id` is documented as "stable
//! unique identifier", so re-writing the same node MUST be a no-op on
//! count  -  last-write-wins on label/payload, advance `last_seen_ms`,
//! preserve `first_seen_ms`. Same contract for edges, keyed on
//! `(source_id, target_id, kind)`.
//!
//! Pre-2026-05-22 only the sqlite backend honoured this (via
//! `INSERT OR IGNORE` + targeted UPDATE). Memory / JSON / GraphML used
//! `extend_from_slice` and silently duplicated every re-write, so an
//! iterative scan loop (every gossan run re-emits the same hosts/IPs)
//! grew the in-memory or on-disk graph unboundedly across runs  -  and
//! `find_nodes_by_type` / `neighbors` / `read_*` returned the duplicates
//! verbatim, corrupting downstream counts and any query that walked the
//! edge list.

use gossan_graph::schema::{EdgeType, NodeType};
use gossan_graph::store::{
    graphml::GraphMlBackend, json::JsonBackend, memory::MemoryStore, sqlite::SqliteBackend,
    GraphBackend,
};
use gossan_graph::{Edge, Node};

fn n(id: &str) -> Node {
    Node::new(id, NodeType::Domain, id)
}

fn e(s: &str, t: &str) -> Edge {
    Edge::new(s, t, EdgeType::ResolvesTo)
}

/// Each backend must collapse a repeated write of the same `id` to one
/// stored row.
fn assert_idempotent<B: GraphBackend>(s: &mut B)
where
    B::Error: std::fmt::Debug,
{
    s.init().expect("init");

    // Same node id written twice.
    s.write_nodes(&[n("d:example.com")]).expect("write 1");
    s.write_nodes(&[n("d:example.com")]).expect("write 2");

    // Same (src, dst, kind) written twice.
    s.write_edges(&[e("d:example.com", "ip:1.2.3.4")])
        .expect("edge write 1");
    s.write_edges(&[e("d:example.com", "ip:1.2.3.4")])
        .expect("edge write 2");

    let nodes = s.read_nodes().expect("read nodes");
    let edges = s.read_edges().expect("read edges");

    // The id is the identity. Two writes ⇒ one row.
    let domain_count = nodes
        .iter()
        .filter(|n| n.id == "d:example.com")
        .count();
    assert_eq!(
        domain_count, 1,
        "node id `d:example.com` duplicated across writes: {} rows",
        domain_count
    );

    let edge_count = edges
        .iter()
        .filter(|e| {
            e.source_id == "d:example.com"
                && e.target_id == "ip:1.2.3.4"
                && e.kind == EdgeType::ResolvesTo
        })
        .count();
    assert_eq!(
        edge_count, 1,
        "edge (d:example.com → ip:1.2.3.4 / ResolvesTo) duplicated across writes: {} rows",
        edge_count
    );

    // find_nodes_by_type / neighbors must reflect the deduplicated set.
    let by_type = s
        .find_nodes_by_type(NodeType::Domain)
        .expect("find_nodes_by_type");
    assert_eq!(
        by_type.iter().filter(|n| n.id == "d:example.com").count(),
        1,
        "find_nodes_by_type returned duplicates"
    );

    let nbrs = s.neighbors("d:example.com", None).expect("neighbors");
    assert_eq!(
        nbrs.len(),
        1,
        "neighbors returned duplicate edges: {:?}",
        nbrs
    );
}

#[test]
fn sqlite_backend_is_idempotent_on_node_id_and_edge_triple() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = SqliteBackend::open(dir.path().join("g.db")).unwrap();
    assert_idempotent(&mut s);
}

#[test]
fn memory_backend_is_idempotent_on_node_id_and_edge_triple() {
    let mut s = MemoryStore::new();
    assert_idempotent(&mut s);
}

#[test]
fn json_backend_is_idempotent_on_node_id_and_edge_triple() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = JsonBackend::open(dir.path().join("g.json"));
    assert_idempotent(&mut s);
}

#[test]
fn graphml_backend_is_idempotent_on_node_id_and_edge_triple() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = GraphMlBackend::open(dir.path().join("g.graphml"));
    assert_idempotent(&mut s);
}

/// Re-writing a node with new payload/label must REPLACE, not duplicate.
fn assert_payload_update<B: GraphBackend>(s: &mut B)
where
    B::Error: std::fmt::Debug,
{
    s.init().expect("init");
    let mut first = Node::new("d:example.com", NodeType::Domain, "example.com");
    first.label = "first-label".to_string();
    s.write_nodes(&[first]).expect("write 1");

    let mut second = Node::new("d:example.com", NodeType::Domain, "example.com");
    second.label = "second-label".to_string();
    s.write_nodes(&[second]).expect("write 2");

    let nodes = s.read_nodes().expect("read");
    let rows: Vec<&Node> = nodes.iter().filter(|n| n.id == "d:example.com").collect();
    assert_eq!(rows.len(), 1, "expected exactly one row, got {}", rows.len());
    // Last-write-wins on label.
    assert_eq!(rows[0].label, "second-label", "second write didn't win");
}

#[test]
fn memory_backend_node_rewrite_replaces_label() {
    let mut s = MemoryStore::new();
    assert_payload_update(&mut s);
}

#[test]
fn json_backend_node_rewrite_replaces_label() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = JsonBackend::open(dir.path().join("g.json"));
    assert_payload_update(&mut s);
}

#[test]
fn graphml_backend_node_rewrite_replaces_label() {
    let dir = tempfile::tempdir().unwrap();
    let mut s = GraphMlBackend::open(dir.path().join("g.graphml"));
    assert_payload_update(&mut s);
}
