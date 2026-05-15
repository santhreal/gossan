//! Property tests for the in-memory graph backend.
//!
//! Per GOSSAN_LEGENDARY A18: arbitrary `Vec<Node> + Vec<Edge>`
//! round-trips through the backend without loss.

use gossan_graph::schema::{EdgeType, NodeType};
use gossan_graph::store::memory::MemoryStore;
use gossan_graph::store::GraphBackend;
use gossan_graph::{Edge, Node};
use proptest::prelude::*;

const NODE_KINDS: &[NodeType] = &[
    NodeType::Domain,
    NodeType::Subdomain,
    NodeType::Ip,
    NodeType::Port,
    NodeType::Service,
    NodeType::Tech,
    NodeType::Endpoint,
    NodeType::Secret,
    NodeType::Cloud,
    NodeType::Finding,
];
const EDGE_KINDS: &[EdgeType] = &[
    EdgeType::ResolvesTo,
    EdgeType::Hosts,
    EdgeType::Runs,
    EdgeType::Exposes,
    EdgeType::Leaks,
    EdgeType::Misconfigured,
    EdgeType::HasFinding,
    EdgeType::HasService,
];

fn node_strategy() -> impl Strategy<Value = Node> {
    ("[a-z][a-z0-9_-]{0,31}", any::<u8>()).prop_map(|(id, kind_idx)| {
        let kind = NODE_KINDS[(kind_idx as usize) % NODE_KINDS.len()];
        Node::new(id.clone(), kind, id)
    })
}

fn edge_strategy() -> impl Strategy<Value = Edge> {
    (
        "[a-z][a-z0-9_-]{0,15}",
        "[a-z][a-z0-9_-]{0,15}",
        any::<u8>(),
    )
        .prop_map(|(src, dst, kind_idx)| {
            let kind = EDGE_KINDS[(kind_idx as usize) % EDGE_KINDS.len()];
            Edge::new(src, dst, kind)
        })
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn round_trip_arbitrary_nodes_and_edges(
        nodes in prop::collection::vec(node_strategy(), 0..50),
        edges in prop::collection::vec(edge_strategy(), 0..100),
    ) {
        let mut s = MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&nodes).unwrap();
        s.write_edges(&edges).unwrap();
        prop_assert_eq!(s.read_nodes().unwrap().len(), nodes.len());
        prop_assert_eq!(s.read_edges().unwrap().len(), edges.len());
    }

    #[test]
    fn neighbors_filtered_by_edge_type(
        edges in prop::collection::vec(edge_strategy(), 1..50),
    ) {
        let mut s = MemoryStore::new();
        s.init().unwrap();
        s.write_edges(&edges).unwrap();
        let target_kind = edges[0].kind;
        for e in &edges {
            let neighbors = s.neighbors(&e.source_id, Some(target_kind)).unwrap();
            for n in &neighbors {
                prop_assert_eq!(n.source_id.as_str(), e.source_id.as_str());
                prop_assert_eq!(n.kind, target_kind);
            }
        }
    }

    #[test]
    fn clear_resets_state(nodes in prop::collection::vec(node_strategy(), 0..50)) {
        let mut s = MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&nodes).unwrap();
        s.clear().unwrap();
        prop_assert!(s.read_nodes().unwrap().is_empty());
        prop_assert!(s.read_edges().unwrap().is_empty());
    }
}
