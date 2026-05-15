//! Graph-store insert perf gate.
//!
//! Per GOSSAN_LEGENDARY Section F: persisting 10k nodes must complete
//! in under 1 second on a release build. Catches regressions in the
//! SQLite write path (missing transaction, accidental flushes,
//! schema-migration cost creeping in).

use gossan_core::{
    target::{DiscoverySource, DomainTarget},
    Target,
};
use gossan_graph::SqliteBackend;
use std::time::{Duration, Instant};

const NODE_COUNT: usize = 10_000;
const MAX_ELAPSED: Duration = Duration::from_secs(1);

#[test]
#[cfg(not(debug_assertions))]
fn graph_insert_10k_nodes_under_1s() {
    let mut backend = SqliteBackend::open(":memory:").expect("in-memory backend opens");
    let targets: Vec<Target> = (0..NODE_COUNT)
        .map(|i| {
            Target::Domain(DomainTarget {
                domain: format!("host{i}.example.com"),
                source: DiscoverySource::Seed,
            })
        })
        .collect();

    let start = Instant::now();
    backend
        .persist_scan(&targets, &[])
        .expect("persist_scan succeeds with empty findings");
    let elapsed = start.elapsed();

    eprintln!(
        "graph insert: {NODE_COUNT} nodes in {elapsed:?} ({:.0}/s)",
        NODE_COUNT as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < MAX_ELAPSED,
        "graph insert: {NODE_COUNT} nodes took {elapsed:?}, > {MAX_ELAPSED:?} regression gate"
    );
}

#[test]
#[cfg(not(debug_assertions))]
fn graph_insert_100k_edges_under_5s() {
    use gossan_graph::schema::{EdgeType, NodeType};
    use gossan_graph::store::memory::MemoryStore;
    use gossan_graph::store::GraphBackend;
    use gossan_graph::{Edge, Node};

    const E: usize = 100_000;
    let mut s = MemoryStore::new();
    s.init().expect("init");
    // Two nodes are enough to terminate edges; the test gates the
    // edge-insert path, not graph topology realism.
    let nodes = vec![
        Node::new("a", NodeType::Domain, "a"),
        Node::new("b", NodeType::Domain, "b"),
    ];
    s.write_nodes(&nodes).unwrap();
    let edges: Vec<Edge> = (0..E)
        .map(|_| Edge::new("a", "b", EdgeType::Hosts))
        .collect();
    let start = Instant::now();
    s.write_edges(&edges).unwrap();
    let elapsed = start.elapsed();
    eprintln!(
        "graph insert: {E} edges in {elapsed:?} ({:.0}/s)",
        E as f64 / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "graph insert: {E} edges took {elapsed:?} > 5s gate"
    );
}

#[test]
fn graph_insert_perf_gate_is_release_only() {
    // Stub so debug builds report a green test.
    let backend = SqliteBackend::open(":memory:");
    assert!(backend.is_ok());
}
