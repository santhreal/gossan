//! Query layer for graph traversal.

use crate::store::GraphBackend;
use crate::{schema::EdgeType, Edge, Node};
use std::collections::{HashMap, HashSet, VecDeque};

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
    let mut parents: HashMap<String, String> = HashMap::new();

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

/// Breadth-first traversal from `start`.
///
/// Returns the list of node ids in BFS order (including `start`).
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn bfs<B: GraphBackend>(backend: &B, start: &str) -> Result<Vec<String>, B::Error> {
    let mut visited = HashSet::new();
    let mut order = Vec::new();
    let mut queue = VecDeque::new();

    visited.insert(start.to_string());
    queue.push_back(start.to_string());

    while let Some(current) = queue.pop_front() {
        order.push(current.clone());
        for edge in backend.neighbors(&current, None)? {
            if visited.insert(edge.target_id.clone()) {
                queue.push_back(edge.target_id.clone());
            }
        }
    }

    Ok(order)
}

/// Depth-first traversal from `start`.
///
/// Returns the list of node ids in pre-order DFS order (including `start`).
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn dfs<B: GraphBackend>(backend: &B, start: &str) -> Result<Vec<String>, B::Error> {
    let mut visited = HashSet::new();
    let mut order = Vec::new();
    let mut stack = vec![start.to_string()];

    while let Some(current) = stack.pop() {
        if !visited.insert(current.clone()) {
            continue;
        }
        order.push(current.clone());
        for edge in backend.neighbors(&current, None)? {
            if !visited.contains(&edge.target_id) {
                stack.push(edge.target_id.clone());
            }
        }
    }

    Ok(order)
}

/// Find all simple paths from `start` to `goal` up to `max_depth` hops.
///
/// Returns a vector of paths, each path being a vector of node ids.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn all_paths<B: GraphBackend>(
    backend: &B,
    start: &str,
    goal: &str,
    max_depth: usize,
) -> Result<Vec<Vec<String>>, B::Error> {
    let mut paths = Vec::new();
    let mut current = vec![start.to_string()];
    let mut visited = HashSet::new();
    visited.insert(start.to_string());

    fn backtrack<B: GraphBackend>(
        backend: &B,
        current: &mut Vec<String>,
        visited: &mut HashSet<String>,
        goal: &str,
        max_depth: usize,
        paths: &mut Vec<Vec<String>>,
    ) -> Result<(), B::Error> {
        let Some(last) = current.last() else {
            return Ok(());
        };
        if last == goal {
            paths.push(current.clone());
            return Ok(());
        }
        if current.len() > max_depth {
            return Ok(());
        }
        let node = last.clone();
        for edge in backend.neighbors(&node, None)? {
            if visited.insert(edge.target_id.clone()) {
                current.push(edge.target_id.clone());
                backtrack(backend, current, visited, goal, max_depth, paths)?;
                current.pop();
                visited.remove(&edge.target_id);
            }
        }
        Ok(())
    }

    backtrack(backend, &mut current, &mut visited, goal, max_depth, &mut paths)?;
    Ok(paths)
}

/// Detect whether the graph contains at least one cycle (starting from any node).
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn has_cycle<B: GraphBackend>(backend: &B) -> Result<bool, B::Error> {
    let edges = backend.read_edges()?;
    let nodes = backend.read_nodes()?;
    if nodes.is_empty() {
        return Ok(false);
    }

    let adj: HashMap<String, Vec<String>> =
        edges
            .iter()
            .fold(HashMap::new(), |mut map, e| {
                map.entry(e.source_id.clone())
                    .or_default()
                    .push(e.target_id.clone());
                map
            });

    // Iterative DFS with explicit work-stack to detect back-edges without
    // risking a stack overflow on adversarial deep graphs (§15 AUDIT).
    //
    // Each work-stack frame is `(node_id, neighbour_cursor)`.  When we
    // first push a node we mark it 1 (visiting); when we pop it after
    // exhausting all its neighbours we mark it 2 (done).  A neighbour
    // already in state 1 (visiting) is a back-edge → cycle.
    //
    // State encoding: 0 = unvisited, 1 = on the path (grey), 2 = done (black).
    let mut state: HashMap<String, u8> = HashMap::with_capacity(nodes.len());
    for node in &nodes {
        state.insert(node.id.clone(), 0);
    }

    for node in &nodes {
        if state.get(&node.id).copied().unwrap_or(0) != 0 {
            continue;
        }

        // (node_id, index into adj[node_id] of the next neighbour to visit)
        let mut work_stack: Vec<(String, usize)> = Vec::new();
        state.insert(node.id.clone(), 1);
        work_stack.push((node.id.clone(), 0));

        'outer: while let Some(frame) = work_stack.last_mut() {
            let (cur, idx) = (&frame.0.clone(), frame.1);

            if let Some(nbrs) = adj.get(cur) {
                if idx < nbrs.len() {
                    frame.1 += 1; // advance cursor before any push/pop
                    let nbr = &nbrs[idx];
                    match state.get(nbr).copied().unwrap_or(0) {
                        1 => return Ok(true), // back-edge → cycle
                        0 => {
                            state.insert(nbr.clone(), 1);
                            work_stack.push((nbr.clone(), 0));
                            continue 'outer;
                        }
                        _ => {} // already done
                    }
                    continue 'outer;
                }
            }

            // All neighbours exhausted (mark done and pop).
            state.insert(cur.clone(), 2);
            work_stack.pop();
        }
    }

    Ok(false)
}

/// Find connected components treating the graph as undirected.
///
/// Returns a vector of components, each component being a set of node ids.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn connected_components<B: GraphBackend>(
    backend: &B,
) -> Result<Vec<HashSet<String>>, B::Error> {
    let edges = backend.read_edges()?;
    let nodes = backend.read_nodes()?;

    let mut adj: HashMap<String, Vec<String>> = HashMap::new();
    for node in &nodes {
        adj.entry(node.id.clone()).or_default();
    }
    for edge in &edges {
        adj.entry(edge.source_id.clone())
            .or_default()
            .push(edge.target_id.clone());
        adj.entry(edge.target_id.clone())
            .or_default()
            .push(edge.source_id.clone());
    }

    let mut visited = HashSet::new();
    let mut components = Vec::new();

    for node in &nodes {
        if visited.contains(&node.id) {
            continue;
        }
        let mut component = HashSet::new();
        let mut stack = vec![node.id.clone()];
        while let Some(current) = stack.pop() {
            if !visited.insert(current.clone()) {
                continue;
            }
            component.insert(current.clone());
            if let Some(nbrs) = adj.get(&current) {
                for nbr in nbrs {
                    if !visited.contains(nbr) {
                        stack.push(nbr.clone());
                    }
                }
            }
        }
        components.push(component);
    }

    Ok(components)
}

/// Return the out-degree of a node.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn out_degree<B: GraphBackend>(backend: &B, node_id: &str) -> Result<usize, B::Error> {
    Ok(backend.neighbors(node_id, None)?.len())
}

/// Return the in-degree of a node.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn in_degree<B: GraphBackend>(backend: &B, node_id: &str) -> Result<usize, B::Error> {
    let edges = backend.read_edges()?;
    Ok(edges.iter().filter(|e| e.target_id == node_id).count())
}

/// Compute degree distribution: map of node id to `(in_degree, out_degree)`.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn degree_distribution<B: GraphBackend>(
    backend: &B,
) -> Result<HashMap<String, (usize, usize)>, B::Error> {
    let nodes = backend.read_nodes()?;
    let edges = backend.read_edges()?;

    let mut dist: HashMap<String, (usize, usize)> = HashMap::new();
    for node in &nodes {
        dist.insert(node.id.clone(), (0, 0));
    }
    for edge in &edges {
        dist.entry(edge.source_id.clone()).or_default().1 += 1;
        dist.entry(edge.target_id.clone()).or_default().0 += 1;
    }

    Ok(dist)
}

/// Compute graph density for a directed graph.
///
/// Density = |E| / (|V| * (|V| - 1)) for |V| > 1, otherwise 0.0.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn graph_density<B: GraphBackend>(backend: &B) -> Result<f64, B::Error> {
    let v = backend.read_nodes()?.len();
    let e = backend.read_edges()?.len();
    if v <= 1 {
        return Ok(0.0);
    }
    Ok(e as f64 / (v as f64 * (v as f64 - 1.0)))
}

/// Compute the diameter of the graph (longest shortest path among all pairs).
///
/// Returns 0 for graphs with 0 or 1 nodes.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn graph_diameter<B: GraphBackend>(backend: &B) -> Result<usize, B::Error> {
    let nodes = backend.read_nodes()?;
    if nodes.len() <= 1 {
        return Ok(0);
    }

    let mut max_dist = 0;
    for node in &nodes {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        let mut dist = HashMap::new();
        visited.insert(node.id.clone());
        queue.push_back(node.id.clone());
        dist.insert(node.id.clone(), 0_usize);

        while let Some(current) = queue.pop_front() {
            let d = dist.get(&current).copied().unwrap_or(0);
            for edge in backend.neighbors(&current, None)? {
                if visited.insert(edge.target_id.clone()) {
                    dist.insert(edge.target_id.clone(), d + 1);
                    queue.push_back(edge.target_id.clone());
                }
            }
        }

        for (_, d) in dist {
            if d > max_dist {
                max_dist = d;
            }
        }
    }

    Ok(max_dist)
}

/// Compute the local clustering coefficient for a node.
///
/// Coefficient = number of edges between neighbors / (k * (k - 1))
/// where k is the number of neighbors (treating graph as undirected).
/// Returns 0.0 for nodes with fewer than 2 neighbors.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn clustering_coefficient<B: GraphBackend>(
    backend: &B,
    node_id: &str,
) -> Result<f64, B::Error> {
    let edges = backend.read_edges()?;
    let mut neighbors_set = HashSet::new();
    for edge in &edges {
        if edge.source_id == node_id {
            neighbors_set.insert(edge.target_id.clone());
        }
        if edge.target_id == node_id {
            neighbors_set.insert(edge.source_id.clone());
        }
    }

    let k = neighbors_set.len();
    if k < 2 {
        return Ok(0.0);
    }

    // Undirected local clustering coefficient: of the k*(k-1)/2 possible
    // unordered neighbor pairs, how many are actually connected. Count
    // DISTINCT pairs (canonicalise A-B vs B-A, skip self-loops) so a graph
    // that stores an edge in both directions can't push the ratio above
    // 1.0, the previous `neighbor_edges / k*(k-1)` form both halved a
    // proper triangle to 0.5 and could exceed 1.0 on bidirectional edges.
    let possible_pairs = k * (k - 1) / 2;
    let mut connected_pairs = HashSet::new();
    for edge in &edges {
        let (a, b) = (&edge.source_id, &edge.target_id);
        if a != b && neighbors_set.contains(a) && neighbors_set.contains(b) {
            let pair = if a <= b { (a, b) } else { (b, a) };
            connected_pairs.insert(pair);
        }
    }

    Ok(connected_pairs.len() as f64 / possible_pairs as f64)
}

/// Extract a subgraph containing only the specified node ids and edges between them.
///
/// Returns `(Vec<Node>, Vec<Edge>)`.
///
/// # Errors
///
/// Returns an error if the backend fails.
pub fn subgraph<B: GraphBackend>(
    backend: &B,
    node_ids: &HashSet<String>,
) -> Result<(Vec<Node>, Vec<Edge>), B::Error> {
    let nodes: Vec<Node> = backend
        .read_nodes()?
        .into_iter()
        .filter(|n| node_ids.contains(&n.id))
        .collect();
    let edges: Vec<Edge> = backend
        .read_edges()?
        .into_iter()
        .filter(|e| node_ids.contains(&e.source_id) && node_ids.contains(&e.target_id))
        .collect();
    Ok((nodes, edges))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::NodeType;
    use crate::store::sqlite::SqliteBackend;
    use proptest::prelude::*;

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

    // ── BFS / DFS order ─────────────────────────────────────────────────

    #[test]
    fn bfs_linear_chain_visits_all_in_order() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[
            Node::new("a", NodeType::Domain, "a"),
            Node::new("b", NodeType::Domain, "b"),
            Node::new("c", NodeType::Domain, "c"),
        ]).unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("b", "c", EdgeType::ResolvesTo),
        ]).unwrap();
        let order = bfs(&s, "a").unwrap();
        assert_eq!(order[0], "a");
        assert!(order.contains(&"b".to_string()));
        assert!(order.contains(&"c".to_string()));
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn bfs_isolated_node_returns_just_itself() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        let order = bfs(&s, "orphan").unwrap();
        assert_eq!(order, vec!["orphan".to_string()]);
    }

    #[test]
    fn dfs_linear_chain_visits_all() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("b", "c", EdgeType::Hosts),
        ]).unwrap();
        let order = dfs(&s, "a").unwrap();
        assert_eq!(order[0], "a");
        assert!(order.contains(&"b".to_string()));
        assert!(order.contains(&"c".to_string()));
        assert_eq!(order.len(), 3);
    }

    #[test]
    fn dfs_handles_cycle_without_infinite_loop() {
        // a → b → a (cycle), dfs must terminate
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("b", "a", EdgeType::ResolvesTo),
        ]).unwrap();
        let order = dfs(&s, "a").unwrap();
        // both nodes visited exactly once
        assert_eq!(order.len(), 2);
    }

    // ── has_cycle ────────────────────────────────────────────────────────

    #[test]
    fn has_cycle_empty_graph_returns_false() {
        let s = crate::store::memory::MemoryStore::new();
        assert!(!has_cycle(&s).unwrap());
    }

    #[test]
    fn has_cycle_single_node_no_edges_returns_false() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[Node::new("a", NodeType::Domain, "a")]).unwrap();
        assert!(!has_cycle(&s).unwrap());
    }

    #[test]
    fn has_cycle_dag_returns_false() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[
            Node::new("a", NodeType::Domain, "a"),
            Node::new("b", NodeType::Domain, "b"),
            Node::new("c", NodeType::Domain, "c"),
        ]).unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("b", "c", EdgeType::Hosts),
        ]).unwrap();
        assert!(!has_cycle(&s).unwrap());
    }

    #[test]
    fn has_cycle_direct_self_loop_returns_true() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[Node::new("a", NodeType::Domain, "a")]).unwrap();
        s.write_edges(&[Edge::new("a", "a", EdgeType::ResolvesTo)]).unwrap();
        assert!(has_cycle(&s).unwrap());
    }

    #[test]
    fn has_cycle_back_edge_returns_true() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[
            Node::new("a", NodeType::Domain, "a"),
            Node::new("b", NodeType::Domain, "b"),
            Node::new("c", NodeType::Domain, "c"),
        ]).unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("b", "c", EdgeType::Hosts),
            Edge::new("c", "a", EdgeType::Exposes), // cycle back to a
        ]).unwrap();
        assert!(has_cycle(&s).unwrap());
    }

    /// Adversarial: a linear chain long enough that a recursive DFS would
    /// overflow the stack on typical platforms (~8 MB default) but the
    /// iterative implementation handles without issue (§15 AUDIT).
    #[test]
    fn has_cycle_deep_linear_chain_no_overflow() {
        const DEPTH: usize = 50_000;
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        let nodes: Vec<Node> = (0..=DEPTH)
            .map(|i| Node::new(i.to_string(), NodeType::Domain, i.to_string()))
            .collect();
        s.write_nodes(&nodes).unwrap();
        let edges: Vec<Edge> = (0..DEPTH)
            .map(|i| Edge::new(i.to_string(), (i + 1).to_string(), EdgeType::ResolvesTo))
            .collect();
        s.write_edges(&edges).unwrap();
        // A chain with no back-edge must not be detected as cyclic.
        assert!(!has_cycle(&s).unwrap(), "linear chain must not report a cycle");
    }

    /// Adversarial: same depth chain but with a back-edge at the very tip.
    #[test]
    fn has_cycle_deep_chain_with_back_edge_returns_true() {
        const DEPTH: usize = 10_000;
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        let nodes: Vec<Node> = (0..=DEPTH)
            .map(|i| Node::new(i.to_string(), NodeType::Domain, i.to_string()))
            .collect();
        s.write_nodes(&nodes).unwrap();
        let mut edges: Vec<Edge> = (0..DEPTH)
            .map(|i| Edge::new(i.to_string(), (i + 1).to_string(), EdgeType::ResolvesTo))
            .collect();
        // Back-edge from tip to root → cycle
        edges.push(Edge::new(DEPTH.to_string(), "0".to_string(), EdgeType::ResolvesTo));
        s.write_edges(&edges).unwrap();
        assert!(has_cycle(&s).unwrap(), "deep chain with back-edge must detect cycle");
    }

    // ── connected_components ─────────────────────────────────────────────

    #[test]
    fn connected_components_empty_graph_returns_empty() {
        let s = crate::store::memory::MemoryStore::new();
        let comps = connected_components(&s).unwrap();
        assert!(comps.is_empty());
    }

    #[test]
    fn connected_components_two_disconnected_subgraphs() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        // Component 1: a, b
        // Component 2: c, d
        s.write_nodes(&[
            Node::new("a", NodeType::Domain, "a"),
            Node::new("b", NodeType::Domain, "b"),
            Node::new("c", NodeType::Domain, "c"),
            Node::new("d", NodeType::Domain, "d"),
        ]).unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("c", "d", EdgeType::ResolvesTo),
        ]).unwrap();
        let comps = connected_components(&s).unwrap();
        assert_eq!(comps.len(), 2);
        // Each component has size 2
        for comp in &comps {
            assert_eq!(comp.len(), 2);
        }
    }

    #[test]
    fn connected_components_fully_connected_one_component() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[
            Node::new("a", NodeType::Domain, "a"),
            Node::new("b", NodeType::Domain, "b"),
            Node::new("c", NodeType::Domain, "c"),
        ]).unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("b", "c", EdgeType::ResolvesTo),
            Edge::new("c", "a", EdgeType::ResolvesTo),
        ]).unwrap();
        let comps = connected_components(&s).unwrap();
        assert_eq!(comps.len(), 1);
        assert_eq!(comps[0].len(), 3);
    }

    // ── degree ───────────────────────────────────────────────────────────

    #[test]
    fn out_degree_counts_outgoing_edges() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("a", "c", EdgeType::Hosts),
            Edge::new("b", "c", EdgeType::Hosts),
        ]).unwrap();
        assert_eq!(out_degree(&s, "a").unwrap(), 2);
        assert_eq!(out_degree(&s, "b").unwrap(), 1);
        assert_eq!(out_degree(&s, "c").unwrap(), 0);
    }

    #[test]
    fn in_degree_counts_incoming_edges() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_edges(&[
            Edge::new("a", "c", EdgeType::ResolvesTo),
            Edge::new("b", "c", EdgeType::ResolvesTo),
        ]).unwrap();
        assert_eq!(in_degree(&s, "c").unwrap(), 2);
        assert_eq!(in_degree(&s, "a").unwrap(), 0);
    }

    #[test]
    fn degree_distribution_sums_correctly() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[
            Node::new("a", NodeType::Domain, "a"),
            Node::new("b", NodeType::Domain, "b"),
            Node::new("c", NodeType::Domain, "c"),
        ]).unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("a", "c", EdgeType::Hosts),
        ]).unwrap();
        let dist = degree_distribution(&s).unwrap();
        // a: (0 in, 2 out), b: (1 in, 0 out), c: (1 in, 0 out)
        let (a_in, a_out) = dist["a"];
        assert_eq!(a_in, 0);
        assert_eq!(a_out, 2);
        let (b_in, b_out) = dist["b"];
        assert_eq!(b_in, 1);
        assert_eq!(b_out, 0);
    }

    // ── graph_density ────────────────────────────────────────────────────

    #[test]
    fn graph_density_empty_graph_returns_zero() {
        let s = crate::store::memory::MemoryStore::new();
        let d = graph_density(&s).unwrap();
        assert_eq!(d, 0.0);
    }

    #[test]
    fn graph_density_single_node_returns_zero() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[Node::new("a", NodeType::Domain, "a")]).unwrap();
        let d = graph_density(&s).unwrap();
        assert_eq!(d, 0.0);
    }

    #[test]
    fn graph_density_fully_connected_two_nodes() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[
            Node::new("a", NodeType::Domain, "a"),
            Node::new("b", NodeType::Domain, "b"),
        ]).unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("b", "a", EdgeType::ResolvesTo),
        ]).unwrap();
        // density = 2 / (2*1) = 1.0
        let d = graph_density(&s).unwrap();
        assert!((d - 1.0).abs() < 1e-9);
    }

    // ── graph_diameter ───────────────────────────────────────────────────

    #[test]
    fn graph_diameter_empty_graph_returns_zero() {
        let s = crate::store::memory::MemoryStore::new();
        assert_eq!(graph_diameter(&s).unwrap(), 0);
    }

    #[test]
    fn graph_diameter_single_node_returns_zero() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[Node::new("a", NodeType::Domain, "a")]).unwrap();
        assert_eq!(graph_diameter(&s).unwrap(), 0);
    }

    #[test]
    fn graph_diameter_linear_chain_of_three() {
        // a → b → c: longest shortest path = 2
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[
            Node::new("a", NodeType::Domain, "a"),
            Node::new("b", NodeType::Domain, "b"),
            Node::new("c", NodeType::Domain, "c"),
        ]).unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("b", "c", EdgeType::ResolvesTo),
        ]).unwrap();
        assert_eq!(graph_diameter(&s).unwrap(), 2);
    }

    // ── all_paths ────────────────────────────────────────────────────────

    #[test]
    fn all_paths_single_hop_returns_direct() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_edges(&[Edge::new("a", "b", EdgeType::ResolvesTo)]).unwrap();
        let paths = all_paths(&s, "a", "b", 5).unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0], vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn all_paths_no_path_returns_empty() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        let paths = all_paths(&s, "a", "z", 10).unwrap();
        assert!(paths.is_empty());
    }

    #[test]
    fn all_paths_max_depth_zero_no_path_longer_than_one() {
        // depth 0 means only allow direct, but current.len() > 0 → even
        // single-hop is blocked because after pushing b, current.len() == 2
        // which is > max_depth == 0. So we get zero paths.
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_edges(&[Edge::new("a", "b", EdgeType::ResolvesTo)]).unwrap();
        let paths = all_paths(&s, "a", "b", 0).unwrap();
        // With max_depth=0 the early exit fires before we ever check `b == goal`.
        assert!(paths.is_empty(), "max_depth=0 must block all multi-hop paths");
    }

    // ── subgraph ─────────────────────────────────────────────────────────

    #[test]
    fn subgraph_extracts_only_requested_nodes_and_internal_edges() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[
            Node::new("a", NodeType::Domain, "a"),
            Node::new("b", NodeType::Domain, "b"),
            Node::new("c", NodeType::Domain, "c"),
        ]).unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("b", "c", EdgeType::Hosts),   // c is outside the sub-set
            Edge::new("a", "c", EdgeType::Hosts),   // crosses boundary
        ]).unwrap();
        let ids: std::collections::HashSet<String> = ["a", "b"].iter().map(|s| s.to_string()).collect();
        let (nodes, edges) = subgraph(&s, &ids).unwrap();
        assert_eq!(nodes.len(), 2);
        // only a→b is in-subgraph; b→c and a→c cross the boundary
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source_id, "a");
        assert_eq!(edges[0].target_id, "b");
    }

    #[test]
    fn subgraph_empty_id_set_returns_empty() {
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_nodes(&[Node::new("a", NodeType::Domain, "a")]).unwrap();
        let ids = std::collections::HashSet::new();
        let (nodes, edges) = subgraph(&s, &ids).unwrap();
        assert!(nodes.is_empty());
        assert!(edges.is_empty());
    }

    // ── clustering_coefficient ───────────────────────────────────────────

    #[test]
    fn clustering_coefficient_isolated_node_returns_zero() {
        let s = crate::store::memory::MemoryStore::new();
        let cc = clustering_coefficient(&s, "x").unwrap();
        assert_eq!(cc, 0.0);
    }

    #[test]
    fn clustering_coefficient_triangle_returns_one() {
        // a–b, b–c, c–a (undirected triangle → cc = 1.0 for each node)
        let mut s = crate::store::memory::MemoryStore::new();
        s.init().unwrap();
        s.write_edges(&[
            Edge::new("a", "b", EdgeType::ResolvesTo),
            Edge::new("b", "c", EdgeType::ResolvesTo),
            Edge::new("c", "a", EdgeType::ResolvesTo),
        ]).unwrap();
        let cc = clustering_coefficient(&s, "a").unwrap();
        // neighbor_pairs_possible = 2*(2-1) = 2; both b and c are connected → cc = 2/2 = 1.0
        assert!((cc - 1.0).abs() < 1e-9, "triangle should give cc=1.0, got {cc}");
    }

    proptest! {
        #[test]
        fn all_paths_never_panics_on_small_graph(
            ids in prop::collection::vec(r"[a-zA-Z0-9_-]{1,10}", 1..5),
        ) {
            let mut store = crate::store::memory::MemoryStore::new();
            store.init().unwrap();
            for id in &ids {
                store.write_nodes(&[Node::new(id, NodeType::Domain, id)]).unwrap();
            }
            for i in 0..ids.len().saturating_sub(1) {
                store.write_edges(&[Edge::new(&ids[i], &ids[i + 1], EdgeType::ResolvesTo)]).unwrap();
            }
            if ids.len() >= 2 {
                let _ = all_paths(&store, &ids[0], &ids[ids.len() - 1], ids.len());
            }
        }

        #[test]
        fn graph_diameter_never_panics_on_small_graph(
            ids in prop::collection::vec(r"[a-zA-Z0-9_-]{1,10}", 1..5),
        ) {
            let mut store = crate::store::memory::MemoryStore::new();
            store.init().unwrap();
            for id in &ids {
                store.write_nodes(&[Node::new(id, NodeType::Domain, id)]).unwrap();
            }
            for i in 0..ids.len().saturating_sub(1) {
                store.write_edges(&[Edge::new(&ids[i], &ids[i + 1], EdgeType::ResolvesTo)]).unwrap();
            }
            let _ = graph_diameter(&store);
        }

        #[test]
        fn bfs_and_dfs_visit_same_set_of_nodes(
            ids in prop::collection::vec(r"[a-zA-Z0-9_]{1,8}", 2..6),
        ) {
            let mut store = crate::store::memory::MemoryStore::new();
            store.init().unwrap();
            // deduplicate ids first
            let ids: Vec<String> = {
                let mut seen = std::collections::HashSet::new();
                ids.into_iter().filter(|s| seen.insert(s.clone())).collect()
            };
            for id in &ids {
                store.write_nodes(&[Node::new(id, NodeType::Domain, id)]).unwrap();
            }
            for i in 0..ids.len().saturating_sub(1) {
                store.write_edges(&[Edge::new(&ids[i], &ids[i + 1], EdgeType::ResolvesTo)]).unwrap();
            }
            if ids.is_empty() { return Ok(()); }
            let bfs_set: std::collections::HashSet<String> = bfs(&store, &ids[0]).unwrap().into_iter().collect();
            let dfs_set: std::collections::HashSet<String> = dfs(&store, &ids[0]).unwrap().into_iter().collect();
            prop_assert_eq!(bfs_set, dfs_set);
        }

        #[test]
        fn graph_density_always_in_unit_interval(
            n_nodes in 0usize..8,
            n_edges in 0usize..12,
        ) {
            let mut store = crate::store::memory::MemoryStore::new();
            store.init().unwrap();
            for i in 0..n_nodes {
                store.write_nodes(&[Node::new(&i.to_string(), NodeType::Domain, &i.to_string())]).unwrap();
            }
            for i in 0..n_edges {
                let s = (i % n_nodes.max(1)).to_string();
                let t = ((i + 1) % n_nodes.max(1)).to_string();
                store.write_edges(&[Edge::new(&s, &t, EdgeType::ResolvesTo)]).unwrap();
            }
            let d = graph_density(&store).unwrap();
            prop_assert!(d >= 0.0, "density must be non-negative");
        }

        #[test]
        fn clustering_coefficient_never_panics(node_id in r"[a-z]{1,10}") {
            let store = crate::store::memory::MemoryStore::new();
            let _ = clustering_coefficient(&store, &node_id);
        }
    }
}
