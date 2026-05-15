//! Graph-relationship builder for correlated findings.
//!
//! Produces `Vec<Node>` + `Vec<Edge>` describing how a synthesised
//! "chain" finding relates to its constituent source findings and
//! the assets they touch. Consumed by `gossan-graph::persist_scan`
//! which writes the rows into the active backend (sqlite / json /
//! graphml / memory).
//!
//! `Finding` is `Arc<...>`-backed and immutable on its
//! evidence/tags lists, so we don't mutate findings here — we
//! produce graph-side data that lives alongside them.

use gossan_graph::{schema::EdgeType, schema::NodeType, Edge, Node};
use secfinding::Finding;

/// Builder that accumulates nodes and edges for a single chain
/// finding. Each call returns `Self` to allow fluent chaining.
pub struct RelationshipBuilder {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    chain_id: String,
}

impl RelationshipBuilder {
    /// Create a new builder seeded with the chain finding as the
    /// root node. All subsequent `link_*` calls add edges that
    /// emanate from this root.
    #[must_use]
    pub fn new(chain_finding: &Finding) -> Self {
        let chain_id = format!("finding:{}", chain_finding.id());
        let chain_node = Node::new(
            chain_id.clone(),
            NodeType::Finding,
            chain_finding.title().to_string(),
        );
        Self {
            nodes: vec![chain_node],
            edges: Vec::new(),
            chain_id,
        }
    }

    /// Link the chain finding to a source finding via a typed edge.
    #[must_use]
    pub fn link_finding(mut self, finding: &Finding, edge_type: EdgeType) -> Self {
        let source_id = format!("finding:{}", finding.id());
        let node = Node::new(
            source_id.clone(),
            NodeType::Finding,
            finding.title().to_string(),
        );
        self.nodes.push(node);
        self.edges
            .push(Edge::new(self.chain_id.clone(), source_id, edge_type));
        self
    }

    /// Link the chain finding to a target asset (host, domain, port, etc.).
    #[must_use]
    pub fn link_target(mut self, target_id: impl Into<String>, kind: NodeType) -> Self {
        let tid = target_id.into();
        self.nodes.push(Node::new(tid.clone(), kind, tid.clone()));
        self.edges.push(Edge::new(
            self.chain_id.clone(),
            tid,
            EdgeType::HasFinding,
        ));
        self
    }

    /// Consume the builder and return the raw nodes and edges for
    /// downstream persistence.
    #[must_use]
    pub fn build(self) -> (Vec<Node>, Vec<Edge>) {
        (self.nodes, self.edges)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secfinding::Severity;

    fn fresh(scanner: &str, target: &str, title: &str) -> Finding {
        Finding::builder(scanner, target, Severity::Medium)
            .title(title)
            .detail("rel-test")
            .build()
            .expect("build")
    }

    #[test]
    fn builder_creates_chain_root_node() {
        let chain = fresh("correlator", "example.com", "ChainTitle");
        let (nodes, edges) = RelationshipBuilder::new(&chain).build();
        assert_eq!(nodes.len(), 1);
        assert_eq!(edges.len(), 0);
        assert_eq!(nodes[0].kind, NodeType::Finding);
        assert_eq!(nodes[0].label, "ChainTitle");
        assert!(nodes[0].id.starts_with("finding:"));
    }

    #[test]
    fn link_finding_adds_node_and_edge() {
        let chain = fresh("correlator", "example.com", "Chain");
        let src = fresh("scanner-a", "example.com", "Src");
        let (nodes, edges) = RelationshipBuilder::new(&chain)
            .link_finding(&src, EdgeType::HasFinding)
            .build();
        assert_eq!(nodes.len(), 2);
        assert_eq!(edges.len(), 1);
        assert!(edges[0].source_id.starts_with("finding:"));
        assert_eq!(edges[0].kind, EdgeType::HasFinding);
    }

    #[test]
    fn link_target_attaches_typed_asset() {
        let chain = fresh("correlator", "example.com", "Chain");
        let (nodes, edges) = RelationshipBuilder::new(&chain)
            .link_target("https://example.com:443/", NodeType::Endpoint)
            .build();
        assert_eq!(nodes.len(), 2);
        assert_eq!(edges.len(), 1);
        assert_eq!(nodes[1].kind, NodeType::Endpoint);
        assert_eq!(edges[0].kind, EdgeType::HasFinding);
    }

    #[test]
    fn fluent_chain_builds_full_graph() {
        let chain = fresh("correlator", "example.com", "Chain");
        let s1 = fresh("scanner-a", "example.com", "S1");
        let s2 = fresh("scanner-b", "example.com", "S2");
        let (nodes, edges) = RelationshipBuilder::new(&chain)
            .link_finding(&s1, EdgeType::HasFinding)
            .link_finding(&s2, EdgeType::HasFinding)
            .link_target("ip:1.2.3.4", NodeType::Ip)
            .build();
        assert_eq!(nodes.len(), 4);
        assert_eq!(edges.len(), 3);
    }
}
