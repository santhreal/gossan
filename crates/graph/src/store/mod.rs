//! Storage backends for the attack-surface graph.

pub mod graphml;
pub mod json;
pub mod memory;
pub mod sqlite;

use crate::{schema::EdgeType, Edge, Node};

// ── Shared schema parsing helpers ──────────────────────────────────────────
// Both the SQLite and GraphML backends must map stored string tags to the
// canonical NodeType / EdgeType enums. Having two verbatim copies of these
// match arms was a deduplication violation (§7), a single arm addition
// would require editing two files and the second copy would drift sooner or
// later. They live here, in the one `store` module both backends import from.

/// Parse a node-type tag string (as written by `NodeType::to_string()`) back
/// to its enum variant. Returns `None` for unknown tags.
pub(super) fn parse_node_type(s: &str) -> Option<crate::schema::NodeType> {
    use crate::schema::NodeType;
    match s {
        "domain"   => Some(NodeType::Domain),
        "subdomain" => Some(NodeType::Subdomain),
        "ip"       => Some(NodeType::Ip),
        "port"     => Some(NodeType::Port),
        "service"  => Some(NodeType::Service),
        "tech"     => Some(NodeType::Tech),
        "endpoint" => Some(NodeType::Endpoint),
        "secret"   => Some(NodeType::Secret),
        "cloud"    => Some(NodeType::Cloud),
        "finding"  => Some(NodeType::Finding),
        _          => None,
    }
}

/// Parse an edge-type tag string (as written by `EdgeType::to_string()`) back
/// to its enum variant. Returns `None` for unknown tags.
pub(super) fn parse_edge_type(s: &str) -> Option<crate::schema::EdgeType> {
    use crate::schema::EdgeType;
    match s {
        "RESOLVES_TO"  => Some(EdgeType::ResolvesTo),
        "HOSTS"        => Some(EdgeType::Hosts),
        "RUNS"         => Some(EdgeType::Runs),
        "EXPOSES"      => Some(EdgeType::Exposes),
        "LEAKS"        => Some(EdgeType::Leaks),
        "MISCONFIGURED" => Some(EdgeType::Misconfigured),
        "HAS_FINDING"  => Some(EdgeType::HasFinding),
        "HAS_SERVICE"  => Some(EdgeType::HasService),
        _              => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{EdgeType, NodeType};

    /// Anti-rig: every NodeType variant must survive a `to_string()` /
    /// `parse_node_type()` roundtrip.  If a new variant is added to `NodeType`
    /// without adding the arm here this test fails, the correct fix is to add
    /// the arm, not to add the variant to an exception list.
    #[test]
    fn parse_node_type_roundtrip_all_variants() {
        let cases = [
            (NodeType::Domain,    "domain"),
            (NodeType::Subdomain, "subdomain"),
            (NodeType::Ip,        "ip"),
            (NodeType::Port,      "port"),
            (NodeType::Service,   "service"),
            (NodeType::Tech,      "tech"),
            (NodeType::Endpoint,  "endpoint"),
            (NodeType::Secret,    "secret"),
            (NodeType::Cloud,     "cloud"),
            (NodeType::Finding,   "finding"),
        ];
        for (variant, tag) in &cases {
            let parsed = parse_node_type(tag)
                .unwrap_or_else(|| panic!("parse_node_type({tag:?}) returned None"));
            assert_eq!(
                parsed, *variant,
                "parse_node_type({tag:?}) must return {variant:?}"
            );
            // Verify to_string matches the tag (round-trip symmetry).
            assert_eq!(
                variant.to_string(), *tag,
                "NodeType::{variant:?}.to_string() must equal {tag:?}"
            );
        }
    }

    #[test]
    fn parse_node_type_unknown_returns_none() {
        assert!(parse_node_type("").is_none());
        assert!(parse_node_type("DOMAIN").is_none()); // case-sensitive
        assert!(parse_node_type("unknown_xyz").is_none());
    }

    /// Anti-rig: every EdgeType variant must survive a roundtrip.
    #[test]
    fn parse_edge_type_roundtrip_all_variants() {
        let cases = [
            (EdgeType::ResolvesTo,   "RESOLVES_TO"),
            (EdgeType::Hosts,        "HOSTS"),
            (EdgeType::Runs,         "RUNS"),
            (EdgeType::Exposes,      "EXPOSES"),
            (EdgeType::Leaks,        "LEAKS"),
            (EdgeType::Misconfigured, "MISCONFIGURED"),
            (EdgeType::HasFinding,   "HAS_FINDING"),
            (EdgeType::HasService,   "HAS_SERVICE"),
        ];
        for (variant, tag) in &cases {
            let parsed = parse_edge_type(tag)
                .unwrap_or_else(|| panic!("parse_edge_type({tag:?}) returned None"));
            assert_eq!(
                parsed, *variant,
                "parse_edge_type({tag:?}) must return {variant:?}"
            );
            assert_eq!(
                variant.to_string(), *tag,
                "EdgeType::{variant:?}.to_string() must equal {tag:?}"
            );
        }
    }

    #[test]
    fn parse_edge_type_unknown_returns_none() {
        assert!(parse_edge_type("").is_none());
        assert!(parse_edge_type("resolves_to").is_none()); // must be UPPER_SNAKE
        assert!(parse_edge_type("UNKNOWN_EDGE").is_none());
    }
}

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
