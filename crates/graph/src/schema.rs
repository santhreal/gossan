//! Typed graph schema with versioning for forward compatibility.

use serde::{Deserialize, Serialize};

/// Current schema version. Bump on breaking node/edge type changes.
pub const SCHEMA_VERSION: u32 = 1;

/// All node types in the attack-surface graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum NodeType {
    Domain,
    Subdomain,
    Ip,
    Port,
    Service,
    Tech,
    Endpoint,
    Secret,
    Cloud,
    Finding,
}

impl std::fmt::Display for NodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeType::Domain => write!(f, "domain"),
            NodeType::Subdomain => write!(f, "subdomain"),
            NodeType::Ip => write!(f, "ip"),
            NodeType::Port => write!(f, "port"),
            NodeType::Service => write!(f, "service"),
            NodeType::Tech => write!(f, "tech"),
            NodeType::Endpoint => write!(f, "endpoint"),
            NodeType::Secret => write!(f, "secret"),
            NodeType::Cloud => write!(f, "cloud"),
            NodeType::Finding => write!(f, "finding"),
        }
    }
}

/// All edge (relationship) types in the attack-surface graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum EdgeType {
    ResolvesTo,
    Hosts,
    Runs,
    Exposes,
    Leaks,
    Misconfigured,
    HasFinding,
    HasService,
}

impl std::fmt::Display for EdgeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdgeType::ResolvesTo => write!(f, "RESOLVES_TO"),
            EdgeType::Hosts => write!(f, "HOSTS"),
            EdgeType::Runs => write!(f, "RUNS"),
            EdgeType::Exposes => write!(f, "EXPOSES"),
            EdgeType::Leaks => write!(f, "LEAKS"),
            EdgeType::Misconfigured => write!(f, "MISCONFIGURED"),
            EdgeType::HasFinding => write!(f, "HAS_FINDING"),
            EdgeType::HasService => write!(f, "HAS_SERVICE"),
        }
    }
}

/// Schema metadata attached to every persisted graph.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphSchema {
    pub version: u32,
}

impl Default for GraphSchema {
    fn default() -> Self {
        Self {
            version: SCHEMA_VERSION,
        }
    }
}

impl GraphSchema {
    /// Create the current schema.
    #[must_use]
    pub fn current() -> Self {
        Self::default()
    }

    /// Validate that a loaded schema is compatible with this code.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored schema version is newer than the
    /// code understands (forward incompatibility).
    pub fn validate(&self) -> Result<(), SchemaError> {
        if self.version > SCHEMA_VERSION {
            return Err(SchemaError::UnsupportedVersion {
                found: self.version,
                max_supported: SCHEMA_VERSION,
            });
        }
        Ok(())
    }
}

/// Schema validation error.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum SchemaError {
    #[error("unsupported schema version {found}, max supported is {max_supported}")]
    UnsupportedVersion { found: u32, max_supported: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_schema_validates() {
        assert!(GraphSchema::current().validate().is_ok());
    }

    #[test]
    fn future_schema_fails() {
        let future = GraphSchema {
            version: SCHEMA_VERSION + 1,
        };
        assert!(future.validate().is_err());
    }

    #[test]
    fn node_type_roundtrip() {
        let types = vec![
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
        for t in types {
            let s = serde_json::to_string(&t).unwrap();
            let back: NodeType = serde_json::from_str(&s).unwrap();
            assert_eq!(t, back);
        }
    }

    #[test]
    fn edge_type_roundtrip() {
        let types = vec![
            EdgeType::ResolvesTo,
            EdgeType::Hosts,
            EdgeType::Runs,
            EdgeType::Exposes,
            EdgeType::Leaks,
            EdgeType::Misconfigured,
            EdgeType::HasFinding,
            EdgeType::HasService,
        ];
        for t in types {
            let s = serde_json::to_string(&t).unwrap();
            let back: EdgeType = serde_json::from_str(&s).unwrap();
            assert_eq!(t, back);
        }
    }
}
