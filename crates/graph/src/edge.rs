//! Typed graph edge.

use serde::{Deserialize, Serialize};

use crate::schema::EdgeType;

/// An edge (relationship) in the attack-surface graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Edge {
    /// Source node id.
    pub source_id: String,
    /// Target node id.
    pub target_id: String,
    /// Semantic relationship type.
    pub kind: EdgeType,
    /// Optional JSON payload with relationship-specific metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    /// Unix timestamp (ms) when the edge was first observed.
    #[serde(default)]
    pub first_seen_ms: u64,
    /// Unix timestamp (ms) when the edge was last observed.
    #[serde(default)]
    pub last_seen_ms: u64,
}

impl Edge {
    /// Create a new edge with the current time as `first_seen`.
    #[must_use]
    pub fn new(source_id: impl Into<String>, target_id: impl Into<String>, kind: EdgeType) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            source_id: source_id.into(),
            target_id: target_id.into(),
            kind,
            payload: None,
            first_seen_ms: now,
            last_seen_ms: now,
        }
    }

    /// Attach a JSON payload.
    #[must_use]
    pub fn with_payload(mut self, payload: impl Serialize) -> Self {
        self.payload = serde_json::to_value(payload).ok();
        self
    }
}
