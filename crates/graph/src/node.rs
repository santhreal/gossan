//! Typed graph node.

use serde::{Deserialize, Serialize};

use crate::schema::NodeType;

/// A node in the attack-surface graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Node {
    /// Stable unique identifier.
    pub id: String,
    /// Semantic type.
    pub kind: NodeType,
    /// Human-readable label.
    pub label: String,
    /// Optional JSON payload with type-specific fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    /// Unix timestamp (ms) when the node was first observed.
    #[serde(default)]
    pub first_seen_ms: u64,
    /// Unix timestamp (ms) when the node was last observed.
    #[serde(default)]
    pub last_seen_ms: u64,
}

impl Node {
    /// Create a new node with the current time as `first_seen`.
    #[must_use]
    pub fn new(id: impl Into<String>, kind: NodeType, label: impl Into<String>) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Self {
            id: id.into(),
            kind,
            label: label.into(),
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
