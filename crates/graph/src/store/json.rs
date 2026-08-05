//! JSON graph backend (stores nodes and edges as a single JSON document).
//!
//! For large graphs (>10K nodes) the backend automatically flushes to a
//! streaming JSONL file instead of a monolithic array.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::store::GraphBackend;
use crate::{schema::EdgeType, Edge, Node};

/// Default node+edge count above which we prefer JSONL streaming for writes.
pub const DEFAULT_STREAMING_THRESHOLD: usize = 10_000;

/// In-memory + JSON file backend.
pub struct JsonBackend {
    path: PathBuf,
    nodes: HashMap<String, Node>,
    edges: HashMap<EdgeKey, Edge>,
    dirty: bool,
    streaming_threshold: usize,
}

/// Stable identity of an edge for deduplication.
type EdgeKey = (String, String, EdgeType);

impl JsonBackend {
    /// Open or create a JSON graph file using [`DEFAULT_STREAMING_THRESHOLD`].
    pub fn open<P: AsRef<Path>>(path: P) -> Self {
        Self::open_with_threshold(path, DEFAULT_STREAMING_THRESHOLD)
    }

    /// Open or create a JSON graph file with an explicit streaming threshold.
    pub fn open_with_threshold<P: AsRef<Path>>(path: P, streaming_threshold: usize) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            nodes: HashMap::new(),
            edges: HashMap::new(),
            dirty: false,
            streaming_threshold,
        }
    }

    /// Open using the threshold from [`gossan_core::Config`].
    pub fn open_from_config<P: AsRef<Path>>(path: P, config: &gossan_core::Config) -> Self {
        Self::open_with_threshold(path, config.graph_json_streaming_threshold)
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        let count = self.nodes.len().saturating_add(self.edges.len());
        if count > self.streaming_threshold {
            self.flush_jsonl()?;
        } else {
            let nodes: Vec<&Node> = self.nodes.values().collect();
            let edges: Vec<&Edge> = self.edges.values().collect();
            let doc = JsonDoc {
                schema: crate::schema::GraphSchema::current(),
                nodes: &nodes,
                edges: &edges,
            };
            let mut file = std::fs::File::create(&self.path)?;
            serde_json::to_writer_pretty(&mut file, &doc)?;
            file.write_all(b"\n")?;
        }
        self.dirty = false;
        Ok(())
    }

    /// Persist any buffered writes. Safe to call repeatedly.
    pub fn commit(&mut self) -> Result<(), std::io::Error> {
        if self.dirty {
            self.flush()?;
        }
        Ok(())
    }

    fn flush_jsonl(&self) -> Result<(), std::io::Error> {
        let nodes_path = self.path.with_extension("nodes.jsonl");
        let edges_path = self.path.with_extension("edges.jsonl");
        let mut nf = std::fs::File::create(&nodes_path)?;
        for n in self.nodes.values() {
            serde_json::to_writer(&mut nf, n)?;
            nf.write_all(b"\n")?;
        }
        let mut ef = std::fs::File::create(&edges_path)?;
        for e in self.edges.values() {
            serde_json::to_writer(&mut ef, e)?;
            ef.write_all(b"\n")?;
        }
        // Write a tiny manifest so consumers know where the data is.
        let manifest = serde_json::json!({
            "format": "jsonl",
            "schema": crate::schema::GraphSchema::current(),
            "nodes_file": nodes_path,
            "edges_file": edges_path,
            "node_count": self.nodes.len(),
            "edge_count": self.edges.len(),
        });
        let mut mf = std::fs::File::create(&self.path)?;
        serde_json::to_writer_pretty(&mut mf, &manifest)?;
        mf.write_all(b"\n")?;
        Ok(())
    }

    fn load(&mut self) -> Result<(), JsonError> {
        if !self.path.exists() {
            return Ok(());
        }
        // The file is one of three shapes:
        //   1. a multi-line pretty-printed `JsonDocOwned` (the small-graph
        //      flush path, first line will just be "{")
        //   2. a single-line manifest with `"format": "jsonl"` (the
        //      streaming flush path; nodes/edges in sibling .jsonl files)
        //   3. mixed JSONL, each line is a Node or Edge
        // Empty files are valid (a fresh handle on a NamedTempFile); we
        // shortcut on zero length to avoid serde failing with "EOF while
        // parsing".
        let raw = std::fs::read_to_string(&self.path)?;
        if raw.trim().is_empty() {
            return Ok(());
        }

        let trimmed_full = raw.trim_start();
        if trimmed_full.starts_with('{') {
            // Try the whole file as one JSON object first, covers
            // cases (1) and (2). Fall back to per-line manifest parse.
            if let Ok(doc) = serde_json::from_str::<JsonDocOwned>(&raw) {
                // Reject graphs written by a newer code version that this
                // binary doesn't understand (forward incompatibility guard).
                doc.schema.validate().map_err(|e| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                })?;
                for n in doc.nodes {
                    Self::merge_node(&mut self.nodes, n);
                }
                for e in doc.edges {
                    Self::merge_edge(&mut self.edges, e);
                }
                return Ok(());
            }
            // If the file starts with '{' but isn't a monolithic doc, it
            // might be a JSONL manifest or mixed JSONL. Don't let a
            // "trailing characters" error escape, fall through to line-
            // by-line handling.
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                if val.get("format").and_then(|v| v.as_str()) == Some("jsonl") {
                    // Forward-incompatibility guard: validate the
                    // manifest schema version before loading sibling
                    // JSONL files (same guard as the monolithic doc path).
                    let schema_val = val.get("schema").ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "JSONL manifest missing required `schema` field",
                        )
                    })?;
                    let schema: crate::schema::GraphSchema = serde_json::from_value(
                        schema_val.clone(),
                    )
                    .map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;
                    schema.validate().map_err(|e| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                    })?;

                    // The manifest *names* the sibling jsonl files. A
                    // malicious manifest could try to point those names at
                    // /etc/passwd, ~/.ssh/id_rsa, etc., and surface their
                    // contents via serde parse-error messages. Constrain
                    // both to the manifest's parent directory and reject
                    // any path that escapes via .. or absolute prefix.
                    let parent = self
                        .path
                        .parent()
                        .map(Path::to_path_buf)
                        .unwrap_or_else(|| PathBuf::from("."));
                    let resolve_sibling = |raw: Option<&str>, default: PathBuf| -> PathBuf {
                        let Some(raw) = raw else { return default };
                        let candidate = PathBuf::from(raw);
                        let file_name = candidate.file_name();
                        let stays_in_parent = !candidate.is_absolute()
                            && !candidate
                                .components()
                                .any(|c| matches!(c, std::path::Component::ParentDir));
                        match (file_name, stays_in_parent) {
                            (Some(name), true) => parent.join(name),
                            _ => default,
                        }
                    };
                    let nodes_file = resolve_sibling(
                        val.get("nodes_file").and_then(|v| v.as_str()),
                        self.path.with_extension("nodes.jsonl"),
                    );
                    let edges_file = resolve_sibling(
                        val.get("edges_file").and_then(|v| v.as_str()),
                        self.path.with_extension("edges.jsonl"),
                    );
                    for n in read_jsonl::<Node>(&nodes_file)? {
                        Self::merge_node(&mut self.nodes, n);
                    }
                    for e in read_jsonl::<Edge>(&edges_file)? {
                        Self::merge_edge(&mut self.edges, e);
                    }
                    return Ok(());
                }
            }
            // Fall through to mixed-JSONL handling below.
        }

        // Mixed JSONL: each non-empty line is a Node or Edge,
        // discriminated by presence of `source_id`.
        for line in raw.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let val: serde_json::Value = serde_json::from_str(line)?;
            if val.get("source_id").is_some() {
                Self::merge_edge(&mut self.edges, serde_json::from_value(val)?);
            } else {
                Self::merge_node(&mut self.nodes, serde_json::from_value(val)?);
            }
        }
        Ok(())
    }

    fn merge_node(map: &mut HashMap<String, Node>, node: Node) {
        if let Some(existing) = map.get_mut(&node.id) {
            existing.kind = node.kind;
            existing.label = node.label.clone();
            existing.payload = node.payload.clone();
            existing.last_seen_ms = node.last_seen_ms;
        } else {
            map.insert(node.id.clone(), node);
        }
    }

    fn merge_edge(map: &mut HashMap<EdgeKey, Edge>, edge: Edge) {
        let key = (edge.source_id.clone(), edge.target_id.clone(), edge.kind);
        if let Some(existing) = map.get_mut(&key) {
            existing.payload = edge.payload.clone();
            existing.last_seen_ms = edge.last_seen_ms;
        } else {
            map.insert(key, edge);
        }
    }
}

fn read_jsonl<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>, JsonError> {
    let mut out = Vec::new();
    if !path.exists() {
        return Ok(out);
    }
    let file = std::fs::File::open(path)?;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
    }
    Ok(out)
}

#[derive(Debug, serde::Serialize)]
struct JsonDoc<'a> {
    schema: crate::schema::GraphSchema,
    nodes: &'a [&'a Node],
    edges: &'a [&'a Edge],
}

#[derive(Debug, serde::Deserialize)]
struct JsonDocOwned {
    schema: crate::schema::GraphSchema,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
}

/// Error type for JSON backend operations.
#[derive(Debug, thiserror::Error)]
pub enum JsonError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}


impl Drop for JsonBackend {
    fn drop(&mut self) {
        if self.dirty {
            if let Err(e) = self.flush() {
                tracing::error!(error = %e, path = %self.path.display(), "json deferred flush on drop failed");
            }
        }
    }
}

impl GraphBackend for JsonBackend {
    type Error = JsonError;

    fn init(&mut self) -> Result<(), Self::Error> {
        self.load()?;
        Ok(())
    }

    fn write_nodes(&mut self, nodes: &[Node]) -> Result<(), Self::Error> {
        for n in nodes {
            JsonBackend::merge_node(&mut self.nodes, n.clone());
        }
        self.dirty = true;
        Ok(())
    }

    fn write_edges(&mut self, edges: &[Edge]) -> Result<(), Self::Error> {
        for e in edges {
            JsonBackend::merge_edge(&mut self.edges, e.clone());
        }
        self.dirty = true;
        Ok(())
    }

    fn read_nodes(&self) -> Result<Vec<Node>, Self::Error> {
        Ok(self.nodes.values().cloned().collect())
    }

    fn read_edges(&self) -> Result<Vec<Edge>, Self::Error> {
        Ok(self.edges.values().cloned().collect())
    }

    fn find_nodes_by_type(&self, kind: crate::schema::NodeType) -> Result<Vec<Node>, Self::Error> {
        Ok(self
            .nodes
            .values()
            .filter(|n| n.kind == kind)
            .cloned()
            .collect())
    }

    fn neighbors(
        &self,
        node_id: &str,
        edge_type: Option<EdgeType>,
    ) -> Result<Vec<Edge>, Self::Error> {
        Ok(self
            .edges
            .values()
            .filter(|e| {
                e.source_id == node_id && edge_type.as_ref().map_or(true, |et| e.kind == *et)
            })
            .cloned()
            .collect())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.nodes.clear();
        self.edges.clear();
        self.dirty = false;
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("nodes.jsonl"));
        let _ = std::fs::remove_file(self.path.with_extension("edges.jsonl"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::NodeType;
    use tempfile::NamedTempFile;

    #[test]
    fn json_roundtrip() {
        let file = NamedTempFile::new().unwrap();
        let mut backend = JsonBackend::open(file.path());
        backend.init().unwrap();

        let node = Node::new("n1", NodeType::Domain, "example.com");
        backend.write_nodes(&[node.clone()]).unwrap();

        let edge = Edge::new("n1", "n2", EdgeType::ResolvesTo);
        backend.write_edges(&[edge.clone()]).unwrap();
        backend.commit().unwrap();

        // Re-open and verify
        let mut backend2 = JsonBackend::open(file.path());
        backend2.init().unwrap();

        let nodes = backend2.read_nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "n1");

        let edges = backend2.read_edges().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source_id, "n1");
    }

    /// Re-writing the same node id collapses to one row and last-write-wins.
    #[test]
    fn json_backend_rewrite_dedups_nodes() {
        let file = NamedTempFile::new().unwrap();
        let mut backend = JsonBackend::open(file.path());
        let mut first = Node::new("n1", NodeType::Domain, "first");
        first.label = "first-label".to_string();
        backend.write_nodes(&[first]).unwrap();

        let mut second = Node::new("n1", NodeType::Ip, "second");
        second.label = "second-label".to_string();
        backend.write_nodes(&[second]).unwrap();
        backend.commit().unwrap();

        let mut backend2 = JsonBackend::open(file.path());
        backend2.init().unwrap();
        let nodes = backend2.read_nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].kind, NodeType::Ip);
        assert_eq!(nodes[0].label, "second-label");
    }

    /// Re-writing the same edge triple collapses to one row.
    #[test]
    fn json_backend_rewrite_dedups_edges() {
        let file = NamedTempFile::new().unwrap();
        let mut backend = JsonBackend::open(file.path());
        backend.write_edges(&[Edge::new("a", "b", EdgeType::ResolvesTo)]).unwrap();
        backend.write_edges(&[Edge::new("a", "b", EdgeType::ResolvesTo)]).unwrap();
        backend.commit().unwrap();

        let mut backend2 = JsonBackend::open(file.path());
        backend2.init().unwrap();
        assert_eq!(backend2.read_edges().unwrap().len(), 1);
    }

    /// Adversarial: a malicious manifest that names an absolute or
    /// `..`-escaped path for `nodes_file` / `edges_file` MUST be
    /// silently ignored, the loader falls back to the safe sibling
    /// default, so we never read /etc/passwd or surface its content
    /// through serde parse-error messages.
    #[test]
    fn json_load_rejects_path_traversal_in_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("scan.json");

        // Drop a benign sibling so the safe default load resolves to
        // an empty corpus rather than an "no such file" error.
        std::fs::write(manifest.with_extension("nodes.jsonl"), "").unwrap();
        std::fs::write(manifest.with_extension("edges.jsonl"), "").unwrap();

        // Sentinel target the attacker would love to leak.
        let sentinel = dir.path().join("secret.jsonl");
        std::fs::write(
            &sentinel,
            r#"{"id":"leaked","kind":"Domain","label":"x"}"#,
        ).unwrap();

        let manifest_body = serde_json::json!({
            "format": "jsonl",
            "schema": crate::schema::GraphSchema::current(),
            "nodes_file": sentinel.to_string_lossy(),
            "edges_file": "../../../etc/passwd",
            "node_count": 0,
            "edge_count": 0,
        });
        std::fs::write(&manifest, serde_json::to_string(&manifest_body).unwrap()).unwrap();

        let mut backend = JsonBackend::open(&manifest);
        backend.init().expect("safe fallback load should succeed");

        let nodes = backend.read_nodes().unwrap();
        assert!(
            !nodes.iter().any(|n| n.id == "leaked"),
            "manifest-named absolute path was followed, path-traversal guard regressed"
        );
    }

    #[test]
    fn json_streaming_threshold() {
        let file = NamedTempFile::new().unwrap();
        let mut backend = JsonBackend::open(file.path());
        backend.init().unwrap();

        // Write just over the threshold
        let mut nodes = Vec::new();
        for i in 0..DEFAULT_STREAMING_THRESHOLD + 1 {
            nodes.push(Node::new(
                format!("n{i}"),
                NodeType::Subdomain,
                format!("sub{i}.example.com"),
            ));
        }
        backend.write_nodes(&nodes).unwrap();
        backend.commit().unwrap();

        // Re-open and verify
        let mut backend2 = JsonBackend::open(file.path());
        backend2.init().unwrap();
        let read_nodes = backend2.read_nodes().unwrap();
        assert_eq!(read_nodes.len(), DEFAULT_STREAMING_THRESHOLD + 1);
    }

    #[test]
    fn json_streaming_threshold_is_configurable() {
        let file = NamedTempFile::new().unwrap();
        let mut backend = JsonBackend::open_with_threshold(file.path(), 3);
        backend.init().unwrap();

        let nodes: Vec<Node> = (0..4)
            .map(|i| {
                Node::new(
                    format!("n{i}"),
                    NodeType::Subdomain,
                    format!("sub{i}.example.com"),
                )
            })
            .collect();
        backend.write_nodes(&nodes).unwrap();
        backend.commit().unwrap();

        assert!(
            file.path().with_extension("nodes.jsonl").exists(),
            "custom threshold of 3 must trigger JSONL streaming at 4 nodes"
        );

        // Config-owned threshold must be honored the same way.
        let file2 = NamedTempFile::new().unwrap();
        let cfg = gossan_core::Config {
            graph_json_streaming_threshold: 2,
            ..gossan_core::Config::default()
        };
        let mut backend2 = JsonBackend::open_from_config(file2.path(), &cfg);
        backend2.init().unwrap();
        let nodes2: Vec<Node> = (0..3)
            .map(|i| Node::new(format!("c{i}"), NodeType::Domain, format!("{i}.com")))
            .collect();
        backend2.write_nodes(&nodes2).unwrap();
        backend2.commit().unwrap();
        assert!(
            file2.path().with_extension("nodes.jsonl").exists(),
            "Config::graph_json_streaming_threshold must drive JsonBackend streaming"
        );
    }

    /// JSONL manifests written by a newer schema version must be rejected.
    #[test]
    fn jsonl_manifest_missing_schema_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("scan.json");
        let nodes_file = manifest.with_extension("nodes.jsonl");
        let edges_file = manifest.with_extension("edges.jsonl");
        std::fs::write(
            &nodes_file,
            r#"{"id":"n1","kind":"Domain","label":"x"}"#,
        ).unwrap();
        std::fs::write(&edges_file, "").unwrap();

        let manifest_body = serde_json::json!({
            "format": "jsonl",
            "nodes_file": nodes_file.to_string_lossy(),
            "edges_file": edges_file.to_string_lossy(),
            "node_count": 1,
            "edge_count": 0,
        });
        std::fs::write(&manifest, serde_json::to_string(&manifest_body).unwrap()).unwrap();

        let mut backend = JsonBackend::open(&manifest);
        assert!(
            backend.init().is_err(),
            "JSONL manifest without schema must be rejected"
        );
    }

        fn jsonl_manifest_schema_version_guard() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = dir.path().join("scan.json");
        let nodes_file = manifest.with_extension("nodes.jsonl");
        let edges_file = manifest.with_extension("edges.jsonl");
        std::fs::write(
            &nodes_file,
            r#"{"id":"n1","kind":"Domain","label":"x"}"#,
        ).unwrap();
        std::fs::write(&edges_file, "").unwrap();

        let manifest_body = serde_json::json!({
            "format": "jsonl",
            "schema": { "version": 999999 },
            "nodes_file": nodes_file.to_string_lossy(),
            "edges_file": edges_file.to_string_lossy(),
            "node_count": 1,
            "edge_count": 0,
        });
        std::fs::write(&manifest, serde_json::to_string(&manifest_body).unwrap()).unwrap();

        let mut backend = JsonBackend::open(&manifest);
        assert!(backend.init().is_err(), "future schema version must be rejected");
    }
}
