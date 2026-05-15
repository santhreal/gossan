//! JSON graph backend — stores nodes and edges as a single JSON document.
//!
//! For large graphs (>10K nodes) the backend automatically flushes to a
//! streaming JSONL file instead of a monolithic array.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::store::GraphBackend;
use crate::{schema::EdgeType, Edge, Node};

/// In-memory + JSON file backend.
pub struct JsonBackend {
    path: PathBuf,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
}

/// Threshold above which we prefer JSONL streaming for writes.
const STREAMING_THRESHOLD: usize = 10_000;

impl JsonBackend {
    /// Open or create a JSON graph file.
    pub fn open<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    fn flush(&self) -> Result<(), std::io::Error> {
        if self.nodes.len() + self.edges.len() > STREAMING_THRESHOLD {
            self.flush_jsonl()?;
        } else {
            let doc = JsonDoc {
                schema: crate::schema::GraphSchema::current(),
                nodes: &self.nodes,
                edges: &self.edges,
            };
            let mut file = std::fs::File::create(&self.path)?;
            serde_json::to_writer_pretty(&mut file, &doc)?;
            file.write_all(b"\n")?;
        }
        Ok(())
    }

    fn flush_jsonl(&self) -> Result<(), std::io::Error> {
        let nodes_path = self.path.with_extension("nodes.jsonl");
        let edges_path = self.path.with_extension("edges.jsonl");
        let mut nf = std::fs::File::create(&nodes_path)?;
        for n in &self.nodes {
            serde_json::to_writer(&mut nf, n)?;
            nf.write_all(b"\n")?;
        }
        let mut ef = std::fs::File::create(&edges_path)?;
        for e in &self.edges {
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
        //      flush path — first line will just be "{")
        //   2. a single-line manifest with `"format": "jsonl"` (the
        //      streaming flush path; nodes/edges in sibling .jsonl files)
        //   3. mixed JSONL — each line is a Node or Edge
        // Empty files are valid (a fresh handle on a NamedTempFile); we
        // shortcut on zero length to avoid serde failing with "EOF while
        // parsing".
        let raw = std::fs::read_to_string(&self.path)?;
        if raw.trim().is_empty() {
            return Ok(());
        }

        let trimmed_full = raw.trim_start();
        if trimmed_full.starts_with('{') {
            // Try the whole file as one JSON object first — covers
            // cases (1) and (2). Fall back to per-line manifest parse.
            if let Ok(doc) = serde_json::from_str::<JsonDocOwned>(&raw) {
                self.nodes = doc.nodes;
                self.edges = doc.edges;
                return Ok(());
            }
            let val: serde_json::Value = serde_json::from_str(&raw)?;
            if val.get("format").and_then(|v| v.as_str()) == Some("jsonl") {
                let nodes_file = val
                    .get("nodes_file")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.path.with_extension("nodes.jsonl"));
                let edges_file = val
                    .get("edges_file")
                    .and_then(|v| v.as_str())
                    .map(PathBuf::from)
                    .unwrap_or_else(|| self.path.with_extension("edges.jsonl"));
                self.nodes = read_jsonl(&nodes_file)?;
                self.edges = read_jsonl(&edges_file)?;
                return Ok(());
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
                self.edges.push(serde_json::from_value(val)?);
            } else {
                self.nodes.push(serde_json::from_value(val)?);
            }
        }
        Ok(())
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
    nodes: &'a [Node],
    edges: &'a [Edge],
}

#[derive(Debug, serde::Deserialize)]
struct JsonDocOwned {
    #[allow(dead_code)]
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

impl GraphBackend for JsonBackend {
    type Error = JsonError;

    fn init(&mut self) -> Result<(), Self::Error> {
        self.load()?;
        Ok(())
    }

    fn write_nodes(&mut self, nodes: &[Node]) -> Result<(), Self::Error> {
        self.nodes.extend(nodes.iter().cloned());
        self.flush()?;
        Ok(())
    }

    fn write_edges(&mut self, edges: &[Edge]) -> Result<(), Self::Error> {
        self.edges.extend(edges.iter().cloned());
        self.flush()?;
        Ok(())
    }

    fn read_nodes(&self) -> Result<Vec<Node>, Self::Error> {
        Ok(self.nodes.clone())
    }

    fn read_edges(&self) -> Result<Vec<Edge>, Self::Error> {
        Ok(self.edges.clone())
    }

    fn find_nodes_by_type(&self, kind: crate::schema::NodeType) -> Result<Vec<Node>, Self::Error> {
        Ok(self
            .nodes
            .iter()
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
            .iter()
            .filter(|e| {
                e.source_id == node_id && edge_type.as_ref().map_or(true, |et| e.kind == *et)
            })
            .cloned()
            .collect())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.nodes.clear();
        self.edges.clear();
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

    #[test]
    fn json_streaming_threshold() {
        let file = NamedTempFile::new().unwrap();
        let mut backend = JsonBackend::open(file.path());
        backend.init().unwrap();

        // Write just over the threshold
        let mut nodes = Vec::new();
        for i in 0..STREAMING_THRESHOLD + 1 {
            nodes.push(Node::new(
                format!("n{i}"),
                NodeType::Subdomain,
                format!("sub{i}.example.com"),
            ));
        }
        backend.write_nodes(&nodes).unwrap();

        // Manifest should exist
        assert!(file.path().exists());
        assert!(file.path().with_extension("nodes.jsonl").exists());

        let mut backend2 = JsonBackend::open(file.path());
        backend2.init().unwrap();
        assert_eq!(
            backend2.read_nodes().unwrap().len(),
            STREAMING_THRESHOLD + 1
        );
    }
}
