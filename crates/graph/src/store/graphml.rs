//! GraphML backend for interoperability with network-analysis tools.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::store::GraphBackend;
use crate::{schema::EdgeType, Edge, Node};

/// GraphML file backend.
pub struct GraphMlBackend {
    path: PathBuf,
    nodes: HashMap<String, Node>,
    edges: HashMap<EdgeKey, Edge>,
    dirty: bool,
}

type EdgeKey = (String, String, EdgeType);

/// Error type for GraphML operations.
#[derive(Debug, thiserror::Error)]
pub enum GraphMlError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("XML parse error: {0}")]
    Xml(String),
    #[error("Missing attribute: {0}")]
    MissingAttr(String),
}

impl GraphMlBackend {
    /// Open or create a GraphML file.
    pub fn open<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            nodes: HashMap::new(),
            edges: HashMap::new(),
            dirty: false,
        }
    }

    fn flush(&mut self) -> Result<(), GraphMlError> {
        let mut f = std::fs::File::create(&self.path)?;
        write_graphml(&mut f, self.nodes.values(), self.edges.values())?;
        self.dirty = false;
        Ok(())
    }

    /// Persist any buffered writes. Safe to call repeatedly.
    pub fn commit(&mut self) -> Result<(), GraphMlError> {
        if self.dirty {
            self.flush()?;
        }
        Ok(())
    }

    fn load(&mut self) -> Result<(), GraphMlError> {
        if !self.path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(&self.path)?;
        let (nodes, edges) = parse_graphml(&content)?;
        for n in nodes {
            Self::merge_node(&mut self.nodes, n);
        }
        for e in edges {
            Self::merge_edge(&mut self.edges, e);
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

impl Drop for GraphMlBackend {
    fn drop(&mut self) {
        if self.dirty {
            if let Err(e) = self.flush() {
                tracing::error!(error = %e, path = %self.path.display(), "graphml deferred flush on drop failed");
            }
        }
    }
}

fn write_graphml<'a>(
    w: &mut impl Write,
    nodes: impl Iterator<Item = &'a Node>,
    edges: impl Iterator<Item = &'a Edge>,
) -> Result<(), std::io::Error> {
    writeln!(w, r#"<?xml version="1.0" encoding="UTF-8"?"#)?;
    writeln!(
        w,
        r#"<graphml xmlns="http://graphml.graphdrawing.org/xmlns">"#,
    )?;

    // Keys for node data
    writeln!(
        w,
        r#"<key id="kind" for="node" attr.name="kind" attr.type="string"/>"#,
    )?;
    writeln!(
        w,
        r#"<key id="label" for="node" attr.name="label" attr.type="string"/>"#,
    )?;
    writeln!(
        w,
        r#"<key id="payload" for="node" attr.name="payload" attr.type="string"/>"#,
    )?;

    // Keys for edge data
    writeln!(
        w,
        r#"<key id="etype" for="edge" attr.name="type" attr.type="string"/>"#,
    )?;
    writeln!(
        w,
        r#"<key id="epayload" for="edge" attr.name="payload" attr.type="string"/>"#,
    )?;

    writeln!(w, r#"<graph id="G" edgedefault="directed">"#)?;

    for n in nodes {
        write!(w, r#"<node id="{}">"#, gossan_core::xml_escape(&n.id))?;
        writeln!(
            w,
            r#"<data key="kind">{}</data>"#,
            gossan_core::xml_escape(&n.kind.to_string())
        )?;
        writeln!(
            w,
            r#"<data key="label">{}</data>"#,
            gossan_core::xml_escape(&n.label)
        )?;
        if let Some(p) = &n.payload {
            writeln!(
                w,
                r#"<data key="payload">{}</data>"#,
                gossan_core::xml_escape(&p.to_string())
            )?;
        }
        writeln!(w, "</node>")?;
    }

    for e in edges {
        write!(
            w,
            r#"<edge source="{}" target="{}">"#,
            gossan_core::xml_escape(&e.source_id),
            gossan_core::xml_escape(&e.target_id)
        )?;
        writeln!(
            w,
            r#"<data key="etype">{}</data>"#,
            gossan_core::xml_escape(&e.kind.to_string())
        )?;
        if let Some(p) = &e.payload {
            writeln!(
                w,
                r#"<data key="epayload">{}</data>"#,
                gossan_core::xml_escape(&p.to_string())
            )?;
        }
        writeln!(w, "</edge>")?;
    }

    writeln!(w, "</graph>\n</graphml>")?;
    Ok(())
}

/// Static compiled regexes for parsing GraphML, built once via `LazyLock`,
/// reused on every load.  Each `LazyLock` holds a `Result` so that a
/// malformed pattern is surfaced as a `GraphMlError::Xml` at parse time
/// rather than a panic (satisfying `deny(clippy::expect_used, panic)`).
static NODE_RE: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"(?s)<node\s+id="([^"]+)"[^\u003e]*>(.*?)</node>"#)
    });

static EDGE_RE: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(
            r#"(?s)<edge\s+source="([^"]+)"\s+target="([^"]+)"[^\u003e]*>(.*?)</edge>"#,
        )
    });

static DATA_RE: std::sync::LazyLock<Result<regex::Regex, regex::Error>> =
    std::sync::LazyLock::new(|| {
        regex::Regex::new(r#"(?s)<data\s+key="([^"]+)">(.*?)</data>"#)
    });

fn parse_graphml(content: &str) -> Result<(Vec<Node>, Vec<Edge>), GraphMlError> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // Very lightweight parser, we look for <node id="..."> ... </node>
    // and <edge source="..." target="..."> ... </edge> blocks.
    // This avoids pulling in an XML crate.
    // The `(?s)` flag makes `.` match newlines so the lazy `(.*?)`
    // inside <node> / <edge> / <data> blocks can span the multi-line
    // pretty-printed output written by `write_graphml`. Without it
    // every roundtrip silently dropped its payload.
    // Regexes are compiled once via LazyLock; no allocation per parse call.
    let node_re = NODE_RE
        .as_ref()
        .map_err(|e| GraphMlError::Xml(e.to_string()))?;
    let edge_re = EDGE_RE
        .as_ref()
        .map_err(|e| GraphMlError::Xml(e.to_string()))?;
    let data_re = DATA_RE
        .as_ref()
        .map_err(|e| GraphMlError::Xml(e.to_string()))?;

    for cap in node_re.captures_iter(content) {
        let id = gossan_core::xml_unescape(&cap[1]);
        let inner = &cap[2];
        let mut kind = None;
        let mut label = None;
        let mut payload = None;
        for dcap in data_re.captures_iter(inner) {
            let key = &dcap[1];
            let value = gossan_core::xml_unescape(&dcap[2]);
            match key {
                "kind" => kind = parse_node_type(&value),
                "label" => label = Some(value),
                "payload" => {
                    match serde_json::from_str(&value) {
                        Ok(v) => payload = Some(v),
                        Err(e) => tracing::warn!(
                            node_id = %id,
                            error = %e,
                            "skipping corrupt GraphML node payload JSON"
                        ),
                    }
                },
                _ => {}
            }
        }
        let Some(kind) = kind else {
            tracing::warn!(
                id = %id,
                "skipping GraphML node with unknown/missing kind tag"
            );
            continue;
        };
        let label = label.unwrap_or_else(|| id.clone());
        nodes.push(Node {
            id,
            kind,
            label,
            payload,
            first_seen_ms: 0,
            last_seen_ms: 0,
        });
    }

    for cap in edge_re.captures_iter(content) {
        let source_id = gossan_core::xml_unescape(&cap[1]);
        let target_id = gossan_core::xml_unescape(&cap[2]);
        let inner = &cap[3];
        let mut kind = None;
        let mut payload = None;
        for dcap in data_re.captures_iter(inner) {
            let key = &dcap[1];
            let value = gossan_core::xml_unescape(&dcap[2]);
            match key {
                "etype" => kind = parse_edge_type(&value),
                "epayload" => {
                    match serde_json::from_str(&value) {
                        Ok(v) => payload = Some(v),
                        Err(e) => tracing::warn!(
                            source_id = %source_id,
                            target_id = %target_id,
                            error = %e,
                            "skipping corrupt GraphML edge payload JSON"
                        ),
                    }
                },
                _ => {}
            }
        }
        let Some(kind) = kind else {
            tracing::warn!(
                source_id = %source_id,
                target_id = %target_id,
                "skipping GraphML edge with unknown/missing etype tag"
            );
            continue;
        };
        edges.push(Edge {
            source_id,
            target_id,
            kind,
            payload,
            first_seen_ms: 0,
            last_seen_ms: 0,
        });
    }

    Ok((nodes, edges))
}

// parse_node_type / parse_edge_type are canonical in super (store/mod.rs).
// Thin wrappers below delegate to super:: so the call sites above stay concise.
fn parse_node_type(s: &str) -> Option<crate::schema::NodeType> {
    super::parse_node_type(s)
}

fn parse_edge_type(s: &str) -> Option<EdgeType> {
    super::parse_edge_type(s)
}

impl GraphBackend for GraphMlBackend {
    type Error = GraphMlError;

    fn init(&mut self) -> Result<(), Self::Error> {
        self.load()?;
        Ok(())
    }

    fn write_nodes(&mut self, nodes: &[Node]) -> Result<(), Self::Error> {
        for n in nodes {
            GraphMlBackend::merge_node(&mut self.nodes, n.clone());
        }
        self.dirty = true;
        Ok(())
    }

    fn write_edges(&mut self, edges: &[Edge]) -> Result<(), Self::Error> {
        for e in edges {
            GraphMlBackend::merge_edge(&mut self.edges, e.clone());
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
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::NodeType;
    use tempfile::NamedTempFile;

    #[test]
    fn graphml_roundtrip() {
        let file = NamedTempFile::new().unwrap();
        let mut backend = GraphMlBackend::open(file.path());
        backend.init().unwrap();

        let node = Node::new("n1", NodeType::Domain, "example.com");
        backend.write_nodes(&[node.clone()]).unwrap();

        let edge = Edge::new("n1", "n2", EdgeType::ResolvesTo);
        backend.write_edges(&[edge.clone()]).unwrap();
        backend.commit().unwrap();

        let mut backend2 = GraphMlBackend::open(file.path());
        backend2.init().unwrap();

        let nodes = backend2.read_nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "n1");
        assert_eq!(nodes[0].kind, NodeType::Domain);
        assert_eq!(nodes[0].label, "example.com");

        let edges = backend2.read_edges().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, EdgeType::ResolvesTo);
    }

    #[test]
    fn graphml_rewrite_dedups_nodes() {
        let file = NamedTempFile::new().unwrap();
        let mut backend = GraphMlBackend::open(file.path());
        let mut first = Node::new("n1", NodeType::Domain, "first");
        first.label = "first-label".to_string();
        backend.write_nodes(&[first]).unwrap();

        let mut second = Node::new("n1", NodeType::Ip, "second");
        second.label = "second-label".to_string();
        backend.write_nodes(&[second]).unwrap();
        backend.commit().unwrap();

        let mut backend2 = GraphMlBackend::open(file.path());
        backend2.init().unwrap();
        let nodes = backend2.read_nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].kind, NodeType::Ip);
        assert_eq!(nodes[0].label, "second-label");
    }

    #[test]
    fn graphml_rewrite_dedups_edges() {
        let file = NamedTempFile::new().unwrap();
        let mut backend = GraphMlBackend::open(file.path());
        backend.write_edges(&[Edge::new("a", "b", EdgeType::ResolvesTo)]).unwrap();
        backend.write_edges(&[Edge::new("a", "b", EdgeType::ResolvesTo)]).unwrap();
        backend.commit().unwrap();

        let mut backend2 = GraphMlBackend::open(file.path());
        backend2.init().unwrap();
        assert_eq!(backend2.read_edges().unwrap().len(), 1);
    }

    #[test]
    fn xml_escape_unescape_roundtrip() {
        let original = r#"<script>alert("xss")</script>"#;
        let escaped = gossan_core::xml_escape(original);
        let unescaped = gossan_core::xml_unescape(&escaped);
        assert_eq!(original, unescaped);
    }
}
