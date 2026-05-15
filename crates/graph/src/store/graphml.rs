//! GraphML backend for interoperability with network-analysis tools.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::store::GraphBackend;
use crate::{schema::EdgeType, Edge, Node};

/// GraphML file backend.
pub struct GraphMlBackend {
    path: PathBuf,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
}

impl GraphMlBackend {
    /// Open or create a GraphML file.
    pub fn open<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    fn flush(&self) -> Result<(), GraphMlError> {
        let mut f = std::fs::File::create(&self.path)?;
        write_graphml(&mut f, &self.nodes, &self.edges)?;
        Ok(())
    }

    fn load(&mut self) -> Result<(), GraphMlError> {
        if !self.path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(&self.path)?;
        let (nodes, edges) = parse_graphml(&content)?;
        self.nodes = nodes;
        self.edges = edges;
        Ok(())
    }
}

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

fn write_graphml(w: &mut impl Write, nodes: &[Node], edges: &[Edge]) -> Result<(), std::io::Error> {
    writeln!(w, r#"<?xml version="1.0" encoding="UTF-8"?>"#)?;
    writeln!(
        w,
        r#"<graphml xmlns="http://graphml.graphdrawing.org/xmlns">"#
    )?;

    // Keys for node data
    writeln!(
        w,
        r#"<key id="kind" for="node" attr.name="kind" attr.type="string"/>"#
    )?;
    writeln!(
        w,
        r#"<key id="label" for="node" attr.name="label" attr.type="string"/>"#
    )?;
    writeln!(
        w,
        r#"<key id="payload" for="node" attr.name="payload" attr.type="string"/>"#
    )?;

    // Keys for edge data
    writeln!(
        w,
        r#"<key id="etype" for="edge" attr.name="type" attr.type="string"/>"#
    )?;
    writeln!(
        w,
        r#"<key id="epayload" for="edge" attr.name="payload" attr.type="string"/>"#
    )?;

    writeln!(w, r#"<graph id="G" edgedefault="directed">"#)?;

    for n in nodes {
        write!(w, r#"<node id="{}" >"#, xml_escape(&n.id))?;
        writeln!(
            w,
            r#"<data key="kind">{}</data>"#,
            xml_escape(&n.kind.to_string())
        )?;
        writeln!(w, r#"<data key="label">{}</data>"#, xml_escape(&n.label))?;
        if let Some(ref p) = n.payload {
            writeln!(
                w,
                r#"<data key="payload">{}</data>"#,
                xml_escape(&p.to_string())
            )?;
        }
        writeln!(w, "</node>")?;
    }

    for e in edges {
        write!(
            w,
            r#"<edge source="{}" target="{}">"#,
            xml_escape(&e.source_id),
            xml_escape(&e.target_id)
        )?;
        writeln!(
            w,
            r#"<data key="etype">{}</data>"#,
            xml_escape(&e.kind.to_string())
        )?;
        if let Some(ref p) = e.payload {
            writeln!(
                w,
                r#"<data key="epayload">{}</data>"#,
                xml_escape(&p.to_string())
            )?;
        }
        writeln!(w, "</edge>")?;
    }

    writeln!(w, "</graph>")?;
    writeln!(w, "</graphml>")?;
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn parse_graphml(content: &str) -> Result<(Vec<Node>, Vec<Edge>), GraphMlError> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // Very lightweight parser — we look for <node id="..."> ... </node>
    // and <edge source="..." target="..."> ... </edge> blocks.
    // This avoids pulling in an XML crate.
    // The `(?s)` flag makes `.` match newlines so the lazy `(.*?)`
    // inside <node> / <edge> / <data> blocks can span the multi-line
    // pretty-printed output written by `write_graphml`. Without it
    // every roundtrip silently dropped its payload.
    let node_re = regex::Regex::new(r#"(?s)<node\s+id="([^"]+)"[^>]*>(.*?)</node>"#)
        .map_err(|e| GraphMlError::Xml(e.to_string()))?;

    let edge_re =
        regex::Regex::new(r#"(?s)<edge\s+source="([^"]+)"\s+target="([^"]+)"[^>]*>(.*?)</edge>"#)
            .map_err(|e| GraphMlError::Xml(e.to_string()))?;

    let data_re = regex::Regex::new(r#"(?s)<data\s+key="([^"]+)">(.*?)</data>"#)
        .map_err(|e| GraphMlError::Xml(e.to_string()))?;

    for cap in node_re.captures_iter(content) {
        let id = cap[1].to_string();
        let inner = &cap[2];
        let mut kind = None;
        let mut label = None;
        let mut payload = None;
        for dcap in data_re.captures_iter(inner) {
            let key = &dcap[1];
            let value = xml_unescape(&dcap[2]);
            match key {
                "kind" => kind = parse_node_type(&value),
                "label" => label = Some(value),
                "payload" => payload = serde_json::from_str(&value).ok(),
                _ => {}
            }
        }
        let kind = kind.unwrap_or(crate::schema::NodeType::Finding);
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
        let source_id = cap[1].to_string();
        let target_id = cap[2].to_string();
        let inner = &cap[3];
        let mut kind = None;
        let mut payload = None;
        for dcap in data_re.captures_iter(inner) {
            let key = &dcap[1];
            let value = xml_unescape(&dcap[2]);
            match key {
                "etype" => kind = parse_edge_type(&value),
                "epayload" => payload = serde_json::from_str(&value).ok(),
                _ => {}
            }
        }
        let kind = kind.unwrap_or(EdgeType::HasFinding);
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

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn parse_node_type(s: &str) -> Option<crate::schema::NodeType> {
    use crate::schema::NodeType;
    match s {
        "domain" => Some(NodeType::Domain),
        "subdomain" => Some(NodeType::Subdomain),
        "ip" => Some(NodeType::Ip),
        "port" => Some(NodeType::Port),
        "service" => Some(NodeType::Service),
        "tech" => Some(NodeType::Tech),
        "endpoint" => Some(NodeType::Endpoint),
        "secret" => Some(NodeType::Secret),
        "cloud" => Some(NodeType::Cloud),
        "finding" => Some(NodeType::Finding),
        _ => None,
    }
}

fn parse_edge_type(s: &str) -> Option<EdgeType> {
    match s {
        "RESOLVES_TO" => Some(EdgeType::ResolvesTo),
        "HOSTS" => Some(EdgeType::Hosts),
        "RUNS" => Some(EdgeType::Runs),
        "EXPOSES" => Some(EdgeType::Exposes),
        "LEAKS" => Some(EdgeType::Leaks),
        "MISCONFIGURED" => Some(EdgeType::Misconfigured),
        "HAS_FINDING" => Some(EdgeType::HasFinding),
        "HAS_SERVICE" => Some(EdgeType::HasService),
        _ => None,
    }
}

impl GraphBackend for GraphMlBackend {
    type Error = GraphMlError;

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
    fn xml_escape_unescape_roundtrip() {
        let original = r#"<script>alert("xss")</script>"#;
        let escaped = xml_escape(original);
        let unescaped = xml_unescape(&escaped);
        assert_eq!(original, unescaped);
    }
}
