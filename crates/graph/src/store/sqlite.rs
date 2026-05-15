//! SQLite backend with schema versioning and temporal diffing.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Transaction};
use chrono::NaiveDateTime;

use crate::schema::{EdgeType, NodeType, SCHEMA_VERSION};
use crate::store::GraphBackend;
use crate::{Edge, Node};

/// SQLite-backed graph store.
pub struct SqliteBackend {
    conn: Connection,
}

/// Temporal diff between two scans.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanDiff {
    pub added_targets: Vec<gossan_core::Target>,
    pub removed_targets: Vec<gossan_core::Target>,
    pub changed_targets: Vec<gossan_core::Target>,
    pub added_findings: Vec<secfinding::Finding>,
    pub removed_findings: Vec<secfinding::Finding>,
    pub changed_findings: Vec<secfinding::Finding>,
}

impl SqliteBackend {
    /// Convert milliseconds timestamp to SQLite datetime string.
    fn ms_to_datetime(ms: u64) -> String {
        let seconds = (ms / 1000) as i64;
        match chrono::DateTime::from_timestamp(seconds, 0) {
            Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
            None => "1970-01-01 00:00:00".to_string(),
        }
    }

    /// Convert SQLite datetime string to milliseconds timestamp.
    fn datetime_to_ms(dt_str: &str) -> u64 {
        match NaiveDateTime::parse_from_str(dt_str, "%Y-%m-%d %H:%M:%S") {
            Ok(dt) => dt.and_utc().timestamp() as u64 * 1000,
            Err(_) => 0,
        }
    }

    /// Open or create a SQLite graph database.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SqliteError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;
        let mut backend = Self { conn };
        backend.init_schema()?;
        Ok(backend)
    }

    /// Open an in-memory database for testing.
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, SqliteError> {
        let conn = Connection::open_in_memory()?;
        let mut backend = Self { conn };
        backend.init_schema()?;
        Ok(backend)
    }

    fn init_schema(&mut self) -> Result<(), SqliteError> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                label TEXT NOT NULL,
                data TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL DEFAULT 'finding',
                label TEXT NOT NULL,
                data TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS relationships (
                source_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                rel_type TEXT NOT NULL,
                data TEXT,
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (source_id, target_id, rel_type)
            );
            CREATE INDEX IF NOT EXISTS idx_relationships_source ON relationships(source_id);
            CREATE INDEX IF NOT EXISTS idx_relationships_target ON relationships(target_id);
            CREATE INDEX IF NOT EXISTS idx_targets_kind ON targets(kind);
            CREATE INDEX IF NOT EXISTS idx_findings_kind ON findings(kind);
            ",
        )?;

        let current: Option<i64> = self
            .conn
            .query_row(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;

        match current {
            None => {
                self.conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?1)",
                    params![SCHEMA_VERSION],
                )?;
            }
            Some(v) => {
                let v = v as u32;
                if v > SCHEMA_VERSION {
                    return Err(SqliteError::Schema(
                        crate::schema::SchemaError::UnsupportedVersion {
                            found: v,
                            max_supported: SCHEMA_VERSION,
                        }
                        .to_string(),
                    ));
                }
                // Run migrations here when SCHEMA_VERSION is bumped.
                if v < SCHEMA_VERSION {
                    self.migrate(v, SCHEMA_VERSION)?;
                }
            }
        }

        Ok(())
    }

    fn migrate(&mut self, from: u32, to: u32) -> Result<(), SqliteError> {
        let tx = self.conn.transaction()?;
        // Placeholder for future migrations.
        // Example:
        // if from < 2 {
        //     tx.execute("ALTER TABLE nodes ADD COLUMN new_col TEXT", [])?;
        // }
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![to],
        )?;
        tx.commit()?;
        tracing::info!(from, to, "graph schema migrated");
        Ok(())
    }

    /// Persist a scan of targets and findings, inferring edges.
    pub fn persist_scan(
        &mut self,
        targets: &[gossan_core::Target],
        findings: &[secfinding::Finding],
    ) -> Result<(), SqliteError> {
        let tx = self.conn.transaction()?;

        for target in targets {
            let node = target_to_node(target);
            Self::upsert_node(&tx, &node)?;
            Self::insert_inferred_target_edges(&tx, target)?;
        }

        for finding in findings {
            let node = finding_to_node(finding);
            Self::upsert_node(&tx, &node)?;

            let target_id = target_id_from_finding(finding)?;
            // A finding's target row must exist before we can hang an
            // edge on it. Callers may legitimately persist findings
            // without first persisting the matching Target (e.g. an
            // out-of-band scanner that only emits findings). Insert a
            // stub Target node — INSERT OR IGNORE means real Target
            // payloads from a same-transaction targets[] entry win.
            Self::insert_stub_target_for_finding(&tx, &target_id, finding)?;
            let edge = Edge::new(&target_id, &node.id, EdgeType::HasFinding);
            Self::upsert_edge(&tx, &edge)?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Compute temporal diff.
    pub fn compute_diff(
        &self,
        targets: &[gossan_core::Target],
        findings: &[secfinding::Finding],
        removed_threshold: std::time::Duration,
    ) -> Result<ScanDiff, SqliteError> {
        let mut diff = ScanDiff {
            added_targets: Vec::new(),
            removed_targets: Vec::new(),
            changed_targets: Vec::new(),
            added_findings: Vec::new(),
            removed_findings: Vec::new(),
            changed_findings: Vec::new(),
        };

        for target in targets {
            let id = target_id(target);
            let existing: Option<String> = self
                .conn
                .query_row(
                    "SELECT data FROM targets WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()?;
            // Compare structurally, not by raw string. The stored `data`
            // column was written by `Node::with_payload` (which goes
            // target → serde_json::Value → Value::to_string) while the
            // diff side serialises target directly. Both should be
            // semantically identical, but key ordering / whitespace /
            // numeric formatting are not contractually byte-equal across
            // those two paths. Decoding both sides to a comparable shape
            // is the only way to ask "did this target actually change?".
            match existing {
                None => diff.added_targets.push(target.clone()),
                Some(old) => {
                    let stored_val: serde_json::Value =
                        serde_json::from_str(&old).unwrap_or(serde_json::Value::Null);
                    let new_val = serde_json::to_value(target)?;
                    if stored_val != new_val {
                        diff.changed_targets.push(target.clone());
                    }
                }
            }
        }

        for finding in findings {
            let id = finding_id(finding);
            let existing: Option<String> = self
                .conn
                .query_row(
                    "SELECT data FROM findings WHERE id = ?1",
                    params![id],
                    |row| row.get(0),
                )
                .optional()?;
            match existing {
                None => diff.added_findings.push(finding.clone()),
                Some(old) => {
                    let stored_val: serde_json::Value =
                        serde_json::from_str(&old).unwrap_or(serde_json::Value::Null);
                    let new_val = serde_json::to_value(finding)?;
                    if stored_val != new_val {
                        diff.changed_findings.push(finding.clone());
                    }
                }
            }
        }

        // Clamp threshold to SQLite's practical limit (~100 years in seconds)
        let threshold_secs = removed_threshold.as_secs().min(3_153_600_000u64) as i64;
        let threshold_datetime = format!("-{} seconds", threshold_secs);

        let mut stmt = self.conn.prepare(
            "SELECT data FROM targets 
             WHERE kind IN ('domain','host','service','web','network','repository','package')
               AND last_seen <= datetime('now', ?1)",
        )?;
        let rows = stmt.query_map(params![threshold_datetime], |row| {
            let data: String = row.get(0)?;
            serde_json::from_str::<gossan_core::Target>(&data)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                ))
        })?;
        for r in rows {
            diff.removed_targets.push(r?);
        }

        let mut stmt = self.conn.prepare(
            "SELECT data FROM findings 
             WHERE last_seen <= datetime('now', ?1)",
        )?;
        let rows = stmt.query_map(params![threshold_datetime], |row| {
            let data: String = row.get(0)?;
            serde_json::from_str::<secfinding::Finding>(&data).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })
        })?;
        for r in rows {
            diff.removed_findings.push(r?);
        }

        Ok(diff)
    }

    fn upsert_node(tx: &Transaction, node: &Node) -> Result<(), SqliteError> {
        let data = node
            .payload
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_default();
        let first_seen = Self::ms_to_datetime(node.first_seen_ms);
        let last_seen = Self::ms_to_datetime(node.last_seen_ms);
        
        // Determine table based on node type
        let table = if node.kind == NodeType::Finding {
            "findings"
        } else {
            "targets"
        };
        
        let insert_query = format!(
            "INSERT OR IGNORE INTO {} (id, kind, label, data, first_seen, last_seen) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            table
        );
        tx.execute(
            &insert_query,
            params![
                node.id,
                node.kind.to_string(),
                node.label,
                data,
                first_seen,
                last_seen
            ],
        )?;
        
        let update_query = format!(
            "UPDATE {} SET last_seen = ?2, data = ?3 WHERE id = ?1",
            table
        );
        tx.execute(
            &update_query,
            params![node.id, last_seen, data],
        )?;
        Ok(())
    }

    fn upsert_edge(tx: &Transaction, edge: &Edge) -> Result<(), SqliteError> {
        let data = edge
            .payload
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or_default();
        let first_seen = Self::ms_to_datetime(edge.first_seen_ms);
        let last_seen = Self::ms_to_datetime(edge.last_seen_ms);
        
        tx.execute(
            "INSERT OR IGNORE INTO relationships (source_id, target_id, rel_type, data, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                edge.source_id,
                edge.target_id,
                edge.kind.to_string(),
                data,
                first_seen,
                last_seen
            ],
        )?;
        tx.execute(
            "UPDATE relationships SET last_seen = ?4, data = ?5
             WHERE source_id = ?1 AND target_id = ?2 AND rel_type = ?3",
            params![edge.source_id, edge.target_id, edge.kind.to_string(), last_seen, data],
        )?;
        Ok(())
    }

    fn insert_stub_target_for_finding(
        tx: &Transaction,
        target_id: &str,
        finding: &secfinding::Finding,
    ) -> Result<(), SqliteError> {
        // Derive NodeType from the target_id's prefix (set by
        // target_id_from_finding). Default to Endpoint for anything
        // not in the known set so we don't lose the row.
        let kind = match target_id.split_once(':').map(|(p, _)| p) {
            Some("domain") => NodeType::Domain,
            Some("host") => NodeType::Ip,
            Some("service") => NodeType::Service,
            Some("web") => NodeType::Endpoint,
            _ => NodeType::Endpoint,
        };
        let label = finding.target().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let now_dt = Self::ms_to_datetime(now);
        // INSERT OR IGNORE only — never clobber a real Target row that
        // was upserted earlier in the same transaction with a real
        // payload.
        tx.execute(
            "INSERT OR IGNORE INTO targets (id, kind, label, data, first_seen, last_seen)
             VALUES (?1, ?2, ?3, '', ?4, ?5)",
            params![target_id, kind.to_string(), label, now_dt, now_dt],
        )?;
        Ok(())
    }

    fn insert_inferred_target_edges(
        tx: &Transaction,
        target: &gossan_core::Target,
    ) -> Result<(), SqliteError> {
        match target {
            gossan_core::Target::Host(h) => {
                if let Some(domain) = &h.domain {
                    let e = Edge::new(
                        format!("domain:{domain}"),
                        format!("host:{}", h.ip),
                        EdgeType::ResolvesTo,
                    );
                    Self::upsert_edge(tx, &e)?;
                }
            }
            gossan_core::Target::Service(s) => {
                let e = Edge::new(
                    format!("host:{}", s.host.ip),
                    format!("service:{}:{}", s.host.ip, s.port),
                    EdgeType::HasService,
                );
                Self::upsert_edge(tx, &e)?;
                if let Some(domain) = &s.host.domain {
                    let e = Edge::new(
                        format!("domain:{domain}"),
                        format!("service:{}:{}", s.host.ip, s.port),
                        EdgeType::HasService,
                    );
                    Self::upsert_edge(tx, &e)?;
                }
            }
            gossan_core::Target::Web(w) => {
                let e = Edge::new(
                    format!("service:{}:{}", w.service.host.ip, w.service.port),
                    format!("web:{}", w.url),
                    EdgeType::Exposes,
                );
                Self::upsert_edge(tx, &e)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Raw SQL escape hatch for advanced queries.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}

impl GraphBackend for SqliteBackend {
    type Error = SqliteError;

    fn init(&mut self) -> Result<(), Self::Error> {
        self.init_schema()?;
        Ok(())
    }

    fn write_nodes(&mut self, nodes: &[Node]) -> Result<(), Self::Error> {
        let tx = self.conn.transaction()?;
        for n in nodes {
            Self::upsert_node(&tx, n)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn write_edges(&mut self, edges: &[Edge]) -> Result<(), Self::Error> {
        let tx = self.conn.transaction()?;
        for e in edges {
            Self::upsert_edge(&tx, e)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn read_nodes(&self) -> Result<Vec<Node>, Self::Error> {
        let mut nodes = Vec::new();
        
        // Read from targets table
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, label, data, first_seen, last_seen FROM targets",
        )?;
        let target_rows = stmt.query_map([], |row| {
            let kind_str: String = row.get(1)?;
            let data_str: String = row.get(3)?;
            let first_seen_str: String = row.get(4)?;
            let last_seen_str: String = row.get(5)?;
            Ok(Node {
                id: row.get(0)?,
                kind: parse_node_type(&kind_str).unwrap_or(NodeType::Domain),
                label: row.get(2)?,
                payload: if data_str.is_empty() {
                    None
                } else {
                    serde_json::from_str(&data_str).ok()
                },
                first_seen_ms: Self::datetime_to_ms(&first_seen_str),
                last_seen_ms: Self::datetime_to_ms(&last_seen_str),
            })
        })?;
        for row in target_rows {
            nodes.push(row?);
        }
        
        // Read from findings table
        let mut stmt = self.conn.prepare(
            "SELECT id, kind, label, data, first_seen, last_seen FROM findings",
        )?;
        let finding_rows = stmt.query_map([], |row| {
            let kind_str: String = row.get(1)?;
            let data_str: String = row.get(3)?;
            let first_seen_str: String = row.get(4)?;
            let last_seen_str: String = row.get(5)?;
            Ok(Node {
                id: row.get(0)?,
                kind: parse_node_type(&kind_str).unwrap_or(NodeType::Finding),
                label: row.get(2)?,
                payload: if data_str.is_empty() {
                    None
                } else {
                    serde_json::from_str(&data_str).ok()
                },
                first_seen_ms: Self::datetime_to_ms(&first_seen_str),
                last_seen_ms: Self::datetime_to_ms(&last_seen_str),
            })
        })?;
        for row in finding_rows {
            nodes.push(row?);
        }
        
        Ok(nodes)
    }

    fn read_edges(&self) -> Result<Vec<Edge>, Self::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT source_id, target_id, rel_type, data, first_seen, last_seen FROM relationships",
        )?;
        let rows = stmt.query_map([], |row| {
            let kind_str: String = row.get(2)?;
            let data_str: String = row.get(3)?;
            let first_seen_str: String = row.get(4)?;
            let last_seen_str: String = row.get(5)?;
            Ok(Edge {
                source_id: row.get(0)?,
                target_id: row.get(1)?,
                kind: parse_edge_type(&kind_str).unwrap_or(EdgeType::HasFinding),
                payload: if data_str.is_empty() {
                    None
                } else {
                    serde_json::from_str(&data_str).ok()
                },
                first_seen_ms: Self::datetime_to_ms(&first_seen_str),
                last_seen_ms: Self::datetime_to_ms(&last_seen_str),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    fn find_nodes_by_type(&self, kind: NodeType) -> Result<Vec<Node>, Self::Error> {
        let kind_str = kind.to_string();
        let table = if kind == NodeType::Finding {
            "findings"
        } else {
            "targets"
        };
        
        let query = format!(
            "SELECT id, kind, label, data, first_seen, last_seen FROM {} WHERE kind = ?1",
            table
        );
        let mut stmt = self.conn.prepare(&query)?;
        let rows = stmt.query_map(params![kind_str], |row| {
            let data_str: String = row.get(3)?;
            let first_seen_str: String = row.get(4)?;
            let last_seen_str: String = row.get(5)?;
            Ok(Node {
                id: row.get(0)?,
                kind: kind.clone(),
                label: row.get(2)?,
                payload: if data_str.is_empty() {
                    None
                } else {
                    serde_json::from_str(&data_str).ok()
                },
                first_seen_ms: Self::datetime_to_ms(&first_seen_str),
                last_seen_ms: Self::datetime_to_ms(&last_seen_str),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    fn neighbors(
        &self,
        node_id: &str,
        edge_type: Option<EdgeType>,
    ) -> Result<Vec<Edge>, Self::Error> {
        let node_id = node_id.to_string();
        let mut stmt = match edge_type {
            Some(ref et) => self.conn.prepare(
                "SELECT source_id, target_id, rel_type, data, first_seen, last_seen
                 FROM relationships WHERE source_id = ?1 AND rel_type = ?2",
            )?,
            None => self.conn.prepare(
                "SELECT source_id, target_id, rel_type, data, first_seen, last_seen
                 FROM relationships WHERE source_id = ?1",
            )?,
        };
        let map_row = |row: &rusqlite::Row<'_>| -> Result<Edge, rusqlite::Error> {
            let kind_str: String = row.get(2)?;
            let data_str: String = row.get(3)?;
            let first_seen_str: String = row.get(4)?;
            let last_seen_str: String = row.get(5)?;
            Ok(Edge {
                source_id: row.get(0)?,
                target_id: row.get(1)?,
                kind: parse_edge_type(&kind_str).unwrap_or(EdgeType::HasFinding),
                payload: if data_str.is_empty() {
                    None
                } else {
                    serde_json::from_str(&data_str).ok()
                },
                first_seen_ms: Self::datetime_to_ms(&first_seen_str),
                last_seen_ms: Self::datetime_to_ms(&last_seen_str),
            })
        };
        let rows = match edge_type {
            Some(et) => stmt.query_map(params![node_id, et.to_string()], map_row)?,
            None => stmt.query_map(params![node_id], map_row)?,
        };
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        self.conn.execute("DELETE FROM relationships", [])?;
        self.conn.execute("DELETE FROM findings", [])?;
        self.conn.execute("DELETE FROM targets", [])?;
        Ok(())
    }
}

/// Error type for SQLite backend operations.
#[derive(Debug, thiserror::Error)]
pub enum SqliteError {
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Schema error: {0}")]
    Schema(String),
}

/// Compute the deterministic node ID for a `Target`. Used internally
/// by the SQLite backend (as the `target_id` column on `edges` /
/// `findings`) and by external callers that want to round-trip
/// Target identity through a graph store. Promoted to `pub` so the
/// legendary unit test can pin the ID format
/// (`domain:<host>` / `host:<ip>` / `service:<ip>:<port>` / etc.)
/// without depending on the `target_id_from_finding` flavour, which
/// works on findings instead of targets.
pub fn target_id(target: &gossan_core::Target) -> String {
    match target {
        gossan_core::Target::Domain(d) => format!("domain:{}", d.domain),
        gossan_core::Target::Host(h) => format!("host:{}", h.ip),
        gossan_core::Target::Service(s) => format!("service:{}:{}", s.host.ip, s.port),
        gossan_core::Target::Web(w) => format!("web:{}", w.url),
        gossan_core::Target::Network(n) => format!("network:{}", n.cidr),
        gossan_core::Target::Repository(r) => format!("repo:{}", r.url),
        gossan_core::Target::InternalPackage(p) => format!("pkg:{}", p.name),
        _ => {
            let data = serde_json::to_string(target).unwrap_or_default();
            format!("unknown:{}", &data[..data.len().min(120)])
        }
    }
}

fn target_to_node(target: &gossan_core::Target) -> Node {
    let id = target_id(target);
    let (kind, label) = match target {
        gossan_core::Target::Domain(d) => (NodeType::Domain, d.domain.clone()),
        gossan_core::Target::Host(h) => (NodeType::Ip, h.ip.to_string()),
        gossan_core::Target::Service(s) => {
            (NodeType::Service, format!("{}:{}", s.host.ip, s.port))
        }
        gossan_core::Target::Web(w) => (NodeType::Endpoint, w.url.to_string()),
        gossan_core::Target::Network(n) => (NodeType::Ip, n.cidr.clone()),
        gossan_core::Target::Repository(r) => (NodeType::Endpoint, r.url.to_string()),
        gossan_core::Target::InternalPackage(p) => (NodeType::Endpoint, p.name.clone()),
        _ => (NodeType::Endpoint, id.clone()),
    };
    Node::new(id, kind, label).with_payload(target)
}

fn finding_id(finding: &secfinding::Finding) -> String {
    let namespace = uuid::Uuid::NAMESPACE_OID;
    let content = format!(
        "{}:{}:{:?}:{}",
        finding.target(),
        finding.title(),
        finding.severity(),
        finding.detail()
    );
    let id = uuid::Uuid::new_v5(&namespace, content.as_bytes());
    format!("finding:{id}")
}

fn finding_to_node(finding: &secfinding::Finding) -> Node {
    let id = finding_id(finding);
    Node::new(id, NodeType::Finding, finding.title().to_string()).with_payload(finding)
}

/// Derive a target node id from a finding target string.
///
/// # Errors
///
/// Returns an error if the target string cannot be parsed into a known shape.
pub fn target_id_from_finding(finding: &secfinding::Finding) -> Result<String, SqliteError> {
    let t = finding.target();

    // Try URL first — but only treat it as a Web target if the parser
    // actually saw a recognized HTTP-family scheme. `url::Url::parse`
    // is happy to interpret `"example.com:443"` as `scheme=example.com,
    // path=443`, which would misclassify a bare host:port pair as a
    // Web URL.
    if let Ok(url) = url::Url::parse(t) {
        if matches!(url.scheme(), "http" | "https" | "ws" | "wss" | "ftp") {
            return Ok(format!("web:{}", url));
        }
    }

    // Try IP address (IPv4 and IPv6)
    if t.parse::<std::net::IpAddr>().is_ok() {
        return Ok(format!("host:{t}"));
    }

    // Try bracketed IPv6
    if t.starts_with('[') && t.contains("]:") {
        if let Some(idx) = t.find(']') {
            let ip_part = &t[1..idx];
            if ip_part.parse::<std::net::IpAddr>().is_ok() {
                return Ok(format!("service:{t}"));
            }
        }
    }

    // host:port or ip:port — but avoid misclassifying domains like example.com:443
    if let Some((host, port)) = t.rsplit_once(':') {
        if port.parse::<u16>().is_ok() {
            if host.parse::<std::net::IpAddr>().is_ok() {
                return Ok(format!("service:{t}"));
            }
            // If it looks like a bare IPv6 without brackets, reject rather than guess.
            if host.contains(':') {
                return Err(SqliteError::Schema(format!(
                    "ambiguous IPv6 service target without brackets: {t}"
                )));
            }
        }
    }

    // Default: domain
    Ok(format!("domain:{t}"))
}

fn parse_node_type(s: &str) -> Option<NodeType> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_id_from_finding_url() {
        let f = secfinding::Finding::new(
            "s",
            "https://example.com/path",
            secfinding::Severity::Info,
            "t",
            "",
        )
        .unwrap();
        assert_eq!(
            target_id_from_finding(&f).unwrap(),
            "web:https://example.com/path"
        );
    }

    #[test]
    fn target_id_from_finding_ipv4() {
        let f = secfinding::Finding::new("s", "1.2.3.4", secfinding::Severity::Info, "t", "")
            .unwrap();
        assert_eq!(target_id_from_finding(&f).unwrap(), "host:1.2.3.4");
    }

    #[test]
    fn target_id_from_finding_ipv6() {
        let f =
            secfinding::Finding::new("s", "::1", secfinding::Severity::Info, "t", "").unwrap();
        assert_eq!(target_id_from_finding(&f).unwrap(), "host:::1");
    }

    #[test]
    fn target_id_from_finding_service() {
        let f =
            secfinding::Finding::new("s", "1.2.3.4:443", secfinding::Severity::Info, "t", "")
                .unwrap();
        assert_eq!(target_id_from_finding(&f).unwrap(), "service:1.2.3.4:443");
    }

    #[test]
    fn target_id_from_finding_domain_with_port() {
        let f = secfinding::Finding::new(
            "s",
            "example.com:443",
            secfinding::Severity::Info,
            "t",
            "",
        )
        .unwrap();
        // Domain with port but no scheme falls through to domain.
        assert_eq!(target_id_from_finding(&f).unwrap(), "domain:example.com:443");
    }

    #[test]
    fn sqlite_roundtrip() {
        let mut backend = SqliteBackend::open_in_memory().unwrap();
        let node = Node::new("n1", NodeType::Domain, "example.com");
        backend.write_nodes(&[node]).unwrap();

        let edge = Edge::new("n1", "n2", EdgeType::ResolvesTo);
        backend.write_edges(&[edge]).unwrap();

        let nodes = backend.read_nodes().unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, "n1");

        let edges = backend.read_edges().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind, EdgeType::ResolvesTo);
    }

    #[test]
    fn schema_version_tracked() {
        let backend = SqliteBackend::open_in_memory().unwrap();
        let v: i64 = backend
            .conn()
            .query_row(
                "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(v, i64::from(SCHEMA_VERSION));
    }
}
