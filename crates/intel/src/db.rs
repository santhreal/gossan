//! SQLite-backed passive intelligence database.

use std::path::Path;

use anyhow::Context;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

/// A single passive intelligence record from bulk datasets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntelRecord {
    pub ip: String,
    pub host: Option<String>,
    pub port: u16,
    pub protocol: String,
    pub banner: Option<String>,
    #[serde(default)]
    pub tech_stack: Vec<String>,
    pub last_seen: Option<String>,
}

/// SQLite-backed passive intelligence database for bulk dataset queries.
pub struct IntelDb {
    // Wrap connection in a Mutex to allow sharing across threads safely
    conn: Mutex<Connection>,
}

impl IntelDb {
    /// Test-only access to the raw SQLite connection.
    ///
    /// Used by integration tests in `tests/intel_tests.rs` to insert
    /// deliberately-corrupt rows that exercise the `query_*`
    /// error-handling paths. NOT intended for production use — open
    /// a fresh `Connection` if you need direct SQL access elsewhere.
    #[doc(hidden)]
    pub fn _test_conn(&self) -> &Mutex<Connection> {
        &self.conn
    }
}

impl IntelDb {
    /// Open an intel database at the given path.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let conn = Connection::open(path).context("opening intel database")?;

        // Optimize for high-speed ingestion
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -64000; -- 64MB cache
             PRAGMA temp_store = MEMORY;",
        )?;

        // SQLite treats NULLs as distinct in inline UNIQUE constraints,
        // so two records with the same (ip, port, protocol) but null
        // host would silently both insert. The expression-based unique
        // index uses COALESCE so null host collapses to '', matching
        // the semantic intent of "same target = same row".
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS intel (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL,
                host        TEXT,
                port        INTEGER NOT NULL,
                protocol    TEXT NOT NULL,
                banner      TEXT,
                tech_stack  TEXT, -- JSON array
                last_seen   TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_intel_unique
                ON intel(ip, COALESCE(host, ''), port, protocol);
            CREATE INDEX IF NOT EXISTS idx_intel_ip ON intel(ip);
            CREATE INDEX IF NOT EXISTS idx_intel_host ON intel(host);",
        )
        .context("initialising intel schema")?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Insert a batch of records transactionally.
    pub fn insert_batch(&self, records: &[IntelRecord]) -> anyhow::Result<()> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        let tx = conn.transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO intel (ip, host, port, protocol, banner, tech_stack, last_seen)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?;

            for r in records {
                let tech_json = serde_json::to_string(&r.tech_stack)?;
                stmt.execute(params![
                    r.ip,
                    r.host,
                    r.port,
                    r.protocol,
                    r.banner,
                    tech_json,
                    r.last_seen
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Query records by IP.
    pub fn query_by_ip(&self, ip: &str) -> anyhow::Result<Vec<IntelRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        let mut stmt = conn.prepare(
            "SELECT ip, host, port, protocol, banner, tech_stack, last_seen
             FROM intel WHERE ip = ?1",
        )?;

        let rows = stmt.query_map(params![ip], |row| {
            let tech_json: String = row.get(5)?;
            let tech_stack: Vec<String> = serde_json::from_str(&tech_json).unwrap_or_default();
            let port_i32: i32 = row.get(2)?;
            let port = u16::try_from(port_i32)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, port_i32.into()))?;
            Ok(IntelRecord {
                ip: row.get(0)?,
                host: row.get(1)?,
                port,
                protocol: row.get(3)?,
                banner: row.get(4)?,
                tech_stack,
                last_seen: row.get(6)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Query records by hostname.
    pub fn query_by_host(&self, host: &str) -> anyhow::Result<Vec<IntelRecord>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        let mut stmt = conn.prepare(
            "SELECT ip, host, port, protocol, banner, tech_stack, last_seen
             FROM intel WHERE host = ?1",
        )?;

        let rows = stmt.query_map(params![host], |row| {
            let tech_json: String = row.get(5)?;
            let tech_stack: Vec<String> = serde_json::from_str(&tech_json).unwrap_or_default();
            let port_i32: i32 = row.get(2)?;
            let port = u16::try_from(port_i32)
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(2, port_i32.into()))?;
            Ok(IntelRecord {
                ip: row.get(0)?,
                host: row.get(1)?,
                port,
                protocol: row.get(3)?,
                banner: row.get(4)?,
                tech_stack,
                last_seen: row.get(6)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}
