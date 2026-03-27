//! Scan checkpoint and resume — persists stage results to a local SQLite file.
//!
//! # Usage
//! ```ignore
//! let store = CheckpointStore::open("gossan-scan.db")?;
//! let scan_id = store.new_scan("example.com", &config_json)?;
//!
//! // After each stage:
//! store.save_stage(scan_id, "subdomain", &targets, &findings)?;
//!
//! // On resume:
//! let record = store.load(scan_id)?;
//! if let Some(stage) = record.stage("subdomain") {
//!     // skip subdomain scan, restore targets
//! }
//! ```

use std::path::Path;

use anyhow::Context;
use chrono::Utc;
use gossan_core::Target;
use rusqlite::{params, Connection};
use secfinding::Finding;
use uuid::Uuid;

/// Persistent scan store backed by SQLite.
pub struct CheckpointStore {
    conn: Connection,
}

/// A single completed pipeline stage stored in the checkpoint.
pub struct StageRecord {
    pub stage: String,
    pub targets: Vec<Target>,
    pub findings: Vec<Finding>,
    pub completed_at: String,
}

/// All data for a saved scan — used to restore state on `--resume`.
pub struct ScanRecord {
    pub scan_id: Uuid,
    pub seed: String,
    pub stages: Vec<StageRecord>,
}

impl ScanRecord {
    /// Return the stage record for `name` if it was completed and saved.
    pub fn stage(&self, name: &str) -> Option<&StageRecord> {
        self.stages.iter().find(|s| s.stage == name)
    }
}

impl CheckpointStore {
    /// Open (or create) the SQLite checkpoint database at `path`.
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let conn = Connection::open(path).context("opening checkpoint database")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                scan_id    TEXT PRIMARY KEY,
                seed       TEXT NOT NULL,
                config     TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stages (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id       TEXT NOT NULL REFERENCES scans(scan_id),
                stage         TEXT NOT NULL,
                targets_json  TEXT NOT NULL,
                findings_json TEXT NOT NULL,
                completed_at  TEXT NOT NULL,
                UNIQUE(scan_id, stage)
            );",
        )
        .context("initialising checkpoint schema")?;
        Ok(Self { conn })
    }

    /// Create a new scan record and return its UUID.
    pub fn new_scan(&self, seed: &str, config_json: &str) -> anyhow::Result<Uuid> {
        let id = Uuid::new_v4();
        self.conn.execute(
            "INSERT INTO scans (scan_id, seed, config, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![id.to_string(), seed, config_json, Utc::now().to_rfc3339()],
        )?;
        Ok(id)
    }

    /// Persist a completed stage.
    pub fn save_stage(
        &self,
        scan_id: Uuid,
        stage: &str,
        targets: &[Target],
        findings: &[Finding],
    ) -> anyhow::Result<()> {
        let targets_json = serde_json::to_string(targets)?;
        let findings_json = serde_json::to_string(findings)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO stages
             (scan_id, stage, targets_json, findings_json, completed_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                scan_id.to_string(),
                stage,
                targets_json,
                findings_json,
                Utc::now().to_rfc3339()
            ],
        )?;
        tracing::debug!(scan_id = %scan_id, stage, "checkpoint saved");
        Ok(())
    }

    /// Load all stage records for a given scan UUID.
    pub fn load(&self, scan_id: Uuid) -> anyhow::Result<ScanRecord> {
        let seed: String = self
            .conn
            .query_row(
                "SELECT seed FROM scans WHERE scan_id = ?1",
                params![scan_id.to_string()],
                |row| row.get(0),
            )
            .context("scan not found")?;

        let mut stmt = self.conn.prepare(
            "SELECT stage, targets_json, findings_json, completed_at
             FROM stages WHERE scan_id = ?1 ORDER BY id",
        )?;

        // Collect raw rows first (can't deserialize inside the rusqlite closure due to borrow rules)
        let raw_rows: Vec<(String, String, String, String)> = stmt
            .query_map(params![scan_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?
            .collect::<Result<_, _>>()?;

        let stages = raw_rows
            .into_iter()
            .map(
                |(stage, t_json, f_json, completed_at)| -> anyhow::Result<StageRecord> {
                    Ok(StageRecord {
                        stage,
                        targets: serde_json::from_str(&t_json)?,
                        findings: serde_json::from_str(&f_json)?,
                        completed_at,
                    })
                },
            )
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(ScanRecord {
            scan_id,
            seed,
            stages,
        })
    }

    /// Delete a scan and all its stage records.
    pub fn delete_scan(&self, scan_id: Uuid) -> anyhow::Result<()> {
        self.conn.execute(
            "DELETE FROM stages WHERE scan_id = ?1",
            params![scan_id.to_string()],
        )?;
        self.conn.execute(
            "DELETE FROM scans  WHERE scan_id = ?1",
            params![scan_id.to_string()],
        )?;
        Ok(())
    }

    /// List all saved scan IDs and seeds (for `gossan list-scans`).
    pub fn list_scans(&self) -> anyhow::Result<Vec<(Uuid, String, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT scan_id, seed, created_at FROM scans ORDER BY created_at DESC")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?
            .filter_map(|r| r.ok())
            .filter_map(|(id, seed, ts)| Uuid::parse_str(&id).ok().map(|u| (u, seed, ts)))
            .collect();
        Ok(rows)
    }
}

#[cfg(test)]
mod tests {
    use gossan_core::{DiscoverySource, DomainTarget, Target};
    use secfinding::{Finding, Severity};

    use super::*;

    fn in_memory() -> CheckpointStore {
        CheckpointStore::open(":memory:").expect("in-memory store")
    }

    fn make_target(domain: &str) -> Target {
        Target::Domain(DomainTarget {
            domain: domain.into(),
            source: DiscoverySource::Seed,
        })
    }

    fn make_finding(title: &str) -> Finding {
        Finding::builder("portscan", "example.com", Severity::High)
            .title(title)
            .detail("detail")
            .build()
            .expect("finding builder: required fields are set")
    }

    #[test]
    fn new_scan_creates_record() {
        let store = in_memory();
        let id = store.new_scan("example.com", "{}").unwrap();
        let scans = store.list_scans().unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0].0, id);
        assert_eq!(scans[0].1, "example.com");
    }

    #[test]
    fn save_and_load_stage() {
        let store = in_memory();
        let id = store.new_scan("example.com", "{}").unwrap();

        let targets = vec![make_target("api.example.com")];
        let findings = vec![make_finding("Open port 443")];
        store
            .save_stage(id, "portscan", &targets, &findings)
            .unwrap();

        let record = store.load(id).unwrap();
        assert_eq!(record.seed, "example.com");
        let stage = record.stage("portscan").expect("stage should exist");
        assert_eq!(stage.targets.len(), 1);
        assert_eq!(stage.findings.len(), 1);
        assert_eq!(stage.findings[0].title, "Open port 443");
    }

    #[test]
    fn stage_not_found_returns_none() {
        let store = in_memory();
        let id = store.new_scan("example.com", "{}").unwrap();
        let record = store.load(id).unwrap();
        assert!(record.stage("subdomain").is_none());
    }

    #[test]
    fn save_stage_is_idempotent() {
        let store = in_memory();
        let id = store.new_scan("example.com", "{}").unwrap();
        store.save_stage(id, "dns", &[], &[]).unwrap();
        // Second save should replace (INSERT OR REPLACE), not error
        store
            .save_stage(id, "dns", &[make_target("example.com")], &[])
            .unwrap();
        let record = store.load(id).unwrap();
        assert_eq!(record.stage("dns").unwrap().targets.len(), 1);
    }

    #[test]
    fn load_missing_scan_errors() {
        let store = in_memory();
        let fake_id = Uuid::new_v4();
        assert!(store.load(fake_id).is_err());
    }

    #[test]
    fn delete_scan_removes_all_records() {
        let store = in_memory();
        let id = store.new_scan("example.com", "{}").unwrap();
        store.save_stage(id, "dns", &[], &[]).unwrap();
        store.delete_scan(id).unwrap();
        assert!(store.list_scans().unwrap().is_empty());
        assert!(store.load(id).is_err());
    }

    #[test]
    fn scan_record_stage_returns_matching_stage() {
        let record = ScanRecord {
            scan_id: Uuid::new_v4(),
            seed: "example.com".into(),
            stages: vec![StageRecord {
                stage: "dns".into(),
                targets: vec![],
                findings: vec![],
                completed_at: "now".into(),
            }],
        };
        assert_eq!(record.stage("dns").unwrap().stage, "dns");
    }

    #[test]
    fn list_scans_returns_multiple_entries() {
        let store = in_memory();
        store.new_scan("one.example", "{}").unwrap();
        store.new_scan("two.example", "{}").unwrap();
        assert_eq!(store.list_scans().unwrap().len(), 2);
    }
}
