//! Per GOSSAN_LEGENDARY A18 / B section: schema-migration v(N)→v(N+1)
//! upgrade path. Existing implementation in
//! `crates/graph/src/store/sqlite.rs::init_schema` runs `migrate(v,
//! SCHEMA_VERSION)` whenever the on-disk version is older than the
//! code version.
//!
//! This test simulates a downgraded schema_version row to prove the
//! upgrade path executes and lands a fresh row at the current
//! SCHEMA_VERSION on reopen.

use gossan_graph::schema::SCHEMA_VERSION;
use gossan_graph::store::sqlite::SqliteBackend;
use gossan_graph::store::GraphBackend;
use rusqlite::Connection;
use tempfile::TempDir;

#[test]
fn old_schema_version_triggers_migration_to_current() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("graph.sqlite");

    // Open once so the schema is initialized at the current version.
    {
        let mut backend = SqliteBackend::open(&path).expect("first open");
        backend.init().expect("init");
    }

    // Manually downgrade schema_version to 0 (simulating a database
    // written by an older binary).
    {
        let conn = Connection::open(&path).expect("downgrade open");
        conn.execute("DELETE FROM schema_version", [])
            .expect("clear");
        conn.execute("INSERT INTO schema_version (version) VALUES (0)", [])
            .expect("insert v0");
    }

    // Reopen — `init_schema` should detect v0 and migrate to current.
    let _backend = SqliteBackend::open(&path).expect("reopen-after-downgrade");

    // Verify the migrated row exists.
    let conn = Connection::open(&path).unwrap();
    let max_v: i64 = conn
        .query_row(
            "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("query max version");
    assert_eq!(max_v, i64::from(SCHEMA_VERSION));
}

#[test]
fn newer_schema_version_is_rejected() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("graph.sqlite");

    {
        let mut backend = SqliteBackend::open(&path).expect("first open");
        backend.init().expect("init");
    }

    // Write a future schema version that gossan doesn't know yet.
    let conn = Connection::open(&path).unwrap();
    conn.execute("DELETE FROM schema_version", []).unwrap();
    conn.execute(
        "INSERT INTO schema_version (version) VALUES (?1)",
        rusqlite::params![SCHEMA_VERSION + 100],
    )
    .unwrap();
    drop(conn);

    // Reopen should error (we won't drop user data, but we won't pretend to know how to read it either).
    let r = SqliteBackend::open(&path);
    assert!(
        r.is_err(),
        "opening DB with future schema must fail (refuse to corrupt data)"
    );
}
