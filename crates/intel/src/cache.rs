//! Persistent TTL cache for intel enrichment.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;

use crate::enrichment::IntelEnrichment;

/// SQLite-backed TTL cache keyed by (source, target_type, target_value).
pub struct IntelCache {
    conn: Mutex<Connection>,
}

impl IntelCache {
    /// Open or create the cache database.
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS cache (
                source TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_value TEXT NOT NULL,
                data TEXT NOT NULL,
                fetched_at INTEGER NOT NULL,
                PRIMARY KEY (source, target_type, target_value)
             );
             CREATE INDEX IF NOT EXISTS idx_cache_lookup ON cache(source, target_type, target_value);
             CREATE INDEX IF NOT EXISTS idx_cache_stale ON cache(fetched_at);"
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Get a cached enrichment if it exists and is not stale.
    pub fn get(
        &self,
        source: &str,
        target_type: &str,
        target_value: &str,
        ttl_secs: u64,
    ) -> anyhow::Result<Option<IntelEnrichment>> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        let row: Option<(String, i64)> = conn
            .query_row(
                "SELECT data, fetched_at FROM cache
             WHERE source = ?1 AND target_type = ?2 AND target_value = ?3",
                params![source, target_type, target_value],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;

        let Some((data, fetched_at)) = row else {
            return Ok(None);
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if now - fetched_at > ttl_secs as i64 {
            return Ok(None);
        }

        Ok(serde_json::from_str(&data).ok())
    }

    /// Store an enrichment in the cache.
    pub fn put(&self, enrichment: &IntelEnrichment) -> anyhow::Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        let data = serde_json::to_string(enrichment)?;
        conn.execute(
            "INSERT OR REPLACE INTO cache (source, target_type, target_value, data, fetched_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                enrichment.source,
                enrichment.target_type,
                enrichment.target_value,
                data,
                enrichment.fetched_at as i64
            ],
        )?;
        Ok(())
    }

    /// Evict entries older than `ttl_secs`.
    pub fn evict_stale(&self, ttl_secs: u64) -> anyhow::Result<usize> {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            - ttl_secs as i64;
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        let n = conn.execute("DELETE FROM cache WHERE fetched_at < ?1", params![cutoff])?;
        Ok(n)
    }

    /// Clear all cached data.
    pub fn clear(&self) -> anyhow::Result<()> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| anyhow::anyhow!("mutex poisoned: {e}"))?;
        conn.execute("DELETE FROM cache", [])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn cache_hit_and_miss() {
        let file = NamedTempFile::new().unwrap();
        let cache = IntelCache::open(file.path()).unwrap();

        let enrichment = IntelEnrichment::new("shodan", "ip", "1.2.3.4");
        cache.put(&enrichment).unwrap();

        let hit = cache.get("shodan", "ip", "1.2.3.4", 3600).unwrap();
        assert!(hit.is_some());

        let miss = cache.get("shodan", "ip", "5.6.7.8", 3600).unwrap();
        assert!(miss.is_none());
    }

    #[test]
    fn cache_ttl_respected() {
        let file = NamedTempFile::new().unwrap();
        let cache = IntelCache::open(file.path()).unwrap();

        let mut enrichment = IntelEnrichment::new("shodan", "ip", "1.2.3.4");
        enrichment.fetched_at = 0; // ancient
        cache.put(&enrichment).unwrap();

        let stale = cache.get("shodan", "ip", "1.2.3.4", 3600).unwrap();
        assert!(stale.is_none());
    }

    #[test]
    fn cache_persists_across_reopen() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();

        let cache = IntelCache::open(&path).unwrap();
        let enrichment = IntelEnrichment::new("vt", "domain", "example.com");
        cache.put(&enrichment).unwrap();
        drop(cache);

        let cache2 = IntelCache::open(&path).unwrap();
        let hit = cache2.get("vt", "domain", "example.com", 3600).unwrap();
        assert!(hit.is_some());
    }

    #[test]
    fn cache_evict_stale() {
        let file = NamedTempFile::new().unwrap();
        let cache = IntelCache::open(file.path()).unwrap();

        let mut old = IntelEnrichment::new("abuseipdb", "ip", "1.1.1.1");
        old.fetched_at = 0;
        cache.put(&old).unwrap();

        let n = cache.evict_stale(60).unwrap();
        assert_eq!(n, 1);

        let miss = cache.get("abuseipdb", "ip", "1.1.1.1", 3600).unwrap();
        assert!(miss.is_none());
    }
}
