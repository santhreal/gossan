//! Bulk data ingestion from external sources into the intel database.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use anyhow::Context;
use crate::db::{IntelDb, IntelRecord};
/// Bulk dataset ingester — imports Project Sonar, Censys, and crt.sh dumps.
pub struct Ingester;

impl Ingester {
    pub fn ingest_jsonl(db: &IntelDb, path: impl AsRef<Path>) -> anyhow::Result<usize> {
        let file = File::open(path).context("opening jsonl file for ingestion")?;
        let reader = BufReader::new(file);
        let mut batch = Vec::with_capacity(1000);
        let mut total = 0;

        for line in reader.lines() {
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    tracing::warn!(error = %e, "malformed line in bulk data, skipping");
                    continue;
                }
            };

            if line.trim().is_empty() {
                continue;
            }

            // Parse line, trimming any trailing whitespace
            let trimmed_line = line.trim();
            match serde_json::from_str::<IntelRecord>(trimmed_line) {
                Ok(record) => {
                    batch.push(record);
                    if batch.len() >= 1000 {
                        db.insert_batch(&batch)?;
                        total += batch.len();
                        batch.clear();
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to parse jsonl line, skipping");
                    continue;
                }
            }
        }

        if !batch.is_empty() {
            db.insert_batch(&batch)?;
            total += batch.len();
        }

        Ok(total)
    }
}
