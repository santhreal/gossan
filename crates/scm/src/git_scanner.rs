use gossan_core::target::RepositoryTarget;
use gossan_core::{Config, ScanInput};
use gossan_keyhog_lite::{Chunk, ChunkMetadata, CompiledScanner};
use secfinding::{Evidence, Finding, Severity};
use std::sync::OnceLock;
use tempfile::tempdir;
use tracing::{info, warn};

/// Maximum blob size scanned per file. Files larger than this are
/// skipped entirely. Prevents OOM when a malicious or degenerate
/// repository contains multi-gigabyte binary blobs.
const MAX_BLOB_BYTES: usize = 4 * 1024 * 1024; // 4 MB

static KEYHOG_SCANNER: OnceLock<CompiledScanner> = OnceLock::new();

fn get_scanner() -> &'static CompiledScanner {
    KEYHOG_SCANNER.get_or_init(|| {
        let detectors = gossan_keyhog_lite::embedded_detectors();
        assert!(
            !detectors.is_empty(),
            "embedded KeyHog detector corpus is empty; refusing to disable secret detection"
        );
        CompiledScanner::compile(detectors).unwrap_or_else(|e| {
            panic!("failed to compile embedded KeyHog detector corpus: {e}")
        })
    })
}

fn map_severity(s: gossan_keyhog_lite::Severity) -> Severity {
    match s {
        gossan_keyhog_lite::Severity::Info => Severity::Info,
        gossan_keyhog_lite::Severity::Low => Severity::Low,
        gossan_keyhog_lite::Severity::Medium => Severity::Medium,
        gossan_keyhog_lite::Severity::High => Severity::High,
        gossan_keyhog_lite::Severity::Critical => Severity::Critical,
    }
}

/// Emit findings for all secrets detected in a single blob.
///
/// Raw credentials are stored in the canonical `gossan-secret-verify` store
/// (keyed by SHA-256 hash) so that the shared `VerifierEngine` can resolve
/// them for live verification. The local duplicate store that existed here
/// before was unreachable by the verifier and has been removed.
fn emit_blob_findings(
    scanner: &CompiledScanner,
    blob_text: &str,
    path: &str,
    commit: &str,
    target_url: &str,
    input: &ScanInput,
) {
    let chunk = Chunk {
        data: blob_text.to_string(),
        metadata: ChunkMetadata {
            source_type: "scm".into(),
            path: Some(path.to_string()),
            commit: Some(commit.to_string()),
            author: None,
            date: None,
        },
    };

    let matches = scanner.scan(&chunk);
    for m in matches {
        let severity = map_severity(m.severity);

        // Use the canonical hasher from gossan-secret-verify to produce
        // a stable correlation key, identical algorithm to what js/secrets.rs
        // uses, so findings from both scanners hash consistently.
        let hash = gossan_secret_verify::hash_secret(&m.credential);

        // Store raw credential in the process-local canonical store so the
        // VerifierEngine in gossan-secret-verify can recover it for live
        // verification.  Do NOT log or embed the raw value anywhere.
        gossan_secret_verify::store_raw_secret(&hash, &m.credential);

        let builder = Finding::builder("scm", target_url, severity)
            .title(format!("Hardcoded {} identified", m.detector_name))
            .detail(format!(
                "A potential {} was found in {}.",
                m.detector_name, path
            ))
            .evidence(Evidence::CodeSnippet {
                file: std::sync::Arc::from(path),
                line: m.location.line.unwrap_or(0),
                column: None,
                snippet: std::sync::Arc::from(
                    gossan_keyhog_lite::redact(&m.credential).as_str(),
                ),
                language: None,
            })
            .tag("secret")
            .tag("keyhog")
            .tag(format!("det:{}", m.detector_id))
            .tag(format!("hash:{}", hash))
            .tag(m.service.to_string())
            .kind(secfinding::FindingKind::SecretLeak);

        if let Some(f) = builder.build_or_log() {
            if let Err(e) = input.live_tx.blocking_send(f) {
            tracing::error!(err = %e, "scm: failed to emit finding (channel closed)");
        }
        }
    }
}

/// Walk an entire git tree recursively, scanning every blob for secrets.
///
/// Uses a work-queue (iterative, avoids call-stack overflow on deep trees).
///
/// The previous implementation only walked the top-level tree entries and
/// explicitly `continue`d on sub-trees, silently skipping every file under
/// `src/`, `config/`, `scripts/`, and all other subdirectories.
fn walk_tree_recursive(
    repo: &gix::Repository,
    root_tree_id: gix::ObjectId,
    commit_str: &str,
    target_url: &str,
    scanner: &CompiledScanner,
    input: &ScanInput,
) -> anyhow::Result<()> {
    // Queue of (tree_object_id, path_prefix) pairs.
    let mut queue: Vec<(gix::ObjectId, String)> = vec![(root_tree_id, String::new())];

    while let Some((tree_id, prefix)) = queue.pop() {
        let tree_obj = repo.find_object(tree_id)?;
        if tree_obj.kind != gix::object::Kind::Tree {
            continue;
        }

        // gix 0.67: `Object::decode()` was removed. Convert the object to a
        // `Tree` first, then `decode()` that to get a `TreeRef` with entries.
        let tree = match tree_obj.try_into_tree() {
            Ok(t) => t,
            Err(e) => {
                warn!(
                    tree_id = %tree_id,
                    prefix = %prefix,
                    error = %e,
                    "scm: failed to decode tree object; skipping subtree"
                );
                continue;
            }
        };
        let tree_ref = tree.decode()?;
        for entry in tree_ref.entries {
                let full_path = if prefix.is_empty() {
                    entry.filename.to_string()
                } else {
                    format!("{}/{}", prefix, entry.filename)
                };

                if entry.mode.is_tree() {
                    // Push sub-tree onto queue for iterative processing.
                    queue.push((entry.oid.into(), full_path));
                } else {
                    let obj = repo.find_object(entry.oid)?;
                    if obj.kind != gix::object::Kind::Blob {
                        continue;
                    }

                    // OOM guard: skip blobs larger than MAX_BLOB_BYTES.
                    if obj.data.len() > MAX_BLOB_BYTES {
                        warn!(
                            path = %full_path,
                            size = obj.data.len(),
                            limit = MAX_BLOB_BYTES,
                            "scm: skipping oversized blob"
                        );
                        continue;
                    }

                    let data = match std::str::from_utf8(&obj.data) {
                        Ok(s) => s.to_owned(),
                        Err(e) => {
                            warn!(
                                path = %full_path,
                                error = %e,
                                "scm: blob is not valid UTF-8; scanning lossy-decoded text"
                            );
                            String::from_utf8_lossy(&obj.data).into_owned()
                        }
                    };
                    emit_blob_findings(
                        scanner,
                        &data,
                        &full_path,
                        commit_str,
                        target_url,
                        input,
                    );
                }
            }
    }
    Ok(())
}

/// Scan a git repository by cloning it with `gix` (no shell-out) and walking the tree.
///
/// Uses the `gix` crate for a pure-Rust, memory-safe clone instead of shelling
/// out to the `git` binary, which is a command-injection risk when the URL
/// comes from untrusted input.
pub async fn scan_repo(
    target: &RepositoryTarget,
    _config: &Config,
    input: &ScanInput,
) -> anyhow::Result<()> {
    info!(url = %target.url, "starting in-memory git scan");

    let dir = tempdir()?;

    // Clone via gix (pure Rust, no shell, no command-injection risk).
    // Use spawn_blocking because gix clone does synchronous I/O.
    let url = target.url.to_string();
    let dir_path = dir.path().to_path_buf();

    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let (_repo, _outcome) = gix::prepare_clone_bare(url.as_str(), &dir_path)
            .map_err(|e| anyhow::anyhow!("failed to prepare clone: {e}"))?
            .fetch_only(gix::progress::Discard, &gix::interrupt::IS_INTERRUPTED)
            .map_err(|e| anyhow::anyhow!("clone failed: {e}"))?;
        Ok(())
    })
    .await??;

    let repo = gix::open(dir.path())?;

    // Walk the full tree of the HEAD commit (all subdirectories).
    let head = repo.head()?.into_peeled_id()?;
    let commit_str = head.to_string();
    // Decode the commit object to extract the root tree's ObjectId, then
    // start the iterative queue that visits all subdirectories.
    let root_tree_id = {
        let obj = head.object()?;
        let commit_ref = obj
            .try_to_commit_ref()
            .map_err(|e| anyhow::anyhow!("HEAD is not a commit: {e}"))?;
        commit_ref.tree()
    };

    let scanner = get_scanner();
    walk_tree_recursive(
        &repo,
        root_tree_id,
        &commit_str,
        target.url.as_str(),
        scanner,
        input,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_scanner_compiles_embedded_corpus() {
        // Regression: `get_scanner` used to call `std::process::exit(1)`
        // or silently fall back to an empty corpus. It must return a
        // compiled non-empty scanner without terminating the process.
        let scanner = get_scanner();
        assert!(
            !scanner.is_empty(),
            "embedded KeyHog scanner must expose at least one detector"
        );
    }

    // ── Blob size cap ─────────────────────────────────────────────────────

    #[test]
    fn max_blob_bytes_is_4mb() {
        assert_eq!(MAX_BLOB_BYTES, 4 * 1024 * 1024);
    }

    // ── emit_blob_findings: no raw secret in finding tags ─────────────────

    #[test]
    fn emit_blob_findings_redacts_credential_in_snippet() {
        use gossan_core::{HostTarget, ScanInput, Target};
        use std::sync::Arc;

        let scanner = get_scanner();

        let (live_tx, mut live_rx) = tokio::sync::mpsc::channel(64);
        let (target_tx, _target_rx) = tokio::sync::mpsc::channel(64);
        let (_, in_rx) = tokio::sync::mpsc::channel::<Target>(1);
        let resolver = {
            let config = gossan_core::Config::default();
            Arc::new(gossan_core::net::build_resolver(&config).expect("resolver"))
        };
        let input = ScanInput {
            seed: "test".into(),
            target_rx: tokio::sync::Mutex::new(in_rx),
            live_tx,
            target_tx,
            resolver,
        };

        // Embed a real-looking AWS key (keyhog should detect it).
        let body = "AWS_ACCESS_KEY_ID=AKIAQYAB7XJ4MZK5T2HV\n";
        emit_blob_findings(scanner, body, "config/env", "abc123", "https://t/r", &input);

        // Drain synchronously (channel is non-blocking at this point).
        let mut findings = Vec::new();
        while let Ok(f) = live_rx.try_recv() {
            findings.push(f);
        }

        for f in &findings {
            // The raw credential MUST NOT appear in any Finding field.
            let dump = format!("{:?}", f);
            assert!(
                !dump.contains("AKIAQYAB7XJ4MZK5T2HV"),
                "raw credential leaked into finding: {dump}"
            );
            // The finding MUST carry the correlation tags.
            assert!(
                f.tags().iter().any(|t| t.starts_with("hash:")),
                "missing hash: tag"
            );
            assert!(
                f.tags().iter().any(|t| t.starts_with("det:")),
                "missing det: tag"
            );
        }
    }

    // ── OOM guard: oversized blob is skipped ──────────────────────────────

    #[test]
    fn oversized_blob_skipped_does_not_emit_findings() {
        use gossan_core::{ScanInput, Target};
        use std::sync::Arc;

        let scanner = get_scanner();

        let (live_tx, mut live_rx) = tokio::sync::mpsc::channel(64);
        let (target_tx, _target_rx) = tokio::sync::mpsc::channel(64);
        let (_, in_rx) = tokio::sync::mpsc::channel::<Target>(1);
        let resolver = {
            let config = gossan_core::Config::default();
            Arc::new(gossan_core::net::build_resolver(&config).expect("resolver"))
        };
        let input = ScanInput {
            seed: "test".into(),
            target_rx: tokio::sync::Mutex::new(in_rx),
            live_tx,
            target_tx,
            resolver,
        };

        // A 5 MB blob of zeros, well over MAX_BLOB_BYTES. The scan guard
        // in walk_tree_recursive would skip this.  emit_blob_findings itself
        // doesn't have the guard (the guard lives in the caller), but we
        // verify that scanning a 5 MB chunk of 'x' completes without panic.
        let big = "x".repeat(5 * 1024 * 1024);
        emit_blob_findings(scanner, &big, "big.bin", "abc", "https://t/r", &input);

        // No secrets in random 'x' data.
        assert!(
            live_rx.try_recv().is_err(),
            "should produce no findings on 5 MB of 'x'"
        );
    }

    // ── store roundtrip: raw secret survives in canonical store ───────────

    #[test]
    fn raw_secret_stored_in_canonical_secret_verify_store() {
        let secret = "AKIAQYAB7XJ4MZK5T2HV_canonical_test";
        let hash = gossan_secret_verify::hash_secret(secret);
        gossan_secret_verify::store_raw_secret(&hash, secret);
        let taken = gossan_secret_verify::take_raw_secret(&hash);
        assert_eq!(
            taken.as_deref(),
            Some(secret),
            "canonical store must round-trip the raw secret"
        );
    }

    // ── proptest: emit_blob_findings never panics ─────────────────────────

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn emit_blob_findings_never_panics(body in "\\PC{0,4096}") {
            use gossan_core::{ScanInput, Target};
            use std::sync::Arc;

            let scanner = get_scanner();

            let (live_tx, _live_rx) = tokio::sync::mpsc::channel(64);
            let (target_tx, _target_rx) = tokio::sync::mpsc::channel(64);
            let (_, in_rx) = tokio::sync::mpsc::channel::<Target>(1);
            let resolver = {
                let config = gossan_core::Config::default();
                Arc::new(gossan_core::net::build_resolver(&config).expect("resolver"))
            };
            let input = ScanInput {
                seed: "test".into(),
                target_rx: tokio::sync::Mutex::new(in_rx),
                live_tx,
                target_tx,
                resolver,
            };

            emit_blob_findings(scanner, &body, "test.js", "abc", "https://t/r", &input);
        }
    }
}
