use gossan_core::target::RepositoryTarget;
use gossan_core::{Config, ScanInput, };
use gossan_keyhog_lite::{Chunk, ChunkMetadata};
use tracing::{info, warn};
use tempfile::tempdir;

/// Scan a git repository by cloning it with `gix` (no shell-out) and walking the tree.
///
/// Uses the `gix` crate for a pure-Rust, memory-safe clone instead of shelling
/// out to the `git` binary, which is a command-injection risk when the URL
/// comes from untrusted input.
pub async fn scan_repo(target: &RepositoryTarget, _config: &Config, _input: &ScanInput) -> anyhow::Result<()> {

    info!(url = %target.url, "starting in-memory git scan");

    let dir = tempdir()?;

    // Clone via gix — pure Rust, no shell, no command-injection risk.
    // Use spawn_blocking because gix clone does synchronous I/O.
    let url = target.url.to_string();
    let dir_path = dir.path().to_path_buf();

    let clone_result = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let (_repo, _outcome) = gix::prepare_clone_bare(url.as_str(), &dir_path)
            .map_err(|e| anyhow::anyhow!("failed to prepare clone: {e}"))?
            .fetch_only(
                gix::progress::Discard,
                &gix::interrupt::IS_INTERRUPTED,
            )
            .map_err(|e| anyhow::anyhow!("clone failed: {e}"))?;
        Ok(())
    })
    .await??;

    let repo = gix::open(dir.path())?;

    // Walk the tree of the HEAD commit
    let head = repo.head()?.into_peeled_id()?;
    let tree = head.object()?.into_commit().tree()?;

    for entry in tree.decode()?.entries {
        if entry.mode.is_tree() { continue; }

        let obj = repo.find_object(entry.oid)?;
        if obj.kind != gix::object::Kind::Blob { continue; }

        let path = entry.filename.to_string();
        let data = String::from_utf8_lossy(&obj.data);

        // Scan the blob
        let _chunk = Chunk {
            data: data.to_string(),
            metadata: ChunkMetadata {
                source_type: "scm".into(),
                path: Some(path.to_string()),
                commit: Some(head.to_string()),
                author: None,
                date: None,
            },
        };

        // Skip scan for now until we have a way to pass a real CompiledScanner.

        // Supply chain discovery: scan for internal packages
        if path == "package.json" || path == "requirements.txt" || path == "composer.json" {
            // Hook for parsing dependencies
        }
    }

    Ok(())
}
