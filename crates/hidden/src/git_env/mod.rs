//! Hidden file/path scanner.
//!
//! Probes 100+ paths for exposed sensitive files: source control, env files,
//! config, backups, framework debug pages, API docs, SSH keys, cloud credentials.
//!
//! Key design decisions:
//! - Fully concurrent: all paths probed simultaneously via buffer_unordered.
//! - Content-validated: body must match expected pattern to eliminate false-positives
//!   (e.g. /.git/HEAD must contain "ref:", not just return HTTP 200).
//! - 403-bypass-integrated: any 403 on a sensitive path is immediately probed
//!   for bypass via IP-spoof headers and path normalisation tricks.

pub mod detect;
pub mod extract;
pub mod rules;

use futures::StreamExt;
use gossan_core::Target;
use secfinding::Finding;

/// Probe the target for hidden files and directories.
pub async fn probe(client: &reqwest::Client, target: &Target) -> anyhow::Result<Vec<Finding>> {
    let Target::Web(asset) = target else {
        return Ok(vec![]);
    };
    let base = asset.url.as_str().trim_end_matches('/');

    let is_catch_all = detect::is_catch_all(client, base).await;
    let checks = rules::get_owned_checks();

    let results: Vec<Vec<Finding>> = futures::stream::iter(checks)
        .map(|c| {
            extract::process_check(
                client.clone(),
                base.to_string(),
                target.clone(),
                c,
                is_catch_all,
            )
        })
        .buffer_unordered(25)
        .collect()
        .await;

    Ok(results.into_iter().flatten().collect())
}
