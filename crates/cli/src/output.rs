//! Output formatting for gossan findings.
//!
//! Delegates to [`santh_output`] for the actual rendering, converting
//! gossan's `Finding` (with `Target` enum) to the universal format.

use gossan_core::{OutputConfig, OutputFormat};
use secfinding::Finding;

/// Print findings using the configured output format.
pub fn print_findings(findings: &[Finding], config: &OutputConfig) {
    // findings is already `&[Finding]` which is `&[secfinding::Finding]`
    let format = match config.format {
        OutputFormat::Json => santh_output::Format::Json,
        OutputFormat::Jsonl => santh_output::Format::Jsonl,
        OutputFormat::Sarif => santh_output::Format::Sarif,
        OutputFormat::Markdown => santh_output::Format::Markdown,
        OutputFormat::Text => santh_output::Format::Text,
    };

    let rendered = match santh_output::render(findings, format, "gossan") {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to render findings: {}", e);
            return;
        }
    };

    if let Some(path) = &config.path {
        if let Ok(mut file) = std::fs::File::create(path) {
            let _ = santh_output::emit(&rendered, &mut file);
        } else {
            tracing::error!("Failed to open output file");
        }
    } else {
        let _ = santh_output::emit(&rendered, std::io::stdout());
    }
}
