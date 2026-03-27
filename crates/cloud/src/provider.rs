//! `CloudProvider` trait — the single extension point for new cloud storage backends.
//!
//! To add a new provider:
//!   1. Create `src/{provider}.rs` and implement `CloudProvider` on a zero-sized struct.
//!   2. Register it in `lib::providers()`.
//!
//! That's it. No other file needs to change.

use async_trait::async_trait;
use gossan_core::Target;
use secfinding::Finding;

/// A single cloud-storage provider probe.
#[async_trait]
pub trait CloudProvider: Send + Sync {
    /// Short identifier used in log messages (e.g. `"s3"`, `"gcs"`).
    fn name(&self) -> &'static str;

    /// Probe `name` as a candidate bucket/account name for this provider.
    ///
    /// `target` is the scan-seed `Target` — used as the finding's target so
    /// findings roll up to the original domain in reports.
    async fn probe(
        &self,
        client: &reqwest::Client,
        name: &str,
        target: &Target,
    ) -> anyhow::Result<Vec<Finding>>;
}

#[cfg(test)]
mod tests {
    use super::CloudProvider;
    use crate::{
        azure::AzureProvider, do_spaces::DoSpacesProvider, gcs::GcsProvider, s3::S3Provider,
    };

    #[test]
    fn provider_names_are_stable() {
        assert_eq!(S3Provider.name(), "s3");
        assert_eq!(GcsProvider.name(), "gcs");
        assert_eq!(AzureProvider.name(), "azure");
        assert_eq!(DoSpacesProvider.name(), "spaces");
    }
}
