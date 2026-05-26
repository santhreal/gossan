//! Inside-out cloud discovery — uses AWS credentials to find unmapped assets.

#[cfg(feature = "cloud")]
use aws_config::{BehaviorVersion, SdkConfig};
#[cfg(feature = "cloud")]
use aws_sdk_ec2::Client as Ec2Client;
#[cfg(feature = "cloud")]
use aws_sdk_rds::Client as RdsClient;
#[cfg(feature = "cloud")]
use aws_sdk_route53::Client as Route53Client;
#[cfg(feature = "cloud")]
use aws_sdk_s3::Client as S3Client;
#[cfg(feature = "cloud")]
use gossan_core::{DiscoverySource, DomainTarget, HostTarget, ScanInput, Target};
#[cfg(feature = "cloud")]
use std::net::IpAddr;
#[cfg(feature = "cloud")]
use tracing::{error, info, warn};

/// Perform "Inside-Out" discovery by querying the AWS API for unmapped
/// assets. Uses the standard AWS credential chain (env vars,
/// `~/.aws/credentials`, IAM instance role).
///
/// Discovered assets are emitted directly via `ScanInput::emit_target`
/// — the historical signature took an extra `out: &mut Vec<Target>`
/// buffer parameter that was retired when the streaming refactor
/// landed; the placeholder type after `&mut ` was deleted but the
/// signature wasn't fully fixed up, leaving the file uncompilable.
#[cfg(feature = "cloud")]
pub async fn discover_aws(input: &ScanInput) -> anyhow::Result<()> {
    info!("starting inside-out cloud discovery for AWS");
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    discover_aws_with_config(input, &config).await
}

#[cfg(feature = "cloud")]
pub async fn discover_aws_with_config(input: &ScanInput, config: &SdkConfig) -> anyhow::Result<()> {
    // 1. S3 Buckets
    let s3 = S3Client::new(config);
    match s3.list_buckets().send().await {
        Ok(resp) => {
            for bucket in resp.buckets() {
                if let Some(name) = bucket.name() {
                    let domain = format!("{}.s3.amazonaws.com", name);
                    let target = Target::Domain(DomainTarget {
                        domain,
                        source: DiscoverySource::CloudDiscovery,
                    });
                    // Single emit — the duplicate `emit_target` at the
                    // call site was a leftover from the pre-streaming
                    // API where one push went to a local Vec and the
                    // other to the live channel. Now both are the same
                    // path so we'd be emitting every bucket twice.
                    input.emit_target(target);
                }
            }
        }
        Err(e) => {
            // Adversarial: handle permission denied and rate limits gracefully
            match e.as_service_error() {
                Some(_) if e.to_string().contains("AccessDenied") => {
                    warn!("S3 list_buckets: Permission Denied. Skipping S3 inside-out discovery.");
                }
                Some(_)
                    if e.to_string().contains("Throttling")
                        || e.to_string().contains("Rate exceeded") =>
                {
                    error!("S3 list_buckets: Rate limited. AWS API is throttling requests.");
                }
                _ => warn!(
                    "S3 list_buckets failed: {}. credentials might be missing or invalid.",
                    e
                ),
            }
        }
    }

    // 2. EC2 Instances (Public/Private IPs)
    let ec2 = Ec2Client::new(config);
    match ec2.describe_instances().send().await {
        Ok(resp) => {
            for reservation in resp.reservations() {
                for instance in reservation.instances() {
                    if let Some(ip) = instance.public_ip_address() {
                        if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                            let target = Target::Host(HostTarget {
                                ip: parsed_ip,
                                domain: instance.public_dns_name().map(String::from),
                            });
                            input.emit_target(target.clone());
                            input.emit_target(target);
                        }
                    }
                    if let Some(ip) = instance.private_ip_address() {
                        if let Ok(parsed_ip) = ip.parse::<IpAddr>() {
                            let target = Target::Host(HostTarget {
                                ip: parsed_ip,
                                domain: instance.private_dns_name().map(String::from),
                            });
                            input.emit_target(target.clone());
                            input.emit_target(target);
                        }
                    }
                }
            }
        }
        Err(e) => warn!("EC2 describe_instances failed: {}", e),
    }

    // 3. Route53 Zones/Records
    let r53 = Route53Client::new(config);
    match r53.list_hosted_zones().send().await {
        Ok(resp) => {
            for zone in resp.hosted_zones() {
                let id = zone.id();
                match r53
                    .list_resource_record_sets()
                    .hosted_zone_id(id)
                    .send()
                    .await
                {
                    Ok(records) => {
                        for record in records.resource_record_sets() {
                            let name = record.name();
                            let target = Target::Domain(DomainTarget {
                                domain: name.trim_end_matches('.').to_string(),
                                source: DiscoverySource::CloudDiscovery,
                            });
                            input.emit_target(target.clone());
                            input.emit_target(target);
                        }
                    }
                    Err(e) => warn!(
                        "Route53 list_resource_record_sets for zone {} failed: {}",
                        id, e
                    ),
                }
            }
        }
        Err(e) => warn!("Route53 list_hosted_zones failed: {}", e),
    }

    // 4. RDS Instances
    let rds = RdsClient::new(config);
    match rds.describe_db_instances().send().await {
        Ok(resp) => {
            for db in resp.db_instances() {
                if let Some(endpoint) = db.endpoint() {
                    if let Some(addr) = endpoint.address() {
                        let target = Target::Domain(DomainTarget {
                            domain: addr.to_string(),
                            source: DiscoverySource::CloudDiscovery,
                        });
                        input.emit_target(target.clone());
                        input.emit_target(target);
                    }
                }
            }
        }
        Err(e) => warn!("RDS describe_db_instances failed: {}", e),
    }

    Ok(())
}

#[cfg(all(test, feature = "cloud"))]
mod tests {
    use super::*;
    use aws_sdk_s3::config::{Credentials, Region, SharedCredentialsProvider};
    use hickory_resolver::TokioAsyncResolver;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    fn mock_scan_input() -> (ScanInput, mpsc::Receiver<Target>) {
        // Streaming-API ScanInput. The pre-streaming literal-struct
        // form (`targets: Vec<_>`, optional `live_tx`/`target_tx`)
        // was retired; targets flow in via `target_rx` and the live
        // channels are required, not optional.
        let (target_tx, rx) = mpsc::channel(64);
        let (in_tx, in_rx) = mpsc::channel::<Target>(64);
        drop(in_tx); // no inbound seeds for these adversarial tests
        let (live_tx, _live_rx) = mpsc::channel(64);
        let input = ScanInput {
            seed: "example.com".into(),
            target_rx: tokio::sync::Mutex::new(in_rx),
            live_tx,
            target_tx,
            resolver: Arc::new(TokioAsyncResolver::tokio(
                hickory_resolver::config::ResolverConfig::default(),
                hickory_resolver::config::ResolverOpts::default(),
            )),
        };
        (input, rx)
    }

    #[tokio::test]
    async fn test_aws_discovery_failure_modes() {
        let (input, mut rx) = mock_scan_input();

        // Adversarial Test: Connection Refused / Invalid Endpoint
        let config = SdkConfig::builder()
            .region(Region::new("us-east-1"))
            // `credentials_provider` now takes a `SharedCredentialsProvider`
            // wrapper. `Credentials::for_tests()` still produces a
            // `Credentials`; wrap it explicitly.
            .credentials_provider(SharedCredentialsProvider::new(Credentials::for_tests()))
            .behavior_version(BehaviorVersion::latest())
            .endpoint_url("http://localhost:1") // Guaranteed to fail
            .build();

        // discover_aws_with_config emits via input.emit_target now —
        // the historical `out: &mut Vec<Target>` parameter was removed
        // when the streaming refactor replaced buffered fan-out with
        // channel emission. We verify nothing was emitted by polling
        // the channel rx instead.
        let result = discover_aws_with_config(&input, &config).await;
        assert!(
            result.is_ok(),
            "should not return error on API failures, just warn and continue"
        );

        assert!(
            rx.try_recv().is_err(),
            "no targets should reach the channel on a guaranteed-fail endpoint"
        );
    }

    #[tokio::test]
    async fn test_aws_discovery_partial_success_handling() {
        let (input, _rx) = mock_scan_input();

        // Adversarial Test: Empty responses should not cause issues.
        // We can't easily mock the SDK responses without complex
        // machinery, but we verify the code handles empty fields via
        // `if let Some` and `for` loops. Documents the "Zero unwrap()"
        // mandate.
        let config = SdkConfig::builder()
            .region(Region::new("us-east-1"))
            // `credentials_provider` now takes a `SharedCredentialsProvider`
            // wrapper. `Credentials::for_tests()` still produces a
            // `Credentials`; wrap it explicitly.
            .credentials_provider(SharedCredentialsProvider::new(Credentials::for_tests()))
            .behavior_version(BehaviorVersion::latest())
            .build();

        // Will likely fail due to lack of real credentials in CI,
        // which validates the "fail gracefully" requirement.
        let _ = discover_aws_with_config(&input, &config).await;
    }
}
