//! Fleet worker (connects to master, receives targets, runs scans).

use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::proto::fleet_control_client::FleetControlClient;
use crate::proto::{
    master_instruction, worker_update, Finding, Heartbeat, TaskCompletion, WorkerUpdate,
};
use gossan_core::{Config, DiscoverySource, DomainTarget, HostTarget, NetworkTarget, ScanInput, Scanner, Target};

/// Reconstruct a [`Target`] from the task string sent by the fleet master.
///
/// The protobuf task message only carries `repeated string targets`, so the
/// worker must infer the intended kind from the string itself. IP literals
/// become [`Target::Host`], valid CIDR notation becomes [`Target::Network`],
/// and everything else is treated as a domain seed.
fn parse_task_target(s: &str) -> anyhow::Result<Target> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        anyhow::bail!("fleet task target string is empty");
    }

    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(Target::Host(HostTarget {
            ip,
            domain: None,
        }));
    }

    if trimmed.contains('/') && trimmed.parse::<ipnet::IpNet>().is_ok() {
        return Ok(Target::Network(NetworkTarget {
            cidr: trimmed.to_string(),
            source: DiscoverySource::Seed,
        }));
    }

    Ok(Target::Domain(DomainTarget {
        domain: trimmed.to_string(),
        source: DiscoverySource::Seed,
    }))
}

/// Connect to `master_url` and execute assigned scan modules via `scanner_factory`.
///
/// `scanner_factory` must return the concrete [`Scanner`] for a module name, or
/// `Ok(None)` when the module is unknown/uncompiled. Construction failures must
/// be returned as `Err` (never mapped to an empty factory).
pub async fn run_worker<F>(
    master_url: &str,
    _config: &Config,
    scanner_factory: F,
) -> anyhow::Result<()>
where
    F: Fn(&str) -> anyhow::Result<Option<Box<dyn Scanner>>> + Send + Sync + 'static,
{
    let worker = Worker::new(master_url.to_string());
    worker.run(scanner_factory).await
}

/// Distributed fleet worker (receives scan chunks from the master).
pub struct Worker {
    id: String,
    master_url: String,
}

impl Worker {
    pub fn new(master_url: String) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            master_url,
        }
    }

    pub async fn run<F>(&self, scanner_factory: F) -> anyhow::Result<()>
    where
        F: Fn(&str) -> anyhow::Result<Option<Box<dyn Scanner>>> + Send + Sync + 'static,
    {
        let mut client = FleetControlClient::connect(self.master_url.clone()).await?;
        let (tx, rx) = mpsc::channel(32);

        // Initial registration message
        tx.send(WorkerUpdate {
            worker_id: self.id.clone(),
            event: Some(worker_update::Event::Heartbeat(Heartbeat {
                concurrent_tasks: 0,
            })),
        })
        .await?;

        let mut stream = client
            .stream_messages(ReceiverStream::new(rx))
            .await?
            .into_inner();
        let factory = Arc::new(scanner_factory);
        let worker_id = self.id.clone();
        let tx_clone = tx.clone();

        info!(worker_id = %worker_id, "Connected to master at {}", self.master_url);

        let mut task_set = tokio::task::JoinSet::new();

        while let Some(instruction) = stream.next().await {
            match instruction {
                Ok(instr) => {
                    if let Some(payload) = instr.instruction {
                        match payload {
                            master_instruction::Instruction::Task(task) => {
                                let factory = factory.clone();
                                let tx = tx_clone.clone();
                                let worker_id = worker_id.clone();

                                task_set.spawn(async move {
                                    let res: anyhow::Result<()> = async {
                                        info!(task_id = %task.task_id, module = %task.module_name, "Executing task");
                                        let scanner = match factory(&task.module_name)? {
                                            Some(s) => s,
                                            None => {
                                                anyhow::bail!(
                                                    "Scanner {} not found",
                                                    task.module_name
                                                );
                                            }
                                        };

                                        let targets: Vec<Target> = task
                                            .targets
                                            .into_iter()
                                            .map(|t| {
                                                parse_task_target(&t).map_err(|e| {
                                                    anyhow::anyhow!(
                                                        "invalid target '{}' in task {}: {e}",
                                                        t,
                                                        task.task_id
                                                    )
                                                })
                                            })
                                            .collect::<Result<_, _>>()?;

                                        let (finding_tx, mut finding_rx) = mpsc::channel(1024);
                                        let task_id_f = task.task_id.clone();
                                        let worker_id_f = worker_id.clone();
                                        let tx_f = tx.clone();

                                        let finding_forwarder = tokio::spawn(async move {
                                            while let Some(f) = finding_rx.recv().await {
                                                let data_json = match serde_json::to_string(&f) {
                                                    Ok(s) => s,
                                                    Err(e) => {
                                                        error!(
                                                            error = %e,
                                                            task_id = %task_id_f,
                                                            "failed to serialize finding for fleet master; dropping finding"
                                                        );
                                                        continue;
                                                    }
                                                };
                                                if let Err(e) = tx_f
                                                    .send(WorkerUpdate {
                                                        worker_id: worker_id_f.clone(),
                                                        event: Some(worker_update::Event::Finding(
                                                            Finding {
                                                                task_id: task_id_f.clone(),
                                                                data_json,
                                                            },
                                                        )),
                                                    })
                                                    .await
                                                {
                                                    error!(
                                                        error = %e,
                                                        task_id = %task_id_f,
                                                        "failed to forward finding to master"
                                                    );
                                                    break;
                                                }
                                            }
                                        });

                                        let config = if task.config_json.is_empty() {
                                            Config::default()
                                        } else {
                                            serde_json::from_str(&task.config_json).map_err(|e| {
                                                anyhow::anyhow!(
                                                    "invalid task.config_json for task {}: {e}",
                                                    task.task_id
                                                )
                                            })?
                                        };
                                        let resolver =
                                            Arc::new(gossan_core::net::build_resolver(&config)?);

                                        let (target_in_tx, target_in_rx) = mpsc::channel(1024);
                                        for t in targets {
                                            target_in_tx.send(t).await.map_err(|e| {
                                                anyhow::anyhow!(
                                                    "failed to enqueue fleet task target: {e}"
                                                )
                                            })?;
                                        }
                                        drop(target_in_tx);

                                        let (_target_out_tx, _target_out_rx) = mpsc::channel(1024);

                                        let input = ScanInput {
                                            seed: "fleet-task".to_string(),
                                            target_rx: tokio::sync::Mutex::new(target_in_rx),
                                            live_tx: finding_tx,
                                            target_tx: _target_out_tx,
                                            resolver,
                                        };

                                        scanner.run(input, &config).await?;
                                        if finding_forwarder.await.is_err() {
                                            warn!("finding forwarder task panicked");
                                        }
                                        Ok(())
                                    }
                                    .await;

                                    match res {
                                        Ok(()) => {
                                            if let Err(e) = tx
                                                .send(WorkerUpdate {
                                                    worker_id,
                                                    event: Some(worker_update::Event::Completion(
                                                        TaskCompletion {
                                                            task_id: task.task_id.clone(),
                                                            success: true,
                                                            error: String::new(),
                                                        },
                                                    )),
                                                })
                                                .await
                                            {
                                                error!(
                                                    error = %e,
                                                    task_id = %task.task_id,
                                                    "failed to report successful task completion to master"
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            let err_msg = e.to_string();
                                            if let Err(send_err) = tx
                                                .send(WorkerUpdate {
                                                    worker_id,
                                                    event: Some(worker_update::Event::Completion(
                                                        TaskCompletion {
                                                            task_id: task.task_id.clone(),
                                                            success: false,
                                                            error: err_msg.clone(),
                                                        },
                                                    )),
                                                })
                                                .await
                                            {
                                                error!(
                                                    error = %send_err,
                                                    task_id = %task.task_id,
                                                    task_error = %err_msg,
                                                    "failed to report task failure to master"
                                                );
                                            }
                                        }
                                    }
                                });
                            }
                            master_instruction::Instruction::Shutdown(_) => {
                                info!("Received shutdown instruction");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "Master stream error");
                    break;
                }
            }
        }

        while let Some(res) = task_set.join_next().await {
            if res.is_err() {
                warn!("worker task panicked");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_new_generates_unique_ids() {
        let w1 = Worker::new("http://localhost:1".to_string());
        let w2 = Worker::new("http://localhost:1".to_string());
        assert_ne!(w1.id, w2.id);
    }

    #[test]
    fn worker_new_stores_url() {
        let w = Worker::new("http://example.com:8080".to_string());
        assert_eq!(w.master_url, "http://example.com:8080");
    }

    #[test]
    fn worker_new_with_empty_url() {
        let w = Worker::new("".to_string());
        assert!(!w.id.is_empty());
        assert_eq!(w.master_url, "");
    }

    #[test]
    fn worker_new_with_unicode_url() {
        let w = Worker::new("http://日本語.example.com".to_string());
        assert_eq!(w.master_url, "http://日本語.example.com");
    }

    #[test]
    fn worker_new_with_very_long_url() {
        let long = format!("http://example.com/{}", "x".repeat(10_000));
        let w = Worker::new(long.clone());
        assert_eq!(w.master_url, long);
    }

    #[test]
    fn worker_new_with_null_bytes_in_url() {
        let url = "http://exam\0ple.com".to_string();
        let w = Worker::new(url.clone());
        assert_eq!(w.master_url, url);
    }

    #[test]
    fn parse_task_target_makes_domain_from_hostname() {
        let t = parse_task_target("example.com").unwrap();
        assert!(matches!(t, Target::Domain(DomainTarget { domain, .. }) if domain == "example.com"));
    }

    #[test]
    fn parse_task_target_makes_host_from_ipv4() {
        let t = parse_task_target("1.2.3.4").unwrap();
        assert!(matches!(t, Target::Host(HostTarget { ip, .. }) if ip.is_ipv4()));
        assert_eq!(t.ip().unwrap().to_string(), "1.2.3.4");
    }

    #[test]
    fn parse_task_target_makes_host_from_ipv6() {
        let t = parse_task_target("::1").unwrap();
        assert!(matches!(t, Target::Host(HostTarget { ip, .. }) if ip.is_ipv6()));
    }

    #[test]
    fn parse_task_target_makes_network_from_cidr() {
        let t = parse_task_target("10.0.0.0/8").unwrap();
        assert!(matches!(t, Target::Network(NetworkTarget { cidr, .. }) if cidr == "10.0.0.0/8"));
    }

    #[test]
    fn parse_task_target_makes_network_from_ipv6_cidr() {
        let t = parse_task_target("2001:db8::/32").unwrap();
        assert!(matches!(t, Target::Network(NetworkTarget { cidr, .. }) if cidr == "2001:db8::/32"));
    }

    #[test]
    fn parse_task_target_rejects_empty_string() {
        assert!(parse_task_target("").is_err());
        assert!(parse_task_target("   ").is_err());
    }

    #[test]
    fn parse_task_target_rejects_invalid_cidr() {
        // A slash without a valid prefix should fall through to domain, but an
        // invalid prefix should be rejected before we create a malformed network.
        let t = parse_task_target("example.com/not-a-prefix").unwrap();
        assert!(matches!(t, Target::Domain(_)));
    }
}
