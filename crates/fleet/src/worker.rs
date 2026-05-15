//! Fleet worker — connects to master, receives targets, runs scans.

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tracing::{info, error};
use uuid::Uuid;

use gossan_core::{Scanner, ScanInput, Config, Target, DomainTarget, DiscoverySource};
use crate::proto::fleet_control_client::FleetControlClient;
use crate::proto::{WorkerUpdate, Heartbeat, Finding, TaskCompletion, worker_update, master_instruction};

pub async fn run_worker(master_url: &str, _config: &Config) -> anyhow::Result<()> {
    let worker = Worker::new(master_url.to_string());
    
    // In a real scenario, we'd pass a factory that can create any scanner.
    // For now, we'll provide an empty factory.
    worker.run(|_name| None).await
}
/// Distributed fleet worker — receives scan chunks from the master.
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
        F: Fn(&str) -> Option<Box<dyn Scanner>> + Send + Sync + 'static 
    {
        let mut client = FleetControlClient::connect(self.master_url.clone()).await?;
        let (tx, rx) = mpsc::channel(32);
        
        // Initial registration message
        tx.send(WorkerUpdate {
            worker_id: self.id.clone(),
            event: Some(worker_update::Event::Heartbeat(Heartbeat { concurrent_tasks: 0 })),
        }).await?;

        let mut stream = client.stream_messages(ReceiverStream::new(rx)).await?.into_inner();
        let factory = Arc::new(scanner_factory);
        let worker_id = self.id.clone();
        let tx_clone = tx.clone();

        info!(worker_id = %worker_id, "Connected to master at {}", self.master_url);

        while let Some(instruction) = stream.next().await {
            match instruction {
                Ok(instr) => {
                    if let Some(payload) = instr.instruction {
                        match payload {
                            master_instruction::Instruction::Task(task) => {
                                let factory = factory.clone();
                                let tx = tx_clone.clone();
                                let worker_id = worker_id.clone();
                                
                                tokio::spawn(async move {
                                    let res: anyhow::Result<()> = async {
                                        info!(task_id = %task.task_id, module = %task.module_name, "Executing task");
                                        let scanner = match factory(&task.module_name) {
                                            Some(s) => s,
                                            None => {
                                                anyhow::bail!("Scanner {} not found", task.module_name);
                                            }
                                        };

                                        let targets: Vec<Target> = task.targets.into_iter().map(|t| {
                                            Target::Domain(DomainTarget {
                                                domain: t,
                                                source: DiscoverySource::Seed,
                                            })
                                        }).collect();

                                        let (finding_tx, mut finding_rx) = mpsc::unbounded_channel();
                                        let task_id_f = task.task_id.clone();
                                        let worker_id_f = worker_id.clone();
                                        let tx_f = tx.clone();

                                        tokio::spawn(async move {
                                            while let Some(f) = finding_rx.recv().await {
                                                let data_json = serde_json::to_string(&f).unwrap_or_default();
                                                let _ = tx_f.send(WorkerUpdate {
                                                    worker_id: worker_id_f.clone(),
                                                    event: Some(worker_update::Event::Finding(Finding {
                                                        task_id: task_id_f.clone(),
                                                        data_json,
                                                    })),
                                                }).await;
                                            }
                                        });

                                        let config = if task.config_json.is_empty() {
                                            Config::default()
                                        } else {
                                            serde_json::from_str(&task.config_json).unwrap_or_else(|e| {
                                                tracing::warn!(error = %e, "failed to parse task config, using defaults");
                                                Config::default()
                                            })
                                        };
                                        let resolver = Arc::new(gossan_core::net::build_resolver(&config)?);
                                        
                                        let (target_in_tx, target_in_rx) = mpsc::unbounded_channel();
                                        for t in targets {
                                            let _ = target_in_tx.send(t);
                                        }
                                        drop(target_in_tx);

                                        let (_target_out_tx, _target_out_rx) = mpsc::unbounded_channel();

                                        let input = ScanInput {
                                            seed: "fleet-task".to_string(),
                                            target_rx: tokio::sync::Mutex::new(target_in_rx),
                                            live_tx: finding_tx,
                                            target_tx: _target_out_tx,
                                            resolver,
                                        };
                                        
                                        scanner.run(input, &config).await?;
                                        Ok(())
                                    }.await;

                                    match res {
                                        Ok(()) => {
                                            let _ = tx.send(WorkerUpdate {
                                                worker_id,
                                                event: Some(worker_update::Event::Completion(TaskCompletion {
                                                    task_id: task.task_id,
                                                    success: true,
                                                    error: String::new(),
                                                })),
                                            }).await;
                                        }
                                        Err(e) => {
                                            let _ = tx.send(WorkerUpdate {
                                                worker_id,
                                                event: Some(worker_update::Event::Completion(TaskCompletion {
                                                    task_id: task.task_id,
                                                    success: false,
                                                    error: e.to_string(),
                                                })),
                                            }).await;
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

        Ok(())
    }
}
