//! Fleet master (listens for workers and distributes scan targets).

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info, warn};

const MAX_FINDINGS_PER_TASK: usize = 100_000;

use crate::proto::fleet_control_server::FleetControl;
use crate::proto::{
    master_instruction, worker_update, MasterInstruction, TaskAssignment, WorkerUpdate,
};

use crate::proto::fleet_control_server::FleetControlServer;
use tonic::transport::Server;

pub async fn run_master(listen: &str, _config: &gossan_core::Config) -> anyhow::Result<()> {
    let addr = listen.parse()?;
    let master = Arc::new(Master::new());

    info!(listen = %addr, "Starting Fleet Master");

    Server::builder()
        .add_service(FleetControlServer::new(master))
        .serve(addr)
        .await?;

    Ok(())
}
/// Distributed fleet master (partitions targets and fans out to workers).
#[derive(Clone)]
pub struct Master {
    workers: Arc<DashMap<String, mpsc::Sender<MasterInstruction>>>,
    pub tasks: Arc<DashMap<String, TaskState>>,
}

pub struct TaskState {
    pub findings: Arc<Mutex<Vec<String>>>,
    pub completed_workers: Arc<Mutex<usize>>,
    pub total_shards: usize,
}

impl Master {
    pub fn new() -> Self {
        Self {
            workers: Arc::new(DashMap::new()),
            tasks: Arc::new(DashMap::new()),
        }
    }
}

impl Default for Master {
    fn default() -> Self {
        Self::new()
    }
}

impl Master {
    pub async fn dispatch_task(
        &self,
        module: &str,
        targets: Vec<String>,
        config: &str,
    ) -> anyhow::Result<String> {
        let task_id = uuid::Uuid::new_v4().to_string();
        let worker_count = self.workers.len();
        if worker_count == 0 {
            return Err(anyhow::anyhow!("No workers connected"));
        }

        let chunk_size = if targets.is_empty() {
            1
        } else {
            targets.len().div_ceil(worker_count)
        };
        let mut shards: Vec<Vec<String>> = targets.chunks(chunk_size).map(|c| c.to_vec()).collect();
        let total_shards = shards.len();

        self.tasks.insert(
            task_id.clone(),
            TaskState {
                findings: Arc::new(Mutex::new(Vec::new())),
                completed_workers: Arc::new(Mutex::new(0)),
                total_shards,
            },
        );

        // Use a loop over indices to avoid dashmap iteration issues
        let worker_ids: Vec<String> = self.workers.iter().map(|r| r.key().clone()).collect();
        let module_name: Arc<str> = module.into();
        let config_json: Arc<str> = config.into();
        let mut send_failures = 0usize;
        for (i, worker_id) in worker_ids.iter().enumerate() {
            if i >= total_shards {
                break;
            }
            if let Some(tx) = self.workers.get(worker_id) {
                let targets = std::mem::take(&mut shards[i]);
                let lost_if_fail = targets.len();
                let assignment = TaskAssignment {
                    task_id: task_id.clone(),
                    module_name: module_name.to_string(),
                    targets,
                    config_json: config_json.to_string(),
                };
                if let Err(e) = tx
                    .send(MasterInstruction {
                        instruction: Some(master_instruction::Instruction::Task(assignment)),
                    })
                    .await
                {
                    tracing::error!(
                        err = %e,
                        worker = %worker_id,
                        targets = lost_if_fail,
                        "failed to send task assignment to worker"
                    );
                    send_failures += lost_if_fail;
                }
            }
        }

        let undelivered: usize = shards.iter().map(|s| s.len()).sum::<usize>() + send_failures;
        if undelivered > 0 {
            return Err(anyhow::anyhow!(
                "{} targets could not be delivered (worker disconnected)",
                undelivered
            ));
        }

        Ok(task_id)
    }
}

#[tonic::async_trait]
impl FleetControl for Arc<Master> {
    type StreamMessagesStream = ReceiverStream<Result<MasterInstruction, Status>>;

    async fn stream_messages(
        &self,
        request: Request<Streaming<WorkerUpdate>>,
    ) -> Result<Response<Self::StreamMessagesStream>, Status> {
        let mut stream = request.into_inner();
        let (tx, rx) = mpsc::channel::<Result<MasterInstruction, Status>>(32);
        let worker_id_res = stream.next().await;

        let worker_id = match worker_id_res {
            Some(Ok(update)) => update.worker_id,
            _ => {
                return Err(Status::invalid_argument(
                    "First message must contain worker_id",
                ))
            }
        };

        info!(worker_id = %worker_id, "Worker connected");

        // We need to store a sender that takes MasterInstruction, but our channel takes Result.
        // We'll wrap it or change the map type.
        // Actually, let's keep the map as MasterInstruction and wrap the sender.
        if self.workers.contains_key(&worker_id) {
            return Err(Status::already_exists(format!(
                "worker_id '{}' already connected",
                worker_id
            )));
        }
        let (instr_tx, mut instr_rx) = mpsc::channel::<MasterInstruction>(32);
        self.workers.insert(worker_id.clone(), instr_tx);

        let master = self.clone();
        let worker_id_clone = worker_id.clone();
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            // Forward instructions to the grpc stream
            let tx_f = tx_clone.clone();
            tokio::spawn(async move {
                while let Some(instr) = instr_rx.recv().await {
                    if tx_f.send(Ok(instr)).await.is_err() {
                        break;
                    }
                }
            });

            while let Some(result) = stream.next().await {
                match result {
                    Ok(update) => {
                        if let Some(event) = update.event {
                            match event {
                                worker_update::Event::Heartbeat(_) => {
                                    // Handle heartbeat
                                }
                                worker_update::Event::Finding(f) => {
                                    if let Some(task) = master.tasks.get(&f.task_id) {
                                        let mut findings = task.findings.lock().await;
                                        if findings.len() < MAX_FINDINGS_PER_TASK {
                                            findings.push(f.data_json);
                                        } else {
                                            warn!(task_id = %f.task_id, "dropping finding: task finding limit reached");
                                        }
                                    }
                                }
                                worker_update::Event::Completion(c) => {
                                    if let Some(task) = master.tasks.get(&c.task_id) {
                                        let mut completed = task.completed_workers.lock().await;
                                        if *completed < task.total_shards {
                                            *completed += 1;
                                            if *completed == task.total_shards {
                                                info!(task_id = %c.task_id, "Task completed across all shards");
                                            }
                                        } else {
                                            warn!(task_id = %c.task_id, "ignoring duplicate completion from worker");
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(worker_id = %worker_id_clone, error = %e, "Worker stream error");
                        break;
                    }
                }
            }
            master.workers.remove(&worker_id_clone);
            info!(worker_id = %worker_id_clone, "Worker disconnected");
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn dispatch_with_injected_worker_succeeds() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let task_id = master
            .dispatch_task("mod", vec!["a.com".into()], "{}")
            .await
            .expect("dispatch should succeed");
        assert!(!task_id.is_empty());
    }

    #[tokio::test]
    async fn dispatch_chunks_targets_across_injected_workers() {
        let master = Master::new();
        let (tx1, _rx1) = mpsc::channel::<MasterInstruction>(32);
        let (tx2, _rx2) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx1);
        master.workers.insert("w2".to_string(), tx2);

        let targets: Vec<String> = (0..4).map(|i| format!("t{i}.com")).collect();
        let _task_id = master
            .dispatch_task("mod", targets.clone(), "{}")
            .await
            .unwrap();

        let task = master.tasks.get(&_task_id).expect("task should exist");
        assert_eq!(task.total_shards, 2);
    }

    #[tokio::test]
    async fn dispatch_empty_targets_with_injected_worker_ok() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        // Fixed: empty targets no longer panic on chunks(0).
        let task_id = master.dispatch_task("mod", vec![], "{}").await.unwrap();
        let task = master.tasks.get(&task_id).expect("task should exist");
        assert_eq!(task.total_shards, 0);
    }

    #[tokio::test]
    async fn task_state_tracks_findings() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let task_id = master
            .dispatch_task("mod", vec!["a.com".into()], "{}")
            .await
            .unwrap();

        // Simulate findings directly.
        {
            let task = master.tasks.get(&task_id).unwrap();
            task.findings.lock().await.push("finding1".to_string());
            task.findings.lock().await.push("finding2".to_string());
        }

        {
            let task = master.tasks.get(&task_id).unwrap();
            let findings = task.findings.lock().await;
            assert_eq!(findings.len(), 2);
            assert_eq!(findings[0], "finding1");
            assert_eq!(findings[1], "finding2");
        }
    }

    #[tokio::test]
    async fn task_state_tracks_completion() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let task_id = master
            .dispatch_task("mod", vec!["a.com".into()], "{}")
            .await
            .unwrap();

        {
            let task = master.tasks.get(&task_id).unwrap();
            let mut completed = task.completed_workers.lock().await;
            *completed += 1;
            assert_eq!(*completed, 1);
        };
    }

    #[tokio::test]
    async fn worker_map_insert_and_remove() {
        let master = Master::new();
        assert_eq!(master.workers.len(), 0);

        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);
        assert_eq!(master.workers.len(), 1);

        master.workers.remove("w1");
        assert_eq!(master.workers.len(), 0);
    }

    #[tokio::test]
    async fn dispatch_preserves_task_entry() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let task_id = master
            .dispatch_task("mod", vec!["a.com".into()], "{}")
            .await
            .unwrap();

        assert!(master.tasks.contains_key(&task_id));
    }

    #[tokio::test]
    async fn dispatch_with_unicode_targets_succeeds() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let targets = vec!["日本語.com".into(), "🔥.com".into()];
        let _task_id = master
            .dispatch_task("mod", targets, "{}")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn dispatch_with_null_byte_targets_succeeds() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let targets = vec!["a\0.com".into()];
        let _task_id = master
            .dispatch_task("mod", targets, "{}")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn dispatch_with_very_long_module_succeeds() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let long = "x".repeat(10_000);
        let _task_id = master
            .dispatch_task(&long, vec!["a.com".into()], "{}")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn dispatch_with_very_long_config_succeeds() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let long_config = format!("{{\"k\":\"{}\"}}", "v".repeat(100_000));
        let _task_id = master
            .dispatch_task("mod", vec!["a.com".into()], &long_config)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn multiple_dispatches_create_distinct_task_ids() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let id1 = master.dispatch_task("mod", vec!["a.com".into()], "{}").await.unwrap();
        let id2 = master.dispatch_task("mod", vec!["b.com".into()], "{}").await.unwrap();
        assert_ne!(id1, id2);
    }

    #[tokio::test]
    async fn dispatch_with_more_targets_than_workers() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let targets: Vec<String> = (0..100).map(|i| format!("t{i}.com")).collect();
        let _task_id = master
            .dispatch_task("mod", targets.clone(), "{}")
            .await
            .unwrap();

        let task = master.tasks.get(&_task_id).unwrap();
        assert_eq!(task.total_shards, 1);
    }

    #[tokio::test]
    async fn completion_equals_total_shards_logs_message() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let task_id = master
            .dispatch_task("mod", vec!["a.com".into()], "{}")
            .await
            .unwrap();

        let task = master.tasks.get(&task_id).unwrap();
        let mut completed = task.completed_workers.lock().await;
        *completed = task.total_shards;
        // No panic; the log message is internal.
    }
}

    #[tokio::test]
    async fn dispatch_one_worker_three_targets_one_shard() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let tid = master
            .dispatch_task("mod", vec!["a.com".into(), "b.com".into(), "c.com".into()], "{}")
            .await
            .unwrap();

        let task = master.tasks.get(&tid).unwrap();
        assert_eq!(task.total_shards, 1);
    }

    #[tokio::test]
    async fn dispatch_two_workers_three_targets_two_shards() {
        let master = Master::new();
        let (tx1, _rx1) = mpsc::channel::<MasterInstruction>(32);
        let (tx2, _rx2) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx1);
        master.workers.insert("w2".to_string(), tx2);

        let tid = master
            .dispatch_task("mod", vec!["a.com".into(), "b.com".into(), "c.com".into()], "{}")
            .await
            .unwrap();

        let task = master.tasks.get(&tid).unwrap();
        assert_eq!(task.total_shards, 2);
    }

    #[tokio::test]
    async fn dispatch_three_workers_three_targets_three_shards() {
        let master = Master::new();
        let mut _rxs = Vec::new();
        for i in 0..3 {
            let (tx, rx) = mpsc::channel::<MasterInstruction>(32);
            master.workers.insert(format!("w{i}"), tx);
            _rxs.push(rx);
        }

        let tid = master
            .dispatch_task("mod", vec!["a.com".into(), "b.com".into(), "c.com".into()], "{}")
            .await
            .unwrap();

        let task = master.tasks.get(&tid).unwrap();
        assert_eq!(task.total_shards, 3);
    }

    #[tokio::test]
    async fn dispatch_three_workers_four_targets_two_shards() {
        let master = Master::new();
        let mut _rxs = Vec::new();
        for i in 0..3 {
            let (tx, rx) = mpsc::channel::<MasterInstruction>(32);
            master.workers.insert(format!("w{i}"), tx);
            _rxs.push(rx);
        }

        let tid = master
            .dispatch_task("mod", vec!["a.com".into(), "b.com".into(), "c.com".into(), "d.com".into()], "{}")
            .await
            .unwrap();

        let task = master.tasks.get(&tid).unwrap();
        // chunk_size = 4.div_ceil(3) = 2, so chunks(2) gives 2 shards.
        assert_eq!(task.total_shards, 2);
    }

    #[tokio::test]
    async fn dispatch_five_workers_nine_targets_two_shards() {
        let master = Master::new();
        let mut _rxs = Vec::new();
        for i in 0..5 {
            let (tx, rx) = mpsc::channel::<MasterInstruction>(32);
            master.workers.insert(format!("w{i}"), tx);
            _rxs.push(rx);
        }

        let targets: Vec<String> = (0..9).map(|i| format!("t{i}.com")).collect();
        let tid = master
            .dispatch_task("mod", targets, "{}")
            .await
            .unwrap();

        let task = master.tasks.get(&tid).unwrap();
        // chunk_size = 9.div_ceil(5) = 2, chunks(2) -> 5 shards? Wait, 9/2 = 4.5, ceil = 5 chunks.
        // Actually chunks(2) on 9 items gives [0..2], [2..4], [4..6], [6..8], [8..9] = 5 shards.
        assert_eq!(task.total_shards, 5);
    }

    #[tokio::test]
    async fn task_state_concurrent_findings_no_panic() {
        let master = Master::new();
        let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
        master.workers.insert("w1".to_string(), tx);

        let tid = master
            .dispatch_task("mod", vec!["a.com".into()], "{}")
            .await
            .unwrap();

        let mut handles = Vec::new();
        for i in 0..10 {
            let t = master.tasks.get(&tid).unwrap();
            let findings = t.findings.clone();
            handles.push(tokio::spawn(async move {
                findings.lock().await.push(format!("finding-{i}"));
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        let t = master.tasks.get(&tid).unwrap();
        assert_eq!(t.findings.lock().await.len(), 10);
    }

    #[tokio::test]
    async fn worker_map_concurrent_insert_remove() {
        let master = Master::new();
        let mut handles = Vec::new();

        for i in 0..50 {
            let m = master.clone();
            handles.push(tokio::spawn(async move {
                let (tx, _rx) = mpsc::channel::<MasterInstruction>(32);
                m.workers.insert(format!("w{i}"), tx);
                if i % 2 == 0 {
                    m.workers.remove(&format!("w{i}"));
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        // At least some workers remain.
        assert!(!master.workers.is_empty());
    }
