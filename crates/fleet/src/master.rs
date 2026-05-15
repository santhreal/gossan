//! Fleet master — listens for workers and distributes scan targets.

use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use dashmap::DashMap;
use tracing::{info, error};

use crate::proto::fleet_control_server::FleetControl;
use crate::proto::{WorkerUpdate, MasterInstruction, TaskAssignment, worker_update, master_instruction};

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
/// Distributed fleet master — partitions targets and fans out to workers.
pub struct Master {
    workers: Arc<DashMap<String, mpsc::Sender<MasterInstruction>>>,
    tasks: Arc<DashMap<String, TaskState>>,
}

struct TaskState {
    findings: Arc<Mutex<Vec<String>>>,
    completed_workers: Arc<Mutex<usize>>,
    total_shards: usize,
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
    pub async fn dispatch_task(&self, module: &str, targets: Vec<String>, config: &str) -> anyhow::Result<String> {
        let task_id = uuid::Uuid::new_v4().to_string();
        let worker_count = self.workers.len();
        if worker_count == 0 {
            return Err(anyhow::anyhow!("No workers connected"));
        }

        let chunk_size = targets.len().div_ceil(worker_count);
        let shards: Vec<Vec<String>> = targets.chunks(chunk_size).map(|c| c.to_vec()).collect();
        let total_shards = shards.len();

        self.tasks.insert(task_id.clone(), TaskState {
            findings: Arc::new(Mutex::new(Vec::new())),
            completed_workers: Arc::new(Mutex::new(0)),
            total_shards,
        });

        // Use a loop over indices to avoid dashmap iteration issues
        let worker_ids: Vec<String> = self.workers.iter().map(|r| r.key().clone()).collect();
        for (i, worker_id) in worker_ids.iter().enumerate() {
            if i >= total_shards { break; }
            if let Some(tx) = self.workers.get(worker_id) {
                let assignment = TaskAssignment {
                    task_id: task_id.clone(),
                    module_name: module.to_string(),
                    targets: shards[i].clone(),
                    config_json: config.to_string(),
                };
                let _ = tx.send(MasterInstruction {
                    instruction: Some(master_instruction::Instruction::Task(assignment)),
                }).await;
            }
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
            _ => return Err(Status::invalid_argument("First message must contain worker_id")),
        };

        info!(worker_id = %worker_id, "Worker connected");
        
        // We need to store a sender that takes MasterInstruction, but our channel takes Result.
        // We'll wrap it or change the map type. 
        // Actually, let's keep the map as MasterInstruction and wrap the sender.
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
                                        task.findings.lock().await.push(f.data_json);
                                    }
                                }
                                worker_update::Event::Completion(c) => {
                                    if let Some(task) = master.tasks.get(&c.task_id) {
                                        let mut completed = task.completed_workers.lock().await;
                                        *completed += 1;
                                        if *completed == task.total_shards {
                                            info!(task_id = %c.task_id, "Task completed across all shards");
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
