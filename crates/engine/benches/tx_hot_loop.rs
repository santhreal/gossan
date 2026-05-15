//! Bench the gossan-engine TX hot loop in isolation from the kernel
//! syscall + network stack.
//!
//! What this measures: how fast the engine can iterate the
//! Blackrock schedule, stamp templates in place, and hand batches to a
//! `PacketEngine`. The real bottleneck for masscan-class scanning is
//! either the syscall ring or the NIC; isolating "engine-internal pps"
//! makes regressions in stamping / scheduling / rate-limit visible
//! without needing root or a real interface.
//!
//! Run with `cargo bench -p gossan-engine --bench tx_hot_loop`.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion, Throughput};
use netforge::engine::{EngineError, EngineStats, PacketEngine, RxPacket};
use netforge::seq::SeqEncoder;
use netforge::{packet, RawPacket};

use gossan_engine::schedule::{BlackrockPermutation, ScanSchedule};

/// Counting stub backend: discards packets, increments an atomic counter.
/// Removes the kernel from the equation so we measure gossan-engine's
/// own throughput ceiling.
struct CountingEngine {
    sent: AtomicU64,
}

impl CountingEngine {
    fn new() -> Self {
        Self {
            sent: AtomicU64::new(0),
        }
    }
}

impl PacketEngine for CountingEngine {
    fn tx_batch(&self, packets: &[RawPacket]) -> Result<usize, EngineError> {
        self.sent.fetch_add(packets.len() as u64, Ordering::Relaxed);
        Ok(packets.len())
    }
    fn rx_batch(&self, _buf: &mut [RxPacket]) -> Result<usize, EngineError> {
        Ok(0)
    }
    fn stats(&self) -> EngineStats {
        EngineStats {
            tx_packets: self.sent.load(Ordering::Relaxed),
            ..EngineStats::default()
        }
    }
    fn name(&self) -> &'static str {
        "counting-stub"
    }
}

/// Extracted hot loop: schedule + stamp + batch flush. Mirrors
/// `EngineScanner::run`'s TX path so the bench tracks production code
/// rather than a re-implemented copy.
fn run_tx_hot_loop(num_targets: u64, num_ports: u64, batch_size: usize) -> u64 {
    let source_ip = Ipv4Addr::new(10, 0, 0, 1);
    let source_port: u16 = 53000;
    let template = packet::build_syn_template(source_ip, source_port);
    let encoder = SeqEncoder::new();
    let backend = CountingEngine::new();
    let schedule = ScanSchedule::new(num_targets, num_ports, 0);

    // Pre-allocate batch with `batch_size` template clones — same shape
    // as the production path.
    let mut batch: Vec<RawPacket> = (0..batch_size).map(|_| template.clone()).collect();
    let mut batch_len = 0usize;
    let mut total_sent = 0u64;

    for (ip_idx, port_idx) in schedule {
        // Synthetic dest IP: just use the index, we never send.
        let target_ip = Ipv4Addr::new(
            10,
            (ip_idx >> 16) as u8 & 0xff,
            (ip_idx >> 8) as u8 & 0xff,
            (ip_idx & 0xff) as u8,
        );
        let port = (port_idx as u16).wrapping_add(1);

        let slot = &mut batch[batch_len];
        let seq = encoder.encode(target_ip, port, source_port, 0);
        packet::stamp_syn(slot, target_ip, port, seq);
        batch_len += 1;

        if batch_len == batch_size {
            let sent = backend.tx_batch(&batch[..batch_len]).unwrap_or(0);
            total_sent += sent as u64;
            batch_len = 0;
        }
    }

    if batch_len > 0 {
        let sent = backend.tx_batch(&batch[..batch_len]).unwrap_or(0);
        total_sent += sent as u64;
    }

    total_sent
}

/// Parallel-TX hot loop. Mirrors EngineScanner::run's stride-based
/// parallelism: thread N processes global indices {N, N+T, N+2T, ...}
/// against the SAME deterministic Blackrock permutation. Each thread
/// has its own CountingEngine and SeqEncoder.
///
/// This is the bench that shows the multi-threaded TX win: with N
/// threads we expect close to N× the single-thread throughput up
/// until kernel/NIC contention (which the counting backend doesn't
/// have, so this bench shows a near-ideal linear ceiling).
fn run_tx_hot_loop_parallel(
    num_targets: u64,
    num_ports: u64,
    batch_size: usize,
    num_threads: usize,
) -> u64 {
    let source_ip = std::net::Ipv4Addr::new(10, 0, 0, 1);
    let source_port_base: u16 = 53000;
    let template = packet::build_syn_template(source_ip, source_port_base);
    let total_probes = num_targets.saturating_mul(num_ports);
    let total_sent = Arc::new(AtomicU64::new(0));
    let permutation_seed: u64 = 0;

    let mut handles = Vec::with_capacity(num_threads);
    for thread_id in 0..num_threads {
        let template = template.clone();
        let total_sent = Arc::clone(&total_sent);
        handles.push(std::thread::spawn(move || -> u64 {
            // Match production: pin to a dedicated CPU core. Without
            // this the bench numbers under-report what `scan.rs` does.
            #[cfg(target_os = "linux")]
            unsafe {
                let cpu_count = std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(1);
                let target_cpu = thread_id % cpu_count;
                let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
                libc::CPU_SET(target_cpu, &mut cpuset);
                let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
            }
            let encoder = SeqEncoder::new();
            let backend = CountingEngine::new();
            let permutation = BlackrockPermutation::new(total_probes.max(1), permutation_seed);
            let stride = num_threads as u64;
            let my_source_port = source_port_base + thread_id as u16;
            let mut batch: Vec<RawPacket> = (0..batch_size).map(|_| template.clone()).collect();
            let mut batch_len = 0usize;
            let mut local_sent: u64 = 0;
            let mut global_idx: u64 = thread_id as u64;
            while global_idx < total_probes {
                let permuted = permutation.shuffle(global_idx);
                let ip_idx = permuted / num_ports;
                let port_idx = permuted % num_ports;
                let target_ip = std::net::Ipv4Addr::new(
                    10,
                    (ip_idx >> 16) as u8 & 0xff,
                    (ip_idx >> 8) as u8 & 0xff,
                    (ip_idx & 0xff) as u8,
                );
                let port = (port_idx as u16).wrapping_add(1);
                let slot = &mut batch[batch_len];
                let seq = encoder.encode(target_ip, port, my_source_port, 0);
                packet::stamp_syn(slot, target_ip, port, seq);
                batch_len += 1;
                if batch_len == batch_size {
                    let sent = backend.tx_batch(&batch[..batch_len]).unwrap_or(0);
                    local_sent += sent as u64;
                    batch_len = 0;
                }
                global_idx += stride;
            }
            if batch_len > 0 {
                let sent = backend.tx_batch(&batch[..batch_len]).unwrap_or(0);
                local_sent += sent as u64;
            }
            total_sent.fetch_add(local_sent, Ordering::Relaxed);
            local_sent
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    total_sent.load(Ordering::Relaxed)
}

fn bench_tx_hot_loop(c: &mut Criterion) {
    // Benchmark a /16 sweep × top-100 ports = 6.5M probes per iteration.
    // Reports throughput in pps directly.
    let num_targets: u64 = 65_536;
    let num_ports: u64 = 100;
    let total_probes = num_targets * num_ports;

    let mut group = c.benchmark_group("tx_hot_loop");
    group.throughput(Throughput::Elements(total_probes));
    group.sample_size(10);

    for batch_size in [256usize, 1024, 4096] {
        group.bench_with_input(
            criterion::BenchmarkId::new("batch", batch_size),
            &batch_size,
            |b, &bs| {
                b.iter_batched(
                    || (),
                    |()| run_tx_hot_loop(num_targets, num_ports, bs),
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

fn bench_parallel_tx(c: &mut Criterion) {
    // Show how multi-threaded TX scales. Same /16 × top-100 workload.
    let num_targets: u64 = 65_536;
    let num_ports: u64 = 100;
    let total_probes = num_targets * num_ports;
    const BATCH_SIZE: usize = 1024;

    let mut group = c.benchmark_group("tx_hot_loop_parallel");
    group.throughput(Throughput::Elements(total_probes));
    group.sample_size(10);

    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(8);
    let candidates: Vec<usize> = [1usize, 2, 4, 8]
        .iter()
        .copied()
        .filter(|&n| n <= cpu_count)
        .collect();

    for &threads in &candidates {
        group.bench_with_input(
            criterion::BenchmarkId::new("threads", threads),
            &threads,
            |b, &t| {
                b.iter_batched(
                    || (),
                    |()| run_tx_hot_loop_parallel(num_targets, num_ports, BATCH_SIZE, t),
                    BatchSize::LargeInput,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_tx_hot_loop, bench_parallel_tx);
criterion_main!(benches);
