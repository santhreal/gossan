//! Core SYN scan engine implementing the Gossan [`Scanner`] trait.
//!
//! Orchestrates the full scan pipeline:
//! 1. Resolve targets to IPs
//! 2. Build SYN packet template
//! 3. Schedule probes via Blackrock permutation
//! 4. TX thread: stamp and send packets at configured rate
//! 5. RX thread: receive SYN-ACKs, verify stateless cookies
//! 6. Emit discovered services as `Target::Service`

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use futures::StreamExt;
use gossan_classify::BannerClassifier;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use async_trait::async_trait;
use gossan_core::{
    Config, HostTarget, PortMode, Protocol, ScanInput, Scanner, ServiceTarget, Target,
};
use netforge::engine::{RxPacket, tcp_flags};
use netforge::packet;
use netforge::seq::SeqEncoder;

use crate::rate::RateLimiter;
use crate::schedule::BlackrockPermutation;

/// Raw SYN scanner using netforge packet engine.
///
/// Performs stateless SYN scanning with randomized probe ordering,
/// configurable rate limiting, and OS fingerprinting from SYN-ACK responses.
pub struct EngineScanner {
    /// Secret for stateless cookie generation.
    encoder: SeqEncoder,
}

impl EngineScanner {
    /// Create a new engine scanner.
    #[must_use]
    pub fn new() -> Self {
        Self {
            encoder: SeqEncoder::new(),
        }
    }
}

impl Default for EngineScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// OS fingerprint heuristic from TTL and window size.
fn identify_os(ttl: u8, window: u16) -> Option<&'static str> {
    match ttl {
        62..=64 => Some("Linux/Unix"),
        126..=128 => Some("Windows"),
        254..=255 => Some("Cisco/Network Device"),
        _ => match window {
            // Some BSD variants use TTL=48 or TTL=50
            _ if ttl >= 48 && ttl <= 50 => Some("BSD"),
            _ => None,
        },
    }
}

/// Response collected from RX thread.
struct SynAckResponse {
    ip: Ipv4Addr,
    port: u16,
    ttl: u8,
    window: u16,
}

/// Per-/24 RST-burst backoff table. Shared between the RX thread (writer)
/// and TX threads (readers). When a /24 sends RSTs over a sustained rate
/// the RX thread inserts (slash24 → backoff_until). TX threads consult
/// this map before queuing a probe and skip subnets that are actively
/// rejecting our scan — which both saves the network and prevents the
/// remote firewall from learning to drop us harder.
///
/// The slash24 key is the /24 prefix packed as `u32::from_be_bytes([a,
/// b, c, 0])` — the high 24 bits are the prefix, low 8 are zero.
#[derive(Clone, Default)]
pub(crate) struct Slash24Backoff {
    inner: Arc<RwLock<HashMap<u32, Instant>>>,
    /// Total probes the TX side declined to send because the destination
    /// /24 was in active backoff. Surfaced as an info log at scan end so
    /// operators can see how aggressive the remote network was.
    pub(crate) skipped: Arc<AtomicU64>,
}

impl Slash24Backoff {
    fn new() -> Self {
        Self::default()
    }

    /// Insert a /24 into backoff for `duration` from now. Concurrent
    /// inserts from the RX thread keep the latest expiry.
    fn block(&self, slash24: u32, duration: Duration) {
        let until = Instant::now() + duration;
        // RwLock write-lock; uncontended hot path because the only
        // writer is the RX thread once per second.
        if let Ok(mut g) = self.inner.write() {
            // Don't shrink an existing longer backoff window.
            let entry = g.entry(slash24).or_insert(until);
            if *entry < until {
                *entry = until;
            }
        }
    }

    /// True if the /24 is currently blocked. Returns false when the
    /// stored expiry is in the past (lazy cleanup happens in `prune`).
    #[inline]
    fn is_blocked(&self, slash24: u32) -> bool {
        let g = match self.inner.read() {
            Ok(g) => g,
            Err(_) => return false, // poisoned lock = open by default
        };
        match g.get(&slash24) {
            Some(until) => *until > Instant::now(),
            None => false,
        }
    }

    /// Drop expired entries. Called from the RX thread once per window
    /// flush so the map stays small under long scans.
    fn prune(&self) {
        let now = Instant::now();
        if let Ok(mut g) = self.inner.write() {
            g.retain(|_, until| *until > now);
        }
    }
}

#[inline]
fn slash24_of(ip: Ipv4Addr) -> u32 {
    let o = ip.octets();
    u32::from_be_bytes([o[0], o[1], o[2], 0])
}

/// Discover the primary outgoing local IPv4 address.
fn get_local_ip(config: &Config) -> anyhow::Result<Ipv4Addr> {
    let target = config
        .resolvers
        .first()
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| "8.8.8.8".to_string());

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(format!("{target}:53"))?;
    if let IpAddr::V4(addr) = socket.local_addr()?.ip() {
        Ok(addr)
    } else {
        anyhow::bail!("could not determine local IPv4 route")
    }
}

/// Resolve port mode to a concrete list of ports.
fn resolve_ports(mode: &PortMode) -> Vec<u16> {
    match mode {
        PortMode::Default => vec![
            80, 443, 22, 21, 23, 25, 53, 110, 143, 3306, 5432, 8080, 8443,
            6379, 27017, 9200, 3000, 5000, 8000, 9000,
        ],
        PortMode::Top100 => vec![
            80, 443, 22, 21, 25, 53, 110, 143, 993, 995, 8080, 8443, 3306,
            5432, 3389, 5900, 1723, 8000, 8888, 9090, 1433, 389, 636, 161,
            162, 123, 69, 514, 5060, 5061, 2049, 111, 135, 139, 445, 1521,
            1080, 3128, 8081, 9000, 9200, 9300, 6379, 27017, 11211, 5672,
            15672, 4369, 25672, 6443, 2379, 2380, 10250, 10255, 4194, 8001,
            8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009, 8010, 8181,
            8282, 8383, 8484, 8585, 8686, 8787, 8888, 9999, 7070, 7071,
            7072, 7443, 4443, 4040, 5000, 5001, 5002, 5003, 5004, 5005,
            5006, 5007, 5008, 5009, 5010, 6000, 6001, 6002, 6003, 6004,
            6005, 6006, 6007, 6008, 6009, 6010,
        ],
        PortMode::Top1000 => {
            // Nmap top 1000 — using a representative subset
            (1..=1024).chain([1433, 1521, 2049, 2379, 3000, 3128, 3306,
                3389, 4443, 5000, 5432, 5672, 5900, 6379, 6443, 7070,
                8000, 8080, 8443, 8888, 9000, 9090, 9200, 9300, 10250,
                11211, 15672, 27017].iter().copied())
                .collect()
        }
        PortMode::Full => (1..=65535).collect(),
        PortMode::Custom(ports) => ports.clone(),
    }
}

#[async_trait]
impl Scanner for EngineScanner {
    fn name(&self) -> &'static str {
        "engine"
    }

    fn tags(&self) -> &[&'static str] {
        &["active", "network", "portscan", "raw", "engine"]
    }

    fn accepts(&self, target: &Target) -> bool {
        matches!(target, Target::Host(_) | Target::Domain(_))
    }

    async fn run(&self, input: ScanInput, config: &Config) -> anyhow::Result<()> {
        let source_ip = get_local_ip(config)?;
        let source_port = 49152 + (std::process::id() as u16 % 16383);
        let ports = resolve_ports(&config.port_mode);

        // Resolve all targets to IPv4 addresses
        let mut target_ips: Vec<(Ipv4Addr, Target)> = Vec::new();

        // Drain incoming targets
        let mut incoming = Vec::new();
        {
            let mut rx = input.target_rx.lock().await;
            while let Ok(t) = rx.try_recv() {
                incoming.push(t);
            }
        }

        for t in &incoming {
            match t {
                Target::Host(h) => {
                    if let IpAddr::V4(ipv4) = h.ip {
                        target_ips.push((ipv4, t.clone()));
                    }
                }
                Target::Domain(d) => {
                    if let Ok(addrs) = input.resolver.lookup_ip(format!("{}.", d.domain)).await {
                        for addr in addrs {
                            if let IpAddr::V4(ipv4) = addr {
                                target_ips.push((ipv4, t.clone()));
                                break;
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if target_ips.is_empty() {
            tracing::warn!("no targets resolved to IPv4 addresses");
            return Ok(());
        }

        tracing::info!(
            targets = target_ips.len(),
            ports = ports.len(),
            total_probes = target_ips.len() * ports.len(),
            rate_pps = config.rate_limit,
            "starting SYN scan via engine"
        );

        // Build packet template
        let template = packet::build_syn_template(source_ip, source_port);

        // Set up result channel
        let (res_tx, res_rx) = crossbeam_channel::bounded(500_000);

        // RX socket — single shared raw socket for receive (all SYN-ACKs
        // come back to whichever fd kernel hands them to since we only
        // bind by source IP, not port). The TX side opens its own raw
        // socket per thread inside the parallel-TX block below.
        let engine_config_rx = netforge::EngineConfig {
            source_ip,
            source_port_start: source_port,
            source_port_end: source_port + 1,
            rate_pps: config.rate_limit as u64,
            ..Default::default()
        };
        let rx_engine = netforge::engine::auto_select(engine_config_rx)?;

        // RX thread: collect SYN-ACKs. The dst_port filter is widened
        // to the per-thread source-port range so SYN-ACKs replying to
        // any TX thread are accepted (each TX thread uses a unique
        // ephemeral source port; see GOSSAN_TX_THREADS comment below).
        let stop_flag = Arc::new(AtomicBool::new(false));
        let rx_stop = Arc::clone(&stop_flag);
        let rx_encoder = SeqEncoder::with_cookie(self.encoder.cookie().clone());
        let rx_source_port_base = source_port;

        // Backoff table shared with all TX threads. RX writes; TX reads.
        let backoff = Slash24Backoff::new();
        let rx_backoff = backoff.clone();

        let rx_handle = std::thread::spawn(move || {
            let mut rx_buf = vec![RxPacket {
                packet: netforge::RawPacket::empty(),
                src_ip: Ipv4Addr::UNSPECIFIED,
                src_port: 0,
                dst_port: 0,
                tcp_flags: 0,
                ack_num: 0,
                seq_num: 0,
                ttl: 0,
                window: 0,
                payload: Vec::new(),
            }; 256];

            // Adaptive RST-burst detection: count RST packets per /24
            // subnet over a 1-second sliding window. When a single /24
            // exceeds RST_BURST_THRESHOLD per second, log a warning so
            // the operator knows that subnet is actively rejecting our
            // probes — a signal masscan does not surface at all.
            const RST_BURST_THRESHOLD: u32 = 100;
            let mut rst_count_per_24: HashMap<u32, u32> = HashMap::new();
            let mut last_rst_window = std::time::Instant::now();

            while !rx_stop.load(Ordering::Relaxed) {
                let count = rx_engine.rx_batch(&mut rx_buf).unwrap_or(0);
                for i in 0..count {
                    let pkt = &rx_buf[i];

                    // Track RSTs by /24 subnet for adaptive backoff.
                    if pkt.tcp_flags & tcp_flags::RST != 0
                        && pkt.dst_port >= rx_source_port_base
                        && pkt.dst_port < rx_source_port_base + 8
                    {
                        let octets = pkt.src_ip.octets();
                        let slash24 =
                            u32::from_be_bytes([octets[0], octets[1], octets[2], 0]);
                        *rst_count_per_24.entry(slash24).or_insert(0) += 1;
                    }

                    // Filter: only SYN-ACKs whose dst_port falls inside
                    // the TX-thread port range [base, base+8). 8 is the
                    // max TX thread count we cap to.
                    if pkt.dst_port < rx_source_port_base
                        || pkt.dst_port >= rx_source_port_base + 8
                    {
                        continue;
                    }
                    if pkt.tcp_flags & tcp_flags::SYN_ACK != tcp_flags::SYN_ACK {
                        continue;
                    }

                    // Verify stateless cookie. The cookie includes the
                    // dst_port so verify with the actual port the SYN
                    // was sent from (= pkt.dst_port from RX perspective).
                    if rx_encoder.verify_synack(
                        pkt.ack_num,
                        pkt.src_ip,
                        pkt.src_port,
                        pkt.dst_port,
                    ) {
                        let _ = res_tx.try_send(SynAckResponse {
                            ip: pkt.src_ip,
                            port: pkt.src_port,
                            ttl: pkt.ttl,
                            window: pkt.window,
                        });
                    }
                }

                // RST window flush: once a second, log any /24 over
                // the burst threshold AND mark it for TX-side backoff.
                // The TX threads consult `rx_backoff` before queuing
                // each probe and will skip blocked /24s for the
                // duration below — masscan does not do this and gets
                // throttled harder by upstream firewalls as a result.
                let now = std::time::Instant::now();
                if now.duration_since(last_rst_window).as_secs() >= 1 {
                    const BACKOFF_DURATION: Duration = Duration::from_secs(30);
                    for (slash24, n) in &rst_count_per_24 {
                        if *n >= RST_BURST_THRESHOLD {
                            let octets = slash24.to_be_bytes();
                            tracing::warn!(
                                subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]),
                                rst_per_sec = n,
                                backoff_s = BACKOFF_DURATION.as_secs(),
                                "engine: RST burst detected — entering backoff"
                            );
                            rx_backoff.block(*slash24, BACKOFF_DURATION);
                        }
                    }
                    rx_backoff.prune();
                    rst_count_per_24.clear();
                    last_rst_window = now;
                }

                if count == 0 {
                    std::thread::sleep(std::time::Duration::from_micros(100));
                }
            }
        });

        // ── Parallel TX ────────────────────────────────────────────────
        // Multiple TX threads each own:
        //   - A separate raw socket (separate netforge engine handle).
        //     Linux's raw-socket egress doesn't lock per-fd, so multiple
        //     fds give linear speedup until the NIC is saturated.
        //   - An exclusive stride of the global probe schedule. Thread
        //     N processes global indices [N, N+num_threads, N+2*num_threads, ...].
        //   - Its own rate limiter sized to (total_rate / num_threads)
        //     so the aggregate rate matches user config.
        //   - Its own batch buffer (1.5 MB) and SeqEncoder bound to the
        //     shared cookie so RX can verify SYN-ACKs from any TX thread.
        //
        // Hot-loop choices that matter:
        //   - Pre-allocate batch ONCE with TX_BATCH template clones; reuse.
        //   - stamp_syn fully overwrites the per-probe bytes — no
        //     copy_from_slice needed each iteration.
        //   - Per-batch rate-limit consume (one spin-wait per batch
        //     instead of per probe).
        //   - 1024 pkts/batch matches kernel mmsghdr cap.
        const TX_BATCH: usize = 1024;
        let num_ips = target_ips.len() as u64;
        let num_ports = ports.len() as u64;
        let total_probes = num_ips.saturating_mul(num_ports);
        let schedule_seed: u64 = fastrand::u64(..);

        // Number of TX threads — capped at 8 because beyond ~4 we hit
        // kernel softirq / ring contention on most NICs and the next
        // win is moving to AF_XDP (the next backend). Honour an env
        // override for ops to dial up/down without recompiling.
        let num_tx_threads: usize = std::env::var("GOSSAN_TX_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| std::thread::available_parallelism()
                .map(|n| n.get().min(8).max(1))
                .unwrap_or(2));

        let scan_start = std::time::Instant::now();
        tracing::info!(
            tx_threads = num_tx_threads,
            total_probes,
            rate_pps = config.rate_limit,
            "engine: parallel TX dispatching"
        );

        let total_sent_atomic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let cookie = self.encoder.cookie().clone();
        // Per-thread rate (rounded up so the aggregate matches even
        // when total_rate doesn't divide evenly). 0 = unlimited.
        let per_thread_rate: u64 = if config.rate_limit == 0 {
            0
        } else {
            ((config.rate_limit as u64) + num_tx_threads as u64 - 1) / num_tx_threads as u64
        };

        // Pack target_ips into a Vec<Ipv4Addr> for cheap shared-by-Arc
        // access in worker threads (Target is large; we only need the IP).
        let ip_slice: Arc<Vec<Ipv4Addr>> =
            Arc::new(target_ips.iter().map(|(ip, _)| *ip).collect());
        let ports_slice: Arc<Vec<u16>> = Arc::new(ports.clone());

        let adaptive_rate_enabled = config.adaptive_rate;
        let icmp_backoff = crate::icmp_backoff::IcmpBackoff::new();
        let mut tx_handles = Vec::with_capacity(num_tx_threads);
        for thread_id in 0..num_tx_threads {
            let cookie_for_thread = cookie.clone();
            let ip_slice = Arc::clone(&ip_slice);
            let ports_slice = Arc::clone(&ports_slice);
            let template_for_thread = template.clone();
            let total_sent_atomic = Arc::clone(&total_sent_atomic);
            let tx_backoff = backoff.clone();
            let tx_icmp_backoff = icmp_backoff.clone();
            let engine_config = netforge::EngineConfig {
                source_ip,
                // Each TX thread gets its own ephemeral source-port slot
                // so kernel-side flow tracking doesn't conflate them.
                source_port_start: source_port + thread_id as u16,
                source_port_end: source_port + thread_id as u16 + 1,
                rate_pps: per_thread_rate,
                ..Default::default()
            };

            tx_handles.push(std::thread::spawn(move || -> u64 {
                // Pin this TX thread to a dedicated CPU core for cache
                // locality. Linux only; other platforms silently no-op.
                // At 90+ Mpps, every L2 miss costs measurable throughput.
                // Failure is non-fatal — we just lose the affinity speedup.
                #[cfg(target_os = "linux")]
                unsafe {
                    let cpu_count = std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(1);
                    let target_cpu = thread_id % cpu_count;
                    let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
                    libc::CPU_SET(target_cpu, &mut cpuset);
                    let _ = libc::sched_setaffinity(
                        0,
                        std::mem::size_of::<libc::cpu_set_t>(),
                        &cpuset,
                    );
                }

                // Per-thread engine + rate limiter + encoder + batch.
                let tx_engine = match netforge::engine::auto_select(engine_config) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::error!(thread_id, error = %e, "TX engine init failed");
                        return 0;
                    }
                };
                let encoder = SeqEncoder::with_cookie(cookie_for_thread);
                let mut rate_limiter = RateLimiter::new(per_thread_rate, TX_BATCH as u64);
                let unlimited = rate_limiter.is_unlimited();
                // AIMD interlock — only armed when explicitly requested.
                // The ceiling is the per-thread share of the configured rate;
                // AdaptiveLoop seeds itself at half-rate per `AdaptiveRate::new`.
                let mut adaptive_loop: Option<crate::rate::AdaptiveLoop> =
                    if adaptive_rate_enabled && !unlimited {
                        Some(crate::rate::AdaptiveLoop::new(per_thread_rate))
                    } else {
                        None
                    };
                // Tick cadence: every TICK_BATCHES batches we re-poll
                // engine stats and re-target the limiter. Cheap.
                const TICK_BATCHES: u32 = 8;
                let mut batches_since_tick: u32 = 0;

                let mut batch: Vec<netforge::RawPacket> =
                    (0..TX_BATCH).map(|_| template_for_thread.clone()).collect();
                let mut batch_len: usize = 0;
                let mut local_sent: u64 = 0;

                // Stride iteration over the SAME deterministic schedule.
                // Thread N handles global_idx ∈ {N, N+T, N+2T, ...}. The
                // permutation is constructed identically in every thread
                // (deterministic from `schedule_seed`); each thread only
                // calls .shuffle() on indices it owns.
                let permutation = BlackrockPermutation::new(total_probes.max(1), schedule_seed);
                let stride = num_tx_threads as u64;
                let mut global_idx: u64 = thread_id as u64;

                while global_idx < total_probes {
                    let permuted = permutation.shuffle(global_idx);
                    let ip_idx = permuted / num_ports;
                    let port_idx = permuted % num_ports;
                    let target_ip = ip_slice[ip_idx as usize];
                    let port = ports_slice[port_idx as usize];

                    // Adaptive backoff consumer. If the RX side flagged
                    // this /24 as actively rejecting probes, skip the
                    // whole probe rather than burn TX budget on it.
                    // The skip is silent — the warn is emitted once
                    // per second from the RX thread when the burst is
                    // first detected.
                    let s24 = slash24_of(target_ip);
                    if tx_backoff.is_blocked(s24) {
                        tx_backoff.skipped.fetch_add(1, Ordering::Relaxed);
                        global_idx += stride;
                        continue;
                    }
                    // Mirror check on the ICMP-unreachable backoff. The
                    // source side (netforge ICMP RX) is open work; the
                    // consumer plug-in is live so a future signal route
                    // does not require a scan.rs edit.
                    if tx_icmp_backoff.is_blocked(s24) {
                        global_idx += stride;
                        continue;
                    }

                    let slot = &mut batch[batch_len];
                    // Each TX thread uses its own source port so the
                    // RX side can disambiguate which thread a SYN-ACK
                    // is replying to. Cookie stamping uses the same port.
                    let my_source_port = source_port + thread_id as u16;
                    let seq = encoder.encode(target_ip, port, my_source_port, 0);
                    packet::stamp_syn(slot, target_ip, port, seq);
                    batch_len += 1;

                    if batch_len == TX_BATCH {
                        if !unlimited {
                            let mut remaining = TX_BATCH as u64;
                            while remaining > 0 {
                                let got = rate_limiter.try_consume_batch(remaining);
                                if got == 0 {
                                    std::hint::spin_loop();
                                    continue;
                                }
                                remaining -= got;
                            }
                        }
                        let sent = tx_engine.tx_batch(&batch[..batch_len]).unwrap_or(0);
                        local_sent += sent as u64;
                        batch_len = 0;

                        if let Some(al) = adaptive_loop.as_mut() {
                            batches_since_tick += 1;
                            if batches_since_tick >= TICK_BATCHES {
                                batches_since_tick = 0;
                                let s = tx_engine.stats();
                                al.tick(s.tx_packets, s.tx_drops);
                                al.apply(&mut rate_limiter);
                            }
                        }
                    }

                    global_idx += stride;
                }

                // Flush partial batch.
                if batch_len > 0 {
                    if !unlimited {
                        let mut remaining = batch_len as u64;
                        while remaining > 0 {
                            let got = rate_limiter.try_consume_batch(remaining);
                            if got == 0 {
                                std::hint::spin_loop();
                                continue;
                            }
                            remaining -= got;
                        }
                    }
                    let sent = tx_engine.tx_batch(&batch[..batch_len]).unwrap_or(0);
                    local_sent += sent as u64;
                }

                total_sent_atomic.fetch_add(local_sent, std::sync::atomic::Ordering::Relaxed);
                local_sent
            }));
        }

        // Live throughput logger — runs on the orchestrator while
        // workers fan out. One info line per second showing aggregate pps.
        let log_atomic = Arc::clone(&total_sent_atomic);
        let log_stop = Arc::new(AtomicBool::new(false));
        let log_stop_handle = Arc::clone(&log_stop);
        let log_handle = std::thread::spawn(move || {
            let mut last_log = std::time::Instant::now();
            let mut last_sent: u64 = 0;
            while !log_stop_handle.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_secs(1));
                let now = std::time::Instant::now();
                let cur_sent = log_atomic.load(std::sync::atomic::Ordering::Relaxed);
                let dt = now.duration_since(last_log).as_secs_f64();
                let pps = ((cur_sent - last_sent) as f64 / dt) as u64;
                tracing::info!(
                    pps = pps,
                    sent = cur_sent,
                    "engine TX"
                );
                last_log = now;
                last_sent = cur_sent;
            }
        });

        // Wait for workers.
        for h in tx_handles {
            let _ = h.join();
        }
        log_stop.store(true, Ordering::Relaxed);
        let _ = log_handle.join();
        let total_sent = total_sent_atomic.load(std::sync::atomic::Ordering::Relaxed);
        let _ = scan_start;

        // tx_drops is no longer easily aggregated — each TX thread had its
        // own engine and we joined them already. Total sent comes from the
        // shared atomic; drops would need a separate atomic if we wanted
        // them. For now report wall-time pps from the scan-start clock.
        let elapsed_s = scan_start.elapsed().as_secs_f64().max(0.000_001);
        let skipped = backoff.skipped.load(Ordering::Relaxed);
        tracing::info!(
            sent = total_sent,
            tx_threads = num_tx_threads,
            elapsed_s,
            pps = (total_sent as f64 / elapsed_s) as u64,
            backoff_skipped = skipped,
            "SYN probes sent. Waiting for responses..."
        );
        if skipped > 0 {
            tracing::info!(
                backoff_skipped = skipped,
                "engine: skipped probes against /24 subnets in active RST backoff"
            );
        }

        // Wait for stragglers
        tokio::time::sleep(config.timeout()).await;
        stop_flag.store(true, Ordering::Relaxed);
        let _ = rx_handle.join();

        // Collect results
        let mut found: HashMap<(Ipv4Addr, u16), SynAckResponse> = HashMap::new();
        while let Ok(resp) = res_rx.try_recv() {
            found.insert((resp.ip, resp.port), resp);
        }

        tracing::info!(
            open_ports = found.len(),
            "scan complete"
        );

        // ── Banner grab + service classification ─────────────────────────
        // For each open port discovered by the SYN scan, do a quick
        // TCP connect-and-read to grab a ~512-byte banner, then run
        // gossan-classify rules to identify the service. This is the
        // masscan-parity item — masscan has `--banners` for the same
        // thing. Concurrency caps prevent banner grab from undoing the
        // scan-time win; with 500-way concurrency the grab phase
        // typically finishes in seconds even for thousands of ports.
        let classifier = Arc::new(BannerClassifier::new());
        // Convert &'static str OS hint to owned String so the closure
        // below isn't HRTB-bound by an unwanted 'static lifetime.
        let mut grab_jobs: Vec<(Ipv4Addr, u16, Option<String>, Option<String>)> =
            Vec::with_capacity(found.len());
        for (ip, t) in &target_ips {
            let domain = match t {
                Target::Domain(d) => Some(d.domain.clone()),
                Target::Host(h) => h.domain.clone(),
                _ => None,
            };
            for &port in &ports {
                if let Some(info) = found.get(&(*ip, port)) {
                    let os = identify_os(info.ttl, info.window).map(|s| s.to_string());
                    grab_jobs.push((*ip, port, domain.clone(), os));
                }
            }
        }

        if !grab_jobs.is_empty() {
            let banner_grab_start = std::time::Instant::now();
            tracing::info!(
                open_ports = grab_jobs.len(),
                "engine: starting banner grab + classification"
            );
            const GRAB_TIMEOUT: Duration = Duration::from_secs(2);
            const GRAB_CONCURRENCY: usize = 500;

            let results = futures::stream::iter(grab_jobs)
                .map(|(ip, port, domain, os)| {
                    let classifier = Arc::clone(&classifier);
                    async move {
                        let banner = grab_banner(ip, port, GRAB_TIMEOUT).await;
                        let classification = banner
                            .as_deref()
                            .and_then(|b| classifier.classify_top(b))
                            .map(|m| format!("{}/{}", m.service, m.version.unwrap_or_else(|| "?".into())));
                        (ip, port, domain, os, banner, classification)
                    }
                })
                .buffer_unordered(GRAB_CONCURRENCY)
                .collect::<Vec<_>>()
                .await;

            tracing::info!(
                grabbed = results.len(),
                elapsed_s = banner_grab_start.elapsed().as_secs_f64(),
                "engine: banner grab complete"
            );

            for (ip, port, domain, os, banner, classification) in results {
                let tls = port == 443 || port == 8443;
                let mut tags: Vec<String> = Vec::new();
                if let Some(o) = os {
                    tags.push(format!("[OS: {o}]"));
                }
                if let Some(c) = &classification {
                    tags.push(format!("[SVC: {c}]"));
                }
                let banner_str = if !tags.is_empty() || banner.is_some() {
                    let mut s = tags.join(" ");
                    if let Some(b) = &banner {
                        if !s.is_empty() {
                            s.push(' ');
                        }
                        // Truncate raw banner to keep ServiceTarget compact.
                        let b_trim = b.trim();
                        let cap = 200;
                        if b_trim.len() > cap {
                            s.push_str(&b_trim[..cap]);
                            s.push_str("…");
                        } else {
                            s.push_str(b_trim);
                        }
                    }
                    Some(s)
                } else {
                    None
                };

                let svc = ServiceTarget {
                    host: HostTarget {
                        ip: IpAddr::V4(ip),
                        domain,
                    },
                    port,
                    protocol: Protocol::Tcp,
                    banner: banner_str,
                    tls,
                };
                input.emit_target(Target::Service(svc));
            }
        }

        Ok(())
    }
}

/// Lightweight banner grabber: TCP-connect, send a generic probe, read
/// up to 512 bytes, return as UTF-8-lossy. None on connect / read
/// failure or empty response. The probe is "GET / HTTP/1.0\r\n\r\n" for
/// likely-web ports and a no-op (read-only) for everything else — many
/// services (SSH, FTP, SMTP, IRC, Redis without AUTH) emit a banner on
/// connect, so we just need to wait briefly for the server to speak.
async fn grab_banner(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<String> {
    let connect_fut = TcpStream::connect((ip, port));
    let mut stream = match tokio::time::timeout(timeout, connect_fut).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    // For HTTP-ish ports, kick the server with a GET so it actually
    // responds. For most other ports the server speaks first.
    if matches!(port, 80 | 8080 | 8000 | 8888 | 443 | 8443 | 9000) {
        let _ = stream
            .write_all(b"GET / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: gossan\r\n\r\n")
            .await;
    }
    let mut buf = [0u8; 512];
    let read_fut = stream.read(&mut buf);
    let n = match tokio::time::timeout(timeout, read_fut).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };
    Some(String::from_utf8_lossy(&buf[..n]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gossan_core::{DiscoverySource, DomainTarget};

    #[test]
    fn scanner_metadata() {
        let scanner = EngineScanner::new();
        assert_eq!(scanner.name(), "engine");
        assert!(scanner.tags().contains(&"raw"));
        assert!(scanner.tags().contains(&"engine"));
    }

    #[test]
    fn accepts_hosts_and_domains() {
        let scanner = EngineScanner::new();
        assert!(scanner.accepts(&Target::Domain(DomainTarget {
            domain: "example.com".into(),
            source: DiscoverySource::Seed,
        })));
        assert!(scanner.accepts(&Target::Host(HostTarget {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            domain: None,
        })));
    }

    #[test]
    fn rejects_non_host_targets() {
        let scanner = EngineScanner::new();
        // Service targets are accepted, but Web targets are not
        let svc = Target::Service(ServiceTarget {
            host: HostTarget {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                domain: None,
            },
            port: 80,
            protocol: Protocol::Tcp,
            banner: None,
            tls: false,
        });
        assert!(!scanner.accepts(&svc));
    }

    #[test]
    fn os_fingerprint_linux() {
        assert_eq!(identify_os(64, 29200), Some("Linux/Unix"));
        assert_eq!(identify_os(63, 14600), Some("Linux/Unix"));
    }

    #[test]
    fn os_fingerprint_windows() {
        assert_eq!(identify_os(128, 65535), Some("Windows"));
        assert_eq!(identify_os(127, 8192), Some("Windows"));
    }

    #[test]
    fn os_fingerprint_cisco() {
        assert_eq!(identify_os(255, 4128), Some("Cisco/Network Device"));
    }

    #[test]
    fn os_fingerprint_unknown() {
        assert_eq!(identify_os(100, 0), None);
    }

    #[test]
    fn resolve_ports_default() {
        let ports = resolve_ports(&PortMode::Default);
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&22));
        assert!(!ports.is_empty());
    }

    #[test]
    fn resolve_ports_full() {
        let ports = resolve_ports(&PortMode::Full);
        assert_eq!(ports.len(), 65535);
        assert_eq!(*ports.first().unwrap_or(&0), 1);
        assert_eq!(*ports.last().unwrap_or(&0), 65535);
    }

    #[test]
    fn resolve_ports_custom() {
        let ports = resolve_ports(&PortMode::Custom(vec![80, 443, 8080]));
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn slash24_of_strips_low_octet() {
        let a: Ipv4Addr = "10.20.30.40".parse().unwrap();
        let b: Ipv4Addr = "10.20.30.41".parse().unwrap();
        let c: Ipv4Addr = "10.20.31.40".parse().unwrap();
        assert_eq!(slash24_of(a), slash24_of(b));
        assert_ne!(slash24_of(a), slash24_of(c));
    }

    #[test]
    fn slash24_backoff_blocks_then_expires() {
        let bo = Slash24Backoff::new();
        let s = slash24_of("203.0.113.7".parse().unwrap());
        assert!(!bo.is_blocked(s), "untouched subnet must not be blocked");
        bo.block(s, Duration::from_millis(50));
        assert!(bo.is_blocked(s), "subnet must be blocked immediately after insert");
        std::thread::sleep(Duration::from_millis(80));
        assert!(
            !bo.is_blocked(s),
            "subnet must auto-expire once backoff window elapses"
        );
    }

    #[test]
    fn slash24_backoff_does_not_shrink_existing_window() {
        let bo = Slash24Backoff::new();
        let s = slash24_of("198.51.100.1".parse().unwrap());
        bo.block(s, Duration::from_secs(60));
        bo.block(s, Duration::from_millis(10));
        // The shorter window must NOT replace the longer one.
        std::thread::sleep(Duration::from_millis(40));
        assert!(bo.is_blocked(s), "longer window must survive a shorter overwrite");
    }

    #[test]
    fn slash24_backoff_prune_removes_expired_only() {
        let bo = Slash24Backoff::new();
        // Distinct /24s. `slash24_of` zeros the low octet, so 192.0.2.10
        // and 192.0.2.20 collide on the same key — use a different /24
        // for `dead` to actually exercise prune's per-key behavior.
        let live = slash24_of("192.0.2.10".parse().unwrap());
        let dead = slash24_of("192.0.3.20".parse().unwrap());
        assert_ne!(live, dead, "test must use distinct /24 keys");
        bo.block(live, Duration::from_secs(60));
        bo.block(dead, Duration::from_millis(5));
        std::thread::sleep(Duration::from_millis(40));
        bo.prune();
        assert!(bo.is_blocked(live));
        // Map entry for `dead` is gone, so is_blocked returns false.
        assert!(!bo.is_blocked(dead));
    }

    #[test]
    fn slash24_backoff_skipped_counter_starts_at_zero() {
        let bo = Slash24Backoff::new();
        assert_eq!(bo.skipped.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn slash24_backoff_clones_share_state() {
        let bo = Slash24Backoff::new();
        let bo2 = bo.clone();
        let s = slash24_of("10.0.0.1".parse().unwrap());
        bo.block(s, Duration::from_secs(60));
        assert!(bo2.is_blocked(s), "clone must observe writes through original");
        bo2.skipped.fetch_add(7, Ordering::Relaxed);
        assert_eq!(bo.skipped.load(Ordering::Relaxed), 7);
    }
}
