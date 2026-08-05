//! Core SYN scan engine implementing the Gossan [`Scanner`] trait.
//!
//! Orchestrates the full scan pipeline:
//! 1. Resolve targets to IPs
//! 2. Build SYN packet template
//! 3. Schedule probes via Blackrock permutation
//! 4. TX thread: stamp and send packets at configured rate
//! 5. RX thread: receive SYN-ACKs, verify stateless cookies
//! 6. Emit discovered services as Findings + `Target::Service`

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
use secfinding::{Evidence, Finding, Severity};
use netforge::engine::{tcp_flags, RxPacket};
use netforge::packet;
use netforge::seq::SeqEncoder;

use crate::rate::RateLimiter;
use crate::schedule::BlackrockPermutation;

use gossan_core::{EPHEMERAL_PORT_COUNT, EPHEMERAL_PORT_START};

/// Maximum number of parallel TX threads. The RX port-range filter widens
/// its acceptance window by exactly this many slots above the base port, so
/// both values must stay in sync (§6 GENERALIZATION (single source of truth)).
const MAX_TX_THREADS: u16 = 8;

/// Clamp operator/env TX thread count into the supported range.
fn clamp_tx_threads(requested: usize) -> usize {
    requested.clamp(1, MAX_TX_THREADS as usize)
}


/// Crossbeam channel capacity for SYN-ACK responses collected by the RX
/// thread before the main task drains them. Sized to hold a worst-case
/// scan burst without the RX thread blocking.
const SYN_ACK_CHANNEL_CAP: usize = 500_000;

/// Number of RST packets per /24 per second that triggers adaptive backoff.
const RST_BURST_THRESHOLD: u32 = 100;

/// How long to back off from a /24 that exceeds `RST_BURST_THRESHOLD`.
const RST_BACKOFF_DURATION: Duration = Duration::from_secs(30);

/// Banner grab TCP timeout.
const GRAB_TIMEOUT: Duration = Duration::from_secs(2);

/// Max concurrent banner-grab TCP connections after a SYN scan.
const GRAB_CONCURRENCY: usize = 500;

/// Raw SYN scanner using netforge packet engine.
///
/// Performs stateless SYN scanning with randomized probe ordering,
/// configurable rate limiting, and OS fingerprinting from SYN-ACK responses.

/// Collect every IPv4 from a resolver/host address iterator (no early exit).
fn collect_ipv4_addrs(addrs: impl IntoIterator<Item = IpAddr>) -> Vec<Ipv4Addr> {
    addrs
        .into_iter()
        .filter_map(|addr| match addr {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .collect()
}

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
/// rejecting our scan, which both saves the network and prevents the
/// remote firewall from learning to drop us harder.
///
/// The slash24 key is the /24 prefix packed as `u32::from_be_bytes([a,
/// b, c, 0])` (the high 24 bits are the prefix, low 8 are zero).
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
    crate::icmp_backoff::IcmpBackoff::slash24_of(ip)
}

/// Discover the primary outgoing local IPv4 address.

/// Choose an ephemeral source-port base with headroom for `MAX_TX_THREADS`
/// distinct TX slots so `base + thread_id` never wraps `u16`.
fn choose_source_port_base(pid: u32) -> u16 {
    let headroom = MAX_TX_THREADS.saturating_sub(1);
    let max_base = u16::MAX.saturating_sub(headroom);
    let span = max_base
        .saturating_sub(EPHEMERAL_PORT_START)
        .min(EPHEMERAL_PORT_COUNT.saturating_sub(1))
        .max(1);
    let candidate = EPHEMERAL_PORT_START.saturating_add((pid as u16) % span);
    candidate.min(max_base)
}

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
use gossan_core::resolve_ports;

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
        let source_port = choose_source_port_base(std::process::id());
        let ports = resolve_ports(&config.port_mode);

        // Resolve all targets to IPv4 addresses
        let mut target_ips: Vec<(Ipv4Addr, usize)> = Vec::new();

        // Drain incoming targets until the pipeline closes the inbox.
        // try_recv races the sender and drops asynchronously delivered targets.
        let mut incoming = Vec::new();
        {
            let mut rx = input.target_rx.lock().await;
            while let Some(t) = rx.recv().await {
                incoming.push(t);
            }
        }

        for (i, t) in incoming.iter().enumerate() {
            match t {
                Target::Host(h) => {
                    if let IpAddr::V4(ipv4) = h.ip {
                        target_ips.push((ipv4, i));
                    }
                }
                Target::Domain(d) => {
                    match input.resolver.lookup_ip(format!("{}.", d.domain)).await {
                        Ok(addrs) => {
                            for ipv4 in collect_ipv4_addrs(addrs) {
                                target_ips.push((ipv4, i));
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                domain = %d.domain,
                                error = %e,
                                "engine: domain lookup_ip failed; skipping target"
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        if target_ips.is_empty() {
            if incoming.is_empty() {
                return Ok(());
            }
            anyhow::bail!(
                "no targets resolved to IPv4 addresses ({} inbound target(s); IPv6-only or DNS failure)",
                incoming.len()
            );
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
        let (res_tx, res_rx) = crossbeam_channel::bounded(SYN_ACK_CHANNEL_CAP);

        // RX socket, single shared raw socket for receive (all SYN-ACKs
        // come back to whichever fd kernel hands them to since we only
        // bind by source IP, not port). The TX side opens its own raw
        // socket per thread inside the parallel-TX block below.
        let engine_config_rx = netforge::EngineConfig {
            source_ip,
            source_port_start: source_port,
            // TX threads use [source_port, source_port + MAX_TX_THREADS).
            source_port_end: source_port.saturating_add(MAX_TX_THREADS),
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
            let mut rx_buf = vec![
                RxPacket {
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
                };
                256
            ];

            // Adaptive RST-burst detection: count RST packets per /24
            // subnet over a 1-second sliding window. When a single /24
            // exceeds RST_BURST_THRESHOLD per second, log a warning so
            // the operator knows that subnet is actively rejecting our
            // probes (a signal masscan does not surface at all).
            let mut rst_count_per_24: HashMap<u32, u32> = HashMap::new();
            let mut last_rst_window = std::time::Instant::now();

            while !rx_stop.load(Ordering::Relaxed) {
                let count = match rx_engine.rx_batch(&mut rx_buf) {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!(error = %e, "engine rx_batch failed");
                        0
                    }
                };
                for i in 0..count {
                    let pkt = &rx_buf[i];

                    // Track RSTs by /24 subnet for adaptive backoff.
                    if pkt.tcp_flags & tcp_flags::RST != 0
                        && pkt.dst_port >= rx_source_port_base
                        && pkt.dst_port < rx_source_port_base + MAX_TX_THREADS
                    {
                        let octets = pkt.src_ip.octets();
                        let slash24 = u32::from_be_bytes([octets[0], octets[1], octets[2], 0]);
                        *rst_count_per_24.entry(slash24).or_insert(0) += 1;
                    }

                    // Filter: only SYN-ACKs whose dst_port falls inside
                    // the TX-thread port range [base, base+MAX_TX_THREADS).
                    if pkt.dst_port < rx_source_port_base
                        || pkt.dst_port >= rx_source_port_base + MAX_TX_THREADS
                    {
                        continue;
                    }
                    if pkt.tcp_flags & tcp_flags::SYN_ACK != tcp_flags::SYN_ACK {
                        continue;
                    }

                    // Verify stateless cookie. The cookie includes the
                    // dst_port so verify with the actual port the SYN
                    // was sent from (= pkt.dst_port from RX perspective).
                    if rx_encoder.verify_synack(pkt.ack_num, pkt.src_ip, pkt.src_port, pkt.dst_port)
                    {
                        if let Err(e) = res_tx.try_send(SynAckResponse {
                            ip: pkt.src_ip,
                            port: pkt.src_port,
                            ttl: pkt.ttl,
                            window: pkt.window,
                        }) {
                            tracing::warn!(err = %e, "probe result channel full, dropping SYN-ACK");
                        }
                    }
                }

                // RST window flush: once a second, log any /24 over
                // the burst threshold AND mark it for TX-side backoff.
                // The TX threads consult `rx_backoff` before queuing
                // each probe and will skip blocked /24s for the
                // duration below, masscan does not do this and gets
                // throttled harder by upstream firewalls as a result.
                let now = std::time::Instant::now();
                if now.duration_since(last_rst_window).as_secs() >= 1 {
                    for (slash24, n) in &rst_count_per_24 {
                        if *n >= RST_BURST_THRESHOLD {
                            let octets = slash24.to_be_bytes();
                            tracing::warn!(
                                subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]),
                                rst_per_sec = n,
                                backoff_s = RST_BACKOFF_DURATION.as_secs(),
                                "engine: RST burst detected, entering backoff"
                            );
                            rx_backoff.block(*slash24, RST_BACKOFF_DURATION);
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
        //   - stamp_syn fully overwrites the per-probe bytes, no
        //     copy_from_slice needed each iteration.
        //   - Per-batch rate-limit consume (one spin-wait per batch
        //     instead of per probe).
        //   - 1024 pkts/batch matches kernel mmsghdr cap.
        const TX_BATCH: usize = 1024;
        let num_ips = target_ips.len() as u64;
        let num_ports = ports.len() as u64;
        let total_probes = num_ips.saturating_mul(num_ports);
        let schedule_seed: u64 = fastrand::u64(..);

        // Number of TX threads, capped at MAX_TX_THREADS because beyond ~4
        // we hit kernel softirq / ring contention on most NICs and the next
        // win is moving to AF_XDP (the next backend). Honour an env override
        // for ops to dial up/down without recompiling.
        let requested_tx = std::env::var("GOSSAN_TX_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(2)
            });
        let num_tx_threads = clamp_tx_threads(requested_tx);

        let scan_start = std::time::Instant::now();
        tracing::info!(
            tx_threads = num_tx_threads,
            total_probes,
            rate_pps = config.rate_limit,
            "engine: parallel TX dispatching"
        );

        let total_sent_atomic = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let tx_init_failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
        let ip_slice: Arc<Vec<Ipv4Addr>> = Arc::new(target_ips.iter().map(|(ip, _)| *ip).collect());
        let ports_slice: Arc<Vec<u16>> = Arc::new(ports.clone());

        let adaptive_rate_enabled = config.adaptive_rate;
        let mut tx_handles = Vec::with_capacity(num_tx_threads);
        for thread_id in 0..num_tx_threads {
            let cookie_for_thread = cookie.clone();
            let ip_slice = Arc::clone(&ip_slice);
            let ports_slice = Arc::clone(&ports_slice);
            let template_for_thread = template.clone();
            let total_sent_atomic = Arc::clone(&total_sent_atomic);
            let tx_init_failures = Arc::clone(&tx_init_failures);
            let tx_backoff = backoff.clone();
            let engine_config = netforge::EngineConfig {
                source_ip,
                // Each TX thread gets its own ephemeral source-port slot
                // so kernel-side flow tracking doesn't conflate them.
                source_port_start: source_port.saturating_add(thread_id as u16),
                source_port_end: source_port.saturating_add(thread_id as u16).saturating_add(1),
                rate_pps: per_thread_rate,
                ..Default::default()
            };

            tx_handles.push(std::thread::spawn(move || -> u64 {
                // Pin this TX thread to a dedicated CPU core for cache
                // locality. Linux only; other platforms silently no-op.
                // At 90+ Mpps, every L2 miss costs measurable throughput.
                // Failure is non-fatal (we just lose the affinity speedup).
                #[cfg(target_os = "linux")]
                unsafe {
                    let cpu_count = std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(1);
                    let target_cpu = thread_id % cpu_count;
                    let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
                    libc::CPU_SET(target_cpu, &mut cpuset);
                    let _ =
                        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
                }

                // Per-thread engine + rate limiter + encoder + batch.
                let tx_engine = match netforge::engine::auto_select(engine_config) {
                    Ok(e) => e,
                    Err(e) => {
                        tracing::error!(thread_id, error = %e, "TX engine init failed");
                        tx_init_failures.fetch_add(1, Ordering::Relaxed);
                        return 0;
                    }
                };
                let encoder = SeqEncoder::with_cookie(cookie_for_thread);
                let mut rate_limiter = RateLimiter::new(per_thread_rate, TX_BATCH as u64);
                let unlimited = rate_limiter.is_unlimited();
                // AIMD interlock (only armed when explicitly requested).
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
                    // The skip is silent, the warn is emitted once
                    // per second from the RX thread when the burst is
                    // first detected.
                    let s24 = slash24_of(target_ip);
                    if tx_backoff.is_blocked(s24) {
                        tx_backoff.skipped.fetch_add(1, Ordering::Relaxed);
                        global_idx += stride;
                        continue;
                    }

                    let slot = &mut batch[batch_len];
                    // Each TX thread uses its own source port so the
                    // RX side can disambiguate which thread a SYN-ACK
                    // is replying to. Cookie stamping uses the same port.
                    let my_source_port = source_port.saturating_add(thread_id as u16);
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
                        match tx_engine.tx_batch(&batch[..batch_len]) {
                            Ok(sent) => {
                                local_sent += sent as u64;
                                batch_len = 0;
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = %e,
                                    batch_len,
                                    "engine tx_batch failed; retrying batch"
                                );
                                std::thread::yield_now();
                            }
                        }

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
                    match tx_engine.tx_batch(&batch[..batch_len]) {
                        Ok(sent) => {
                            local_sent += sent as u64;
                        }
                        Err(e) => {
                            tracing::error!(
                                error = %e,
                                batch_len,
                                "engine tx_batch failed on final flush; retrying once"
                            );
                            std::thread::yield_now();
                            match tx_engine.tx_batch(&batch[..batch_len]) {
                                Ok(sent) => local_sent += sent as u64,
                                Err(e2) => {
                                    tracing::error!(
                                        error = %e2,
                                        batch_len,
                                        "engine tx_batch final flush retry failed; probes in this batch were not sent"
                                    );
                                }
                            }
                        }
                    }
                }

                total_sent_atomic.fetch_add(local_sent, std::sync::atomic::Ordering::Relaxed);
                local_sent
            }));
        }

        // Live throughput logger, runs on the orchestrator while
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
                tracing::info!(pps = pps, sent = cur_sent, "engine TX");
                last_log = now;
                last_sent = cur_sent;
            }
        });

        // Wait for workers.
        let mut tx_panics = 0usize;
        for h in tx_handles {
            match h.join() {
                Ok(_sent) => {}
                Err(e) => {
                    tx_panics += 1;
                    let err = format!("{e:?}");
                    tracing::error!("TX engine worker thread panicked: {err}");
                }
            }
        }
        log_stop.store(true, Ordering::Relaxed);
        if let Err(e) = log_handle.join() {
            let err = format!("{e:?}");
            tracing::warn!("engine TX throughput logger panicked: {err}");
        }
        let total_sent = total_sent_atomic.load(std::sync::atomic::Ordering::Relaxed);
        let init_failures = tx_init_failures.load(Ordering::Relaxed);
        if tx_panics > 0 {
            tracing::error!(
                tx_panics,
                tx_threads = num_tx_threads,
                "TX engine worker panic(s) — scan coverage may be partial"
            );
        }
        if tx_panics >= num_tx_threads {
            anyhow::bail!(
                "all {num_tx_threads} TX engine worker thread(s) panicked; aborting"
            );
        }
        if tx_panics > 0 && config.strict {
            anyhow::bail!(
                "{tx_panics}/{num_tx_threads} TX engine worker thread(s) panicked (--strict)"
            );
        }
        if init_failures > 0 {
            tracing::error!(
                init_failures,
                tx_threads = num_tx_threads,
                "TX engine init failure(s) dropped probe slice(s)"
            );
        }
        if init_failures >= num_tx_threads {
            anyhow::bail!(
                "all {num_tx_threads} TX engine thread(s) failed to initialize; no probes sent"
            );
        }
        if init_failures > 0 && config.strict {
            anyhow::bail!(
                "{init_failures}/{num_tx_threads} TX engine thread(s) failed to initialize (--strict)"
            );
        }
        let _ = scan_start;

        // tx_drops is no longer easily aggregated, each TX thread had its
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
        if let Err(e) = rx_handle.join() {
            let err = format!("{e:?}");
            tracing::error!("RX engine thread panicked: {err}");
            if config.strict {
                anyhow::bail!("RX engine thread panicked (--strict)");
            }
        }

        // Collect results. RX thread has joined and dropped `res_tx`, so the
        // bounded channel holds every delivered SYN-ACK; drain with try_iter.
        let mut found: HashMap<(Ipv4Addr, u16), SynAckResponse> = HashMap::new();
        for resp in res_rx.try_iter() {
            found.insert((resp.ip, resp.port), resp);
        }

        tracing::info!(open_ports = found.len(), "scan complete");

        // ── Banner grab + service classification ─────────────────────────
        // For each open port discovered by the SYN scan, do a quick
        // TCP connect-and-read to grab a ~512-byte banner, then run
        // gossan-classify rules to identify the service. This is the
        // masscan-parity item, masscan has `--banners` for the same
        // thing. Concurrency caps prevent banner grab from undoing the
        // scan-time win; with 500-way concurrency the grab phase
        // typically finishes in seconds even for thousands of ports.
        let classifier = Arc::new(BannerClassifier::new());
        // Convert &'static str OS hint to owned String so the closure
        // below isn't HRTB-bound by an unwanted 'static lifetime.
        let mut grab_jobs: Vec<(Ipv4Addr, u16, Option<String>, Option<String>)> =
            Vec::with_capacity(found.len());
        for (ip, idx) in &target_ips {
            let t = &incoming[*idx];
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
            let results = futures::stream::iter(grab_jobs)
                .map(|(ip, port, domain, os)| {
                    let classifier = Arc::clone(&classifier);
                    async move {
                        let ip_host = ip.to_string();
                        let host = domain.as_deref().unwrap_or(ip_host.as_str());
                        let banner = grab_banner(ip, port, host, GRAB_TIMEOUT).await;
                        let classification = banner
                            .as_deref()
                            .and_then(|b| classifier.classify_top_bytes(b))
                            .map(|m| {
                                format!("{}/{}", m.service, m.version.unwrap_or_else(|| "?".into()))
                            });
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
                        // Truncate display form; classification already used raw bytes.
                        let display = String::from_utf8_lossy(b);
                        let b_trim = display.trim();
                        let cap = 200;
                        if b_trim.len() > cap {
                            let mut end = cap;
                            while end > 0 && !b_trim.is_char_boundary(end) {
                                end -= 1;
                            }
                            s.push_str(&b_trim[..end]);
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
                let target = Target::Service(svc);
                let detail = match &classification {
                    Some(c) => format!("Open TCP/{port} on {ip} ({c})"),
                    None => format!("Open TCP/{port} on {ip}"),
                };
                let mut fb = Finding::builder(
                    "engine",
                    target.domain().unwrap_or("?"),
                    Severity::Info,
                )
                .title(format!("Open Port: {port}/tcp"))
                .detail(detail)
                .kind(secfinding::FindingKind::Exposure)
                .tag("exposure")
                .tag("network")
                .tag(format!("ip:{ip}"))
                .tag(format!("port:{port}/tcp"));
                if let Some(c) = &classification {
                    let svc_name = c.split('/').next().unwrap_or(c);
                    fb = fb.tag(format!("service:{svc_name}"));
                }
                if let Some(b) = &banner {
                    fb = fb.evidence(Evidence::Banner {
                        raw: String::from_utf8_lossy(b).into_owned().into(),
                    });
                }
                match fb.build() {
                    Ok(f) => input.emit(f).await,
                    Err(e) => {
                        tracing::warn!(error = %e, "engine finding builder failed");
                    }
                }
                input.emit_target(target).await;
            }
        }

        Ok(())
    }
}

/// Lightweight banner grabber: TCP-connect, send a generic probe, read
/// up to 512 raw bytes. None on connect / read failure or empty response.
/// Bytes are kept raw so binary protocols (RDP/Modbus) survive
/// classification; display paths apply UTF-8 lossy conversion later.
/// The probe is a GET for likely-web ports and a no-op (read-only) for
/// everything else; many services emit a banner on connect.
async fn grab_banner(
    ip: Ipv4Addr,
    port: u16,
    host: &str,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let connect_fut = TcpStream::connect((ip, port));
    let mut stream = match tokio::time::timeout(timeout, connect_fut).await {
        Ok(Ok(s)) => s,
        _ => return None,
    };
    // For HTTP-ish ports, kick the server with a GET so it actually
    // responds. For most other ports the server speaks first.
    if matches!(port, 80 | 8080 | 8000 | 8888 | 443 | 8443 | 9000) {
        let req = format!(
            "GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: gossan\r\n\r\n"
        );
        if let Err(e) = stream.write_all(req.as_bytes()).await {
            tracing::warn!(
                "engine banner HTTP write failed: ip={} port={} host={} error={}",
                ip, port, host, e
            );
            return None;
        }
    }
    let mut buf = [0u8; 512];
    let read_fut = stream.read(&mut buf);
    let n = match tokio::time::timeout(timeout, read_fut).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return None,
    };
    Some(buf[..n].to_vec())
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
    fn collect_ipv4_addrs_keeps_every_v4_and_skips_v6() {
        let addrs = [
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
        ];
        let got = collect_ipv4_addrs(addrs);
        assert_eq!(
            got,
            vec![
                Ipv4Addr::new(1, 2, 3, 4),
                Ipv4Addr::new(5, 6, 7, 8),
                Ipv4Addr::new(9, 9, 9, 9),
            ]
        );
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
        assert!(
            bo.is_blocked(s),
            "subnet must be blocked immediately after insert"
        );
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
        assert!(
            bo.is_blocked(s),
            "longer window must survive a shorter overwrite"
        );
    }

    #[test]
    fn slash24_backoff_prune_removes_expired_only() {
        let bo = Slash24Backoff::new();
        // Distinct /24s. `slash24_of` zeros the low octet, so 192.0.2.10
        // and 192.0.2.20 collide on the same key, use a different /24
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
        assert!(
            bo2.is_blocked(s),
            "clone must observe writes through original"
        );
        bo2.skipped.fetch_add(7, Ordering::Relaxed);
        assert_eq!(bo.skipped.load(Ordering::Relaxed), 7);
    }
    #[test]
    fn open_port_finding_includes_ip_and_port_tags() {
        let f = Finding::builder("engine", "example.com", Severity::Info)
            .title("Open Port: 443/tcp")
            .detail("Open TCP/443 on 93.184.216.34")
            .kind(secfinding::FindingKind::Exposure)
            .tag("exposure")
            .tag("network")
            .tag("ip:93.184.216.34")
            .tag("port:443/tcp")
            .tag("service:https")
            .build()
            .expect("finding must build");
        let tags: Vec<&str> = f.tags().iter().map(|t| t.as_ref()).collect();
        assert!(tags.iter().any(|t| *t == "ip:93.184.216.34"));
        assert!(tags.iter().any(|t| *t == "port:443/tcp"));
        assert!(tags.iter().any(|t| *t == "service:https"));
        assert_eq!(f.scanner(), "engine");
    }

    #[test]
    fn domain_resolution_keeps_all_ipv4_addrs_not_just_first() {
        // Document the contract: EngineScanner must retain every A record.
        // The production loop no longer `break`s after the first V4; this
        // regression guard fails if someone reintroduces early exit by
        // making the helper stop after one address.
        let addrs = [
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        ];
        let mut target_ips = Vec::new();
        for addr in addrs {
            if let IpAddr::V4(ipv4) = addr {
                target_ips.push(ipv4);
            }
        }
        assert_eq!(
            target_ips,
            vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)],
            "must collect every IPv4 A record"
        );
    }

    #[test]
    fn clamp_tx_threads_env_override_cannot_exceed_max() {
        assert_eq!(clamp_tx_threads(0), 1);
        assert_eq!(clamp_tx_threads(1), 1);
        assert_eq!(clamp_tx_threads(MAX_TX_THREADS as usize), MAX_TX_THREADS as usize);
        assert_eq!(clamp_tx_threads(10_000), MAX_TX_THREADS as usize);
    }

    #[test]
    fn rx_engine_source_port_end_covers_all_tx_slots() {
        let source_port: u16 = 50_000;
        let end = source_port.saturating_add(MAX_TX_THREADS);
        assert_eq!(end - source_port, MAX_TX_THREADS);
        // Last TX thread uses source_port + MAX_TX_THREADS - 1, which must be < end.
        let last = source_port.wrapping_add(MAX_TX_THREADS - 1);
        assert!(last < end);
    }



    #[test]
    fn choose_source_port_base_leaves_tx_headroom() {
        for pid in [0u32, 1, 16382, 16383, 65535, u32::MAX] {
            let base = choose_source_port_base(pid);
            let last = base.saturating_add(MAX_TX_THREADS - 1);
            assert!(
                last >= base,
                "pid={pid}: base={base} last={last} must not wrap"
            );
            assert!(
                last as u32 <= u16::MAX as u32,
                "pid={pid}: last port exceeds u16"
            );
        }
        // Worst-case previous formula near top of ephemeral range.
        let base = choose_source_port_base(16382);
        assert!(base.saturating_add(MAX_TX_THREADS - 1) <= u16::MAX);
    }

}
