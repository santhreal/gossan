//! Throughput benchmark for the stateless SYN engine (`#392`).
//!
//! Three layers, deliberately separated so each reports an *honest*
//! number for what it actually measured:
//!
//! 1. [`stateless_engine_software_ceiling`]  -  **runs anywhere, no
//!    privilege.** Drives the real engine (blackrock permute → cookie
//!    ISN → IPv4/TCP SYN build → classify loop) through a discarding
//!    transport. This is the pure-logic ceiling: the NIC can never emit
//!    faster than the engine can *produce* packets, so this is a hard
//!    upper bound on achievable wire pps and a regression gate on the
//!    encode path. No syscalls, so it is not the wire number  -  it is
//!    labelled as such and never compared to masscan.
//!
//! 2. [`stateless_engine_loopback_wire`]  -  `#[ignore]`, needs
//!    `CAP_NET_RAW`. Exercises the *full* syscall path
//!    (`RawSynTransport` → kernel → loopback). Without the capability
//!    it prints a loud SKIP and returns  -  it never silently "passes"
//!    pretending the fast path ran (anti-rigging).
//!
//! 3. [`stateless_vs_masscan`]  -  `#[ignore]`, needs `CAP_NET_RAW`.
//!    Head-to-head against the real `masscan` binary on an identical
//!    loopback workload. If `masscan` is not installed it prints the
//!    exact reproduction commands and refuses to invent a baseline.
//!
//! # Running the privileged layers
//!
//! ```text
//! sudo -E env "PATH=$PATH" cargo test -p gossan-portscan \
//!     --test stateless_bench --release -- --ignored --nocapture
//! ```
//!
//! or, non-root with file capabilities (the recommended deployment):
//!
//! ```text
//! setcap cap_net_raw+ep "$(command -v cargo)"   # or the test binary
//! cargo test -p gossan-portscan --test stateless_bench --release \
//!     -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

use gossan_portscan::stateless::cookie::SynCookie;
use gossan_portscan::stateless::transport::{linux, local_source_ipv4, run_blocking};
use gossan_portscan::stateless::{StatelessScanner, SynTransport};

/// Discards every SYN and never replies. Isolates pure engine cost
/// (permute + cookie + packet build) from any I/O.
struct NullTransport {
    sent: u64,
}

impl SynTransport for NullTransport {
    fn send(&mut self, _dst: SocketAddrV4, _ip_tcp: &[u8]) -> std::io::Result<()> {
        self.sent += 1;
        Ok(())
    }
    fn try_recv(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

fn synthetic_ips(n: u32) -> Vec<Ipv4Addr> {
    // 10.x.y.z space  -  never routed, irrelevant here (NullTransport
    // discards), but keeps the decode arithmetic realistic.
    (0..n)
        .map(|i| Ipv4Addr::new(10, (i >> 8) as u8, (i & 0xff) as u8, 7))
        .collect()
}

#[test]
fn stateless_engine_software_ceiling() {
    // 2048 hosts × 1024 ports ≈ 2.1M probes  -  large enough that the
    // per-probe encode cost dominates loop/timer overhead.
    let ips = synthetic_ips(2048);
    let ports: Vec<u16> = (1..=1024).collect();
    let cookie = SynCookie::with_key([0x5a; 16]);
    let mut scanner = StatelessScanner::new(
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 9), 40_000),
        ips,
        ports,
        cookie,
        0x9e37_79b9,
    );
    let total = scanner.total();
    assert_eq!(total, 2048 * 1024, "domain size sanity");

    let mut transport = NullTransport { sent: 0 };
    let start = Instant::now();
    // pps = 0 (unlimited) and zero grace ⇒ no sleeping, pure throughput.
    run_blocking(&mut scanner, &mut transport, 0, Duration::ZERO).expect("run");
    let elapsed = start.elapsed();

    assert_eq!(
        transport.sent, total,
        "every probe must be produced exactly once"
    );
    let pps = (total as f64 / elapsed.as_secs_f64()) as u64;
    let mode = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    eprintln!(
        "stateless_engine_software_ceiling [{mode}]: {total} probes encoded \
         in {:?} => {pps} probes/s (PURE ENGINE, no NIC; upper bound on \
         wire pps)",
        elapsed
    );

    // Regression gate. The encode path is a handful of integer ops, a
    // keyed-cookie hash, and one 40-byte alloc per probe. The bound is
    // build-mode-aware: an unoptimised debug build runs ~20× slower, so
    // a flat release threshold would spuriously fail the default
    // `cargo test --workspace` (debug). Both bounds still catch a real
    // regression (heap blowup / O(n) rescan in `next_probe`)  -  debug
    // just has the looser, mode-appropriate floor.
    let floor = if cfg!(debug_assertions) {
        100_000
    } else {
        1_000_000
    };
    assert!(
        pps > floor,
        "software encode ceiling collapsed to {pps} probes/s ({mode}, \
         floor {floor})  -  the per-probe path regressed"
    );
}

#[test]
#[ignore = "requires CAP_NET_RAW; run manually with sudo/setcap"]
fn stateless_engine_loopback_wire() {
    if !linux::raw_available() {
        eprintln!(
            "SKIPPED stateless_engine_loopback_wire: CAP_NET_RAW unavailable. \
             This is NOT a pass  -  the wire path did not run. Re-run with:\n  \
             sudo -E env \"PATH=$PATH\" cargo test -p gossan-portscan \
             --test stateless_bench --release -- --ignored --nocapture"
        );
        return;
    }

    let dst = Ipv4Addr::LOCALHOST;
    let src_ip = local_source_ipv4(dst).unwrap_or(Ipv4Addr::LOCALHOST);
    let src = SocketAddrV4::new(src_ip, 54_321);
    let ports: Vec<u16> = (1..=10_000).collect();
    let cookie = SynCookie::random();
    let mut scanner = StatelessScanner::new(
        src,
        vec![dst],
        ports.clone(),
        cookie,
        0xdead_beef,
    );
    let total = scanner.total();

    let mut transport = linux::RawSynTransport::new().expect("raw transport (cap present)");
    let start = Instant::now();
    let outcomes = run_blocking(
        &mut scanner,
        &mut transport,
        0,
        Duration::from_millis(200),
    )
    .expect("wire run");
    let elapsed = start.elapsed();
    let pps = (total as f64 / elapsed.as_secs_f64()) as u64;

    eprintln!(
        "stateless_engine_loopback_wire: {total} SYNs to 127.0.0.1:1..=10000 \
         in {:?} => {pps} pps (FULL syscall path); {} outcomes classified",
        elapsed,
        outcomes.len()
    );
    // Loopback raw TX is syscall-bound but still far above the connect
    // scanner. A number this low means the raw socket path is broken.
    assert!(
        pps > 50_000,
        "loopback wire pps {pps} far below expectation  -  raw TX path broken"
    );
}

#[test]
#[ignore = "requires CAP_NET_RAW + masscan; run manually"]
fn stateless_vs_masscan() {
    use std::process::Command;

    let masscan = Command::new("sh")
        .arg("-c")
        .arg("command -v masscan")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());

    let Some(masscan_bin) = masscan else {
        eprintln!(
            "SKIPPED stateless_vs_masscan: `masscan` not on PATH. No baseline \
             will be fabricated. To run the head-to-head:\n  \
             sudo apt-get install -y masscan   # or: brew install masscan\n  \
             then re-run this test with --ignored.\n  \
             Reference masscan workload: \
             `masscan 127.0.0.1 -p1-65535 --rate 10000000 -oJ -`"
        );
        return;
    };

    if !linux::raw_available() {
        eprintln!(
            "SKIPPED stateless_vs_masscan: CAP_NET_RAW unavailable (masscan at \
             {masscan_bin} found, but neither engine can open a raw socket). \
             This is NOT a pass."
        );
        return;
    }

    let dst = Ipv4Addr::LOCALHOST;
    let src_ip = local_source_ipv4(dst).unwrap_or(Ipv4Addr::LOCALHOST);
    let src = SocketAddrV4::new(src_ip, 54_322);
    let ports: Vec<u16> = (1..=65_535).collect();
    let n_ports = ports.len() as u64;

    // --- gossan stateless engine ---
    let cookie = SynCookie::random();
    let mut scanner =
        StatelessScanner::new(src, vec![dst], ports, cookie, 0x1234_5678);
    let total = scanner.total();
    let mut transport = linux::RawSynTransport::new().expect("raw transport");
    let g_start = Instant::now();
    run_blocking(&mut scanner, &mut transport, 0, Duration::from_millis(200))
        .expect("gossan wire run");
    let g_elapsed = g_start.elapsed();
    let g_pps = (total as f64 / g_elapsed.as_secs_f64()) as u64;

    // --- masscan, identical workload ---
    let m_start = Instant::now();
    let m_out = Command::new(&masscan_bin)
        .args([
            "127.0.0.1",
            "-p1-65535",
            "--rate",
            "100000000",
            "-oJ",
            "-",
        ])
        .output()
        .expect("masscan run");
    let m_elapsed = m_start.elapsed();
    let m_pps = (n_ports as f64 / m_elapsed.as_secs_f64()) as u64;

    eprintln!(
        "stateless_vs_masscan (127.0.0.1, 65535 ports):\n  \
         gossan-stateless: {g_pps:>10} pps  ({:?})\n  \
         masscan         : {m_pps:>10} pps  ({:?})\n  \
         ratio (gossan/masscan): {:.2}x  [masscan stderr: {} bytes]",
        g_elapsed,
        m_elapsed,
        g_pps as f64 / m_pps.max(1) as f64,
        m_out.stderr.len(),
    );
    // No assertion on the ratio: this test *reports*, it does not gate
    // a hardware-dependent number. The win/lose verdict is the
    // operator's to read from the printed line.
}
