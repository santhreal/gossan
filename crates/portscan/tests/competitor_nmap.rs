//! Competitor benchmark — gossan-portscan vs nmap on a controlled
//! localhost fixture.
//!
//! We bind 10 ephemeral TCP listeners on 127.0.0.1, each spawning a
//! cheap accept-and-close loop so banner-grab doesn't hang on the
//! 5s deadline. We then run gossan-portscan against the bound port
//! range, then nmap, and compare findings + wall time.
//!
//! gossan emits open ports through `target_tx` as `Target::Service`,
//! not through the `live_tx` Finding channel — counting from the wrong
//! channel will silently report 0 findings even when every port is
//! detected. This bench counts `Target::Service` events directly.

use gossan_core::{
    target::{HostTarget, ServiceTarget},
    Config, ScanInput, Scanner, Target,
};
use gossan_portscan::PortScanner;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;

const NUM_PORTS: usize = 10;

fn spawn_listeners() -> (Vec<u16>, Arc<std::sync::atomic::AtomicBool>) {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut ports = Vec::with_capacity(NUM_PORTS);
    for _ in 0..NUM_PORTS {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind");
        l.set_nonblocking(true).expect("nonblocking");
        ports.push(l.local_addr().unwrap().port());
        let stop_ = Arc::clone(&stop);
        std::thread::spawn(move || {
            // Accept-and-drop loop. Drops the inbound stream
            // immediately so probe.banner_grab gets EOF rather than
            // hanging on the 5s deadline.
            while !stop_.load(std::sync::atomic::Ordering::Relaxed) {
                match l.accept() {
                    Ok((stream, _)) => {
                        // Send a recognisable banner then drop, so
                        // gossan + nmap both classify it the same way.
                        use std::io::Write;
                        let mut s = stream;
                        let _ = s.write_all(b"BENCH/1.0 ready\r\n");
                        drop(s);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
    }
    (ports, stop)
}

fn nmap_present() -> bool {
    Command::new("which")
        .arg("nmap")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_nmap(ports: &[u16]) -> (usize, u128) {
    let port_arg = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let t0 = Instant::now();
    let out = Command::new("nmap")
        .args(["-sT", "-p", &port_arg, "-Pn", "-T4", "--open", "127.0.0.1"])
        .output()
        .expect("run nmap");
    let elapsed = t0.elapsed().as_micros();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let count = stdout.lines().filter(|l| l.contains("/tcp open")).count();
    (count, elapsed)
}

async fn run_gossan_portscan(ports: Vec<u16>) -> (usize, u128) {
    let (live_tx, _live_rx) = mpsc::unbounded_channel();
    let (target_tx, mut target_rx) = mpsc::unbounded_channel();
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let resolver = Arc::new(TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    ));
    in_tx
        .send(Target::Host(HostTarget {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            domain: None,
        }))
        .unwrap();
    drop(in_tx);

    let input = ScanInput {
        seed: "127.0.0.1".into(),
        target_rx: tokio::sync::Mutex::new(in_rx),
        live_tx,
        target_tx,
        resolver,
    };
    let mut config = Config::default();
    config.timeout_secs = 2;
    config.port_mode = gossan_core::config::PortMode::Custom(ports);

    let scanner = PortScanner;
    let t0 = Instant::now();
    scanner.run(input, &config).await.expect("scan");
    let elapsed = t0.elapsed().as_micros();
    let mut services = 0;
    while let Ok(t) = target_rx.try_recv() {
        if matches!(t, Target::Service(ServiceTarget { .. })) {
            services += 1;
        }
    }
    (services, elapsed)
}

#[tokio::test]
async fn portscan_finds_all_ten_listeners() {
    let (ports, stop) = spawn_listeners();
    let (n, us) = run_gossan_portscan(ports).await;
    println!("gossan-portscan: services={n} time={}ms", us / 1000);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    assert!(
        n >= NUM_PORTS,
        "expected >= {NUM_PORTS} open ports, got {n}"
    );
}

#[tokio::test]
async fn portscan_versus_nmap() {
    if !nmap_present() {
        eprintln!("SKIP: nmap not installed");
        return;
    }
    let (ports, stop) = spawn_listeners();
    let (ours_n, ours_us) = run_gossan_portscan(ports.clone()).await;
    let (peer_n, peer_us) = run_nmap(&ports);
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    println!(
        "vs nmap -sT — ours: services={ours_n} time={}ms | nmap: open_ports={peer_n} time={}ms",
        ours_us / 1000,
        peer_us / 1000
    );
    assert_eq!(ours_n, NUM_PORTS, "gossan must find all {NUM_PORTS}");
    assert!(peer_n >= 1, "nmap must find at least 1 (sanity)");
}
