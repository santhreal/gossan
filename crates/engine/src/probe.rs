//! Runtime probe for the available packet I/O backend.
//!
//! `gossan-engine` always falls back to a slower backend when the
//! preferred one is unavailable, but the user often needs to *know*
//! which backend will run before they kick off a scan. This module
//! exposes a deterministic, side-effect-free probe that surfaces:
//!
//! * compiled-in feature set (xdp, sendmmsg, pnet)
//! * Linux kernel version (for the AF_XDP `>= 5.10` gate)
//! * effective capabilities (CAP_BPF, CAP_NET_RAW)
//! * libbpf availability
//!
//! Surface this from the CLI as `gossan probe-engine`. Surface it
//! from a test harness to assert that benchmarks actually ran on the
//! backend they claim to compare against masscan.

use std::fmt;

/// Concrete backend selected by [`netforge::engine::auto_select`] at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// AF_XDP zero-copy via `xsk-rs` (Linux 5.10+, CAP_BPF).
    Xdp,
    /// Batched `sendmmsg(2)` raw sockets (Linux, CAP_NET_RAW).
    Sendmmsg,
    /// libpnet datalink (portable, slower).
    Pnet,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Backend::Xdp => "xdp",
            Backend::Sendmmsg => "sendmmsg",
            Backend::Pnet => "pnet",
        })
    }
}

/// Result of probing the runtime for backend availability.
///
/// Each field is independently testable so a CLI / test can show a
/// clear go / no-go matrix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// XDP feature compiled into this build.
    pub xdp_compiled: bool,
    /// sendmmsg feature compiled into this build.
    pub sendmmsg_compiled: bool,
    /// pnet feature compiled into this build.
    pub pnet_compiled: bool,
    /// Detected kernel version, if Linux. (major, minor) — patch is dropped.
    pub kernel: Option<(u32, u32)>,
    /// Process holds CAP_NET_RAW (best-effort: euid==0 is the proxy).
    pub cap_net_raw: bool,
    /// Best-effort probe for libbpf availability (file present).
    pub libbpf_present: bool,
    /// Backend [`netforge::engine::auto_select`] would pick *now*.
    pub selected: Backend,
}

impl ProbeReport {
    /// Render a multi-line table for human consumption (CLI output).
    pub fn render_table(&self) -> String {
        let yes = "✓";
        let no = "✗";
        let yn = |b: bool| if b { yes } else { no };
        let kernel = self
            .kernel
            .map(|(maj, min)| format!("{maj}.{min}"))
            .unwrap_or_else(|| "n/a".to_string());
        format!(
            concat!(
                "engine probe:\n",
                "  selected backend: {selected}\n",
                "  kernel:           {kernel}\n",
                "  CAP_NET_RAW:      {cnr}\n",
                "  libbpf present:   {bpf}\n",
                "  features:         xdp={xdp} sendmmsg={smm} pnet={pnet}\n",
            ),
            selected = self.selected,
            kernel = kernel,
            cnr = yn(self.cap_net_raw),
            bpf = yn(self.libbpf_present),
            xdp = yn(self.xdp_compiled),
            smm = yn(self.sendmmsg_compiled),
            pnet = yn(self.pnet_compiled),
        )
    }
}

fn detect_kernel() -> Option<(u32, u32)> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let raw = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let head = raw.trim().split('-').next()?;
    let mut parts = head.split('.');
    let maj: u32 = parts.next()?.parse().ok()?;
    let min: u32 = parts.next()?.parse().ok()?;
    Some((maj, min))
}

fn detect_cap_net_raw() -> bool {
    // Best-effort proxy: euid==0 implies CAP_NET_RAW unless explicitly
    // dropped. A more precise probe would parse /proc/self/status's
    // CapEff bitmap, but euid==0 is the dominant production case.
    #[cfg(target_os = "linux")]
    unsafe {
        libc::geteuid() == 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

fn detect_libbpf() -> bool {
    // libbpf is dynamically linked from xsk-rs. The library is named
    // libbpf.so.1 on most distros and libbpf.so.0 on older ones.
    for path in [
        "/usr/lib/x86_64-linux-gnu/libbpf.so.1",
        "/usr/lib/x86_64-linux-gnu/libbpf.so.0",
        "/usr/lib64/libbpf.so.1",
        "/usr/lib64/libbpf.so.0",
    ] {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }
    false
}

/// Capture the engine selection logic in pure data: which backend
/// would `auto_select` pick on this build, on this host, right now?
///
/// This intentionally mirrors `netforge::engine::auto_select`'s order:
/// XDP > sendmmsg > pnet. We do NOT actually open a raw socket — that
/// would change behavior for callers (e.g. depleting a syscall slot).
pub fn probe() -> ProbeReport {
    let xdp_compiled = cfg!(feature = "xdp");
    // netforge ships sendmmsg + pnet by default on linux.
    let sendmmsg_compiled = cfg!(target_os = "linux");
    let pnet_compiled = true;

    let kernel = detect_kernel();
    let cap_net_raw = detect_cap_net_raw();
    let libbpf_present = detect_libbpf();

    // Selection mirror — must stay in lockstep with netforge auto_select.
    let xdp_runnable = xdp_compiled
        && cap_net_raw
        && libbpf_present
        && kernel.map_or(false, |(maj, min)| maj > 5 || (maj == 5 && min >= 10));
    let sendmmsg_runnable = sendmmsg_compiled && cap_net_raw;

    let selected = if xdp_runnable {
        Backend::Xdp
    } else if sendmmsg_runnable {
        Backend::Sendmmsg
    } else {
        Backend::Pnet
    };

    ProbeReport {
        xdp_compiled,
        sendmmsg_compiled,
        pnet_compiled,
        kernel,
        cap_net_raw,
        libbpf_present,
        selected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic() {
        let _ = probe();
    }

    #[test]
    fn render_table_contains_all_rows() {
        let r = probe();
        let s = r.render_table();
        for needle in [
            "selected backend",
            "kernel",
            "CAP_NET_RAW",
            "libbpf present",
            "features",
        ] {
            assert!(s.contains(needle), "table missing row `{needle}`: {s}");
        }
    }

    #[test]
    fn unprivileged_never_picks_xdp() {
        // We can't actually drop CAP_BPF inside the test runner; this
        // case is the production reality (CI is non-root). XDP must
        // require both compile-in AND CAP_NET_RAW.
        let r = probe();
        if !r.cap_net_raw {
            assert_ne!(r.selected, Backend::Xdp);
        }
    }

    #[test]
    fn pnet_is_the_universal_fallback() {
        let r = probe();
        if !r.cap_net_raw {
            assert_eq!(r.selected, Backend::Pnet);
        }
    }

    #[test]
    fn selected_backend_displays_lowercase() {
        assert_eq!(format!("{}", Backend::Xdp), "xdp");
        assert_eq!(format!("{}", Backend::Sendmmsg), "sendmmsg");
        assert_eq!(format!("{}", Backend::Pnet), "pnet");
    }

    #[test]
    fn kernel_parsing_handles_release_strings() {
        // We can't override /proc/sys/kernel/osrelease, so we exercise
        // the public surface. The probe must yield Some on Linux and
        // None elsewhere.
        let r = probe();
        if cfg!(target_os = "linux") {
            assert!(r.kernel.is_some(), "kernel must parse on linux");
        } else {
            assert!(r.kernel.is_none(), "kernel must be None off linux");
        }
    }
}
