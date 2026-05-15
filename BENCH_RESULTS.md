# Competitor Benchmark Results

Real, reproducible numbers from the local gossan competitor benchmarks
(`crates/*/tests/competitor_*.rs`). Methodology is documented inline
in each test file. Re-run with:

```sh
cargo test --workspace --tests 'competitor_*' -- --nocapture
```

## Secret Scanning — gossan-keyhog-lite vs trufflehog vs gitleaks

Corpus: `crates/keyhog-lite/tests/competitor_corpus/known_secrets.txt`
(13 known fake secrets covering AWS, GitHub, Slack, Stripe, SendGrid,
Google Cloud, Twilio, Discord, Mailgun, JWT, RSA private key marker).

| Scanner            | Findings | Wall time |
|--------------------|----------|-----------|
| gossan-keyhog-lite | **12**   | **9–21 ms** |
| gitleaks 8.30.0    | 3        | 476 ms |
| trufflehog 3.95.2  | 5        | 2 462 ms |

gossan finds **4× more secrets** than gitleaks and **2.4× more** than
trufflehog. Speed: **22× faster than gitleaks**, **117× faster than
trufflehog** on the same corpus. trufflehog spawns a Go binary per
invocation (cold-start overhead) and gitleaks loads its full rule TOML
on every run; gossan-keyhog-lite is an in-process call with the
pre-compiled aho-corasick prefilter and detector regex set.

## Port Scanning — gossan-portscan vs nmap

Corpus: 10 ephemeral TCP listeners on `127.0.0.1` (each spawns an
accept-and-close loop with a `BENCH/1.0 ready\r\n` banner so both
scanners hit the same code path).

| Scanner                | Open ports found | Wall time |
|------------------------|------------------|-----------|
| gossan-portscan (TCP)  | **10 / 10**      | 278 ms |
| nmap 7.94 SVN (`-sT`)  | 10 / 10          | **64 ms** |

Both find every port. nmap is **4.3× faster** on this 10-port
localhost run because gossan's TCP-connect path also runs banner-grab
+ service-classify on each open port; nmap `-sT` only probes
liveness. The fair comparison for raw scan throughput is gossan-engine
(SYN scanner) vs masscan/zmap; that bench requires `CAP_NET_RAW` and
runs under `tests/realnet_*.rs (#[ignore])`.

## Pending — peer not installed locally

| Crate              | Peer(s)                   | Status |
|--------------------|---------------------------|--------|
| gossan-subdomain   | amass, subfinder          | Skip — neither installed; see `crates/subdomain/tests/competitor_skip.rs` for install hints |
| gossan-hidden      | nuclei                    | Skip — not installed; install via `go install ... nuclei@latest` |
| gossan-techstack   | projectdiscovery/httpx, webanalyze | Skip — python httpx in PATH is the wrong binary; pd httpx must be at `~/go/bin/httpx` |
| gossan-dns         | dnsx, massdns             | Skip — neither installed |
| gossan-engine      | masscan, zmap             | Skip — `#[ignore]` until run as root |

Each of those bench files is wired and will run on a host with the
peer installed; the install hint is printed when the test skips.

## Reproduction

All bench tests except the engine SYN benches run unprivileged. From
the repo root:

```sh
# Fast subset (no privilege, no peer install required):
cargo test -p gossan-keyhog-lite --test competitor_secrets -- --nocapture
cargo test -p gossan-portscan    --test competitor_nmap    -- --nocapture

# Probe everything else (each prints SKIP + install hint when peer is missing):
cargo test -p gossan-subdomain --test competitor_skip     -- --nocapture
cargo test -p gossan-hidden    --test competitor_nuclei   -- --nocapture
cargo test -p gossan-techstack --test competitor_httpx    -- --nocapture
cargo test -p gossan-dns       --test competitor_dnsx     -- --nocapture
```
