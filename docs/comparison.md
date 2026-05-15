# gossan vs The Field

What does gossan do that the standard recon stack doesn't, and
where does it concede ground.

## Quick comparison

| Capability                              | gossan | masscan | naabu | amass | nuclei | nmap |
|-----------------------------------------|:------:|:-------:|:-----:|:-----:|:------:|:----:|
| Subdomain discovery (CT + bruteforce)   | ✅     |         |   ✅  |   ✅  |        |      |
| Port scan (stateless SYN, ≥10 Mpps)     | ✅     |   ✅    |       |       |        |      |
| Port scan (TCP-connect, no privileges)  | ✅     |         |   ✅  |       |        |  ✅  |
| Banner grab + classify post-scan        | ✅     |   ✅    |   ⚠️ |       |        |  ✅  |
| TLS cert + cipher fingerprint           | ✅     |         |       |       |        |  ✅  |
| Tech-stack fingerprint (truestack)      | ✅     |         |       |       |   ⚠️  |      |
| DNS audit (SPF/DMARC/DKIM/CAA)          | ✅     |         |       |       |        |      |
| Hidden endpoint dirbust + CVE rules     | ✅     |         |       |       |   ✅   |      |
| JS analysis (endpoints + secrets)       | ✅     |         |       |       |        |      |
| Cloud asset discovery (S3/GCS/Azure)    | ✅     |         |       |       |        |      |
| Origin IP behind CDN/WAF                | ✅     |         |       |       |        |      |
| Source-control mapping (GitHub/GitLab)  | ✅     |         |       |       |        |      |
| Cross-module correlation                | ✅     |         |       |       |        |      |
| Distributed master/worker fleet         | ✅     |         |       |       |        |      |
| Resumable from checkpoint               | ✅     |   ✅    |       |       |        |      |
| Output: JSON                            | ✅     |   ✅    |   ✅  |   ✅  |   ✅   |  ✅  |
| Output: SARIF                           | ✅     |         |       |       |   ✅   |      |
| Output: masscan-grepable -oG            | ✅     |   ✅    |       |       |        |      |

## Speed

The masscan-class metric is "how many SYN probes can you push out
the NIC in 1 second".

| Tool       | 1-thread | 8-thread | NIC-bound? |
|------------|---------:|---------:|------------|
| gossan     |  17 Mpps | 96-110 Mpps | yes (10 GbE bound) |
| masscan    |  ~5 Mpps |  ~25 Mpps | yes |
| naabu      |  ~50 kpps | ~200 kpps | no (TCP-connect) |
| nmap       |   ~5 kpps |    ~5 kpps | no |

Numbers are with the counting-stub backend (no kernel); on a real
NIC both gossan and masscan top out at line rate. The
single-thread gap (17 → 5 Mpps) comes from gossan's stride-
partitioned Blackrock permutation + per-thread raw socket vs
masscan's single-socket TX loop.

## Where gossan concedes ground

- **OS fingerprint**: nmap's `-O` corpus (1500+ rules) is the gold
  standard. gossan ships a 4-rule TTL/window heuristic and pulls
  the rest from `truestack` + banner classification. nmap is
  better for OS detection alone.
- **Service-version DB**: nmap's `nmap-service-probes` has 1700+
  probes; gossan-portscan currently ships ~200 in
  `rules/service_probes.toml`. We're closing the gap, not closed.
- **TLS handshake intel**: testssl.sh runs hundreds of probes
  per host (cipher matrix, vuln-by-vuln). gossan's TLS path
  collects subject/SAN/cipher/version per host; depth comes after
  the engine fast path is complete.

## Scan a /16 in 30 seconds

```
sudo gossan engine 10.0.0.0/16 --rate 1000000
```

(The `engine` subcommand uses the netforge SYN engine. CAP_NET_RAW
required.)

## Scan a single domain end-to-end

```
gossan example.com --format json --out scan.json
```

Pipeline: subdomain → DNS audit → port scan → banner classify →
tech stack → JS secrets → hidden endpoints → cloud assets → cross-
module correlation. ~30 seconds for a typical SMB target.

## Hand off to other tools

- `gossan example.com --format masscan-grep | nmap -iL - -sV`
- `gossan example.com --format jsonl | jq '.title'`
- `gossan example.com --format sarif --out scan.sarif`  (then
  `sarif github upload-sarif scan.sarif`)
