# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in **gossan**, please report
it privately. **Do not** open a public GitHub issue for vulnerabilities.

### How to report

1. Email **security@santhsecurity.com** with subject
   `gossan: <one-line description>`.
2. Or open a private GitHub Security Advisory at
   https://github.com/santhsecurity/gossan/security/advisories/new.

Please include:

- Affected version (`gossan --version`)
- Steps to reproduce, with a minimal repro (URL / config / inputs)
- Impact assessment (confidentiality / integrity / availability)
- Any suggested mitigations

We aim to acknowledge within 72 hours and to ship a fix or detailed
status update within 14 days.

## What we consider in-scope

- **Code execution / sandbox escape** in any gossan subcommand.
- **Memory safety** issues in the engine TX/RX hot path or in any
  parser (banner, TLS cert, source map, JS, etc.).
- **Credential / PII leakage** through findings, logs, output files,
  or telemetry. (Telemetry is not a thing in gossan; we mention it
  defensively.)
- **Supply-chain compromise** of any directly vendored crate
  (`crates/keyhog-lite/` is the only one currently vendored).
- **Path traversal / arbitrary file write** via output paths,
  checkpoint paths, or rule-file paths *when the gossan process is
  running with elevated privileges* (engine SYN scan needs CAP_NET_RAW).
- **DoS amplification** in any scanner stage that takes user input.

## What we consider out-of-scope

- Findings against the **target** of a scan — gossan is the tool;
  vulnerabilities the tool finds in scanned hosts belong to those
  hosts' security teams, not gossan's.
- "It scans noisy / it triggers WAF / it gets blocked" — gossan is
  an authorized-target scanner. Throttling / blocking is the
  defender's job.
- Paths the user supplies via `--out` / `--checkpoint` / `--wordlist`:
  the user is the authoritative actor on their own filesystem.

## Embargo

For high-severity issues (RCE, sandbox escape, mass credential
disclosure) we coordinate disclosure with the reporter and request
a 90-day embargo from initial report. For lower-severity issues
we typically publish the fix and advisory together.

## Hall of fame

Reported and acknowledged vulnerabilities are credited in
[`CHANGELOG.md`](CHANGELOG.md) under the release that contains the
fix.
