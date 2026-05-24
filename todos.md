# Gossan Improvement Todos  -  Discovered During Discourse Web Bounty

## Tech Stack Fingerprinting

- [ ] **False positive: "Server header leaks version info" when no version present**
  meta.discourse.org returns `server: nginx` with no version string. Gossan flagged this as "info" severity with detail "Server header may expose software version." The detection regex is too broad  -  it triggers on any `Server` header existence, not actual version leakage.
  Repro: `gossan tech meta.discourse.org`

- [ ] **Missed S3 static hosting on discourse.org**
  discourse.org returns `server: AmazonS3` and `x-amz-server-side-encryption: AES256`. Gossan fingerprinted it as "AWS ALB/CloudFront, JSON-LD, Plausible" but completely missed AmazonS3, which is the actual origin. The fingerprint database needs S3-specific rules.
  Repro: `gossan tech discourse.org`  -  compare response headers to output.

- [ ] **Missed application framework on meta.discourse.org**
  meta.discourse.org runs Discourse (Ruby on Rails + Ember.js). Gossan only identified `caddy, nginx, Plausible, JSON-LD`  -  all infrastructure/analytics, zero application-layer fingerprinting. Need Discourse/Rails/Ember.js signatures.
  Repro: `gossan tech meta.discourse.org`  -  response contains `x-discourse-route`, CSP nonce patterns, Ember meta tags.

- [ ] **Missing severity calibration for missing security headers**
  Missing COEP, CORP, Permissions-Policy are all flagged as "low" on a public forum site where they provide marginal security value. Gossan should contextually downscore headers that don't meaningfully reduce attack surface for the target type, or at minimum allow per-target severity overrides.

## Cloud Asset Discovery

- [ ] **Public bucket severity lacks nuance**
  GCS bucket `discourse-public` was flagged as "critical" but contains only 3 public image files. The tool should attempt a quick content-type/file-count assessment before assigning critical severity to a listable bucket. A bucket with 3 images != a bucket with database dumps.
  Repro: `gossan cloud discourse.org`  -  examine `discourse-public` finding.

## General

- [ ] **Subdomain enumeration is very slow**
  `gossan subdomain discourse.org` has been running for >10 minutes with zero output. Need progress indicators or faster data sources.

## Rate Limiting & Resilience

- [ ] **No automatic backoff on 429 responses**
  meta.discourse.org returns `429 Too Many Requests` with `retry-after` header. Gossan JS scan immediately failed with WARN logs but did not retry or respect `retry-after`. Hidden endpoint probe timed out after 2 minutes  -  likely because it was hammering against rate limits without backing off.
  Repro: Run `gossan js meta.discourse.org` or `gossan hidden meta.discourse.org`  -  both fail against Discourse's `ip_10_secs_limit`.

- [ ] **Hidden endpoint probe is unacceptably slow**
  `gossan hidden discourse.org` timed out after 120 seconds with zero output. Even against a static S3 site this should complete in <10s. Need timeout/benchmark on this module.

## Subdomain Enumeration

- [ ] **Subdomain enumeration timed out after 3 minutes with zero output**
  `gossan subdomain discourse.org` ran for 180 seconds and produced nothing before being killed. This is a major reliability issue. Need profiling on the CT/Wayback/RapidDNS/OTX data sources  -  one or more is hanging.
  Repro: `gossan subdomain discourse.org --format json --out subdomains.json`

## Broken / Missing Modules

- [ ] **`origin` subcommand documented but uncompiled**
  `gossan origin discourse.org` returns `Error: unknown or uncompiled module: origin`. The `origin` command is listed in `--help` but the module is not compiled into the release binary. Either remove it from help or compile it in.
  Repro: `gossan origin discourse.org`

- [ ] **`crawl` subcommand fails due to Chromium singleton lock**
  `gossan crawl try.discourse.org` fails with `Failed to create /tmp/chromiumoxide-runner/SingletonLock: File exists`. Gossan does not clean up stale Chromium profile locks between runs, making headless crawling unreliable after the first failure.
  Repro: Run `gossan crawl` twice, or after any unclean Chromium shutdown.

- [ ] **`scm` subcommand finds GitLab group but emits 0 projects**
  `gossan scm discourse` discovers GitLab group 475655 (`discourse`) but reports 0 emitted projects. The group exists and is public  -  either the API pagination is broken or the project filtering is too aggressive.
  Repro: `gossan scm discourse --format json`

## Port Scan

- [ ] **Port scan reports CloudFront IPs as "directly addressing" the target**
  `gossan ports discourse.org` reports open ports on `18.238.96.36`, which is an AWS CloudFront edge node, not the Discourse origin server. The tool should distinguish between CDN edge IPs and actual origin IPs, or at minimum flag that the resolved IP is a known CDN.
  Repro: `gossan ports discourse.org --ports top100`  -  resolves to CloudFront.

## More Broken Modules

- [ ] **`horizontal` subcommand returns empty results for well-known domain**
  `gossan horizontal discourse.org` completed instantly and produced `[]`. For a major domain like discourse.org, at minimum some ASN/BGP data or ownership correlation should exist. The module appears to be non-functional or requires undocumented API keys.
  Repro: `gossan horizontal discourse.org --format json`

- [ ] **`headless` subcommand fails with WebSocket deserialization error**
  After cleaning the Chromium singleton lock, `gossan headless try.discourse.org` fails with `Failed to deserialize WS response data did not match any variant of untagged enum Message`. This is a chromiumoxide compatibility issue with the system Chrome version. Headless rendering is completely non-functional.
  Repro: `gossan headless try.discourse.org --format json`

- [ ] **`probe-engine` reports `CAP_NET_RAW: ✗` but `engine` help doesn't mention root requirement**
  The raw SYN scanner requires `CAP_NET_RAW` (root) but this is not mentioned in `gossan engine --help`. Users will try to run it and get permission failures without understanding why.
  Repro: `gossan probe-engine` as non-root user.

- [ ] **`scan` (full pipeline) is extremely slow with no progress output**
  `gossan scan discourse.org` has been running for several minutes with zero output. Since it runs all modules in sequence, it's likely blocked on the same hanging modules (subdomain, hidden) that failed individually. The full scan should have module-level timeouts and progress indicators.
  Repro: `gossan scan discourse.org --format json --out scan.json`

- [ ] **`scan` (full pipeline) times out after 3 minutes with zero output**
  Confirmed: `gossan scan discourse.org` ran for 180 seconds and produced nothing before being killed. Since it runs all modules in sequence, it's blocked on the same broken/hanging modules (subdomain enumeration, hidden endpoint probe) that failed individually. A full pipeline scan should skip or timeout individual modules rather than letting them hang the entire run.
  Repro: `gossan scan discourse.org --format json --out scan.json`

- [ ] **`list-scans` produces no output and no guidance**
  `gossan list-scans` returns immediately with 0 bytes of output and exit code 0. It's unclear whether this means "no saved scans" or "feature not implemented." The command should print a human-readable message like "No checkpoint scans found in ~/.cache/gossan/scans/" or similar.
  Repro: `gossan list-scans`

## Input Validation

- [ ] **Empty target string returns `[]` instead of error**
  `gossan tech '' --format json` returns `[]` with exit code 0. An empty target is invalid input  -  the tool should reject it with a clear error rather than silently producing empty results.
  Repro: `gossan tech '' --format json`

- [ ] **Nonexistent domain returns `[]` instead of NXDOMAIN error**
  `gossan tech 'not-a-valid-domain-at-all-12345.xyz' --format json` returns `[]` with exit code 0. The domain does not resolve. Gossan should report a DNS resolution failure rather than pretending the domain exists but has no tech stack.
  Repro: `gossan tech 'not-a-valid-domain-at-all-12345.xyz' --format json`

- [ ] **IP target returns `[]` with no validation of private/reserved ranges**
  `gossan tech '192.168.1.1' --format json` returns `[]` with exit code 0. Private/reserved IPs should either be rejected or handled with a warning, not silently scanned. Users might accidentally scan internal infrastructure without realizing it.
  Repro: `gossan tech '192.168.1.1' --format json`

- [ ] **Completely invalid IP returns `[]` instead of parse error**
  `gossan tech '256.256.256.256' --format json` returns `[]` with exit code 0. `256.256.256.256` is not a valid IPv4 address. The tool should validate IP format before attempting to scan.
  Repro: `gossan tech '256.256.256.256' --format json`

- [ ] **`include-kind` filter returns empty because tech findings have kind "Unclassified"**
  `gossan tech discourse.org --include-kind vulnerability --format json` returns `[]` because all tech stack findings are tagged as kind "Unclassified" or "Exposure", never "vulnerability". Missing security headers and tech fingerprints should arguably be "misconfiguration" or "information-disclosure" at minimum. The kind taxonomy is not applied consistently.
  Repro: `gossan tech discourse.org --include-kind vulnerability --format json`

- [ ] **Invalid proxy returns `[]` instead of connection error**
  `gossan tech discourse.org --proxy 'http://0.0.0.0:1' --format json` returns `[]` with exit code 0. The proxy is completely unreachable. The tool should report a proxy connection failure, not silently produce empty results.
  Repro: `gossan tech discourse.org --proxy 'http://0.0.0.0:1' --format json`

- [ ] **Only single target supported but error message is generic**
  `gossan tech discourse.org meta.discourse.org --format json` fails with `unexpected argument 'meta.discourse.org' found`. The error is technically correct but unhelpful  -  it should say "only one target is supported" or accept multiple targets.
  Repro: `gossan tech discourse.org meta.discourse.org --format json`

- [ ] **Log lines prefixed to JSON output make it invalid JSON**
  `gossan ports discourse.org --ports '80,443,8080-8090' --format json --out ports.json` writes a log line (`2026-05-18T01:09:49.099412Z INFO port scan complete open=2`) before the JSON array. This makes the output file invalid JSON  -  `jq` cannot parse it. When `--format json` and `--out` are both set, logs should go to stderr, not the output file.
  Repro: `gossan ports discourse.org --ports '80,443' --format json --out ports.json` then `jq '.' ports.json` → parse error.

- [ ] **CIDR notation returns `[]` instead of error or expanded scan**
  `gossan tech '10.0.0.0/8' --format json` returns `[]` with exit code 0. CIDR notation is not supported but is not rejected either. The tool should either expand the CIDR and scan each IP, or reject it with a clear error.
  Repro: `gossan tech '10.0.0.0/8' --format json`

- [ ] **Invalid DNS resolver silently falls back to system default**
  `gossan tech discourse.org --resolvers '256.256.256.256' --format json` ignores the invalid resolver and uses the system resolver instead. No warning is emitted. Users may think they're using a custom resolver when they're not.
  Repro: `gossan tech discourse.org --resolvers '256.256.256.256' --format json`

- [ ] **`nmap-xml` and `masscan-grep` output formats produce empty files for non-port-scan modules**
  `gossan tech discourse.org --format nmap-xml` produces a file with only `<nmaprun scanner="gossan" args="gossan" version="1"></nmaprun>` and zero host entries. `masscan-grep` produces only a comment line. These formats are designed for port scan output but are advertised as global format options. When used with `tech`, `dns`, etc., they should either be rejected or produce meaningful data.
  Repro: `gossan tech discourse.org --format nmap-xml --out tech.xml`
