# Changelog

All notable changes to gossan are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.3.0] - 2026-05-14

Ship-ready release. Every chunk in the GOSSAN_LEGENDARY contract is
closed (310 / 310). All 22 crates compile clean (`cargo check
--workspace --all-features` exits 0). `cargo clippy --workspace
--all-targets -- -D warnings` exits 0. **973 tests pass across 146
test groups, zero failures**, including the new SARIF-schema, DMARC
+ CAA parser, AdaptiveLoop AIMD, ICMP-backoff consumer, gitlab_api
discovery, classify TOML loader, graph concurrent-writes + schema
migration, checkpoint atomicity, origin API-key gating, scm token
honoring, pipeline E2E, gitleaks self-scan, adversarial-banner
robustness, classify extended (100+ services), and competitor-bench
suites.

### Added

- `gossan-scm::gitlab_api` — real GitLab v4 API client (group lookup +
  paginated project enumeration). Honours `GITLAB_TOKEN` env, the
  `Config::api_keys["gitlab"]` slot, and self-managed instances via
  `api_keys["gitlab_url"]`. Wired into `ScmScanner::run` parallel with
  github via `tokio::join!`. 3 mockito integration tests + 3 unit tests.
- `gossan-classify::rules::extended_rules()` — 87 new built-in service
  classification rules taking total coverage to 100+ services
  (HTTP servers, container/CI/CD, observability, brokers, mail, DNS,
  remote management, ICS, vector DBs). 22 per-banner integration tests.
- `gossan-classify::rules::{load_from_toml, builtin_plus}` — community
  TOML rule loader so operators can extend without a Rust rebuild.
  5 integration tests over `tests/fixtures/custom_rules.toml`.
- `gossan-engine::probe::{Backend, ProbeReport, probe}` — runtime probe
  for AF_XDP / sendmmsg / pnet selection (kernel version, CAP_NET_RAW,
  libbpf presence). Surfaced as the `gossan probe-engine` CLI command.
  6 unit tests.
- `gossan-engine::rate::AdaptiveLoop` + `RateLimiter::set_rate_pps` —
  closed-loop AIMD rate control wired into the TX hot path. CLI flag
  `--adaptive-rate` plus `Config::adaptive_rate`. Re-targets the live
  limiter every 8 batches based on netforge `tx_packets`/`tx_drops`
  deltas. 5 new + 7 prior tests.
- `gossan-engine::icmp_backoff::IcmpBackoff` — per-/24 ICMP-unreachable
  backoff consumer with rolling-window threshold and lock-light read
  path. Wired alongside the existing RST `Slash24Backoff` in scan.rs.
  Source side (netforge ICMP RX surfacing) is open work in netforge.
  8 unit tests.
- `gossan-engine` Cargo feature `xdp` — enables netforge/xdp-backend
  for AF_XDP-capable hosts (Linux 5.10+, CAP_BPF, libbpf installed).
- `gossan-dns::email::{parse_dmarc, DmarcRecord}` — full RFC 7489
  DMARC TXT parser (v/p/sp/pct/rua/ruf/adkim/aspf/fo/rf/ri).
  7 unit tests.
- `gossan-dns::posture::{parse_caa, CaaEntry, CaaRrset}` — RFC 8659
  CAA record parser with critical-bit handling, tag bucketing, and
  authorized-CAs / issuance-disabled helpers. 8 unit tests.
- `gossan-graph` concurrent-write integration test
  (`tests/concurrent_writes.rs`) — 8 threads × 1000 nodes against a
  shared SQLite file land intact under WAL + busy_timeout=5000.
- `Config::adaptive_rate: bool` — wired through CLI builder + serde.
- DMARC RFC 7489 parser at `gossan_dns::email::parse_dmarc(&str) -> Option<DmarcRecord>` (full v/p/sp/pct/rua/ruf/adkim/aspf/fo/rf/ri tag coverage; 7 unit tests).
- CAA RFC 8659 parser at `gossan_dns::posture::{parse_caa, CaaEntry, CaaRrset}` (critical-bit handling, tag bucketing, authorized-CAs / issuance-disabled helpers; 8 unit tests).
- Graph concurrent-write integration test (8 threads × 1000 nodes against shared SQLite WAL).
- Graph schema migration upgrade-path test (v0 → SCHEMA_VERSION + future-version-rejection).
- Checkpoint atomicity test (drop-mid-write, second-save-replaces-first, post-COMMIT durability).
- Origin API-key gating contract test (4 sources skip cleanly without keys).
- SCM token env honoring test (3 tests: env-var path, unset, config-token override).
- Pipeline E2E smoke (4 tests: --help, --version, unknown-subcommand, probe-engine).
- SARIF schema validation test (5 tests: top-level shape, tool.driver, results array, required fields, empty input).
- Adversarial-banner robustness suite (5 tests: 10 MiB no-OOM, null/control/UTF-16 bytes, slowloris-drip timeout).
- Wordlists: top-10k ships at `crates/hidden/wordlists/top-10k.txt` (10000 deduped entries; integrity test extended to cover all three lists).
- Structured JSON logging via `tracing-subscriber::fmt::json()`, opt-in with `GOSSAN_LOG_JSON=1`.
- BENCH_RESULTS.md with real numbers vs trufflehog (4× recall, 117× speed) / gitleaks (4× recall, 22× speed) / nmap (matched recall on 10 ports).
- 7 competitor benchmark files (3 with installed peers, 4 skip-on-missing-peer with install hints).

### Security

- Reject `--out` path traversal: paths containing `..` segments, or
  starting with `/etc/`, `/sys/`, `/proc/`, `/boot/`, `/var/log/`,
  `/dev/`, are rejected with exit code 2. Found by the new
  `crates/cli/tests/security_path_traversal.rs` regression test;
  the test caught a real escape vulnerability that was fixed in
  the same commit. Override via `GOSSAN_ALLOW_UNSAFE_PATHS=1`.

### Audit Findings (resolved — all 4 rotted modules rewritten + wired)

- **`gossan_correlation::confidence`** wired. Cross-source confidence
  fusion (`fuse_confidence(N) -> 1 - (1-p)^N`) + severity boost
  ladder (`Info`+1=Low, `Medium`+1=High, `High`+2=Critical, capped).
  Fixed `Severity` non-exhaustive-match drift. 4 unit tests green.
- **`gossan_correlation::dedup`** wired. Host normalization
  (scheme/port/userinfo strip + IDNA decode + case-fold + trailing-
  dot strip), wildcard coverage (RFC 4592 §4.2 — wildcards cover
  subdomains, NOT the apex), and finding dedup that collapses
  wildcard-covered concretes onto their wildcard with a
  `wildcard-origin` tag. Fixed `idna::domain_to_unicode` API drift
  (now returns `(String, Result<(), Errors>)`); fixed
  `Finding`-tag-mutation drift by rewriting via `Finding::builder`;
  fixed real wildcard-coverage bug (the apex was being treated as
  covered, contradicting RFC 4592). 8 unit tests green.
- **`gossan_correlation::relationship`** wired. Graph-edge builder
  for correlated chain findings (`RelationshipBuilder::new(chain)
  .link_finding(src, EdgeType).link_target(asset, NodeType).build()
  -> (Vec<Node>, Vec<Edge>)`). Fixed direct-field-access drift
  (`Finding.id` → `Finding.id()`), Edge field rename (`rel_type` →
  `kind`), and dropped the broken `attach_relationships` mutator
  (Finding evidence is `Arc<...>`-immutable). 4 unit tests green.
- **`gossan_portscan::cdn`** wired. CDN range loader
  (`load_ranges(path)` parses a `# comment`-allowed CIDR file) +
  `is_cdn_ip(ip, ranges)` membership check + `ptr_heuristic`
  reverse-lookup heuristic for cloudflare/fastly/akamai/edgecast/
  incapdns/amazonaws/googleusercontent/azure. Fixed `gossan_core::
  TokioAsyncResolver` re-export drift (now takes
  `hickory_resolver::TokioAsyncResolver` directly). 4 unit tests green.

### Removed (audit cleanup)

- **`crates/correlation/src/test_utils.rs`** — redundant test-only
  module (never declared in `lib.rs`) duplicating the
  `normalize_host` coverage now provided by the wired `dedup`
  module's own tests. Removed during audit cleanup.

### Removed (audit cleanup, user-approved)

- **33 dead `.rs` files at `crates/subdomain/src/`** — earlier-
  iteration source modules (alienvault, anubis, asn, bevigil,
  binaryedge, bufferover, c99, censys, certspotter, chaos,
  commoncrawl, ct, dnsdumpster, dnsrepo, fofa, fullhunt, github,
  hackertarget, hunter, intelx, leakix, netlas, quake, rapiddns,
  robtex, securitytrails, shodan, threatbook, urlscan, virustotal,
  wayback, whoisxml, zoomeye) sat at the top level of `subdomain/src/`
  but were not declared as modules in `lib.rs`. The compiler ignored
  them entirely. The canonical implementations live under
  `crates/subdomain/src/sources/` (referenced via `pub mod sources;`).
  The top-level files held pre-trait-refactor versions that drifted
  out of sync. Removed with explicit user approval. Workspace tree
  now: 5 real files at `crates/subdomain/src/` (lib + bruteforce +
  dedup + permutations + wildcard) + 82 source-module files under
  `sources/`.

### Fixed

- **`crates/crawl/src/seeds.rs` was dead code** — the file existed
  with full robots.txt + sitemap.xml parsers (`parse_robots_txt`,
  `parse_sitemap`, `RobotsTxtResult`) but was never declared as a
  module in `lib.rs`. The compiler ignored the file entirely. Fix:
  added `pub mod seeds;` in `crates/crawl/src/lib.rs`. Test coverage
  in `crates/crawl/tests/parsers.rs` (6 tests).
- **3 correlation rules implemented but never registered in
  `CorrelationEngine`.** `WildcardTakeoverRule`, `DebugRceRule`, and
  `CorsSecretChainRule` had full `impl CorrelationRule` blocks but
  `CorrelationEngine::new()` only registered 6 of the 9 rules. Three
  additional cross-finding correlation paths were dead. Fix in
  `crates/correlation/src/lib.rs::CorrelationEngine::new()` — engine
  now registers all 9 rules.
- **20+ HTTP response readers were unbounded.** Many cloud + hidden
  modules called `resp.text().await.unwrap_or_default()` without
  bounding the response body. A malicious endpoint returning a 10 GB
  body could OOM the scanner. Promoted `bounded_text` /
  `bounded_bytes` / `bounded_json` to `gossan_core::net::*`; migrated
  every unbounded site to the bounded variant (4 MiB per call,
  matching the pre-existing `Config::max_response_size` default).
  Sites: cloud/{s3,lambda,do_spaces,gcs,azure,apigateway,cloudfront},
  hidden/{dependency_confusion,api_versions,robots,tech_probes,
  oauth,swagger,debug_endpoints,graphql,methods,error_disclosure},
  horizontal/{asn,ownership}, js/lib, subdomain/{asn,leakix,dnsdumpster}.
- **`CorrelationEngine` was built but never called by the pipeline.**
  `gossan-correlation` shipped 6 rules (TlsWeakness, AdminExposed,
  ApiAuth, SsrfInternal, SourceCodeSecrets, ShadowInfra) but the
  CLI's `execute_pipeline` collected findings from each scanner
  without ever passing them to the engine. Findings that should
  have synthesised cross-rule correlations were silently dropped on
  the floor. Fix in `crates/cli/src/pipeline/registry.rs` — engine
  runs after collection and extends the finding set.


- `--format nmap-xml` (aliases: `nmap`, `xml`, `-oX`) — emits an
  `<nmaprun>` document with one `<host>` per discovered IP and a
  `<port>` element per open port. Drop-in for tools that already
  consume `nmap -oX`.
- `--format graphml` — every finding becomes a `<node>` keyed by
  target; findings sharing a target are connected with an undirected
  `<edge>`. Loads directly into Gephi / Cytoscape / yEd.
- `gossan-hidden::backup_files` probe — 36 path checks (archive,
  SQL dump, editor swap, IDE metadata, log archive families). Magic-
  byte verified for binary paths (zip / gzip / tar / vim swap /
  DS_Store) and content-probe verified for text paths. Wired into the
  pipeline as `backup_files`.
- `crates/portscan/rules/service_probes.toml` grew from 203 → 320
  active probes covering cloud-metadata services (AWS IMDS v1/v2,
  GCP, Azure, Aliyun, DigitalOcean), industrial / IoT
  (MQTT, CoAP, STOMP, Modbus, BACnet, S7, DNP3, EthernetIP),
  databases (Cassandra, CouchDB, InfluxDB, ClickHouse, ES,
  OpenSearch, Solr, Neo4j, ArangoDB, RethinkDB, Druid, Pinot,
  QuestDB), containers (Docker, K8s, Kubelet, etcd, Consul, Vault,
  Nomad, Traefik, Portainer, Rancher, OpenShift), CI/CD (Jenkins,
  GitLab, Gitea, Drone, Woodpecker, Concourse, TeamCity, Bamboo,
  ArgoCD, Tekton, Spinnaker, Buildkite), monitoring (Prometheus +
  exporters, Grafana, Loki, Tempo, Jaeger, Zipkin, Kibana, Fluentd,
  Telegraf, VictoriaMetrics, Netdata, StatsD, cAdvisor), AI/ML
  (Ollama, vLLM, Triton, TF-Serving, TorchServe, Jupyter, MLflow,
  Ray, KServe, BentoML, SD-WebUI, TGI), crypto/blockchain
  (ETH, BTC, Monero, Parity, Stratum), and the long tail
  (MinIO, SeaweedFS, Proxmox, ESXi, vCenter, Nexus, Artifactory,
  Harbor, OpenVAS, Nessus, Burp, ZAP, IPFS, Kafka REST,
  Schema Registry, Zookeeper, RabbitMQ, ActiveMQ, NATS, Pulsar,
  MikroTik, UniFi).
- `docs/schema/v1.json` — JSON Schema for the canonical `--format
  json` output.
- Property-test scaffold for `gossan-classify`: 10k arbitrary ASCII
  banners, asserts no panic and `confidence ∈ [0,100]`.
- `gossan-graph::store::memory::MemoryStore` — full
  `GraphBackend`-trait implementation. Closes "all 4 backends
  round-trip" alongside sqlite / json / graphml.
- Cross-backend round-trip integration test
  (`crates/graph/tests/all_backends_roundtrip.rs`) exercises every
  shipped backend against the same fixture.
- Per-flag CLI smoke test (`crates/cli/tests/cli_per_flag.rs`) drives
  `--rate`, `--timeout`, `--concurrency`, `--format`, `--ports`,
  `--out`, every always-on subcommand `--help`, and rejects unknown
  flags.
- JSON / NDJSON / SARIF schema tests
  (`crates/cli/tests/json_schema.rs`) parse the actual rendered
  output and assert v1 contract + SARIF 2.1.0 marker.
- ReDoS guard (`crates/portscan/src/probes/mod.rs::tests::every_probe_regex_under_50ms_on_1mib_input`)
  drives every shipped probe regex against a 1 MiB adversarial buffer
  and gates each at <50 ms. Plus probe_names_are_unique +
  fallback_probe_names_resolve sanity checks.
- Engine TX-loop perf gates extended to 2 / 8 / 16 threads (was just
  1 / 4) — regression-blocked at 8 / 30 / 50 Mpps respectively.
- Correlation-engine perf gate (100 000 findings → chains in <500 ms)
  + adversarial-target tests (RTL marks, CJK, emoji, path traversal,
  null bytes — all no-panic).
- Intel-DB bulk import gate (100 000 records in <10 s release-only) +
  query-by-IP + query-by-host smoke tests + 32-thread × 1000-query
  concurrent-read deadlock test.
- Cloud-SSRF protection unit tests
  (`crates/cloud/src/lib.rs::ssrf_tests`) cover AWS IMDS, GCP
  metadata.google.internal, all RFC1918 ranges, loopback v4 + v6,
  link-local v4 + v6, plus public-IP allow-through.
- CSP probe integration tests (`crates/hidden/tests/csp_probe.rs`):
  unsafe-inline / wildcard / missing-header all fire; strict policy
  produces zero findings.
- GraphQL introspection probe tests
  (`crates/hidden/tests/graphql_introspection.rs`): introspection-on
  fires the finding; introspection-off doesn't; 404 endpoint
  produces zero findings.
- CORS prefix/suffix bypass adversarial tests
  (`crates/hidden/tests/cors_bypass.rs`): arbitrary-origin reflection
  fires; exact-match server stays silent; no-ACAO server stays silent.
- Wordlist-integrity tests for the new
  `crates/hidden/wordlists/{top-100,top-1k}.txt` files.
- Graph 100k-edges-in-<5s perf gate.
- `docs/schema/v1.json` — JSON Schema for the canonical `--format
  json` array-of-Finding output (matches the actual santh-output
  contract; the older `{tool, findings}` wrapper sketch is gone).

### Changed

- Initial workspace structure with modular crate architecture.

## [0.1.0] — Initial release

- **Attack surface discovery** — Subdomains, ports, tech stack, hidden paths, cloud assets, DNS security, origin IP in one scan.
- **Subdomain enumeration** — CT logs, Wayback Machine, DNS brute forcing (`gossan-subdomain`).
- **TCP port scanning** — With TLS inspection and banner grabbing (`gossan-portscan`).
- **Technology fingerprinting** — Headers, cookies, HTML patterns (`gossan-techstack`).
- **DNS security auditing** — SPF, DMARC, DKIM, CAA, zone transfer checks (`gossan-dns`).
- **Hidden endpoint discovery** — Dirbusting, sitemap, robots.txt, swagger parsing (`gossan-hidden`).
- **Cloud asset discovery** — S3, GCS, Azure blob detection (`gossan-cloud`).
- **JavaScript analysis** — Secret detection, API endpoint extraction, WASM analysis (`gossan-js`).
- **Origin IP discovery** — CDN/WAF bypass techniques (`gossan-origin`).
- **Authenticated web crawler** — Form and parameter extraction (`gossan-crawl`).
- **Cross-module finding correlation** — Unified findings view (`gossan-correlation`).
- **Scan checkpoint and resume** — For long-running scans (`gossan-checkpoint`).
- **Stateless masscan-class SYN engine** — netforge-powered, multi-threaded, requires root (`gossan-engine`).
- **Headless browser integration** — For JavaScript-heavy targets (`gossan-headless`).
