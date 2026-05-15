# gossan-graph

Graph-based Attack Surface Management (ASM) store for Gossan.

Persists discovered targets and findings as a typed graph (nodes:
endpoints, hosts, services, repos, packages; edges: hosted-on,
serves, depends-on, owned-by, discovered-via). Backends:

- **SQLite** (default) — single-file local store, good for single-node
  scans and ad-hoc queries.
- **JSON** — human-inspectable export.
- **GraphML** — interop with Gephi / yEd / Cytoscape.

## Usage

```rust,no_run
use gossan_graph::SqliteBackend;
let backend = SqliteBackend::open("scan.gossan.db")?;
backend.persist_scan(&targets, &findings)?;
# Ok::<_, Box<dyn std::error::Error>>(())
```

## Temporal diff

The store records a scan_id per persistence, so subsequent scans can be
diff'd against a baseline to surface new / changed / removed findings.

## License

MIT
