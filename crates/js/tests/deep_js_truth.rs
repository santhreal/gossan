//! Deep truth tests for `gossan-js`  -  the crate had 6 tests and ZERO
//! negative/adversarial coverage on its two highest-stakes paths:
//! secret detection (a leak here is account takeover) and endpoint
//! extraction (drives new scan targets + reported locations).
//!
//! These assert TRUTH, not shape: exact finding classification, the
//! data-exfil redaction invariant (raw credential must never reach a
//! serialized finding), single-use raw-store semantics, exact endpoint
//! sets with accurate line numbers, sanitized negative twins, and
//! adversarial inputs. Real `gossan_keyhog_lite` embedded detectors are
//! used  -  never a stub  -  so a regression to "matches nothing" fails
//! loudly here.

use gossan_core::testkit::web_target;
use gossan_js::endpoints::{self, Endpoint};
use gossan_js::secrets::{self, take_raw_secret};

// Realistic non-placeholder AWS access keys: `AKIA` + 16 upper-alnum,
// matching the embedded `aws-access-key` detector `(AKIA|ASIA)[0-9A-Z]{16}`.
// Deliberately NOT the canonical docs key `AKIAIOSFODNN7EXAMPLE` and
// containing none of keyhog's placeholder markers (EXAMPLE / TEST_ /
// FAKE / XXXXX / …)  -  keyhog's `looks_like_placeholder` filter
// correctly suppresses those as documentation false-positives, a
// precision feature locked by `aws_documentation_example_key_is_ignored`
// below. Using a marker-bearing key here would test the FP filter, not
// detection.
const AWS_KEY: &str = "AKIA1234567890ABCDEF";
const AWS_KEY_2: &str = "AKIAZXCVBNMQWERTYUIO";

fn serialize(f: &secfinding::Finding) -> String {
    serde_json::to_string(f).expect("Finding is Serialize")
}

fn tag_with_prefix(json: &str, prefix: &str) -> Option<String> {
    // tags serialize as JSON strings in an array; find "<prefix>...".
    let needle = format!("\"{prefix}");
    let start = json.find(&needle)? + 1;
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ─────────────────────── secrets: the critical path ───────────────────

#[test]
fn aws_secret_fires_with_correct_classification() {
    let t = web_target("http://example.com/");
    let js = format!("var cfg = {{ key: \"{AWS_KEY}\" }};\n");
    let findings = secrets::scan("https://example.com/app.js", &js, &t);

    assert_eq!(
        findings.len(),
        1,
        "exactly one AWS key must be detected, got {findings:?}"
    );
    let j = serialize(&findings[0]);
    assert!(
        j.contains("secret-leak"),
        "finding must serialize kind as `secret-leak`; json={j}"
    );
    assert!(
        j.contains("aws") || j.to_lowercase().contains("aws"),
        "finding must attribute the aws service/detector; json={j}"
    );
    assert!(
        tag_with_prefix(&j, "det:").is_some(),
        "must carry a det:<id> tag; json={j}"
    );
    assert!(
        tag_with_prefix(&j, "hash:").is_some(),
        "must carry a hash:<sha256> tag for correlation; json={j}"
    );
}

/// THE invariant. A leak of the raw credential into ANY serialized
/// field (title, detail, evidence snippet, tags) is a critical
/// data-exfil bug: reports get shipped, logged, indexed. The raw value
/// must appear NOWHERE in the serialized finding  -  only its redaction
/// and its hash.
#[test]
fn raw_secret_never_appears_in_serialized_finding() {
    let t = web_target("http://example.com/");
    let js = format!("const AWS='{AWS_KEY}'; // do not leak me\n");
    let findings = secrets::scan("https://cdn.example.com/main.js", &js, &t);
    assert_eq!(findings.len(), 1, "precondition: one finding");

    let j = serialize(&findings[0]);
    assert!(
        !j.contains(AWS_KEY),
        "RAW SECRET LEAKED into serialized finding  -  critical exfil bug. \
         json={j}"
    );
    // The redacted form keyhog produces MUST be what is shown instead.
    let redacted = gossan_keyhog_lite::redact(AWS_KEY);
    assert!(
        j.contains(&redacted),
        "evidence must carry the redacted credential `{redacted}`; json={j}"
    );
    assert_ne!(redacted, AWS_KEY, "redact() must actually transform it");
}

/// The raw value is recoverable exactly once via the hash (the
/// verifier engine depends on this), then it is gone (single-use
/// `remove`  -  a second take must not resurrect a secret).
///
/// Uses a UNIQUE key: `store_raw_secret`/`take_raw_secret` back a
/// process-global map, and cargo runs tests concurrently  -  any other
/// test scanning the same credential would re-insert this hash between
/// the two takes and (correctly) defeat a shared-key assertion. The
/// single-use contract is real; the test must isolate its hash to
/// observe it deterministically. (Surfaced by deep-testing: the shared
/// `AWS_KEY` made the 2nd take non-deterministic.)
#[test]
fn raw_store_take_is_exact_and_single_use() {
    const UNIQUE_KEY: &str = "AKIA0R1S2T3U4V5W6X7Y";
    let t = web_target("http://example.com/");
    let js = format!("export const K = \"{UNIQUE_KEY}\";\n");
    let findings = secrets::scan("https://example.com/s.js", &js, &t);
    assert_eq!(findings.len(), 1);

    let hash = tag_with_prefix(&serialize(&findings[0]), "hash:")
        .expect("hash tag present")
        .strip_prefix("hash:")
        .expect("hash: prefix")
        .to_string();

    assert_eq!(
        take_raw_secret(&hash).as_deref(),
        Some(UNIQUE_KEY),
        "raw value must be recoverable exactly via its hash"
    );
    assert_eq!(
        take_raw_secret(&hash),
        None,
        "second take MUST be None  -  single-use store, no secret resurrection"
    );
}

/// Negative precision: realistic JS with high-entropy NON-secrets (a
/// sha256 hex, a UUID, a long base64 sourcemap-shaped blob, a webpack
/// chunk hash). The wrapper must add no false positives.
#[test]
fn clean_js_yields_no_secret_findings() {
    let t = web_target("http://example.com/");
    let clean = r#"
        const sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
        const id  = "550e8400-e29b-41d4-a716-446655440000";
        const chunk = "app.7f3a9c2e1b8d4f6a.chunk.js";
        const css = "/static/css/main.0a1b2c3d.css";
        function add(a,b){ return a+b; }
        export default { id, sri, chunk, add };
    "#;
    let findings = secrets::scan("https://example.com/clean.js", clean, &t);
    assert!(
        findings.is_empty(),
        "no secret may be reported on benign high-entropy JS, got {findings:?}"
    );
}

/// Precision contract (regression-gated). keyhog deliberately suppresses
/// documentation placeholders  -  most notably the canonical AWS docs
/// access key `AKIAIOSFODNN7EXAMPLE` and any credential/line bearing an
/// EXAMPLE/TEST_/FAKE/PLACEHOLDER marker. This is THE single biggest
/// real-world false-positive class for secret scanners (every AWS
/// tutorial pastes that key). If a refactor ever lets the example key
/// through, this fails  -  a real precision regression, not a nuisance.
/// Discovered by deep-testing: the first fixtures naively used this very
/// key and (correctly) found nothing.
#[test]
fn aws_documentation_example_key_is_ignored() {
    let t = web_target("http://example.com/");
    let js = "const AWS_ACCESS_KEY_ID = \"AKIAIOSFODNN7EXAMPLE\";\n";
    let findings = secrets::scan("https://example.com/docs.js", js, &t);
    assert!(
        findings.is_empty(),
        "the canonical AWS docs example key MUST be filtered as a \
         placeholder (precision), got {findings:?}"
    );
    // A marker in the surrounding LINE must also suppress (keyhog checks
    // both the credential and its line)  -  a real key on a `// example`
    // line is documentation, not a leak.
    let js2 = format!("var k = \"{AWS_KEY}\"; // example only, not real\n");
    assert!(
        secrets::scan("u", &js2, &t).is_empty(),
        "a real-shaped key on an `example` line must be suppressed too"
    );
}

#[test]
fn two_distinct_secrets_yield_two_findings_with_distinct_hashes() {
    let t = web_target("http://example.com/");
    let js = format!("a=\"{AWS_KEY}\";\nb=\"{AWS_KEY_2}\";\n");
    let findings = secrets::scan("https://example.com/m.js", &js, &t);
    assert_eq!(findings.len(), 2, "both keys detected, got {findings:?}");

    let h0 = tag_with_prefix(&serialize(&findings[0]), "hash:");
    let h1 = tag_with_prefix(&serialize(&findings[1]), "hash:");
    assert!(h0.is_some() && h1.is_some());
    assert_ne!(h0, h1, "distinct secrets must hash distinctly");
    for f in &findings {
        let j = serialize(f);
        assert!(!j.contains(AWS_KEY) && !j.contains(AWS_KEY_2),
            "neither raw key may appear serialized; json={j}");
    }
}

// ─────────────────────── endpoints: truth + a real bug ────────────────

fn set(eps: &[Endpoint]) -> std::collections::BTreeSet<(String, usize)> {
    eps.iter().map(|e| (e.path.clone(), e.line)).collect()
}

#[test]
fn exact_endpoint_set_with_accurate_lines() {
    // line: content
    // 1   : (blank from leading \n)
    // 2   : const base = '/api/users?active=true';
    // 3   : fetch('/v1/orders');
    // 4   : axios.post('/auth/login');
    // 5   : new URL('https://api.example.com/data');
    let js = "\nconst base = '/api/users?active=true';\nfetch('/v1/orders');\naxios.post('/auth/login');\nnew URL('https://api.example.com/data');";
    let eps = endpoints::extract("https://x/app.js", js);
    let got = set(&eps);

    let want: std::collections::BTreeSet<(String, usize)> = [
        ("/api/users?active=true".to_string(), 2),
        ("/v1/orders".to_string(), 3),
        ("/auth/login".to_string(), 4),
        ("https://api.example.com/data".to_string(), 5),
    ]
    .into_iter()
    .collect();

    assert_eq!(
        got, want,
        "endpoint extraction must yield exactly this (path,line) set"
    );
}

/// THE bug hunt. `/api/widget` is *called* on line 2 (`fetch(...)`) and
/// also appears as an inert string literal on line 6. `extract`
/// iterates patterns in a fixed order (API-prefix pattern BEFORE the
/// fetch pattern) and dedups by path, so it reports whichever pattern
/// matched first  -  the line-6 literal  -  not the textually-first
/// occurrence on line 2. A recon finding that points at the inert
/// literal instead of the real call site is a wrong location. The
/// reported line MUST be the first textual occurrence: line 2.
#[test]
fn endpoint_line_is_the_first_textual_occurrence_not_pattern_order() {
    let js = "// 1\nfetch('/api/widget');\n// 3\n// 4\n// 5\nconst ref = '/api/widget';\n";
    let eps = endpoints::extract("u", js);
    let w = eps
        .iter()
        .find(|e| e.path == "/api/widget")
        .unwrap_or_else(|| panic!("missing /api/widget; got {eps:?}"));
    assert_eq!(
        w.line, 2,
        "must report the first textual occurrence (the fetch call on \
         line 2), not the later string literal  -  got line {}",
        w.line
    );
    assert_eq!(
        eps.iter().filter(|e| e.path == "/api/widget").count(),
        1,
        "the same path must be reported once, not per pattern"
    );
}

/// Real negative: a non-API path that is NOT inside a call must not be
/// harvested; the same path INSIDE a fetch() is a real call site and
/// MUST be. Precision and recall in one assertion pair.
#[test]
fn non_api_literal_excluded_but_real_call_included() {
    let js = "const css = '/static/app.css';\nfetch('/static/data.json');";
    let eps = endpoints::extract("u", js);
    assert!(
        !eps.iter().any(|e| e.path == "/static/app.css"),
        "a bare non-API literal must not be harvested: {eps:?}"
    );
    assert!(
        eps.iter().any(|e| e.path == "/static/data.json"),
        "a path passed to fetch() IS a real call site and must be \
         extracted: {eps:?}"
    );
}

#[test]
fn adversarial_minified_one_liner_keeps_line_one_and_all_endpoints() {
    // Minifiers collapse everything to a single line  -  every endpoint
    // is line 1, and dedup must not drop distinct paths.
    let js = "fetch('/api/a');axios.get('/api/b');fetch('/api/c');new URL('/v2/d')";
    let eps = endpoints::extract("u", js);
    let got = set(&eps);
    let want: std::collections::BTreeSet<(String, usize)> = [
        ("/api/a".to_string(), 1),
        ("/api/b".to_string(), 1),
        ("/api/c".to_string(), 1),
        ("/v2/d".to_string(), 1),
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want, "minified extraction must be complete & line=1");
}

// ─────────────────────── as_target: pivot safety ──────────────────────

#[test]
fn as_target_only_resolves_real_absolute_hosts() {
    use gossan_core::Target;

    let ep = |p: &str| Endpoint {
        path: p.to_string(),
        js_url: "u".into(),
        line: 1,
    };

    // Absolute https → Domain with the EXACT host.
    match ep("https://api.evil-cdn.com/v1/x").as_target() {
        Some(Target::Domain(d)) => assert_eq!(d.domain, "api.evil-cdn.com"),
        other => panic!("expected Domain(api.evil-cdn.com), got {other:?}"),
    }
    // Absolute http with IP literal → Host with the parsed IP.
    match ep("http://10.0.0.5/internal").as_target() {
        Some(Target::Host(h)) => {
            assert_eq!(h.ip.to_string(), "10.0.0.5");
        }
        other => panic!("expected Host(10.0.0.5), got {other:?}"),
    }
    // Relative path is NOT a pivot target.
    assert!(ep("/api/users").as_target().is_none());
    // Scheme tricks must NOT produce a scan target.
    assert!(ep("javascript:alert(1)").as_target().is_none());
    assert!(ep("data:text/html,<script>").as_target().is_none());
}
