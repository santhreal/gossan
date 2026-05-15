//! Endpoint extraction from JS bodies.
//!
//! Per GOSSAN_LEGENDARY A9: regex-extract `fetch("/api/...")`,
//! `axios.get("/...")`, etc.; assert N endpoints found in fixture.

use gossan_js::endpoints::extract;

const SAMPLE_JS: &str = r#"
async function load() {
  const r = await fetch("/api/users");
  const meta = await fetch("/api/v2/meta");
  axios.get("/api/orders");
  axios.post("/api/orders/create", payload);
  $.ajax({ url: "/api/legacy", type: "GET" });
}
"#;

#[test]
fn extracts_fetch_axios_endpoints() {
    let endpoints = extract("https://example.com/app.js", SAMPLE_JS);
    let urls: Vec<String> = endpoints
        .iter()
        .map(|e| format!("{:?}", e))
        .collect();
    // We don't pin the exact internal Endpoint shape — just assert
    // the extractor finds the expected URLs.
    let body_joined = urls.join(" ");
    for path in ["/api/users", "/api/v2/meta", "/api/orders"] {
        assert!(
            body_joined.contains(path),
            "expected `{path}` in extracted endpoints; got: {body_joined}"
        );
    }
}

#[test]
fn empty_body_yields_no_endpoints() {
    let endpoints = extract("https://example.com/empty.js", "");
    assert!(endpoints.is_empty());
}

#[test]
fn pure_lorem_yields_no_endpoints() {
    let endpoints = extract(
        "https://example.com/lorem.js",
        "var x = 1; var y = 2; function hello() { return 'world'; }",
    );
    assert!(endpoints.is_empty());
}
