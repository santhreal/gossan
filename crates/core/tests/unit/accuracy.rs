use gossan_core::accuracy::{ResponseBaseline, generate_dom_fingerprint, calculate_fuzzy_hash};
use std::collections::HashMap;

#[test]
fn test_mirror_maze_detection() {
    // 1. Create a baseline from a "garbage" response (e.g. 404 landing page)
    let baseline_html = "<html><body><h1>Not Found</h1><p>The page you requested does not exist.</p></body></html>";
    let mut baseline_headers = HashMap::new();
    baseline_headers.insert("Server".to_string(), "nginx".to_string());
    baseline_headers.insert("Content-Type".to_string(), "text/html".to_string());

    let baseline = ResponseBaseline {
        avg_length: baseline_html.len(),
        headers: baseline_headers.clone(),
        fuzzy_hash: calculate_fuzzy_hash(baseline_html),
        dom_fingerprint: generate_dom_fingerprint(baseline_html),
    };

    // 2. Test a "Mirror" response (slightly different text but same structure)
    let mirror_html = "<html><body><h1>Mirror</h1><p>Another page that looks exactly the same.</p></body></html>";
    let mirror_fuzzy = calculate_fuzzy_hash(mirror_html);
    let mirror_dom = generate_dom_fingerprint(mirror_html);
    
    // Structure is identical, headers are identical, length is similar
    assert!(baseline.is_mirror(mirror_html.len(), &baseline_headers, mirror_fuzzy, &mirror_dom));

    // 3. Test a "Signal" response (JSON API endpoint)
    let signal_html = "{\"status\":\"ok\",\"version\":\"1.0.0\",\"endpoints\":[\"/api/v1/user\"]}";
    let signal_fuzzy = calculate_fuzzy_hash(signal_html);
    let signal_dom = generate_dom_fingerprint(signal_html);
    let mut signal_headers = baseline_headers.clone();
    signal_headers.insert("Content-Type".to_string(), "application/json".to_string());

    // This should NOT be a mirror (totally different DOM and content type)
    assert!(!baseline.is_mirror(signal_html.len(), &signal_headers, signal_fuzzy, &signal_dom));
    
    // 4. Test a "Signal" response (different headers but same structure)
    // Sometimes a mirror returns different headers for real apps
    let mut exploit_headers = baseline_headers.clone();
    exploit_headers.insert("X-Santh-Signal".to_string(), "true".to_string());
    let similarity = baseline.similarity(mirror_html.len(), &exploit_headers, mirror_fuzzy, &mirror_dom);
    
    // Similarity should drop due to header mismatch
    assert!(similarity < 1.0);
}
