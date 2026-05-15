#![no_main]

use libfuzzer_sys::fuzz_target;
use gossan_js::{secrets, endpoints, vulnerabilities};
use gossan_core::Target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    let target = Target::Domain(gossan_core::DomainTarget {
        domain: "example.com".into(),
        source: gossan_core::DiscoverySource::Seed,
    });
    let js_url = "https://example.com/app.js";

    // Fuzz all analyzers.
    // They internally use Regex which can potentially hang or panic if crafted maliciously.
    let _ = secrets::scan(js_url, &s, &target);
    let _ = endpoints::extract(js_url, &s);
    let _ = vulnerabilities::scan(js_url, &s, &target);
});
