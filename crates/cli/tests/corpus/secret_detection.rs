use gossan_js::secrets;
use gossan_core::{Target, DomainTarget, DiscoverySource, ScanInput, Config};
use std::path::Path;
use std::fs;

#[tokio::test]
async fn test_secret_detection_corpus_recall() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let corpus_path = Path::new(&manifest_dir).join("../../../../software/keyhog/tests/data/corpus/secrets");
    let entries = fs::read_dir(&corpus_path).expect(&format!("Failed to read corpus at {:?}", corpus_path));
    
    let target = Target::Domain(DomainTarget {
        domain: "corpus-test.local".into(),
        source: DiscoverySource::Seed,
    });

    let mut total_found = 0;
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            let content = fs::read_to_string(&path).expect("Failed to read file");
            let js_url = format!("https://corpus-test.local/{}", path.file_name().unwrap().to_string_lossy());
            
            // Note: secrets::scan returns Vec<Finding>
            let findings = secrets::scan(&js_url, &content, &target);
            total_found += findings.len();
        }
    }

    // We expect a significant number of secrets to be found from the secrets corpus
    assert!(total_found > 0, "Should have found secrets in the secrets corpus");
    println!("Total secrets found in corpus: {}", total_found);
}
