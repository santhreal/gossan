use gossan_correlation::CorrelationEngine;
use secfinding::{Finding, Severity};
use proptest::prelude::*;
use proptest::collection::vec;

// Create a valid Finding via the builder pattern, avoiding direct instantiation 
// of the private fields if any exist or handling Uuid/Date generation cleanly
fn create_finding(scanner: String, target: String, title: String) -> Finding {
    // Determine a random severity based on string length just to vary it
    let severity = match title.len() % 4 {
        0 => Severity::Low,
        1 => Severity::Medium,
        2 => Severity::High,
        _ => Severity::Critical,
    };
    
    Finding::builder(scanner, target, severity)
        .title(title)
        .build()
        .expect("finding builder")
}

// Strategy to generate a list of arbitrary findings
prop_compose! {
    fn arbitrary_finding()(
        // FindingBuilder requires scanner, target, and title to be non-empty strings
        scanner in "[a-zA-Z0-9_-]+",
        target in "[a-zA-Z0-9_\\-\\.]+",
        title in "[a-zA-Z0-9_ \\-\\.]+",
    ) -> Finding {
        create_finding(scanner, target, title)
    }
}

proptest! {
    #[test]
    fn engine_never_panics_on_arbitrary_findings(
        findings in vec(arbitrary_finding(), 0..100)
    ) {
        let engine = CorrelationEngine::new();
        // The core invariant: The engine should NEVER panic regardless of input.
        // We assert that chains produced cannot exceed the input findings, as chains
        // represent correlated sets of findings.
        let chains = engine.run(&findings, &[]);
        prop_assert!(chains.len() <= findings.len());
    }
    
    #[test]
    fn engine_does_not_mutate_or_consume_input_findings(
        findings in vec(arbitrary_finding(), 0..10)
    ) {
        let engine = CorrelationEngine::new();
        let findings_clone = findings.clone();
        
        // This is a pure function from the perspective of inputs
        let chains = engine.run(&findings, &[]);
        prop_assert!(chains.len() <= findings.len());
        
        // Ensure the input hasn't been altered (Rust's borrow checker enforces this for `&`, 
        // but we verify the values remain exactly the same just to be absolutely sure 
        // no weird internal mutability is happening)
        assert_eq!(findings, findings_clone);
    }
    
    #[test]
    fn engine_returns_empty_when_no_correlation_criteria_met(
        // Generate findings that explicitly DO NOT contain correlation keywords
        findings in vec(arbitrary_finding().prop_filter("No keywords", |f| {
            let title = f.title().to_lowercase();
            // `f.scanner()` already returns `&str`; the historical
            // `let scanner = &f.scanner()` made it `&&str`, which
            // doesn't `PartialEq<str>` directly. Bind without the
            // extra ref so the comparison below is `&str == &str`.
            let scanner: &str = f.scanner();

            !title.contains("tls") &&
            !title.contains("certificate") &&
            !title.contains("admin") &&
            !title.contains("dashboard") &&
            !title.contains("missing") &&
            !title.contains("auth") &&
            scanner != "hidden"
        }), 0..50)
    ) {
        let engine = CorrelationEngine::new();
        let chains = engine.run(&findings, &[]);
        
        // If no findings contain the trigger keywords, NO chains should EVER be produced
        prop_assert!(chains.is_empty(), "Engine produced a chain without trigger conditions!");
    }
}
