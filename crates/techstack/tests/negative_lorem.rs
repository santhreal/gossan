//! Negative test for tech-stack fingerprinting.
//!
//! Per GOSSAN_LEGENDARY A7: random Lorem Ipsum HTML must trigger
//! zero rules. We exercise the same detection pipeline the runtime
//! bridge uses (`truestack::fingerprints::detect` against an empty
//! header map and a Lorem body).

#[test]
fn lorem_ipsum_triggers_no_fingerprints() {
    let body = include_str!("./fixtures/lorem.html");
    let headers: &[(&str, &str)] = &[];
    let techs = truestack::fingerprints::detect(headers, body);
    assert!(
        techs.is_empty(),
        "Lorem Ipsum HTML must yield zero techs; got {} techs: {:?}",
        techs.len(),
        techs.iter().map(|t| &t.name).collect::<Vec<_>>()
    );
}

#[test]
fn empty_body_triggers_no_fingerprints() {
    let headers: &[(&str, &str)] = &[];
    let techs = truestack::fingerprints::detect(headers, "");
    assert!(techs.is_empty(), "empty body must yield zero techs");
}
