//! Regression: the SSTI confirmation pattern (`159401` = 473×337) must
//! only be honoured on an actual template-injection probe. The old
//! guard compared against the dead literal "49" (the retired
//! `{{7*7}}→49` canary), so any response whose body merely *contained*
//! the substring 159401 was reported as a Critical "SSTI confirmed".

use gossan_core::testkit::web_target;
use gossan_hidden::error_disclosure;
use gossan_core::ScanClient as Client;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// `web_target` is now the shared `gossan_core::testkit::web_target`.

/// Adversarial: a benign, non-SSTI endpoint returns a body that just
/// happens to contain the digits `159401` (an order id, a price, part
/// of a longer number). It was never reached via a template probe, so
/// it MUST NOT be reported as SSTI / Critical.
#[tokio::test]
async fn coincidental_159401_is_not_reported_as_ssti() {
    let server = MockServer::start().await;
    // Only this non-SSTI trigger path responds; everything else
    // (including the `/` template-probe path) 404s with an empty body.
    Mock::given(method("GET"))
        .and(path("/gossan-error-probe-9z3k2p"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("<p>Thank you  -  order #159401 confirmed.</p>"),
        )
        .mount(&server)
        .await;

    let client = gossan_core::ScanClient::default_client();
    let target = web_target(&server.uri());
    let findings = error_disclosure::probe(&client, &target).await.unwrap();

    assert!(
        !findings
            .iter()
            .any(|f| f.title().contains("SSTI")
                || f.tags().iter().any(|t| t.as_ref() == "ssti")),
        "coincidental 159401 must not be flagged as SSTI: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
}

/// Negative twin: a real template-injection probe (`{{473*337}}`)
/// whose response echoes the evaluated product `159401` MUST still be
/// confirmed as Critical SSTI  -  the fix is precise, not a mute.
#[tokio::test]
async fn real_evaluated_template_is_still_confirmed_ssti() {
    let server = MockServer::start().await;
    // The SSTI trigger suffixes all have path `/`; return the evaluated
    // product so `is_ssti_probe && body contains 159401` holds.
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("result: 159401"))
        .mount(&server)
        .await;

    let client = gossan_core::ScanClient::default_client();
    let target = web_target(&server.uri());
    let findings = error_disclosure::probe(&client, &target).await.unwrap();

    let ssti: Vec<_> = findings
        .iter()
        .filter(|f| f.tags().iter().any(|t| t.as_ref() == "ssti"))
        .collect();
    assert_eq!(
        ssti.len(),
        1,
        "expected exactly one confirmed SSTI finding, got: {:?}",
        findings.iter().map(|f| f.title()).collect::<Vec<_>>()
    );
    assert!(ssti[0]
        .title()
        .contains("Server-Side Template Injection (SSTI) confirmed"));
}
