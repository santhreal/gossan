use gossan_origin::{util, OriginCandidate, ValidationState};
use std::net::IpAddr;
use std::sync::Arc;
use wiremock::{
    matchers::{method, path_regex},
    Mock, MockServer, ResponseTemplate,
};

#[tokio::test]
async fn validator_confirms_known_good_origin() {
    let cdn = MockServer::start().await;
    let origin = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><head><title>Hello Origin</title></head><body>Hello Origin</body></html>",
        ))
        .mount(&cdn)
        .await;

    Mock::given(method("GET"))
        .and(path_regex("/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><head><title>Hello Origin</title></head><body>Hello Origin</body></html>",
        ))
        .mount(&origin)
        .await;

    let domain = cdn.address().to_string();
    let ip: IpAddr = origin.address().ip();
    let port: u16 = origin.address().port();

    // Wiremock binds to 127.0.0.1:<ephemeral>; pass the port so the
    // validator hits the actual mock and so the global-routability
    // gate doesn't reject loopback pre-emptively.
    let candidate = OriginCandidate::new_with_port(ip, port, "ssl_cert_ct_log", 70);
    let config = gossan_core::Config::default();

    // validate() now takes a 4th arg `&ScanClient` (the
    // pre-existing 3-arg signature was retired when origin
    // probing was unified onto the shared HTTP client). Use the
    // default client for tests; resolver does not matter because
    // mock servers respond directly.
    let resolver =
        Arc::new(hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap());
    let client = gossan_core::ScanClient::from_config(&config, resolver).unwrap();
    let validated =
        gossan_origin::validator::validate(vec![candidate], &domain, &config, &client).await;

    assert_eq!(validated.len(), 1);
    assert_eq!(validated[0].validated, ValidationState::Confirmed);
    assert_eq!(validated[0].confidence, 100);
    assert_eq!(validated[0].method, "validated_origin");
}

#[tokio::test]
async fn validator_rejects_generic_nginx_page() {
    let cdn = MockServer::start().await;
    let origin = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path_regex("/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><head><title>Real Site</title></head><body>Real Site</body></html>",
        ))
        .mount(&cdn)
        .await;

    Mock::given(method("GET"))
        .and(path_regex("/.*"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><head><title>Welcome to nginx!</title></head><body>Welcome to nginx!</body></html>",
        ))
        .mount(&origin)
        .await;

    let domain = cdn.address().to_string();
    let ip: IpAddr = origin.address().ip();

    let candidate = OriginCandidate::new_with_port(ip, origin.address().port(), "dns_history", 85);
    let config = gossan_core::Config::default();

    // validate() now takes a 4th arg `&ScanClient` (the
    // pre-existing 3-arg signature was retired when origin
    // probing was unified onto the shared HTTP client). Use the
    // default client for tests; resolver does not matter because
    // mock servers respond directly.
    let resolver =
        Arc::new(hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap());
    let client = gossan_core::ScanClient::from_config(&config, resolver).unwrap();
    let validated =
        gossan_origin::validator::validate(vec![candidate], &domain, &config, &client).await;

    assert_eq!(validated.len(), 1);
    assert_eq!(validated[0].validated, ValidationState::Rejected);
}

#[tokio::test]
async fn validator_confirms_by_404_divergence() {
    let cdn = MockServer::start().await;
    let origin = MockServer::start().await;

    // Baseline: root page must return something so baseline is established.
    Mock::given(method("GET"))
        .and(path_regex("^/$"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><head><title>Real Site</title></head><body>Real Site</body></html>",
        ))
        .mount(&cdn)
        .await;

    Mock::given(method("GET"))
        .and(path_regex("^/$"))
        .respond_with(ResponseTemplate::new(200).set_body_string(
            "<html><head><title>Different</title></head><body>Different</body></html>",
        ))
        .mount(&origin)
        .await;

    // CDN 404 page
    Mock::given(method("GET"))
        .and(path_regex("/nonexistent-.*"))
        .respond_with(
            ResponseTemplate::new(404).set_body_string("<html><body>Cloudflare 404</body></html>"),
        )
        .mount(&cdn)
        .await;

    // Origin 404 page
    Mock::given(method("GET"))
        .and(path_regex("/nonexistent-.*"))
        .respond_with(
            ResponseTemplate::new(404).set_body_string("<html><body>nginx 404</body></html>"),
        )
        .mount(&origin)
        .await;

    let domain = cdn.address().to_string();
    let ip: IpAddr = origin.address().ip();

    let candidate = OriginCandidate::new_with_port(ip, origin.address().port(), "favicon_hash", 80);
    let config = gossan_core::Config::default();

    // validate() now takes a 4th arg `&ScanClient` (the
    // pre-existing 3-arg signature was retired when origin
    // probing was unified onto the shared HTTP client). Use the
    // default client for tests; resolver does not matter because
    // mock servers respond directly.
    let resolver =
        Arc::new(hickory_resolver::TokioAsyncResolver::tokio_from_system_conf().unwrap());
    let client = gossan_core::ScanClient::from_config(&config, resolver).unwrap();
    let validated =
        gossan_origin::validator::validate(vec![candidate], &domain, &config, &client).await;

    assert_eq!(validated.len(), 1);
    assert_eq!(validated[0].validated, ValidationState::Confirmed);
    assert_eq!(validated[0].confidence, 95);
    assert_eq!(validated[0].method, "validated_origin_404");
}
