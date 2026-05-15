use super::*;
use gossan_core::{DiscoverySource, NetworkTarget, ScanInput, Target};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_portscan_network_expansion() {
    let server = MockServer::start().await;
    let addr = server.address();

    // Create a network target that includes the mock server's IP
    let cidr = format!("{}/32", addr.ip());

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string("HTTP/1.1 200 OK\r\nServer: test\r\n\r\n"),
        )
        .mount(&server)
        .await;

    let scanner = PortScanner::new();
    let mut config = Config::default();
    config.port_mode = gossan_core::PortMode::Custom(vec![addr.port()]);

    // Streaming-API construction. Old form was `ScanInput { targets:
    // Vec<_>, live_tx: None, target_tx: None }` and `scanner.run`
    // returned a struct with `.targets` / `.findings`. Both retired:
    // targets flow in via `target_rx`, results flow out via the two
    // tx channels, and `run` returns `Result<()>`.
    let (in_tx, in_rx) = tokio::sync::mpsc::unbounded_channel::<Target>();
    let _ = in_tx.send(Target::Network(NetworkTarget {
        cidr,
        source: DiscoverySource::Seed,
    }));
    drop(in_tx);
    let (live_tx, _live_rx) = tokio::sync::mpsc::unbounded_channel();
    let (target_tx, mut target_rx) = tokio::sync::mpsc::unbounded_channel();
    let input = ScanInput {
        seed: "example.com".into(),
        target_rx: tokio::sync::Mutex::new(in_rx),
        live_tx,
        target_tx,
        resolver: std::sync::Arc::new(
            gossan_core::net::build_resolver(&config).expect("test resolver"),
        ),
    };

    scanner.run(input, &config).await.unwrap();

    // Drain whatever the scanner emitted onto target_tx to verify
    // it found the open port. Channels close when the ScanInput
    // (which holds the senders) is dropped at the end of run.
    let mut emitted: Vec<Target> = Vec::new();
    while let Ok(t) = target_rx.try_recv() {
        emitted.push(t);
    }
    assert!(
        !emitted.is_empty(),
        "Should have found at least one service"
    );
    assert!(emitted.iter().any(|t| {
        if let Target::Service(s) = t {
            s.port == addr.port()
        } else {
            false
        }
    }));
}
