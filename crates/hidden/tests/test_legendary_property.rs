use gossan_core::{Target, WebAssetTarget};
use gossan_hidden::cors;
use proptest::prelude::*;
use reqwest::{Client, Url};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn create_mock_target(url: &str) -> Target {
    Target::Web(Box::new(WebAssetTarget {
        url: Url::parse(url).unwrap(),
        service: gossan_core::ServiceTarget {
            host: gossan_core::HostTarget {
                ip: "127.0.0.1".parse().unwrap(),
                domain: Some("example.com".to_string()),
            },
            port: 80,
            protocol: gossan_core::Protocol::Tcp,
            banner: None,
            tls: false,
        },
        tech: vec![],
        status: 200,
        title: None,
        favicon_hash: None,
        body_hash: None,
        forms: vec![],
        params: vec![],
    }))
}

// Ensure proptests run within a tokio runtime context
proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))] // Keep it low since we spin up a server for each case

    #[test]
    fn test_cors_random_headers_dont_panic(
        acao in any::<String>().prop_filter("Only valid ascii headers", |s| s.is_ascii() && s.len() < 100 && !s.contains('\r') && !s.contains('\n') && !s.contains('\0')),
        acac in any::<String>().prop_filter("Only valid ascii headers", |s| s.is_ascii() && s.len() < 100 && !s.contains('\r') && !s.contains('\n') && !s.contains('\0'))
    ) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let server = MockServer::start().await;

            Mock::given(method("GET"))
                .and(path("/"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("access-control-allow-origin", acao.as_str())
                        .insert_header("access-control-allow-credentials", acac.as_str())
                )
                .mount(&server)
                .await;

            let client = Client::new();
            let target = create_mock_target(&server.uri());

            let result = cors::probe(&client, &target).await;

            // Invariant: it should never panic and should always return Ok
            assert!(result.is_ok());
        });
    }
}
