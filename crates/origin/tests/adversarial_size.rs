use gossan_origin::util::{bounded_bytes, bounded_text};
use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn bounded_text_truncates_large_response() {
    let mock_server = MockServer::start().await;
    let huge = vec![b'a'; 20 * 1024 * 1024];

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(huge))
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/", mock_server.address()))
        .send()
        .await
        .unwrap();

    let limit = 1024;
    let text = bounded_text(resp, limit).await.unwrap();
    assert_eq!(text.len(), limit);
}

#[tokio::test]
async fn bounded_bytes_truncates_large_response() {
    let mock_server = MockServer::start().await;
    let huge = vec![0u8; 20 * 1024 * 1024];

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(huge))
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/", mock_server.address()))
        .send()
        .await
        .unwrap();

    let limit = 4096;
    let bytes = bounded_bytes(resp, limit).await.unwrap();
    assert_eq!(bytes.len(), limit);
}
