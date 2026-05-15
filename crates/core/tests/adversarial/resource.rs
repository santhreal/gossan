use gossan_core::ratelimit::read_response_limited;
use gossan_core::reqwest as reqwest;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_response_bomb_shield_adversarial() {
    let mock_server = MockServer::start().await;
    
    // Create a mock that returns 1MB of data
    let large_data = vec![0u8; 1024 * 1024];
    Mock::given(method("GET"))
        .and(path("/large"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(large_data, "application/octet-stream"))
        .mount(&mock_server)
        .await;

    let client = reqwest::Client::new();
    let resp = client.get(&format!("{}/large", mock_server.uri())).send().await.unwrap();
    
    // 1. Limit to 512KB - should FAIL
    let res = read_response_limited(resp, 512 * 1024).await;
    assert!(res.is_err(), "Should have failed due to response size limit");
    assert!(res.unwrap_err().to_string().contains("max size"));

    // 2. Limit to 2MB - should PASS
    let resp2 = client.get(&format!("{}/large", mock_server.uri())).send().await.unwrap();
    let res2 = read_response_limited(resp2, 2 * 1024 * 1024).await;
    assert!(res2.is_ok(), "Should have passed within limit");
    assert_eq!(res2.unwrap().len(), 1024 * 1024);
}
