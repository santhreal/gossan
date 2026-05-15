use gossan_core::ratelimit::read_response_limited;
use wiremock::{MockServer, Mock, ResponseTemplate, matchers::any};
use reqwest::Client;

#[tokio::test]
async fn test_read_response_limited_gap_decompression_bomb() {
    // Gap: The `read_response_limited` function reads the response body and limits by size.
    // However, it does not explicitly handle or limit "decompression bombs" (e.g., highly compressed gzip).
    // `reqwest` handles decompression automatically by default. If a server sends a tiny compressed response
    // that expands to 1GB, `reqwest` will stream the decompressed bytes.
    // The `max_size` check *should* trigger on the decompressed stream length, preventing OOM.
    // But does it? The Content-Length header check might be bypassed if the server lies or omits it.
    
    // We mock a server that returns a huge stream (we'll simulate it locally with a huge byte array).
    let server = MockServer::start().await;
    
    Mock::given(any())
        // Simulate a response without Content-Length that streams forever
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 10_000_000])) // 10MB
        .mount(&server)
        .await;

    let client = Client::new();
    let resp = client.get(server.uri()).send().await.unwrap();

    // We set max size to 1MB
    let result = read_response_limited(resp, 1_000_000).await;
    
    // Gap: Wiremock currently serves this *without* a gzip header, but if we simulated 
    // a highly compressed gzip response, the reqwest streaming would transparently decompress it.
    // Since reqwest processes it as chunks of decompressed data, the stream check *should* catch it.
    // However, if the chunk size itself exceeds the memory we want to allocate, we might still 
    // have issues. For this gap test, we just ensure the 10MB byte stream correctly triggers 
    // the stream limit error since there's no Content-Length header.
    assert!(result.is_err(), "Must reject bodies larger than max_size during stream reading");
}
