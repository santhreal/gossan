use gossan_core::net::build_proxy_route;

#[test]
fn test_build_proxy_route_adversarial_null_bytes() {
    let route = build_proxy_route(Some("socks5://local\0host:1080"));
    // Depending on string splitting, it might strip or not. Either way, it shouldn't panic.
    match route {
        Ok(r) => {
            let s = format!("{:?}", r);
            assert!(
                s.contains("local") || s.contains("host") || s.contains("1080"),
                "Should contain part of the host or port"
            );
        }
        Err(e) => {
            assert!(!e.is_empty(), "Error message must not be empty");
        }
    }
}

#[test]
fn test_build_proxy_route_adversarial_huge_port() {
    let route = build_proxy_route(Some("socks5://localhost:4294967295"));
    assert!(route.is_err(), "Huge port should be rejected gracefully");
    assert!(
        route.unwrap_err().contains("invalid port number"),
        "Error should clearly state it's an invalid port"
    );
}

#[test]
fn test_build_proxy_route_adversarial_zero_port() {
    let route = build_proxy_route(Some("socks5://localhost:0"));
    // Either it parses and connects to port 0, or it errors. Neither should panic.
    match route {
        Ok(r) => {
            let s = format!("{:?}", r);
            assert!(
                s.contains("port: 0"),
                "If it parsed, it must contain port 0"
            );
        }
        Err(e) => {
            assert!(!e.is_empty(), "Error message must not be empty");
        }
    }
}

#[test]
fn test_build_proxy_route_adversarial_no_host_only_port() {
    let route = build_proxy_route(Some("socks5://:1080"));
    // Either it errors out or parses with an empty host. Neither should panic.
    match route {
        Ok(r) => {
            let s = format!("{:?}", r);
            assert!(
                s.contains("host: \"\"") || s.contains("1080"),
                "If parsed, should map empty host correctly"
            );
        }
        Err(e) => {
            assert!(!e.is_empty(), "Error message must not be empty");
        }
    }
}

#[test]
fn test_build_proxy_route_adversarial_unrecognized_scheme() {
    let route = build_proxy_route(Some("ftp://proxy:21"));
    // Right now it defaults to SOCKS5 for unrecognized schemes, which is an interesting design choice
    match route {
        Ok(r) => {
            let s = format!("{:?}", r);
            assert!(
                s.contains("Socks5"),
                "It should default to Socks5 if unrecognized"
            );
            assert!(
                s.contains("ftp://proxy"),
                "It should include the scheme as part of the host if unrecognized"
            );
        }
        Err(e) => {
            assert!(!e.is_empty(), "Error message must not be empty");
        }
    }
}

#[test]
fn test_build_proxy_route_adversarial_very_long_url() {
    let host = "a".repeat(100_000);
    let url = format!("socks5://{}:1080", host);
    let route = build_proxy_route(Some(&url));
    match route {
        Ok(r) => {
            let s = format!("{:?}", r);
            assert!(
                s.len() > 100_000,
                "The route representation should be massive"
            );
        }
        Err(e) => {
            assert!(!e.is_empty(), "Error message must not be empty");
        }
    }
}
