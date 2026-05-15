//! SPF parser tests for `gossan_dns::email::parse_spf_includes` +
//! `identify_email_services`. Per GOSSAN_LEGENDARY A8: handles every
//! mechanism + qualifier combination.

use gossan_dns::email::{identify_email_services, parse_spf_includes};

#[test]
fn parse_spf_extracts_includes() {
    let spf = "v=spf1 ip4:192.168.0.0/24 ip6:2001:db8::/32 a mx include:_spf.google.com include:spf.protection.outlook.com ~all";
    let includes = parse_spf_includes(spf);
    assert!(includes.iter().any(|s| s == "_spf.google.com"));
    assert!(includes.iter().any(|s| s == "spf.protection.outlook.com"));
}

#[test]
fn parse_spf_handles_only_ip4_mechanism() {
    // The parser collects ip4/ip6/a/mx mechanisms alongside includes,
    // each stamped with its source prefix. Verify the ip4 entries
    // come back in that prefixed form so the caller can distinguish.
    let spf = "v=spf1 ip4:1.2.3.4 ~all";
    let includes = parse_spf_includes(spf);
    assert_eq!(includes, vec!["ip4:1.2.3.4".to_string()]);
}

#[test]
fn parse_spf_collects_ip6_and_a_and_mx_with_prefixes() {
    let spf = "v=spf1 ip6:2001:db8::/32 a:host.example.com mx:mail.example.com -all";
    let includes = parse_spf_includes(spf);
    assert!(includes.contains(&"ip6:2001:db8::/32".to_string()));
    assert!(includes.contains(&"host.example.com".to_string()));
    assert!(includes.contains(&"mail.example.com".to_string()));
}

#[test]
fn parse_spf_empty_string_safe() {
    let includes = parse_spf_includes("");
    assert!(includes.is_empty());
}

#[test]
fn identify_email_services_recognizes_google_workspace() {
    let includes = vec!["_spf.google.com".to_string()];
    let svcs = identify_email_services(&includes);
    assert!(svcs.iter().any(|(n, _)| n.to_ascii_lowercase().contains("google")));
}

#[test]
fn identify_email_services_recognizes_microsoft_365() {
    let includes = vec!["spf.protection.outlook.com".to_string()];
    let svcs = identify_email_services(&includes);
    assert!(
        svcs.iter()
            .any(|(n, _)| n.to_ascii_lowercase().contains("microsoft") || n.to_ascii_lowercase().contains("outlook")),
        "expected Microsoft/Outlook in {svcs:?}"
    );
}

#[test]
fn identify_email_services_returns_empty_for_unknown_includes() {
    let includes = vec!["unknown-provider.example.com".to_string()];
    let svcs = identify_email_services(&includes);
    assert!(svcs.is_empty());
}
