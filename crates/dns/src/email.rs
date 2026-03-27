//! Email authentication security: SPF, DMARC, and DKIM auditing.
//!
//! Goes beyond simple record presence checks:
//!
//! **SPF**: Recursively resolves `include:` chains and counts total DNS lookups
//! against the RFC 7208 §4.6.4 limit of 10. Detects `+all` (allow-all),
//! `~all` (softfail), missing records, and overly permissive configurations.
//!
//! **DMARC**: Validates policy strength (`p=none` vs `p=reject`), subdomain
//! policy inheritance (`sp=`), and aggregate report destination (`rua=`).
//!
//! **DKIM**: Probes 13 common selectors (Google, Mailchimp, SendGrid, etc.)
//! and reports which signing infrastructure is active.

use gossan_core::Target;
use hickory_resolver::TokioAsyncResolver;
use secfinding::{Evidence, Finding, FindingBuilder, Severity};

use crate::resolver::lookup_txt;

/// Common DKIM selectors covering major email providers.
const DKIM_SELECTORS: &[&str] = &[
    "default", "google", "mail", "k1", "k2", "selector1", "selector2",
    "smtp", "dkim", "mandrill", "mailchimp", "sendgrid", "postmark",
];

/// Maximum SPF `include:` recursion depth before declaring permerror.
const MAX_SPF_INCLUDES: usize = 10;

fn fb(target: &Target, severity: Severity, title: impl Into<String>, detail: impl Into<String>) -> FindingBuilder {
    Finding::builder("dns", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
}

/// Run all email authentication checks against a domain.
pub async fn check(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(check_spf(resolver, domain, target).await);
    findings.extend(check_dmarc(resolver, domain, target).await);
    findings.extend(check_dkim(resolver, domain, target).await);
    findings
}

// ── SPF ─────────────────────────────────────────────────────────────────────

/// SPF analysis with recursive `include:` resolution and lookup counting.
async fn check_spf(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();

    let records = match lookup_txt(resolver, domain).await {
        Ok(r) => r,
        Err(_) => return findings,
    };

    let spf_rec = match records.iter().find(|r| r.starts_with("v=spf1")) {
        Some(rec) => rec.clone(),
        None => {
            findings.push(
                fb(target, Severity::Medium, "No SPF record",
                   format!("{domain} has no SPF record — email spoofing is possible."))
                .tag("email-security").tag("spf")
                .build().expect("finding builder: required fields are set"),
            );
            return findings;
        }
    };

    // Check terminal mechanism
    if spf_rec.contains("+all") {
        findings.push(
            fb(target, Severity::High, "SPF allows all senders (+all)",
               format!("{domain} SPF has +all — any server can send as this domain."))
            .tag("email-security").tag("spf")
            .evidence(Evidence::DnsRecord { record_type: "TXT".into(), value: spf_rec.clone() })
            .build().expect("finding builder: required fields are set"),
        );
    } else if spf_rec.contains("~all") {
        findings.push(
            fb(target, Severity::Low, "SPF softfail (~all) — not enforced",
               format!("{domain} uses ~all — emails failing SPF are still delivered."))
            .tag("email-security").tag("spf")
            .build().expect("finding builder: required fields are set"),
        );
    }

    // Recursive include resolution — count total lookups
    let lookup_count = count_spf_lookups(resolver, &spf_rec, 0).await;
    if lookup_count > MAX_SPF_INCLUDES {
        findings.push(
            fb(target, Severity::Medium,
               format!("SPF exceeds 10-lookup limit ({lookup_count} lookups)"),
               format!("{domain} SPF record requires {lookup_count} DNS lookups — \
                        exceeding RFC 7208 §4.6.4 limit of 10. Mail receivers will \
                        return permerror, effectively disabling SPF protection."))
            .tag("email-security").tag("spf").tag("permerror")
            .evidence(Evidence::DnsRecord { record_type: "TXT".into(), value: spf_rec.clone() })
            .build().expect("finding builder: required fields are set"),
        );
    }

    findings
}

/// Recursively count DNS lookups required by an SPF record.
///
/// Each `include:`, `a:`, `mx:`, `ptr:`, `exists:`, and `redirect=` mechanism
/// costs one lookup. `include:` is followed recursively.
/// Returns total lookup count across the full include chain.
async fn count_spf_lookups(
    resolver: &TokioAsyncResolver,
    spf_record: &str,
    depth: usize,
) -> usize {
    if depth > 12 {
        return 100; // circular reference protection
    }

    let mut count = 0;
    for token in spf_record.split_whitespace() {
        let mechanism = token.trim_start_matches('+')
            .trim_start_matches('-')
            .trim_start_matches('~')
            .trim_start_matches('?');

        if mechanism.starts_with("include:") {
            count += 1;
            let included_domain = mechanism.trim_start_matches("include:");
            if let Ok(records) = lookup_txt(resolver, included_domain).await {
                if let Some(child_spf) = records.iter().find(|r| r.starts_with("v=spf1")) {
                    count += Box::pin(count_spf_lookups(resolver, child_spf, depth + 1)).await;
                }
            }
        } else if mechanism.starts_with("a:") || mechanism.starts_with("a/")
            || mechanism == "a"
        {
            count += 1;
        } else if mechanism.starts_with("mx:") || mechanism.starts_with("mx/")
            || mechanism == "mx"
        {
            count += 1;
        } else if mechanism.starts_with("ptr") {
            count += 1;
        } else if mechanism.starts_with("exists:") {
            count += 1;
        } else if mechanism.starts_with("redirect=") {
            count += 1;
            let redirect_domain = mechanism.trim_start_matches("redirect=");
            if let Ok(records) = lookup_txt(resolver, redirect_domain).await {
                if let Some(child_spf) = records.iter().find(|r| r.starts_with("v=spf1")) {
                    count += Box::pin(count_spf_lookups(resolver, child_spf, depth + 1)).await;
                }
            }
        }
    }
    count
}

// ── DMARC ───────────────────────────────────────────────────────────────────

/// DMARC policy analysis: presence, enforcement level, subdomain policy, report URIs.
async fn check_dmarc(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dmarc_domain = format!("_dmarc.{domain}");

    let records = match lookup_txt(resolver, &dmarc_domain).await {
        Ok(r) => r,
        Err(_) => {
            findings.push(
                fb(target, Severity::Medium, "No DMARC record",
                   format!("{domain} has no DMARC record — phishing via email spoofing is unmitigated."))
                .tag("email-security").tag("dmarc")
                .build().expect("finding builder: required fields are set"),
            );
            return findings;
        }
    };

    let rec = match records.iter().find(|r| r.starts_with("v=DMARC1")) {
        Some(r) => r.clone(),
        None => {
            findings.push(
                fb(target, Severity::Medium, "No DMARC record",
                   format!("{domain} has no DMARC record."))
                .tag("email-security").tag("dmarc")
                .build().expect("finding builder: required fields are set"),
            );
            return findings;
        }
    };

    // Policy strength
    if rec.contains("p=none") {
        findings.push(
            fb(target, Severity::Low, "DMARC policy is p=none (monitor only)",
               format!("{domain} DMARC does not reject or quarantine — unenforced."))
            .tag("email-security").tag("dmarc")
            .build().expect("finding builder: required fields are set"),
        );
    } else if rec.contains("p=quarantine") {
        findings.push(
            fb(target, Severity::Info, "DMARC policy is p=quarantine",
               format!("{domain} DMARC quarantines but does not outright reject spoofed emails."))
            .tag("email-security").tag("dmarc")
            .build().expect("finding builder: required fields are set"),
        );
    }

    // Subdomain policy
    if !rec.contains("sp=reject") && !rec.contains("p=none") {
        findings.push(
            fb(target, Severity::Low, "DMARC missing sp=reject (subdomain spoofing risk)",
               format!("{domain} DMARC lacks sp=reject — unconfigured subdomains are spoofable."))
            .tag("email-security").tag("dmarc")
            .build().expect("finding builder: required fields are set"),
        );
    }

    // Report URI disclosure
    if let Some(part) = rec.split(';').find(|p| p.trim().starts_with("rua=")) {
        let addr = part.trim().trim_start_matches("rua=");
        findings.push(
            fb(target, Severity::Info, "DMARC aggregate report recipient",
               format!("{domain} aggregate DMARC reports go to: {addr}"))
            .evidence(Evidence::DnsRecord { record_type: "TXT".into(), value: rec.clone() })
            .tag("email-security").tag("disclosure")
            .build().expect("finding builder: required fields are set"),
        );
    }

    findings
}

// ── DKIM ────────────────────────────────────────────────────────────────────

/// Probe common DKIM selectors to discover email signing infrastructure.
async fn check_dkim(
    resolver: &TokioAsyncResolver,
    domain: &str,
    target: &Target,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut dkim_found = false;

    for selector in DKIM_SELECTORS {
        let dkim_name = format!("{selector}._domainkey.{domain}");
        if let Ok(records) = lookup_txt(resolver, &dkim_name).await {
            if records.iter().any(|r| r.contains("v=DKIM1") || r.contains("p=")) {
                dkim_found = true;
                findings.push(
                    fb(target, Severity::Info, format!("DKIM selector active: {selector}"),
                       format!("{domain} DKIM selector '{selector}' resolves — email signing configured."))
                    .evidence(Evidence::DnsRecord {
                        record_type: "TXT".into(),
                        value: records.first().cloned().unwrap_or_default(),
                    })
                    .tag("email-security").tag("dkim")
                    .build().expect("finding builder: required fields are set"),
                );
                break; // one active selector is sufficient confirmation
            }
        }
    }

    if !dkim_found {
        findings.push(
            fb(target, Severity::Low, "No DKIM record found",
               format!("{domain} — none of {} common DKIM selectors resolved.", DKIM_SELECTORS.len()))
            .tag("email-security").tag("dkim")
            .build().expect("finding builder: required fields are set"),
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkim_selectors_include_major_providers() {
        for sel in ["default", "google", "mailchimp", "sendgrid", "postmark"] {
            assert!(DKIM_SELECTORS.contains(&sel), "missing DKIM selector: {sel}");
        }
    }

    #[test]
    fn dkim_selector_count_is_comprehensive() {
        assert!(
            DKIM_SELECTORS.len() >= 13,
            "should have 13+ DKIM selectors, got {}",
            DKIM_SELECTORS.len()
        );
    }

    #[test]
    fn max_spf_includes_matches_rfc() {
        assert_eq!(MAX_SPF_INCLUDES, 10, "RFC 7208 §4.6.4 mandates 10-lookup limit");
    }
}
