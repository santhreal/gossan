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
//! **DKIM**: Probes common selectors loaded from TOML configuration
//! (Google, Mailchimp, SendGrid, etc.) and reports which signing infrastructure is active.

use gossan_core::Target;
use hickory_resolver::TokioResolver;
use secfinding::{Evidence, Finding, FindingBuilder, FindingKind, Severity};
use serde::Deserialize;
use std::sync::OnceLock;

use crate::resolver::{lookup_txt, lookup_txt_classified, TxtLookup};

/// DKIM selector definition from TOML.
#[derive(Debug, Clone, Deserialize)]
struct DkimSelector {
    name: String,
    provider: String,
}

/// TOML file containing DKIM selector definitions.
#[derive(Debug, Deserialize)]
struct DkimSelectorsFile {
    selector: Vec<DkimSelector>,
}

/// Built-in dkim_selectors.toml content (embedded at compile time).
const BUILTIN_DKIM_SELECTORS: &str = include_str!("../rules/dkim_selectors.toml");

/// Global cache for built-in DKIM selectors.
static DKIM_SELECTORS: OnceLock<Vec<DkimSelector>> = OnceLock::new();

/// Initialize and return the built-in DKIM selectors.
fn builtin_dkim_selectors() -> &'static Vec<DkimSelector> {
    DKIM_SELECTORS.get_or_init(|| {
        match toml::from_str::<DkimSelectorsFile>(BUILTIN_DKIM_SELECTORS) {
            Ok(file) => file.selector,
            Err(e) => {
                tracing::error!(error = %e, "failed to parse built-in dkim_selectors.toml");
                // Fallback to minimal hardcoded list only on parse failure
                vec![
                    DkimSelector {
                        name: "default".to_string(),
                        provider: "Generic".to_string(),
                    },
                    DkimSelector {
                        name: "google".to_string(),
                        provider: "Google Workspace".to_string(),
                    },
                    DkimSelector {
                        name: "selector1".to_string(),
                        provider: "Microsoft 365".to_string(),
                    },
                ]
            }
        }
    })
}

/// Get DKIM selector names from TOML configuration.
fn dkim_selector_names() -> &'static [DkimSelector] {
    builtin_dkim_selectors()
}

/// Maximum SPF `include:` recursion depth before declaring permerror.
const MAX_SPF_INCLUDES: usize = 10;

fn fb(
    target: &Target,
    severity: Severity,
    title: impl Into<String>,
    detail: impl Into<String>,
) -> FindingBuilder {
    Finding::builder("dns", target.domain().unwrap_or("?"), severity)
        .title(title)
        .detail(detail)
}

/// Run all email authentication checks against a domain.
pub async fn check(resolver: &TokioResolver, domain: &str, target: &Target) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(check_spf(resolver, domain, target).await);
    findings.extend(check_dmarc(resolver, domain, target).await);
    findings.extend(check_dkim(resolver, domain, target).await);
    findings
}

// ── SPF ─────────────────────────────────────────────────────────────────────
/// Classification of an SPF record's `all` mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SpfAllClass {
    /// No `all` mechanism present: implicit `+all` per RFC 7208 §4.6.1.
    Missing,
    /// `+all` or bare `all`: pass all senders.
    PassAll,
    /// `~all`: softfail, not enforced.
    SoftFail,
    /// `?all`: neutral, no policy.
    Neutral,
    /// `-all`: hardfail, properly enforced.
    HardFail,
}

/// Classify the `all` mechanism in an SPF record by token-exact matching.
///
/// Uses `split_whitespace` so `+all` inside a domain name (e.g.
/// `include:mail+all.example.com`) does not false-positive.
#[must_use]
fn spf_all_classification(spf_rec: &str) -> SpfAllClass {
    let has_all = spf_rec.split_whitespace().any(|m| {
        let m = m.strip_prefix('+').unwrap_or(m);
        m == "all" || m == "~all" || m == "-all" || m == "?all"
    });
    if !has_all {
        return SpfAllClass::Missing;
    }
    if spf_rec.split_whitespace().any(|m| m == "+all" || m == "all") {
        SpfAllClass::PassAll
    } else if spf_rec.split_whitespace().any(|m| m == "~all") {
        SpfAllClass::SoftFail
    } else if spf_rec.split_whitespace().any(|m| m == "?all") {
        SpfAllClass::Neutral
    } else {
        SpfAllClass::HardFail
    }
}

/// SPF analysis with recursive `include:` resolution and lookup counting.
async fn check_spf(resolver: &TokioResolver, domain: &str, target: &Target) -> Vec<Finding> {
    let mut findings = Vec::new();

    let records = match lookup_txt_classified(resolver, domain).await {
        Ok(TxtLookup::Records(r)) => r,
        Ok(TxtLookup::Absent) => Vec::new(),
        Err(e) => {
            tracing::warn!(
                domain,
                error = %e,
                "SPF TXT lookup failed; not treating as missing SPF"
            );
            gossan_core::try_push_finding(
                fb(
                    target,
                    Severity::Info,
                    "SPF check could not complete",
                    format!(
                        "TXT lookup for {domain} failed ({e}); SPF presence/strength was not evaluated."
                    ),
                )
                .kind(FindingKind::Misconfiguration)
                .tag("email-security")
                .tag("spf")
                .tag("incomplete"),
                &mut findings,
            );
            return findings;
        }
    };

    let spf_rec = match records.iter().find(|r| r.starts_with("v=spf1")) {
        Some(rec) => rec.clone(),
        None => {
            gossan_core::try_push_finding(
                fb(
                    target,
                    Severity::Medium,
                    "No SPF record",
                    format!("{domain} has no SPF record, email spoofing is possible."),
                )
                .kind(FindingKind::Misconfiguration)
                .tag("email-security")
                .tag("spf"),
                &mut findings,
            );
            return findings;
        }
    };

    match spf_all_classification(&spf_rec) {
        SpfAllClass::Missing => {
            gossan_core::try_push_finding(
                fb(
                    target,
                    Severity::High,
                    "SPF has no 'all' mechanism (implicit +all)",
                    format!(
                        "{domain} SPF record has no 'all' mechanism. \
                         Per RFC 7208 §4.6.1, the default is '+all', allowing \
                         any server to send email as this domain."
                    ),
                )
                .tag("email-security")
                .tag("spf")
                .evidence(Evidence::DnsRecord {
                    record_type: "TXT".into(),
                    value: spf_rec.clone().into(),
                }),
                &mut findings,
            );
        }
        SpfAllClass::PassAll => {
            gossan_core::try_push_finding(
                fb(
                    target,
                    Severity::High,
                    "SPF allows all senders (+all)",
                    format!("{domain} SPF has +all, any server can send as this domain."),
                )
                .tag("email-security")
                .tag("spf")
                .evidence(Evidence::DnsRecord {
                    record_type: "TXT".into(),
                    value: spf_rec.clone().into(),
                }),
                &mut findings,
            );
        }
        SpfAllClass::SoftFail => {
            gossan_core::try_push_finding(
                fb(
                    target,
                    Severity::Low,
                    "SPF softfail (~all), not enforced",
                    format!("{domain} uses ~all, emails failing SPF are still delivered."),
                )
                .tag("email-security")
                .tag("spf"),
                &mut findings,
            );
        }
        SpfAllClass::Neutral => {
            gossan_core::try_push_finding(
                fb(
                    target,
                    Severity::Medium,
                    "SPF neutral (?all), no policy enforced",
                    format!(
                        "{domain} uses ?all, emails failing SPF are accepted \
                         with no policy applied. Use -all for enforcement."
                    ),
                )
                .tag("email-security")
                .tag("spf"),
                &mut findings,
            );
        }
        SpfAllClass::HardFail => {}
    }

    // Recursive include resolution, count total lookups
    let lookup_count = count_spf_lookups(resolver, &spf_rec, 0).await;
    if lookup_count > MAX_SPF_INCLUDES {
        gossan_core::try_push_finding(
            fb(
                target,
                Severity::Medium,
                format!("SPF exceeds 10-lookup limit ({lookup_count} lookups)"),
                format!(
                    "{domain} SPF record requires {lookup_count} DNS lookups. \
                        exceeding RFC 7208 §4.6.4 limit of 10. Mail receivers will \
                        return permerror, effectively disabling SPF protection."
                ),
            )
            .tag("email-security")
            .tag("spf")
            .tag("permerror")
            .evidence(Evidence::DnsRecord {
                record_type: "TXT".into(),
                value: spf_rec.clone().into(),
            }),
            &mut findings,
        );
    }

    findings
}

/// Recursively count DNS lookups required by an SPF record.
///
/// Each `include:`, `a:`, `mx:`, `ptr:`, `exists:`, and `redirect=` mechanism
/// costs one lookup. `include:` is followed recursively.
/// Returns total lookup count across the full include chain.
async fn count_spf_lookups(resolver: &TokioResolver, spf_record: &str, depth: usize) -> usize {
    if depth > 12 {
        return 100; // circular reference protection
    }

    let mut count = 0;
    for token in spf_record.split_whitespace() {
        let mechanism = token
            .trim_start_matches('+')
            .trim_start_matches('-')
            .trim_start_matches('~')
            .trim_start_matches('?');

        if mechanism.starts_with("include:") {
            count += 1;
            let included_domain = mechanism.trim_start_matches("include:");
            match lookup_txt_classified(resolver, included_domain).await {
                Ok(TxtLookup::Records(records)) => {
                    if let Some(child_spf) = records.iter().find(|r| r.starts_with("v=spf1")) {
                        count += Box::pin(count_spf_lookups(resolver, child_spf, depth + 1)).await;
                    }
                }
                Ok(TxtLookup::Absent) => {}
                Err(e) => {
                    tracing::warn!(
                        domain = %included_domain,
                        error = %e,
                        "SPF include: TXT lookup failed; not counting nested lookups"
                    );
                }
            }
        } else if mechanism.starts_with("a:")
            || mechanism.starts_with("a/")
            || mechanism == "a"
            || mechanism.starts_with("mx:")
            || mechanism.starts_with("mx/")
            || mechanism == "mx"
            || mechanism.starts_with("ptr")
            || mechanism.starts_with("exists:")
        {
            count += 1;
        } else if mechanism.starts_with("redirect=") {
            count += 1;
            let redirect_domain = mechanism.trim_start_matches("redirect=");
            match lookup_txt_classified(resolver, redirect_domain).await {
                Ok(TxtLookup::Records(records)) => {
                    if let Some(child_spf) = records.iter().find(|r| r.starts_with("v=spf1")) {
                        count += Box::pin(count_spf_lookups(resolver, child_spf, depth + 1)).await;
                    }
                }
                Ok(TxtLookup::Absent) => {}
                Err(e) => {
                    tracing::warn!(
                        domain = %redirect_domain,
                        error = %e,
                        "SPF redirect: TXT lookup failed; not counting nested lookups"
                    );
                }
            }
        }
    }
    count
}

// ── DMARC ───────────────────────────────────────────────────────────────────

/// Parsed DMARC TXT record fields (RFC 7489).
///
/// Returned by [`parse_dmarc`]. Tags absent from the source record are
/// `None`: the caller is responsible for applying RFC defaults
/// (`sp=p`, `pct=100`, `adkim=r`, `aspf=r`, `fo=0`, `rf=afrf`, `ri=86400`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DmarcRecord {
    /// Required `v=DMARC1`.
    pub version: Option<String>,
    /// `p=` policy: `none|quarantine|reject`.
    pub policy: Option<String>,
    /// `sp=` subdomain policy. Defaults to `p` when absent.
    pub subdomain_policy: Option<String>,
    /// `pct=` percentage applied (0..=100). Defaults to 100.
    pub pct: Option<u8>,
    /// Aggregate report URIs (`rua=`).
    pub rua: Vec<String>,
    /// Forensic report URIs (`ruf=`).
    pub ruf: Vec<String>,
    /// `adkim=` DKIM alignment (`r|s`).
    pub adkim: Option<String>,
    /// `aspf=` SPF alignment (`r|s`).
    pub aspf: Option<String>,
    /// `fo=` failure-options.
    pub fo: Option<String>,
    /// `rf=` reporting format.
    pub rf: Option<String>,
    /// `ri=` reporting interval seconds.
    pub ri: Option<u32>,
}

/// Parse a DMARC TXT record into structured fields.
///
/// Returns `None` if the record does not begin with `v=DMARC1` (case
/// sensitive per RFC 7489 §6.4 (the version tag is the marker)).
/// Unknown tags are tolerated and dropped silently. Whitespace
/// around `;` separators and `=` is permitted and stripped.
#[must_use]
pub fn parse_dmarc(record: &str) -> Option<DmarcRecord> {
    let trimmed = record.trim();
    if !trimmed.to_lowercase().starts_with("v=dmarc1") {
        return None;
    }
    let mut out = DmarcRecord::default();
    for part in trimmed.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let k = k.trim().to_lowercase();
        let v = v.trim();
        match k.as_str() {
            "v" => out.version = Some(v.into()),
            "p" => out.policy = Some(v.to_lowercase()),
            "sp" => out.subdomain_policy = Some(v.to_lowercase()),
            "pct" => out.pct = v.parse::<u8>().ok().filter(|n| *n <= 100),
            "rua" => {
                out.rua = v.split(',').map(|s| s.trim().to_string()).collect();
            }
            "ruf" => {
                out.ruf = v.split(',').map(|s| s.trim().to_string()).collect();
            }
            "adkim" => out.adkim = Some(v.to_lowercase()),
            "aspf" => out.aspf = Some(v.to_lowercase()),
            "fo" => out.fo = Some(v.to_lowercase()),
            "rf" => out.rf = Some(v.to_lowercase()),
            "ri" => out.ri = v.parse::<u32>().ok(),
            _ => {} // unknown tag; tolerate per RFC 7489 §6.6
        }
    }
    Some(out)
}

/// DMARC analysis issues identified from a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DmarcIssue {
    /// Missing DMARC record.
    Missing,
    /// Policy is p=none (unenforced).
    PolicyNone,
    /// Policy is p=quarantine (soft enforcement).
    PolicyQuarantine,
    /// Subdomain policy is none or missing under main none policy.
    SubdomainSpoofable,
    /// Subdomain policy is explicitly weaker than main policy.
    SubdomainWeakerThanMain,
}

/// Analyze a DMARC record for security issues.
#[must_use]
pub fn analyze_dmarc(record: &str) -> Vec<DmarcIssue> {
    let Some(parsed) = parse_dmarc(record) else {
        return vec![DmarcIssue::Missing];
    };

    let mut issues = Vec::new();
    let p = parsed
        .policy
        .as_deref()
        .unwrap_or("none")
        .to_lowercase();
    let sp = parsed
        .subdomain_policy
        .as_deref()
        .map(|s| s.to_lowercase());
    let effective_sp = sp.clone().unwrap_or_else(|| p.clone());

    if p == "none" {
        issues.push(DmarcIssue::PolicyNone);
    } else if p == "quarantine" {
        issues.push(DmarcIssue::PolicyQuarantine);
    }

    if effective_sp == "none" {
        issues.push(DmarcIssue::SubdomainSpoofable);
    }

    if let Some(sp_val) = sp {
        let p_strength = match p.as_str() {
            "reject" => 2,
            "quarantine" => 1,
            _ => 0,
        };
        let sp_strength = match sp_val.as_str() {
            "reject" => 2,
            "quarantine" => 1,
            _ => 0,
        };
        if sp_strength < p_strength {
            issues.push(DmarcIssue::SubdomainWeakerThanMain);
        }
    }

    issues
}

/// DMARC policy analysis: presence, enforcement level, subdomain policy, report URIs.
async fn check_dmarc(resolver: &TokioResolver, domain: &str, target: &Target) -> Vec<Finding> {
    let mut findings = Vec::new();
    let dmarc_domain = format!("_dmarc.{domain}");

    let records = match lookup_txt_classified(resolver, &dmarc_domain).await {
        Ok(TxtLookup::Records(r)) => r,
        Ok(TxtLookup::Absent) => {
            gossan_core::try_push_finding(
                fb(
                    target,
                    Severity::Medium,
                    "No DMARC record",
                    format!(
                        "{domain} has no DMARC record, phishing via email spoofing is unmitigated."
                    ),
                )
                .tag("email-security")
                .tag("dmarc"),
                &mut findings,
            );
            return findings;
        }
        Err(e) => {
            tracing::warn!(
                domain = %dmarc_domain,
                error = %e,
                "DMARC TXT lookup failed; not treating as missing DMARC"
            );
            gossan_core::try_push_finding(
                fb(
                    target,
                    Severity::Info,
                    "DMARC check could not complete",
                    format!(
                        "TXT lookup for {dmarc_domain} failed ({e}); DMARC presence/policy was not evaluated."
                    ),
                )
                .tag("email-security")
                .tag("dmarc")
                .tag("incomplete"),
                &mut findings,
            );
            return findings;
        }
    };

    let rec = match records.iter().find(|r| r.to_lowercase().trim().starts_with("v=dmarc1")) {
        Some(r) => r.clone(),
        None => {
            gossan_core::try_push_finding(
                fb(
                    target,
                    Severity::Medium,
                    "No DMARC record",
                    format!("{domain} has no DMARC record."),
                )
                .tag("email-security")
                .tag("dmarc"),
                &mut findings,
            );
            return findings;
        }
    };

    let Some(parsed) = parse_dmarc(&rec) else {
        return findings;
    };

    // Policy strength
    let p = parsed.policy.as_deref().unwrap_or("none");
    if p == "none" {
        gossan_core::try_push_finding(
            fb(
                target,
                Severity::Low,
                "DMARC policy is p=none (monitor only)",
                format!("{domain} DMARC does not reject or quarantine, unenforced."),
            )
            .tag("email-security")
            .tag("dmarc"),
            &mut findings,
        );
    } else if p == "quarantine" {
        gossan_core::try_push_finding(
            fb(
                target,
                Severity::Info,
                "DMARC policy is p=quarantine",
                format!("{domain} DMARC quarantines but does not outright reject spoofed emails."),
            )
            .tag("email-security")
            .tag("dmarc"),
            &mut findings,
        );
    }

    // Subdomain policy
    let effective_sp = parsed.subdomain_policy.as_deref().unwrap_or(p);
    if effective_sp != "reject" && p != "none" {
        gossan_core::try_push_finding(
            fb(
                target,
                Severity::Low,
                "DMARC missing sp=reject (subdomain spoofing risk)",
                format!("{domain} DMARC lacks sp=reject, unconfigured subdomains are spoofable."),
            )
            .tag("email-security")
            .tag("dmarc"),
            &mut findings,
        );
    }

    // Report URI disclosure
    if !parsed.rua.is_empty() {
        let addr = parsed.rua.join(", ");
        gossan_core::try_push_finding(
            fb(
                target,
                Severity::Info,
                "DMARC aggregate report recipient",
                format!("{domain} aggregate DMARC reports go to: {addr}"),
            )
            .evidence(Evidence::DnsRecord {
                record_type: "TXT".into(),
                value: rec.clone().into(),
            })
            .tag("email-security")
            .tag("disclosure"),
            &mut findings,
        );
    }

    findings
}

// ── DKIM ────────────────────────────────────────────────────────────────────

/// Probe common DKIM selectors loaded from TOML to discover email signing infrastructure.
async fn check_dkim(resolver: &TokioResolver, domain: &str, target: &Target) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut dkim_found = false;

    for selector in dkim_selector_names() {
        let dkim_name = format!("{}._domainkey.{domain}", selector.name);
        let records = match lookup_txt_classified(resolver, &dkim_name).await {
            Ok(TxtLookup::Records(r)) => r,
            Ok(TxtLookup::Absent) => continue,
            Err(e) => {
                tracing::warn!(
                    name = %dkim_name,
                    error = %e,
                    "DKIM selector TXT lookup failed; skipping selector"
                );
                continue;
            }
        };
        {
            let Some(evidence) = records
                .iter()
                .find(|r| r.contains("v=DKIM1") || r.contains("p="))
                .cloned()
            else {
                continue;
            };
            dkim_found = true;
            gossan_core::try_push_finding(
                fb(
                    target,
                    Severity::Info,
                    format!("DKIM selector active: {}", selector.name),
                    format!(
                        "{domain} DKIM selector '{}' ({}) resolves, email signing configured.",
                        selector.name, selector.provider
                    ),
                )
                .evidence(Evidence::DnsRecord {
                    record_type: "TXT".into(),
                    value: evidence.into(),
                })
                .tag("email-security")
                .tag("dkim"),
                &mut findings,
            );
            break; // one active selector is sufficient confirmation
        }
    }

    if !dkim_found {
        gossan_core::try_push_finding(
            fb(
                target,
                Severity::Low,
                "No DKIM record found",
                format!(
                    "{domain}, none of {} common DKIM selectors resolved.",
                    dkim_selector_names().len()
                ),
            )
            .tag("email-security")
            .tag("dkim"),
            &mut findings,
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn dkim_selectors_load_from_toml() {
        let selectors = dkim_selector_names();
        assert!(
            !selectors.is_empty(),
            "should have DKIM selectors from TOML"
        );
        assert!(
            selectors.iter().any(|s| s.name == "google"),
            "should include google selector"
        );
    }

    #[test]
    fn dkim_selectors_include_major_providers() {
        let names: Vec<_> = dkim_selector_names()
            .iter()
            .map(|s| s.name.clone())
            .collect();
        for expected in ["default", "google", "mailchimp", "sendgrid", "postmark"] {
            assert!(
                names.contains(&expected.to_string()),
                "missing selector: {}",
                expected
            );
        }
    }

    #[test]
    fn dkim_selector_count_is_comprehensive() {
        assert!(
            dkim_selector_names().len() >= 13,
            "should have 13+ DKIM selectors, got {}",
            dkim_selector_names().len()
        );
    }

    #[test]
    fn parse_dmarc_canonical_record() {
        let r = parse_dmarc(
            "v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:agg@example.com; ruf=mailto:fns@example.com; adkim=s; aspf=r; fo=1; rf=afrf; ri=86400",
        )
        .expect("must parse");
        assert_eq!(r.version.as_deref(), Some("DMARC1"));
        assert_eq!(r.policy.as_deref(), Some("reject"));
        assert_eq!(r.subdomain_policy.as_deref(), Some("quarantine"));
        assert_eq!(r.pct, Some(100));
        assert_eq!(r.rua, vec!["mailto:agg@example.com"]);
        assert_eq!(r.ruf, vec!["mailto:fns@example.com"]);
        assert_eq!(r.adkim.as_deref(), Some("s"));
        assert_eq!(r.aspf.as_deref(), Some("r"));
        assert_eq!(r.fo.as_deref(), Some("1"));
        assert_eq!(r.rf.as_deref(), Some("afrf"));
        assert_eq!(r.ri, Some(86400));
    }

    #[test]
    fn parse_dmarc_rejects_non_dmarc1() {
        assert!(parse_dmarc("v=spf1 ip4:1.2.3.4 -all").is_none());
        assert!(parse_dmarc("p=reject; pct=100").is_none());
        assert!(parse_dmarc("").is_none());
    }

    #[test]
    fn parse_dmarc_handles_multi_uri_lists() {
        let r = parse_dmarc("v=DMARC1; p=reject; rua=mailto:a@x.com,mailto:b@x.com; ruf=mailto:c@x.com,mailto:d@x.com,mailto:e@x.com")
            .unwrap();
        assert_eq!(r.rua.len(), 2);
        assert_eq!(r.ruf.len(), 3);
        assert_eq!(r.rua[1], "mailto:b@x.com");
    }

    #[test]
    fn parse_dmarc_clamps_invalid_pct() {
        // Per RFC pct ∈ 0..=100. 200 must be rejected.
        let r = parse_dmarc("v=DMARC1; p=reject; pct=200").unwrap();
        assert_eq!(r.pct, None);
        let r = parse_dmarc("v=DMARC1; p=reject; pct=garbage").unwrap();
        assert_eq!(r.pct, None);
    }

    #[test]
    fn parse_dmarc_tolerates_unknown_tags_and_whitespace() {
        let r = parse_dmarc("v=DMARC1 ;  p=reject ; xyz=abc ;  pct=50").unwrap();
        assert_eq!(r.policy.as_deref(), Some("reject"));
        assert_eq!(r.pct, Some(50));
    }

    #[test]
    fn parse_dmarc_min_record_just_v_and_p() {
        let r = parse_dmarc("v=DMARC1; p=none").unwrap();
        assert_eq!(r.policy.as_deref(), Some("none"));
        assert_eq!(r.subdomain_policy, None);
        assert!(r.rua.is_empty());
    }

    #[test]
    fn parse_dmarc_p_quarantine_recognized() {
        let r = parse_dmarc("v=DMARC1; p=quarantine; sp=reject").unwrap();
        assert_eq!(r.policy.as_deref(), Some("quarantine"));
        assert_eq!(r.subdomain_policy.as_deref(), Some("reject"));
    }

    #[test]
    fn max_spf_includes_matches_rfc() {
        assert_eq!(
            MAX_SPF_INCLUDES, 10,
            "RFC 7208 §4.6.4 mandates 10-lookup limit"
        );
    }

    /// Adversarial: SPF record with empty include domain must not panic.
    #[test]
    fn parse_spf_includes_handles_empty_include() {
        let includes = parse_spf_includes("v=spf1 +include: -all");
        assert!(includes.iter().any(|s| s.is_empty()));
    }

    proptest! {
        /// Property: `parse_dmarc` never panics for arbitrary input.
        #[test]
        fn parse_dmarc_never_panics(record in ".*") {
            let _ = parse_dmarc(&record);
        }

        /// Property: `parse_dmarc` only returns Some when the record starts
        /// with a DMARC1 version tag (case-insensitive).
        #[test]
        fn parse_dmarc_some_iff_dmarc1(record in ".{0,512}") {
            let result = parse_dmarc(&record);
            let is_dmarc = record.trim().len() >= 8
                && record.trim().chars().take(8).collect::<String>()
                    .eq_ignore_ascii_case("v=dmarc1");
            prop_assert_eq!(result.is_some(), is_dmarc);
        }

        /// Property: `analyze_dmarc` never panics.
        #[test]
        fn analyze_dmarc_never_panics(record in ".*") {
            let _ = analyze_dmarc(&record);
        }

        /// Property: `parse_spf_includes` never panics.
        #[test]
        fn parse_spf_includes_never_panics(record in ".*") {
            let _ = parse_spf_includes(&record);
        }

        /// Property: `identify_email_services` never panics.
        #[test]
        fn identify_email_services_never_panics(
            includes in prop::collection::vec(".*", 0..20)
        ) {
            let _ = identify_email_services(&includes);
        }
    }

    #[test]
    fn spf_all_classification_missing_all() {
        // No `all` mechanism: implicit +all per RFC 7208.
        assert_eq!(
            spf_all_classification("v=spf1 ip4:1.2.3.4 include:_spf.google.com"),
            SpfAllClass::Missing
        );
    }

    #[test]
    fn spf_all_classification_pass_all() {
        assert_eq!(
            spf_all_classification("v=spf1 ip4:1.2.3.4 +all"),
            SpfAllClass::PassAll
        );
        // Bare `all` is equivalent to `+all`.
        assert_eq!(
            spf_all_classification("v=spf1 all"),
            SpfAllClass::PassAll
        );
    }

    #[test]
    fn spf_all_classification_softfail() {
        assert_eq!(
            spf_all_classification("v=spf1 ip4:1.2.3.4 ~all"),
            SpfAllClass::SoftFail
        );
    }

    #[test]
    fn spf_all_classification_neutral() {
        assert_eq!(
            spf_all_classification("v=spf1 ip4:1.2.3.4 ?all"),
            SpfAllClass::Neutral
        );
    }

    #[test]
    fn spf_all_classification_hardfail() {
        assert_eq!(
            spf_all_classification("v=spf1 ip4:1.2.3.4 -all"),
            SpfAllClass::HardFail
        );
    }

    #[test]
    fn spf_all_classification_substring_in_domain_does_not_false_positive() {
        // `+all` inside a domain name must not match; the record has `-all`
        // as the terminal mechanism.
        assert_eq!(
            spf_all_classification("v=spf1 include:mail+all.example.com -all"),
            SpfAllClass::HardFail
        );
    }
}

/// Parse SPF records to discover third-party services and mail infrastructure.
///
/// SPF `include:` directives reveal which services are authorized to send
/// email for the domain. This exposes:
/// - Email providers (Google Workspace, O365, SendGrid, Mailgun)
/// - Marketing platforms (Mailchimp, HubSpot)
/// - Internal mail servers (custom SPF entries)
pub fn parse_spf_includes(spf_record: &str) -> Vec<String> {
    let mut includes = Vec::new();
    for part in spf_record.split_whitespace() {
        let clean = part
            .trim_start_matches('+')
            .trim_start_matches('-')
            .trim_start_matches('~')
            .trim_start_matches('?');
        if let Some(domain) = clean.strip_prefix("include:") {
            includes.push(domain.to_string());
        } else if let Some(ip_range) = clean.strip_prefix("ip4:") {
            includes.push(format!("ip4:{}", ip_range));
        } else if let Some(ip_range) = clean.strip_prefix("ip6:") {
            includes.push(format!("ip6:{}", ip_range));
        } else if let Some(domain) = clean.strip_prefix("a:") {
            includes.push(domain.to_string());
        } else if let Some(domain) = clean.strip_prefix("mx:") {
            includes.push(domain.to_string());
        }
    }
    includes
}

/// Map SPF includes to known services for intelligence.
pub fn identify_email_services(includes: &[String]) -> Vec<(&'static str, &'static str)> {
    let mut services = Vec::new();
    for inc in includes {
        let lower = inc.to_lowercase();
        if lower.contains("google") || lower.contains("_spf.google") {
            services.push(("Google Workspace", "email"));
        } else if lower.contains("outlook") || lower.contains("protection.outlook") {
            services.push(("Microsoft 365", "email"));
        } else if lower.contains("sendgrid") {
            services.push(("SendGrid", "transactional-email"));
        } else if lower.contains("mailgun") {
            services.push(("Mailgun", "transactional-email"));
        } else if lower.contains("mailchimp") || lower.contains("mandrillapp") {
            services.push(("Mailchimp/Mandrill", "marketing-email"));
        } else if lower.contains("amazonses") {
            services.push(("AWS SES", "transactional-email"));
        } else if lower.contains("hubspot") {
            services.push(("HubSpot", "marketing"));
        } else if lower.contains("zendesk") {
            services.push(("Zendesk", "support"));
        } else if lower.contains("freshdesk") {
            services.push(("Freshdesk", "support"));
        } else if lower.contains("salesforce") {
            services.push(("Salesforce", "crm"));
        }
    }
    services
}
