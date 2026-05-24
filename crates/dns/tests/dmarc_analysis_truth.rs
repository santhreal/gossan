//! Deep truth tests for `gossan_dns::email` DMARC analysis.
//!
//! `check_dmarc` previously decided email-spoofing posture with raw
//! `rec.contains("p=none")` substring checks while a correct
//! `parse_dmarc` sat unused. That produced THREE compounding wrong
//! findings on real records  -  proven here against the now-parser-based
//! `analyze_dmarc`. A wrong DMARC finding directly misleads a defender
//! about whether their domain is spoofable, so these assert exact
//! posture, not shape. Contract-first; the engine was fixed to satisfy
//! them, never the reverse.

use gossan_dns::email::{analyze_dmarc, parse_dmarc, DmarcIssue};

fn issues(rec: &str) -> Vec<DmarcIssue> {
    analyze_dmarc(rec)
}

// ───────────────────────── parser exactness ──────────────────────────

#[test]
fn parse_dmarc_extracts_every_tag_exactly() {
    let r = parse_dmarc("v=DMARC1; p=reject; sp=none; pct=100; rua=mailto:agg@x.com,mailto:b@y.com; ruf=mailto:f@x.com; adkim=s; aspf=r")
        .expect("valid DMARC record must parse");
    assert_eq!(r.policy.as_deref(), Some("reject"));
    assert_eq!(r.subdomain_policy.as_deref(), Some("none"));
    assert_eq!(r.pct, Some(100));
    assert_eq!(
        r.rua,
        vec!["mailto:agg@x.com".to_string(), "mailto:b@y.com".to_string()]
    );
    assert_eq!(r.ruf, vec!["mailto:f@x.com".to_string()]);
    assert_eq!(r.adkim.as_deref(), Some("s"));
    assert_eq!(r.aspf.as_deref(), Some("r"));
    assert!(parse_dmarc("not a dmarc record").is_none());
    assert!(parse_dmarc("").is_none());
    // pct out of range is rejected (not clamped to a wrong number).
    assert_eq!(parse_dmarc("v=DMARC1; p=none; pct=250").unwrap().pct, None);
}

// ───────── DEFECT 1+3: `sp=none` must not be read as `p=none` ──────────

/// THE headline bug. `"sp=none"` contains the substring `"p=none"`, so
/// the old code reported a STRONG `p=reject; sp=none` domain as "DMARC
/// p=none (monitor only)  -  spoofing unmitigated" (false, alarming) AND
/// simultaneously suppressed the *real* `sp=none` subdomain risk. The
/// parser-based analysis must do the exact opposite.
#[test]
fn reject_with_sp_none_is_not_policy_none_and_flags_the_real_risk() {
    let got = issues("v=DMARC1; p=reject; sp=none");
    assert!(
        !got.contains(&DmarcIssue::PolicyNone),
        "p=reject MUST NOT be reported as p=none (the `sp=none` substring \
         bug); got {got:?}"
    );
    assert!(
        got.contains(&DmarcIssue::SubdomainSpoofable),
        "sp=none IS a real subdomain-spoofing risk and must be reported \
         (it was masked by the substring bug); got {got:?}"
    );
    assert!(
        got.contains(&DmarcIssue::SubdomainWeakerThanMain),
        "sp=none under p=reject is an explicit weaker-subdomain finding; \
         got {got:?}"
    );
}

/// DEFECT 3 / RFC 7489 §6.3: a clean `p=reject` with NO `sp` protects
/// subdomains by inheritance  -  it must produce NO findings at all (the
/// old code emitted a spurious "missing sp=reject").
#[test]
fn reject_without_sp_is_clean_subdomains_inherit() {
    assert_eq!(
        issues("v=DMARC1; p=reject"),
        Vec::<DmarcIssue>::new(),
        "p=reject with no sp is fully protected (subdomains inherit \
         reject)  -  zero findings"
    );
    assert_eq!(
        issues("v=DMARC1; p=reject; pct=100; rua=mailto:x@y.com"),
        Vec::<DmarcIssue>::new(),
        "report URIs / pct do not weaken a p=reject posture"
    );
}

// ─────────── DEFECT 2: `p=quarantine` substring via `sp=` ─────────────

#[test]
fn quarantine_classification_is_exact() {
    // p=quarantine, no sp → quarantine inherits to subdomains (not
    // spoofable), single finding.
    assert_eq!(
        issues("v=DMARC1; p=quarantine"),
        vec![DmarcIssue::PolicyQuarantine]
    );
    // p=reject; sp=quarantine → main is strong; subdomain explicitly
    // weaker than main, but quarantine still enforces (not spoofable).
    let got = issues("v=DMARC1; p=reject; sp=quarantine");
    assert!(!got.contains(&DmarcIssue::PolicyNone));
    assert!(!got.contains(&DmarcIssue::PolicyQuarantine),
        "main policy is reject, not quarantine; got {got:?}");
    assert!(!got.contains(&DmarcIssue::SubdomainSpoofable),
        "sp=quarantine still enforces  -  not spoofable; got {got:?}");
    assert_eq!(got, vec![DmarcIssue::SubdomainWeakerThanMain]);
}

// ─────────────────────── p=none / missing ────────────────────────────

#[test]
fn none_and_missing_are_reported() {
    let none = issues("v=DMARC1; p=none");
    assert!(none.contains(&DmarcIssue::PolicyNone));
    assert!(
        none.contains(&DmarcIssue::SubdomainSpoofable),
        "p=none inherits to subdomains → spoofable; got {none:?}"
    );
    assert_eq!(issues("v=spf1 -all"), vec![DmarcIssue::Missing]);
    assert_eq!(issues(""), vec![DmarcIssue::Missing]);
    // A v=DMARC1 with no p= at all is not enforced.
    assert!(issues("v=DMARC1; rua=mailto:x@y.com").contains(&DmarcIssue::PolicyNone));
}

// ─────────────────────── adversarial precision ───────────────────────

/// The exact input that the old substring check mis-graded: `p=none`
/// appears INSIDE the `rua` mailto value. Parser-based analysis must
/// read the real policy (`reject`) and emit nothing.
#[test]
fn p_none_inside_rua_value_does_not_fabricate_policy_none() {
    let got = issues("v=DMARC1; p=reject; rua=mailto:p=none@reports.example.com");
    assert_eq!(
        got,
        Vec::<DmarcIssue>::new(),
        "a `p=none` substring inside a report URI must NOT be read as the \
         policy  -  parser, not substring; got {got:?}"
    );
}

/// RFC 7489: policy tag VALUES are case-insensitive. `p=Reject` is a
/// valid strong policy and must not be mis-graded as unenforced.
#[test]
fn policy_values_are_case_insensitive() {
    assert_eq!(
        issues("v=DMARC1; p=Reject; sp=REJECT"),
        Vec::<DmarcIssue>::new(),
        "upper/mixed-case reject is still reject"
    );
    assert!(issues("v=DMARC1; p=NONE").contains(&DmarcIssue::PolicyNone));
}
