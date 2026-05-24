//! Canonical host / domain normalisation shared across scanners.
//!
//! Before this module the codebase had: two different `normalize_host`
//! implementations inside the `correlation` crate alone (one
//! conservative, one rich), plus `cloud::org_name` and
//! `scm::registrable_org` independently reimplementing PSL
//! registrable-domain → org extraction, plus an ad-hoc
//! `parent_domain` heuristic. They are unified here so every scanner
//! clusters hosts the same way (a divergence directly causes cross-host
//! correlation false positives / negatives).

/// Normalise a host or target string for identity comparison and
/// deduplication.
///
/// Strips scheme, userinfo, path, port (incl. `[::1]:443` bracket
/// form), and a trailing dot; case-folds; and decodes a leading
/// `xn--` punycode label to its unicode form so an IDN and its
/// A-label compare equal.
///
/// This is the *rich* normalisation (formerly only in
/// `correlation::dedup`). The correlation rules previously used a
/// weaker variant; unifying on this one is an intentional behaviour
/// change  -  host clustering is now case/IDN/trailing-dot insensitive
/// everywhere, which removes a class of cross-host FP/FN.
#[must_use]
pub fn normalize_host(target: &str) -> String {
    let mut s = target;

    if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
    }

    // Strip userinfo (user:pass@host).
    if let Some(at) = s.find('@') {
        s = &s[at + 1..];
    }

    // Strip path, then port.
    if let Some(idx) = s.find('/') {
        s = &s[..idx];
    }
    if let Some(idx) = s.rfind(':') {
        if s.starts_with('[') && s.contains("]:") {
            // Bracketed `[v6]:port`  -  strip the port, keep `[v6]`.
            s = &s[..idx];
        } else if s.matches(':').count() == 1
            && s[idx + 1..].chars().all(|c| c.is_ascii_digit())
        {
            // Exactly one colon ⇒ `host:port`. A *bare* IPv6 literal
            // (`2001:db8::1`) has ≥2 colons; without this guard the
            // last hextet `::1` was misread as a port and the address
            // was corrupted to `2001:db8:`, giving the same host two
            // different cluster keys vs its bracketed form and breaking
            // every correlation rule that keys on normalize_host.
            s = &s[..idx];
        }
    }

    let mut out = s.to_lowercase();
    out = out.trim_end_matches('.').to_string();

    // Fold A-labels (`xn--…`) to their U-label form so an IDN and its
    // punycode encoding share one cluster key. This must apply to a
    // `xn--` label in ANY position (`www.xn--…`, `api.xn--brand.com`,
    // IDN TLDs)  -  not only the leading label, which was the original
    // `out.starts_with("xn--")` bug: a non-leading A-label and its
    // U-label produced different keys, the exact cross-host
    // scope/correlation divergence this module exists to remove.
    // `idna::domain_to_unicode` decodes every label of the dotted
    // name. Guarded off IPs and bracketed IPv6 so the bare-IPv6
    // normalisation (and its adversarial test) is preserved  -  those
    // never contain an `xn--` label anyway, but the explicit guard
    // keeps the IDNA pass strictly scoped to real hostnames.
    let looks_ip =
        out.starts_with('[') || out.parse::<std::net::IpAddr>().is_ok();
    if !looks_ip && out.split('.').any(|label| label.starts_with("xn--")) {
        let (decoded, _maybe_err) = idna::domain_to_unicode(&out);
        out = decoded.to_lowercase();
    }

    out
}

/// The registrable ("eTLD+1") domain for `host` per the Mozilla Public
/// Suffix List, or `None` for IPs / unrecognised TLDs / bare labels.
#[must_use]
pub fn registrable(host: &str) -> Option<String> {
    let h = normalize_host(host);
    if h.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let dom = psl::domain(h.as_bytes())?;
    std::str::from_utf8(dom.as_bytes()).ok().map(str::to_string)
}

/// The organisation label of a target  -  the first label of its
/// registrable domain (`shop.example.co.uk` → `example`), falling back
/// to the first label for bare hostnames, and the address itself for
/// IPs. Mirrors the behaviour the `cloud` and `scm` scanners depend on.
#[must_use]
pub fn org_label(input: &str) -> String {
    let host = normalize_host(input);
    if host.is_empty() {
        return host;
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    if let Some(reg) = psl::domain(host.as_bytes()) {
        if let Ok(s) = std::str::from_utf8(reg.as_bytes()) {
            if let Some(label) = s.split('.').next() {
                if !label.is_empty() {
                    return label.to_string();
                }
            }
        }
    }
    host.split('.')
        .next()
        .unwrap_or(&host)
        .to_string()
}

/// Coarse "same blast radius" parent  -  the last two labels of the host.
///
/// Deliberately PSL-unaware: `a.example.co.uk` and `b.example.co.uk`
/// collapse to `co.uk`, which is intentionally broad for the
/// same-target heuristic correlation rules use it for. Callers that
/// need true registrable identity must use [`registrable`].
#[must_use]
pub fn parent_domain(host: &str) -> String {
    let h = normalize_host(host);
    let labels: Vec<&str> = h.split('.').filter(|s| !s.is_empty()).collect();
    if labels.len() < 2 {
        return h;
    }
    labels[labels.len() - 2..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_strips_scheme_userinfo_port_path_and_casefolds() {
        // Behaviour is intentionally identical to the former
        // `correlation::dedup::normalize_host` (first-`@` userinfo
        // split, etc.)  -  this is a behaviour-preserving consolidation,
        // not a rewrite, so the cases asserted here are the ones that
        // helper actually handled.
        assert_eq!(normalize_host("https://user@Example.COM:443/a/b"), "example.com");
        assert_eq!(normalize_host("https://Example.COM/a/b"), "example.com");
        assert_eq!(normalize_host("http://example.com."), "example.com");
        assert_eq!(normalize_host("[::1]:8443"), "[::1]");
        assert_eq!(normalize_host("1.2.3.4:80"), "1.2.3.4");
    }

    #[test]
    fn normalize_decodes_leading_punycode() {
        // xn--mnchen-3ya == münchen
        assert_eq!(normalize_host("xn--mnchen-3ya"), "münchen");
    }

    /// CONTRACT (systemic): the module exists so "an IDN and its
    /// A-label compare equal ... every scanner clusters hosts the same
    /// way (a divergence directly causes cross-host correlation
    /// false positives/negatives)". That MUST hold for an `xn--` label
    /// in ANY position, not only the leading one  -  real IDNs appear as
    /// `www.xn--…`, `api.xn--brand.com`, and IDN TLDs `xn--…`. Pre-fix
    /// the decode was gated on `out.starts_with("xn--")`, so a
    /// non-leading A-label and its U-label produced DIFFERENT cluster
    /// keys  -  the exact scope/correlation divergence this module is
    /// supposed to remove.
    #[test]
    fn normalize_decodes_punycode_in_any_label_position() {
        // Second-label IDN: A-label form must fold to the U-label form.
        assert_eq!(
            normalize_host("www.xn--mnchen-3ya.de"),
            "www.münchen.de"
        );
        assert_eq!(
            normalize_host("https://API.xn--mnchen-3ya.de:443/x"),
            "api.münchen.de"
        );
        // The two encodings of the SAME host MUST share one key.
        assert_eq!(
            normalize_host("www.xn--mnchen-3ya.de"),
            normalize_host("www.münchen.de"),
            "A-label and U-label of a non-leading IDN must cluster equal"
        );
        // IDN TLD (xn-- as the LAST label) also folds.
        assert_eq!(
            normalize_host("shop.xn--mnchen-3ya.xn--mnchen-3ya"),
            "shop.münchen.münchen"
        );
        // Regression guard: pure-ASCII and IP/IPv6 are untouched by the
        // (now unconditional-where-applicable) IDNA step.
        assert_eq!(normalize_host("api.example.com"), "api.example.com");
        assert_eq!(normalize_host("1.2.3.4:80"), "1.2.3.4");
        assert_eq!(normalize_host("[::1]:8443"), "[::1]");
        assert_eq!(normalize_host("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn org_label_uses_registrable_first_label() {
        assert_eq!(org_label("example.com"), "example");
        assert_eq!(org_label("shop.example.co.uk"), "example");
        assert_eq!(org_label("https://api.example.com.br:443/x"), "example");
        assert_eq!(org_label("www.agency.gov.au"), "agency");
        assert_eq!(org_label("localhost"), "localhost");
        assert_eq!(org_label("192.0.2.10"), "192.0.2.10");
        assert_eq!(org_label("cdn.example-site.com"), "example-site");
    }

    #[test]
    fn registrable_handles_etld_and_rejects_ip() {
        assert_eq!(registrable("a.b.example.co.uk").as_deref(), Some("example.co.uk"));
        assert_eq!(registrable("example.com").as_deref(), Some("example.com"));
        assert_eq!(registrable("10.0.0.1"), None);
    }

    #[test]
    fn parent_domain_is_last_two_labels() {
        assert_eq!(parent_domain("a.b.example.com"), "example.com");
        assert_eq!(parent_domain("https://x.example.com:443/p"), "example.com");
        assert_eq!(parent_domain("localhost"), "localhost");
    }

    /// ADVERSARIAL: a bare IPv6 literal must NOT be mangled by the
    /// port-strip heuristic. Pre-fix `normalize_host("2001:db8::1")`
    /// stripped the final `:1` as a "port", yielding the garbage
    /// `"2001:db8:"`  -  a different cluster key from the same host's
    /// bracketed form, which silently breaks cross-host correlation.
    #[test]
    fn normalize_does_not_corrupt_bare_ipv6() {
        for v6 in ["2001:db8::1", "fe80::1", "::1", "2001:4860:4860::8888"] {
            let n = normalize_host(v6);
            assert_eq!(n, v6.to_lowercase(), "bare IPv6 {v6} was corrupted to {n}");
            assert!(
                n.parse::<std::net::Ipv6Addr>().is_ok(),
                "normalized bare IPv6 {v6} -> {n} no longer parses as an address"
            );
        }
        // Case-fold still applies.
        assert_eq!(normalize_host("2001:DB8::1"), "2001:db8::1");
    }

    /// PROVING (negative twin): a real `host:port` with a single colon
    /// still has its port stripped  -  the guard suppresses only the
    /// bare-IPv6 misfire, not legitimate port removal.
    #[test]
    fn normalize_still_strips_real_single_colon_port() {
        assert_eq!(normalize_host("example.com:443"), "example.com");
        assert_eq!(normalize_host("1.2.3.4:8080"), "1.2.3.4");
        assert_eq!(normalize_host("[::1]:8443"), "[::1]");
    }
}
