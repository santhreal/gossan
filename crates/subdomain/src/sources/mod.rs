//! Subdomain source trait and registry.

pub mod common;
pub use common::*;

macro_rules! source_mods {
    ($($name:ident),+ $(,)?) => {
        $(pub mod $name;)+
    };
}

source_mods! {
    alienvault, amazon_ct, anubis, apple_ct, ask, asn, baidu, bevigil, binaryedge, bing, bufferover, builtwith, c99, censys, certspotter, chaos, circl, cloudflare_ct, columbus, commoncrawl, crobat, ct, digicert_ct, digitorus, dnsdumpster, dnslytics, dnsrepo, duckduckgo, entrust_ct, exalead, facebook_ct, farsight_dnsdb, fofa, fullhunt, github, godaddy_ct, google, google_ct, greynoise, hackertarget, hackertarget_dns, hunter, identrust_ct, intelx, ipinfo, jter, leakix, mnemonic, netlas, omnisint, passivetotal, pastebin, ptrarchive, pugrecon, quake, rapiddns, riddler, robtex, rook, sectigo_ct, securitytrails, shodan, sitedossier, sonarsearch, spyse, subdomaincenter, sublist3r, synapsint, threatbook, threatcrowd, threatminer, urlscan, viewdns, virustotal, wayback, whoisxml, yahoo, yandex, zone_walk, zoomeye
}

use async_trait::async_trait;
use gossan_core::{Config, DiscoverySource, Target};
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use std::num::NonZeroU32;

/// Per-source rate limit configuration.
#[derive(Clone, Copy)]
pub struct SourceRate {
    quota: Quota,
}

impl SourceRate {
    /// `n` requests per second.
    pub fn per_second(n: u32) -> Self {
        let nz = NonZeroU32::new(n.max(1)).unwrap_or(NonZeroU32::MIN);
        Self {
            quota: Quota::per_second(nz),
        }
    }

    /// `n` requests per minute.
    pub fn per_minute(n: u32) -> Self {
        let nz = NonZeroU32::new(n.max(1)).unwrap_or(NonZeroU32::MIN);
        Self {
            quota: Quota::per_minute(nz),
        }
    }

    /// Build a `governor` rate limiter from this specification.
    pub fn build_limiter(&self) -> DefaultDirectRateLimiter {
        RateLimiter::direct(self.quota)
    }
}

/// Every passive subdomain source implements this trait.
#[async_trait]
pub trait SubdomainSource: Send + Sync {
    /// Stable source identifier.
    fn name(&self) -> &'static str;

    /// Whether this source needs an API key to function.
    fn requires_api_key(&self) -> bool;

    /// Environment variable / config key name for the API key.
    fn api_key_name(&self) -> &'static str;

    /// Documented rate limit for this source.
    fn rate_limit(&self) -> SourceRate;

    /// How targets discovered by this source should be tagged.
    fn discovery_source(&self) -> DiscoverySource;

    /// Query the source for subdomains of `domain`.
    async fn query(
        &self,
        domain: &str,
        config: &Config,
        client: &reqwest::Client,
        limiter: &DefaultDirectRateLimiter,
    ) -> anyhow::Result<Vec<Target>>;
}

/// Registry of all implemented sources.
pub fn all_sources() -> Vec<Box<dyn SubdomainSource>> {
    vec![
        Box::new(alienvault::Alienvault),
        Box::new(amazon_ct::AmazonCt),
        Box::new(anubis::Anubis),
        Box::new(apple_ct::AppleCt),
        Box::new(ask::Ask),
        Box::new(asn::Asn),
        Box::new(baidu::Baidu),
        Box::new(bevigil::Bevigil),
        Box::new(binaryedge::Binaryedge),
        Box::new(bing::Bing),
        Box::new(bufferover::Bufferover),
        Box::new(builtwith::BuiltWith),
        Box::new(c99::C99),
        Box::new(censys::Censys),
        Box::new(certspotter::Certspotter),
        Box::new(chaos::Chaos),
        Box::new(circl::Circl),
        Box::new(cloudflare_ct::CloudflareCt),
        Box::new(columbus::Columbus),
        Box::new(commoncrawl::CommonCrawl),
        Box::new(crobat::Robat),
        Box::new(ct::Ct),
        Box::new(digicert_ct::DigicertCt),
        Box::new(digitorus::Digitorus),
        Box::new(dnsdumpster::DnsDumpster),
        Box::new(dnslytics::Dnslytics),
        Box::new(dnsrepo::Dnsrepo),
        Box::new(duckduckgo::Duckduckgo),
        Box::new(entrust_ct::EntrustCt),
        Box::new(exalead::Exalead),
        Box::new(facebook_ct::FacebookCt),
        Box::new(farsight_dnsdb::FarsightDnsdb),
        Box::new(fofa::Fofa),
        Box::new(fullhunt::Fullhunt),
        Box::new(github::GitHub),
        Box::new(godaddy_ct::GodaddyCt),
        Box::new(google::Google),
        Box::new(google_ct::GoogleCt),
        Box::new(greynoise::Greynoise),
        Box::new(hackertarget::Hackertarget),
        Box::new(hackertarget_dns::HackertargetDns),
        Box::new(hunter::Hunter),
        Box::new(identrust_ct::IdentrustCt),
        Box::new(intelx::IntelX),
        Box::new(ipinfo::Ipinfo),
        Box::new(jter::Jter),
        Box::new(leakix::Leakix),
        Box::new(mnemonic::Mnemonic),
        Box::new(netlas::Netlas),
        Box::new(omnisint::Omnisint),
        Box::new(passivetotal::Passivetotal),
        Box::new(pastebin::Pastebin),
        Box::new(ptrarchive::Ptrarchive),
        Box::new(pugrecon::Pugrecon),
        Box::new(quake::Quake),
        Box::new(rapiddns::Rapiddns),
        Box::new(riddler::Riddler),
        Box::new(robtex::Robtex),
        Box::new(rook::Rook),
        Box::new(sectigo_ct::SectigoCt),
        Box::new(securitytrails::Securitytrails),
        Box::new(shodan::Shodan),
        Box::new(sitedossier::Sitedossier),
        Box::new(sonarsearch::Sonarsearch),
        Box::new(spyse::Spyse),
        Box::new(subdomaincenter::Subdomaincenter),
        Box::new(sublist3r::Sublist3r),
        Box::new(synapsint::Synapsint),
        Box::new(threatbook::Threatbook),
        Box::new(threatcrowd::Threatcrowd),
        Box::new(threatminer::Threatminer),
        Box::new(urlscan::Urlscan),
        Box::new(viewdns::Viewdns),
        Box::new(virustotal::Virustotal),
        Box::new(wayback::Wayback),
        Box::new(whoisxml::Whoisxml),
        Box::new(yahoo::Yahoo),
        Box::new(yandex::Yandex),
        Box::new(zone_walk::ZoneWalk),
        Box::new(zoomeye::Zoomeye),
    ]
}
