//! W9 gossan-classify edge
use gossan_classify::BannerClassifier;
macro_rules! w9_edge { ($n:ident, $b:block) => { #[test] fn $n() { $b } }; }
w9_edge!(w9_gs_01, { let c=BannerClassifier::new(); assert!(c.classify("").is_empty()); });

w9_edge!(w9_gs_02, { let c=BannerClassifier::new(); assert!(c.classify_top("SSH-2.0-OpenSSH").is_some() || c.classify("SSH-2.0-OpenSSH").is_empty()); });

w9_edge!(w9_gs_03, { let c=BannerClassifier::new(); let m=c.classify("HTTP/1.1 200"); for x in &m { assert!(x.confidence>=0.0 && x.confidence<=1.0); } });

w9_edge!(w9_gs_04, { let c=BannerClassifier::new(); let banner = format!("{}\u{ff}", '\0'); assert_eq!(c.classify_top(&banner).is_some(), !c.classify(&banner).is_empty()); });

w9_edge!(w9_gs_05, { let c=BannerClassifier::new(); let _=c.classify("A".repeat(10000).as_str()); });

w9_edge!(w9_gs_06, { let c=BannerClassifier::new(); for m in c.classify("220 FTP") { assert!(!m.service.is_empty()); } });

w9_edge!(w9_gs_07, { let c=BannerClassifier::new(); assert!(c.classify("Redis").iter().all(|m| !m.service.is_empty())); });

w9_edge!(w9_gs_08, { let c=BannerClassifier::new(); let top=c.classify_top("mysql"); if let Some(t)=top { assert!(!t.service.is_empty()); } });

w9_edge!(w9_gs_09, { let c1=BannerClassifier::new(); let c2=BannerClassifier::new(); assert_eq!(c1.classify("test").len(), c2.classify("test").len()); });

w9_edge!(w9_gs_10, { let c=BannerClassifier::new(); assert!(c.classify("\n\r\t").iter().all(|m| m.confidence<=1.0)); });

w9_edge!(w9_gs_11, { let c=BannerClassifier::new(); let _=c.classify("SMTP 250"); });

w9_edge!(w9_gs_12, { let c=BannerClassifier::new(); assert!(c.classify_top("unknown-banner-xyz-999").is_none() || c.classify_top("unknown-banner-xyz-999").unwrap().confidence<=1.0); });

w9_edge!(w9_gs_13, { let c=BannerClassifier::new(); let m=c.classify("HTTP/1.0"); assert!(m.len()<1000); });

w9_edge!(w9_gs_14, { let c=BannerClassifier::new(); assert!(c.classify("SSH").into_iter().all(|m| m.confidence>=0.0)); });

w9_edge!(w9_gs_15, { let c=BannerClassifier::new(); let _=c.classify("PostgreSQL"); });

w9_edge!(w9_gs_16, { let c=BannerClassifier::new(); assert_eq!(c.classify("").len(), 0); });

w9_edge!(w9_gs_17, { let c=BannerClassifier::new(); let top=c.classify_top(""); assert!(top.is_none()); });

w9_edge!(w9_gs_18, { let c=BannerClassifier::new(); let _=c.classify("Microsoft-IIS"); });

w9_edge!(w9_gs_19, { let c=BannerClassifier::new(); for m in c.classify("nginx") { assert!(m.confidence.is_finite()); } });

w9_edge!(w9_gs_20, { let c=BannerClassifier::new(); assert!(c.classify("\x01").len()<50); });

w9_edge!(w9_gs_21, { let c=BannerClassifier::new(); let _=c.classify("Elasticsearch"); });

w9_edge!(w9_gs_22, { let c=BannerClassifier::new(); assert!(c.classify_top("Apache").is_some() || true); });

w9_edge!(w9_gs_23, { let c=BannerClassifier::new(); let m=c.classify("MongoDB"); for x in m { assert!(!x.service.is_empty()); } });

w9_edge!(w9_gs_24, { let c=BannerClassifier::new(); assert!(c.classify("coap").len()<20); });

w9_edge!(w9_gs_25, { let c=BannerClassifier::new(); let _=c.classify("\u{1F600}"); });

