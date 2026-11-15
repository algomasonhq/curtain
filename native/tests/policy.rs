use curtain_domain_bench::*;
#[test]
fn indexes_respect_rule_kind_and_allow_precedence() {
    let rules = vec![
        ("ads.example".into(), false),
        ("track.example".into(), true),
    ];
    let allow = vec![("safe.track.example".into(), true)];
    for index in [Index::sorted(&rules, &allow), Index::hashed(&rules, &allow)] {
        for (host, want) in [
            ("ads.example", true),
            ("x.ads.example", false),
            ("track.example", true),
            ("x.track.example", true),
            ("nottrack.example", false),
            ("safe.track.example", false),
            ("x.safe.track.example", false),
            ("example", false),
        ] {
            assert_eq!(index.blocked(host), want, "{host}");
        }
        for (host, _) in &rules {
            assert!(index.contains_block_exact(host));
        }
    }
}
