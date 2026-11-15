/// Independent specification: full rule scan, no reversed keys or ancestor lookups.
pub fn oracle(host: &str, rules: &[(String, bool)], allow: &[(String, bool)]) -> bool {
    let matches = |(rule, suffix): &(String, bool)| {
        host == rule
            || (*suffix
                && host
                    .strip_suffix(rule)
                    .is_some_and(|prefix| prefix.ends_with('.')))
    };
    !allow.iter().any(matches) && rules.iter().any(matches)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_linear_oracle() {
        let b = vec![("ads.example".into(), true), ("exact.test".into(), false)];
        let a = vec![("ok.ads.example".into(), false)];
        assert!(oracle("x.ads.example", &b, &a));
        assert!(!oracle("notads.example", &b, &a));
        assert!(!oracle("ok.ads.example", &b, &a));
        assert!(oracle("x.ok.ads.example", &b, &a));
        assert!(!oracle("x.exact.test", &b, &a));
    }
}
