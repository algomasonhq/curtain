mod cache;
pub mod compact;
pub mod validation;
pub use cache::DecisionCache;
mod index;
pub use index::Index;
/// ASCII DNS hostname syntax only; does not decode or validate IDNA punycode payloads.
pub fn normalize(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return None;
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
    }
    Some(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalize_validates_hostname() {
        assert_eq!(normalize("ExAmple.COM."), Some("example.com".into()));
        assert_eq!(
            normalize("xn--bcher-kva.example"),
            Some("xn--bcher-kva.example".into())
        );
        for s in [
            "",
            ".",
            "a..b",
            "-a.com",
            "a-.com",
            "a_b.com",
            "a/b",
            "é.com",
            "a.com..",
            "127.0.0.1",
            "[::1]",
        ] {
            assert_eq!(normalize(s), None, "{s}");
        }
        assert!(normalize(&format!("{}.com", "x".repeat(64))).is_none());
        assert!(normalize(&vec!["x".repeat(63); 4].join(".")).is_none());
    }
}
