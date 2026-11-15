use curtain_domain_bench::compact::{View, encode};
#[test]
fn canonical_preserves_types_and_rejects_bad_rows() {
    use curtain_domain_bench::compact::parse_row;
    assert_eq!(
        parse_row("exact\ta.example\tabc\n").unwrap(),
        ("a.example", 1)
    );
    assert_eq!(
        parse_row("suffix\ta.example\tabc\n").unwrap(),
        ("a.example", 2)
    );
    for line in [
        "regex\ta.example\tabc",
        "exact\tA.example\tabc",
        "exact\ta.example",
        "exact\ta.example\tx\ty",
    ] {
        assert!(parse_row(line).is_err());
    }
}
#[test]
fn label_boundaries_overlap_allow_precedence_and_subdomains() {
    let bytes = encode(&[
        ("a.example", 3),
        ("b.example", 4),
        ("ok.a.example", 8),
        ("safe.a.example", 16),
    ])
    .unwrap();
    let v = View::new(&bytes).unwrap();
    for host in ["a.example", "x.a.example", "x.b.example", "x.ok.a.example"] {
        assert!(v.blocked(host), "{host}");
    }
    for host in [
        "nota.example",
        "b.example",
        "ok.a.example",
        "safe.a.example",
        "x.safe.a.example",
    ] {
        assert!(!v.blocked(host), "{host}");
    }
}
#[test]
fn multiblock_empty_and_normalization_contract() {
    assert_eq!(View::new(&encode(&[]).unwrap()).unwrap().count(), 0);
    let keys: Vec<_> = (0..129).map(|i| format!("a{i:04}.example")).collect();
    let rules: Vec<_> = keys.iter().map(|s| (s.as_str(), 1)).collect();
    let bytes = encode(&rules).unwrap();
    let v = View::new(&bytes).unwrap();
    for s in &keys {
        assert_eq!(v.flags(s), 1);
    }
    for bad in ["é.example", "A.example", "a..b", "127.0.0.1", "a.example."] {
        assert!(encode(&[(bad, 1)]).is_err());
    }
    assert!(encode(&[("xn--bcher-kva.example", 1)]).is_ok());
    // Syntax-only A-label contract: no Unicode conversion or punycode validation here.
    assert!(encode(&[("xn--a.example", 1)]).is_ok());
    let longest = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert!(encode(&[(&longest, 1)]).is_ok());
    assert!(encode(&[(&format!("{longest}x"), 1)]).is_err());
}

#[test]
fn rechecksummed_malformed_structure_is_rejected_without_panics() {
    use sha2::{Digest, Sha256};
    let original = encode(&[("a.example", 1), ("b.example", 2)]).unwrap();
    let rehash = |bytes: &mut Vec<u8>| {
        let mut hasher = Sha256::new();
        hasher.update(&bytes[..32]);
        hasher.update(&bytes[64..]);
        bytes[32..64].copy_from_slice(&hasher.finalize());
    };
    for (position, value) in [
        (64, 255),
        (72, 1),
        (73, 254),
        (74, 0),
        (75, b'A'),
        (72 + 3 + 9, 254),
    ] {
        let mut bytes = original.clone();
        bytes[position] = value;
        rehash(&mut bytes);
        assert!(
            View::new(&bytes).is_err(),
            "accepted malformed byte {position}"
        );
    }
    for position in [8, 16, 24] {
        let mut bytes = original.clone();
        bytes[position..position + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        rehash(&mut bytes);
        assert!(View::new(&bytes).is_err());
    }
    // Mutations with a valid checksum may encode a different VALID index; the
    // invariant is bounded parsing (no panic), not rejecting legitimate data.
    for position in 64..original.len() {
        for value in [0, 1, 63, 127, 254, 255] {
            let mut bytes = original.clone();
            bytes[position] = value;
            rehash(&mut bytes);
            let _ = View::new(&bytes);
        }
    }
}
#[test]
fn rejects_corrupt_and_truncated_artifacts() {
    let bytes = encode(&[("a.example", 1), ("b.example", 2)]).unwrap();
    for end in 0..bytes.len() {
        assert!(View::new(&bytes[..end]).is_err(), "accepted length {end}");
    }
    for pos in 0..bytes.len() {
        let mut bad = bytes.clone();
        bad[pos] ^= 0x80;
        assert!(View::new(&bad).is_err(), "accepted mutation {pos}");
    }
}

#[test]
fn roundtrip_semantic_bits() {
    let bytes = encode(&[("a.example", 1), ("b.example", 3)]).unwrap();
    let index = View::new(&bytes).unwrap();
    assert_eq!(index.flags("a.example"), 1);
    assert_eq!(index.flags("b.example"), 3);
    assert_eq!(index.flags("absent.example"), 0);
    assert!(!index.blocked("x.a.example"));
    assert!(index.blocked("x.b.example"));
}
