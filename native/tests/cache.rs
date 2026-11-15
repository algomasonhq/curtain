use curtain_domain_bench::*;
#[test]
fn lru_evicts_least_recent_and_invalidates_generation() {
    let mut c = DecisionCache::new(2);
    assert_eq!(c.get("a", 1), None);
    c.put("a", true, 1);
    c.put("b", false, 1);
    assert_eq!(c.get("a", 1), Some(true));
    c.put("c", true, 1);
    assert_eq!(c.get("b", 1), None);
    assert_eq!(c.len(), 2);
    assert_eq!(c.get("a", 2), None);
    assert_eq!(c.len(), 0);
    for i in 0..10001 {
        c.put(&format!("x{i}"), true, 2);
    }
    assert_eq!(c.len(), 2);
    let mut zero = DecisionCache::new(0);
    zero.put("a", true, 0);
    assert_eq!(zero.get("a", 0), None);
}
