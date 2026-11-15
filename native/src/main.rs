use curtain_domain_bench::{DecisionCache, Index, normalize, validation::oracle};
use std::{
    hint::black_box,
    io::{BufRead, BufReader},
    time::Instant,
};
fn workloads(rules: &[(String, bool)]) -> Vec<(&'static str, Vec<String>)> {
    let n = rules.len().min(16384);
    let hits: Vec<String> = (0..n)
        .map(|i| rules[i * rules.len() / n].0.clone())
        .filter(|s| s.len() <= 240)
        .collect();
    let miss = (0..hits.len())
        .map(|i| format!("miss-{i}.curtain-benchmark.invalid"))
        .collect();
    let sub = hits.iter().map(|s| format!("probe.{s}")).collect();
    let allow = hits
        .iter()
        .take(512)
        .map(|s| format!("safe.{s}"))
        .collect::<Vec<_>>();
    let hot = (0..262144)
        .map(|i| {
            if i % 10 == 0 {
                hits[(i / 10) % hits.len()].clone()
            } else {
                hits[(i * 31) % hits.len().min(512)].clone()
            }
        })
        .collect();
    let scan = (0..rules.len().min(65536))
        .map(|i| rules[i * rules.len() / rules.len().min(65536)].0.clone())
        .collect();
    vec![
        ("hit", hits),
        ("miss", miss),
        ("subdomain", sub),
        ("allowlist", allow),
        ("mixed_hotset_scan", hot),
        ("scan", scan),
    ]
}
fn repetitions(sequence_len: usize) -> usize {
    65536usize.div_ceil(sequence_len).max(1)
}
fn rss_kib() -> usize {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: curtain-domain-bench sorted|hash CORPUS"
    );
    assert!(matches!(args[1].as_str(), "sorted" | "hash"));
    let load = Instant::now();
    let mut rules = Vec::new();
    let mut rejected = 0usize;
    let mut source_lines = 0usize;
    for line in BufReader::new(std::fs::File::open(&args[2]).unwrap()).lines() {
        let line = line.unwrap();
        source_lines += 1;
        if let Some(host) = normalize(&line) {
            rules.push((host, true));
        } else {
            rejected += 1;
        }
    }
    rules.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    rules.dedup_by(|a, b| a.0 == b.0);
    let load_s = load.elapsed().as_secs_f64();
    let work = workloads(&rules);
    let allow: Vec<_> = work[3].1.iter().map(|s| (s.clone(), true)).collect();
    let baseline_rss = rss_kib();
    let start = Instant::now();
    let index = if args[1] == "sorted" {
        Index::sorted(&rules, &allow)
    } else {
        Index::hashed(&rules, &allow)
    };
    let build_s = start.elapsed().as_secs_f64();
    let build_rss = rss_kib();
    let check = Instant::now();
    for (host, _) in &rules {
        assert!(index.contains_block_exact(host), "missing {host}");
    }
    let membership_s = check.elapsed().as_secs_f64();
    // Full linear oracle on distributed samples; independent of both index algorithms.
    let mut oracle_checks = 0;
    for (_, queries) in &work {
        for i in 0..16.min(queries.len()) {
            let q = &queries[i * queries.len() / 16.min(queries.len())];
            assert_eq!(
                index.blocked(q),
                oracle(q, &rules, &allow),
                "oracle mismatch {q}"
            );
            oracle_checks += 1;
        }
    }
    let entries = rules.len();
    drop(rules);
    let retained_rss = rss_kib();
    println!(
        "{{\"index\":\"{}\",\"source_lines\":{},\"accepted_unique\":{},\"rejected_lines\":{},\"load_normalize_sort_s\":{},\"build_s\":{},\"source_membership_checks\":{},\"membership_s\":{},\"linear_oracle_checks\":{},\"compiled_payload_bytes\":{},\"baseline_rss_kib\":{},\"built_rss_kib\":{},\"after_drop_source_rss_kib\":{},\"workloads\":[",
        args[1],
        source_lines,
        entries,
        rejected,
        load_s,
        build_s,
        entries,
        membership_s,
        oracle_checks,
        index.footprint(),
        baseline_rss,
        build_rss,
        retained_rss
    );
    let mut first = true;
    for (name, queries) in &work {
        let expected: Vec<_> = queries.iter().map(|q| index.blocked(q)).collect();
        let want = !matches!(*name, "miss" | "allowlist");
        assert!(
            expected.iter().all(|&v| v == want),
            "workload classification {name}"
        );
        let distinct_queries = queries
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        let blocked_count = expected.iter().filter(|&&x| x).count();
        let repeat = repetitions(queries.len());
        let batch_size = queries.len() * repeat;
        for cached in [false, true] {
            let mut cache = DecisionCache::new(10000);
            let mut times = Vec::new();
            let mut total = 0;
            let mut sum = 0usize;
            let mut cache_hits = 0usize;
            // 32 full batches, no per-query clocks. Cache persists across batches.
            for batch in 0..33 {
                let start = Instant::now();
                for q in queries.iter().cycle().take(batch_size) {
                    let decision = if cached {
                        if let Some(v) = cache.get(black_box(q), 1) {
                            if batch > 0 {
                                cache_hits += 1;
                            }
                            v
                        } else {
                            let v = index.blocked(black_box(q));
                            cache.put(q, v, 1);
                            v
                        }
                    } else {
                        index.blocked(black_box(q))
                    };
                    // Equality checked outside timed batches below; keep result observable.
                    sum = sum.wrapping_add(black_box(decision) as usize);
                }
                let elapsed = start.elapsed().as_nanos() as u64;
                if batch > 0 {
                    times.push(elapsed as f64 / batch_size as f64);
                    total += elapsed;
                }
            }
            black_box(sum);
            // Exhaustive workload equivalence for cached path, untimed.
            for (q, want) in queries.iter().zip(&expected) {
                let got = if cached {
                    cache.get(q, 1).unwrap_or_else(|| {
                        let v = index.blocked(q);
                        cache.put(q, v, 1);
                        v
                    })
                } else {
                    index.blocked(q)
                };
                assert_eq!(got, *want);
            }
            let raw_batch_mean_ns = times.clone();
            times.sort_by(f64::total_cmp);
            let count = batch_size * 32;
            if !first {
                println!(",");
            }
            first = false;
            print!(
                "{{\"name\":\"{name}\",\"cache\":{cached},\"sequence_len\":{},\"distinct_queries\":{distinct_queries},\"blocked_per_sequence\":{blocked_count},\"measured_queries\":{count},\"batch_size\":{},\"batches\":32,\"mean_ns\":{},\"batch_mean_p50_ns\":{},\"batch_mean_p95_ns\":{},\"queries_per_s\":{},\"cache_hits\":{cache_hits},\"raw_batch_mean_ns\":{raw_batch_mean_ns:?}}}",
                queries.len(),
                batch_size,
                total as f64 / count as f64,
                times[16],
                times[30],
                count as f64 / (total as f64 / 1e9)
            );
        }
    }
    println!("]}}");
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mixed_scan_exceeds_cache_capacity() {
        let rules: Vec<_> = (0..20000)
            .map(|i| (format!("r{i}.example"), true))
            .collect();
        let w = workloads(&rules);
        let unique: std::collections::HashSet<_> = w[4].1.iter().collect();
        assert!(
            unique.len() > 10000,
            "mixed scan must not entirely fit in the LRU: {}",
            unique.len()
        );
    }
    #[test]
    fn batches_have_enough_queries() {
        assert_eq!(repetitions(512) * 512, 65536);
        assert_eq!(repetitions(16384) * 16384, 65536);
        assert_eq!(repetitions(262144), 1);
    }
    #[test]
    fn workload_shapes() {
        let w = workloads(&[("ads.example".into(), true)]);
        assert_eq!(w.len(), 6);
        assert_eq!(w[0].0, "hit");
        assert!(w.iter().all(|(_, q)| !q.is_empty()));
        assert_eq!(w[1].1[0], "miss-0.curtain-benchmark.invalid");
        assert_eq!(w[2].1[0], "probe.ads.example");
    }
}
