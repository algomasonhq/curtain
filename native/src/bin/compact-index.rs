//! Host-only compiled-index experiment. All corpus rules are experimental, not enabled policy.
use curtain_domain_bench::{
    Index,
    compact::{Builder, View, parse_row},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::File,
    hint::black_box,
    io::{BufRead, BufReader},
    time::Instant,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn rows(path: &str, mut visit: impl FnMut(&str, u8) -> Result<()>) -> Result<usize> {
    let mut reader = BufReader::new(File::open(path)?);
    let mut line = String::new();
    let mut count = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let (host, flag) = parse_row(&line)?;
        visit(host, flag)?;
        count += 1;
    }
    Ok(count)
}
fn grouped(
    path: &str,
    mut visit: impl FnMut(&str, u8) -> Result<()>,
) -> Result<(usize, usize, [usize; 6])> {
    let mut previous = String::new();
    let mut flags = 0;
    let mut count = 0;
    let mut types = [0; 6];
    let mut emit = |key: &str, f: u8| -> Result<()> {
        visit(key, f)?;
        count += 1;
        for (i, n) in types.iter_mut().enumerate() {
            *n += usize::from(f & (1 << i) != 0);
        }
        Ok(())
    };
    let total = rows(path, |host, flag| {
        if host != previous {
            if !previous.is_empty() {
                if host < previous.as_str() {
                    return Err("canonical not sorted by domain".into());
                }
                emit(&previous, flags)?;
            }
            previous.clear();
            previous.push_str(host);
            flags = 0;
        }
        flags |= flag;
        Ok(())
    })?;
    if !previous.is_empty() {
        emit(&previous, flags)?;
    }
    Ok((total, count, types))
}
fn rss() -> usize {
    status("VmRSS:")
}
fn status(prefix: &str) -> usize {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|s| s.starts_with(prefix))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}
fn map(path: &str) -> Result<memmap2::Mmap> {
    let file = File::open(path)?;
    // SAFETY: CLI requires immutable files for the entire process lifetime. Never
    // truncate/modify a mapped inode; publish replacements by atomic rename.
    // As with all file-backed mmap APIs this cannot protect against a hostile writer.
    Ok(unsafe { memmap2::MmapOptions::new().map(&file)? })
}
fn workloads(path: &str) -> Result<BTreeMap<String, Vec<String>>> {
    let mut work = BTreeMap::new();
    for row in BufReader::new(File::open(path)?).lines() {
        let row = row?;
        let (name, host) = row.split_once('\t').ok_or("bad workload row")?;
        if curtain_domain_bench::normalize(host).as_deref() != Some(host) {
            return Err("workload not normalized".into());
        }
        work.entry(name.to_string())
            .or_insert_with(Vec::new)
            .push(host.to_string());
    }
    Ok(work)
}
fn bench(work: &BTreeMap<String, Vec<String>>, lookup: impl Fn(&str) -> bool) -> Value {
    let mut results = Vec::new();
    for (name, queries) in work {
        let decisions: Vec<u8> = queries.iter().map(|s| u8::from(lookup(s))).collect();
        let expected = decisions.iter().map(|&b| b as usize).sum::<usize>();
        use sha2::{Digest, Sha256};
        let decision_sha256 = format!("{:x}", Sha256::digest(&decisions));
        let mut batches = Vec::new();
        let mut consumed = 0usize;
        let mut elapsed = 0.0;
        let mut n = 0;
        for _ in 0..8 {
            for batch in queries.chunks(1024) {
                let start = Instant::now();
                for host in batch {
                    consumed += usize::from(black_box(lookup(black_box(host))));
                }
                let ns = start.elapsed().as_secs_f64() * 1e9;
                elapsed += ns;
                n += batch.len();
                batches.push(ns / batch.len() as f64);
            }
        }
        assert_eq!(consumed, expected * 8);
        batches.sort_by(f64::total_cmp);
        let percentile = |p: f64| batches[((batches.len() - 1) as f64 * p) as usize];
        results.push(json!({"workload":name,"decision_sha256":decision_sha256,"sequence_length":queries.len(),"distinct_keys":queries.iter().collect::<std::collections::HashSet<_>>().len(),"blocked_per_sequence":expected,"queries":n,"batches":batches.len(),"batch_size_max":1024,"ns_per_query_mean":elapsed/n as f64,"batch_average_ns_p50":percentile(0.50),"batch_average_ns_p95":percentile(0.95),"batch_average_ns_p99":percentile(0.99),"queries_per_second":n as f64/(elapsed/1e9),"decision_cache":false}));
    }
    json!(results)
}
fn source_matches(query: &str, domain: &str, flag: u8) -> (bool, bool) {
    // Independent specification: scan every original source row, compare full
    // names or label-boundary ends_with. No index traversal/ancestor searches.
    let apex = query == domain;
    let descendant = query.strip_suffix(domain).is_some_and(|s| s.ends_with('.'));
    let block = (apex && flag & 3 != 0) || (descendant && flag & 6 != 0);
    let allow = (apex && flag & 24 != 0) || (descendant && flag & 48 != 0);
    (block, allow)
}
fn run() -> Result<Value> {
    let args: Vec<_> = std::env::args().collect();
    let mode=args.get(1).ok_or("usage: compact-index build CANONICAL OUT | verify INDEX CANONICAL QUERIES | mmap INDEX QUERIES | hash|sorted CANONICAL QUERIES")?;
    let path = args.get(2).ok_or("missing input")?;
    let other = args.get(3).ok_or("missing output/workload")?;
    let start = Instant::now();
    let initial = rss();
    if mode == "build" {
        let mut builder = Builder::default();
        let (provenance, domains, types) = grouped(path, |key, flags| {
            builder.push(key, flags)?;
            Ok(())
        })?;
        let encoded = builder.finish();
        // Do not overwrite existing artifacts; snapshots stay reproducible.
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(other)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        return Ok(
            json!({"mode":mode,"seconds":start.elapsed().as_secs_f64(),"provenance_rows":provenance,"domains":domains,"rule_counts_bits":types,"artifact_bytes":encoded.len(),"rss_initial_kib":initial,"rss_end_kib":rss(),"peak_rss_kib":status("VmHWM:")}),
        );
    }
    if mode == "verify" {
        let mapped = map(path)?;
        let index = View::new(&mapped)?;
        let work = workloads(args.get(4).ok_or("missing queries")?)?;
        let mut sampled = Vec::new();
        for queries in work.values() {
            let n = queries.len().min(32);
            for i in 0..n {
                sampled.push(queries[i * queries.len() / n].as_str());
            }
        }
        let mut outcomes = vec![(false, false); sampled.len()];
        let provenance = rows(other, |key, flag| {
            if index.flags(key) & flag == 0 {
                return Err(format!("missing semantic membership {key} {flag}").into());
            }
            for (query, result) in sampled.iter().zip(&mut outcomes) {
                let (b, a) = source_matches(query, key, flag);
                result.0 |= b;
                result.1 |= a;
            }
            Ok(())
        })?;
        let (_, domains, types) = grouped(other, |key, flags| {
            if index.flags(key) != flags {
                return Err("wrong compiled flags".into());
            }
            Ok(())
        })?;
        if domains != index.count() {
            return Err("extra or missing compiled keys".into());
        }
        for (query, (b, a)) in sampled.iter().zip(outcomes) {
            if index.blocked(query) != (b && !a) {
                return Err(format!("oracle mismatch {query}").into());
            }
        }
        return Ok(
            json!({"mode":mode,"seconds":start.elapsed().as_secs_f64(),"all_provenance_memberships":provenance,"all_domain_flags":domains,"rule_counts_bits":types,"independent_linear_source_oracle_queries":sampled.len(),"mismatches":0,"peak_rss_kib":status("VmHWM:")}),
        );
    }
    if mode == "mmap" {
        let mapped = map(path)?;
        let index = View::new(&mapped)?;
        let load = start.elapsed().as_secs_f64();
        let loaded = rss();
        let work = workloads(other)?;
        let results = bench(&work, |s| index.blocked(s));
        return Ok(
            json!({"mode":mode,"load_seconds_including_full_validation":load,"artifact_bytes":mapped.len(),"domains":index.count(),"rss_initial_kib":initial,"rss_loaded_kib":loaded,"rss_after_workload_kib":rss(),"peak_rss_kib":status("VmHWM:"),"workloads":results}),
        );
    }
    if mode != "hash" && mode != "sorted" {
        return Err("unknown mode".into());
    }
    let mut block = Vec::new();
    let mut allow = Vec::new();
    let (provenance, domains, types) = grouped(path, |key, flags| {
        if flags & 36 != 0 {
            return Err("legacy baseline cannot represent subdomains-only".into());
        }
        if flags & 3 != 0 {
            block.push((key.to_string(), flags & 2 != 0));
        }
        if flags & 24 != 0 {
            allow.push((key.to_string(), flags & 16 != 0));
        }
        Ok(())
    })?;
    let index = if mode == "hash" {
        Index::hashed(&block, &allow)
    } else {
        Index::sorted(&block, &allow)
    };
    let footprint = index.footprint();
    drop(block);
    drop(allow);
    let load = start.elapsed().as_secs_f64();
    let loaded = rss();
    let work = workloads(other)?;
    let results = bench(&work, |s| index.blocked(s));
    Ok(
        json!({"mode":mode,"load_and_build_seconds":load,"domains":domains,"provenance_rows":provenance,"rule_counts_bits":types,"payload_estimate_bytes":footprint,"rss_initial_kib":initial,"rss_loaded_kib":loaded,"rss_after_workload_kib":rss(),"peak_rss_kib":status("VmHWM:"),"workloads":results}),
    )
}
fn main() {
    match run() {
        Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
        Err(error) => {
            eprintln!("compact-index: {error}");
            std::process::exit(1);
        }
    }
}
