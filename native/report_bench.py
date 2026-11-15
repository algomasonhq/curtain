#!/usr/bin/env python3
"""Validate real benchmark artifacts and generate the report; no fabricated data."""
import hashlib
import json
import platform
import subprocess
from pathlib import Path

root = Path(__file__).resolve().parent
out = root.parent/'reports'
out.mkdir(exist_ok=True)
results = [json.loads((root/'evidence'/f'{k}.json').read_text()) for k in ('sorted','hash')]
processes = [json.loads((root/'evidence'/f'{k}-process.json').read_text()) for k in ('sorted','hash')]
assert all(p['exit_code'] == 0 for p in processes)
for r in results:
    assert r['source_lines'] == r['accepted_unique'] + r['rejected_lines']
    assert r['source_membership_checks'] == r['accepted_unique']
    assert len(r['workloads']) == 12
    for w in r['workloads']:
        assert len(w['raw_batch_mean_ns']) == w['batches'] == 32
        assert w['measured_queries'] == w['batch_size'] * 32
        assert w['batch_size'] >= 65536
        assert abs(sum(w['raw_batch_mean_ns'])/32-w['mean_ns']) < 1e-6
        assert w['batch_mean_p95_ns'] == sorted(w['raw_batch_mean_ns'])[30]
        assert w['blocked_per_sequence'] == (0 if w['name'] in ('miss','allowlist') else w['sequence_len'])
for a,b in zip(results[0]['workloads'],results[1]['workloads']):
    for field in ('name','cache','sequence_len','distinct_queries','blocked_per_sequence','measured_queries'):
        assert a[field] == b[field]
corpus=root.parent/'data/blocklists/domains.experimental.txt'
h=hashlib.sha256()
with corpus.open('rb') as f:
    for block in iter(lambda:f.read(1024*1024),b''):
        h.update(block)
metadata={'corpus':str(corpus),'corpus_bytes':corpus.stat().st_size,'corpus_sha256':h.hexdigest(),'rustc':subprocess.check_output(['rustc','-Vv'],text=True),'platform':platform.platform(),'cpu':next(l.split(':',1)[1].strip() for l in Path('/proc/cpuinfo').read_text().splitlines() if l.startswith('model name')),'executable_bytes':(root/'target/release/curtain-domain-bench').stat().st_size,'independent_oracle':'96 queries per index against linear full-corpus rule scan','equivalence':'All workload decisions asserted homogeneous by classification, with cache/uncached equality per query; counts and sequence dimensions agree across indexes.'}
(root/'evidence/metadata.json').write_text(json.dumps(metadata,indent=2)+'\n')
(out/'domain-benchmark-results.json').write_text(json.dumps({'metadata':metadata,'results':results,'processes':processes},indent=2)+'\n')
lines=['# Curtain native domain benchmark — experimental suffix policy','',f"Host: {metadata['cpu']}; {metadata['platform']}. Rust: {metadata['rustc'].splitlines()[0]}.",'',f"Corpus: `{corpus}`; {metadata['corpus_bytes']:,} bytes; SHA-256 `{metadata['corpus_sha256']}`.",f"Both indexes loaded all {results[0]['accepted_unique']:,} source entries, rejected {results[0]['rejected_lines']}, and verified exact membership of every entry.",'','## Build and memory','','| Index | Normalize/load/sort s | Index build s | Exact membership verification s | Index payload/estimate MiB | Child peak RSS MiB | RSS after dropping source MiB | Process wall s |','|---|---:|---:|---:|---:|---:|---:|---:|']
for r,p in zip(results,processes):
    lines.append(f"| {r['index']} | {r['load_normalize_sort_s']:.3f} | {r['build_s']:.3f} | {r['membership_s']:.3f} | {r['compiled_payload_bytes']/2**20:.2f} | {p['peak_rss_kib']/1024:.2f} | {r['after_drop_source_rss_kib']/1024:.2f} | {p['wall_s']:.3f} |")
lines += ['',f"Executable: {metadata['executable_bytes']:,} bytes (release with debug=1, unstripped). Compiler output: `native/evidence/release-build.txt`.",'','Packed payload is exactly byte arena + u32 ends + bool flags (including 512 allow rules); excludes Vec headers/allocator metadata. Hash payload is an estimate: owned key lengths + capacity × (size_of<(String,bool)> + 1 control byte); excludes allocator overhead, table padding and unused string capacity. No serialized index artifact or Android size claim. RSS is measured in separate Linux child processes via wait4 ru_maxrss and /proc/self/status. Peak includes loading, source strings, sorting and verification. Dropped-source RSS retains allocator pages and is NOT isolated index live memory; current RSS and ru_maxrss are different kernel observations. Cache allocation is included in process peak but not index footprint.','', '## Lookup results','','Times are batch-average ns/query, not individual query latency percentiles. Mq/s = million decisions/sec.','', '| Index | Workload | Cache | Mean ns | Batch mean p50 ns | Batch mean p95 ns | Mq/s | Cache hit % |','|---|---|---|---:|---:|---:|---:|---:|']
for r in results:
    for w in r['workloads']:
        lines.append(f"| {r['index']} | {w['name']} | {w['cache']} | {w['mean_ns']:.1f} | {w['batch_mean_p50_ns']:.1f} | {w['batch_mean_p95_ns']:.1f} | {w['queries_per_s']/1e6:.3f} | {100*w['cache_hits']/w['measured_queries']:.2f} |")
lines += ['','## Method and correctness','','* Std-only Rust. Immutable sorted index packs reversed ASCII bytes into one contiguous arena and uses binary search with a stack query buffer. Each hostname ancestor is searched at DNS label boundaries; exact flags do not inherit. Chosen over a per-label heap-map trie to avoid millions of allocations. No giant naive tree. u32 arena offsets impose a checked 4GiB limit.','* Hash index uses std HashMap<String,bool> with randomized default hashing. Exact and suffix flags are distinct; allow rules are evaluated first. A suffix rule includes itself and descendants. Inputs to indexes must already be normalized, unique ASCII hostnames; duplicate rule conflict resolution is intentionally an ingestion concern. The harness normalizes/sorts/deduplicates.','* Normalization lowercases ASCII, permits one root dot, checks nonempty 1–63 byte LDH labels and total length ≤253, rejects Unicode, underscores, URL syntax and IP literals. ASCII xn-- labels are syntax-validated only: no punycode decoding, IDNA2008 semantic validation, PSL or Unicode conversion. Caller must supply A-labels, not U-labels.','* Raw source rule semantics remain unresolved: every corpus row is EXPERIMENTALLY treated as a suffix-block rule, not a faithful source-policy import. Allowlist rules and probe queries are constructed benchmark fixtures over real source domains, not real user allowlist data. No synthetic million-rule substitute.','* All source entries checked for exact membership in both indexes. Each index also passed 96 distributed workload queries against an independent full-corpus linear ends_with/boundary oracle (not its own lookup algorithm). Oracle is sampled, not exhaustive for all possible subdomains. Every benchmark query was classified as expected (all hit/subdomain/hotset/scan block, all miss/allowlist allow), giving exhaustive per-sequence outcome equivalence across both indexes; cached paths were separately compared per query.','* Workloads: 16,384 distributed real hits; 16,384 reserved .invalid misses; corresponding probe subdomains; 512 explicit safe subdomain exceptions; 262,144-query ~90% hot-512 / ~10% rotating real-domain scan (16,384 distinct keys, exceeds cache); 65,536-key scan. Selection is deterministic, not DNS traffic capture.','* One warmup batch then 32 measured batches of ≥65,536 queries per arm. Cache persists between batches; no per-query clock. std::hint::black_box keeps inputs/results observable. JSON retains every measured batch mean. p50 is upper median (sorted sample index 16), p95 is nearest-rank index 30 of 32. These are percentiles of batch means, NOT nanosecond individual lookup percentiles.','* Normalization/ingestion is outside lookup timing; library lookups require prevalidated input. Index source checks and oracle verification are also untimed. Fixed workload/cache/index order, one run per index, no CPU pinning or thermal control; randomized hash seed and CPU frequency noise affect results. This is not a statistically controlled Android comparison.','* Cache is single-thread only, capacity 10,000, HashMap plus BTreeMap true recency (O(log n), duplicated owned keys, no unbounded stale queue). Generation change clears all entries; caller must supply a new generation for every policy replacement. No production synchronization/atomic snapshot integration. Tests cover recency eviction, boundedness, zero capacity and generation changes.','', '## Interpretation and limitations','','The 10k LRU is not an assumed optimization: compare the actual rows. It can help the packed index on a hotset but adds overhead to cheap hash lookups and thrashing scans; it is not guaranteed to improve performance. The hash index trades considerably more memory for lookup speed on this host. Neither desktop results nor allocator RSS establish suitability for Pixel 4a. No Android device was attached; no APK, VPN packet path, concurrency, DNS parser, HTTPS filtering or end-to-end battery/latency work was attempted.','', '## Reproduce and evidence','','Run from `native`:','```sh','cargo test','cargo fmt --check','cargo clippy --all-targets -- -D warnings','cargo build --release','python3 run_bench.py','python3 report_bench.py','```','','`run_bench.py` invokes the following in separate processes and records wait4 resource usage:','```sh','target/release/curtain-domain-bench sorted ../data/blocklists/domains.experimental.txt','target/release/curtain-domain-bench hash ../data/blocklists/domains.experimental.txt','```','','Tests/fmt/clippy passed; exact output in `native/evidence/07-batches-green.txt`, `fmt.txt`, `clippy.txt`. Strict vertical TDD evidence is retained as successive red/green logs: normalization; rule-kind/allow precedence; LRU; independent oracle; workload generation; mixed scan exceeding LRU; sufficient batch lengths. Each red log shows an actual assertion failure before implementation. `/usr/bin/time` was absent (retained failure log), so resource measurement uses Python wait4. The workspace has no enclosing Git repository; no commit or baseline diff was possible.','',f"Machine-readable combined results: `{out/'domain-benchmark-results.json'}`."]
(out/'domain-benchmark.md').write_text('\n'.join(lines)+'\n')
print('Verified report:',out/'domain-benchmark.md')
print('Verified JSON:',out/'domain-benchmark-results.json')
print('Test log:',(root/'evidence/07-batches-green.txt').read_text())
print('Clippy log:',(root/'evidence/clippy.txt').read_text())
print('Build log:',(root/'evidence/release-build.txt').read_text())
for r in results:
    print(r['index'], 'build_s',r['build_s'],'payload_MiB',r['compiled_payload_bytes']/2**20)
    for w in r['workloads']:
        print(w['name'],w['cache'],round(w['mean_ns'],1),round(w['queries_per_s']/1e6,3),'cache_hit_pct',round(100*w['cache_hits']/w['measured_queries'],2))
