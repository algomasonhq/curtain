#!/usr/bin/env python3
"""Reproduce audited-corpus compact index experiment; never touches source files."""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import platform
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
NATIVE = ROOT / 'native'
EVIDENCE = NATIVE / 'compact-evidence'
CANONICAL = ROOT / 'data/blocklists/canonical.tsv'


def sha(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def queries(target):
    hit, exact, suffix, scan = [], [], [], []
    type_count = [0, 0]
    with CANONICAL.open() as stream:
        rows = (line.rstrip('\n').split('\t') for line in stream)
        for i, (host, group) in enumerate(itertools.groupby(rows, key=lambda row: row[1])):
            kinds = {row[0] for row in group}
            if i % 149 == 0:
                scan.append(host)
            if len(host) <= 230:
                if i % 997 == 0:
                    hit.append(host)
                if 'exact' in kinds and 'suffix' not in kinds:
                    if type_count[0] % 997 == 0:
                        exact.append('probe.deep.' + host)
                    type_count[0] += 1
                if 'suffix' in kinds:
                    if type_count[1] % 997 == 0:
                        suffix.append('probe.deep.' + host)
                    type_count[1] += 1
    miss = []
    for i in range(16384):
        x = (i * 11400714819323198485) & ((1 << 64) - 1)
        labels = [f'q{i:x}', f'r{x:x}', f't{x >> 20:x}'][:1 + i % 3]
        miss.append('.'.join(labels + ['invalid']))
    mixed = [hit[(i // 10) % len(hit)] if i % 10 == 0 else hit[(i * 31) % min(512, len(hit))] for i in range(65536)]
    work = {'hit': hit, 'exact-descendant': exact, 'suffix-descendant': suffix,
            'diverse-miss': miss, 'mixed-hotset-scan': mixed, 'scan': scan}
    with target.open('w') as stream:
        for name, hosts in work.items():
            for host in hosts:
                stream.write(f'{name}\t{host}\n')
    return {name: len(hosts) for name, hosts in work.items()}


def run(args, label):
    command = [str(NATIVE / 'target/release/compact-index'), *map(str, args)]
    started = time.monotonic()
    with (EVIDENCE / f'{label}.json').open('w') as stdout, (EVIDENCE / f'{label}.stderr.txt').open('w') as stderr:
        child = subprocess.Popen(command, stdout=stdout, stderr=stderr)
        _, status, usage = os.wait4(child.pid, 0)
        child.returncode = os.waitstatus_to_exitcode(status)
    (EVIDENCE / f'{label}.process.json').write_text(json.dumps({
        'command': command, 'exit_code': child.returncode,
        'wall_seconds': time.monotonic() - started, 'peak_rss_kib': usage.ru_maxrss,
        'user_seconds': usage.ru_utime, 'system_seconds': usage.ru_stime,
        'minor_faults': usage.ru_minflt, 'major_faults': usage.ru_majflt,
    }, indent=2) + '\n')
    if child.returncode:
        raise RuntimeError(f'{label} failed: {(EVIDENCE / f"{label}.stderr.txt").read_text()}')
    return json.loads((EVIDENCE / f'{label}.json').read_text())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runs', type=int, default=3)
    args = parser.parse_args()
    EVIDENCE.mkdir(exist_ok=True)
    artifact = EVIDENCE / 'audited.fc'
    workload = EVIDENCE / 'queries.tsv'
    if artifact.exists():
        raise SystemExit('Evidence artifact exists; archive the evidence directory before rerunning.')
    started = time.time()
    sizes = queries(workload)
    builds = []
    artifact_hash = None
    for i in range(args.runs):
        output = artifact if i == 0 else EVIDENCE / f'rebuild-{i}.fc'
        builds.append(run(['build', CANONICAL, output], f'build-{i}'))
        hashed = sha(output)
        if artifact_hash is None:
            artifact_hash = hashed
        assert hashed == artifact_hash, 'non-deterministic build'
        if i:
            output.unlink()
    verify = run(['verify', artifact, CANONICAL, workload], 'verify')
    measurements = {mode: [] for mode in ['mmap', 'sorted', 'hash']}
    # Rotate order to reduce order-related bias; each invocation is a fresh process.
    modes = list(measurements)
    for i in range(args.runs):
        for mode in modes[i % len(modes):] + modes[:i % len(modes)]:
            measurements[mode].append(run([mode, artifact if mode == 'mmap' else CANONICAL, workload], f'{mode}-{i}'))
    # All semantic decisions must agree, not merely throughput counters.
    decisions = None
    for mode, runs in measurements.items():
        for result in runs:
            signature = [(w['workload'], w['decision_sha256'], w['blocked_per_sequence'], w['sequence_length']) for w in result['workloads']]
            if decisions is None:
                decisions = signature
            assert signature == decisions, f'decision-count disagreement: {mode}'
    metadata = {
        'canonical_sha256': sha(CANONICAL), 'artifact_sha256': artifact_hash,
        'workloads_sha256': sha(workload), 'binary_sha256': sha(NATIVE / 'target/release/compact-index'),
        'cargo_lock_sha256': sha(NATIVE / 'Cargo.lock'), 'workloads': sizes,
        'sources_sha256': {str(path.relative_to(ROOT)): sha(path) for path in [NATIVE / 'src/compact.rs', NATIVE / 'src/bin/compact-index.rs', NATIVE / 'src/index.rs', NATIVE / 'run_compact.py']},
        'platform': platform.platform(), 'machine': platform.machine(),
        'rustc': subprocess.check_output(['rustc', '-Vv'], text=True),
        'cargo': subprocess.check_output(['cargo', '-V'], text=True),
        'cpu': subprocess.check_output(['lscpu'], text=True),
        'meminfo': Path('/proc/meminfo').read_text(),
        'environment': {key: os.environ.get(key) for key in ['RUSTFLAGS', 'CARGO_BUILD_TARGET']},
        'elapsed_seconds': time.time() - started,
        'builds': builds, 'verification': verify, 'measurements': measurements,
        'method': 'cache off; validation touches all mapped bytes; OS page cache not dropped; warm untimed pass then 8 passes, chunks <=1024; independent fresh processes',
    }
    (ROOT / 'reports/compact-index.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps({'report': 'reports/compact-index.json', 'elapsed_seconds': metadata['elapsed_seconds'], 'verification': verify}, indent=2))


if __name__ == '__main__':
    main()
