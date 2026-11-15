#!/usr/bin/env python3
"""Conservative source-aware blocklist ingestion; never enables a policy."""
import ipaddress
import re
import idna
import argparse
from collections import Counter
import datetime
import hashlib
from html.parser import HTMLParser
import itertools
import json
import os
from pathlib import Path
import subprocess


class FirebogParser(HTMLParser):
    """Read markers from original HTML, not lossy clean-text extraction."""
    def __init__(self):
        super().__init__()
        self.sources = {}
        self.category = None
        self.item = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = attrs.get('class', '').split()
        if tag == 'ul' and 'bdUrlList' in classes:
            self.category = next((c for c in classes if c != 'bdUrlList'), 'unknown')
        if tag == 'li' and self.category:
            self.item = {'category': self.category, 'recommendation': 'not-recommended' if 'bdCross' in classes else 'ticked' if 'bdTick' in classes else 'unmarked', 'html_classes': classes, 'links': []}
        if tag == 'a' and self.item is not None and attrs.get('href'):
            self.item['links'].append(attrs['href'])

    def handle_endtag(self, tag):
        if tag == 'li' and self.item is not None:
            links = self.item.pop('links')
            if links:
                self.item['publisher_url'] = links[0]
                self.sources[links[-1]] = self.item
            self.item = None
        if tag == 'ul':
            self.category = None


def sha256(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def validate_download(path, expected_hash=None):
    actual = sha256(path)
    if expected_hash and actual != expected_hash:
        raise ValueError('SHA256 mismatch against archive manifest')
    # Scan whole file before accepting any domain, not only a header prefix.
    with path.open(encoding='utf-8-sig', errors='strict') as f:
        for number, line in enumerate(f, 1):
            if '\x00' in line or re.search(r'<\s*(?:!doctype|html|head|body|script|title|div|a\s|/html)\b', line, re.I):
                raise ValueError(f'HTML/binary download at line {number}')
            if number <= 20 and re.match(r'\s*(?:access denied|forbidden|not found|HTTP/\d(?:\.\d)?\s+[45]\d\d|[45]\d\d[: ]|bad gateway|service unavailable|internal server error|error[: ]|<\?xml|\{\s*"error")', line, re.I):
                raise ValueError(f'Error download at line {number}')
    return actual


def disk_sort(source, target, root, keys=()):
    subprocess.run(['sort', '-u', '-S', '64M', '-T', str(root), *keys, '-o', str(target), str(source)],
                   env={**os.environ, 'LC_ALL': 'C'}, check=True)


def source_contract(url):
    if url == 'https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt':
        return 'suffix', 'subdomains'
    if url in {f'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/{name}.txt' for name in ('pro', 'nsfw', 'gambling', 'tif')}:
        return 'exact', 'suffix'
    return 'exact', 'subdomains'


def audit(root, report_path=None):
    root = Path(root)
    original = {name: sha256(root/name) for name in ('manifest.json', 'summary.json', 'firebog.html', 'firebog-catalog.txt', 'domains.experimental.txt')}
    rows = json.loads((root/'manifest.json').read_text())
    parser = FirebogParser()
    parser.feed((root/'firebog.html').read_text())
    catalog = {l.strip() for l in (root/'firebog-catalog.txt').read_text().splitlines() if l.strip().startswith(('http://', 'https://'))}
    reconciliation = {'machine_count': len(catalog), 'page_count': len(parser.sources),
                      'machine_only': sorted(catalog-parser.sources.keys()),
                      'page_only': sorted(parser.sources.keys()-catalog),
                      'downloaded_not_machine': sorted(r['url'] for r in rows if r['url'] not in catalog)}
    (root/'normalized').mkdir(exist_ok=True)
    metadata = []
    totals = Counter()
    combined = root/'canonical.unsorted.tsv'
    with combined.open('w') as out, (root/'audit-diagnostics.tsv').open('w') as diag:
        diag.write('source_id\tline\tstatus\toriginal_text_json\n')
        for row in rows:
            url = row['url']
            sid = hashlib.sha256(url.encode()).hexdigest()[:20]
            info = parser.sources.get(url, {'category': 'supplement', 'recommendation': 'not-on-page'})
            categories = [info['category']]
            if any(s in url.lower() for s in ('adult', 'porn', '/nsfw.txt')):
                categories = ['adult']
            elif url.endswith('/gambling.txt'):
                categories = ['gambling']
            elif 'hagezi' in url and url.endswith('/pro.txt'):
                categories = ['ads', 'tracking', 'malware', 'phishing', 'scams']
            elif 'hagezi' in url and url.endswith('/tif.txt'):
                categories = ['malware', 'phishing', 'scams']
            # Reviewed publisher contracts only; a filename is not a format guarantee.
            plain_type, wildcard_type = source_contract(url)
            entry = {'id': sid, 'url': url, 'enabled': False, 'license_review': 'pending',
                     'firebog': info, 'content_categories': categories, 'in_machine_catalog': url in catalog,
                     'plain_domain_semantics': plain_type, 'asterisk_semantics': wildcard_type,
                     'counts': {k: 0 for k in ('lines', 'accepted', 'exceptions', 'rejected', 'unsupported', 'unsupported_exceptions', 'unique', 'duplicates')},
                     'license_evidence': [], 'warnings': []}
            metadata.append(entry)
            if 'file' not in row:
                entry['status'] = 'failed'
                entry['error'] = row.get('error', 'No archive file')
                continue
            path = root/row['file']
            entry['file'] = row['file']
            counts = entry['counts']
            try:
                entry['sha256'] = validate_download(path, row.get('sha256'))
            except (OSError, UnicodeError, ValueError) as exc:
                entry.update(status='failed', error=str(exc))
                continue
            entry['bytes'] = path.stat().st_size
            unsorted = root/'normalized'/f'{sid}.unsorted.tsv'
            normalized = root/'normalized'/f'{sid}.tsv'
            observed = Counter()
            with path.open(encoding='utf-8-sig') as f, unsorted.open('w') as norm:
                for number, line in enumerate(f, 1):
                    counts['lines'] += 1
                    if number <= 200 and re.search(r'licen[cs]|copyright|non-commercial|attribution', line, re.I):
                        entry['license_evidence'].append({'line': number, 'text': line.strip()[:600]})
                    if number <= 20 and 'NOT designed to work with DNS sinkholes' in line:
                        entry['warnings'].append('Lossy upstream adblock-to-domain mirror; original exceptions/context cannot be reconstructed. Quarantine pending upstream review.')
                    for kind, value in parse_line(line, plain_type, wildcard_type):
                        if kind in ('rejected', 'unsupported'):
                            counts[kind] += 1
                            counts['unsupported_exceptions'] += int(kind == 'unsupported' and line.strip().startswith('@@'))
                            diag.write(f'{sid}\t{number}\t{kind}\t{json.dumps(line.rstrip(), ensure_ascii=True)}\n')
                        else:
                            counts['accepted'] += 1
                            counts['exceptions'] += int(kind.startswith('allow-'))
                            observed[kind] += 1
                            norm.write(f'{kind}\t{value}\n')
            disk_sort(unsorted, normalized, root)
            unsorted.unlink()
            with normalized.open() as norm:
                for line in norm:
                    counts['unique'] += 1
                    out.write(line.rstrip('\n') + '\t' + sid + '\n')
            counts['duplicates'] = counts['accepted']-counts['unique']
            entry['normalized_file'] = str(normalized.relative_to(root))
            entry['normalized_sha256'] = sha256(normalized)
            entry['observed_rule_types'] = dict(sorted(observed.items()))
            entry['status'] = 'ok' if counts['accepted'] else 'failed'
            if not counts['accepted']:
                entry['error'] = 'No supported rules; not a usable blocklist'
            totals.update(counts)
            print(f"{sid}: {counts['unique']} unique, {counts['rejected']} rejected, {counts['unsupported']} unsupported", flush=True)
    canonical = root/'canonical.tsv'
    disk_sort(combined, canonical, root, ('-k2,2', '-k1,1', '-k3,3'))
    combined.unlink()
    unique = Counter()
    provenance_rows = 0
    unique_domains = 0
    semantics = 0
    overlap = 0
    allows = []
    # Exceptions are usually tiny. Store only allows, never millions of domains.
    # Build an on-disk allow file too so the exception evidence remains inspectable.
    with canonical.open() as f, (root/'exceptions.tsv').open('w') as ef:
        for line in f:
            if line.startswith('allow-'):
                ef.write(line)
                kind, name, sid = line.rstrip().split('\t')
                allows.append((kind, name))
    allows = sorted(set(allows))
    with canonical.open() as f, (root/'semantics-conflicts.tsv').open('w') as cf:
        cf.write('domain\tissue\trule_types\n')
        for name, group in itertools.groupby((line.rstrip().split('\t') for line in f), key=lambda r: r[1]):
            unique_domains += 1
            kinds = set()
            for kind, _, sid in group:
                kinds.add(kind)
                provenance_rows += 1
            for kind in kinds:
                unique[kind] += 1
            if 'exact' in kinds and 'suffix' in kinds:
                semantics += 1
                cf.write(f'{name}\texact-and-suffix-preserved\t' + ','.join(sorted(kinds)) + '\n')
            for kind in kinds-{'allow-suffix', 'allow-exact'}:
                for allow_kind, allowed in allows:
                    # Report overlapping scopes; do not choose a precedence policy.
                    intersects = (name == allowed or (allow_kind == 'allow-suffix' and name.endswith('.'+allowed))
                                  or (kind in ('suffix', 'subdomains') and allowed.endswith('.'+name)))
                    if intersects:
                        overlap += 1
                        cf.write(f'{name}\tallow-block-overlap:{allowed}\t{kind},{allow_kind}\n')
    summary = {'sources': len(rows), 'successful_sources': sum(e['status'] == 'ok' for e in metadata),
               'failed_sources': sum(e['status'] == 'failed' for e in metadata),
               'counts': dict(totals), 'canonical_provenance_rows': provenance_rows,
               'unique_rules': dict(sorted(unique.items())), 'unique_domains': unique_domains,
               'firebog_recommendations': dict(sorted(Counter(e['firebog']['recommendation'] for e in metadata).items())),
               'same_domain_exact_suffix': semantics,
               'allow_block_overlaps': overlap, 'canonical_sha256': sha256(canonical),
               'original_inputs_sha256': original, 'idna_version': idna.__version__,
               'generated_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    manifest = {'schema_version': 1, 'policy': 'Experimental only; all sources disabled. Licensing review pending for every source. No safety certification.',
                'canonical_schema': ['rule_type', 'domain', 'source_id'],
                'rule_semantics': {'exact': 'Only the named domain', 'suffix': 'Named domain plus all descendant labels',
                                   'subdomains': 'Descendant labels only; apex excluded', 'allow-suffix': 'Exception for named domain and descendants; no automatic precedence'},
                'catalog_reconciliation': reconciliation, 'sources': metadata}
    (root/'audit-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    (root/'audit-summary.json').write_text(json.dumps(summary, indent=2)+'\n')
    report = ['# Curtain list audit', '', 'Experimental ingestion only. **All sources disabled; licensing review pending.**',
              'Ads/adult/gambling/malware coverage is not a guarantee of safety for a five-year-old. DNS lists cannot classify paths or same-site content and can be bypassed.', '',
              '## Reproduce', '```sh', "python -m unittest discover -s tools -p 'test_audit*.py' -v", 'python tools/audit_blocklists.py', '```',
              'Requires Python 3.11+, idna (UTS46 non-transitional/IDNA2008), and GNU sort; sort uses 64 MiB buffers and disk spill under data/blocklists.', '',
              '## Totals', '```json', json.dumps(summary, indent=2), '```', '',
              '## Semantics and provenance',
              '- canonical.tsv is headerless type/domain/source-id TSV sorted by domain, type, source. Per-source normalized files deduplicate type/domain, preserving provenance across sources.',
              '- Exact and suffix rules are never merged. suffix includes apex; generic *. uses subdomains (apex excluded). HaGeZi asterisk exports use inclusive suffix coverage according to its equivalent-standard-exports contract; Jarelllama plain wildcard_domains uses inclusive suffix. Archived publisher documentation is in evidence/.',
              '- Hosts sink addresses are accepted only for 0.0.0.0, 127.0.0.1, :: and ::1; every following domain is exact. Other mappings, IPs, URLs, local names and invalid IDNA/host syntax are rejected.',
              '- Only unmodified ||domain^ / @@||domain^ adblock anchors become suffix / allow-suffix. Modifiers, paths, regex and cosmetic filters are retained as unsupported diagnostics, never flattened.',
              '- HTML, binary, error responses, invalid UTF-8 and hash mismatches fail whole downloads before ingestion.',
              '- Exceptions remain explicit and unresolved. semantics-conflicts.tsv records identical-domain exact/suffix overlap and supported exception/block scope overlap. It is not exhaustive redundancy analysis of nested blocking suffixes.',
              '- Counts accepted/exceptions are input occurrences; unique removes duplicates within each source. Global unique_rules removes provenance duplicates separately per type. Unsupported exceptions are a subset of unsupported, not accepted exceptions.',
              '- Lossy Firebog adblock mirrors explicitly warn that exceptions were already discarded upstream. Ingestion cannot undo this; these sources require upstream review before any policy use.', '',
              '## Firebog HTML / machine reconciliation', '```json', json.dumps(reconciliation, indent=2), '```',
              'bdTick means Firebog green/ticked (least likely to interfere), not certification. bdCross means not recommended. Unmarked is not a recommendation. all catalog includes crossed-out lists.', '',
              '## Sources', '| ID | Category | Firebog flag | Status | Accepted | Unique | Rejected | Unsupported | Exceptions / unsupported exceptions |',
              '|---|---|---|---|---:|---:|---:|---:|---:|']
    for e in metadata:
        c = e['counts']
        report.append(f"| {e['id']} | {','.join(e['content_categories'])} | {e['firebog']['recommendation']} | {e['status']} | {c['accepted']} | {c['unique']} | {c['rejected']} | {c['unsupported']} | {c['exceptions']} / {c['unsupported_exceptions']} |")
    report += ['', 'Source URLs, archived hashes, licensing header evidence (claims only, not reviewed grants), parser contracts and warnings: audit-manifest.json.', '', '## Failures']
    report += [f"- {e['url']}: {e['error']}" for e in metadata if e['status'] == 'failed']
    report += ['', '## Retrieval follow-up', 'See audit-retrievals.json for original-source retries and official alternative evidence. The original manifest/raw/summary and domains.experimental.txt remain unchanged; follow-up evidence is not silently substituted into the original benchmark.', '',
               '## Licensing', 'Every license_review remains pending. Header license strings are unverified publisher claims. Upstream aggregation, attribution, noncommercial constraints, copyleft compatibility and redistribution rights require human review. No licenses are certified by this audit.', '']
    followup = root/'audit-retrievals.json'
    if followup.exists():
        report += ['', '### Archived retrieval log', '```json', json.dumps(json.loads(followup.read_text()), indent=2), '```', '']
    dest = Path(report_path) if report_path else root/'list-audit.md'
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text('\n'.join(report))
    for name, digest in original.items():
        if sha256(root/name) != digest:
            raise RuntimeError(f'Original input changed: {name}')
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1]/'data/blocklists')
    parser.add_argument('--report', type=Path, default=Path(__file__).resolve().parents[1]/'reports/list-audit.md')
    args = parser.parse_args()
    print(json.dumps(audit(args.root, args.report), indent=2))



LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
LOCAL = {'localhost', 'local', 'localdomain', 'lan', 'internal', 'home', 'invalid', 'test', 'onion'}
SINKS = {'0.0.0.0', '127.0.0.1', '::', '::1'}


def domain(value):
    try:
        value = value.lower()
        if not value.isascii() or 'xn--' in value:
            value = idna.encode(value, uts46=True, std3_rules=True).decode('ascii')
    except UnicodeError:
        return None
    labels = value.split('.')
    if len(value) > 253 or len(labels) < 2 or labels[-1] in LOCAL or labels[-2:] == ['home', 'arpa']:
        return None
    if labels[-1].isdigit() or not all(LABEL.fullmatch(x) for x in labels):
        return None
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        return value


def parse_line(line, plain_type='exact', wildcard_type='subdomains'):
    text = line.lstrip('\ufeff').strip()
    if not text or text.startswith(('#', '!')):
        return []
    anchor = re.fullmatch(r'(@@)?\|\|([^\s|^/$#]+)\^', text)
    if anchor:
        d = domain(anchor[2])
        return [('allow-suffix' if anchor[1] else 'suffix', d)] if d else [('rejected', text)]
    if text.startswith(('|', '@', '/', '[')) or any(x in text for x in ('##', '#@#', '$', '^')):
        return [('unsupported', text)]
    if text.startswith(('https://', 'http://')):
        return [('rejected', text)]
    if text.startswith('*.'):
        d = domain(text[2:])
        return [(wildcard_type, d)] if d else [('rejected', text)]
    text = text.split('#', 1)[0].strip()
    fields = text.split()
    if fields[0] in SINKS:
        if len(fields) == 1:
            return [('rejected', text)]
        fields = fields[1:]
        plain_type = 'exact'
    elif len(fields) != 1:
        return [('rejected', text)]
    return [(plain_type, d) if (d := domain(x)) else ('rejected', x) for x in fields]


if __name__ == '__main__':
    main()
