#!/usr/bin/env python3
"""Archive Firebog's complete catalog plus category supplements for experiments.
Downloading a list does not endorse enabling or redistributing it.
"""
import concurrent.futures
import datetime
import hashlib
import json
from pathlib import Path
import re
import urllib.request
import argparse
import html

ROOT = Path(__file__).resolve().parents[1] / 'data' / 'blocklists'
SUPPLEMENTS = {
    'https://v.firebog.net/hosts/Prigent-Adult.txt',
    'https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_top1m.list',
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.txt',
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw.txt',
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.txt',
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.txt',
}

def fetch(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'Curtain-blocklist-research/0.1'})
    with urllib.request.urlopen(request, timeout=40) as response:
        body = response.read(150_000_001)
        if len(body) > 150_000_000:
            raise ValueError('Source exceeds archive size limit')
        return body

def download(url):
    row = {'url': url, 'enabled': False, 'license_review': 'pending'}
    try:
        body = fetch(url)
        if b'<html' in body[:1000].lower() or b'<!doctype html' in body[:1000].lower():
            raise ValueError('HTML returned instead of blocklist')
        filename = hashlib.sha256(url.encode()).hexdigest()[:20] + '.txt'
        (ROOT / 'raw' / filename).write_bytes(body)
        row.update(file='raw/' + filename, bytes=len(body), sha256=hashlib.sha256(body).hexdigest())
    except Exception as exc:
        row['error'] = str(exc)
    return row

def domains(body):
    for line in body.splitlines():
        line = line.split('#', 1)[0].strip().lower()
        if not line or line.startswith(('!', '[', '@', '/')):
            continue
        fields = line.split()
        if fields[0] in ('0.0.0.0', '127.0.0.1', '::', '::1'):
            fields = fields[1:]
        elif len(fields) != 1:
            continue
        for value in fields:
            if value.startswith('||') and value.endswith('^'):
                value = value[2:-1]
            value = value.rstrip('.')
            try:
                value = value.encode('idna').decode('ascii')
            except UnicodeError:
                continue
            if len(value) <= 253 and '.' in value and not re.fullmatch(r'[0-9.]+', value) and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
                yield value

def main():
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    parser.add_argument('--snapshot', type=Path, help='Use exact URLs and Firebog markers from an audit-manifest.json instead of the current live catalog')
    args = parser.parse_args()
    ROOT = args.root
    (ROOT / 'raw').mkdir(parents=True, exist_ok=True)
    if args.snapshot:
        sources = json.loads(args.snapshot.read_text())['sources']
        urls = sorted(s['url'] for s in sources)
        if len(urls) != len(set(urls)):
            raise ValueError('Duplicate snapshot source URL')
        catalog = '\n'.join(s['url'] for s in sources if s['in_machine_catalog']).encode() + b'\n'
        # Reconstruct markers, not copyrighted upstream page content. Historical
        # page/catalog hashes are not expected to match this fresh acquisition.
        parts = []
        for s in sources:
            info = s['firebog']
            if info['recommendation'] == 'not-on-page':
                continue
            cls = 'bdCross' if info['recommendation'] == 'not-recommended' else 'bdTick' if info['recommendation'] == 'ticked' else ''
            parts.append(f'<ul class="bdUrlList {html.escape(info["category"], quote=True)}"><li class="{cls}"><a href="{html.escape(info.get("publisher_url", s["url"]), quote=True)}">Publisher</a><a href="{html.escape(s["url"], quote=True)}">Source</a></li></ul>')
        page = ''.join(parts).encode()
    else:
        catalog = fetch('https://v.firebog.net/hosts/lists.php?type=all')
        page = fetch('https://firebog.net/')
        urls = sorted({line.strip() for line in catalog.decode().splitlines() if line.strip().startswith(('https://', 'http://'))} | SUPPLEMENTS)
    (ROOT / 'firebog-catalog.txt').write_bytes(catalog)
    (ROOT / 'firebog.html').write_bytes(page)
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        for row in pool.map(download, urls):
            rows.append(row)
            (ROOT / 'manifest.json').write_text(json.dumps(rows, indent=2) + '\n')
            print(('OK ' if 'file' in row else 'FAIL ') + row['url'], flush=True)
    unique = set()
    for row in rows:
        if 'file' in row:
            extracted = set(domains((ROOT / row['file']).read_text(errors='replace')))
            row['parsed_domains'] = len(extracted)
            unique.update(extracted)
    (ROOT / 'domains.experimental.txt').write_text(''.join(domain + '\n' for domain in sorted(unique)))
    (ROOT / 'manifest.json').write_text(json.dumps(rows, indent=2) + '\n')
    summary = {'fetched_at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'attempted_sources': len(rows), 'successful_sources': sum('file' in r for r in rows), 'failed_sources': sum('error' in r for r in rows), 'unique_domains': len(unique), 'purpose': 'Experimental corpus, not an approved default policy. Exact versus suffix semantics must be preserved from original sources before production compilation.'}
    (ROOT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    main()
