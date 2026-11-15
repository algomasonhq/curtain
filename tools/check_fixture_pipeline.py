#!/usr/bin/env python3
"""Offline deterministic ingestion -> Rust compile -> verify -> signed-package smoke.

Synthetic reserved example domains only. Ephemeral signing keys stay outside the
repository. This is not a substitute for the optional full published-corpus tests.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from audit_blocklists import audit
from prepare_update import prepare, canonical
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[1]
def run(*args):
    subprocess.run(args, cwd=ROOT, check=True)
def main():
    with tempfile.TemporaryDirectory() as td:
        base = Path(td); root = base / 'inputs'; root.mkdir(); (root / 'raw').mkdir()
        url = 'https://fixture.example.org/list'
        body = '0.0.0.0 ads.example.org ads.example.org\n||tracker.example.org^\n@@||safe.tracker.example.org^\n*.desc.example.org\nhttps://rejected.example.org/path\n||unsupported.example.org^$third-party\n'
        (root / 'raw/list.txt').write_text(body)
        (root / 'manifest.json').write_text(json.dumps([dict(url=url, file='raw/list.txt', sha256=hashlib.sha256(body.encode()).hexdigest())]))
        (root / 'summary.json').write_text('{}')
        (root / 'domains.experimental.txt').write_text('')
        (root / 'firebog-catalog.txt').write_text(url + '\n')
        (root / 'firebog.html').write_text('<ul class="bdUrlList advertising"><li class="bdTick"><a href="'+url+'">fixture</a></li></ul>')
        first = audit(root)
        assert first['sources'] == 1 and first['unique_domains'] == 4
        assert first['counts']['rejected'] == 1 and first['counts']['unsupported'] == 1
        expected = (root / 'canonical.tsv').read_bytes()
        audit(root)
        assert (root / 'canonical.tsv').read_bytes() == expected
        binary = ROOT / 'native/target/debug/compact-index'
        run('cargo', 'build', '--locked', '--manifest-path', str(ROOT / 'native/Cargo.toml'), '--bin', 'compact-index')
        queries = base / 'queries.tsv'
        queries.write_text('fixture\tads.example.org\nfixture\tchild.tracker.example.org\nfixture\tsafe.tracker.example.org\nfixture\tchild.desc.example.org\nfixture\tdesc.example.org\nfixture\tclean.example.org\n')
        a = base / 'a.fc'; b = base / 'b.fc'
        for out in [a,b]: run(str(binary), 'build', str(root / 'canonical.tsv'), str(out))
        assert a.read_bytes() == b.read_bytes()
        run(str(binary), 'verify', str(a), str(root / 'canonical.tsv'), str(queries))
        public = base / 'fixture-public.pem'
        manifest = prepare(a, base / 'package', base / 'keys/update.pem', public, 1)
        signature = __import__('base64').b64decode(manifest.pop('signature'))
        serialization.load_pem_public_key(public.read_bytes()).verify(signature, canonical(manifest))
        assert (base / 'package/indexes/000001.fc').read_bytes() == a.read_bytes()
        print('PASS deterministic canonical + index, all fixture flags/oracle, signed package; SHA256=' + hashlib.sha256(a.read_bytes()).hexdigest())
if __name__ == '__main__': main()
