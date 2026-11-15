"""Run: python -m unittest discover -s tools -p 'test_audit*.py' -v."""
import importlib
import unittest


class ParserTests(unittest.TestCase):
    def test_hosts_multiple_domains_are_exact_and_local_names_rejected(self):
        self.assertIsNotNone(importlib.util.find_spec('audit_blocklists'), 'source-aware parser is missing')
        from audit_blocklists import parse_line
        self.assertEqual(parse_line('0.0.0.0 Ads.Example.com second.example.org # note'),
                         [('exact', 'ads.example.com'), ('exact', 'second.example.org')])
        self.assertEqual(parse_line('127.0.0.1 localhost router.local 127.0.0.2'),
                         [('rejected', 'localhost'), ('rejected', 'router.local'), ('rejected', '127.0.0.2')])
        self.assertEqual(parse_line('plain.example.com'), [('exact', 'plain.example.com')])

    def test_adblock_anchor_exceptions_modifiers_and_cosmetic_preserved(self):
        from audit_blocklists import parse_line
        self.assertEqual(parse_line('||ads.example.com^'), [('suffix', 'ads.example.com')])
        self.assertEqual(parse_line('@@||safe.example.com^'), [('allow-suffix', 'safe.example.com')])
        for line in ('||ads.example.com^$third-party', '@@||safe.example.com^$domain=example.org',
                     '||ads.example.com/path', '/banner\\d+/', 'example.com##.advert', '[Adblock Plus 2.0]'):
            with self.subTest(line=line):
                self.assertEqual(parse_line(line), [('unsupported', line)])
        self.assertEqual(parse_line('! comment'), [])

    def test_wildcard_contract_idna_and_invalid_host_cases(self):
        from audit_blocklists import parse_line
        self.assertEqual(parse_line('*.ads.example.com'), [('subdomains', 'ads.example.com')])
        self.assertEqual(parse_line('*.ads.example.com', wildcard_type='suffix'), [('suffix', 'ads.example.com')])
        self.assertEqual(parse_line('ads.example.com', plain_type='suffix'), [('suffix', 'ads.example.com')])
        self.assertEqual(parse_line('0.0.0.0 ads.example.com', plain_type='suffix'), [('exact', 'ads.example.com')])
        self.assertEqual(parse_line('BÜCHER.de'), [('exact', 'xn--bcher-kva.de')])
        for text in ('https://ads.example.com/path', 'user@example.com', 'foo..com', '-bad.com',
                     'bad_.com', '127.0.0.1', '::1', 'router.local', 'foo.localhost', 'foo.home.arpa',
                     'foo.lan', 'example.com..', 'a'*64+'.com', 'xn--.com', '💩.com', 'foo.123'):
            with self.subTest(text=text):
                self.assertEqual(parse_line(text), [('rejected', text)])

    def test_archive_pipeline_reconciles_flags_dedups_and_rejects_error_downloads(self):
        from pathlib import Path
        import tempfile
        import json
        import hashlib
        import audit_blocklists as a
        self.assertTrue(hasattr(a, 'audit'), 'archive ingestion is missing')
        # Temporary artifacts remain inside the allowed data tree.
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / 'data/blocklists') as td:
            root = Path(td)
            (root / 'raw').mkdir()
            rows = []
            for name, body in [('one', '0.0.0.0 ads.example.com ads.example.com\n||ads.example.com^\n@@||example.com^\n||ad.example.net^$third-party\n@@||safe.example.net^$domain=example.org\nhttps://bad.example.com/\n'),
                               ('two', '<html>\ncontamination.example.com\n</html>'),
                               ('three', 'Access denied\ncontamination.example.com\n')]:
                (root / ('raw/' + name)).write_text(body)
                rows.append(dict(url='https://lists.example.org/'+name, file='raw/'+name,
                                 sha256=hashlib.sha256(body.encode()).hexdigest(), enabled=False))
            rows.append(dict(url='https://lists.example.org/dead', error='HTTP 410'))
            (root/'manifest.json').write_text(json.dumps(rows))
            (root/'summary.json').write_text('{}')
            (root/'audit-retrievals.json').write_text(json.dumps({'alternative_rationale': 'stale-2024-not-substituted'}))
            (root/'domains.experimental.txt').write_text('original.example.com\n')
            (root/'firebog-catalog.txt').write_text('\n'.join(r['url'] for r in rows)+'\n')
            (root/'firebog.html').write_text('<ul class="bdUrlList advertising"><li class="bdCross"><a href="https://publisher.example.org">Publisher</a><a href="https://lists.example.org/one">one</a></li><li class="bdTick"><a href="https://lists.example.org/pageonly">extra</a></li></ul>')
            result = a.audit(root)
            self.assertEqual(result['sources'], 4)
            self.assertEqual(result['successful_sources'], 1)
            self.assertEqual(result['failed_sources'], 3)
            self.assertEqual(result['unique_rules'], {'allow-suffix': 1, 'exact': 1, 'suffix': 1})
            self.assertEqual(result['same_domain_exact_suffix'], 1)
            self.assertEqual(result.get('unique_domains'), 2)
            self.assertEqual(result.get('firebog_recommendations'), {'not-recommended': 1, 'not-on-page': 3})
            self.assertEqual(result['allow_block_overlaps'], 2)
            metadata = json.loads((root/'audit-manifest.json').read_text())
            first = metadata['sources'][0]
            self.assertEqual(first['firebog']['recommendation'], 'not-recommended')
            self.assertEqual(first['firebog']['category'], 'advertising')
            self.assertEqual(first['counts']['duplicates'], 1)
            self.assertEqual(first['counts']['unsupported'], 2)
            self.assertEqual(first['counts']['unsupported_exceptions'], 1)
            self.assertEqual(first['counts']['rejected'], 1)
            self.assertEqual(first['license_review'], 'pending')
            self.assertFalse(first['enabled'])
            self.assertEqual(metadata['catalog_reconciliation']['page_only'], ['https://lists.example.org/pageonly'])
            canonical = (root/'canonical.tsv').read_text()
            self.assertNotIn('contamination', canonical)
            self.assertEqual(len(canonical.splitlines()), 3)
            self.assertIn('@@||safe.example.net^$domain=example.org', (root/'audit-diagnostics.tsv').read_text())
            self.assertEqual((root/'domains.experimental.txt').read_text(), 'original.example.com\n')
            self.assertIn('stale-2024-not-substituted', (root/'list-audit.md').read_text())

    def test_web_error_variants_cannot_leak_valid_domains(self):
        from pathlib import Path
        import tempfile
        from audit_blocklists import validate_download
        for body in ('HTTP/1.1 403 Forbidden\nleak.example.com\n',
                     '<!DOCTYPE html>\nleak.example.com\n',
                     '429 Too Many Requests\nleak.example.com\n',
                     '<?xml version="1.0"?><Error>AccessDenied</Error>\nleak.example.com\n'):
            with self.subTest(body=body), tempfile.NamedTemporaryFile(dir=Path(__file__).resolve().parents[1]/'data/blocklists') as f:
                f.write(body.encode())
                f.flush()
                with self.assertRaises(ValueError):
                    validate_download(Path(f.name))

    def test_only_reviewed_publishers_can_override_plain_or_star_semantics(self):
        import audit_blocklists as a
        self.assertTrue(hasattr(a, 'source_contract'), 'reviewed source contracts missing')
        self.assertEqual(a.source_contract('https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt'), ('suffix', 'subdomains'))
        self.assertEqual(a.source_contract('https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw.txt'), ('exact', 'suffix'))
        self.assertEqual(a.source_contract('https://unreviewed.example.org/wildcard_domains/scams.txt'), ('exact', 'subdomains'))
        self.assertEqual(a.source_contract('https://unreviewed.example.org/hagezi/dns-blocklists/main/wildcard/nsfw.txt'), ('exact', 'subdomains'))

    def test_verbatim_download_format_fixtures(self):
        from pathlib import Path
        import json
        from audit_blocklists import parse_line, source_contract
        fixture = Path(__file__).with_name('fixtures')/'download-formats.json'
        self.assertTrue(fixture.exists(), 'verbatim raw-download fixture corpus missing')
        for case in json.loads(fixture.read_text()):
            with self.subTest(url=case['url'], line=case['line_number']):
                plain, star = source_contract(case['url'])
                self.assertEqual(parse_line(case['text'], plain, star), [tuple(x) for x in case['expected']])


if __name__ == '__main__':
    unittest.main()
