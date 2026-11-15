"""Offline acquisition tests: exact frozen catalog, no implicit source replacement."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import fetch_blocklists as fetcher


class FetchTests(unittest.TestCase):
    def test_snapshot_uses_all_62_exact_urls_and_recorded_markers(self):
        snapshot = Path(__file__).resolve().parents[1] / 'data/blocklists/audit-manifest.json'
        original = json.loads(snapshot.read_text())
        urls = sorted(s['url'] for s in original['sources'])
        self.assertEqual(len(urls), 62)
        self.assertEqual(sum(s['status'] == 'ok' for s in original['sources']), 59)
        body = b'0.0.0.0 ads.example.org\n'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            old_root = fetcher.ROOT
            try:
                with patch('sys.argv', ['fetch', '--root', td, '--snapshot', str(snapshot)]), patch.object(fetcher, 'fetch', return_value=body) as network:
                    fetcher.main()
                self.assertEqual(sorted(call.args[0] for call in network.call_args_list), urls)
                rows = json.loads((root / 'manifest.json').read_text())
                self.assertEqual([r['url'] for r in rows], urls)
                self.assertTrue(all(r['sha256'] == hashlib.sha256(body).hexdigest() for r in rows))
                from audit_blocklists import FirebogParser
                parser = FirebogParser()
                parser.feed((root / 'firebog.html').read_text())
                for s in original['sources']:
                    if s['firebog']['recommendation'] != 'not-on-page':
                        self.assertEqual(parser.sources[s['url']], s['firebog'])
            finally:
                fetcher.ROOT = old_root


if __name__ == '__main__':
    unittest.main()
