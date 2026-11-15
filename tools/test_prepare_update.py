"""Local-only packaging tests; all private fixture keys stay in scratch."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

SCRIPT = Path(__file__).with_name('prepare_update.py')


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source.fc'
        self.source.write_bytes(b'CURTFC01' + bytes(range(256)))
        self.out = self.root / 'out'
        self.key = self.root / 'signing' / 'update-ed25519.pem'
        self.public = self.root / 'public.pem'

    def run_package(self, version=1):
        return subprocess.run([sys.executable, str(SCRIPT), '--source', str(self.source),
                               '--output', str(self.out), '--key', str(self.key),
                               '--public-key', str(self.public), '--version', str(version)],
                              capture_output=True, text=True)

    def manifest(self):
        return json.loads((self.out / 'version.json').read_text())

    def test_signed_package_source_hash_tampering_and_identity_reuse(self):
        self.assertTrue(SCRIPT.exists(), 'packaging script is missing')
        result = self.run_package()
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = self.manifest()
        self.assertEqual(set(manifest), {'version', 'format', 'file', 'bytes', 'sha256', 'signature'})
        self.assertEqual(manifest['version'], 1)
        self.assertEqual(manifest['format'], 1)
        self.assertEqual(manifest['file'], 'indexes/000001.fc')
        self.assertEqual(manifest['bytes'], self.source.stat().st_size)
        self.assertEqual(manifest['sha256'], hashlib.sha256(self.source.read_bytes()).hexdigest())
        self.assertEqual((self.out / manifest['file']).read_bytes(), self.source.read_bytes())
        public = serialization.load_pem_public_key(self.public.read_bytes())
        signature = base64.b64decode(manifest.pop('signature'), validate=True)
        canonical = lambda data: json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
        public.verify(signature, canonical(manifest))
        for name, value in [('version', 2), ('format', 2), ('file', 'indexes/evil.fc'), ('bytes', 0), ('sha256', '0'*64)]:
            changed = dict(manifest, **{name: value})
            with self.subTest(field=name), self.assertRaises(InvalidSignature):
                public.verify(signature, canonical(changed))
        identity = self.key.read_bytes()
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.key.parent.stat().st_mode & 0o777, 0o700)
        result = self.run_package(2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.key.read_bytes(), identity)
        second = self.manifest()
        public.verify(base64.b64decode(second.pop('signature')), canonical(second))

    def test_monotonic_versions_and_immutable_overwrite(self):
        self.assertEqual(self.run_package().returncode, 0)
        before = (self.out / 'version.json').read_bytes()
        index = self.out / 'indexes/000001.fc'
        inode = index.stat().st_ino
        self.assertEqual(self.run_package().returncode, 0)  # identical repeat is a no-op
        self.assertEqual(index.stat().st_ino, inode)
        self.source.write_bytes(b'changed source')
        self.assertNotEqual(self.run_package().returncode, 0)
        self.assertEqual((self.out / 'version.json').read_bytes(), before)
        self.assertEqual(index.stat().st_ino, inode)
        self.assertEqual(self.run_package(2).returncode, 0)
        latest = (self.out / 'version.json').read_bytes()
        self.assertNotEqual(self.run_package(1).returncode, 0)
        self.assertEqual((self.out / 'version.json').read_bytes(), latest)
        self.assertNotEqual(self.run_package(0).returncode, 0)

    def test_orphan_conflict_and_corrupt_manifest_are_not_overwritten(self):
        self.out.mkdir()
        (self.out / 'indexes').mkdir()
        orphan = self.out / 'indexes/000001.fc'
        orphan.write_bytes(b'preserve me')
        self.assertNotEqual(self.run_package().returncode, 0)
        self.assertEqual(orphan.read_bytes(), b'preserve me')
        self.assertFalse((self.out / 'version.json').exists())
        orphan.unlink()
        self.assertEqual(self.run_package().returncode, 0)
        damaged = self.manifest()
        damaged['version'] = 500
        (self.out / 'version.json').write_text(json.dumps(damaged))
        before = (self.out / 'version.json').read_bytes()
        self.assertNotEqual(self.run_package(501).returncode, 0)
        self.assertEqual((self.out / 'version.json').read_bytes(), before)

    def test_public_key_mismatch_does_not_rotate_identity(self):
        self.assertEqual(self.run_package().returncode, 0)
        identity = self.key.read_bytes()
        self.public.write_text('not the trusted public key')
        self.assertNotEqual(self.run_package(2).returncode, 0)
        self.assertEqual(self.key.read_bytes(), identity)
        self.assertEqual(self.manifest()['version'], 1)


if __name__ == '__main__':
    unittest.main()
