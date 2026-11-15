#!/usr/bin/env python3
"""Verify signed CDN metadata and whole-file length/hash (no network, no key writes)."""
import argparse
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from prepare_update import canonical, digest

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('index', type=Path)
    parser.add_argument('--public-key', type=Path, default=Path(__file__).with_name('update-public-key.pem'))
    args = parser.parse_args()
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('Duplicate field')
            result[key] = value
        return result
    data = json.loads(args.manifest.read_text(), object_pairs_hook=unique)
    if set(data) != {'version','format','file','bytes','sha256','signature'}:
        raise ValueError('Unexpected manifest fields')
    sig = base64.b64decode(data.pop('signature'), validate=True)
    serialization.load_pem_public_key(args.public_key.read_bytes()).verify(sig, canonical(data))
    assert type(data['version']) is int and 1 <= data['version'] <= 999999
    assert type(data['format']) is int and data['format'] == 1
    assert data['file'] == f"indexes/{data['version']:06d}.fc"
    assert args.index.name == Path(data['file']).name
    assert type(data['bytes']) is int and args.index.stat().st_size == data['bytes']
    assert digest(args.index) == data['sha256']
    print('PASS signature, version/path, byte length, whole-file SHA-256:', data)
if __name__ == '__main__': main()
