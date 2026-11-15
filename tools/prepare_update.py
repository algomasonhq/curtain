#!/usr/bin/env python3
"""Prepare a signed experimental static package. Never uploads anything."""
import argparse
import base64
import hashlib
import fcntl

from cryptography.exceptions import InvalidSignature
import json
import os
from pathlib import Path
import shutil
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]


def canonical(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def signing_key(path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    if not path.exists():
        key = Ed25519PrivateKey.generate()
        encoded = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
        # Exclusive creation: never replace an existing identity.
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            pass
        else:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
    if path.is_symlink():
        raise ValueError('Private key must not be a symlink')
    os.chmod(path, 0o600)
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError('Existing signing identity is not Ed25519')
    return key


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def prepare(source, output, key_path, public_path, version):
    if type(version) is not int or not 1 <= version <= 999999:
        raise ValueError('Version must be an integer in 1..999999')
    if key_path.resolve().is_relative_to(ROOT) or key_path.resolve().is_relative_to(output.resolve()):
        raise ValueError('Private key must remain outside repository and package output')
    output.mkdir(parents=True, exist_ok=True)
    # Serialize cooperating publishers, including different signing identities.
    with (output / '.prepare.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return prepare_locked(source, output, key_path, public_path, version)


def prepare_locked(source, output, key_path, public_path, version):
    key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(key_path.parent, 0o700)
    with (key_path.parent / '.identity.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        key = signing_key(key_path)
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    if public_path.exists() and public_path.read_bytes() != public:
        raise ValueError('Public key mismatch; refusing identity rotation')
    manifest = dict(version=version, format=1, file=f'indexes/{version:06d}.fc',
                    bytes=source.stat().st_size, sha256=digest(source))
    manifest_path = output / 'version.json'
    if manifest_path.exists():
        previous = json.loads(manifest_path.read_text(encoding='utf-8'))
        if set(previous) != set(manifest) | {'signature'}:
            raise ValueError('Invalid existing manifest fields')
        signature = base64.b64decode(previous.pop('signature'), validate=True)
        try:
            key.public_key().verify(signature, canonical(previous))
        except InvalidSignature:
            raise ValueError('Existing manifest signature is invalid') from None
        if type(previous['version']) is not int or version < previous['version']:
            raise ValueError('Version rollback refused')
        if version == previous['version'] and previous != manifest:
            raise ValueError('Existing version metadata is immutable; increment version')
    target = output / manifest['file']
    if target.exists():
        if target.stat().st_size != manifest['bytes'] or digest(target) != manifest['sha256']:
            raise ValueError('Existing versioned index is immutable; increment version')
        if public_path.exists() and manifest_path.exists() and previous == manifest:
            return dict(manifest, signature=base64.b64encode(key.sign(canonical(manifest))).decode('ascii'))
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.index-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as dest, source.open('rb') as src:
            shutil.copyfileobj(src, dest, 1024 * 1024)
            dest.flush()
            os.fsync(dest.fileno())
        if Path(name).stat().st_size != manifest['bytes'] or digest(Path(name)) != manifest['sha256']:
            raise ValueError('Source changed during copy')
        os.replace(name, target)
    finally:
        Path(name).unlink(missing_ok=True)
    manifest['signature'] = base64.b64encode(key.sign(canonical(manifest))).decode('ascii')
    atomic_write(public_path, public)
    atomic_write(output / 'version.json', canonical(manifest) + b'\n')
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'native/compact-evidence/audited.fc')
    parser.add_argument('--output', type=Path, default=ROOT / 'artifacts/r2/curtain')
    parser.add_argument('--key', type=Path, default=Path.home() / '.local/share/curtain/signing/update-ed25519.pem')
    parser.add_argument('--public-key', type=Path, default=ROOT / 'tools/update-public-key.pem')
    parser.add_argument('--version', type=int, default=1)
    args = parser.parse_args()
    try:
        manifest = prepare(args.source, args.output, args.key, args.public_key, args.version)
    except (ValueError, OSError) as error:
        parser.exit(1, f'Packaging refused: {error}\n')
    print(json.dumps(manifest, sort_keys=True))


if __name__ == '__main__':
    main()
