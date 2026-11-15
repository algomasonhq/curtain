#!/usr/bin/env python3
"""Verify a caller-selected APK without copying or replacing release artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('apk', type=Path)
    args = parser.parse_args()
    tools = Path(os.environ['ANDROID_HOME']) / 'build-tools/35.0.0'
    subprocess.run([str(tools/'apksigner'), 'verify', '--verbose', '--print-certs', str(args.apk)], check=True)
    badging = subprocess.check_output([str(tools/'aapt'), 'dump', 'badging', str(args.apk)], text=True)
    assert "package: name='org.curtain.dns' versionCode='2'" in badging
    assert "sdkVersion:'35'" in badging and "targetSdkVersion:'35'" in badging
    manifest = subprocess.check_output([str(tools/'aapt'), 'dump', 'xmltree', str(args.apk), 'AndroidManifest.xml'], text=True)
    assert 'WorkManagerInitializer' not in manifest
    with zipfile.ZipFile(args.apk) as archive:
        assert archive.testzip() is None
        assert not any(name.endswith(('.fc', '.so')) for name in archive.namelist())
    print(json.dumps({'bytes': args.apk.stat().st_size, 'sha256': hashlib.sha256(args.apk.read_bytes()).hexdigest(), 'zip_crc': 'PASS', 'fc_assets': 0, 'native_so': 0}))
if __name__ == '__main__': main()
