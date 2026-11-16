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
    parser.add_argument('--inspection', action='store_true', help='Require the pinned arm64/x86_64 inspection engine instead of a DNS-only APK')
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
        names=archive.namelist()
        assert not any(name.endswith('.fc') for name in names)
        native=sorted(name for name in names if name.endswith('.so'))
        if args.inspection:
            assert native == ['lib/arm64-v8a/libhev-socks5-tunnel.so', 'lib/x86_64/libhev-socks5-tunnel.so'], native
            assert '.InspectionVpnService' in manifest
            assert 'android.permission.ACCESS_NETWORK_STATE' in manifest
        else:
            assert not native, native
        assert not any(name.endswith(('.pem','.key','.p12','.pfx')) for name in names), 'Unexpected certificate/key material'
    print(json.dumps({'bytes': args.apk.stat().st_size, 'sha256': hashlib.sha256(args.apk.read_bytes()).hexdigest(), 'zip_crc': 'PASS', 'fc_assets': 0, 'native_so': len(native), 'native_entries': native}))
if __name__ == '__main__': main()
