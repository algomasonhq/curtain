#!/usr/bin/env python3
"""Private API35 AVD harness: real unproxied VPN TLS plus owned TLS origin.

Run against the disposable emulator-5580, already booted with curtain35aosp.
No private CA material is copied to Android or into the repository/artifacts.
The test APK injects fixture-only origin trust via reflection; production has
no trust bypass or test hook. Installation-CA trust is client-only test setup.
"""
from pathlib import Path
import base64
import datetime
import http.server
import ipaddress
import json
import os
import ssl
import subprocess
import tempfile
import threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[1]
SDK = Path(os.environ['ANDROID_HOME'])
ADB = str(SDK / 'platform-tools/adb')
SERIAL = os.environ.get('ANDROID_SERIAL', 'emulator-5580')
EVIDENCE = ROOT.parent / 'artifacts' / 'browsing-vpn-evidence'
EVIDENCE.mkdir(parents=True, exist_ok=True)


def adb(*args, timeout=120):
    p = subprocess.run([ADB, '-s', SERIAL, *args], capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError(f'adb {args[:3]}: {p.stdout}{p.stderr}')
    return p.stdout


requests = []
uploads = []
class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def do_GET(self):
        requests.append(self.path)
        body = b's' * (3*1024*1024+3) if self.path == '/stream' else 'Origin allowed ✓\n'.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        for offset in range(0, len(body), 8192):
            self.wfile.write(body[offset:offset+8192])
            self.wfile.flush()
    def do_POST(self):
        requests.append(self.path)
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            parts = []
            while True:
                n = int(self.rfile.readline().strip(), 16)
                if n == 0:
                    assert self.rfile.readline() == b'\r\n'
                    break
                parts.append(self.rfile.read(n))
                assert self.rfile.read(2) == b'\r\n'
            body = b''.join(parts)
        else:
            body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        assert len(body) == 2*1024*1024+17
        assert body == bytes(i % 251 for i in range(len(body)))
        uploads.append({'path': self.path, 'bytes': len(body), 'framing': self.headers.get('Transfer-Encoding', 'content-length')})
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_):
        pass


# TMPDIR must be the user-scoped Hermes scratch, never system /tmp.
with tempfile.TemporaryDirectory(prefix='curtain-tls-fixture-', dir=os.environ.get('TMPDIR', str(Path.home()/'.hermes/cache/scratch'))) as tmp:
    tmp = Path(tmp)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Curtain ephemeral emulator origin')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1))
            .not_valid_after(now+datetime.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('10.0.2.2'))]), critical=False)
            .sign(key, hashes.SHA256()))
    keyfile = tmp/'origin.key'
    keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    keyfile.chmod(0o600)
    certfile = tmp/'origin.pem'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    settings_before = {key: adb('shell', 'settings', 'get', 'global', key).strip()
                       for key in ('private_dns_mode', 'hidden_api_policy')}
    try:
        assert adb('shell', 'getprop', 'sys.boot_completed').strip() == '1'
        adb('install', '-r', str(ROOT/'app/build/outputs/apk/debug/app-debug.apk'))
        adb('install', '-r', str(ROOT/'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'))
        adb('shell', 'am', 'force-stop', 'org.curtain.dns')
        adb('shell', 'appops', 'set', 'org.curtain.dns', 'ACTIVATE_VPN', 'allow')
        adb('shell', 'settings', 'put', 'global', 'private_dns_mode', 'off')
        adb('shell', 'settings', 'put', 'global', 'hidden_api_policy', '1')
        adb('logcat', '-c')
        result = adb('shell', 'am', 'instrument', '-w', '-e', 'inspection', 'true',
                     '-e', 'originPort', str(server.server_port), '-e', 'originCertificate',
                     base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode(),
                     'org.curtain.dns.test/org.curtain.dns.SmokeInstrumentation', timeout=660)
        (EVIDENCE/'instrumentation.txt').write_text(result)
        print(result, flush=True)
        assert result.rstrip().endswith('PASS') and 'FAIL:' not in result
        assert requests == ['/allowed', '/echo?n=0', '/echo?n=1', '/stream'], requests
        assert [x['framing'] for x in uploads] == ['content-length', 'chunked']
        summary = {'originRequests': requests, 'originRequestCount': len(requests), 'uploads': uploads,
                   'blockedOrModifiedReachedOrigin': False, 'explicitClientProxy': False,
                   'testOriginTrust': 'test APK reflection only; protected socket factory retained'}
        (EVIDENCE/'origin.json').write_text(json.dumps(summary, indent=2)+'\n')
        print(json.dumps(summary), flush=True)
    finally:
        (EVIDENCE/'logcat.txt').write_text(adb('logcat', '-d'))
        (EVIDENCE/'connectivity.txt').write_text(adb('shell', 'dumpsys', 'connectivity'))
        adb('shell', 'am', 'force-stop', 'org.curtain.dns')
        for key, value in settings_before.items():
            if value == 'null':
                adb('shell', 'settings', 'delete', 'global', key)
            else:
                adb('shell', 'settings', 'put', 'global', key, value)
            assert adb('shell', 'settings', 'get', 'global', key).strip() == value
        server.shutdown()
        server.server_close()
