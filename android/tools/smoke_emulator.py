#!/usr/bin/env python3
"""Optional server smoke run: no root, no KVM permission changes."""
from pathlib import Path
import os
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
SDK = Path(os.environ['ANDROID_HOME'])
ADB = str(SDK / 'platform-tools/adb')
EVIDENCE = ROOT / 'evidence'

def run(*args, timeout=120):
    result = subprocess.run([ADB, *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
    print('adb', *args, '\n', result.stdout, flush=True)
    if result.returncode:
        raise RuntimeError(f'adb returned {result.returncode}')
    return result.stdout

with (EVIDENCE / 'emulator-foreground.txt').open('w') as log:
    emulator = subprocess.Popen([str(SDK / 'emulator/emulator'), '-avd', 'curtain35aosp', '-no-window', '-no-audio', '-no-boot-anim', '-gpu', 'swiftshader', '-feature', '-Vulkan', '-accel', 'off', '-cores', '2', '-memory', '1536', '-no-snapshot', '-no-metrics'], stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 420
        while time.monotonic() < deadline:
            if emulator.poll() is not None:
                raise RuntimeError(f'emulator exited {emulator.returncode}')
            check = subprocess.run([ADB, 'shell', 'getprop', 'sys.boot_completed'], capture_output=True, text=True, timeout=20)
            if check.stdout.strip() == '1':
                break
            time.sleep(5)
        else:
            raise RuntimeError('Emulator did not boot in 420 seconds')
        run('install', '-r', str(ROOT / 'app/build/outputs/apk/debug/app-debug.apk'))
        run('install', '-r', str(ROOT / 'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'))
        run('shell', 'appops', 'set', 'org.curtain.dns', 'ACTIVATE_VPN', 'allow')
        run('shell', 'settings', 'put', 'global', 'private_dns_mode', 'off')
        result = run('shell', 'am', 'instrument', '-w', 'org.curtain.dns.test/org.curtain.dns.SmokeInstrumentation', timeout=440)
        (EVIDENCE / 'emulator-smoke.txt').write_text(result)
        for name, args in [('diagnostic-logcat', ['logcat', '-d']), ('diagnostic-connectivity', ['shell', 'dumpsys', 'connectivity']), ('diagnostic-vpn', ['shell', 'dumpsys', 'vpn_management']), ('diagnostic-routes', ['shell', 'ip', 'route', 'show', 'table', 'all'])]:
            diagnostic = subprocess.run([ADB, *args], capture_output=True, text=True, timeout=30)
            (EVIDENCE / (name + '.txt')).write_text(diagnostic.stdout + diagnostic.stderr)
        if 'PASS' not in result:
            raise RuntimeError('Instrumentation did not report PASS')
        run('shell', 'dumpsys', 'connectivity')
    finally:
        subprocess.run([ADB, 'emu', 'kill'], capture_output=True, timeout=10)
        if emulator.poll() is None:
            emulator.terminate()
            try:
                emulator.wait(timeout=10)
            except subprocess.TimeoutExpired:
                emulator.kill()
