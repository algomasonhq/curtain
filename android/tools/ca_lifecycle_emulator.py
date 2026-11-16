#!/usr/bin/env python3
"""Own a disposable API35 emulator for CA UI completion and real-TUN regression.

Prerequisite: deliberately begin CA rotation and remove its exact old fingerprint
through Android Settings on this private AVD. CaLifecycleSmoke completes the real
confirmation/export/Settings install, or resumes the already completed rotation.
This installs debug/test APKs and changes this disposable emulator's user CA trust.
Never point it at a physical phone. It does not set up root/device administration.
"""
from pathlib import Path
import os
import subprocess
import sys
import time

ANDROID = Path(__file__).resolve().parents[1]
REPO = ANDROID.parent
SDK = Path(os.environ['ANDROID_HOME'])
ADB = str(SDK / 'platform-tools/adb')
SERIAL = 'emulator-5580'
AVD = os.environ.get('CURTAIN_CA_AVD', 'curtain35aosp')
EVIDENCE = REPO / 'artifacts' / 'ca-ui-evidence'


def adb(*args, timeout=60):
    result = subprocess.run([ADB, '-s', SERIAL, *args], capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout


def main():
    # Do not take ownership of an emulator which somebody else started.
    devices = subprocess.check_output([ADB, 'devices'], text=True)
    if any(line.startswith(SERIAL + '\t') for line in devices.splitlines()):
        raise RuntimeError(f'{SERIAL} already exists; stop your own emulator first')
    production = ANDROID / 'app/build/outputs/apk/debug/app-debug.apk'
    tests = ANDROID / 'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'
    if not production.is_file() or not tests.is_file():
        raise RuntimeError('Build debug and androidTest APKs first')
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    with (EVIDENCE / 'owned-emulator.log').open('w') as log:
        process = subprocess.Popen([
            str(SDK / 'emulator/emulator'), '-avd', AVD, '-port', '5580',
            '-no-window', '-no-audio', '-no-boot-anim', '-gpu', 'swiftshader_indirect',
            '-accel', 'off', '-memory', '2048', '-cores', '4', '-no-snapshot',
        ], stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f'Emulator exited before readiness: {process.returncode}')
                try:
                    booted = adb('shell', 'getprop', 'sys.boot_completed', timeout=8).strip() == '1'
                    storage = subprocess.run([ADB, '-s', SERIAL, 'shell', 'test', '-d',
                                              '/sdcard/Download'], capture_output=True, timeout=8)
                    if booted and storage.returncode == 0:
                        break
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
                time.sleep(2)
            else:
                raise RuntimeError('Emulator/shared-storage readiness timeout')
            adb('install', '-r', str(production))
            adb('install', '-r', str(tests))
            adb('shell', 'input', 'keyevent', 'KEYCODE_WAKEUP')
            # This does not collect or enter any PIN. A secure lock is a human gate.
            adb('shell', 'wm', 'dismiss-keyguard')
            result = adb('shell', 'am', 'instrument', '-w', '-e', 'caLifecycle', 'true',
                         'org.curtain.dns.test/org.curtain.dns.SmokeInstrumentation', timeout=300)
            (EVIDENCE / 'ca-instrumentation.txt').write_text(result)
            print(result, flush=True)
            if not result.rstrip().endswith('PASS') or 'FAIL:' in result:
                raise RuntimeError('CA lifecycle instrumentation failed; see evidence')
            environment = os.environ.copy()
            environment['ANDROID_SERIAL'] = SERIAL
            result = subprocess.run([sys.executable, str(ANDROID / 'tools/inspection_vpn_emulator.py')],
                                    env=environment, capture_output=True, text=True, timeout=450)
            evidence = REPO / 'artifacts/browsing-vpn-evidence/final-artifact-run.txt'
            evidence.parent.mkdir(parents=True, exist_ok=True)
            evidence.write_text(result.stdout + result.stderr)
            print(result.stdout + result.stderr, flush=True)
            result.check_returncode()
        finally:
            try:
                adb('shell', 'am', 'force-stop', 'org.curtain.dns')
                (EVIDENCE / 'completion-logcat.txt').write_text(adb('logcat', '-d'))
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
            try:
                adb('emu', 'kill')
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            print(f'Emulator cleanup exit: {process.returncode}', flush=True)


if __name__ == '__main__':
    main()
