#!/usr/bin/env python3
"""Bounded local-only full CDN download + VPN + process-restart smoke; no publication."""
from pathlib import Path
import functools
import http.server
import os
import subprocess
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
SDK=Path(os.environ['ANDROID_HOME'])
ADB=str(SDK/'platform-tools/adb')
EVIDENCE=Path(os.environ.get('CURTAIN_EVIDENCE', str(ROOT/'evidence')))
EVIDENCE.mkdir(parents=True, exist_ok=True)
handler=functools.partial(http.server.SimpleHTTPRequestHandler,directory=str(ROOT.parent/'artifacts/r2'))
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),handler)
threading.Thread(target=server.serve_forever,daemon=True).start()

def run(*args,timeout=120):
    result=subprocess.run([ADB,*args],capture_output=True,text=True,timeout=timeout)
    print('adb',*args,'\n',result.stdout,result.stderr,flush=True)
    if result.returncode:
        raise RuntimeError(f'adb exit {result.returncode}')
    return result.stdout

with (EVIDENCE/'cdn-emulator-foreground.txt').open('w') as log:
    emulator=subprocess.Popen([str(SDK/'emulator/emulator'),'-avd','curtain35aosp','-no-window','-no-audio','-no-boot-anim','-gpu','swiftshader','-feature','-Vulkan','-accel','off','-cores','2','-memory','1536','-no-snapshot','-no-metrics'],stdout=log,stderr=subprocess.STDOUT)
    try:
        deadline=time.monotonic()+300
        while time.monotonic()<deadline:
            if emulator.poll() is not None:
                raise RuntimeError(f'emulator exited {emulator.returncode}')
            check=subprocess.run([ADB,'shell','getprop','sys.boot_completed'],capture_output=True,text=True,timeout=20)
            if check.stdout.strip()=='1':
                break
            time.sleep(5)
        else:
            raise RuntimeError('TCG boot exceeded 300s bound')
        run('install','-r',str(ROOT/'app/build/outputs/apk/debug/app-debug.apk'))
        run('install','-r',str(ROOT/'app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk'))
        run('shell','pm','clear','org.curtain.dns')
        run('shell','appops','set','org.curtain.dns','ACTIVATE_VPN','allow')
        run('shell','settings','put','global','private_dns_mode','off')
        # Re-associate this private AVD: a saved boot association can advertise
        # an IP while netd's IPv4 default-route installation has failed.
        run('shell','svc','wifi','disable')
        wifi_deadline=time.monotonic()+60
        while time.monotonic()<wifi_deadline:
            if 'Wifi is disabled' in run('shell','cmd','wifi','status',timeout=15):
                break
            time.sleep(1)
        else:
            raise RuntimeError('Wi-Fi disable acknowledgment exceeded 60s')
        run('shell','svc','wifi','enable')
        wifi_deadline=time.monotonic()+60
        while time.monotonic()<wifi_deadline:
            if 'Wifi is enabled' in run('shell','cmd','wifi','status',timeout=15):
                break
            time.sleep(1)
        else:
            raise RuntimeError('Wi-Fi enable acknowledgment exceeded 60s')
        run('shell','cmd','wifi','start-scan')
        run('shell','cmd','wifi','list-scan-results')
        # The emulator advertises this open local SSID; no phone/account credentials.
        run('shell','cmd','wifi','connect-network','AndroidWifi','open')
        network_deadline=time.monotonic()+60
        while time.monotonic()<network_deadline:
            if 'Wifi is connected' in run('shell','cmd','wifi','status',timeout=15):
                break
            time.sleep(3)
        else:
            raise RuntimeError('Emulator AndroidWifi did not connect within 60s')
        fixture=f'http://10.0.2.2:{server.server_port}/curtain/'
        result=run('shell','am','instrument','-w','-e','fixture',fixture,'org.curtain.dns.test/org.curtain.dns.SmokeInstrumentation',timeout=420)
        (EVIDENCE/'cdn-emulator-download-smoke.txt').write_text(result)
        if not result.rstrip().endswith('PASS') or 'FAIL:' in result:
            raise RuntimeError('First download instrumentation failed')
        # Force a new app process; stop only the fixture HTTP service, not ordinary Internet.
        run('shell','am','force-stop','org.curtain.dns')
        server.shutdown(); server.server_close()
        result=run('shell','am','instrument','-w','-e','fixture',fixture,'org.curtain.dns.test/org.curtain.dns.SmokeInstrumentation',timeout=420)
        (EVIDENCE/'cdn-emulator-offline-smoke.txt').write_text(result)
        if not result.rstrip().endswith('PASS') or 'FAIL:' in result:
            raise RuntimeError('Offline rules restart instrumentation failed')
        print('PASS: real full download; VPN block/allow/HTTPS/stop; same checks after process restart with CDN offline',flush=True)
    finally:
        for name,args in [('logcat',['logcat','-d']),('connectivity',['shell','dumpsys','connectivity']),('jobs',['shell','dumpsys','jobscheduler'])]:
            try:
                diagnostic=subprocess.run([ADB,*args],capture_output=True,text=True,timeout=30)
                (EVIDENCE/f'cdn-emulator-{name}.txt').write_text(diagnostic.stdout+diagnostic.stderr)
            except subprocess.TimeoutExpired:
                pass
        subprocess.run([ADB,'emu','kill'],capture_output=True,timeout=15)
        if emulator.poll() is None:
            emulator.terminate()
            try:
                emulator.wait(timeout=10)
            except subprocess.TimeoutExpired:
                emulator.kill()
        server.shutdown(); server.server_close()
