#!/usr/bin/env python3
"""Run each index in an isolated child and retain actual output and peak RSS."""
import json
import resource
import subprocess
import time
from pathlib import Path

root = Path(__file__).resolve().parent
for kind in ('sorted', 'hash'):
    started = time.monotonic()
    with (root/'evidence'/f'{kind}.json').open('w') as out, (root/'evidence'/f'{kind}-stderr.txt').open('w') as err:
        child = subprocess.Popen([str(root/'target/release/curtain-domain-bench'), kind, str(root.parent/'data/blocklists/domains.experimental.txt')], stdout=out, stderr=err)
        pid, status, usage = __import__('os').wait4(child.pid, 0)
        child.returncode = __import__('os').waitstatus_to_exitcode(status)
    data = {'index':kind,'exit_code':child.returncode,'wall_s':time.monotonic()-started,'peak_rss_kib':usage.ru_maxrss,'user_s':usage.ru_utime,'system_s':usage.ru_stime}
    (root/'evidence'/f'{kind}-process.json').write_text(json.dumps(data,indent=2)+'\n')
    print(json.dumps(data),flush=True)
    if child.returncode:
        raise SystemExit(child.returncode)
