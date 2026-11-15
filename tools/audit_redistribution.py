#!/usr/bin/env python3
"""Read-only network evidence collection; never alters source data or publishes."""
import concurrent.futures, datetime, hashlib, json, re, urllib.request, urllib.error
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'reports/licensing-evidence'
OUT.mkdir(parents=True,exist_ok=True)
manifest=json.loads((ROOT/'data/blocklists/audit-manifest.json').read_text())
jobs={}
def add(url, sid): jobs.setdefault(url,set()).add(sid)
for s in manifest['sources']:
 if s['status']!='ok': continue
 sid=s['id']; u=s['url']; pub=s.get('firebog',{}).get('publisher_url')
 if pub: add(pub,sid)
 match=re.match(r'https://raw.githubusercontent.com/([^/]+/[^/]+)/([^/]+)/',u)
 if not match and pub:
  match=re.match(r'https://github.com/([^/]+/[^/]+)',pub.rstrip('/'))
  if match: repo=match[1]; branch='HEAD'
 elif match: repo=match[1]; branch=match[2]
 if match:
  for f in ['LICENSE','LICENSE.md','LICENSE.txt','README.md']:
   add(f'https://raw.githubusercontent.com/{repo}/{branch}/{f}',sid)
 else:
  # The archived input header is evidence too; avoid redownloading megabyte data.
  pass
extra={
 'https://phishing.army/license/':['7c9b29c127ec4245c83a'],
 'https://git.frogeye.fr/geoffrey/eulaurarien/raw/branch/master/LICENSE':['ae3ae6e073b74350ec89','27971c0b41e4246015b2'],
 'https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/LICENSE':['7ce05a7969fd86f4b2ae','11170fa6b9b3e8fc77c9'],
 'https://gitlab.com/quidsup/notrack-blocklists/-/raw/master/README.md':['7ce05a7969fd86f4b2ae','11170fa6b9b3e8fc77c9'],
 'https://gitlab.com/malware-filter/phishing-filter/-/raw/master/LICENSE':['ce575d06f871ba55f910'],
 'https://gitlab.com/malware-filter/phishing-filter/-/raw/master/README.md':['ce575d06f871ba55f910'],
 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/README.md':['e7868de6fead6b660297','bd4249d44d231e54da8e','496340023ef0f01ff0a3','108b90fb7cea2a21b8a3'],
 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/usedsources.md':['e7868de6fead6b660297','bd4249d44d231e54da8e','496340023ef0f01ff0a3','108b90fb7cea2a21b8a3'],
 'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/LICENSE.md':['7f0588e41d381da9f33b'],
 'https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/LICENSE':['adeb91c87c37c4cdce52'],
 'https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/README.md':['adeb91c87c37c4cdce52'],
 'https://creativecommons.org/licenses/by/3.0/legalcode.txt':['e70556964925b652f70f'],
 'https://creativecommons.org/licenses/by/4.0/legalcode.txt':['9401af26c002c3d5751a'],
 'https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode.txt':['ab365ffc549f930dc78c'],
}
for url,sids in extra.items():
 for sid in sids:add(url,sid)
def fetch(item):
 url,sids=item; rec={'url':url,'source_ids':sorted(sids),'retrieved_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
 try:
  req=urllib.request.Request(url,headers={'User-Agent':'Curtain-redistribution-audit/1.0'})
  with urllib.request.urlopen(req,timeout=18) as r:
   raw=r.read(3_000_000); rec.update(status=r.status,final_url=r.url,content_type=r.headers.get('Content-Type'))
  name=hashlib.sha256(url.encode()).hexdigest()[:20]+'.txt'
  (OUT/name).write_bytes(raw)
  rec.update(file='reports/licensing-evidence/'+name,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
 except Exception as e:rec.update(status='error',error=str(e))
 return rec
if __name__=='__main__':
 with concurrent.futures.ThreadPoolExecutor(max_workers=18) as pool: records=list(pool.map(fetch,jobs.items()))
 (OUT/'retrievals.json').write_text(json.dumps(records,indent=2)+'\n')
 print(json.dumps({'requests':len(records),'successful':sum(r['status']==200 for r in records),'failed':sum(r['status']!=200 for r in records)}))
 for r in records:
  if r['status']==200 and any(x in r['url'] for x in ['LICENSE','usedsources','hagezi/dns-blocklists/main/README']):
   t=(ROOT/r['file']).read_text(errors='replace')
   print('\nURL',r['url'],'FILE',r['file'],'\n',t[:1100])
