#!/usr/bin/env python3
"""Renames GrinSight Fly to GrinSight in the given files (paths on stdin).
On-disk format marks keep their old wording: changing them would close
existing wallets."""
import sys
KEEP=['grinsight-fly-profile','GrinSight Fly tail guard key v1','GrinSight Fly transport store key v1']
RULES=[
 ('Name: "{group}\\GrinSight Fly"','Name: "{group}\\GrinSight Light"'),
 ('Name: "{autodesktop}\\GrinSight Fly"','Name: "{autodesktop}\\GrinSight Light"'),
 ('DefaultGroupName=GrinSight Fly','DefaultGroupName=GrinSight Light'),
 ('Name=GrinSight Fly','Name=GrinSight Light'),
 ('GrinSightFly.exe','GrinSight.exe'),
 ('Get-Process -Name GrinSightFly,','Get-Process -Name GrinSight,'),
 ('GrinSightFly-','GrinSight-'),
 ('GrinSightFly','GrinSightLight'),
 ('grinsight-fly.iss','grinsight.iss'),
 ('grinsight-fly.ico','grinsight.ico'),
 ('grinsight-fly','grinsight-light'),
 ('grinsight_fly','grinsight_light'),
 ('GrinSight Fly','GrinSight'),
]
changed=0
for p in sys.stdin.read().splitlines():
    try: b=open(p,'rb').read(); s=b.decode('utf-8')
    except Exception as e: print('SKIP',p,e); continue
    t=s
    for i,k in enumerate(KEEP): t=t.replace(k,'\x00KEEP%d\x00'%i)
    for a,c in RULES: t=t.replace(a,c)
    for i,k in enumerate(KEEP): t=t.replace('\x00KEEP%d\x00'%i,k)
    if t!=s:
        open(p,'wb').write(t.encode('utf-8')); changed+=1; print('changed',p)
print('files changed:',changed)
