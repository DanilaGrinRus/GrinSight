#!/usr/bin/env python3
"""Deliberate breakages of O50 (the history hidden in the window)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
UI=('/tmp/uic/app',['cargo','test','--locked','--offline','--lib'])
P='/tmp/uic/app/src/live.rs'
M=[
 ('with nothing hidden, the oldest is','    through != 0 && time <= through','    time <= through'),
 ('what came after is hidden too','    through != 0 && time <= through','    through != 0'),
 ('the block it was hidden through stays','    through != 0 && time <= through','    through != 0 && time < through'),
 ('the hidden ones stay in the lists','        order.retain(|at| times.get(*at).is_some_and(|time| !hidden(*time, crate::history_hidden())));','        order.retain(|at| times.get(*at).is_some());'),
]
bad=0
for name,old,new in M:
    src=open(P).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(P,'w').write(src.replace(old,new))
    try: r=subprocess.run(UI[1],cwd=UI[0],env=ENV,capture_output=True,text=True,timeout=1500)
    finally: open(P,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
