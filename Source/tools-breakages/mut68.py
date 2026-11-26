#!/usr/bin/env python3
"""Deliberate breakages of O70 (conversations in windows of their own: three at most, one for a contact,
read as the main window reads them). Run against the check copy of the window (/tmp/uic/app)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
A='/tmp/uic/app'
T=['cargo','test','--locked','--offline','--lib','apart']
P=A+'/src/live/apart.rs'
M=[
 ('a fourth window may open','pub(crate) const MOST: usize = 3;','pub(crate) const MOST: usize = 4;'),
 ('the limit is one too many','    } else if open.len() >= MOST {','    } else if open.len() > MOST {'),
 ('a contact gets a second window','    if open.iter().any(|k| k == key) {','    if open.iter().any(|k| k != key) {'),
 ('with three open the contact that has a window is refused','    if open.iter().any(|k| k == key) {\n        Opened::Already\n    } else if open.len() >= MOST {\n        Opened::Full','    if open.len() >= MOST {\n        Opened::Full\n    } else if open.iter().any(|k| k == key) {\n        Opened::Already'),
 ("the contact's words are shown as the wallet's",'super::text(m, "dir").as_deref() == Some("out"),','super::text(m, "dir").as_deref() != Some("out"),'),
 ('the time of a message is lost','m.get("at").and_then(Value::as_u64).unwrap_or(0),','0,'),
]
bad=0
for name,old,new in M:
    src=open(P).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(P,'w').write(src.replace(old,new))
    try: r=subprocess.run(T,cwd=A,env=ENV,capture_output=True,text=True,timeout=1500)
    finally: open(P,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
