#!/usr/bin/env python3
"""Deliberate breakages of O52 and O53 (a payment to itself is one line; a message not taken says why)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
UI=('/tmp/uic/app',['cargo','test','--locked','--offline','--lib'])
P='/tmp/uic/app/src/live.rs'
M=[
 ('a payment to itself is shown as money gone','            let left = if own_one { row.fee } else { row.amount.saturating_add(row.fee) };','            let left = row.amount.saturating_add(row.fee);'),
 ('its arrival has a line of its own','            if own.contains(&row.slate_id) {\n                continue;\n            }','            if own.contains(&row.slate_id) && false {\n                continue;\n            }'),
 ('payments without a number are taken for one payment','sends.iter().filter(|s| !s.slate_id.is_empty() && incoming','sends.iter().filter(|s| incoming'),
 ('every payment is called a payment to itself','            let own_one = own.contains(&row.slate_id);','            let own_one = !own.is_empty();'),
 ('a wallet without a message key says nothing of it','        "the wallet has no transport identity" => tr(','        "the wallet has no transport identity " => tr('),
 ('a service that is not running is not named','        "the transport cannot seal now" => tr(','        "the transport cannot seal now " => tr('),
 ('nothing to collect is not said','        "there are not two outputs to collect" => tr(','        "there are not two outputs to collect " => tr('),
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
