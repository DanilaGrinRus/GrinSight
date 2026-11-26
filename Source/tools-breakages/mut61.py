#!/usr/bin/env python3
"""Deliberate breakages of the window for K197 and of O54, O55 (taking back in the window; held files named; an unsigned payment opens from its line)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
UI=('/tmp/uic/app',['cargo','test','--locked','--offline','--lib'])
P='/tmp/uic/app/src/live.rs'
M=[
 ('a payment being taken back says "going to the network"','    if row.replaced_by.is_some() && row.state == "finalized" {','    if row.replaced_by.is_some() && row.state == "finalized" && false {'),
 ('a payment taken back says "contested - check it"','    if ended && sends.iter().any(|x| x.replaces.as_deref() == Some(row.op.as_str()) && x.state == "confirmed") {','    if ended && false {'),
 ('any contested payment is said to be taken back','    if ended && sends.iter().any(|x| x.replaces.as_deref() == Some(row.op.as_str()) && x.state == "confirmed") {','    if ended {'),
 ('a taking back that lost says "failed"','    if row.replaces.is_some() && ended {','    if row.replaces.is_some() && ended && false {'),
 ('taking back is offered for a payment being taken back','back: waiting && !own_one && row.replaced_by.is_none() }','back: waiting && !own_one }'),
 ('taking back is offered for the taking back itself','back: waiting && !own_one && row.replaced_by.is_none() }','back: waiting && row.replaced_by.is_none() }'),
 ('the taking back is called collecting','            let who = if own_one && row.replaces.is_some() {','            let who = if own_one && row.replaces.is_some() && false {'),
 ('an unsigned payment to a contact does not open from its line','            refs.push(if row.state == "prepared" && !row.locked && !row.invoice {','            refs.push(if row.state == "prepared" && !row.locked && !row.invoice && row.to.is_none() {'),
 ('held files are not named','    if step.contains("WouldBlock") || step.contains("locked") {','    if step.contains("WouldBlock ") {'),
 ('the step is not named','        format!("{said} ({})", step.trim())','        said.into()'),
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
