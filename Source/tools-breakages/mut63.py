#!/usr/bin/env python3
"""Deliberate breakages of O60 (a doubt about Tor is said before the signature, with the ways out)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
UI=('/tmp/uic/app',['cargo','test','--locked','--offline','--lib'])
L='/tmp/uic/app/src/live.rs'; S='/tmp/uic/app/src/sync.rs'
M=[
 (S,'the doubt is said with Tor switched off','    if f.tor_off {\n        return None;\n    }\n    if not_sent(f).is_some() {','    if not_sent(f).is_some() {'),
 (S,'a payment that waits for Tor is no sign','    if not_sent(f).is_some() {\n        return Some(tr("An earlier payment','    if not_sent(f).is_some() && false {\n        return Some(tr("An earlier payment'),
 (S,'a Tor that is down is no sign','(f.transport.configured && f.transport.phase == "down") || (f.onion.configured && f.onion.phase == "failed")','(f.transport.configured && f.transport.phase == "down ") || (f.onion.configured && f.onion.phase == "failed")'),
 (S,'a failed Tor for addresses is no sign','|| (f.onion.configured && f.onion.phase == "failed")','|| (f.onion.configured && f.onion.phase == "failed ")'),
 (S,'a part that is not set up is taken for a broken Tor','(f.transport.configured && f.transport.phase == "down")','(f.transport.phase == "down")'),
 (L,'the doubt does not reach the window to sign','    app.set_sign_tor_doubt(doubt.map(sign_doubt_words).unwrap_or_default().into());','    app.set_sign_tor_doubt(SharedString::new());'),
 (L,'asked though everything goes directly anyway','    let doubt = if crate::direct() { None } else { crate::sync::tor_doubt(&view.sync) };','    let doubt = crate::sync::tor_doubt(&view.sync);'),
]
bad=0
for P,name,old,new in M:
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
