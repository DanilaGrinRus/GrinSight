#!/usr/bin/env python3
"""Deliberate breakages of K190 (confirmations and the owner's number for "received") and K191 (the texts of a payment, again)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
BR=(F+'/paycore/bridge',['cargo','test','--offline','--test','bridge'])
UI=('/tmp/uic/app',['cargo','test','--locked','--lib','payment_line_tests'])
M=[
 ('the owner\'s number is not used',BR,'paycore/bridge/src/lib.rs','k_conf: self.k_conf_owner.unwrap_or(basis.k_conf).max(1), ..basis }','k_conf: basis.k_conf.max(1), ..basis }'),
 ('zero confirmations are taken',BR,'paycore/bridge/src/lib.rs','if !(1..=MAX_K_CONF).contains(&count) {','if count > MAX_K_CONF {'),
 ('any number of confirmations is taken',BR,'paycore/bridge/src/lib.rs','if !(1..=MAX_K_CONF).contains(&count) {','if count == 0 {'),
 ('the history does not say the number in force',BR,'paycore/bridge/src/lib.rs','                let k_conf = self.wallet_basis().k_conf;','                let k_conf = self.ports.chain.k_conf();'),
 ('the history gives no block of an incoming payment',BR,'paycore/bridge/src/lib.rs','"kernel_height": self.core.incoming_kernel_height(&id),','"kernel_height": Value::Null,'),
 ('a payment that is not signed is said to be',BR,'paycore/bridge/src/lib.rs','"signed": self.core.send_result(&op).is_some(),','"signed": false,'),
 ('the reply of an unknown payment is "found"',BR,'paycore/bridge/src/lib.rs','let s2 = self.core.incoming_reply(&id).ok_or(CoreError::NotFound)?;','let s2 = self.core.incoming_reply(&id).unwrap_or_default();'),
 ('the block a payment is in is not counted',UI,'/tmp/uic/app/src/live.rs','    Some(tip.checked_sub(kernel)?.saturating_add(1))','    tip.checked_sub(kernel)'),
 ('a block above the tip gives confirmations',UI,'/tmp/uic/app/src/live.rs','    Some(tip.checked_sub(kernel)?.saturating_add(1))','    Some(tip.saturating_sub(kernel).saturating_add(1))'),
 ('a preliminary payment is said to be received',UI,'/tmp/uic/app/src/live.rs','        ("preliminary", Some(have)) if k_conf > 0 => (fill(tr("in a block · confirmations: {} of {}"','        ("preliminary", Some(have)) if k_conf > 0 => (fill(tr("received · confirmations: {} of {}"'),
]
bad=0
for name,(cwd,cmd),f,old,new in M:
    p=f if f.startswith('/') else os.path.join(F,f); src=open(p).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(p,'w').write(src.replace(old,new))
    try: r=subprocess.run(cmd,cwd=cwd,env=ENV,capture_output=True,text=True,timeout=1200)
    finally: open(p,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
