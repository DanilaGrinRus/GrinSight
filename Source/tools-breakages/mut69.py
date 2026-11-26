#!/usr/bin/env python3
"""Deliberate breakages of K201 (changed Tor bridges are taken up while the wallet is open: every process
that uses Tor is let go and started anew on the new lines) and of O71 (the wallet tries the built-in
bridges by itself). The window's part runs against the check copy /tmp/uic/app."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
H='/home/claude/fly/paycore/host'
HT=(H,['cargo','test','--offline','--features','test-chain','--','the_users_tor_bridges','follows_the','follows_the_tor','chain_layer_inside_the_program'])
A='/tmp/uic/app'
AT=(A,['cargo','test','--locked','--offline','--lib','--','the_built_in_bridges','a_payment_taken_back_says_so'])
C=H+'/src/chain.rs'; T=H+'/src/transport.rs'; O=H+'/src/onion.rs'; L=H+'/src/lib.rs'
W=A+'/src/tor.rs'; B=A+'/src/live/bridges.rs'
M=[
 (HT,L,'the host is told and nothing is started anew','                chain::bridges_changed(&self.places.tor);\n',''),
 (HT,C,'the chain process stays on the old lines','        if bridges_turn(&self.launcher.tor_off) != self.turn {\n            // the old one first','        if false {\n            // the old one first'),
 (HT,C,'the chain process is started anew at every call','        self.turn = bridges_turn(&self.launcher.tor_off);\n',''),
 (HT,T,'the message program stays on the old lines','(false, false) if crate::chain::bridges_turn(&self.launcher.off) != self.turn => {','(false, false) if false => {'),
 (HT,T,'the message program is started on the lines read at its first start','        self.config.tor_bridges = crate::tor_bridges::text();\n',''),
 (HT,O,'the address program stays on the old lines','        if crate::chain::bridges_turn(&self.given.off) != self.turn {\n            // the old one first','        if false {\n            // the old one first'),
 (HT,O,'the address program is started anew at every call','        self.turn = crate::chain::bridges_turn(&self.given.off);\n',''),
 (AT,W,'the way already chosen is tried again','        Mode::Obfs4 => vec![Mode::Snowflake],','        Mode::Obfs4 => vec![Mode::Obfs4, Mode::Snowflake],'),
 (AT,W,"the owner's own bridges are replaced",'        Mode::Own => Vec::new(),','        Mode::Own => vec![Mode::Obfs4],'),
 (AT,W,'a Tor that was up before the try counts','s.transport_ready && s.transport_starts > t.starts;','s.transport_ready;'),
 (AT,W,'the address program counts without having been down','s.onion_up && t.seen_down;','s.onion_up;'),
 (AT,W,'the try never gives up','    } else if elapsed >= TRY_WAIT {','    } else if false {'),
 (AT,W,'working at the last moment is given up','    if messages || address {\n        Verdict::Worked\n    } else if elapsed >= TRY_WAIT {\n        Verdict::GiveUp','    if elapsed >= TRY_WAIT {\n        Verdict::GiveUp\n    } else if messages || address {\n        Verdict::Worked'),
 (AT,B,'after a failure the choice is not put back','                None => {\n                    let original = t.original.0;\n                    put_back(app);','                None => {\n                    let original = t.original.0;\n                    with(|f| f.bridge_try = None);'),
 (AT,B,'a lock in the middle leaves the tried way in the file','''    if let Some((t, _)) = with(|f| f.bridge_try.take()) {
        if let Some(path) = tor_file() {
            let _ = save(&path, t.original.0, &t.original.1);
        }
    }''','''    let _ = with(|f| f.bridge_try.take());'''),
 (AT,B,'the bridges are offered without the program for them','    if crate::tor_off() || !with(|f| f.tor_program) {','    if crate::tor_off() {'),
 (AT,B,'a way that worked is not kept','        Verdict::Worked => {\n            with(|f| f.bridge_try = None);','        Verdict::Worked => {\n            put_back(app);'),
]
import sys
if len(sys.argv)>1: M=[m for m in M if m[0] is AT and m[1]==B]
bad=0
for (cwd,cmd),P,name,old,new in M:
    src=open(P).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(P,'w').write(src.replace(old,new))
    try: r=subprocess.run(cmd,cwd=cwd,env=ENV,capture_output=True,text=True,timeout=1500)
    finally: open(P,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
