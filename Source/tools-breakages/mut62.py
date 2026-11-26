#!/usr/bin/env python3
"""Deliberate breakages of K198 (the agreement to the direct way for one payment is kept with the payment)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
R='/home/claude/fly/paycore/'
BR=(R+'bridge',['cargo','test','--offline','--test','bridge','--','payments_through_json_only','finished_transactions'])
WA=(R+'wallet',['cargo','test','--offline','--test','core','direct_way'])
S=R+'wallet/src/state.rs'; L=R+'wallet/src/lib.rs'; B=R+'bridge/src/lib.rs'
M=[
 (WA,S,'the agreement is not kept','                s.direct = true;\n                Ok(())','                let _ = s;\n                Ok(())'),
 (WA,S,'an unsigned payment takes the agreement','                if self.send_status(op).ok_or(CoreError::NotFound)? != SendStatus::Finalized {\n                    return Err(CoreError::Refused("only a signed payment that is in no block takes the direct way"));\n                }\n','                self.send_status(op).ok_or(CoreError::NotFound)?;\n'),
 (WA,L,'the agreement is written every time','        if self.send_direct(op) {\n            return Ok(());\n        }\n        self.commit_plain(Event::Direct { op: *op })','        self.commit_plain(Event::Direct { op: *op })'),
 (WA,L,'every payment is said to be agreed','self.st.sends.get(&state::hex(op)).is_some_and(|s| s.direct)','self.st.sends.get(&state::hex(op)).is_some()'),
 (BR,B,'the agreement is acted on and not written','                if p.flag("direct")? {\n                    self.core.send_agree_direct(&op)?;\n                }\n','                let _ = p.flag("direct")?;\n'),
 (BR,B,'the handler forgets the agreement','let outcome = if self.core.send_direct(&op) { self.ports.broadcaster.post_tx_direct(&fin.tx) } else { self.ports.broadcaster.post_tx(&fin.tx) };','let outcome = self.ports.broadcaster.post_tx(&fin.tx);'),
 (BR,B,'the handler sends every payment directly','let outcome = if self.core.send_direct(&op) { self.ports.broadcaster.post_tx_direct(&fin.tx) } else { self.ports.broadcaster.post_tx(&fin.tx) };','let outcome = self.ports.broadcaster.post_tx_direct(&fin.tx);'),
 (BR,B,'the history does not say the agreement','                            "direct": self.core.send_direct(&op),','                            "direct": false,'),
]
bad=0
for where,P,name,old,new in M:
    src=open(P).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(P,'w').write(src.replace(old,new))
    try: r=subprocess.run(where[1],cwd=where[0],env=ENV,capture_output=True,text=True,timeout=1500)
    finally: open(P,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
