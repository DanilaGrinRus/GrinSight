#!/usr/bin/env python3
"""Deliberate breakages of K200 (the sender's text of an incoming payment is kept and given again)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
R='/home/claude/fly/paycore/'
BR=(R+'bridge',['cargo','test','--offline','--test','bridge','--','payments_through_json_only','the_senders_text'])
S=R+'wallet/src/state.rs'; L=R+'wallet/src/lib.rs'; B=R+'bridge/src/lib.rs'
M=[
 (L,"the sender's text is not kept",'            s1: s1.to_vec(),','            s1: Vec::new(),'),
 (L,"the wallet's own invoice is given as a sender's text",'            s1_fp: sha(&built.i1).to_vec(),\n            s1: Vec::new(),','            s1_fp: sha(&built.i1).to_vec(),\n            s1: built.i1.clone(),'),
 (S,'the text of a payment given up is kept','                d.s1.clear();\n',''),
 (L,'an empty text is given as a text','        (!d.s1.is_empty()).then(|| d.s1.clone())','        Some(d.s1.clone())'),
 (B,"the reply is given for the sender's text",'                let s1 = self.core.incoming_request(&id).ok_or(CoreError::NotFound)?;','                let s1 = self.core.incoming_reply(&id).ok_or(CoreError::NotFound)?;'),
 (B,'the history does not say the text is kept','                            "request_kept": self.core.incoming_request(&id).is_some(),','                            "request_kept": false,'),
]
bad=0
for P,name,old,new in M:
    src=open(P).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(P,'w').write(src.replace(old,new))
    try: r=subprocess.run(BR[1],cwd=BR[0],env=ENV,capture_output=True,text=True,timeout=1500)
    finally: open(P,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
