#!/usr/bin/env python3
"""Deliberate breakages of K195 (the owner's outputs: the mark "not to be spent" and the choice of what a payment is paid with)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
BR=(F+'/paycore/bridge',['cargo','test','--offline','--test','bridge','the_owner_chooses'])
WA=(F+'/paycore/wallet',['cargo','test','--offline','--test','core','the_mark_not'])
S='paycore/wallet/src/state.rs'; L='paycore/wallet/src/lib.rs'; B='paycore/bridge/src/lib.rs'
M=[
 ("the wallet's own choice takes a marked output",BR,S,"if o.spent.is_some() || !self.mature(o, maturity) || self.is_kept(&o.commit) {","if o.spent.is_some() || !self.mature(o, maturity) {"),
 ("a late lock takes a marked output",BR,S,"                    && self.reserved_by(&o.commit).is_none()\n                    && !self.is_kept(&o.commit)","                    && self.reserved_by(&o.commit).is_none()"),
 ("a marked output is chosen without the owner's word",BR,S,"if self.is_kept(&o.commit) && !spend_kept {","if self.is_kept(&o.commit) && !spend_kept && false {"),
 ("the owner's word does not let a marked output be chosen",BR,S,"if self.is_kept(&o.commit) && !spend_kept {","if self.is_kept(&o.commit) {"),
 ("an output is taken twice",BR,S,"if inputs.iter().any(|o| o.commit == commit.as_slice()) {","if false {"),
 ("an output held by another payment is chosen",BR,S,"if !self.mature(o, maturity) || self.reserved_by(&o.commit).is_some() {","if !self.mature(o, maturity) {"),
 ("no output chosen is the wallet's own choice",BR,S,'        if chosen.is_empty() {\n            return Err(CoreError::Refused("no output is chosen"));\n        }','        if chosen.is_empty() {\n            return self.select_inputs(amount, None, maturity);\n        }'),
 ("outputs that do not cover the amount are topped up",BR,S,'        Err(CoreError::Refused("the chosen outputs do not cover the amount and its fee"))','        self.select_inputs(amount, None, maturity)'),
 ("a marked output is counted as spendable",BR,S,"            } else if self.is_kept(&o.commit) {\n                // K195: marked","            } else if false {\n                // K195: marked"),
 ("a held output is counted as marked",BR,S,"            let slot = if self.reserved_by(&o.commit).is_some() {\n                &mut b.reserved\n            } else if self.is_kept(&o.commit) {","            let slot = if self.is_kept(&o.commit) {\n                &mut b.kept\n            } else if self.reserved_by(&o.commit).is_some() {\n                &mut b.reserved\n            } else if false {"),
 ("the mark is not kept",BR,S,"                    self.kept.insert(key);","                    let _ = key;"),
 ("the mark cannot be taken off",BR,S,"                    self.kept.remove(&key);","                    let _ = key;"),
 ("an output that is not there is marked",WA,S,"                    if !self.outputs.get(&key).is_some_and(|o| o.spent.is_none()) {\n                        return Err(CoreError::NotFound);\n                    }","")  ,
 ("the smallest first",BR,S,"list.sort_by(|a, b| b.0.value.cmp(&a.0.value).then(a.0.commit.cmp(&b.0.commit)));","list.sort_by(|a, b| a.0.value.cmp(&b.0.value).then(a.0.commit.cmp(&b.0.commit)));"),
 ("marking again writes again",BR,L,"        if self.st.is_kept(commit) == on {\n            return Ok(());\n        }",""),
 ("the wallet ignores the choice",BR,L,"            Some((commits, spend_kept)) => self.st.select_chosen(amount, commits, *spend_kept, self.maturity)?,","            Some(_) => self.st.select_inputs(amount, replaces.as_ref(), self.maturity)?,"),
 ("the bridge drops the owner's word",BR,B,"None => self.core.send_prepare_chosen(amount, ttl, chosen, spend_kept, proof_to, None)?,","None => self.core.send_prepare_chosen(amount, ttl, chosen, false, proof_to, None)?,"),
 ("the bridge gives the owner's word by itself",BR,B,"None => self.core.send_prepare_chosen(amount, ttl, chosen, spend_kept, proof_to, None)?,","None => self.core.send_prepare_chosen(amount, ttl, chosen, true, proof_to, None)?,"),
 ("the owner's word is taken without a choice",BR,B,'                if p.flag("spend_kept")? {\n                    return Err(bad_params("spend_kept goes with inputs"));\n                }',''),
 ("a held output is listed as spendable",BR,B,'"state": if o.reserved { "reserved" }','"state": if o.reserved && false { "reserved" }'),
 ("the list does not say the mark",BR,B,'                            "kept": o.kept,','                            "kept": false,'),
 ("the balance does not say what is marked",BR,B,'"kept": b.kept.to_string(),','"kept": "0",'),
]
bad=0
for name,(cwd,cmd),f,old,new in M:
    p=os.path.join(F,f); src=open(p).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(p,'w').write(src.replace(old,new))
    try: r=subprocess.run(cmd,cwd=cwd,env=ENV,capture_output=True,text=True,timeout=1500)
    finally: open(p,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
