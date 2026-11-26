#!/usr/bin/env python3
"""Deliberate breakages of K196 (collecting outputs into one; small outputs taken along with a payment)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
R='/home/claude/fly/paycore/'
BR=(R+'bridge',['cargo','test','--offline','--test','bridge','--','outputs_are_collected','small_outputs','a_failed_collecting'])
WA=(R+'wallet',['cargo','test','--offline','--test','core','small_outputs'])
S=R+'wallet/src/state.rs'; L=R+'wallet/src/lib.rs'; B=R+'bridge/src/lib.rs'
USABLE='.filter(|o| o.spent.is_none() && self.mature(o, maturity) && self.reserved_by(&o.commit).is_none() && !self.is_kept(&o.commit))'
M=[
 (BR,S,'one output is collected','        if commits.len() < 2 {','        if commits.len() < 1 {'),
 (BR,S,'the fee of collecting is not taken off','        let fee = grin_core::libtx::tx_fee(commits.len(), 1, 1);\n        let amount','        let fee = 0u64;\n        let amount'),
 (BR,S,'collecting takes the dust','                    .filter(|o| o.value > one_more)\n','                    .filter(|o| o.value > 0)\n'),
 (BR,S,'collecting takes a marked output by its own choice',USABLE+'\n                    .filter(|o| o.value > one_more)','.filter(|o| o.spent.is_none() && self.mature(o, maturity) && self.reserved_by(&o.commit).is_none())\n                    .filter(|o| o.value > one_more)'),
 (BR,S,'a payment without change takes small outputs','        if picked.change == 0 || picked.inputs.is_empty() {','        if picked.inputs.is_empty() {'),
 (BR,S,'a marked output goes along',USABLE+'\n            .filter(|o| !picked.inputs','.filter(|o| o.spent.is_none() && self.mature(o, maturity) && self.reserved_by(&o.commit).is_none())\n            .filter(|o| !picked.inputs'),
 (BR,S,'the dust goes along','            if o.value <= fee_with.saturating_sub(fee_now) {\n                continue;\n            }','            if o.value == 0 {\n                continue;\n            }'),
 (BR,S,'the largest go along, not the smallest','        pool.sort_by(|a, b| a.value.cmp(&b.value).then(a.commit.cmp(&b.commit)));\n        for o in pool.into_iter().take(most) {','        pool.sort_by(|a, b| b.value.cmp(&a.value).then(a.commit.cmp(&b.commit)));\n        for o in pool.into_iter().take(most) {'),
 (BR,S,'the fee is not reckoned again','        picked.fee = fee;\n        Ok(())','        Ok(())'),
 (BR,S,'the change is not reckoned again','        picked.change = total.checked_sub(amount).and_then(|left| left.checked_sub(fee)).ok_or(CoreError::Build)?;','        let _ = total;'),
 (BR,L,"small outputs are added to the owner's choice",'        if chosen.is_none() && !late && replaces.is_none() {','        if !late && replaces.is_none() {'),
 (WA,L,'a late lock reckons small outputs in','        if chosen.is_none() && !late && replaces.is_none() {','        if chosen.is_none() && replaces.is_none() {'),
 (WA,L,'a replacement takes small outputs','        if chosen.is_none() && !late && replaces.is_none() {','        if chosen.is_none() && !late && self.gather > 0 {'),
 (BR,L,'the word is not kept','    pub fn set_gather(&mut self, most: usize) {\n        self.gather = most;','    pub fn set_gather(&mut self, most: usize) {\n        let _ = most;'),
 (BR,B,'the word cannot be taken back','                self.core.set_gather(if on { GATHER_MOST } else { 0 });','                self.core.set_gather(GATHER_MOST);'),
 (BR,B,'more than eight go along','const GATHER_MOST: usize = 8;','const GATHER_MOST: usize = 9;'),
 (BR,B,'what is not yes or no is taken for a word','                    _ => return Err(bad_params("on")),\n                };\n                self.core.set_gather','                    _ => false,\n                };\n                self.core.set_gather'),
 (BR,B,'the word to spend marked ones without naming them','                if spend_kept && chosen.is_none() {\n                    return Err(bad_params("spend_kept goes with inputs"));\n                }\n                let (prepared, amount, fee, count)','                let (prepared, amount, fee, count)'),
 (BR,B,'the payment to itself is not signed','                let done = self.dispatch("paycore.send.finalize", &Params(&end))?;','                let done = json!({});'),
 (BR,B,'the history does not give the number of a payment','                            "slate_id": self.core.send_slate_id(&op).map(|id| hex(&id)),','                            "slate_id": Value::Null,'),
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
