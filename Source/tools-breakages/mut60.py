#!/usr/bin/env python3
"""Deliberate breakages of K197 (taking back a signed payment that is in no block)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
R='/home/claude/fly/paycore/'
BR=(R+'bridge',['cargo','test','--offline','--test','bridge','--','taken_back','payments_through_json_only','the_owner_chooses'])
S=R+'wallet/src/state.rs'; L=R+'wallet/src/lib.rs'; B=R+'bridge/src/lib.rs'
M=[
 (S,'an unsigned payment is taken back','        if self.send_status(op) != Some(SendStatus::Finalized) {\n            return Err(CoreError::Refused("only a signed payment that is in no block can be taken back"));\n        }\n','        if self.send_status(op).is_none() {\n            return Err(CoreError::Refused("only a signed payment that is in no block can be taken back"));\n        }\n'),
 (S,'the payment of an invoice is taken back','        if s.invoice {\n            return Err(CoreError::Refused("the payment of an invoice is not taken back"));\n        }\n',''),
 (S,'a payment is taken back twice','        if self.replaced_by(op).is_some() {\n            return Err(CoreError::Refused("this payment is being taken back already"));\n        }\n',''),
 (S,'the fee of taking back is not taken off','        let fee = grin_core::libtx::tx_fee(commits.len(), 1, 1);\n        let amount = total.checked_sub(fee).filter(|left| *left > 0).ok_or(CoreError::Refused("the payment would not pay the fee of taking it back"))?;','        let fee = 0u64;\n        let amount = total.checked_sub(fee).filter(|left| *left > 0).ok_or(CoreError::Refused("the payment would not pay the fee of taking it back"))?;'),
 (S,'a cancelled taking back still holds the payment back','self.sends.values().find(|x| Self::in_flight(x) && x.replaces == Some(*op)).map(|x| x.op)','self.sends.values().find(|x| x.replaces == Some(*op)).map(|x| x.op)'),
 (S,'the payment taken back is a question to the owner for ever','.any(|s| Self::in_flight(s) && s.conflict_height.is_some() && !self.sends.values().any(|x| x.replaces == Some(s.op) && x.kernel_height.is_some()))','.any(|s| Self::in_flight(s) && s.conflict_height.is_some())'),
 (S,'an output held by any payment can be chosen','self.reserved_by(&o.commit).is_some_and(|holder| Some(&holder.op) != held_by)','self.reserved_by(&o.commit).is_some_and(|holder| Some(&holder.op) != held_by && held_by.is_none() && false)'),
 (L,'the inputs of the payment cannot be chosen for taking it back','replaces.as_ref().filter(|_| take_back))?,','None)?,'),
 (L,'taking back is checked as the replacement of a contested payment','            Some(_) if take_back => {}\n','            Some(_) if take_back && false => {}\n'),
 (L,'the taking back does not name what it replaces','How { chosen: Some((commits, true)), replaces: Some(*op), take_back: true, ..How::default() }','How { chosen: Some((commits, true)), ..How::default() }'),
 (B,'the payment taken back is handed to the network again','            .filter(|op| self.core.send_replaced_by(op).is_none())\n',''),
 (B,'the payment taken back is sent again by hand','                if self.core.send_replaced_by(&op).is_some() {\n                    return Err(CoreError::Refused("this payment is being taken back").into());\n                }\n',''),
 (B,'asking what it comes to takes the payment back','                if p.flag("plan")? {\n                    let (amount, fee, count) = self.core.take_back_plan(&old)?;','                if p.flag("plan")? && false {\n                    let (amount, fee, count) = self.core.take_back_plan(&old)?;'),
 (B,'the history does not say what replaces a payment','"replaced_by": self.core.send_replaced_by(&op).map(|id| hex(&id)),','"replaced_by": Value::Null,'),
 (B,'the history does not say what a payment replaces','"replaces": self.core.send_replaces(&op).map(|id| hex(&id)),','"replaces": Value::Null,'),
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
