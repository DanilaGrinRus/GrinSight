#!/usr/bin/env python3
"""Deliberate breakages of K199 (the check code of a contact and the owner's mark that it was compared)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
R='/home/claude/fly/paycore/'
BR=(R+'bridge',['cargo','test','--offline','--test','bridge','check_code'])
S=R+'wallet/src/state.rs'; L=R+'wallet/src/lib.rs'; B=R+'bridge/src/lib.rs'
M=[
 (L,'each wallet puts its own side first','        sides.sort();\n',''),
 (L,"the contact's address is not in the code",'[c.key.as_slice(), theirs.as_slice()].concat()','[c.key.as_slice(), c.key.as_slice()].concat()'),
 (L,"the wallet's own address is not in the code",'[own.public.as_slice(), mine.as_slice()].concat()','[own.public.as_slice(), own.public.as_slice()].concat()'),
 (L,'the message keys are not in the code','let mut sides = [[own.public.as_slice(), mine.as_slice()].concat(), [c.key.as_slice(), theirs.as_slice()].concat()];','let mut sides = [[mine.as_slice(), mine.as_slice()].concat(), [theirs.as_slice(), theirs.as_slice()].concat()];'),
 (L,'five words','pub const CHECK_WORDS: usize = 6;','pub const CHECK_WORDS: usize = 5;'),
 (L,'the mark is written every time','        if now == on {\n            return Ok(());\n        }\n        self.commit_plain(Event::ContactChecked','        let _ = now;\n        self.commit_plain(Event::ContactChecked'),
 (S,'the mark outlives a change of the address','let checked = self.contacts.get(&k).is_some_and(|c| c.checked && c.address == *address);','let checked = self.contacts.get(&k).is_some_and(|c| c.checked);'),
 (S,'the mark is lost with a new name','let checked = self.contacts.get(&k).is_some_and(|c| c.checked && c.address == *address);','let checked = false;'),
 (S,'a contact without an address is marked','                if *on && c.address.is_none() {\n                    return Err(CoreError::Refused("the contact has no address to check"));\n                }\n',''),
 (S,'a wallet without a message key marks','                if *on && !own {\n                    return Err(CoreError::Refused("the wallet has no transport identity"));\n                }\n',''),
 (S,'the mark is not kept','                c.checked = *on;\n                Ok(())','                let _ = c;\n                Ok(())'),
 (B,'the list does not say the mark','                            "checked": c.checked,','                            "checked": false,'),
 (B,'what is not yes or no marks','                    _ => return Err(bad_params("on")),\n                };\n                self.core.contact_check(&key, on)?;','                    _ => true,\n                };\n                self.core.contact_check(&key, on)?;'),
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
