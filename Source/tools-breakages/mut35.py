#!/usr/bin/env python3
"""Deliberate breakages of the second audit round's fixes (K121-K123, findings
20-26). Each must make a test fail."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
PC='/home/claude/fly/paycore'
UI='/tmp/uicheck'
HL='/home/claude/fly/ui/host-link'
BRIDGE=(PC,['cargo','test','--offline','--features','stub','--manifest-path','bridge/Cargo.toml','--test','delivery','--test','bridge'])
WINDOW=(UI,['cargo','test','--offline','--lib'])
LINK=(HL,['cargo','test','--offline'])
B='bridge/src/lib.rs'; S='wallet/src/state.rs'; W='wallet/src/lib.rs'
L='src/live.rs'; A='src/lib.rs'
M=[
 ('a waiting message rotated out (K122)', BRIDGE, S, "        let Some(i) = list.iter().position(|r| !r.waiting()) else { break };", "        let Some(i) = list.iter().position(|_| true) else { break };"),
 ('no trim after the relay accepted (K122)', BRIDGE, S, "                trim_conversation(list);\n                Ok(())", "                Ok(())"),
 ('waiting messages unbounded (K121)', BRIDGE, W, "        if waiting >= MAX_WAITING_MESSAGES {", "        if waiting >= usize::MAX {"),
 ('history rows without evidence (22)', BRIDGE, B, '"status": evidence.as_ref().map(|o| o.status),', '"status": "confirmed",'),
 ('history ignores the selected branch (22)', BRIDGE, B, "                if basis.selected.is_none() || basis.selected != self.core.tip() =>", "                if false =>"),
 ('review without the recipient (K123)', BRIDGE, B, '"receiver_address": review.receiver.map(|key| hex(&key)),', '"receiver_address": Option::<String>::None,'),
 # the check stands in both readers of a prepared payment (its numbers and its text): both are broken
 ('review of a signed payment (K123)', BRIDGE, W, "        if self.st.send_status(op) != Some(SendStatus::Prepared) {\n            return Err(CoreError::Refused(\"payment is not prepared\"));", "        if false {\n            return Err(CoreError::Refused(\"payment is not prepared\"));", 2),
 ('the service peer not checked (20)', LINK, 'src/lib.rs', "    if peer_uid? != own_uid {", "    if false {"),
 ('a missing host opens a wallet (21)', WINDOW, A, "    app.set_login_note(tr(\"Wallet process missing. Check the installation.\"", "    crate::fill_sample(app);\n    app.set_login_note(tr(\"Wallet process missing. Check the installation.\""),
 ('options skipped before the first chain folder (23)', WINDOW, L, "                builder.recursive(false).create(&chain)?;", "                continue;"),
 ('a read error taken for clearing (23)', WINDOW, L, "        Ok(_) => Err(std::io::ErrorKind::InvalidData.into()),", "        Ok(_) => Ok(None),"),
 ('a review of another payment shown (25)', WINDOW, L, "    if review.get(\"op\")?.as_str()? != flow.op { return None; }\n", ""),
 ('the chat read in the worker (26)', WINDOW, L, "    let (selected, network) = with(|f| (f.chat.clone(), f.testnet));\n    move || read(selected, network)", "    move || read(with(|f| f.chat.clone()), with(|f| f.testnet))"),
]
only=sys.argv[1:]; bad=0; n=0
for name,(root,cmd),f,old,new,*times in M:
    if only and not any(o in name for o in only): continue
    n+=1
    p=os.path.join(root,f); src=open(p).read()
    if src.count(old)!=(times[0] if times else 1):
        print('NOT APPLIED',name,src.count(old), flush=True); bad+=1; continue
    open(p,'w').write(src.replace(old,new))
    try:
        r=subprocess.run(cmd,cwd=root,env=ENV,capture_output=True,text=True,timeout=1500)
    finally:
        open(p,'w').write(src)
    text=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name, flush=True); bad+=1
    elif 'error[' in text or 'could not compile' in text: print('NO BUILD',name, flush=True); bad+=1
    else:
        failed=[l.split()[1] for l in text.splitlines() if l.startswith('test ') and l.endswith('FAILED')]
        print('caught ',name,'<-',', '.join(failed[:2]), flush=True)
print('breakages:',n,'problems:',bad)
