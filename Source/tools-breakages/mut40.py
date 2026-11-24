#!/usr/bin/env python3
"""Deliberate breakages of the fifth audit round's fixes (findings 43-50,
K145-K150, O13). The window's sources are taken from /tmp/uicheck (a copy of
ui/app with the images stubbed). Findings 46 and 49 are PowerShell scripts:
their checks are installer/test-stop-own.ps1 and
tools-audit/test-portable-staging.ps1, run on Windows."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
EXPIRE=(F+'/paycore/wallet',['cargo','test','--offline','--test','core','expiration_keeps'])
LOCKS=(F+'/paycore/wallet',['cargo','test','--offline','--test','core','rollback_locks'])
CHAINLIB=(F+'/chain/fly-chain',['cargo','test','--offline','--lib'])
CHAINBIN=(F+'/chain/fly-chain',['cargo','test','--offline','--bins'])
POST=(F+'/chain/fly-chain',['cargo','test','--offline','--features','test-net','--test','post','an_observed_aggregate'])
WINDOW=('/tmp/uicheck',['cargo','test','--offline','--lib'])
M=[
 ('43 a signed invoice stops the closing of drafts', EXPIRE, 'src/state.rs', "            .filter(|d| !d.abandoned && !d.bound && d.armed.is_none())", "            .filter(|d| !d.abandoned && !d.bound)"),
 ('44 selected without a current confirmed time', CHAINLIB, 'src/node.rs', "        (self.selected && seconds.is_some(), seconds)", "        (self.selected, seconds)"),
 ('44 the wallet told the published flag', CHAINLIB, 'src/feed.rs', "                .filter(|blocks| blocks.at_tip && selected && blocks.height == view.height && blocks.hash == view.hash)", "                .filter(|blocks| blocks.at_tip && view.selected && blocks.height == view.height && blocks.hash == view.hash)"),
 ('45 the notice about a contact name lost at signing', WINDOW, 'src/live.rs', "                    (name.text, notice.into(), groups)", "                    (name.text, String::new(), groups)"),
 ('45 the notice about a message lost', WINDOW, 'src/live.rs', "    let shown = foreign_text(words, MESSAGE_CHARS);\n    let notice = text_notice(&shown);", "    let shown = foreign_text(words, MESSAGE_CHARS);\n    let notice = \"\";"),
 ('47 the lock judged by the status on screen', LOCKS, 'src/lib.rs', "        if self.st.sends.get(&state::hex(op)).is_some_and(|s| s.locked) {\n            return Err(CoreError::Refused(\n                \"operation is locked after a detected rollback\",", "        if self.send_locked(op) {\n            return Err(CoreError::Refused(\n                \"operation is locked after a detected rollback\","),
 ('48 a transaction heard before it is checked', POST, 'src/adapter.rs', "            tx.validate(core::transaction::Weighting::AsTransaction)\n                .map_err(|_| chain::Error::Other(\"invalid transaction observation\".to_string()))?;\n", ""),
 ('50 a long agent name printed whole', CHAINBIN, 'src/probe.rs', "    agent.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(60).collect()", "    agent.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').collect()"),
 ('50 control characters of an agent name printed', CHAINBIN, 'src/probe.rs', "    agent.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(60).collect()", "    agent.chars().take(60).collect()"),
]
only=sys.argv[1:]; bad=0; n=0
for name,(root,cmd),f,old,new in M:
    if only and not any(o in name for o in only): continue
    n+=1
    p=os.path.join(root,f); src=open(p).read()
    if src.count(old)!=1:
        print('NOT APPLIED',name,src.count(old), flush=True); bad+=1; continue
    open(p,'w').write(src.replace(old,new))
    try:
        r=subprocess.run(cmd,cwd=root,env=ENV,capture_output=True,text=True,timeout=2400)
    finally:
        open(p,'w').write(src)
    text=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name, flush=True); bad+=1
    elif 'error[' in text or 'could not compile' in text: print('NO BUILD',name, flush=True); bad+=1
    else:
        failed=[l.split()[1] for l in text.splitlines() if l.startswith('test ') and l.endswith('FAILED')]
        print('caught ',name,'<-',', '.join(failed[:2]), flush=True)
print('breakages:',n,'problems:',bad)
