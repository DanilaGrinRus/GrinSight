#!/usr/bin/env python3
"""Deliberate breakages of the fourth audit round's fixes (findings 35-42,
K129-K136). Each must make a test fail."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
UI='/tmp/uicheck'
STATE=(F+'/chain/state',['cargo','test','--offline','--features','testkit','--test','advance'])
FLY=(F+'/chain/fly-chain',['cargo','test','--offline','--features','test-net','--test','post','--test','blocks'])
STORE=(F+'/paycore/store',['cargo','test','--offline','--lib'])
WCORE=(F+'/paycore/wallet',['cargo','test','--offline','--test','core','invoice_cutoff'])
WOLD=(F+'/paycore/wallet',['cargo','test','--offline','--test','old'])
BRIDGE=(F+'/paycore',['cargo','test','--offline','--features','stub','--manifest-path','bridge/Cargo.toml','--test','bridge'])
PIPE=(F+'/paycore/chain-pipe',['cargo','test','--offline','--features','stub','--test','pipe'])
WINDOW=(UI,['cargo','test','--offline','--lib'])
M=[
 ('35 reconstructed sizes not compared', STATE, 'src/advance.rs', "        if outputs.size() != verified.output_mmr_size\n            || rangeproofs.size() != verified.output_mmr_size\n            || kernels.size() != verified.kernel_mmr_size\n        {", "        if false\n        {"),
 ('36 the bridge gives no balance with the status', BRIDGE, 'bridge/src/lib.rs', '                    "balance": balance,\n', ''),
 ('36 the window takes the balance from a second call', WINDOW, 'src/live.rs', '        view.balance = c.get("balance").and_then(|b| {', '        view.balance = call("paycore.balance", json!({})).ok().and_then(|b| {'),
 ('37 pool evidence outlives the reorg', FLY, 'src/post.rs', "                sent.seen = false;\n", ""),
 ('38 answers from a detached branch', FLY, 'src/follow.rs', "        if !self.on_chain(chain) {\n            return Err(Unknown);\n        }\n        let base", "        let base"),
 ('38 the ancestry of a reanchor not checked', FLY, 'src/follow.rs', "            return Ok(if chain.hash_at(at.height) == Some(at.hash) {", "            return Ok(if true {"),
 ('39 a journal past the reader limit', STORE, 'src/store.rs', "        let end = self.journal_end(bytes.len(), reserve)?;", "        let end = self.journal_len.saturating_add(bytes.len());"),
 ('39 a snapshot past the reader limit', STORE, 'src/format.rs', "    if state.len() > cap.saturating_sub(16 + NONCE_LEN + TAG_LEN) {", "    if state.len() > cap {"),
 ('40 an invoice paid at its cutoff', WCORE, 'src/lib.rs', "        slates::check_ttl(parsed.slate.ttl_cutoff_height, self.tip_height())?;\n        self.require_complete_for_spend()?;\n        if parsed.amount > max_amount {", "        self.require_complete_for_spend()?;\n        if parsed.amount > max_amount {"),
 ('41 an unknown auto-receive shown as off', WINDOW, 'src/live.rs', "            Some(value) if value.as_u64().is_some() => Some(true),\n            _ => None,", "            Some(value) if value.as_u64().is_some() => Some(true),\n            _ => Some(false),"),
 ('42 a detached branch keeps chain evidence', WOLD, 'src/state.rs', "                        Some(false) => {\n                            self.discard_chain_evidence();", "                        Some(false) => {\n                            let _ = 0;"),
 ('42 old journals not migrated', WOLD, 'src/lib.rs', "        if core.st.legacy_chain_evidence && core.st.old.is_some() && core.st.tip.is_some() {", "        if false && core.st.legacy_chain_evidence && core.st.old.is_some() && core.st.tip.is_some() {"),
 ('42 an extension to the same height accepted', PIPE, 'src/lib.rs', "                .filter(|anchor| anchor.height > previous.height)\n", ""),
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
