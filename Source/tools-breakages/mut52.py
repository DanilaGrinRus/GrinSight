#!/usr/bin/env python3
"""Deliberate breakages of K192 (the owner's agreement to the direct way for one payment)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
CH=(F+'/chain/fly-chain',['cargo','test','--offline','--features','test-net','--test','post','direct_way'])
PI=(F+'/paycore/chain-pipe',['cargo','test','--offline'])
BR=(F+'/paycore/bridge',['cargo','test','--offline','--test','bridge'])
HO=(F+'/paycore/host',['cargo','test','--offline','--features','test-chain','--lib'])
UI=('/tmp/uic/app',['cargo','test','--locked','--offline','--lib','payment_line_tests'])
M=[
 ('the agreement is not kept',CH,'chain/fly-chain/src/post.rs','        sent.direct = true;\n','        sent.direct = false;\n'),
 ('the agreement for one is taken for all',CH,'chain/fly-chain/src/post.rs','        sent.direct = true;\n','        sent.direct = true;\n        self.direct = true;\n'),
 ('a failed try ignores the agreement for this one',CH,'chain/fly-chain/src/post.rs','                if direct || sent.direct {','                if direct {'),
 ('directly while a try through Tor is under way',CH,'chain/fly-chain/src/post.rs','            Route::Tor { busy: false, failed: Some(_), .. } => sent.go_direct(now, peers),','            Route::Tor { .. } => sent.go_direct(now, peers),'),
 ('not at once after a failed try',CH,'chain/fly-chain/src/post.rs','            Route::Tor { busy: false, failed: Some(_), .. } => sent.go_direct(now, peers),','            Route::Tor { busy: false, failed: Some(_), .. } if false => sent.go_direct(now, peers),'),
 ('the node drops the agreement',CH,'chain/fly-chain/src/node.rs','                if direct {\n                    let peers','                if false {\n                    let peers'),
 ('the node takes every handing over as agreed',CH,'chain/fly-chain/src/node.rs','                if direct {\n                    let peers','                if true {\n                    let peers'),
 ('the feed drops the agreement',CH,'chain/fly-chain/src/feed.rs','        self.hand_over(tx, true)','        self.hand_over(tx, false)'),
 ('the pipe client sends it as a plain one',PI,'paycore/chain-pipe/src/lib.rs','self.hand_over(wire::POST_DIRECT, tx)','self.hand_over(wire::POST, tx)'),
 ('the pipe client sends every one as agreed',PI,'paycore/chain-pipe/src/lib.rs','self.hand_over(wire::POST, tx)','self.hand_over(wire::POST_DIRECT, tx)'),
 ('the pipe server hands it on as a plain one',PI,'paycore/chain-pipe/src/lib.rs','feed.post_direct(&body)','feed.post(&body)'),
 ('the wallet does not pass the agreement',BR,'paycore/bridge/src/lib.rs','let outcome = if p.flag("direct")? {','let outcome = if p.flag("direct")? && false {'),
 ('the wallet agrees by itself',BR,'paycore/bridge/src/lib.rs','let outcome = if p.flag("direct")? {','let outcome = if p.flag("direct")? || true {'),
 ('the host hands it on as a plain one',HO,'paycore/host/src/chain.rs','            Ok(mut chain) => chain.post_direct(tx),','            Ok(mut chain) => chain.post(tx),'),
 ('the host layer hands it on as a plain one',HO,'paycore/host/src/chain.rs','            Some(chain) => chain.post_direct(tx),','            Some(chain) => chain.post(tx),'),
 ('the host broadcaster drops the agreement',HO,'paycore/host/src/chain.rs','        match self.post_direct(tx) {','        match self.post(tx) {'),
 ('the window never says the agreement',UI,'/tmp/uic/app/src/live.rs','    if direct {\n        json!({ "op": op, "direct": true })','    if false {\n        json!({ "op": op, "direct": true })'),
 ('the window always says the agreement',UI,'/tmp/uic/app/src/live.rs','    if direct {\n        json!({ "op": op, "direct": true })','    if true {\n        json!({ "op": op, "direct": true })'),
]
bad=0
for name,(cwd,cmd),f,old,new in M:
    p=f if f.startswith('/') else os.path.join(F,f); src=open(p).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(p,'w').write(src.replace(old,new))
    try: r=subprocess.run(cmd,cwd=cwd,env=ENV,capture_output=True,text=True,timeout=1200)
    finally: open(p,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
