#!/usr/bin/env python3
"""Deliberate breakages of K188 (the wallet's own starting point, made by the chain program from the chain it verified)."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
PIPE=(F+'/paycore/chain-pipe',['cargo','test','--offline','--test','pipe'])
FEED=(F+'/chain/fly-chain',['cargo','test','--offline','--lib','feed'])
SEL=(F+'/chain/fly-chain',['cargo','test','--offline','--features','test-net','--test','select','the_wallet_is_given'])
BR=(F+'/paycore/bridge',['cargo','test','--offline','--test','chain','a_starting_point'])
UI=('/tmp/uic/app',['cargo','test','--locked','--lib','option_tests'])
M=[
 ('an empty record is taken from the chain program',PIPE,'paycore/chain-pipe/src/lib.rs','Some((wire::POINT_IS, body)) if !body.is_empty() && body.len() <= MAX_POINT_LEN => Ok(body),','Some((wire::POINT_IS, body)) if body.len() <= MAX_POINT_LEN => Ok(body),'),
 ('a record longer than one may be is taken',PIPE,'paycore/chain-pipe/src/lib.rs','Some((wire::POINT_IS, body)) if !body.is_empty() && body.len() <= MAX_POINT_LEN => Ok(body),','Some((wire::POINT_IS, body)) if !body.is_empty() => Ok(body),'),
 ('the reason is handed on as it came',PIPE,'paycore/chain-pipe/src/lib.rs','Ok(text) if !text.is_empty() => Err(plain_problem(text)),','Ok(text) if !text.is_empty() => Err(text.to_string()),'),
 ('an answer to another question does not end the conversation',PIPE,'paycore/chain-pipe/src/lib.rs','            Some(_) => self.confused(Err(silent())),\n            None => Err(silent()),','            Some(_) => Err(silent()),\n            None => Err(silent()),'),
 ('a reason that is not text does not end the conversation',PIPE,'paycore/chain-pipe/src/lib.rs','                _ => self.confused(Err(silent())),','                _ => Err(silent()),'),
 ('the chain program sends an empty record',PIPE,'paycore/chain-pipe/src/lib.rs','if record.is_empty() || record.len() > MAX_POINT_LEN {','if record.len() > MAX_POINT_LEN {'),
 ('the chain program sends a record too long',PIPE,'paycore/chain-pipe/src/lib.rs','if record.is_empty() || record.len() > MAX_POINT_LEN {','if record.is_empty() {'),
 ('the reason leaves the chain program as the layer said it',PIPE,'paycore/chain-pipe/src/lib.rs','                        let text = plain_problem(&why);','                        let text = why.clone();'),
 ('a request for a point with something attached is answered',PIPE,'paycore/chain-pipe/src/lib.rs','wire::POINT if body.is_empty() => {','wire::POINT => {'),
 ('a point is made of a tip that is not selected',FEED,'chain/fly-chain/src/feed.rs','Some(status) if status.selected.is_some() && !status.provisional => {}','Some(status) if !status.provisional => {}'),
 ('a point is made of what is provisional',FEED,'chain/fly-chain/src/feed.rs','Some(status) if status.selected.is_some() && !status.provisional => {}','Some(status) if status.selected.is_some() => {}'),
 ('the point is made at the tip, not where nodes give their state out',SEL,'chain/fly-chain/src/lib.rs','    let at = node::archive_height(tip);','    let at = tip;'),
 ('the time of making is not written into the point',SEL,'chain/fly-chain/src/node.rs','reply.try_send(crate::point_from(&self.chain, made));','reply.try_send(crate::point_from(&self.chain, 0));'),
 ('a record that is not text is handed to the window',BR,'paycore/bridge/src/lib.rs','match feed.point().map(String::from_utf8) {','match feed.point().map(|b| Ok::<String, std::string::FromUtf8Error>(String::from_utf8_lossy(&b).into_owned())) {'),
 ('an empty record is handed to the window',BR,'paycore/bridge/src/lib.rs','Ok(Ok(point)) if !point.is_empty() => Ok(json!({ "point": point })),','Ok(Ok(point)) => Ok(json!({ "point": point })),'),
 ('the layer\'s reason is dropped',BR,'paycore/bridge/src/lib.rs','Err(why) => Err(fail(-32033, "no_point", &why)),','Err(_) => Err(fail(-32033, "no_point", "")),'),
 ('a real point is too long for the window',UI,'/tmp/uic/app/src/live.rs','const MAX_POINT: usize = 64 * 1024;','const MAX_POINT: usize = 8192;'),
 ('a point longer than the chain program reads is kept',UI,'/tmp/uic/app/src/live.rs','    if t.len() >= MAX_POINT {','    if t.len() >= MAX_POINT.saturating_mul(4) {'),
 ('a point without a block replaces the one before',UI,'/tmp/uic/app/src/live.rs','.and_then(|v| v.get("height").and_then(Value::as_u64)).ok_or(unfit)?;','.and_then(|v| v.get("height").and_then(Value::as_u64)).unwrap_or(0);'),
 ('"not at the tip yet" is said like anything else',UI,'/tmp/uic/app/src/live.rs','if reason.contains("only when the tip is confirmed") {','if reason.contains("never said") {'),
 ('a silent chain program is said like anything else',UI,'/tmp/uic/app/src/live.rs','reason.contains("busy") || reason.contains("did not answer") || reason.contains("not running")','reason.contains("busy")'),
]
only=sys.argv[1:] 
bad=0
for name,(cwd,cmd),f,old,new in M:
    if only and not any(o in cwd+f for o in only): continue
    p=f if f.startswith('/') else os.path.join(F,f); src=open(p).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(p,'w').write(src.replace(old,new))
    try: r=subprocess.run(cmd,cwd=cwd,env=ENV,capture_output=True,text=True,timeout=900)
    finally: open(p,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
