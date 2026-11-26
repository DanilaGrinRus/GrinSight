#!/usr/bin/env python3
"""Deliberate breakages of K194 (own money without a payment record is listed) and O49 (its words; operations by time)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
BR=(F+'/paycore/bridge',['cargo','test','--offline','--test','bridge','payments_through_json_only'])
UI=('/tmp/uic/app',['cargo','test','--locked','--offline','--lib'])
M=[
 ('money without a record is not listed',BR,'paycore/wallet/src/state.rs','filter(|o| !of_record(&o.commit))','filter(|o| o.bound && !of_record(&o.commit))'),
 ('the change of its own payments is listed',BR,'paycore/wallet/src/state.rs','self.sends.values().any(|s| s.change.as_ref().is_some_and(|(_, _, change)| change == commit))','false'),
 ('the money of a payment with a record is listed twice',BR,'paycore/wallet/src/state.rs','|| self.drafts.values().any(|d| d.commit == *commit)','|| false'),
 ('the oldest first',BR,'paycore/wallet/src/state.rs','found.sort_by(|a, b| b.height.cmp(&a.height).then(a.commit.cmp(&b.commit)));','found.sort_by(|a, b| a.height.cmp(&b.height).then(b.commit.cmp(&a.commit)));'),
 ('what spent it is not said',BR,'paycore/bridge/src/lib.rs','"spent_height": o.spent,','"spent_height": Value::Null,'),
 ('found by the search is said of everything',BR,'paycore/bridge/src/lib.rs','"by_search": o.old,','"by_search": true,'),
 ('a payment does not say when it was made',BR,'paycore/bridge/src/lib.rs','"made_height": self.core.send_made_height(&op),','"made_height": Value::Null,'),
 ('an incoming payment does not say when it was made',BR,'paycore/bridge/src/lib.rs','"made_height": self.core.incoming_made_height(&id),','"made_height": Value::Null,'),
 ('the window lists no such money',UI,'/tmp/uic/app/src/live.rs','        for row in &view.found {\n            refs.push(OpRef::None);','        for row in view.found.iter().take(0) {\n            refs.push(OpRef::None);'),
 ('the operations are not put in order',UI,'/tmp/uic/app/src/live.rs','        order.sort_by(|a, b| times.get(*b).cmp(&times.get(*a)).then(b.cmp(a)));','        order.reverse();'),
 ('what is under way is not on top',UI,'/tmp/uic/app/src/live.rs','        (None, true) => u64::MAX,','        (None, true) => made.unwrap_or(0),'),
 ('what ended without a block stands on top',UI,'/tmp/uic/app/src/live.rs','        (None, false) => made.unwrap_or(0),','        (None, false) => u64::MAX,'),
 ('money found by the search is said to be received now',UI,'/tmp/uic/app/src/live.rs','    if row.by_search {\n        return (fill(tr("found by the search','    if row.by_search && false {\n        return (fill(tr("found by the search'),
 ('one confirmation short is "received"',UI,'/tmp/uic/app/src/live.rs','        Some(have) if have >= k_conf.max(1) =>','        Some(have) if have.saturating_add(8) >= k_conf.max(1) =>'),
 ('a block reward is not told apart',UI,'/tmp/uic/app/src/live.rs','    let kind = if row.coinbase {','    let kind = if row.coinbase && false {'),
 ('while catching up it is said to be received',UI,'/tmp/uic/app/src/live.rs','    if catching_up {\n        return (fill(tr("in a block · the wallet is catching up with the tip · {}"','    if catching_up && false {\n        return (fill(tr("in a block · the wallet is catching up with the tip · {}"'),
]
bad=0
for name,(cwd,cmd),f,old,new in M:
    p=f if f.startswith('/') else os.path.join(F,f); src=open(p).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(p,'w').write(src.replace(old,new))
    try: r=subprocess.run(cmd,cwd=cwd,env=ENV,capture_output=True,text=True,timeout=1500)
    finally: open(p,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
