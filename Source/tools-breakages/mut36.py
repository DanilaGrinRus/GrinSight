#!/usr/bin/env python3
"""Deliberate breakages of the third audit round's fixes (findings 27-34, K125-K128).
Each must make a test fail."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
PC='/home/claude/fly/paycore'
UI='/tmp/uicheck'
AND='/mnt/user-data/outputs/v02state/android'
BRIDGE=(PC,['cargo','test','--offline','--features','stub','--manifest-path','bridge/Cargo.toml','--test','bridge'])
HOST=(PC,['cargo','test','--offline','--features','test-chain','--manifest-path','host/Cargo.toml','--test','host','--','active_network','backup_actions'])
WINDOW=(UI,['cargo','test','--offline','--lib'])
JAVA=(AND,['bash','-c','rm -rf /tmp/jf && mkdir -p /tmp/jf && javac -d /tmp/jf java/org/grinsight/fly/WindowFence.java tests/org/grinsight/fly/WindowFenceTest.java && java -cp /tmp/jf org.grinsight.fly.WindowFenceTest'])
B='bridge/src/lib.rs'; H='host/src/lib.rs'; L='src/live.rs'; F='java/org/grinsight/fly/WindowFence.java'
M=[
 ('27 a late answer reaches the next session', WINDOW, L, "        if SESSION.with(|s| Arc::ptr_eq(&session, &s.borrow())) {", "        if SESSION.with(|s| Arc::strong_count(&s.borrow())) > 0 || Arc::ptr_eq(&session, &session) {"),
 ('27 entering without a confirmed lock', WINDOW, L, "    if retry {\n        lock()?;\n    }\n    unlock()", "    let _ = (retry, lock);\n    unlock()"),
 ('28 the fence lets an old answer through', JAVA, F, "        if (waiting.equals(topLevelStringId)) waiting = null;\n        return false;", "        waiting = null;\n        return true;"),
 ('29 a declared address names the sender', WINDOW, L, "    let from = contact.unwrap_or_else(|| tr(\"Sender unverified\", \"Отправитель не подтверждён\").into());", "    let from = contact.or_else(|| sender.and_then(|k| f.contacts.iter().find(|c| c.address.as_deref() == Some(address_of_key(&k, f.testnet.unwrap_or(false)).as_str())).map(|c| c.shown.clone()))).unwrap_or_else(|| tr(\"Sender unverified\", \"Отправитель не подтверждён\").into());"),
 ('30 the wallet status from the chain process', BRIDGE, B, "            \"paycore.wallet.chain_status\" => {\n                let basis = self.wallet_basis();", "            \"paycore.wallet.chain_status\" => {\n                let basis = self.ports.chain.payment_basis();"),
 ('31 an unknown network taken for Mainnet', WINDOW, L, "        _ => None,\n    }\n}\n\nfn view_address", "        _ => Some(false),\n    }\n}\n\nfn view_address"),
 ('31 the session forgets its network on a timeout', WINDOW, L, "    let (selected, network) = with(|f| (f.chat.clone(), f.testnet));", "    let (selected, network) = with(|f| (f.chat.clone(), None::<bool>));"),
 ('32 a stale balance stays on screen', WINDOW, L, "    } else {\n        app.set_balance(\"—\".into());", "    } else if false {\n        app.set_balance(\"—\".into());"),
 ('33 the network read from the file', HOST, H, "            Some(wallet) => Some(wallet.network),", "            Some(_) => profile::network(&self.places.profile).ok(),"),
 ('34 backup actions for any profile file', HOST, H, "        if self.runner.as_ref().is_some_and(|wallet|", "        if false && self.runner.as_ref().is_some_and(|wallet|"),
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
        r=subprocess.run(cmd,cwd=root,env=ENV,capture_output=True,text=True,timeout=1500)
    finally:
        open(p,'w').write(src)
    text=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name, flush=True); bad+=1
    elif 'error[' in text or 'could not compile' in text or ': error:' in text: print('NO BUILD',name, flush=True); bad+=1
    else:
        failed=[l.split()[1] for l in text.splitlines() if l.startswith('test ') and l.endswith('FAILED')] or (['AssertionError'] if 'AssertionError' in text else [])
        print('caught ',name,'<-',', '.join(failed[:2]), flush=True)
print('breakages:',n,'problems:',bad)
