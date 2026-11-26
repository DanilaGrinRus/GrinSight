#!/usr/bin/env python3
"""Deliberate breakages of K193 (the owner's Tor switch turned while the wallet is open)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
CH=(F+'/chain/fly-chain',['cargo','test','--offline','--features','test-net','--test','post','tor_switch'])
PI=(F+'/paycore/chain-pipe',['cargo','test','--offline'])
HU=(F+'/paycore/host',['cargo','test','--offline','--features','test-chain','--lib'])
HI=(F+'/paycore/host',['cargo','test','--offline','--features','test-chain','--test','host','the_product_program'])
UI=('/tmp/uic/app',['cargo','test','--locked','--offline','--lib','what_is_switched_off'])
M=[
 ('switched off, what waited does not go',CH,'chain/fly-chain/src/post.rs','''        self.sent.iter_mut().filter(|sent| matches!(sent.route, Route::Tor { busy: false, failed: Some(_), .. })).filter_map(|sent| sent.go_direct(now, peers)).collect()''','''        let _ = (now, peers);\n        Vec::new()'''),
 ('switched off, what is under way goes directly at once',CH,'chain/fly-chain/src/post.rs','''        self.sent.iter_mut().filter(|sent| matches!(sent.route, Route::Tor { busy: false, failed: Some(_), .. })).filter_map''','''        self.sent.iter_mut().filter(|sent| matches!(sent.route, Route::Tor { .. })).filter_map'''),
 ('the switch is not kept',CH,'chain/fly-chain/src/post.rs','        self.tor_off = off;\n        if !off {','        self.tor_off = false;\n        if !off {'),
 ('switched back on, the direct way stays open',CH,'chain/fly-chain/src/post.rs','        self.tor_off = off;\n        if !off {','        self.tor_off = self.tor_off || off;\n        if !off {'),
 ('switched off does not open the direct way',CH,'chain/fly-chain/src/post.rs','        self.direct || self.tor_off\n','        self.direct\n'),
 ('the reason stays after the switch',CH,'chain/fly-chain/src/post.rs','        // what Tor could not do is no trouble any more: it is not asked to\n        self.trouble = None;\n','        // what Tor could not do is no trouble any more: it is not asked to\n'),
 ('off from the start is forgotten',CH,'chain/fly-chain/src/post.rs','            direct,\n            tor_off,\n            ..Outbox::default()','            direct,\n            tor_off: tor_off && false,\n            ..Outbox::default()'),
 ('the node does not tell its sending thread',CH,'chain/fly-chain/src/node.rs','                self.tor_off.store(off, Ordering::SeqCst);\n','                let _ = &self.tor_off;\n'),
 ('the node does not turn the outbox',CH,'chain/fly-chain/src/node.rs','                let todo = self.outbox.tor_switched(off, Instant::now(), &peers);','                let todo = self.outbox.tor_switched(false, Instant::now(), &peers);'),
 ('the sending thread ignores the switch',CH,'chain/fly-chain/src/send.rs','    if off.load(std::sync::atomic::Ordering::SeqCst) {\n        dial.rest();','    if off.load(std::sync::atomic::Ordering::SeqCst) && false {\n        dial.rest();'),
 ('the pipe client says "off" for "on"',PI,'paycore/chain-pipe/src/lib.rs','self.ask(wire::TOR, &[u8::from(off)])','self.ask(wire::TOR, &[1])'),
 ('the pipe client takes any answer for "taken up"',PI,'paycore/chain-pipe/src/lib.rs','            Some((wire::DONE, body)) if body.is_empty() => true,\n            // the layer on the other side has no such switch\n            Some((wire::UNKNOWN, body)) if body.is_empty() => false,\n            Some(_) => self.confused(false),','            Some(_) => true,'),
 ('the pipe server says "taken up" for a layer that did not',PI,'paycore/chain-pipe/src/lib.rs','if feed.set_tor(off) { wire::DONE } else { wire::UNKNOWN }','if feed.set_tor(off) || true { wire::DONE } else { wire::UNKNOWN }'),
 ('the pipe server turns the switch the other way',PI,'paycore/chain-pipe/src/lib.rs','                    [0] => false,\n                    [1] => true,','                    [0] => true,\n                    [1] => false,'),
 ('the host does not tell the chain process',HU,'paycore/host/src/chain.rs','            if want != self.told_off && chain.set_tor(want) {','            if want != self.told_off && false && chain.set_tor(want) {'),
 ('the host takes a turn not taken up for done',HU,'paycore/host/src/chain.rs','            if want != self.told_off && chain.set_tor(want) {\n                self.told_off = want;\n            }','            if want != self.told_off {\n                let _ = chain.set_tor(want);\n                self.told_off = want;\n            }'),
 ('the host tells the chain process at every call',HU,'paycore/host/src/chain.rs','            if want != self.told_off && chain.set_tor(want) {','            if chain.set_tor(want) {'),
 ('the Tor process of the address ignores the switch',HU,'paycore/host/src/onion.rs','        if crate::chain::tor_is_off(&self.given.off) {\n            if !matches!','        if crate::chain::tor_is_off(&self.given.off) && false {\n            if !matches!'),
 ('the Tor process of the address is started with Tor off',HU,'paycore/host/src/onion.rs','        if crate::chain::tor_is_off(&onion.given.off) {\n            onion.stage = Stage::Down(Instant::now(), TOR_OFF.to_string());\n        } else {\n            onion.launch();\n        }','        onion.launch();'),
 ('switched on, the Tor process waits out its pause',HU,'paycore/host/src/onion.rs','        if matches!(&self.stage, Stage::Down(_, why) if why == TOR_OFF) {\n            self.launch();\n        }','        if matches!(&self.stage, Stage::Down(_, why) if why == TOR_OFF) {\n            self.down("");\n        }'),
 ('the transport ignores the switch',HU,'paycore/host/src/transport.rs','            (true, false) => self.rest(),','            (true, false) => {}'),
 ('the transport is started with Tor off',HU,'paycore/host/src/transport.rs','        if crate::chain::tor_is_off(&mailbox.launcher.off) {\n            mailbox.rest();\n        } else {\n            mailbox.launch();\n        }','        mailbox.launch();'),
 ('switched on, the transport stays down',HU,'paycore/host/src/transport.rs','            (false, true) => self.launch(),','            (false, true) => {}'),
 ('the host does not turn the switch',HI,'paycore/host/src/lib.rs','                    self.places.tor.store(off, std::sync::atomic::Ordering::SeqCst);','                    let _ = &self.places.tor;'),
 ('the host turns the switch with no chain program',HI,'paycore/host/src/lib.rs','            "host.tor" => match (p.off, self.places.chain.is_some()) {','            "host.tor" => match (p.off, true) {'),
 ('the host starts with the switch on whatever was said',HI,'paycore/host/src/lib.rs','chain::TorSwitch::new(std::sync::atomic::AtomicBool::new(args.tor_off))','chain::TorSwitch::new(std::sync::atomic::AtomicBool::new(false))'),
 ('the status does not say the switch',HI,'paycore/host/src/lib.rs','"tor_off": chain::tor_is_off(&self.places.tor),','"tor_off": false,'),
 ('the window takes the Tor programs out with a chain program',UI,'/tmp/uic/app/src/lib.rs','    let unflagged = tor_off && !base.iter().any(|a| a == "--chain");','    let unflagged = tor_off;'),
 ('the window names the Tor programs without a chain program',UI,'/tmp/uic/app/src/lib.rs','    let unflagged = tor_off && !base.iter().any(|a| a == "--chain");','    let unflagged = false;'),
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
