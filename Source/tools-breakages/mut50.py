#!/usr/bin/env python3
"""Deliberate breakages of K189 (Tor and Nostr switched off by the owner)."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
PIPE=(F+'/paycore/chain-pipe',['cargo','test','--offline','--test','pipe','the_wire_form'])
POST=(F+'/chain/fly-chain',['cargo','test','--offline','--features','test-net','--test','post','with_tor_switched_off'])
HOST=(F+'/paycore/host',['cargo','test','--offline','--features','test-chain','--test','host'])
UI=('/tmp/uic/app',['cargo','test','--locked','--lib'])
import sys as _s
M=[
 ('"Tor off" does not cross the pipe',PIPE,'paycore/chain-pipe/src/wire.rs','        out.push(u8::from(self.tor_off));','        out.push(0);'),
 ('a byte that is neither on nor off is read as on',PIPE,'paycore/chain-pipe/src/wire.rs','            tor_off: match c.u8()? {\n                0 => false,\n                1 => true,\n                _ => return None,','            tor_off: match c.u8()? {\n                0 => false,\n                _ => true,'),
 ('with Tor off the program still reaches public nodes through "Tor"',POST,'chain/fly-chain/src/send.rs','        if off {\n            return Dial::Off;\n        }','        let _ = off;'),
 ('Tor off is not taken as the choice of the direct way',POST,'chain/fly-chain/src/node.rs','Outbox::new(settings.direct_post || settings.tor_off)','Outbox::new(settings.direct_post)'),
 ('the chain process is not told that Tor is off',HOST,'paycore/host/src/session.rs','                tor_off: given.tor_off,','                tor_off: false,'),
 ('"no Tor" is taken together with a program that needs Tor',HOST,'paycore/host/src/lib.rs','if tor_off && (launcher.is_some() || onion.is_some()) {','if tor_off && false {'),
 ('"no Tor" is taken without a chain program',HOST,'paycore/host/src/lib.rs','    if tor_off && chain.is_none() {','    if tor_off && chain.is_none() && false {'),
 ('with Tor off the program for the address is still started',UI,'/tmp/uic/app/src/lib.rs','            "--onion" => tor_off,','            "--onion" => false,'),
 ('with Tor off the message program is still started',UI,'/tmp/uic/app/src/lib.rs','            "--transport" | "--relay" => tor_off || nostr_off,','            "--transport" | "--relay" => nostr_off,'),
 ('with Nostr off the message program is still started',UI,'/tmp/uic/app/src/lib.rs','            "--transport" | "--relay" => tor_off || nostr_off,','            "--transport" | "--relay" => tor_off,'),
 ('the chain program is not told of Tor off',UI,'/tmp/uic/app/src/lib.rs','        if tor_off {\n            out.push("--chain-no-tor".into());\n        }','        let _ = tor_off;'),
 ('a flag is said twice',UI,'/tmp/uic/app/src/lib.rs','            "--chain-direct-post" | "--chain-no-tor" => {\n                // said anew below, never twice\n                continue;\n            }\n',''),
 ('Tor off is shown as if transactions were private',UI,'/tmp/uic/app/src/sync.rs','    } else if f.tor_off || not_sent(f).is_some() {\n        2','    } else if not_sent(f).is_some() {\n        2'),
 ('Tor off is not said in the line about transactions',UI,'/tmp/uic/app/src/sync.rs','    } else if f.tor_off {\n        (tr("Tor is switched off: transactions go','    } else if false {\n        (tr("Tor is switched off: transactions go'),
 ('Nostr switched off is said as "not set up"',UI,'/tmp/uic/app/src/sync.rs','    let messages = if f.nostr_off {','    let messages = if false {'),
]
bad=0
for name,(cwd,cmd),f,old,new in M:
    if len(sys.argv)>1 and sys.argv[1] not in cwd: continue
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
