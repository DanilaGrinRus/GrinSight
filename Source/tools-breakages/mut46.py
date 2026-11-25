#!/usr/bin/env python3
"""Deliberate breakages of the rules of edition 0.53 that live in Rust built
on a computer (K177: a chain layer inside the program; K178: the wallet of
the page answers on its own thread). The rules of the gateway and of the
bridge are broken where they live: web/gateway/breakages.mjs and
run-web-dial-test.ps1 -Breakages."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
HC=(F+'/paycore/host',['cargo','test','--offline','--lib','chain'])
HI=(F+'/paycore/host',['cargo','test','--offline','--lib','inline'])
W=(F+'/web/wallet',['cargo','test','--offline','--lib'])
N=(F+'/chain/fly-chain',['cargo','test','--offline','--lib','net::'])
C='paycore/host/src/chain.rs'; I='paycore/host/src/inline.rs'; L='web/wallet/src/lib.rs'
M=[
 ('K177 a layer inside the program is never started', HC, C, '            Some(inside) => inside(&config, CALL_TIMEOUT),', '            Some(_) => PipeChain::spawn_begin(&self.launcher.program, &config, CALL_TIMEOUT),'),
 ('K177 a layer inside goes on when the wallet lets go of it', HC, C, '                // the other end is gone: the stream is over\n                Err(_) => return Ok(0),', '                Err(_) => loop {\n                    std::thread::sleep(Duration::from_secs(3600));\n                },'),
 ('K177 the end of a layer inside is told to nobody', HC, C, '            let _ = fly_paycore_bridge::chain_pipe::serve(&mut asked, &mut answers, make);\n            ended();', '            let _ = fly_paycore_bridge::chain_pipe::serve(&mut asked, &mut answers, make);\n            let _ = ended;'),
 ('K177 a stream inside loses what does not fit the reader', HC, C, '            let Some(byte) = self.rest.pop_front() else { break };\n            *slot = byte;', '            let Some(byte) = self.rest.pop_front() else { break };\n            *slot = byte;\n            self.rest.clear();'),
 ('K177 the wallet on one thread gets no chain layer', HI, I, '        self.places.chain = Some(chain);\n', ''),
 ('K177 the status of the wallet on one thread hides its chain layer', HI, I, '        let chain = if self.places.chain.is_some() {', '        let chain = if false {'),
 ('K177 what the chain layer reports is not the wallet\'s to see', HI, I, 'session::open(&secrets, &self.places, &self.setup, reset, &Default::default(), &self.chain_report)?', 'session::open(&secrets, &self.places, &self.setup, reset, &Default::default(), &Default::default())?'),
 ('K178 an answer is taken twice', W, L, '    let taken = held(&ANSWERS).as_mut().and_then(|answers| answers.remove(&id));', '    let taken = held(&ANSWERS).as_mut().and_then(|answers| answers.get(&id).cloned());'),
 ('K178 requests without end are taken from a page that takes no answers', W, L, '|n| (n < MAX_WAITING).then(|| n.saturating_add(1))', '|n| Some(n.saturating_add(1))'),
 ('K178 answers taken do not make room for more requests', W, L, '    if taken.is_some() {\n        let _ = OUTSTANDING.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1));\n    }', ''),
 ('K178 a request of any length is read', W, L, '    if request.is_null() || len == 0 || len > MAX_LINE {', '    if request.is_null() || len == 0 {'),
 ('K178 what is not text is taken', W, L, '    let Ok(line) = std::str::from_utf8(bytes) else {\n        return 0;\n    };\n    i32::from(post(Ask::Call(', '    let line = &String::from_utf8_lossy(bytes).into_owned();\n    i32::from(post(Ask::Call('),
 ('K178 a request is taken before the wallet is started', W, L, '    let Some(wallet) = WALLET.get() else {\n        return false;\n    };', '    let Some(wallet) = WALLET.get() else {\n        return true;\n    };'),
 ('K178 a second start makes a second wallet', W, L, '    if WALLET.get().is_some() {\n        return true;\n    }', ''),
 ('K178 a round is answered with the answer of a request', W, L, '                answer(id, Zeroizing::new(json!({"notes": notes, "more": more}).to_string()));', '                answer(id, Zeroizing::new(json!({"notes": notes, "more": !more}).to_string()));'),
 ('K176 a name with a port loses the port', N, 'chain/fly-chain/src/net.rs', '            Ok(port) => (host, Some(port)),', '            Ok(_) => (host, default_port),'),
 ('K176 a name without a port gets none', N, 'chain/fly-chain/src/net.rs', '        _ => (text, default_port),', '        _ => (text, None),'),
]
only=sys.argv[1:]; bad=0; n=0
for name,(root,cmd),f,old,new in M:
    if only and not any(o in name for o in only): continue
    n+=1
    p=os.path.join(F,f); src=open(p).read()
    if src.count(old)!=1:
        print('NOT APPLIED',name,src.count(old), flush=True); bad+=1; continue
    open(p,'w').write(src.replace(old,new))
    try:
        r=subprocess.run(cmd,cwd=root,env=ENV,capture_output=True,text=True,timeout=420)
    except subprocess.TimeoutExpired:
        # a test that never ends has not passed
        subprocess.run(['pkill','-f','pc-target/debug/deps/fly_'])
        print('caught ',name,'<- the tests did not end', flush=True); continue
    finally:
        open(p,'w').write(src)
    text=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name, flush=True); bad+=1
    elif 'error[' in text or 'could not compile' in text or 'error:' in text and 'test failed' not in text: print('NO BUILD',name, flush=True); bad+=1
    else:
        failed=[l.split()[1] for l in text.splitlines() if l.startswith('test ') and l.endswith('FAILED')]
        print('caught ',name,'<-',', '.join(failed[:2]), flush=True)
print('breakages:',n,'problems:',bad)
