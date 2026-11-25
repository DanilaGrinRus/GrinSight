#!/usr/bin/env python3
"""Deliberate breakages of the rules of edition 0.51 (K169-K171: the wallet
process without threads and the payment core for the browser). Every rule is
broken in the code that keeps it; a test has to fail for each. The breakage
of the single writer inside the browser's file system (K171) lives in code
built only for the browser; it is run on the build machine
(run-web-tests.ps1) and is not in this list."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
H=(F+'/paycore/host',['cargo','test','--offline','--lib','inline'])
W=(F+'/web/core',['cargo','test','--offline','--lib'])
I='paycore/host/src/inline.rs'; L='web/core/src/lib.rs'
M=[
 ('K169 a locked wallet reaches the core', H, I, '            None => answer(&id, Err(fail(-32040, "locked", ""))),\n            Some(wallet) => Zeroizing::new(wallet.bridge.call(line)),', '            None => answer(&id, Ok(json!({"address": ""}))),\n            Some(wallet) => Zeroizing::new(wallet.bridge.call(line)),'),
 ('K169 locking leaves the core open', H, I, '                // the bridge, the core and its keys end here\n                self.open = None;', ''),
 ('K169 a second unlock opens the wallet twice', H, I, '        if self.open.is_some() {\n            return Err(fail(-32045, "already_unlocked", ""));\n        }', ''),
 ('K169 a wallet is made over an existing one', H, I, '        if profile::exists(&self.places.profile) {\n            return Err(ProfileError::Exists.into());\n        }', ''),
 ('K169 a line of any length is read', H, I, '        if line.len() > MAX_REQUEST_LEN {', '        if false {'),
 ('K169 the guard may lie inside the profile', H, I, '        if guard_root.starts_with(&profile) {', '        if false {'),
 ('K169 the test network of automated runs is accepted', H, I, '            Some(Network::Automated) if !self.setup.allow_automated => Err(bad_params("network: unknown")),', ''),
 ('K169 the words are shown without the password', H, I, '                let shown = password(&p.password, "password")\n                    .and_then(|pass| self.profile_for_session(&pass))', '                let shown = password(&p.password, "password")\n                    .and_then(|pass| self.profile_for_session(&pass).or_else(|_| profile::open(&self.places.profile, b"one", self.setup.kdf_min_log_n).map_err(HostFail::from)))'),
 ('K170 a request of any length is read by the module', W, L, '    if request.is_null() || len == 0 || len > MAX_LINE {', '    if request.is_null() || len == 0 {'),
 ('K170 what is not text is answered', W, L, '    let Ok(line) = std::str::from_utf8(bytes) else {\n        return std::ptr::null_mut();\n    };', '    let line = &String::from_utf8_lossy(bytes).into_owned();'),
 ('K170 the module answers before it is started', W, L, '        None => zeroize::Zeroizing::new(String::new()),', '        None => zeroize::Zeroizing::new("{}".to_string()),'),
 ('K171 the journal gets a second writer on a computer', W, 'paycore/store/src/fs.rs', '        match file.try_lock() {\n            Ok(()) => Ok(FsLock { _file: file }),', '        match file.try_lock().or(Ok::<(), fs::TryLockError>(())) {\n            Ok(()) => Ok(FsLock { _file: file }),'),
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
        r=subprocess.run(cmd,cwd=root,env=ENV,capture_output=True,text=True,timeout=2400)
    finally:
        open(p,'w').write(src)
    text=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name, flush=True); bad+=1
    elif 'error[' in text or 'could not compile' in text or 'error:' in text and 'test failed' not in text: print('NO BUILD',name, flush=True); bad+=1
    else:
        failed=[l.split()[1] for l in text.splitlines() if l.startswith('test ') and l.endswith('FAILED')]
        print('caught ',name,'<-',', '.join(failed[:2]), flush=True)
print('breakages:',n,'problems:',bad)
