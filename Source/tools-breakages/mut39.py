#!/usr/bin/env python3
"""Deliberate breakages of ed. 0.45: letting a payment go (K142-K144). The
window's sources are taken from /tmp/uicheck (a copy of ui/app with the
images stubbed)."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
WCORE=(F+'/paycore/wallet',['cargo','test','--offline','--test','core','rollback_locks'])
DELIVERY=(F+'/paycore',['cargo','test','--offline','--features','stub','--manifest-path','bridge/Cargo.toml','--test','delivery','a_payment_locked'])
RUNNER=(F+'/paycore',['cargo','test','--offline','--features','stub','--manifest-path','bridge/Cargo.toml','--test','runner','the_worker_closes'])
WINDOW=('/tmp/uicheck',['cargo','test','--offline','--lib'])
M=[
 ('K142 a locked payment is cancelled like any other', WCORE, 'src/lib.rs', "        if self.st.sends.get(&state::hex(op)).is_some_and(|s| s.locked) {\n            return Err(CoreError::Refused(\n                \"operation is locked after a detected rollback\",\n            ));\n        }\n        self.commit_sealed(Event::Cancelled { op: *op })?;", "        self.commit_sealed(Event::Cancelled { op: *op })?;"),
 ('K142 a released payment is called cancelled', WCORE, 'src/state.rs', "                s.released = s.locked;\n", ""),
 ('K142 any payment can be released', WCORE, 'src/lib.rs', "        if !self.send_locked(op) {\n            return Err(CoreError::Refused(\"operation is not locked\"));\n        }\n", ""),
 ('K142 what was cancelled before the rollback reads as released', WCORE, 'src/state.rs', "        Some(if s.cancelled && s.released {", "        Some(if s.cancelled && s.locked {"),
 ('K142 the bridge releases without being told to', DELIVERY, 'bridge/src/lib.rs', '                if p.flag("release_locked")? {', '                if p.flag("release_locked")? || self.core.send_locked(&op) {'),
 ('K143 the history does not say a payment is locked', DELIVERY, 'bridge/src/lib.rs', '                            "locked": self.core.send_locked(&op),\n', '                            "locked": false,\n'),
 ('K143 the history does not say who a payment was sent to', DELIVERY, 'bridge/src/lib.rs', '                            "deliver_to": self.core.delivery_contact(&op).map(|key| hex(&key)),\n', ''),
 ('K143 the text of a prepared payment is not given again', DELIVERY, 'bridge/src/lib.rs', '"slate_id": hex(&review.id), "slate": self.slate_out(&s1)? }))', '"slate_id": hex(&review.id) }))'),
 ('K143 a payment sent to a contact has no line', WINDOW, 'src/live.rs', "    } else if row.to.is_some() {\n        Wait::Sent(row.op.clone())\n    } else {\n        Wait::Reply(row.op.clone())\n    })", "    } else if row.to.is_some() {\n        return None;\n    } else {\n        Wait::Reply(row.op.clone())\n    })"),
 ('K143 a locked payment is offered for a signature', WINDOW, 'src/live.rs', "    Some(if row.locked {\n        Wait::Locked(row.op.clone())\n    } else if row.held {", "    Some(if row.locked && !row.held {\n        Wait::Locked(row.op.clone())\n    } else if row.held {"),
 ('K142 the window releases with an ordinary cancel', WINDOW, 'src/live.rs', '        json!({ "op": op, "release_locked": true })', '        json!({ "op": op })'),
 ('K142 a released payment shown as cancelled', WINDOW, 'src/live.rs', '        "released" => (tr("reserve released after the restore — it may have been signed before", "резерв снят после восстановления — мог быть подписан раньше"), 2),\n', '        "released" => send_state("cancelled", invoice, locked),\n'),
 ('K144 the worker does not close old drafts', RUNNER, 'bridge/src/runner.rs', '        ("paycore.receive.expire", ""),\n', ''),
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
