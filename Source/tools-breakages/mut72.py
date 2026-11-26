#!/usr/bin/env python3
"""Deliberate breakages of K202 (the history before the starting point is checked by sampling its work; a point
of the owner's own carries the program's point and keeps that check) and O75 (contacts and their conversation,
the own point under "Details", the line about the history). The core part runs in chain/headers and
chain/fly-chain of this tree; the window part against the check copy /tmp/uic/app."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
H=ROOT+'/chain/headers'; C=ROOT+'/chain/fly-chain'; A='/tmp/uic/app'
TH=['cargo','test','--locked','--offline','--all-features','--test','headers','--test','baked']
TC=['cargo','test','--locked','--offline','--test','own_point']
TU=['cargo','test','--locked','--offline','--lib','--','contacts_and_their_conversation','new_messages_are_counted','payments_and_days','the_history_before_the_point']
PEAKS=H+'/src/peaks.rs'; CHECK=H+'/src/checkpoint.rs'; PROOF=H+'/src/proof.rs'; CHAIN=H+'/src/chain.rs'; LIB=C+'/src/lib.rs'
FEED=C+'/src/feed.rs'; TF=['cargo','test','--locked','--offline','--lib','--','the_history_before_the_start_is_said_last']
LIVE=A+'/src/live.rs'; SYNC=A+'/src/sync.rs'; APP=A+'/ui/app.slint'
M=[
 (PEAKS,H,TH,'K202: the followed leaf takes the wrong sibling','                up.push(left);\n            } else if','                up.push(node);\n            } else if'),
 (PEAKS,H,TH,'K202: the peaks to the right are left out of the path','        let mut out: Vec<Hash> = right.into_iter().collect();','        let mut out: Vec<Hash> = Vec::new();'),
 (CHECK,H,TH,'K202: a point is written without the path','            Some(Base { height: track.target(), path: plain(&track.path()?) })','            None'),
 (CHAIN,H,TH,'K202: the chain does not follow its point up to the new one','            track.append(&header(Some(at))?).map_err(|_| lost())?;','            let _ = header(Some(at))?;'),
 (PROOF,H,TH,'K202: the path is not checked against the point of the program','            placed(start.peaks.root(), start.peaks.leaves(), &proof.point, &place)','            !place.path.is_empty() || placed(start.peaks.root(), start.peaks.leaves(), &proof.point, &place)'),
 (PROOF,H,TH,'K202: a point that carries it is said to be the program\'s own','        Ok(passed) => History::Extended(passed),','        Ok(passed) => History::Sampled(passed),'),
 (LIB,C,TC,'K202: an own point is made of a chain the proof does not reach','    if refused(chain.start()) {\n        return Err("no starting point of your own','    if false && refused(chain.start()) {\n        return Err("no starting point of your own'),
 (LIVE,A,TU,'O75: the open conversation does not count as seen','    if open || *mark > count {','    if *mark > count {'),
 (LIVE,A,TU,'O75: the lines are not put in order of time','    events.sort_by_key(|(at, _)| *at);',''),
 (LIVE,A,TU,'O75: a cancelled payment is shown','        if matches!(row.state.as_str(), "cancelled" | "expired") {','        if matches!(row.state.as_str(), "never") {'),
 (APP,A,TU,'O75: a contact is deleted without the window','            ask-remove(i) => { root.remove-asking = i; }','            ask-remove(i) => { root.contact-remove(i); }'),
 (APP,A,TU,'O75: the own point is back on the main screen','        Muted { text: @tr("Payment delivery"); font-size: 12px; }','        Btn { text: "x"; clicked => { root.make-point(); } }\n        Muted { text: @tr("Payment delivery"); font-size: 12px; }'),
 (SYNC,A,TU,'K202: the line about a point that carries the program\'s is not read','        "sampled to the program\'s point" => (','        "sampled to the program\'s point!" => ('),
 (SYNC,A,TU,'K202: cut words are read as "not passed"','        _ => return None,\n    };','        _ => (tr("not checked: the proof in the program did not pass", "не проверена: доказательство в программе не прошло проверку"), 2),\n    };'),
 (SYNC,A,TU,'K202: the words about the history are shown as a trouble','        } else if part.starts_with("history:") || "history:".starts_with(part) {\n','        } else if part.starts_with("history:x") {\n'),
 (FEED,C,TF,'K202: the history is said before the tip again','    if let Some(history) = view.history {\n        text.push_str("; ");\n        text.push_str(history);\n    }\n    text\n}','    text\n}'),
]
bad=0
for F,cwd,T,name,old,new in [(m[0],m[1],m[2],m[3],m[4],m[5]) for m in M]:
    src=open(F).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(F,'w').write(src.replace(old,new))
    try: r=subprocess.run(T,cwd=cwd,env=ENV,capture_output=True,text=True,timeout=2400)
    finally: open(F,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t and 'back on the main screen' not in name: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
