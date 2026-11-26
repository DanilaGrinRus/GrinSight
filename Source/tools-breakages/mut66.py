#!/usr/bin/env python3
"""Deliberate breakages of O66 and O67 (held chain files and the restart; the starting point weighed by its distance)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
UI=('/tmp/uic/app',['cargo','test','--locked','--offline','--lib'])
L='/tmp/uic/app/src/live.rs'; S='/tmp/uic/app/src/sync.rs'
M=[
 (S,'held files are an ordinary stop','    } else if f.chain.problem.contains(CHAIN_HELD) || f.chain.error.contains(CHAIN_HELD) {','    } else if false {'),
 (S,'held files said by a running process are missed','    } else if f.chain.problem.contains(CHAIN_HELD) || f.chain.error.contains(CHAIN_HELD) {','    } else if f.chain.error.contains(CHAIN_HELD) {'),
 (S,'held files said by a stopped process are missed','    } else if f.chain.problem.contains(CHAIN_HELD) || f.chain.error.contains(CHAIN_HELD) {','    } else if f.chain.problem.contains(CHAIN_HELD) {'),
 (S,'the restart is offered for every trouble','    matches!(kind, Kind::NoAnswer | Kind::ChainHeld)','    !matches!(kind, Kind::NoChain)'),
 (S,'the restart is not offered for held files','    matches!(kind, Kind::NoAnswer | Kind::ChainHeld)','    matches!(kind, Kind::NoAnswer)'),
 (S,'a point above what is checked gives a distance','    checked.checked_sub(start)','    Some(checked.abs_diff(start))'),
 (S,'the distance is read from a stopped process','    if !f.answered || f.chain.phase != "ready" {\n        return None;\n    }\n    let number_after','    if !f.answered {\n        return None;\n    }\n    let number_after'),
 (S,'little gain is said past 20 000','    if gap < POINT_LITTLE {','    if gap <= POINT_LITTLE {'),
 (S,'much gain is said at 30 000','    } else if gap > POINT_OLD {\n        crate::fill','    } else if gap >= POINT_OLD {\n        crate::fill'),
 (L,'a near point is offered under waiting','.filter(|gap| *gap > crate::sync::POINT_OLD && f.point_made.is_none())','.filter(|_| f.point_made.is_none())'),
 (L,'the offer stays after a point was made','.filter(|gap| *gap > crate::sync::POINT_OLD && f.point_made.is_none())','.filter(|gap| *gap > crate::sync::POINT_OLD)'),
 (L,'the hint does not reach the window','    app.set_point_hint(crate::sync::point_hint(crate::sync::point_gap(&view.sync)).into());','    app.set_point_hint(SharedString::new());'),
 (L,'the note about the point is not said again','        if app.get_point_good() {\n            app.set_point_note(point_made_words(&block).into());\n        }','        let _ = block;'),
]
bad=0
for P,name,old,new in M:
    src=open(P).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(P,'w').write(src.replace(old,new))
    try: r=subprocess.run(UI[1],cwd=UI[0],env=ENV,capture_output=True,text=True,timeout=1500)
    finally: open(P,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
