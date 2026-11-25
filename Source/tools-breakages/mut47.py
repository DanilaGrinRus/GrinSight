#!/usr/bin/env python3
"""Deliberate breakages of О33 (the stages of following the network, ui/app/src/sync.rs)."""
import subprocess, os, shutil
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
SRC='/home/claude/fly/ui/app/src/sync.rs'; DST='/tmp/uicheck/src/sync.rs'
M=[
 ('a stage nobody spoke of is shown as done', '        (None, false) => ("—".into(), 0),\n    };\n    out.push(row(tr("State", "Состояние"), value, tone));', '        (None, false) => ("—".into(), 1),\n    };\n    out.push(row(tr("State", "Состояние"), value, tone));'),
 ('headers still behind the nodes are shown as verified', '(_, Some(at), Some(nodes)) if nodes > at =>', '(_, Some(at), Some(nodes)) if nodes > at && false =>'),
 ('blocks short of the tip are shown as at the tip', 'Some(height) => out.blocks = Some((height, at_tip)),', 'Some(height) => out.blocks = Some((height, true)),'),
 ('a state being collected is shown as collected', '        (Some((done, all)), _) => (fill(tr("piece {} of {}", "кусок {} из {}"), &[&spaced(done), &spaced(all)]), 3),', '        (Some(_), _) => (tr("collected and checked", "собрано и проверено").to_string(), 1),'),
 ('a tip confirmed with a caveat is shown as plainly confirmed', '            out.confirmed = Some(!rest.is_empty());', '            out.confirmed = Some(false);'),
 ('a tip that is not confirmed is shown as confirmed', '        (None, Some(why)) => why,', '        (None, Some(_)) => (tr("confirmed by public nodes", "подтверждена публичными нодами").to_string(), 1),'),
 ('what the chain says besides the stages is dropped', '        } else {\n            out.rest.push(part.to_string());\n        }\n    }\n    out\n}', '        }\n    }\n    out\n}'),
 ('no node connected is passed over in silence', '    if let Some(nodes) = &said.nodes {', '    if let Some(nodes) = said.nodes.as_ref().filter(|_| false) {'),
 ('a wallet behind the tip is shown as at the tip', '        (Some("behind"), Some(w), Some(s)) => (fill(tr("block {} of {} · {} left", "блок {} из {} · осталось {}"), &[&spaced(w), &spaced(s), &spaced(s.saturating_sub(w))]), 3),', '        (Some("behind"), Some(w), Some(_)) => (fill(tr("at the tip, block {}", "на вершине, блок {}"), &[&spaced(w)]), 1),'),
 ('a chain process that is starting is not a stage', '    if !working {\n        let (value, tone) = phase_words(&f.chain);', '    if false {\n        let (value, tone) = phase_words(&f.chain);'),
]
src=open(SRC).read(); bad=0
for name,old,new in M:
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old)); bad+=1; continue
    open(DST,'w').write(src.replace(old,new))
    r=subprocess.run(['cargo','test','--offline','--lib','sync'],cwd='/tmp/uicheck',env=ENV,capture_output=True,text=True)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name); bad+=1
    else: print('caught ',name)
shutil.copy(SRC,DST)
print('breakages:',len(M),'problems:',bad)
