#!/usr/bin/env python3
"""Deliberate breakages of O51 (the outputs in the window: the mark and the choice for a payment)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
UI=('/tmp/uic/app',['cargo','test','--locked','--offline','--lib'])
P='/tmp/uic/app/src/live.rs'
M=[
 ('a marked output is asked for without the word','    if marked && !spend_kept {','    if marked && !spend_kept && false {'),
 ('the word is said for a choice with no marked output','    Ok(Some((chosen.iter().map(|o| o.commit.clone()).collect(), marked)))','    Ok(Some((chosen.iter().map(|o| o.commit.clone()).collect(), spend_kept)))'),
 ('an output the wallet no longer lists is asked for','    let chosen: Vec<&OutRow> = outputs.iter().filter(|o| picked.contains(&o.commit)).collect();\n    if chosen.is_empty() {\n        return Ok(None);\n    }','    let chosen: Vec<&OutRow> = outputs.iter().filter(|o| picked.contains(&o.commit)).collect();\n    if picked.is_empty() {\n        return Ok(None);\n    }'),
 ('every output is asked for','    let chosen: Vec<&OutRow> = outputs.iter().filter(|o| picked.contains(&o.commit)).collect();\n    if chosen.is_empty() {','    let chosen: Vec<&OutRow> = outputs.iter().collect();\n    if picked.is_empty() {'),
 ('what is marked is not said under the balance','    if kept > 0 {\n        parts.push(fill(tr("{} GRIN marked','    if kept > 0 && false {\n        parts.push(fill(tr("{} GRIN marked'),
 ('a held output is said to be free','        "reserved" => tr("held by a payment under way", "занят платежом в пути"),','        "reserved" => "",'),
]
bad=0
for name,old,new in M:
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
