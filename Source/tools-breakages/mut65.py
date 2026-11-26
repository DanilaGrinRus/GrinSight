#!/usr/bin/env python3
"""Deliberate breakages of the window for O63-O65 (a list of contacts; the answer to an invoice; the check code and the address of a payment)."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
UI=('/tmp/uic/app',['cargo','test','--locked','--offline','--lib'])
P='/tmp/uic/app/src/live.rs'
M=[
 ('a line that is not a key is asked of the wallet','        if !key.starts_with("npub1") {\n            return Err(fill(tr("Line {}: a message key starts with npub1"','        if key.starts_with("npub1 ") {\n            return Err(fill(tr("Line {}: a message key starts with npub1"'),
 ('an address goes to the wrong line','        let typed = addresses.get(line).copied().unwrap_or_default();','        let typed = addresses.get(out.len()).copied().unwrap_or_default();'),
 ('an address of the other network is taken','address(typed).ok().filter(|a| a.testnet == testnet).and_then(|a| key_of_address(&a))','address(typed).ok().and_then(|a| key_of_address(&a))'),
 ('a broken address is passed over in silence','.ok_or_else(|| fill(tr("Line {}: the address is broken or of the other network", "Строка {}: адрес с ошибкой или из другой сети"), &[&at]))?;\n            if let Some(fields)','.unwrap_or([0u8; 32]);\n            if let Some(fields)'),
 ('the names do not go on from the contacts there are','taken.saturating_add(out.len()).saturating_add(1)','out.len().saturating_add(1)'),
 ('more than 200 at once','    if out.len() > 200 {','    if out.len() > 2000 {'),
 ('an empty list is asked of the wallet','    if out.is_empty() {\n        return Err(tr("There is no message key in the list"','    if out.is_empty() && false {\n        return Err(tr("There is no message key in the list"'),
 ('any text is taken for the answer to an invoice','    if stage != Some("I2") {','    if stage.is_none() {'),
 ('the answer to another invoice is taken','    if expected.is_some_and(|e| e != id) {','    if expected.is_some_and(|e| e != id) && false {'),
 ('an answer that names no invoice is taken','    let id = id.ok_or(tr("The answer does not name its invoice", "В ответе не назван счёт"))?;','    let id = id.unwrap_or_default();'),
 ('five words are shown as a code','    if words.len() == 6 {\n        words.join','    if words.len() >= 5 {\n        words.join'),
 ('anything is shown as a word of the code','.filter(|w| !w.is_empty() && w.len() <= 8 && w.chars().all(|c| c.is_ascii_lowercase()))','.filter(|w| !w.is_empty())'),
 ('another address is not said','        Some(saved) if saved != declared => tr("The payment names another address','        Some(saved) if saved != declared && false => tr("The payment names another address'),
 ('another address than the checked one is said softly','        Some(saved) if saved != declared && checked => tr(','        Some(saved) if saved != declared && checked && false => tr('),
 ('an unchecked address is called checked','        Some(_) if checked => tr("The address of the payment is the one you checked','        Some(_) => tr("The address of the payment is the one you checked'),
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
