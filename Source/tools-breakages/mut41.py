#!/usr/bin/env python3
"""Deliberate breakages of the interface rules of edition 0.8 (O14-O18) and of
the version line. The window's sources are taken from /tmp/uicheck (a copy of
ui/app with the images stubbed). What only the scenario against the real
wallet process checks (the by-hand choice, the version in the top row) has no
breakage here. Nor has the password field's refusal to copy: Slint itself
gives nothing from a password field to the clipboard, so removing our own
guard changes nothing a test could see."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
W='/tmp/uicheck'
SYNC=(W,['cargo','test','--offline','--lib','sync::'])
KEYS=(W,['cargo','test','--offline','--lib','keys_tests'])
BAL=(W,['cargo','test','--offline','--lib','a_balance_under_search'])
VER=(W,['cargo','test','--offline','--lib','version_tests'])
PASTE='                    if (event.text == "м" || event.text == "М" || event.text == "\\u{16}") { self.paste(); return accept; }\n                    if (event.text == "ф" || event.text == "Ф" || event.text == "\\u{1}") { self.select-all(); return accept; }\n                    if (!root.secret'
M=[
 ('O14 what is left is not counted', SYNC, 'src/sync.rs', '&spaced(s.saturating_sub(w))]', '&spaced(s)]'),
 ('O14 an unknown number is shown as zero', SYNC, 'src/sync.rs', 'n.map_or_else(|| "—".into(), spaced)', 'spaced(n.unwrap_or(0))'),
 ('O14 a silent wallet process looks like a working one', SYNC, 'src/sync.rs', '    if !f.answered {\n        return vec![row(', '    if false {\n        return vec![row('),
 ('O15 a stopped chain process is no trouble', SYNC, 'src/sync.rs', '    } else if f.chain.phase == "down" {', '    } else if false {'),
 ('O15 a trouble is written down again at every look', SYNC, 'src/sync.rs', 'if !self.entries.iter().any(|e| e.open && &e.trouble == trouble) {', 'if true {'),
 ('O15 a trouble that is gone still looks open', SYNC, 'src/sync.rs', 'if entry.open && !current.contains(&entry.trouble) {', 'if false {'),
 ('O15 the journal grows without end', SYNC, 'src/sync.rs', 'let extra = self.entries.len().saturating_sub(KEPT);', 'let extra = 0usize;'),
 ('O16 Ctrl with the Cyrillic letter does not paste', KEYS, 'ui/flows.slint', PASTE, PASTE.replace('self.paste(); ','',1)),
 ('a sum under search looks final', BAL, 'src/live.rs', '        if incomplete {\n            note.push_str(', '        if false {\n            note.push_str('),
 ('O19 a short password is refused again', (W,['cargo','test','--offline','--lib','password_tests']), 'src/live.rs', '    if first.is_empty() {\n        return Some(tr("Enter a password"', '    if first.chars().count() < 8 {\n        return Some(tr("Enter a password"'),
 ('O19 an empty password is accepted', (W,['cargo','test','--offline','--lib','password_tests']), 'src/live.rs', '    if first.is_empty() {\n        return Some(tr("Enter a password"', '    if false {\n        return Some(tr("Enter a password"'),
 ('O20 a transaction that was not sent is no trouble', SYNC, 'src/sync.rs', '    } else if let Some(why) = not_sent(f) {\n        out.push(one(Kind::NotSent, &why));', '    } else if let Some(why) = not_sent(f).filter(|_| false) {\n        out.push(one(Kind::NotSent, &why));'),
 ('O20 Tor for messages looks connected while it starts', SYNC, 'src/sync.rs', '"starting" => (tr("Tor for messages: connecting…", "Tor для сообщений: подключается…"), false),', '"starting" => (tr("Tor for messages: connected", "Tor для сообщений: подключён"), true),'),
 ('O14 the chain process is quoted while it is down', SYNC, 'src/sync.rs', '    if !f.answered || f.chain.phase != "ready" {\n        return Vec::new();', '    if !f.answered {\n        return Vec::new();'),
 ('O21 the text is offered for a payment sent to a contact', (W,['cargo','test','--offline','--lib','the_text_is_offered']), 'src/live.rs', '&& !row.invoice && row.to.is_none() {', '&& !row.invoice {'),
 ('the version is not three numbers', VER, 'src/lib.rs', 'pub const APP_VERSION: &str = "0.4.3";', 'pub const APP_VERSION: &str = "0.4";'),
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
