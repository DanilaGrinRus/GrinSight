#!/usr/bin/env python3
"""Deliberate breakages of the rules of edition 0.50 (K165-K168: what the
address process takes from a sender and what it tells of it) and of the
interface rules O27-O32 (the mark under the buttons, the words about Tor
for messages, bridges from the main screen, the sign in the recent
payments, the held money, the count of what came to the address). Every
rule is broken in the code that keeps it; a test has to fail for each."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
O=(F+'/onion',['cargo','test','--offline'])
W='/tmp/uicheck'
U=(W,['cargo','test','--offline','--lib'])
H='onion/src/http.rs'; MN='onion/src/main.rs'
M=[
 ('K165 only the bare path is the wallet\'s', O, H, '    let parts: Vec<&str> = path.split(\'/\').filter(|part| !part.is_empty()).collect();\n    parts == ["v2", "foreign"]', '    path == "/v2/foreign"'),
 ('K165 a path that only ends like the wallet\'s is taken', O, H, '    parts == ["v2", "foreign"]', '    parts.ends_with(&["v2", "foreign"])'),
 ('K165 another method is taken', O, H, '    if method != "POST" || !is_wallet_path(path) {', '    if !is_wallet_path(path) {'),
 ('K166 one request and the connection ends', O, MN, '    for turn in 0..MAX_TURNS {', '    for turn in 0..1 {'),
 ('K166 a connection is served without end', O, MN, '    for turn in 0..MAX_TURNS {', '    for turn in 0..usize::MAX {'),
 ('K166 the answer tells the sender to close', O, H, 'Content-Length: {}\\r\\nConnection: keep-alive\\r\\n\\r\\n{body}', 'Content-Length: {}\\r\\nConnection: close\\r\\n\\r\\n{body}'),
 ('K167 a body in chunks is refused', O, H, '        return String::from_utf8(unchunk(rest, max, false)?).map_err(|_| Bad::Form);', '        return Err(Bad::Form);'),
 ('K167 chunks and a length at once are taken', O, H, '        if !coding.trim().eq_ignore_ascii_case("chunked") || header(head, "content-length").is_some() {', '        if !coding.trim().eq_ignore_ascii_case("chunked") {'),
 ('K167 another coding is read as chunks', O, H, '        if !coding.trim().eq_ignore_ascii_case("chunked") || header(head, "content-length").is_some() {', '        if header(head, "content-length").is_some() {'),
 ('K167 chunks of any size are read', O, H, 'unchunk(rest, max, false)', 'unchunk(rest, usize::MAX, false)'),
 ('K168 the first line is kept at any length', O, H, '    line.iter().take(48).map(', '    line.iter().map('),
 ('K168 the first line is kept with any bytes', O, H, "map(|b| if b.is_ascii_graphic() || *b == b' ' { char::from(*b) } else { '?' }).collect()", "map(|b| char::from(*b)).collect()"),
 ('K168 more of a foreign request is kept than its first line', O, H, "    let line = data.split(|b| *b == b'\\r' || *b == b'\\n').next().unwrap_or_default();", "    let line = data;"),
 ('K168 what was handed to the wallet is not counted', O, MN, '        count(|s| &mut s.taken);\n', ''),
 ('K168 a foreign request is not counted', O, MN, '                    http::Bad::Other => |s| &mut s.not_wallet,', '                    http::Bad::Other => |s| &mut s.malformed,'),
 ('K168 a foreign request reaches the wallet', O, H, '    if method != "POST" || !is_wallet_path(path) {\n        return Err(Bad::Other);\n    }', ''),
 ('K168 the count takes the place of a failure', O, MN, '            if state.phase == Phase::Listening {\n                state.problem = held(&shared.seen).words();', '            if !held(&shared.seen).words().is_empty() {\n                state.problem = held(&shared.seen).words();'),
 ('K168 the count is said when nothing came', O, MN, '        if parts.is_empty() {\n            String::new()\n        } else {', '        if false {\n            String::new()\n        } else {'),
 ('O27 verified is said while old outputs are looked for', U, 'src/live.rs', '        Some(("at_tip", tip, _)) if searching => (', '        Some(("at_tip", tip, _)) if false => ('),
 ('O27 catching up is marked as good', U, 'src/live.rs', '            tr("CATCHING UP", "ДОГОНЯЕТ"),\n            false,\n            fill(tr("the wallet is at block {} of {}', '            tr("CATCHING UP", "ДОГОНЯЕТ"),\n            true,\n            fill(tr("the wallet is at block {} of {}'),
 ('O27 a tip not chosen is shown as a dash', U, 'src/live.rs', '        Some(("behind", tip, None)) => (', '        Some(("behind", tip, None)) if false => ('),
 ('O28 a missing message key points at Problems', U, 'src/sync.rs', '"none" => (tr("Tor for messages: not started — create a message key under My details"', '"none" => (tr("Tor for messages: not working — see Problems"'),
 ('O29 no way to the bridges from the main screen', U, 'ui/app.slint', 'auto-known: root.auto-known; set-auto(v) => { root.set-auto(v); } bridges => { root.tor-options(); } }\n                OpsCard', 'auto-known: root.auto-known; set-auto(v) => { root.set-auto(v); } }\n                OpsCard'),
 ('O30 the sign stands at a line with nothing to show', U, 'src/live.rs', '        !matches!(self, OpRef::None)', '        true'),
 ('O30 the sign is drawn at every line', U, 'ui/app.slint', '                if op.show: Rectangle {', '                if true: Rectangle {'),
 ('O31 held money is not said', U, 'src/live.rs', '    if reserved > 0 {\n        parts.push(', '    if false {\n        parts.push('),
 ('O31 held money is said without its amount', U, 'src/live.rs', '"{} GRIN заняты платежом в пути"), &[&amount(reserved)]', '"{} GRIN заняты платежом в пути"), &[""]'),
 ('O31 held money is written no larger than other marks', U, 'ui/app.slint', 'Chip { text: root.incoming; text-size: 15px; }', 'Chip { text: root.incoming; }'),
 ('O32 the count is shown while the address does not listen', U, 'src/sync.rs', '    if !f.answered || f.onion.phase != "listening" || !f.onion.problem', '    if !f.answered || !f.onion.problem'),
 ('O32 any words of the process pass for the count', U, 'src/sync.rs', ' || !f.onion.problem.starts_with("came to the address: ") {', ' {'),
 ('O32 the Russian count loses a number', U, 'src/sync.rs', 'map(|(_, ru)| format!("{number} {ru}"))', 'map(|(_, ru)| format!("{ru}"))'),
 ('O32 the Russian count rewrites a foreign line', U, 'src/sync.rs', '        } else {\n            out.push(part.to_string());', '        } else {\n            out.push(part.replace("silent", "молча"));'),
]
only=sys.argv[1:]; bad=0; n=0
for name,(root,cmd),f,old,new in M:
    if only and not any(o in name for o in only): continue
    n+=1
    base = W if root==W else F
    p=os.path.join(base,f); src=open(p).read()
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
