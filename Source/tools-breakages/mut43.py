#!/usr/bin/env python3
"""Deliberate breakages of the rules of edition 0.49 (K159-K164: Tor
bridges) and of the interface rules O24 (Slatepack as a file), O25 (QR code)
and O26 (the choice of bridges in the window). Every rule is broken in the
code that keeps it; a test has to fail for each.

The size of a file is checked twice in `files::load` (before reading, so
that a huge file is not read at all, and after, so that a file that grew
is not taken): the breakage takes both away, one alone changes nothing.

Three breakages are slow by nature: with the check of the bridges taken
away the process goes on to bring Tor up for real, and the test fails only
when that attempt runs out of time (there is no Tor network where the
breakages are run)."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
TB=(F+'/tor-bridges',['cargo','test','--offline'])
HB=(F+'/paycore/host',['cargo','test','--offline','--features','test-chain','tor_bridges'])
CP=(F+'/paycore/chain-pipe',['cargo','test','--offline','--features','stub','the_wire_form'])
MP=(F+'/paycore/mailbox-pipe',['cargo','test','--offline','--features','stub','tor_bridges_cross'])
P=(F+'/paycore/onion-pipe',['cargo','test','--offline'])
FC=(F+'/chain/fly-chain',['cargo','test','--offline','--lib','bridge_tests'])
CT=(F+'/chain/tor',['cargo','test','--offline','bridges_that_cannot'])
O=(F+'/onion',['cargo','test','--offline','bridges_that_cannot'])
TT=(F+'/transport/tor',['cargo','test','--offline','bridges_that_cannot'])
W='/tmp/uicheck'
TR=(W,['cargo','test','--offline','--lib','tor::'])
FI=(W,['cargo','test','--offline','--lib','files::'])
QR=(W,['cargo','test','--offline','--lib','qr'])
TBS='tor-bridges/src/lib.rs'
HT='paycore/host/src/tor_bridges.rs'
GIVE='tor_bridges: crate::tor_bridges::text(),'
M=[
 ('K159 the chain process is handed no bridges', HB, 'paycore/host/src/chain.rs', GIVE, 'tor_bridges: String::new(),'),
 ('K159 the message transport is handed no bridges', HB, 'paycore/host/src/transport.rs', GIVE, 'tor_bridges: String::new(),'),
 ('K159 the address process is handed no bridges', HB, 'paycore/host/src/onion.rs', GIVE, 'tor_bridges: String::new(),'),
 ('K159 the chain process loses the bridges on the way', CP, 'paycore/chain-pipe/src/wire.rs', '            tor_bridges: c.short_text()?,', '            tor_bridges: c.short_text().map(|_| String::new())?,'),
 ('K159 the message transport loses the bridges on the way', MP, 'paycore/mailbox-pipe/src/wire.rs', '            tor_bridges: c.short_text()?,', '            tor_bridges: c.short_text().map(|_| String::new())?,'),
 ('K159 the address process loses the bridges on the way', P, 'paycore/onion-pipe/src/lib.rs', '        let tor_bridges = c.short_text()?;', '        let tor_bridges = c.short_text().map(|_| String::new())?;'),
 ('K160 bridges are a wish, not the only way', TB, TBS, '        config.bridges().enabled(tor_config::BoolOrAuto::Explicit(true));', ''),
 ('K160 the chain process goes round bridges it cannot use', FC, 'chain/fly-chain/src/send.rs', 'fly_chain_tor::TorBridges::parse(bridges).map_err', 'fly_chain_tor::TorBridges::parse("").map_err'),
 ('K160 the chain Tor starts without the bridges it was given', CT, 'chain/tor/src/lib.rs', '        bridges.apply(&mut config, program).map_err(|_| TorError::Bridges)?;', ''),
 ('K160 the address process goes round bridges it cannot use', O, 'onion/src/main.rs', 'fly_tor_bridges::TorBridges::parse(bridges).map_err(|_| BRIDGES_UNUSABLE)?;', 'fly_tor_bridges::TorBridges::parse("").map_err(|_| BRIDGES_UNUSABLE)?;'),
 ('K160 the message transport goes round bridges it cannot use', TT, 'transport/tor/src/native.rs', 'fly_tor_bridges::TorBridges::parse(bridges).map_err(|_| TorError::Bridges)?;', 'fly_tor_bridges::TorBridges::parse("").map_err(|_| TorError::Bridges)?;'),
 ('K161 a file that cannot be read is taken for no bridges', HB, HT, '    if file.take(limit).read_to_end(&mut bytes).is_err() || bytes.len() > MAX_FILE {\n        return UNUSABLE.to_string();', '    if file.take(limit).read_to_end(&mut bytes).is_err() || bytes.len() > MAX_FILE {\n        return String::new();'),
 ('K161 a file that is not text is taken for no bridges', HB, HT, '        _ => UNUSABLE.to_string(),', '        _ => String::new(),'),
 ('K161 a file with a zero byte is passed on', HB, HT, "        Ok(text) if !text.contains('\\0') => text,", '        Ok(text) => text,'),
 ('K162 any number of bridge lines is taken', TB, TBS, '            if lines.len() >= MAX_LINES {', '            if false {'),
 ('K162 a line of any length is taken', TB, TBS, '            if line.len() > MAX_LINE {', '            if false {'),
 ('K162 a text of any length is read', TB, TBS, '        if text.len() > MAX_TEXT {', '        if false {'),
 ('K162 a line that is not a bridge line is taken', TB, TBS, '            if line.parse::<BridgeConfigBuilder>().is_err() {\n                return Err(BridgeError::NotABridge);\n            }', ''),
 ('K162 the lines are printed with the value', TB, TBS, 'write!(f, "TorBridges({})", self.lines.len())', 'write!(f, "TorBridges({:?})", self.lines)'),
 ('K163 a transport is started without its program', TB, TBS, '        if !transports.is_empty() && !program.is_file() {', '        if false {'),
 ('K163 the program is looked for under another name', TB, TBS, '    Some(own.parent()?.join(PROGRAM))', '    Some(own.parent()?.join("pt"))'),
 ('K164 the built-in bridges are not those of the bundle', TR, 'src/tor.rs', 'all.get("bridges").and_then(|b| b.get(kind))', 'all.get("bridges").and_then(|b| b.get("meek").or(b.get(kind)))'),
 ('O24 a saved text is written over another', FI, 'src/files.rs', 'std::fs::OpenOptions::new().write(true).create_new(true).open(&path)', 'std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&path)'),
 ('O24 an empty text is saved', FI, 'src/files.rs', '    if text.is_empty() {\n        return Err(FileError::Empty);\n    }', ''),
 ('O24 a file of any size is read', FI, 'src/files.rs', '    if meta.len() > MAX_FILE {\n        return Err(FileError::Large);\n    }\n    let bytes = std::fs::read(path).map_err(|_| FileError::Read)?;\n    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE {\n        return Err(FileError::Large);\n    }', '    let bytes = std::fs::read(path).map_err(|_| FileError::Read)?;'),
 ('O24 what is not a plain file is read', FI, 'src/files.rs', '    if !meta.file_type().is_file() {\n        return Err(FileError::Read);\n    }', ''),
 ('O24 more files are offered than the bound', FI, 'src/files.rs', '    found.into_iter().take(MAX_LISTED).map(', '    found.into_iter().map('),
 ('O25 the code has no light border', QR, 'src/qr.rs', 'pub(crate) const QUIET: usize = 4;', 'pub(crate) const QUIET: usize = 0;'),
 ('O25 a code is drawn of another text than the one shown', QR, 'src/qr.rs', 'QrCode::encode_binary(text.as_bytes(), QrCodeEcc::Low)', 'QrCode::encode_binary(text.to_ascii_lowercase().as_bytes(), QrCodeEcc::Low)'),
 ('O25 too long a text gives a picture', QR, 'src/live.rs', "    let Some(grid) = crate::qr::grid(text) else { return slint::Image::default() };", "    let Some(grid) = crate::qr::grid(text).or_else(|| crate::qr::grid(\"x\")) else { return slint::Image::default() };"),
 ('O25 a code is offered at the box for the words', QR, 'ui/flows.slint', 'TextBox { label: @tr("24 words, separated by spaces");', 'TextBox { with-qr: true; label: @tr("24 words, separated by spaces");'),
 ('O26 a wrong line is refused without its number', TR, 'src/tor.rs', '            return Err(OwnError::NotABridge(number));', '            return Err(OwnError::NotABridge(0));'),
 ('O26 a line without a fingerprint passes for a bridge', TR, 'src/tor.rs', '    if print.len() != 40 || !print.bytes().all(|b| b.is_ascii_hexdigit()) {\n        return false;\n    }', ''),
 ('O26 a file changed by hand is shown as built-in', TR, 'src/tor.rs', '        Some("obfs4") if lines == built_in("obfs4") => (Mode::Obfs4, String::new()),', '        Some("obfs4") => (Mode::Obfs4, String::new()),'),
 ('O26 directly leaves bridges in the file', TR, 'src/tor.rs', '        Mode::Direct => return Ok(String::new()),', '        Mode::Direct => built_in("obfs4"),'),
 ('O26 a refused choice wipes the one that was there', TR, 'src/tor.rs', '        Err(e) => return Ok(Err(e)),', '        Err(e) => {\n            let _ = std::fs::write(path, "");\n            return Ok(Err(e));\n        }'),
 ('O26 more own bridges are taken than the processes read', TR, 'src/tor.rs', '        if lines.len() >= MAX_LINES {\n            return Err(OwnError::TooMany);\n        }', ''),
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
