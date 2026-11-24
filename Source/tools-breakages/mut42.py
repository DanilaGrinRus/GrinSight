#!/usr/bin/env python3
"""Deliberate breakages of the rules of edition 0.48 (K151-K158: payments to
and from an address through Tor) and of the interface rules O22 and O23. Every rule is
broken in the code that keeps it; a test has to fail for each.

Two checks of the bridge have no breakage here, because the payment core
keeps the same rule under them and the outcome does not change when the
bridge's own check is removed: that a contact is answered by itself only with
unattended receive on (`receive_stateless` refuses when it is off, and the
payment then waits for the user), and the amount bound passed to
`receive_stateless` (dust is refused before that call). The core's tests keep
those. That locking the wallet ends its Tor process is a property of where
the process lives (inside the bridge the lock drops), checked by the test of
two hosts; there is no single line to break for it."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
B=(F+'/paycore/bridge',['cargo','test','--offline','--test','onion'])
BL=(F+'/paycore/bridge',['cargo','test','--offline','--lib','onion'])
H=(F+'/paycore/host',['cargo','test','--offline','--features','test-chain','a_payment_to_an_address'])
HU=(F+'/paycore/host',['cargo','test','--offline','--features','test-chain','--lib','onion'])
O=(F+'/onion',['cargo','test','--offline'])
P=(F+'/paycore/onion-pipe',['cargo','test','--offline'])
W='/tmp/uicheck'
SY=(W,['cargo','test','--offline','--lib','sync::'])
TA=(W,['cargo','test','--offline','--lib','tor_ask_tests'])
ON='paycore/bridge/src/onion.rs'
M=[
 ('K151 a payment that names no address is sent somewhere', B, ON, '        let Some(to) = review.receiver else {\n            return Err(CoreError::Refused("the payment names no address").into());\n        };', '        let to = review.receiver.unwrap_or([0x33; 32]);'),
 ('K151 the same request posts the payment twice', B, ON, '        if matches!(self.onion.sends.get(op), Some(Sending::Posted(_))) {\n            // the same request again', '        if false {\n            // the same request again'),
 ('K151 a post Tor did not take is counted as sent', B, ON, '        if !taken {\n            return Err(CoreError::Refused("Tor is not ready yet").into());\n        }', ''),
 ('K151 a payment whose reply is here is sent again', B, ON, '        if self.core.send_held(op).is_some() {\n            return Err(CoreError::Refused("a reply is already here").into());\n        }', ''),
 ('K152 the reply is signed without the user', B, ON, '                if self.auto_sign {\n                    if let Some(sel)', '                if true {\n                    if let Some(sel)'),
 ('K152 a reply through Tor is signed off the selected tip', B, ON, '                    if let Some(sel) = self.ports.chain.selected_tip() {\n                        match self.core.send_finalize_held_at(op, sel) {', '                    if let Some(sel) = self.ports.chain.selected_tip().or(self.core.tip()) {\n                        match self.core.send_finalize_held_at(op, sel) {'),
 ('K153 anybody is answered without the user', B, ON, '        let known = summary.sender.is_some_and(|a| self.is_contact_address(&a));\n        if known &&', '        let known = true;\n        if known &&'),
 ('K154 more than three payments wait', B, ON, '        if self.onion.asks.len() >= ONION_MAX_ASKS {', '        if self.onion.asks.len() >= 64 {'),
 ('K154 the same payment waits twice', B, ON, '        if self.onion.asks.iter().any(|ask| ask.slate_id == summary.id) {', '        if false {'),
 ('K154 yes after the time is up is signed', B, ON, '        if ask.since.elapsed() >= self.onion.hold {\n            if let Some(port) = self.onion.port.as_mut() {\n                port.answer(ask.id, &rpc_err(&ask.rpc_id, "the owner of the wallet did not answer in time"));\n            }\n            return Err', '        if false {\n            if let Some(port) = self.onion.port.as_mut() {\n                port.answer(ask.id, &rpc_err(&ask.rpc_id, "the owner of the wallet did not answer in time"));\n            }\n            return Err'),
 ('K154 a payment nobody answered waits for ever', B, ON, 'partition(|ask| ask.since.elapsed() >= hold);', 'partition(|_| false);'),
 ('K154 a declined payment gets no answer', B, ON, '                port.answer(ask.id, &rpc_err(&ask.rpc_id, "the owner of the wallet declined the payment"));', ''),
 ('K155 dust is taken', B, ON, '        if summary.amount < self.onion.min_amount {', '        if false {'),
 ('K156 an invoice is taken for a payment', B, ON, '        if summary.stage != SlateStage::S1 {', '        if false {'),
 ('K156 any method is taken for receive_tx', B, ON, '            Some("receive_tx") => {}\n            _ => return refuse(&rpc, "this wallet takes payments only"),', '            _ => {}'),
 ('K156 a request of any size is read', B, ON, '        if body.len() > MAX_REQUEST {', '        if false {'),
 ('K156 a refusal repeats the id as it came', BL, ON, "        Some(Value::String(s)) if s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') => {", '        Some(Value::String(s)) if s.len() <= 6400 => {'),
 ('K156 a refusal repeats any id', B, ON, "        Some(Value::String(s)) if s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') => {", '        Some(Value::String(s)) if s.len() <= 6400 => {'),
 ('K157 an answer that is no reply is kept', B, ON, '                Ok(SlateStage::S2) => match self.core.send_hold_reply(op, &s2) {', '                Ok(_) => match self.core.send_hold_reply(op, &s2) {'),
 ('K157 an outcome nobody waits for is taken', B, ON, '        if !matches!(self.onion.sends.get(op), Some(Sending::Posted(_))) {\n            // an outcome nobody waits for\n            return Ok(None);\n        }', ''),
 ('K157 the other wallet is quoted as it speaks', BL, ON, 'format!("the wallet at this address refused: {}", plain_text(&said, 120))', 'format!("the wallet at this address refused: {said}")'),
 ('K157 an error with a result is taken for the result', BL, ON, '    if let Some(error) = answer.get("error").filter(|e| !e.is_null()) {\n        return Err(quoted(error.get("message").unwrap_or(&Value::Null)));\n    }', ''),
 ('K157 a post without an outcome waits for ever', B, ON, '            if matches!(sending, Sending::Posted(at) if at.elapsed() >= within) {', '            if false {'),
 ('K158 the Tor process is given another key', B, 'paycore/wallet/src/lib.rs', '    pub fn address_secret_for_onion(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, CoreError> {\n        self.address_secret()', '    pub fn address_secret_for_onion(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, CoreError> {\n        self.identity_secret().ok_or(CoreError::NotFound)'),
 ('K158 two wallets share one Tor directory', H, 'paycore/host/src/session.rs', '    profile.join(format!("onion-{}", hex(instance)))', '    profile.parent().unwrap_or(profile).join("onion-shared")'),
 ('K158 a Tor process that is not there takes a post', HU, 'paycore/host/src/onion.rs', '        self.live().is_some_and(|onion| onion.post(ticket, to, body))', '        self.live().is_none_or(|onion| onion.post(ticket, to, body))'),
 ('K158 the service is run with another key than the address', O, 'onion/src/main.rs', '    let pair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(secret);\n    tor_hscrypto', '    let pair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(&[secret[0]; 32]);\n    tor_hscrypto'),
 ('K158 a request body of any length is kept', O, 'onion/src/http.rs', '            if n > max {\n                Err(Bad::Large)', '            if false {\n                Err(Bad::Large)'),
 ('K158 a head that never ends is kept', O, 'onion/src/http.rs', '        return Err(if data.len() > MAX_HEAD { Bad::Large } else { Bad::Short });', '        return Err(Bad::Short);'),
 ('K158 any request is taken for a wallet post', O, 'onion/src/http.rs', '    if method != "POST" || path.trim_end_matches(\'/\') != PATH {', '    if false {'),
 ('K158 a cut answer is taken for a whole one', O, 'onion/src/http.rs', '                None => return Err(if ended { Bad::Form } else { Bad::Short }),\n            },\n            // no length', '                None => rest.to_vec(),\n            },\n            // no length'),
 ('K158 chunks of any size are kept', O, 'onion/src/http.rs', '        if n > max || out.len().saturating_add(n) > max {', '        if false {'),
 ('K158 more is under way than the bound', O, 'onion/src/main.rs', '            if seen >= max {\n                return None;\n            }', ''),
 ('K158 Tor keeps its files outside its directory', O, 'onion/src/main.rs', '    let tor = child(&root, "tor")?;', '    let tor = child(&std::env::temp_dir(), "tor")?;'),
 ('K158 words of the Tor process are shown as they come', P, 'paycore/onion-pipe/src/lib.rs', '                    0 => Err(fly_paycore_pipe_link::plain_text(&text, 200)),', '                    0 => Err(text),'),
 ('K158 a body larger than the bound crosses the pipe', P, 'paycore/onion-pipe/src/lib.rs', '    if bytes.len() > MAX_BODY {\n        return None;\n    }', ''),
 ('O22 Tor for the address looks on while it connects', SY, 'src/sync.rs', '"starting" | "none" => (tr("Tor for your address: connecting…", "Tor для вашего адреса: подключается…"), false),', '"starting" | "none" => (tr("Tor for your address: on", "Tor для вашего адреса: работает"), true),'),
 ('O22 a payment that did not get through is no trouble', SY, 'src/sync.rs', '    for why in &f.onion_failed {\n        let trouble = one(Kind::TorSend, why);\n        if !out.contains(&trouble) {', '    for why in f.onion_failed.iter().take(0) {\n        let trouble = one(Kind::TorSend, why);\n        if !out.contains(&trouble) {'),
 ('O22 a failed Tor for the address is no trouble', SY, 'src/sync.rs', '    if f.onion.configured && f.onion.phase == "failed" {', '    if false {'),
 ('O22 the same reason fills the list', SY, 'src/sync.rs', '        let trouble = one(Kind::TorSend, why);\n        if !out.contains(&trouble) {', '        let trouble = one(Kind::TorSend, why);\n        if true {'),
 ('O22 any name is taken for a payment through Tor', TA, 'src/live.rs', '    id.strip_prefix(TOR_ASK)?.parse().ok()', '    id.trim_start_matches(TOR_ASK).trim().parse().ok()'),
 ('O23 a refusal does not say what to wait for', TA, 'src/live.rs', '        "the search for old outputs is not over" => tr(', '        "the search is not over" => tr('),
 ('O23 the wallet\'s own words are shown for an unknown refusal', TA, 'src/live.rs', '            "refused" => refused(message).into(),', '            "refused" => if refused(message).starts_with("The wallet will not") { message.clone() } else { refused(message).into() },'),
 ('O23 a reply that came is not shown in the window', TA, 'src/live.rs', '    if held {\n        return TorOutcome::Sign;\n    }', ''),
 ('O23 a failure of Tor is not shown in the window', TA, 'src/live.rs', '        Some(why) => TorOutcome::Failed(why.to_string()),\n        None => TorOutcome::Wait,', '        _ => TorOutcome::Wait,'),
 ('O23 a closed window is opened by an outcome', TA, 'src/live.rs', '    if !shown {\n        return TorOutcome::Gone;\n    }', ''),
 ('O23 the reason Tor failed is shown as the process wrote it', TA, 'src/live.rs', '    if reason.starts_with("Tor did not reach the wallet at this address") {', '    if false {'),
 ('O22 an address being announced is called unreachable', SY, 'src/sync.rs', 'if f.onion.problem.is_empty() || f.onion.problem.contains("being announced") => (', 'if f.onion.problem.is_empty() => ('),
 ('O22 a refusal of Tor is said in the general words', TA, 'src/live.rs', '            if message.contains("Tor is not ready yet") {', '            if false {'),
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
