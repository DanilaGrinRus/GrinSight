#!/usr/bin/env python3
"""Deliberate breakages of ed. 0.44: the two hypotheses of the fourth audit
round (K137, and the wallet's selected tip standing on blocks) and paying
an invoice from the window (K138, K139), the device key of the guard
(K140) and the place of an installed copy's data (K141). The window's sources are taken from
/tmp/uicheck (a copy of ui/app with the images stubbed)."""
import subprocess, os, sys
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
F='/home/claude/fly'
ACCEPT=(F+'/chain/fly-chain',['cargo','test','--offline','--test','accept'])
FEED=(F+'/chain/fly-chain',['cargo','test','--offline','--lib','feed'])
WCORE=(F+'/paycore/wallet',['cargo','test','--offline','--test','core','an_invoice_is_reviewed'])
BRIDGE=(F+'/paycore',['cargo','test','--offline','--features','stub','--manifest-path','bridge/Cargo.toml','--test','bridge'])
HOST=(F+'/paycore/host',['cargo','test','--offline','--features','test-chain','--test','host','the_device_key'])
# the reading of the first line is tested on every system; the wrapping of the guard's key is not for Windows
HOSTLIB=(F+'/paycore/host',['cargo','test','--offline','--features','test-chain','--lib','device_key'])
WINDOW=('/tmp/uicheck',['cargo','test','--offline','--lib'])
SEL="                .filter(|blocks| blocks.at_tip && selected && blocks.height == view.height && blocks.hash == view.hash)"
M=[
 ('K137 an asking that did not start is waited for', ACCEPT, 'src/accept.rs', "        if started.is_err() && self.round.as_ref().is_some_and(|round| round.id == id) {\n            self.round = None;\n        }", "        let _ = id;"),
 ('selected without the blocks at the tip', FEED, 'src/feed.rs', SEL, SEL.replace("blocks.at_tip && ","")),
 ('selected for another block than the header', FEED, 'src/feed.rs', SEL, SEL.replace(" && blocks.height == view.height && blocks.hash == view.hash","")),
 ('selected without the asking', FEED, 'src/feed.rs', SEL, SEL.replace(" && selected","")),
 ('K138 a fee above the agreed one is signed', WCORE, 'src/lib.rs', '        if picked.fee > max_fee {\n            return Err(CoreError::Refused("the fee is higher than agreed"));\n        }\n', ''),
 ('K138 the review of a paid invoice counts anew', WCORE, 'src/lib.rs', "                        fee: s.fee,\n", "                        fee: s.fee.saturating_add(1),\n"),
 ('K138 the review does not look at the cutoff', WCORE, 'src/lib.rs', "        slates::check_ttl(parsed.slate.ttl_cutoff_height, self.tip_height())?;\n        self.require_complete_for_spend()?;\n        if self.st.any_contested() {", "        self.require_complete_for_spend()?;\n        if self.st.any_contested() {"),
 ('K138 the bridge drops the agreed fee', BRIDGE, 'bridge/src/lib.rs', 'let max_fee = p.amount_or("max_fee", u64::MAX)?;', 'let max_fee = u64::MAX;'),
 ('K138 the window pays without naming the fee', WINDOW, 'src/live.rs', ', "max_fee": flow.fee.to_string() })', ' })'),
 ('K138 an invoice shown without the wallet\'s fee', WINDOW, 'src/live.rs', '    let fee = number("fee")?;', '    let fee = number("fee").unwrap_or(0);'),
 ('K139 the history does not mark the payment of an invoice', BRIDGE, 'bridge/src/lib.rs', '                            "invoice": self.core.send_is_invoice(&op),\n', ''),
 ('K139 a paid invoice said to be going to the network', WINDOW, 'src/live.rs', '        "finalized" if invoice =>', '        "finalized" if invoice && false =>'),
 ('K140 the device key is left out of the guard', HOST, 'src/session.rs', "        device: places.device_key.clone(),", "        device: None,"),
 ('K140 a short device key is taken', HOSTLIB, 'src/lib.rs', "    if digits.len() != 64 {\n        return Err(wrong);\n    }", "    if digits.len() > 64 {\n        return Err(wrong);\n    }"),
 ('K140 the status calls every guard device-bound', HOST, 'src/session.rs', "    } else if places.device_key.is_some() {", "    } else if true {"),
 ('K141 an installed copy keeps the wallet in the program folder', WINDOW, 'src/lib.rs', '        "windows" if installed =>', '        "windows" if installed && false =>'),
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
