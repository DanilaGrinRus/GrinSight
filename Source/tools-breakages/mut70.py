#!/usr/bin/env python3
"""Deliberate breakages of the fixes of audit round 6: finding 51 (the consent to spend marked outputs and the
choice of outputs do not outlive the payment they were given for), 52 (a choice of bridges saved by hand ends the
wallet's own try), 53 (after Tor is switched on again nothing goes out directly without a consent that holds now).
The window's part runs against the check copy /tmp/uic/app."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
A='/tmp/uic/app'
AT=(A,['cargo','test','--locked','--offline','--lib','--','changing_the_payment_outputs','closing_a_send_sheet','saving_a_bridge_choice'])
C='/home/claude/fly/chain/fly-chain'
CT=(C,['cargo','test','--offline','--features','test-net','--test','post','--','the_tor_switch_turned'])
L=A+'/src/live.rs'; P=C+'/src/post.rs'
M=[
 (AT,L,'51: another output is chosen and the consent stays','            true\n        });\n        if changed {\n            app.set_spend_kept(false);\n        }','            true\n        });\n        if changed && false {\n            app.set_spend_kept(false);\n        }'),
 (AT,L,'51: the outputs change under the choice and the consent stays','    if changed {\n        app.set_spend_kept(false);\n    }\n    show_outputs(app);','    show_outputs(app);'),
 (AT,L,'51: a mark changed on a chosen output is not noticed','        f.picked.len() != before || marks_changed','        f.picked.len() != before'),
 (AT,L,'51: the closed send window keeps its choice','            if sheet == 1 {\n                clear_output_choice(&app);\n            }\n',''),
 (AT,L,'52: a choice saved by hand leaves the try going','                bridges::manual_saved(&app);\n',''),
 (CT,P,'53: the list of announced answers without a consent','                (self.direct() || sent.direct)\n                    && sent.mined.is_none()','                sent.mined.is_none()'),
 (CT,P,'53: the queue goes on directly after Tor is on again','            if !(direct || sent.direct) || peers.is_empty() {','            if peers.is_empty() {'),
 (CT,P,'53: an agreement for one payment does not count','            if !(direct || sent.direct) || peers.is_empty() {','            if !direct || peers.is_empty() {'),
]
bad=0
for (cwd,cmd),F,name,old,new in M:
    src=open(F).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(F,'w').write(src.replace(old,new))
    try: r=subprocess.run(cmd,cwd=cwd,env=ENV,capture_output=True,text=True,timeout=2400)
    finally: open(F,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
