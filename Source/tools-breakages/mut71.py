#!/usr/bin/env python3
"""Deliberate breakages of O73 (what a "?" says opens in a window of its own; the details are a window; the state
stands above the money; settings in one window) and O74 (the words copied to the clipboard are taken back if they
are still there, and only then). Runs against the check copy /tmp/uic/app."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
A='/tmp/uic/app'
T=['cargo','test','--locked','--offline','--lib','--','help_and_details','the_words_go_to_the_clipboard','bridges_are_reached']
APP=A+'/ui/app.slint'; PAGES=A+'/ui/pages.slint'; FLOWS=A+'/ui/flows.slint'
M=[
 (APP,'O73: the help window is not there','        if Help.open: Rectangle {','        if false && Help.open: Rectangle {'),
 (FLOWS,'O73: a "?" without its words','VerticalLayout { alignment: center; Ask { title: @tr("Choose the outputs to pay with"); text:','VerticalLayout { alignment: center; Ask { } } Rectangle { visible: false; Text { text:'),
 (APP,'O73: the details unfold in the page again','        if (root.page == 1 || root.page == 4 || root.page == 5) && root.sheet == 15: SyncSheet {','        if root.sync-details: SyncSheet {\n    in-out property <bool> sync-details;'),
 (APP,'O73: no settings window','        if (root.page == 1 || root.page == 4 || root.page == 5) && root.sheet == 16: SettingsSheet {','        if false: SettingsSheet {'),
 (APP,'O74: the clipboard is emptied even when it holds something else','            if (words-probe.text == root.words-clip) {','            if (true) {'),
 (APP,'O74: the clipboard is never emptied','                words-blank.select-all();\n                words-blank.copy();','                words-blank.select-all();'),
 (APP,'O74: the words are not put on the clipboard','        words-out.select-all();\n        words-out.copy();','        words-out.select-all();'),
 (APP,'O74: what was copied is forgotten at once','        root.words-clip = root.words-line;',''),
]
bad=0
for F,name,old,new in M:
    src=open(F).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old),flush=True); bad+=1; continue
    open(F,'w').write(src.replace(old,new))
    try: r=subprocess.run(T,cwd=A,env=ENV,capture_output=True,text=True,timeout=2400)
    finally: open(F,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name,flush=True); bad+=1
    elif 'could not compile' in t and 'O73: the details' not in name and 'a "?" without' not in name: print('NO BUILD',name,flush=True); bad+=1
    else: print('caught ',name,flush=True)
print('breakages:',len(M),'problems:',bad)
