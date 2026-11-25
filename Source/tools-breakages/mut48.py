#!/usr/bin/env python3
"""Deliberate breakages of K187 (a wallet is deleted for its password and two of its words): paycore/host."""
import subprocess, os
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
R='/home/claude/fly/paycore/host'
M=[
 ('the words are not asked for', 'src/inline.rs', '        if !crate::words_match(&secrets.seed, said)? {', '        if !crate::words_match(&secrets.seed, said)? && false {'),
 ('one right word of the two is enough', 'src/lib.rs', '        all &= own.get(place.saturating_sub(1))', '        all = own.get(place.saturating_sub(1))'),
 ('the same word twice counts as two', 'src/lib.rs', '        if place == 0 || place > own.len() || places.contains(&place) {', '        if place == 0 || place > own.len() {'),
 ('a place that is not one of the 24 is taken', 'src/lib.rs', '        if place == 0 || place > own.len() || places.contains(&place) {', '        if places.contains(&place) {'),
 ('a third word is passed over', 'src/lib.rs', '    if parts.len() != DELETE_WORDS.saturating_mul(2) {', '    if parts.len() < DELETE_WORDS.saturating_mul(2) {'),
 ('a word typed in capitals is not the word', 'src/lib.rs', 'mine == &word.to_lowercase().as_str()', 'mine == word'),
 ('the neighbour\'s guard goes with the wallet\'s', 'src/session.rs', '        places.guard_root.join(hex(instance)),\n    ];', '        places.guard_root.clone(),\n    ];'),
 ('the journal is left behind', 'src/session.rs', '        journal_dir(&places.profile, instance),\n        places.guard_root', '        places.guard_root'),
 ('the profile\'s file is left behind', 'src/inline.rs', '        session::forget(&self.places, &secrets.instance).map_err(|e| fail(-32049, "profile_io", &format!("{:?}", e.kind())))?;\n        profile::remove(&self.places.profile)?;', '        session::forget(&self.places, &secrets.instance).map_err(|e| fail(-32049, "profile_io", &format!("{:?}", e.kind())))?;'),
 ('the wallet stays open after it is deleted', 'src/inline.rs', '        // the bridge, the core and its keys end here\n        self.open = None;\n        session::forget', '        session::forget'),
 ('the wallet is closed before the words are checked', 'src/inline.rs', '        let secrets = self.profile_for_session(&pass)?;\n        if !crate::words_match', '        let secrets = self.profile_for_session(&pass)?;\n        self.open = None;\n        if !crate::words_match'),
]
bad=0
for name,f,old,new in M:
    p=os.path.join(R,f); src=open(p).read()
    if src.count(old)!=1: print('NOT APPLIED',name,src.count(old)); bad+=1; continue
    open(p,'w').write(src.replace(old,new))
    try: r=subprocess.run(['cargo','test','--offline','--lib','inline'],cwd=R,env=ENV,capture_output=True,text=True,timeout=400)
    finally: open(p,'w').write(src)
    t=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name); bad+=1
    elif 'could not compile' in t: print('NO BUILD',name); bad+=1
    else: print('caught ',name)
print('breakages:',len(M),'problems:',bad)
