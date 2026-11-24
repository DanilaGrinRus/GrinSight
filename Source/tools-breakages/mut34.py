#!/usr/bin/env python3
"""Deliberate breakages of K120-K122 (text messages). Each must make a test fail."""
import subprocess, os, sys
ROOT='/home/claude/fly/paycore'
ENV=dict(os.environ, CARGO_INCREMENTAL='0', CARGO_PROFILE_DEV_DEBUG='0', CARGO_PROFILE_TEST_DEBUG='0', CARGO_TARGET_DIR='/home/claude/pc-target')
UNIT=['cargo','test','--offline','--manifest-path','bridge/Cargo.toml','--test','delivery','text_messages']
B='bridge/src/lib.rs'
S='wallet/src/state.rs'
W='wallet/src/lib.rs'
M=[
 ('text taken for a slate', B, "        if let Some(body) = msg.text.strip_prefix(MESSAGE_PREFIX) {", "        if let Some(body) = msg.text.strip_prefix(\"never\") {"),
 ('forgotten before kept', B, "            return match self.core.message_received(msg.from, msg.id, body, unix_now()) {", "            return match Ok::<bool, CoreError>(body.is_empty()) {"),
 ('a stranger kept', S, "        if contact.len() != 32 || !self.contacts.contains_key(&k) {", "        if contact.len() != 32 {"),
 ('any length kept', S, "        if m.text.is_empty() || m.text.len() > crate::MAX_MESSAGE_LEN {", "        if m.text.is_empty() {"),
 ('history unbounded', S, "    while list.len() > crate::MAX_MESSAGES_PER_CONTACT.saturating_add(waiting) {", "    while list.len() > usize::MAX {"),
 ('conversation outlives the contact', S, "                if self.conversations.0.contains_key(&k) {\n                    std::sync::Arc::make_mut(&mut self.conversations.0).remove(&k);\n                }\n", ""),
 ('a lost message given up', B, "                Published::Expired => self.core.message_note(id, false)?,\n                _ => {}", "                _ => self.core.message_note(id, false)?,"),
 ('the window not checked', B, "            let expired = confirmed.is_some_and(|t| t >= envelope.expires_at);", "            let expired = false;"),
 ('sealed before the checks', W, "        if text.is_empty() || text.len() > MAX_MESSAGE_LEN {\n            return Err(CoreError::Refused(\"message is not usable\"));\n        }\n        let waiting", "        let _ = seal(\"x\");\n        if text.is_empty() || text.len() > MAX_MESSAGE_LEN {\n            return Err(CoreError::Refused(\"message is not usable\"));\n        }\n        let waiting"),
 ('resealed on every round', B, "            let Some(envelope) = self.core.message_envelope(id) else {\n                continue;\n            };\n            let expired", "            let Some(envelope) = self.core.message_envelope(id) else {\n                continue;\n            };\n            let _ = mailbox.seal(&[0u8; 32], \"again\");\n            let expired"),
]
only=sys.argv[1:]; bad=0; n=0
for name,f,old,new in M:
    if only and not any(o in name for o in only): continue
    n+=1
    p=os.path.join(ROOT,f); src=open(p).read()
    if src.count(old)!=1:
        print('NOT APPLIED',name,src.count(old), flush=True); bad+=1; continue
    open(p,'w').write(src.replace(old,new))
    try:
        r=subprocess.run(UNIT,cwd=ROOT,env=ENV,capture_output=True,text=True,timeout=1500)
    finally:
        open(p,'w').write(src)
    text=r.stdout+r.stderr
    if r.returncode==0: print('MISSED ',name, flush=True); bad+=1
    elif 'error[' in text or 'could not compile' in text: print('NO BUILD',name, flush=True); bad+=1
    else:
        failed=[l.split()[1] for l in text.splitlines() if l.startswith('test ') and l.endswith('FAILED')]
        print('caught ',name,'<-',', '.join(failed[:2]), flush=True)
print('breakages:',n,'problems:',bad)
