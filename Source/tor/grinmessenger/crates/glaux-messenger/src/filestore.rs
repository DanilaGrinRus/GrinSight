// SPDX-License-Identifier: MIT OR Apache-2.0
//! Persistent local mailbox: envelopes at rest, one JSON file per message.
//!
//! Only the signed+encrypted envelope is written — never the opened payload.
//! The directory is keyed by the recipient slatepack address, file names are
//! UUIDs, writes are atomic, and ack deletes by validated UUID. This is the M2
//! storage step; the UI/history layer is still to come.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::address::Address;
use crate::envelope::{unix_now, Envelope};
use crate::error::{Error, Result};
use crate::store::Transport;
use crate::MAX_TTL_SECS;

pub struct FileMailbox {
    root: PathBuf,
    max_per_recipient: usize,
    max_ciphertext: usize,
    lock: Mutex<()>,
}

impl FileMailbox {
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| Error::Store(format!("mailbox: {e}")))?;
        Ok(Self {
            root,
            max_per_recipient: 100,
            max_ciphertext: 64 * 1024,
            lock: Mutex::new(()),
        })
    }

    pub fn with_limits(mut self, max_per_recipient: usize, max_ciphertext: usize) -> Self {
        self.max_per_recipient = max_per_recipient;
        self.max_ciphertext = max_ciphertext;
        self
    }

    fn recipient_dir(&self, recipient: &Address) -> PathBuf {
        self.root.join(recipient.to_string())
    }

    fn guard(&self) -> Result<(std::sync::MutexGuard<'_, ()>, fs::File)> {
        let started=std::time::Instant::now();
        let guard = loop {
            match self.lock.try_lock() {
                Ok(g) => break g,
                Err(std::sync::TryLockError::WouldBlock) if started.elapsed() < std::time::Duration::from_secs(3) => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(std::sync::TryLockError::WouldBlock) => return Err(Error::Store("mailbox lock timed out".into())),
                Err(_) => return Err(Error::Store("mailbox poisoned".into())),
            }
        };
        let file = fs::OpenOptions::new().read(true).write(true).create(true).open(self.root.join("mailbox.lock"))
            .map_err(|e| Error::Store(format!("mailbox lock: {e}")))?;
        loop {
            match file.try_lock() {
                Ok(()) => break,
                Err(std::fs::TryLockError::WouldBlock) if started.elapsed() < std::time::Duration::from_secs(3) => std::thread::sleep(std::time::Duration::from_millis(20)),
                Err(std::fs::TryLockError::WouldBlock) => return Err(Error::Store("mailbox lock timed out".into())),
                Err(e) => return Err(Error::Store(format!("mailbox lock: {e}"))),
            }
        }
        Ok((guard,file))
    }

    pub fn ack_exact(&self, recipient: &Address, tokens: &[String]) -> Result<usize> {
        let _guard=self.guard()?; let mut removed=0;
        for token in tokens {
            let (id,digest)=token.split_once(':').ok_or_else(|| Error::Store("mailbox content-specific ACK required".into()))?;
            if uuid::Uuid::parse_str(id).is_err() { return Err(Error::Store("invalid mailbox id".into())); }
            let path=self.recipient_dir(recipient).join(format!("{id}.json"));
            if !path.exists() { continue; }
            let bytes=fs::read(&path).map_err(|e|Error::Store(format!("mailbox read: {e}")))?;
            let envelope:Envelope=serde_json::from_slice(&bytes).map_err(|e|Error::Store(format!("mailbox envelope: {e}")))?;
            if crate::ack::envelope_digest(&envelope)? != digest { return Err(Error::Store("mailbox ACK content conflict".into())); }
            fs::remove_file(path).map_err(|e|Error::Store(format!("mailbox remove: {e}")))?;removed+=1;
        }
        Ok(removed)
    }
}

impl Transport for FileMailbox {
    fn deliver(&self, envelope: &Envelope) -> Result<()> {
        let _guard = self.guard()?;
        let recipient = Address::parse(&envelope.recipient)?;
        if uuid::Uuid::parse_str(&envelope.id).is_err() {
            return Err(Error::Envelope("id должен быть UUID".into()));
        }
        if envelope.ttl == 0 || envelope.ttl > MAX_TTL_SECS {
            return Err(Error::BadTtl(envelope.ttl));
        }
        if envelope.ciphertext.len() > self.max_ciphertext {
            return Err(Error::Quota(format!(
                "сообщение {} Б > {} Б",
                envelope.ciphertext.len(),
                self.max_ciphertext
            )));
        }
        if envelope.is_expired(unix_now()) {
            return Err(Error::Expired);
        }

        let dir = self.recipient_dir(&recipient);
        fs::create_dir_all(&dir).map_err(|e| Error::Store(format!("mailbox: {e}")))?;
        purge_expired(&dir, unix_now());
        let path = dir.join(format!("{}.json", envelope.id));
        if path.exists() {
            // Retries are accepted only if they contain the identical envelope.
            let bytes=fs::read(&path).map_err(|_| Error::Store("mailbox duplicate unreadable".into()))?;
            let existing:Envelope=serde_json::from_slice(&bytes).map_err(|_| Error::Store("mailbox duplicate invalid".into()))?;
            return if existing == *envelope { Ok(()) } else { Err(Error::Store("conflicting envelope id".into())) };
        }
        if count_json(&dir) >= self.max_per_recipient {
            return Err(Error::Quota(format!(
                "очередь получателя заполнена: {}",
                self.max_per_recipient
            )));
        }

        let bytes =
            serde_json::to_vec(envelope).map_err(|e| Error::Envelope(format!("envelope: {e}")))?;
        write_atomic(&path, &bytes)
    }

    fn fetch(&self, recipient: &Address, now: u64, limit: usize) -> Result<Vec<Envelope>> {
        let _guard = self.guard()?;
        let dir = self.recipient_dir(recipient);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        purge_expired(&dir, now);
        let mut items = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| Error::Store(format!("mailbox: {e}")))? {
            let path = entry
                .map_err(|e| Error::Store(format!("mailbox: {e}")))?
                .path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };
            let Ok(envelope) = serde_json::from_slice::<Envelope>(&bytes) else {
                continue;
            };
            if envelope.is_expired(now) {
                let _ = fs::remove_file(&path);
                continue;
            }
            items.push(envelope);
        }
        items.sort_by_key(|envelope| envelope.created_at);
        Ok(items.into_iter().take(limit.max(1)).collect())
    }

    fn ack(&self, recipient: &Address, ids: &[String]) -> Result<usize> {
        let _guard = self.guard()?;
        let dir = self.recipient_dir(recipient);
        if !dir.exists() {
            return Ok(0);
        }
        let mut removed = 0;
        for id in ids {
            if uuid::Uuid::parse_str(id).is_err() {
                continue;
            }
            let path = dir.join(format!("{id}.json"));
            if path.exists() && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        Ok(removed)
    }
}

fn count_json(dir: &Path) -> usize {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("json"))
                .count()
        })
        .unwrap_or(0)
}

fn purge_expired(dir: &Path, now: u64) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = fs::read(&path) else {
            continue;
        };
        if serde_json::from_slice::<Envelope>(&bytes).is_ok_and(|envelope| envelope.is_expired(now))
        {
            let _ = fs::remove_file(&path);
        }
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("{}.tmp",uuid::Uuid::new_v4()));
    let mut f=fs::OpenOptions::new().write(true).create_new(true).open(&tmp)
        .map_err(|e| Error::Store(format!("mailbox write: {e}")))?;
    f.write_all(bytes).and_then(|_|f.sync_all()).map_err(|e| Error::Store(format!("mailbox write: {e}")))?;
    drop(f);
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        Error::Store(format!("mailbox rename: {e}"))
    })?;
    #[cfg(unix)]
    fs::File::open(path.parent().ok_or_else(||Error::Store("mailbox parent missing".into()))?)
        .and_then(|dir|dir.sync_all()).map_err(|e|Error::Store(format!("mailbox directory sync: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Identity, MessageKind};
    use crate::{DEFAULT_TTL_SECS, MAX_TTL_SECS};

    fn identities() -> (Identity, Identity) {
        (
            Identity::from_seed([7u8; 32], "tgrin").unwrap(),
            Identity::from_seed([9u8; 32], "tgrin").unwrap(),
        )
    }

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("glaux-msg-{tag}-{}", uuid::Uuid::new_v4()))
    }

    fn envelope(alice: &Identity, bob: &Identity, text: &str) -> Envelope {
        Envelope::seal_now(
            alice,
            bob.address(),
            MessageKind::Text { text: text.into() },
            DEFAULT_TTL_SECS,
        )
        .unwrap()
    }

    #[test]
    fn duplicate_id_with_different_ciphertext_is_not_acknowledged() {
        let dir=temp_dir("conflict"); let (alice,bob)=identities();
        let store=FileMailbox::open(&dir).unwrap();
        let original=envelope(&alice,&bob,"sample"); store.deliver(&original).unwrap();
        store.deliver(&original).unwrap();
        let mut conflicting=original.clone(); conflicting.ciphertext[0]^=1;
        assert!(store.deliver(&conflicting).is_err());
        assert_eq!(store.fetch(bob.address(),unix_now(),10).unwrap(),vec![original.clone()]);
        store.ack(bob.address(), &[original.id]).unwrap();
        let _=std::fs::remove_dir(dir.join(bob.address().to_string()));
        let _=std::fs::remove_dir(dir);
    }

    #[test]
    fn exact_ack_does_not_remove_a_replacement() {
        let dir=temp_dir("exact-ack");let (a,b)=identities();let mailbox=FileMailbox::open(&dir).unwrap();
        let old=envelope(&a,&b,"old");let token=format!("{}:{}",old.id,crate::ack::envelope_digest(&old).unwrap());
        mailbox.deliver(&old).unwrap();assert_eq!(mailbox.ack_exact(b.address(),&[token.clone()]).unwrap(),1);
        let mut replacement=old.clone();replacement.ciphertext[0]^=1;mailbox.deliver(&replacement).unwrap();
        assert!(mailbox.ack_exact(b.address(),&[token]).is_err());
        assert_eq!(mailbox.fetch(b.address(),unix_now(),10).unwrap(),vec![replacement]);
        drop(mailbox);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn another_process_holding_mailbox_lock_times_out() {
        const DIR:&str="GS_MAILBOX_LOCK_CHILD";
        if let Some(dir)=std::env::var_os(DIR) {
            let mailbox=FileMailbox::open(&dir).unwrap();let _guard=mailbox.guard().unwrap();
            fs::write(PathBuf::from(dir).join("ready"),b"ready").unwrap();
            std::thread::sleep(std::time::Duration::from_secs(8));return;
        }
        let dir=temp_dir("lock-timeout");let mailbox=FileMailbox::open(&dir).unwrap();
        let mut child=std::process::Command::new(std::env::current_exe().unwrap()).arg("--exact").arg("filestore::tests::another_process_holding_mailbox_lock_times_out").env(DIR,&dir).spawn().unwrap();
        let start=std::time::Instant::now();while !dir.join("ready").exists() && start.elapsed()<std::time::Duration::from_secs(5) { std::thread::sleep(std::time::Duration::from_millis(10)); }
        assert!(dir.join("ready").exists());let start=std::time::Instant::now();
        let err=mailbox.fetch(identities().1.address(),unix_now(),10).err().unwrap().to_string();
        assert!(err.contains("timed out"));assert!(start.elapsed()<std::time::Duration::from_secs(5));
        child.kill().unwrap();child.wait().unwrap();drop(mailbox);let _=fs::remove_dir_all(dir);
    }

    #[test]
    fn persists_across_reopen_and_never_writes_plaintext() {
        let dir = temp_dir("persist");
        let (alice, bob) = identities();
        let item = envelope(&alice, &bob, "top secret");
        {
            let mailbox = FileMailbox::open(&dir).unwrap();
            mailbox.deliver(&item).unwrap();
            let files = fs::read_dir(dir.join(bob.address().to_string()))
                .unwrap()
                .count();
            assert_eq!(files, 1);
        }
        // Raw bytes on disk: ciphertext only, no body/sender.
        let raw = fs::read(
            dir.join(bob.address().to_string())
                .join(format!("{}.json", item.id)),
        )
        .unwrap();
        let raw = String::from_utf8_lossy(&raw);
        assert!(!raw.contains("top secret"), "{raw}");
        assert!(!raw.contains(&alice.address().to_string()), "{raw}");

        let reopened = FileMailbox::open(&dir).unwrap();
        let fetched = reopened.fetch(bob.address(), unix_now(), 10).unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(
            fetched[0].open(&bob, unix_now()).unwrap().sender,
            *alice.address()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn ack_and_duplicate_delivery() {
        let dir = temp_dir("ack");
        let (alice, bob) = identities();
        let item = envelope(&alice, &bob, "x");
        let mailbox = FileMailbox::open(&dir).unwrap();
        mailbox.deliver(&item).unwrap();
        mailbox.deliver(&item).unwrap();
        assert_eq!(
            mailbox.fetch(bob.address(), unix_now(), 10).unwrap().len(),
            1
        );
        assert_eq!(
            mailbox
                .ack(bob.address(), std::slice::from_ref(&item.id))
                .unwrap(),
            1
        );
        assert!(mailbox
            .fetch(bob.address(), unix_now(), 10)
            .unwrap()
            .is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn quota_ttl_and_uuid_are_enforced() {
        let dir = temp_dir("quota");
        let (alice, bob) = identities();
        let mailbox = FileMailbox::open(&dir).unwrap().with_limits(1, 64 * 1024);
        mailbox.deliver(&envelope(&alice, &bob, "a")).unwrap();
        assert!(matches!(
            mailbox.deliver(&envelope(&alice, &bob, "b")),
            Err(Error::Quota(_))
        ));

        let mut bad_id = envelope(&alice, &bob, "c");
        bad_id.id = "../../escape".into();
        assert!(matches!(mailbox.deliver(&bad_id), Err(Error::Envelope(_))));

        let mut long_ttl = envelope(&alice, &bob, "d");
        long_ttl.ttl = MAX_TTL_SECS + 1;
        assert!(matches!(mailbox.deliver(&long_ttl), Err(Error::BadTtl(_))));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_messages_are_not_returned() {
        let dir = temp_dir("expired");
        let (alice, bob) = identities();
        let mailbox = FileMailbox::open(&dir).unwrap();
        let mut old = envelope(&alice, &bob, "old");
        old.created_at = 1;
        old.ttl = 1;
        // Deliver uses wall clock, so write directly to simulate a stale file.
        fs::create_dir_all(dir.join(bob.address().to_string())).unwrap();
        fs::write(
            dir.join(bob.address().to_string())
                .join(format!("{}.json", old.id)),
            serde_json::to_vec(&old).unwrap(),
        )
        .unwrap();
        assert!(mailbox
            .fetch(bob.address(), unix_now(), 10)
            .unwrap()
            .is_empty());
        let _ = fs::remove_dir_all(&dir);
    }
}
