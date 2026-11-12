// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted conversation history (M2).
//!
//! The caller supplies a 32-byte key (the app will derive it from the wallet
//! password with Argon2id once phase 3 lands). Each record is a JSON object
//! encrypted with ChaCha20-Poly1305 and stored as `peer/<uuid>.msg`; the peer
//! address is the only visible metadata. The key is zeroized on drop.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::address::Address;
use crate::envelope::{unix_now, MessageKind};
use crate::error::{Error, Result};

const AAD_DOMAIN: &[u8] = b"glaux-messenger-history-v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Incoming,
    Outgoing,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MessageRecord {
    pub id: String,
    pub direction: Direction,
    pub kind: MessageKind,
    pub created_at: u64,
    /// Unix timestamp after which the local history record may be deleted.
    /// `None` keeps legacy records (and messages without an explicit expiry).
    #[serde(default)]
    pub expires_at: Option<u64>,
}

pub struct History {
    root: PathBuf,
    key: Zeroizing<[u8; 32]>,
    max_per_peer: usize,
    lock: Mutex<()>,
}

impl History {
    pub fn open(root: impl Into<PathBuf>, key: [u8; 32]) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| Error::Store(format!("history: {e}")))?;
        Ok(Self {
            root,
            key: Zeroizing::new(key),
            max_per_peer: 2_000,
            lock: Mutex::new(()),
        })
    }

    pub fn with_limit(mut self, max_per_peer: usize) -> Self {
        self.max_per_peer = max_per_peer;
        self
    }

    fn guard(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.lock
            .lock()
            .map_err(|_| Error::Store("history poisoned".into()))
    }

    fn peer_dir(&self, peer: &Address) -> PathBuf {
        self.root.join(peer.to_string())
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.key[..]))
    }

    fn aad(peer: &Address, id: &str) -> Vec<u8> {
        let mut out = AAD_DOMAIN.to_vec();
        out.extend_from_slice(peer.to_string().as_bytes());
        out.push(0);
        out.extend_from_slice(id.as_bytes());
        out
    }

    pub fn record(&self, peer: &Address, record: &MessageRecord) -> Result<()> {
        let _guard = self.guard()?;
        self.cleanup_peer_locked(peer, unix_now());
        if uuid::Uuid::parse_str(&record.id).is_err() {
            return Err(Error::Envelope("history id должен быть UUID".into()));
        }
        let dir = self.peer_dir(peer);
        fs::create_dir_all(&dir).map_err(|e| Error::Store(format!("history: {e}")))?;
        let plaintext = Zeroizing::new(
            serde_json::to_vec(record)
                .map_err(|e| Error::Envelope(format!("history json: {e}")))?,
        );
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| Error::Crypto(format!("history RNG: {e}")))?;
        let ciphertext = self
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &Self::aad(peer, &record.id),
                },
            )
            .map_err(|_| Error::Crypto("history encrypt".into()))?;

        let mut bytes = Vec::with_capacity(12 + ciphertext.len());
        bytes.extend_from_slice(&nonce);
        bytes.extend_from_slice(&ciphertext);
        write_atomic(&dir.join(format!("{}.msg", record.id)), &bytes)?;
        self.prune(peer);
        Ok(())
    }

    pub fn list(&self, peer: &Address, limit: usize) -> Result<Vec<MessageRecord>> {
        let _guard = self.guard()?;
        self.cleanup_peer_locked(peer, unix_now());
        let mut records = self.read_records(peer)?;
        records.sort_by_key(|record| record.created_at);
        // Keep the newest page, then return it chronologically. Taking the
        // first N made new messages invisible once a peer passed the limit.
        let keep = limit.max(1).min(records.len());
        let start = records.len() - keep;
        Ok(records.split_off(start))
    }

    /// Persistent dedup probe: the record file is the durable "seen" marker,
    /// so a relay replay after a restart is not surfaced as a new message.
    pub fn contains(&self, peer: &Address, id: &str) -> Result<bool> {
        let _guard = self.guard()?;
        if uuid::Uuid::parse_str(id).is_err() {
            return Ok(false);
        }
        Ok(self.peer_dir(peer).join(format!("{id}.msg")).is_file())
    }

    fn read_records(&self, peer: &Address) -> Result<Vec<MessageRecord>> {
        let dir = self.peer_dir(peer);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut records = Vec::new();
        for entry in fs::read_dir(&dir).map_err(|e| Error::Store(format!("history: {e}")))? {
            let path = entry
                .map_err(|e| Error::Store(format!("history: {e}")))?
                .path();
            if path.extension().and_then(|e| e.to_str()) != Some("msg") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let bytes = fs::read(&path).map_err(|e| Error::Store(format!("history: {e}")))?;
            if bytes.len() <= 12 {
                continue;
            }
            let nonce: [u8; 12] = bytes[..12]
                .try_into()
                .map_err(|_| Error::Envelope("history nonce".into()))?;
            let plaintext = self
                .cipher()
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &bytes[12..],
                        aad: &Self::aad(peer, id),
                    },
                )
                .map_err(|_| Error::Crypto("history: не удалось расшифровать запись".into()))?;
            records.push(
                serde_json::from_slice(&plaintext)
                    .map_err(|e| Error::Envelope(format!("history json: {e}")))?,
            );
        }
        Ok(records)
    }
    pub fn conversations(&self) -> Result<Vec<Address>> {
        let _guard = self.guard()?;
        let mut peers = Vec::new();
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Ok(peers);
        };
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(peer) = Address::parse(name) {
                    self.cleanup_peer_locked(&peer, unix_now());
                    peers.push(peer);
                }
            }
        }
        Ok(peers)
    }

    pub fn delete(&self, peer: &Address, id: &str) -> Result<bool> {
        let _guard = self.guard()?;
        if uuid::Uuid::parse_str(id).is_err() {
            return Ok(false);
        }
        let path = self.peer_dir(peer).join(format!("{id}.msg"));
        if path.exists() {
            fs::remove_file(&path).map_err(|e| Error::Store(format!("history: {e}")))?;
            return Ok(true);
        }
        Ok(false)
    }

    fn cleanup_peer_locked(&self, peer: &Address, now: u64) -> usize {
        let Ok(records) = self.read_records(peer) else {
            return 0;
        };
        let mut removed = 0;
        for record in records {
            if record
                .expires_at
                .is_some_and(|expires_at| expires_at <= now)
            {
                let path = self.peer_dir(peer).join(format!("{}.msg", record.id));
                if fs::remove_file(path).is_ok() {
                    removed += 1;
                }
            }
        }
        removed
    }

    /// Delete locally expired encrypted history records. Corrupt records are
    /// left untouched so a damaged file is not silently treated as absent.
    pub fn cleanup_expired(&self, now: u64) -> Result<usize> {
        let _guard = self.guard()?;
        let mut removed = 0;
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Ok(0);
        };
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if let Ok(peer) = Address::parse(&name) {
                removed += self.cleanup_peer_locked(&peer, now);
            }
        }
        Ok(removed)
    }

    fn prune(&self, peer: &Address) {
        let Ok(count) = count_msg(&self.peer_dir(peer)) else {
            return;
        };
        if count <= self.max_per_peer {
            return;
        }
        let Ok(mut records) = self.read_records(peer) else {
            return;
        };
        records.sort_by_key(|record| record.created_at);
        let excess = count.saturating_sub(self.max_per_peer);
        for record in records.into_iter().take(excess) {
            let path = self.peer_dir(peer).join(format!("{}.msg", record.id));
            let _ = fs::remove_file(path);
        }
    }
}
fn count_msg(dir: &Path) -> std::io::Result<usize> {
    Ok(fs::read_dir(dir)?
        .flatten()
        .filter(|entry| entry.path().extension().and_then(|e| e.to_str()) == Some("msg"))
        .count())
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("history"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let write = || -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| Error::Store(format!("history write: {e}")))?;
        file.write_all(bytes)
            .map_err(|e| Error::Store(format!("history write: {e}")))?;
        file.sync_all()
            .map_err(|e| Error::Store(format!("history fsync: {e}")))?;
        drop(file);
        fs::rename(&tmp, path).map_err(|e| Error::Store(format!("history rename: {e}")))
    };
    match write() {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::MessageKind;
    use uuid::Uuid;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("glaux-hist-{tag}-{}", Uuid::new_v4()))
    }

    fn peer() -> Address {
        let identity = crate::Identity::from_seed([9u8; 32], "tgrin").unwrap();
        identity.address().clone()
    }

    fn record(text: &str, at: u64) -> MessageRecord {
        MessageRecord {
            id: Uuid::new_v4().to_string(),
            direction: Direction::Incoming,
            kind: MessageKind::Text { text: text.into() },
            created_at: at,
            expires_at: None,
        }
    }

    #[test]
    fn expired_records_are_removed_but_legacy_records_stay() {
        let dir = temp_dir("ttl");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let peer = peer();
        let mut expired = record("old", 1);
        expired.expires_at = Some(2);
        history.record(&peer, &expired).unwrap();
        let legacy = record("legacy", 3);
        history.record(&peer, &legacy).unwrap();

        let listed = history.list(&peer, 10).unwrap();
        assert_eq!(listed.len(), 1, "only the legacy record remains");
        assert_eq!(listed[0].id, legacy.id);
        assert!(!dir
            .join(peer.to_string())
            .join(format!("{}.msg", expired.id))
            .exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn contains_is_the_persistent_dedup_marker() {
        let dir = temp_dir("contains");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let record = record("once", 1);
        history.record(&peer(), &record).unwrap();
        assert!(history.contains(&peer(), &record.id).unwrap());
        assert!(!history
            .contains(&peer(), &Uuid::new_v4().to_string())
            .unwrap());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn roundtrip_ordered_and_encrypted_at_rest() {
        let dir = temp_dir("round");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let peer = peer();
        history.record(&peer, &record("second", 2)).unwrap();
        history.record(&peer, &record("first", 1)).unwrap();

        let raw = fs::read_dir(dir.join(peer.to_string()))
            .unwrap()
            .flatten()
            .map(|entry| fs::read(entry.path()).unwrap())
            .collect::<Vec<_>>();
        for bytes in &raw {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("first"), "plaintext leaked");
            assert!(!text.contains("second"), "plaintext leaked");
        }

        let records = history.list(&peer, 10).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].created_at, 1);
        assert_eq!(records[1].created_at, 2);
        assert_eq!(history.conversations().unwrap(), vec![peer.clone()]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_key_and_tamper_fail() {
        let dir = temp_dir("keys");
        let peer = peer();
        let item = record("x", 1);
        {
            let history = History::open(&dir, [7u8; 32]).unwrap();
            history.record(&peer, &item).unwrap();
        }
        let other = History::open(&dir, [8u8; 32]).unwrap();
        assert!(other.list(&peer, 10).is_err());

        let path = dir.join(peer.to_string()).join(format!("{}.msg", item.id));
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, bytes).unwrap();
        let history = History::open(&dir, [7u8; 32]).unwrap();
        assert!(history.list(&peer, 10).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_and_uuid_validation() {
        let dir = temp_dir("delete");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let peer = peer();
        let item = record("x", 1);
        history.record(&peer, &item).unwrap();
        assert!(history.delete(&peer, &item.id).unwrap());
        assert!(!history.delete(&peer, "../../etc/passwd").unwrap());
        assert!(history.list(&peer, 10).unwrap().is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_returns_the_newest_page() {
        let dir = temp_dir("newest");
        let history = History::open(&dir, [7u8; 32]).unwrap();
        let peer = peer();
        for at in 1..=5 {
            history
                .record(&peer, &record(&format!("m{at}"), at))
                .unwrap();
        }
        let records = history.list(&peer, 2).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].created_at, 4);
        assert_eq!(records[1].created_at, 5);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn quota_prunes_oldest() {
        let dir = temp_dir("prune");
        let history = History::open(&dir, [7u8; 32]).unwrap().with_limit(2);
        let peer = peer();
        for at in 1..=4 {
            history
                .record(&peer, &record(&format!("m{at}"), at))
                .unwrap();
        }
        let records = history.list(&peer, 10).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].created_at, 3);
        assert_eq!(records[1].created_at, 4);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn large_history_is_bounded_and_lists_newest_first() {
        let dir = temp_dir("large");
        let history = History::open(&dir, [7u8; 32]).unwrap().with_limit(100);
        let peer = peer();
        for at in 1..=120u64 {
            history
                .record(&peer, &record(&format!("m{at}"), at))
                .unwrap();
        }
        let files = fs::read_dir(dir.join(peer.to_string())).unwrap().count();
        assert!(files <= 100, "history grew to {files} records");
        let records = history.list(&peer, 20).unwrap();
        assert_eq!(records.len(), 20, "newest page is not full");
        assert_eq!(
            records.last().unwrap().created_at,
            120,
            "newest record is missing"
        );
        assert!(
            records
                .windows(2)
                .all(|pair| pair[0].created_at <= pair[1].created_at),
            "history page is not chronological"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
