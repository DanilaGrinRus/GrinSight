// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted local read markers.
//!
//! Wallet UI processes need unread counters that survive restarts. Read markers
//! are a map `peer address -> last-read unix timestamp`, encrypted at rest with
//! the same storage key as history/contacts (they leak who the wallet talks to).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

const AAD: &[u8] = b"glaux-messenger-wallet-read-state-v1";
const FILE: &str = "read_state.enc";
const NONCE_LEN: usize = 12;
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Markers {
    legacy: BTreeMap<String, u64>,
    read: BTreeMap<String, BTreeSet<String>>,
}

impl Markers {
    pub fn is_read(&self, peer: &str, id: &str) -> bool {
        self.read.get(peer).is_some_and(|ids| ids.contains(id))
    }
}

pub struct ReadState {
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    markers: Mutex<Markers>,
}

impl ReadState {
    pub fn open(root: impl Into<PathBuf>, key: [u8; 32]) -> Result<Self, String> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| format!("read_state: {e}"))?;
        let path = root.join(FILE);
        let markers = match fs::File::open(&path) {
            Ok(file) => {
                let mut raw = Vec::new();
                file.take((MAX_STATE_BYTES + 1) as u64).read_to_end(&mut raw).map_err(|e| format!("read_state read: {e}"))?;
                if raw.len() > MAX_STATE_BYTES { return Err("read_state: file exceeds size limit".into()); }
                decode(&raw, &key)?
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Markers::default(),
            Err(e) => return Err(format!("read_state {}: {e}", path.display())),
        };
        Ok(Self {
            path,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            markers: Mutex::new(markers),
        })
    }

    pub fn snapshot(&self) -> Markers { self.lock().clone() }

    /// Convert old timestamp cutoffs only against messages present at startup.
    /// Never apply the old cutoff to arrivals after migration.
    pub fn migrate_legacy(&self, messages: &[(String, String, u64)]) -> Result<(), String> {
        let mut guard = self.lock();
        if guard.legacy.is_empty() { return Ok(()); }
        let mut next = guard.clone();
        for (peer, id, created) in messages {
            if next.legacy.get(peer).is_some_and(|cutoff| created <= cutoff) {
                next.read.entry(peer.clone()).or_default().insert(id.clone());
            }
        }
        next.legacy.clear();
        self.persist(&next)?;
        *guard = next;
        Ok(())
    }

    pub fn mark_read(&self, peer: &str, ids: &[String]) -> Result<(), String> {
        let mut guard = self.lock();
        let mut next = guard.clone();
        // Only IDs in the current visible snapshot need to remain marked.
        // Forgotten older IDs may be shown as unread, never the reverse.
        next.read.insert(peer.to_string(), ids.iter().cloned().collect());
        self.persist(&next)?;
        *guard = next;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Markers> {
        self.markers.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn persist(&self, markers: &Markers) -> Result<(), String> {
        let mut bytes = Vec::new();
        bytes.push(2u8); // file format version
        bytes.extend_from_slice(&serde_json::to_vec(markers).map_err(|e| format!("json: {e}"))?);
        if bytes.len() + NONCE_LEN + 16 > MAX_STATE_BYTES { return Err("read_state: size limit reached; cannot mark messages read".into()); }
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|e| format!("RNG: {e}"))?;
        let ciphertext = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &bytes,
                    aad: AAD,
                },
            )
            .map_err(|_| "read_state: encrypt failed".to_string())?;
        let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        let tmp = self.path.with_extension("enc.tmp");
        fs::write(&tmp, &out).map_err(|e| format!("read_state write: {e}"))?;
        fs::rename(&tmp, &self.path).map_err(|e| format!("read_state rename: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

fn decode(raw: &[u8], key: &[u8; 32]) -> Result<Markers, String> {
    if raw.len() < NONCE_LEN + 1 {
        return Err("read_state: file is truncated".into());
    }
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&raw[..NONCE_LEN]),
            Payload {
                msg: &raw[NONCE_LEN..],
                aad: AAD,
            },
        )
        .map_err(|_| {
            "read_state: cannot decrypt (wrong storage key or corrupt file)".to_string()
        })?;
    match plaintext.first() {
        Some(1) => Ok(Markers { legacy: serde_json::from_slice(&plaintext[1..]).map_err(|e| format!("read_state JSON: {e}"))?, read: BTreeMap::new() }),
        Some(2) => serde_json::from_slice(&plaintext[1..]).map_err(|e| format!("read_state JSON: {e}")),
        _ => Err("read_state: unsupported file version".into()),
    }
}

/// The storage key is secret material; keep it in a zeroizing wrapper at call
/// sites even though this module only borrows it.
pub type SecretKey = Zeroizing<[u8; 32]>;

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "glaux-wallet-read-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn markers_track_ids_across_restart_and_failed_write() {
        let dir = temp_dir("roundtrip");
        let key = [5u8; 32];
        let state = ReadState::open(&dir, key).unwrap();
        state.mark_read("peer-a", &["first".into()]).unwrap();
        assert!(state.snapshot().is_read("peer-a", "first"));
        assert!(!state.snapshot().is_read("peer-a", "late"));
        drop(state);
        let reopened = ReadState::open(&dir, key).unwrap();
        assert!(reopened.snapshot().is_read("peer-a", "first"));
        assert!(!reopened.snapshot().is_read("peer-a", "late"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn legacy_cutoff_applies_only_to_messages_present_at_migration() {
        let dir = temp_dir("migration");
        fs::create_dir_all(&dir).unwrap();
        let key = [5; 32];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let nonce = [7u8; NONCE_LEN];
        let mut plaintext = vec![1u8];
        plaintext.extend_from_slice(br#"{"peer":100}"#);
        let encrypted = cipher.encrypt(Nonce::from_slice(&nonce), Payload { msg: &plaintext, aad: AAD }).unwrap();
        let mut legacy = nonce.to_vec();
        legacy.extend_from_slice(&encrypted);
        fs::write(dir.join(FILE), legacy).unwrap();
        let state = ReadState::open(&dir, key).unwrap();
        state.migrate_legacy(&[("peer".into(), "old".into(), 99)]).unwrap();
        assert!(state.snapshot().is_read("peer", "old"));
        assert!(!state.snapshot().is_read("peer", "late"));
        drop(state);
        let reopened = ReadState::open(&dir, [5;32]).unwrap();
        assert!(reopened.snapshot().is_read("peer", "old"));
        assert!(!reopened.snapshot().is_read("peer", "late"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn quota_failure_preserves_existing_marks_and_rejects_new_ids() {
        let dir = temp_dir("quota");
        let state = ReadState::open(&dir, [8;32]).unwrap();
        state.mark_read("peer", &["previous".into()]).unwrap();
        let huge = "a".repeat(MAX_STATE_BYTES);
        assert!(state.mark_read("peer", &[huge]).is_err());
        assert!(state.snapshot().is_read("peer", "previous"));
        drop(state);
        let reopened = ReadState::open(&dir, [8;32]).unwrap();
        assert!(reopened.snapshot().is_read("peer", "previous"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn wrong_key_fails_closed() {
        let dir = temp_dir("wrongkey");
        {
            let state = ReadState::open(&dir, [1u8; 32]).unwrap();
            state.mark_read("peer-a", &["one".into()]).unwrap();
        }
        assert!(ReadState::open(&dir, [2u8; 32]).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
