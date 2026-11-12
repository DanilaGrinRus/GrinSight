// SPDX-License-Identifier: MIT OR Apache-2.0
//! Encrypted local read markers.
//!
//! Wallet UI processes need unread counters that survive restarts. Read markers
//! are a map `peer address -> last-read unix timestamp`, encrypted at rest with
//! the same storage key as history/contacts (they leak who the wallet talks to).

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

const AAD: &[u8] = b"glaux-messenger-wallet-read-state-v1";
const FILE: &str = "read_state.enc";
const NONCE_LEN: usize = 12;

pub struct ReadState {
    path: PathBuf,
    cipher: ChaCha20Poly1305,
    markers: Mutex<BTreeMap<String, u64>>,
}

impl ReadState {
    pub fn open(root: impl Into<PathBuf>, key: [u8; 32]) -> Result<Self, String> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(|e| format!("read_state: {e}"))?;
        let path = root.join(FILE);
        let markers = match fs::read(&path) {
            Ok(raw) => decode(&raw, &key)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(format!("read_state {}: {e}", path.display())),
        };
        Ok(Self {
            path,
            cipher: ChaCha20Poly1305::new(Key::from_slice(&key)),
            markers: Mutex::new(markers),
        })
    }

    /// Last read timestamp for `peer`, if the wallet has ever marked it read.
    pub fn read_at(&self, peer: &str) -> Option<u64> {
        self.lock().get(peer).copied()
    }

    /// All read markers (peer -> timestamp).
    pub fn snapshot(&self) -> BTreeMap<String, u64> {
        self.lock().clone()
    }

    /// Persist a read marker. `timestamp` is the newest message creation time
    /// the wallet has seen for this peer.
    pub fn mark_read(&self, peer: &str, timestamp: u64) -> Result<(), String> {
        let mut markers = self.lock();
        let previous = markers.get(peer).copied().unwrap_or(0);
        markers.insert(peer.to_string(), previous.max(timestamp));
        self.persist(&markers)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, u64>> {
        self.markers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn persist(&self, markers: &BTreeMap<String, u64>) -> Result<(), String> {
        let mut bytes = Vec::new();
        bytes.push(1u8); // file format version
        bytes.extend_from_slice(&serde_json::to_vec(markers).map_err(|e| format!("json: {e}"))?);
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

fn decode(raw: &[u8], key: &[u8; 32]) -> Result<BTreeMap<String, u64>, String> {
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
    if plaintext.first() != Some(&1) {
        return Err("read_state: unsupported file version".into());
    }
    serde_json::from_slice(&plaintext[1..]).map_err(|e| format!("read_state JSON: {e}"))
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
    fn markers_roundtrip_and_do_not_go_backwards() {
        let dir = temp_dir("roundtrip");
        let key = [5u8; 32];
        {
            let state = ReadState::open(&dir, key).unwrap();
            state.mark_read("peer-a", 100).unwrap();
            state.mark_read("peer-a", 50).unwrap();
            assert_eq!(state.read_at("peer-a"), Some(100));
        }
        let reopened = ReadState::open(&dir, key).unwrap();
        assert_eq!(reopened.read_at("peer-a"), Some(100));
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn wrong_key_fails_closed() {
        let dir = temp_dir("wrongkey");
        {
            let state = ReadState::open(&dir, [1u8; 32]).unwrap();
            state.mark_read("peer-a", 1).unwrap();
        }
        assert!(ReadState::open(&dir, [2u8; 32]).is_err());
        std::fs::remove_dir_all(dir).ok();
    }
}
