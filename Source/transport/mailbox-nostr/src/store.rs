//! Replies kept until a relay has taken them.
//!
//! A reply to an incoming payment is sealed once and must be resent exactly
//! as it was, across restarts. The payment core cannot keep it (receiving
//! without state writes nothing to its journal), so it lives here: one small
//! file per incoming message, encrypted with a key the host supplies, under
//! a name that reveals nothing about the message it answers.
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Replies kept at once; more are refused, never replaced.
pub const MAX_REPLIES: usize = 512;
/// Largest stored reply: two keys, a deadline and one envelope.
pub const MAX_REPLY_LEN: usize = 72 + fly_nostr_research::nostr::contact_session::MAX_ENVELOPE_JSON;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const SUFFIX: &str = ".reply";
// v2: the delivery deadline is stored with the envelope, which no longer shows it
const AAD: &[u8] = b"fly stored reply v2";

/// Why a reply could not be stored.
#[derive(Debug)]
pub enum StoreError {
    /// The limit of stored replies is reached.
    Full,
    /// The file system refused.
    Io(io::ErrorKind),
}

/// A stored reply: who it is for and the sealed envelope as JSON text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredReply {
    /// Contact the reply goes to.
    pub contact: [u8; 32],
    /// Unix second after which the reply is not published any more.
    pub deadline: u64,
    /// The sealed envelope, exactly as it must be published.
    pub envelope: String,
}

/// Encrypted, create-only storage of replies in one directory.
pub struct ReplyStore {
    dir: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "stored reply cannot be read")
}

impl ReplyStore {
    /// Use `dir` (created if missing) with a storage key that must be the
    /// same on every start; it should come from the wallet's secrets.
    pub fn open(dir: &Path, key: [u8; 32]) -> io::Result<ReplyStore> {
        fs::create_dir_all(dir)?;
        Ok(ReplyStore {
            dir: dir.to_path_buf(),
            key: Zeroizing::new(key),
        })
    }

    fn path(&self, incoming: &[u8; 32]) -> PathBuf {
        let mut h = Sha256::new();
        h.update(b"fly reply file name v1");
        h.update(self.key.as_ref());
        h.update(incoming);
        let digest = h.finalize();
        let mut name = String::new();
        for b in digest.iter().take(16) {
            name.push_str(&format!("{b:02x}"));
        }
        name.push_str(SUFFIX);
        self.dir.join(name)
    }

    fn open_file(&self, path: &Path) -> io::Result<([u8; 32], StoredReply)> {
        let file = File::open(path)?;
        let limit = NONCE_LEN.saturating_add(MAX_REPLY_LEN).saturating_add(TAG_LEN).saturating_add(1);
        let mut buf = Vec::new();
        file.take(u64::try_from(limit).map_err(|_| invalid())?).read_to_end(&mut buf)?;
        let (nonce, sealed) = buf.split_first_chunk::<NONCE_LEN>().ok_or_else(invalid)?;
        let cipher = XChaCha20Poly1305::new(self.key.as_ref().into());
        let plain = Zeroizing::new(
            cipher
                .decrypt(XNonce::from_slice(nonce), Payload { msg: sealed, aad: AAD })
                .map_err(|_| invalid())?,
        );
        let (incoming, rest) = plain.split_first_chunk::<32>().ok_or_else(invalid)?;
        let (contact, rest) = rest.split_first_chunk::<32>().ok_or_else(invalid)?;
        let (deadline, envelope) = rest.split_first_chunk::<8>().ok_or_else(invalid)?;
        let envelope = std::str::from_utf8(envelope).map_err(|_| invalid())?.to_string();
        Ok((*incoming, StoredReply { contact: *contact, deadline: u64::from_le_bytes(*deadline), envelope }))
    }

    fn count(&self) -> io::Result<usize> {
        let mut n = 0usize;
        for entry in fs::read_dir(&self.dir)? {
            if entry?.file_name().to_string_lossy().ends_with(SUFFIX) {
                n = n.saturating_add(1);
            }
        }
        Ok(n)
    }

    /// The reply stored for an incoming message, if any. A file that cannot
    /// be opened with this key is an error, not "nothing stored".
    pub fn get(&self, incoming: &[u8; 32]) -> io::Result<Option<StoredReply>> {
        let path = self.path(incoming);
        match self.open_file(&path) {
            Ok((stored_for, reply)) if stored_for == *incoming => Ok(Some(reply)),
            Ok(_) => Err(invalid()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Store the reply to an incoming message. An existing reply is never
    /// replaced: the call fails with `AlreadyExists`.
    pub fn put(&self, incoming: &[u8; 32], reply: &StoredReply) -> Result<(), StoreError> {
        let io_err = |e: io::Error| StoreError::Io(e.kind());
        if reply.envelope.len().saturating_add(72) > MAX_REPLY_LEN || reply.envelope.is_empty() {
            return Err(StoreError::Io(io::ErrorKind::InvalidInput));
        }
        let path = self.path(incoming);
        if path.exists() {
            return Err(StoreError::Io(io::ErrorKind::AlreadyExists));
        }
        if self.count().map_err(io_err)? >= MAX_REPLIES {
            return Err(StoreError::Full);
        }
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce).map_err(|_| StoreError::Io(io::ErrorKind::Other))?;
        let mut plain = Zeroizing::new(incoming.to_vec());
        plain.extend_from_slice(&reply.contact);
        plain.extend_from_slice(&reply.deadline.to_le_bytes());
        plain.extend_from_slice(reply.envelope.as_bytes());
        let cipher = XChaCha20Poly1305::new(self.key.as_ref().into());
        let sealed = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plain.as_slice(), aad: AAD })
            .map_err(|_| StoreError::Io(io::ErrorKind::Other))?;
        let tmp = path.with_extension("tmp");
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .map_err(io_err)?;
        f.write_all(&nonce).map_err(io_err)?;
        f.write_all(&sealed).map_err(io_err)?;
        f.sync_all().map_err(io_err)?;
        drop(f);
        fs::rename(&tmp, &path).map_err(io_err)?;
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }

    /// Remove replies that `expired` says are past use. A reply must stay
    /// as long as the message it answers can still arrive, so that it is
    /// resent rather than built again; after that it is only clutter. Files
    /// this key cannot open are left alone. Returns how many were removed.
    pub fn purge(&self, mut expired: impl FnMut(&StoredReply) -> bool) -> io::Result<usize> {
        let mut removed = 0usize;
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if !path.to_string_lossy().ends_with(SUFFIX) {
                continue;
            }
            if let Ok((_, reply)) = self.open_file(&path) {
                if expired(&reply) && fs::remove_file(&path).is_ok() {
                    removed = removed.saturating_add(1);
                }
            }
        }
        Ok(removed)
    }
}
