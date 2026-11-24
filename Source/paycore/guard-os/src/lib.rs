//! Tail guard whose key is held by the operating system.
//!
//! [`fly_paycore_store::FileGuard`] authenticates the guard value with a key
//! the caller supplies. This crate supplies that key: 32 random bytes that
//! exist on disk only wrapped by the platform ([`Protector`]). On Windows the
//! wrapping is DPAPI ([`Dpapi`]), so the key can be unwrapped only by the
//! same user on the same machine. A wallet directory that is copied or
//! restored elsewhere arrives without a usable key; the guard then reports
//! "no value" and the store starts a new branch and locks what was open.
//!
//! Two small files live in a directory outside the wallet directory:
//!
//! * `guard.key` - the wrapped key;
//! * `guard-<id>.dat` - the authenticated value, `<id>` derived from the key,
//!   so a value written under an older key is never mistaken for a damaged
//!   one.
//!
//! All logic is plain safe Rust and is tested with a stand-in protector. The
//! only `unsafe` is the call into DPAPI in the Windows-only module.
#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

use fly_paycore_store::{FileGuard, Guard, GuardValue};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

#[cfg(windows)]
mod dpapi;
#[cfg(windows)]
pub use dpapi::Dpapi;

const KEY_FILE: &str = "guard.key";
const KEY_TMP: &str = "guard.key.tmp";
const MAGIC: &[u8; 8] = b"FLYGKW01";
/// A wrapped 32-byte key is a few hundred bytes; anything larger is not ours.
const MAX_BLOB_LEN: usize = 4096;
const KEY_LEN: usize = 32;

/// Wraps and unwraps a small secret with a key the operating system holds.
pub trait Protector {
    /// Wrap `plain`. The result may be stored on disk.
    fn protect(&self, plain: &[u8]) -> io::Result<Vec<u8>>;
    /// Unwrap what [`Protector::protect`] returned. Fails if the blob was
    /// made by another user or machine, or was altered.
    fn unprotect(&self, blob: &[u8]) -> io::Result<Zeroizing<Vec<u8>>>;
}

/// Why the guard could not be opened with the key on disk.
#[derive(Debug)]
pub enum OpenError {
    /// The key file exists but this user on this machine cannot unwrap it:
    /// the profile was copied from elsewhere, or the file was altered. The
    /// host decides whether to call [`OsGuard::reset`].
    Foreign,
    /// The key file is not in the expected format.
    Damaged,
    /// The file system or the platform reported an error.
    Io(io::Error),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Foreign => f.write_str("guard key belongs to another user or machine"),
            OpenError::Damaged => f.write_str("guard key file is damaged"),
            OpenError::Io(e) => write!(f, "guard storage: {}", e.kind()),
        }
    }
}
impl std::error::Error for OpenError {}
impl From<io::Error> for OpenError {
    fn from(e: io::Error) -> Self {
        OpenError::Io(e)
    }
}

/// How the key of an opened guard came to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The key on disk was unwrapped.
    Existing,
    /// There was no key; a new one was made. For a wallet that already has a
    /// journal this means the guard value is gone.
    Created,
    /// The old key was unusable and was replaced on request.
    Reset,
}

/// A tail guard keyed by the operating system.
pub struct OsGuard {
    inner: FileGuard,
}

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

fn value_path(dir: &Path, key: &[u8; KEY_LEN]) -> PathBuf {
    let mut h = Sha256::new();
    h.update(b"fly guard value file v1");
    h.update(key);
    let digest = h.finalize();
    let mut name = String::from("guard-");
    for b in digest.iter().take(8) {
        name.push_str(&format!("{b:02x}"));
    }
    name.push_str(".dat");
    dir.join(name)
}

fn read_key_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let limit = MAGIC
        .len()
        .saturating_add(4)
        .saturating_add(MAX_BLOB_LEN)
        .saturating_add(1);
    let mut buf = Vec::new();
    file.take(u64::try_from(limit).map_err(|_| invalid("limit"))?)
        .read_to_end(&mut buf)?;
    Ok(Some(buf))
}

/// The wrapped blob inside a key file, or `None` if the format is wrong.
fn parse_key_file(buf: &[u8]) -> Option<&[u8]> {
    let rest = buf.strip_prefix(MAGIC.as_slice())?;
    let (len, blob) = rest.split_first_chunk::<4>()?;
    let len = usize::try_from(u32::from_le_bytes(*len)).ok()?;
    if len == 0 || len > MAX_BLOB_LEN || blob.len() != len {
        return None;
    }
    Some(blob)
}

fn write_key_file(dir: &Path, blob: &[u8]) -> io::Result<()> {
    if blob.is_empty() || blob.len() > MAX_BLOB_LEN {
        return Err(invalid("wrapped key size"));
    }
    let len = u32::try_from(blob.len()).map_err(|_| invalid("wrapped key size"))?;
    let tmp = dir.join(KEY_TMP);
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    f.write_all(MAGIC)?;
    f.write_all(&len.to_le_bytes())?;
    f.write_all(blob)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, dir.join(KEY_FILE))?;
    // make the rename itself durable where the platform lets a directory be
    // opened; where it does not, the next start simply finds no key
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

impl OsGuard {
    /// Open the guard kept in `dir`, which must exist and lie outside the
    /// wallet directory. A missing key is created; a key that cannot be
    /// unwrapped is reported and left untouched.
    pub fn open<P: Protector>(dir: &Path, protector: &P) -> Result<(OsGuard, Origin), OpenError> {
        let Some(buf) = read_key_file(&dir.join(KEY_FILE))? else {
            return Ok((Self::create(dir, protector)?, Origin::Created));
        };
        let blob = parse_key_file(&buf).ok_or(OpenError::Damaged)?;
        let plain = protector
            .unprotect(blob)
            .map_err(|_| OpenError::Foreign)?;
        let key: Zeroizing<[u8; KEY_LEN]> = Zeroizing::new(
            <[u8; KEY_LEN]>::try_from(plain.as_slice()).map_err(|_| OpenError::Foreign)?,
        );
        Ok((Self::with_key(dir, &key)?, Origin::Existing))
    }

    /// Replace an unusable key with a new one. The previous guard value can
    /// no longer be read; the store will treat the wallet as possibly rolled
    /// back, which is the right reading of a profile that came from elsewhere.
    pub fn reset<P: Protector>(dir: &Path, protector: &P) -> Result<(OsGuard, Origin), OpenError> {
        Ok((Self::create(dir, protector)?, Origin::Reset))
    }

    fn create<P: Protector>(dir: &Path, protector: &P) -> Result<OsGuard, OpenError> {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        getrandom::getrandom(key.as_mut())
            .map_err(|_| io::Error::other("no randomness"))?;
        let blob = protector.protect(key.as_ref())?;
        // the wrapped key must open again before anything relies on it
        let back = protector.unprotect(&blob)?;
        if back.as_slice() != key.as_slice() {
            return Err(OpenError::Io(invalid("wrapped key does not round-trip")));
        }
        write_key_file(dir, &blob)?;
        Ok(Self::with_key(dir, &key)?)
    }

    fn with_key(dir: &Path, key: &[u8; KEY_LEN]) -> io::Result<OsGuard> {
        Ok(OsGuard {
            inner: FileGuard::new(&value_path(dir, key), *key)?,
        })
    }
}

impl Guard for OsGuard {
    fn load(&self) -> io::Result<Option<GuardValue>> {
        self.inner.load()
    }
    fn store(&self, value: &GuardValue) -> io::Result<()> {
        self.inner.store(value)
    }
}
