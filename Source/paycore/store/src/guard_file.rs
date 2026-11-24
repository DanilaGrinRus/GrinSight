//! Tail guard kept in a file outside the wallet directory.
//!
//! The value is authenticated with a key the caller supplies. On its own this
//! detects a rollback or replacement of the wallet directory (restored
//! backup, synced folder, copied profile part) as long as the guard file is
//! not rolled back together with it. Binding the key to the device is the
//! platform layer's job: on Windows the key is unwrapped with DPAPI, on
//! Android it lives in the Keystore. A whole-disk rollback or a clone of the
//! whole device is outside what any file can detect (specification, 18).
use crate::crypto::ct_eq;
use crate::io::{Guard, GuardValue};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"FLYGRD01";
const BODY_LEN: usize = 48;
const FILE_LEN: usize = 80;

/// A tail guard stored in one small authenticated file.
pub struct FileGuard {
    path: PathBuf,
    tmp: PathBuf,
    key: Zeroizing<[u8; 32]>,
}

fn invalid(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

impl FileGuard {
    /// `path` must lie outside the wallet directory and its parent directory
    /// must exist. `key` authenticates the value; it must not be stored in
    /// the wallet directory either.
    pub fn new(path: &Path, key: [u8; 32]) -> io::Result<FileGuard> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "guard path"))?;
        let mut tmp_name = name.to_os_string();
        tmp_name.push(".tmp");
        Ok(FileGuard {
            path: path.to_path_buf(),
            tmp: path.with_file_name(tmp_name),
            key: Zeroizing::new(key),
        })
    }

    fn mac(&self, body: &[u8]) -> io::Result<[u8; 32]> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(self.key.as_ref())
            .map_err(|_| invalid("guard key"))?;
        m.update(body);
        Ok(m.finalize().into_bytes().into())
    }
}

impl Guard for FileGuard {
    fn load(&self) -> io::Result<Option<GuardValue>> {
        let file = match File::open(&self.path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        // one byte more than expected, to notice a longer file
        let mut buf = Vec::with_capacity(FILE_LEN.saturating_add(1));
        file.take(u64::try_from(FILE_LEN.saturating_add(1)).map_err(|_| invalid("guard"))?)
            .read_to_end(&mut buf)?;
        // a damaged guard is an error, never "no guard": absence is trusted
        // only when the file does not exist
        if buf.len() != FILE_LEN {
            return Err(invalid("guard file length"));
        }
        let (body, mac) = buf.split_at(BODY_LEN);
        let mac: [u8; 32] = mac.try_into().map_err(|_| invalid("guard"))?;
        if !ct_eq(&self.mac(body)?, &mac) {
            return Err(invalid("guard file does not authenticate"));
        }
        let (magic, rest) = body.split_at(MAGIC.len());
        if magic != MAGIC {
            return Err(invalid("guard file version"));
        }
        let (seq, tail) = rest.split_at(8);
        Ok(Some(GuardValue {
            next_seq: u64::from_le_bytes(seq.try_into().map_err(|_| invalid("guard"))?),
            tail: tail.try_into().map_err(|_| invalid("guard"))?,
        }))
    }

    fn store(&self, value: &GuardValue) -> io::Result<()> {
        let mut body = Vec::with_capacity(FILE_LEN);
        body.extend_from_slice(MAGIC);
        body.extend_from_slice(&value.next_seq.to_le_bytes());
        body.extend_from_slice(&value.tail);
        let mac = self.mac(&body)?;
        body.extend_from_slice(&mac);

        let mut o = OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&self.tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
        drop(f);
        // the old value stays readable until the new one is complete
        fs::rename(&self.tmp, &self.path)?;
        #[cfg(unix)]
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }
}
