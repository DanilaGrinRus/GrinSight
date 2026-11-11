// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transport key for the Nostr transport: a dedicated secp256k1 key per profile.
//!
//! It is not derived from the wallet seed and cannot move funds. Losing it lets
//! someone decrypt messages addressed to this key, so the file is written with
//! owner-only permissions where the platform supports it; the runtime applies
//! the Windows ACL for the containing directory.

use std::fs;
use std::path::Path;
use std::str::FromStr;

use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};

use super::{hex_encode, random_bytes};
use crate::error::{Error, Result};

fn crypto(message: impl Into<String>) -> Error {
    Error::Crypto(format!("nostr/keys: {}", message.into()))
}

/// A transport key. `Debug` intentionally hides the secret.
#[derive(Clone)]
pub struct NostrKeys {
    secret: SecretKey,
}

impl std::fmt::Debug for NostrKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NostrKeys")
            .field("public", &self.public_hex())
            .finish_non_exhaustive()
    }
}

impl NostrKeys {
    /// Generate a fresh transport key from the OS RNG.
    pub fn generate() -> Result<Self> {
        for _ in 0..8 {
            let bytes = random_bytes::<32>()?;
            if let Ok(secret) = SecretKey::from_str(&hex_encode(&bytes)) {
                return Ok(Self { secret });
            }
        }
        Err(crypto("could not generate a transport key"))
    }

    /// Import a hex-encoded transport key (tests, migration, recovery).
    pub fn from_hex(value: &str) -> Result<Self> {
        let secret = SecretKey::from_str(value.trim())
            .map_err(|_| crypto("invalid secp256k1 transport key"))?;
        Ok(Self { secret })
    }

    /// x-only public key (the Nostr identity of this wallet profile).
    pub fn public(&self) -> XOnlyPublicKey {
        PublicKey::from_secret_key(&self.secret)
            .x_only_public_key()
            .0
    }

    /// Hex form of the public key used in tags and directory entries.
    pub fn public_hex(&self) -> String {
        hex_encode(&self.public().to_byte_array())
    }

    pub(crate) fn secret(&self) -> &SecretKey {
        &self.secret
    }

    /// Load a key file, or create one when it does not exist yet.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            return Self::load(path);
        }
        let keys = Self::generate()?;
        keys.save(path)?;
        Ok(keys)
    }

    /// Read a key file written by [`NostrKeys::save`].
    pub fn load(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .map_err(|error| Error::Store(format!("nostr: transport key: {error}")))?;
        let line = raw
            .lines()
            .map(str::trim)
            .find(|line| !line.is_empty() && !line.starts_with('#'))
            .ok_or_else(|| crypto("empty transport key file"))?;
        Self::from_hex(line)
    }

    /// Atomically write the key file (temp file, permissions, rename).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| Error::Store(format!("nostr: transport key dir: {error}")))?;
        }
        let tmp = path.with_extension("key.tmp");
        let secret_bytes = self.secret.to_secret_bytes();
        fs::write(&tmp, format!("{}\n", hex_encode(&secret_bytes)))
            .map_err(|error| Error::Store(format!("nostr: transport key write: {error}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
        }
        fs::rename(&tmp, path).map_err(|error| {
            let _ = fs::remove_file(&tmp);
            Error::Store(format!("nostr: transport key rename: {error}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_public_and_roundtrip() {
        let keys = NostrKeys::generate().expect("generate");
        let hex = keys.public_hex();
        assert_eq!(hex.len(), 64);

        let dir = std::env::temp_dir().join(format!("flint-nostr-keys-{}", std::process::id()));
        let path = dir.join("transport.key");
        keys.save(&path).expect("save");
        let loaded = NostrKeys::load(&path).expect("load");
        assert_eq!(loaded.public_hex(), hex);
        // The file stores one hex line and no debug output.
        let raw = fs::read_to_string(&path).expect("read");
        assert_eq!(raw.trim().len(), 64);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_hex_is_rejected() {
        assert!(NostrKeys::from_hex("zz").is_err());
        assert!(NostrKeys::from_hex("").is_err());
    }
}
