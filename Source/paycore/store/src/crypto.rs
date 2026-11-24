//! Key derivation, frame encryption and hashing.
use crate::format::Identity;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Length of the XChaCha20-Poly1305 nonce.
pub(crate) const NONCE_LEN: usize = 24;
/// Length of the Poly1305 tag.
pub(crate) const TAG_LEN: usize = 16;

/// Secret the journal keys are derived from. The caller derives it from the
/// wallet keychain. It is wiped when dropped and cannot be printed or cloned.
pub struct RootKey(Zeroizing<[u8; 32]>);

impl RootKey {
    /// Wrap 32 secret bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        RootKey(Zeroizing::new(bytes))
    }
}

pub(crate) struct Keys {
    frame: Zeroizing<[u8; 32]>,
    snapshot: Zeroizing<[u8; 32]>,
    mac: Zeroizing<[u8; 32]>,
}

pub(crate) struct CryptoError;

fn expand(root: &RootKey, label: &[u8], id: &Identity) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(b"fly-paycore/v1"), root.0.as_ref());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand_multi_info(
        &[label, &[id.network], &id.genesis, &id.instance],
        out.as_mut(),
    )
    .map_err(|_| CryptoError)?;
    Ok(out)
}

impl Keys {
    pub(crate) fn derive(root: &RootKey, id: &Identity) -> Result<Keys, CryptoError> {
        Ok(Keys {
            frame: expand(root, b"frame", id)?,
            snapshot: expand(root, b"snapshot", id)?,
            mac: expand(root, b"header-mac", id)?,
        })
    }

    pub(crate) fn header_mac(&self, data: &[u8]) -> Result<[u8; 32], CryptoError> {
        let mut m =
            <Hmac<Sha256> as Mac>::new_from_slice(self.mac.as_ref()).map_err(|_| CryptoError)?;
        m.update(data);
        Ok(m.finalize().into_bytes().into())
    }

    pub(crate) fn seal_frame(
        &self,
        aad: &[u8],
        body: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
        seal(&self.frame, aad, body)
    }

    pub(crate) fn open_frame(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        open(&self.frame, nonce, aad, ct)
    }

    pub(crate) fn seal_snapshot(
        &self,
        aad: &[u8],
        body: &[u8],
    ) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
        seal(&self.snapshot, aad, body)
    }

    pub(crate) fn open_snapshot(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        open(&self.snapshot, nonce, aad, ct)
    }
}

fn seal(
    key: &Zeroizing<[u8; 32]>,
    aad: &[u8],
    body: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let mut nonce = [0u8; NONCE_LEN];
    // Operating system generator only; a failure is an error, never a fallback.
    getrandom::getrandom(&mut nonce).map_err(|_| CryptoError)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: body, aad })
        .map_err(|_| CryptoError)?;
    Ok((nonce, ct))
}

fn open(
    key: &Zeroizing<[u8; 32]>,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| CryptoError)
}

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Constant-time equality for hashes and MACs.
pub(crate) fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.ct_eq(b).into()
}
