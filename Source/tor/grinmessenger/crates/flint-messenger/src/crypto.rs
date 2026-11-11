// SPDX-License-Identifier: MIT OR Apache-2.0
//! ECIES from the slatepack ed25519 key to an X25519/ChaCha20-Poly1305 box.
//!
//! The recipient's ed25519 public key is converted to its Montgomery form; the
//! sender uses an ephemeral X25519 key. The shared secret is fed through HKDF-
//! SHA256 (salt = recipient X25519 key), and the payload key encrypts with
//! ChaCha20-Poly1305. The envelope header is the AEAD associated data.

use chacha20poly1305::aead::{Aead, NewAead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::edwards::CompressedEdwardsY;
use hkdf::Hkdf;
use sha2::{Digest, Sha256, Sha512};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::address::Address;
use crate::error::{Error, Result};

const KDF_INFO: &[u8] = b"flint-messenger/v1/encryption";

pub(crate) struct Sealed {
    pub ephemeral_key: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// ed25519 seed -> X25519 scalar: standard clamped `SHA512(seed)[..32]`.
fn x25519_secret_from_seed(seed: &[u8; 32]) -> [u8; 32] {
    let digest = Sha512::digest(seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&digest[..32]);
    scalar
}

/// ed25519 public key -> X25519 public key (Edwards y -> Montgomery u).
fn x25519_public_from_ed(key: &[u8; 32]) -> Result<[u8; 32]> {
    let point = CompressedEdwardsY(*key)
        .decompress()
        .ok_or_else(|| Error::Crypto("адрес: ключ не на кривой ed25519".into()))?;
    Ok(point.to_montgomery().to_bytes())
}

fn recipient_key(recipient: &Address) -> Result<[u8; 32]> {
    x25519_public_from_ed(&recipient.key())
}

fn derive_key(shared: &[u8; 32], salt: &[u8; 32]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), shared);
    let mut okm = [0u8; 32];
    hk.expand(KDF_INFO, &mut okm)
        .map_err(|_| Error::Crypto("HKDF не смог вывести ключ".into()))?;
    Ok(okm)
}

fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|e| Error::Crypto(format!("RNG: {e}")))?;
    Ok(out)
}

pub(crate) fn seal(recipient: &Address, plaintext: &[u8], aad: &[u8]) -> Result<Sealed> {
    let recipient_x = recipient_key(recipient)?;
    let ephemeral_secret = StaticSecret::from(random_bytes::<32>()?);
    let ephemeral_key = PublicKey::from(&ephemeral_secret).to_bytes();
    let shared = ephemeral_secret.diffie_hellman(&PublicKey::from(recipient_x));
    let key = derive_key(shared.as_bytes(), &recipient_x)?;
    let nonce = random_bytes::<12>()?;

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("ChaCha20-Poly1305: шифрование не удалось".into()))?;
    Ok(Sealed {
        ephemeral_key,
        nonce,
        ciphertext,
    })
}

pub(crate) fn open(
    seed: &[u8; 32],
    ephemeral_key: [u8; 32],
    nonce: [u8; 12],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let secret = StaticSecret::from(x25519_secret_from_seed(seed));
    let recipient_x = PublicKey::from(&secret).to_bytes();
    let shared = secret.diffie_hellman(&PublicKey::from(ephemeral_key));
    let key = derive_key(shared.as_bytes(), &recipient_x)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Crypto("ChaCha20-Poly1305: не удалось расшифровать".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(seed: [u8; 32]) -> Address {
        let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
        Address::from_key("tgrin", signing.verifying_key().to_bytes()).unwrap()
    }

    #[test]
    fn box_roundtrips_and_is_bound_to_aad() {
        let seed = [7u8; 32];
        let recipient = address(seed);
        let sealed = seal(&recipient, b"hello", b"header").expect("seal");
        let opened = open(
            &seed,
            sealed.ephemeral_key,
            sealed.nonce,
            &sealed.ciphertext,
            b"header",
        )
        .expect("open");
        assert_eq!(opened, b"hello");

        let bad = open(
            &seed,
            sealed.ephemeral_key,
            sealed.nonce,
            &sealed.ciphertext,
            b"other",
        );
        assert!(bad.is_err());
    }

    #[test]
    fn other_key_cannot_open() {
        let recipient = address([7u8; 32]);
        let sealed = seal(&recipient, b"hello", b"").expect("seal");
        assert!(open(
            &[8u8; 32],
            sealed.ephemeral_key,
            sealed.nonce,
            &sealed.ciphertext,
            b""
        )
        .is_err());
    }
}
