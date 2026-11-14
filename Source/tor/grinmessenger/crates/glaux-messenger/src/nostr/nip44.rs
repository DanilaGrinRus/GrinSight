// SPDX-License-Identifier: MIT OR Apache-2.0
//! NIP-44 v2 payloads: secp256k1 ECDH → HKDF → ChaCha20 → HMAC-SHA256.
//!
//! The contract lives in `docs/PROTOCOL.md` (транспорты, Nostr) and
//! `docs/ARCHITECTURE.md`. The wire format follows NIP-44 v2
//! exactly: `base64(0x02 || nonce32 || ciphertext || mac32)`.
//!
//! Security notes: this is encryption without signatures — the enclosing Nostr
//! event must be verified before decryption, and there is no forward secrecy.

use chacha20::cipher::{NewCipher, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secp256k1::{ecdh, Parity, PublicKey, SecretKey, XOnlyPublicKey};
use sha2::Sha256;

use crate::error::{Error, Result};

/// Only NIP-44 version 2 is accepted.
pub const VERSION: u8 = 2;
const SALT: &[u8] = b"nip44-v2";
/// Smallest base64 payload the spec allows (99 raw bytes).
pub const MIN_PAYLOAD_CHARS: usize = 132;
/// Our own upper bound: a Glaux envelope is far smaller than this.
pub const MAX_PAYLOAD_CHARS: usize = 256 * 1024;

fn crypto(message: impl Into<String>) -> Error {
    Error::Crypto(format!("nostr/nip44: {}", message.into()))
}

/// Unhashed 32-byte x coordinate of `secret * peer` (BIP-340 point encoding).
pub fn shared_x(secret: &SecretKey, peer: &XOnlyPublicKey) -> [u8; 32] {
    let point = PublicKey::from_x_only_public_key(*peer, Parity::Even);
    let shared = ecdh::shared_secret_point(&point, secret);
    let mut x = [0u8; 32];
    x.copy_from_slice(&shared[..32]);
    x
}

/// Long-term conversation key; symmetric in the two key roles.
pub fn conversation_key(secret: &SecretKey, peer: &XOnlyPublicKey) -> [u8; 32] {
    let x = shared_x(secret, peer);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(SALT), &x);
    let mut key = [0u8; 32];
    key.copy_from_slice(&prk);
    key
}

/// Per-message keys: `chacha_key`, `chacha_nonce`, `hmac_key`.
pub fn message_keys(
    conversation: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<([u8; 32], [u8; 12], [u8; 32])> {
    let hkdf =
        Hkdf::<Sha256>::from_prk(conversation).map_err(|_| crypto("invalid conversation key"))?;
    let mut okm = [0u8; 76];
    hkdf.expand(nonce, &mut okm)
        .map_err(|_| crypto("HKDF expand failed"))?;
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    let mut mac = [0u8; 32];
    key.copy_from_slice(&okm[0..32]);
    iv.copy_from_slice(&okm[32..44]);
    mac.copy_from_slice(&okm[44..76]);
    Ok((key, iv, mac))
}

/// Padded length of an unpadded plaintext length (NIP-44 power-of-two buckets).
pub fn padded_len(unpadded: usize) -> usize {
    if unpadded <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (unpadded - 1).leading_zeros());
    let chunk = if next_power <= 256 {
        32
    } else {
        next_power / 8
    };
    chunk * (((unpadded - 1) / chunk) + 1)
}

fn pad(plaintext: &[u8]) -> Result<Vec<u8>> {
    let len = plaintext.len();
    if len == 0 || len > u32::MAX as usize {
        return Err(crypto("invalid plaintext length"));
    }
    let (prefix, mut out) = if len < 65_536 {
        (2usize, (len as u16).to_be_bytes().to_vec())
    } else {
        let mut header = vec![0u8, 0u8];
        header.extend_from_slice(&(len as u32).to_be_bytes());
        (6usize, header)
    };
    out.reserve(prefix + padded_len(len));
    out.extend_from_slice(plaintext);
    out.resize(prefix + padded_len(len), 0);
    Ok(out)
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>> {
    if padded.len() < 34 {
        return Err(crypto("padded payload too short"));
    }
    let first = u16::from_be_bytes([padded[0], padded[1]]);
    let (len, prefix) = if first == 0 {
        if padded.len() < 38 {
            return Err(crypto("extended prefix too short"));
        }
        let len = u32::from_be_bytes([padded[2], padded[3], padded[4], padded[5]]) as usize;
        if len < 65_536 {
            return Err(crypto("invalid extended prefix"));
        }
        (len, 6usize)
    } else {
        (first as usize, 2usize)
    };
    if len == 0 || padded.len() != prefix + padded_len(len) {
        return Err(crypto("invalid padding"));
    }
    let body = &padded[prefix..prefix + len];
    if padded[prefix + len..].iter().any(|b| *b != 0) {
        return Err(crypto("non-zero padding"));
    }
    Ok(body.to_vec())
}

fn mac(key: &[u8], nonce: &[u8; 32], ciphertext: &[u8]) -> [u8; 32] {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    hmac.update(nonce);
    hmac.update(ciphertext);
    let out = hmac.finalize().into_bytes();
    let mut mac = [0u8; 32];
    mac.copy_from_slice(&out);
    mac
}

/// Encrypt `plaintext` with the conversation key and a caller-supplied nonce.
pub fn encrypt(plaintext: &[u8], conversation: &[u8; 32], nonce: &[u8; 32]) -> Result<String> {
    let (key, iv, hmac_key) = message_keys(conversation, nonce)?;
    let padded = pad(plaintext)?;
    let mut ciphertext = padded;
    let mut cipher =
        ChaCha20::new_from_slices(&key, &iv).map_err(|_| crypto("invalid chacha key/iv"))?;
    cipher.apply_keystream(&mut ciphertext);
    let tag = mac(&hmac_key, nonce, &ciphertext);
    let mut payload = Vec::with_capacity(1 + 32 + ciphertext.len() + 32);
    payload.push(VERSION);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&tag);
    Ok(base64_encode(&payload))
}

/// Decrypt a NIP-44 v2 payload; rejects unknown versions and a bad MAC.
pub fn decrypt(payload: &str, conversation: &[u8; 32]) -> Result<Vec<u8>> {
    if payload.starts_with('#') {
        return Err(crypto("unsupported payload encoding"));
    }
    if payload.len() < MIN_PAYLOAD_CHARS || payload.len() > MAX_PAYLOAD_CHARS {
        return Err(crypto("invalid payload size"));
    }
    let raw = base64_decode(payload).map_err(|_| crypto("invalid base64"))?;
    if raw.len() < 99 {
        return Err(crypto("invalid payload length"));
    }
    if raw[0] != VERSION {
        return Err(crypto(format!("unsupported version {}", raw[0])));
    }
    let nonce: [u8; 32] = raw[1..33].try_into().expect("32 bytes");
    let ciphertext = &raw[33..raw.len() - 32];
    let tag = &raw[raw.len() - 32..];
    let (key, iv, hmac_key) = message_keys(conversation, &nonce)?;
    let mut verifier = Hmac::<Sha256>::new_from_slice(&hmac_key).expect("HMAC key");
    verifier.update(&nonce);
    verifier.update(ciphertext);
    verifier
        .verify_slice(tag)
        .map_err(|_| crypto("MAC mismatch"))?;
    let mut padded = ciphertext.to_vec();
    let mut cipher =
        ChaCha20::new_from_slices(&key, &iv).map_err(|_| crypto("invalid chacha key/iv"))?;
    cipher.apply_keystream(&mut padded);
    unpad(&padded)
}

fn base64_encode(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

fn base64_decode(value: &str) -> std::result::Result<Vec<u8>, ()> {
    base64::decode(value).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(hex: &str) -> SecretKey {
        use std::str::FromStr;
        SecretKey::from_str(hex).expect("test secret")
    }

    fn xonly(secret: &SecretKey) -> XOnlyPublicKey {
        PublicKey::from_secret_key(secret).x_only_public_key().0
    }

    #[test]
    fn padding_buckets() {
        assert_eq!(padded_len(1), 32);
        assert_eq!(padded_len(32), 32);
        assert_eq!(padded_len(33), 64);
        assert_eq!(padded_len(65_535), 65_536);
        assert_eq!(padded_len(65_536), 65_536);
        assert_eq!(padded_len(65_537), 81_920);
    }

    #[test]
    fn official_vector_a() {
        // NIP-44 v2 test vector published in the NIP.
        let sec1 = secret("0000000000000000000000000000000000000000000000000000000000000001");
        let sec2 = secret("0000000000000000000000000000000000000000000000000000000000000002");
        let conv = conversation_key(&sec1, &xonly(&sec2));
        assert_eq!(
            to_hex(&conv),
            "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
        );
        // Swapping the roles must produce the same conversation key.
        assert_eq!(conv, conversation_key(&sec2, &xonly(&sec1)));

        let nonce = [0u8; 32];
        let mut nonce = nonce;
        nonce[31] = 1;
        let payload = encrypt(b"a", &conv, &nonce).expect("encrypt");
        assert_eq!(
            payload,
            "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
        );
        assert_eq!(decrypt(&payload, &conv).expect("decrypt"), b"a");
    }

    #[test]
    fn roundtrip_and_rejections() {
        let a = secret("0000000000000000000000000000000000000000000000000000000000000001");
        let b = secret("0000000000000000000000000000000000000000000000000000000000000002");
        let conv = conversation_key(&a, &xonly(&b));
        let nonce = [7u8; 32];
        let long = vec![b'x'; 1000];
        let payload = encrypt(&long, &conv, &nonce).expect("encrypt");
        assert_eq!(decrypt(&payload, &conv).expect("decrypt"), long);

        // A different conversation key must fail the MAC check.
        let other = conversation_key(&a, &xonly(&a));
        assert!(decrypt(&payload, &other).is_err());
        // Unknown version byte is rejected.
        let mut raw = base64::decode(&payload).expect("base64");
        raw[0] = 3;
        assert!(decrypt(&base64::encode(raw), &conv).is_err());
        // Truncated payloads are rejected before allocation-heavy work.
        assert!(decrypt(&payload[..40], &conv).is_err());
        // Empty plaintext is invalid.
        assert!(encrypt(b"", &conv, &nonce).is_err());
    }

    #[test]
    fn extended_prefix_roundtrip() {
        let a = secret("0000000000000000000000000000000000000000000000000000000000000001");
        let b = secret("0000000000000000000000000000000000000000000000000000000000000002");
        let conv = conversation_key(&a, &xonly(&b));
        let nonce = [9u8; 32];
        let msg = vec![b'a'; 65_537];
        let payload = encrypt(&msg, &conv, &nonce).expect("encrypt");
        assert_eq!(decrypt(&payload, &conv).expect("decrypt"), msg);
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push_str(&format!("{:02x}", b));
        }
        out
    }
}
