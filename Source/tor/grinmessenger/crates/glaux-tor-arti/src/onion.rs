// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Adapter for the slatepack-address ↔ Tor v3 onion helpers from Glaux's
// `crates/core/src/address.rs` and grin-wallet's `OnionV3Address`
// (Apache-2.0, https://github.com/mimblewimble/grin-wallet).

//! Tor v3 onion address derivation.
//!
//! The messenger identity is an ed25519 key encoded as a bech32 slatepack
//! address (`grin1…` / `tgrin1…`). The same public key is the Tor v3 onion
//! identity, so knowing an address is enough to compute the peer's `.onion`
//! without a directory.

use bech32::{self, FromBase32, ToBase32};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::SigningKey;
use sha3::{Digest, Sha3_256};

use crate::error::{Result, TorError};

/// Human-readable prefixes accepted as messenger addresses.
pub const ADDRESS_HRPS: [&str; 2] = ["grin", "tgrin"];

/// Tor v3 encodes `version` as the last byte of the address body.
const ONION_V3: u8 = 3;
/// Onion v3 checksum domain separation string.
const CHECKSUM_PREFIX: &[u8] = b".onion checksum";

/// The ed25519 public key of a raw 32-byte seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Tor v3 onion id (56 lowercase base32 chars, no `.onion`) for a raw seed.
pub fn onion_address(seed: &[u8; 32]) -> String {
    onion_from_public_key(&public_key(seed))
}

/// Tor v3 onion id for an ed25519 public key.
pub fn onion_from_public_key(public_key: &[u8; 32]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(CHECKSUM_PREFIX);
    hasher.update(public_key);
    hasher.update([ONION_V3]);
    let checksum = hasher.finalize();

    let mut body = Vec::with_capacity(35);
    body.extend_from_slice(public_key);
    body.push(checksum[0]);
    body.push(checksum[1]);
    body.push(ONION_V3);
    BASE32_NOPAD.encode(&body).to_ascii_lowercase()
}

/// Compute the onion id that corresponds to a bech32 slatepack address.
pub fn onion_from_address(address: &str) -> Result<String> {
    let (hrp, data) = bech32::decode(address.trim())
        .map_err(|e| TorError::Onion(format!("адрес: не bech32 ({e})")))?;
    if !ADDRESS_HRPS.contains(&hrp.as_str()) {
        return Err(TorError::Onion(format!(
            "адрес: неизвестный префикс {hrp:?}"
        )));
    }
    let bytes = Vec::<u8>::from_base32(&data)
        .map_err(|e| TorError::Onion(format!("адрес: не base32 ({e})")))?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| TorError::Onion("адрес: ожидались 32 байта ключа".into()))?;
    Ok(onion_from_public_key(&key))
}

/// Decode a Tor v3 onion id back to the ed25519 public key.
///
/// Accepts both a bare id and a `….onion` hostname.
pub fn parse_onion(onion: &str) -> Result<[u8; 32]> {
    let trimmed = onion
        .trim()
        .trim_end_matches('.')
        .trim_end_matches(".onion");
    if trimmed.len() != 56 {
        return Err(TorError::Onion(format!(
            "ожидались 56 символов onion id, получено {}",
            trimmed.len()
        )));
    }
    let body = BASE32_NOPAD
        .decode(trimmed.to_ascii_uppercase().as_bytes())
        .map_err(|e| TorError::Onion(format!("не base32 ({e})")))?;
    if body.len() != 35 {
        return Err(TorError::Onion(format!(
            "ожидались 35 байт onion, получено {}",
            body.len()
        )));
    }
    if body[34] != ONION_V3 {
        return Err(TorError::Onion(format!(
            "неподдерживаемая версия onion: {}",
            body[34]
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&body[..32]);
    let mut hasher = Sha3_256::new();
    hasher.update(CHECKSUM_PREFIX);
    hasher.update(key);
    hasher.update([ONION_V3]);
    let checksum = hasher.finalize();
    if body[32] != checksum[0] || body[33] != checksum[1] {
        return Err(TorError::Onion("контрольная сумма onion неверна".into()));
    }
    Ok(key)
}

/// Encode raw ed25519 key bytes as a slatepack-style bech32 address (tooling).
pub fn address_from_key(hrp: &str, key: &[u8; 32]) -> Result<String> {
    if !ADDRESS_HRPS.contains(&hrp) {
        return Err(TorError::Onion(format!("неизвестный hrp {hrp:?}")));
    }
    bech32::encode(hrp, key.to_base32()).map_err(|e| TorError::Onion(format!("bech32: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vector from upstream `ov3.rs` / Glaux's `address.rs`.
    const KEY: [u8; 32] = [
        0xd0, 0x3c, 0x09, 0xe9, 0xc1, 0x9b, 0xb7, 0x4a, 0xa9, 0xea, 0x44, 0xe0, 0xfe, 0x5a, 0xe2,
        0x37, 0xa9, 0xbf, 0x40, 0xbd, 0xdf, 0x09, 0x41, 0x06, 0x4a, 0x80, 0x91, 0x3a, 0x44, 0x59,
        0xc8, 0xbb,
    ];
    const ONION: &str = "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid";

    #[test]
    fn key_vector_matches_the_reference_onion() {
        assert_eq!(onion_from_public_key(&KEY), ONION);
    }

    #[test]
    fn address_roundtrips_to_the_same_onion() {
        let address = address_from_key("tgrin", &KEY).expect("encode");
        assert_eq!(onion_from_address(&address).expect("derive"), ONION);
    }

    #[test]
    fn onion_parses_back_to_the_key() {
        assert_eq!(parse_onion(ONION).expect("parse"), KEY);
        assert_eq!(
            parse_onion(&format!("{ONION}.onion")).expect("parse hostname"),
            KEY
        );
    }

    #[test]
    fn seed_derives_a_stable_onion() {
        let seed = [7u8; 32];
        let first = onion_address(&seed);
        assert_eq!(first, onion_address(&seed));
        assert_eq!(first.len(), 56);
        assert!(first
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_ne!(first, onion_address(&[8u8; 32]));
    }

    #[test]
    fn junk_is_rejected() {
        assert!(onion_from_address("tgrin1notreally").is_err());
        assert!(onion_from_address("bc1qsomethingelse").is_err());
        assert!(onion_from_address("").is_err());
        assert!(parse_onion("not-an-onion").is_err());
        assert!(parse_onion(&"a".repeat(56)).is_err());
    }
}
