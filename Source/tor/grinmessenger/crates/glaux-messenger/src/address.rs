// SPDX-License-Identifier: MIT OR Apache-2.0
//! Slatepack address = bech32(ed25519 public key). No new identity is created:
//! the messenger uses the wallet's existing address key.

use std::fmt;
use std::str::FromStr;

use bech32::{self, FromBase32, ToBase32};
use data_encoding::BASE32;
use sha3::{Digest, Sha3_256};

use crate::error::{Error, Result};

/// Accepted human-readable prefixes (mainnet / testnet).
pub const HRPS: [&str; 2] = ["grin", "tgrin"];

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Address {
    hrp: String,
    key: [u8; 32],
}

impl Address {
    pub fn parse(raw: &str) -> Result<Self> {
        let (hrp, data) =
            bech32::decode(raw.trim()).map_err(|e| Error::Address(format!("не bech32 ({e})")))?;
        if !HRPS.contains(&hrp.as_str()) {
            return Err(Error::Address(format!("неизвестный префикс {hrp:?}")));
        }
        let bytes = Vec::<u8>::from_base32(&data)
            .map_err(|e| Error::Address(format!("не base32 ({e})")))?;
        let key: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Address("ожидались 32 байта ключа".into()))?;
        Ok(Self { hrp, key })
    }

    pub fn from_key(hrp: &str, key: [u8; 32]) -> Result<Self> {
        if !HRPS.contains(&hrp) {
            return Err(Error::Address(format!("неизвестный префикс {hrp:?}")));
        }
        Ok(Self {
            hrp: hrp.to_string(),
            key,
        })
    }

    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    pub fn hrp(&self) -> &str {
        &self.hrp
    }

    /// Tor v3 onion of this address key. A slatepack address already is the
    /// ed25519 public key Tor uses, so knowing an address is enough to reach
    /// its direct onion without a directory or relay.
    pub fn onion(&self) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(self.key);
        hasher.update([0x03u8]);
        let checksum = hasher.finalize();

        let mut bytes = Vec::with_capacity(35);
        bytes.extend_from_slice(&self.key);
        bytes.push(checksum[0]);
        bytes.push(checksum[1]);
        bytes.push(0x03);
        BASE32.encode(&bytes).to_ascii_lowercase()
    }

    pub fn onion_url(&self) -> String {
        format!("http://{}.onion", self.onion())
    }

    /// Verify an ed25519 signature made by the address key. Used by relay
    /// fetch-proofs: only the holder of the address seed can list its mailbox.
    pub fn verify_bytes(&self, message: &[u8], signature: &[u8; 64]) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let Ok(key) = VerifyingKey::from_bytes(&self.key) else {
            return false;
        };
        let signature = Signature::from_bytes(signature);
        key.verify(message, &signature).is_ok()
    }
}

/// Transcript signed by the recipient to authenticate a relay fetch request.
/// The relay must not accept `GET /glaux/v1/msg` for an address without this
/// proof, otherwise anyone who learns an address can read its metadata (count,
/// sizes, timestamps, ids) and enumerate traffic.
pub fn fetch_proof_transcript(address: &Address, timestamp: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(b"glaux-gateway-fetch-v1");
    out.push(0);
    out.extend_from_slice(address.to_string().as_bytes());
    out.push(0);
    out.extend_from_slice(timestamp.to_string().as_bytes());
    out
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = bech32::encode(&self.hrp, self.key.to_base32()).map_err(|_| fmt::Error)?;
        f.write_str(&encoded)
    }
}

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_roundtrips() {
        let key = [42u8; 32];
        let address = Address::from_key("tgrin", key).expect("address");
        let text = address.to_string();
        assert!(text.starts_with("tgrin1"));
        let parsed = Address::parse(&text).expect("parse");
        assert_eq!(parsed.key(), key);
        assert_eq!(parsed.hrp(), "tgrin");
    }

    #[test]
    fn onion_matches_the_upstream_v3_vector() {
        // Same key as grin_wallet_util's `ov3` test vector.
        let key = [
            0xd0, 0x3c, 0x09, 0xe9, 0xc1, 0x9b, 0xb7, 0x4a, 0xa9, 0xea, 0x44, 0xe0, 0xfe, 0x5a,
            0xe2, 0x37, 0xa9, 0xbf, 0x40, 0xbd, 0xdf, 0x09, 0x41, 0x06, 0x4a, 0x80, 0x91, 0x3a,
            0x44, 0x59, 0xc8, 0xbb,
        ];
        let address = Address::from_key("tgrin", key).expect("address");
        assert_eq!(
            address.onion(),
            "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid"
        );
        assert_eq!(
            address.onion_url(),
            "http://2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid.onion"
        );
    }

    #[test]
    fn junk_and_foreign_prefixes_are_rejected() {
        assert!(Address::parse("").is_err());
        assert!(Address::parse("tgrin1notreally").is_err());
        assert!(Address::parse("bc1qsomethingelse").is_err());
    }

    #[test]
    fn key_length_is_enforced() {
        // 31-byte payload: valid bech32, invalid slatepack key.
        let short = bech32::encode("tgrin", vec![1u8; 31].to_base32()).unwrap();
        assert!(Address::parse(&short).is_err());
    }
}
