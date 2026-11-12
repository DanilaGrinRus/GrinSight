// SPDX-License-Identifier: MIT OR Apache-2.0
//! NIP-01 event: canonical id, BIP-340 signature, verification.

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{hex_decode, hex_encode};
use crate::error::{Error, Result};

/// NIP-59 seal.
pub const KIND_SEAL: u32 = 13;
/// NIP-17 direct message rumor.
pub const KIND_DM: u32 = 14;
/// NIP-59 gift wrap.
pub const KIND_GIFT_WRAP: u32 = 1059;
/// NIP-09 deletion request (used for the best-effort transport ACK).
pub const KIND_DELETE: u32 = 5;

fn crypto(message: impl Into<String>) -> Error {
    Error::Crypto(format!("nostr/event: {}", message.into()))
}

/// A signed Nostr event. `id` is the SHA-256 of the canonical serialization.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(default)]
    pub sig: String,
}

impl Event {
    /// Build an unsigned event with its canonical id already computed.
    pub fn unsigned(
        pubkey: String,
        created_at: u64,
        kind: u32,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Self {
        let id = compute_id(&pubkey, created_at, kind, &tags, &content);
        Self {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: String::new(),
        }
    }

    /// Canonical NIP-01 id: `sha256([0, pubkey, created_at, kind, tags, content])`.
    pub fn canonical_id(&self) -> String {
        compute_id(
            &self.pubkey,
            self.created_at,
            self.kind,
            &self.tags,
            &self.content,
        )
    }

    /// Sign with BIP-340 (deterministic nonce) and fill `sig`.
    pub fn sign(mut self, secret: &SecretKey) -> Result<Self> {
        let id = hex_decode(&self.id)?;
        if id.len() != 32 {
            return Err(crypto("id must be 32 bytes"));
        }
        let keypair = Keypair::from_secret_key(secret);
        let signature = secp256k1::schnorr::sign_no_aux_rand(&id, &keypair);
        self.sig = hex_encode(signature.as_ref());
        Ok(self)
    }

    /// Verify the id, the signature and return the signer's x-only key.
    pub fn verify(&self) -> Result<XOnlyPublicKey> {
        if self.canonical_id() != self.id {
            return Err(crypto("event id does not match its content"));
        }
        let pubkey_bytes = hex_decode(&self.pubkey)?;
        let id = hex_decode(&self.id)?;
        let sig_bytes = hex_decode(&self.sig)?;
        if pubkey_bytes.len() != 32 || id.len() != 32 || sig_bytes.len() != 64 {
            return Err(crypto("invalid key, id or signature length"));
        }
        let pubkey_bytes: [u8; 32] = pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| crypto("invalid x-only public key"))?;
        let signature_bytes: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| crypto("invalid signature"))?;
        let pubkey = XOnlyPublicKey::from_byte_array(pubkey_bytes)
            .map_err(|_| crypto("invalid x-only public key"))?;
        let signature = Signature::from_byte_array(signature_bytes);
        secp256k1::schnorr::verify(&signature, &id, &pubkey).map_err(|_| Error::BadSignature)?;
        Ok(pubkey)
    }

    /// Hex values of every `p` tag (the addressed recipients).
    pub fn p_tags(&self) -> Vec<String> {
        self.tags
            .iter()
            .filter(|tag| tag.len() >= 2 && tag[0] == "p")
            .map(|tag| tag[1].clone())
            .collect()
    }

    /// Hex values of every `e` tag (referenced event ids).
    pub fn e_tags(&self) -> Vec<String> {
        self.tags
            .iter()
            .filter(|tag| tag.len() >= 2 && tag[0] == "e")
            .map(|tag| tag[1].clone())
            .collect()
    }
}

fn compute_id(
    pubkey: &str,
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    // serde_json emits the compact array form the protocol hashes.
    let canonical = serde_json::to_string(&(0u8, pubkey, created_at, kind, tags, content))
        .expect("serializing strings and integers cannot fail");
    hex_encode(&Sha256::digest(canonical.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn keypair(hex: &str) -> SecretKey {
        SecretKey::from_str(hex).expect("test secret")
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let secret = keypair("0000000000000000000000000000000000000000000000000000000000000001");
        let event = Event::unsigned(
            hex_encode(&secp256k1::PublicKey::from_secret_key(&secret).serialize()[1..]),
            1_700_000_000,
            KIND_DM,
            vec![vec!["p".into(), "aa".repeat(32)]],
            "hello".into(),
        )
        .sign(&secret)
        .expect("sign");
        let signer = event.verify().expect("verify");
        assert_eq!(hex_encode(&signer.to_byte_array()), event.pubkey);
    }

    #[test]
    fn tampering_is_rejected() {
        let secret = keypair("0000000000000000000000000000000000000000000000000000000000000001");
        let event = Event::unsigned(
            hex_encode(&secp256k1::PublicKey::from_secret_key(&secret).serialize()[1..]),
            1_700_000_000,
            KIND_SEAL,
            vec![],
            "sealed".into(),
        )
        .sign(&secret)
        .expect("sign");

        let mut changed = event.clone();
        changed.content = "tampered".into();
        assert!(changed.verify().is_err());

        let mut forged = event;
        forged.sig = "00".repeat(64);
        assert!(forged.verify().is_err());
    }
}
