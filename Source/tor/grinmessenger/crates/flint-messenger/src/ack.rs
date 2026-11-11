// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signed mailbox acknowledgement.
//!
//! The original M1 ack was a capability: anyone who knew the recipient address
//! could delete its messages. On a public store-and-forward relay that is a
//! trivial denial of service. This proof signs `(recipient, message id,
//! timestamp)` with the recipient's slatepack key; the relay verifies it without
//! learning any secret, and a captured proof cannot be replayed for another id.

use data_encoding::HEXLOWER;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::envelope::Identity;
use crate::error::{Error, Result};

const DOMAIN: &[u8] = b"flint-messenger-ack-v1";

/// Relays should reject an ack whose timestamp is farther than this.
pub const MAX_SKEW_SECS: u64 = 300;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AckProof {
    pub to: String,
    /// Message id this ack is allowed to delete.
    pub id: String,
    /// Unix seconds when the ack was signed.
    pub ts: u64,
    /// Hex-encoded ed25519 signature over `ack_transcript(to, id, ts)`.
    pub signature: String,
}

impl AckProof {
    pub fn sign(identity: &Identity, id: &str, ts: u64) -> Self {
        let to = identity.address().to_string();
        let signature = identity.sign_bytes(&ack_transcript(&to, id, ts));
        Self {
            to,
            id: id.to_string(),
            ts,
            signature: HEXLOWER.encode(&signature),
        }
    }

    /// Verify the signature and return the address that signed it. The caller
    /// must compare `to`/`id` with the mailbox operation and check `ts` against
    /// its own clock.
    pub fn verify(&self) -> Result<Address> {
        let address = Address::parse(&self.to)?;
        let bytes = HEXLOWER
            .decode(self.signature.as_bytes())
            .map_err(|_| Error::BadSignature)?;
        let signature = Signature::from_slice(&bytes).map_err(|_| Error::BadSignature)?;
        let key = VerifyingKey::from_bytes(&address.key()).map_err(|_| Error::BadSignature)?;
        key.verify(&ack_transcript(&self.to, &self.id, self.ts), &signature)
            .map_err(|_| Error::BadSignature)?;
        Ok(address)
    }
}

fn ack_transcript(to: &str, id: &str, ts: u64) -> Vec<u8> {
    let mut out = DOMAIN.to_vec();
    out.extend_from_slice(&(to.len() as u64).to_le_bytes());
    out.extend_from_slice(to.as_bytes());
    out.extend_from_slice(&(id.len() as u64).to_le_bytes());
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&ts.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> Identity {
        Identity::from_seed([seed; 32], "tgrin").unwrap()
    }

    #[test]
    fn signs_and_verifies_the_recipient() {
        let bob = identity(9);
        let proof = AckProof::sign(&bob, "message-id", 1_760_000_000);
        assert_eq!(proof.verify().unwrap(), *bob.address());
    }

    #[test]
    fn wrong_recipient_id_timestamp_or_signature_is_rejected() {
        let bob = identity(9);
        let mut proof = AckProof::sign(&bob, "message-id", 1_760_000_000);
        proof.to = identity(7).address().to_string();
        assert!(proof.verify().is_err());

        let mut proof = AckProof::sign(&bob, "message-id", 1_760_000_000);
        proof.id = "another-id".into();
        assert!(proof.verify().is_err());

        let mut proof = AckProof::sign(&bob, "message-id", 1_760_000_000);
        proof.ts += 1;
        assert!(proof.verify().is_err());

        let mut proof = AckProof::sign(&bob, "message-id", 1_760_000_000);
        proof.signature = "00".repeat(64);
        assert!(proof.verify().is_err());
    }
}
