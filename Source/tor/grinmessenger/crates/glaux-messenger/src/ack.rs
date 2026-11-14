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
use sha2::{Digest, Sha256};

use crate::address::Address;
use crate::envelope::Identity;
use crate::error::{Error, Result};

const DOMAIN: &[u8] = b"glaux-messenger-ack-v1";

/// Relays should reject an ack whose timestamp is farther than this.
pub const MAX_SKEW_SECS: u64 = 300;

/// Version 2 identifies the exact canonical encrypted envelope, not just UUID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AckProofV2 { pub to: String, pub id: String, pub digest: String, pub ts: u64, pub signature: String }

pub fn envelope_digest(envelope: &crate::envelope::Envelope) -> Result<String> {
    let canonical = serde_json::to_vec(envelope).map_err(|e| Error::Envelope(format!("ack envelope: {e}")))?;
    Ok(HEXLOWER.encode(&Sha256::digest(canonical)))
}

fn transcript_v2(to: &str, id: &str, digest: &str, ts: u64) -> Vec<u8> {
    let mut data = b"glaux-messenger-ack-v2\0".to_vec();
    for field in [to, id, digest] { data.extend_from_slice(&(field.len() as u64).to_le_bytes()); data.extend_from_slice(field.as_bytes()); }
    data.extend_from_slice(&ts.to_le_bytes()); data
}

impl AckProofV2 {
    pub fn sign(identity: &Identity, id: &str, digest: &str, ts: u64) -> Self {
        let to = identity.address().to_string();
        let signature = HEXLOWER.encode(&identity.sign_bytes(&transcript_v2(&to, id, digest, ts)));
        Self { to, id: id.into(), digest: digest.into(), ts, signature }
    }
    pub fn verify(&self) -> Result<Address> {
        if self.digest.len()!=64 || HEXLOWER.decode(self.digest.as_bytes()).map_or(true, |v|v.len()!=32) { return Err(Error::BadSignature); }
        let address = Address::parse(&self.to)?;
        let sig = HEXLOWER.decode(self.signature.as_bytes()).map_err(|_| Error::BadSignature)?;
        let signature=Signature::from_slice(&sig).map_err(|_| Error::BadSignature)?;
        let key=VerifyingKey::from_bytes(&address.key()).map_err(|_| Error::BadSignature)?;
        key.verify(&transcript_v2(&self.to,&self.id,&self.digest,self.ts),&signature).map_err(|_| Error::BadSignature)?;
        Ok(address)
    }
}

/// Recipient-signed rejection of the exact raw malformed payload. Domain and
/// endpoint are deliberately separate from acknowledgement of valid envelopes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RawRejectProof { pub to: String, pub id: String, pub digest: String, pub ts: u64, pub signature: String }

pub fn raw_payload_digest(payload: &str) -> String {
    HEXLOWER.encode(&Sha256::digest(payload.as_bytes()))
}

/// Restrict irreversible rejection to syntactically malformed JSON, or a
/// malformed record that explicitly claims a version this client knows.
/// Unknown/missing versions are retained for forward compatibility.
pub fn definitely_malformed_raw(payload: &str) -> bool {
    match serde_json::from_str::<serde_json::Value>(payload) {
        Err(_) => true,
        Ok(value) => match value.get("version").and_then(|v|v.as_u64()) {
            Some(1 | 2) => serde_json::from_value::<crate::envelope::Envelope>(value).is_err(),
            _ => false,
        },
    }
}

fn raw_reject_transcript(to: &str, id: &str, digest: &str, ts: u64) -> Vec<u8> {
    let mut data = b"glaux-messenger-raw-reject-v1\0".to_vec();
    for field in [to, id, digest] { data.extend_from_slice(&(field.len() as u64).to_le_bytes()); data.extend_from_slice(field.as_bytes()); }
    data.extend_from_slice(&ts.to_le_bytes()); data
}

impl RawRejectProof {
    pub fn sign(identity: &Identity, id: &str, digest: &str, ts: u64) -> Self {
        let to=identity.address().to_string();
        let signature=HEXLOWER.encode(&identity.sign_bytes(&raw_reject_transcript(&to,id,digest,ts)));
        Self { to, id:id.into(), digest:digest.into(), ts, signature }
    }
    pub fn verify(&self) -> Result<Address> {
        if self.digest.len()!=64 || self.digest.bytes().any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b)) { return Err(Error::BadSignature); }
        let address=Address::parse(&self.to)?;
        let sig=HEXLOWER.decode(self.signature.as_bytes()).map_err(|_|Error::BadSignature)?;
        let signature=Signature::from_slice(&sig).map_err(|_|Error::BadSignature)?;
        let key=VerifyingKey::from_bytes(&address.key()).map_err(|_|Error::BadSignature)?;
        key.verify(&raw_reject_transcript(&self.to,&self.id,&self.digest,self.ts),&signature).map_err(|_|Error::BadSignature)?;
        Ok(address)
    }
}

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
