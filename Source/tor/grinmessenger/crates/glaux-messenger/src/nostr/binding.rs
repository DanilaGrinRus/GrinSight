// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signed binding between a Glaux identity and an unrelated Nostr key.
//! The caller must persist accepted bindings atomically to reject rollback and
//! conflicting bindings with the same sequence number.
use crate::{Address, Identity};
use serde::{Deserialize, Serialize};

const MAX_LIFETIME: u64 = 7 * 24 * 60 * 60;
const MAX_FUTURE_SKEW: u64 = 5 * 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NostrBinding {
    pub owner: String,
    pub transport_key: String,
    pub sequence: u64,
    pub issued: u64,
    pub expires: u64,
    pub signature_hex: String,
}

fn transcript(binding: &NostrBinding) -> Vec<u8> {
    let mut result = b"grinsight-glaux-nostr-binding-v1\0".to_vec();
    for part in [binding.owner.as_bytes(), binding.transport_key.as_bytes()] {
        result.extend_from_slice(&(part.len() as u32).to_be_bytes());
        result.extend_from_slice(part);
    }
    for number in [binding.sequence, binding.issued, binding.expires] {
        result.extend_from_slice(&number.to_be_bytes());
    }
    result
}

impl NostrBinding {
    pub fn create(identity: &Identity, key: &str, sequence: u64, issued: u64, expires: u64) -> Result<Self, &'static str> {
        let canonical = super::hex_encode(&super::parse_public_hex(key).map_err(|_| "invalid Nostr key")?.to_byte_array());
        let mut binding = Self { owner: identity.address().to_string(), transport_key: canonical, sequence, issued, expires, signature_hex: String::new() };
        binding.check_lifetime(issued)?;
        binding.signature_hex = data_encoding::HEXLOWER.encode(&identity.sign_bytes(&transcript(&binding)));
        Ok(binding)
    }

    fn check_lifetime(&self, now: u64) -> Result<(), &'static str> {
        if self.expires <= self.issued || self.expires.saturating_sub(self.issued) > MAX_LIFETIME || now >= self.expires || self.issued > now.saturating_add(MAX_FUTURE_SKEW) {
            return Err("invalid binding lifetime");
        }
        Ok(())
    }

    pub fn verify_update(&self, expected: &Address, now: u64, previous: Option<&Self>) -> Result<(), &'static str> {
        self.check_lifetime(now)?;
        if self.owner.len() > 128 || self.transport_key.len() != 64 || self.signature_hex.len() != 128 {
            return Err("invalid binding size");
        }
        let parsed=super::parse_public_hex(&self.transport_key).map_err(|_| "invalid Nostr key")?;
        if self.transport_key != super::hex_encode(&parsed.to_byte_array()) || self.owner != expected.to_string() { return Err("invalid owner or key"); }
        if let Some(p)=previous {
            if p.owner != self.owner || self.sequence < p.sequence || (self.sequence == p.sequence && transcript(self) != transcript(p)) {
                return Err("rollback or conflicting sequence");
            }
        }
        let bytes=data_encoding::HEXLOWER.decode(self.signature_hex.as_bytes()).map_err(|_| "invalid signature")?;
        let signature: [u8;64]=bytes.try_into().map_err(|_| "invalid signature")?;
        if !expected.verify_bytes(&transcript(self), &signature) { return Err("invalid signature"); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NostrKeys;
    #[test]
    fn binding_authenticates_key_and_rejects_rollback_or_conflict() {
        let identity=Identity::from_seed([7;32],"tgrin").unwrap();
        let other=Identity::from_seed([8;32],"tgrin").unwrap();
        let first=NostrKeys::from_hex(&format!("{:064x}",1)).unwrap();
        let second=NostrKeys::from_hex(&format!("{:064x}",2)).unwrap();
        let binding=NostrBinding::create(&identity,&first.public_hex(),1,1000,1500).unwrap();
        let json=serde_json::to_string(&binding).unwrap();
        let recovered:NostrBinding=serde_json::from_str(&json).unwrap();
        assert!(recovered.verify_update(identity.address(),1100,None).is_ok());
        assert!(recovered.verify_update(other.address(),1100,None).is_err());
        assert!(recovered.verify_update(identity.address(),1500,None).is_err());
        let conflict=NostrBinding::create(&identity,&second.public_hex(),1,1000,1500).unwrap();
        assert!(conflict.verify_update(identity.address(),1100,Some(&binding)).is_err());
        let next=NostrBinding::create(&identity,&second.public_hex(),2,1000,1500).unwrap();
        assert!(next.verify_update(identity.address(),1100,Some(&binding)).is_ok());
        assert!(binding.verify_update(identity.address(),1100,Some(&next)).is_err());
        let mut changed=binding; changed.transport_key=second.public_hex();
        assert!(changed.verify_update(identity.address(),1100,None).is_err());
    }
}
