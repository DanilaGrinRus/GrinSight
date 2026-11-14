//! Experimental authenticated binding of a Glaux key to an I2P destination.
//! Not a delivery or discovery protocol.
use crate::{Address, Identity};
use serde::{Deserialize, Serialize};

const MAX_DURATION: u64 = 7 * 24 * 60 * 60;
const MAX_FUTURE_SKEW: u64 = 5 * 60;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub owner: String,
    pub destination: String,
    pub sequence: u64,
    pub issued: u64,
    pub expires: u64,
    pub signature_hex: String,
}

fn valid_destination(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-~=".contains(&b))
}
fn transcript(b: &Binding) -> Vec<u8> {
    let mut out = b"grinsight-glaux-i2p-binding-v1\0".to_vec();
    for field in [b.owner.as_bytes(), b.destination.as_bytes()] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes()); out.extend_from_slice(field);
    }
    for number in [b.sequence, b.issued, b.expires] { out.extend_from_slice(&number.to_be_bytes()); }
    out
}
impl Binding {
    pub fn create(owner: &Identity, destination: &str, sequence: u64, issued: u64, expires: u64) -> Result<Self, &'static str> {
        let mut b = Self { owner: owner.address().to_string(), destination: destination.into(), sequence, issued, expires, signature_hex: String::new() };
        b.validate_fields(issued)?;
        b.signature_hex = data_encoding::HEXLOWER.encode(&owner.sign_bytes(&transcript(&b)));
        Ok(b)
    }
    fn validate_fields(&self, now: u64) -> Result<(), &'static str> {
        if !valid_destination(&self.destination) { return Err("invalid destination"); }
        if self.expires <= self.issued || self.expires.saturating_sub(self.issued) > MAX_DURATION || now >= self.expires || self.issued > now.saturating_add(MAX_FUTURE_SKEW) { return Err("invalid binding lifetime"); }
        Ok(())
    }
    /// `minimum_sequence` must be obtained from durable, authenticated state;
    /// caller must persist it atomically with the accepted binding.
    pub fn verify(&self, expected: &Address, now: u64, minimum_sequence: u64) -> Result<(), &'static str> {
        self.validate_fields(now)?;
        if self.owner.len() > 128 || self.signature_hex.len() != 128 { return Err("invalid binding size"); }
        if self.owner != expected.to_string() || self.sequence < minimum_sequence { return Err("invalid owner or stale binding"); }
        let bytes = data_encoding::HEXLOWER.decode(self.signature_hex.as_bytes()).map_err(|_| "invalid signature")?;
        let signature: [u8;64] = bytes.try_into().map_err(|_| "invalid signature")?;
        if !expected.verify_bytes(&transcript(self), &signature) { return Err("invalid signature"); }
        Ok(())
    }
    /// Call only with a previously verified binding for the same contact;
    /// atomically persist the accepted value to maintain the rollback check.
    pub fn verify_update(&self, expected: &Address, now: u64, previous: Option<&Binding>) -> Result<(), &'static str> {
        self.verify(expected, now, previous.map_or(0, |p| p.sequence))?;
        if let Some(p) = previous {
            if p.owner != self.owner { return Err("previous binding owner mismatch"); }
            if p.sequence == self.sequence && transcript(p) != transcript(self) { return Err("conflicting binding sequence"); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_binds_owner_destination_network_sequence_and_expiry() {
        let a=Identity::from_seed([1; 32], "tgrin").unwrap();
        let other=Identity::from_seed([2; 32], "tgrin").unwrap();
        let binding=Binding::create(&a, "abcd~ef-123=", 4, 1000, 1500).unwrap();
        let encoded=serde_json::to_string(&binding).unwrap();
        let decoded: Binding=serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded,binding);
        assert!(binding.verify(a.address(), 1100, 4).is_ok());
        assert!(binding.verify(other.address(), 1100, 4).is_err());
        assert!(binding.verify(a.address(), 1100, 5).is_err());
        assert!(binding.verify(a.address(), 1500, 4).is_err());
        let mut altered=binding.clone(); altered.destination.push('a');
        assert!(altered.verify(a.address(), 1100, 4).is_err());
        altered=binding.clone(); altered.sequence+=1;
        assert!(altered.verify(a.address(), 1100, 4).is_err());
        altered=binding.clone(); altered.expires+=1;
        assert!(altered.verify(a.address(), 1100, 4).is_err());
        let conflict=Binding::create(&a, "another-destination", 4, 1000, 1500).unwrap();
        assert!(conflict.verify(a.address(), 1100, 4).is_ok());
        assert!(conflict.verify_update(a.address(), 1100, Some(&binding)).is_err());
        let next=Binding::create(&a, "another-destination", 5, 1000, 1500).unwrap();
        assert!(next.verify_update(a.address(), 1100, Some(&binding)).is_ok());
    }
    #[test]
    fn rejects_bad_destination_and_unbounded_lifetime() {
        let a=Identity::from_seed([1; 32], "tgrin").unwrap();
        assert!(Binding::create(&a,"bad\nDESTINATION",0,1000,1500).is_err());
        assert!(Binding::create(&a,"ok",0,1000,1000+MAX_DURATION+1).is_err());
    }
}
