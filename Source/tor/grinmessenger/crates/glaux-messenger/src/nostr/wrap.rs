// SPDX-License-Identifier: MIT OR Apache-2.0
//! NIP-59 gift wraps carrying NIP-17 direct messages (kind 14 rumors).
//!
//! `gift_wrap` builds rumor → seal (kind 13) → gift wrap (kind 1059) with a
//! fresh ephemeral key and a randomized timestamp. `unwrap` verifies every
//! signature before decrypting and returns the sender's transport key.

use std::str::FromStr;

use secp256k1::{PublicKey, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};

use super::event::{Event, KIND_DM, KIND_GIFT_WRAP, KIND_SEAL};
use super::{hex_encode, nip44, random_bytes};
use crate::error::{Error, Result};

fn crypto(message: impl Into<String>) -> Error {
    Error::Crypto(format!("nostr/wrap: {}", message.into()))
}

/// Unsigned inner event (NIP-59 rumor): no id, no signature.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rumor {
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

/// x-only public key of a secret key, as lowercase hex.
pub fn xonly_hex(secret: &SecretKey) -> String {
    hex_encode(
        &PublicKey::from_secret_key(secret)
            .x_only_public_key()
            .0
            .to_byte_array(),
    )
}

fn random_secret() -> Result<SecretKey> {
    // A uniformly random 32-byte scalar is a valid secp256k1 key except for the
    // negligible chance it is zero or >= the curve order; retry in that case.
    for _ in 0..8 {
        let bytes = random_bytes::<32>()?;
        if let Ok(secret) = SecretKey::from_str(&hex_encode(&bytes)) {
            return Ok(secret);
        }
    }
    Err(crypto("could not generate a transport key"))
}

/// Wrap `content` for `recipient` and return the signed kind 1059 event.
pub fn gift_wrap(
    sender: &SecretKey,
    recipient: &XOnlyPublicKey,
    content: String,
    now: u64,
) -> Result<Event> {
    gift_wrap_with_expiration(sender, recipient, content, now, None)
}

/// Include an optional NIP-40 expiry in the outer event. This reveals timing
/// metadata and is only a request: a relay may retain the ciphertext anyway.
pub fn gift_wrap_with_expiration(
    sender: &SecretKey,
    recipient: &XOnlyPublicKey,
    content: String,
    now: u64,
    expiration: Option<u64>,
) -> Result<Event> {
    gift_wrap_inner(sender,recipient,content,now,expiration,None)
}

#[cfg(test)]
pub(crate) fn gift_wrap_with_test_jitter(sender:&SecretKey,recipient:&XOnlyPublicKey,content:String,now:u64,jitter:u64)->Result<Event> {
    gift_wrap_inner(sender,recipient,content,now,None,Some(jitter))
}

fn gift_wrap_inner(sender:&SecretKey,recipient:&XOnlyPublicKey,content:String,now:u64,expiration:Option<u64>, forced_jitter:Option<u64>) -> Result<Event> {
    if expiration.is_some_and(|when| when <= now) { return Err(crypto("expiration is not in the future")); }
    let sender_hex = xonly_hex(sender);
    let recipient_hex = hex_encode(&recipient.to_byte_array());

    let rumor = Rumor {
        pubkey: sender_hex.clone(),
        created_at: now,
        kind: KIND_DM,
        tags: vec![vec!["p".to_string(), recipient_hex.clone()]],
        content,
    };
    let rumor_json = serde_json::to_string(&rumor).map_err(|e| crypto(e.to_string()))?;

    let conversation = nip44::conversation_key(sender, recipient);
    let seal_content =
        nip44::encrypt(rumor_json.as_bytes(), &conversation, &random_bytes::<32>()?)?;
    let seal =
        Event::unsigned(sender_hex, now, KIND_SEAL, Vec::new(), seal_content).sign(sender)?;
    let seal_json = serde_json::to_string(&seal).map_err(|e| crypto(e.to_string()))?;

    let ephemeral = random_secret()?;
    let ephemeral_hex = xonly_hex(&ephemeral);
    let wrap_conversation = nip44::conversation_key(&ephemeral, recipient);
    let wrap_content = nip44::encrypt(
        seal_json.as_bytes(),
        &wrap_conversation,
        &random_bytes::<32>()?,
    )?;

    let jitter = if let Some(jitter)=forced_jitter { jitter } else {
        let bytes = random_bytes::<4>()?;
        (u32::from_be_bytes(bytes) as u64) % 172_800
    };
    let mut tags = vec![vec!["p".to_string(), recipient_hex]];
    if let Some(expires) = expiration { tags.push(vec!["expiration".to_string(), expires.to_string()]); }
    Event::unsigned(
        ephemeral_hex,
        now.saturating_sub(jitter),
        KIND_GIFT_WRAP,
        tags,
        wrap_content,
    )
    .sign(&ephemeral)
}

/// Unwrap a gift wrap addressed to `recipient`; returns the sender key and rumor.
pub fn unwrap(event: &Event, recipient: &SecretKey) -> Result<(XOnlyPublicKey, Rumor)> {
    if event.kind != KIND_GIFT_WRAP {
        return Err(crypto(format!("expected kind 1059, got {}", event.kind)));
    }
    let our_hex = xonly_hex(recipient);
    if !event.p_tags().iter().any(|tag| tag == &our_hex) {
        return Err(Error::WrongRecipient);
    }
    let ephemeral = event.verify()?;
    let conversation = nip44::conversation_key(recipient, &ephemeral);
    let seal_json = nip44::decrypt(&event.content, &conversation)?;
    let seal: Event =
        serde_json::from_slice(&seal_json).map_err(|e| crypto(format!("bad seal: {e}")))?;
    if seal.kind != KIND_SEAL {
        return Err(crypto(format!("expected kind 13, got {}", seal.kind)));
    }
    let sender = seal.verify()?;
    let conversation = nip44::conversation_key(recipient, &sender);
    let rumor_json = nip44::decrypt(&seal.content, &conversation)?;
    let rumor: Rumor =
        serde_json::from_slice(&rumor_json).map_err(|e| crypto(format!("bad rumor: {e}")))?;
    if rumor.pubkey != hex_encode(&sender.to_byte_array()) {
        return Err(crypto("rumor pubkey does not match the seal signer"));
    }
    Ok((sender, rumor))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(hex: &str) -> SecretKey {
        SecretKey::from_str(hex).expect("test secret")
    }

    fn xonly(secret: &SecretKey) -> XOnlyPublicKey {
        PublicKey::from_secret_key(secret).x_only_public_key().0
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let alice = secret("0000000000000000000000000000000000000000000000000000000000000001");
        let bob = secret("0000000000000000000000000000000000000000000000000000000000000002");
        let event = gift_wrap(
            &alice,
            &xonly(&bob),
            "slatepack-envelope".into(),
            1_700_000_000,
        )
        .expect("wrap");
        assert_eq!(event.kind, KIND_GIFT_WRAP);
        assert!(event.created_at <= 1_700_000_000);
        let (sender, rumor) = unwrap(&event, &bob).expect("unwrap");
        assert_eq!(hex_encode(&sender.to_byte_array()), xonly_hex(&alice));
        assert_eq!(rumor.content, "slatepack-envelope");
        assert_eq!(rumor.kind, KIND_DM);
        assert_eq!(rumor.pubkey, xonly_hex(&alice));
    }

    #[test]
    fn optional_expiration_is_signed_and_does_not_prevent_decryption() {
        let alice = secret("0000000000000000000000000000000000000000000000000000000000000001");
        let bob = secret("0000000000000000000000000000000000000000000000000000000000000002");
        let peer = PublicKey::from_secret_key(&bob).x_only_public_key().0;
        let event = gift_wrap_with_expiration(&alice, &peer, "test".into(), 1000, Some(2000)).unwrap();
        assert!(event.tags.contains(&vec!["expiration".to_string(), "2000".to_string()]));
        assert_eq!(unwrap(&event, &bob).unwrap().1.content, "test");
        let mut altered=event; altered.tags[1][1] = "3000".into();
        assert!(altered.verify().is_err());
        assert!(gift_wrap_with_expiration(&alice, &peer, "test".into(), 1000, Some(1000)).is_err());
    }

    #[test]
    fn wrong_recipient_and_tampering_are_rejected() {
        let alice = secret("0000000000000000000000000000000000000000000000000000000000000001");
        let bob = secret("0000000000000000000000000000000000000000000000000000000000000002");
        let eve = secret("0000000000000000000000000000000000000000000000000000000000000003");
        let event = gift_wrap(&alice, &xonly(&bob), "x".into(), 1_700_000_000).expect("wrap");

        assert!(matches!(unwrap(&event, &eve), Err(Error::WrongRecipient)));

        let mut tampered = event.clone();
        tampered.content = "AAAA".into();
        assert!(unwrap(&tampered, &bob).is_err());

        // Re-addressing a valid wrap to another recipient breaks the p tag check.
        let mut redirected = event;
        redirected.tags = vec![vec!["p".to_string(), xonly_hex(&eve)]];
        redirected.id = redirected.canonical_id();
        assert!(unwrap(&redirected, &bob).is_err());
    }
}
