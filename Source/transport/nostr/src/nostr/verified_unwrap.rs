//! Research-only input boundary for synthetic NIP-59 messages.
//! This is not a network receiver, contact database or payment handler.

use nostr_sdk::{nips::{nip44, nip59::UnwrappedGift}, Event, JsonUtil, Keys, Kind, PublicKey, UnsignedEvent};
use zeroize::Zeroizing;

// Local resource policy, not a Nostr protocol limit. Parsing an Event from an
// untrusted frame must be bounded separately before this function is called.
const MAX_CONTENT_BYTES: usize = super::protocol::MAX_WRAP_CONTENT;
const MAX_EVENT_JSON_BYTES: usize = 128 * 1024;

/// Bounds an already received event string before JSON decoding. A transport
/// must impose its own frame limit before it allocates this input string.
pub async fn unwrap_contact_json(
    keys: &Keys,
    json: &str,
    expected_sender: &PublicKey,
) -> Result<UnwrappedGift, &'static str> {
    if json.len() > MAX_EVENT_JSON_BYTES {
        return Err("event too large");
    }
    let event = Event::from_json(json).map_err(|_| "invalid event")?;
    unwrap_from_contact(keys, &event, expected_sender).await
}

/// Verify the outer event and pin the decrypted sender to a trusted contact.
/// Caller supplies the authenticated sender key; discovery is not trust.
pub async fn unwrap_from_contact(
    keys: &Keys,
    event: &Event,
    expected_sender: &PublicKey,
) -> Result<UnwrappedGift, &'static str> {
    let message = unwrap_verified_sender(keys, event).await?;
    if message.sender != *expected_sender {
        return Err("unexpected sender");
    }
    Ok(message)
}

/// Verify and decrypt a request from an as-yet unknown sender. The returned
/// key authenticates only this message, not a person, a payment address or
/// authorization to sign. A caller must impose frame limits, rate limits,
/// replay policy, wallet policy and user-facing status separately.
pub async fn unwrap_verified_sender(
    keys: &Keys,
    event: &Event,
) -> Result<UnwrappedGift, &'static str> {
    if event.kind != Kind::GiftWrap || event.content.len() > MAX_CONTENT_BYTES {
        return Err("invalid gift wrap");
    }
    // Count the raw tags too: public_keys() silently ignores malformed tags.
    if event.tags.iter().filter(|tag| tag.as_slice().first().map(String::as_str) == Some("p")).count() != 1 {
        return Err("invalid recipient");
    }
    let mut recipients = event.tags.public_keys();
    if recipients.next() != Some(&keys.public_key()) || recipients.next().is_some() {
        return Err("invalid recipient");
    }
    event.verify().map_err(|_| "invalid outer signature")?;
    // The upstream SDK's v2 unwrap verifies the seal's signature but does not
    // check its kind. Validate that layer explicitly before using its result.
    let message = match ::nip44::payload_version(&event.content) {
        Ok(2) => unwrap_v2_checked(keys, event)?,
        Ok(3) => super::wrapv3::unwrap(keys, event).await.map_err(|_| "invalid encrypted message")?,
        _ => return Err("invalid encrypted message"),
    };
    if message.rumor.pubkey != message.sender {
        return Err("invalid sender");
    }
    message.rumor.verify_id().map_err(|_| "invalid message id")?;
    if message.rumor.kind != Kind::PrivateDirectMessage
        || message.rumor.content.len() > super::protocol::MAX_RUMOR_CONTENT
    {
        return Err("invalid message content");
    }
    Ok(message)
}

/// Bounded JSON entry for an unknown sender. A transport must bound the frame
/// before allocation; successful decryption confers no payment authority.
pub async fn unwrap_sender_json(keys: &Keys, json: &str) -> Result<UnwrappedGift, &'static str> {
    if json.len() > MAX_EVENT_JSON_BYTES { return Err("event too large"); }
    let event = Event::from_json(json).map_err(|_| "invalid event")?;
    unwrap_verified_sender(keys, &event).await
}

fn unwrap_v2_checked(keys: &Keys, event: &Event) -> Result<UnwrappedGift, &'static str> {
    let seal_json = Zeroizing::new(nip44::decrypt(keys.secret_key(), &event.pubkey, &event.content)
        .map_err(|_| "invalid encrypted message")?);
    let seal = Event::from_json(&*seal_json).map_err(|_| "invalid encrypted message")?;
    if seal.kind != Kind::Seal { return Err("invalid seal"); }
    seal.verify().map_err(|_| "invalid seal")?;
    let rumor_json = Zeroizing::new(nip44::decrypt(keys.secret_key(), &seal.pubkey, &seal.content)
        .map_err(|_| "invalid encrypted message")?);
    let rumor = UnsignedEvent::from_json(&*rumor_json).map_err(|_| "invalid encrypted message")?;
    if rumor.pubkey != seal.pubkey { return Err("invalid sender"); }
    Ok(UnwrappedGift { sender: seal.pubkey, rumor })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unknown_sender_is_authenticated_but_never_promoted_to_contact() {
        use nostr_sdk::{EventBuilder, Tag};
        let alice = Keys::generate(); let bob = Keys::generate(); let mallory = Keys::generate();
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
            .tag(Tag::public_key(bob.public_key())).build(alice.public_key());
        let v2 = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor, []).await.unwrap();
        let v3 = super::super::wrapv3::wrap(&alice, &bob.public_key(), "synthetic".into(), vec![]).unwrap();
        for event in [v2, v3] {
            let message = unwrap_sender_json(&bob, &event.as_json()).await.unwrap();
            assert_eq!(message.sender, alice.public_key());
            assert_eq!(message.rumor.pubkey, alice.public_key());
            assert!(unwrap_from_contact(&bob, &event, &mallory.public_key()).await.is_err());
            assert!(unwrap_verified_sender(&mallory, &event).await.is_err());
            let mut modified = event;
            modified.created_at = nostr_sdk::Timestamp::from(0);
            assert!(unwrap_verified_sender(&bob, &modified).await.is_err());
        }
        assert_eq!(unwrap_sender_json(&bob, &" ".repeat(MAX_EVENT_JSON_BYTES + 1)).await.err(), Some("event too large"));
    }

    #[tokio::test]
    async fn signed_message_requires_the_expected_sender_and_recipient() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let other = Keys::generate();
        let event = super::super::wrapv3::wrap(&alice, &bob.public_key(), "synthetic".into(), vec![]).unwrap();
        assert!(unwrap_from_contact(&bob, &event, &alice.public_key()).await.is_ok());
        assert!(unwrap_from_contact(&bob, &event, &other.public_key()).await.is_err());
        assert!(unwrap_from_contact(&other, &event, &alice.public_key()).await.is_err());
    }

    #[tokio::test]
    async fn changed_signed_fields_and_oversized_content_are_refused() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let mut event = super::super::wrapv3::wrap(&alice, &bob.public_key(), "synthetic".into(), vec![]).unwrap();
        event.created_at = nostr_sdk::Timestamp::from(0);
        assert_eq!(unwrap_from_contact(&bob, &event, &alice.public_key()).await.err(), Some("invalid outer signature"));
        event.content = "A".repeat(MAX_CONTENT_BYTES + 1);
        assert_eq!(unwrap_from_contact(&bob, &event, &alice.public_key()).await.err(), Some("invalid gift wrap"));
    }

    #[tokio::test]
    async fn v2_message_also_requires_the_expected_contact() {
        use nostr_sdk::{EventBuilder, Tag};
        let alice = Keys::generate();
        let bob = Keys::generate();
        let other = Keys::generate();
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
            .tag(Tag::public_key(bob.public_key())).build(alice.public_key());
        let event = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor, []).await.unwrap();
        assert!(unwrap_from_contact(&bob, &event, &alice.public_key()).await.is_ok());
        assert!(unwrap_from_contact(&bob, &event, &other.public_key()).await.is_err());
    }

    #[tokio::test]
    async fn rejects_unexpected_rumor_kind_and_oversized_plaintext() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let wrong_kind = super::super::wrapv3::wrap_kind(
            &alice, &bob.public_key(), Kind::TextNote, "synthetic".into(), vec![]
        ).unwrap();
        assert_eq!(unwrap_from_contact(&bob, &wrong_kind, &alice.public_key()).await.err(), Some("invalid message content"));
        let oversized = super::super::wrapv3::wrap(
            &alice, &bob.public_key(), "a".repeat(super::super::protocol::MAX_RUMOR_CONTENT + 1), vec![]
        ).unwrap();
        assert!(unwrap_from_contact(&bob, &oversized, &alice.public_key()).await.is_err());
    }

    #[tokio::test]
    async fn json_boundary_checks_size_shape_and_signature() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let event = super::super::wrapv3::wrap(&alice, &bob.public_key(), "synthetic".into(), vec![]).unwrap();
        assert!(unwrap_contact_json(&bob, &event.as_json(), &alice.public_key()).await.is_ok());
        assert_eq!(unwrap_contact_json(&bob, "{}", &alice.public_key()).await.err(), Some("invalid event"));
        assert_eq!(unwrap_contact_json(&bob, &" ".repeat(MAX_EVENT_JSON_BYTES + 1), &alice.public_key()).await.err(), Some("event too large"));
        let mut modified = event.clone();
        modified.created_at = nostr_sdk::Timestamp::from(0);
        assert_eq!(unwrap_contact_json(&bob, &modified.as_json(), &alice.public_key()).await.err(), Some("invalid outer signature"));
    }
}
