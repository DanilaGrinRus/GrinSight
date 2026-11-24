//! Synthetic regression tests for the verified NIP-59 input boundary.
//! Each malformed event remains encrypted and signed by the test contact.
//! Expected rejection does not establish network or wallet safety.
use fly_nostr_research::nostr::verified_unwrap::unwrap_from_contact;
use nostr_sdk::{
    nips::nip44::{self as nip44v2, Version}, Event, EventBuilder, EventId, JsonUtil, Keys,
    Kind, PublicKey, Tag, UnsignedEvent,
};

#[derive(Clone, Copy)]
enum Cipher {
    V2,
    V3,
}

fn encrypt(sender: &Keys, recipient: &PublicKey, plaintext: &str, context: u32, cipher: Cipher) -> String {
    match cipher {
        Cipher::V2 => nip44v2::encrypt(sender.secret_key(), recipient, plaintext, Version::V2)
            .expect("synthetic v2 encryption"),
        Cipher::V3 => {
            let secret = secp256k1::SecretKey::from_byte_array(sender.secret_key().to_secret_bytes())
                .expect("synthetic secret key");
            let public = secp256k1::XOnlyPublicKey::from_byte_array(*recipient.as_bytes())
                .expect("synthetic public key");
            let key = nip44::get_conversation_key_v3(secret, public);
            nip44::encrypt_v3(&key, plaintext.as_bytes(), context, b"")
                .expect("synthetic v3 encryption")
        }
    }
}

fn rumor(sender: &Keys, recipient: &PublicKey) -> UnsignedEvent {
    let mut rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
        .tag(Tag::public_key(*recipient))
        .build(sender.public_key());
    rumor.ensure_id();
    rumor
}

fn gift_wrap(
    sender: &Keys,
    recipient: &PublicKey,
    rumor: &UnsignedEvent,
    seal_kind: Kind,
    cipher: Cipher,
    extra_tags: Vec<Tag>,
) -> Event {
    let seal_ciphertext = encrypt(sender, recipient, &rumor.as_json(), 13, cipher);
    let seal = EventBuilder::new(seal_kind, seal_ciphertext)
        .sign_with_keys(sender)
        .expect("synthetic signed seal");
    assert!(seal.verify().is_ok());
    let ephemeral = Keys::generate();
    let outer_ciphertext = encrypt(&ephemeral, recipient, &seal.as_json(), 1059, cipher);
    let event = EventBuilder::new(Kind::GiftWrap, outer_ciphertext)
        .tag(Tag::public_key(*recipient))
        .tags(extra_tags)
        .sign_with_keys(&ephemeral)
        .expect("synthetic signed gift wrap");
    assert!(event.verify().is_ok());
    event
}

#[tokio::test]
async fn v2_non_seal_kind_is_rejected() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let rumor = rumor(&alice, &bob.public_key());
    let valid = gift_wrap(&alice, &bob.public_key(), &rumor, Kind::Seal, Cipher::V2, vec![]);
    assert!(unwrap_from_contact(&bob, &valid, &alice.public_key()).await.is_ok());
    let malformed = gift_wrap(&alice, &bob.public_key(), &rumor, Kind::TextNote, Cipher::V2, vec![]);
    assert!(unwrap_from_contact(&bob, &malformed, &alice.public_key()).await.is_err());
}

async fn rejects_forged_rumor_id(cipher: Cipher) {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let mut rumor = rumor(&alice, &bob.public_key());
    let valid = gift_wrap(&alice, &bob.public_key(), &rumor, Kind::Seal, cipher, vec![]);
    assert!(unwrap_from_contact(&bob, &valid, &alice.public_key()).await.is_ok());
    rumor.id = Some(EventId::from_hex(&"ff".repeat(32)).expect("synthetic event id"));
    assert!(rumor.verify_id().is_err());
    let malformed = gift_wrap(&alice, &bob.public_key(), &rumor, Kind::Seal, cipher, vec![]);
    assert!(unwrap_from_contact(&bob, &malformed, &alice.public_key()).await.is_err());
}

#[tokio::test]
async fn v2_forged_rumor_id_is_rejected() {
    rejects_forged_rumor_id(Cipher::V2).await;
}

#[tokio::test]
async fn v3_forged_rumor_id_is_rejected() {
    rejects_forged_rumor_id(Cipher::V3).await;
}

#[tokio::test]
async fn malformed_extra_p_tag_is_rejected() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let rumor = rumor(&alice, &bob.public_key());
    let valid = gift_wrap(&alice, &bob.public_key(), &rumor, Kind::Seal, Cipher::V3, vec![]);
    assert!(unwrap_from_contact(&bob, &valid, &alice.public_key()).await.is_ok());
    // Tag::parse retains raw syntactically valid tag arrays even when their p
    // value is not a public key. It is nevertheless covered by outer signature.
    let extra = Tag::parse(["p", "not-a-public-key"]).expect("raw p tag");
    let malformed = gift_wrap(&alice, &bob.public_key(), &rumor, Kind::Seal, Cipher::V3, vec![extra]);
    assert_eq!(malformed.tags.public_keys().count(), 1);
    assert!(unwrap_from_contact(&bob, &malformed, &alice.public_key()).await.is_err());
}
