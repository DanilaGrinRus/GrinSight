//! Local, synthetic negative tests for the copied upstream v3 implementation.
//! No network, real identities, wallet keys, or payment processing.
use base64::{engine::general_purpose::STANDARD, Engine};
use fly_nostr_research::nostr::wrapv3;
use nostr_sdk::{Event, EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag};

fn conversation_key(sender: &Keys, receiver: &PublicKey) -> [u8; 32] {
    let secret = secp256k1::SecretKey::from_byte_array(sender.secret_key().to_secret_bytes())
        .expect("synthetic secret");
    let public = secp256k1::XOnlyPublicKey::from_byte_array(*receiver.as_bytes())
        .expect("synthetic public key");
    nip44::get_conversation_key_v3(secret, public)
}

fn make_seal(signer: &Keys, rumor_author: &Keys, recipient: &PublicKey) -> Event {
    let mut rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
        .tag(Tag::public_key(*recipient))
        .build(rumor_author.public_key());
    rumor.ensure_id();
    let key = conversation_key(signer, recipient);
    let ciphertext = nip44::encrypt_v3(&key, rumor.as_json().as_bytes(), 13, b"")
        .expect("encrypt synthetic rumor");
    EventBuilder::new(Kind::Seal, ciphertext)
        .sign_with_keys(signer)
        .expect("sign synthetic seal")
}

fn make_wrap(seal: &Event, recipient: &PublicKey, wrap_kind: u32) -> Event {
    let ephemeral = Keys::generate();
    let key = conversation_key(&ephemeral, recipient);
    let ciphertext = nip44::encrypt_v3(&key, seal.as_json().as_bytes(), wrap_kind, b"")
        .expect("encrypt synthetic seal");
    EventBuilder::new(Kind::GiftWrap, ciphertext)
        .tag(Tag::public_key(*recipient))
        .sign_with_keys(&ephemeral)
        .expect("sign synthetic wrap")
}

#[tokio::test]
async fn invalid_inner_seal_signature_is_rejected() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let mut seal = make_seal(&alice, &alice, &bob.public_key());
    // Alter signed content, then encrypt it into a correctly signed outer event.
    seal.content.push('A');
    assert!(seal.verify().is_err());
    let wrap = make_wrap(&seal, &bob.public_key(), 1059);
    assert!(wrap.verify().is_ok());
    assert!(wrapv3::unwrap(&bob, &wrap).await.is_err());
}

#[tokio::test]
async fn signed_seal_with_a_different_rumor_author_is_rejected() {
    let alice = Keys::generate();
    let mallory = Keys::generate();
    let bob = Keys::generate();
    let seal = make_seal(&alice, &mallory, &bob.public_key());
    assert!(seal.verify().is_ok());
    let wrap = make_wrap(&seal, &bob.public_key(), 1059);
    assert!(wrap.verify().is_ok());
    assert!(wrapv3::unwrap(&bob, &wrap).await.is_err());
}

#[tokio::test]
async fn wrong_recipient_or_wrong_v3_context_is_rejected() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let mallory = Keys::generate();
    let seal = make_seal(&alice, &alice, &bob.public_key());
    let valid = make_wrap(&seal, &bob.public_key(), 1059);
    assert!(wrapv3::unwrap(&bob, &valid).await.is_ok());
    assert!(wrapv3::unwrap(&mallory, &valid).await.is_err());
    // A correctly signed outer event with the wrong AEAD context must fail.
    let wrong_context = make_wrap(&seal, &bob.public_key(), 13);
    assert!(wrong_context.verify().is_ok());
    assert!(wrapv3::unwrap(&bob, &wrong_context).await.is_err());
}

#[tokio::test]
async fn altered_ciphertext_with_a_valid_outer_signature_is_rejected() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let ephemeral = Keys::generate();
    let seal = make_seal(&alice, &alice, &bob.public_key());
    let key = conversation_key(&ephemeral, &bob.public_key());
    let ciphertext = nip44::encrypt_v3(&key, seal.as_json().as_bytes(), 1059, b"")
        .expect("encrypt synthetic seal");
    let mut decoded = STANDARD.decode(ciphertext).expect("valid base64");
    let index = decoded.len() / 2;
    decoded[index] ^= 1;
    let wrap = EventBuilder::new(Kind::GiftWrap, STANDARD.encode(decoded))
        .tag(Tag::public_key(bob.public_key()))
        .sign_with_keys(&ephemeral)
        .expect("sign altered wrap");
    assert!(wrap.verify().is_ok());
    assert!(wrapv3::unwrap(&bob, &wrap).await.is_err());
}

#[tokio::test]
async fn outer_signature_requires_a_separate_input_boundary_check() {
    let alice = Keys::generate();
    let bob = Keys::generate();
    let mut wrap = wrapv3::wrap(&alice, &bob.public_key(), "synthetic".into(), vec![])
        .expect("synthetic wrap");
    assert!(wrap.verify().is_ok());
    // Tags are signed but are not part of either encrypted layer. The copied
    // upstream seam does not check the outer signature; callers must do so
    // before using the result. This test captures that boundary explicitly.
    wrap.tags = Default::default();
    assert!(wrap.verify().is_err());
    assert!(wrapv3::unwrap(&bob, &wrap).await.is_ok());
}
