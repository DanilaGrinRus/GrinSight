//! Offline interface test against the unmodified Goblin source snapshot at
//! commit bc62dd68ebd7a7d09ee753ecb5ea209266e21730. This exercises message
//! codecs, not the Goblin application, its wallet, Tor or a public relay.
#[path = "fixtures/goblin-bc62dd68/protocol.rs"]
pub mod goblin_protocol;
#[path = "fixtures/goblin-bc62dd68/sanitize.rs"]
pub mod goblin_sanitize;
#[path = "fixtures/goblin-bc62dd68/wrapv3.rs"]
pub mod goblin_wrapv3;

// The snapshot's modules refer to their original crate paths.
mod nostr {
    pub use crate::goblin_protocol as protocol;
    pub use crate::goblin_sanitize as sanitize;
}

use fly_nostr_research::nostr::{protocol as fly_protocol, verified_unwrap, wrapv3 as fly_wrap};
use nostr_sdk::{EventBuilder, Keys, Kind, Tag};

// Called by the isolated chain runner. Only fixed disposable test identities
// can be used. Neither the envelope nor its plaintext is written to a log.
#[tokio::test]
async fn chain_slatepack_interop_peer() {
    use std::io::{Read, Write};
    use nostr_sdk::{Event, JsonUtil};
    let direction = match std::env::var("FLY_TEST_GOBLIN_DIRECTION") {
        Ok(value) => value,
        Err(_) => return,
    };
    let mut data = Vec::new();
    std::io::stdin().take(131_073).read_to_end(&mut data).unwrap();
    assert!(data.len() <= 131_072);
    let event = Event::from_json(&data).unwrap();
    event.verify().unwrap();
    let keys = |last: u8| Keys::parse(&format!("{last:064x}")).unwrap();
    let (sender, recipient) = match direction.as_str() {
        "s1" => (keys(1), keys(2)),
        "s2" => (keys(2), keys(1)),
        _ => panic!("unknown test direction"),
    };
    let decoded = goblin_wrapv3::unwrap(&recipient, &event).await.unwrap();
    assert_eq!(decoded.sender, sender.public_key());
    let armor = goblin_protocol::extract_slatepack(&decoded.rumor.content).unwrap();
    let encoded = goblin_wrapv3::wrap(&sender, &recipient.public_key(),
        goblin_protocol::build_payment_content(&armor), goblin_protocol::build_rumor_tags(None)).unwrap();
    let binary: String = encoded.as_json().bytes().map(|c| format!("{c:02x}")).collect();
    writeln!(std::io::stdout(), "FLY_GOBLIN_EVENT={binary}").unwrap();
}

#[tokio::test]
async fn goblin_and_fly_exchange_v2_and_v3_payment_messages() {
    let goblin = Keys::generate(); let fly = Keys::generate(); let outsider = Keys::generate();
    let armor = "BEGINSLATEPACK. synthetic ENDSLATEPACK.";
    let goblin_text = goblin_protocol::build_payment_content(armor);
    let goblin_event = goblin_wrapv3::wrap(&goblin, &fly.public_key(), goblin_text,
        goblin_protocol::build_rumor_tags(Some("test"))).unwrap();
    let opened = verified_unwrap::unwrap_from_contact(&fly, &goblin_event, &goblin.public_key()).await.unwrap();
    assert_eq!(fly_protocol::extract_slatepack(&opened.rumor.content).as_deref(), Some(armor));
    assert!(verified_unwrap::unwrap_from_contact(&fly, &goblin_event, &outsider.public_key()).await.is_err());

    let fly_text = fly_protocol::build_payment_content(armor);
    let rumor = EventBuilder::new(Kind::PrivateDirectMessage, fly_text.clone())
        .tag(Tag::public_key(goblin.public_key())).tags(fly_protocol::build_rumor_tags(None))
        .build(fly.public_key());
    let v2 = EventBuilder::gift_wrap(&fly, &goblin.public_key(), rumor, []).await.unwrap();
    let v3 = fly_wrap::wrap(&fly, &goblin.public_key(), fly_text, fly_protocol::build_rumor_tags(None)).unwrap();
    for event in [v2, v3] {
        let opened = goblin_wrapv3::unwrap(&goblin, &event).await.unwrap();
        assert_eq!(opened.sender, fly.public_key());
        assert_eq!(goblin_protocol::extract_slatepack(&opened.rumor.content).as_deref(), Some(armor));
        assert!(goblin_wrapv3::unwrap(&outsider, &event).await.is_err());
    }
}
