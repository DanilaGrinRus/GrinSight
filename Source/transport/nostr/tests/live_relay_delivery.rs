//! Explicitly opted-in public-relay test with ephemeral test keys only.
#![cfg(not(target_arch = "wasm32"))]
use std::{path::PathBuf, time::Duration};
use fly_nostr_research::nostr::contact_session::{ContactSession, Publication};
use fly_nostr_research::nostr::{queue_record::{Network, QueueIdentity, QueueKey}, queue_store};
use fly_tor::SharedTor;
use nostr_sdk::Keys;

#[test]
#[ignore = "publishes one encrypted synthetic event to a public relay over Tor"]
fn live_two_clients_deliver_v2_via_tor() {
    assert_eq!(std::env::var("FLY_ALLOW_TOR_NOSTR_DELIVERY").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("FLY_ROOT").expect("FLY_ROOT required"));
    let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    assert_eq!(temp, std::fs::canonicalize(root.join(".tmp")).unwrap());
    let name = format!("fly-nostr-delivery-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    let tor_dir = temp.join(name);
    std::fs::create_dir(&tor_dir).unwrap();
    let relay = std::env::var("FLY_TEST_NOSTR_RELAY").expect("test relay required");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let tor = SharedTor::bootstrap(&tor_dir, Duration::from_secs(120)).await.expect("bootstrap");
        let alice = Keys::generate(); let bob = Keys::generate();
        let sender = ContactSession::connect(tor.clone(), alice.clone(), bob.public_key(), &relay, Duration::from_secs(90))
            .await.expect("sender session");
        let mut recipient = ContactSession::connect(tor, bob.clone(), alice.public_key(), &relay, Duration::from_secs(90))
            .await.expect("recipient session");
        let text = "GrinSight Fly synthetic self-test";
        let prepared = sender.prepare(text).await.expect("prepare");
        let queue_dir = tor_dir.join("synthetic-outbox");
        std::fs::create_dir(&queue_dir).expect("synthetic queue dir");
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot: [3; 16],
            sender: alice.public_key(), recipient: bob.public_key() };
        let key = QueueKey::derive(&[9; 32], &identity).expect("synthetic key");
        queue_store::persist(&queue_dir, &key, &identity, &prepared, nostr_sdk::Timestamp::now().as_secs()).expect("persist");
        assert_eq!(sender.publish_stored(&queue_dir, &key, &identity, Duration::from_secs(45)).await.expect("publish"), Publication::RelayAccepted);
        assert_eq!(recipient.receive(Duration::from_secs(45)).await.expect("receive"), text);
        sender.close().await;
        recipient.close().await;
    });
}

#[test]
#[ignore = "publishes one encrypted synthetic event to a public relay over Tor"]
fn live_offline_recipient_fetches_stored_event() {
    assert_eq!(std::env::var("FLY_ALLOW_TOR_NOSTR_DELIVERY").as_deref(), Ok("1"));
    let root = PathBuf::from(std::env::var_os("FLY_ROOT").expect("FLY_ROOT required"));
    let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
    assert_eq!(temp, std::fs::canonicalize(root.join(".tmp")).unwrap());
    let name = format!("fly-nostr-offline-{}-{}", std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
    let tor_dir = temp.join(name); std::fs::create_dir(&tor_dir).unwrap();
    let relay = std::env::var("FLY_TEST_NOSTR_RELAY").expect("test relay required");
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let tor = SharedTor::bootstrap(&tor_dir, Duration::from_secs(120)).await.expect("bootstrap");
        let alice = Keys::generate(); let bob = Keys::generate();
        let sender = ContactSession::connect(tor.clone(), alice.clone(), bob.public_key(), &relay, Duration::from_secs(90))
            .await.expect("sender session");
        let text = "GrinSight Fly offline-recipient self-test";
        let prepared = sender.prepare(text).await.expect("prepare");
        let queue_dir = tor_dir.join("synthetic-outbox"); std::fs::create_dir(&queue_dir).unwrap();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot: [3; 16],
            sender: alice.public_key(), recipient: bob.public_key() };
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        queue_store::persist(&queue_dir, &key, &identity, &prepared, nostr_sdk::Timestamp::now().as_secs()).unwrap();
        assert_eq!(sender.publish_stored(&queue_dir, &key, &identity, Duration::from_secs(45)).await.unwrap(), Publication::RelayAccepted);
        sender.close().await;
        // Only now is the recipient session created and subscribed.
        let mut recipient = ContactSession::connect(tor, bob, alice.public_key(), &relay, Duration::from_secs(90))
            .await.expect("recipient session");
        assert_eq!(recipient.receive(Duration::from_secs(45)).await.expect("offline delivery"), text);
        recipient.close().await;
    });
}
