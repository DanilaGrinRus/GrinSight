//! The real transport process, started the way the wallet starts it.
use fly_paycore_mailbox::Mailbox;
use fly_paycore_mailbox_pipe::{Config, PipeMailbox};
use nostr_sdk::Keys;
use std::path::Path;
use std::time::{Duration, Instant};

const PROGRAM: &str = env!("CARGO_BIN_EXE_fly-mailbox");

fn config(data_dir: &str, start_secs: u32) -> Config {
    let me = Keys::generate();
    Config {
        identity_secret: me.secret_key().to_secret_bytes(),
        identity_public: me.public_key().to_bytes(),
        store_key: [9; 32],
        relay: "wss://relay.invalid".into(),
        data_dir: data_dir.into(),
        contacts: vec![Keys::generate().public_key().to_bytes()],
        delivery_window_secs: 600,
        publish_timeout_ms: 2000,
        poll_ms: 200,
        start_timeout_secs: start_secs,
        tor_bridges: String::new(),
    }
}

/// The process speaks the protocol and refuses, before touching the network,
/// a start-up message it cannot use.
#[test]
fn the_process_refuses_an_unusable_configuration_without_network() {
    let started = Instant::now();
    let r = PipeMailbox::spawn(Path::new(PROGRAM), &config("relative/dir", 30), Duration::from_secs(10));
    assert_eq!(
        r.err().as_deref(),
        Some("the transport did not start: the data directory must exist and be given in full")
    );
    let mut zero = config("relative/dir", 30);
    zero.identity_secret = [0; 32];
    let r = PipeMailbox::spawn(Path::new(PROGRAM), &zero, Duration::from_secs(10));
    assert_eq!(r.err().as_deref(), Some("the transport did not start: the identity key is not usable"));
    // a public key that does not belong to the secret
    let mut other = config("relative/dir", 30);
    other.identity_public = Keys::generate().public_key().to_bytes();
    let r = PipeMailbox::spawn(Path::new(PROGRAM), &other, Duration::from_secs(10));
    assert_eq!(r.err().as_deref(), Some("the transport did not start: the identity key is not usable"));
    assert!(started.elapsed() < Duration::from_secs(10), "it waited for the network: {:?}", started.elapsed());
}

/// Brings up Tor for real and seals one message. Uses the network: run it on
/// purpose with `cargo test -- --ignored`.
#[test]
#[ignore = "bootstraps Tor over the network"]
fn live_the_process_brings_up_tor_and_seals() {
    let dir = std::env::temp_dir().join(format!("fly-mailbox-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let c = config(&dir.to_string_lossy(), 180);
    let to = c.contacts[0];
    let started = Instant::now();
    let mut m = PipeMailbox::spawn(Path::new(PROGRAM), &c, Duration::from_secs(30)).expect("the transport did not start");
    println!("Tor came up in {:?}", started.elapsed());
    let envelope = m
        .seal(&to, "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY GWmtgsneoXf7N4D uVWuyZSamPhfF1u AHRaYWvhF7jQvKx wNJAc7qmVm9JVcm NJLEw4k5BU7jY6S eb. ENDSLATEPACK.")
        .unwrap();
    assert!(!envelope.bytes.is_empty());
    // the relay does not exist: honest "unknown", through Tor
    println!("publish to a relay that does not exist: {:?}", m.publish(&envelope));
    assert!(m.next_incoming().is_none());
    drop(m);
    let _ = std::fs::remove_dir_all(&dir);
}
