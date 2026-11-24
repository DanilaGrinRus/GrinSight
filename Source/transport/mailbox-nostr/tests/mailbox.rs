//! The mailbox against a small relay on the loopback interface: two
//! profiles, real gift wraps, real WebSocket connections, no Tor.
use fly_mailbox_nostr::store::{ReplyStore, StoreError, StoredReply, MAX_REPLIES};
use fly_mailbox_nostr::{Connecting, Connector, NostrMailbox, Timing, RECONNECT_AFTER, RECONNECT_MAX};
use fly_nostr_research::nostr::contact_session::{ContactSession, Note};
use fly_paycore_mailbox::{Mailbox, Published};
use futures_util::{SinkExt, StreamExt};
use nostr_sdk::{ClientMessage, Event, JsonUtil, Keys, PublicKey};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_tungstenite::tungstenite::Message as Wire;

const S1: &str = "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY GWmtgsneoXf7N4D uVWuyZSamPhfF1u AHRaYWvhF7jQvKx wNJAc7qmVm9JVcm NJLEw4k5BU7jY6S eb. ENDSLATEPACK.";
const S2: &str = "BEGINSLATEPACK. 5H1qx1wHe668tFW yC2gfL8PPd8kSgv pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY GWmtgsneoXf7N4D uVWuyZSamPhfF1u AHRaYWvhF7jQvKx wNJAc7qmVm9JVcm NJLEw4k5BU7jY6S eb. ENDSLATEPACK.";
const OTHER: &str = "BEGINSLATEPACK. 6H1qx1wHe668tFW yC2gfL8PPd8kSgv pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY GWmtgsneoXf7N4D uVWuyZSamPhfF1u AHRaYWvhF7jQvKx wNJAc7qmVm9JVcm NJLEw4k5BU7jY6S eb. ENDSLATEPACK.";

const UP: u8 = 0;
/// Takes the event and says nothing; the event is lost.
const DOWN: u8 = 1;
/// Stores the event, but the acknowledgement is lost.
const SILENT: u8 = 2;
/// Answers every event with a refusal in its own words.
const REFUSING: u8 = 3;
/// What the refusing relay says, as it stands in its JSON answer.
/// Anybody's text: a control character, a letter of another script, and
/// (with what is appended to it) more than anyone should be shown.
const REFUSAL: &str = "blocked: not\\u0007 on the list \\u0444";

#[derive(Default)]
struct RelayState {
    mode: AtomicU8,
    events: Mutex<Vec<Event>>,
    subs: Mutex<Vec<(String, UnboundedSender<String>)>>,
    publishes: AtomicU32,
    connections: AtomicU32,
    /// Reads and writes only for a connection that has proved its key (NIP-42).
    auth: std::sync::atomic::AtomicBool,
    /// Keys that have proved themselves, in order.
    authed: Mutex<Vec<PublicKey>>,
    refusals: AtomicU32,
    /// Takes a gift wrap only if it carries its addressee and nothing else,
    /// in the words of the relay that taught us this.
    strict: std::sync::atomic::AtomicBool,
}
struct Relay {
    url: String,
    state: Arc<RelayState>,
}
impl Relay {
    fn start() -> Relay {
        let state = Arc::new(RelayState::default());
        let shared = state.clone();
        let (ready, port) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                ready.send(listener.local_addr().unwrap().port()).unwrap();
                loop {
                    let (socket, peer) = listener.accept().await.unwrap();
                    assert!(peer.ip().is_loopback());
                    let state = shared.clone();
                    tokio::spawn(async move {
                        let Ok(ws) = tokio_tungstenite::accept_async(socket).await else { return };
                        state.connections.fetch_add(1, Ordering::SeqCst);
                        let (mut sink, mut stream) = ws.split();
                        let (out, mut outbox) = unbounded_channel::<String>();
                        // the challenge comes with the first refusal, not with
                        // the greeting: whatever the client sends first is
                        // certain to be turned away once
                        let mut proved = !state.auth.load(Ordering::SeqCst);
                        let challenge = "[\"AUTH\",\"a-challenge-for-this-connection\"]".to_string();
                        tokio::spawn(async move {
                            while let Some(text) = outbox.recv().await {
                                if sink.send(Wire::Text(text.into())).await.is_err() {
                                    return;
                                }
                            }
                        });
                        while let Some(Ok(frame)) = stream.next().await {
                            let Wire::Text(text) = frame else { continue };
                            match ClientMessage::from_json(text.as_str()) {
                                Ok(ClientMessage::Auth(event)) => {
                                    let good = event.verify().is_ok()
                                        && event.kind == nostr_sdk::Kind::Authentication
                                        && event.as_json().contains("a-challenge-for-this-connection");
                                    if good {
                                        proved = true;
                                        state.authed.lock().unwrap().push(event.pubkey);
                                    }
                                    let _ = out.send(format!("[\"OK\",\"{}\",{good},\"\"]", event.id));
                                }
                                Ok(ClientMessage::Req { subscription_id, .. }) if !proved => {
                                    state.refusals.fetch_add(1, Ordering::SeqCst);
                                    let _ = out.send(format!(
                                        "[\"CLOSED\",\"{subscription_id}\",\"auth-required: prove who is reading\"]"
                                    ));
                                    let _ = out.send(challenge.clone());
                                }
                                Ok(ClientMessage::Event(event)) if !proved => {
                                    state.refusals.fetch_add(1, Ordering::SeqCst);
                                    let _ = out.send(format!(
                                        "[\"OK\",\"{}\",false,\"auth-required: prove who is writing\"]",
                                        event.id
                                    ));
                                    let _ = out.send(challenge.clone());
                                }
                                Ok(ClientMessage::Req { subscription_id, .. }) => {
                                    let sub = subscription_id.to_string();
                                    for e in state.events.lock().unwrap().iter() {
                                        let _ = out.send(format!("[\"EVENT\",\"{sub}\",{}]", e.as_json()));
                                    }
                                    let _ = out.send(format!("[\"EOSE\",\"{sub}\"]"));
                                    state.subs.lock().unwrap().push((sub, out.clone()));
                                }
                                Ok(ClientMessage::Event(event)) => {
                                    state.publishes.fetch_add(1, Ordering::SeqCst);
                                    let mode = state.mode.load(Ordering::SeqCst);
                                    if mode == DOWN || event.verify().is_err() {
                                        continue;
                                    }
                                    if state.strict.load(Ordering::SeqCst) && event.tags.len() != 1 {
                                        state.refusals.fetch_add(1, Ordering::SeqCst);
                                        let _ = out.send(format!(
                                            "[\"OK\",\"{}\",false,\"blocked: expiration not allowed on gift wraps\"]",
                                            event.id
                                        ));
                                        continue;
                                    }
                                    if mode == REFUSING {
                                        let _ = out.send(format!("[\"OK\",\"{}\",false,\"{REFUSAL}{}\"]", event.id, "!".repeat(400)));
                                        continue;
                                    }
                                    let fresh = {
                                        let mut events = state.events.lock().unwrap();
                                        let fresh = !events.iter().any(|e| e.id == event.id);
                                        if fresh {
                                            events.push(event.as_ref().clone());
                                        }
                                        fresh
                                    };
                                    if fresh {
                                        for (sub, to) in state.subs.lock().unwrap().iter() {
                                            let _ = to.send(format!("[\"EVENT\",\"{sub}\",{}]", event.as_json()));
                                        }
                                    }
                                    if mode == UP {
                                        let _ = out.send(format!("[\"OK\",\"{}\",true,\"\"]", event.id));
                                    }
                                }
                                _ => {}
                            }
                        }
                    });
                }
            });
        });
        Relay {
            url: format!("ws://127.0.0.1:{}", port.recv().unwrap()),
            state,
        }
    }
    fn stored(&self) -> Vec<Event> {
        self.state.events.lock().unwrap().clone()
    }
    fn set(&self, mode: u8) {
        self.state.mode.store(mode, Ordering::SeqCst);
    }
}

struct Loopback {
    relay: String,
}
/// An address where nothing listens, and how often it was tried.
const NOBODY: &str = "ws://127.0.0.1:1";
static KNOCKS: AtomicU32 = AtomicU32::new(0);
impl Connector for Loopback {
    fn connect<'a>(&'a mut self, keys: &'a Keys, contact: PublicKey, note: &'a Note) -> Connecting<'a> {
        if self.relay == NOBODY {
            KNOCKS.fetch_add(1, Ordering::SeqCst);
        }
        Box::pin(ContactSession::connect_loopback_noted(
            keys.clone(),
            contact,
            &self.relay,
            Duration::from_secs(5),
            note,
        ))
    }
}

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str) -> Temp {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("fly-mailbox-{tag}-{}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(&p).unwrap();
        Temp(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
/// Ask until a message is there.
fn wait_incoming(m: &mut NostrMailbox<Loopback>) -> fly_paycore_mailbox::Incoming {
    let until = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(found) = m.next_incoming() {
            return found;
        }
        assert!(std::time::Instant::now() < until, "no message arrived");
    }
}
fn timing() -> Timing {
    Timing {
        delivery_window: Duration::from_secs(600),
        publish_timeout: Duration::from_secs(2),
        poll: Duration::from_millis(300),
        ..Timing::default()
    }
}
fn mailbox(keys: &Keys, contacts: &[&Keys], relay: &str, dir: &Temp, timing: Timing) -> NostrMailbox<Loopback> {
    let contacts: Vec<[u8; 32]> = contacts.iter().map(|k| k.public_key().to_bytes()).collect();
    NostrMailbox::new(
        keys.clone(),
        &contacts,
        Loopback { relay: relay.to_string() },
        ReplyStore::open(&dir.0, [9; 32]).unwrap(),
        timing,
    )
    .unwrap()
}
fn id_of(bytes: &[u8]) -> [u8; 32] {
    *Event::from_json(std::str::from_utf8(bytes).unwrap()).unwrap().id.as_bytes()
}

/// A payment message goes out, the reply comes back, and every repeat on
/// the way is the same message.
#[test]
fn a_message_crosses_and_the_reply_comes_back() {
    let relay = Relay::start();
    let (alice, bob) = (Keys::generate(), Keys::generate());
    let (da, db) = (Temp::new("a"), Temp::new("b"));
    let mut a = mailbox(&alice, &[&bob], &relay.url, &da, timing());
    let mut b = mailbox(&bob, &[&alice], &relay.url, &db, timing());
    let to_bob = bob.public_key().to_bytes();
    let from_alice = alice.public_key().to_bytes();

    // sealing touches neither the relay nor the text's privacy
    let envelope = a.seal(&to_bob, S1).unwrap();
    assert_eq!(relay.state.connections.load(Ordering::SeqCst), 0, "sealing connected to the relay");
    assert_eq!(envelope.event_id, id_of(&envelope.bytes));
    assert!(!String::from_utf8_lossy(&envelope.bytes).contains("BEGINSLATEPACK"));
    assert!(!String::from_utf8_lossy(&envelope.bytes).contains("expiration"));
    assert_ne!(a.seal(&to_bob, S1).unwrap().event_id, envelope.event_id);

    assert_eq!(a.publish(&envelope), Published::Accepted);
    assert_eq!(a.publish(&envelope), Published::Accepted);
    assert_eq!(relay.stored().len(), 1, "a repeat became a second message");
    assert_eq!(*relay.stored()[0].id.as_bytes(), envelope.event_id);

    // the recipient gets it, again and again until it says it is done
    let got = b.next_incoming().expect("nothing arrived");
    assert_eq!((got.id, got.from, got.text.as_str()), (envelope.event_id, from_alice, S1));
    assert!(b.next_incoming().is_none(), "the same message twice in one round");
    assert_eq!(b.next_incoming().map(|m| m.id), Some(envelope.event_id));
    assert!(b.next_incoming().is_none());

    // nothing is stored for it yet
    assert_eq!(b.resend_reply(&got.id), None);
    assert_eq!(b.reply(&got.id, S2), Published::Accepted);
    assert_eq!(relay.stored().len(), 2);
    let reply_id = *relay.stored()[1].id.as_bytes();
    // asked again, the mailbox sends the stored reply, not a new one
    assert_eq!(b.resend_reply(&got.id), Some(Published::Accepted));
    assert_eq!(b.reply(&got.id, OTHER), Published::Accepted);
    assert_eq!(relay.stored().len(), 2, "the reply was built again");
    b.done(&got.id);
    assert!(b.next_incoming().is_none());
    assert!(b.next_incoming().is_none(), "a finished message came again");

    let back = a.next_incoming().expect("the reply did not arrive");
    assert_eq!((back.id, back.from, back.text.as_str()), (reply_id, to_bob, S2));
    a.done(&back.id);
    assert!(a.next_incoming().is_none());
    assert!(a.next_incoming().is_none());
}

/// Whatever the relay does, the answer is honest: accepted only when the
/// relay said so, and a later retry is the same event.
#[test]
fn relay_trouble_is_reported_as_it_is() {
    let relay = Relay::start();
    let (alice, bob) = (Keys::generate(), Keys::generate());
    let (da, db, dc) = (Temp::new("a"), Temp::new("b"), Temp::new("c"));
    let mut a = mailbox(&alice, &[&bob], &relay.url, &da, timing());
    let to_bob = bob.public_key().to_bytes();
    let envelope = a.seal(&to_bob, S1).unwrap();

    relay.set(DOWN);
    assert_eq!(a.publish(&envelope), Published::Unknown);
    assert!(relay.stored().is_empty());
    relay.set(SILENT);
    assert_eq!(a.publish(&envelope), Published::Unknown);
    assert_eq!(relay.stored().len(), 1);
    relay.set(UP);
    assert_eq!(a.publish(&envelope), Published::Accepted);
    assert_eq!(relay.stored().len(), 1);
    assert!(relay.state.publishes.load(Ordering::SeqCst) >= 3);

    // no relay at all: sealing still works, publishing is "unknown"
    let mut offline = mailbox(&alice, &[&bob], "ws://127.0.0.1:9", &dc, timing());
    let sealed = offline.seal(&to_bob, S1).unwrap();
    assert_eq!(offline.publish(&sealed), Published::Unknown);
    assert!(offline.next_incoming().is_none());

    // what is refused before the network
    assert!(a.seal(&Keys::generate().public_key().to_bytes(), S1).is_err(), "sealed for a stranger");
    assert!(a.seal(&to_bob, "{\"not\":\"armor\"}").is_err());
    let mut junk = envelope.clone();
    junk.bytes = b"{}".to_vec();
    let before = relay.state.publishes.load(Ordering::SeqCst);
    assert_eq!(a.publish(&junk), Published::Unknown);
    let mut tampered = envelope.clone();
    let at = tampered.bytes.len() / 2;
    tampered.bytes[at] = if tampered.bytes[at] == b'a' { b'b' } else { b'a' };
    assert_eq!(a.publish(&tampered), Published::Unknown);
    assert_eq!(relay.state.publishes.load(Ordering::SeqCst), before, "a bad envelope reached the relay");

    // a closed delivery window is said to be closed
    let short = Timing { delivery_window: Duration::from_secs(1), ..timing() };
    let mut hasty = mailbox(&alice, &[&bob], &relay.url, &db, short);
    let late = hasty.seal(&to_bob, S1).unwrap();
    std::thread::sleep(Duration::from_millis(2100));
    assert_eq!(hasty.publish(&late), Published::Expired);
    assert_eq!(relay.stored().len(), 1);
}

/// A reply that could not be sent survives a restart and is sent as it was.
/// A relay that lets only proven keys read and write (NIP-42) is answered
/// with the profile's key, without anyone being asked, and then works like
/// any other. Being asked to prove the key is not a failure.
#[test]
fn a_relay_that_asks_for_authentication_is_answered() {
    let relay = Relay::start();
    relay.state.auth.store(true, Ordering::SeqCst);
    let (ka, kb) = (Keys::generate(), Keys::generate());
    let (da, db) = (Temp::new("auth-a"), Temp::new("auth-b"));
    let mut a = mailbox(&ka, &[&kb], &relay.url, &da, timing());
    let mut b = mailbox(&kb, &[&ka], &relay.url, &db, timing());
    let b_key = kb.public_key().to_bytes();

    let sealed = a.seal(&b_key, S1).unwrap();
    let outcome = a.publish(&sealed);
    assert_eq!((outcome, a.problem()), (Published::Accepted, None));
    let got = wait_incoming(&mut b);
    assert_eq!((got.from, got.text.as_str()), (ka.public_key().to_bytes(), S1));
    assert_eq!(b.reply(&got.id, S2), Published::Accepted);
    b.done(&got.id);
    let back = wait_incoming(&mut a);
    assert_eq!((back.from, back.text.as_str()), (b_key, S2));
    assert_eq!((a.problem(), b.problem()), (None, None));
    // each side proved its own key and no other; the relay did turn both
    // away before that
    let authed = relay.state.authed.lock().unwrap().clone();
    assert!(authed.contains(&ka.public_key()) && authed.contains(&kb.public_key()));
    assert!(authed.iter().all(|k| *k == ka.public_key() || *k == kb.public_key()));
    assert!(relay.state.refusals.load(Ordering::SeqCst) >= 2, "the relay turns each side away once");
    assert_eq!(relay.state.connections.load(Ordering::SeqCst), 2, "one connection each, not one per attempt");
}

/// What a relay sees of a payment is a gift wrap with its addressee and
/// nothing else: no deadline for the relay to object to or to tell our
/// messages by. The deadline is inside; a message that is read after it has
/// passed is not taken, and a reply past its deadline is not sent.
#[test]
fn the_deadline_travels_inside_the_envelope() {
    let relay = Relay::start();
    relay.state.strict.store(true, Ordering::SeqCst);
    let (ka, kb) = (Keys::generate(), Keys::generate());
    let (da, db) = (Temp::new("inside-a"), Temp::new("inside-b"));
    let brief = Timing { delivery_window: Duration::from_secs(2), ..timing() };
    let mut a = mailbox(&ka, &[&kb], &relay.url, &da, brief);
    let b_key = kb.public_key().to_bytes();

    let began = std::time::Instant::now();
    let sealed = a.seal(&b_key, S1).unwrap();
    assert!(!String::from_utf8_lossy(&sealed.bytes).contains("expiration"));
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert!((now + 1..=now + 3).contains(&sealed.expires_at), "the caller is told the deadline");
    let outcome = a.publish(&sealed);
    assert_eq!((outcome, a.problem()), (Published::Accepted, None), "a strict relay took it");
    assert_eq!(relay.state.refusals.load(Ordering::SeqCst), 0);
    let stored = relay.stored();
    assert_eq!((stored.len(), stored[0].tags.len()), (1, 1));
    assert_eq!(stored[0].tags.public_keys().next(), Some(&kb.public_key()));

    // read in time: taken, and answered
    let mut b = mailbox(&kb, &[&ka], &relay.url, &db, brief);
    let got = wait_incoming(&mut b);
    assert!(began.elapsed() < Duration::from_secs(2), "the test was too slow to mean anything");
    assert_eq!(got.text, S1);
    assert_eq!(b.reply(&got.id, S2), Published::Accepted);
    assert_eq!(relay.stored().iter().filter(|e| e.tags.len() != 1).count(), 0);
    // the stored reply is not sent once its own deadline has passed
    std::thread::sleep(Duration::from_millis(2200));
    assert_eq!(b.resend_reply(&got.id), Some(Published::Expired));
    // Crossing the deadline does not offer the unacknowledged message to a
    // new application poll, even on the same still-open session.
    assert!(b.next_incoming().is_none());
    assert!(b.next_incoming().is_none());
    assert_eq!(a.publish(&sealed), Published::Expired, "the core's deadline stops publication");
    let stored = relay.stored().len();

    // read late: the relay still serves both messages, nobody takes them
    drop((a, b));
    let (da2, db2) = (Temp::new("inside-a2"), Temp::new("inside-b2"));
    let mut late_b = mailbox(&kb, &[&ka], &relay.url, &db2, brief);
    let mut late_a = mailbox(&ka, &[&kb], &relay.url, &da2, brief);
    for _ in 0..4 {
        assert!(late_b.next_incoming().is_none(), "a payment past its deadline was handed to the core");
        assert!(late_a.next_incoming().is_none(), "a reply past its deadline was handed to the core");
    }
    assert_eq!(relay.stored().len(), stored);
}

/// What stands in the way is said in words: the relay's own answer, cut to
/// plain text; that the relay cannot be reached; and nothing once it works.
/// A relay that cannot be reached is tried again after a pause that grows.
#[test]
fn the_reason_of_a_failure_is_kept_for_the_user() {
    let relay = Relay::start();
    let (ka, kb) = (Keys::generate(), Keys::generate());
    let dir = Temp::new("reason");
    let mut a = mailbox(&ka, &[&kb], &relay.url, &dir, timing());
    let sealed = a.seal(&kb.public_key().to_bytes(), S1).unwrap();
    assert_eq!(a.problem(), None);

    relay.set(REFUSING);
    assert_eq!(a.publish(&sealed), Published::Unknown);
    let said = a.problem().unwrap();
    assert!(said.starts_with("the relay did not accept the message: blocked: not? on the list ?!!!"), "{said}");
    assert!(said.len() <= 240 && said.chars().all(|c| c.is_ascii_graphic() || c == ' '), "{said}");
    // a relay that takes the message and says nothing
    relay.set(DOWN);
    assert_eq!(a.publish(&sealed), Published::Unknown);
    assert_eq!(a.problem().as_deref(), Some("the relay did not answer in time"));
    relay.set(UP);
    assert_eq!(a.publish(&sealed), Published::Accepted);
    assert_eq!(a.problem(), None, "it works: there is nothing to say");

    // no relay at that address: said so, and not knocked on at every call
    let dead = Temp::new("dead");
    let (first, longest) = (Duration::from_millis(400), Duration::from_millis(1000));
    let patient = Timing { reconnect: first, reconnect_max: longest, ..timing() };
    let mut c = mailbox(&ka, &[&kb], NOBODY, &dead, patient);
    let knocks = || KNOCKS.load(Ordering::SeqCst);
    let try_many = |c: &mut NostrMailbox<Loopback>| {
        for _ in 0..20 {
            assert_eq!(c.publish(&sealed), Published::Unknown);
            assert!(c.next_incoming().is_none());
        }
    };
    try_many(&mut c);
    assert_eq!(knocks(), 1);
    let said = c.problem().unwrap();
    assert!(said.starts_with("the relay could not be reached"), "{said}");
    // after the first pause once more, then twice as long, then no longer
    // than the limit
    std::thread::sleep(first + Duration::from_millis(50));
    try_many(&mut c);
    assert_eq!(knocks(), 2);
    std::thread::sleep(first + Duration::from_millis(50));
    try_many(&mut c);
    assert_eq!(knocks(), 2, "the pause did not grow");
    std::thread::sleep(first);
    try_many(&mut c);
    assert_eq!(knocks(), 3);
    std::thread::sleep(longest + Duration::from_millis(50));
    try_many(&mut c);
    std::thread::sleep(longest + Duration::from_millis(50));
    try_many(&mut c);
    assert_eq!(knocks(), 5, "the pause grew past its limit");
    assert_eq!(c.problem().unwrap(), said, "the reason stays while nothing new is known");
    // the product's pauses
    assert_eq!((RECONNECT_AFTER, RECONNECT_MAX), (Duration::from_secs(5), Duration::from_secs(300)));
    assert_eq!((Timing::default().reconnect, Timing::default().reconnect_max), (RECONNECT_AFTER, RECONNECT_MAX));
}

#[test]
fn a_stored_reply_survives_a_restart() {
    let relay = Relay::start();
    let (alice, bob) = (Keys::generate(), Keys::generate());
    let (da, db) = (Temp::new("a"), Temp::new("b"));
    let mut a = mailbox(&alice, &[&bob], &relay.url, &da, timing());
    let envelope = a.seal(&bob.public_key().to_bytes(), S1).unwrap();
    assert_eq!(a.publish(&envelope), Published::Accepted);

    let mut b = mailbox(&bob, &[&alice], &relay.url, &db, timing());
    let got = b.next_incoming().unwrap();
    relay.set(DOWN);
    assert_eq!(b.reply(&got.id, S2), Published::Unknown);
    assert_eq!(relay.stored().len(), 1);
    drop(b);

    // a new start: the request comes again from the relay, the reply from disk
    relay.set(UP);
    let mut b = mailbox(&bob, &[&alice], &relay.url, &db, timing());
    let again = b.next_incoming().expect("the request did not come again");
    assert_eq!(again.id, got.id);
    assert_eq!(b.reply(&again.id, OTHER), Published::Accepted);
    b.done(&again.id);
    let back = a.next_incoming().expect("the reply did not arrive");
    assert_eq!(back.text, S2, "the reply was built again after the restart");
    assert_eq!(relay.stored().len(), 2);

    // with another storage key the stored reply is unreadable: it is not
    // replaced, and nothing is sent in its place
    let contacts = [alice.public_key().to_bytes()];
    let mut wrong = NostrMailbox::new(
        bob.clone(),
        &contacts,
        Loopback { relay: relay.url.clone() },
        ReplyStore::open(&db.0, [8; 32]).unwrap(),
        timing(),
    )
    .unwrap();
    let again = wrong.next_incoming().unwrap();
    assert_eq!(wrong.resend_reply(&again.id), None, "another key names another file");
    assert_eq!(relay.stored().len(), 2);
}

/// Only contacts are heard, and only payment messages are handed on.
#[test]
fn strangers_and_chatter_are_not_handed_on() {
    let relay = Relay::start();
    let (alice, bob, carol) = (Keys::generate(), Keys::generate(), Keys::generate());
    let (da, db, dc) = (Temp::new("a"), Temp::new("b"), Temp::new("c"));
    let mut a = mailbox(&alice, &[&bob], &relay.url, &da, timing());
    // carol knows alice, alice does not know carol
    let mut c = mailbox(&carol, &[&alice], &relay.url, &dc, timing());
    let from_carol = c.seal(&alice.public_key().to_bytes(), S1).unwrap();
    assert_eq!(c.publish(&from_carol), Published::Accepted);
    // bob sends ordinary text, then a payment message
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let session = ContactSession::connect_loopback(bob.clone(), alice.public_key(), &relay.url, Duration::from_secs(5))
            .await
            .unwrap();
        let rumor = nostr_sdk::EventBuilder::new(nostr_sdk::Kind::PrivateDirectMessage, "see you at eight")
            .tag(nostr_sdk::Tag::public_key(alice.public_key()))
            .build(bob.public_key());
        let chat = nostr_sdk::EventBuilder::gift_wrap(&bob, &alice.public_key(), rumor, []).await.unwrap();
        session.publish_envelope(&chat.as_json(), u64::MAX, Duration::from_secs(2)).await.unwrap();
        session.close().await;
    });
    let mut b = mailbox(&bob, &[&alice], &relay.url, &db, timing());
    let pay = b.seal(&alice.public_key().to_bytes(), S2).unwrap();
    assert_eq!(b.publish(&pay), Published::Accepted);
    assert_eq!(relay.stored().len(), 3);

    let got = a.next_incoming().expect("the payment message did not arrive");
    assert_eq!((got.from, got.text.as_str()), (bob.public_key().to_bytes(), S2));
    a.done(&got.id);
    assert!(a.next_incoming().is_none());
    assert!(a.next_incoming().is_none(), "something else was handed on");
    // a mailbox cannot be made with itself or with too many contacts
    let me = [alice.public_key().to_bytes()];
    assert!(NostrMailbox::new(alice.clone(), &me, Loopback { relay: relay.url.clone() },
        ReplyStore::open(&da.0, [9; 32]).unwrap(), timing()).is_err());
}

/// The reply store on its own: create-only, bounded, authenticated.
#[test]
fn the_reply_store_is_create_only_bounded_and_authenticated() {
    let dir = Temp::new("store");
    let store = ReplyStore::open(&dir.0, [1; 32]).unwrap();
    let reply = StoredReply { contact: [5; 32], deadline: 1_234_567_890_123, envelope: "{\"sealed\":true}".into() };
    assert_eq!(store.get(&[7; 32]).unwrap(), None);
    store.put(&[7; 32], &reply).unwrap();
    assert_eq!(store.get(&[7; 32]).unwrap(), Some(reply.clone()));
    assert!(matches!(store.put(&[7; 32], &reply), Err(StoreError::Io(std::io::ErrorKind::AlreadyExists))));
    // nothing readable on disk, and the name does not give the message away
    let files: Vec<_> = std::fs::read_dir(&dir.0).unwrap().map(|e| e.unwrap()).collect();
    assert_eq!(files.len(), 1);
    let name = files[0].file_name().to_string_lossy().into_owned();
    assert!(!name.contains(&"07".repeat(8)));
    let raw = std::fs::read(files[0].path()).unwrap();
    assert!(!raw.windows(6).any(|w| w == b"sealed"));
    assert!(!raw.windows(8).any(|w| w == [5u8; 8]));
    // every changed byte is noticed; a truncated file too
    for i in (0..raw.len()).step_by(3) {
        let mut bad = raw.clone();
        bad[i] ^= 1;
        std::fs::write(files[0].path(), &bad).unwrap();
        assert!(store.get(&[7; 32]).is_err(), "byte {i}");
    }
    std::fs::write(files[0].path(), &raw[..10]).unwrap();
    assert!(store.get(&[7; 32]).is_err());
    std::fs::write(files[0].path(), &raw).unwrap();
    assert_eq!(store.get(&[7; 32]).unwrap(), Some(reply.clone()));
    // a file moved under another message's name is refused
    let other = ReplyStore::open(&dir.0, [1; 32]).unwrap();
    other.put(&[8; 32], &reply).unwrap();
    let names: Vec<_> = std::fs::read_dir(&dir.0).unwrap().map(|e| e.unwrap().path()).collect();
    let (x, y) = (std::fs::read(&names[0]).unwrap(), std::fs::read(&names[1]).unwrap());
    std::fs::write(&names[0], &y).unwrap();
    std::fs::write(&names[1], &x).unwrap();
    assert!(store.get(&[7; 32]).is_err() && store.get(&[8; 32]).is_err());
    std::fs::write(&names[0], &x).unwrap();
    std::fs::write(&names[1], &y).unwrap();
    // another key reads nothing
    assert_eq!(ReplyStore::open(&dir.0, [2; 32]).unwrap().get(&[7; 32]).unwrap(), None);
    // bounded, and purging frees room
    let mut n = 2usize;
    let mut id = [0u8; 32];
    while n < MAX_REPLIES {
        id[..8].copy_from_slice(&(n as u64 + 100).to_le_bytes());
        store.put(&id, &reply).unwrap();
        n += 1;
    }
    assert!(matches!(store.put(&[0xEE; 32], &reply), Err(StoreError::Full)));
    assert_eq!(store.get(&[7; 32]).unwrap(), Some(reply.clone()), "a full store lost a reply");
    assert_eq!(store.purge(|r| r.contact == [5; 32]).unwrap(), MAX_REPLIES);
    assert_eq!(store.get(&[7; 32]).unwrap(), None);
    store.put(&[0xEE; 32], &reply).unwrap();
}

/// The session constructor used by these tests cannot leave the machine.
#[test]
fn the_test_connector_reaches_loopback_only() {
    use fly_nostr_research::nostr::contact_session::SessionError;
    let (alice, bob) = (Keys::generate(), Keys::generate());
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    for relay in [
        "ws://relay.example",
        "wss://relay.example",
        "ws://192.168.1.10:7000",
        "ws://8.8.8.8",
        "wss://127.0.0.1:7000",
        "ws://localhost:7000",
        "http://127.0.0.1:7000",
        "not a url",
    ] {
        let r = rt.block_on(ContactSession::connect_loopback(
            alice.clone(),
            bob.public_key(),
            relay,
            Duration::from_secs(1),
        ));
        assert_eq!(r.err(), Some(SessionError::InvalidInput), "{relay}");
    }
}

/// The same mailbox behind the process pipe: the wallet's side talks to
/// `serve`, which runs the Nostr mailbox on another thread.
#[test]
fn the_mailbox_works_behind_the_pipe() {
    use fly_paycore_mailbox_pipe::{serve, Config, PipeMailbox};
    let relay = Relay::start();
    let (alice, bob) = (Keys::generate(), Keys::generate());
    let (da, db) = (Temp::new("pa"), Temp::new("pb"));
    let behind_pipe = |me: &Keys, other: &Keys, dir: &Temp| -> PipeMailbox {
        let config = Config {
            identity_secret: me.secret_key().to_secret_bytes(),
            identity_public: me.public_key().to_bytes(),
            store_key: [9; 32],
            relay: relay.url.clone(),
            data_dir: dir.0.to_string_lossy().into_owned(),
            contacts: vec![other.public_key().to_bytes()],
            delivery_window_secs: 600,
            publish_timeout_ms: 2000,
            poll_ms: 300,
            start_timeout_secs: 10,
            tor_bridges: String::new(),
        };
        let (client_reads, mut server_writes) = std::io::pipe().unwrap();
        let (mut server_reads, client_writes) = std::io::pipe().unwrap();
        std::thread::spawn(move || {
            serve(&mut server_reads, &mut server_writes, |config: Config| {
                let url = config.relay.clone();
                fly_mailbox_nostr::from_config(&config, move |_| Ok(Loopback { relay: url }))
            })
        });
        PipeMailbox::connect(client_reads, client_writes, &config, Duration::from_secs(8)).unwrap()
    };
    let mut a = behind_pipe(&alice, &bob, &da);
    let mut b = behind_pipe(&bob, &alice, &db);
    let envelope = a.seal(&bob.public_key().to_bytes(), S1).unwrap();
    assert_eq!(envelope.event_id, id_of(&envelope.bytes));
    assert!(a.seal(&Keys::generate().public_key().to_bytes(), S1).is_err());
    assert_eq!(a.publish(&envelope), Published::Accepted);
    assert_eq!(a.publish(&envelope), Published::Accepted);
    assert_eq!(relay.stored().len(), 1);
    let got = b.next_incoming().expect("nothing arrived");
    assert_eq!((got.id, got.from, got.text.as_str()), (envelope.event_id, alice.public_key().to_bytes(), S1));
    assert_eq!(b.resend_reply(&got.id), None);
    assert_eq!(b.reply(&got.id, S2), Published::Accepted);
    assert_eq!(b.reply(&got.id, OTHER), Published::Accepted);
    assert_eq!(relay.stored().len(), 2, "the reply was built again");
    b.done(&got.id);
    assert!(b.next_incoming().is_none());
    let back = a.next_incoming().expect("the reply did not arrive");
    assert_eq!(back.text, S2);
    // the reply went to disk under the data directory, encrypted
    let stored: Vec<_> = std::fs::read_dir(db.0.join("replies")).unwrap().flatten().collect();
    assert_eq!(stored.len(), 1);
    // a configuration the transport cannot use is refused at the start
    let (client_reads, mut server_writes) = std::io::pipe().unwrap();
    let (mut server_reads, client_writes) = std::io::pipe().unwrap();
    std::thread::spawn(move || {
        serve(&mut server_reads, &mut server_writes, |config: Config| {
            fly_mailbox_nostr::from_config(&config, move |_| Ok(Loopback { relay: String::new() }))
        })
    });
    let bad = Config {
        identity_secret: [0; 32],
        identity_public: [0; 32],
        store_key: [9; 32],
        relay: relay.url.clone(),
        data_dir: "relative/path".into(),
        contacts: vec![],
        delivery_window_secs: 600,
        publish_timeout_ms: 2000,
        poll_ms: 300,
        start_timeout_secs: 5,
        tor_bridges: String::new(),
    };
    let r = PipeMailbox::connect(client_reads, client_writes, &bad, Duration::from_secs(5));
    assert!(r.err().unwrap().starts_with("the transport did not start: "));
}
