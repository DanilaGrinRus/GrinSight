//! Handing the wallet's transactions to the network: what is checked
//! before one is sent, how it goes out - through Tor, to a public node's
//! API or to one node as a stem transaction, once more to be announced if
//! it does not come back, over the program's own connections only if the
//! user agreed - and how the program comes to know that nodes hold it or
//! that it is in a block. In a test build "Tor" is a straight connection
//! to nodes on this computer.
//! First without a network, on the verified state of a chain mined here;
//! then with the Grin node's own network code on the other end. Run with
//! `cargo test --features test-net`.
mod kit;

use fly_chain::post::{Do, Outbox, ASK_EVERY, MAX_SENT, RESEND_EVERY, RETRY_AFTER, STEM_FOR};
use fly_chain::TEST_START_FILE;
use fly_chain_headers::testkit::TestChain;
use fly_chain_headers::Net;
use fly_chain_state::advance::{Check, Live};
use fly_chain_state::testkit::Source;
use fly_paycore_chain_pipe::{Config, PipeChain};
use fly_paycore_chain_port::{ChainFeed, Level, Posted};
use grin_core::consensus::REWARD;
use grin_core::core::hash::Hashed;
use grin_core::core::Transaction;
use grin_core::global::{self, ChainTypes};
use fly_chain::accept::{TEST_ROOTS_FILE, TEST_SOURCES_FILE};
use fly_chain::send::TEST_NO_TOR_FILE;
use kit::{wait_for, Node, Temp, FLY};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// A fee nodes take for one input and one output, and for two of each.
const FEE: u32 = 15_000_000;
const FEE_2: u32 = 30_000_000;

/// Forty blocks of others and twenty whose rewards the tests can spend
/// (41..=60), with the verified state at the tip.
fn shared() -> &'static (Source, Live) {
    static SOURCE: std::sync::OnceLock<(Source, Live)> = std::sync::OnceLock::new();
    let shared = SOURCE.get_or_init(|| {
        let mut source = Source::thin(40);
        source.grow_paying(20);
        let mut live = Live::new(source.collect()).unwrap();
        let from = source.archive().height as usize + 1;
        for b in &source.blocks[from..] {
            live.apply(b, &b.header, Check::Kept, None).unwrap();
        }
        (source, live)
    });
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    shared
}
fn bytes(tx: &Transaction) -> Vec<u8> {
    grin_core::ser::ser_vec(tx, grin_core::ser::ProtocolVersion::local()).unwrap()
}
fn excess(tx: &Transaction) -> [u8; 33] {
    tx.kernels()[0].excess.0
}
fn peers() -> Vec<SocketAddr> {
    (1..=3).map(|n| format!("10.0.0.{n}:3414").parse().unwrap()).collect()
}

/// A genuine aggregate must be checked before it can stop a payment's retry.
#[test]
fn an_observed_aggregate_waits_for_verification() {
    use fly_chain::adapter::{Adapter, Event, OurTip, Watch};
    use grin_p2p::ChainAdapter;
    use std::sync::{atomic::AtomicUsize, mpsc};

    let (_, live) = shared();
    let ours = Source::spend_paid(41, FEE);
    let other = Source::spend_paid(42, FEE);
    let combined = grin_core::core::transaction::aggregate(&[ours.clone(), other]).unwrap();
    let mut outbox = Outbox::new(false);
    let (reply, job) = outbox.post(&bytes(&ours), Instant::now(), Some(live), true);
    assert_eq!(reply, Posted::Unknown);
    assert!(job.is_some());
    let (events, observed) = mpsc::sync_channel(1);
    let watch = Watch { kernels: outbox.watched(), ..Watch::default() };
    let adapter = Adapter::new(events, Arc::new(OurTip::default()), Arc::new(AtomicUsize::new(0)), Arc::new(std::sync::Mutex::new(watch)));
    let secp = grin_util::static_secp_instance();
    let busy = secp.lock();
    let (starting, started) = mpsc::sync_channel(0);
    let worker = std::thread::spawn(move || {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        starting.send(()).unwrap();
        adapter.transaction_received(combined, false)
    });
    started.recv_timeout(Duration::from_secs(5)).unwrap();
    let premature = observed.recv_timeout(Duration::from_millis(250));
    drop(busy);
    assert!(worker.join().unwrap().unwrap());
    assert!(matches!(premature, Err(mpsc::RecvTimeoutError::Timeout)),
        "the outbox was told of an aggregate while verification was unavailable");
    assert!(matches!(observed.recv_timeout(Duration::from_secs(5)), Ok(Event::Heard { .. })));
}

/// Nothing is sent that cannot be valid on the verified chain, and the
/// wallet is told so; nothing is sent, or judged, without a verified state
/// at the tip - then the answer is "unknown", never "refused".
#[test]
fn a_transaction_is_checked_before_it_is_sent() {
    let (_, live) = shared();
    let (now, peers) = (Instant::now(), peers());
    let mut outbox = Outbox::new(false);
    let mut refused = |what: &str, bytes: &[u8]| {
        let (answer, todo) = outbox.post(bytes, now, Some(live), true);
        assert!(answer == Posted::Rejected && todo.is_none(), "{what}: {answer:?}");
        assert!(outbox.is_empty(), "{what}: nothing is kept track of");
    };
    let good = Source::spend_paid(41, FEE);
    refused("not a transaction", b"not a transaction");
    refused("nothing", b"");
    let mut longer = bytes(&good);
    longer.push(0);
    refused("a transaction and something after it", &longer);
    let mut bent = bytes(&good);
    let last = bent.len() - 1;
    bent[last] ^= 1;
    refused("a signature that does not hold", &bent);
    refused("a fee below what nodes take", &bytes(&Source::spend_paid(41, 20_000)));
    refused("an input that is not there", &bytes(&Source::spend_paid(77, FEE)));
    refused("amounts that do not add up", &bytes(&Source::paid_tx(&[41], &[(REWARD, 3, 41)], FEE, None)));
    refused("locked to a later height", &bytes(&Source::paid_tx(&[41], &[(REWARD - u64::from(FEE), 3, 41)], FEE, Some(62))));
    // the reward of block 43 is an unspent output: no second one like it
    let twice = Source::paid_tx(&[41, 42], &[(REWARD, 1, 43), (REWARD - u64::from(FEE_2), 3, 9)], FEE_2, None);
    refused("an output that is there already", &bytes(&twice));

    // "unknown" when this program cannot judge
    let mut outbox = Outbox::new(false);
    for (what, live, at_tip) in [("no verified state", None, true), ("not at the tip", Some(live), false)] {
        let (answer, todo) = outbox.post(&bytes(&good), now, live, at_tip);
        assert!(answer == Posted::Unknown && todo.is_none() && outbox.is_empty(), "{what}: {answer:?}");
    }
    // what can be valid goes through Tor, as a stem transaction; no node
    // of the program's own is needed for that
    let locked_now = Source::paid_tx(&[42], &[(REWARD - u64::from(FEE), 3, 42)], FEE, Some(61));
    for tx in [&good, &locked_now] {
        let (answer, todo) = outbox.post(&bytes(tx), now, Some(live), true);
        let Some(Do::Send { key, tx: sent, fluff: false, .. }) = todo else { panic!("{todo:?}") };
        assert!(answer == Posted::Unknown && sent.hash() == tx.hash() && key == vec![excess(tx)]);
    }
    assert!(outbox.waiting());
    assert!(outbox.announced().is_empty(), "nothing sent through Tor is given out over the program's own connections");
    let _ = peers;
}

/// A transaction that was sent is not sent again. Through Tor: while a
/// try is under way nothing more is done; the time of the stem runs from
/// when it went; when it is up, the transaction is sent once more to be
/// announced, and so again every so often - each time starting at another
/// node. Nothing goes over the program's own connections: nobody there is
/// told of it or asked for it. Once a node handed it over - alone or
/// joined with others - it is "accepted" and nothing more is sent; in a
/// block it is no longer looked out for; taken out of the block by a turn
/// of the chain, it is again.
#[test]
fn a_sent_transaction_is_followed() {
    let (_, live) = shared();
    let (t0, peers) = (Instant::now(), peers());
    let tx = Source::spend_paid(41, FEE);
    let mut outbox = Outbox::new(false);
    let post = |outbox: &mut Outbox, at: Instant| outbox.post(&bytes(&tx), at, Some(live), true);
    let (answer, todo) = post(&mut outbox, t0);
    let Some(Do::Send { key, fluff: false, turn: first, .. }) = todo else { panic!("{todo:?}") };
    assert_eq!(answer, Posted::Unknown);
    assert!(matches!(post(&mut outbox, t0), (Posted::Unknown, None)), "not sent twice");
    assert_eq!(outbox.watched(), vec![(excess(&tx), tx.kernels()[0].hash())]);
    // under way: nothing, however long
    assert!(outbox.tend(t0 + STEM_FOR * 10, &peers).is_empty());
    // it went a second later; the stem's time runs from then
    let went = t0 + Duration::from_secs(1);
    assert!(outbox.sent(&key, Ok(()), went, &peers).is_none());
    assert!(outbox.tend(went + STEM_FOR - Duration::from_millis(1), &peers).is_empty());
    let t1 = went + STEM_FOR;
    let due = outbox.tend(t1, &[]);
    let [Do::Send { fluff: true, turn: second, tx: told, .. }] = &due[..] else { panic!("{due:?}") };
    assert!(told.hash() == tx.hash() && *second != first, "announced, starting elsewhere");
    assert!(outbox.announced().is_empty(), "given to nobody over the program's own connections");
    assert!(outbox.tend(t1 + RESEND_EVERY * 5, &peers).is_empty(), "under way again");
    assert!(outbox.sent(&key, Ok(()), t1, &peers).is_none());
    assert!(outbox.tend(t1 + RESEND_EVERY - Duration::from_millis(1), &peers).is_empty());
    let mut turns = vec![first, *second];
    for round in 1..=3u32 {
        let at = t1 + RESEND_EVERY * round;
        let due = outbox.tend(at, &peers);
        let [Do::Send { fluff: true, turn, .. }] = &due[..] else { panic!("{due:?}") };
        assert!(!turns.contains(turn), "each time elsewhere");
        turns.push(*turn);
        assert!(outbox.sent(&key, Ok(()), at, &peers).is_none());
    }
    // nothing of it ever went over the program's own connections
    assert!(outbox.announced().is_empty());
    assert!(outbox.trouble().is_none());

    // a node hands it over: accepted, nothing more is sent
    let other = Source::spend_paid(42, FEE);
    assert!(!outbox.heard(&[other.kernels()[0].hash()]), "somebody else's transaction");
    assert_eq!(post(&mut outbox, t1).0, Posted::Unknown);
    assert!(outbox.heard(&[other.kernels()[0].hash(), tx.kernels()[0].hash()]), "joined with another on its way");
    assert_eq!(post(&mut outbox, t1).0, Posted::Accepted);
    assert!(outbox.tend(t1 + RESEND_EVERY * 20, &peers).is_empty(), "nothing more is sent");

    // in a block, out of it, in again
    outbox.block(61, &[excess(&other)]);
    assert!(outbox.waiting());
    outbox.block(62, &[excess(&tx), excess(&other)]);
    assert!(!outbox.waiting() && outbox.watched().is_empty() && outbox.announced().is_empty());
    outbox.taken_back(Some(62));
    assert!(!outbox.waiting(), "the chain turned above its block");
    outbox.taken_back(Some(61));
    assert!(outbox.waiting() && outbox.watched() == vec![(excess(&tx), tx.kernels()[0].hash())]);
    // Inclusion consumed the earlier pool evidence. On the new branch
    // neither a block nor a fresh observation in the pool is known yet.
    assert_eq!(post(&mut outbox, t1).0, Posted::Unknown);
    assert!(t1.checked_add(RESEND_EVERY.saturating_mul(10))
        .is_some_and(|due| !outbox.tend(due, &peers).is_empty()));
    outbox.block(63, &[excess(&tx)]);
    outbox.taken_back(None);
    assert!(outbox.waiting(), "a turn below everything remembered");

    // seen before the stem's time: never sent again
    let mut outbox = Outbox::new(false);
    let (_, todo) = post(&mut outbox, t0);
    let Some(Do::Send { key, .. }) = todo else { panic!() };
    outbox.sent(&key, Ok(()), t0, &peers);
    assert!(outbox.heard(&[tx.kernels()[0].hash()]));
    assert!(outbox.tend(t0 + STEM_FOR * 10, &peers).is_empty() && outbox.announced().is_empty());
    // in a block before the stem's time: the same
    let mut outbox = Outbox::new(false);
    let (_, todo) = post(&mut outbox, t0);
    let Some(Do::Send { key, .. }) = todo else { panic!() };
    outbox.sent(&key, Ok(()), t0, &peers);
    outbox.block(61, &[excess(&tx)]);
    assert!(outbox.tend(t0 + STEM_FOR * 10, &peers).is_empty());
    // an answer for a transaction it does not know changes nothing
    assert!(outbox.sent(&[[9u8; 33]], Err("x".into()), t0, &peers).is_none());
}

/// When Tor fails, the transaction does not go out from this computer's
/// address: the try is made again after a while, as what it was - a stem
/// as a stem, an announcement as an announcement - and the reason is kept
/// for the wallet to show until a try succeeds. Only if the user agreed
/// does it go over the program's own connections instead: then as a stem
/// to one of them, and from there on the way it always went that way -
/// announced to all of them when the stem's time is up, then asked for one
/// node at a time, and given to whoever asks.
#[test]
fn when_tor_fails() {
    let (_, live) = shared();
    let (t0, peers) = (Instant::now(), peers());
    let tx = Source::spend_paid(41, FEE);

    // without the user's agreement
    let mut outbox = Outbox::new(false);
    let (_, todo) = outbox.post(&bytes(&tx), t0, Some(live), true);
    let Some(Do::Send { key, turn: first, .. }) = todo else { panic!() };
    assert!(outbox.sent(&key, Err("Tor did not come up".into()), t0, &peers).is_none(), "not over the program's own connections");
    assert_eq!(outbox.trouble(), Some("Tor did not come up"));
    assert!(outbox.tend(t0 + RETRY_AFTER - Duration::from_millis(1), &peers).is_empty());
    let due = outbox.tend(t0 + RETRY_AFTER, &peers);
    let [Do::Send { fluff: false, turn, .. }] = &due[..] else { panic!("{due:?}") };
    assert_ne!(*turn, first, "again, as a stem, elsewhere");
    assert!(outbox.tend(t0 + RETRY_AFTER * 10, &peers).is_empty(), "under way");
    assert_eq!(outbox.trouble(), Some("Tor did not come up"), "the reason stays until a try succeeds");
    let t1 = t0 + RETRY_AFTER;
    assert!(outbox.sent(&key, Ok(()), t1, &peers).is_none());
    assert_eq!(outbox.trouble(), None);
    // the stem's time is up; the announcement fails and is tried again as one
    let due = outbox.tend(t1 + STEM_FOR, &peers);
    assert!(matches!(&due[..], [Do::Send { fluff: true, .. }]));
    outbox.sent(&key, Err("Tor did not reach the node".into()), t1 + STEM_FOR, &peers);
    let due = outbox.tend(t1 + STEM_FOR + RETRY_AFTER, &peers);
    assert!(matches!(&due[..], [Do::Send { fluff: true, .. }]), "{due:?}");
    assert!(outbox.announced().is_empty());
    // a transaction in a block needs no more tries, and has no trouble
    outbox.sent(&key, Err("Tor did not come up".into()), t1 + STEM_FOR, &peers);
    outbox.block(61, &[excess(&tx)]);
    assert_eq!(outbox.trouble(), None);
    assert!(outbox.tend(t1 + STEM_FOR * 10, &peers).is_empty());

    // with the user's agreement
    let mut outbox = Outbox::new(true);
    assert!(outbox.direct());
    let (_, todo) = outbox.post(&bytes(&tx), t0, Some(live), true);
    let Some(Do::Send { key, .. }) = todo else { panic!() };
    // with nobody connected it stays with Tor
    assert!(outbox.sent(&key, Err("Tor did not come up".into()), t0, &[]).is_none());
    let due = outbox.tend(t0 + RETRY_AFTER, &peers);
    assert!(matches!(&due[..], [Do::Send { fluff: false, .. }]));
    let todo = outbox.sent(&key, Err("Tor did not come up".into()), t0 + RETRY_AFTER, &peers);
    let Some(Do::Stem { to, tx: sent }) = todo else { panic!("{todo:?}") };
    assert!(peers.contains(&to) && sent.hash() == tx.hash());
    assert_eq!(outbox.trouble(), None, "it went");
    assert!(outbox.announced().is_empty(), "a stem transaction is given to nobody who asks");
    let t1 = t0 + RETRY_AFTER;
    assert!(outbox.tend(t1 + STEM_FOR - Duration::from_millis(1), &peers).is_empty());
    assert!(outbox.tend(t1 + STEM_FOR, &[]).is_empty(), "nobody to tell");
    let t2 = t1 + STEM_FOR;
    let due = outbox.tend(t2, &peers);
    assert!(matches!(&due[..], [Do::Announce { to, tx: told }] if *to == peers && told.hash() == tx.hash()), "{due:?}");
    let announced = outbox.announced();
    assert!(announced.len() == 1 && announced[0].1.hash() == tx.hash() && announced[0].0 == tx.kernels()[0].hash());
    assert!(outbox.tend(t2 + ASK_EVERY - Duration::from_millis(1), &peers).is_empty());
    let mut asked = Vec::new();
    for round in 1..=3u32 {
        let due = outbox.tend(t2 + ASK_EVERY * round, &peers);
        let [Do::Ask { to, kernel }] = &due[..] else { panic!("{due:?}") };
        assert!(*kernel == tx.kernels()[0].hash() && peers.contains(to));
        asked.push(*to);
    }
    assert!(asked[0] != asked[1] && asked[1] != asked[2], "another node each time");
    // an answer from Tor arriving late changes nothing on this way
    assert!(outbox.sent(&key, Ok(()), t2, &peers).is_none());
    assert!(outbox.heard(&[tx.kernels()[0].hash()]));
    assert!(outbox.tend(t2 + ASK_EVERY * 20, &peers).is_empty());

    // with the agreement, an announcement that fails through Tor goes to all
    let mut outbox = Outbox::new(true);
    let (_, todo) = outbox.post(&bytes(&tx), t0, Some(live), true);
    let Some(Do::Send { key, .. }) = todo else { panic!() };
    outbox.sent(&key, Ok(()), t0, &peers);
    assert!(matches!(&outbox.tend(t0 + STEM_FOR, &peers)[..], [Do::Send { fluff: true, .. }]));
    let todo = outbox.sent(&key, Err("Tor did not reach the node".into()), t0 + STEM_FOR, &peers);
    assert!(matches!(&todo, Some(Do::Announce { to, .. }) if *to == peers), "{todo:?}");
    assert_eq!(outbox.announced().len(), 1);
}

/// The program keeps no list of what it sent when it is started again:
/// the wallet remembers and hands a transaction over once more. If it is
/// not in a block yet, it is new to the program: checked, and sent as a
/// stem. If it is in the chain - all its outputs are unspent there and its
/// inputs are gone - the answer is "accepted" and nothing is sent or kept
/// track of. That is said only of a transaction that holds by itself and
/// only when everything fits: a changed signature, an output that is not
/// there, an input that still is - refused, as before.
#[test]
fn a_transaction_handed_over_again_after_a_restart() {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let mut source = Source::thin(40);
    source.grow_paying(20);
    let live_at = |source: &Source| {
        let mut live = Live::new(source.collect()).unwrap();
        let from = source.archive().height as usize + 1;
        for b in &source.blocks[from..] {
            live.apply(b, &b.header, Check::Kept, None).unwrap();
        }
        live
    };
    let (now, peers) = (Instant::now(), peers());
    let one = Source::spend_paid(41, FEE);
    let two = Source::paid_tx(&[42, 43], &[(REWARD, 3, 142), (REWARD - u64::from(FEE_2), 3, 143)], FEE_2, None);

    // started anew before the transactions reached a block: each is sent again
    let live = live_at(&source);
    let mut outbox = Outbox::new(false);
    for tx in [&one, &two] {
        let (answer, todo) = outbox.post(&bytes(tx), now, Some(&live), true);
        assert!(answer == Posted::Unknown && matches!(todo, Some(Do::Send { fluff: false, .. })), "{answer:?}");
    }

    // a block with both; the program is started anew after it
    source.mine_with(&[one.clone(), two.clone()]);
    let live = live_at(&source);
    let mut outbox = Outbox::new(false);
    for tx in [&one, &two, &one] {
        let (answer, todo) = outbox.post(&bytes(tx), now, Some(&live), true);
        assert!(answer == Posted::Accepted && todo.is_none(), "{answer:?} {todo:?}");
    }
    assert!(outbox.is_empty() && !outbox.waiting(), "nothing is kept track of");
    assert!(outbox.tend(now + STEM_FOR * 2, &peers).is_empty(), "and nothing is sent later");
    // without a verified state at the tip nothing is said
    let (answer, _) = outbox.post(&bytes(&one), now, Some(&live), false);
    assert_eq!(answer, Posted::Unknown);
    let (answer, _) = outbox.post(&bytes(&one), now, None, true);
    assert_eq!(answer, Posted::Unknown);

    let mut refused = |what: &str, bytes: &[u8]| {
        let (answer, todo) = outbox.post(bytes, now, Some(&live), true);
        assert!(answer == Posted::Rejected && todo.is_none() && outbox.is_empty(), "{what}: {answer:?}");
    };
    // the same transaction with a signature that does not hold
    let mut bent = bytes(&one);
    let last = bent.len() - 1;
    bent[last] ^= 1;
    refused("in the chain, but not this transaction", &bent);
    // its inputs are gone and its output is not there: another
    // transaction took them
    refused("the inputs were spent by another transaction", &bytes(&Source::spend_paid(41, FEE + 1_000)));
    // one of its two outputs is in the chain, the other is not
    let half = Source::paid_tx(&[42, 43], &[(REWARD, 3, 142), (REWARD - u64::from(FEE_2), 3, 999)], FEE_2, None);
    refused("only one of its outputs is there", &bytes(&half));
    // all its outputs are there and an input is unspent as well
    let again = Source::paid_tx(&[44], &[(REWARD - u64::from(FEE), 3, 41)], FEE, None);
    assert!(live.unspent(&again.outputs()[0].commitment().0).is_some(), "the output of the first transaction");
    refused("an output that is there, with an input that is too", &bytes(&again));
}

/// Only so many transactions are kept track of. When there is no room, one
/// that is in a block makes way for a new one - the one longest in a block
/// first; if none is in a block, the new one is not sent.
#[test]
fn room_is_made_by_what_is_in_a_block() {
    let (_, live) = shared();
    let now = Instant::now();
    let txs: Vec<Transaction> = (41..=41 + MAX_SENT as u64 + 1).map(|height| Source::spend_paid(height, FEE)).collect();
    let mut outbox = Outbox::new(false);
    for tx in &txs[..MAX_SENT] {
        assert!(matches!(outbox.post(&bytes(tx), now, Some(live), true), (Posted::Unknown, Some(Do::Send { fluff: false, .. }))));
    }
    let (one_more, another) = (&txs[MAX_SENT], &txs[MAX_SENT + 1]);
    assert!(matches!(outbox.post(&bytes(one_more), now, Some(live), true), (Posted::Unknown, None)), "no room");
    assert_eq!(outbox.watched().len(), MAX_SENT);
    outbox.block(70, &[excess(&txs[5])]);
    outbox.block(65, &[excess(&txs[3])]);
    assert!(matches!(outbox.post(&bytes(one_more), now, Some(live), true), (Posted::Unknown, Some(Do::Send { fluff: false, .. }))));
    // the one that made way is not known any more: its inputs are in the
    // state this test stands on, so it would be sent anew - the one longest in a block
    assert!(matches!(outbox.post(&bytes(&txs[5]), now, Some(live), true), (Posted::Accepted, None)), "the newer block stays");
    assert!(matches!(outbox.post(&bytes(another), now, Some(live), true), (Posted::Unknown, Some(Do::Send { fluff: false, .. }))));
    assert!(matches!(outbox.post(&bytes(&txs[5]), now, Some(live), true), (Posted::Unknown, None)), "it made way, and there is no room for it now");
}

fn chain_with_funds() -> Arc<RwLock<Source>> {
    let mut source = Source::thin(40);
    source.grow_paying(6);
    Arc::new(RwLock::new(source))
}

/// How the program is started.
#[derive(Clone, Copy, Default)]
struct Start {
    /// The user agreed to the direct way.
    direct: bool,
    /// "Tor" does not come up.
    no_tor: bool,
    /// The user switched Tor off.
    tor_off: bool,
    /// How many of the public nodes given, the last ones, are the user's
    /// own rather than listed.
    own: usize,
}

fn program(tag: &str, source: &Arc<RwLock<Source>>, nodes: &[&Node], public: &[&Public], start: Start) -> (Temp, PipeChain) {
    let t = Temp::new(tag);
    let record = TestChain::from_headers(source.read().unwrap().headers()).record(14);
    std::fs::write(t.0.join(TEST_START_FILE), record).unwrap();
    let (public, own) = public.split_at(public.len() - start.own);
    if !own.is_empty() {
        let mine: String = own.iter().map(|p| format!("https://localhost:{}\n", p.port)).collect();
        std::fs::write(t.0.join(fly_chain::accept::OWN_NODES_FILE), mine).unwrap();
        std::fs::write(t.0.join(TEST_ROOTS_FILE), include_bytes!("../../tips/tests/certs/ca.pem")).unwrap();
    }
    if !public.is_empty() {
        let listed: String = public.iter().enumerate().map(|(i, p)| format!("https://localhost:{} Operator-{i} {}\n", p.port, i + 1)).collect();
        std::fs::write(t.0.join(TEST_SOURCES_FILE), listed).unwrap();
        std::fs::write(t.0.join(TEST_ROOTS_FILE), include_bytes!("../../tips/tests/certs/ca.pem")).unwrap();
    }
    if start.no_tor {
        std::fs::write(t.0.join(TEST_NO_TOR_FILE), b"").unwrap();
    }
    let config = Config {
        network: 3,
        genesis: Net::Automated.genesis_hash(),
        data_dir: t.0.to_str().unwrap().to_string(),
        peers: nodes.iter().map(|node| node.addr.to_string()).collect(),
        start_timeout_secs: 30,
        direct_post: start.direct,
        tor_off: start.tor_off,
        tor_bridges: String::new(),
    };
    let mut chain = PipeChain::spawn(std::path::Path::new(FLY), &config, Duration::from_secs(10)).unwrap();
    wait_for("the blocks", || chain.status().is_some_and(|s| s.level == Level::AtTip));
    (t, chain)
}

/// A public node of the test: takes `push_transaction` over TLS and keeps
/// what it was given, or answers that it will not take it.
struct Public {
    port: u16,
    /// The transactions and whether each was to be announced at once.
    pushed: Arc<Mutex<Vec<(Transaction, bool)>>>,
    refuse: Arc<std::sync::atomic::AtomicBool>,
}

impl Public {
    fn start() -> Public {
        let chain = vec![CertificateDer::from_pem_slice(include_bytes!("../../tips/tests/certs/localhost.pem")).unwrap()];
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../tips/tests/certs/localhost.key")).unwrap();
        let config = Arc::new(
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let public = Public {
            port: listener.local_addr().unwrap().port(),
            pushed: Arc::new(Mutex::new(Vec::new())),
            refuse: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let (pushed, refuse) = (public.pushed.clone(), public.refuse.clone());
        std::thread::spawn(move || {
            for socket in listener.incoming() {
                let Ok(socket) = socket else { continue };
                let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
                let Ok(connection) = ServerConnection::new(config.clone()) else { continue };
                let mut tls = StreamOwned::new(connection, socket);
                let mut asked = Vec::new();
                let mut chunk = [0u8; 4096];
                // the head, then as many bytes as it says
                let body = loop {
                    match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => break None,
                        Ok(n) => asked.extend_from_slice(&chunk[..n]),
                    }
                    let Some(end) = asked.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                    let head = String::from_utf8_lossy(&asked[..end]).to_lowercase();
                    let len: usize = head.lines().find_map(|l| l.strip_prefix("content-length: ")).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
                    if asked.len() >= end + 4 + len {
                        break Some(asked[end + 4..end + 4 + len].to_vec());
                    }
                };
                let Some(body) = body else { continue };
                let call: serde_json::Value = serde_json::from_slice(&body).unwrap();
                let answer = if call["method"] == "push_transaction" && !refuse.load(std::sync::atomic::Ordering::SeqCst) {
                    let tx: Transaction = serde_json::from_value(call["params"][0].clone()).unwrap();
                    pushed.lock().unwrap().push((tx, call["params"][1].as_bool().unwrap()));
                    r#"{"id":1,"jsonrpc":"2.0","result":{"Ok":null}}"#.to_string()
                } else {
                    r#"{"id":1,"jsonrpc":"2.0","result":{"Err":{"Internal":"not now"}}}"#.to_string()
                };
                let reply = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{answer}", answer.len());
                let _ = tls.write_all(reply.as_bytes());
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        public
    }
    fn count(&self) -> usize {
        self.pushed.lock().unwrap().len()
    }
}

/// Through "Tor" to the nodes of the network, when no public node is
/// listed: the transaction goes to one node only, as a stem transaction,
/// over a connection of its own, and only once. When another node passes
/// it on (as the network does once a stem transaction has been announced),
/// the wallet is told "accepted", and no node was asked anything. In a
/// block it stays "accepted". What cannot be valid reaches no node.
#[test]
fn a_payment_goes_out_as_a_stem_and_is_known_when_the_network_has_it() {
    let source = chain_with_funds();
    let (a, b) = (Node::with_state(&source), Node::with_state(&source));
    let (_t, mut chain) = program("stem", &source, &[&a, &b], &[], Start::default());
    global::set_local_chain_type(ChainTypes::AutomatedTesting);

    assert_eq!(chain.post(b"not a transaction"), Posted::Rejected);
    assert_eq!(chain.post(&bytes(&Source::spend_paid(77, FEE))), Posted::Rejected, "an input that is not there");
    let tx = Source::spend_paid(41, FEE);
    assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown, "no node says whether it took it");
    wait_for("the stem", || a.stems() + b.stems() == 1);
    assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown);
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!((a.stems() + b.stems(), a.pooled() + b.pooled()), (1, 0), "one node, once, and nothing else reached any node");
    let (stem, other) = if a.stems() == 1 { (&a, &b) } else { (&b, &a) };
    assert_eq!(stem.served.stems.lock().unwrap()[0].hash(), tx.hash());

    // the network has it: the other node passes it on
    other.relay(&tx);
    wait_for("the wallet to be told", || chain.post(&bytes(&tx)) == Posted::Accepted);
    assert_eq!(a.served.txs_asked.load(std::sync::atomic::Ordering::Relaxed) + b.served.txs_asked.load(std::sync::atomic::Ordering::Relaxed), 0, "nobody was asked for it");
    // long after the stem's time: it was seen, so nothing more is sent
    std::thread::sleep(STEM_FOR + Duration::from_secs(1));
    assert_eq!((stem.pooled(), a.stems() + b.stems()), (0, 1));

    // in a block
    let headers = {
        let mut source = source.write().unwrap();
        source.mine_with(std::slice::from_ref(&tx));
        source.headers()
    };
    for node in [&a, &b] {
        node.set(&headers);
        node.announce();
    }
    wait_for("the block", || chain.status().is_some_and(|s| s.tip.is_some_and(|tip| tip.height == 47)));
    assert_eq!(chain.post(&bytes(&tx)), Posted::Accepted);
}

/// A stem that does not come back from the network is sent through "Tor"
/// once more when its time is up - not before - to another node, and so
/// again every so often. Nothing about it goes over the program's own
/// connections: no node there is told of it or asked for it. When a node
/// hands it back, the wallet is told "accepted".
#[test]
fn a_stem_that_does_not_come_back_is_sent_again() {
    let source = chain_with_funds();
    let (a, b) = (Node::with_state(&source), Node::with_state(&source));
    let (_t, mut chain) = program("embargo", &source, &[&a, &b], &[], Start::default());
    global::set_local_chain_type(ChainTypes::AutomatedTesting);

    let tx = Source::spend_paid(42, FEE);
    let began = Instant::now();
    assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown);
    wait_for("the stem", || a.stems() + b.stems() == 1);
    let first_to_a = a.stems() == 1;
    while began.elapsed() + Duration::from_millis(600) < STEM_FOR {
        assert_eq!(a.stems() + b.stems(), 1, "not again before the stem's time");
        assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown);
        std::thread::sleep(Duration::from_millis(200));
    }
    wait_for("the second try", || a.stems() + b.stems() == 2);
    assert!(began.elapsed() >= STEM_FOR);
    assert_eq!((a.stems(), b.stems()), (1, 1), "the other node this time (first to a: {first_to_a})");
    wait_for("and again", || a.stems() + b.stems() >= 3);
    let asked = a.served.txs_asked.load(std::sync::atomic::Ordering::Relaxed) + b.served.txs_asked.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!((a.pooled() + b.pooled(), asked), (0, 0), "nothing over the program's own connections");
    a.relay(&tx);
    wait_for("the wallet to be told", || chain.post(&bytes(&tx)) == Posted::Accepted);
    let sent = a.stems() + b.stems();
    std::thread::sleep(post_resend() * 2);
    assert_eq!(a.stems() + b.stems(), sent, "nothing more once a node handed it back");
}

fn post_resend() -> Duration {
    fly_chain::post::RESEND_EVERY + Duration::from_millis(500)
}

/// A transaction that gets into a block before any node handed it over is
/// "accepted" because of the block alone, and is not sent again. When the
/// chain turns onto a branch that does not have it, it is in no block any
/// more: it is sent through "Tor" once more, so that it can get into a
/// block of the chain there is now.
#[test]
fn a_transaction_that_falls_out_of_the_chain_is_sent_again() {
    let source = chain_with_funds();
    let (a, b) = (Node::with_state(&source), Node::with_state(&source));
    let (_t, mut chain) = program("turn", &source, &[&a, &b], &[], Start::default());
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let tell = |source: &Arc<RwLock<Source>>| {
        let headers = source.read().unwrap().headers();
        for node in [&a, &b] {
            node.set(&headers);
            node.announce();
        }
    };

    let tx = Source::spend_paid(43, FEE);
    assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown);
    wait_for("the stem", || a.stems() + b.stems() == 1);
    source.write().unwrap().mine_with(std::slice::from_ref(&tx));
    tell(&source);
    wait_for("the block", || chain.status().is_some_and(|s| s.tip.is_some_and(|tip| tip.height == 47)));
    wait_for("the wallet to be told", || chain.post(&bytes(&tx)) == Posted::Accepted);
    std::thread::sleep(STEM_FOR + Duration::from_millis(1500));
    assert_eq!((a.stems() + b.stems(), a.pooled() + b.pooled()), (1, 0), "what is in a block is not sent again");

    // another branch from 46 on, three blocks long, without the transaction
    source.write().unwrap().branch(46, 3);
    tell(&source);
    wait_for("the other branch", || chain.status().is_some_and(|s| s.tip.is_some_and(|tip| tip.height == 49)));
    wait_for("the transaction sent again", || a.stems() + b.stems() >= 2);
    assert_eq!(a.pooled() + b.pooled(), 0);
    a.relay(&tx);
    wait_for("the wallet to be told", || chain.post(&bytes(&tx)) == Posted::Accepted);
}

/// With public nodes listed, the transaction goes to one of them by its
/// API, as a stem; no node of the network gets it from this program. When
/// the stem's time is up it goes once more, to another public node, to be
/// announced at once. A public node that will not take it is passed by for
/// the next one; when no public node takes it, a node of the network gets
/// it as a stem. What arrives is the very transaction the wallet handed
/// over.
#[test]
fn public_nodes_take_it_by_their_api() {
    let source = chain_with_funds();
    let (a, b) = (Node::with_state(&source), Node::with_state(&source));
    let (one, two) = (Public::start(), Public::start());
    let (_t, mut chain) = program("api", &source, &[&a, &b], &[&one, &two], Start::default());
    global::set_local_chain_type(ChainTypes::AutomatedTesting);

    let tx = Source::spend_paid(44, FEE);
    assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown);
    wait_for("the push", || one.count() + two.count() == 1);
    let (first, second) = if one.count() == 1 { (&one, &two) } else { (&two, &one) };
    let (given, fluff) = first.pushed.lock().unwrap()[0].clone();
    assert!(given.hash() == tx.hash() && bytes(&given) == bytes(&tx) && !fluff, "the very transaction, as a stem");
    wait_for("the announcement", || second.count() == 1);
    assert!(second.pushed.lock().unwrap()[0].1, "to be announced, by the other public node");
    assert_eq!((a.stems() + b.stems(), a.pooled() + b.pooled()), (0, 0), "no node of the network got it");

    // both refuse: the next goes to a node of the network
    one.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    two.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    let other = Source::spend_paid(45, FEE);
    assert_eq!(chain.post(&bytes(&other)), Posted::Unknown);
    wait_for("the stem to a node", || a.stems() + b.stems() == 1);
    assert_eq!(one.count() + two.count(), 2, "neither took it");
}

/// When "Tor" does not come up, nothing goes out from this computer's
/// address and the wallet is told why. With the user's agreement the
/// transaction goes over the program's own connections instead.
#[test]
fn without_tor() {
    let source = chain_with_funds();
    let (a, b) = (Node::with_state(&source), Node::with_state(&source));
    let public = Public::start();
    let (_t, mut chain) = program("no-tor", &source, &[&a, &b], &[&public], Start { no_tor: true, ..Start::default() });
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let tx = Source::spend_paid(41, FEE);
    assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown);
    wait_for("the reason", || {
        chain.problem().is_some_and(|text| {
            text.starts_with("a transaction is not sent: Tor did not come up; tried again, never from this computer's address without your agreement; headers verified")
        })
    });
    std::thread::sleep(fly_chain::post::RETRY_AFTER * 3);
    assert_eq!((a.stems() + b.stems(), a.pooled() + b.pooled(), public.count()), (0, 0, 0), "nothing went anywhere");
    assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown);
    drop(chain);

    // with the agreement
    let (_t, mut chain) = program("no-tor-agreed", &source, &[&a, &b], &[&public], Start { no_tor: true, direct: true, ..Start::default() });
    assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown);
    wait_for("the stem over the program's own connection", || a.stems() + b.stems() == 1);
    assert_eq!(public.count(), 0);
    // announced to all when the stem's time is up, as before
    wait_for("the announcement", || a.pooled() == 1 && b.pooled() == 1);
    wait_for("the wallet to be told", || chain.post(&bytes(&tx)) == Posted::Accepted);
    let text = chain.problem().unwrap_or_default();
    assert!(!text.contains("is not sent"), "{text}");
}

/// K192: the owner's agreement to the direct way for one transaction. Given
/// while a try through Tor is under way, it changes nothing until that try
/// fails - and a transaction Tor does send is not sent directly as well.
/// Given after a try has failed, the transaction goes over the program's
/// own connections at once. It is for that transaction only, and for no
/// transaction this program does not keep track of.
#[test]
fn the_agreement_to_the_direct_way_for_one() {
    let (_, live) = shared();
    let (t0, peers) = (Instant::now(), peers());
    let (first, second) = (Source::spend_paid(41, FEE), Source::spend_paid(42, FEE));
    let fail = || Err("Tor did not come up".to_string());

    // a transaction never handed over is not agreed to
    let mut outbox = Outbox::new(false);
    assert!(matches!(outbox.agree_direct(&bytes(&first), t0, &peers), (false, None)));
    assert!(matches!(outbox.agree_direct(b"not a transaction", t0, &peers), (false, None)));

    // agreed to while the try is under way: nothing yet; Tor sends it - never directly
    let (_, todo) = outbox.post(&bytes(&first), t0, Some(live), true);
    let Some(Do::Send { key, .. }) = todo else { panic!() };
    assert!(matches!(outbox.agree_direct(&bytes(&first), t0, &peers), (true, None)));
    assert!(outbox.sent(&key, Ok(()), t0, &peers).is_none());
    assert!(matches!(outbox.agree_direct(&bytes(&first), t0, &peers), (true, None)), "Tor has sent it");
    assert!(!outbox.direct(), "the agreement is not for everything");

    // agreed to while the try is under way, and the try fails: directly then
    let mut outbox = Outbox::new(false);
    let (_, todo) = outbox.post(&bytes(&first), t0, Some(live), true);
    let Some(Do::Send { key, .. }) = todo else { panic!() };
    let (_, todo) = outbox.post(&bytes(&second), t0, Some(live), true);
    let Some(Do::Send { key: other, .. }) = todo else { panic!() };
    assert!(matches!(outbox.agree_direct(&bytes(&first), t0, &peers), (true, None)));
    let todo = outbox.sent(&key, fail(), t0, &peers);
    let Some(Do::Stem { to, tx: sent }) = todo else { panic!("{todo:?}") };
    assert!(peers.contains(&to) && sent.hash() == first.hash());
    // the other one was not agreed to: it waits for Tor, and that is said
    assert!(outbox.sent(&other, fail(), t0, &peers).is_none());
    assert_eq!(outbox.trouble(), Some("Tor did not come up"));
    let due = outbox.tend(t0 + RETRY_AFTER, &peers);
    assert!(matches!(&due[..], [Do::Send { key, .. }] if *key == other), "{due:?}");

    // agreed to after the try failed: directly at once; nothing waits any more
    let mut outbox = Outbox::new(false);
    let (_, todo) = outbox.post(&bytes(&first), t0, Some(live), true);
    let Some(Do::Send { key, .. }) = todo else { panic!() };
    assert!(outbox.sent(&key, fail(), t0, &peers).is_none());
    assert_eq!(outbox.trouble(), Some("Tor did not come up"));
    // with nobody connected it cannot go; the agreement is kept for the next failure
    assert!(matches!(outbox.agree_direct(&bytes(&first), t0, &[]), (true, None)));
    assert_eq!(outbox.trouble(), Some("Tor did not come up"));
    let (known, todo) = outbox.agree_direct(&bytes(&first), t0, &peers);
    let Some(Do::Stem { tx: sent, .. }) = todo else { panic!("{todo:?}") };
    assert!(known && sent.hash() == first.hash());
    assert_eq!(outbox.trouble(), None, "it went");
    assert!(outbox.tend(t0 + RETRY_AFTER, &peers).is_empty(), "not through Tor again");
}

/// K192: when "Tor" does not come up and the direct way is not agreed to
/// for everything, nothing goes out - until the owner agrees for this one
/// transaction: then it goes over the program's own connections at once.
/// Another transaction, handed over without that agreement, still waits.
#[test]
fn the_direct_way_agreed_to_for_one_transaction() {
    let source = chain_with_funds();
    let (a, b) = (Node::with_state(&source), Node::with_state(&source));
    let public = Public::start();
    let (_t, mut chain) = program("direct-once", &source, &[&a, &b], &[&public], Start { no_tor: true, ..Start::default() });
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let first = Source::spend_paid(41, FEE);
    let second = Source::spend_paid(42, FEE);
    assert_eq!(chain.post(&bytes(&first)), Posted::Unknown);
    assert_eq!(chain.post(&bytes(&second)), Posted::Unknown);
    wait_for("the reason", || chain.problem().is_some_and(|text| text.contains("a transaction is not sent: Tor did not come up")));
    std::thread::sleep(fly_chain::post::RETRY_AFTER * 2);
    assert_eq!((a.stems() + b.stems(), public.count()), (0, 0), "something went out without the agreement");
    // the owner agrees for the first one
    assert_eq!(chain.post_direct(&bytes(&first)), Posted::Unknown);
    wait_for("the stem of the first over the program's own connection", || a.stems() + b.stems() == 1);
    wait_for("the announcement of the first", || a.pooled() == 1 && b.pooled() == 1);
    wait_for("the wallet to be told", || chain.post(&bytes(&first)) == Posted::Accepted);
    // the second was not agreed to: it has gone nowhere and is still said to wait
    std::thread::sleep(fly_chain::post::RETRY_AFTER * 2);
    assert_eq!((a.stems() + b.stems(), a.pooled(), b.pooled(), public.count()), (1, 1, 1, 0));
    assert_eq!(chain.post(&bytes(&second)), Posted::Unknown);
    let text = chain.problem().unwrap_or_default();
    assert!(text.contains("a transaction is not sent: Tor did not come up"), "{text}");
}

/// K189: with Tor switched off by the user no "Tor" is brought up and no
/// public node is asked through it; the transaction goes over the
/// program's own connections at once, without the separate agreement to
/// the direct way, and the wallet is not told of any trouble.
#[test]
fn with_tor_switched_off() {
    let source = chain_with_funds();
    let (a, b) = (Node::with_state(&source), Node::with_state(&source));
    let public = Public::start();
    // "Tor" would come up here, and the direct way is not agreed to
    let (_t, mut chain) = program("tor-off", &source, &[&a, &b], &[&public], Start { tor_off: true, ..Start::default() });
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let tx = Source::spend_paid(41, FEE);
    assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown);
    wait_for("the stem over the program's own connection", || a.stems() + b.stems() == 1);
    assert_eq!(public.count(), 0, "a public node was reached through \"Tor\"");
    wait_for("the announcement", || a.pooled() == 1 && b.pooled() == 1);
    wait_for("the wallet to be told", || chain.post(&bytes(&tx)) == Posted::Accepted);
    assert_eq!(public.count(), 0);
    let text = chain.problem().unwrap_or_default();
    assert!(!text.contains("is not sent"), "{text}");
}

/// A node the user listed as their own gets the transaction first - the
/// stem and the announcement - and the listed public nodes only when it
/// will not take it.
#[test]
fn the_users_own_node_comes_first() {
    let source = chain_with_funds();
    let (a, b) = (Node::with_state(&source), Node::with_state(&source));
    let (one, two, mine) = (Public::start(), Public::start(), Public::start());
    let (_t, mut chain) = program("own", &source, &[&a, &b], &[&one, &two, &mine], Start { own: 1, ..Start::default() });
    global::set_local_chain_type(ChainTypes::AutomatedTesting);

    let tx = Source::spend_paid(44, FEE);
    assert_eq!(chain.post(&bytes(&tx)), Posted::Unknown);
    wait_for("the stem", || mine.count() == 1);
    assert!(!mine.pushed.lock().unwrap()[0].1, "as a stem");
    wait_for("the announcement", || mine.count() == 2);
    assert!(mine.pushed.lock().unwrap()[1].1, "to be announced");
    assert_eq!((one.count() + two.count(), a.stems() + b.stems()), (0, 0), "nobody else got it");

    // it will not take the next: a listed one does
    mine.refuse.store(true, std::sync::atomic::Ordering::SeqCst);
    let other = Source::spend_paid(45, FEE);
    assert_eq!(chain.post(&bytes(&other)), Posted::Unknown);
    wait_for("a listed public node", || one.count() + two.count() == 1);
    assert_eq!(mine.count(), 2);
}
