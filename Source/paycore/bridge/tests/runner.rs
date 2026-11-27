//! The one worker of an unlocked profile, on real files, with a stand-in
//! relay shared between two profiles.
use fly_paycore_bridge::ports::{
    Broadcaster, ChainView, Clock, Envelope, Incoming, JsonCodec, Mailbox, Ports, Published,
};
use fly_paycore_bridge::runner::{Runner, RunnerError};
use fly_paycore_bridge::Bridge;
use fly_paycore_keys::path::KeyPath;
use fly_paycore_store::{FileGuard, FsDir, Identity, RootKey};
use fly_paycore_wallet::{Advance, Broadcast, ChainState, Core};
use grin_core::global::{self, ChainTypes};
use grin_core::libtx::proof::{self, ProofBuilder};
use grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const GRIN: u64 = 1_000_000_000;
const TICK: Duration = Duration::from_millis(200);
type B = Bridge<FsDir, FileGuard, ExtKeychain>;
/// id, from, to, text
type Stored = ([u8; 32], [u8; 32], [u8; 32], String);

#[derive(Default)]
struct Relay {
    down: AtomicBool,
    stored: Mutex<Vec<Stored>>,
    publishes: AtomicU32,
    next_id: AtomicU32,
}
struct Post {
    me: [u8; 32],
    relay: Arc<Relay>,
    done: BTreeSet<[u8; 32]>,
    round: BTreeSet<[u8; 32]>,
    replies: BTreeMap<[u8; 32], Envelope>,
    /// Set when the mailbox is dropped: the profile's transport is gone.
    gone: Arc<AtomicBool>,
}
impl Drop for Post {
    fn drop(&mut self) {
        self.gone.store(true, Ordering::SeqCst);
    }
}
impl Mailbox for Post {
    fn seal(&mut self, to: &[u8; 32], text: &str) -> Result<Envelope, String> {
        let n = self.relay.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let mut event_id = [0xEE; 32];
        event_id[..4].copy_from_slice(&n.to_le_bytes());
        let mut bytes = self.me.to_vec();
        bytes.extend_from_slice(to);
        bytes.extend_from_slice(text.as_bytes());
        Ok(Envelope {
            event_id,
            bytes,
            expires_at: u64::MAX,
        })
    }
    fn publish(&mut self, e: &Envelope) -> Published {
        self.relay.publishes.fetch_add(1, Ordering::SeqCst);
        if self.relay.down.load(Ordering::SeqCst) {
            return Published::Unknown;
        }
        let mut stored = self.relay.stored.lock().unwrap();
        if !stored.iter().any(|m| m.0 == e.event_id) {
            stored.push((
                e.event_id,
                e.bytes[..32].try_into().unwrap(),
                e.bytes[32..64].try_into().unwrap(),
                String::from_utf8(e.bytes[64..].to_vec()).unwrap(),
            ));
        }
        Published::Accepted
    }
    fn next_incoming(&mut self) -> Option<Incoming> {
        let found = self
            .relay
            .stored
            .lock()
            .unwrap()
            .iter()
            .find(|m| m.2 == self.me && !self.done.contains(&m.0) && !self.round.contains(&m.0))
            .cloned();
        match found {
            Some((id, from, _, text)) => {
                self.round.insert(id);
                Some(Incoming { id, from, text })
            }
            None => {
                self.round.clear();
                None
            }
        }
    }
    fn resend_reply(&mut self, incoming: &[u8; 32]) -> Option<Published> {
        let stored = self.replies.get(incoming).cloned()?;
        Some(self.publish(&stored))
    }
    fn reply(&mut self, incoming: &[u8; 32], text: &str) -> Published {
        if let Some(p) = self.resend_reply(incoming) {
            return p;
        }
        let to = self
            .relay
            .stored
            .lock()
            .unwrap()
            .iter()
            .find(|m| m.0 == *incoming)
            .unwrap()
            .1;
        let envelope = self.seal(&to, text).unwrap();
        self.replies.insert(*incoming, envelope.clone());
        self.publish(&envelope)
    }
    fn done(&mut self, incoming: &[u8; 32]) {
        self.done.insert(*incoming);
    }
}

struct Net;
impl Broadcaster for Net {
    fn post_tx(&mut self, _tx: &[u8]) -> Broadcast {
        Broadcast::Accepted
    }
}
/// The confirmed time of the profile in a folder: 1000 seconds, unless a
/// test moved it for that folder.
struct Time(PathBuf);
static CLOCKS: Mutex<Vec<(PathBuf, u64)>> = Mutex::new(Vec::new());
fn set_clock(base: &Path, seconds: u64) {
    let mut clocks = CLOCKS.lock().unwrap();
    clocks.retain(|(of, _)| of != base);
    clocks.push((base.to_path_buf(), seconds));
}
impl Clock for Time {
    fn confirmed_time(&self) -> Option<u64> {
        let clocks = CLOCKS.lock().unwrap();
        Some(clocks.iter().find(|(of, _)| of == &self.0).map_or(1_000, |(_, at)| *at))
    }
}
struct View;
impl ChainView for View {
    fn chain_state(&self) -> ChainState {
        ChainState::AtTip
    }
    fn k_conf(&self) -> u64 {
        3
    }
    fn rangeproofs_authenticated(&self) -> bool {
        true
    }
}

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str) -> Temp {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("fly-runner-{tag}-{}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(p.join("os")).unwrap();
        Temp(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
/// The transport secret of test profile `seed` and the key that belongs to it.
fn secret(seed: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[31] = seed;
    s
}
fn contact(seed: u8) -> [u8; 32] {
    use grin_util::secp::key::{PublicKey, SecretKey};
    let secp = grin_util::static_secp_instance();
    let secp = secp.lock();
    let sk = SecretKey::from_slice(&secp, &secret(seed)).unwrap();
    PublicKey::from_secret_key(&secp, &sk).unwrap().serialize_vec(&secp, true)[1..33]
        .try_into()
        .unwrap()
}

/// Open (or create and fund) the profile `seed` in `base`, on this thread.
fn open(base: &Path, seed: u8, relay: Arc<Relay>, gone: Arc<AtomicBool>) -> Result<B, String> {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let kc = ExtKeychain::from_seed(&[seed; 32], true).map_err(|e| format!("{e:?}"))?;
    let dir = FsDir::new(&base.join("wallet")).map_err(|e| e.to_string())?;
    let guard = FileGuard::new(&base.join("os").join("guard"), [7; 32]).map_err(|e| e.to_string())?;
    let root = RootKey::new([0x42; 32]);
    let id = Identity {
        network: 2,
        genesis: [7; 32],
        instance: [seed; 16],
    };
    let fresh = !base.join("wallet").join("CURRENT").exists()
        && std::fs::read_dir(base.join("wallet")).map(|d| d.count() <= 1).unwrap_or(true);
    let core = if fresh {
        let mut core = Core::create(dir, guard, &root, id, kc.clone(), 0, 3).map_err(|e| format!("{e:?}"))?;
        // one block with funds for profile 1, one empty block
        let mut a = Advance {
            height: 1,
            hash: [1; 32],
            ..Advance::default()
        };
        if seed == 1 {
            let builder = ProofBuilder::new(&kc);
            for (n, v) in [5 * GRIN, 3 * GRIN].iter().enumerate() {
                let key = KeyPath::Legacy {
                    account: 0,
                    index: n as u32,
                }
                .to_identifier();
                let commit = kc.commit(*v, &key, SwitchCommitmentType::Regular).unwrap();
                let rp = proof::create(&kc, &builder, *v, &key, SwitchCommitmentType::Regular, commit, None)
                    .unwrap();
                a.outputs.push((commit, rp, n as u64 + 1, false));
            }
        }
        core.chain_advance(&a).map_err(|e| format!("{e:?}"))?;
        core.chain_advance(&Advance {
            height: 2,
            hash: [2; 32],
            ..Advance::default()
        })
        .map_err(|e| format!("{e:?}"))?;
        // profiles 1 and 2 know each other
        core.identity_import(&secret(seed), false).map_err(|e| format!("{e:?}"))?;
        core.contact_set(contact(3 - seed), "the other one", None).map_err(|e| format!("{e:?}"))?;
        core
    } else {
        Core::open(dir, guard, &root, id, kc, 3).map_err(|e| format!("{e:?}"))?.0
    };
    Ok(Bridge::new(
        core,
        Ports {
            broadcaster: Box::new(Net),
            clock: Box::new(Time(base.to_path_buf())),
            chain: Box::new(View),
            codec: Box::new(JsonCodec),
            mailbox: Some(Box::new(Post {
                me: contact(seed),
                relay,
                done: BTreeSet::new(),
                round: BTreeSet::new(),
                replies: BTreeMap::new(),
                gone,
            })),
        },
    ))
}

struct Profile {
    runner: Runner,
    events: Arc<Mutex<Vec<Value>>>,
    gone: Arc<AtomicBool>,
}
fn start(base: &Path, seed: u8, relay: &Arc<Relay>) -> Result<Profile, String> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let sink = events.clone();
    let gone = Arc::new(AtomicBool::new(false));
    let (b, r, g) = (base.to_path_buf(), relay.clone(), gone.clone());
    let runner = Runner::start(
        move || open(&b, seed, r, g),
        TICK,
        Box::new(move |note| sink.lock().unwrap().push(serde_json::from_str(note).unwrap())),
    )?;
    Ok(Profile {
        runner,
        events,
        gone,
    })
}
fn rpc(r: &Runner, method: &str, params: Value) -> Result<Value, Value> {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let v: Value = serde_json::from_str(&r.call(&req.to_string()).unwrap()).unwrap();
    match v.get("result") {
        Some(x) => Ok(x.clone()),
        None => Err(v["error"].clone()),
    }
}
fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(20);
    while !ready() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A chain layer far ahead of the wallet: a starting block and many empty
/// blocks after it.
struct Far(u64);
impl fly_paycore_bridge::chain_port::ChainFeed for Far {
    fn status(&mut self) -> Option<fly_paycore_bridge::chain_port::Status> {
        None
    }
    fn next(&mut self, at: Option<fly_paycore_bridge::chain_port::Tip>) -> Result<fly_paycore_bridge::chain_port::Step, fly_paycore_bridge::chain_port::Unknown> {
        use fly_paycore_bridge::chain_port::{BlockFacts, Step, Tip};
        let hash = |height: u64| [(height % 251) as u8; 32];
        Ok(match at {
            Some(at) if at.hash == hash(at.height) && at.height >= 100 => {
                if at.height >= self.0 {
                    Step::Nothing
                } else {
                    Step::Block(Box::new(BlockFacts { height: at.height + 1, hash: hash(at.height + 1), ..BlockFacts::default() }))
                }
            }
            _ => Step::Reanchor(Tip { height: 100, hash: hash(100) }),
        })
    }
    fn post(&mut self, _tx: &[u8]) -> fly_paycore_bridge::chain_port::Posted {
        fly_paycore_bridge::chain_port::Posted::Unknown
    }
}

/// A wallet with a long way to go does not sit out the pause between
/// rounds: while the chain layer has more than one round takes, the next
/// round follows at once. With a pause of a minute, six hundred blocks -
/// ten rounds - are taken in seconds, and requests are answered meanwhile.
#[test]
fn a_wallet_that_is_behind_does_not_pause_between_rounds() {
    let t = Temp::new("behind");
    let (relay, gone) = (Arc::new(Relay::default()), Arc::new(AtomicBool::new(false)));
    let base = t.0.clone();
    let runner = Runner::start(
        move || {
            let mut bridge = open(&base, 1, relay, gone)?;
            bridge.set_chain_feed(Box::new(Far(700)));
            Ok(bridge)
        },
        Duration::from_secs(60),
        Box::new(|_| {}),
    )
    .unwrap();
    let tip = |r: &Runner| rpc(r, "paycore.info", json!({})).unwrap()["tip_height"].as_u64();
    let started = Instant::now();
    wait_for("the tip", || tip(&runner) == Some(700));
    assert!(started.elapsed() < Duration::from_secs(20));
    // at the tip the pause is the pause again: nothing asks the chain layer for a while
    assert_eq!(tip(&runner), Some(700));
    runner.stop();
}

/// A chain layer at block 100 whose pieces of old outputs come one after
/// another, a little apart - as they do from nodes on a network.
struct Trickle {
    began: Option<Instant>,
    every: Duration,
    pieces: u64,
}
impl fly_paycore_bridge::chain_port::ChainFeed for Trickle {
    fn status(&mut self) -> Option<fly_paycore_bridge::chain_port::Status> {
        None
    }
    fn next(&mut self, at: Option<fly_paycore_bridge::chain_port::Tip>) -> Result<fly_paycore_bridge::chain_port::Step, fly_paycore_bridge::chain_port::Unknown> {
        use fly_paycore_bridge::chain_port::{Step, Tip};
        Ok(match at {
            Some(at) if at.height == 100 => Step::Nothing,
            _ => Step::Reanchor(Tip { height: 100, hash: [100; 32] }),
        })
    }
    fn post(&mut self, _tx: &[u8]) -> fly_paycore_bridge::chain_port::Posted {
        fly_paycore_bridge::chain_port::Posted::Unknown
    }
    fn old_outputs(&mut self, piece: u64) -> Result<fly_paycore_bridge::chain_port::OldOutputs, fly_paycore_bridge::chain_port::Unknown> {
        use fly_paycore_bridge::chain_port::{OldOutputs, Tip, Unknown};
        // the first piece is there when it is first asked for, each later one `every` after the one before
        let began = *self.began.get_or_insert_with(Instant::now);
        let there = began.elapsed().as_millis() / self.every.as_millis().max(1);
        if u128::from(piece) > there {
            return Err(Unknown);
        }
        Ok(OldOutputs {
            outputs: Vec::new(),
            at: Tip { height: 100, hash: [100; 32] },
            before: 100,
            next: Some(piece + 1).filter(|next| *next < self.pieces),
            pieces: self.pieces,
            bare: false,
        })
    }
}

/// Pieces of old outputs that come a little apart are read as they come:
/// a round that finds the next piece not there yet does not send the
/// handler into its pause, even a round that read nothing at all. The
/// pieces here come further apart than rounds follow one another, so
/// every other round reads nothing; with a pause of a minute, twelve
/// pieces half a second apart are still read in seconds.
#[test]
fn pieces_that_trickle_in_are_read_without_the_pause() {
    let t = Temp::new("trickle");
    let (relay, gone) = (Arc::new(Relay::default()), Arc::new(AtomicBool::new(false)));
    let base = t.0.clone();
    let runner = Runner::start(
        move || {
            let mut bridge = open(&base, 1, relay, gone)?;
            bridge.set_chain_feed(Box::new(Trickle { began: None, every: Duration::from_millis(500), pieces: 12 }));
            Ok(bridge)
        },
        Duration::from_secs(60),
        Box::new(|_| {}),
    )
    .unwrap();
    // The wallet of these tests stands on blocks of its own; the chain
    // layer puts it on block 100, past blocks it has not seen, and the
    // search for old outputs starts by itself.
    let started = Instant::now();
    wait_for("the search", || rpc(&runner, "paycore.search.status", json!({})).unwrap()["state"] == "done");
    assert!(started.elapsed() < Duration::from_secs(15), "{:?}", started.elapsed());
    let timing = rpc(&runner, "paycore.chain.timing", json!({})).unwrap();
    assert_eq!(timing["pieces"]["read"], json!(12), "{timing}");
    assert!(timing["pieces"]["not_ready"].as_u64() > Some(12), "most rounds found the next piece not there yet: {timing}");
    runner.stop();
}

/// Nobody asks for delivery: the worker publishes, receives and reports by
/// itself, and the interface only prepares and confirms.
#[test]
fn the_worker_delivers_without_being_asked() {
    let (ta, tb) = (Temp::new("a"), Temp::new("b"));
    let relay = Arc::new(Relay::default());
    let a = start(&ta.0, 1, &relay).unwrap();
    let b = start(&tb.0, 2, &relay).unwrap();
    rpc(&b.runner, "paycore.receive.set_auto", json!({"on": true})).unwrap();
    let p = rpc(
        &a.runner,
        "paycore.send.prepare",
        json!({"amount": GRIN.to_string(), "deliver_to": hex(&contact(2))}),
    )
    .unwrap();
    let held = |events: &Arc<Mutex<Vec<Value>>>| {
        events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e["params"]["event"]["kind"] == "reply_held" && e["params"]["event"]["op"] == p["op"])
    };
    wait_for("the reply to be held", || held(&a.events));
    {
        let ev = a.events.lock().unwrap();
        assert!(ev.iter().all(|e| e["method"] == "paycore.event"));
        assert!(ev
            .iter()
            .any(|e| e["params"]["source"] == "published" && e["params"]["event"]["delivery"] == "relay_accepted"));
    }
    assert!(b
        .events
        .lock()
        .unwrap()
        .iter()
        .any(|e| e["params"]["event"]["kind"] == "payment_answered"));
    let st = rpc(&a.runner, "paycore.send.status", json!({"op": p["op"]})).unwrap();
    assert_eq!((&st["state"], &st["reply_held"]), (&json!("prepared"), &json!(true)));
    // the worker never signs by itself: that takes the user's confirmation
    std::thread::sleep(TICK * 3);
    assert_eq!(rpc(&a.runner, "paycore.send.status", json!({"op": p["op"]})).unwrap()["state"], "prepared");
    let fin = rpc(&a.runner, "paycore.send.finalize_held", json!({"op": p["op"]})).unwrap();
    assert!(fin["tx"].as_str().unwrap().len() > 100);
    assert_eq!(relay.stored.lock().unwrap().len(), 2, "one message each way");
}

/// A payment the user accepted and the sender never completed (cancelled
/// on their side, or simply left) does not stay open for ever: after seven
/// days of confirmed time the worker closes the draft by itself, without
/// the interface asking. One second earlier it is still open.
#[test]
fn the_worker_closes_receive_drafts_whose_time_ran_out() {
    let (ta, tb) = (Temp::new("a"), Temp::new("b"));
    let relay = Arc::new(Relay::default());
    let a = start(&ta.0, 1, &relay).unwrap();
    let b = start(&tb.0, 2, &relay).unwrap();
    let p = rpc(&a.runner, "paycore.send.prepare", json!({"amount": GRIN.to_string()})).unwrap();
    rpc(&b.runner, "paycore.receive.draft", json!({"slate": p["slate"]})).unwrap();
    // the sender cancels; nothing tells the recipient
    rpc(&a.runner, "paycore.send.cancel", json!({"op": p["op"]})).unwrap();
    let abandoned = || rpc(&b.runner, "paycore.history", json!({})).unwrap()["incoming"][0]["abandoned"].clone();
    let week = 7 * 24 * 3600;
    set_clock(&tb.0, 1_000 + week - 1);
    std::thread::sleep(TICK * 4);
    assert_eq!(abandoned(), false, "a second short of seven days");
    set_clock(&tb.0, 1_000 + week);
    wait_for("the draft to be closed by the worker", || abandoned() == true);
}

/// Locking the profile ends the worker: nothing is published afterwards, the
/// transport is dropped, the files can be opened again, and only then.
#[test]
fn locking_the_profile_ends_everything() {
    let t = Temp::new("lock");
    let relay = Arc::new(Relay::default());
    relay.down.store(true, Ordering::SeqCst);
    let a = start(&t.0, 1, &relay).unwrap();
    let p = rpc(
        &a.runner,
        "paycore.send.prepare",
        json!({"amount": GRIN.to_string(), "deliver_to": hex(&contact(2))}),
    )
    .unwrap();
    // the relay is silent, so the worker keeps trying
    wait_for("several attempts", || relay.publishes.load(Ordering::SeqCst) >= 3);
    // a second worker on the same profile is refused while this one runs
    assert!(start(&t.0, 1, &relay).is_err(), "two workers on one profile");
    assert!(!a.gone.load(Ordering::SeqCst));

    let Profile { runner, gone, .. } = a;
    runner.stop();
    assert!(gone.load(Ordering::SeqCst), "the transport outlived the lock");
    let after = relay.publishes.load(Ordering::SeqCst);
    std::thread::sleep(TICK * 4);
    assert_eq!(relay.publishes.load(Ordering::SeqCst), after, "published after the lock");

    // Reopening preserves the record and reserve. The lost signing session
    // cannot finish this exchange, even when its relay comes back.
    let again = start(&t.0, 1, &relay).unwrap();
    let st = rpc(&again.runner, "paycore.send.status", json!({"op": p["op"]})).unwrap();
    assert_eq!((&st["state"], &st["delivery"]), (&json!("prepared"), &json!("waiting_relay")));
    assert_eq!(st["session_expired"], true);
    assert_eq!(st["reserve"], true);
    relay.down.store(false, Ordering::SeqCst);
    let pump = rpc(&again.runner, "paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(pump["published"], json!([]));
    std::thread::sleep(TICK * 4);
    assert_eq!(relay.publishes.load(Ordering::SeqCst), after);
    assert!(relay.stored.lock().unwrap().is_empty());
    // dropping the handle locks as well
    let gone = again.gone.clone();
    drop(again);
    assert!(gone.load(Ordering::SeqCst));
}

/// Requests from many threads are handled one at a time, and after the lock
/// they are refused rather than left hanging.
#[test]
fn requests_are_serialized_and_refused_after_the_lock() {
    let t = Temp::new("many");
    let relay = Arc::new(Relay::default());
    let a = Arc::new(start(&t.0, 1, &relay).unwrap());
    let mut threads = Vec::new();
    for n in 0..8u64 {
        let a = a.clone();
        threads.push(std::thread::spawn(move || {
            let mut ops = Vec::new();
            for _ in 0..5 {
                // each thread prepares and cancels its own small payments
                let p = rpc(&a.runner, "paycore.send.prepare", json!({"amount": (1000 + n).to_string()}));
                if let Ok(p) = p {
                    rpc(&a.runner, "paycore.send.cancel", json!({"op": p["op"]})).unwrap();
                    ops.push(p["op"].clone());
                }
                let bal = rpc(&a.runner, "paycore.balance", json!({})).unwrap();
                let sum: u64 = ["spendable", "reserved", "immature"]
                    .iter()
                    .map(|k| bal[*k].as_str().unwrap().parse::<u64>().unwrap())
                    .sum();
                assert_eq!(sum, 8 * GRIN, "a torn view of the balance: {bal}");
            }
            ops.len()
        }));
    }
    let made: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
    assert!(made > 0, "no payment could be prepared at all");
    let bal = rpc(&a.runner, "paycore.balance", json!({})).unwrap();
    assert_eq!(bal["reserved"], "0");
    let hist = rpc(&a.runner, "paycore.history", json!({})).unwrap();
    assert_eq!(hist["sends"].as_array().unwrap().len(), made);

    let a = Arc::try_unwrap(a).ok().unwrap();
    let Profile { runner, gone, .. } = a;
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        runner.stop();
        tx.send(()).unwrap();
    });
    rx.recv_timeout(Duration::from_secs(20)).expect("the lock hangs");
    handle.join().unwrap();
    assert!(gone.load(Ordering::SeqCst));
}

/// A profile that cannot be opened starts no worker, and a stopped handle
/// answers every call with "stopped".
#[test]
fn a_profile_that_does_not_open_starts_no_worker() {
    let r = Runner::start(
        || Err::<B, String>("wrong password".into()),
        TICK,
        Box::new(|_| {}),
    );
    assert_eq!(r.err().as_deref(), Some("wrong password"));

    // requests that wait while the profile is being locked are not started
    let t = Temp::new("stopped");
    let relay = Arc::new(Relay::default());
    let a = Arc::new(start(&t.0, 1, &relay).unwrap());
    let mut callers = Vec::new();
    for _ in 0..16 {
        let a = a.clone();
        callers.push(std::thread::spawn(move || {
            let mut stopped = 0u32;
            for _ in 0..200 {
                match a.runner.call(r#"{"jsonrpc":"2.0","id":1,"method":"paycore.history"}"#) {
                    Ok(text) => assert!(text.contains("\"result\"")),
                    Err(RunnerError::Stopped) => stopped += 1,
                    Err(RunnerError::Busy) => {}
                }
            }
            stopped
        }));
    }
    std::thread::sleep(Duration::from_millis(30));
    a.runner.lock_now();
    let stopped: u32 = callers.into_iter().map(|c| c.join().unwrap()).sum();
    assert!(stopped > 0, "the lock came too late to refuse anything");
    assert!(a.gone.load(Ordering::SeqCst), "the transport outlived the lock");
    assert_eq!(
        a.runner.call(r#"{"jsonrpc":"2.0","id":1,"method":"paycore.info"}"#),
        Err(RunnerError::Stopped)
    );
}

/// The topology of v0.2 with a stand-in transport: each profile's worker
/// talks through the pipe to its own transport process, and the two
/// transport processes share a directory as their relay.
/// Run with `cargo test --features stub`.
#[cfg(feature = "stub")]
#[test]
fn two_profiles_pay_through_two_transport_processes() {
    use fly_paycore_bridge::pipe::{Config, PipeMailbox};
    const STUB: &str = env!("CARGO_BIN_EXE_bridge-mailbox-stub");
    let (ta, tb, shared) = (Temp::new("pa"), Temp::new("pb"), Temp::new("relay"));
    let pids = Arc::new(Mutex::new(Vec::new()));
    let start_piped = |base: &Path, seed: u8| -> Profile {
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let (b, dir, pids) = (base.to_path_buf(), shared.0.clone(), pids.clone());
        let runner = Runner::start(
            move || {
                let bridge = open(&b, seed, Arc::new(Relay::default()), Arc::new(AtomicBool::new(false)))?;
                let mut bridge = Bridge::new(bridge.into_core(), fresh_ports());
                // the bridge starts the transport process itself, from what
                // the journal says about the identity and the contacts
                bridge.set_mailbox_factory(Box::new(move |spec| {
                    assert_eq!(*spec.identity_secret, secret(seed));
                    assert_eq!(spec.contacts, vec![contact(3 - seed)]);
                    assert_eq!(spec.identity_public, contact(seed));
                    let config = Config {
                        identity_secret: *spec.identity_secret,
                        identity_public: spec.identity_public,
                        store_key: *spec.store_key,
                        relay: "wss://relay.example".into(),
                        data_dir: dir.to_string_lossy().into_owned(),
                        contacts: spec.contacts.clone(),
                        delivery_window_secs: 900,
                        publish_timeout_ms: 1000,
                        poll_ms: 100,
                        start_timeout_secs: 10,
                        tor_bridges: String::new(),
                    };
                    let mailbox = PipeMailbox::spawn(Path::new(STUB), &config, Duration::from_secs(5))?;
                    pids.lock().unwrap().push(mailbox.process_id().unwrap());
                    Ok(Box::new(mailbox))
                }));
                Ok(bridge)
            },
            TICK,
            Box::new(move |note| sink.lock().unwrap().push(serde_json::from_str(note).unwrap())),
        )
        .unwrap();
        Profile {
            runner,
            events,
            gone: Arc::new(AtomicBool::new(false)),
        }
    };
    let a = start_piped(&ta.0, 1);
    let b = start_piped(&tb.0, 2);
    {
        let pids = pids.lock().unwrap();
        assert_eq!(pids.len(), 2);
        assert!(pids[0] != pids[1] && !pids.contains(&std::process::id()));
    }
    let alive = || {
        std::fs::read_dir(&shared.0)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "alive"))
            .count()
    };
    assert_eq!(alive(), 2);
    rpc(&b.runner, "paycore.receive.set_auto", json!({"on": true})).unwrap();
    let p = rpc(
        &a.runner,
        "paycore.send.prepare",
        json!({"amount": GRIN.to_string(), "deliver_to": hex(&contact(2))}),
    )
    .unwrap();
    wait_for("the reply to be held", || {
        a.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e["params"]["event"]["kind"] == "reply_held" && e["params"]["event"]["op"] == p["op"])
    });
    let fin = rpc(&a.runner, "paycore.send.finalize_held", json!({"op": p["op"]})).unwrap();
    assert!(fin["tx"].as_str().unwrap().len() > 100);
    // locking a profile ends its transport process as well
    drop(a);
    wait_for("the first transport process to end", || alive() == 1);
    drop(b);
    wait_for("the second transport process to end", || alive() == 0);
}

#[cfg(feature = "stub")]
fn fresh_ports() -> Ports {
    Ports {
        broadcaster: Box::new(Net),
        clock: Box::new(Time(PathBuf::new())),
        chain: Box::new(View),
        codec: Box::new(JsonCodec),
        mailbox: None,
    }
}
