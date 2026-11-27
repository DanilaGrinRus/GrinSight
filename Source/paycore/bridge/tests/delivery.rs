//! Payments that travel by themselves: two wallets, each behind its bridge,
//! and a stand-in relay between their mailboxes. Nothing but JSON-RPC drives
//! the wallets.
use fly_paycore_bridge::ports::{
    Broadcaster, ChainView, Clock, Envelope, Incoming, Mailbox, Ports, Published, SlateCodec,
};
use fly_paycore_bridge::{Bridge, MAX_PER_SENDER, MAX_RECEIVE, MAX_STRIKES};
use fly_paycore_keys::path::KeyPath;
use fly_paycore_store::sim::{Sim, SimDir, SimGuard};
use fly_paycore_store::{Identity, RootKey};
use fly_paycore_wallet::{Advance, Broadcast, ChainState, Core};
use grin_core::core::transaction::{Transaction, Weighting};
use grin_core::global::{self, ChainTypes};
use grin_core::libtx::proof::{self, ProofBuilder};
use grin_core::ser;
use grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use serde_json::{json, Value};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::Duration;

const GRIN: u64 = 1_000_000_000;
const WINDOW_END: u64 = 5_000;
type B = Bridge<SimDir, SimGuard, ExtKeychain>;
type Tip = (u64, [u8; 32]);
/// id, from, to, text
type Stored = ([u8; 32], [u8; 32], [u8; 32], String);

// ----- the stand-in relay ---------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// Stores and acknowledges.
    Up,
    /// Loses the message and says nothing.
    Down,
    /// Stores the message but the acknowledgement is lost.
    Silent,
    Busy,
    Full,
    /// The transport itself says the window is closed.
    Late,
}

struct Relay {
    mode: Mode,
    /// id -> (from, to, text), in order of first arrival
    stored: Vec<Stored>,
    publishes: u32,
    next_id: u64,
}
impl Relay {
    fn new() -> Rc<RefCell<Relay>> {
        Rc::new(RefCell::new(Relay {
            mode: Mode::Up,
            stored: vec![],
            publishes: 0,
            next_id: 0,
        }))
    }
    fn fresh_id(&mut self) -> [u8; 32] {
        self.next_id += 1;
        let mut id = [0xEE; 32];
        id[..8].copy_from_slice(&self.next_id.to_le_bytes());
        id
    }
    fn store(&mut self, id: [u8; 32], from: [u8; 32], to: [u8; 32], text: &str) {
        if !self.stored.iter().any(|m| m.0 == id) {
            self.stored.push((id, from, to, text.to_string()));
        }
    }
    /// Someone publishes straight to the relay (spam, or a third party).
    fn inject(&mut self, from: [u8; 32], to: [u8; 32], text: &str) {
        let id = self.fresh_id();
        self.store(id, from, to, text);
    }
    fn held_for(&self, to: [u8; 32]) -> usize {
        self.stored.iter().filter(|m| m.2 == to).count()
    }
}

/// One wallet's mailbox. Its state outlives a restart of the bridge, as a
/// real transport's storage would.
struct PostState {
    me: [u8; 32],
    relay: Rc<RefCell<Relay>>,
    done: BTreeSet<[u8; 32]>,
    round: BTreeSet<[u8; 32]>,
    replies: BTreeMap<[u8; 32], Envelope>,
    seals: u32,
}
#[derive(Clone)]
struct Post(Rc<RefCell<PostState>>);

fn pack(from: &[u8; 32], to: &[u8; 32], text: &str) -> Vec<u8> {
    let mut b = from.to_vec();
    b.extend_from_slice(to);
    b.extend_from_slice(text.as_bytes());
    b
}
fn unpack(bytes: &[u8]) -> ([u8; 32], [u8; 32], String) {
    (
        bytes[..32].try_into().unwrap(),
        bytes[32..64].try_into().unwrap(),
        String::from_utf8(bytes[64..].to_vec()).unwrap(),
    )
}

impl Mailbox for Post {
    fn seal(&mut self, to: &[u8; 32], text: &str) -> Result<Envelope, String> {
        let mut s = self.0.borrow_mut();
        s.seals += 1;
        let event_id = s.relay.borrow_mut().fresh_id();
        Ok(Envelope {
            event_id,
            bytes: pack(&s.me, to, text),
            expires_at: WINDOW_END,
        })
    }
    fn publish(&mut self, envelope: &Envelope) -> Published {
        let s = self.0.borrow();
        let mut relay = s.relay.borrow_mut();
        relay.publishes += 1;
        let (from, to, text) = unpack(&envelope.bytes);
        assert_eq!(from, s.me, "an envelope of someone else was published");
        match relay.mode {
            Mode::Up => {
                relay.store(envelope.event_id, from, to, &text);
                Published::Accepted
            }
            Mode::Silent => {
                relay.store(envelope.event_id, from, to, &text);
                Published::Unknown
            }
            Mode::Down => Published::Unknown,
            Mode::Busy => Published::Busy,
            Mode::Full => Published::Full,
            Mode::Late => Published::Expired,
        }
    }
    fn next_incoming(&mut self) -> Option<Incoming> {
        let mut s = self.0.borrow_mut();
        let me = s.me;
        let found = s
            .relay
            .borrow()
            .stored
            .iter()
            .find(|m| m.2 == me && !s.done.contains(&m.0) && !s.round.contains(&m.0))
            .cloned();
        match found {
            Some((id, from, _, text)) => {
                s.round.insert(id);
                Some(Incoming { id, from, text })
            }
            None => {
                s.round.clear();
                None
            }
        }
    }
    fn resend_reply(&mut self, incoming: &[u8; 32]) -> Option<Published> {
        let stored = self.0.borrow().replies.get(incoming).cloned()?;
        Some(self.publish(&stored))
    }
    fn reply(&mut self, incoming: &[u8; 32], text: &str) -> Published {
        if let Some(p) = self.resend_reply(incoming) {
            return p;
        }
        let to = {
            let s = self.0.borrow();
            let relay = s.relay.borrow();
            relay.stored.iter().find(|m| m.0 == *incoming).unwrap().1
        };
        let envelope = self.seal(&to, text).unwrap();
        self.0.borrow_mut().replies.insert(*incoming, envelope.clone());
        self.publish(&envelope)
    }
    fn done(&mut self, incoming: &[u8; 32]) {
        self.0.borrow_mut().done.insert(*incoming);
    }
}

// ----- the other ports --------------------------------------------------------

struct Net;
impl Broadcaster for Net {
    fn post_tx(&mut self, _tx: &[u8]) -> Broadcast {
        Broadcast::Accepted
    }
}
struct Time(Rc<Cell<Option<u64>>>);
impl Clock for Time {
    fn confirmed_time(&self) -> Option<u64> {
        self.0.get()
    }
}
struct View(Rc<Cell<Option<Tip>>>);
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
    fn selected_tip(&self) -> Option<(u64, [u8; 32])> {
        self.0.get()
    }
}
/// Slate JSON as text, counting how often untrusted text was decoded.
struct Counting(Rc<Cell<u32>>, Rc<Cell<u32>>);
impl SlateCodec for Counting {
    fn decode(&mut self, text: &str) -> Result<Vec<u8>, String> {
        self.0.set(self.0.get() + 1);
        Ok(text.as_bytes().to_vec())
    }
    fn encode(&mut self, slate: &[u8]) -> Result<String, String> {
        self.1.set(self.1.get() + 1);
        String::from_utf8(slate.to_vec()).map_err(|_| "slate is not text".to_string())
    }
}

struct Wallet {
    b: Option<B>,
    seed: u8,
    sim: Sim,
    post: Post,
    clock: Rc<Cell<Option<u64>>>,
    sel: Rc<Cell<Option<Tip>>>,
    decodes: Rc<Cell<u32>>,
    encodes: Rc<Cell<u32>>,
}
fn kc(seed: u8) -> ExtKeychain {
    ExtKeychain::from_seed(&[seed; 32], true).unwrap()
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
fn identity(seed: u8) -> Identity {
    Identity {
        network: 2,
        genesis: [7; 32],
        instance: [seed; 16],
    }
}
impl Wallet {
    fn new(seed: u8, relay: &Rc<RefCell<Relay>>) -> Wallet {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let sim = Sim::new();
        let core = Core::create(
            sim.dir(),
            sim.guard(),
            &RootKey::new([0x42; 32]),
            identity(seed),
            kc(seed),
            0,
            3,
        )
        .unwrap();
        let mut w = Wallet {
            b: None,
            seed,
            sim,
            post: Post(Rc::new(RefCell::new(PostState {
                me: contact(seed),
                relay: relay.clone(),
                done: BTreeSet::new(),
                round: BTreeSet::new(),
                replies: BTreeMap::new(),
                seals: 0,
            }))),
            clock: Rc::new(Cell::new(Some(1_000))),
            sel: Rc::new(Cell::new(None)),
            decodes: Rc::new(Cell::new(0)),
            encodes: Rc::new(Cell::new(0)),
        };
        w.b = Some(Bridge::new(core, w.ports()));
        // these tests pump as fast as they can; the pauses have their own test
        w.b().set_publish_retry(Duration::ZERO, Duration::ZERO);
        w.b().core_mut().identity_import(&secret(seed), false).unwrap();
        w
    }
    fn ports(&self) -> Ports {
        Ports {
            broadcaster: Box::new(Net),
            clock: Box::new(Time(self.clock.clone())),
            chain: Box::new(View(self.sel.clone())),
            codec: Box::new(Counting(self.decodes.clone(), self.encodes.clone())),
            mailbox: Some(Box::new(self.post.clone())),
        }
    }
    fn b(&mut self) -> &mut B {
        self.b.as_mut().unwrap()
    }
    /// Close the wallet and open it again from its files.
    fn restart(&mut self) {
        drop(self.b.take());
        let (core, report) = Core::open(
            self.sim.dir(),
            self.sim.guard(),
            &RootKey::new([0x42; 32]),
            identity(self.seed),
            kc(self.seed),
            3,
        )
        .unwrap();
        assert!(!report.recovered);
        self.b = Some(Bridge::new(core, self.ports()));
        self.b().set_publish_retry(Duration::ZERO, Duration::ZERO);
    }
    fn rpc(&mut self, method: &str, params: Value) -> Result<Value, Value> {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let text = self.b().call(&req.to_string());
        let v: Value = serde_json::from_str(&text).unwrap();
        match v.get("result") {
            Some(r) => Ok(r.clone()),
            None => Err(v["error"].clone()),
        }
    }
    fn kinds(&mut self) -> Vec<String> {
        self.rpc("paycore.delivery.receive", json!({})).unwrap()["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kind"].as_str().unwrap().to_string())
            .collect()
    }
    fn signatures(&mut self) -> u64 {
        self.b().core().signatures_made()
    }
}

struct Chain {
    height: u64,
    pos: u64,
}
impl Chain {
    fn tip(&self) -> (u64, [u8; 32]) {
        (self.height, [self.height as u8; 32])
    }
    fn push(&mut self, mut a: Advance, wallets: &mut [&mut Wallet]) {
        self.height += 1;
        a.height = self.height;
        a.hash = [self.height as u8; 32];
        for w in wallets.iter_mut() {
            w.b().core_mut().chain_advance(&a).unwrap();
        }
    }
    fn fund(&mut self, seed: u8, values: &[u64], wallets: &mut [&mut Wallet]) {
        let k = kc(seed);
        let builder = ProofBuilder::new(&k);
        let mut a = Advance::default();
        for (n, v) in values.iter().enumerate() {
            let key = KeyPath::Legacy {
                account: 0,
                index: n as u32,
            }
            .to_identifier();
            let commit = k.commit(*v, &key, SwitchCommitmentType::Regular).unwrap();
            let rp = proof::create(
                &k,
                &builder,
                *v,
                &key,
                SwitchCommitmentType::Regular,
                commit,
                None,
            )
            .unwrap();
            self.pos += 1;
            a.outputs.push((commit, rp, self.pos, false));
        }
        self.push(a, wallets);
    }
    fn mine(&mut self, tx: &[u8], wallets: &mut [&mut Wallet]) {
        let tx: Transaction = ser::deserialize(
            &mut &tx[..],
            ser::ProtocolVersion::local(),
            ser::DeserializationMode::default(),
        )
        .unwrap();
        tx.validate(Weighting::AsTransaction).unwrap();
        let mut a = Advance::default();
        for o in tx.outputs() {
            self.pos += 1;
            a.outputs.push((o.commitment(), o.proof, self.pos, false));
        }
        let ins: Vec<grin_core::core::transaction::CommitWrapper> = tx.inputs().into();
        a.inputs = ins.iter().map(|c| c.commitment()).collect();
        a.kernels = tx.kernels().iter().map(|k| k.excess).collect();
        self.push(a, wallets);
    }
    fn empty(&mut self, n: u64, wallets: &mut [&mut Wallet]) {
        for _ in 0..n {
            self.push(Advance::default(), wallets);
        }
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

struct World {
    relay: Rc<RefCell<Relay>>,
    a: Wallet,
    b: Wallet,
    chain: Chain,
}
/// Wallet 1 has funds and pays; wallet 2 receives unattended unless told
/// otherwise.
fn world(auto_receive: bool) -> World {
    let relay = Relay::new();
    let mut a = Wallet::new(1, &relay);
    let mut b = Wallet::new(2, &relay);
    let mut chain = Chain { height: 0, pos: 0 };
    chain.fund(1, &[5 * GRIN, 3 * GRIN, 2 * GRIN], &mut [&mut a, &mut b]);
    chain.empty(1, &mut [&mut a, &mut b]);
    a.b().core_mut().contact_set(contact(2), "Bob", None).unwrap();
    b.b().core_mut().contact_set(contact(1), "Alice", None).unwrap();
    if auto_receive {
        b.rpc("paycore.receive.set_auto", json!({"on": true})).unwrap();
    }
    World { relay, a, b, chain }
}
fn prepare(a: &mut Wallet, to: u8, amount: u64) -> Value {
    a.rpc(
        "paycore.send.prepare",
        json!({"amount": amount.to_string(), "deliver_to": hex(&contact(to))}),
    )
    .unwrap()
}
fn status(w: &mut Wallet, op: &Value) -> Value {
    w.rpc("paycore.send.status", json!({"op": op})).unwrap()
}

// ----- scenarios ------------------------------------------------------------

/// The whole payment: S1 goes out by itself, the recipient answers by
/// itself, the reply waits for the sender's decision, the transaction is
/// valid and confirms on both sides.
#[test]
fn payment_travels_by_itself_and_waits_for_the_user() {
    let World {
        relay,
        mut a,
        mut b,
        mut chain,
    } = world(true);
    let p = prepare(&mut a, 2, 2 * GRIN);
    assert_eq!(p["delivery"], "queued");
    assert_eq!(relay.borrow().publishes, 0, "preparing must not publish");
    assert_eq!(status(&mut a, &p["op"])["delivery"], "queued");

    let pumped = a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(pumped["published"][0]["delivery"], "relay_accepted");
    assert_eq!(pumped["published"][0]["op"], p["op"]);
    // accepted once: nothing left to publish
    let again = a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(again["published"], json!([]));
    assert_eq!(relay.borrow().publishes, 1);
    // an acknowledgement is not a payment
    let st = status(&mut a, &p["op"]);
    assert_eq!((&st["state"], &st["reply_held"]), (&json!("prepared"), &json!(false)));

    assert_eq!(b.kinds(), vec!["payment_answered"]);
    assert!(b.kinds().is_empty(), "an answered message came again");

    let ev = a.rpc("paycore.delivery.receive", json!({})).unwrap();
    assert_eq!(ev["events"][0]["kind"], "reply_held");
    assert_eq!(ev["events"][0]["op"], p["op"]);
    assert_eq!(ev["events"][0]["from"], hex(&contact(2)));
    let st = status(&mut a, &p["op"]);
    assert_eq!((&st["state"], &st["reply_held"]), (&json!("prepared"), &json!(true)));
    assert_eq!(a.signatures(), 0, "holding a reply must not sign");
    let hist = a.rpc("paycore.history", json!({})).unwrap();
    assert_eq!(hist["sends"][0]["reply_held"], true);
    assert_eq!(hist["sends"][0]["delivery"], "relay_accepted");

    let fin = a
        .rpc("paycore.send.finalize_held", json!({"op": p["op"]}))
        .unwrap();
    assert_eq!(a.signatures(), 1);
    let tx = unhex(fin["tx"].as_str().unwrap());
    chain.mine(&tx, &mut [&mut a, &mut b]);
    chain.empty(4, &mut [&mut a, &mut b]);
    assert_eq!(status(&mut a, &p["op"])["state"], "confirmed");
    let bal = b.rpc("paycore.balance", json!({})).unwrap();
    assert_eq!(bal["spendable"], (2 * GRIN).to_string());
    // one envelope each way, sealed once each
    assert_eq!(relay.borrow().stored.len(), 2);
    assert_eq!((a.post.0.borrow().seals, b.post.0.borrow().seals), (1, 1));
}

/// Without a mailbox the delivery methods say so and nothing else changes.
#[test]
fn without_a_mailbox_slates_travel_by_hand() {
    let World { mut a, .. } = world(true);
    let mut ports = a.ports();
    ports.mailbox = None;
    let core = a.b.take().unwrap().into_core();
    a.b = Some(Bridge::new(core, ports));
    let ops = a.sim.ops();
    for (method, params) in [
        ("paycore.send.prepare", json!({"amount": "1000000000", "deliver_to": hex(&contact(2))})),
        ("paycore.delivery.pump", json!({})),
        ("paycore.delivery.receive", json!({})),
        ("paycore.delivery.ack", json!({"id": hex(&[1; 32])})),
        ("paycore.delivery.reply", json!({"id": hex(&[1; 32]), "slate": "x"})),
    ] {
        let e = a.rpc(method, params).unwrap_err();
        assert_eq!(e["data"]["kind"], "no_mailbox", "{method}");
    }
    assert_eq!(a.sim.ops(), ops);
    assert_eq!(a.rpc("paycore.balance", json!({})).unwrap()["reserved"], "0");
    // by hand it still works
    a.rpc("paycore.send.prepare", json!({"amount": "1000000000"})).unwrap();
    // and delivery does not combine with replacement
    let core = a.b.take().unwrap().into_core();
    a.b = Some(Bridge::new(core, a.ports()));
    let e = a
        .rpc(
            "paycore.send.prepare",
            json!({"amount": "1000000000", "deliver_to": hex(&contact(2)), "not_a_repeat": true}),
        )
        .unwrap_err();
    assert_eq!(e["data"]["kind"], "invalid_params");
}

/// Unattended signing happens only on the tip the chain layer selected; a
/// reply that could not be signed stays held and is signed later.
#[test]
fn auto_sign_needs_the_selected_tip() {
    let World {
        relay: _relay,
        mut a,
        mut b,
        mut chain,
    } = world(true);
    a.b().set_auto_sign(true);
    a.sel.set(Some(chain.tip()));
    let before = a.rpc("paycore.chain.status", json!({})).unwrap();
    assert_eq!(before["selected_height"], chain.height);
    assert_eq!(before["tip_height"], chain.height);
    assert_eq!(before["confirmed_time"], 1_000);
    let p = prepare(&mut a, 2, GRIN);
    let reserved = a.rpc("paycore.balance", json!({})).unwrap()["reserved"].clone();
    assert_ne!(reserved, "0");
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    b.kinds();
    // A previously used wallet loses its selected tip and confirmed time
    // between S1 and the arrival of S2.
    a.sel.set(None);
    a.clock.set(None);
    assert_eq!(a.kinds(), vec!["reply_held"]);
    assert_eq!(a.signatures(), 0);
    assert_eq!(a.rpc("paycore.balance", json!({})).unwrap()["reserved"], reserved);
    assert!(a.rpc("paycore.chain.status", json!({})).unwrap()["confirmed_time"].is_null());
    // A recovered clock alone does not permit automatic signing.
    a.clock.set(Some(1_100));
    assert!(a.kinds().is_empty());
    assert_eq!(a.signatures(), 0);
    // it vouches for a tip the wallet does not stand on
    a.sel.set(Some((chain.height + 1, [9; 32])));
    assert!(a.kinds().is_empty());
    let mut fork = chain.tip();
    fork.1[3] ^= 1;
    a.sel.set(Some(fork));
    assert!(a.kinds().is_empty());
    assert_eq!(a.signatures(), 0);
    assert_eq!(a.rpc("paycore.balance", json!({})).unwrap()["reserved"], reserved);
    assert_eq!(status(&mut a, &p["op"])["reply_held"], true);
    // and now for the right one
    a.sel.set(Some(chain.tip()));
    let ev = a.rpc("paycore.delivery.receive", json!({})).unwrap();
    assert_eq!(ev["events"][0]["kind"], "reply_signed");
    assert_eq!(ev["events"][0]["op"], p["op"]);
    assert_eq!(a.signatures(), 1);
    assert_eq!(a.rpc("paycore.balance", json!({})).unwrap()["reserved"], reserved);
    let op: [u8; 16] = unhex(p["op"].as_str().unwrap()).try_into().unwrap();
    assert_eq!(
        a.b().core().armed_at(&op),
        Some((chain.height, chain.tip().1.to_vec()))
    );
    assert!(a.kinds().is_empty(), "signed twice");
    assert_eq!(a.signatures(), 1);

    // with the tip in place a fresh reply is signed as it arrives
    let q = prepare(&mut a, 2, GRIN);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    b.kinds();
    assert_eq!(a.kinds(), vec!["reply_signed"]);
    assert_eq!(a.signatures(), 2);
    for op in [&p["op"], &q["op"]] {
        let fin = a.rpc("paycore.send.result", json!({"op": op})).unwrap();
        chain.mine(&unhex(fin["tx"].as_str().unwrap()), &mut [&mut a, &mut b]);
    }

    // a fresh reply that arrives while the tip is not the wallet's is held
    let mut fork = chain.tip();
    fork.1[5] ^= 1;
    a.sel.set(Some(fork));
    let f = prepare(&mut a, 2, GRIN / 4);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    b.kinds();
    assert_eq!(a.kinds(), vec!["reply_held"]);
    assert_eq!(a.signatures(), 2);
    a.rpc("paycore.send.cancel", json!({"op": f["op"]})).unwrap();

    // switched off (the default), the same situation only holds the reply
    a.b().set_auto_sign(false);
    a.sel.set(Some(chain.tip()));
    let r = prepare(&mut a, 2, GRIN / 2);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    b.kinds();
    assert_eq!(a.kinds(), vec!["reply_held"]);
    assert_eq!(a.signatures(), 2);
    assert_eq!(status(&mut a, &r["op"])["state"], "prepared");
}

/// Whatever the relay does, the recipient gets the message once, a retry is
/// the same message, and a silent relay does not grow the journal.
#[test]
fn relay_troubles_never_duplicate_or_change_the_message() {
    let World {
        relay,
        mut a,
        mut b,
        ..
    } = world(true);
    let p = prepare(&mut a, 2, GRIN);
    let op: [u8; 16] = unhex(p["op"].as_str().unwrap()).try_into().unwrap();
    let sealed = a.b().core().delivery_envelope(&op).unwrap();

    relay.borrow_mut().mode = Mode::Down;
    let r = a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(r["published"][0]["delivery"], "waiting_relay");
    let ops = a.sim.ops();
    for _ in 0..5 {
        a.rpc("paycore.delivery.pump", json!({})).unwrap();
    }
    assert_eq!(a.sim.ops(), ops, "a silent relay grew the journal");
    assert_eq!(relay.borrow().held_for(contact(2)), 0);

    for (mode, name) in [(Mode::Busy, "queue_busy"), (Mode::Full, "queue_full")] {
        relay.borrow_mut().mode = mode;
        let r = a.rpc("paycore.delivery.pump", json!({})).unwrap();
        assert_eq!(r["published"][0]["delivery"], name);
    }

    // stored, but the acknowledgement is lost: the wallet tries again
    relay.borrow_mut().mode = Mode::Silent;
    let r = a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(r["published"][0]["delivery"], "waiting_relay");
    assert_eq!(relay.borrow().held_for(contact(2)), 1);
    relay.borrow_mut().mode = Mode::Up;
    let r = a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(r["published"][0]["delivery"], "relay_accepted");
    {
        let relay = relay.borrow();
        assert_eq!(relay.held_for(contact(2)), 1, "the retry was a second message");
        assert_eq!(relay.stored[0].0, sealed.event_id);
        assert_eq!(pack(&relay.stored[0].1, &relay.stored[0].2, &relay.stored[0].3), sealed.bytes);
    }
    assert_eq!(a.post.0.borrow().seals, 1, "the envelope was sealed again");
    assert_eq!(b.kinds(), vec!["payment_answered"]);
    assert_eq!(a.kinds(), vec!["reply_held"]);
    assert_eq!(a.signatures(), 0);
}

#[test]
fn reopened_wallet_reports_expired_exchanges_and_does_not_deliver_the_old_request() {
    let World { relay, mut a, .. } = world(true);
    let send = prepare(&mut a, 2, GRIN);
    a.rpc("paycore.invoice.issue", json!({"amount": GRIN.to_string()})).unwrap();
    let before = a.rpc("paycore.history", json!({})).unwrap();
    assert_eq!(before["sends"][0]["session_expired"], false);
    assert_eq!(before["incoming"][0]["session_expired"], false);

    a.restart();
    let after = a.rpc("paycore.history", json!({})).unwrap();
    assert_eq!(after["sends"][0]["locked"], true);
    assert_eq!(after["sends"][0]["session_expired"], true);
    assert_eq!(after["incoming"][0]["session_expired"], true);
    assert_eq!(after["incoming"][0]["signature_unknown"], false);
    let state = status(&mut a, &send["op"]);
    assert_eq!(state["session_expired"], true);
    assert_eq!(state["reserve"], true);
    a.b().set_auto_sign(true);
    let result = a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(result["published"], json!([]));
    assert_eq!(relay.borrow().publishes, 0);
    assert_eq!(a.signatures(), 0);
}

/// The recipient's reply is stored by its mailbox and resent as it is.
#[test]
fn a_reply_is_resent_not_rebuilt() {
    let World {
        relay,
        mut a,
        mut b,
        ..
    } = world(true);
    prepare(&mut a, 2, GRIN);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    relay.borrow_mut().mode = Mode::Down;
    assert_eq!(b.kinds(), vec!["reply_pending"]);
    assert_eq!(b.kinds(), vec!["reply_pending"]);
    b.restart();
    relay.borrow_mut().mode = Mode::Up;
    assert_eq!(b.kinds(), vec!["payment_answered"]);
    assert!(b.kinds().is_empty());
    assert_eq!(b.post.0.borrow().seals, 1, "the reply was sealed again");
    assert_eq!(b.encodes.get(), 1, "the reply was built again");
    assert_eq!(relay.borrow().held_for(contact(1)), 1);
    assert_eq!(a.kinds(), vec!["reply_held"]);
}

/// An envelope the relay did not accept is not offered again at once: the
/// pause grows with every refusal up to a limit. Trouble on our own side of
/// the relay is retried soon, and the user can ask for a try right now.
#[test]
fn a_refused_envelope_waits_before_it_is_offered_again() {
    let World { relay, mut a, .. } = world(true);
    let (first, longest) = (Duration::from_millis(300), Duration::from_millis(900));
    a.b().set_publish_retry(first, longest);
    prepare(&mut a, 2, GRIN);
    relay.borrow_mut().mode = Mode::Down;
    let tries = |relay: &Rc<RefCell<Relay>>| relay.borrow().publishes;
    let before = tries(&relay);
    let pump = |a: &mut Wallet, now: bool| {
        let r = a.rpc("paycore.delivery.pump", json!({"now": now})).unwrap();
        (r["published"].as_array().unwrap().len(), r["waiting"].as_u64().unwrap())
    };
    assert_eq!(pump(&mut a, false), (1, 0));
    assert_eq!(tries(&relay), before + 1);
    // at once, and again: nothing is offered, the envelope waits
    for _ in 0..3 {
        assert_eq!(pump(&mut a, false), (0, 1));
    }
    assert_eq!(tries(&relay), before + 1);
    // after the first pause it is offered once more, and then waits twice as long
    std::thread::sleep(first + Duration::from_millis(50));
    assert_eq!(pump(&mut a, false), (1, 0));
    assert_eq!(tries(&relay), before + 2);
    std::thread::sleep(first + Duration::from_millis(50));
    assert_eq!(pump(&mut a, false), (0, 1), "the pause did not grow");
    std::thread::sleep(first);
    assert_eq!(pump(&mut a, false), (1, 0));
    assert_eq!(tries(&relay), before + 3);
    // the pause stops growing at the limit
    std::thread::sleep(longest + Duration::from_millis(50));
    assert_eq!(pump(&mut a, false), (1, 0));
    std::thread::sleep(longest + Duration::from_millis(50));
    assert_eq!(pump(&mut a, false), (1, 0), "the pause grew past its limit");
    assert_eq!(tries(&relay), before + 5);
    // the user asks: now
    assert_eq!(pump(&mut a, true), (1, 0));
    assert_eq!(tries(&relay), before + 6);
    // trouble before the relay is retried after the first pause, however
    // long the envelope has been waiting
    relay.borrow_mut().mode = Mode::Busy;
    assert_eq!(pump(&mut a, true), (1, 0));
    assert_eq!(pump(&mut a, false), (0, 1));
    std::thread::sleep(first + Duration::from_millis(50));
    relay.borrow_mut().mode = Mode::Up;
    let r = a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(r["published"][0]["delivery"], "relay_accepted");
    // accepted: nothing waits and nothing is offered
    assert_eq!(pump(&mut a, true), (0, 0));
    // the pauses are the bridge's own: the default is the product's
    assert_eq!(fly_paycore_bridge::PUBLISH_RETRY_FIRST, Duration::from_secs(2));
    assert_eq!(fly_paycore_bridge::PUBLISH_RETRY_MAX, Duration::from_secs(300));
}

/// Past the delivery window nothing is published; the payment stays open
/// until the user cancels it.
#[test]
fn an_expired_envelope_is_not_published() {
    let World { relay, mut a, .. } = world(true);
    let p = prepare(&mut a, 2, GRIN);
    relay.borrow_mut().mode = Mode::Down;
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    relay.borrow_mut().mode = Mode::Up;
    a.clock.set(Some(WINDOW_END));
    let before = relay.borrow().publishes;
    let r = a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(r["published"][0]["delivery"], "expired");
    assert_eq!(relay.borrow().publishes, before);
    assert_eq!(a.rpc("paycore.delivery.pump", json!({})).unwrap()["published"], json!([]));
    let st = status(&mut a, &p["op"]);
    assert_eq!((&st["state"], &st["delivery"]), (&json!("prepared"), &json!("expired")));
    assert_ne!(a.rpc("paycore.balance", json!({})).unwrap()["reserved"], "0");
    a.rpc("paycore.send.cancel", json!({"op": p["op"]})).unwrap();
    assert_eq!(a.rpc("paycore.balance", json!({})).unwrap()["reserved"], "0");
    // without a confirmed clock the transport's own verdict is taken
    let late = prepare(&mut a, 2, GRIN);
    a.clock.set(None);
    relay.borrow_mut().mode = Mode::Late;
    let r = a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(r["published"][0]["delivery"], "expired");
    assert_eq!(a.rpc("paycore.delivery.pump", json!({})).unwrap()["published"], json!([]));
    a.rpc("paycore.send.cancel", json!({"op": late["op"]})).unwrap();
    relay.borrow_mut().mode = Mode::Up;
    // an unconfirmed clock does not stop publishing: the relay enforces the window
    let q = prepare(&mut a, 2, GRIN);
    a.clock.set(None);
    let r = a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(r["published"][0]["op"], q["op"]);
    assert_eq!(r["published"][0]["delivery"], "relay_accepted");
}

/// Garbage and floods cost a bounded amount of work, write nothing and sign
/// nothing; a sender who keeps sending rubbish is muted.
#[test]
fn floods_and_garbage_are_bounded() {
    let World {
        relay,
        mut a,
        mut b,
        ..
    } = world(true);
    let p = prepare(&mut a, 2, GRIN);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    let ops = a.sim.ops();
    let me = contact(1);

    // the awaited contact floods us with rubbish, a stranger joins in
    for n in 0..40 {
        relay.borrow_mut().inject(contact(2), me, &format!("{{\"rubbish\":{n}}}"));
        relay.borrow_mut().inject(contact(9), me, "not even json");
    }
    relay.borrow_mut().inject(contact(8), me, &"x".repeat(200 * 1024));
    let mut rounds = 0;
    loop {
        let before = a.decodes.get();
        let ev = a.rpc("paycore.delivery.receive", json!({})).unwrap();
        let events = ev["events"].as_array().unwrap().clone();
        if events.is_empty() {
            break;
        }
        rounds += 1;
        assert!(rounds < 100, "the flood never drained");
        assert!(events.len() <= MAX_RECEIVE);
        let worked = a.decodes.get() - before;
        assert!(
            worked <= 3 * MAX_PER_SENDER,
            "one call decoded {worked} messages"
        );
        for e in &events {
            assert!(
                ["dropped", "deferred"].contains(&e["kind"].as_str().unwrap()),
                "{e}"
            );
        }
    }
    // every sender was cut off at the same number of invalid messages
    assert_eq!(a.decodes.get(), 2 * MAX_STRIKES, "muted senders were still read");
    assert_eq!(a.sim.ops(), ops, "rubbish reached the journal");
    assert_eq!(a.signatures(), 0);
    assert_eq!(status(&mut a, &p["op"])["state"], "prepared");

    // while muted, even a good reply is not read
    b.kinds();
    let before = a.decodes.get();
    let ev = a.rpc("paycore.delivery.receive", json!({})).unwrap();
    assert_eq!(ev["events"][0]["reason"], "sender is muted");
    assert_eq!(a.decodes.get(), before);
    assert_eq!(status(&mut a, &p["op"])["reply_held"], false);

    // a new payment to the contact lifts the mute
    let q = prepare(&mut a, 2, GRIN);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    b.kinds();
    assert_eq!(a.kinds(), vec!["reply_held"]);
    assert_eq!(status(&mut a, &q["op"])["reply_held"], true);
    // reopening the wallet lifts it too
    for _ in 0..MAX_STRIKES {
        relay.borrow_mut().inject(contact(2), me, "rubbish");
    }
    while !a.kinds().is_empty() {}
    relay.borrow_mut().inject(contact(2), me, "rubbish");
    assert_eq!(
        a.rpc("paycore.delivery.receive", json!({})).unwrap()["events"][0]["reason"],
        "sender is muted"
    );
    a.restart();
    relay.borrow_mut().inject(contact(2), me, "rubbish");
    assert_eq!(
        a.rpc("paycore.delivery.receive", json!({})).unwrap()["events"][0]["reason"],
        "not a slate"
    );
}

/// A reply counts only from the contact the payment went to, only once, and
/// only while the payment is open.
#[test]
fn replies_from_the_wrong_place_or_time_are_refused() {
    let World {
        relay,
        mut a,
        mut b,
        ..
    } = world(true);
    let mut c = Wallet::new(3, &relay);
    c.b()
        .core_mut()
        .chain_advance(&Advance {
            height: 1,
            hash: [1; 32],
            ..Advance::default()
        })
        .unwrap();
    let p = prepare(&mut a, 2, GRIN);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    let ops = a.sim.ops();

    // a third party got hold of S1 and answers it with a valid reply
    let theirs = c
        .rpc("paycore.receive.draft", json!({"slate": p["slate"]}))
        .unwrap();
    relay
        .borrow_mut()
        .inject(contact(3), contact(1), theirs["slate"].as_str().unwrap());
    let ev = a.rpc("paycore.delivery.receive", json!({})).unwrap();
    assert_eq!(ev["events"][0]["kind"], "dropped");
    assert_eq!(ev["events"][0]["reason"], "reply does not come from the recipient");
    assert_eq!(status(&mut a, &p["op"])["reply_held"], false);
    assert_eq!(a.sim.ops(), ops);

    // the real reply arrives twice; the second changes nothing
    b.kinds();
    let genuine = relay.borrow().stored.last().unwrap().3.clone();
    assert_eq!(a.kinds(), vec!["reply_held"]);
    let ops = a.sim.ops();
    relay.borrow_mut().inject(contact(2), contact(1), &genuine);
    assert_eq!(a.kinds(), vec!["reply_held"]);
    assert_eq!(a.sim.ops(), ops, "a repeated reply was written again");
    // the recipient changes its mind and sends another valid reply
    let other = b
        .rpc("paycore.receive.draft", json!({"slate": p["slate"]}))
        .unwrap();
    relay
        .borrow_mut()
        .inject(contact(2), contact(1), other["slate"].as_str().unwrap());
    let ev = a.rpc("paycore.delivery.receive", json!({})).unwrap();
    assert_eq!(ev["events"][0]["reason"], "another reply was already chosen");
    assert_eq!(a.signatures(), 0);

    // a reply to a cancelled payment is not kept
    let q = prepare(&mut a, 2, GRIN);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    a.rpc("paycore.send.cancel", json!({"op": q["op"]})).unwrap();
    b.kinds();
    let ev = a.rpc("paycore.delivery.receive", json!({})).unwrap();
    assert_eq!(ev["events"][0]["reason"], "operation was cancelled");
    assert!(a.rpc("paycore.send.finalize_held", json!({"op": q["op"]})).is_err());
    assert_eq!(a.signatures(), 0);
    // none of this counted against the recipient
    let r = prepare(&mut a, 2, GRIN / 2);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    b.kinds();
    assert_eq!(a.kinds(), vec!["reply_held"]);
    assert_eq!(status(&mut a, &r["op"])["reply_held"], true);
}

/// With unattended receive off, an incoming payment waits for the user and
/// the approved reply goes back through the mailbox.
#[test]
fn an_incoming_payment_can_wait_for_approval() {
    let World {
        relay,
        mut a,
        mut b,
        mut chain,
    } = world(false);
    let p = prepare(&mut a, 2, GRIN);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    let ops = b.sim.ops();
    let ev = b.rpc("paycore.delivery.receive", json!({})).unwrap();
    assert_eq!(ev["events"][0]["kind"], "needs_approval");
    assert_eq!(ev["events"][0]["slate"], p["slate"]);
    assert_eq!(b.sim.ops(), ops, "an unapproved payment was written");
    // it stays with the transport until the user decides
    b.restart();
    let ev = b.rpc("paycore.delivery.receive", json!({})).unwrap();
    assert_eq!(ev["events"][0]["kind"], "needs_approval");
    let id = ev["events"][0]["id"].clone();

    let s2 = b
        .rpc("paycore.receive.draft", json!({"slate": ev["events"][0]["slate"]}))
        .unwrap();
    relay.borrow_mut().mode = Mode::Down;
    let sent = b
        .rpc("paycore.delivery.reply", json!({"id": id, "slate": s2["slate"]}))
        .unwrap();
    assert_eq!(sent["sent"], false);
    relay.borrow_mut().mode = Mode::Up;
    let sent = b
        .rpc("paycore.delivery.reply", json!({"id": id, "slate": s2["slate"]}))
        .unwrap();
    assert_eq!(sent["sent"], true);
    assert_eq!(b.post.0.borrow().seals, 1);
    assert!(b.kinds().is_empty(), "an answered payment came again");

    assert_eq!(a.kinds(), vec!["reply_held"]);
    let fin = a
        .rpc("paycore.send.finalize_held", json!({"op": p["op"]}))
        .unwrap();
    chain.mine(&unhex(fin["tx"].as_str().unwrap()), &mut [&mut a, &mut b]);
    assert_eq!(status(&mut a, &p["op"])["state"], "confirmed");

    // the user may also decline: the message is acknowledged and gone
    prepare(&mut a, 2, GRIN / 2);
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    let ev = b.rpc("paycore.delivery.receive", json!({})).unwrap();
    b.rpc("paycore.delivery.ack", json!({"id": ev["events"][0]["id"]}))
        .unwrap();
    assert!(b.kinds().is_empty());
}

/// The same payment with slates as Slatepack text, the form the real
/// transport carries and other Grin wallets read.
#[test]
fn a_payment_travels_as_slatepack_text() {
    let World {
        relay,
        mut a,
        mut b,
        mut chain,
    } = world(true);
    a.b().set_slatepack(true);
    b.b().set_slatepack(true);
    let p = prepare(&mut a, 2, 2 * GRIN);
    let s1 = p["slate"].as_str().unwrap();
    assert!(s1.starts_with("BEGINSLATEPACK."), "{s1}");
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    // what crosses the relay is Slatepack text, in both directions
    assert_eq!(relay.borrow().stored[0].3, s1);
    assert_eq!(b.kinds(), vec!["payment_answered"]);
    assert!(relay.borrow().stored[1].3.starts_with("BEGINSLATEPACK."));
    assert_eq!(a.kinds(), vec!["reply_held"]);
    let fin = a
        .rpc("paycore.send.finalize_held", json!({"op": p["op"]}))
        .unwrap();
    chain.mine(&unhex(fin["tx"].as_str().unwrap()), &mut [&mut a, &mut b]);
    chain.empty(4, &mut [&mut a, &mut b]);
    assert_eq!(status(&mut a, &p["op"])["state"], "confirmed");
    assert_eq!(
        b.rpc("paycore.balance", json!({})).unwrap()["spendable"],
        (2 * GRIN).to_string()
    );
    // the port codec was not used at all
    assert_eq!((a.decodes.get(), a.encodes.get()), (0, 0));
    assert_eq!((b.decodes.get(), b.encodes.get()), (0, 0));

    // by hand, too: JSON is no longer taken, Slatepack text is
    let q = a
        .rpc("paycore.send.prepare", json!({"amount": "1000000000"}))
        .unwrap();
    assert!(q["slate"].as_str().unwrap().starts_with("BEGINSLATEPACK."));
    let e = b
        .rpc("paycore.receive.auto", json!({"slate": "{\"not\":\"armor\"}"}))
        .unwrap_err();
    assert_eq!(e["data"]["kind"], "codec");
    let s2 = b
        .rpc("paycore.receive.auto", json!({"slate": q["slate"]}))
        .unwrap();
    a.rpc(
        "paycore.send.finalize",
        json!({"op": q["op"], "slate": s2["slate"]}),
    )
    .unwrap();
    // rubbish in armor counts against the sender like any other rubbish
    relay
        .borrow_mut()
        .inject(contact(2), contact(1), "BEGINSLATEPACK. nonsense ENDSLATEPACK.");
    assert_eq!(
        a.rpc("paycore.delivery.receive", json!({})).unwrap()["events"][0]["reason"],
        "not a slate"
    );
}

/// The interface manages the identity and the contacts through JSON, and the
/// bridge starts the transport anew whenever either changes.
#[test]
fn identity_and_contacts_drive_the_transport() {
    use fly_paycore_bridge::ports::{MailboxFactory, TransportSpec};
    use fly_paycore_wallet::{npub_encode, nsec_decode, nsec_encode};
    /// identity secret, store key, contacts
    type Spec = ([u8; 32], [u8; 32], Vec<[u8; 32]>);
    struct Seen {
        specs: Vec<Spec>,
        alive: u32,
        overlap: bool,
        fail: bool,
    }
    struct Tracked(Rc<RefCell<Seen>>, Post);
    impl Drop for Tracked {
        fn drop(&mut self) {
            self.0.borrow_mut().alive -= 1;
        }
    }
    impl Mailbox for Tracked {
        fn seal(&mut self, to: &[u8; 32], text: &str) -> Result<Envelope, String> {
            self.1.seal(to, text)
        }
        fn publish(&mut self, e: &Envelope) -> Published {
            self.1.publish(e)
        }
        fn next_incoming(&mut self) -> Option<Incoming> {
            self.1.next_incoming()
        }
        fn resend_reply(&mut self, i: &[u8; 32]) -> Option<Published> {
            self.1.resend_reply(i)
        }
        fn reply(&mut self, i: &[u8; 32], t: &str) -> Published {
            self.1.reply(i, t)
        }
        fn done(&mut self, i: &[u8; 32]) {
            self.1.done(i)
        }
    }

    let relay = Relay::new();
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let sim = Sim::new();
    let core = Core::create(sim.dir(), sim.guard(), &RootKey::new([0x42; 32]), identity(5), kc(5), 0, 3).unwrap();
    let mut ports = Wallet::new(6, &relay).ports();
    ports.mailbox = None;
    let mut b: B = Bridge::new(core, ports);
    let seen = Rc::new(RefCell::new(Seen { specs: vec![], alive: 0, overlap: false, fail: false }));
    let (log, post_relay) = (seen.clone(), relay.clone());
    let factory: MailboxFactory = Box::new(move |spec: &TransportSpec| {
        let mut s = log.borrow_mut();
        if s.alive != 0 {
            s.overlap = true;
        }
        if s.fail {
            return Err("Tor did not come up".to_string());
        }
        s.specs.push((*spec.identity_secret, *spec.store_key, spec.contacts.clone()));
        s.alive += 1;
        let post = Post(Rc::new(RefCell::new(PostState {
            me: [0; 32],
            relay: post_relay.clone(),
            done: BTreeSet::new(),
            round: BTreeSet::new(),
            replies: BTreeMap::new(),
            seals: 0,
        })));
        Ok(Box::new(Tracked(log.clone(), post)))
    });
    let rpc = |b: &mut B, method: &str, params: Value| -> Result<Value, Value> {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let v: Value = serde_json::from_str(&b.call(&req.to_string())).unwrap();
        match v.get("result") {
            Some(r) => Ok(r.clone()),
            None => Err(v["error"].clone()),
        }
    };

    // no identity: no transport, and nothing was started
    b.set_mailbox_factory(factory);
    let st = rpc(&mut b, "paycore.transport.status", json!({})).unwrap();
    assert_eq!(st, json!({"identity": false, "running": false, "error": null}));
    assert_eq!(rpc(&mut b, "paycore.identity.get", json!({})).unwrap(), json!({"public": null}));
    assert!(rpc(&mut b, "paycore.identity.export", json!({})).is_err());
    assert!(seen.borrow().specs.is_empty());

    // a new identity starts the transport with it
    let id = rpc(&mut b, "paycore.identity.create", json!({})).unwrap();
    let public: [u8; 32] = unhex(id["public"].as_str().unwrap()).try_into().unwrap();
    assert_eq!(id["npub"], npub_encode(&public).unwrap());
    assert_eq!((&id["imported"], &id["previous"]), (&json!(false), &json!([])));
    let exported = rpc(&mut b, "paycore.identity.export", json!({})).unwrap();
    let nsec = exported["nsec"].as_str().unwrap().to_string();
    assert!(nsec.starts_with("nsec1"));
    {
        let s = seen.borrow();
        assert_eq!(s.specs.len(), 1);
        assert_eq!(s.specs[0].0, *nsec_decode(&nsec).unwrap(), "the transport got another key");
        assert!(s.specs[0].1 != s.specs[0].0 && s.specs[0].2.is_empty());
    }
    assert_eq!(rpc(&mut b, "paycore.transport.status", json!({})).unwrap()["running"], true);
    assert_eq!(rpc(&mut b, "paycore.identity.create", json!({})).unwrap_err()["data"]["kind"], "refused");

    // contacts: by npub or by key; a new key restarts the transport, a new name does not
    let bob = contact(2);
    rpc(&mut b, "paycore.contacts.set", json!({"npub": npub_encode(&bob).unwrap(), "name": "Bob"})).unwrap();
    assert_eq!(seen.borrow().specs.len(), 2);
    assert_eq!(seen.borrow().specs[1].2, vec![bob]);
    rpc(&mut b, "paycore.contacts.set", json!({"key": hex(&bob), "name": "Robert"})).unwrap();
    assert_eq!(seen.borrow().specs.len(), 2, "a new name restarted the transport");
    rpc(&mut b, "paycore.contacts.set", json!({"key": hex(&contact(3)), "name": "Carol"})).unwrap();
    let list = rpc(&mut b, "paycore.contacts.list", json!({})).unwrap();
    assert_eq!(list["contacts"][0]["name"], "Carol");
    assert_eq!(list["contacts"][1], json!({"key": hex(&bob), "npub": npub_encode(&bob).unwrap(), "name": "Robert", "address": null, "checked": false}));
    for (params, kind) in [
        (json!({"npub": "npub1nonsense", "name": "X"}), "invalid_params"),
        (json!({"key": hex(&[0xFF; 32]), "name": "X"}), "refused"),
        (json!({"key": hex(&bob), "name": ""}), "refused"),
        (json!({"name": "nobody"}), "invalid_params"),
    ] {
        assert_eq!(rpc(&mut b, "paycore.contacts.set", params).unwrap_err()["data"]["kind"], kind);
    }
    rpc(&mut b, "paycore.contacts.remove", json!({"key": hex(&contact(3))})).unwrap();
    assert_eq!(rpc(&mut b, "paycore.contacts.remove", json!({"key": hex(&contact(3))})).unwrap_err()["data"]["kind"], "not_found");
    assert_eq!(seen.borrow().specs.len(), 4);
    assert_eq!(seen.borrow().specs[3].2, vec![bob]);

    // an imported identity replaces the old one and the transport follows
    let theirs = nsec_encode(&secret(7)).unwrap();
    assert_eq!(rpc(&mut b, "paycore.identity.import", json!({"nsec": "nsec1nonsense"})).unwrap_err()["data"]["kind"], "invalid_params");
    assert_eq!(rpc(&mut b, "paycore.identity.import", json!({"nsec": theirs.as_str()})).unwrap_err()["data"]["kind"], "refused");
    let id = rpc(&mut b, "paycore.identity.import", json!({"nsec": theirs.as_str(), "replace": true})).unwrap();
    assert_eq!(id["public"], hex(&contact(7)));
    assert_eq!((&id["imported"], &id["previous"]), (&json!(true), &json!([npub_encode(&public).unwrap()])));
    {
        let s = seen.borrow();
        assert_eq!(s.specs.len(), 5);
        assert_eq!(s.specs[4].0, secret(7));
        assert_ne!(s.specs[4].1, s.specs[3].1, "the store key did not follow the identity");
        assert_eq!(s.alive, 1);
        assert!(!s.overlap, "two transports were alive at once");
    }

    // a transport that does not start is reported, and can be started again
    seen.borrow_mut().fail = true;
    let st = rpc(&mut b, "paycore.transport.restart", json!({})).unwrap();
    assert_eq!(st, json!({"running": false, "error": "Tor did not come up"}));
    assert_eq!(seen.borrow().alive, 0);
    let e = rpc(&mut b, "paycore.send.prepare", json!({"amount": "1", "deliver_to": hex(&bob)})).unwrap_err();
    assert_eq!(e["data"]["kind"], "no_mailbox");
    seen.borrow_mut().fail = false;
    assert_eq!(rpc(&mut b, "paycore.transport.restart", json!({})).unwrap()["running"], true);
    drop(b);
    assert_eq!(seen.borrow().alive, 0, "the transport outlived the bridge");
}

/// K120–K122: words between contacts travel the same way as payments, are
/// kept in the journal and are never taken for a slate.
#[test]
fn text_messages_travel_and_are_kept() {
    let mut w = world(false);
    let (a, b, relay) = (&mut w.a, &mut w.b, &w.relay);
    let bob = hex(&contact(2));
    let alice = hex(&contact(1));
    let sent = a.rpc("paycore.messages.send", json!({"key": bob, "text": "Привет, это я\nвторая строка"})).unwrap();
    assert_eq!(sent["state"], "waiting");
    let list = a.rpc("paycore.messages.list", json!({"key": bob})).unwrap()["messages"].clone();
    assert_eq!((list[0]["dir"].as_str(), list[0]["state"].as_str()), (Some("out"), Some("waiting")));

    // the delivery round publishes it; a relay accepting it is all that is said
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    let list = a.rpc("paycore.messages.list", json!({"key": bob})).unwrap()["messages"].clone();
    assert_eq!(list[0]["state"], "relay_accepted");

    // the other side keeps it; it is not decoded as a slate
    let decodes = b.decodes.get();
    assert_eq!(b.kinds(), vec!["message"]);
    assert_eq!(b.decodes.get(), decodes, "a text message was taken for a slate");
    let got = b.rpc("paycore.messages.list", json!({"key": alice})).unwrap()["messages"].clone();
    assert_eq!((got[0]["dir"].as_str(), got[0]["text"].as_str()), (Some("in"), Some("Привет, это я\nвторая строка")));
    assert_eq!(got[0]["id"], sent["id"]);
    // kept in the journal: after a restart it is there, and not offered again
    b.restart();
    assert_eq!(b.rpc("paycore.messages.list", json!({"key": alice})).unwrap()["messages"].as_array().unwrap().len(), 1);
    assert!(b.kinds().is_empty());
    let summary = b.rpc("paycore.messages.summary", json!({})).unwrap()["conversations"].clone();
    assert_eq!((summary[0]["key"].as_str(), summary[0]["count"].as_u64()), (Some(alice.as_str()), Some(1)));

    // a relay that loses it: the same envelope again, never a new one
    relay.borrow_mut().mode = Mode::Down;
    a.rpc("paycore.messages.send", json!({"key": bob, "text": "ещё"})).unwrap();
    let seals = a.post.0.borrow().seals;
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    let list = a.rpc("paycore.messages.list", json!({"key": bob})).unwrap()["messages"].clone();
    assert_eq!(list[1]["state"], "waiting");
    // a restart keeps the waiting envelope
    a.restart();
    relay.borrow_mut().mode = Mode::Up;
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert_eq!(a.post.0.borrow().seals, seals, "the message was sealed again");
    let list = a.rpc("paycore.messages.list", json!({"key": bob})).unwrap()["messages"].clone();
    assert_eq!(list[1]["state"], "relay_accepted");
    assert_eq!(b.kinds(), vec!["message"]);
    assert_eq!(relay.borrow().stored.iter().filter(|m| m.3.ends_with("ещё")).count(), 1);

    // a closed window: not published, said so, the envelope gone
    relay.borrow_mut().mode = Mode::Down;
    a.rpc("paycore.messages.send", json!({"key": bob, "text": "поздно"})).unwrap();
    a.clock.set(Some(WINDOW_END));
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    let list = a.rpc("paycore.messages.list", json!({"key": bob})).unwrap()["messages"].clone();
    assert_eq!(list[2]["state"], "expired");
    let publishes = relay.borrow().publishes;
    a.rpc("paycore.delivery.pump", json!({"now": true})).unwrap();
    assert_eq!(relay.borrow().publishes, publishes, "an expired message was published");
    a.clock.set(Some(1_000));
    relay.borrow_mut().mode = Mode::Up;
}

/// K120, K122: only contacts, only words of a bounded size, a bounded history.
#[test]
fn text_messages_are_bounded() {
    let mut w = world(false);
    let (a, b, relay) = (&mut w.a, &mut w.b, &w.relay);
    let bob = hex(&contact(2));
    let alice = hex(&contact(1));
    // the sender's limits come before sealing
    let long = "я".repeat(1001); // 2002 bytes
    assert_eq!(a.rpc("paycore.messages.send", json!({"key": bob, "text": long})).unwrap_err()["data"]["kind"], "refused");
    assert_eq!(a.rpc("paycore.messages.send", json!({"key": bob, "text": ""})).unwrap_err()["data"]["kind"], "refused");
    assert_eq!(a.rpc("paycore.messages.send", json!({"key": hex(&contact(3)), "text": "hi"})).unwrap_err()["data"]["kind"], "refused");
    assert_eq!(a.post.0.borrow().seals, 0, "a refused message was sealed");

    // a stranger's words are not kept; an oversized text counts against the sender
    relay.borrow_mut().inject(contact(3), contact(2), "GSTEXT1\nkauf jetzt");
    let ev = b.rpc("paycore.delivery.receive", json!({})).unwrap()["events"][0].clone();
    assert_eq!((ev["kind"].as_str(), ev["reason"].as_str()), (Some("dropped"), Some("not a contact")));
    relay.borrow_mut().inject(contact(1), contact(2), &format!("GSTEXT1\n{}", "x".repeat(2001)));
    let ev = b.rpc("paycore.delivery.receive", json!({})).unwrap()["events"][0].clone();
    assert_eq!(ev["kind"], "dropped");
    assert!(b.rpc("paycore.messages.summary", json!({})).unwrap()["conversations"].as_array().unwrap().is_empty());

    // a hundred are kept, the oldest go
    for n in 0..105 {
        a.rpc("paycore.messages.send", json!({"key": bob, "text": format!("n{n}")})).unwrap();
        a.rpc("paycore.delivery.pump", json!({})).unwrap();
    }
    let mine = a.rpc("paycore.messages.list", json!({"key": bob})).unwrap()["messages"].clone();
    assert_eq!(mine.as_array().unwrap().len(), 100);
    assert_eq!(mine[0]["text"], "n5");
    for _ in 0..60 {
        if b.kinds().is_empty() {
            break;
        }
    }
    let theirs = b.rpc("paycore.messages.list", json!({"key": alice})).unwrap()["messages"].clone();
    assert_eq!(theirs.as_array().unwrap().len(), 100);
    assert_eq!(theirs[99]["text"], "n104");

    // removing the contact removes the conversation
    a.rpc("paycore.contacts.remove", json!({"key": bob})).unwrap();
    a.b().core_mut().contact_set(contact(2), "Bob", None).unwrap();
    assert!(a.rpc("paycore.messages.list", json!({"key": bob})).unwrap()["messages"].as_array().unwrap().is_empty());
    a.restart();
    assert!(a.rpc("paycore.messages.list", json!({"key": bob})).unwrap()["messages"].as_array().unwrap().is_empty());
}

#[test]
fn waiting_messages_outlive_the_rotation() {
    // audit round 2, finding 24: a full conversation must not drop an own
    // message the relay has not accepted yet (K122, ред. 0.41)
    let mut w = world(false);
    let a = &mut w.a;
    let bob = contact(2);
    let before = a.rpc("paycore.messages.send", json!({"key": hex(&bob), "text": "pending"})).unwrap();
    let id = a.b().core().message_pending()[0];
    let envelope = a.b().core().message_envelope(&id).unwrap().bytes;
    for n in 0..100u8 {
        a.b().core_mut().message_received(bob, [n; 32], "fixture", u64::from(n)).unwrap();
    }
    let shown = a.rpc("paycore.messages.list", json!({"key": hex(&bob)})).unwrap()["messages"].clone();
    assert_eq!(shown.as_array().unwrap().len(), 101);
    assert_eq!(shown[0]["text"], "pending");
    // one more from the contact: the oldest of the others goes, not the waiting one
    a.b().core_mut().message_received(bob, [200; 32], "fixture", 200).unwrap();
    let shown = a.rpc("paycore.messages.list", json!({"key": hex(&bob)})).unwrap()["messages"].clone();
    assert_eq!(shown.as_array().unwrap().len(), 101);
    assert_eq!(shown[0]["text"], "pending");
    a.b().core_mut().checkpoint(None).unwrap();
    a.restart();
    assert_eq!(a.b().core().message_envelope(&id).map(|e| e.bytes), Some(envelope));
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    assert!(!a.b().core().message_pending().contains(&id));
    assert_eq!(w.b.kinds(), vec!["message"]);
    assert_eq!(w.b.rpc("paycore.messages.list", json!({"key": hex(&contact(1))})).unwrap()["messages"][0]["id"], before["id"]);
    // accepted, it is an ordinary row again: the next message trims to a hundred
    w.a.b().core_mut().message_received(bob, [201; 32], "fixture", 201).unwrap();
    let shown = w.a.rpc("paycore.messages.list", json!({"key": hex(&bob)})).unwrap()["messages"].clone();
    assert_eq!(shown.as_array().unwrap().len(), 100);
    assert_ne!(shown[0]["text"], "pending");
}

#[test]
fn waiting_messages_are_bounded() {
    // K121 (ред. 0.41): at most a hundred own messages wait for one contact
    let mut w = world(false);
    let a = &mut w.a;
    let bob = hex(&contact(2));
    for n in 0..MAX_WAITING {
        a.rpc("paycore.messages.send", json!({"key": bob, "text": format!("w{n}")})).unwrap();
    }
    let seals = a.post.0.borrow().seals;
    let err = a.rpc("paycore.messages.send", json!({"key": bob, "text": "one more"})).unwrap_err();
    assert_eq!(err["data"]["kind"], "refused");
    assert_eq!(a.post.0.borrow().seals, seals, "a refused message was sealed");
    a.rpc("paycore.delivery.pump", json!({})).unwrap();
    a.rpc("paycore.messages.send", json!({"key": bob, "text": "after the relay"})).unwrap();
}

const MAX_WAITING: usize = fly_paycore_wallet::MAX_WAITING_MESSAGES;

/// What an interface needs to let go of a payment, and what it is told
/// about one a rollback has locked. Every prepared payment is listed with
/// who it was sent to (or nobody, when passed on by hand) and whether it is
/// locked; its stored text can be had again. After a detected rollback a
/// prepared payment may have been signed in the part of the journal that
/// was lost: an ordinary cancel is refused, the reserve stays, and only the
/// user's explicit word releases it - as "released", never as "cancelled".
#[test]
fn a_payment_locked_by_a_rollback_is_released_not_cancelled() {
    let World { mut a, .. } = world(false);
    let sent = prepare(&mut a, 2, GRIN);
    let by_hand = a.rpc("paycore.send.prepare", json!({"amount": GRIN.to_string()})).unwrap();
    let row = |a: &mut Wallet, op: &Value| -> Value {
        let sends = a.rpc("paycore.history", json!({})).unwrap()["sends"].clone();
        sends.as_array().unwrap().iter().find(|s| &s["op"] == op).unwrap().clone()
    };
    let (r_sent, r_hand) = (row(&mut a, &sent["op"]), row(&mut a, &by_hand["op"]));
    assert_eq!((&r_sent["state"], &r_sent["locked"], &r_sent["deliver_to"]), (&json!("prepared"), &json!(false), &json!(hex(&contact(2)))));
    assert_eq!((&r_hand["state"], &r_hand["locked"], &r_hand["deliver_to"]), (&json!("prepared"), &json!(false), &Value::Null));
    // the text of a prepared payment again, as it was given out
    let review = a.rpc("paycore.send.review", json!({"op": by_hand["op"]})).unwrap();
    assert_eq!(review["slate"], by_hand["slate"]);
    let read = a.rpc("paycore.slate.read", json!({"slate": by_hand["slate"]})).unwrap();
    assert_eq!(review["slate_id"], read["slate_id"]);
    // releasing is not for a payment that is not locked
    let e = a.rpc("paycore.send.cancel", json!({"op": by_hand["op"], "release_locked": true})).unwrap_err();
    assert_eq!(e["data"]["kind"], "refused");
    assert_eq!(row(&mut a, &by_hand["op"])["state"], "prepared");

    // the journal goes back to a copy taken now; one more frame is lost
    let copy = a.sim.disk_image();
    a.rpc("paycore.send.prepare", json!({"amount": (GRIN / 10).to_string()})).unwrap();
    drop(a.b.take());
    a.sim.restore_disk(&copy);
    let (core, report) = Core::open(a.sim.dir(), a.sim.guard(), &RootKey::new([0x42; 32]), identity(a.seed), kc(a.seed), 3).unwrap();
    assert!(report.recovered);
    a.b = Some(Bridge::new(core, a.ports()));

    let reserved = a.rpc("paycore.balance", json!({})).unwrap()["reserved"].clone();
    assert_ne!(reserved, "0");
    for op in [&sent["op"], &by_hand["op"]] {
        assert_eq!((&row(&mut a, op)["state"], &row(&mut a, op)["locked"]), (&json!("prepared"), &json!(true)));
        let e = a.rpc("paycore.send.cancel", json!({"op": op})).unwrap_err();
        assert_eq!(e["data"]["kind"], "refused");
        assert_eq!(a.rpc("paycore.balance", json!({})).unwrap()["reserved"], reserved, "the reserve stays");
    }
    // nothing is published for a locked payment
    assert_eq!(a.rpc("paycore.delivery.pump", json!({})).unwrap()["published"], json!([]));
    for op in [&sent["op"], &by_hand["op"]] {
        a.rpc("paycore.send.cancel", json!({"op": op, "release_locked": true})).unwrap();
        let after = row(&mut a, op);
        assert_eq!((&after["state"], &after["locked"]), (&json!("released"), &json!(false)));
        assert_eq!(status(&mut a, op)["state"], "released");
        assert_eq!(a.rpc("paycore.send.review", json!({"op": op})).unwrap_err()["data"]["kind"], "refused");
    }
    assert_eq!(a.rpc("paycore.balance", json!({})).unwrap()["reserved"], "0");
    assert_eq!(a.signatures(), 0);
}
