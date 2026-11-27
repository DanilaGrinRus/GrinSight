//! Payments to and from an address through Tor (specification 7.25,
//! K151-K158): two wallets, each behind its bridge, and a stand-in for Tor
//! between their onion services. Nothing but JSON-RPC drives the wallets.
use fly_paycore_bridge::onion_pipe::{Event, Onion, Phase, State};
use fly_paycore_bridge::ports::{Broadcaster, ChainView, Clock, JsonCodec, Ports};
use fly_paycore_bridge::{Bridge, ONION_MAX_ASKS, ONION_MIN_AMOUNT};
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
use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::time::Duration;

const GRIN: u64 = 1_000_000_000;
type B = Bridge<SimDir, SimGuard, ExtKeychain>;
type Selected = Rc<Cell<Option<(u64, [u8; 32])>>>;

// ----- the stand-in for Tor -------------------------------------------------

/// Every onion service there is: what waits at each, and where the answer
/// to each request goes back to.
#[derive(Default)]
struct Tor {
    /// address key -> events of the wallet that listens there
    events: BTreeMap<[u8; 32], VecDeque<Event>>,
    /// request id -> (who posted, with which ticket)
    back: BTreeMap<u64, ([u8; 32], [u8; 16])>,
    next: u64,
    /// every post, as it went out
    posts: Vec<([u8; 32], String)>,
    /// every answer a service gave
    answers: Vec<String>,
    up: bool,
}

struct Wire {
    me: [u8; 32],
    tor: Rc<RefCell<Tor>>,
}

impl Onion for Wire {
    fn post(&mut self, ticket: &[u8; 16], to: &[u8; 32], body: &str) -> bool {
        let mut tor = self.tor.borrow_mut();
        if !tor.up {
            return false;
        }
        tor.posts.push((*to, body.to_string()));
        tor.next += 1;
        let id = tor.next;
        tor.back.insert(id, (self.me, *ticket));
        if tor.events.contains_key(to) {
            tor.events.get_mut(to).unwrap().push_back(Event::Request { id, body: body.to_string() });
        } else {
            // nobody listens at that address
            tor.back.remove(&id);
            tor.events.entry(self.me).or_default().push_back(Event::Posted {
                ticket: *ticket,
                result: Err("Tor did not reach the wallet at this address".into()),
            });
        }
        true
    }
    fn next(&mut self) -> Option<Event> {
        self.tor.borrow_mut().events.get_mut(&self.me)?.pop_front()
    }
    fn answer(&mut self, id: u64, body: &str) {
        let mut tor = self.tor.borrow_mut();
        tor.answers.push(body.to_string());
        if let Some((who, ticket)) = tor.back.remove(&id) {
            tor.events.entry(who).or_default().push_back(Event::Posted { ticket, result: Ok(body.to_string()) });
        }
    }
    fn state(&mut self) -> State {
        State { phase: Phase::Listening, problem: String::new() }
    }
}

// ----- wallets --------------------------------------------------------------

struct Net;
impl Broadcaster for Net {
    fn post_tx(&mut self, _tx: &[u8]) -> Broadcast {
        Broadcast::Accepted
    }
}
struct Time;
impl Clock for Time {
    fn confirmed_time(&self) -> Option<u64> {
        Some(1_000)
    }
}
struct View(Selected);
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

struct Wallet {
    b: B,
    sim: Sim,
    address: [u8; 32],
    sel: Selected,
}
fn kc(seed: u8) -> ExtKeychain {
    ExtKeychain::from_seed(&[seed; 32], true).unwrap()
}
impl Wallet {
    fn new(seed: u8, tor: &Rc<RefCell<Tor>>) -> Wallet {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let sim = Sim::new();
        let identity = Identity { network: 2, genesis: [7; 32], instance: [seed; 16] };
        let core = Core::create(sim.dir(), sim.guard(), &RootKey::new([0x42; 32]), identity, kc(seed), 0, 3).unwrap();
        let sel = Rc::new(Cell::new(None));
        let ports = Ports {
            broadcaster: Box::new(Net),
            clock: Box::new(Time),
            chain: Box::new(View(sel.clone())),
            codec: Box::new(JsonCodec),
            mailbox: None,
        };
        let mut b = Bridge::new(core, ports);
        let address = b.core().receive_address().unwrap();
        tor.borrow_mut().events.insert(address, VecDeque::new());
        b.set_onion(Box::new(Wire { me: address, tor: tor.clone() }));
        Wallet { b, sim, address, sel }
    }
    fn rpc(&mut self, method: &str, params: Value) -> Result<Value, Value> {
        let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let v: Value = serde_json::from_str(&self.b.call(&req.to_string())).unwrap();
        match v.get("result") {
            Some(r) => Ok(r.clone()),
            None => Err(v["error"].clone()),
        }
    }
    /// One round of the Tor side; the kinds of what happened.
    fn pump(&mut self) -> Vec<String> {
        self.rpc("paycore.onion.pump", json!({})).unwrap()["onion"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["kind"].as_str().unwrap().to_string())
            .collect()
    }
    fn status(&mut self) -> Value {
        self.rpc("paycore.onion.status", json!({})).unwrap()
    }
    fn signatures(&self) -> u64 {
        self.b.core().signatures_made()
    }
    fn approve_request(&mut self) {
        assert_eq!(self.pump(), vec!["needs_approval"]);
        let id = self.status()["asks"][0]["id"].clone();
        self.rpc("paycore.onion.accept", json!({"id": id})).unwrap();
    }
    fn knows(&mut self, seed: u8, other: &Wallet) {
        self.b.core_mut().contact_set([seed; 32], "a contact", Some(other.address)).unwrap();
    }
}

struct Chain {
    height: u64,
    pos: u64,
}
impl Chain {
    fn push(&mut self, mut a: Advance, wallets: &mut [&mut Wallet]) {
        self.height += 1;
        a.height = self.height;
        a.hash = [self.height as u8; 32];
        for w in wallets.iter_mut() {
            w.b.core_mut().chain_advance(&a).unwrap();
            w.sel.set(Some((a.height, a.hash)));
        }
    }
    fn fund(&mut self, seed: u8, values: &[u64], wallets: &mut [&mut Wallet]) {
        let k = kc(seed);
        let builder = ProofBuilder::new(&k);
        let mut a = Advance::default();
        for (n, v) in values.iter().enumerate() {
            let key = KeyPath::Legacy { account: 0, index: n as u32 }.to_identifier();
            let commit = k.commit(*v, &key, SwitchCommitmentType::Regular).unwrap();
            let rp = proof::create(&k, &builder, *v, &key, SwitchCommitmentType::Regular, commit, None).unwrap();
            self.pos += 1;
            a.outputs.push((commit, rp, self.pos, false));
        }
        self.push(a, wallets);
    }
    fn mine(&mut self, tx: &[u8], wallets: &mut [&mut Wallet]) {
        let tx: Transaction =
            ser::deserialize(&mut &tx[..], ser::ProtocolVersion::local(), ser::DeserializationMode::default()).unwrap();
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
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

struct World {
    tor: Rc<RefCell<Tor>>,
    a: Wallet,
    b: Wallet,
    chain: Chain,
}
/// Wallet 1 has money and pays; wallet 2 receives.
fn world() -> World {
    let tor = Rc::new(RefCell::new(Tor { up: true, ..Tor::default() }));
    let mut a = Wallet::new(1, &tor);
    let mut b = Wallet::new(2, &tor);
    let mut chain = Chain { height: 0, pos: 0 };
    chain.fund(1, &[5 * GRIN, 3 * GRIN, 2 * GRIN, GRIN, GRIN], &mut [&mut a, &mut b]);
    chain.push(Advance::default(), &mut [&mut a, &mut b]);
    World { tor, a, b, chain }
}
/// A payment prepared for an address, as the window does it.
fn prepare(a: &mut Wallet, to: &[u8; 32], amount: u64) -> Value {
    a.rpc("paycore.send.prepare", json!({"amount": amount.to_string(), "proof_to": hex(to)})).unwrap()
}
fn send_state(w: &mut Wallet, op: &Value) -> Value {
    w.rpc("paycore.send.status", json!({"op": op})).unwrap()
}
/// A request as another wallet's Tor would bring it.
fn arrive(tor: &Rc<RefCell<Tor>>, at: &Wallet, body: &str) -> u64 {
    let mut tor = tor.borrow_mut();
    tor.next += 1;
    let id = tor.next;
    tor.events.get_mut(&at.address).unwrap().push_back(Event::Request { id, body: body.to_string() });
    id
}
fn receive_tx(slate: &Value) -> String {
    json!({"jsonrpc": "2.0", "id": 7, "method": "receive_tx", "params": [slate, null, null]}).to_string()
}
fn slate_of(p: &Value) -> Value {
    serde_json::from_str(p["slate"].as_str().unwrap()).unwrap()
}

// ----- scenarios ------------------------------------------------------------

/// K151, K152, K154: the whole payment. The payment goes to the onion
/// service of the address it names; the recipient is asked in the window
/// and says yes; the reply comes back in the same connection and waits
/// for the sender's signature; the transaction is valid and confirms.
#[test]
fn a_payment_travels_to_an_address_and_waits_for_both_users() {
    let World { tor, mut a, mut b, mut chain } = world();
    let p = prepare(&mut a, &b.address, GRIN);
    let signed = (a.signatures(), b.signatures());
    let ops = (a.sim.ops(), b.sim.ops());
    let sent = a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(sent["state"], "posted");
    // it went to the address the payment names, in the words of Grin wallets
    {
        let tor = tor.borrow();
        assert_eq!(tor.posts.len(), 1);
        assert_eq!(tor.posts[0].0, b.address);
        let body: Value = serde_json::from_str(&tor.posts[0].1).unwrap();
        assert_eq!(body["method"], "receive_tx");
        assert_eq!(body["params"][0], slate_of(&p));
        assert_eq!(body["params"][0]["sta"], "S1");
    }
    // sending signed nothing and wrote nothing
    assert_eq!((a.signatures(), a.sim.ops()), (signed.0, ops.0));
    // the same request again posts nothing twice
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(tor.borrow().posts.len(), 1);
    assert_eq!(a.status()["sends"][0]["state"], "posted");

    // the recipient does not know the sender: the user is asked, nothing
    // is signed or written meanwhile
    assert_eq!(b.pump(), vec!["needs_approval"]);
    assert_eq!((b.signatures(), b.sim.ops()), (signed.1, ops.1));
    let asked = b.status();
    assert_eq!(asked["asks"].as_array().unwrap().len(), 1);
    assert_eq!(asked["asks"][0]["amount"], GRIN.to_string());
    assert_eq!(asked["asks"][0]["claimed_sender"], hex(&a.address));
    assert_eq!(asked["asks"][0]["known_sender"], false);
    assert!(tor.borrow().answers.is_empty());
    assert!(a.pump().is_empty());

    let reply = b.rpc("paycore.onion.accept", json!({"id": asked["asks"][0]["id"]})).unwrap();
    assert!(b.sim.ops() > ops.1, "the accepted payment was not written down");
    assert!(b.status()["asks"].as_array().unwrap().is_empty());
    // what the sender got is what the wallet keeps for showing again
    let answer: Value = serde_json::from_str(&tor.borrow().answers[0]).unwrap();
    assert_eq!(answer["id"], 1);
    assert_eq!(answer["result"]["Ok"], serde_json::from_str::<Value>(reply["slate"].as_str().unwrap()).unwrap());
    assert_eq!(answer["result"]["Ok"]["sta"], "S2");

    // K152: the reply is kept; the sender's wallet signs nothing by itself
    assert_eq!(a.pump(), vec!["reply_held"]);
    assert_eq!(a.signatures(), signed.0);
    assert_eq!(send_state(&mut a, &p["op"])["reply_held"], true);
    assert_eq!(send_state(&mut a, &p["op"])["state"], "prepared");
    assert!(a.status()["sends"].as_array().unwrap().is_empty());
    // with the reply here the payment is not sent again
    let e = a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap_err();
    assert_eq!(e["data"]["reason"], "a reply is already here");
    assert_eq!(tor.borrow().posts.len(), 1);
    let fin = a.rpc("paycore.send.finalize_held", json!({"op": p["op"]})).unwrap();
    assert!(!fin["payment_proof"].is_null());
    chain.mine(&unhex(fin["tx"].as_str().unwrap()), &mut [&mut a, &mut b]);
    assert_eq!(send_state(&mut a, &p["op"])["state"], "confirmed");
    let got = b.rpc("paycore.balance", json!({})).unwrap();
    assert_eq!(got["immature"].as_str().unwrap().parse::<u64>().unwrap() + got["spendable"].as_str().unwrap().parse::<u64>().unwrap(), GRIN);
}

/// K151: only a prepared payment that names an address is sent, and only
/// where there is Tor.
#[test]
fn what_is_not_a_payment_to_an_address_is_not_sent() {
    let World { tor, mut a, b, .. } = world();
    // a payment by hand names nobody
    let plain = a.rpc("paycore.send.prepare", json!({"amount": GRIN.to_string()})).unwrap();
    let e = a.rpc("paycore.onion.send", json!({"op": plain["op"]})).unwrap_err();
    assert_eq!(e["data"]["reason"], "the payment names no address");
    let e = a.rpc("paycore.onion.send", json!({"op": hex(&[9; 16])})).unwrap_err();
    assert_eq!(e["message"], "not_found");
    // a cancelled payment
    let p = prepare(&mut a, &b.address, GRIN);
    a.rpc("paycore.send.cancel", json!({"op": p["op"]})).unwrap();
    let e = a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap_err();
    assert_eq!(e["data"]["reason"], "payment is not prepared");
    // Tor is not up: nothing is taken, the payment is as it was
    let p = prepare(&mut a, &b.address, GRIN);
    tor.borrow_mut().up = false;
    let e = a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap_err();
    assert_eq!(e["data"]["reason"], "Tor is not ready yet");
    assert!(a.status()["sends"].as_array().unwrap().is_empty());
    assert!(tor.borrow().posts.is_empty());
    assert_eq!(send_state(&mut a, &p["op"])["state"], "prepared");
}

/// Without a Tor process every method says so; nothing else changes.
#[test]
fn without_tor_the_methods_say_so() {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let sim = Sim::new();
    let identity = Identity { network: 2, genesis: [7; 32], instance: [5; 16] };
    let core = Core::create(sim.dir(), sim.guard(), &RootKey::new([0x42; 32]), identity, kc(5), 0, 3).unwrap();
    let ports = Ports {
        broadcaster: Box::new(Net),
        clock: Box::new(Time),
        chain: Box::new(View(Rc::new(Cell::new(None)))),
        codec: Box::new(JsonCodec),
        mailbox: None,
    };
    let mut b: B = Bridge::new(core, ports);
    let mut call = |method: &str, params: Value| -> Value {
        serde_json::from_str(&b.call(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string())).unwrap()
    };
    assert_eq!(call("paycore.onion.pump", json!({}))["error"]["message"], "no_onion");
    assert_eq!(call("paycore.onion.send", json!({"op": hex(&[1; 16])}))["error"]["message"], "no_onion");
    assert_eq!(call("paycore.onion.status", json!({}))["result"]["phase"], "none");
}

/// K158: the Tor process is given the key of the wallet's address and
/// nothing else of the wallet.
#[test]
fn the_tor_process_gets_the_address_key_and_nothing_else() {
    let World { tor, mut a, .. } = world();
    let seen = Rc::new(RefCell::new(Vec::new()));
    let (seen_in, tor_in, me) = (seen.clone(), tor.clone(), a.address);
    a.b.set_onion_factory(Box::new(move |secret, public| {
        assert_eq!(*public, me);
        seen_in.borrow_mut().push(**secret);
        Ok(Box::new(Wire { me, tor: tor_in.clone() }))
    }));
    let seen = seen.borrow();
    assert_eq!(seen.len(), 1);
    // the public half of what it got is the address
    let public = ed25519_public(&seen[0]);
    assert_eq!(public, a.address);
    assert_eq!(a.status()["phase"], "listening");
}
fn ed25519_public(secret: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

/// A saved address is a display hint. Direct Foreign requests always need approval.
#[test]
fn direct_payments_require_approval_even_when_the_claimed_address_is_saved() {
    let World { tor, mut a, mut b, mut chain } = world();
    b.knows(1, &a);
    b.rpc("paycore.receive.set_auto", json!({"on": true})).unwrap();
    let p = prepare(&mut a, &b.address, GRIN);
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    let before = (b.signatures(), b.sim.ops());
    assert_eq!(b.pump(), vec!["needs_approval"]);
    let ask = b.status()["asks"][0].clone();
    assert_eq!(ask["claimed_address_in_contacts"], true);
    assert_eq!(ask["known_sender"], false);
    assert_eq!((b.signatures(), b.sim.ops()), before);
    assert!(tor.borrow().answers.is_empty());
    b.rpc("paycore.onion.accept", json!({"id": ask["id"]})).unwrap();
    assert!(b.status()["asks"].as_array().unwrap().is_empty());
    assert_eq!(a.pump(), vec!["reply_held"]);
    let fin = a.rpc("paycore.send.finalize_held", json!({"op": p["op"]})).unwrap();
    chain.mine(&unhex(fin["tx"].as_str().unwrap()), &mut [&mut a, &mut b]);
    assert_eq!(send_state(&mut a, &p["op"])["state"], "confirmed");

    // unattended receive on, the sender is nobody the user added: asked
    let World { mut a, mut b, .. } = world();
    b.rpc("paycore.receive.set_auto", json!({"on": true})).unwrap();
    let signed = b.signatures();
    let ops_asked = b.sim.ops();
    let p = prepare(&mut a, &b.address, GRIN);
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(b.pump(), vec!["needs_approval"]);
    assert_eq!(b.signatures(), signed);
    assert_eq!(b.sim.ops(), ops_asked, "a payment nobody approved was written");

    // a contact, but unattended receive is off: asked
    let World { mut a, mut b, .. } = world();
    b.knows(1, &a);
    let signed = b.signatures();
    let p = prepare(&mut a, &b.address, GRIN);
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(b.pump(), vec!["needs_approval"]);
    assert_eq!(b.status()["asks"][0]["claimed_address_in_contacts"], true);
    assert_eq!(b.status()["asks"][0]["known_sender"], false);
    assert_eq!(b.signatures(), signed);

    // a payment that names no sender at all is nobody's: asked
    let World { tor: tor2, mut a, mut b, .. } = world();
    b.knows(1, &a);
    b.rpc("paycore.receive.set_auto", json!({"on": true})).unwrap();
    let signed = b.signatures();
    let plain = a.rpc("paycore.send.prepare", json!({"amount": GRIN.to_string()})).unwrap();
    arrive(&tor2, &b, &receive_tx(&slate_of(&plain)));
    assert_eq!(b.pump(), vec!["needs_approval"]);
    assert_eq!(b.status()["asks"][0]["claimed_sender"], Value::Null);
    assert_eq!(b.signatures(), signed);
    drop(tor);
}

/// K154: at most three payments wait for the user; the fourth is refused
/// at once and leaves no trace.
#[test]
fn no_more_than_three_payments_wait_for_the_user() {
    let World { tor, mut a, mut b, .. } = world();
    let ops = b.sim.ops();
    let mut prepared = Vec::new();
    for _ in 0..ONION_MAX_ASKS + 1 {
        let p = prepare(&mut a, &b.address, GRIN / 4);
        a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
        prepared.push(p);
    }
    assert_eq!(b.pump(), vec!["needs_approval", "needs_approval", "needs_approval", "dropped"]);
    assert_eq!(b.status()["asks"].as_array().unwrap().len(), ONION_MAX_ASKS);
    assert_eq!(b.sim.ops(), ops);
    // the fourth sender is told to come back, and learns nothing else
    let refusal: Value = serde_json::from_str(&tor.borrow().answers[0]).unwrap();
    assert_eq!(refusal["error"]["message"], "the wallet is busy, try again later");
    assert_eq!(a.pump(), vec!["tor_failed"]);
    let failed = a.status();
    assert_eq!(failed["sends"].as_array().unwrap().iter().filter(|s| s["state"] == "failed").count(), 1);
    assert_eq!(send_state(&mut a, &prepared[3]["op"])["state"], "prepared");
    // once the user has decided about one, there is room again
    let first = b.status()["asks"][0]["id"].clone();
    b.rpc("paycore.onion.decline", json!({"id": first})).unwrap();
    assert_eq!(b.status()["asks"].as_array().unwrap().len(), ONION_MAX_ASKS - 1);
    // the same payment arriving again while it waits is not a second one,
    // room or no room
    arrive(&tor, &b, &receive_tx(&slate_of(&prepared[1])));
    assert_eq!(b.pump(), vec!["dropped"]);
    assert_eq!(b.status()["asks"].as_array().unwrap().len(), ONION_MAX_ASKS - 1);
    let again: Value = serde_json::from_str(tor.borrow().answers.last().unwrap()).unwrap();
    assert_eq!(again["error"]["message"], "this payment already waits for the owner of the wallet");
    a.rpc("paycore.onion.send", json!({"op": prepared[3]["op"]})).unwrap();
    assert_eq!(b.pump(), vec!["needs_approval"]);
    assert_eq!(b.sim.ops(), ops, "a payment nobody approved was written");
}

/// K154: the user says no, or does not answer in time: nothing is signed
/// or written, and the sender is told plainly.
#[test]
fn a_declined_or_late_payment_signs_nothing() {
    let World { tor, mut a, mut b, .. } = world();
    let (signed, ops) = (b.signatures(), b.sim.ops());
    let p = prepare(&mut a, &b.address, GRIN);
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(b.pump(), vec!["needs_approval"]);
    let id = b.status()["asks"][0]["id"].clone();
    b.rpc("paycore.onion.decline", json!({"id": id})).unwrap();
    assert!(b.status()["asks"].as_array().unwrap().is_empty());
    assert_eq!(a.pump(), vec!["tor_failed"]);
    assert_eq!(
        a.status()["sends"][0]["reason"],
        "the wallet at this address refused: the owner of the wallet declined the payment"
    );
    // a decision about what no longer waits
    let e = b.rpc("paycore.onion.accept", json!({"id": id})).unwrap_err();
    assert_eq!(e["data"]["reason"], "the sender no longer waits");
    b.rpc("paycore.onion.decline", json!({"id": id})).unwrap();

    // the sender tries again; this time nobody answers in time
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(b.pump(), vec!["needs_approval"]);
    let id = b.status()["asks"][0]["id"].clone();
    b.b.set_onion_waits(Duration::ZERO, Duration::from_secs(600));
    // yes after the time is up reaches nobody: it is not signed
    let e = b.rpc("paycore.onion.accept", json!({"id": id})).unwrap_err();
    assert_eq!(e["data"]["reason"], "the sender no longer waits");
    assert_eq!(a.pump(), vec!["tor_failed"]);
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(b.pump(), vec!["needs_approval", "ask_expired"]);
    assert_eq!(a.pump(), vec!["tor_failed"]);
    assert_eq!(
        a.status()["sends"][0]["reason"],
        "the wallet at this address refused: the owner of the wallet did not answer in time"
    );
    assert_eq!((b.signatures(), b.sim.ops()), (signed, ops));
    // the sender's payment is as it was and can be cancelled
    assert_eq!(send_state(&mut a, &p["op"])["state"], "prepared");
    a.rpc("paycore.send.cancel", json!({"op": p["op"]})).unwrap();
    drop(tor);
}

/// K155: dust is refused before anything else is done with it, whoever
/// it says it is from.
#[test]
fn dust_is_refused() {
    let World { tor, mut a, mut b, .. } = world();
    b.knows(1, &a);
    b.rpc("paycore.receive.set_auto", json!({"on": true})).unwrap();
    let (signed, ops) = (b.signatures(), b.sim.ops());
    let p = prepare(&mut a, &b.address, ONION_MIN_AMOUNT - 1);
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(b.pump(), vec!["dropped"]);
    assert!(b.status()["asks"].as_array().unwrap().is_empty());
    assert_eq!((b.signatures(), b.sim.ops()), (signed, ops));
    let refusal: Value = serde_json::from_str(&tor.borrow().answers[0]).unwrap();
    assert_eq!(refusal["error"]["message"], "the amount is too small for this wallet");
    // the smallest amount that is taken
    let p = prepare(&mut a, &b.address, ONION_MIN_AMOUNT);
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(b.pump(), vec!["needs_approval"]);
    // the host may set the bound
    b.b.set_onion_min_amount(GRIN);
    let p = prepare(&mut a, &b.address, GRIN - 1);
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(b.pump(), vec!["dropped"]);
    assert_eq!(b.status()["min_amount"], GRIN.to_string());
}

/// K156: whatever arrives at the onion service is anybody's text. It is
/// refused in fixed words that repeat nothing of it, signs nothing and
/// writes nothing.
#[test]
fn garbage_at_the_onion_service_is_refused_and_leaves_no_trace() {
    let World { tor, mut a, mut b, .. } = world();
    b.knows(1, &a);
    b.rpc("paycore.receive.set_auto", json!({"on": true})).unwrap();
    let (signed, ops) = (b.signatures(), b.sim.ops());
    let p = prepare(&mut a, &b.address, GRIN);
    let s1 = slate_of(&p);
    let invoice = b.rpc("paycore.invoice.issue", json!({"amount": GRIN.to_string()})).unwrap();
    let ops = ops.max(b.sim.ops());
    let signed = signed.max(b.signatures());
    let mut broken = s1.clone();
    broken["sigs"] = json!("SECRET-MARKER");
    let mut reply_as_payment = s1.clone();
    reply_as_payment["sta"] = json!("S2");
    let huge = format!("{{\"method\":\"receive_tx\",\"params\":[\"{}\"]}}", "x".repeat(100 * 1024));
    let cases: Vec<(String, &str)> = vec![
        ("".into(), "the request is not one"),
        ("SECRET-MARKER not json".into(), "the request is not one"),
        ("[1,2,3]".into(), "this wallet takes payments only"),
        (huge, "the request is too large"),
        (json!({"method": "finalize_tx", "id": "SECRET MARKER", "params": [s1]}).to_string(), "this wallet takes payments only"),
        (json!({"method": "build_coinbase", "params": [{"fees": 1, "height": 2}]}).to_string(), "this wallet takes payments only"),
        (json!({"method": "SECRET-MARKER"}).to_string(), "this wallet takes payments only"),
        (json!({"method": "receive_tx"}).to_string(), "the request holds no payment"),
        (json!({"method": "receive_tx", "params": ["SECRET-MARKER"]}).to_string(), "the request holds no payment"),
        (json!({"method": "receive_tx", "params": {"slate": s1}}).to_string(), "the request holds no payment"),
        (json!({"method": "receive_tx", "params": [{"SECRET-MARKER": 1}]}).to_string(), "not a payment this wallet can read"),
        (receive_tx(&broken), "not a payment this wallet can read"),
        // an invoice asks this wallet to pay: never through here
        (receive_tx(&slate_of(&invoice)), "this wallet takes payments only"),
        (receive_tx(&reply_as_payment), "this wallet takes payments only"),
    ];
    for (body, words) in &cases {
        let before = tor.borrow().answers.len();
        arrive(&tor, &b, body);
        assert_eq!(b.pump(), vec!["dropped"], "{words}");
        let tor = tor.borrow();
        assert_eq!(tor.answers.len(), before + 1);
        let answer: Value = serde_json::from_str(tor.answers.last().unwrap()).unwrap();
        assert_eq!(answer["error"]["message"], *words);
        assert!(!tor.answers.last().unwrap().contains("SECRET"), "a refusal repeated the request");
        assert!(answer.get("result").is_none());
    }
    assert!(b.status()["asks"].as_array().unwrap().is_empty());
    assert_eq!((b.signatures(), b.sim.ops()), (signed, ops));
    // the one question that is answered: which wallets this one speaks to
    arrive(&tor, &b, &json!({"jsonrpc": "2.0", "id": 3, "method": "check_version", "params": []}).to_string());
    assert_eq!(b.pump(), vec!["asked_version"]);
    let answer: Value = serde_json::from_str(tor.borrow().answers.last().unwrap()).unwrap();
    assert_eq!(answer, json!({"id": 3, "jsonrpc": "2.0", "result": {"Ok": {"foreign_api_version": 2, "supported_slate_versions": ["V4"]}}}));
    assert_eq!((b.signatures(), b.sim.ops()), (signed, ops));
}

/// K157: what comes back to a post is anybody's text too. Only the reply
/// to this very payment is kept; anything else leaves the payment as it
/// was, with plain words about why.
#[test]
fn only_the_reply_to_this_payment_is_kept() {
    let World { tor, mut a, mut b, .. } = world();
    b.knows(1, &a);
    b.rpc("paycore.receive.set_auto", json!({"on": true})).unwrap();
    // a real reply, to another payment of the same sender
    let other = prepare(&mut a, &b.address, GRIN / 2);
    a.rpc("paycore.onion.send", json!({"op": other["op"]})).unwrap();
    b.approve_request();
    let other_reply = tor.borrow().answers[0].clone();
    assert_eq!(a.pump(), vec!["reply_held"]);

    let p = prepare(&mut a, &b.address, GRIN);
    let (signed, ops) = (a.signatures(), a.sim.ops());
    let s1 = slate_of(&p);
    let cases: Vec<(String, &str)> = vec![
        (other_reply, "the reply does not match the payment"),
        (json!({"result": {"Ok": s1}}).to_string(), "the answer is not a reply to a payment"),
        (json!({"result": {"Ok": {"junk": true}}}).to_string(), "the answer is not a reply to a payment"),
        ("<html>502</html>".into(), "the answer is not a wallet's answer"),
        (json!({"error": {"message": "go away"}}).to_string(), "the wallet at this address refused: go away"),
    ];
    for (answer, words) in cases {
        // somebody else sits at the address and answers what it likes
        tor.borrow_mut().events.remove(&b.address);
        tor.borrow_mut().events.insert(b.address, VecDeque::new());
        a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
        let id = match tor.borrow_mut().events.get_mut(&b.address).unwrap().pop_front() {
            Some(Event::Request { id, .. }) => id,
            _ => panic!("no request"),
        };
        Wire { me: b.address, tor: tor.clone() }.answer(id, &answer);
        assert_eq!(a.pump(), vec!["tor_failed"], "{words}");
        let status = a.status();
        let mine = status["sends"].as_array().unwrap().iter().find(|s| s["op"] == p["op"]).unwrap();
        assert_eq!(mine["reason"], words);
        assert_eq!(send_state(&mut a, &p["op"])["reply_held"], false);
        assert_eq!(send_state(&mut a, &p["op"])["state"], "prepared");
    }
    assert_eq!((a.signatures(), a.sim.ops()), (signed, ops));
    // an outcome nobody waits for changes nothing
    tor.borrow_mut().events.get_mut(&a.address).unwrap().push_back(Event::Posted { ticket: [9; 16], result: Ok("{}".into()) });
    assert!(a.pump().is_empty());
}

/// K157: a post that got no answer is "not known", never "not received":
/// the payment stays prepared, the money reserved, and the user decides.
#[test]
fn a_post_without_an_outcome_leaves_the_payment_as_it_was() {
    let World { tor, mut a, b, .. } = world();
    // nobody listens at the address
    let nobody = [0x33; 32];
    let p = prepare(&mut a, &nobody, GRIN);
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    assert_eq!(a.pump(), vec!["tor_failed"]);
    assert_eq!(a.status()["sends"][0]["reason"], "Tor did not reach the wallet at this address");
    assert_eq!(send_state(&mut a, &p["op"])["state"], "prepared");
    // the Tor process never says what became of a post
    let q = prepare(&mut a, &b.address, GRIN);
    a.rpc("paycore.onion.send", json!({"op": q["op"]})).unwrap();
    assert!(a.pump().is_empty());
    a.b.set_onion_waits(Duration::from_secs(40), Duration::ZERO);
    assert_eq!(a.pump(), vec!["tor_failed"]);
    let status = a.status();
    let mine = status["sends"].as_array().unwrap().iter().find(|s| s["op"] == q["op"]).unwrap();
    assert_eq!(mine["reason"], "Tor gave no outcome; whether the wallet at this address got the payment is not known");
    let balance = a.rpc("paycore.balance", json!({})).unwrap();
    assert_ne!(balance["reserved"], "0");
    // the answer that comes after all is not taken for one that is waited for
    let id = match tor.borrow_mut().events.get_mut(&b.address).unwrap().pop_front() {
        Some(Event::Request { id, .. }) => id,
        _ => panic!("no request"),
    };
    Wire { me: b.address, tor: tor.clone() }.answer(id, "{}");
    assert!(a.pump().is_empty());
    assert_eq!(send_state(&mut a, &q["op"])["reply_held"], false);
}

/// K152 with the host's switch for signing replies by itself: the same
/// rule as for replies that come through the message transport - only on
/// the selected tip.
#[test]
fn a_reply_through_tor_is_signed_by_itself_only_where_the_host_allows() {
    let World { mut a, mut b, .. } = world();
    b.knows(1, &a);
    b.rpc("paycore.receive.set_auto", json!({"on": true})).unwrap();
    a.b.set_auto_sign(true);
    let p = prepare(&mut a, &b.address, GRIN);
    a.rpc("paycore.onion.send", json!({"op": p["op"]})).unwrap();
    b.approve_request();
    assert_eq!(a.pump(), vec!["reply_signed"]);
    assert_eq!(send_state(&mut a, &p["op"])["state"], "finalized");
    // without a selected tip the reply waits for the user
    let q = prepare(&mut a, &b.address, GRIN);
    a.sel.set(None);
    a.rpc("paycore.onion.send", json!({"op": q["op"]})).unwrap();
    b.approve_request();
    assert_eq!(a.pump(), vec!["reply_held"]);
    assert_eq!(send_state(&mut a, &q["op"])["state"], "prepared");
}
