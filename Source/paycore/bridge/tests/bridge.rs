//! The bridge driven the way the UI drives it: JSON in, JSON out.
use fly_paycore_bridge::ports::{Broadcaster, ChainView, Clock, JsonCodec, Ports};
use fly_paycore_bridge::{Bridge, MAX_REQUEST_LEN};
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
use std::cell::RefCell;
use std::rc::Rc;

const GRIN: u64 = 1_000_000_000;
type B = Bridge<SimDir, SimGuard, ExtKeychain>;

struct Net {
    posted: Rc<RefCell<Vec<Vec<u8>>>>,
    answer: Rc<RefCell<Broadcast>>,
}
impl Broadcaster for Net {
    fn post_tx(&mut self, tx: &[u8]) -> Broadcast {
        self.posted.borrow_mut().push(tx.to_vec());
        *self.answer.borrow()
    }
    // with the owner's agreement to the direct way: marked, for the test to tell
    fn post_tx_direct(&mut self, tx: &[u8]) -> Broadcast {
        self.posted.borrow_mut().push([b"direct:".as_slice(), tx].concat());
        *self.answer.borrow()
    }
}
struct Time(Option<u64>);
impl Clock for Time {
    fn confirmed_time(&self) -> Option<u64> {
        self.0
    }
}
type TipRef = Rc<RefCell<Option<(u64, [u8; 32])>>>;
struct View(bool, TipRef);
impl ChainView for View {
    fn payment_basis(&self) -> fly_paycore_bridge::ports::PaymentBasis {
        fly_paycore_bridge::ports::PaymentBasis {
            state: self.chain_state(),
            selected: self.selected_tip(),
            k_conf: self.k_conf(),
        }
    }
    fn chain_state(&self) -> ChainState {
        ChainState::AtTip
    }
    fn k_conf(&self) -> u64 {
        3
    }
    fn selected_tip(&self) -> Option<(u64, [u8; 32])> {
        *self.1.borrow()
    }
    fn rangeproofs_authenticated(&self) -> bool {
        self.0
    }
}

struct Wallet {
    b: B,
    posted: Rc<RefCell<Vec<Vec<u8>>>>,
    answer: Rc<RefCell<Broadcast>>,
    selected: TipRef,
    _sim: Sim,
}

fn kc(seed: u8) -> ExtKeychain {
    ExtKeychain::from_seed(&[seed; 32], true).unwrap()
}

fn wallet(seed: u8, rp_authenticated: bool) -> Wallet {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let sim = Sim::new();
    let id = Identity {
        network: 2,
        genesis: [7; 32],
        instance: [seed; 16],
    };
    let core = Core::create(
        sim.dir(),
        sim.guard(),
        &RootKey::new([0x42; 32]),
        id,
        kc(seed),
        0,
        3,
    )
    .unwrap();
    let posted = Rc::new(RefCell::new(Vec::new()));
    let answer = Rc::new(RefCell::new(Broadcast::Accepted));
    let selected = TipRef::default();
    let ports = Ports {
        broadcaster: Box::new(Net {
            posted: posted.clone(),
            answer: answer.clone(),
        }),
        clock: Box::new(Time(Some(1_000))),
        chain: Box::new(View(rp_authenticated, selected.clone())),
        codec: Box::new(JsonCodec),
        mailbox: None,
    };
    Wallet {
        b: Bridge::new(core, ports),
        posted,
        answer,
        selected,
        _sim: sim,
    }
}

/// A toy chain that tells every wallet the same facts.
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
            *w.selected.borrow_mut() = Some((a.height, a.hash));
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

fn rpc(w: &mut Wallet, method: &str, params: Value) -> Result<Value, Value> {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let text = w.b.call(&req.to_string());
    let v: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["jsonrpc"], "2.0");
    assert_eq!(v["id"], 1);
    assert!(v.get("result").is_some() != v.get("error").is_some());
    match v.get("result") {
        Some(r) => Ok(r.clone()),
        None => Err(v["error"].clone()),
    }
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}
fn kind(e: &Value) -> &str {
    e["data"]["kind"].as_str().unwrap()
}

fn pair() -> (Wallet, Wallet, Chain) {
    let mut a = wallet(1, true);
    let mut b = wallet(2, true);
    let mut chain = Chain { height: 0, pos: 0 };
    chain.fund(1, &[5 * GRIN, 3 * GRIN], &mut [&mut a, &mut b]);
    chain.empty(1, &mut [&mut a, &mut b]);
    (a, b, chain)
}

/// A whole payment, an invoice and a late-locked payment between two
/// wallets, with nothing but JSON-RPC between the "UI" and the core.
#[test]
fn payments_through_json_only() {
    let (mut a, mut b, mut chain) = pair();
    assert_eq!(
        rpc(&mut a, "paycore.balance", json!({})).unwrap()["spendable"],
        "8000000000"
    );
    let info = rpc(&mut a, "paycore.info", json!({})).unwrap();
    assert_eq!(
        (info["api_version"].as_u64(), info["tip_height"].as_u64()),
        (Some(1), Some(2))
    );

    // ordinary send with a payment proof; the amount as a decimal string
    let to = rpc(&mut b, "paycore.address", json!({})).unwrap()["address"].clone();
    let p = rpc(
        &mut a,
        "paycore.send.prepare",
        json!({"amount": "2000000000", "proof_to": to}),
    )
    .unwrap();
    // The review must be bound to the operation, even with no UI cache.
    let review = rpc(&mut a, "paycore.send.review", json!({"op": p["op"]})).unwrap();
    assert_eq!(review["receiver_address"], to);
    assert_eq!(review["amount"], "2000000000");
    assert!(review["fee"].as_str().unwrap().parse::<u64>().unwrap() > 0);
    let s2 = rpc(
        &mut b,
        "paycore.receive.draft",
        json!({"slate": p["slate"]}),
    )
    .unwrap();
    let fin = rpc(
        &mut a,
        "paycore.send.finalize",
        json!({"op": p["op"], "slate": s2["slate"]}),
    )
    .unwrap();
    assert_eq!(fin["payment_proof"]["amount"], "2000000000");
    assert_eq!(fin["payment_proof"]["receiver_address"], to);
    // a signed payment is not shown for signing again (K123)
    assert_eq!(
        rpc(&mut a, "paycore.send.review", json!({"op": p["op"]})).unwrap_err()["data"]["kind"],
        "refused"
    );
    // the stored result is the same and broadcasting never signs again
    assert_eq!(
        rpc(&mut a, "paycore.send.result", json!({"op": p["op"]})).unwrap(),
        fin
    );
    *a.answer.borrow_mut() = Broadcast::Unknown;
    assert_eq!(
        rpc(&mut a, "paycore.send.broadcast", json!({"op": p["op"]})).unwrap()["outcome"],
        "unknown"
    );
    *a.answer.borrow_mut() = Broadcast::Accepted;
    assert_eq!(
        rpc(&mut a, "paycore.send.broadcast", json!({"op": p["op"]})).unwrap()["outcome"],
        "accepted"
    );
    let tx = unhex(fin["tx"].as_str().unwrap());
    assert_eq!(*a.posted.borrow(), vec![tx.clone(), tx.clone()]);
    assert_eq!(a.b.core().signatures_made(), 1);
    // K192: the agreement to the direct way goes with this one payment and
    // only when it is given; the same stored bytes, nothing signed again
    assert_eq!(rpc(&mut a, "paycore.send.broadcast", json!({"op": p["op"], "direct": true})).unwrap()["outcome"], "accepted");
    assert_eq!(a.posted.borrow().last(), Some(&[b"direct:".as_slice(), &tx].concat()));
    assert_eq!(rpc(&mut a, "paycore.send.broadcast", json!({"op": p["op"], "direct": false})).unwrap()["outcome"], "accepted");
    assert_eq!(a.posted.borrow().last(), Some(&tx));
    assert_eq!(kind(&rpc(&mut a, "paycore.send.broadcast", json!({"op": p["op"], "direct": "yes"})).unwrap_err()), "invalid_params");
    assert_eq!((a.posted.borrow().len(), a.b.core().signatures_made()), (4, 1));
    a.posted.borrow_mut().truncate(2);
    let st = rpc(&mut a, "paycore.send.status", json!({"op": p["op"]})).unwrap();
    assert_eq!(st["state"], "finalized");
    assert_eq!(
        st["broadcasts"],
        json!({"accepted": 3, "rejected": 0, "unknown": 1})
    );

    let incoming = rpc(&mut b, "paycore.history", json!({})).unwrap()["incoming"][0].clone();
    let sid = incoming["slate_id"].clone();
    assert_eq!(incoming["status"], "not_confirmed");
    assert_eq!(incoming["status_rule"], "S4");
    assert_eq!(
        rpc(&mut b, "paycore.receive.status", json!({"slate_id": sid})).unwrap()["status_rule"],
        "S4"
    );
    chain.mine(&tx, &mut [&mut a, &mut b]);
    chain.empty(2, &mut [&mut a, &mut b]);
    assert_eq!(
        rpc(&mut a, "paycore.send.status", json!({"op": p["op"]})).unwrap()["state"],
        "confirmed"
    );
    let row = rpc(&mut b, "paycore.receive.status", json!({"slate_id": sid})).unwrap();
    assert_eq!(
        (row["status"].as_str(), row["status_rule"].as_str()),
        (Some("confirmed"), Some("S8"))
    );
    assert_eq!(
        rpc(&mut b, "paycore.balance", json!({})).unwrap()["spendable"],
        "2000000000"
    );

    assert_eq!(rpc(&mut b, "paycore.history", json!({})).unwrap()["incoming"][0]["status_rule"], "S8");

    // K190: the history says in which block and against which tip, and the
    // number of confirmations that makes "received" is the owner's to
    // choose - one at least. It changes the word, never the money.
    let h = rpc(&mut b, "paycore.history", json!({})).unwrap();
    let (tip, kernel) = (h["tip_height"].as_u64().unwrap(), h["incoming"][0]["kernel_height"].as_u64().unwrap());
    assert_eq!((tip - kernel + 1, h["k_conf"].as_u64()), (3, Some(3)));
    let sent = rpc(&mut a, "paycore.history", json!({})).unwrap()["sends"][0].clone();
    assert_eq!((sent["kernel_height"].as_u64(), sent["signed"].as_bool()), (Some(kernel), Some(true)));
    let balance = rpc(&mut b, "paycore.balance", json!({})).unwrap();
    assert_eq!(rpc(&mut b, "paycore.settings.confirmations", json!({"count": 4})).unwrap(), json!({"k_conf": 4}));
    let h = rpc(&mut b, "paycore.history", json!({})).unwrap();
    assert_eq!((h["k_conf"].as_u64(), h["incoming"][0]["status"].as_str(), h["incoming"][0]["status_rule"].as_str()), (Some(4), Some("preliminary"), Some("S6")));
    assert_eq!(rpc(&mut b, "paycore.balance", json!({})).unwrap(), balance);
    for count in [0u64, 1001] {
        assert_eq!(kind(&rpc(&mut b, "paycore.settings.confirmations", json!({"count": count})).unwrap_err()), "invalid_params", "{count}");
    }
    assert_eq!(rpc(&mut b, "paycore.history", json!({})).unwrap()["k_conf"], 4, "a refused number changed the one in force");
    rpc(&mut b, "paycore.settings.confirmations", json!({"count": 1})).unwrap();
    assert_eq!(rpc(&mut b, "paycore.history", json!({})).unwrap()["incoming"][0]["status"], "confirmed");
    rpc(&mut b, "paycore.settings.confirmations", json!({"count": 3})).unwrap();
    // K191: the reply made to an incoming payment is given again as it was
    assert_eq!(h["incoming"][0]["reply_kept"], true);
    assert_eq!(rpc(&mut b, "paycore.receive.reply", json!({"slate_id": sid})).unwrap()["slate"], s2["slate"]);
    assert_eq!(kind(&rpc(&mut b, "paycore.receive.reply", json!({"slate_id": "00".repeat(16)})).unwrap_err()), "not_found");
    assert_eq!(rpc(&mut b, "paycore.balance", json!({})).unwrap(), balance);

    // A change of selected branch precedes the wallet's next sync step.
    let applied = b.b.core().tip().unwrap();
    *b.selected.borrow_mut() = Some((applied.0, [0x61; 32]));
    let displayed = rpc(&mut b, "paycore.wallet.chain_status", json!({})).unwrap();
    assert_eq!(displayed["state"], "behind");
    assert_eq!(displayed["balance"], rpc(&mut b, "paycore.balance", json!({})).unwrap());
    assert_eq!(displayed["tip_height"], displayed["selected_height"]);
    let changed = rpc(&mut b, "paycore.receive.status", json!({"slate_id": sid})).unwrap();
    assert_eq!(changed["status_rule"], "S2");
    let row = &rpc(&mut b, "paycore.history", json!({})).unwrap()["incoming"][0];
    assert_eq!(row["status_rule"], "S2");
    assert_eq!(row["status"], "preliminary");
    *b.selected.borrow_mut() = Some(applied);
    assert_eq!(rpc(&mut b, "paycore.wallet.chain_status", json!({})).unwrap()["state"], "at_tip");

    // invoice: B asks for 1 grin, A pays at most 1 grin
    let inv = rpc(&mut b, "paycore.invoice.issue", json!({"amount": GRIN})).unwrap();
    let too_much = rpc(
        &mut a,
        "paycore.invoice.pay",
        json!({"slate": inv["slate"], "max_amount": GRIN - 1}),
    );
    assert_eq!(kind(&too_much.unwrap_err()), "refused");
    // what paying takes, by the payer's own count; with a fee above the
    // agreed one nothing is paid
    let review = rpc(&mut a, "paycore.invoice.review", json!({"slate": inv["slate"]})).unwrap();
    assert_eq!((&review["slate_id"], &review["amount"], &review["paid_op"]), (&inv["slate_id"], &json!(GRIN.to_string()), &Value::Null));
    let fee: u64 = review["fee"].as_str().unwrap().parse().unwrap();
    assert!(fee > 0);
    let dearer = rpc(
        &mut a,
        "paycore.invoice.pay",
        json!({"slate": inv["slate"], "max_amount": GRIN, "max_fee": (fee - 1).to_string()}),
    );
    assert_eq!(kind(&dearer.unwrap_err()), "refused");
    assert_eq!(rpc(&mut a, "paycore.invoice.review", json!({"slate": inv["slate"]})).unwrap()["paid_op"], Value::Null);
    let paid = rpc(
        &mut a,
        "paycore.invoice.pay",
        json!({"slate": inv["slate"], "max_amount": GRIN, "max_fee": review["fee"]}),
    )
    .unwrap();
    // the history tells the payment of an invoice from an ordinary one
    let sends = rpc(&mut a, "paycore.history", json!({})).unwrap()["sends"].clone();
    let kinds: Vec<bool> = sends.as_array().unwrap().iter().map(|s| s["invoice"].as_bool().unwrap()).collect();
    assert_eq!(kinds.iter().filter(|invoice| **invoice).count(), 1);
    assert!(kinds.len() > 1);
    assert!(sends.as_array().unwrap().iter().any(|s| s["op"] == paid["op"] && s["invoice"] == true && s["state"] == "finalized"));
    let again = rpc(&mut a, "paycore.invoice.review", json!({"slate": inv["slate"]})).unwrap();
    assert_eq!((&again["paid_op"], &again["fee"], &again["amount"]), (&paid["op"], &review["fee"], &review["amount"]));
    let done = rpc(
        &mut b,
        "paycore.invoice.finalize",
        json!({"slate_id": inv["slate_id"], "slate": paid["slate"]}),
    )
    .unwrap();
    // the payer does not broadcast a paid invoice
    assert_eq!(
        kind(&rpc(&mut a, "paycore.send.broadcast", json!({"op": paid["op"]})).unwrap_err()),
        "refused"
    );
    chain.mine(&unhex(done["tx"].as_str().unwrap()), &mut [&mut a, &mut b]);
    assert_eq!(
        rpc(&mut a, "paycore.send.status", json!({"op": paid["op"]})).unwrap()["state"],
        "confirmed"
    );

    // late lock, received without a draft (auto receive)
    assert!(rpc(&mut b, "paycore.receive.set_auto", json!({"on": true})).is_ok());
    let late = rpc(
        &mut a,
        "paycore.send.prepare",
        json!({"amount": GRIN / 2, "late": true}),
    )
    .unwrap();
    let reserved = rpc(&mut a, "paycore.balance", json!({})).unwrap()["reserved"].clone();
    assert_eq!(reserved, "0");
    let s2 = rpc(
        &mut b,
        "paycore.receive.auto",
        json!({"slate": late["slate"], "min_amount": 1000}),
    )
    .unwrap();
    let fin = rpc(
        &mut a,
        "paycore.send.finalize",
        json!({"op": late["op"], "slate": s2["slate"]}),
    )
    .unwrap();
    chain.mine(&unhex(fin["tx"].as_str().unwrap()), &mut [&mut a, &mut b]);
    let hist = rpc(&mut a, "paycore.history", json!({})).unwrap();
    assert_eq!(hist["sends"].as_array().unwrap().len(), 3);
    assert!(hist["sends"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["state"] == "confirmed"));
}

/// Errors are structured and stable; refusals come from the core's rules.
/// A chain layer that has nothing new for a wallet with a position, or
/// cannot say.
struct Quiet(Rc<RefCell<bool>>);
impl fly_paycore_bridge::chain_port::ChainFeed for Quiet {
    fn status(&mut self) -> Option<fly_paycore_bridge::chain_port::Status> {
        None
    }
    fn next(&mut self, _: Option<fly_paycore_bridge::chain_port::Tip>) -> Result<fly_paycore_bridge::chain_port::Step, fly_paycore_bridge::chain_port::Unknown> {
        if *self.0.borrow() {
            Ok(fly_paycore_bridge::chain_port::Step::Nothing)
        } else {
            Err(fly_paycore_bridge::chain_port::Unknown)
        }
    }
    fn post(&mut self, _: &[u8]) -> fly_paycore_bridge::chain_port::Posted {
        fly_paycore_bridge::chain_port::Posted::Unknown
    }
}

/// `paycore.send.pump`, which the profile handler calls every round, hands
/// the finished transactions that are not in the chain to the chain layer
/// by itself: one at a time, the one handed over longest ago, each no
/// more often than the pause allows - and only while the wallet has every
/// block the chain layer has. The same bytes every time, no new signature.
/// An outcome is written to the journal, and reported, only when it is not
/// the one before.
#[test]
fn finished_transactions_are_handed_to_the_chain_layer() {
    let (mut a, mut b, mut chain) = pair();
    let pay = |a: &mut Wallet, b: &mut Wallet, amount: &str| {
        let p = rpc(a, "paycore.send.prepare", json!({"amount": amount})).unwrap();
        let s2 = rpc(b, "paycore.receive.draft", json!({"slate": p["slate"]})).unwrap();
        let fin = rpc(a, "paycore.send.finalize", json!({"op": p["op"], "slate": s2["slate"]})).unwrap();
        (p["op"].clone(), unhex(fin["tx"].as_str().unwrap()))
    };
    let (op1, tx1) = pay(&mut a, &mut b, "2000000000");
    let pump = |a: &mut Wallet| rpc(a, "paycore.send.pump", json!({})).unwrap()["broadcast"].clone();
    let counts = |a: &mut Wallet, op: &Value| rpc(a, "paycore.send.status", json!({"op": op})).unwrap()["broadcasts"].clone();
    *a.answer.borrow_mut() = Broadcast::Unknown;

    // a wallet that does not know whether it has every block hands nothing over
    assert_eq!(pump(&mut a), json!([]));
    let tip = Rc::new(RefCell::new(false));
    a.b.set_chain_feed(Box::new(Quiet(tip.clone())));
    rpc(&mut a, "paycore.chain.sync", json!({})).unwrap();
    assert_eq!(pump(&mut a), json!([]));
    assert!(a.posted.borrow().is_empty());

    // at the tip: handed over, and the outcome reported and written
    *tip.borrow_mut() = true;
    rpc(&mut a, "paycore.chain.sync", json!({})).unwrap();
    assert_eq!(pump(&mut a), json!([{"op": op1, "outcome": "unknown"}]));
    assert_eq!(*a.posted.borrow(), vec![tx1.clone()]);
    // not again before its time
    assert_eq!(pump(&mut a), json!([]));
    assert_eq!(a.posted.borrow().len(), 1);
    // when its time has come: handed over again, and the same outcome is not written again
    a.b.set_broadcast_every(std::time::Duration::ZERO);
    for _ in 0..3 {
        assert_eq!(pump(&mut a), json!([]));
    }
    assert_eq!(*a.posted.borrow(), vec![tx1.clone(); 4]);
    assert_eq!(counts(&mut a, &op1), json!({"accepted": 0, "rejected": 0, "unknown": 1}));
    // another outcome is
    *a.answer.borrow_mut() = Broadcast::Accepted;
    assert_eq!(pump(&mut a), json!([{"op": op1, "outcome": "accepted"}]));
    assert_eq!(pump(&mut a), json!([]));
    assert_eq!(counts(&mut a, &op1), json!({"accepted": 1, "rejected": 0, "unknown": 1}));
    assert_eq!(a.b.core().signatures_made(), 1, "nothing is signed for this");
    // what the interface asked for by hand is not written a second time by the handler
    *a.answer.borrow_mut() = Broadcast::Rejected;
    assert_eq!(rpc(&mut a, "paycore.send.broadcast", json!({"op": op1})).unwrap()["outcome"], "rejected");
    assert_eq!(pump(&mut a), json!([]));
    assert_eq!(counts(&mut a, &op1), json!({"accepted": 1, "rejected": 1, "unknown": 1}));

    // two transactions: one at a time, in turn
    let (op2, tx2) = pay(&mut a, &mut b, "1000000000");
    a.posted.borrow_mut().clear();
    assert_eq!(pump(&mut a), json!([{"op": op2, "outcome": "rejected"}]), "the one never handed over first");
    for _ in 0..4 {
        pump(&mut a);
    }
    assert_eq!(*a.posted.borrow(), vec![tx2.clone(), tx1.clone(), tx2.clone(), tx1.clone(), tx2.clone()]);

    // in the chain: no more
    chain.mine(&tx1, &mut [&mut a, &mut b]);
    a.posted.borrow_mut().clear();
    for _ in 0..3 {
        pump(&mut a);
    }
    assert_eq!(*a.posted.borrow(), vec![tx2.clone(); 3]);
    // and nothing while the chain layer cannot say that the wallet is at the tip
    *tip.borrow_mut() = false;
    rpc(&mut a, "paycore.chain.sync", json!({})).unwrap();
    assert_eq!(pump(&mut a), json!([]));
    assert_eq!(a.posted.borrow().len(), 3);
}

/// The transaction of an invoice is with the wallet that issued it: the
/// payer signs first and never has it. The issuer's handler hands it to
/// the chain layer as it does a payment of its own - at the tip, no more
/// often than the pause allows, the same bytes, until the kernel is in a
/// block - and the payer's handler has nothing to hand over. Nothing is
/// written for it: the invoice's record changes with the chain.
#[test]
fn the_transaction_of_an_invoice_is_handed_over_by_who_issued_it() {
    let (mut a, mut b, mut chain) = pair();
    // the issuer has money of its own as well, for a payment beside the invoice
    chain.fund(2, &[4 * GRIN], &mut [&mut a, &mut b]);
    chain.empty(1, &mut [&mut a, &mut b]);
    let issued = rpc(&mut b, "paycore.invoice.issue", json!({"amount": "2000000000"})).unwrap();
    let paid = rpc(&mut a, "paycore.invoice.pay", json!({"slate": issued["slate"], "max_amount": "2000000000"})).unwrap();
    let fin = rpc(&mut b, "paycore.invoice.finalize", json!({"slate_id": issued["slate_id"], "slate": paid["slate"]})).unwrap();
    let tx = unhex(fin["tx"].as_str().unwrap());
    let pump = |w: &mut Wallet| rpc(w, "paycore.send.pump", json!({})).unwrap()["broadcast"].clone();
    for w in [&mut a, &mut b] {
        *w.answer.borrow_mut() = Broadcast::Unknown;
        // not before the wallet knows it has every block
        assert_eq!(pump(w), json!([]));
        w.b.set_chain_feed(Box::new(Quiet(Rc::new(RefCell::new(true)))));
        rpc(w, "paycore.chain.sync", json!({})).unwrap();
    }
    // the payer has no transaction to hand over
    assert_eq!(pump(&mut a), json!([]));
    assert!(a.posted.borrow().is_empty());
    // the issuer has
    let ops = b._sim.ops();
    assert_eq!(pump(&mut b), json!([{"invoice": issued["slate_id"], "outcome": "unknown"}]));
    assert_eq!(*b.posted.borrow(), vec![tx.clone()]);
    assert_eq!(pump(&mut b), json!([]), "not again before its time");
    assert_eq!(b.posted.borrow().len(), 1);
    b.b.set_broadcast_every(std::time::Duration::ZERO);
    for _ in 0..3 {
        assert_eq!(pump(&mut b), json!([]), "the same outcome is not reported again");
    }
    assert_eq!(*b.posted.borrow(), vec![tx.clone(); 4]);
    *b.answer.borrow_mut() = Broadcast::Accepted;
    assert_eq!(pump(&mut b), json!([{"invoice": issued["slate_id"], "outcome": "accepted"}]));
    assert_eq!(b._sim.ops(), ops, "nothing is written for it");
    assert_eq!(b.b.core().signatures_made(), 1, "and nothing is signed");

    // a payment of its own beside it: one transaction a call, in turn
    *a.answer.borrow_mut() = Broadcast::Unknown;
    let p = rpc(&mut b, "paycore.send.prepare", json!({"amount": "500000000"})).unwrap();
    let s2 = rpc(&mut a, "paycore.receive.draft", json!({"slate": p["slate"]})).unwrap();
    let sent = rpc(&mut b, "paycore.send.finalize", json!({"op": p["op"], "slate": s2["slate"]})).unwrap();
    let tx2 = unhex(sent["tx"].as_str().unwrap());
    b.posted.borrow_mut().clear();
    for _ in 0..4 {
        pump(&mut b);
    }
    assert_eq!(*b.posted.borrow(), vec![tx2.clone(), tx.clone(), tx2.clone(), tx.clone()], "the one never handed over first");

    // in a block: no more
    chain.mine(&tx, &mut [&mut a, &mut b]);
    b.posted.borrow_mut().clear();
    for _ in 0..3 {
        pump(&mut b);
    }
    assert!(!b.posted.borrow().contains(&tx));
}

#[test]
fn errors_are_structured() {
    let (mut a, mut b, _chain) = pair();
    let e = |r: Result<Value, Value>| -> (i64, String) {
        let e = r.unwrap_err();
        (e["code"].as_i64().unwrap(), kind(&e).to_string())
    };
    assert_eq!(
        e(rpc(&mut a, "paycore.nope", json!({}))),
        (-32601, "method_not_found".into())
    );
    assert_eq!(
        e(rpc(&mut a, "paycore.send.prepare", json!({}))),
        (-32602, "invalid_params".into())
    );
    assert_eq!(
        e(rpc(&mut a, "paycore.send.prepare", json!({"amount": -5}))).0,
        -32602
    );
    assert_eq!(
        e(rpc(&mut a, "paycore.send.prepare", json!({"amount": 1.5}))).0,
        -32602
    );
    assert_eq!(
        e(rpc(
            &mut a,
            "paycore.send.prepare",
            json!({"amount": "12x"})
        ))
        .0,
        -32602
    );
    assert_eq!(
        e(rpc(
            &mut a,
            "paycore.send.prepare",
            json!({"amount": "99999999999999999999999"})
        ))
        .0,
        -32602
    );
    assert_eq!(
        e(rpc(
            &mut a,
            "paycore.send.prepare",
            json!({"amount": 1, "late": "yes"})
        ))
        .0,
        -32602
    );
    assert_eq!(
        e(rpc(
            &mut a,
            "paycore.send.prepare",
            json!({"amount": 1, "proof_to": "abcd"})
        ))
        .0,
        -32602
    );
    assert_eq!(
        e(rpc(&mut a, "paycore.send.prepare", json!({"amount": 0}))).1,
        "refused"
    );
    assert_eq!(
        e(rpc(
            &mut a,
            "paycore.send.prepare",
            json!({"amount": 100 * GRIN})
        ))
        .1,
        "insufficient_funds"
    );
    assert_eq!(
        e(rpc(
            &mut a,
            "paycore.send.status",
            json!({"op": "00".repeat(16)})
        ))
        .1,
        "not_found"
    );
    assert_eq!(
        e(rpc(&mut a, "paycore.send.cancel", json!({"op": "zz"}))).0,
        -32602
    );
    assert_eq!(
        e(rpc(
            &mut b,
            "paycore.receive.draft",
            json!({"slate": "{not a slate"})
        ))
        .1,
        "bad_slate"
    );
    assert_eq!(
        e(rpc(&mut b, "paycore.receive.draft", json!({"slate": 7}))).0,
        -32602
    );
    // auto receive is refused while the chain layer cannot authenticate range proofs
    let mut c = wallet(3, false);
    assert_eq!(
        e(rpc(&mut c, "paycore.receive.set_auto", json!({"on": true}))).1,
        "refused"
    );
    assert_eq!(
        e(rpc(&mut b, "paycore.receive.auto", json!({"slate": "{}"}))).1,
        "refused"
    );

    // a second, different reply and a cancel after signing
    let p = rpc(&mut a, "paycore.send.prepare", json!({"amount": GRIN})).unwrap();
    let r1 = rpc(
        &mut b,
        "paycore.receive.draft",
        json!({"slate": p["slate"]}),
    )
    .unwrap();
    let mut c = wallet(4, true);
    c.b.core_mut()
        .chain_advance(&Advance {
            height: 1,
            hash: [1; 32],
            ..Advance::default()
        })
        .unwrap();
    let r2 = rpc(
        &mut c,
        "paycore.receive.draft",
        json!({"slate": p["slate"]}),
    )
    .unwrap();
    rpc(
        &mut a,
        "paycore.send.finalize",
        json!({"op": p["op"], "slate": r1["slate"]}),
    )
    .unwrap();
    assert_eq!(
        e(rpc(
            &mut a,
            "paycore.send.finalize",
            json!({"op": p["op"], "slate": r2["slate"]})
        ))
        .1,
        "conflict"
    );
    assert_eq!(
        e(rpc(&mut a, "paycore.send.cancel", json!({"op": p["op"]}))).1,
        "refused"
    );
    assert_eq!(a.b.core().signatures_made(), 1);
}

struct Xs(u64);
impl Xs {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Protocol-level garbage: every answer is well-formed JSON-RPC, nothing
/// panics, and no request that fails changes the wallet.
#[test]
fn malformed_requests_never_panic() {
    let (mut a, mut b, _chain) = pair();
    for (req, code) in [
        ("", -32700),
        ("{", -32700),
        ("[]", -32600),
        (
            "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"paycore.balance\"}]",
            -32600,
        ),
        (
            "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"paycore.balance\"}",
            -32600,
        ),
        ("{\"jsonrpc\":\"2.0\",\"id\":1}", -32600),
        (
            "{\"jsonrpc\":\"2.0\",\"id\":{},\"method\":\"paycore.balance\"}",
            -32600,
        ),
        ("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":7}", -32600),
        (
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"paycore.balance\",\"params\":[1]}",
            -32602,
        ),
    ] {
        let v: Value = serde_json::from_str(&a.b.call(req)).unwrap();
        assert_eq!(v["error"]["code"], code, "{req}");
    }
    let big = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"paycore.balance\",\"params\":{{\"x\":\"{}\"}}}}",
        "a".repeat(MAX_REQUEST_LEN)
    );
    let v: Value = serde_json::from_str(&a.b.call(&big)).unwrap();
    assert_eq!(v["error"]["code"], -32600);
    // a notification is executed and not answered
    assert_eq!(
        a.b.call("{\"jsonrpc\":\"2.0\",\"method\":\"paycore.balance\"}"),
        ""
    );

    // damaged copies of real requests
    let p = rpc(&mut a, "paycore.send.prepare", json!({"amount": GRIN})).unwrap();
    let s2 = rpc(
        &mut b,
        "paycore.receive.draft",
        json!({"slate": p["slate"]}),
    )
    .unwrap();
    let seeds = [
        json!({"jsonrpc":"2.0","id":1,"method":"paycore.send.finalize","params":{"op":p["op"],"slate":s2["slate"]}}).to_string(),
        json!({"jsonrpc":"2.0","id":1,"method":"paycore.receive.draft","params":{"slate":p["slate"]}}).to_string(),
        json!({"jsonrpc":"2.0","id":1,"method":"paycore.invoice.pay","params":{"slate":p["slate"],"max_amount":"5"}}).to_string(),
        json!({"jsonrpc":"2.0","id":1,"method":"paycore.send.prepare","params":{"amount":"0","late":true,"proof_to":"00"}}).to_string(),
    ];
    let mut rng = Xs(0x2545_F491_4F6C_DD1D);
    let mut errors = 0u32;
    for round in 0..4000 {
        let mut req = seeds[(rng.next() % 4) as usize].clone().into_bytes();
        for _ in 0..1 + rng.next() % 3 {
            if req.len() < 2 {
                break;
            }
            let i = (rng.next() % req.len() as u64) as usize;
            match rng.next() % 4 {
                0 => req[i] = b"{}[]\":,0123456789abcdefnul\\ "[(rng.next() % 28) as usize],
                1 => {
                    req.remove(i);
                }
                2 => req.truncate(i.max(1)),
                _ => req.insert(i, (rng.next() % 96 + 32) as u8),
            }
        }
        let Ok(text) = String::from_utf8(req) else {
            continue;
        };
        let tail = b.b.core().journal_tail();
        let signs = b.b.core().signatures_made();
        let answer = b.b.call(&text);
        if answer.is_empty() {
            continue;
        }
        let v: Value =
            serde_json::from_str(&answer).unwrap_or_else(|_| panic!("round {round}: {answer}"));
        assert_eq!(v["jsonrpc"], "2.0");
        if v.get("error").is_some() {
            errors += 1;
            assert!(v["error"]["code"].is_i64() && v["error"]["data"]["kind"].is_string());
            assert!(
                b.b.core().journal_tail() == tail && b.b.core().signatures_made() == signs,
                "round {round}: a failed request left a trace"
            );
        }
    }
    assert!(errors > 2000, "{errors}");
    // the untouched request still works afterwards
    rpc(
        &mut a,
        "paycore.send.finalize",
        json!({"op": p["op"], "slate": s2["slate"]}),
    )
    .unwrap();
}

/// K119: a slate is read for showing without touching the wallet; what the
/// window shows is what the slate says, and garbage is refused, not guessed.
#[test]
fn a_slate_is_read_before_deciding_without_changing_anything() {
    let (mut a, mut b, _chain) = pair();
    let to = rpc(&mut b, "paycore.address", json!({})).unwrap()["address"].clone();
    let from = rpc(&mut a, "paycore.address", json!({})).unwrap()["address"].clone();
    let p = rpc(
        &mut a,
        "paycore.send.prepare",
        json!({"amount": "2000000000", "proof_to": to}),
    )
    .unwrap();
    let fee = rpc(&mut a, "paycore.history", json!({})).unwrap()["sends"][0]["fee"].clone();
    let frames = b.b.core_mut().journal_frames();
    let read = rpc(&mut b, "paycore.slate.read", json!({"slate": p["slate"]})).unwrap();
    assert_eq!(read["stage"], "S1");
    assert_eq!(read["amount"], "2000000000");
    assert_eq!(read["fee"], fee);
    assert_ne!(read["fee"], "0");
    assert_eq!(read["receiver_address"], to);
    assert_eq!(read["sender_address"], from);
    assert_eq!(read["slate_id"].as_str().map(str::len), Some(32));
    // reading wrote nothing and left the receiver's money where it was
    assert_eq!(b.b.core_mut().journal_frames(), frames);
    assert_eq!(rpc(&mut b, "paycore.history", json!({})).unwrap()["incoming"], json!([]));

    // the reply reads as the reply; it does not repeat the amount, and the
    // answer says so instead of showing a zero
    let s2 = rpc(&mut b, "paycore.receive.draft", json!({"slate": p["slate"]})).unwrap();
    let back = rpc(&mut a, "paycore.slate.read", json!({"slate": s2["slate"]})).unwrap();
    assert_eq!(back["stage"], "S2");
    assert!(back["amount"].is_null() || back["amount"] == "2000000000");
    assert_ne!(back["amount"], "0");
    assert_eq!(back["slate_id"], read["slate_id"]);

    // without a proof there are no addresses
    let plain = rpc(&mut a, "paycore.send.prepare", json!({"amount": "1000000000"})).unwrap();
    let r = rpc(&mut b, "paycore.slate.read", json!({"slate": plain["slate"]})).unwrap();
    assert_eq!((r["sender_address"].clone(), r["receiver_address"].clone()), (Value::Null, Value::Null));

    let bad = rpc(&mut b, "paycore.slate.read", json!({"slate": "{\"not\": \"a slate\"}"})).unwrap_err();
    assert!(bad["code"].as_i64().is_some());
    assert!(rpc(&mut b, "paycore.slate.read", json!({})).is_err());
}
