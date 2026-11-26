//! The bridge driven the way the UI drives it: JSON in, JSON out.
use fly_paycore_bridge::ports::{Broadcaster, ChainView, Clock, JsonCodec, Ports};
use fly_paycore_bridge::{Bridge, MAX_REQUEST_LEN};
use fly_paycore_keys::path::KeyPath;
use fly_paycore_store::sim::{Fault, Sim, SimDir, SimGuard};
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
    // K198: the agreement was written with the payment and holds for every
    // later sending of it, asked for by hand or done by the handler
    assert_eq!(rpc(&mut a, "paycore.history", json!({})).unwrap()["sends"].as_array().unwrap().iter().find(|s| s["op"] == p["op"]).unwrap()["direct"], true);
    let w0 = a._sim.ops();
    assert_eq!(rpc(&mut a, "paycore.send.broadcast", json!({"op": p["op"], "direct": false})).unwrap()["outcome"], "accepted");
    assert_eq!(a.posted.borrow().last(), Some(&[b"direct:".as_slice(), &tx].concat()));
    a.posted.borrow_mut().pop();
    let w1 = a._sim.ops();
    rpc(&mut a, "paycore.send.broadcast", json!({"op": p["op"], "direct": true})).unwrap();
    a.posted.borrow_mut().pop();
    assert_eq!(a._sim.ops() - w1, w1 - w0, "said again, the agreement itself is not written again");
    a.posted.borrow_mut().push(tx.clone());
    assert_eq!(kind(&rpc(&mut a, "paycore.send.broadcast", json!({"op": p["op"], "direct": "yes"})).unwrap_err()), "invalid_params");
    assert_eq!((a.posted.borrow().len(), a.b.core().signatures_made()), (4, 1));
    a.posted.borrow_mut().truncate(2);
    let st = rpc(&mut a, "paycore.send.status", json!({"op": p["op"]})).unwrap();
    assert_eq!(st["state"], "finalized");
    assert_eq!(
        st["broadcasts"],
        json!({"accepted": 4, "rejected": 0, "unknown": 1})
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
    // K200: and the sender's text as it came, read only; of a payment given up it is not kept
    assert_eq!(h["incoming"][0]["request_kept"], true);
    let ops = b._sim.ops();
    assert_eq!(rpc(&mut b, "paycore.receive.request", json!({"slate_id": sid})).unwrap()["slate"], p["slate"]);
    assert_eq!(b._sim.ops(), ops);
    assert_eq!(kind(&rpc(&mut b, "paycore.receive.request", json!({"slate_id": "00".repeat(16)})).unwrap_err()), "not_found");
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
    // K197: the payment of an invoice is signed, in no block - and is not taken back
    let e = rpc(&mut a, "paycore.send.take_back", json!({"op": paid["op"]})).unwrap_err();
    assert_eq!(e["data"]["reason"], "the payment of an invoice is not taken back");
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
    // K194: money that came with no record of a payment is listed too, and
    // only that. For the receiver: what unattended receive took, with its
    // block; the two payments it has a record of are not said twice.
    let got = rpc(&mut b, "paycore.history", json!({})).unwrap();
    let found = got["found"].as_array().unwrap();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        (&found[0]["amount"], &found[0]["height"], &found[0]["by_search"], &found[0]["coinbase"], &found[0]["spent_height"]),
        (&json!((GRIN / 2).to_string()), &got["tip_height"], &json!(false), &json!(false), &Value::Null)
    );
    assert_eq!(got["incoming"].as_array().unwrap().len(), 2);
    // every operation says where it stands in time
    let before_its_block = |row: &Value| row["made_height"].as_u64().is_some_and(|made| Some(made) < row["kernel_height"].as_u64());
    assert!(got["incoming"].as_array().unwrap().iter().all(before_its_block));
    assert!(hist["sends"].as_array().unwrap().iter().all(before_its_block));
    // for the sender: the coins it began with, each with the block that
    // spent it - and not the change of its own three payments
    let found = hist["found"].as_array().unwrap();
    let said: Vec<(&str, u64, Option<u64>)> = found.iter().map(|f| (f["amount"].as_str().unwrap(), f["height"].as_u64().unwrap(), f["spent_height"].as_u64())).collect();
    assert_eq!(said, [("5000000000", 1, Some(3)), ("3000000000", 1, Some(6))], "newest first, then by commitment");
    // the list is a reading: nothing is written
    let ops = a._sim.ops();
    rpc(&mut a, "paycore.history", json!({})).unwrap();
    assert_eq!(a._sim.ops(), ops);
}

/// K195: the owner's outputs, the mark "not to be spent" and the choice of
/// what a payment is paid with. The wallet begins with two coins, 5 and 3.
#[test]
fn the_owner_chooses_what_is_spent() {
    let (mut a, mut b, mut chain) = pair();
    let list = |w: &mut Wallet| rpc(w, "paycore.outputs.list", json!({})).unwrap()["outputs"].as_array().unwrap().clone();
    let balance = |w: &mut Wallet| {
        let b = rpc(w, "paycore.balance", json!({})).unwrap();
        (b["spendable"].as_str().unwrap().to_string(), b["reserved"].as_str().unwrap().to_string(), b["kept"].as_str().unwrap().to_string())
    };
    let s = |x: &str| x.to_string();
    let outs = list(&mut a);
    let seen: Vec<(&str, &str, bool)> = outs.iter().map(|o| (o["amount"].as_str().unwrap(), o["state"].as_str().unwrap(), o["kept"].as_bool().unwrap())).collect();
    assert_eq!(seen, [("5000000000", "spendable", false), ("3000000000", "spendable", false)], "the largest first");
    let (five, three) = (outs[0]["commit"].clone(), outs[1]["commit"].clone());
    let ops = a._sim.ops();
    list(&mut a);
    assert_eq!(a._sim.ops(), ops, "the list is a reading");

    // the mark: the output is the owner's still, and not on offer
    assert_eq!(rpc(&mut a, "paycore.outputs.keep", json!({"commit": five, "on": true})).unwrap(), json!({"kept": true}));
    assert_eq!(balance(&mut a), (s("3000000000"), s("0"), s("5000000000")));
    assert_eq!(list(&mut a)[0]["kept"], true);
    let marked = a._sim.ops();
    rpc(&mut a, "paycore.outputs.keep", json!({"commit": five, "on": true})).unwrap();
    assert_eq!(a._sim.ops(), marked, "marked already: nothing is written");
    // the wallet's own choice passes it by: 4 cannot be paid from the 3 that are on offer
    let e = rpc(&mut a, "paycore.send.prepare", json!({"amount": 4 * GRIN})).unwrap_err();
    assert_eq!(kind(&e), "insufficient_funds");
    // an output that is not this wallet's, and what is not a mark
    let foreign = "09".to_string() + &"ab".repeat(32);
    assert_eq!(kind(&rpc(&mut a, "paycore.outputs.keep", json!({"commit": foreign, "on": true})).unwrap_err()), "not_found");
    for bad in [json!({"commit": five}), json!({"commit": five, "on": "yes"}), json!({"commit": "zz", "on": true}), json!({"on": true})] {
        assert_eq!(kind(&rpc(&mut a, "paycore.outputs.keep", bad.clone()).unwrap_err()), "invalid_params", "{bad}");
    }

    // the choice: exactly these outputs, all of them, or nothing
    let prepare = |w: &mut Wallet, extra: Value| {
        let mut params = json!({"amount": GRIN});
        params.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
        rpc(w, "paycore.send.prepare", params)
    };
    let refused = |w: &mut Wallet, extra: Value| prepare(w, extra).unwrap_err()["data"]["reason"].as_str().unwrap_or_default().to_string();
    assert_eq!(refused(&mut a, json!({"inputs": [five]})), "a chosen output is marked not to be spent");
    assert_eq!(refused(&mut a, json!({"inputs": []})), "no output is chosen");
    assert_eq!(refused(&mut a, json!({"inputs": [three, three]})), "an output is chosen twice");
    assert_eq!(refused(&mut a, json!({"inputs": [foreign]})), "a chosen output is not an unspent output of this wallet");
    assert_eq!(rpc(&mut a, "paycore.send.prepare", json!({"amount": 3 * GRIN, "inputs": [three]})).unwrap_err()["data"]["reason"], "the chosen outputs do not cover the amount and its fee");
    for bad in [json!({"inputs": "all"}), json!({"inputs": ["zz"]}), json!({"inputs": [three], "late": true}), json!({"inputs": [three], "not_a_repeat": true}), json!({"spend_kept": true}), json!({"inputs": [three], "spend_kept": 1})] {
        assert_eq!(kind(&prepare(&mut a, bad.clone()).unwrap_err()), "invalid_params", "{bad}");
    }
    assert_eq!(balance(&mut a), (s("3000000000"), s("0"), s("5000000000")), "nothing was reserved by a refusal");

    // paid with the chosen one, with a payment proof asked of the
    // recipient: the 3 is held, the marked 5 is not touched
    let to = rpc(&mut b, "paycore.address", json!({})).unwrap()["address"].clone();
    let p = prepare(&mut a, json!({"inputs": [three], "proof_to": to})).unwrap();
    assert_eq!(balance(&mut a), (s("0"), s("3000000000"), s("5000000000")));
    assert_eq!(refused(&mut a, json!({"inputs": [three]})), "a chosen output cannot be spent now");
    assert_eq!(list(&mut a)[1]["state"], "reserved");
    let s2 = rpc(&mut b, "paycore.receive.draft", json!({"slate": p["slate"]})).unwrap();
    let fin = rpc(&mut a, "paycore.send.finalize", json!({"op": p["op"], "slate": s2["slate"]})).unwrap();
    assert_eq!(fin["payment_proof"]["receiver_address"], to);
    chain.mine(&unhex(fin["tx"].as_str().unwrap()), &mut [&mut a, &mut b]);
    let after = list(&mut a);
    assert_eq!(after.len(), 2, "the marked coin and the change");
    assert_eq!((&after[0]["commit"], &after[0]["kept"]), (&five, &json!(true)));
    let change: u64 = after[1]["amount"].as_str().unwrap().parse().unwrap();
    assert!(change < 2 * GRIN && change > 2 * GRIN - GRIN / 10, "3 less 1 less the fee: {change}");

    // the marked one is spent only on the owner's separate word, for this payment
    let p = prepare(&mut a, json!({"inputs": [five], "spend_kept": true})).unwrap();
    assert_eq!(balance(&mut a).1, "5000000000");
    rpc(&mut a, "paycore.send.cancel", json!({"op": p["op"]})).unwrap();
    assert_eq!(balance(&mut a).2, "5000000000", "the mark stays when the payment is cancelled");
    // taken off, the coin is on offer again
    assert_eq!(rpc(&mut a, "paycore.outputs.keep", json!({"commit": five, "on": false})).unwrap(), json!({"kept": false}));
    assert_eq!(balance(&mut a).2, "0");
    let ok = rpc(&mut a, "paycore.send.prepare", json!({"amount": 4 * GRIN})).unwrap();
    rpc(&mut a, "paycore.send.cancel", json!({"op": ok["op"]})).unwrap();
    // a late lock chooses its inputs when it is signed: a mark set in
    // between is honoured then, and nothing is signed
    let late = rpc(&mut a, "paycore.send.prepare", json!({"amount": 4 * GRIN, "late": true})).unwrap();
    rpc(&mut a, "paycore.outputs.keep", json!({"commit": five, "on": true})).unwrap();
    let s2 = rpc(&mut b, "paycore.receive.draft", json!({"slate": late["slate"]})).unwrap();
    let signed = a.b.core().signatures_made();
    let e = rpc(&mut a, "paycore.send.finalize", json!({"op": late["op"], "slate": s2["slate"]})).unwrap_err();
    assert_eq!(kind(&e), "insufficient_funds");
    assert_eq!(a.b.core().signatures_made(), signed);
}

/// K199: the check code of two wallets is the same six words in both when
/// each has the other's message key and address right, and other words
/// when an address was swapped on the way; the owner's mark that it was
/// compared is written with the contact and goes when the address changes.
#[test]
fn two_wallets_show_one_check_code() {
    let (mut a, mut b, _chain) = pair();
    let mut c = wallet(3, true);
    let reason = |e: &Value| e["data"]["reason"].as_str().unwrap_or_default().to_string();
    let words = |w: &mut Wallet, key: &Value| -> Vec<String> { rpc(w, "paycore.contacts.code", json!({"key": key})).unwrap()["words"].as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect() };
    let checked = |w: &mut Wallet, key: &Value| rpc(w, "paycore.contacts.list", json!({})).unwrap()["contacts"].as_array().unwrap().iter().find(|x| x["key"] == *key).unwrap()["checked"].clone();
    let key_a = rpc(&mut a, "paycore.identity.create", json!({})).unwrap()["public"].clone();
    let key_b = rpc(&mut b, "paycore.identity.create", json!({})).unwrap()["public"].clone();
    let (addr_a, addr_b, addr_c) = (rpc(&mut a, "paycore.address", json!({})).unwrap()["address"].clone(), rpc(&mut b, "paycore.address", json!({})).unwrap()["address"].clone(), rpc(&mut c, "paycore.address", json!({})).unwrap()["address"].clone());

    // a contact without an address has nothing to check, and a stranger is not a contact
    rpc(&mut a, "paycore.contacts.set", json!({"key": key_b, "name": "B"})).unwrap();
    assert_eq!(reason(&rpc(&mut a, "paycore.contacts.code", json!({"key": key_b})).unwrap_err()), "the contact has no address to check");
    assert_eq!(reason(&rpc(&mut a, "paycore.contacts.check", json!({"key": key_b, "on": true})).unwrap_err()), "the contact has no address to check");
    assert_eq!(kind(&rpc(&mut a, "paycore.contacts.code", json!({"key": key_a})).unwrap_err()), "not_found");
    assert_eq!(kind(&rpc(&mut a, "paycore.contacts.check", json!({"key": key_a, "on": true})).unwrap_err()), "not_found");
    assert_eq!(kind(&rpc(&mut a, "paycore.contacts.check", json!({"key": key_b, "on": "yes"})).unwrap_err()), "invalid_params");
    // a wallet with no message key of its own has no side to the code
    rpc(&mut c, "paycore.contacts.set", json!({"key": key_b, "name": "B", "address": addr_b})).unwrap();
    assert_eq!(reason(&rpc(&mut c, "paycore.contacts.code", json!({"key": key_b})).unwrap_err()), "the wallet has no transport identity");
    assert_eq!(reason(&rpc(&mut c, "paycore.contacts.check", json!({"key": key_b, "on": true})).unwrap_err()), "the wallet has no transport identity");

    // each has the other right: the same six words, read only
    rpc(&mut a, "paycore.contacts.set", json!({"key": key_b, "name": "B", "address": addr_b})).unwrap();
    rpc(&mut b, "paycore.contacts.set", json!({"key": key_a, "name": "A", "address": addr_a})).unwrap();
    let ops = a._sim.ops();
    let (at_a, at_b) = (words(&mut a, &key_b), words(&mut b, &key_a));
    assert_eq!(a._sim.ops(), ops);
    assert_eq!(at_a, at_b);
    assert_eq!(at_a.len(), 6);
    assert!(at_a.iter().all(|w| (3..=8).contains(&w.len()) && w.chars().all(|ch| ch.is_ascii_lowercase())), "{at_a:?}");
    // an address swapped on the way: other words on the side that was fooled
    rpc(&mut a, "paycore.contacts.set", json!({"key": key_b, "name": "B", "address": addr_c})).unwrap();
    assert_ne!(words(&mut a, &key_b), at_b);
    rpc(&mut a, "paycore.contacts.set", json!({"key": key_b, "name": "B", "address": addr_b})).unwrap();
    // a message key swapped on the way, the address right: other words too
    let key_c = rpc(&mut c, "paycore.identity.create", json!({})).unwrap()["public"].clone();
    rpc(&mut a, "paycore.contacts.set", json!({"key": key_c, "name": "not B", "address": addr_b})).unwrap();
    assert_ne!(words(&mut a, &key_c), at_b);

    // the mark: written once, kept through a new name, gone with a new address
    assert_eq!(checked(&mut a, &key_b), false);
    assert_eq!(rpc(&mut a, "paycore.contacts.check", json!({"key": key_b, "on": true})).unwrap(), json!({"checked": true}));
    let ops = a._sim.ops();
    rpc(&mut a, "paycore.contacts.check", json!({"key": key_b, "on": true})).unwrap();
    assert_eq!(a._sim.ops(), ops, "marked already: nothing is written");
    rpc(&mut a, "paycore.contacts.set", json!({"key": key_b, "name": "Bee", "address": addr_b})).unwrap();
    assert_eq!(checked(&mut a, &key_b), true);
    rpc(&mut a, "paycore.contacts.set", json!({"key": key_b, "name": "Bee", "address": addr_c})).unwrap();
    assert_eq!(checked(&mut a, &key_b), false, "another address was not compared");
    rpc(&mut a, "paycore.contacts.set", json!({"key": key_b, "name": "Bee", "address": addr_b})).unwrap();
    assert_eq!(checked(&mut a, &key_b), false, "and coming back does not bring the mark back");
    rpc(&mut a, "paycore.contacts.check", json!({"key": key_b, "on": true})).unwrap();
    assert_eq!(rpc(&mut a, "paycore.contacts.check", json!({"key": key_b, "on": false})).unwrap(), json!({"checked": false}));
    assert_eq!(checked(&mut a, &key_b), false);
}

/// K200: the sender's text of an incoming payment is kept with the
/// payment's record and given again as it came; of a payment that was
/// given up it is not kept.
#[test]
fn the_senders_text_is_kept_until_the_payment_is_given_up() {
    let (mut a, mut b, _chain) = pair();
    let p = rpc(&mut a, "paycore.send.prepare", json!({"amount": GRIN})).unwrap();
    rpc(&mut b, "paycore.receive.draft", json!({"slate": p["slate"]})).unwrap();
    let id = rpc(&mut b, "paycore.slate.read", json!({"slate": p["slate"]})).unwrap()["slate_id"].clone();
    let kept = |w: &mut Wallet| rpc(w, "paycore.history", json!({})).unwrap()["incoming"][0]["request_kept"].clone();
    assert_eq!(kept(&mut b), true);
    assert_eq!(rpc(&mut b, "paycore.receive.request", json!({"slate_id": id})).unwrap()["slate"], p["slate"]);
    rpc(&mut b, "paycore.receive.abandon", json!({"slate_id": id})).unwrap();
    assert_eq!(kind(&rpc(&mut b, "paycore.receive.request", json!({"slate_id": id})).unwrap_err()), "not_found");
    assert_eq!(kept(&mut b), false);
    // an invoice of the wallet's own has no sender and no sender's text
    let inv = rpc(&mut b, "paycore.invoice.issue", json!({"amount": GRIN})).unwrap();
    assert_eq!(kind(&rpc(&mut b, "paycore.receive.request", json!({"slate_id": inv["slate_id"]})).unwrap_err()), "not_found");
}

/// K196: the owner collects outputs into one: the wallet pays itself
/// everything they hold less the fee - one output comes back, the history
/// has the payment and its arrival under one number, and what failed on
/// the way lets go of the outputs.
#[test]
fn outputs_are_collected_into_one() {
    let (mut a, _b, mut chain) = pair();
    let list = |w: &mut Wallet| rpc(w, "paycore.outputs.list", json!({})).unwrap()["outputs"].as_array().unwrap().clone();
    let balance = |w: &mut Wallet| {
        let b = rpc(w, "paycore.balance", json!({})).unwrap();
        (b["spendable"].as_str().unwrap().to_string(), b["reserved"].as_str().unwrap().to_string())
    };
    let reason = |e: &Value| e["data"]["reason"].as_str().unwrap_or_default().to_string();
    let outs = list(&mut a);
    let (five, three) = (outs[0]["commit"].clone(), outs[1]["commit"].clone());

    // what is not a request, and what there is nothing to collect from
    for bad in [json!({"spend_kept": true}), json!({"inputs": "all"}), json!({"inputs": ["zz"]})] {
        assert_eq!(kind(&rpc(&mut a, "paycore.outputs.collect", bad.clone()).unwrap_err()), "invalid_params", "{bad}");
    }
    assert_eq!(reason(&rpc(&mut a, "paycore.outputs.collect", json!({"inputs": [five]})).unwrap_err()), "there are not two outputs to collect");
    // a marked output is not taken by the wallet's own choice, and a named one needs the owner's word
    rpc(&mut a, "paycore.outputs.keep", json!({"commit": five, "on": true})).unwrap();
    assert_eq!(reason(&rpc(&mut a, "paycore.outputs.collect", json!({})).unwrap_err()), "there are not two outputs to collect");
    assert_eq!(reason(&rpc(&mut a, "paycore.outputs.collect", json!({"inputs": [five, three]})).unwrap_err()), "a chosen output is marked not to be spent");
    let before = a._sim.ops();
    assert_eq!(balance(&mut a), ("3000000000".to_string(), "0".to_string()));
    assert_eq!(a._sim.ops(), before, "a refusal wrote nothing");
    rpc(&mut a, "paycore.outputs.keep", json!({"commit": five, "on": false})).unwrap();

    // the wallet's own choice: everything it could spend
    let fee = grin_core::libtx::tx_fee(2, 1, 1);
    // asked first what it would come to: an answer, and nothing else
    let before = a._sim.ops();
    let plan = rpc(&mut a, "paycore.outputs.collect", json!({"plan": true})).unwrap();
    assert_eq!(plan, json!({"amount": (8 * GRIN - fee).to_string(), "fee": fee.to_string(), "inputs": 2}));
    assert_eq!((a._sim.ops(), balance(&mut a)), (before, ("8000000000".to_string(), "0".to_string())));
    let done = rpc(&mut a, "paycore.outputs.collect", json!({})).unwrap();
    assert_eq!((done["amount"].as_str().unwrap(), done["fee"].as_str().unwrap(), done["inputs"].as_u64()), ((8 * GRIN - fee).to_string().as_str(), fee.to_string().as_str(), Some(2)));
    assert_eq!(balance(&mut a), ("0".to_string(), "8000000000".to_string()), "held by the payment until it is in a block");
    chain.mine(&unhex(done["tx"].as_str().unwrap()), &mut [&mut a]);
    let outs = list(&mut a);
    assert_eq!(outs.len(), 1);
    assert_eq!(outs[0]["amount"], (8 * GRIN - fee).to_string());
    // one number for the payment and for its arrival
    let h = rpc(&mut a, "paycore.history", json!({})).unwrap();
    let sent = h["sends"].as_array().unwrap().iter().find(|s| s["op"] == done["op"]).unwrap().clone();
    assert!(sent["slate_id"].is_string());
    let came: Vec<&Value> = h["incoming"].as_array().unwrap().iter().filter(|r| r["slate_id"] == sent["slate_id"]).collect();
    assert_eq!(came.len(), 1, "{h}");
    // one output is not collected
    assert_eq!(reason(&rpc(&mut a, "paycore.outputs.collect", json!({})).unwrap_err()), "there are not two outputs to collect");
}

/// K196: on the owner's standing word a payment takes the wallet's small
/// outputs along and they come back inside its change - the amount paid
/// is the same, and what is marked, what would not pay for itself and
/// what the owner chose by hand is not touched.
#[test]
fn small_outputs_travel_with_a_payment() {
    let fresh = || {
        let mut a = wallet(1, true);
        let mut b = wallet(2, true);
        let mut chain = Chain { height: 0, pos: 0 };
        chain.fund(1, &[5 * GRIN, 3 * GRIN, GRIN / 5, GRIN / 10, 1000], &mut [&mut a, &mut b]);
        chain.empty(1, &mut [&mut a, &mut b]);
        (a, b, chain)
    };
    let held = |w: &mut Wallet| -> Vec<String> {
        let outs = rpc(w, "paycore.outputs.list", json!({})).unwrap()["outputs"].as_array().unwrap().clone();
        outs.iter().filter(|o| o["state"] != "spendable").map(|o| o["amount"].as_str().unwrap().to_string()).collect()
    };
    let s = |v: u64| v.to_string();
    let fee = |inputs: usize, outputs: usize| grin_core::libtx::tx_fee(inputs, outputs, 1);

    // not asked: the payment takes what it needs
    let (mut a, mut b, mut chain) = fresh();
    for bad in [json!({}), json!({"on": 1}), json!({"on": "yes"})] {
        assert_eq!(kind(&rpc(&mut a, "paycore.settings.gather", bad.clone()).unwrap_err()), "invalid_params", "{bad}");
    }
    let p = rpc(&mut a, "paycore.send.prepare", json!({"amount": GRIN})).unwrap();
    assert_eq!(held(&mut a), [s(5 * GRIN)]);
    rpc(&mut a, "paycore.send.cancel", json!({"op": p["op"]})).unwrap();

    // asked: the small ones go along, the dust and the marked one stay
    let ops = a._sim.ops();
    assert_eq!(rpc(&mut a, "paycore.settings.gather", json!({"on": true})).unwrap(), json!({"gather": true}));
    assert_eq!(a._sim.ops(), ops, "the word is kept in memory");
    assert_eq!(rpc(&mut a, "paycore.history", json!({})).unwrap()["gather"], true);
    assert_eq!(rpc(&mut b, "paycore.history", json!({})).unwrap()["gather"], false);
    let outs = rpc(&mut a, "paycore.outputs.list", json!({})).unwrap()["outputs"].as_array().unwrap().clone();
    let fifth = outs.iter().find(|o| o["amount"] == s(GRIN / 5)).unwrap()["commit"].clone();
    rpc(&mut a, "paycore.outputs.keep", json!({"commit": fifth, "on": true})).unwrap();
    let p = rpc(&mut a, "paycore.send.prepare", json!({"amount": GRIN})).unwrap();
    assert_eq!(held(&mut a), [s(5 * GRIN), s(3 * GRIN), s(GRIN / 10)]);
    let s2 = rpc(&mut b, "paycore.receive.draft", json!({"slate": p["slate"]})).unwrap();
    let fin = rpc(&mut a, "paycore.send.finalize", json!({"op": p["op"], "slate": s2["slate"]})).unwrap();
    chain.mine(&unhex(fin["tx"].as_str().unwrap()), &mut [&mut a, &mut b]);
    assert_eq!(rpc(&mut b, "paycore.balance", json!({})).unwrap()["spendable"], s(GRIN), "the amount paid is the amount asked");
    let outs = rpc(&mut a, "paycore.outputs.list", json!({})).unwrap()["outputs"].as_array().unwrap().clone();
    let now: Vec<&str> = outs.iter().map(|o| o["amount"].as_str().unwrap()).collect();
    let change = 5 * GRIN + 3 * GRIN + GRIN / 10 - GRIN - fee(3, 2);
    assert_eq!(now, [s(change).as_str(), s(GRIN / 5).as_str(), "1000"]);

    // the owner's own choice is the whole choice
    let (mut a, _b, _chain) = fresh();
    rpc(&mut a, "paycore.settings.gather", json!({"on": true})).unwrap();
    let outs = rpc(&mut a, "paycore.outputs.list", json!({})).unwrap()["outputs"].as_array().unwrap().clone();
    rpc(&mut a, "paycore.send.prepare", json!({"amount": GRIN, "inputs": [outs[0]["commit"]]})).unwrap();
    assert_eq!(held(&mut a), [s(5 * GRIN)]);

    // a payment that has no change has nowhere to bring them
    let (mut a, _b, _chain) = fresh();
    rpc(&mut a, "paycore.settings.gather", json!({"on": true})).unwrap();
    rpc(&mut a, "paycore.send.prepare", json!({"amount": 5 * GRIN - fee(1, 1)})).unwrap();
    assert_eq!(held(&mut a), [s(5 * GRIN)]);

    // collecting passes the dust by as well: it would cost more than it holds
    let (mut a, _b, mut chain) = fresh();
    let done = rpc(&mut a, "paycore.outputs.collect", json!({})).unwrap();
    assert_eq!(done["inputs"], 4);
    chain.mine(&unhex(done["tx"].as_str().unwrap()), &mut [&mut a]);
    let outs = rpc(&mut a, "paycore.outputs.list", json!({})).unwrap()["outputs"].as_array().unwrap().clone();
    let now: Vec<&str> = outs.iter().map(|o| o["amount"].as_str().unwrap()).collect();
    assert_eq!(now, [s(5 * GRIN + 3 * GRIN + GRIN / 5 + GRIN / 10 - fee(4, 1)).as_str(), "1000"]);

    // no more than eight go along, the smallest ones
    let mut a = wallet(1, true);
    let mut chain = Chain { height: 0, pos: 0 };
    let mut values = vec![5 * GRIN];
    values.extend((1..=10u64).map(|n| GRIN / 100 * n));
    chain.fund(1, &values, &mut [&mut a]);
    chain.empty(1, &mut [&mut a]);
    rpc(&mut a, "paycore.settings.gather", json!({"on": true})).unwrap();
    rpc(&mut a, "paycore.send.prepare", json!({"amount": GRIN})).unwrap();
    let mut expect = vec![s(5 * GRIN)];
    expect.extend((1..=8u64).rev().map(|n| s(GRIN / 100 * n)));
    assert_eq!(held(&mut a), expect);

    // and the word taken back
    let (mut a, _b, _chain) = fresh();
    rpc(&mut a, "paycore.settings.gather", json!({"on": true})).unwrap();
    assert_eq!(rpc(&mut a, "paycore.settings.gather", json!({"on": false})).unwrap(), json!({"gather": false}));
    rpc(&mut a, "paycore.send.prepare", json!({"amount": GRIN})).unwrap();
    assert_eq!(held(&mut a), [s(5 * GRIN)]);
}

/// K197: the owner takes back a signed payment that is in no block: the
/// wallet pays itself with the same inputs, stops handing the first one
/// to the network, and whichever of the two reaches a block, the other
/// dies and the money is counted once.
#[test]
fn a_signed_payment_is_taken_back() {
    let reason = |e: &Value| e["data"]["reason"].as_str().unwrap_or_default().to_string();
    let start = || {
        let (mut a, mut b, chain) = pair();
        let p = rpc(&mut a, "paycore.send.prepare", json!({"amount": 2 * GRIN})).unwrap();
        let s2 = rpc(&mut b, "paycore.receive.draft", json!({"slate": p["slate"]})).unwrap();
        let fin = rpc(&mut a, "paycore.send.finalize", json!({"op": p["op"], "slate": s2["slate"]})).unwrap();
        (a, b, chain, p["op"].clone(), unhex(fin["tx"].as_str().unwrap()))
    };
    let row = |w: &mut Wallet, op: &Value| rpc(w, "paycore.history", json!({})).unwrap()["sends"].as_array().unwrap().iter().find(|s| s["op"] == *op).unwrap().clone();
    let spendable = |w: &mut Wallet| rpc(w, "paycore.balance", json!({})).unwrap()["spendable"].as_str().unwrap().to_string();
    let fee = grin_core::libtx::tx_fee(1, 1, 1);

    let (mut a, mut b, mut chain, first, tx1) = start();
    // what cannot be taken back
    assert_eq!(kind(&rpc(&mut a, "paycore.send.take_back", json!({"op": "00".repeat(16)})).unwrap_err()), "not_found");
    assert_eq!(kind(&rpc(&mut a, "paycore.send.take_back", json!({})).unwrap_err()), "invalid_params");
    let unsigned = rpc(&mut a, "paycore.send.prepare", json!({"amount": GRIN})).unwrap();
    assert_eq!(reason(&rpc(&mut a, "paycore.send.take_back", json!({"op": unsigned["op"]})).unwrap_err()), "only a signed payment that is in no block can be taken back");
    rpc(&mut a, "paycore.send.cancel", json!({"op": unsigned["op"]})).unwrap();
    // asked first what it comes to: an answer and nothing else
    let before = a._sim.ops();
    let plan = rpc(&mut a, "paycore.send.take_back", json!({"op": first, "plan": true})).unwrap();
    assert_eq!(plan, json!({"amount": (5 * GRIN - fee).to_string(), "fee": fee.to_string(), "inputs": 1}));
    assert_eq!(a._sim.ops(), before);
    assert_eq!(row(&mut a, &first)["replaced_by"], Value::Null);

    // the first payment was handed to the network once
    let tip = Rc::new(RefCell::new(true));
    a.b.set_chain_feed(Box::new(Quiet(tip.clone())));
    rpc(&mut a, "paycore.chain.sync", json!({})).unwrap();
    a.b.set_broadcast_every(std::time::Duration::ZERO);
    rpc(&mut a, "paycore.send.pump", json!({})).unwrap();
    assert_eq!(*a.posted.borrow(), vec![tx1.clone()]);

    // taken back: a payment to itself with the same input, signed
    let back = rpc(&mut a, "paycore.send.take_back", json!({"op": first})).unwrap();
    let tx2 = unhex(back["tx"].as_str().unwrap());
    assert_eq!((back["amount"].as_str().unwrap(), back["inputs"].as_u64()), ((5 * GRIN - fee).to_string().as_str(), Some(1)));
    let (old, new) = (row(&mut a, &first), row(&mut a, &back["op"]));
    assert_eq!((old["replaced_by"].clone(), new["replaces"].clone(), old["state"].as_str(), new["state"].as_str()), (back["op"].clone(), first.clone(), Some("finalized"), Some("finalized")));
    assert_eq!(spendable(&mut a), "3000000000", "the input is held once, the other output is free");
    // not twice, and the first is not sent again - by hand or by itself
    assert_eq!(reason(&rpc(&mut a, "paycore.send.take_back", json!({"op": first})).unwrap_err()), "this payment is being taken back already");
    assert_eq!(reason(&rpc(&mut a, "paycore.send.broadcast", json!({"op": first})).unwrap_err()), "this payment is being taken back");
    a.posted.borrow_mut().clear();
    for _ in 0..4 {
        rpc(&mut a, "paycore.send.pump", json!({})).unwrap();
    }
    assert_eq!(*a.posted.borrow(), vec![tx2.clone(); 4]);

    // the taking back is in a block: the money is the owner's again, the
    // first payment is contested and then dead, and asks nothing of the owner
    chain.mine(&tx2, &mut [&mut a, &mut b]);
    assert_eq!((row(&mut a, &back["op"])["state"].as_str(), row(&mut a, &first)["state"].as_str()), (Some("confirmed"), Some("contested")));
    assert_eq!(spendable(&mut a), (8 * GRIN - fee).to_string());
    let next = rpc(&mut a, "paycore.send.prepare", json!({"amount": GRIN})).unwrap();
    rpc(&mut a, "paycore.send.cancel", json!({"op": next["op"]})).unwrap();
    a.posted.borrow_mut().clear();
    rpc(&mut a, "paycore.send.pump", json!({})).unwrap();
    assert!(a.posted.borrow().is_empty());
    assert_eq!(rpc(&mut b, "paycore.balance", json!({})).unwrap()["spendable"], "0");

    // the other way: the first payment reaches a block all the same
    let (mut a, mut b, mut chain, first, tx1) = start();
    let back = rpc(&mut a, "paycore.send.take_back", json!({"op": first})).unwrap();
    chain.mine(&tx1, &mut [&mut a, &mut b]);
    assert_eq!((row(&mut a, &first)["state"].as_str(), row(&mut a, &back["op"])["state"].as_str()), (Some("confirmed"), Some("contested")));
    assert_eq!(rpc(&mut b, "paycore.balance", json!({})).unwrap()["spendable"], (2 * GRIN).to_string());
    let paid = 2 * GRIN + grin_core::libtx::tx_fee(1, 2, 1);
    assert_eq!(spendable(&mut a), (8 * GRIN - paid).to_string(), "what was paid is gone once, and nothing is counted twice");

    // a taking back that was not signed is let go, and the first payment goes on
    let (mut a, _b, _chain, first, tx1) = start();
    let tip = Rc::new(RefCell::new(true));
    a.b.set_chain_feed(Box::new(Quiet(tip)));
    rpc(&mut a, "paycore.chain.sync", json!({})).unwrap();
    a.b.set_broadcast_every(std::time::Duration::ZERO);
    let (prepared, ..) = a.b.core_mut().take_back_prepare(&<[u8; 16]>::try_from(unhex(first.as_str().unwrap())).unwrap()).unwrap();
    rpc(&mut a, "paycore.send.pump", json!({})).unwrap();
    assert!(a.posted.borrow().is_empty(), "held back while the taking back is under way");
    a.b.core_mut().send_cancel(&prepared.op).unwrap();
    rpc(&mut a, "paycore.send.pump", json!({})).unwrap();
    assert_eq!(*a.posted.borrow(), vec![tx1]);
    assert_eq!(row(&mut a, &first)["replaced_by"], Value::Null);
}

/// K196: whatever fails while outputs are being collected, they are not
/// left held by something the owner cannot see: either nothing holds them,
/// or the history has the payment, to be finished or cancelled like any
/// other once the wallet is opened again.
#[test]
fn a_failed_collecting_is_an_ordinary_payment() {
    let (mut held, mut free) = (0, 0);
    for n in 1..200u64 {
        let (mut a, _b, _chain) = pair();
        a._sim.set_fault(Some(Fault::Fail(a._sim.ops() + n)));
        let out = rpc(&mut a, "paycore.outputs.collect", json!({}));
        a._sim.set_fault(None);
        if out.is_ok() {
            assert!(n > 1, "no failure was tried");
            break;
        }
        assert_eq!(kind(&out.unwrap_err()), "storage");
        let b = rpc(&mut a, "paycore.balance", json!({})).unwrap();
        let h = rpc(&mut a, "paycore.history", json!({})).unwrap();
        let sends = h["sends"].as_array().unwrap();
        if b["reserved"] == "0" {
            assert!(sends.is_empty(), "{n}");
            free += 1;
        } else {
            assert_eq!(b["reserved"], "8000000000");
            assert_eq!(sends.len(), 1, "{n}");
            assert!(sends[0]["state"] != "cancelled", "{n}");
            held += 1;
        }
    }
    assert!(held > 0 && free > 0);
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

    // K198: the handler says the owner's agreement to the direct way with
    // the payment it was given for, every time, and with no other
    rpc(&mut a, "paycore.send.broadcast", json!({"op": op2, "direct": true})).unwrap();
    a.posted.borrow_mut().clear();
    for _ in 0..4 {
        pump(&mut a);
    }
    let direct2 = [b"direct:".as_slice(), &tx2].concat();
    assert_eq!(*a.posted.borrow(), vec![tx1.clone(), direct2.clone(), tx1.clone(), direct2.clone()]);
    let tx2 = direct2;

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
