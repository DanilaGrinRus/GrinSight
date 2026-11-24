//! The bridge following a chain layer: the wallet says where it stands,
//! the layer says what comes next.
use fly_paycore_bridge::chain_port::{BlockFacts, ChainFeed, OldOutputs, OutputFact, Step, Tip, Unknown};
use fly_paycore_bridge::ports::{Broadcaster, ChainView, Clock, JsonCodec, Ports};
use fly_paycore_bridge::{Bridge, MAX_CHAIN_STEPS, MAX_OLD_PIECES};
use fly_paycore_keys::path::KeyPath;
use fly_paycore_store::sim::{Sim, SimDir, SimGuard};
use fly_paycore_store::{Identity, RootKey};
use fly_paycore_wallet::{Broadcast, ChainState, Core};
use grin_core::global::{self, ChainTypes};
use grin_core::libtx::proof::{self, ProofBuilder};
use grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

const GRIN: u64 = 1_000_000_000;

struct Net;
impl Broadcaster for Net {
    fn post_tx(&mut self, _tx: &[u8]) -> Broadcast {
        Broadcast::Unknown
    }
}
impl Clock for Net {
    fn confirmed_time(&self) -> Option<u64> {
        Some(1_000)
    }
}
impl ChainView for Net {
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

/// A chain in memory: a starting block and what follows it.
#[derive(Default)]
struct Mem {
    anchor: Option<Tip>,
    blocks: Vec<BlockFacts>,
    dark: bool,
    asked: Vec<Option<(u64, u8)>>,
    /// Handed over as it is, whatever the wallet's position.
    forced: Option<Step>,
    /// The old outputs that are unspent, four positions to a piece.
    old: Vec<OutputFact>,
    old_pieces: u64,
    old_dark: bool,
    /// Blocks of the chain from before the starting block.
    known: Vec<Tip>,
    /// Pieces from this one on are not there yet.
    old_coming: Option<u64>,
    old_asked: Vec<u64>,
    /// Change a piece on its way out.
    old_bend: Option<fn(&mut OldOutputs)>,
    /// Asked by a wallet that names a block of this chain, pieces below
    /// this one come without range proofs.
    old_bare_below: u64,
    /// Requests that named a block: piece, height and first byte of the hash.
    old_since: Vec<(u64, u64, u8)>,
}
impl Mem {
    fn tip(&self) -> Tip {
        self.blocks.last().map(|b| Tip { height: b.height, hash: b.hash }).unwrap_or(self.anchor.unwrap())
    }
    fn push(&mut self, fill: u8, outputs: Vec<OutputFact>) {
        let height = self.tip().height + 1;
        self.blocks.push(BlockFacts { height, hash: [fill; 32], outputs, ..BlockFacts::default() });
    }
    fn hash_at(&self, height: u64) -> Option<[u8; 32]> {
        let anchor = self.anchor?;
        if height == anchor.height {
            return Some(anchor.hash);
        }
        self.blocks.iter().find(|b| b.height == height).map(|b| b.hash)
    }
}
struct Shared(Rc<RefCell<Mem>>);
impl ChainFeed for Shared {
    fn status(&mut self) -> Option<fly_paycore_bridge::chain_port::Status> {
        None
    }
    fn next(&mut self, at: Option<Tip>) -> Result<Step, Unknown> {
        let mut m = self.0.borrow_mut();
        m.asked.push(at.map(|t| (t.height, t.hash[0])));
        if let Some(step) = m.forced.take() {
            return Ok(step);
        }
        if m.dark {
            return Err(Unknown);
        }
        let anchor = m.anchor.ok_or(Unknown)?;
        let Some(at) = at else { return Ok(Step::Reanchor(anchor)) };
        match m.hash_at(at.height) {
            Some(hash) if hash == at.hash => match m.blocks.iter().find(|b| b.height == at.height + 1) {
                Some(b) => Ok(Step::Block(Box::new(b.clone()))),
                None => Ok(Step::Nothing),
            },
            _ if at.height > anchor.height => Ok(Step::Rollback { to: at.height - 1 }),
            _ if at.height < anchor.height && m.known.contains(&at) => Ok(Step::ReanchorExtending(anchor)),
            _ => Ok(Step::Reanchor(anchor)),
        }
    }
    fn post(&mut self, _tx: &[u8]) -> fly_paycore_bridge::chain_port::Posted {
        fly_paycore_bridge::chain_port::Posted::Unknown
    }
    fn old_outputs(&mut self, piece: u64) -> Result<OldOutputs, Unknown> {
        let mut m = self.0.borrow_mut();
        m.old_asked.push(piece);
        if m.old_dark || piece >= m.old_pieces || m.old_coming.is_some_and(|from| piece >= from) {
            return Err(Unknown);
        }
        let mut old = OldOutputs {
            outputs: m.old.iter().filter(|o| o.pos / 4 == piece).cloned().collect(),
            at: m.tip(),
            before: m.anchor.ok_or(Unknown)?.height,
            next: Some(piece + 1).filter(|next| *next < m.old_pieces),
            pieces: m.old_pieces,
            bare: false,
        };
        if let Some(bend) = m.old_bend {
            bend(&mut old);
        }
        Ok(old)
    }
    fn old_outputs_since(&mut self, piece: u64, since: Tip) -> Result<OldOutputs, Unknown> {
        self.0.borrow_mut().old_since.push((piece, since.height, since.hash[0]));
        let bend = self.0.borrow_mut().old_bend.take();
        let old = self.old_outputs(piece);
        let mut m = self.0.borrow_mut();
        m.old_bend = bend;
        let mut old = old?;
        // only a block the layer can vouch for; here: one it was told of
        if piece < m.old_bare_below && m.known.contains(&since) {
            old.outputs.iter_mut().for_each(|o| o.proof.clear());
            old.bare = true;
        }
        if let Some(bend) = m.old_bend {
            bend(&mut old);
        }
        Ok(old)
    }
}

struct Wallet {
    b: Bridge<SimDir, SimGuard, ExtKeychain>,
    sim: Sim,
    chain: Rc<RefCell<Mem>>,
}
fn kc() -> ExtKeychain {
    ExtKeychain::from_seed(&[1; 32], true).unwrap()
}
fn wallet(with_feed: bool) -> Wallet {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    let sim = Sim::new();
    let id = Identity { network: 2, genesis: [7; 32], instance: [1; 16] };
    let core = Core::create(sim.dir(), sim.guard(), &RootKey::new([0x42; 32]), id, kc(), 0, 3).unwrap();
    let ports = Ports {
        broadcaster: Box::new(Net),
        clock: Box::new(Net),
        chain: Box::new(Net),
        codec: Box::new(JsonCodec),
        mailbox: None,
    };
    let chain = Rc::new(RefCell::new(Mem::default()));
    let mut b = Bridge::new(core, ports);
    if with_feed {
        b.set_chain_feed(Box::new(Shared(chain.clone())));
    }
    Wallet { b, sim, chain }
}
/// An output of the wallet, as a block carries it.
fn coin(amount: u64, index: u32) -> OutputFact {
    let k = kc();
    let key = KeyPath::Legacy { account: 0, index }.to_identifier();
    let commit = k.commit(amount, &key, SwitchCommitmentType::Regular).unwrap();
    let rp = proof::create(&k, &ProofBuilder::new(&k), amount, &key, SwitchCommitmentType::Regular, commit, None).unwrap();
    OutputFact { commit: commit.0, proof: rp.proof[..rp.plen].to_vec(), pos: u64::from(index) + 1, coinbase: false }
}
/// An output of somebody else.
fn foreign(amount: u64, pos: u64) -> OutputFact {
    let k = ExtKeychain::from_seed(&[2; 32], true).unwrap();
    let key = KeyPath::Legacy { account: 0, index: 1 }.to_identifier();
    let commit = k.commit(amount, &key, SwitchCommitmentType::Regular).unwrap();
    let rp = proof::create(&k, &ProofBuilder::new(&k), amount, &key, SwitchCommitmentType::Regular, commit, None).unwrap();
    OutputFact { commit: commit.0, proof: rp.proof[..rp.plen].to_vec(), pos, coinbase: false }
}
fn rpc(w: &mut Wallet, method: &str, params: Value) -> Result<Value, Value> {
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let v: Value = serde_json::from_str(&w.b.call(&req.to_string())).unwrap();
    match v.get("result") {
        Some(r) => Ok(r.clone()),
        None => Err(v["error"].clone()),
    }
}
fn sync(w: &mut Wallet) -> Value {
    rpc(w, "paycore.chain.sync", json!({})).unwrap()
}
fn spendable(w: &mut Wallet) -> u64 {
    rpc(w, "paycore.balance", json!({})).unwrap()["spendable"].as_str().unwrap().parse().unwrap()
}
/// Whether the balance says it may not be all the seed holds.
fn incomplete(w: &mut Wallet) -> Value {
    rpc(w, "paycore.balance", json!({})).unwrap()["incomplete"].clone()
}

#[test]
fn the_wallet_follows_the_chain_layer() {
    // without a chain layer the method says so
    let mut none = wallet(false);
    assert_eq!(rpc(&mut none, "paycore.chain.sync", json!({})).unwrap_err()["data"]["kind"], "no_chain");

    let mut w = wallet(true);
    assert_eq!(
        rpc(&mut w, "paycore.chain.status", json!({})).unwrap(),
        json!({"state": "at_tip", "k_conf": 3, "rangeproofs_authenticated": true, "selected_height": null,
               "confirmed_time": 1000, "tip_height": null})
    );
    // a chain layer that knows nothing yet
    let r = sync(&mut w);
    assert_eq!(r, json!({"chain": [], "tip_height": null, "more": false, "unknown": true}));

    {
        let mut m = w.chain.borrow_mut();
        m.anchor = Some(Tip { height: 100, hash: [1; 32] });
        m.push(11, vec![coin(5 * GRIN, 0)]);
        m.push(12, vec![]);
        m.push(13, vec![]);
    }
    // a wallet without a position gets a starting point, then the blocks
    let r = sync(&mut w);
    assert_eq!(r["chain"], json!([{"applied": 3, "rolled_back": 0, "reanchored": true, "tip_height": 103}]));
    assert_eq!((&r["tip_height"], &r["more"], &r["unknown"]), (&json!(103), &json!(false), &json!(false)));
    assert_eq!(w.chain.borrow().asked[1..], [None, Some((100, 1)), Some((101, 11)), Some((102, 12)), Some((103, 13))]);
    assert_eq!(spendable(&mut w), 5 * GRIN, "the wallet found its own output in the block");
    // at the tip: nothing is said and nothing is written
    let ops = w.sim.ops();
    let r = sync(&mut w);
    assert_eq!(r, json!({"chain": [], "tip_height": 103, "more": false, "unknown": false}));
    assert_eq!(w.sim.ops(), ops);

    // a long way to catch up is taken in bounded pieces
    for i in 0..100u8 {
        w.chain.borrow_mut().push(100 + i, vec![]);
    }
    let r = sync(&mut w);
    assert_eq!((&r["chain"][0]["applied"], &r["more"]), (&json!(MAX_CHAIN_STEPS), &json!(true)));
    let r = sync(&mut w);
    assert_eq!((&r["chain"][0]["applied"], &r["more"], &r["tip_height"]), (&json!(100 - MAX_CHAIN_STEPS), &json!(false), &json!(203)));

    // a second output arrives, then the chain reorganises it away
    w.chain.borrow_mut().push(50, vec![coin(3 * GRIN, 1)]);
    w.chain.borrow_mut().push(51, vec![]);
    sync(&mut w);
    assert_eq!(spendable(&mut w), 8 * GRIN);
    {
        let mut m = w.chain.borrow_mut();
        let keep = m.blocks.len() - 2;
        m.blocks.truncate(keep);
        m.push(60, vec![]);
        m.push(61, vec![]);
        m.push(62, vec![]);
    }
    let r = sync(&mut w);
    assert_eq!(r["chain"], json!([{"applied": 3, "rolled_back": 2, "reanchored": false, "tip_height": 206}]));
    assert_eq!(spendable(&mut w), 5 * GRIN, "the output of the abandoned branch is gone");
    assert_eq!(w.b.core().tip(), Some((206, [62; 32])));

    // the chain layer loses sight of the chain: "unknown", and nothing moves
    w.chain.borrow_mut().dark = true;
    let ops = w.sim.ops();
    let r = sync(&mut w);
    assert_eq!(r, json!({"chain": [], "tip_height": 206, "more": false, "unknown": true}));
    assert_eq!(w.sim.ops(), ops);
    assert_eq!(spendable(&mut w), 5 * GRIN);
    w.chain.borrow_mut().dark = false;

    // the wallet's position survives a restart: it is in the journal
    let asked = w.chain.borrow().asked.len();
    sync(&mut w);
    assert_eq!(w.chain.borrow().asked[asked], Some((206, 62)));
}

/// The core does not take the chain layer's word for where a block goes:
/// a block that does not sit right above the wallet's position, or one
/// with a broken range proof, changes nothing.
#[test]
fn a_step_that_does_not_fit_is_refused() {
    let mut w = wallet(true);
    {
        let mut m = w.chain.borrow_mut();
        m.anchor = Some(Tip { height: 100, hash: [1; 32] });
        m.push(11, vec![coin(5 * GRIN, 0)]);
    }
    sync(&mut w);
    assert_eq!(spendable(&mut w), 5 * GRIN);
    let before = (w.b.core().tip(), w.sim.ops());
    let cases = [
        ("a block two above", Step::Block(Box::new(BlockFacts { height: 103, hash: [9; 32], ..BlockFacts::default() }))),
        ("the same height again", Step::Block(Box::new(BlockFacts { height: 101, hash: [9; 32], ..BlockFacts::default() }))),
        (
            "an output without a range proof",
            Step::Block(Box::new(BlockFacts {
                height: 102,
                hash: [9; 32],
                outputs: vec![OutputFact { commit: [2; 33], proof: vec![], pos: 9, coinbase: false }],
                ..BlockFacts::default()
            })),
        ),
        (
            "a range proof longer than any",
            Step::Block(Box::new(BlockFacts {
                height: 102,
                hash: [9; 32],
                outputs: vec![OutputFact { commit: [2; 33], proof: vec![1; 6000], pos: 9, coinbase: false }],
                ..BlockFacts::default()
            })),
        ),
        ("a step back that goes forward", Step::Rollback { to: 500 }),
    ];
    for (what, step) in cases {
        w.chain.borrow_mut().forced = Some(step);
        let e = rpc(&mut w, "paycore.chain.sync", json!({})).unwrap_err();
        assert_eq!(e["data"]["kind"], "refused", "{what}: {e}");
        assert_eq!((w.b.core().tip(), w.sim.ops()), before, "{what}: something changed");
    }
    assert_eq!(spendable(&mut w), 5 * GRIN);
    // and the wallet goes on from where it stood
    w.chain.borrow_mut().push(12, vec![]);
    assert_eq!(sync(&mut w)["tip_height"], 102);
}

fn search(w: &mut Wallet) -> Value {
    rpc(w, "paycore.search.status", json!({})).unwrap()
}
/// A chain whose wallet-to-be was paid before block 100: a 5 in the first
/// piece and a 7 in the third, among outputs of others.
fn with_old_outputs(w: &mut Wallet) {
    let mut m = w.chain.borrow_mut();
    m.anchor = Some(Tip { height: 100, hash: [1; 32] });
    m.push(11, vec![]);
    m.push(12, vec![]);
    m.old = vec![foreign(GRIN, 0), coin(5 * GRIN, 0), foreign(2 * GRIN, 5), coin(7 * GRIN, 8)];
    m.old_pieces = 3;
}

/// The search for old outputs is part of following the chain: once the
/// wallet has every block the chain layer has, it reads the pieces and
/// keeps what its seed opens. Nobody is asked for pieces unless a search
/// is under way.
#[test]
fn the_old_outputs_are_read_at_the_tip() {
    let mut w = wallet(true);
    with_old_outputs(&mut w);
    assert_eq!(search(&mut w), json!({"state": "none"}));
    let r = sync(&mut w);
    assert_eq!(r["chain"].as_array().unwrap().len(), 1);
    assert!(w.chain.borrow().old_asked.is_empty(), "no search, no pieces");
    assert_eq!(spendable(&mut w), 0);
    assert_eq!(incomplete(&mut w), json!(false), "a wallet that never needed a search knows what it has");

    assert_eq!(
        rpc(&mut w, "paycore.search.start", json!({})).unwrap(),
        json!({"state": "reading", "next": 0, "pieces": 0, "found": 0, "gone": 0})
    );
    // until every piece is read the balance says it may not be everything
    assert_eq!((spendable(&mut w), incomplete(&mut w)), (0, json!(true)));
    let done = json!({"state": "done", "next": null, "pieces": 3, "found": 2, "gone": 0});
    let r = sync(&mut w);
    assert_eq!(r, json!({"chain": [{"search": done}], "tip_height": 102, "more": false, "unknown": false}));
    assert_eq!(incomplete(&mut w), json!(false));
    assert_eq!(w.chain.borrow().old_asked, [0, 1, 2]);
    assert_eq!(spendable(&mut w), 12 * GRIN);
    assert_eq!(search(&mut w), done);
    // over: nothing more is asked or written
    let ops = w.sim.ops();
    assert_eq!(sync(&mut w), json!({"chain": [], "tip_height": 102, "more": false, "unknown": false}));
    assert_eq!((w.chain.borrow().old_asked.len(), w.sim.ops()), (3, ops));

    // on the user's word it is read again, from the first piece
    rpc(&mut w, "paycore.search.start", json!({})).unwrap();
    sync(&mut w);
    assert_eq!(w.chain.borrow().old_asked, [0, 1, 2, 0, 1, 2]);
    assert_eq!(search(&mut w), json!({"state": "done", "next": null, "pieces": 3, "found": 0, "gone": 0}));
    assert_eq!(spendable(&mut w), 12 * GRIN);

    // a wallet made for the search, before it has any position
    let mut w = wallet(true);
    with_old_outputs(&mut w);
    rpc(&mut w, "paycore.search.start", json!({})).unwrap();
    let r = sync(&mut w);
    assert_eq!(r["chain"][0]["reanchored"], json!(true));
    assert_eq!(r["chain"][1]["search"]["state"], "done");
    assert_eq!(spendable(&mut w), 12 * GRIN);
}

/// "I cannot say" is never "an empty piece", and a piece is not read
/// before the wallet has the block it is for: the same piece is asked for
/// again, and nothing is written meanwhile.
#[test]
fn a_piece_is_waited_for_and_never_guessed() {
    let mut w = wallet(true);
    with_old_outputs(&mut w);
    sync(&mut w);
    rpc(&mut w, "paycore.search.start", json!({})).unwrap();
    let reading = |next: u64, pieces: u64, found: u64| json!({"state": "reading", "next": next, "pieces": pieces, "found": found, "gone": 0});
    let ops = w.sim.ops();

    // the chain layer cannot give the piece now
    w.chain.borrow_mut().old_dark = true;
    let r = sync(&mut w);
    assert_eq!(r, json!({"chain": [], "tip_height": 102, "more": false, "unknown": false}));
    assert_eq!((search(&mut w), w.sim.ops()), (reading(0, 0, 0), ops));
    assert_eq!(incomplete(&mut w), json!(true), "a search that waits is not a search that is over");
    w.chain.borrow_mut().old_dark = false;

    // pieces that are not the answer to the question
    let bends: [fn(&mut OldOutputs); 5] = [
        |old| old.next = None,
        |old| old.next = Some(7),
        |old| old.pieces = 1,
        |old| old.before = old.at.height + 1,
        |old| old.outputs[0].proof.clear(),
    ];
    for bend in bends {
        w.chain.borrow_mut().old_bend = Some(bend);
        let r = sync(&mut w);
        assert_eq!(r["chain"], json!([]));
        assert_eq!((search(&mut w), w.sim.ops()), (reading(0, 0, 0), ops));
    }
    // a piece for a block the wallet does not stand at
    w.chain.borrow_mut().old_bend = Some(|old| old.at.height += 1);
    let r = sync(&mut w);
    assert_eq!((&r["chain"], &r["more"]), (&json!([]), &json!(true)), "the block first, then the piece");
    w.chain.borrow_mut().old_bend = Some(|old| old.at.hash[3] ^= 1);
    assert_eq!(sync(&mut w)["chain"], json!([]));
    assert_eq!((search(&mut w), w.sim.ops()), (reading(0, 0, 0), ops));
    w.chain.borrow_mut().old_bend = None;
    assert_eq!(w.chain.borrow().old_asked, [0; 8], "the same piece every time");

    // the chain layer cannot say what comes next: the wallet may be
    // behind, and no piece is asked for
    w.chain.borrow_mut().dark = true;
    assert_eq!(sync(&mut w)["unknown"], json!(true));
    assert_eq!(w.chain.borrow().old_asked.len(), 8);
    w.chain.borrow_mut().dark = false;

    // more blocks than one round takes: the pieces wait for the last of them
    for i in 0..=MAX_CHAIN_STEPS as u8 {
        w.chain.borrow_mut().push(20 + i, vec![]);
    }
    let r = sync(&mut w);
    assert_eq!((&r["chain"][0]["applied"], &r["more"]), (&json!(MAX_CHAIN_STEPS), &json!(true)));
    assert_eq!(w.chain.borrow().old_asked.len(), 8);
    let r = sync(&mut w);
    assert_eq!(r["chain"][1]["search"]["state"], "done");
    assert_eq!(spendable(&mut w), 12 * GRIN);
}

/// The chain layer fetches pieces as the wallet reads them, and they come
/// out of order. While pieces have been coming, a round that meets one
/// that is not there yet says that there is more - whether it read any
/// itself or not: the next round follows without the pause. Once no piece
/// has come for a while, or before any has come at all, it does not say
/// so: a chain layer with nothing to give is asked again after the pause,
/// not five times a second.
#[test]
fn pieces_on_their_way_are_not_waited_for_through_the_pause() {
    let mut w = wallet(true);
    with_old_outputs(&mut w);
    sync(&mut w);
    rpc(&mut w, "paycore.search.start", json!({})).unwrap();
    // before any piece has come: the ordinary pace
    w.chain.borrow_mut().old_coming = Some(0);
    assert_eq!(sync(&mut w), json!({"chain": [], "tip_height": 102, "more": false, "unknown": false}));
    w.chain.borrow_mut().old_coming = Some(2);
    let r = sync(&mut w);
    assert_eq!((&r["chain"][0]["search"]["next"], &r["more"]), (&json!(2), &json!(true)));
    // nothing came meanwhile: the piece that is next is still on its way
    let r = sync(&mut w);
    assert_eq!(r, json!({"chain": [], "tip_height": 102, "more": true, "unknown": false}));
    // and no piece for longer than pieces are waited for
    w.b.set_old_coming_for(Duration::ZERO);
    let r = sync(&mut w);
    assert_eq!(r, json!({"chain": [], "tip_height": 102, "more": false, "unknown": false}));
    assert_eq!(w.chain.borrow().old_asked, [0, 0, 1, 2, 2, 2]);
    w.chain.borrow_mut().old_coming = None;
    let r = sync(&mut w);
    assert_eq!((&r["chain"][0]["search"]["state"], &r["more"]), (&json!("done"), &json!(false)));
    assert_eq!(spendable(&mut w), 12 * GRIN);
}

/// `paycore.chain.timing` counts what was asked of the chain layer and
/// what the wallet wrote, with the time each took: a measurement, with
/// nothing of the wallet's contents in it.
#[test]
fn the_time_of_following_the_chain_is_counted() {
    let mut w = wallet(true);
    with_old_outputs(&mut w);
    let timing = |w: &mut Wallet| rpc(w, "paycore.chain.timing", json!({})).unwrap();
    let t = timing(&mut w);
    assert_eq!((&t["rounds"], &t["blocks"]["asked"], &t["pieces"]["read"], &t["wallet"]["events"]), (&json!(0), &json!(0), &json!(0), &json!(0)));
    // the anchor, two blocks, and "nothing new"
    sync(&mut w);
    let t = timing(&mut w);
    assert_eq!((&t["rounds"], &t["blocks"]["asked"], &t["pieces"]["read"]), (&json!(1), &json!(4), &json!(0)));
    assert_eq!(t["wallet"]["events"], json!(3), "the anchor and two blocks were written");
    // three pieces, one of them asked for before it was there
    rpc(&mut w, "paycore.search.start", json!({})).unwrap();
    w.chain.borrow_mut().old_coming = Some(2);
    sync(&mut w);
    w.chain.borrow_mut().old_coming = None;
    sync(&mut w);
    let t = timing(&mut w);
    assert_eq!((&t["rounds"], &t["pieces"]["read"], &t["pieces"]["not_ready"]), (&json!(3), &json!(3), &json!(1)));
    // the start of the search and three pieces were written as well
    assert_eq!(t["wallet"]["events"], json!(7));
    for part in [&t["blocks"]["ask_ms"], &t["pieces"]["ask_ms"], &t["wallet"]["keys_ms"], &t["wallet"]["check_ms"], &t["wallet"]["write_ms"], &t["wallet"]["apply_ms"]] {
        assert!(part.is_u64(), "{t}");
    }
    let text = t.to_string();
    assert!(!text.contains("found") && !text.contains("commit"), "{text}");
}

/// One round reads a bounded number of pieces and says that there is more.
#[test]
fn the_old_outputs_are_read_in_bounded_rounds() {
    let mut w = wallet(true);
    with_old_outputs(&mut w);
    w.chain.borrow_mut().old_pieces = MAX_OLD_PIECES as u64 + 10;
    sync(&mut w);
    rpc(&mut w, "paycore.search.start", json!({})).unwrap();
    let r = sync(&mut w);
    assert_eq!(r["more"], json!(true));
    assert_eq!(r["chain"][0]["search"]["next"], json!(MAX_OLD_PIECES));
    assert_eq!(w.chain.borrow().old_asked.len(), MAX_OLD_PIECES);
    let r = sync(&mut w);
    assert_eq!(r["more"], json!(false));
    assert_eq!(r["chain"][0]["search"]["state"], "done");
    assert_eq!(spendable(&mut w), 12 * GRIN);
}

/// A wallet that followed the chain and then missed blocks says, with
/// every piece it asks for, which block it knew its outputs up to. A
/// chain layer that has that block gives what was there by then without
/// range proofs: the wallet looks its own outputs up in those pieces and
/// searches the rest. What it ends up with is what a search for
/// everything gives.
#[test]
fn a_wallet_that_was_away_says_where_it_stood() {
    let mut w = wallet(true);
    {
        let mut m = w.chain.borrow_mut();
        m.anchor = Some(Tip { height: 100, hash: [1; 32] });
        m.push(11, vec![foreign(GRIN, 0), coin(5 * GRIN, 0), coin(3 * GRIN, 1)]);
        m.push(12, vec![]);
    }
    sync(&mut w);
    assert_eq!(spendable(&mut w), 8 * GRIN);
    assert_eq!(search(&mut w), json!({"state": "none"}));

    // The chain layer starts again far ahead. Meanwhile the 3 was spent
    // and a 7 came in.
    {
        let mut m = w.chain.borrow_mut();
        m.known = vec![Tip { height: 102, hash: [12; 32] }];
        m.anchor = Some(Tip { height: 200, hash: [2; 32] });
        m.blocks.clear();
        m.push(21, vec![]);
        m.old = vec![foreign(GRIN, 0), coin(5 * GRIN, 0), foreign(2 * GRIN, 5), coin(7 * GRIN, 8)];
        m.old_pieces = 3;
        m.old_bare_below = 2;
    }
    let r = sync(&mut w);
    assert_eq!(r["chain"][0]["reanchored"], json!(true));
    let done = json!({"state": "done", "next": null, "pieces": 3, "found": 1, "gone": 1, "since": 102});
    assert_eq!(r["chain"].as_array().unwrap().last().unwrap()["search"], done);
    assert_eq!(w.chain.borrow().old_since, [(0, 102, 12), (1, 102, 12), (2, 102, 12)], "every piece is asked for with the block");
    assert_eq!(w.chain.borrow().old_asked, [0, 1, 2]);
    assert_eq!(spendable(&mut w), 12 * GRIN);
    assert_eq!(search(&mut w), done);

    // On the user's word everything is searched: no block is named, and
    // a piece that comes without range proofs all the same is not taken.
    rpc(&mut w, "paycore.search.start", json!({})).unwrap();
    w.chain.borrow_mut().old_bend = Some(|old| {
        old.outputs.iter_mut().for_each(|o| o.proof.clear());
        old.bare = true;
    });
    let ops = w.sim.ops();
    sync(&mut w);
    assert_eq!(w.chain.borrow().old_since.len(), 3, "no block is named");
    assert_eq!(search(&mut w), json!({"state": "reading", "next": 0, "pieces": 0, "found": 0, "gone": 0}));
    assert_eq!(w.sim.ops(), ops, "nothing is written");
    w.chain.borrow_mut().old_bend = None;
    sync(&mut w);
    assert_eq!(search(&mut w), json!({"state": "done", "next": null, "pieces": 3, "found": 0, "gone": 0}));
    assert_eq!(spendable(&mut w), 12 * GRIN);

    // A layer that does not have the block the wallet names gives every
    // piece whole, and the wallet reads it as ever.
    {
        let mut m = w.chain.borrow_mut();
        m.known.clear();
        m.anchor = Some(Tip { height: 300, hash: [3; 32] });
        m.blocks.clear();
        m.push(31, vec![]);
        m.old.push(coin(2 * GRIN, 9));
        m.old_since.clear();
    }
    sync(&mut w);
    assert!(w.chain.borrow().old_since.is_empty(), "no trusted prefix on the unknown branch");
    assert_eq!(search(&mut w), json!({"state": "done", "next": null, "pieces": 3, "found": 3, "gone": 0}));
    assert_eq!(spendable(&mut w), 14 * GRIN);

    // A piece with range proofs for some outputs and without for others
    // is not a piece.
    {
        let mut m = w.chain.borrow_mut();
        m.known = vec![Tip { height: 301, hash: [31; 32] }];
        m.anchor = Some(Tip { height: 400, hash: [4; 32] });
        m.blocks.clear();
        m.push(41, vec![]);
        m.old_bare_below = 3;
        m.old_bend = Some(|old| {
            if let Some(o) = old.outputs.first_mut() {
                o.proof = vec![1; 40];
            }
        });
    }
    let ops = w.sim.ops();
    sync(&mut w);
    let reading = json!({"state": "reading", "next": 0, "pieces": 0, "found": 0, "gone": 0, "since": 301});
    assert_eq!(search(&mut w), reading);
    sync(&mut w);
    assert_eq!(search(&mut w), reading);
    assert!(w.sim.ops() > ops, "the new starting point was written, no piece");
    w.chain.borrow_mut().old_bend = None;
    sync(&mut w);
    assert_eq!(search(&mut w), json!({"state": "done", "next": null, "pieces": 3, "found": 0, "gone": 0, "since": 301}));
    assert_eq!(spendable(&mut w), 14 * GRIN);
}

/// The journal does not grow without end: following the chain, it is folded
/// into a snapshot once it has enough frames, and nothing is lost by it.
#[test]
fn the_journal_is_folded_while_following_the_chain() {
    let mut w = wallet(true);
    {
        let mut m = w.chain.borrow_mut();
        m.anchor = Some(Tip { height: 100, hash: [1; 32] });
        m.push(11, vec![coin(5 * GRIN, 0)]);
        for i in 0..10u8 {
            m.push(20 + i, vec![]);
        }
    }
    // every block is a frame of the journal
    sync(&mut w);
    assert!(w.b.core().journal_frames() >= 11, "frames: {}", w.b.core().journal_frames());
    w.b.set_fold_after(8);
    for i in 0..20u8 {
        w.chain.borrow_mut().push(40 + i, vec![]);
    }
    let folds_before = w.sim.ops();
    sync(&mut w);
    assert!(w.b.core().journal_frames() < 8, "frames left: {}", w.b.core().journal_frames());
    assert_ne!(w.sim.ops(), folds_before);
    assert_eq!(spendable(&mut w), 5 * GRIN);
    let tip = w.b.core().tip();
    // the folded wallet, opened again from its files, is the same wallet
    let Wallet { b, sim, .. } = w;
    drop(b);
    let id = Identity { network: 2, genesis: [7; 32], instance: [1; 16] };
    let (again, _) = Core::open(sim.dir(), sim.guard(), &RootKey::new([0x42; 32]), id, kc(), 3).unwrap();
    assert_eq!(again.tip(), tip);
    assert_eq!(again.balance().spendable, 5 * GRIN);
    assert!(again.journal_frames() < 8);
}
