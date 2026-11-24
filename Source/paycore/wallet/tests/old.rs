//! The search for outputs that are older than the wallet's blocks
//! (specification 7.19): a wallet made from an existing seed, or one that
//! was away for longer than the chain layer keeps blocks, is handed what is
//! unspent piece by piece and keeps what its seed opens.
use fly_paycore_keys::path::KeyPath;
use fly_paycore_store::sim::{Sim, SimDir, SimGuard};
use fly_paycore_store::{Identity, RootKey};
use fly_paycore_wallet::{Advance, Core, CoreError, OldPiece, OldProgress, SendStatus};
use grin_core::global::{self, ChainTypes};
use grin_core::libtx::proof::{self, ProofBuilder};
use grin_keychain::{ExtKeychain, Keychain, SwitchCommitmentType};
use grin_util::secp::pedersen::{Commitment, RangeProof};

type C = Core<SimDir, SimGuard, ExtKeychain>;
const MATURITY: u64 = 3;
const GRIN: u64 = 1_000_000_000;
/// Outputs in one stretch of the toy output MMR.
const STRETCH: u64 = 4;

fn net() {
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
}
fn id() -> Identity {
    Identity {
        network: 2,
        genesis: [7; 32],
        instance: [9; 16],
    }
}
fn kc(seed: u8) -> ExtKeychain {
    ExtKeychain::from_seed(&[seed; 32], true).unwrap()
}
fn create(sim: &Sim, seed: u8) -> C {
    Core::create(sim.dir(), sim.guard(), &RootKey::new([0x42; 32]), id(), kc(seed), 0, MATURITY).unwrap()
}
fn open(sim: &Sim, seed: u8) -> C {
    Core::open(sim.dir(), sim.guard(), &RootKey::new([0x42; 32]), id(), kc(seed), MATURITY).unwrap().0
}

#[derive(Clone)]
struct Out {
    commit: Commitment,
    proof: RangeProof,
    coinbase: bool,
    born: u64,
    died: Option<u64>,
}

/// A toy chain that knows everything: every output, when it was created
/// and when it was spent. Position of an output is its number.
#[derive(Clone)]
struct World {
    height: u64,
    branch: u8,
    outs: Vec<Out>,
    blocks: Vec<Advance>,
    paths: u32,
}
impl World {
    fn new() -> World {
        World {
            height: 0,
            branch: 0,
            outs: Vec::new(),
            blocks: Vec::new(),
            paths: 0,
        }
    }
    fn hash(&self, height: u64) -> [u8; 32] {
        self.blocks[height as usize - 1].hash
    }
    /// The next block: it pays `(seed, value, coinbase)` and spends `spend`.
    fn block(&mut self, pay: &[(u8, u64, bool)], spend: &[Commitment]) -> Vec<Commitment> {
        self.height += 1;
        let mut a = Advance {
            height: self.height,
            hash: [self.height as u8; 32],
            ..Advance::default()
        };
        a.hash[1] = (self.height >> 8) as u8;
        a.hash[2] = self.branch;
        let mut made = Vec::new();
        for (seed, value, coinbase) in pay {
            let k = kc(*seed);
            let key = KeyPath::Legacy { account: 0, index: self.paths }.to_identifier();
            self.paths += 1;
            let commit = k.commit(*value, &key, SwitchCommitmentType::Regular).unwrap();
            let rp = proof::create(&k, &ProofBuilder::new(&k), *value, &key, SwitchCommitmentType::Regular, commit, None).unwrap();
            a.outputs.push((commit, rp, self.outs.len() as u64, *coinbase));
            self.outs.push(Out {
                commit,
                proof: rp,
                coinbase: *coinbase,
                born: self.height,
                died: None,
            });
            made.push(commit);
        }
        for c in spend {
            let out = self.outs.iter_mut().find(|o| o.commit == *c && o.died.is_none()).expect("spends what is unspent");
            out.died = Some(self.height);
            a.inputs.push(*c);
        }
        self.blocks.push(a);
        made
    }
    /// The next block: it holds this transaction and nothing else.
    fn mine_tx(&mut self, tx: &[u8]) -> Vec<Commitment> {
        let tx: grin_core::core::Transaction =
            grin_core::ser::deserialize(&mut &tx[..], grin_core::ser::ProtocolVersion::local(), grin_core::ser::DeserializationMode::default()).unwrap();
        self.height += 1;
        let mut a = Advance {
            height: self.height,
            hash: [self.height as u8; 32],
            ..Advance::default()
        };
        a.hash[1] = (self.height >> 8) as u8;
        a.hash[2] = self.branch;
        let mut made = Vec::new();
        for o in tx.outputs() {
            a.outputs.push((o.commitment(), o.proof(), self.outs.len() as u64, false));
            self.outs.push(Out {
                commit: o.commitment(),
                proof: o.proof(),
                coinbase: false,
                born: self.height,
                died: None,
            });
            made.push(o.commitment());
        }
        let inputs: Vec<grin_core::core::transaction::CommitWrapper> = tx.inputs().into();
        for i in inputs {
            let c = i.commitment();
            self.outs.iter_mut().find(|o| o.commit == c && o.died.is_none()).expect("spends what is unspent").died = Some(self.height);
            a.inputs.push(c);
        }
        a.kernels = tx.kernels().iter().map(|k| k.excess).collect();
        self.blocks.push(a);
        made
    }
    fn empty(&mut self, n: u64) {
        (0..n).for_each(|_| {
            self.block(&[], &[]);
        });
    }
    /// Give the wallet every block above its position.
    fn feed(&self, w: &mut C) {
        let from = w.tip_height().unwrap_or(0);
        for a in &self.blocks[from as usize..] {
            w.chain_advance(a).unwrap();
        }
    }
    fn pieces(&self, before: u64) -> u64 {
        (self.outs.iter().filter(|o| o.born <= before).count() as u64).div_ceil(STRETCH).max(1)
    }
    /// Piece `i` as an honest chain layer gives it while it stands at the
    /// tip: complete up to `before`.
    fn piece(&self, i: u64, before: u64) -> OldPiece {
        let pieces = self.pieces(before);
        let mut p = OldPiece {
            piece: i,
            last: i + 1 == pieces,
            pieces,
            before,
            at: (self.height, self.hash(self.height)),
            outputs: Vec::new(),
            bare: None,
        };
        for (pos, o) in self.outs.iter().enumerate() {
            if pos as u64 / STRETCH == i && o.born <= before && o.died.is_none() {
                p.outputs.push((o.commit, o.proof, pos as u64, o.coinbase));
            }
        }
        p
    }
    /// The same piece without range proofs: what is unspent in it.
    fn bare(&self, i: u64, before: u64) -> OldPiece {
        let mut p = self.piece(i, before);
        p.bare = Some(p.outputs.drain(..).map(|(commit, _, pos, _)| (commit.0, pos)).collect());
        p
    }
    /// Piece `i` as an honest chain layer gives it to a wallet that says
    /// it knew its outputs up to the block `since`: without range proofs
    /// if the stretch was full by that block and the block is of this
    /// chain, whole otherwise.
    fn piece_since(&self, i: u64, before: u64, since: (u64, [u8; 32])) -> OldPiece {
        let on_chain = since.0 >= 1 && since.0 <= self.height && self.hash(since.0) == since.1;
        let there = self.outs.iter().filter(|o| o.born <= since.0).count() as u64;
        if on_chain && (i + 1) * STRETCH <= there {
            self.bare(i, before)
        } else {
            self.piece(i, before)
        }
    }
    /// Read every piece that is left the way the handler does: with the
    /// block the search names, if it names one. Returns how many pieces
    /// came without range proofs and how many whole.
    fn search_since(&self, w: &mut C, before: u64) -> (u64, u64) {
        let (mut bare, mut whole) = (0, 0);
        while let Some(s) = w.old_search().filter(|s| s.next.is_some()) {
            let i = s.next.unwrap();
            let piece = match s.since {
                Some(since) => self.piece_since(i, before, since),
                None => self.piece(i, before),
            };
            if piece.bare.is_some() {
                bare += 1;
            } else {
                whole += 1;
            }
            w.old_apply(&piece).unwrap();
        }
        (bare, whole)
    }
    /// Read every piece that is left, complete up to `before`.
    fn search(&self, w: &mut C, before: u64) {
        while let Some(i) = w.old_search().and_then(|s| s.next) {
            w.old_apply(&self.piece(i, before)).unwrap();
        }
    }
    /// What `seed` holds unspent, as the chain has it.
    fn holds(&self, seed: u8) -> Vec<([u8; 33], u64)> {
        let k = kc(seed);
        let mut all: Vec<([u8; 33], u64)> = self
            .outs
            .iter()
            .filter(|o| o.died.is_none())
            .filter_map(|o| fly_paycore_keys::scan::rewind(&k, o.commit, o.proof).unwrap().map(|f| (o.commit.0, f.amount)))
            .collect();
        all.sort();
        all
    }
}

fn held(w: &C) -> Vec<([u8; 33], u64)> {
    let mut all = w.unspent();
    all.sort();
    all
}
fn refused(r: Result<usize, CoreError>, why: &str) {
    match r {
        Err(CoreError::Refused(said)) => assert_eq!(said, why),
        other => panic!("expected the refusal \"{why}\", got {other:?}"),
    }
}
/// Where the search stands, without the block it began with.
fn search_of(w: &C) -> Option<(Option<u64>, u64, u64, u64)> {
    w.old_search().map(|s: OldProgress| (s.next, s.pieces, s.found, s.gone))
}
fn progress(next: Option<u64>, pieces: u64, found: u64, gone: u64) -> Option<(Option<u64>, u64, u64, u64)> {
    Some((next, pieces, found, gone))
}
fn since_of(w: &C) -> Option<u64> {
    w.old_search().and_then(|s| s.since).map(|(height, _)| height)
}

/// A history in which seed 1 was paid before the wallet's blocks begin:
/// two outputs it still has, one it spent early, one it spends later, and
/// outputs of somebody else all around. Blocks 1..=10.
fn history() -> (World, Vec<Commitment>) {
    net();
    let mut w = World::new();
    let mut own = Vec::new();
    w.block(&[(2, 7 * GRIN, false), (2, GRIN, true)], &[]);
    own.extend(w.block(&[(1, 5 * GRIN, false), (2, 3 * GRIN, false)], &[]).drain(..1));
    own.extend(w.block(&[(2, 2 * GRIN, false), (1, 4 * GRIN, false), (1, 6 * GRIN, false)], &[]).drain(1..));
    own.extend(w.block(&[(1, 9 * GRIN, false)], &[]));
    // seed 1 spends its 4: gone before the wallet is restored
    w.block(&[(2, 4 * GRIN, false)], &[own[1]]);
    w.empty(5);
    (w, own)
}

/// A wallet made from a seed that already has a history starts at the block
/// the chain layer gives it and knows nothing of what the seed was paid
/// before. The search finds exactly what is still unspent: not what was
/// spent before, not what belongs to others. From then on the wallet holds
/// what a wallet that followed the chain from its first block holds, and
/// the journal brings the same state back.
#[test]
fn a_restored_wallet_finds_what_the_seed_holds() {
    let (mut world, own) = history();
    let sim_all = Sim::new();
    let mut all_along = create(&sim_all, 1);
    world.feed(&mut all_along);

    let sim = Sim::new();
    let mut w = create(&sim, 1);
    assert_eq!(w.old_search(), None, "nobody asked for a search");
    w.old_search_start().unwrap();
    assert_eq!(search_of(&w), progress(Some(0), 0, 0, 0));
    // the first position of a new wallet is not a gap: the search is as it was
    w.chain_reanchor(8, world.hash(8)).unwrap();
    assert_eq!(search_of(&w), progress(Some(0), 0, 0, 0));
    world.feed(&mut w);
    assert_eq!(held(&w), Vec::new(), "nothing is known before the search");

    assert_eq!(world.pieces(8), 3);
    assert_eq!(w.old_apply(&world.piece(0, 8)).unwrap(), 1);
    assert_eq!(search_of(&w), progress(Some(1), 3, 1, 0));
    assert_eq!(w.old_apply(&world.piece(1, 8)).unwrap(), 2);
    assert_eq!(w.old_apply(&world.piece(2, 8)).unwrap(), 0);
    assert_eq!(search_of(&w), progress(None, 3, 3, 0));
    assert_eq!(held(&w), world.holds(1));
    assert_eq!(held(&w), held(&all_along));
    assert_eq!(w.balance().spendable, 20 * GRIN);
    assert_eq!(w.balance(), all_along.balance());

    // what happens to the found outputs later the blocks tell
    world.block(&[(1, GRIN, false)], &[own[3]]);
    world.feed(&mut w);
    world.feed(&mut all_along);
    assert_eq!(held(&w), world.holds(1));
    assert_eq!(held(&w), held(&all_along));
    assert_eq!(w.balance().spendable, 12 * GRIN);

    // the journal brings the same state back, and so does a snapshot
    let before = (held(&w), w.balance(), w.old_search(), w.tip());
    drop(w);
    let mut w = open(&sim, 1);
    assert_eq!((held(&w), w.balance(), w.old_search(), w.tip()), before);
    w.checkpoint(None).unwrap();
    drop(w);
    let w = open(&sim, 1);
    assert_eq!((held(&w), w.balance(), w.old_search(), w.tip()), before);
}

/// A piece says what is unspent after one block. It is taken only by a
/// wallet that stands at that very block, as the piece that is next, and
/// only if it reaches the blocks the wallet has. A refused piece changes
/// nothing.
#[test]
fn a_piece_is_taken_only_where_it_is_true() {
    let (mut world, own) = history();
    let sim = Sim::new();
    let mut w = create(&sim, 1);
    refused(w.old_apply(&world.piece(0, 8)), "no search for old outputs is under way");
    w.old_search_start().unwrap();
    refused(w.old_apply(&world.piece(0, 8)), "the piece is for another block");
    w.chain_reanchor(8, world.hash(8)).unwrap();
    // the wallet is behind the block the piece is for: a spend in between
    // it has not seen yet would be lost
    refused(w.old_apply(&world.piece(0, 8)), "the piece is for another block");
    world.feed(&mut w);

    let good = world.piece(0, 8);
    let change = |f: &dyn Fn(&mut OldPiece)| {
        let mut p = good.clone();
        f(&mut p);
        p
    };
    refused(w.old_apply(&world.piece(1, 8)), "not the piece that is next");
    refused(w.old_apply(&change(&|p| p.at.0 = 9)), "the piece is for another block");
    refused(w.old_apply(&change(&|p| p.at.0 = 11)), "the piece is for another block");
    refused(w.old_apply(&change(&|p| p.at.1[5] ^= 1)), "the piece is for another block");
    refused(w.old_apply(&change(&|p| p.before = 11)), "the piece does not reach the wallet's blocks");
    // complete only up to a block below the wallet's first: what was
    // created in between neither the piece nor the blocks would show
    refused(w.old_apply(&change(&|p| p.before = 7)), "the piece does not reach the wallet's blocks");
    refused(w.old_apply(&change(&|p| p.last = true)), "the piece does not fit the number of pieces");
    refused(w.old_apply(&change(&|p| p.pieces = 1)), "the piece does not fit the number of pieces");
    refused(w.old_apply(&change(&|p| p.pieces = 0)), "the piece does not fit the number of pieces");
    assert_eq!(search_of(&w), progress(Some(0), 0, 0, 0));
    assert_eq!(held(&w), Vec::new());

    w.old_apply(&good).unwrap();
    refused(w.old_apply(&good), "not the piece that is next");
    refused(w.old_apply(&world.piece(2, 8)), "not the piece that is next");
    // a block arrives: a piece read before it is no longer for the wallet's block
    let stale = world.piece(1, 8);
    world.block(&[], &[own[2]]);
    world.feed(&mut w);
    refused(w.old_apply(&stale), "the piece is for another block");
    // the last piece must be the last
    refused(w.old_apply(&OldPiece { last: true, ..world.piece(1, 8) }), "the piece does not fit the number of pieces");
    refused(w.old_apply(&OldPiece { last: false, ..world.piece(2, 8) }), "not the piece that is next");
    w.old_apply(&world.piece(1, 8)).unwrap();
    refused(w.old_apply(&OldPiece { last: false, ..world.piece(2, 8) }), "the piece does not fit the number of pieces");
    refused(w.old_apply(&OldPiece { pieces: 4, ..world.piece(2, 8) }), "the piece does not fit the number of pieces");
    w.old_apply(&world.piece(2, 8)).unwrap();
    refused(w.old_apply(&world.piece(2, 8)), "not the piece that is next");
    assert_eq!(held(&w), world.holds(1));

    // nothing of the refused pieces is in the journal
    let before = (held(&w), w.old_search());
    drop(w);
    let w = open(&sim, 1);
    assert_eq!((held(&w), w.old_search()), before);
}

/// The archive point moves while the wallet reads: later pieces are
/// complete up to a higher block and there are more of them. Nothing is
/// lost and nothing is counted twice - what is young the wallet has from
/// its blocks.
#[test]
fn the_pieces_may_grow_while_they_are_read() {
    let (mut world, _) = history();
    let sim = Sim::new();
    let mut w = create(&sim, 1);
    w.old_search_start().unwrap();
    w.chain_reanchor(8, world.hash(8)).unwrap();
    world.feed(&mut w);
    w.old_apply(&world.piece(0, 8)).unwrap();
    // five more outputs, two of them the wallet's, which it sees in the block
    world.block(&[(1, GRIN, false), (2, GRIN, false), (2, GRIN, false), (1, 2 * GRIN, false), (2, GRIN, false)], &[]);
    world.feed(&mut w);
    assert_eq!((world.pieces(8), world.pieces(11)), (3, 4));
    w.old_apply(&world.piece(1, 11)).unwrap();
    w.old_apply(&world.piece(2, 11)).unwrap();
    assert_eq!(search_of(&w), progress(Some(3), 4, 3, 0));
    w.old_apply(&world.piece(3, 11)).unwrap();
    assert_eq!(search_of(&w), progress(None, 4, 3, 0), "the young outputs were known already");
    assert_eq!(held(&w), world.holds(1));
    assert_eq!(w.balance().spendable, 23 * GRIN);

    // And the other way round: the chain layer starts anew in the middle
    // and its later pieces are complete only up to a lower block. An
    // output younger than that is missing from them; it is the wallet's
    // from its block and is not given up for being missing.
    w.old_search_start().unwrap();
    w.old_apply(&world.piece(0, 11)).unwrap();
    w.old_apply(&world.piece(1, 11)).unwrap();
    let low = world.piece(2, 8);
    assert!(low.last && low.outputs.len() == 1, "of this stretch only somebody's output of block 5; those of block 11 are too young");
    w.old_apply(&low).unwrap();
    assert_eq!(search_of(&w), progress(None, 3, 0, 0));
    assert_eq!(held(&w), world.holds(1));
    assert_eq!(w.balance().spendable, 23 * GRIN);
}

/// A wallet that was away for longer than the chain layer keeps blocks is
/// put at a new block. What it held may have been spent in between, and
/// what it was paid there it has not seen. The search starts by itself
/// and settles both; an operation that counted on a spent output is
/// contested.
#[test]
fn a_wallet_that_missed_blocks_learns_what_is_gone_and_what_came() {
    net();
    let mut world = World::new();
    let own = world.block(&[(1, 5 * GRIN, false), (1, 3 * GRIN, false), (2, GRIN, false), (1, 2 * GRIN, false)], &[]);
    world.empty(4);
    let sim = Sim::new();
    let mut w = create(&sim, 1);
    w.chain_reanchor(0, [0; 32]).unwrap();
    assert_eq!(w.old_search(), None, "the first position of a wallet is not a gap");
    world.feed(&mut w);
    assert_eq!(w.balance().spendable, 10 * GRIN);
    // an operation that reserves all three
    let p = w.send_prepare(9 * GRIN, 0, None, false).unwrap();
    assert_eq!(w.send_status(&p.op), Some(SendStatus::Prepared));

    // the blocks the wallet does not get: its 3 is spent, a 7 comes in
    let came = world.block(&[(2, GRIN, false), (1, 7 * GRIN, false)], &[own[1]]);
    assert_eq!(world.holds(1).len(), 3);
    world.empty(8);
    w.chain_reanchor_extending(12, world.hash(12)).unwrap();
    assert_eq!(search_of(&w), progress(Some(0), 0, 0, 0), "the search starts with the gap");
    world.feed(&mut w);
    // until the search is over the wallet shows what it knew
    assert_eq!(w.balance().reserved, 10 * GRIN);
    assert_eq!(w.send_status(&p.op), Some(SendStatus::Prepared));

    assert_eq!(world.pieces(12), 2);
    w.old_apply(&world.piece(0, 12)).unwrap();
    assert_eq!(search_of(&w), progress(Some(1), 2, 0, 0));
    assert_eq!(w.balance().reserved, 10 * GRIN, "nothing is given up before every piece is read");
    w.old_apply(&world.piece(1, 12)).unwrap();
    assert_eq!(search_of(&w), progress(None, 2, 1, 1));
    assert_eq!(held(&w), world.holds(1));
    assert!(held(&w).iter().any(|(c, v)| *c == came[1].0 && *v == 7 * GRIN));
    assert!(!held(&w).iter().any(|(c, _)| *c == own[1].0));
    assert_eq!(w.send_status(&p.op), Some(SendStatus::Contested));

    let before = (held(&w), w.balance(), w.old_search(), w.send_status(&p.op));
    drop(w);
    let mut w = open(&sim, 1);
    assert_eq!((held(&w), w.balance(), w.old_search(), w.send_status(&p.op)), before);

    // a second search on the user's word finds nothing new and gives up nothing
    w.old_search_start().unwrap();
    assert_eq!(search_of(&w), progress(Some(0), 0, 0, 0));
    world.search(&mut w, 12);
    assert_eq!(search_of(&w), progress(None, 2, 0, 0));
    assert_eq!(held(&w), before.0);
    // an output created after the pieces were complete is not given up
    // for not being in them
    world.block(&[(1, GRIN, false)], &[]);
    world.feed(&mut w);
    w.old_search_start().unwrap();
    world.search(&mut w, 12);
    assert_eq!(search_of(&w), progress(None, 2, 0, 0));
    assert_eq!(held(&w), world.holds(1));
}

/// What a piece said was true on the branch the wallet stood on. When
/// blocks are taken back, the pieces read above them are read again: an
/// output spent on the abandoned branch, and so missing from its piece, is
/// alive on the other one.
#[test]
fn pieces_read_on_an_abandoned_branch_are_read_again() {
    let (mut world, own) = history();
    let sim = Sim::new();
    let mut w = create(&sim, 1);
    w.old_search_start().unwrap();
    w.chain_reanchor(8, world.hash(8)).unwrap();
    world.feed(&mut w);
    w.old_apply(&world.piece(0, 8)).unwrap();
    let fork = world.clone();
    // on this branch the seed's 6 is spent in block 11
    world.block(&[], &[own[2]]);
    world.feed(&mut w);
    w.old_apply(&world.piece(1, 8)).unwrap();
    assert_eq!(search_of(&w), progress(Some(2), 3, 2, 0));
    assert_eq!(w.balance().spendable, 14 * GRIN);

    // the other branch: block 11 spends nothing
    let mut world = fork;
    world.branch = 1;
    w.chain_rollback(10).unwrap();
    assert_eq!(w.old_search().unwrap().next, Some(1), "the piece read at block 11 is read again");
    world.empty(1);
    world.feed(&mut w);
    world.search(&mut w, 8);
    assert_eq!(held(&w), world.holds(1));
    assert_eq!(w.balance().spendable, 20 * GRIN);
    assert_eq!(search_of(&w), progress(None, 3, 3, 0));

    // the same after the search was over: read again, and nothing the
    // wallet holds is given up for not being in the pieces read again
    let fork = world.clone();
    let mut w2 = create(&Sim::new(), 1);
    w2.old_search_start().unwrap();
    w2.chain_reanchor(8, world.hash(8)).unwrap();
    world.feed(&mut w2);
    w2.old_apply(&world.piece(0, 8)).unwrap();
    world.block(&[], &[own[3]]);
    world.feed(&mut w2);
    world.search(&mut w2, 8);
    assert_eq!(search_of(&w2), progress(None, 3, 2, 0));
    assert_eq!(w2.balance().spendable, 11 * GRIN);
    let mut world = fork;
    world.branch = 2;
    w2.chain_rollback(11).unwrap();
    assert_eq!(w2.old_search().unwrap().next, Some(1));
    world.empty(1);
    world.feed(&mut w2);
    world.search(&mut w2, 8);
    assert_eq!(held(&w2), world.holds(1));
    assert_eq!(w2.balance().spendable, 20 * GRIN);
    assert_eq!(search_of(&w2), progress(None, 3, 3, 0));

    // a step back that does not reach the block a piece was read at changes nothing
    world.empty(2);
    world.feed(&mut w2);
    w2.chain_rollback(13).unwrap();
    assert_eq!(search_of(&w2), progress(None, 3, 3, 0));
}

/// An output the search added is known to have existed by the block the
/// piece was complete up to. Taken back below that block, the wallet no
/// longer knows that it exists: the output goes and the search starts
/// over. And a coinbase output found by the search matures from that
/// block, never earlier.
#[test]
fn a_found_output_is_as_old_as_its_piece_says_and_no_older() {
    net();
    let mut world = World::new();
    world.block(&[(1, 5 * GRIN, false), (1, 60 * GRIN, true)], &[]);
    world.empty(1);
    let mut w = create(&Sim::new(), 1);
    w.old_search_start().unwrap();
    w.chain_reanchor(1, world.hash(1)).unwrap();
    world.feed(&mut w);
    // complete up to block 2, where the wallet stands
    world.search(&mut w, 2);
    assert_eq!(search_of(&w), progress(None, 1, 2, 0));
    assert_eq!((w.balance().spendable, w.balance().immature), (5 * GRIN, 60 * GRIN));
    world.empty(2);
    world.feed(&mut w);
    assert_eq!(w.balance().immature, 60 * GRIN, "block 4: two blocks after the piece");
    world.empty(1);
    world.feed(&mut w);
    assert_eq!((w.balance().spendable, w.balance().immature), (65 * GRIN, 0));

    // back to block 1: below the block the piece was complete up to
    for to in [4, 3, 2] {
        w.chain_rollback(to).unwrap();
        assert_eq!(search_of(&w), progress(None, 1, 2, 0), "block {to} is not below the piece");
    }
    w.chain_rollback(1).unwrap();
    assert_eq!(search_of(&w), progress(Some(0), 0, 0, 0));
    assert_eq!(held(&w), Vec::new());
}

/// A history for a wallet that follows the chain from its first block:
/// seed 1 is paid in blocks 1..=5 among outputs of others - enough of
/// them for several stretches. Returns the outputs of seed 1.
fn followed() -> (World, Vec<Commitment>) {
    net();
    let mut w = World::new();
    let mut own = Vec::new();
    own.extend(w.block(&[(1, 5 * GRIN, false), (2, GRIN, false), (2, GRIN, false), (1, 3 * GRIN, false)], &[]).into_iter().step_by(3));
    w.block(&[(2, GRIN, false), (2, GRIN, false), (2, GRIN, false)], &[]);
    own.extend(w.block(&[(2, GRIN, false), (1, 2 * GRIN, false), (2, GRIN, false)], &[]).drain(1..2));
    w.block(&[(2, GRIN, false), (2, GRIN, false)], &[]);
    own.extend(w.block(&[(1, 4 * GRIN, false)], &[]));
    (w, own)
}

/// A wallet that knew every output of its own and then missed blocks does
/// not search what it had already seen: below the block it stood at
/// there is nothing to find, only to learn which of its outputs are still
/// unspent. It says which block that was; an honest chain layer gives
/// the stretches that were full by then without range proofs, and the
/// wallet looks its own outputs up in them. What came later is searched
/// as ever. The wallet ends up holding what a search for everything
/// gives it.
#[test]
fn a_wallet_that_was_away_searches_only_what_is_new() {
    let (mut world, own) = followed();
    assert_eq!(world.outs.len(), 13, "three stretches full, a fourth begun");
    let sim = Sim::new();
    let mut w = create(&sim, 1);
    w.chain_reanchor(0, [0; 32]).unwrap();
    world.feed(&mut w);
    assert_eq!(w.balance().spendable, 14 * GRIN);
    assert_eq!(w.old_search(), None);
    let stood = (5, world.hash(5));
    // the same wallet, to be searched for everything
    let sim2 = Sim::new();
    let mut twin = create(&sim2, 1);
    twin.chain_reanchor(0, [0; 32]).unwrap();
    world.feed(&mut twin);

    // The blocks neither wallet gets: the 3 is spent, a 7 and a 6 come
    // in - one in the stretch that was begun, one in a new stretch.
    let came = world.block(&[(1, 7 * GRIN, false), (2, GRIN, false), (2, GRIN, false), (2, GRIN, false), (1, 6 * GRIN, false)], &[own[1]]);
    world.empty(6);
    assert_eq!(world.pieces(12), 5);
    w.chain_reanchor_extending(12, world.hash(12)).unwrap();
    assert_eq!(w.old_search().unwrap().since, Some(stood), "the search is told where the wallet stood");
    assert_eq!(search_of(&w), progress(Some(0), 0, 0, 0));
    // Until the search is over the wallet does not know what it holds -
    // its 3 is spent, and it counts it: nothing is prepared for sending.
    let counted = w.balance();
    assert!(matches!(w.send_prepare(GRIN, 0, None, false), Err(CoreError::Refused("the search for old outputs is not over"))));
    assert!(matches!(w.send_prepare_late(GRIN, 0, None), Err(CoreError::Refused("the search for old outputs is not over"))));
    assert_eq!(w.balance(), counted, "and nothing is reserved");
    // the journal keeps it
    drop(w);
    let mut w = open(&sim, 1);
    assert_eq!(w.old_search().unwrap().since, Some(stood));

    // three stretches were full by block 5: those come bare
    let (bare, whole) = world.search_since(&mut w, 12);
    assert_eq!((bare, whole), (3, 2));
    assert_eq!(search_of(&w), progress(None, 5, 2, 1), "two found, one gone");
    assert_eq!(held(&w), world.holds(1));
    // the search is over: the wallet sends from what it has
    let p = w.send_prepare(GRIN, 0, None, false).unwrap();
    w.send_cancel(&p.op).unwrap();
    assert!(held(&w).iter().any(|(c, v)| *c == came[0].0 && *v == 7 * GRIN));
    assert!(held(&w).iter().any(|(c, v)| *c == came[4].0 && *v == 6 * GRIN));
    assert!(!held(&w).iter().any(|(c, _)| *c == own[1].0));
    assert_eq!(w.balance().spendable, 24 * GRIN);

    // the search for everything ends at the same
    twin.chain_reanchor_extending(12, world.hash(12)).unwrap();
    twin.old_search_start().unwrap();
    assert_eq!(twin.old_search().unwrap().since, None, "on the user's word everything is searched");
    assert_eq!(world.search_since(&mut twin, 12), (0, 5));
    assert_eq!(held(&twin), held(&w));
    assert_eq!(twin.balance(), w.balance());

    // and the journal brings the same state back
    let before = (held(&w), w.balance(), w.old_search());
    drop(w);
    let w = open(&sim, 1);
    assert_eq!((held(&w), w.balance(), w.old_search()), before);
}

/// A piece without range proofs is taken only by a search that began with
/// a block the wallet knew its outputs up to. A search for everything
/// refuses it: nothing can be found in it, and "nothing found" would
/// stand for "nothing of mine". Refused, it changes nothing.
#[test]
fn a_piece_without_range_proofs_is_not_taken_by_a_search_for_everything() {
    let (world, own) = history();
    // restored from the seed: everything is searched
    let sim = Sim::new();
    let mut w = create(&sim, 1);
    w.old_search_start().unwrap();
    w.chain_reanchor(8, world.hash(8)).unwrap();
    world.feed(&mut w);
    assert_eq!(w.old_search().unwrap().since, None);
    let state = (held(&w), w.old_search());
    refused(w.old_apply(&world.bare(0, 8)), "a piece without range proofs in a search for everything");
    assert_eq!((held(&w), w.old_search()), state);
    // no search at all
    let sim3 = Sim::new();
    let mut fresh = create(&sim3, 1);
    fresh.chain_reanchor(8, world.hash(8)).unwrap();
    world.feed(&mut fresh);
    refused(fresh.old_apply(&world.bare(0, 8)), "a piece without range proofs in a search for everything");
    // read whole, the same piece gives the wallet its outputs
    w.old_apply(&world.piece(0, 8)).unwrap();
    assert!(held(&w).iter().any(|(c, _)| *c == own[0].0));

    // In a search that takes bare pieces, a piece is one or the other.
    let (mut world, _) = followed();
    let sim2 = Sim::new();
    let mut w = create(&sim2, 1);
    w.chain_reanchor(0, [0; 32]).unwrap();
    world.feed(&mut w);
    world.empty(7);
    w.chain_reanchor_extending(12, world.hash(12)).unwrap();
    assert_eq!(since_of(&w), Some(5));
    let mut both = world.bare(0, 12);
    both.outputs = world.piece(0, 12).outputs;
    let state = (held(&w), w.old_search());
    refused(w.old_apply(&both), "a piece without range proofs that has some");
    assert_eq!((held(&w), w.old_search()), state);
    // the rules of a piece hold for a bare one as well
    refused(w.old_apply(&world.bare(1, 12)), "not the piece that is next");
    let mut other = world.bare(0, 12);
    other.at.1[5] ^= 1;
    refused(w.old_apply(&other), "the piece is for another block");
    assert_eq!((held(&w), w.old_search()), state);
    // a bare piece shows only what the wallet knows: an output of its
    // seed that it has no record of is not found in one
    w.old_apply(&world.bare(0, 12)).unwrap();
    assert_eq!(search_of(&w), progress(Some(1), 4, 0, 0));
}

/// What the wallet knew before a gap it still knows after the next one.
/// A search that was not finished when another gap opened leaves the
/// wallet knowing no more than that search began with; a finished one
/// makes the block the wallet stands at the one it knows up to; a search
/// for everything that was cut short stays a search for everything; and
/// when blocks are taken back and the search starts over, it starts with
/// what it had.
#[test]
fn what_the_wallet_knew_is_carried_through_gaps() {
    let (mut world, _) = followed();
    let sim = Sim::new();
    let mut w = create(&sim, 1);
    w.chain_reanchor(0, [0; 32]).unwrap();
    world.feed(&mut w);
    world.block(&[(1, 7 * GRIN, false)], &[]);
    world.empty(6);
    // the first gap: the wallet stood at 5
    w.chain_reanchor_extending(12, world.hash(12)).unwrap();
    assert_eq!(since_of(&w), Some(5));
    w.old_apply(&world.piece_since(0, 12, (5, world.hash(5)))).unwrap();
    assert_eq!(search_of(&w), progress(Some(1), 4, 0, 0));
    // a second gap before that search is over: still 5, not 12 - the 7
    // of block 6 has not been found yet
    world.empty(8);
    w.chain_reanchor_extending(20, world.hash(20)).unwrap();
    assert_eq!(since_of(&w), Some(5));
    assert_eq!(search_of(&w), progress(Some(0), 0, 0, 0), "from the first piece");
    world.feed(&mut w);
    assert_eq!(world.search_since(&mut w, 20), (3, 1));
    assert_eq!(held(&w), world.holds(1));
    assert_eq!(w.balance().spendable, 21 * GRIN);
    // the search is over; the wallet follows to 23 and misses blocks again:
    // now it knows everything up to 23
    world.empty(3);
    world.feed(&mut w);
    world.block(&[(2, GRIN, false), (2, GRIN, false), (1, 9 * GRIN, false)], &[]);
    world.empty(5);
    w.chain_reanchor_extending(27, world.hash(27)).unwrap();
    assert_eq!(w.old_search().unwrap().since, Some((23, world.hash(23))));
    // blocks are taken back below what a piece was complete up to: the
    // search starts over and still knows where the wallet stood
    world.feed(&mut w);
    w.old_apply(&world.piece_since(0, 29, (23, world.hash(23)))).unwrap();
    assert_eq!(search_of(&w), progress(Some(1), 5, 0, 0));
    w.chain_rollback(28).unwrap();
    assert_eq!(search_of(&w), progress(Some(0), 0, 0, 0));
    assert_eq!(since_of(&w), Some(23));
    world.height = 28;
    world.blocks.truncate(28);
    world.branch = 1;
    world.empty(2);
    world.feed(&mut w);
    assert_eq!(world.search_since(&mut w, 28), (3, 2));
    assert_eq!(held(&w), world.holds(1));
    assert_eq!(w.balance().spendable, 30 * GRIN);

    // The search is over. A block is taken back, above what the pieces
    // were complete up to: the pieces are read again for what they find.
    // Until they are, the wallet may lack an output that was spent in
    // the block taken back; a gap now leaves it knowing what it knew
    // when that search began.
    w.chain_rollback(29).unwrap();
    assert_eq!(search_of(&w), progress(Some(0), 5, 1, 0));
    world.empty(9);
    w.chain_reanchor_extending(37, world.hash(37)).unwrap();
    assert_eq!(since_of(&w), Some(23), "not 29");
    world.feed(&mut w);
    assert_eq!(world.search_since(&mut w, 37), (3, 2));
    assert_eq!(held(&w), world.holds(1));

    // A wallet restored from its seed, cut off in the middle of its
    // search for everything: the next search is for everything too.
    let (mut world, _) = history();
    let sim = Sim::new();
    let mut w = create(&sim, 1);
    w.old_search_start().unwrap();
    w.chain_reanchor(8, world.hash(8)).unwrap();
    world.feed(&mut w);
    w.old_apply(&world.piece(0, 8)).unwrap();
    world.empty(10);
    w.chain_reanchor_extending(20, world.hash(20)).unwrap();
    assert_eq!(w.old_search().unwrap().since, None);
    assert_eq!(search_of(&w), progress(Some(0), 0, 0, 0));
    assert_eq!(world.search_since(&mut w, 20), (0, 3));
    assert_eq!(held(&w), world.holds(1));
    // finished; from here on the wallet knows all it has
    world.empty(10);
    w.chain_reanchor_extending(30, world.hash(30)).unwrap();
    assert_eq!(w.old_search().unwrap().since, Some((20, world.hash(20))));
}

/// The block a wallet says it knew its outputs up to may not be of the
/// chain any more: the wallet stood on a branch that was abandoned while
/// it was away. An honest chain layer then gives every piece whole, and
/// the search for everything sets right what the wallet had seen on that
/// branch.
#[test]
fn a_wallet_that_stood_on_an_abandoned_branch_is_searched_whole() {
    let (mut world, own) = followed();
    let sim = Sim::new();
    let mut w = create(&sim, 1);
    w.chain_reanchor(0, [0; 32]).unwrap();
    world.feed(&mut w);
    // The branch the wallet saw is abandoned from block 5 on: on the
    // other one its 4 of block 5 never existed, and a 2 comes instead.
    let seen = world.hash(5);
    world.height = 4;
    world.blocks.truncate(4);
    world.outs.truncate(12);
    world.branch = 1;
    world.block(&[(1, 2 * GRIN, false)], &[]);
    assert_ne!(world.hash(5), seen);
    world.empty(7);
    w.chain_reanchor(12, world.hash(12)).unwrap();
    assert_eq!(w.old_search().unwrap().since, None);
    assert_eq!(world.search_since(&mut w, 12), (0, 4), "no piece comes bare");
    assert_eq!(held(&w), world.holds(1));
    assert!(!held(&w).iter().any(|(c, _)| *c == own[3].0), "what the abandoned branch paid is gone");
    assert_eq!(w.balance().spendable, 12 * GRIN);
}

/// A payment the wallet sent and then did not see confirmed, because it
/// was away when the block came. Its inputs are gone when the wallet is
/// back - and its change output is on the chain. Only this operation's
/// transaction could have put it there, so the operation is confirmed, by
/// a height not later than the pieces were complete up to, and not
/// contested. The same from a search for everything. Where there is no
/// such evidence - the change was spent before the wallet looked - the
/// operation is contested, as before: the wallet cannot tell who spent
/// its inputs.
#[test]
fn a_payment_confirmed_while_the_wallet_was_away_is_confirmed() {
    let (mut world, sim, mut w, op, tx) = sent();
    assert!(w.balance().reserved >= 6 * GRIN);

    // the block with the payment, and more, while the wallet is away
    let made = world.mine_tx(&tx);
    assert_eq!(made.len(), 2, "the payment and the change");
    world.empty(6);
    w.chain_reanchor_extending(12, world.hash(12)).unwrap();
    assert_eq!(since_of(&w), Some(5));
    world.feed(&mut w);
    assert_eq!(w.send_status(&op), Some(SendStatus::Finalized), "nothing is concluded before the search");
    world.search_since(&mut w, 12);
    assert_eq!(w.send_status(&op), Some(SendStatus::Confirmed));
    assert_eq!(held(&w), world.holds(1));
    assert_eq!(w.balance().reserved, 0);
    assert_eq!(w.balance().spendable + w.balance().immature, 14 * GRIN - 6 * GRIN - fin_fee(&w, &op));
    // the journal brings it back
    let state = (held(&w), w.balance(), w.send_status(&op), w.old_search());
    drop(w);
    let mut w = open(&sim, 1);
    assert_eq!((held(&w), w.balance(), w.send_status(&op), w.old_search()), state);
    // a search for everything says the same
    w.old_search_start().unwrap();
    world.search_since(&mut w, 12);
    assert_eq!((held(&w), w.balance(), w.send_status(&op)), (state.0.clone(), state.1, state.2));

    // The same payment, but the change was spent by the time the wallet
    // looked - a copy of the wallet elsewhere did it. Nothing on the
    // chain says whose transaction took the inputs: contested.
    let (mut world, _sim, mut w, op, tx) = sent();
    let made = world.mine_tx(&tx);
    let change = *made.iter().find(|c| world.holds(1).iter().any(|(held, _)| *held == c.0)).unwrap();
    world.block(&[], &[change]);
    world.empty(5);
    w.chain_reanchor_extending(12, world.hash(12)).unwrap();
    world.feed(&mut w);
    world.search_since(&mut w, 12);
    assert_eq!(w.send_status(&op), Some(SendStatus::Contested));
    assert_eq!(held(&w), world.holds(1));
}

/// What a search concluded about an operation holds as long as what it
/// read holds. A step back below the height the pieces were complete up
/// to takes the conclusion away with the found outputs, and the pieces
/// read again bring it back if the payment is still in the chain. And if
/// the wallet is later put on a chain where the operation's inputs are
/// unspent, the operation is not in that chain: it is in flight again.
#[test]
fn a_confirmation_by_search_holds_while_what_was_read_holds() {
    let (mut world, _sim, mut w, op, tx) = sent();
    world.empty(3);
    // The payment is in block 10. The wallet is put at block 10: it has
    // not seen that block. A chain that parts at block 9 is kept aside.
    let mut other = world.clone();
    world.empty(1);
    world.mine_tx(&tx);
    world.empty(2);
    w.chain_reanchor_extending(10, world.hash(10)).unwrap();
    world.feed(&mut w);
    world.search_since(&mut w, 12);
    assert_eq!(w.send_status(&op), Some(SendStatus::Confirmed));
    assert_eq!(w.balance().reserved, 0);

    // A step back to block 11, below what the pieces were complete up to:
    // the search starts over, and until it has read the pieces again the
    // operation is in flight.
    w.chain_rollback(11).unwrap();
    assert_eq!(w.send_status(&op), Some(SendStatus::Finalized));
    world.height = 11;
    world.blocks.truncate(11);
    world.branch = 2;
    world.empty(2);
    world.feed(&mut w);
    world.search_since(&mut w, 13);
    assert_eq!(w.send_status(&op), Some(SendStatus::Confirmed), "block 10 is still in the chain");
    assert_eq!(held(&w), world.holds(1));

    // The chain turns below block 10, deeper than the wallet can step
    // back: it is put on the other branch, where the payment is not in a
    // block and its inputs are unspent.
    other.branch = 1;
    other.empty(5);
    w.chain_reanchor(11, other.hash(11)).unwrap();
    assert_eq!(w.send_status(&op), Some(SendStatus::Finalized), "the previous inclusion is unproven on this branch");
    other.feed(&mut w);
    assert_eq!(other.search_since(&mut w, 13).0, 0, "the wallet stood on another branch: every piece whole");
    assert_eq!(w.send_status(&op), Some(SendStatus::Finalized), "its inputs are unspent: it may yet be mined");
    assert_eq!(held(&w), other.holds(1));
    assert!(w.balance().reserved >= 6 * GRIN);
    // and there it is mined, in a block the wallet sees
    other.mine_tx(&tx);
    other.feed(&mut w);
    assert_eq!(w.send_status(&op), Some(SendStatus::Confirmed));
    assert_eq!(held(&w), other.holds(1));
}

/// The wallet of seed 1 on the chain of `followed`, at block 5, with a
/// payment of 6 to seed 2 signed and not yet in a block: the chain, the
/// wallet's machine, the wallet, the operation and its transaction.
fn sent() -> (World, Sim, C, fly_paycore_wallet::OpId, Vec<u8>) {
    let (world, _) = followed();
    let (sim, sim_b) = (Sim::new(), Sim::new());
    let mut w = create(&sim, 1);
    let mut b = create(&sim_b, 2);
    for c in [&mut w, &mut b] {
        c.chain_reanchor(0, [0; 32]).unwrap();
        world.feed(c);
    }
    assert_eq!(w.balance().spendable, 14 * GRIN);
    let p = w.send_prepare(6 * GRIN, 0, None, false).unwrap();
    let s2 = b.receive_draft(&p.s1, None).unwrap();
    let fin = w.send_finalize(&p.op, &s2).unwrap();
    assert_eq!(w.send_status(&p.op), Some(SendStatus::Finalized));
    (world, sim, w, p.op, fin.tx)
}

/// The fee of an operation, from the history.
fn fin_fee(w: &C, op: &fly_paycore_wallet::OpId) -> u64 {
    w.sends().into_iter().find(|(o, ..)| o == op).map(|(_, _, _, fee)| fee).unwrap()
}

#[test]
fn a_detached_payment_loses_both_chain_confirmations() -> Result<(), &'static str> {
    use fly_paycore_wallet::{ChainState, Row};
    let (mut world, _) = followed();
    let mut other = world.clone();
    let (sa, sb) = (Sim::new(), Sim::new());
    let mut a = create(&sa, 1);
    let mut b = create(&sb, 2);
    world.feed(&mut a);
    world.feed(&mut b);
    let p = a.send_prepare(6 * GRIN, 0, None, false).map_err(|_| "prepare")?;
    let s2 = b.receive_draft(&p.s1, None).map_err(|_| "receive")?;
    let id = fly_paycore_wallet::slate_summary(&s2).map_err(|_| "slate")?.id;
    let fin = a.send_finalize(&p.op, &s2).map_err(|_| "finalize")?;
    world.mine_tx(&fin.tx);
    world.feed(&mut a);
    world.feed(&mut b);
    assert_eq!(b.incoming_row(&id, ChainState::AtTip, 1), Some(Row::S8));
    assert_eq!(a.send_status(&p.op), Some(SendStatus::Confirmed));
    other.branch = 1;
    other.empty(8);
    for wallet in [&mut a, &mut b] {
        wallet.chain_reanchor(other.height, other.hash(other.height)).map_err(|_| "new anchor")?;
        other.search(wallet, other.height);
    }
    drop(a);
    drop(b);
    let (mut a, mut b) = (open(&sa, 1), open(&sb, 2));
    assert_eq!(b.incoming_row(&id, ChainState::AtTip, 1), Some(Row::S4));
    assert_eq!(a.send_status(&p.op), Some(SendStatus::Finalized));
    assert!(a.balance().reserved >= 6 * GRIN);
    other.mine_tx(&fin.tx);
    other.feed(&mut a);
    other.feed(&mut b);
    assert_eq!(a.send_status(&p.op), Some(SendStatus::Confirmed));
    assert_eq!(b.incoming_row(&id, ChainState::AtTip, 1), Some(Row::S7a));
    Ok(())
}

#[test]
fn old_reanchors_and_folded_snapshots_recheck_chain_facts_once() {
    use fly_paycore_store::Store;
    for folded in [false, true] {
        let (mut world, sim, mut wallet, op, tx) = sent();
        world.mine_tx(&tx);
        world.feed(&mut wallet);
        assert_eq!(wallet.send_status(&op), Some(SendStatus::Confirmed));
        if folded {
            wallet.old_search_start().unwrap();
            world.search(&mut wallet, world.height);
            wallet.checkpoint(None).unwrap();
        }
        drop(wallet);
        let mut old = Store::open(sim.dir(), sim.guard(), &RootKey::new([0x42; 32]), id()).unwrap();
        if folded {
            let mut snapshot: serde_json::Value = serde_json::from_slice(old.snapshot.as_ref().unwrap()).unwrap();
            snapshot.as_object_mut().unwrap().remove("legacy_chain_evidence").unwrap();
            old.store.checkpoint(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
        } else {
            let event = serde_json::json!({"Reanchor":{"height":world.height+10, "hash":vec![17u8;32], "since":null}});
            old.store.commit(fly_paycore_wallet::KIND_EVENT, &serde_json::to_vec(&event).unwrap()).unwrap();
        }
        drop(old);
        let wallet = open(&sim, 1);
        assert_eq!(wallet.send_status(&op), Some(SendStatus::Finalized));
        assert!(wallet.tip().is_none());
        let progress = wallet.old_search().unwrap();
        assert_eq!((progress.next, progress.since), (Some(0), None));
        let tip = wallet.journal_tail();
        drop(wallet);
        let wallet = open(&sim, 1);
        assert_eq!(wallet.journal_tail(), tip, "migration must not repeat");
        assert_eq!(wallet.send_status(&op), Some(SendStatus::Finalized));
    }
}
