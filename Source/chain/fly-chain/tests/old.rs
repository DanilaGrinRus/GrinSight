//! The outputs that are older than the blocks: range proofs of what is
//! unspent, fetched from nodes for a wallet that asks, checked against the
//! verified header and handed over piece by piece. Run with
//! `cargo test --features test-net`.
mod kit;

use fly_chain::old::{full_pieces, leaves_after, Came, Old, ASKED_WITHIN};
use fly_chain::schedule::{ASK_GAP, MAX_STRAY};
use fly_chain::TEST_START_FILE;
use fly_chain_headers::testkit::TestChain;
use fly_chain_headers::{hash_bytes, Net};
use fly_chain_state::advance::{Check, Live};
use fly_chain_state::archive::rangeproof_segments;
use fly_chain_state::testkit::Source;
use fly_paycore_chain_pipe::{Config, PipeChain};
use fly_paycore_chain_port::{ChainFeed, Level, OldOutputs, OutputFact, Step, Tip, Unknown};
use grin_core::core::hash::Hashed;
use grin_core::core::{Segment, SegmentIdentifier};
use grin_core::global::{self, ChainTypes};
use kit::{read_old, wait_for, Node, Temp, FLY};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// 236 blocks; the state is given out at 210.
fn shared() -> &'static Source {
    static SOURCE: std::sync::OnceLock<Source> = std::sync::OnceLock::new();
    let source = SOURCE.get_or_init(|| Source::mine(236));
    global::set_local_chain_type(ChainTypes::AutomatedTesting);
    source
}
fn live_at(source: &Source, height: u64) -> Live {
    let mut live = Live::new(source.collect()).unwrap();
    for b in &source.blocks[211..=height as usize] {
        live.apply(b, &b.header, Check::Kept, None).unwrap();
    }
    live
}
/// What a wallet must be given by a chain layer that stands at `live`:
/// every output created up to block `before` that is unspent, with the
/// proof it has in its block, in the order of the output MMR.
fn expected(source: &Source, live: &Live, before: usize) -> Vec<OutputFact> {
    let mut all: Vec<OutputFact> = source.blocks[..=before]
        .iter()
        .flat_map(|b| b.outputs())
        .filter_map(|o| {
            let proof = o.proof();
            live.unspent(&o.commitment().0).map(|unspent| OutputFact {
                commit: o.commitment().0,
                proof: proof.proof[..proof.plen].to_vec(),
                pos: unspent.pos,
                coinbase: o.is_coinbase(),
            })
        })
        .collect();
    all.sort_by_key(|o| o.pos);
    all
}
fn tip_of(live: &Live) -> Tip {
    Tip {
        height: live.header().height,
        hash: hash_bytes(live.header()),
    }
}
fn id(idx: u64) -> SegmentIdentifier {
    SegmentIdentifier { height: 11, idx }
}

/// Without a network: the pieces are asked for when a wallet asks, at the
/// archive header the nodes serve, a few ahead; a segment is taken only if
/// it was asked for and passes the node's check against the verified
/// header; and a piece is, of what was unspent at the archive header, what
/// is unspent after the last block applied now.
#[test]
fn a_piece_is_what_is_unspent_now() {
    let source = shared();
    let archive = source.archive();
    let segmenter = source.chain.segmenter().unwrap();
    let cut = |idx: u64| segmenter.rangeproof_segment(id(idx)).unwrap();
    let pieces = rangeproof_segments(&archive);
    assert!(pieces >= 2);
    let (a, b): (SocketAddr, SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
    // one block after the archive header: it has spent some old outputs already
    let live = live_at(source, 211);
    let mut now = Instant::now();
    let mut old = Old::new();

    // nobody asks: nothing is fetched
    old.serve_at(&archive, &live);
    assert!(!old.wanted(now));
    assert_eq!(old.plan(now, &[a, b]), vec![]);
    // a wallet asks: "I cannot say", and the pieces are asked for, one
    // request to a peer at a time
    assert_eq!(old.ask(0, None, now, &live), Err(Unknown));
    assert!(old.wanted(now));
    assert_eq!(old.plan(now, &[a, b]), vec![(a, archive.hash(), id(0)), (b, archive.hash(), id(1))]);
    assert_eq!(old.plan(now, &[a, b]), vec![], "asked already");

    // not for this header; not asked of this peer; not a segment of this height
    assert_eq!(old.arrived(a, source.blocks[200].header.hash(), cut(0), &live), Came::Unasked);
    assert_eq!(old.arrived(b, archive.hash(), cut(0), &live), Came::Unasked);
    let (_, hash_pos, hashes, leaf_pos, leaves, proof) = cut(0).parts();
    let short = Segment::from_parts(SegmentIdentifier { height: 10, idx: 0 }, hash_pos, hashes, leaf_pos, leaves, proof);
    assert_eq!(old.arrived(a, archive.hash(), short, &live), Came::Unasked);
    assert_eq!(old.held(), 0);
    // One proof changed: not what the header commits to. The proof of an
    // unspent output, that is - the node's check does not read the leaf of
    // a spent one, and which leaves are spent differs from one mined chain
    // to the next.
    let (sid, hash_pos, hashes, leaf_pos, mut leaves, proof) = cut(0).parts();
    let unspent_pos = expected(source, &live, 210)[0].pos;
    let read_leaf = leaf_pos.iter().position(|pos| *pos == unspent_pos).unwrap();
    leaves[read_leaf].proof[40] ^= 1;
    let bent = Segment::from_parts(sid, hash_pos, hashes, leaf_pos, leaves, proof);
    assert_eq!(old.arrived(a, archive.hash(), bent, &live), Came::Invalid);
    assert_eq!(old.ask(0, None, now, &live), Err(Unknown), "nothing of it is handed over");
    // it is asked for again, and the true one is taken
    now += ASK_GAP;
    assert_eq!(old.plan(now, &[a]), vec![(a, archive.hash(), id(0))]);
    assert_eq!(old.arrived(a, archive.hash(), cut(0), &live), Came::Taken);
    assert_eq!(old.arrived(a, archive.hash(), cut(0), &live), Came::Unasked, "a second answer to one request");
    assert_eq!(old.arrived(b, archive.hash(), cut(1), &live), Came::Taken);
    assert_eq!(old.held(), 2);

    // every piece, as the wallet reads them
    let mut given: Vec<OutputFact> = Vec::new();
    for piece in 0..pieces {
        let answer = loop {
            match old.ask(piece, None, now, &live) {
                Ok(answer) => break answer,
                Err(Unknown) => {
                    now += ASK_GAP;
                    for (peer, block, sid) in old.plan(now, &[a, b]) {
                        assert_eq!(block, archive.hash());
                        assert_eq!(old.arrived(peer, block, cut(sid.idx), &live), Came::Taken);
                    }
                }
            }
        };
        assert_eq!((answer.at, answer.before, answer.pieces), (tip_of(&live), 210, pieces));
        assert_eq!(answer.next, Some(piece + 1).filter(|next| *next < pieces));
        assert!(answer.answers(piece));
        given.extend(answer.outputs);
    }
    assert!(given.windows(2).all(|pair| pair[0].pos < pair[1].pos), "no output twice, in order");
    assert_eq!(given, expected(source, &live, 210));
    // spent between the archive header and the last block: not given;
    // created after the archive header: not given, the blocks have it
    let at_archive = expected(source, &live_at(source, 210), 210);
    assert!(given.len() < at_archive.len(), "the chain spends old outputs after 210");
    assert!(expected(source, &live, 211).len() > given.len(), "and creates new ones");
    assert_eq!(old.held(), 1, "what the wallet has read is let go of");

    // a piece that is held says what is unspent when it is asked for:
    // more blocks have been applied since it came
    let later = live_at(source, 236);
    let last = pieces - 1;
    let answer = old.ask(last, None, now, &later).unwrap();
    assert_eq!((answer.at, answer.before), (tip_of(&later), 210));
    let (first, _) = cut(last).segment_pos_range(archive.output_mmr_size);
    let stretch = |all: Vec<OutputFact>| all.into_iter().filter(|o| o.pos >= first).collect::<Vec<OutputFact>>();
    assert_eq!(answer.outputs, stretch(expected(source, &later, 210)));
    assert!(answer.outputs.len() < stretch(given.clone()).len(), "the blocks 212 to 236 spend outputs of this stretch");

    // the wallet stops asking: nothing more is fetched, nothing is held
    assert_eq!(old.plan(now + ASKED_WITHIN, &[a, b]), vec![]);
    assert_eq!(old.held(), 1);
    assert_eq!(old.plan(now + ASKED_WITHIN + Duration::from_millis(1), &[a, b]), vec![]);
    assert_eq!(old.held(), 0);
    assert!(!old.wanted(now + ASKED_WITHIN + Duration::from_millis(1)));
}

/// A wallet that followed the chain and then missed blocks knew every
/// output of its own up to the block it stood at. A stretch of the output
/// MMR that was full by that block is given to it at once and without
/// range proofs - what is unspent there now, from the state held here -
/// and no node is asked for it. The stretches after that are fetched and
/// given with their range proofs, as to any wallet.
#[test]
fn what_a_wallet_knew_comes_without_range_proofs() {
    let source = shared();
    let archive = source.archive();
    let segmenter = source.chain.segmenter().unwrap();
    let cut = |idx: u64| segmenter.rangeproof_segment(id(idx)).unwrap();
    let pieces = rangeproof_segments(&archive);
    assert_eq!(pieces, 2, "one stretch full, one begun");
    let (a, b): (SocketAddr, SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
    let leaves = |height: usize| grin_core::core::pmmr::n_leaves(source.blocks[height].header.output_mmr_size);
    // the first block after which the first stretch was full
    let full_at = (1..=210).find(|h| leaves(*h) >= 2048).unwrap();
    assert!(full_at > 100 && full_at < 210);
    let live = live_at(source, 220);
    let mut now = Instant::now();
    let bare = |all: Vec<OutputFact>, piece: u64| -> Vec<OutputFact> {
        let (first, last) = id(piece).segment_pos_range(archive.output_mmr_size);
        all.into_iter()
            .filter(|o| (first..=last).contains(&o.pos))
            .map(|o| OutputFact { proof: Vec::new(), ..o })
            .collect()
    };

    // The wallet stood at a block by which the first stretch was full.
    let mut old = Old::new();
    old.serve_at(&archive, &live);
    let answer = old.ask(0, Some(leaves(full_at)), now, &live).unwrap();
    assert!(answer.bare && answer.answers_since(0) && !answer.answers(0));
    assert_eq!((answer.at, answer.before, answer.pieces, answer.next), (tip_of(&live), 210, 2, Some(1)));
    assert_eq!(answer.outputs, bare(expected(source, &live, 210), 0));
    assert!(answer.outputs.len() > 100, "{}", answer.outputs.len());
    assert_eq!(old.held(), 0, "nothing was fetched for it");
    // only the stretch after it is asked for
    assert_eq!(old.plan(now, &[a, b]), vec![(a, archive.hash(), id(1))]);
    assert_eq!(old.ask(1, Some(leaves(full_at)), now, &live), Err(Unknown), "that one needs its range proofs");
    assert_eq!(old.arrived(a, archive.hash(), cut(1), &live), Came::Taken);
    let answer = old.ask(1, Some(leaves(full_at)), now, &live).unwrap();
    assert!(!answer.bare && answer.answers(1));
    let (first, _) = id(1).segment_pos_range(archive.output_mmr_size);
    let whole: Vec<OutputFact> = expected(source, &live, 210).into_iter().filter(|o| o.pos >= first).collect();
    assert_eq!(answer.outputs, whole);
    assert_eq!(answer.next, None);

    // a bare piece says what is unspent now, as any piece does
    let later = live_at(source, 236);
    let then = old.ask(0, Some(leaves(full_at)), now, &later).unwrap();
    assert_eq!((then.at, then.before), (tip_of(&later), 210));
    assert_eq!(then.outputs, bare(expected(source, &later, 210), 0));

    // One block earlier the stretch was not full: the wallet may not
    // know an output of its own in it, and the piece comes whole.
    let mut old = Old::new();
    old.serve_at(&archive, &live);
    assert_eq!(full_pieces(leaves(full_at - 1)), 0);
    assert_eq!(old.ask(0, Some(leaves(full_at - 1)), now, &live), Err(Unknown));
    assert_eq!(old.plan(now, &[a, b]), vec![(a, archive.hash(), id(0)), (b, archive.hash(), id(1))]);
    assert_eq!(old.arrived(a, archive.hash(), cut(0), &live), Came::Taken);
    let answer = old.ask(0, Some(leaves(full_at - 1)), now, &live).unwrap();
    assert!(!answer.bare);
    assert_eq!(answer.outputs.iter().map(|o| o.commit).collect::<Vec<_>>(), bare(expected(source, &live, 210), 0).iter().map(|o| o.commit).collect::<Vec<_>>());

    // A wallet that names no block gets every piece whole, also right
    // after one that named one.
    now += ASK_GAP;
    let mut old = Old::new();
    old.serve_at(&archive, &live);
    assert!(old.ask(0, Some(leaves(full_at)), now, &live).unwrap().bare);
    assert_eq!(old.ask(0, None, now, &live), Err(Unknown));
    assert_eq!(old.plan(now, &[a, b]), vec![(a, archive.hash(), id(0)), (b, archive.hash(), id(1))]);

    // A wallet that knew everything up to a block above the archive
    // header: every stretch the nodes serve comes bare, the last one too,
    // and nothing is asked of anybody.
    let mut old = Old::new();
    old.serve_at(&archive, &live);
    let all = old.ask(0, Some(u64::MAX), now, &live).unwrap();
    assert!(all.bare && all.next == Some(1));
    let last = old.ask(1, Some(u64::MAX), now, &live).unwrap();
    assert!(last.bare && last.next.is_none() && last.answers_since(1));
    assert_eq!(last.outputs, bare(expected(source, &live, 210), 1));
    assert_eq!(old.plan(now, &[a, b]), vec![]);
    // more blocks are applied: the piece is cut from the state as it is
    // now, not as it was when a bare piece was last given
    let early = live_at(source, 211);
    let first = old.ask(1, Some(u64::MAX), now, &early).unwrap();
    assert_eq!(first.outputs, bare(expected(source, &early, 210), 1));
    let then = old.ask(1, Some(u64::MAX), now, &later).unwrap();
    assert_eq!(then.at, tip_of(&later));
    assert_eq!(then.outputs, bare(expected(source, &later, 210), 1));
    assert!(then.outputs.len() < first.outputs.len(), "the blocks 212 to 236 spend outputs of this stretch");

    // before it is known where the nodes serve, nothing is said
    let mut old = Old::new();
    assert_eq!(old.ask(0, Some(u64::MAX), now, &live), Err(Unknown));
    // and blocks taken back let go of what bare pieces were cut from
    old.serve_at(&archive, &live);
    assert!(old.ask(0, Some(u64::MAX), now, &live).is_ok());
    old.taken_back();
    assert_eq!(old.ask(0, Some(u64::MAX), now, &live), Err(Unknown));
}

/// Which block a wallet knew its outputs up to is the wallet's word. It
/// counts only for a block of the chain followed here, not above the
/// last block applied; then the header of that block says how many
/// outputs there were. Anything else - a block of another branch, one
/// this program has no header for - counts for nothing.
#[test]
fn only_a_block_of_the_followed_chain_says_what_a_wallet_knew() {
    let source = shared();
    let header = |height: usize| source.blocks[height].header.clone();
    let tip = |height: usize| Tip {
        height: height as u64,
        hash: hash_bytes(&header(height)),
    };
    let since = tip(150);
    let leaves = grin_core::core::pmmr::n_leaves(header(150).output_mmr_size);
    assert!(leaves > 1000);
    assert_eq!(leaves_after(since, Some(since.hash), 220, || Some(header(150))), Some(leaves));
    assert_eq!(leaves_after(since, Some(since.hash), 150, || Some(header(150))), Some(leaves), "the block applied last");
    // the chain has another block at that height, or none
    assert_eq!(leaves_after(since, Some(tip(151).hash), 220, || Some(header(150))), None);
    assert_eq!(leaves_after(since, None, 220, || Some(header(150))), None);
    let mut read = false;
    assert_eq!(leaves_after(since, None, 220, || { read = true; Some(header(150)) }), None);
    assert!(!read, "no header is read for a block that is not of the chain");
    // a block above the last one applied
    assert_eq!(leaves_after(since, Some(since.hash), 149, || Some(header(150))), None);
    // the header cannot be read, or is not that block's
    assert_eq!(leaves_after(since, Some(since.hash), 220, || None), None);
    assert_eq!(leaves_after(since, Some(since.hash), 220, || Some(header(151))), None);
    assert_eq!(leaves_after(since, Some(since.hash), 220, || Some(header(149))), None);
    // a wallet that names the right hash at another height
    let wrong = Tip { height: 151, hash: since.hash };
    assert_eq!(leaves_after(wrong, Some(since.hash), 220, || Some(header(150))), None);
    assert_eq!(leaves_after(wrong, Some(tip(151).hash), 220, || Some(header(151))), None);
}

/// Blocks taken back, the archive header moved on, a peer that sends what
/// nobody asked for.
#[test]
fn what_is_held_is_true_or_it_is_let_go() {
    let source = shared();
    let archive = source.archive();
    let segmenter = source.chain.segmenter().unwrap();
    let cut = |idx: u64| segmenter.rangeproof_segment(id(idx)).unwrap();
    let (a, b): (SocketAddr, SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
    let live = live_at(source, 236);
    let mut now = Instant::now();
    let mut old = Old::new();
    old.serve_at(&archive, &live);
    assert_eq!(old.ask(0, None, now, &live), Err(Unknown));
    assert_eq!(old.plan(now, &[a]), vec![(a, archive.hash(), id(0))]);
    assert_eq!(old.arrived(a, archive.hash(), cut(0), &live), Came::Taken);
    assert!(old.ask(0, None, now, &live).is_ok());

    // Blocks are taken back. What is held said what was unspent on the
    // branch that is gone: none of it is handed over, and nothing is asked
    // for until it is known again where the nodes serve.
    old.taken_back();
    assert_eq!((old.held(), old.ask(0, None, now, &live)), (0, Err(Unknown)));
    now += ASK_GAP;
    assert_eq!(old.plan(now, &[a]), vec![]);
    old.serve_at(&archive, &live);
    assert_eq!(old.plan(now, &[a]), vec![(a, archive.hash(), id(0))]);

    // The nodes move on to another archive header while a request is out:
    // it will not be answered, and the piece is asked for at once at the
    // new header - also of the same peer, which is not to blame. An
    // answer for the old header is not taken.
    let moved = source.blocks[220].header.clone();
    old.serve_at(&moved, &live);
    assert_eq!(old.plan(now, &[b]), vec![(b, moved.hash(), id(0))]);
    assert_eq!(old.arrived(a, archive.hash(), cut(0), &live), Came::Unasked);
    // the same header again changes nothing: the request stays out
    old.serve_at(&moved, &live);
    now += ASK_GAP;
    assert_eq!(old.plan(now, &[a, b]), vec![(a, moved.hash(), id(1))]);
    // requests that are never answered are given up, and asked of the other peer
    now += Duration::from_secs(600);
    assert_eq!(old.expire(now), vec![], "one unanswered request is not held against a peer");
    assert_eq!(old.ask(0, None, now, &live), Err(Unknown));
    assert_eq!(old.plan(now, &[a, b]), vec![(a, moved.hash(), id(0)), (b, moved.hash(), id(1))]);
    // a header the state cannot be taken back to: nothing can be checked,
    // nothing is asked for
    old.serve_at(&source.blocks[200].header, &live);
    assert_eq!(old.plan(now + ASK_GAP, &[a, b]), vec![]);
    assert_eq!(old.ask(0, None, now, &live), Err(Unknown));

    // a peer that keeps sending segments nobody asked it for
    old.serve_at(&archive, &live);
    let pushy: SocketAddr = "127.0.0.1:3".parse().unwrap();
    for _ in 0..MAX_STRAY {
        assert_eq!(old.arrived(pushy, archive.hash(), cut(0), &live), Came::Unasked);
    }
    assert_eq!(old.arrived(pushy, archive.hash(), cut(0), &live), Came::Pushy);
    // a peer that is gone: what it was asked is asked of another
    now += Duration::from_secs(700);
    assert_eq!(old.ask(0, None, now, &live), Err(Unknown));
    assert_eq!(old.plan(now, &[a]), vec![(a, archive.hash(), id(0))]);
    old.forget(a);
    assert_eq!(old.plan(now, &[b]), vec![(b, archive.hash(), id(0))]);
}

/// The first request for a segment at an archive header makes a node build
/// its state there, which can take longer than an answer is waited for.
/// Until a node has answered at that header it is asked one piece at a
/// time; and at the next archive header it has to build again.
#[test]
fn a_node_is_asked_one_piece_until_it_has_answered() {
    let source = shared();
    let archive = source.archive();
    let segmenter = source.chain.segmenter().unwrap();
    let cut = |idx: u64| segmenter.rangeproof_segment(id(idx)).unwrap();
    let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let live = live_at(source, 236);
    let mut now = Instant::now();
    let mut old = Old::new();
    old.serve_at(&archive, &live);
    assert_eq!(old.ask(0, None, now, &live), Err(Unknown));
    assert_eq!(old.plan(now, &[a]), vec![(a, archive.hash(), id(0))]);
    for _ in 0..8 {
        now += ASK_GAP;
        assert_eq!(old.plan(now, &[a]), vec![], "a second request before the first is answered");
    }
    assert_eq!(old.arrived(a, archive.hash(), cut(0), &live), Came::Taken);
    // The wallet goes away and comes back; nothing is held any more. The
    // node has answered at this header: now several requests may be out
    // to it at once.
    now += ASKED_WITHIN + Duration::from_secs(1);
    assert_eq!((old.plan(now, &[a]), old.held()), (vec![], 0));
    assert_eq!(old.ask(0, None, now, &live), Err(Unknown));
    assert_eq!(old.plan(now, &[a]), vec![(a, archive.hash(), id(0))]);
    now += ASK_GAP;
    assert_eq!(old.plan(now, &[a]), vec![(a, archive.hash(), id(1))]);

    // the nodes move on: at the new header the node has to build again
    let moved = source.blocks[220].header.clone();
    old.serve_at(&moved, &live);
    now += ASK_GAP;
    assert_eq!(old.plan(now, &[a]), vec![(a, moved.hash(), id(0))]);
    now += ASK_GAP;
    assert_eq!(old.plan(now, &[a]), vec![], "a second request before the first is answered");
}

/// A thin chain of 40 blocks on a node that has pruned its files; five of
/// its outputs, made in the blocks 6 to 10, are never spent.
fn chain_of_40() -> Arc<RwLock<Source>> {
    let source = Source::thin_with_old(40);
    source.compact();
    Arc::new(RwLock::new(source))
}
fn program(tag: &str, source: &Arc<RwLock<Source>>, peers: &[&Node]) -> (Temp, PipeChain) {
    let t = Temp::new(tag);
    let record = TestChain::from_headers(source.read().unwrap().headers()).record(14);
    std::fs::write(t.0.join(TEST_START_FILE), record).unwrap();
    let config = Config {
        network: 3,
        genesis: Net::Automated.genesis_hash(),
        data_dir: t.0.to_str().unwrap().to_string(),
        peers: peers.iter().map(|node| node.addr.to_string()).collect(),
        start_timeout_secs: 30,
        direct_post: false,
        tor_off: false,
        tor_bridges: String::new(),
    };
    let chain = PipeChain::spawn(std::path::Path::new(FLY), &config, Duration::from_secs(10)).unwrap();
    (t, chain)
}
/// Ask for a piece the way a wallet does: again after a pause, until it is given.
fn read(chain: &mut PipeChain, piece: u64) -> OldOutputs {
    let mut answer = None;
    wait_for("the piece", || {
        answer = chain.old_outputs(piece).ok();
        answer.is_some()
    });
    answer.unwrap()
}

/// The program on a pipe, against a node: a wallet that asks is given the
/// old outputs - what was unspent at the archive header and still is,
/// each with its range proof - and nothing is fetched for a wallet that
/// does not ask.
#[test]
fn the_wallet_is_given_the_old_outputs() {
    let source = chain_of_40();
    let node = Node::with_state(&source);
    let (_t, mut chain) = program("old", &source, &[&node]);
    assert_eq!(chain.old_outputs(0), Err(Unknown), "before any block is applied");
    wait_for("the blocks", || chain.status().is_some_and(|s| s.level == Level::AtTip));
    let tip = chain.status().unwrap().tip.unwrap();
    assert_eq!(tip.height, 40);
    // the state was collected with the last segment of the rangeproof
    // MMR; since then nothing was asked
    let before = node.served.proofs_asked.load(Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(1500));
    assert_eq!(node.served.proofs_asked.load(Ordering::Relaxed), before, "nobody asked for old outputs");

    let mut given = Vec::new();
    let mut piece = Some(0);
    while let Some(i) = piece {
        let answer = read(&mut chain, i);
        assert_eq!((answer.at, answer.before), (tip, 20));
        piece = answer.next;
        given.extend(answer.outputs);
    }
    let live = {
        let source = source.read().unwrap();
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let mut live = Live::new(source.collect()).unwrap();
        for b in &source.blocks[21..=40] {
            live.apply(b, &b.header, Check::Kept, None).unwrap();
        }
        live
    };
    let want = expected(&source.read().unwrap(), &live, 20);
    assert_eq!(want.len(), 5, "the five that are never spent; what else was unspent at 20 has been spent since");
    assert_eq!(given, want);
    assert!(node.served.proofs_asked.load(Ordering::Relaxed) > before);
    // a piece that is not there
    assert_eq!(chain.old_outputs(1_000_000), Err(Unknown));

    // A wallet that names the block it knew its outputs up to. On this
    // chain no stretch of the output MMR is full, so there is nothing a
    // wallet can be spared: the piece comes whole, the same as before -
    // for a block of the chain, for the last block, for a block the
    // chain does not have and for one of another branch alike.
    let whole = read(&mut chain, 0);
    assert!(!whole.bare && !whole.outputs.is_empty());
    let block = |height: usize| Tip {
        height: height as u64,
        hash: hash_bytes(&source.read().unwrap().blocks[height].header),
    };
    let other_branch = Tip { height: 30, hash: [7; 32] };
    let never = Tip { height: 4_000_000, hash: [7; 32] };
    let below_the_start = Tip { height: 3, hash: block(3).hash };
    for since in [block(30), block(40), block(15), other_branch, never, below_the_start] {
        assert_eq!(chain.old_outputs_since(0, since), Ok(whole.clone()), "{}", since.height);
    }
    assert_eq!(chain.old_outputs_since(1_000_000, block(30)), Err(Unknown));
    assert!(chain.alive());

    // The chain grows by a block that the wallet has not been given: the
    // piece now says what is unspent after that block, and names it.
    source.write().unwrap().grow(1);
    node.set(&source.read().unwrap().headers());
    node.announce();
    wait_for("the new block", || chain.status().is_some_and(|s| s.tip.is_some_and(|t| t.height == 41)));
    let answer = read(&mut chain, 0);
    assert_eq!(answer.at.height, 41);
    assert!(matches!(chain.next(Some(tip)), Ok(Step::Block(facts)) if facts.hash == answer.at.hash));
}

/// The program on a pipe, with a state that has a full stretch of the
/// output MMR: a wallet that names a block of the chain by which that
/// stretch was full is given it at once, without range proofs, and no
/// node is asked for it. Named a block of another branch, the program
/// has nothing to give before the range proofs are there.
///
/// The state is put into the data directory beforehand: it is too large
/// for the messages of the test network. The headers and the blocks come
/// from the node.
#[test]
fn a_wallet_that_names_its_block_is_spared_the_range_proofs() {
    let source = Source::mine_from(236, false);
    let full_at = (1..=210usize)
        .find(|h| grin_core::core::pmmr::n_leaves(source.blocks[*h].header.output_mmr_size) >= 2048)
        .unwrap();
    let block = |height: usize| Tip {
        height: height as u64,
        hash: hash_bytes(&source.blocks[height].header),
    };
    let (since, earlier) = (block(full_at), block(full_at - 1));
    let live = live_at(&source, 236);
    let archive = source.archive();
    let (first, last) = id(0).segment_pos_range(archive.output_mmr_size);
    let want: Vec<OutputFact> = expected(&source, &live, 210)
        .into_iter()
        .filter(|o| (first..=last).contains(&o.pos))
        .map(|o| OutputFact { proof: Vec::new(), ..o })
        .collect();
    assert!(want.len() > 100);

    let t = Temp::new("old-bare");
    std::fs::write(t.0.join(TEST_START_FILE), TestChain::from_headers(source.headers()).record(14)).unwrap();
    {
        let (mut store, _) = fly_chain_state::store::Store::open(&t.0, archive.clone()).unwrap();
        while store.wanted() != fly_chain_state::archive::Wanted::Nothing {
            source.serve_store(&mut store).unwrap();
        }
    }
    let source = Arc::new(RwLock::new(source));
    let node = Node::with_state(&source);
    let config = Config {
        network: 3,
        genesis: Net::Automated.genesis_hash(),
        data_dir: t.0.to_str().unwrap().to_string(),
        peers: vec![node.addr.to_string()],
        start_timeout_secs: 30,
        direct_post: false,
        tor_off: false,
        tor_bridges: String::new(),
    };
    let mut chain = PipeChain::spawn(std::path::Path::new(FLY), &config, Duration::from_secs(10)).unwrap();
    wait_for("the blocks", || chain.status().is_some_and(|s| s.level == Level::AtTip));
    let tip = chain.status().unwrap().tip.unwrap();
    assert_eq!(tip.height, 236);
    let asked = node.served.proofs_asked.load(Ordering::Relaxed);

    let mut answer = None;
    wait_for("the bare piece", || {
        answer = chain.old_outputs_since(0, since).ok();
        answer.is_some()
    });
    let answer = answer.unwrap();
    assert!(answer.bare);
    assert_eq!((answer.at, answer.before, answer.pieces, answer.next), (tip, 210, 2, Some(1)));
    assert_eq!(answer.outputs, want);
    assert_eq!(node.served.proofs_asked.load(Ordering::Relaxed), asked, "no node was asked for it");
    // one block earlier the stretch was not full; a block of another
    // branch says nothing about what the wallet has seen: no bare piece
    assert_eq!(chain.old_outputs_since(0, earlier), Err(Unknown));
    assert_eq!(chain.old_outputs_since(0, Tip { height: since.height, hash: earlier.hash }), Err(Unknown));
    assert_eq!(chain.old_outputs(0), Err(Unknown));
    assert!(chain.alive());
}

/// A node that sends range proofs the verified header does not commit to
/// is left for good; an honest node is asked instead, and nothing of what
/// the first one sent reaches the wallet.
#[test]
fn a_node_that_sends_other_range_proofs_is_left() {
    let source = chain_of_40();
    let liar = Node::with_state(&source);
    let (_t, mut chain) = program("badproofs", &source, &[&liar]);
    wait_for("the blocks", || chain.status().is_some_and(|s| s.level == Level::AtTip));
    liar.served.bend_proofs.store(true, Ordering::Relaxed);
    let (asked, connections) = (liar.served.proofs_asked.load(Ordering::Relaxed), liar.peers.lock().unwrap().len());
    assert_eq!(chain.old_outputs(0), Err(Unknown));
    wait_for("the remark", || chain.problem().is_some_and(|text| text.contains("range proofs that do not fit the verified header")));
    assert_eq!(chain.old_outputs(0), Err(Unknown));
    // Left, and for good. The wallet goes on asking for eight seconds:
    // the node is not asked again and not connected to again.
    let until = Instant::now() + Duration::from_secs(8);
    while Instant::now() < until {
        assert_eq!(chain.old_outputs(0), Err(Unknown));
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(liar.served.proofs_asked.load(Ordering::Relaxed) <= asked + 2, "it was asked again and again");
    assert_eq!(liar.peers.lock().unwrap().len(), connections, "it was connected to again");
    drop(chain);

    let honest = Node::with_state(&source);
    let (_t, mut chain) = program("goodproofs", &source, &[&liar, &honest]);
    wait_for("the blocks", || chain.status().is_some_and(|s| s.level == Level::AtTip));
    let answer = read(&mut chain, 0);
    for o in &answer.outputs {
        let source = source.read().unwrap();
        let in_block = source.blocks.iter().flat_map(|b| b.outputs()).find(|out| out.commitment().0 == o.commit).unwrap();
        assert_eq!(o.proof, in_block.proof().proof[..in_block.proof().plen].to_vec());
    }
    assert!(!answer.outputs.is_empty());
}

/// The chain moves to another branch while the wallet reads. What the
/// program held said what was unspent on the branch that is gone; it is
/// fetched again, and the piece names a block of the new branch.
#[test]
fn pieces_are_fetched_again_when_the_chain_moves() {
    let source = chain_of_40();
    let node = Node::with_state(&source);
    let (_t, mut chain) = program("oldreorg", &source, &[&node]);
    wait_for("the blocks", || chain.status().is_some_and(|s| s.level == Level::AtTip));
    let first = read(&mut chain, 0);
    assert_eq!(first.at.height, 40);
    // held: asked for again, it is given at once, and no node is asked
    let asked = node.served.proofs_asked.load(Ordering::Relaxed);
    assert_eq!(chain.old_outputs(0), Ok(first.clone()));
    assert_eq!(node.served.proofs_asked.load(Ordering::Relaxed), asked);

    // a heavier branch that leaves this one at 38; the wallet goes on asking
    source.write().unwrap().branch(38, 4);
    node.set(&source.read().unwrap().headers());
    node.announce();
    let tip = hash_bytes(&source.read().unwrap().blocks[42].header);
    let mut last = None;
    wait_for("the other branch", || {
        last = chain.old_outputs(0).ok();
        last.as_ref().is_some_and(|old| old.at == Tip { height: 42, hash: tip })
    });
    assert!(node.served.proofs_asked.load(Ordering::Relaxed) > asked, "what was held was handed over after the blocks were taken back");
    assert_eq!(last.unwrap().outputs, first.outputs, "the five that are never spent, on this branch as well");
}

/// With everything on file the program keeps three nodes. When a wallet
/// starts to read the old outputs, more nodes are connected to: there is
/// much to fetch again.
#[test]
fn more_nodes_are_asked_while_a_wallet_reads() {
    let source = chain_of_40();
    let first = Node::with_state(&source);
    let (t, chain) = program("oldmany", &source, &[&first]);
    let mut chain = chain;
    wait_for("the blocks", || chain.status().is_some_and(|s| s.level == Level::AtTip));
    drop(chain);
    std::thread::sleep(Duration::from_secs(1));

    // the same data directory, six fresh nodes
    let nodes: Vec<Node> = (0..6).map(|_| Node::with_state(&source)).collect();
    let connected = |nodes: &[Node]| nodes.iter().map(|node| node.peers.lock().unwrap().len()).sum::<usize>();
    let config = Config {
        network: 3,
        genesis: Net::Automated.genesis_hash(),
        data_dir: t.0.to_str().unwrap().to_string(),
        peers: nodes.iter().map(|node| node.addr.to_string()).collect(),
        start_timeout_secs: 30,
        direct_post: false,
        tor_off: false,
        tor_bridges: String::new(),
    };
    let mut chain = PipeChain::spawn(std::path::Path::new(FLY), &config, Duration::from_secs(10)).unwrap();
    wait_for("the blocks from the files", || chain.status().is_some_and(|s| s.level == Level::AtTip));
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(connected(&nodes), 3, "nothing to fetch");
    // the wallet reads
    wait_for("more nodes", || {
        let _ = chain.old_outputs(0);
        connected(&nodes) == 6
    });
}

/// `fly-chain old`: the program reads the old outputs by itself, the way
/// it is tried against the real networks.
#[test]
fn the_program_reads_the_old_outputs_by_itself() {
    let source = chain_of_40();
    let node = Node::with_state(&source);
    let t = Temp::new("oldtrial");
    let record = TestChain::from_headers(source.read().unwrap().headers()).record(14);
    std::fs::write(t.0.join(TEST_START_FILE), record).unwrap();
    let run = read_old(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    let number = |key: &str| run.field("old: pieces=", key).parse::<u64>().unwrap();
    assert_eq!((number("pieces"), number("outputs"), number("at"), number("before")), (1, 5, 40, 20));
    assert_eq!(number("proof_bytes"), 5 * 675);
}
