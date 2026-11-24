//! Collecting the state: the program against nodes that have a real chain
//! of the Grin node's own code behind them and give its state out in
//! segments cut by the node's segmenter. Run with
//! `cargo test --features test-net`.
//!
//! The chains behind the nodes are thin ones: on the test network the
//! node's network code carries no message of more than some fifteen
//! kilobytes, so the state has to be small - four segments in all. Several
//! segments of outputs, arriving in any order, are tried without the
//! network in `segments_out_of_turn`, on a chain with thousands of outputs;
//! the choice between the large segments of outputs and the small ones in
//! `the_large_segments_are_asked_for_first`, on a longer one.
#![cfg(feature = "test-net")]
mod kit;

use fly_chain::schedule::Piece;
use fly_chain::state::{Arrived, Fetch, Took};
use fly_chain::TEST_START_FILE;
use fly_chain_headers::hash_bytes;
use fly_chain_headers::testkit::TestChain;
use fly_chain_state::testkit::Source;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{Segment, SegmentIdentifier};
use kit::{collect, hex, Node, Run, Temp};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

/// A thin chain of 40 blocks from the plain genesis block of the test
/// network, on a node that has pruned its files: it gives its state out at
/// height 20. Mined once; nothing here changes it.
fn shared() -> Arc<RwLock<Source>> {
    static SOURCE: OnceLock<Arc<RwLock<Source>>> = OnceLock::new();
    // The node's code reads the network from a setting of the thread it
    // runs on. The chain is mined on whichever test thread comes first;
    // every other one has to say for itself which network this is.
    grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::AutomatedTesting);
    SOURCE
        .get_or_init(|| {
            let source = Source::thin(40);
            source.compact();
            Arc::new(RwLock::new(source))
        })
        .clone()
}
/// Height of its archive header.
const ARCHIVE: u64 = 20;
/// A starting point below it: the lowest the header rules allow.
const START: u64 = 14;

/// A data directory with a starting point at `start` on `source`'s chain.
fn data(tag: &str, source: &Arc<RwLock<Source>>, start: u64) -> Temp {
    let t = Temp::new(tag);
    let record = TestChain::from_headers(source.read().unwrap().headers()).record(start);
    std::fs::write(t.0.join(TEST_START_FILE), record).unwrap();
    t
}

fn number(run: &Run, line: &str, key: &str) -> usize {
    run.field(line, key).parse().unwrap()
}

/// From a node, piece by piece, every piece asked for once; then from the
/// file, without asking any node; then with no node at all.
#[test]
fn the_state_is_collected_and_kept() {
    let source = shared();
    let (archive, unspent) = {
        let source = source.read().unwrap();
        (source.archive(), source.unspent_at(ARCHIVE).len())
    };
    assert_eq!((archive.height, unspent), (ARCHIVE, 5));
    let node = Node::with_state(&source);
    let t = data("state", &source, START);

    let run = collect(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(run.field("state:", "height"), ARCHIVE.to_string());
    assert_eq!(run.field("state:", "hash"), hex(&hash_bytes(&archive)));
    assert_eq!(run.field("state:", "kept"), "0");
    let segments = number(&run, "state:", "segments");
    assert_eq!(segments, 4, "one of the bitmap, one of outputs, two tails");
    assert_eq!(run.field("collected:", "height"), ARCHIVE.to_string());
    assert_eq!(number(&run, "collected:", "unspent"), unspent);
    assert_eq!(node.served.asked.load(Ordering::Relaxed), segments, "every piece was asked for once");
    assert_eq!(*node.served.output_heights.lock().unwrap(), vec![15], "the outputs in one large segment");

    // a restart has the state from the file: every piece passes again, and
    // no node is asked for anything
    let run = collect(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(number(&run, "state:", "kept"), segments);
    assert_eq!(run.field("state:", "cut_bytes"), "0");
    assert_eq!(number(&run, "collected:", "unspent"), unspent);
    assert_eq!(node.served.asked.load(Ordering::Relaxed), segments);

    // and with no node at all
    let run = collect(&t, &[], 30);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(number(&run, "collected:", "unspent"), unspent);

    // The same file in the data directory of another chain: it is the
    // state at a header that chain does not have. Nothing is done to it
    // until nodes are there and it is known what to collect instead.
    let other = Source::thin(50);
    other.compact();
    assert_ne!(other.blocks[20].hash(), source.read().unwrap().blocks[20].hash());
    let other = Arc::new(RwLock::new(other));
    let node2 = Node::with_state(&other);
    let t2 = data("foreign", &other, START);
    // the headers of that chain first, so that it has a header at the
    // height the file names
    assert_eq!(kit::follow(&t2, &[node2.addr], 60).code, 0);
    let file = t.0.join(fly_chain_state::store::FILE_NAME);
    let file2 = t2.0.join(fly_chain_state::store::FILE_NAME);
    std::fs::copy(&file, &file2).unwrap();
    let run = collect(&t2, &[], 4);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(!run.out.contains("state:"), "{}", run.out);
    assert_eq!(std::fs::read(&file2).unwrap(), std::fs::read(&file).unwrap(), "left as it was");
    let run = collect(&t2, &[node2.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(run.field("state:", "height"), "30");
    assert_eq!(run.field("state:", "kept"), "0");
    assert_eq!(run.field("collected:", "hash"), hex(&hash_bytes(&other.read().unwrap().archive())));
}

/// A node that sends a segment that is not the state at the verified
/// header is left for good. What it sent before that and was true - the
/// bitmap - is kept; an honest node finishes the work.
#[test]
fn a_node_that_sends_what_is_not_the_state_is_left() {
    let source = shared();
    let unspent = source.read().unwrap().unspent_at(ARCHIVE).len();
    let liar = Node::with_state(&source);
    liar.served.bend.store(true, Ordering::Relaxed);
    let t = data("liar", &source, START);

    let run = collect(&t, &[liar.addr], 10);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("a node sent a piece of the state that does not fit the verified header; it was left"), "{}", run.out);
    assert!(run.out.contains(" state=1/"), "the bitmap, which was true, and nothing after it:\n{}", run.out);
    assert!(!run.out.contains(" state=2/"), "{}", run.out);
    let asked = liar.served.asked.load(Ordering::Relaxed);
    assert_eq!(asked, 2, "the bitmap and the segment of outputs");
    assert_eq!(liar.peers.lock().unwrap().len(), 1, "it was not connected to again");

    let honest = Node::with_state(&source);
    let run = collect(&t, &[liar.addr, honest.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(run.field("state:", "kept"), "1", "the bitmap from the first run");
    assert_eq!(number(&run, "collected:", "unspent"), unspent);
    // The three pieces that were missing came from the two nodes between
    // them - the first one sends the tails as they are and may be asked
    // for one - but the segment of outputs can only have come from the
    // honest node.
    let from_honest = honest.served.asked.load(Ordering::Relaxed);
    let from_liar = liar.served.asked.load(Ordering::Relaxed) - asked;
    assert!(from_honest >= 1 && from_honest + from_liar >= 3, "{from_honest} and {from_liar}");
}

/// A node that does not answer is not waited for without end: its pieces
/// go to another node, and after three unanswered requests in a row it is
/// left - for a while, not for good.
#[test]
fn a_node_that_does_not_answer_is_not_waited_for() {
    let source = shared();
    let unspent = source.read().unwrap().unspent_at(ARCHIVE).len();
    let mute = Node::with_state(&source);
    mute.served.limit.store(0, Ordering::Relaxed);
    let t = data("mute", &source, START);

    let run = collect(&t, &[mute.addr], 12);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains(" state=0/"), "{}", run.out);
    assert_eq!(mute.served.asked.load(Ordering::Relaxed), 3, "the first piece, three times; then the node was left\n{}", run.out);
    let left = run.out.lines().skip_while(|line| !line.contains("peers=1")).any(|line| line.contains("peers=0"));
    assert!(left, "{}", run.out);
    assert_eq!(mute.peers.lock().unwrap().len(), 1, "not for good, but not connected to again at once");

    let honest = Node::with_state(&source);
    let run = collect(&t, &[mute.addr, honest.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(number(&run, "collected:", "unspent"), unspent);
}

/// A node that gives the output MMR only in the segments nodes exchange
/// with one another: the large one it is asked for first gets silence,
/// and then the small ones are asked for. The node is not left for it.
#[test]
fn a_node_that_gives_only_small_segments_is_asked_for_those() {
    let source = shared();
    let unspent = source.read().unwrap().unspent_at(ARCHIVE).len();
    let node = Node::with_state(&source);
    node.served.max_output_height.store(11, Ordering::Relaxed);
    let t = data("small-only", &source, START);

    let run = collect(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(number(&run, "collected:", "unspent"), unspent);
    assert_eq!(*node.served.output_heights.lock().unwrap(), vec![15, 11], "the large one once, then the small one");
    assert_eq!(node.served.asked.load(Ordering::Relaxed), 5, "the four pieces and the one that was not given");
    let left = run.out.lines().skip_while(|line| !line.contains("peers=1")).any(|line| line.contains("peers=0"));
    assert!(!left, "{}", run.out);
    assert_eq!(node.peers.lock().unwrap().len(), 1, "one connection, kept");

    // the file is in small segments; a node that gives large ones is not
    // asked for anything
    let other = Node::with_state(&source);
    let run = collect(&t, &[other.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(number(&run, "state:", "kept"), 4);
    assert_eq!(other.served.asked.load(Ordering::Relaxed), 0);
}

/// Collecting that was cut short goes on from the file: what is there is
/// not asked for again.
#[test]
fn collecting_goes_on_after_a_restart() {
    let source = shared();
    let unspent = source.read().unwrap().unspent_at(ARCHIVE).len();
    let node = Node::with_state(&source);
    node.served.limit.store(2, Ordering::Relaxed);
    let t = data("resume", &source, START);

    let run = collect(&t, &[node.addr], 8);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains(" state=2/"), "{}", run.out);
    assert_eq!(node.served.answered.load(Ordering::Relaxed), 2);

    node.served.limit.store(usize::MAX, Ordering::Relaxed);
    let run = collect(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(run.field("state:", "kept"), "2");
    assert_eq!(number(&run, "collected:", "unspent"), unspent);
    assert_eq!(node.served.answered.load(Ordering::Relaxed), number(&run, "state:", "segments"), "two then, the rest now");
}

/// Nodes give their state out only at the archive header they have now.
/// When the chain has grown past the next one, what was collected at the
/// old one cannot be finished: collecting begins again at the new one.
#[test]
fn collecting_begins_again_when_the_network_moves_on() {
    let source = Source::thin(40);
    source.compact();
    let source = Arc::new(RwLock::new(source));
    assert_eq!(source.read().unwrap().archive().height, 20);
    let node = Node::with_state(&source);
    node.served.limit.store(1, Ordering::Relaxed);
    let t = data("moves", &source, START);

    let run = collect(&t, &[node.addr], 6);
    assert_eq!(run.code, 1, "{}", run.out);
    assert_eq!(run.field("state: height", "height"), "20");
    assert!(run.out.contains(" state=1/"), "{}", run.out);

    {
        let mut source = source.write().unwrap();
        source.grow(10);
        source.compact();
    }
    let (archive, unspent, headers) = {
        let source = source.read().unwrap();
        (source.archive(), source.unspent_at(30).len(), source.headers())
    };
    assert_eq!(archive.height, 30);
    node.set(&headers);
    node.served.limit.store(usize::MAX, Ordering::Relaxed);
    let run = collect(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("state: the network moved on from height 20; begun again"), "{}", run.out);
    assert_eq!(run.field("state: height", "height"), "30");
    assert_eq!(run.field("state: height", "kept"), "0");
    assert_eq!(run.field("collected:", "hash"), hex(&hash_bytes(&archive)));
    assert_eq!(number(&run, "collected:", "unspent"), unspent);

    // a state that is complete is kept when the network moves on: it is
    // not what nodes give out any more, and it does not need to be
    let asked = node.served.asked.load(Ordering::Relaxed);
    {
        let mut source = source.write().unwrap();
        source.grow(10);
        source.compact();
        assert_eq!(source.archive().height, 40);
        node.set(&source.headers());
    }
    let run = collect(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(run.field("collected:", "height"), "30");
    assert_eq!(run.field("state: height", "kept"), "4");
    assert_eq!(node.served.asked.load(Ordering::Relaxed), asked);
}

/// The state cannot be collected at a header below the starting point: no
/// verified header is there to check it against. And a node that does not
/// give its state out in segments is not asked for it. Both are said.
#[test]
fn what_stands_in_the_way_is_said() {
    let source = shared();
    let node = Node::with_state(&source);
    let t = data("late", &source, 25);
    let run = collect(&t, &[node.addr], 5);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(
        run.out.contains("nodes give their state out at height 20, below this program's starting point (25); it can be collected in 10 blocks"),
        "{}",
        run.out
    );
    assert_eq!(node.served.asked.load(Ordering::Relaxed), 0);

    let headers = source.read().unwrap().headers();
    let old = Node::start(&headers);
    let t = data("old", &source, START);
    let run = collect(&t, &[old.addr], 5);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("no connected node gives its state out in segments"), "{}", run.out);
    assert_eq!(old.served.asked.load(Ordering::Relaxed), 0);

    // Eight such nodes take every place there is while the state is
    // wanted; after a while one of them is left to make room, and the node
    // that comes instead has it.
    let more: Vec<Node> = (0..7).map(|_| Node::start(&headers)).collect();
    let mut addrs = vec![old.addr];
    addrs.extend(more.iter().map(|node| node.addr));
    addrs.push(node.addr);
    let run = collect(&t, &addrs, 40);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("peers=8") && !run.out.contains("peers=9"), "{}", run.out);
    assert_eq!(old.served.asked.load(Ordering::Relaxed) + more.iter().map(|node| node.served.asked.load(Ordering::Relaxed)).sum::<usize>(), 0);
    assert_eq!(node.served.asked.load(Ordering::Relaxed), 4);
}

/// Segments of the output MMR are asked for ahead and may arrive in any
/// order. One that comes before its turn is checked against the header at
/// once and waits; one that nobody asked this peer for, or that is for
/// another header, is not looked at.
#[test]
fn segments_out_of_turn() {
    let source = Source::mine(236);
    let archive = source.archive();
    let block = archive.hash();
    let segmenter = source.chain.segmenter().unwrap();
    let dir = Temp::new("fetch");
    let (a, b): (SocketAddr, SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
    let output = |idx| SegmentIdentifier { height: 11, idx };
    let step = Duration::from_millis(300);
    let mut now = Instant::now();

    // in the segments nodes exchange: this chain is two of them
    let mut fetch = Fetch::open_in(&dir.0, archive.clone(), false, 11).unwrap();
    let (total, _) = fetch.progress();
    // the bitmap: one segment, asked of one peer
    let id = SegmentIdentifier { height: 9, idx: 0 };
    assert_eq!(fetch.plan(now, &[a, b]), vec![(a, Piece::Bitmap(id))]);
    let (segment, output_root) = segmenter.bitmap_segment(id).unwrap();
    let bitmap = || Arrived::Bitmap {
        output_root,
        segment: segment.clone(),
    };
    assert_eq!(fetch.arrived(b, block, bitmap()), Took::Unasked, "from a peer that was not asked");
    assert_eq!(fetch.arrived(a, Hash::from_vec(&[1; 32]), bitmap()), Took::Unasked, "for another header");
    assert_eq!(fetch.arrived(a, block, bitmap()), Took::Taken);
    assert_eq!(fetch.arrived(a, block, bitmap()), Took::Unasked, "twice");
    assert_eq!(fetch.progress(), (total, 1));
    // a peer that goes on sending what nobody asked it for
    let pushy: SocketAddr = "127.0.0.1:3".parse().unwrap();
    for _ in 0..fly_chain::schedule::MAX_STRAY {
        assert_eq!(fetch.arrived(pushy, block, bitmap()), Took::Unasked);
    }
    assert_eq!(fetch.arrived(pushy, block, bitmap()), Took::Pushy);

    // the outputs: both segments are asked for, one of each peer
    now += step;
    assert_eq!(fetch.plan(now, &[a, b]), vec![(a, Piece::Output(output(0))), (b, Piece::Output(output(1)))]);
    let good = |idx| segmenter.output_segment(output(idx)).unwrap().0;
    // the second comes first, and it is not the state: refused at once
    let (id, hash_pos, hashes, leaf_pos, mut leaves, proof) = good(1).parts();
    for leaf in &mut leaves {
        leaf.commit.0[9] ^= 1;
    }
    let bent = Segment::from_parts(id, hash_pos, hashes, leaf_pos, leaves, proof);
    assert_eq!(fetch.arrived(b, block, Arrived::Output(bent)), Took::Invalid);
    // it is asked for again, of the other peer
    now += step;
    assert_eq!(fetch.plan(now, &[a]), vec![(a, Piece::Output(output(1)))]);
    assert_eq!(fetch.arrived(a, block, Arrived::Output(good(1))), Took::Taken, "it passes the check and waits for its turn");
    assert_eq!(fetch.progress(), (total, 1), "the collector has not been given it yet");
    now += step;
    assert_eq!(fetch.plan(now, &[a, b]), vec![], "nothing more to ask for until the first segment comes");
    assert_eq!(fetch.arrived(a, block, Arrived::Output(good(0))), Took::Taken);
    assert_eq!(fetch.progress(), (total, 3), "the first, and the one that waited");

    // the two tails
    now += step;
    let plan = fetch.plan(now, &[a, b]);
    let [(from, Piece::RangeproofTail(id))] = plan.as_slice() else { panic!("{plan:?}") };
    assert_eq!(fetch.arrived(*from, block, Arrived::Rangeproof(segmenter.rangeproof_segment(*id).unwrap())), Took::Taken);
    now += step;
    let plan = fetch.plan(now, &[a, b]);
    let [(from, Piece::KernelTail(id))] = plan.as_slice() else { panic!("{plan:?}") };
    assert!(fetch.state().is_none());
    assert_eq!(fetch.arrived(*from, block, Arrived::Kernel(segmenter.kernel_segment(*id).unwrap())), Took::Taken);
    let unspent = source.unspent_at(archive.height).len();
    assert_eq!(fetch.state().unwrap().unspent.len(), unspent);
    assert_eq!(fetch.progress(), (total, total));
    now += step;
    assert_eq!(fetch.plan(now, &[a, b]), vec![]);
    drop(fetch);

    // the file gives it all back - in the segments it was collected in,
    // whatever a new file would be begun in
    let fetch = Fetch::open(&dir.0, archive, false).unwrap();
    assert_eq!(fetch.opened().kept, total);
    assert_eq!(fetch.state().unwrap().unspent.len(), unspent);
}

/// The output MMR is asked for in large segments first: fewer requests
/// for the same tree. A node is not bound to give those. When the first
/// that were asked for went unanswered and none has come from anybody,
/// the small ones every node gives are asked for from there on, and
/// nobody is held to have been silent. Once a large one has come the
/// large ones stay: segments of two heights do not go together. Either
/// way the state is the same.
#[test]
fn the_large_segments_are_asked_for_first() {
    use fly_chain::schedule::SEGMENT_TIMEOUT;
    let source = Source::mine(476);
    let archive = source.archive();
    let block = archive.hash();
    let segmenter = source.chain.segmenter().unwrap();
    let (a, b): (SocketAddr, SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
    let large = |idx| SegmentIdentifier { height: 12, idx };
    let small = |idx| SegmentIdentifier { height: 11, idx };
    let give = |id| Arrived::Output(segmenter.output_segment(id).unwrap().0);
    let step = Duration::from_millis(300);
    let unspent = source.unspent_at(archive.height).len();
    // the bitmap, and the fetch stands before the output MMR
    let begin = |fetch: &mut Fetch, now: &mut Instant| {
        let id = SegmentIdentifier { height: 9, idx: 0 };
        assert_eq!(fetch.plan(*now, &[a, b]), vec![(a, Piece::Bitmap(id))]);
        let (segment, output_root) = segmenter.bitmap_segment(id).unwrap();
        assert_eq!(fetch.arrived(a, block, Arrived::Bitmap { output_root, segment }), Took::Taken);
        *now += step;
    };
    // the two tails, and the state is there
    let end = |fetch: &mut Fetch, now: &mut Instant| {
        *now += step;
        let plan = fetch.plan(*now, &[a, b]);
        let [(from, Piece::RangeproofTail(id))] = plan.as_slice() else { panic!("{plan:?}") };
        assert_eq!(fetch.arrived(*from, block, Arrived::Rangeproof(segmenter.rangeproof_segment(*id).unwrap())), Took::Taken);
        *now += step;
        let plan = fetch.plan(*now, &[a, b]);
        let [(from, Piece::KernelTail(id))] = plan.as_slice() else { panic!("{plan:?}") };
        assert_eq!(fetch.arrived(*from, block, Arrived::Kernel(segmenter.kernel_segment(*id).unwrap())), Took::Taken);
        let state = fetch.take_state().unwrap();
        (state.unspent.clone(), state.outputs.clone(), state.bitmap.root())
    };

    // a new file: the largest segments nodes give
    let dir = Temp::new("large-default");
    let fetch = Fetch::open(&dir.0, archive.clone(), false).unwrap();
    assert_eq!(fetch.output_height(), Some(15));
    drop(fetch);

    // Nobody answers the large ones.
    let dir = Temp::new("large-unanswered");
    let mut now = Instant::now();
    let mut fetch = Fetch::open_in(&dir.0, archive.clone(), false, 12).unwrap();
    assert_eq!(fetch.output_height(), Some(12));
    let (total, _) = fetch.progress();
    assert_eq!(total, 5, "the bitmap, two large segments of outputs, two tails");
    begin(&mut fetch, &mut now);
    assert_eq!(fetch.plan(now, &[a, b]), vec![(a, Piece::Output(large(0))), (b, Piece::Output(large(1)))]);
    // until the time for an answer is over they are waited for
    now += SEGMENT_TIMEOUT;
    assert_eq!(fetch.expire(now), vec![]);
    assert_eq!((fetch.output_height(), fetch.progress()), (Some(12), (5, 1)));
    assert_eq!(fetch.plan(now, &[a, b]), vec![]);
    // then the small ones are asked for: three of them, of the same peers
    now += Duration::from_millis(1);
    assert_eq!(fetch.expire(now), vec![], "nobody is left for it");
    assert_eq!((fetch.output_height(), fetch.progress()), (Some(11), (6, 1)));
    assert_eq!(fetch.plan(now, &[a, b]), vec![(a, Piece::Output(small(0))), (b, Piece::Output(small(1)))]);
    // a large one that comes now was taken back: nobody waits for it
    assert_eq!(fetch.arrived(a, block, give(large(0))), Took::Unasked);
    assert_eq!(fetch.progress(), (6, 1));
    // and no silence was counted: the requests that follow may go
    // unanswered twice more before anybody is left
    for _ in 0..2 {
        now += SEGMENT_TIMEOUT + Duration::from_millis(1);
        assert_eq!(fetch.expire(now), vec![]);
        assert_eq!(fetch.plan(now, &[a, b]).len(), 2);
    }
    assert_eq!(fetch.output_height(), Some(11), "and the choice is not made again");
    now += SEGMENT_TIMEOUT + Duration::from_millis(1);
    let mut left = fetch.expire(now);
    left.sort();
    assert_eq!(left, vec![a, b], "three in a row");
    for idx in 0..3 {
        now += step;
        let plan = fetch.plan(now, &[a]);
        assert!(plan.contains(&(a, Piece::Output(small(idx)))), "{plan:?}");
        assert_eq!(fetch.arrived(a, block, give(small(idx))), Took::Taken);
    }
    assert_eq!(fetch.progress(), (6, 4));
    let from_small = end(&mut fetch, &mut now);
    assert_eq!(from_small.0.len(), unspent);
    drop(fetch);
    // the file was written in small segments and is read in them
    let mut fetch = Fetch::open_in(&dir.0, archive.clone(), false, 12).unwrap();
    assert_eq!(fetch.opened().kept, 6);
    assert_eq!(fetch.take_state().unwrap().unspent, from_small.0);
    drop(fetch);

    // One large segment has come: the large ones stay, and the peer that
    // did not answer is the one that is counted silent.
    let dir = Temp::new("large-answered");
    let mut now = Instant::now();
    let mut fetch = Fetch::open_in(&dir.0, archive.clone(), false, 12).unwrap();
    begin(&mut fetch, &mut now);
    assert_eq!(fetch.plan(now, &[a, b]), vec![(a, Piece::Output(large(0))), (b, Piece::Output(large(1)))]);
    assert_eq!(fetch.arrived(b, block, give(large(1))), Took::Taken, "before its turn: it waits");
    assert_eq!(fetch.progress(), (5, 1));
    for _ in 0..2 {
        now += SEGMENT_TIMEOUT + Duration::from_millis(1);
        assert_eq!(fetch.expire(now), vec![]);
        assert_eq!(fetch.output_height(), Some(12));
        // with nobody else to ask, the same peer again
        assert_eq!(fetch.plan(now, &[a]), vec![(a, Piece::Output(large(0)))]);
    }
    now += SEGMENT_TIMEOUT + Duration::from_millis(1);
    assert_eq!(fetch.expire(now), vec![a], "three in a row");
    assert_eq!(fetch.output_height(), Some(12));
    assert_eq!(fetch.plan(now, &[a, b]), vec![(b, Piece::Output(large(0)))], "of the other peer");
    // a small one is not what was asked for
    assert_eq!(fetch.arrived(b, block, give(small(0))), Took::Unasked);
    assert_eq!(fetch.arrived(b, block, give(large(0))), Took::Taken);
    assert_eq!(fetch.progress(), (5, 3), "the first, and the one that waited");
    drop(fetch);
    // a restart goes on in large segments, whatever it would begin in
    let mut fetch = Fetch::open_in(&dir.0, archive.clone(), false, 11).unwrap();
    assert_eq!((fetch.opened().kept, fetch.output_height(), fetch.progress()), (3, Some(12), (5, 3)));
    let from_large = end(&mut fetch, &mut now);
    assert!(from_large == from_small, "the same state from segments of either height");

    // The first large one has been taken: a later one that goes unanswered
    // changes nothing.
    let dir = Temp::new("large-begun");
    let mut now = Instant::now();
    let mut fetch = Fetch::open_in(&dir.0, archive, false, 12).unwrap();
    begin(&mut fetch, &mut now);
    assert_eq!(fetch.plan(now, &[a, b]), vec![(a, Piece::Output(large(0))), (b, Piece::Output(large(1)))]);
    assert_eq!(fetch.arrived(a, block, give(large(0))), Took::Taken);
    now += SEGMENT_TIMEOUT + Duration::from_millis(1);
    assert_eq!(fetch.expire(now), vec![]);
    assert_eq!((fetch.output_height(), fetch.progress()), (Some(12), (5, 2)));
    assert_eq!(fetch.plan(now, &[a, b]), vec![(a, Piece::Output(large(1)))]);
}

/// Reopening a completed local archive does not need a peer. A reader
/// holding the blocks file briefly should not require a process restart.
#[test]
fn an_existing_archive_resumes_after_a_local_lock_is_released() {
    use fly_chain_headers::Net;
    use fly_chain_state::store::Store;
    use std::sync::atomic::AtomicBool;

    let source = shared();
    let dir = data("unlock-blocks", &source, ARCHIVE);
    {
        let source = source.read().unwrap();
        let mut store = Store::begin(&dir.0, source.archive()).unwrap();
        let (total, _) = store.progress();
        for _ in 0..total {
            source.serve_store(&mut store).unwrap();
        }
        assert!(store.finish().is_some());
    }
    let file = std::fs::File::create(dir.0.join(fly_chain_state::blocks::FILE_NAME)).unwrap();
    file.try_lock().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let net = Net::Automated;
    let (view, _events, worker) = fly_chain::start(
        net, net.genesis_hash(), dir.0.clone(), vec![], false, String::new(), stop.clone(),
    ).unwrap();
    kit::wait_for("archive reopened with the blocks file busy", || {
        let view = view.lock().unwrap();
        view.state.as_ref().is_some_and(|s| s.complete) && view.blocks.is_none()
    });
    drop(file);
    let until = Instant::now() + Duration::from_secs(10);
    let resumed = loop {
        if view.lock().unwrap().blocks.as_ref().is_some_and(|b| b.base == ARCHIVE && b.height == ARCHIVE) {
            break true;
        }
        if Instant::now() >= until { break false; }
        std::thread::sleep(Duration::from_millis(50));
    };
    stop.store(true, Ordering::Relaxed);
    worker.join().unwrap();
    assert!(resumed, "the locally verified archive should become usable after the lock is released");
}
