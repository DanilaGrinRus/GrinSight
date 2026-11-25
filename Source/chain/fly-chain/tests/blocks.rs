//! Following the chain with blocks: the program against nodes that have a
//! real chain of the Grin node's own code behind them. Run with
//! `cargo test --features test-net`.
#![cfg(feature = "test-net")]
mod kit;

use fly_chain::follow::{Follow, Got, WINDOW};
use fly_chain::TEST_START_FILE;
use fly_chain_headers::chain::HeaderChain;
use fly_chain_headers::testkit::TestChain;
use fly_chain_headers::{hash_bytes, Net};
use fly_chain_state::testkit::Source;
use fly_paycore_chain_pipe::{Config, PipeChain};
use fly_paycore_chain_port::{ChainFeed, Level, Posted, Step, Tip, Unknown};
use grin_core::core::pmmr;
use kit::{apply, hex, wait_for, Node, Run, Temp, FLY};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// A thin chain of 40 blocks on a node that has pruned its files: the
/// state is given out at 20, and the blocks 21 to 40 lead to the tip.
fn chain_of_40() -> Arc<RwLock<Source>> {
    let source = Source::thin(40);
    source.compact();
    Arc::new(RwLock::new(source))
}

fn data(tag: &str, source: &Arc<RwLock<Source>>) -> Temp {
    let t = Temp::new(tag);
    let record = TestChain::from_headers(source.read().unwrap().headers()).record(14);
    std::fs::write(t.0.join(TEST_START_FILE), record).unwrap();
    t
}

fn number(run: &Run, line: &str, key: &str) -> u64 {
    run.field(line, key).parse().unwrap()
}

/// From the collected state to the tip, every block asked for once; again
/// from the file without asking; on as the chain grows; and over to
/// another branch when the chain moves, taking back what is not on it.
#[test]
fn blocks_are_applied_to_the_tip() {
    let source = chain_of_40();
    let node = Node::with_state(&source);
    let t = data("blocks", &source);
    let tip = |source: &Arc<RwLock<Source>>| {
        let source = source.read().unwrap();
        let last = source.blocks.last().unwrap().header.clone();
        (last.height, hex(&hash_bytes(&last)), source.unspent_at(last.height).len() as u64)
    };

    let run = apply(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!((number(&run, "blocks:", "base"), number(&run, "blocks:", "kept")), (20, 0));
    let (height, hash, unspent) = tip(&source);
    assert_eq!(height, 40);
    assert_eq!((number(&run, "applied:", "height"), run.field("applied:", "hash"), number(&run, "applied:", "unspent")), (40, hash, unspent));
    assert_eq!(number(&run, "applied:", "blocks"), 20);
    assert_eq!(node.served.blocks_asked.load(Ordering::Relaxed), 20, "every block was asked for once");

    // a restart applies the blocks from the file again and asks for none
    let run = apply(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!((number(&run, "blocks:", "kept"), number(&run, "blocks:", "cut_bytes")), (20, 0));
    assert_eq!(number(&run, "applied:", "unspent"), unspent);
    assert_eq!(node.served.blocks_asked.load(Ordering::Relaxed), 20);

    // the chain grows
    source.write().unwrap().grow(5);
    node.set(&source.read().unwrap().headers());
    let run = apply(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    let (height, hash, unspent) = tip(&source);
    assert_eq!(height, 45);
    assert_eq!((number(&run, "applied:", "height"), run.field("applied:", "hash"), number(&run, "applied:", "unspent")), (45, hash, unspent));
    assert_eq!(node.served.blocks_asked.load(Ordering::Relaxed), 25);

    // The chain moves to another branch that leaves this one at 42: the
    // blocks 43 to 45 are taken back, and the six of the branch applied.
    source.write().unwrap().branch(42, 6);
    node.set(&source.read().unwrap().headers());
    let run = apply(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("the chain moved to another branch; the blocks of the old one were taken back"), "{}", run.out);
    let (height, hash, unspent) = tip(&source);
    assert_eq!(height, 48);
    assert_eq!((number(&run, "applied:", "height"), run.field("applied:", "hash"), number(&run, "applied:", "unspent")), (48, hash, unspent));
    assert_eq!(number(&run, "blocks:", "kept"), 25, "the file still held the old branch when it was opened");
    assert_eq!(node.served.blocks_asked.load(Ordering::Relaxed), 31);
    // And the file now holds the new branch. With no node there, the
    // blocks are applied from it all the same - but nobody says that this
    // is the tip, and the program does not say so either.
    let run = apply(&t, &[], 4);
    assert_eq!((run.code, number(&run, "blocks:", "kept")), (1, 28), "{}", run.out);
    assert!(run.out.contains(" blocks=48/48") && run.out.contains("blocks applied to 48;"), "{}", run.out);
    assert!(!run.out.contains("applied:"), "{}", run.out);
}

/// A node that sends, under a verified header, a block that is not that
/// header's block is left for good; an honest node goes on from there.
#[test]
fn a_node_that_sends_another_block_is_left() {
    let source = chain_of_40();
    let liar = Node::with_state(&source);
    liar.served.bend_blocks.store(true, Ordering::Relaxed);
    let t = data("badblock", &source);

    let run = apply(&t, &[liar.addr], 12);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("for the verified header at 21"), "{}", run.out);
    assert!(run.out.contains("it was left"), "{}", run.out);
    assert!(run.out.contains(" blocks=20/40"), "nothing was applied:\n{}", run.out);
    assert!(!run.out.contains(" blocks=21/40"), "{}", run.out);
    assert_eq!(liar.peers.lock().unwrap().len(), 1, "it was not connected to again");
    assert!(liar.served.blocks_asked.load(Ordering::Relaxed) <= 2, "and not asked for more");

    let honest = Node::with_state(&source);
    let run = apply(&t, &[liar.addr, honest.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(number(&run, "applied:", "height"), 40);
    assert_eq!(honest.served.blocks_asked.load(Ordering::Relaxed), 20);
}

/// The wallet is answered from the blocks that were applied: where to
/// start, block after block, nothing new at the tip, a step back for a
/// block that is not on the chain, a new start for a position below the
/// blocks - and "unknown", never "nothing new", for anything else.
#[test]
fn the_wallet_is_given_the_blocks() {
    let source = chain_of_40();
    let node = Node::with_state(&source);
    let t = data("feed", &source);
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
    // before anything is collected: unknown, and no position leads anywhere
    let first = chain.status().unwrap();
    assert!(matches!(first.level, Level::Unknown | Level::Behind | Level::AtTip));
    wait_for("the blocks", || chain.status().is_some_and(|s| s.level == Level::AtTip));

    let (blocks, headers) = {
        let source = source.read().unwrap();
        (source.blocks.clone(), source.headers())
    };
    let tip_of = |height: usize| Tip { height: height as u64, hash: hash_bytes(&headers[height]) };
    let status = chain.status().unwrap();
    assert_eq!((status.level, status.tip, status.selected), (Level::AtTip, Some(tip_of(40)), None), "no tip is called selected");
    assert_eq!((status.confirmed_time, status.k_conf, status.rangeproofs_authenticated), (None, 10, true));

    // a wallet without a position starts at the archive header
    assert_eq!(chain.next(None), Ok(Step::Reanchor(tip_of(20))));
    // and is given every block above it, as the block is
    let mut at = tip_of(20);
    for height in 21..=40usize {
        let Ok(Step::Block(facts)) = chain.next(Some(at)) else { panic!("block {height}") };
        let block = &blocks[height];
        assert_eq!((facts.height, facts.hash), (height as u64, hash_bytes(&block.header)));
        let first = headers[height - 1].output_mmr_count();
        assert_eq!(facts.outputs.len(), block.outputs().len());
        for (i, (fact, output)) in facts.outputs.iter().zip(block.outputs()).enumerate() {
            let proof = output.proof();
            assert_eq!(fact.commit, output.commitment().0);
            assert_eq!(fact.proof, proof.proof[..proof.plen].to_vec());
            assert_eq!(fact.pos, pmmr::insertion_to_pmmr_index(first + i as u64));
            assert_eq!(fact.coinbase, output.is_coinbase());
        }
        let inputs: Vec<grin_core::core::CommitWrapper> = block.inputs().into();
        assert_eq!(facts.inputs, inputs.iter().map(|i| i.commitment().0).collect::<Vec<_>>());
        assert_eq!(facts.kernels, block.kernels().iter().map(|k| k.excess.0).collect::<Vec<_>>());
        assert!(facts.v_delta.is_empty());
        at = tip_of(height);
    }
    assert_eq!(chain.next(Some(at)), Ok(Step::Nothing), "at the tip");

    // a block that is not on the chain: one step back, and again from there
    let strange = Tip { height: 30, hash: [7; 32] };
    assert_eq!(chain.next(Some(strange)), Ok(Step::Rollback { to: 29 }));
    assert!(matches!(chain.next(Some(tip_of(29))), Ok(Step::Block(facts)) if facts.height == 30));
    // at the archive header itself, or below it, no step back leads anywhere
    assert_eq!(chain.next(Some(Tip { height: 20, hash: [7; 32] })), Ok(Step::Reanchor(tip_of(20))));
    assert_eq!(chain.next(Some(tip_of(15))), Ok(Step::ReanchorExtending(tip_of(20))));
    assert_eq!(chain.next(Some(Tip { height: 15, hash: [7; 32] })), Ok(Step::Reanchor(tip_of(20))));
    // a position above what has been applied: unknown
    assert_eq!(chain.next(Some(Tip { height: 41, hash: [7; 32] })), Err(Unknown));
    assert_eq!(chain.post(&[1, 2, 3]), Posted::Rejected, "three bytes are not a transaction: refused here, and nothing was sent anywhere");

    // The chain grows, and for a while the node gives out the new header
    // but not the block: the program is behind, and a wallet at the old
    // tip is not told "nothing new".
    node.served.mute_blocks.store(true, Ordering::Relaxed);
    source.write().unwrap().grow(1);
    node.set(&source.read().unwrap().headers());
    node.announce();
    wait_for("the new header", || chain.status().is_some_and(|s| s.level == Level::Behind));
    assert_eq!(chain.status().unwrap().tip, Some(at), "what can be handed over ends at the old tip");
    assert_eq!(chain.next(Some(at)), Err(Unknown));
    // then the block comes: the wallet at the old tip is given it
    node.served.mute_blocks.store(false, Ordering::Relaxed);
    let new = source.read().unwrap().blocks[41].header.clone();
    wait_for("the new block", || chain.status().is_some_and(|s| s.tip.is_some_and(|tip| tip.height == 41)));
    assert!(matches!(chain.next(Some(at)), Ok(Step::Block(facts)) if facts.hash == hash_bytes(&new)));
    let text = chain.problem().unwrap();
    assert!(text.contains("blocks applied to the tip, 41") && text.contains("nobody vouches for it"), "{text}");
}

/// Blocks are asked for ahead and may arrive in any order. One that comes
/// before its turn waits only under the verified header itself; one that
/// nobody asked this peer for is not looked at.
#[test]
fn blocks_out_of_turn() -> Result<(), Box<dyn std::error::Error>> {
    let source = Source::thin(40);
    source.compact();
    let headers = source.headers();
    let dir = Temp::new("follow");
    let (mut chain, _) = HeaderChain::open(&dir.0, Net::Automated, &TestChain::from_headers(headers.clone()).record(14)).unwrap();
    chain.offer(&headers[15..], 2_000_000_000).unwrap();
    assert_eq!(chain.tip().height, 40);
    let mut follow = Follow::open(&dir.0, source.collect(), &chain).unwrap();
    assert_eq!((follow.base(), follow.header().height), (20, 20));
    let (a, b): (std::net::SocketAddr, std::net::SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
    let step = Duration::from_millis(300);
    let mut now = std::time::Instant::now();
    let block = |height: usize| source.blocks[height].clone();
    let tip_of = |height: usize| Tip { height: height as u64, hash: hash_bytes(&headers[height]) };

    // one request to each peer in a round, the next blocks in order, each
    // by the hash of its verified header
    assert_eq!(follow.plan(now, &chain, &[a, b]), vec![(a, 21, hash_bytes(&headers[21])), (b, 22, hash_bytes(&headers[22]))]);
    now += step;
    assert_eq!(follow.plan(now, &chain, &[a, b]), vec![(a, 23, hash_bytes(&headers[23])), (b, 24, hash_bytes(&headers[24]))]);
    // from a peer that was not asked for it, and one never asked for
    assert_eq!(follow.arrived(b, block(21), &chain), Got::Unasked);
    assert_eq!(follow.arrived(a, block(30), &chain), Got::Unasked);
    // The second comes first. Under a header that has the verified hash
    // and says something else it does not wait...
    let mut other = block(22);
    other.header.total_kernel_offset = headers[21].total_kernel_offset.clone();
    assert_eq!(follow.arrived(b, other, &chain), Got::Invalid);
    // ...asked for again, as it is, it does
    now += step;
    assert_eq!(follow.plan(now, &chain, &[a]), vec![(a, 22, hash_bytes(&headers[22]))]);
    assert_eq!(follow.arrived(a, block(22), &chain), Got::Taken);
    assert_eq!(follow.arrived(b, block(24), &chain), Got::Taken);
    assert_eq!(follow.header().height, 20, "nothing is applied before the first comes");
    // while the wallet stands where the blocks end, short of the tip, it
    // is not told "nothing new"
    assert_eq!(follow.step(Some(tip_of(20)), &chain, false), Err(Unknown));
    assert_eq!(follow.arrived(a, block(21), &chain), Got::Taken);
    assert_eq!(follow.header().height, 22, "the first, and the one that waited behind it");
    assert_eq!(follow.arrived(a, block(23), &chain), Got::Taken);
    assert_eq!(follow.header().height, 24);
    assert_eq!(follow.unspent(), source.unspent_at(24).len());
    assert!(matches!(follow.step(Some(tip_of(23)), &chain, false), Ok(Step::Block(facts)) if facts.height == 24));
    assert_eq!(follow.step(Some(tip_of(24)), &chain, false), Err(Unknown));
    assert_eq!(follow.step(Some(tip_of(24)), &chain, true), Ok(Step::Nothing));
    // a window ahead and no more
    now += step;
    let mut asked = Vec::new();
    for _ in 0..40 {
        asked.extend(follow.plan(now, &chain, &[a, b]).into_iter().map(|(_, height, _)| height));
        now += step;
    }
    assert_eq!(asked, (25..25 + 8).collect::<Vec<u64>>(), "four to each of two peers; the window is {WINDOW}");
    // a peer that keeps sending blocks nobody asked it for
    let pushy: std::net::SocketAddr = "127.0.0.1:3".parse().unwrap();
    for _ in 0..fly_chain::schedule::MAX_STRAY {
        assert_eq!(follow.arrived(pushy, block(30), &chain), Got::Unasked);
    }
    assert_eq!(follow.arrived(pushy, block(30), &chain), Got::Pushy);

    // The header worker has switched; block housekeeping has not run yet.
    // A wallet at the common prefix must wait for the new branch's body.
    let mut alt = TestChain::from_headers(headers.clone()).fork_at(23);
    alt.mine_salted(22, 60, 173);
    let tail = alt.headers.get(24..).ok_or("fixture branch")?;
    chain.offer(tail, 2_000_000_000)?;
    assert_eq!(chain.hash_at(24), Some(hash_bytes(tail.first().ok_or("fixture successor")?)));
    assert_ne!(chain.hash_at(24), Some(tip_of(24).hash));
    assert!(matches!(follow.step(Some(tip_of(23)), &chain, false), Err(Unknown)));
    Ok(())
}

/// While there is much to fetch - the state, a long run of blocks - more
/// nodes are kept connected than otherwise: no node is asked faster, there
/// are more of them to ask. With everything on file and nothing to fetch,
/// three are enough.
#[test]
fn more_nodes_are_asked_while_there_is_much_to_fetch() {
    let source = chain_of_40();
    let six = || (0..6).map(|_| Node::with_state(&source)).collect::<Vec<Node>>();
    let addrs = |nodes: &[Node]| nodes.iter().map(|node| node.addr).collect::<Vec<std::net::SocketAddr>>();
    let connected = |nodes: &[Node]| nodes.iter().map(|node| node.peers.lock().unwrap().len()).collect::<Vec<usize>>();

    // The state is wanted, and no node gives a piece of it: within four
    // seconds - long before any of them is left for its silence - all six
    // are connected to.
    let silent = six();
    silent.iter().for_each(|node| node.served.limit.store(0, Ordering::Relaxed));
    let run = kit::collect(&data("manysilent", &source), &addrs(&silent), 4);
    assert_eq!(run.code, 1, "{}", run.out);
    assert_eq!(connected(&silent), vec![1; 6], "the state is wanted");

    // The state is on file - collected from one node that gave no blocks -
    // and twenty blocks are to be fetched: all of six fresh nodes.
    let t = data("many", &source);
    let first = Node::with_state(&source);
    first.served.mute_blocks.store(true, Ordering::Relaxed);
    assert_eq!(kit::collect(&t, &[first.addr], 60).code, 0);
    let nodes = six();
    let run = apply(&t, &addrs(&nodes), 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!((number(&run, "state:", "kept"), number(&run, "blocks:", "kept"), number(&run, "applied:", "height")), (4, 0, 40));
    assert_eq!(connected(&nodes), vec![1; 6], "twenty blocks are wanted");

    // again, from the files: nothing to fetch
    let run = apply(&t, &addrs(&nodes), 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(number(&run, "blocks:", "kept"), 20);
    let now = connected(&nodes);
    assert_eq!(now.iter().sum::<usize>(), 6 + 3, "three nodes are enough when nothing is fetched: {now:?}");
}

/// A node that keeps silent about blocks does not hold the others up: the
/// block whose turn it is goes to a second node as well after a moment,
/// long before the request to the silent one times out, and the blocks go
/// on from there.
#[test]
fn a_silent_node_holds_nothing_up() {
    let source = chain_of_40();
    let t = data("hedge", &source);
    let first = Node::with_state(&source);
    first.served.mute_blocks.store(true, Ordering::Relaxed);
    assert_eq!(kit::collect(&t, &[first.addr], 60).code, 0);
    // one node keeps silent about every block, one answers
    let (silent, honest) = (Node::with_state(&source), Node::with_state(&source));
    silent.served.mute_blocks.store(true, Ordering::Relaxed);
    let began = std::time::Instant::now();
    let run = apply(&t, &[silent.addr, honest.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(number(&run, "applied:", "height"), 40);
    // twenty blocks; a request times out after three seconds in this
    // build, a second node is asked after one
    let took = began.elapsed();
    assert!(silent.served.blocks_asked.load(Ordering::Relaxed) >= 1, "the silent one was asked");
    assert!(took < std::time::Duration::from_secs(25), "{took:?}\n{}", run.out);
}
