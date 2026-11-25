//! The program against nodes: on the other end of each connection is the
//! Grin node's own network code, with a chain mined in the test behind it.
//! Run with `cargo test --features test-net`.
#![cfg(feature = "test-net")]
mod kit;

use fly_chain::TEST_START_FILE;
use fly_chain_headers::testkit::TestChain;
use fly_chain_headers::{hash_bytes, Net};
use fly_paycore_chain_pipe::{Config, PipeChain};
use fly_paycore_chain_port::{ChainFeed, Level, Posted, Tip, Unknown};
use grin_core::pow::Difficulty;
use kit::{follow, hex, wait_for, Node, Temp, FLY};
use std::net::{SocketAddr, TcpListener};
use std::process::Command;
use std::time::Duration;

/// From the starting point to the node's tip, in as many answers as it
/// takes; again after a restart without asking for what is stored; on to
/// new headers; over to a heavier branch.
#[test]
fn the_headers_of_a_node_are_followed() {
    let mut main = TestChain::new();
    main.mine(700, 60);
    let node = Node::start(&main.headers);
    let t = Temp::new("follow");
    std::fs::write(t.0.join(TEST_START_FILE), main.record(20)).unwrap();

    let run = follow(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("start: height=20 (development starting point: nobody vouches for it)"), "{}", run.out);
    assert_eq!(run.field("opened:", "kept"), "0");
    assert_eq!(run.field("synced:", "height"), main.tip().height.to_string());
    assert_eq!(run.field("synced:", "hash"), hex(&hash_bytes(main.tip())));
    assert_eq!(run.field("synced:", "work"), main.tip().total_difficulty().to_num().to_string());
    assert_eq!(node.requests(), 2, "689 headers: one full answer and the rest");

    // a restart verifies what is stored and asks for nothing it has
    let run = follow(&t, &[node.addr], 60);
    assert_eq!((run.code, run.field("opened:", "kept")), (0, "689".to_string()), "{}", run.out);
    assert_eq!(run.field("synced:", "hash"), hex(&hash_bytes(main.tip())));
    assert_eq!(node.requests(), 2, "nothing was asked: the node claims no more work than is verified");

    // the chain grows
    main.mine(30, 60);
    node.set(&main.headers);
    let run = follow(&t, &[node.addr], 60);
    assert_eq!((run.code, run.field("opened:", "kept")), (0, "689".to_string()), "{}", run.out);
    assert_eq!(run.field("synced:", "height"), main.tip().height.to_string());
    assert_eq!(node.requests(), 3);

    // the node moves to a heavier branch that leaves the old one 12 blocks back
    let mut branch = main.fork_at(main.tip().height - 12);
    branch.mine_salted(20, 60, 50);
    node.set(&branch.headers);
    let run = follow(&t, &[node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(run.field("synced:", "hash"), hex(&hash_bytes(branch.tip())));
    let run = follow(&t, &[node.addr], 60);
    assert_eq!(run.field("opened:", "kept"), (branch.tip().height - 20).to_string(), "the file holds the new branch");

    // wrong starts: an explanation and nothing else
    for args in [&["headers"][..], &["headers", "--network", "moon", "--data", "x"], &["headers", "--network", "test"], &["serve"]] {
        let out = Command::new(FLY).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&out.stderr).starts_with("fly-chain: "), "{args:?}");
        assert!(out.stdout.is_empty());
    }
}

/// A node that sends a header no valid chain can contain is left, whatever
/// it claims; the headers before that one were valid and are kept; an
/// honest node beside it is followed to the end.
#[test]
fn a_node_that_lies_is_left() {
    let mut main = TestChain::new();
    main.mine(60, 60); // to height 69
    // the liar's chain: honest to 40, then a header that claims more work
    // than the rule gives it, then headers built on that one
    let mut lie = main.fork_at(40);
    let mut bad = lie.next_after(40, 60, 1);
    bad.pow.total_difficulty = bad.pow.total_difficulty + Difficulty::from_num(5);
    TestChain::remine(&mut bad, Difficulty::from_num(25));
    lie.headers.push(bad);
    lie.mine_salted(40, 60, 2);
    let liar = Node::start_as(&lie.headers, Net::Automated.genesis_hash(), Some(1_000_000_000));

    let t = Temp::new("liar");
    std::fs::write(t.0.join(TEST_START_FILE), main.record(20)).unwrap();
    let run = follow(&t, &[liar.addr], 8);
    assert_eq!(run.code, 1, "{}", run.out);
    assert_eq!(run.field("timeout:", "height"), "40", "{}", run.out);
    assert!(run.out.contains("a node sent a header that claims work the rules do not give it; it was left"), "{}", run.out);
    assert_eq!(liar.requests(), 1, "it was not asked again in this run");

    let honest = Node::start(&main.headers);
    let run = follow(&t, &[liar.addr, honest.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert_eq!(run.field("opened:", "kept"), "20");
    assert_eq!(run.field("synced:", "hash"), hex(&hash_bytes(main.tip())));

    // a node that only boasts, on a lighter branch: its headers are valid,
    // they wait, the chain stays, and the node is not asked without end
    let mut lighter = main.fork_at(60);
    lighter.mine_salted(5, 60, 77);
    let boaster = Node::start_as(&lighter.headers, Net::Automated.genesis_hash(), Some(1_000_000_000));
    let run = follow(&t, &[boaster.addr], 9);
    assert_eq!((run.code, run.field("timeout:", "height")), (1, "69".to_string()), "claims are not headers: {}", run.out);
    assert_eq!(run.field("timeout:", "hash"), hex(&hash_bytes(main.tip())));
    assert_eq!(boaster.requests(), 1, "a claim is no reason to ask without end");
}

/// No node, a node of another chain, a starting point that is not one: said
/// in words, nothing is made up.
#[test]
fn without_a_usable_node_nothing_is_claimed() {
    let mut main = TestChain::new();
    main.mine(20, 60);
    let t = Temp::new("alone");
    // no starting point
    let run = follow(&t, &[], 3);
    assert_eq!(run.code, 2);
    assert!(run.out.contains("fly-chain: the test network needs a starting point in the data directory"), "{}", run.out);
    // a starting point that does not pass its check
    let mut record = main.record_value(20);
    record["peaks"][0][0] = serde_json_number(&record["peaks"][0][0]);
    std::fs::write(t.0.join(TEST_START_FILE), record.to_string()).unwrap();
    let run = follow(&t, &[], 3);
    assert_eq!(run.code, 3, "{}", run.out);
    assert!(run.out.contains("failed: the starting point of this program does not pass its own check"), "{}", run.out);

    std::fs::write(t.0.join(TEST_START_FILE), main.record(20)).unwrap();
    // nobody listens there
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let run = follow(&t, &[dead], 7);
    assert_eq!((run.code, run.field("timeout:", "height")), (1, "20".to_string()), "{}", run.out);
    assert!(run.out.contains("no node is connected (1 known; last attempt: no connection)"), "{}", run.out);
    // a node of another chain: it sees the other genesis in the greeting
    // and hangs up, and that is all this side learns
    let stranger = Node::start_as(&main.headers, [9; 32], None);
    let run = follow(&t, &[stranger.addr], 4);
    assert_eq!((run.code, run.field("timeout:", "height")), (1, "20".to_string()), "{}", run.out);
    assert!(run.out.contains("last attempt: the connection was closed"), "{}", run.out);
    assert_eq!(stranger.requests(), 0);
    // something that is no node at all
    let mute = TcpListener::bind("127.0.0.1:0").unwrap();
    let run = follow(&t, &[mute.local_addr().unwrap()], 12);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("no node is connected"), "{}", run.out);
    // a name that does not resolve, and no name at all on this network
    let mut command = Command::new(FLY);
    command.args(["headers", "--network", "automated", "--seconds", "10", "--peer", "no-such-host.invalid:1", "--data"]).arg(&t.0);
    let out = String::from_utf8_lossy(&command.output().unwrap().stdout).into_owned();
    assert!(out.contains("no node address is known"), "{out}");
}
fn serde_json_number(v: &serde_json::Value) -> serde_json::Value {
    serde_json::json!((v.as_u64().unwrap() + 1) % 256)
}

/// Started by the wallet's side of the pipe: the program follows the
/// headers and tells the wallet only what it knows about blocks - nothing.
#[test]
fn the_wallet_is_told_only_what_is_known() {
    let mut main = TestChain::new();
    main.mine(40, 60);
    let node = Node::start(&main.headers);
    let t = Temp::new("pipe");
    std::fs::write(t.0.join(TEST_START_FILE), main.record(20)).unwrap();
    let config = |network: u8, genesis: [u8; 32]| Config {
        network,
        genesis,
        data_dir: t.0.to_str().unwrap().to_string(),
        peers: vec![node.addr.to_string()],
        start_timeout_secs: 30,
        direct_post: false,
        tor_off: false,
        tor_bridges: String::new(),
    };
    let wait = Duration::from_secs(10);
    let genesis = Net::Automated.genesis_hash();
    let mut chain = PipeChain::spawn(std::path::Path::new(FLY), &config(3, genesis), wait).unwrap();
    let status = chain.status().unwrap();
    assert_eq!((status.level, status.tip, status.selected, status.confirmed_time), (Level::Unknown, None, None, None));
    assert_eq!((status.k_conf, status.rangeproofs_authenticated), (10, false));
    let at = Tip { height: main.tip().height, hash: hash_bytes(main.tip()) };
    assert_eq!(chain.next(Some(at)), Err(Unknown), "not 'nothing new': the wallet is not at a verified tip");
    assert_eq!(chain.next(None), Err(Unknown));
    assert_eq!(chain.post(&[1, 2, 3]), Posted::Rejected, "three bytes are not a transaction: refused here, and nothing was sent anywhere");
    let reached = |chain: &mut PipeChain, height: u64| {
        let text = chain.problem().unwrap();
        assert!(text.contains("no block has been applied yet") && text.contains("nobody vouches for it") || text.contains("verifying"), "{text}");
        text.starts_with(&format!("headers verified to {height} "))
    };
    wait_for("the headers", || reached(&mut chain, main.tip().height));
    // a new header is announced: followed without being restarted
    main.mine(3, 60);
    node.set(&main.headers);
    node.announce();
    wait_for("the announced header", || reached(&mut chain, main.tip().height));
    assert!(chain.alive());
    // the wallet's side goes away: so does the program, and the file is free
    drop(chain);
    wait_for("the header file to be free", || {
        fly_chain_headers::chain::HeaderChain::open(&t.0, Net::Automated, &main.record(20)).is_ok()
    });

    // another genesis than the program has for that network, an unknown
    // network, a real network asked for with the wrong genesis: no start
    for (network, hash, why) in [
        (3, [7; 32], "the chain process did not start: the wallet names another genesis than this program has for that network"),
        (9, genesis, "the chain process did not start: a network this program does not know"),
        (1, genesis, "the chain process did not start: the wallet names another genesis than this program has for that network"),
    ] {
        let failed = PipeChain::spawn(std::path::Path::new(FLY), &config(network, hash), wait).err();
        assert_eq!(failed.as_deref(), Some(why));
    }
}
