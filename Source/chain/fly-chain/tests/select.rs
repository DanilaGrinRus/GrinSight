//! The selected tip, end to end: the program against a node with a real
//! chain behind it and against "public nodes" that listen on this
//! computer over TLS and say what the test tells them to. Run with
//! `cargo test --features test-net`.
#![cfg(feature = "test-net")]
mod kit;

use fly_chain::accept::{MEMORY_FILE, TEST_ROOTS_FILE, TEST_SOURCES_FILE};
use fly_chain::{OWN_POINT_FILE, TEST_START_FILE};
use fly_chain_headers::checkpoint;
use fly_chain_headers::origin::Origin;
use fly_chain_headers::testkit::TestChain;
use fly_chain_headers::{hash_bytes, Net};
use fly_chain_state::testkit::Source;
use fly_chain_tips::memory::Memory;
use fly_paycore_chain_pipe::{Config, PipeChain};
use fly_paycore_chain_port::{ChainFeed, Level, Status, Tip};
use grin_core::core::BlockHeader;
use kit::{follow, point, select, wait_for, Node, Temp, FLY};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn clock() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// A public node of the test: answers the question about the tip with the
/// header it was last told to name, or hangs up if it was told nothing;
/// and the question about a height with the header at that height of the
/// chain it was given, or of the one it was told to lie about.
struct Operator {
    port: u16,
    says: Arc<Mutex<Option<BlockHeader>>>,
    chain: Arc<Mutex<Vec<BlockHeader>>>,
    /// Seconds its clock is off.
    clock_off: Arc<AtomicI64>,
    asked: Arc<AtomicUsize>,
}

impl Operator {
    fn start() -> Operator {
        let chain = vec![CertificateDer::from_pem_slice(include_bytes!("../../tips/tests/certs/localhost.pem")).unwrap()];
        let key = PrivateKeyDer::from_pem_slice(include_bytes!("../../tips/tests/certs/localhost.key")).unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
        let config = Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let operator = Operator {
            port: listener.local_addr().unwrap().port(),
            says: Arc::new(Mutex::new(None)),
            chain: Arc::new(Mutex::new(Vec::new())),
            clock_off: Arc::new(AtomicI64::new(0)),
            asked: Arc::new(AtomicUsize::new(0)),
        };
        let (says, clock_off, asked) = (operator.says.clone(), operator.clock_off.clone(), operator.asked.clone());
        let chain = operator.chain.clone();
        std::thread::spawn(move || {
            for socket in listener.incoming() {
                let Ok(socket) = socket else { continue };
                let _ = socket.set_read_timeout(Some(Duration::from_secs(5)));
                let Ok(connection) = ServerConnection::new(config.clone()) else { continue };
                let mut tls = StreamOwned::new(connection, socket);
                let mut question = Vec::new();
                let mut chunk = [0u8; 1024];
                let whole = loop {
                    match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => break false,
                        Ok(n) => question.extend_from_slice(&chunk[..n]),
                    }
                    if question.ends_with(br#""id":1}"#) {
                        break true;
                    }
                };
                let text = String::from_utf8_lossy(&question).into_owned();
                let body = if let Some(at) = text.find(r#""method":"get_header","params":["#) {
                    let rest = &text[at + r#""method":"get_header","params":["#.len()..];
                    let height: usize = rest[..rest.find(',').unwrap()].parse().unwrap();
                    let Some(header) = chain.lock().unwrap().get(height).cloned() else { continue };
                    let hash: String = hash_bytes(&header).iter().map(|b| format!("{b:02x}")).collect();
                    format!(
                        r#"{{"id":1,"jsonrpc":"2.0","result":{{"Ok":{{"hash":"{hash}","height":{},"previous":"{hash}","total_difficulty":{},"version":5}}}}}}"#,
                        header.height,
                        header.pow.total_difficulty.to_num()
                    )
                } else {
                    let named = says.lock().unwrap().clone();
                    let (true, Some(header)) = (whole, named) else { continue };
                    asked.fetch_add(1, Ordering::SeqCst);
                    let hash: String = hash_bytes(&header).iter().map(|b| format!("{b:02x}")).collect();
                    format!(
                        r#"{{"id":1,"jsonrpc":"2.0","result":{{"Ok":{{"height":{},"last_block_pushed":"{hash}","prev_block_to_last":"{hash}","total_difficulty":{}}}}}}}"#,
                        header.height,
                        header.pow.total_difficulty.to_num()
                    )
                };
                let date = (clock() as i64 + clock_off.load(Ordering::SeqCst)) as u64;
                let date = fly_chain_tips::date::write(date).unwrap();
                let answer = format!("HTTP/1.1 200 OK\r\nDate: {date}\r\nContent-Length: {}\r\n\r\n{body}", body.len());
                let _ = tls.write_all(answer.as_bytes());
                tls.conn.send_close_notify();
                let _ = tls.flush();
            }
        });
        operator
    }
    fn say(&self, header: &BlockHeader) {
        *self.says.lock().unwrap() = Some(header.clone());
    }
}

struct World {
    source: Arc<RwLock<Source>>,
    node: Node,
    operators: Vec<Operator>,
    data: Temp,
}

impl World {
    /// A chain of 40 blocks on a node, and five public nodes of four
    /// networks that all name its tip.
    fn new(tag: &str) -> World {
        let source = Source::thin(40);
        source.compact();
        let source = Arc::new(RwLock::new(source));
        let node = Node::with_state(&source);
        let data = Temp::new(tag);
        let record = TestChain::from_headers(source.read().unwrap().headers()).record(14);
        std::fs::write(data.0.join(TEST_START_FILE), record).unwrap();
        let operators: Vec<Operator> = (0..5).map(|_| Operator::start()).collect();
        let listed: String = operators
            .iter()
            .zip([1, 2, 3, 4, 4])
            .enumerate()
            .map(|(i, (operator, network))| format!("https://localhost:{} Operator-{i} {network}\n", operator.port))
            .collect();
        std::fs::write(data.0.join(TEST_SOURCES_FILE), listed).unwrap();
        std::fs::write(data.0.join(TEST_ROOTS_FILE), include_bytes!("../../tips/tests/certs/ca.pem")).unwrap();
        let world = World {
            source,
            node,
            operators,
            data,
        };
        world.all_say(40);
        for operator in &world.operators {
            *operator.chain.lock().unwrap() = world.source.read().unwrap().headers();
        }
        world
    }
    fn header(&self, height: usize) -> BlockHeader {
        self.source.read().unwrap().headers()[height].clone()
    }
    fn tip(&self, height: usize) -> Tip {
        Tip {
            height: height as u64,
            hash: hash_bytes(&self.header(height)),
        }
    }
    fn all_say(&self, height: usize) {
        let header = self.header(height);
        for operator in &self.operators {
            operator.say(&header);
        }
    }
    /// The chain grows by a block; the node has it and tells.
    fn grow(&self) {
        self.source.write().unwrap().grow(1);
        self.show();
    }
    fn show(&self) {
        self.node.set(&self.source.read().unwrap().headers());
        self.node.announce();
    }
    fn program(&self) -> PipeChain {
        let config = Config {
            network: 3,
            genesis: Net::Automated.genesis_hash(),
            data_dir: self.data.0.to_str().unwrap().to_string(),
            peers: vec![self.node.addr.to_string()],
            start_timeout_secs: 30,
            direct_post: false,
            tor_off: false,
            tor_bridges: String::new(),
        };
        PipeChain::spawn(std::path::Path::new(FLY), &config, Duration::from_secs(10)).unwrap()
    }
    fn asked(&self) -> usize {
        self.operators.iter().map(|o| o.asked.load(Ordering::SeqCst)).sum()
    }
}

fn selected(chain: &mut PipeChain, tip: Tip) -> bool {
    chain.status().is_some_and(|s| s.selected == Some(tip))
}

fn at_tip_unselected(chain: &mut PipeChain, tip: Tip) -> Option<Status> {
    chain.status().filter(|s| s.level == Level::AtTip && s.tip == Some(tip) && s.selected.is_none())
}

#[test]
fn the_tip_is_selected_when_public_nodes_name_it() {
    let world = World::new("select");
    let mut chain = world.program();
    wait_for("the selected tip", || selected(&mut chain, world.tip(40)));
    let status = chain.status().unwrap();
    assert_eq!((status.level, status.tip), (Level::AtTip, Some(world.tip(40))));
    // The time is the one the public nodes wrote, and it is this
    // computer's; the starting point is a development point.
    let time = status.confirmed_time.unwrap();
    assert!(time <= clock() && clock() - time < 20, "{time}");
    assert!(status.provisional);
    let text = chain.problem().unwrap();
    assert!(text.contains("blocks applied to the tip, 40; the tip is confirmed by public nodes"), "{text}");
    // Every one of the five was asked once, and the number of the asking
    // is on the disk.
    assert_eq!(world.asked(), 5);
    assert_eq!(Memory::open(&world.data.0.join(MEMORY_FILE)).unwrap().generation(), 1);
    // The tip a quorum named needs no second asking.
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(world.asked(), 5);

    // The chain grows. The public nodes still name the old tip: they are
    // behind, and the new tip is not selected.
    world.grow();
    wait_for("the new tip, unselected", || at_tip_unselected(&mut chain, world.tip(41)).is_some());
    wait_for("the answer of the public nodes", || {
        chain.problem().is_some_and(|text| text.contains("public nodes did not confirm the tip (5 answered, 3 needed, 0 named it)"))
    });
    assert!(chain.status().unwrap().selected.is_none());
    // They catch up: asked again, and the tip is selected.
    world.all_say(41);
    wait_for("the new tip, selected", || selected(&mut chain, world.tip(41)));

    // Two of the three networks' nodes go silent: two of five that name
    // the tip are not half the list.
    world.grow();
    world.all_say(42);
    for operator in &world.operators[..3] {
        *operator.says.lock().unwrap() = None;
    }
    wait_for("too few answers", || {
        chain.problem().is_some_and(|text| text.contains("(2 answered, 3 needed, 2 named it)"))
    });
    assert!(at_tip_unselected(&mut chain, world.tip(42)).is_some());
    world.all_say(42);
    wait_for("the tip, selected again", || selected(&mut chain, world.tip(42)));
}

#[test]
fn a_public_node_that_names_more() {
    let world = World::new("claim");
    let mut chain = world.program();
    wait_for("the selected tip", || selected(&mut chain, world.tip(40)));

    // The chain grows by two blocks, and the node of the program's
    // connections shows only the first. One public node names the second.
    world.source.write().unwrap().grow(2);
    let headers = world.source.read().unwrap().headers();
    world.node.set(&headers[..42]);
    world.node.announce();
    world.all_say(41);
    world.operators[4].say(&headers[42]);
    wait_for("the claim", || {
        chain.problem().is_some_and(|text| text.contains("public node localhost names more work than is verified here"))
    });
    wait_for("the blocks at the tip", || at_tip_unselected(&mut chain, world.tip(41)).is_some());
    // Four public nodes named the tip the program has; it is not selected
    // all the same, now or after more askings.
    std::thread::sleep(Duration::from_secs(6));
    assert!(at_tip_unselected(&mut chain, world.tip(41)).is_some());
    // The claim is on the disk.
    assert!(Memory::open(&world.data.0.join(MEMORY_FILE)).unwrap().claims().blocks());

    // A restart does not make it go away.
    drop(chain);
    let mut chain = world.program();
    wait_for("the program again", || chain.status().is_some_and(|s| s.level == Level::AtTip));
    std::thread::sleep(Duration::from_secs(4));
    assert!(at_tip_unselected(&mut chain, world.tip(41)).is_some());
    let text = chain.problem().unwrap();
    assert!(text.contains("names more work than is verified here"), "{text}");

    // The block arrives and is verified: the claim is settled, and when
    // the public nodes name the new tip it is selected.
    world.show();
    world.all_say(42);
    wait_for("the claimed block, selected", || selected(&mut chain, world.tip(42)));
    assert!(!Memory::open(&world.data.0.join(MEMORY_FILE)).unwrap().claims().blocks());
    // The numbers of the askings went on over the restart.
    assert!(Memory::open(&world.data.0.join(MEMORY_FILE)).unwrap().generation() >= 3);
}

#[test]
fn public_nodes_that_disagree_about_the_time() {
    let world = World::new("time");
    // One of them is ten minutes ahead.
    world.operators[2].clock_off.store(600, Ordering::SeqCst);
    let mut chain = world.program();
    wait_for("the time trouble", || {
        chain.problem().is_some_and(|text| text.contains("the time is not confirmed: public nodes disagree about it"))
    });
    wait_for("the blocks at the tip", || at_tip_unselected(&mut chain, world.tip(40)).is_some());
    let status = at_tip_unselected(&mut chain, world.tip(40)).unwrap();
    assert_eq!(status.confirmed_time, None);
    // Its clock is set right: the time is confirmed and the tip selected.
    world.operators[2].clock_off.store(0, Ordering::SeqCst);
    wait_for("the selected tip", || selected(&mut chain, world.tip(40)));
    assert!(chain.status().unwrap().confirmed_time.is_some());
}

#[test]
fn without_public_nodes_nothing_is_selected() {
    let world = World::new("nobody");
    std::fs::remove_file(world.data.0.join(TEST_SOURCES_FILE)).unwrap();
    let mut chain = world.program();
    wait_for("the tip", || chain.status().is_some_and(|s| s.level == Level::AtTip));
    std::thread::sleep(Duration::from_secs(2));
    let status = at_tip_unselected(&mut chain, world.tip(40)).unwrap();
    assert_eq!(status.confirmed_time, None);
    let text = chain.problem().unwrap();
    assert!(text.contains("no public nodes are listed for this network: no tip is confirmed"), "{text}");
    assert_eq!(world.asked(), 0);

    // Public nodes whose authority the program was not given: none of
    // them is an answer.
    let world = World::new("strangers");
    std::fs::write(world.data.0.join(TEST_ROOTS_FILE), include_bytes!("../../tips/tests/certs/stranger.pem")).unwrap();
    let mut chain = world.program();
    wait_for("no answers", || {
        chain.problem().is_some_and(|text| text.contains("the time is not confirmed: too few public nodes answered"))
    });
    wait_for("the blocks at the tip", || at_tip_unselected(&mut chain, world.tip(40)).is_some());
    std::thread::sleep(Duration::from_secs(2));
    assert!(at_tip_unselected(&mut chain, world.tip(40)).is_some());
    assert_eq!(world.asked(), 0);
}

#[test]
fn the_program_run_by_hand_says_when_the_tip_is_selected() {
    let world = World::new("by-hand");
    let run = select(&world.data, &[world.node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("selected: height=40 "), "{}", run.out);
    assert!(run.out.contains("; the tip is confirmed by public nodes"), "{}", run.out);
    let time: u64 = run.field("selected:", "confirmed_time").parse().unwrap();
    assert!(time <= clock() && clock() - time < 60);

    // With nobody to ask it waits its time out and says why.
    std::fs::remove_file(world.data.0.join(TEST_SOURCES_FILE)).unwrap();
    let run = select(&world.data, &[world.node.addr], 8);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("timeout: height=40 "), "{}", run.out);
    assert!(run.out.contains("no public nodes are listed for this network"), "{}", run.out);
}

/// A release point: made from the verified headers at the height where
/// nodes give their state out, named by public nodes of operators on
/// different networks, written with an origin that vouches for it.
#[test]
fn a_release_point_is_made() {
    let world = World::new("release");
    let out = Temp::new("release-out");
    let run = point(&world.data, &[world.node.addr], &["--kind", "release", "--out", out.0.to_str().unwrap()]);
    assert_eq!(run.code, 0, "{}", run.out);
    // 40 blocks: the state is given out at 20 on this network
    assert_eq!(run.field("made:", "height"), "20");
    assert!(run.out.contains("confirmed_by=Operator-0,Operator-1,Operator-2,Operator-3,Operator-4"), "{}", run.out);
    let record = std::fs::read(out.0.join("automated.json")).unwrap();
    let start = checkpoint::check(&record, Net::Automated).unwrap();
    assert_eq!((start.height(), start.hash()), (20, hash_bytes(&world.header(20))));
    let origin = Origin::read(&std::fs::read(out.0.join("automated.origin.json")).unwrap()).unwrap();
    assert!(origin.vouches_for(&start));
    assert_eq!(origin.confirmed.len(), 5);
    assert!(origin.from.starts_with("headers from the nodes named: 127.0.0.1:"), "{}", origin.from);
    // the record is the one the full range of the Grin code gives
    let built: serde_json::Value = serde_json::from_slice(&record).unwrap();
    let mut want = TestChain::from_headers(world.source.read().unwrap().headers()).record_value(20);
    want["release_time"] = built["release_time"].clone();
    assert_eq!(built, want);

    // lower, as asked; higher than where the state is given out, refused
    let run = point(&world.data, &[world.node.addr], &["--kind", "release", "--out", out.0.to_str().unwrap(), "--height", "18"]);
    assert_eq!((run.code, run.field("made:", "height")), (0, "18".to_string()), "{}", run.out);
    let run = point(&world.data, &[world.node.addr], &["--kind", "release", "--out", out.0.to_str().unwrap(), "--height", "21"]);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("failed: height 21 is above 20, where nodes give their state out now"), "{}", run.out);
    // too close to this program's own point (14)
    let run = point(&world.data, &[world.node.addr], &["--kind", "release", "--out", out.0.to_str().unwrap(), "--height", "16"]);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("it has to be at least three above this program's starting point (14)"), "{}", run.out);
}

/// One public node with another header at that height stops any point;
/// operators of one network do not make a release point, and an own
/// point is written all the same.
#[test]
fn a_point_against_public_nodes() {
    let world = World::new("against");
    let out = Temp::new("against-out");
    let out_dir = out.0.to_str().unwrap().to_string();
    // the fifth names a header of another branch at 20
    let mut other = world.source.read().unwrap().headers();
    other[20].pow.proof.nonces[0] ^= 1;
    *world.operators[4].chain.lock().unwrap() = other;
    for kind in ["release", "own"] {
        let run = point(&world.data, &[world.node.addr], &["--kind", kind, "--out", &out_dir]);
        assert_eq!(run.code, 1, "{}", run.out);
        assert!(run.out.contains("failed: public nodes name another header at height 20: localhost; no point is written"), "{}", run.out);
        assert!(run.out.contains("said: localhost (Operator-4): ANOTHER header"), "{}", run.out);
    }
    assert_eq!(std::fs::read_dir(&out.0).unwrap().count(), 0);

    // only two answer, both on one network
    *world.operators[4].chain.lock().unwrap() = Vec::new();
    for operator in &world.operators[..3] {
        *operator.chain.lock().unwrap() = Vec::new();
    }
    let run = point(&world.data, &[world.node.addr], &["--kind", "release", "--out", &out_dir]);
    assert_eq!(run.code, 1, "{}", run.out);
    assert!(run.out.contains("a release point needs public nodes of two operators on different networks to name it; 1 named it"), "{}", run.out);
    assert_eq!(std::fs::read_dir(&out.0).unwrap().count(), 0);
    let run = point(&world.data, &[world.node.addr], &["--kind", "own", "--out", &out_dir]);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("kind=own confirmed_by=nobody"), "{}", run.out);
    let record = std::fs::read(out.0.join(OWN_POINT_FILE)).unwrap();
    assert_eq!(checkpoint::check(&record, Net::Automated).unwrap().height(), 20);
}

/// A point the user gives: it takes the place of the one the program has,
/// the header file of that one gives way, and what is selected on top of
/// it is not provisional.
#[test]
fn a_point_the_user_gives() {
    let world = World::new("own");
    let headers = world.source.read().unwrap().headers();
    // the program has followed the chain from its own point first
    let run = follow(&world.data, &[world.node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("start: height=14 (development starting point: nobody vouches for it)"), "{}", run.out);
    std::fs::write(world.data.0.join(OWN_POINT_FILE), TestChain::from_headers(headers.clone()).record(20)).unwrap();
    let run = follow(&world.data, &[world.node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("start: height=20 (starting point you gave this program)"), "{}", run.out);
    assert!(run.out.contains("replaced: the header file of the starting point at 14 gave way to this one"), "{}", run.out);
    // the headers above 20 were in the old file and verify from the new point
    assert!(run.out.contains("opened: kept=20 "), "{}", run.out);

    let mut chain = world.program();
    wait_for("the selected tip", || selected(&mut chain, world.tip(40)));
    let status = chain.status().unwrap();
    assert!(!status.provisional, "a point the user gave is vouched for by the user");
    assert_eq!(status.level, Level::AtTip);
    let text = chain.problem().unwrap();
    assert!(text.contains("from a starting point you gave this program (20)"), "{text}");
    drop(chain);

    // a point that does not pass its check: nothing starts
    let mut bent: serde_json::Value = serde_json::from_slice(&TestChain::from_headers(headers.clone()).record(20)).unwrap();
    bent["total_work"] = serde_json::json!(bent["total_work"].as_u64().unwrap() + 1);
    std::fs::write(world.data.0.join(OWN_POINT_FILE), bent.to_string()).unwrap();
    let run = follow(&world.data, &[world.node.addr], 10);
    assert_eq!(run.code, 2, "{}", run.out);
    assert!(run.out.contains("fly-chain: your own starting point does not pass its check"), "{}", run.out);
    std::fs::write(world.data.0.join(OWN_POINT_FILE), b"not a record").unwrap();
    let run = follow(&world.data, &[world.node.addr], 10);
    assert!(run.out.contains("your own starting point does not pass its check"), "{}", run.out);
    // a point of another network
    std::fs::write(
        world.data.0.join(OWN_POINT_FILE),
        std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../headers/points/main.json")).unwrap(),
    )
    .unwrap();
    let run = follow(&world.data, &[world.node.addr], 10);
    assert!(run.out.contains("fly-chain: your own starting point is for another network"), "{}", run.out);
    // gone: back to the program's own point, whose file gives way in turn
    std::fs::remove_file(world.data.0.join(OWN_POINT_FILE)).unwrap();
    let run = follow(&world.data, &[world.node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("start: height=14 (development"), "{}", run.out);
    assert!(run.out.contains("replaced: the header file of the starting point at 20 gave way to this one"), "{}", run.out);
}

/// K188: the wallet asks the program for a starting point made from the
/// chain it follows. None is made on top of a point nobody vouches for,
/// none while the tip is not confirmed by public nodes, none that would
/// not be three above the point the program started from. When one is
/// made it is the record of the header nodes give their state out at,
/// with the time of making written in; it passes the check of a starting
/// point, and the program started from it follows the same chain.
#[test]
fn the_wallet_is_given_a_point_made_from_the_chain_it_follows() {
    let world = World::new("wallet-point");
    let headers = || world.source.read().unwrap().headers();
    // from the development point: the tip is selected, provisionally
    let mut chain = world.program();
    wait_for("the selected tip", || selected(&mut chain, world.tip(40)));
    assert!(chain.status().unwrap().provisional);
    let why = chain.point().unwrap_err();
    assert!(why.contains("provisional: nobody vouches for the point this program started from"), "{why}");
    drop(chain);

    // from a point the user gave, at 20: nodes give their state out at 20
    // while the tip is 40, and a point there would be the same point
    std::fs::write(world.data.0.join(OWN_POINT_FILE), TestChain::from_headers(headers()).record(20)).unwrap();
    let mut chain = world.program();
    wait_for("the selected tip", || selected(&mut chain, world.tip(40)));
    assert!(!chain.status().unwrap().provisional);
    let why = chain.point().unwrap_err();
    assert!(why.starts_with("no new starting point can be made yet: it would be at block 20") && why.contains("started from (20); the tip is 40"), "{why}");

    // the chain grows by twenty; the public nodes are behind
    world.source.write().unwrap().grow(20);
    world.show();
    wait_for("the new tip, unselected", || at_tip_unselected(&mut chain, world.tip(60)).is_some());
    let why = chain.point().unwrap_err();
    assert!(why.contains("only when the tip is confirmed by public nodes"), "{why}");
    assert!(chain.alive(), "a refusal is an answer");

    // they catch up
    world.all_say(60);
    wait_for("the new tip, selected", || selected(&mut chain, world.tip(60)));
    let before = clock();
    let record = chain.point().unwrap();
    let start = checkpoint::check(&record, Net::Automated).unwrap();
    assert_eq!((start.height(), start.hash()), (40, hash_bytes(&world.header(40))));
    let mut made: serde_json::Value = serde_json::from_slice(&record).unwrap();
    let time = made["release_time"].as_u64().unwrap();
    assert!(time >= before && time <= clock(), "{time}");
    let expected = TestChain::from_headers(headers()).record_value(40);
    made["release_time"] = expected["release_time"].clone();
    assert_eq!(made, expected);
    // asking changed nothing: the program goes on from the point it had
    assert_eq!(checkpoint::check(&std::fs::read(world.data.0.join(OWN_POINT_FILE)).unwrap(), Net::Automated).unwrap().height(), 20);
    assert!(selected(&mut chain, world.tip(60)));
    drop(chain);

    // the point made is one a program starts from
    std::fs::write(world.data.0.join(OWN_POINT_FILE), &record).unwrap();
    let run = follow(&world.data, &[world.node.addr], 60);
    assert_eq!(run.code, 0, "{}", run.out);
    assert!(run.out.contains("start: height=40 (starting point you gave this program)"), "{}", run.out);
    let mut chain = world.program();
    wait_for("the selected tip from the new point", || selected(&mut chain, world.tip(60)));
    assert!(!chain.status().unwrap().provisional);
}

/// A node the user listed as their own is asked about the tip like the
/// listed ones, but is no voice of its own. Half the list and more names
/// the tip - the user's node and two operators of one network - and the
/// tip is not selected: there are no two independent voices. An operator
/// of another network joins them, and it is. A line of the file that
/// names no node is said.
#[test]
fn the_users_own_node_is_asked_but_is_no_voice() {
    let world = World::new("own-node");
    let mine = Operator::start();
    mine.say(&world.header(40));
    std::fs::write(
        world.data.0.join(fly_chain::accept::OWN_NODES_FILE),
        format!("https://localhost:{}\nnot an address\n", mine.port),
    )
    .unwrap();
    // of the listed, the two of network 4 name the tip; the one of
    // network 1 answers too - so the time is confirmed - but is a block behind
    for operator in &world.operators[1..3] {
        *operator.says.lock().unwrap() = None;
    }
    world.operators[0].say(&world.header(39));
    let mut chain = world.program();
    wait_for("the own node to be asked", || mine.asked.load(Ordering::SeqCst) >= 1);
    wait_for("the blocks at the tip", || at_tip_unselected(&mut chain, world.tip(40)).is_some());
    std::thread::sleep(Duration::from_secs(3));
    wait_for("the verdict", || chain.problem().is_some_and(|text| text.contains("(4 answered, 3 needed, 3 named it)")));
    assert!(at_tip_unselected(&mut chain, world.tip(40)).is_some(), "three named it, and no two of them are independent");
    let text = chain.problem().unwrap();
    assert!(text.contains("1 line(s) of own-nodes.txt name no node"), "{text}");
    // an operator of another network answers: selected
    world.operators[0].say(&world.header(40));
    wait_for("the selected tip", || selected(&mut chain, world.tip(40)));
}
