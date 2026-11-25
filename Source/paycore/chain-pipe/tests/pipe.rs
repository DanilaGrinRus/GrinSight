//! The chain pipe inside one process: both ends over operating-system pipes.
use fly_paycore_chain_pipe::wire::{decode_block, decode_old, decode_status, encode_block, encode_old, encode_status, encode_tip};
use fly_paycore_chain_pipe::{serve, Config, PipeChain, MAX_FRAME, VERSION};
use fly_paycore_chain_port::{
    BlockFacts, ChainFeed, Level, OldOutputs, OutputFact, Posted, Status, Step, Tip, Unknown, MAX_INPUTS, MAX_KERNELS,
    MAX_OLD_OUTPUTS, MAX_OUTPUTS, MAX_PROOF_LEN, MAX_TX_LEN,
};
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn config() -> Config {
    Config {
        network: 2,
        genesis: [0x17; 32],
        data_dir: "/var/lib/fly/chain".into(),
        peers: vec!["203.0.113.5:13414".into(), "node.example:3413".into()],
        start_timeout_secs: 2,
        direct_post: false,
        tor_off: false,
        tor_bridges: String::new(),
    }
}
fn tip(height: u64, fill: u8) -> Tip {
    Tip { height, hash: [fill; 32] }
}
fn block(height: u64, fill: u8, outputs: usize) -> BlockFacts {
    BlockFacts {
        height,
        hash: [fill; 32],
        outputs: (0..outputs)
            .map(|i| OutputFact {
                commit: [(i % 251) as u8; 33],
                proof: vec![fill; MAX_PROOF_LEN],
                pos: 1_000_000 + i as u64,
                coinbase: i == 0,
            })
            .collect(),
        inputs: vec![[8; 33], [9; 33]],
        kernels: vec![[7; 33]],
        v_delta: vec![1, 2, 3],
    }
}
fn full_status() -> Status {
    Status {
        level: Level::AtTip,
        tip: Some(tip(700, 7)),
        selected: Some(tip(699, 6)),
        confirmed_time: Some(1_795_000_000),
        k_conf: 10,
        rangeproofs_authenticated: true,
        provisional: true,
    }
}

/// Answers from a script and records what it was asked.
#[derive(Default)]
struct Script {
    asked: Arc<Mutex<Vec<String>>>,
    status: Vec<Option<Status>>,
    steps: Vec<Result<Step, Unknown>>,
    posts: Vec<Posted>,
    problems: Vec<Option<String>>,
    old: Vec<Result<OldOutputs, Unknown>>,
    points: Vec<Result<Vec<u8>, String>>,
}
fn old(outputs: usize, next: Option<u64>, pieces: u64) -> OldOutputs {
    OldOutputs {
        outputs: block(0, 4, outputs).outputs,
        at: tip(900, 9),
        before: 880,
        next,
        pieces,
        bare: false,
    }
}
impl ChainFeed for Script {
    fn old_outputs(&mut self, piece: u64) -> Result<OldOutputs, Unknown> {
        self.asked.lock().unwrap().push(format!("old {piece}"));
        self.old.remove(0)
    }
    fn old_outputs_since(&mut self, piece: u64, since: Tip) -> Result<OldOutputs, Unknown> {
        self.asked.lock().unwrap().push(format!("old {piece} since {}/{}", since.height, since.hash[0]));
        self.old.remove(0)
    }
    fn status(&mut self) -> Option<Status> {
        self.asked.lock().unwrap().push("status".into());
        self.status.remove(0)
    }
    fn next(&mut self, at: Option<Tip>) -> Result<Step, Unknown> {
        self.asked.lock().unwrap().push(format!("next {:?}", at.map(|t| (t.height, t.hash[0]))));
        self.steps.remove(0)
    }
    fn post(&mut self, tx: &[u8]) -> Posted {
        self.asked.lock().unwrap().push(format!("post {} {}", tx.len(), tx[0]));
        self.posts.remove(0)
    }
    fn post_direct(&mut self, tx: &[u8]) -> Posted {
        self.asked.lock().unwrap().push(format!("post-direct {} {}", tx.len(), tx[0]));
        self.posts.remove(0)
    }
    fn problem(&mut self) -> Option<String> {
        if self.problems.is_empty() {
            return None;
        }
        self.problems.remove(0)
    }
    fn point(&mut self) -> Result<Vec<u8>, String> {
        self.asked.lock().unwrap().push("point".into());
        self.points.remove(0)
    }
}

struct Ends {
    client_reads: PipeReader,
    client_writes: PipeWriter,
    server_reads: PipeReader,
    server_writes: PipeWriter,
}
fn ends() -> Ends {
    let (client_reads, server_writes) = std::io::pipe().unwrap();
    let (server_reads, client_writes) = std::io::pipe().unwrap();
    Ends {
        client_reads,
        client_writes,
        server_reads,
        server_writes,
    }
}

/// Every answer crosses the pipe and comes back as it was, the largest
/// block included; the configuration arrives unchanged; nothing about the
/// wallet but its position and the finished transaction is sent.
#[test]
fn every_answer_crosses_and_comes_back() {
    let e = ends();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::new(Mutex::new(None));
    let (asked2, seen2) = (asked.clone(), seen.clone());
    let largest = block(101, 3, MAX_OUTPUTS);
    assert!(encode_block(&largest).unwrap().len() > 1_400_000);
    let largest2 = largest.clone();
    let (mut sr, mut sw) = (e.server_reads, e.server_writes);
    let server = std::thread::spawn(move || {
        serve(&mut sr, &mut sw, move |c: Config| {
            *seen2.lock().unwrap() = Some(c);
            Ok(Script {
                asked: asked2,
                status: vec![Some(full_status()), None, Some(Status { level: Level::Unknown, tip: None, selected: None, confirmed_time: None, k_conf: 0, rangeproofs_authenticated: false, provisional: false })],
                steps: vec![
                    Ok(Step::Reanchor(tip(100, 1))),
                    Ok(Step::Block(Box::new(largest2))),
                    Ok(Step::Nothing),
                    Ok(Step::Rollback { to: 99 }),
                    Err(Unknown),
                    Ok(Step::Reanchor(tip(5, 5))),
                ],
                posts: vec![Posted::Accepted, Posted::Rejected, Posted::Unknown],
                problems: vec![Some(format!("peer said: no\n\u{1b}[31mway\u{7} \u{e9}{}", "x".repeat(500))), Some(String::new()), None],
                old: Vec::new(),
                points: Vec::new(),
            })
        })
    });
    let mut c = PipeChain::connect(e.client_reads, e.client_writes, &config(), Duration::from_secs(5)).unwrap();
    assert_eq!(seen.lock().unwrap().take(), Some(config()), "the configuration changed on the way");

    assert_eq!(c.status(), Some(full_status()));
    assert_eq!(c.status(), None);
    assert_eq!(c.status().unwrap().level, Level::Unknown);

    assert_eq!(c.next(None), Ok(Step::Reanchor(tip(100, 1))));
    assert_eq!(c.next(Some(tip(100, 1))), Ok(Step::Block(Box::new(largest))));
    assert_eq!(c.next(Some(tip(101, 3))), Ok(Step::Nothing));
    assert_eq!(c.next(Some(tip(101, 3))), Ok(Step::Rollback { to: 99 }));
    assert_eq!(c.next(Some(tip(99, 9))), Err(Unknown));
    assert!(c.alive(), "\"unknown\" is an answer, not a failure of the pipe");
    assert_eq!(c.next(Some(tip(99, 9))), Ok(Step::Reanchor(tip(5, 5))));

    let tx = vec![0x42; 70_000];
    assert_eq!(c.post(&tx), Posted::Accepted);
    assert_eq!(c.post(&tx), Posted::Rejected);
    assert_eq!(c.post(&tx), Posted::Unknown);
    // a transaction that cannot be one is not sent, and not called rejected
    assert_eq!(c.post(&[]), Posted::Unknown);
    assert_eq!(c.post(&vec![1; MAX_TX_LEN + 1]), Posted::Unknown);

    let said = c.problem().unwrap();
    assert!(said.starts_with("peer said: no??[31mway? ?xxx"), "{said}");
    assert_eq!(said.len(), 240);
    assert_eq!(c.problem(), None, "an empty description is no description");
    assert_eq!(c.problem(), None);
    assert!(c.alive());
    drop(c);
    server.join().unwrap().unwrap();
    let asked = asked.lock().unwrap();
    assert_eq!(
        asked.iter().filter(|a| a.starts_with("next")).cloned().collect::<Vec<_>>(),
        ["next None", "next Some((100, 1))", "next Some((101, 3))", "next Some((101, 3))", "next Some((99, 9))", "next Some((99, 9))"]
    );
    assert_eq!(asked.iter().filter(|a| a.starts_with("post")).count(), 3, "refused locally, never sent");
}

/// The encoding itself: what goes in comes out, limits hold in both
/// directions, and every byte is accounted for.
#[test]
fn the_wire_form_is_exact_and_bounded() {
    let b = block(12, 4, 3);
    let bytes = encode_block(&b).unwrap();
    assert_eq!(decode_block(&bytes), Some(b.clone()));
    for cut in [0, 1, 39, 40, bytes.len() - 1] {
        assert_eq!(decode_block(&bytes[..cut]), None, "cut at {cut}");
    }
    let mut tail = bytes.clone();
    tail.push(0);
    assert_eq!(decode_block(&tail), None, "a byte too many");
    let empty = BlockFacts { height: 1, hash: [1; 32], ..BlockFacts::default() };
    assert_eq!(decode_block(&encode_block(&empty).unwrap()), Some(empty));

    // over the limits: not encoded, and not decoded if someone else encoded it
    let mut over = b.clone();
    over.outputs = vec![b.outputs[0].clone(); MAX_OUTPUTS + 1];
    assert_eq!(encode_block(&over), None);
    let mut over = b.clone();
    over.inputs = vec![[1; 33]; MAX_INPUTS + 1];
    assert_eq!(encode_block(&over), None);
    let mut over = b.clone();
    over.kernels = vec![[1; 33]; MAX_KERNELS + 1];
    assert_eq!(encode_block(&over), None);
    for proof in [vec![], vec![1; MAX_PROOF_LEN + 1]] {
        let mut over = b.clone();
        over.outputs[0].proof = proof;
        assert_eq!(encode_block(&over), None);
    }
    // a count that promises more than the limit is refused before the items are read
    let mut lying = bytes.clone();
    lying[40..44].copy_from_slice(&((MAX_OUTPUTS as u32) + 1).to_le_bytes());
    assert_eq!(decode_block(&lying), None);
    lying[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_block(&lying), None);
    // and so is a block that really carries one output more than the limit
    let item = 33 + 8 + 1 + 2 + b.outputs[0].proof.len();
    let after = 44 + item * b.outputs.len();
    let mut crowded = bytes[..40].to_vec();
    crowded.extend_from_slice(&((MAX_OUTPUTS as u32) + 1).to_le_bytes());
    for _ in 0..=MAX_OUTPUTS {
        crowded.extend_from_slice(&bytes[44..44 + item]);
    }
    crowded.extend_from_slice(&bytes[after..]);
    assert_eq!(decode_block(&crowded), None);
    // the same block with exactly the limit is read
    let mut full = bytes[..40].to_vec();
    full.extend_from_slice(&(MAX_OUTPUTS as u32).to_le_bytes());
    for _ in 0..MAX_OUTPUTS {
        full.extend_from_slice(&bytes[44..44 + item]);
    }
    full.extend_from_slice(&bytes[after..]);
    assert_eq!(decode_block(&full).map(|b| b.outputs.len()), Some(MAX_OUTPUTS));
    // a coinbase flag that is neither yes nor no
    let mut odd = bytes.clone();
    odd[44 + 33 + 8] = 2;
    assert_eq!(decode_block(&odd), None);

    for s in [full_status(), Status { level: Level::Behind, tip: Some(tip(1, 1)), selected: None, confirmed_time: None, k_conf: 3, rangeproofs_authenticated: false, provisional: false }] {
        let bytes = encode_status(&s);
        assert_eq!(decode_status(&bytes), Some(s));
        assert_eq!(decode_status(&bytes[..bytes.len() - 1]), None);
        let mut odd = bytes.clone();
        odd[0] = 3;
        assert_eq!(decode_status(&odd), None, "a level that does not exist");
        // the last byte says whether the tip stands on something nobody
        // vouches for: yes or no, and it changes the status read
        let last = bytes.len() - 1;
        let mut flipped = bytes.clone();
        flipped[last] ^= 1;
        assert_eq!(decode_status(&flipped), Some(Status { provisional: !s.provisional, ..s }));
        flipped[last] = 2;
        assert_eq!(decode_status(&flipped), None, "neither yes nor no");
        let mut tail = bytes.clone();
        tail.push(1);
        assert_eq!(decode_status(&tail), None);
    }
    let c = config();
    assert_eq!(Config::decode(&c.encode().unwrap()), Some(c.clone()));
    let mut other = c.encode().unwrap();
    other[0] = VERSION + 1;
    assert_eq!(Config::decode(&other), None);
    // the user's agreement to the direct way is its last byte: yes, no, or nothing
    let agreed = Config { direct_post: true, ..c.clone() };
    let bytes = agreed.encode().unwrap();
    assert_eq!(Config::decode(&bytes), Some(agreed));
    assert_eq!((bytes.last(), c.encode().unwrap().last()), (Some(&1), Some(&0)));
    let mut odd = bytes.clone();
    *odd.last_mut().unwrap() = 2;
    assert_eq!(Config::decode(&odd), None, "neither yes nor no");
    assert_eq!(Config::decode(&bytes[..bytes.len() - 1]), None, "without it");
    let mut longer = bytes.clone();
    longer.push(0);
    assert_eq!(Config::decode(&longer), None);
    // Tor switched off (K189) is the byte before it: yes or no, nothing else
    let off = Config { tor_off: true, ..c.clone() };
    let bytes = off.encode().unwrap();
    assert_eq!(Config::decode(&bytes), Some(off));
    let at = bytes.len() - 2;
    assert_eq!((bytes[at], c.encode().unwrap()[at]), (1, 0));
    let mut odd = bytes.clone();
    odd[at] = 2;
    assert_eq!(Config::decode(&odd), None, "neither on nor off");
    // Tor bridges cross as they were given; more than the message carries does not cross
    let lines = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=abc iat-mode=0\n198.51.100.25:443 7DD62766BF2052432051D7B7E08A22F7E34A4543";
    let bridged = Config { tor_bridges: lines.into(), ..c.clone() };
    assert_eq!(Config::decode(&bridged.encode().unwrap()).map(|b| b.tor_bridges), Some(lines.to_string()));
    assert_ne!(bridged.encode(), c.encode());
    assert_eq!(c.tor_bridges, "");
    assert!(Config { tor_bridges: "a".repeat(70_000), ..c.clone() }.encode().is_none());
}

/// A raw peer: says "ready", then answers every request with fixed bytes.
fn raw_peer(answers: Vec<Vec<u8>>, then_hang: bool) -> PipeChain {
    let e = ends();
    let (mut sr, mut sw) = (e.server_reads, e.server_writes);
    std::thread::spawn(move || {
        let read_one = |sr: &mut PipeReader| -> bool {
            let mut len = [0u8; 4];
            if sr.read_exact(&mut len).is_err() {
                return false;
            }
            let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
            sr.read_exact(&mut body).is_ok()
        };
        if !read_one(&mut sr) {
            return;
        }
        sw.write_all(&2u32.to_le_bytes()).unwrap();
        sw.write_all(&[0x90, VERSION]).unwrap();
        for a in answers {
            if !read_one(&mut sr) {
                return;
            }
            if sw.write_all(&a).is_err() {
                return;
            }
        }
        if then_hang {
            let _ = read_one(&mut sr);
            std::thread::sleep(Duration::from_secs(30));
        }
        // otherwise: both ends close here, as when the process dies
    });
    PipeChain::connect(e.client_reads, e.client_writes, &config(), Duration::from_millis(400)).unwrap()
}
fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut f = ((body.len() + 1) as u32).to_le_bytes().to_vec();
    f.push(tag);
    f.extend_from_slice(body);
    f
}

/// What the wallet's side says when the chain process is not there to
/// answer: no status, an unknown step, an unknown broadcast. Never
/// "nothing new", which would mean "you are at the tip".
fn assert_conservative(c: &mut PipeChain, within: Duration) {
    let started = Instant::now();
    assert_eq!(c.status(), None);
    assert_eq!(c.next(Some(tip(5, 5))), Err(Unknown), "silence became \"nothing new\"");
    assert_eq!(c.next(None), Err(Unknown));
    assert_eq!(c.post(&[1, 2, 3]), Posted::Unknown);
    assert_eq!(c.problem(), None);
    assert!(!c.alive());
    assert!(started.elapsed() < within, "it took {:?}", started.elapsed());
}

#[test]
fn a_dead_or_silent_chain_is_never_nothing_new() {
    // gone right after the start
    let mut c = raw_peer(vec![], false);
    assert_conservative(&mut c, Duration::from_secs(2));
    // answers once, then dies
    let mut c = raw_peer(vec![frame(0x82, &[])], false);
    assert_eq!(c.next(Some(tip(5, 5))), Ok(Step::Nothing));
    assert_conservative(&mut c, Duration::from_secs(2));
    // alive but silent: one time limit, then every call fails at once
    let mut c = raw_peer(vec![], true);
    let started = Instant::now();
    assert_eq!(c.next(Some(tip(5, 5))), Err(Unknown));
    assert!(started.elapsed() >= Duration::from_millis(350));
    assert_conservative(&mut c, Duration::from_millis(200));
    // a transaction sent into silence is "unknown", not "rejected"
    let mut c = raw_peer(vec![], true);
    assert_eq!(c.post(&[9; 100]), Posted::Unknown);
    assert!(!c.alive());
}

/// The chain process is not trusted with the shape of its answers: one
/// that does not fit the question ends the conversation.
#[test]
fn an_answer_that_does_not_fit_the_question_ends_the_conversation() {
    let at = tip(50, 5);
    let good = encode_block(&block(51, 6, 2)).unwrap();
    let mut with_tail = good.clone();
    with_tail.push(0);
    let cases: Vec<(&str, Option<Tip>, Vec<u8>)> = vec![
        ("a block two above the position", Some(at), frame(0x83, &encode_block(&block(52, 6, 1)).unwrap())),
        ("the block at the position itself", Some(at), frame(0x83, &encode_block(&block(50, 6, 1)).unwrap())),
        ("a block for a wallet without a position", None, frame(0x83, &good)),
        ("\"nothing new\" for a wallet without a position", None, frame(0x82, &[])),
        ("\"nothing new\" with a payload", Some(at), frame(0x82, &[0])),
        ("a step back that goes nowhere", Some(at), frame(0x84, &50u64.to_le_bytes())),
        ("a step back that goes forward", Some(at), frame(0x84, &51u64.to_le_bytes())),
        ("a step back for a wallet without a position", None, frame(0x84, &1u64.to_le_bytes())),
        ("a step back with a tail", Some(at), frame(0x84, &[1; 9])),
        ("verified extension without a prior position", None, frame(0x8A, &encode_tip(Some(at)))),
        ("verified extension to the same height", Some(at), frame(0x8A, &encode_tip(Some(at)))),
        ("a new start without a block", Some(at), frame(0x85, &encode_tip(None))),
        ("a new start cut short", Some(at), frame(0x85, &[1; 20])),
        ("a block with a byte too many", Some(at), frame(0x83, &with_tail)),
        ("a block cut short", Some(at), frame(0x83, &good[..good.len() - 5])),
        ("\"unknown\" with a payload", Some(at), frame(0x8F, &[1])),
        ("an answer to another question", Some(at), frame(0x86, &[1])),
        ("an unknown tag", Some(at), frame(0x33, b"??")),
        ("a frame of length zero", Some(at), 0u32.to_le_bytes().to_vec()),
        ("a frame one byte too large", Some(at), ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec()),
        ("half a frame", Some(at), vec![9, 0, 0, 0, 0x83]),
    ];
    for (what, position, bytes) in cases {
        let mut c = raw_peer(vec![bytes], false);
        assert_eq!(c.next(position), Err(Unknown), "{what}");
        assert!(!c.alive(), "{what}: the conversation went on");
    }
    for (what, bytes) in [
        ("a status of a level that does not exist", frame(0x81, &[9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])),
        ("a status cut short", frame(0x81, &encode_status(&full_status())[..10])),
        ("a block instead of a status", frame(0x83, &good)),
        ("\"unknown\" with a payload", frame(0x8F, &[0])),
    ] {
        let mut c = raw_peer(vec![bytes], false);
        assert_eq!(c.status(), None, "{what}");
        assert!(!c.alive(), "{what}: the conversation went on");
    }
    for (what, bytes) in [
        ("a result that does not exist", frame(0x86, &[9])),
        ("two results", frame(0x86, &[1, 1])),
        ("no result", frame(0x86, &[])),
        ("\"nothing new\" for a broadcast", frame(0x82, &[])),
    ] {
        let mut c = raw_peer(vec![bytes], false);
        assert_eq!(c.post(&[1, 2, 3]), Posted::Unknown, "{what}");
        assert!(!c.alive(), "{what}: the conversation went on");
    }
    for (what, bytes) in [("a problem that is not text", frame(0x87, &[0xFF, 0xFE])), ("an empty problem", frame(0x87, &[]))] {
        let mut c = raw_peer(vec![bytes], false);
        assert_eq!(c.problem(), None, "{what}");
        assert!(!c.alive(), "{what}");
    }
    // and the same answers where they do fit are taken
    let mut c = raw_peer(vec![frame(0x83, &good), frame(0x84, &49u64.to_le_bytes()), frame(0x8F, &[]), frame(0x81, &encode_status(&full_status()))], false);
    assert!(matches!(c.next(Some(at)), Ok(Step::Block(_))));
    assert_eq!(c.next(Some(at)), Ok(Step::Rollback { to: 49 }));
    assert_eq!(c.next(Some(at)), Err(Unknown));
    assert_eq!(c.status(), Some(full_status()));
    assert!(c.alive());
}

/// The old outputs cross the pipe piece by piece, the largest piece
/// included. "I cannot say" stays "I cannot say", and a piece the chain
/// layer hands over that is not the answer to the question is "I cannot
/// say" as well - never an empty piece.
#[test]
fn old_outputs_cross_and_come_back() {
    let e = ends();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let asked2 = asked.clone();
    let largest = old(MAX_OLD_OUTPUTS, Some(8), 4612);
    assert!(encode_old(&largest, 7, false).unwrap().len() > 1_400_000);
    let script = vec![
        Ok(old(2, Some(1), 4612)),
        Ok(largest.clone()),
        Err(Unknown),
        Ok(old(0, None, 4612)),
        // not the answer to the question it was asked: the piece after 4612 pieces
        Ok(old(1, Some(4), 4612)),
    ];
    let (mut sr, mut sw) = (e.server_reads, e.server_writes);
    let server = std::thread::spawn(move || {
        serve(&mut sr, &mut sw, move |_c: Config| {
            Ok(Script {
                asked: asked2,
                old: script,
                ..Script::default()
            })
        })
    });
    let mut c = PipeChain::connect(e.client_reads, e.client_writes, &config(), Duration::from_secs(5)).unwrap();
    assert_eq!(c.old_outputs(0), Ok(old(2, Some(1), 4612)));
    assert_eq!(c.old_outputs(7), Ok(largest));
    assert_eq!(c.old_outputs(8), Err(Unknown));
    assert!(c.alive(), "\"unknown\" is an answer, not a failure of the pipe");
    assert_eq!(c.old_outputs(4611), Ok(old(0, None, 4612)));
    assert_eq!(c.old_outputs(9), Err(Unknown), "a piece that answers another question was handed on");
    assert!(c.alive());
    drop(c);
    server.join().unwrap().unwrap();
    assert_eq!(*asked.lock().unwrap(), ["old 0", "old 7", "old 8", "old 4611", "old 9"]);
}

/// K192: the owner's agreement to the direct way for one transaction
/// crosses the pipe with that transaction and with no other; the answer
/// comes back as for any transaction; a layer that knows no such
/// difference posts it as always; silence is "unknown".
#[test]
fn the_agreement_to_the_direct_way_crosses_with_its_transaction() {
    let e = ends();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let asked2 = asked.clone();
    let (mut sr, mut sw) = (e.server_reads, e.server_writes);
    let server = std::thread::spawn(move || {
        serve(&mut sr, &mut sw, move |_c: Config| {
            Ok(Script {
                asked: asked2,
                posts: vec![Posted::Unknown, Posted::Accepted, Posted::Rejected, Posted::Unknown],
                ..Script::default()
            })
        })
    });
    let mut c = PipeChain::connect(e.client_reads, e.client_writes, &config(), Duration::from_secs(5)).unwrap();
    assert_eq!(c.post(&[7, 1]), Posted::Unknown);
    assert_eq!(c.post_direct(&[7, 1]), Posted::Accepted);
    assert_eq!(c.post_direct(&[8, 1, 2]), Posted::Rejected);
    assert_eq!(c.post(&[8, 1, 2]), Posted::Unknown);
    // nothing is sent for what cannot be a transaction
    assert_eq!(c.post_direct(&[]), Posted::Unknown);
    assert!(c.alive());
    drop(c);
    server.join().unwrap().unwrap();
    assert_eq!(*asked.lock().unwrap(), ["post 2 7", "post-direct 2 7", "post-direct 3 8", "post 3 8"]);

    // a layer that knows no such difference: the transaction is posted as always
    struct Plain(Arc<Mutex<Vec<u8>>>);
    impl ChainFeed for Plain {
        fn status(&mut self) -> Option<Status> {
            None
        }
        fn next(&mut self, _at: Option<Tip>) -> Result<Step, Unknown> {
            Err(Unknown)
        }
        fn post(&mut self, tx: &[u8]) -> Posted {
            self.0.lock().unwrap().extend_from_slice(tx);
            Posted::Accepted
        }
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    assert_eq!(Plain(seen.clone()).post_direct(&[5, 6]), Posted::Accepted);
    assert_eq!(*seen.lock().unwrap(), [5, 6]);
    // silence, and an answer to another question
    let mut c = raw_peer(vec![], true);
    assert_eq!(c.post_direct(&[1]), Posted::Unknown);
    let mut c = raw_peer(vec![frame(0x88, &[])], false);
    assert_eq!(c.post_direct(&[1]), Posted::Unknown);
    assert!(!c.alive());
}

/// K188: a starting point the chain layer made crosses the pipe as it is;
/// the reason there is none crosses as plain text; a record that cannot
/// be one - empty, or longer than a record may be - is never handed on,
/// from either side; and a layer that makes no points says so.
#[test]
fn a_starting_point_or_the_reason_there_is_none_crosses() {
    use fly_paycore_chain_pipe::{NO_POINT_ANSWER, POINT_UNFIT};
    use fly_paycore_chain_port::MAX_POINT_LEN;
    let e = ends();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let asked2 = asked.clone();
    let record = br#"{"height":40,"hash":"ab"}"#.to_vec();
    let longest = vec![b'x'; MAX_POINT_LEN];
    let script = vec![
        Ok(record.clone()),
        Err("not yet: the tip is not confirmed\u{7}\n".to_string()),
        Ok(longest.clone()),
        Ok(Vec::new()),
        Ok(vec![b'x'; MAX_POINT_LEN + 1]),
        Err(String::new()),
    ];
    let (mut sr, mut sw) = (e.server_reads, e.server_writes);
    let server = std::thread::spawn(move || {
        serve(&mut sr, &mut sw, move |_c: Config| {
            Ok(Script {
                asked: asked2,
                points: script,
                ..Script::default()
            })
        })
    });
    let mut c = PipeChain::connect(e.client_reads, e.client_writes, &config(), Duration::from_secs(5)).unwrap();
    assert_eq!(c.point(), Ok(record));
    assert_eq!(c.point(), Err("not yet: the tip is not confirmed??".to_string()));
    assert_eq!(c.point(), Ok(longest));
    assert_eq!(c.point(), Err(POINT_UNFIT.to_string()), "an empty record was handed on");
    assert_eq!(c.point(), Err(POINT_UNFIT.to_string()), "a record longer than one may be was handed on");
    assert_eq!(c.point(), Err(POINT_UNFIT.to_string()), "a refusal without a reason");
    assert!(c.alive(), "a refusal is an answer, not a failure of the pipe");
    drop(c);
    server.join().unwrap().unwrap();
    assert_eq!(asked.lock().unwrap().len(), 6);

    // the other side is anybody: what it sends as a point is held to the same
    for (what, answer) in [
        ("an empty record", frame(0x8B, &[])),
        ("a record too long", frame(0x8B, &vec![b'x'; MAX_POINT_LEN + 1])),
        ("a reason that is not text", frame(0x87, &[0xff, 0xfe])),
        ("an empty reason", frame(0x87, &[])),
        ("an answer to another question", frame(0x88, &[])),
    ] {
        let mut c = raw_peer(vec![answer], false);
        assert_eq!(c.point(), Err(NO_POINT_ANSWER.to_string()), "{what}");
        assert!(!c.alive(), "{what}: the conversation went on");
    }
    // and the reason it gives is shown only as plain text
    let mut c = raw_peer(vec![frame(0x87, b"why\x07\x1b[31m")], false);
    assert_eq!(c.point(), Err("why??[31m".to_string()));
    // silence is not a point
    let mut c = raw_peer(vec![], true);
    assert_eq!(c.point(), Err(NO_POINT_ANSWER.to_string()));

    // a layer that makes no points
    struct Plain;
    impl ChainFeed for Plain {
        fn status(&mut self) -> Option<Status> {
            None
        }
        fn next(&mut self, _at: Option<Tip>) -> Result<Step, Unknown> {
            Err(Unknown)
        }
        fn post(&mut self, _tx: &[u8]) -> Posted {
            Posted::Unknown
        }
    }
    let mut input = frame(0x10, &config().encode().unwrap());
    input.extend_from_slice(&frame(0x07, &[]));
    let mut out = Vec::new();
    assert!(serve(&mut input.as_slice(), &mut out, |_c: Config| Ok(Plain)).is_ok());
    assert_eq!(out, [frame(0x90, &[VERSION]), frame(0x87, b"this chain layer makes no starting points")].concat());
    // what the layer says is made plain before it leaves the process
    let mut out = Vec::new();
    let said = |_c: Config| Ok(Script { points: vec![Err("a\u{7}b".to_string())], ..Script::default() });
    assert!(serve(&mut input.as_slice(), &mut out, said).is_ok());
    assert_eq!(out, [frame(0x90, &[VERSION]), frame(0x87, b"a?b")].concat());
}

/// The same piece without range proofs.
fn bare(outputs: usize, next: Option<u64>, pieces: u64) -> OldOutputs {
    let mut piece = old(outputs, next, pieces);
    piece.outputs.iter_mut().for_each(|o| o.proof.clear());
    piece.bare = true;
    piece
}

/// A wallet that knew its outputs up to a block asks with that block,
/// and the block crosses the pipe as it is. Only such a question may be
/// answered with a piece without range proofs; a whole piece answers it
/// as well. A bare piece that the chain layer hands over for a question
/// that named no block is "I cannot say", and one that arrives in answer
/// to such a question ends the conversation: read as a piece, it would
/// say "nothing of yours here" where nothing could be found.
#[test]
fn a_question_that_names_a_block_may_get_a_bare_piece() {
    let e = ends();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let asked2 = asked.clone();
    let script = vec![
        Ok(bare(MAX_OLD_OUTPUTS, Some(1), 4612)),
        Ok(old(2, Some(8), 4612)),
        Err(Unknown),
        Ok(bare(0, None, 4612)),
        // bare, for a question that named no block
        Ok(bare(2, Some(4), 4612)),
        // with a range proof on one output and none on the others
        Ok(OldOutputs { bare: true, ..old(2, Some(5), 4612) }),
        Ok(OldOutputs { bare: false, ..bare(2, Some(6), 4612) }),
    ];
    let (mut sr, mut sw) = (e.server_reads, e.server_writes);
    let server = std::thread::spawn(move || {
        serve(&mut sr, &mut sw, move |_c: Config| {
            Ok(Script {
                asked: asked2,
                old: script,
                ..Script::default()
            })
        })
    });
    let mut c = PipeChain::connect(e.client_reads, e.client_writes, &config(), Duration::from_secs(5)).unwrap();
    let since = tip(4_000_000, 77);
    assert_eq!(c.old_outputs_since(0, since), Ok(bare(MAX_OLD_OUTPUTS, Some(1), 4612)));
    assert_eq!(c.old_outputs_since(7, since), Ok(old(2, Some(8), 4612)), "a whole piece is an answer too");
    assert_eq!(c.old_outputs_since(8, since), Err(Unknown));
    assert_eq!(c.old_outputs_since(4611, since), Ok(bare(0, None, 4612)));
    assert_eq!(c.old_outputs(3), Err(Unknown), "a bare piece for a question that named no block");
    assert_eq!(c.old_outputs_since(4, since), Err(Unknown), "bare, with range proofs");
    assert_eq!(c.old_outputs_since(5, since), Err(Unknown), "whole, without range proofs");
    assert!(c.alive(), "the chain process said \"unknown\" each time");
    drop(c);
    server.join().unwrap().unwrap();
    assert_eq!(
        *asked.lock().unwrap(),
        ["old 0 since 4000000/77", "old 7 since 4000000/77", "old 8 since 4000000/77", "old 4611 since 4000000/77", "old 3", "old 4 since 4000000/77", "old 5 since 4000000/77"]
    );

    // the encoding: a bare piece is far smaller, and it is the answer
    // only to a question that named a block
    let piece = bare(3, Some(6), 9);
    let bytes = encode_old(&piece, 5, true).unwrap();
    assert_eq!(bytes.len(), 8 + 8 + 32 + 8 + 8 + 1 + 1 + 4 + 3 * (33 + 8 + 1 + 2));
    assert_eq!(decode_old(&bytes, 5, true), Some(piece.clone()));
    assert_eq!(encode_old(&piece, 5, false), None);
    assert_eq!(decode_old(&bytes, 5, false), None);
    let mut with_proof = bytes.clone();
    let len_at = 70 + 33 + 8 + 1;
    with_proof[len_at] = 1;
    with_proof.push(9);
    assert_eq!(decode_old(&with_proof, 5, true), None, "a bare piece with a range proof in it");
    let mut whole = bytes.clone();
    whole[65] = 0;
    assert_eq!(decode_old(&whole, 5, true), None, "a whole piece without range proofs");

    // a chain process that answers a plain question with a bare piece
    let mut c = raw_peer(vec![frame(0x89, &bytes)], false);
    assert_eq!(c.old_outputs(5), Err(Unknown));
    assert!(!c.alive(), "the conversation went on");
    let mut c = raw_peer(vec![frame(0x89, &bytes)], false);
    assert_eq!(c.old_outputs_since(5, since), Ok(piece));
    assert!(c.alive());
}

/// The encoding of a piece: what goes in comes out, the limits hold in
/// both directions, every byte is accounted for, and a piece is read only
/// as the answer to the question that was asked.
#[test]
fn the_wire_form_of_old_outputs_is_exact_and_bounded() {
    let piece = old(3, Some(6), 9);
    let bytes = encode_old(&piece, 5, false).unwrap();
    assert_eq!(bytes.len(), 8 + 8 + 32 + 8 + 8 + 1 + 1 + 4 + 3 * (33 + 8 + 1 + 2 + MAX_PROOF_LEN));
    assert_eq!(decode_old(&bytes, 5, false), Some(piece.clone()));
    let last = old(1, None, 6);
    assert_eq!(decode_old(&encode_old(&last, 5, false).unwrap(), 5, false), Some(last));
    assert_eq!(decode_old(&encode_old(&old(0, Some(1), 2), 0, false).unwrap(), 0, false), Some(old(0, Some(1), 2)));

    // the same bytes as the answer to another question
    assert_eq!(decode_old(&bytes, 4, false), None);
    assert_eq!(decode_old(&bytes, 6, false), None);
    assert_eq!(decode_old(&bytes, 8, false), None, "the last piece cannot name a next one");
    assert_eq!(encode_old(&piece, 4, false), None);
    // every byte is accounted for
    let mut tail = bytes.clone();
    tail.push(0);
    assert_eq!(decode_old(&tail, 5, false), None);
    for cut in [0, 1, 7, 8, 47, 48, 55, 56, 63, 64, 65, 66, 69, 70, 100, bytes.len() - 1] {
        assert_eq!(decode_old(&bytes[..cut], 5, false), None, "cut at {cut}");
    }
    // fields that have no such value
    let field = |at: usize, value: &[u8]| {
        let mut b = bytes.clone();
        b[at..at + value.len()].copy_from_slice(value);
        b
    };
    assert_eq!(decode_old(&field(0, &4u64.to_le_bytes()), 5, false), None, "the number of another piece");
    assert_eq!(decode_old(&field(64, &[2]), 5, false), None, "\"is there a next piece\" is yes or no");
    assert_eq!(decode_old(&field(64, &[0]), 5, false), None, "the end before the last piece");
    assert_eq!(decode_old(&field(48, &901u64.to_le_bytes()), 5, false), None, "complete up to a block that is not applied");
    assert!(decode_old(&field(48, &900u64.to_le_bytes()), 5, false).is_some());
    assert_eq!(decode_old(&field(65, &[2]), 5, false), None, "\"without range proofs\" is yes or no");
    assert_eq!(decode_old(&field(65, &[2]), 5, true), None);
    assert_eq!(decode_old(&field(65, &[1]), 5, false), None, "a bare piece in answer to a question that named no block");
    assert_eq!(decode_old(&field(65, &[1]), 5, true), None, "a bare piece with range proofs");
    assert_eq!(decode_old(&field(66, &4u32.to_le_bytes()), 5, false), None, "more outputs announced than sent");
    assert_eq!(decode_old(&field(66, &2u32.to_le_bytes()), 5, false), None, "fewer outputs announced than sent");
    assert_eq!(decode_old(&field(66, &u32::MAX.to_le_bytes()), 5, false), None, "a count beyond the limit allocates nothing");
    let coinbase_at = 70 + 33 + 8;
    assert_eq!(decode_old(&field(coinbase_at, &[2]), 5, false), None, "\"coinbase\" is yes or no");
    assert_eq!(decode_old(&field(coinbase_at + 1, &0u16.to_le_bytes()), 5, false), None, "an empty proof");
    assert_eq!(decode_old(&field(coinbase_at + 1, &((MAX_PROOF_LEN + 1) as u16).to_le_bytes()), 5, false), None, "a proof too long");
    // the limits in the other direction
    let mut many = old(MAX_OLD_OUTPUTS, Some(6), 9);
    assert!(encode_old(&many, 5, false).is_some());
    many.outputs.push(many.outputs[0].clone());
    assert_eq!(encode_old(&many, 5, false), None);
    let mut empty_proof = old(2, Some(6), 9);
    empty_proof.outputs[1].proof.clear();
    assert_eq!(encode_old(&empty_proof, 5, false), None);
}

/// The chain process is not trusted with the shape of a piece either.
#[test]
fn an_old_piece_that_does_not_fit_the_question_ends_the_conversation() {
    let good = encode_old(&old(2, Some(6), 9), 5, false).unwrap();
    let mut with_tail = good.clone();
    with_tail.push(0);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("the piece before the one asked for", frame(0x89, &encode_old(&old(2, Some(5), 9), 4, false).unwrap())),
        ("the last piece of a shorter list", frame(0x89, &encode_old(&old(2, None, 5), 4, false).unwrap())),
        ("a piece with a byte too many", frame(0x89, &with_tail)),
        ("a piece cut short", frame(0x89, &good[..good.len() - 5])),
        ("an empty answer", frame(0x89, &[])),
        ("\"unknown\" with a payload", frame(0x8F, &[1])),
        ("\"nothing new\" instead of a piece", frame(0x82, &[])),
        ("a block instead of a piece", frame(0x83, &encode_block(&block(51, 6, 2)).unwrap())),
    ];
    for (what, bytes) in cases {
        let mut c = raw_peer(vec![bytes], false);
        assert_eq!(c.old_outputs(5), Err(Unknown), "{what}");
        assert!(!c.alive(), "{what}: the conversation went on");
    }
    // a dead or silent chain process: "I cannot say"
    let mut c = raw_peer(vec![], false);
    assert_eq!(c.old_outputs(5), Err(Unknown));
    let mut c = raw_peer(vec![], true);
    assert_eq!(c.old_outputs(5), Err(Unknown));
    assert!(!c.alive());
    // and where the piece does fit it is taken
    let mut c = raw_peer(vec![frame(0x89, &good), frame(0x8F, &[])], false);
    assert_eq!(c.old_outputs(5), Ok(old(2, Some(6), 9)));
    assert_eq!(c.old_outputs(6), Err(Unknown));
    assert!(c.alive());
}

/// A chain process that fails to start, never answers, or speaks another
/// version is reported; the wallet does not wait for it either.
#[test]
fn a_chain_that_does_not_start_is_reported() {
    // says why
    let e = ends();
    let (mut sr, mut sw) = (e.server_reads, e.server_writes);
    let server = std::thread::spawn(move || {
        serve(&mut sr, &mut sw, |_c: Config| -> Result<Script, String> { Err("no peer\ncan be reached".into()) })
    });
    let r = PipeChain::connect(e.client_reads, e.client_writes, &config(), Duration::from_secs(5));
    assert_eq!(r.err().as_deref(), Some("the chain process did not start: no peer?can be reached"));
    server.join().unwrap().unwrap();
    // another version
    let e = ends();
    let (mut sr, mut sw) = (e.server_reads, e.server_writes);
    std::thread::spawn(move || {
        let mut len = [0u8; 4];
        sr.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
        sr.read_exact(&mut body).unwrap();
        sw.write_all(&2u32.to_le_bytes()).unwrap();
        sw.write_all(&[0x90, VERSION + 1]).unwrap();
        std::thread::sleep(Duration::from_secs(2));
    });
    let r = PipeChain::connect(e.client_reads, e.client_writes, &config(), Duration::from_secs(1));
    assert_eq!(r.err().as_deref(), Some("the chain process did not start"));
    // polled, not waited for
    let e = ends();
    let _hold = (e.server_reads, e.server_writes);
    let began = Instant::now();
    let mut starting = PipeChain::connect_begin(e.client_reads, e.client_writes, &config(), Duration::from_millis(100)).unwrap();
    assert!(starting.poll().is_none());
    assert!(began.elapsed() < Duration::from_millis(1500));
    std::thread::sleep(Duration::from_millis(2100));
    assert_eq!(starting.poll().unwrap().err().as_deref(), Some("the chain process did not start"));
}

/// The chain process's side stops on requests it does not understand
/// instead of guessing at them.
#[test]
fn the_server_stops_on_requests_it_does_not_understand() {
    let hello = frame(0x10, &config().encode().unwrap());
    let run = |input: Vec<u8>| -> (std::io::Result<()>, Vec<u8>) {
        let mut out = Vec::new();
        let r = serve(&mut input.as_slice(), &mut out, |_c: Config| {
            Ok(Script { steps: vec![Ok(Step::Block(Box::new(BlockFacts { height: 6, hash: [6; 32], outputs: vec![OutputFact { commit: [1; 33], proof: vec![], pos: 1, coinbase: false }], ..BlockFacts::default() })))], ..Script::default() })
        });
        (r, out)
    };
    let (r, out) = run(hello.clone());
    assert!(r.is_ok());
    assert_eq!(out, frame(0x90, &[VERSION]));
    assert!(run(frame(0x02, &encode_tip(None))).0.is_err(), "a first frame that is not the start-up message");
    let (r, out) = run(frame(0x10, &[VERSION, 2, 1, 2, 3]));
    assert!(r.is_err());
    assert_eq!(out.get(4), Some(&0x91));
    for (what, request) in [
        ("an unknown request", frame(0x44, &[])),
        ("\"status\" with a payload", frame(0x01, &[1])),
        ("\"problem\" with a payload", frame(0x04, &[1])),
        ("\"point\" with a payload", frame(0x07, &[1])),
        ("a position cut short", frame(0x02, &[1, 5, 0, 0])),
        ("a position with a tail", frame(0x02, &[0, 1])),
        ("no position at all", frame(0x02, &[])),
        ("an empty transaction", frame(0x03, &[])),
        ("an empty transaction with the agreement", frame(0x08, &[])),
        ("a piece without a number", frame(0x05, &[])),
        ("a piece number cut short", frame(0x05, &[1; 7])),
        ("a piece number with a tail", frame(0x05, &[0; 9])),
        ("a piece and no block", frame(0x06, &[0; 8])),
        ("a piece and a block cut short", frame(0x06, &[0; 47])),
        ("a piece and a block with a tail", frame(0x06, &[0; 49])),
        ("a frame cut off", vec![40, 0, 0, 0, 0x02, 1, 2]),
    ] {
        let mut input = hello.clone();
        input.extend_from_slice(&request);
        let (r, out) = run(input);
        assert!(r.is_err(), "{what}");
        assert_eq!(out, frame(0x90, &[VERSION]), "{what}: something was answered");
    }
    // a block the feed produced but the port cannot carry is "unknown", not "nothing"
    let mut input = hello.clone();
    input.extend_from_slice(&frame(0x02, &encode_tip(Some(tip(5, 5)))));
    let (r, out) = run(input);
    assert!(r.is_ok());
    assert_eq!(out, [frame(0x90, &[VERSION]), frame(0x8F, &[])].concat());
    // old outputs from a feed that has none to give: "unknown"
    let mut input = hello.clone();
    input.extend_from_slice(&frame(0x05, &3u64.to_le_bytes()));
    let mut out = Vec::new();
    struct Plain;
    impl ChainFeed for Plain {
        fn status(&mut self) -> Option<Status> {
            None
        }
        fn next(&mut self, _at: Option<Tip>) -> Result<Step, Unknown> {
            Err(Unknown)
        }
        fn post(&mut self, _tx: &[u8]) -> Posted {
            Posted::Unknown
        }
    }
    assert!(serve(&mut input.as_slice(), &mut out, |_c: Config| Ok(Plain)).is_ok());
    assert_eq!(out, [frame(0x90, &[VERSION]), frame(0x8F, &[])].concat());
}
