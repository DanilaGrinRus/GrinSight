//! The chain pipe across a real process boundary: a stand-in chain process
//! that serves blocks from a directory.
//! Run with `cargo test --features stub`.
#![cfg(feature = "stub")]
use fly_paycore_chain_pipe::wire::encode_block;
use fly_paycore_chain_pipe::{Config, PipeChain};
use fly_paycore_chain_port::{BlockFacts, ChainFeed, Level, Posted, Step, Tip, Unknown};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const STUB: &str = env!("CARGO_BIN_EXE_chain-stub");

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str) -> Temp {
        let p = std::env::temp_dir().join(format!(
            "fly-chain-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(p.join("blocks")).unwrap();
        Temp(p)
    }
    fn put(&self, name: &str, content: &[u8]) {
        std::fs::write(self.0.join(name), content).unwrap();
    }
    fn remove(&self, name: &str) {
        std::fs::remove_file(self.0.join(name)).unwrap();
    }
    fn anchor(&self, t: Tip) {
        self.put("anchor", &[t.height.to_le_bytes().as_slice(), &t.hash].concat());
    }
    fn block(&self, height: u64, fill: u8) -> BlockFacts {
        let b = BlockFacts { height, hash: [fill; 32], kernels: vec![[fill; 33]], ..BlockFacts::default() };
        self.put(&format!("blocks/{height:020}.blk"), &encode_block(&b).unwrap());
        b
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn config(dir: &Path, peer: Option<&str>) -> Config {
    Config {
        network: 3,
        genesis: [7; 32],
        data_dir: dir.to_string_lossy().into_owned(),
        peers: peer.map(str::to_string).into_iter().collect(),
        start_timeout_secs: 10,
        direct_post: false,
        tor_bridges: String::new(),
    }
}
fn markers(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "chain-alive"))
        .count()
}
fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn tip(height: u64, fill: u8) -> Tip {
    Tip { height, hash: [fill; 32] }
}

/// A wallet walks the chain of a chain process: a starting point, block
/// after block, the tip, a reorganisation, a chain that has gone dark.
#[test]
fn a_wallet_follows_the_chain_of_another_process() {
    let t = Temp::new("walk");
    t.anchor(tip(100, 1));
    let b101 = t.block(101, 11);
    let b102 = t.block(102, 12);
    let mut c = PipeChain::spawn(Path::new(STUB), &config(&t.0, None), Duration::from_secs(5)).unwrap();
    assert!(c.process_id().is_some());
    assert_eq!(markers(&t.0), 1);

    let s = c.status().unwrap();
    assert_eq!((s.level, s.tip, s.selected, s.confirmed_time, s.k_conf), (Level::AtTip, Some(tip(102, 12)), None, None, 3));
    t.put("time", b"1795000000");
    t.put("selected", b"");
    t.put("k_conf", b"10");
    let s = c.status().unwrap();
    assert_eq!((s.selected, s.confirmed_time, s.k_conf), (Some(tip(102, 12)), Some(1_795_000_000), 10));

    // from nowhere: a starting point; then block by block to the tip
    assert_eq!(c.next(None), Ok(Step::Reanchor(tip(100, 1))));
    assert_eq!(c.next(Some(tip(100, 1))), Ok(Step::Block(Box::new(b101))));
    assert_eq!(c.next(Some(tip(101, 11))), Ok(Step::Block(Box::new(b102))));
    assert_eq!(c.next(Some(tip(102, 12))), Ok(Step::Nothing));
    // a new block appears
    let b103 = t.block(103, 13);
    assert_eq!(c.next(Some(tip(102, 12))), Ok(Step::Block(Box::new(b103))));
    // the chain reorganises below the wallet: one step back at a time
    t.block(102, 22);
    t.block(103, 23);
    assert_eq!(c.next(Some(tip(103, 13))), Ok(Step::Rollback { to: 102 }));
    assert_eq!(c.next(Some(tip(102, 12))), Ok(Step::Rollback { to: 101 }));
    assert!(matches!(c.next(Some(tip(101, 11))), Ok(Step::Block(b)) if b.hash == [22; 32]));
    // a wallet from another chain altogether, or from before the starting point
    assert_eq!(c.next(Some(tip(100, 99))), Ok(Step::Reanchor(tip(100, 1))));
    assert_eq!(c.next(Some(tip(40, 4))), Ok(Step::Reanchor(tip(100, 1))));
    // a wallet ahead of this chain process: it cannot say
    assert_eq!(c.next(Some(tip(500, 5))), Err(Unknown));
    // the layer loses sight of the chain: unknown, and the pipe stays up
    t.put("dark", b"");
    assert_eq!(c.status(), None);
    assert_eq!(c.next(Some(tip(103, 23))), Err(Unknown));
    assert!(c.alive());
    t.remove("dark");
    assert_eq!(c.next(Some(tip(103, 23))), Ok(Step::Nothing));
    t.put("behind", b"");
    assert_eq!(c.status().unwrap().level, Level::Behind);

    // broadcast: what the node said, and "unknown" when it said nothing
    let tx = vec![0x5A; 900];
    assert_eq!(c.post(&tx), Posted::Accepted);
    assert_eq!(std::fs::read(t.0.join("posted/000000.tx")).unwrap(), tx);
    t.put("post-mode", b"rejected");
    assert_eq!(c.post(&tx), Posted::Rejected);
    t.put("post-mode", b"unknown");
    assert_eq!(c.post(&tx), Posted::Unknown);
    assert_eq!(std::fs::read_dir(t.0.join("posted")).unwrap().count(), 2, "sent, though the answer was lost");
    t.put("trouble", b"no peer answers");
    assert_eq!(c.problem().as_deref(), Some("no peer answers"));

    // the wallet closes the pipe: the chain process ends by itself
    drop(c);
    wait_for("the chain process to end", || markers(&t.0) == 0);
}

/// Two wallets, two chain processes, one chain.
#[test]
fn two_chain_processes_serve_the_same_chain() {
    let (shared, a, b) = (Temp::new("shared"), Temp::new("a"), Temp::new("b"));
    shared.anchor(tip(10, 1));
    shared.block(11, 2);
    let peer = format!("dir:{}", shared.0.to_str().unwrap());
    let mut ca = PipeChain::spawn(Path::new(STUB), &config(&a.0, Some(&peer)), Duration::from_secs(5)).unwrap();
    let mut cb = PipeChain::spawn(Path::new(STUB), &config(&b.0, Some(&peer)), Duration::from_secs(5)).unwrap();
    assert_eq!(markers(&shared.0), 2);
    assert_eq!(ca.next(Some(tip(10, 1))), cb.next(Some(tip(10, 1))));
    assert_eq!(ca.status(), cb.status());
    drop(ca);
    wait_for("one chain process to end", || markers(&shared.0) == 1);
    assert_eq!(cb.next(Some(tip(11, 2))), Ok(Step::Nothing));
}

/// A chain process that refuses, never becomes ready, talks nonsense or
/// does not exist is reported, and the wallet is not held up by it.
#[test]
fn a_chain_process_that_does_not_start_is_reported() {
    let t = Temp::new("start");
    let r = PipeChain::spawn(Path::new(STUB), &config(&t.0, Some("refuse")), Duration::from_secs(5));
    assert_eq!(r.err().as_deref(), Some("the chain process did not start: no peer can be reached"));
    let r = PipeChain::spawn(Path::new(STUB), &config(&t.0, Some("garbage")), Duration::from_secs(5));
    assert_eq!(r.err().as_deref(), Some("the chain process did not start"));
    let r = PipeChain::spawn(&t.0.join("no-such-program"), &config(&t.0, None), Duration::from_secs(5));
    assert_eq!(r.err().as_deref(), Some("the chain process could not be started"));

    let mut silent = config(&t.0, Some("silent"));
    silent.start_timeout_secs = 2;
    let began = Instant::now();
    let mut starting = PipeChain::spawn_begin(Path::new(STUB), &silent, Duration::from_millis(100)).unwrap();
    assert!(starting.poll().is_none());
    assert!(began.elapsed() < Duration::from_millis(1500), "poll must not wait");
    std::thread::sleep(Duration::from_millis(1000));
    assert!(starting.poll().is_none(), "given up before its start time");
    let mut answer = None;
    wait_for("the start time to pass", || {
        answer = starting.poll();
        answer.is_some()
    });
    assert!(began.elapsed() >= Duration::from_secs(2));
    assert_eq!(answer.unwrap().err().as_deref(), Some("the chain process did not start"));
    // dropped while starting: its process is ended at once
    silent.start_timeout_secs = 600;
    let starting = PipeChain::spawn_begin(Path::new(STUB), &silent, Duration::from_millis(100)).unwrap();
    let began = Instant::now();
    drop(starting);
    assert!(began.elapsed() < Duration::from_secs(2));
    // a chain process that dies in the middle of a call
    let mut c = PipeChain::spawn(Path::new(STUB), &config(&t.0, None), Duration::from_secs(5)).unwrap();
    let pid = c.process_id().unwrap();
    let done = if cfg!(windows) {
        std::process::Command::new("taskkill").args(["/PID", &pid.to_string(), "/F"]).output()
    } else {
        std::process::Command::new("kill").args(["-9", &pid.to_string()]).output()
    };
    assert!(done.unwrap().status.success());
    assert_eq!(c.next(Some(tip(1, 1))), Err(Unknown));
    assert_eq!(c.status(), None);
    assert!(!c.alive());
}
