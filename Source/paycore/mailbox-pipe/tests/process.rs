//! The pipe across a real process boundary: two stand-in transport
//! processes that share a directory as their "relay".
//! Run with `cargo test --features stub`.
#![cfg(feature = "stub")]
use fly_paycore_mailbox::{Mailbox, Published};
use fly_paycore_mailbox_pipe::{Config, PipeMailbox};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const STUB: &str = env!("CARGO_BIN_EXE_mailbox-stub");

struct Temp(PathBuf);
impl Temp {
    fn new(tag: &str) -> Temp {
        let p = std::env::temp_dir().join(format!(
            "fly-pipe-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Temp(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn config(me: u8, dir: &Path) -> Config {
    Config {
        identity_secret: [me; 32],
        identity_public: [me; 32],
        store_key: [0x22; 32],
        relay: "wss://relay.example".into(),
        data_dir: dir.to_string_lossy().into_owned(),
        contacts: vec![],
        delivery_window_secs: 900,
        publish_timeout_ms: 1000,
        poll_ms: 100,
        start_timeout_secs: 10,
        tor_bridges: String::new(),
    }
}
fn start(me: u8, dir: &Path) -> PipeMailbox {
    PipeMailbox::spawn(Path::new(STUB), &config(me, dir), Duration::from_secs(5)).unwrap()
}
fn markers(dir: &Path) -> usize {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "alive"))
        .count()
}
fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(10);
    while !ready() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// A message goes from one process to the other and the reply comes back;
/// dropping the mailbox ends its process.
#[test]
fn a_message_crosses_between_two_processes() {
    let dir = Temp::new("two");
    let mut a = start(1, &dir.0);
    let mut b = start(2, &dir.0);
    assert_ne!(a.process_id(), b.process_id());
    assert_ne!(a.process_id(), Some(std::process::id()), "the transport runs in the wallet's process");
    assert_eq!(markers(&dir.0), 2);

    let envelope = a.seal(&[2; 32], "BEGINSLATEPACK. one ENDSLATEPACK.").unwrap();
    assert_eq!(a.publish(&envelope), Published::Accepted);
    assert_eq!(a.publish(&envelope), Published::Accepted);
    let got = b.next_incoming().expect("nothing arrived in the other process");
    assert_eq!((got.id, got.from, got.text.as_str()), (envelope.event_id, [1; 32], "BEGINSLATEPACK. one ENDSLATEPACK."));
    assert_eq!(b.next_incoming(), None);
    assert_eq!(b.resend_reply(&got.id), None);
    assert_eq!(b.reply(&got.id, "BEGINSLATEPACK. two ENDSLATEPACK."), Published::Accepted);
    b.done(&got.id);
    assert_eq!(b.next_incoming(), None);
    assert_eq!(b.next_incoming(), None);
    let back = a.next_incoming().expect("the reply did not come back");
    assert_eq!((back.from, back.text.as_str()), ([2; 32], "BEGINSLATEPACK. two ENDSLATEPACK."));

    // locking the profile: the mailbox is dropped and its process ends by itself
    drop(a);
    wait_for("the first process to end", || markers(&dir.0) == 1);
    drop(b);
    wait_for("the second process to end", || markers(&dir.0) == 0);
}

/// The transport process crashes, hangs or refuses to start: the wallet's
/// side notices, says no more than it knows, and does not hang.
#[test]
fn a_crashed_or_hung_process_does_not_take_the_wallet_with_it() {
    let dir = Temp::new("faults");
    // crash in the middle of a call
    let mut a = start(1, &dir.0);
    let started = Instant::now();
    assert!(a.seal(&[0xDD; 32], "text").is_err());
    assert!(!a.alive());
    assert_eq!(a.resend_reply(&[1; 32]), Some(Published::Busy));
    assert_eq!(a.next_incoming(), None);
    assert!(started.elapsed() < Duration::from_secs(4));
    drop(a);

    // hang in the middle of a call: one timeout, then the process is ended
    let mut b = PipeMailbox::spawn(Path::new(STUB), &config(2, &dir.0), Duration::from_millis(500)).unwrap();
    let started = Instant::now();
    assert!(b.seal(&[0xCC; 32], "text").is_err());
    assert!(started.elapsed() >= Duration::from_millis(450) && started.elapsed() < Duration::from_secs(4));
    assert!(!b.alive());
    assert_eq!(b.process_id(), None, "a hung process was left running");
    let started = Instant::now();
    assert_eq!(b.reply(&[1; 32], "text"), Published::Unknown);
    assert!(started.elapsed() < Duration::from_millis(100), "a dead transport was waited for again");

    // a transport that refuses its configuration
    let mut bad = config(3, &dir.0);
    bad.relay = "refuse".into();
    let r = PipeMailbox::spawn(Path::new(STUB), &bad, Duration::from_secs(5));
    assert_eq!(r.err().as_deref(), Some("the transport did not start: the relay address is not usable"));
    // a program that is not there, and one that is not a transport
    assert!(PipeMailbox::spawn(Path::new("no-such-program-here"), &config(4, &dir.0), Duration::from_secs(1)).is_err());
    // one that never becomes ready, and one that answers with something else
    for (relay, limit) in [("silent", 6), ("garbage", 4)] {
        let mut c = config(5, &dir.0);
        c.relay = relay.into();
        c.start_timeout_secs = 1;
        let started = Instant::now();
        let r = PipeMailbox::spawn(Path::new(STUB), &c, Duration::from_millis(500));
        assert_eq!(r.err().as_deref(), Some("the transport did not start"), "{relay}");
        assert!(started.elapsed() < Duration::from_secs(limit), "{relay}: {:?}", started.elapsed());
    }
}

/// The secrets cross the pipe, not the command line or the environment.
#[test]
fn nothing_is_passed_outside_the_pipe() {
    let dir = Temp::new("env");
    std::env::set_var("FLY_TEST_SECRET_IN_ENV", "must not be inherited");
    let a = start(1, &dir.0);
    let pid = a.process_id().unwrap();
    #[cfg(target_os = "linux")]
    {
        let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap();
        assert_eq!(cmdline.split(|b| *b == 0).filter(|s| !s.is_empty()).count(), 1, "arguments were passed");
        let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap();
        assert!(environ.is_empty(), "the environment was inherited: {}", String::from_utf8_lossy(&environ));
    }
    let _ = pid;
    drop(a);
}

/// Starting the transport does not hold the wallet up: the answer is
/// polled for, and a transport that never answers is given up on its own
/// start time, not earlier and not never.
#[test]
fn the_wallet_does_not_wait_for_the_transport_to_start() {
    let dir = Temp::new("begin");
    // an ordinary start: not ready at once, ready soon, then usable
    let began = Instant::now();
    let mut starting = PipeMailbox::spawn_begin(Path::new(STUB), &config(1, &dir.0), Duration::from_secs(5)).unwrap();
    assert!(starting.process_id().is_some());
    let mut ready = None;
    wait_for("the transport to report ready", || {
        ready = starting.poll();
        ready.is_some()
    });
    assert!(began.elapsed() < Duration::from_secs(5));
    let mut mailbox = ready.unwrap().unwrap();
    assert!(mailbox.seal(&[2; 32], "hello").is_ok());
    // the value is used up after it has answered
    assert!(matches!(starting.poll(), Some(Err(_))));
    drop(mailbox);
    wait_for("the process to end", || markers(&dir.0) == 0);

    // a transport that never answers
    let mut silent = config(1, &dir.0);
    silent.relay = "silent".into();
    silent.start_timeout_secs = 2;
    let began = Instant::now();
    let mut starting =
        PipeMailbox::spawn_begin(Path::new(STUB), &silent, Duration::from_millis(100)).unwrap();
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
    assert_eq!(answer.unwrap().err().as_deref(), Some("the transport did not start"));

    // dropped while starting: its process is ended at once
    silent.start_timeout_secs = 600;
    let starting = PipeMailbox::spawn_begin(Path::new(STUB), &silent, Duration::from_millis(100)).unwrap();
    let began = Instant::now();
    drop(starting);
    assert!(began.elapsed() < Duration::from_secs(2));

    // a transport that refuses says why
    let mut refuse = config(1, &dir.0);
    refuse.relay = "refuse".into();
    let mut starting = PipeMailbox::spawn_begin(Path::new(STUB), &refuse, Duration::from_secs(5)).unwrap();
    let mut answer = None;
    wait_for("the refusal", || {
        answer = starting.poll();
        answer.is_some()
    });
    assert_eq!(
        answer.unwrap().err().as_deref(),
        Some("the transport did not start: the relay address is not usable")
    );
}
