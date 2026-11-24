//! The pipe within one process: a scripted mailbox behind `serve`, and
//! servers that die, hang or talk nonsense.
use fly_paycore_mailbox::{Envelope, Incoming, Mailbox, Published};
use fly_paycore_mailbox_pipe::{serve, Config, PipeMailbox, MAX_FRAME, VERSION};
use std::io::{PipeReader, PipeWriter, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn config() -> Config {
    Config {
        identity_secret: [0x11; 32],
        identity_public: [0x11; 32],
        store_key: [0x22; 32],
        relay: "wss://relay.example".into(),
        data_dir: "C:\\Users\\тест\\AppData\\fly".into(),
        contacts: vec![[0xA1; 32], [0xB2; 32]],
        delivery_window_secs: 900,
        publish_timeout_ms: 20_000,
        poll_ms: 100,
        start_timeout_secs: 2,
        tor_bridges: String::new(),
    }
}

/// Answers from a script and records what it was asked.
#[derive(Default)]
struct Script {
    log: Arc<Mutex<Vec<String>>>,
    publish: Vec<Published>,
    incoming: Vec<Option<Incoming>>,
    resend: Vec<Option<Published>>,
    problems: Vec<Option<String>>,
}
impl Mailbox for Script {
    fn seal(&mut self, to: &[u8; 32], text: &str) -> Result<Envelope, String> {
        self.log.lock().unwrap().push(format!("seal {:02x} {}", to[0], text.len()));
        if text == "bad" {
            return Err("secret detail that must not cross".into());
        }
        Ok(Envelope {
            event_id: [text.len() as u8; 32],
            bytes: text.as_bytes().iter().rev().copied().collect(),
            expires_at: 1_234_567_890_123,
        })
    }
    fn publish(&mut self, e: &Envelope) -> Published {
        self.log
            .lock()
            .unwrap()
            .push(format!("publish {:02x} {} {}", e.event_id[0], e.expires_at, e.bytes.len()));
        self.publish.remove(0)
    }
    fn next_incoming(&mut self) -> Option<Incoming> {
        self.log.lock().unwrap().push("next".into());
        self.incoming.remove(0)
    }
    fn resend_reply(&mut self, incoming: &[u8; 32]) -> Option<Published> {
        self.log.lock().unwrap().push(format!("resend {:02x}", incoming[0]));
        self.resend.remove(0)
    }
    fn reply(&mut self, incoming: &[u8; 32], text: &str) -> Published {
        self.log.lock().unwrap().push(format!("reply {:02x} {text}", incoming[0]));
        Published::Full
    }
    fn done(&mut self, incoming: &[u8; 32]) {
        self.log.lock().unwrap().push(format!("done {:02x}", incoming[0]));
    }
    fn problem(&mut self) -> Option<String> {
        if self.problems.is_empty() {
            return None;
        }
        self.problems.remove(0)
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

/// Every call crosses the pipe and comes back as it was.
#[test]
fn every_call_crosses_and_comes_back() {
    let e = ends();
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::new(Mutex::new(None));
    let (log2, seen2) = (log.clone(), seen.clone());
    let all = [
        Published::Accepted,
        Published::Unknown,
        Published::Busy,
        Published::Full,
        Published::Expired,
    ];
    let long = "я".repeat(40_000);
    let long2 = long.clone();
    let (mut sr, mut sw) = (e.server_reads, e.server_writes);
    let server = std::thread::spawn(move || {
        serve(&mut sr, &mut sw, move |c: Config| {
            *seen2.lock().unwrap() = Some(c);
            Ok(Script {
                log: log2,
                publish: all.to_vec(),
                incoming: vec![
                    Some(Incoming { id: [7; 32], from: [8; 32], text: long2 }),
                    None,
                    Some(Incoming { id: [9; 32], from: [8; 32], text: String::new() }),
                ],
                resend: vec![None, Some(Published::Accepted), Some(Published::Expired)],
                // a relay's words may be anything: control characters, other
                // scripts, any length
                problems: vec![Some(format!("the relay said: no\n\u{1b}[31mway\u{7} é{}", "x".repeat(500))), Some(String::new()), None],
            })
        })
    });
    let mut m = PipeMailbox::connect(e.client_reads, e.client_writes, &config(), Duration::from_secs(5)).unwrap();
    assert_eq!(seen.lock().unwrap().take(), Some(config()), "the configuration changed on the way");

    let sealed = m.seal(&[0xA1; 32], "hello").unwrap();
    assert_eq!((sealed.event_id, sealed.expires_at, sealed.bytes.as_slice()), ([5; 32], 1_234_567_890_123, &b"olleh"[..]));
    // the transport's own words about a failure stay on its side
    assert_eq!(m.seal(&[0xA1; 32], "bad"), Err("the transport could not seal the message".to_string()));
    let big = Envelope { event_id: [0x42; 32], expires_at: u64::MAX, bytes: vec![0xEE; MAX_FRAME - 64] };
    for expected in all {
        assert_eq!(m.publish(&big), expected);
    }
    let first = m.next_incoming().unwrap();
    assert_eq!((first.id, first.from, first.text.as_str()), ([7; 32], [8; 32], long.as_str()));
    assert_eq!(m.next_incoming(), None);
    assert_eq!(m.next_incoming().unwrap().text, "");
    assert_eq!(m.resend_reply(&[3; 32]), None);
    assert_eq!(m.resend_reply(&[3; 32]), Some(Published::Accepted));
    assert_eq!(m.resend_reply(&[3; 32]), Some(Published::Expired));
    assert_eq!(m.reply(&[4; 32], "an answer"), Published::Full);
    m.done(&[6; 32]);
    // the transport's description of its trouble arrives as plain text of
    // bounded length, whatever it was made of
    let said = m.problem().unwrap();
    assert!(said.starts_with("the relay said: no??[31mway? ?xxx"), "{said}");
    assert_eq!(said.len(), 240);
    assert!(said.chars().all(|c| c.is_ascii_graphic() || c == ' '));
    assert_eq!(m.problem(), None, "an empty description is no description");
    assert_eq!(m.problem(), None);
    assert!(m.alive());
    drop(m);
    server.join().unwrap().unwrap();
    let log = log.lock().unwrap();
    assert_eq!(log[0], "seal a1 5");
    assert_eq!(log[2], format!("publish 42 {} {}", u64::MAX, MAX_FRAME - 64));
    assert_eq!(log[log.len() - 2], "reply 04 an answer");
    assert_eq!(log[log.len() - 1], "done 06");
    // nothing secret in what Debug prints
    let shown = format!("{:?}", config());
    assert!(!shown.contains("17") && !shown.contains("11") && !shown.contains("relay"), "{shown}");
}

/// What the wallet's side says when the transport is not there to answer:
/// never more than it knows, and never "there is no stored reply".
fn assert_conservative(m: &mut PipeMailbox, within: Duration) {
    let started = Instant::now();
    assert!(m.seal(&[1; 32], "text").is_err());
    assert_eq!(m.publish(&Envelope { event_id: [1; 32], bytes: vec![1], expires_at: 1 }), Published::Unknown);
    assert_eq!(m.next_incoming(), None);
    assert_eq!(m.resend_reply(&[1; 32]), Some(Published::Busy), "a missing answer became \"no stored reply\"");
    assert_eq!(m.reply(&[1; 32], "text"), Published::Unknown);
    m.done(&[1; 32]);
    assert_eq!(m.problem(), None);
    assert!(!m.alive());
    assert!(started.elapsed() < within, "it took {:?}", started.elapsed());
}

#[test]
fn a_transport_that_fails_to_start_is_reported() {
    let e = ends();
    let (mut sr, mut sw) = (e.server_reads, e.server_writes);
    let server = std::thread::spawn(move || {
        serve(&mut sr, &mut sw, |_c: Config| Err::<Script, String>("Tor did not come up".into()))
    });
    let r = PipeMailbox::connect(e.client_reads, e.client_writes, &config(), Duration::from_secs(5));
    assert_eq!(r.err().as_deref(), Some("the transport did not start: Tor did not come up"));
    server.join().unwrap().unwrap();

    // a peer that never says anything: the start times out
    let e = ends();
    let _keep = (e.server_reads, e.server_writes);
    let started = Instant::now();
    let r = PipeMailbox::connect(e.client_reads, e.client_writes, &config(), Duration::from_millis(200));
    assert_eq!(r.err().as_deref(), Some("the transport did not start"));
    assert!(started.elapsed() < Duration::from_secs(4));

    // a peer of another version
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
    let r = PipeMailbox::connect(e.client_reads, e.client_writes, &config(), Duration::from_secs(1));
    assert!(r.is_err());
}

/// A raw peer: says "ready", then answers every request with fixed bytes.
fn raw_peer(answers: Vec<Vec<u8>>, then_hang: bool) -> PipeMailbox {
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
    PipeMailbox::connect(e.client_reads, e.client_writes, &config(), Duration::from_millis(400)).unwrap()
}
fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut f = ((body.len() + 1) as u32).to_le_bytes().to_vec();
    f.push(tag);
    f.extend_from_slice(body);
    f
}

#[test]
fn a_dead_or_silent_transport_is_never_overstated() {
    // gone right after the start
    let mut m = raw_peer(vec![], false);
    assert_conservative(&mut m, Duration::from_secs(2));
    // answers once, then is gone
    let mut m = raw_peer(vec![frame(0x85, &[])], false);
    assert_eq!(m.next_incoming(), None);
    assert!(m.alive());
    assert_conservative(&mut m, Duration::from_secs(2));
    // alive but silent: one timeout, then everything fails at once
    let mut m = raw_peer(vec![], true);
    let started = Instant::now();
    assert_eq!(m.resend_reply(&[1; 32]), Some(Published::Busy));
    assert!(started.elapsed() >= Duration::from_millis(350) && started.elapsed() < Duration::from_secs(3));
    assert_conservative(&mut m, Duration::from_millis(200));
}

#[test]
fn a_transport_that_talks_nonsense_is_cut_off() {
    let nonsense: Vec<(&str, Vec<u8>)> = vec![
        ("an answer to another question", frame(0x87, &[])),
        ("an unknown tag", frame(0x33, b"??")),
        ("a result code that does not exist", frame(0x83, &[9])),
        ("two result codes", frame(0x83, &[1, 1])),
        ("no result code", frame(0x83, &[])),
        ("a frame of length zero", 0u32.to_le_bytes().to_vec()),
        ("a frame of four gigabytes", u32::MAX.to_le_bytes().to_vec()),
        ("a frame one byte too large", ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec()),
        ("half a frame", vec![9, 0, 0, 0, 0x83]),
    ];
    for (what, bytes) in nonsense {
        let mut m = raw_peer(vec![bytes], false);
        assert_eq!(
            m.publish(&Envelope { event_id: [1; 32], bytes: vec![1], expires_at: 1 }),
            Published::Unknown,
            "{what}"
        );
        assert!(!m.alive(), "{what}: the conversation went on");
    }
    // per call: malformed answers of the right kind
    let mut m = raw_peer(vec![frame(0x81, &[1; 39])], false);
    assert!(m.seal(&[1; 32], "x").is_err(), "an envelope without an id");
    let mut m = raw_peer(vec![frame(0x81, &[1; 40])], false);
    assert!(m.seal(&[1; 32], "x").is_err(), "an envelope without bytes");
    assert!(!m.alive());
    let mut m = raw_peer(vec![frame(0x84, &[1; 63])], false);
    assert_eq!(m.next_incoming(), None);
    assert!(!m.alive());
    let mut bad_text = vec![1u8; 64];
    bad_text.extend_from_slice(&[0xFF, 0xFE]);
    let mut m = raw_peer(vec![frame(0x84, &bad_text)], false);
    assert_eq!(m.next_incoming(), None, "text that is not text");
    for (what, body) in [("a description that is not text", &[0xFF, 0xFE][..]), ("an empty description", &[][..])] {
        let mut m = raw_peer(vec![frame(0x88, body)], false);
        assert_eq!(m.problem(), None, "{what}");
        assert!(!m.alive(), "{what}: the conversation went on");
    }
    // a well-formed message in a frame one byte over the limit is not taken
    let mut over = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
    over.push(0x84);
    over.extend_from_slice(&vec![b'a'; MAX_FRAME]);
    let mut m = raw_peer(vec![over], false);
    assert_eq!(m.next_incoming(), None, "an oversized frame was read");
    assert!(!m.alive());
    let mut m = raw_peer(vec![frame(0x86, &[1])], false);
    assert_eq!(m.resend_reply(&[1; 32]), Some(Published::Busy), "\"no reply\" with a tail");
    let mut m = raw_peer(vec![frame(0x85, &[])], false);
    assert_eq!(m.resend_reply(&[1; 32]), Some(Published::Busy), "\"nothing arrived\" as an answer about a reply");
    assert!(!m.alive());
}

/// The transport's side gives up on a wallet it does not understand.
#[test]
fn the_server_stops_on_requests_it_does_not_understand() {
    let hello = |c: &Config| -> Vec<u8> {
        // the client's own start-up frame, captured from a real client
        let e = ends();
        let (mut sr, _sw) = (e.server_reads, e.server_writes);
        let c = c.clone();
        let t = std::thread::spawn(move || {
            let _ = PipeMailbox::connect(e.client_reads, e.client_writes, &c, Duration::from_millis(100));
        });
        let mut len = [0u8; 4];
        sr.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
        sr.read_exact(&mut body).unwrap();
        t.join().unwrap();
        let mut f = len.to_vec();
        f.extend_from_slice(&body);
        f
    };
    let good = hello(&config());
    let run = |input: Vec<u8>| -> (std::io::Result<()>, Vec<u8>) {
        let mut out = Vec::new();
        let r = serve(&mut input.as_slice(), &mut out, |_c: Config| Ok(Script::default()));
        (r, out)
    };
    // nothing at all, and a clean start followed by the end of the pipe
    assert!(run(vec![]).0.is_ok());
    let (r, out) = run(good.clone());
    assert!(r.is_ok());
    assert_eq!(out, frame(0x90, &[VERSION]));
    // a first frame that is not the start-up message
    assert!(run(frame(0x03, &[])).0.is_err());
    // a start-up message cut short, or with a tail, or of another version
    let mut short = good.clone();
    short.truncate(good.len() - 3);
    short[..4].copy_from_slice(&((good.len() - 7) as u32).to_le_bytes());
    let (r, out) = run(short);
    assert!(r.is_err());
    assert_eq!(out.get(4), Some(&0x91));
    let mut other = good.clone();
    other[5] = VERSION + 1;
    assert!(run(other).0.is_err());
    // after a good start: requests that make no sense
    for (what, request) in [
        ("an unknown request", frame(0x44, &[])),
        ("a key cut short", frame(0x06, &[1; 31])),
        ("a key with a tail", frame(0x04, &[1; 33])),
        ("\"next\" with a payload", frame(0x03, &[1])),
        ("\"problem\" with a payload", frame(0x07, &[1])),
        ("an envelope without a deadline", frame(0x02, &[1; 35])),
        ("text that is not text", frame(0x01, &[[1u8; 32].as_slice(), &[0xFF, 0xFE]].concat())),
        ("a frame cut off", vec![40, 0, 0, 0, 0x01, 1, 2]),
    ] {
        let mut input = good.clone();
        input.extend_from_slice(&request);
        let (r, out) = run(input);
        assert!(r.is_err(), "{what}");
        assert_eq!(out, frame(0x90, &[VERSION]), "{what}: something was answered");
    }
}
