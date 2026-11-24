//! Sending a transaction through Tor.
//!
//! The node a transaction first reaches can tell where it came from: this
//! program passes on no transactions of others. So the wallet's
//! transactions do not leave from this computer's address. They go through
//! Tor, on a thread of their own:
//!
//! 1. to a node the user listed as their own, by its API over HTTPS, and
//!    then to a public node of the list (7.21) the same way
//!    (`push_transaction`): first as a stem transaction, which the node
//!    passes on along a path before it is announced; when the time of the
//!    stem is up and no node handed the transaction back, once more for
//!    announcing at once;
//! 2. if no public node takes it: to a node of the network, by the node's
//!    own network code, as a stem transaction.
//!
//! Each try goes to another node than the one before. Tor is brought up
//! the first time something is to be sent, and stays up.
//!
//! When Tor cannot be brought up or reaches nobody, nothing is sent any
//! other way - unless the user agreed that a transaction may then go to a
//! node directly, from this computer's address. Without that agreement the
//! wallet is told why the transaction did not go, and it is tried again.
use crate::adapter::Event;
use fly_chain_tips::{Asker, Source};
use grin_core::core::Transaction;
use grin_core::pow::Difficulty;
use grin_p2p::handshake::Handshake;
use grin_p2p::types::NetAdapter;
use grin_p2p::{Capabilities, Peer, PeerAddr};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::time::Duration;

/// How long Tor is given to come up.
pub const START_WITHIN: Duration = Duration::from_secs(120);
/// How long one connection through Tor is given.
pub const REACH_WITHIN: Duration = Duration::from_secs(60);
/// How long one call to a public node is given once connected.
pub const CALL_WITHIN: Duration = Duration::from_secs(30);
/// How long a stem transaction sent to a node by its own network code is
/// given to leave this program before the connection is closed.
pub const LINGER: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 1 } else { 3 });
/// How many public nodes, and then how many network nodes, are tried for
/// one transaction.
pub const TRIES: usize = 2;
/// Most transactions waiting to be sent.
pub const QUEUE: usize = 16;

/// Name of a file in the data directory that makes a test build behave as
/// if Tor could not be brought up.
pub const TEST_NO_TOR_FILE: &str = "no-tor";

/// How the transaction went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Way {
    /// A public node took it by its API.
    Api {
        /// The name of the node.
        host: String,
    },
    /// It was sent to a node of the network as a stem transaction.
    Network {
        /// The node.
        to: SocketAddr,
    },
}

/// What the thread is asked to do.
pub struct Job {
    /// The kernels of the transaction: how the answer finds it again.
    pub key: Vec<[u8; 33]>,
    /// The transaction.
    pub tx: Box<Transaction>,
    /// To be announced at once rather than sent as a stem.
    pub fluff: bool,
    /// Where to start among the public nodes and the network's nodes, so
    /// that a second try goes elsewhere.
    pub turn: usize,
    /// Nodes of the network it may go to.
    pub nodes: Vec<SocketAddr>,
}

/// How a connection to a node is made.
pub enum Dial {
    /// Through Tor, brought up under this directory when first needed.
    Tor {
        /// The data directory of the chain process.
        dir: PathBuf,
        /// Tor, once it is up.
        tor: Option<fly_chain_tor::Tor>,
        /// Tor bridges the user chose, one a line; empty for none. With
        /// any, Tor is reached through them only.
        bridges: String,
    },
    /// Straight to the node: only in a test build, for nodes on this
    /// computer. `up` false: as if Tor could not be brought up.
    #[cfg(feature = "test-net")]
    Straight {
        /// Whether "Tor" comes up.
        up: bool,
    },
}

impl Dial {
    /// How this build reaches nodes for the data directory `dir`.
    pub fn of(dir: PathBuf, bridges: String) -> Dial {
        #[cfg(feature = "test-net")]
        {
            let _ = bridges;
            Dial::Straight {
                up: !dir.join(TEST_NO_TOR_FILE).exists(),
            }
        }
        #[cfg(not(feature = "test-net"))]
        {
            Dial::Tor { dir, tor: None, bridges }
        }
    }

    /// An address on this computer that leads to `host` at `port`.
    fn open(&mut self, host: &str, port: u16) -> Result<SocketAddr, String> {
        match self {
            Dial::Tor { dir, tor, bridges } => {
                if tor.is_none() {
                    // lines that are not bridge lines stop Tor here: it is never reached
                    // directly when the user asked for bridges
                    let chosen = fly_chain_tor::TorBridges::parse(bridges).map_err(|_| fly_chain_tor::TorError::Bridges.to_string())?;
                    let started = fly_chain_tor::Tor::start_through(dir, START_WITHIN, &chosen, &fly_chain_tor::own_program());
                    *tor = Some(started.map_err(|e| e.to_string())?);
                }
                let tor = tor.as_ref().ok_or("Tor did not come up")?;
                tor.bridge(host, port, REACH_WITHIN).map(|bridge| bridge.at).map_err(|e| e.to_string())
            }
            #[cfg(feature = "test-net")]
            Dial::Straight { up } => {
                if !*up {
                    return Err("Tor did not come up".to_string());
                }
                use std::net::ToSocketAddrs;
                (host, port)
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut found| found.find(SocketAddr::is_ipv4))
                    .ok_or_else(|| "Tor did not reach the node".to_string())
            }
        }
    }
}

/// What the thread works with.
pub struct Setup {
    /// How to reach nodes.
    pub dial: Dial,
    /// The public nodes and how to authenticate them: the user's own
    /// first.
    pub sources: Vec<Source>,
    /// How many of them, at the start, are the user's own.
    pub own: usize,
    /// Their authorities; nothing if the secure channel cannot be set up.
    pub asker: Option<Asker>,
    /// The handshake of the node's network code, as the program has it.
    pub handshake: Arc<Handshake>,
    /// Where the network code hands what it receives.
    pub adapter: Arc<dyn NetAdapter>,
}

/// The body of a call that hands a transaction to a node's API.
pub fn push_body(tx: &Transaction, fluff: bool) -> Option<String> {
    let tx = serde_json::to_value(tx).ok()?;
    let call = serde_json::json!({"jsonrpc": "2.0", "method": "push_transaction", "params": [tx, fluff], "id": 1});
    serde_json::to_string(&call).ok()
}

/// Whether a node's answer to `push_transaction` says it took the
/// transaction; if not, its words, cut short.
pub fn pushed(body: &[u8]) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| "the answer is not JSON".to_string())?;
    if let Some(error) = value.get("error").filter(|e| !e.is_null()) {
        return Err(format!("the node would not take it: {}", words(error)));
    }
    let result = value.get("result").ok_or("no result in the answer")?;
    if let Some(err) = result.get("Err") {
        return Err(format!("the node would not take it: {}", words(err)));
    }
    match result.get("Ok") {
        Some(serde_json::Value::Null) => Ok(()),
        _ => Err("not the answer a node gives".to_string()),
    }
}

/// A node's words, printable and short: they go into what the user sees.
fn words(value: &serde_json::Value) -> String {
    value.to_string().chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(120).collect()
}

/// Start the thread. It takes jobs from the returned queue and tells the
/// node's thread how each went.
pub fn start(mut setup: Setup, events: SyncSender<Event>) -> Option<SyncSender<Job>> {
    let (queue, jobs) = sync_channel::<Job>(QUEUE);
    std::thread::Builder::new()
        .name("fly-chain-send".into())
        .spawn(move || work(&mut setup, &jobs, &events))
        .ok()?;
    Some(queue)
}

fn work(setup: &mut Setup, jobs: &Receiver<Job>, events: &SyncSender<Event>) {
    while let Ok(job) = jobs.recv() {
        let result = send(setup, &job);
        if events.send(Event::Sent { key: job.key, result }).is_err() {
            return;
        }
    }
}

/// The items of `list` starting at `turn`, around.
fn from_turn<T: Clone>(list: &[T], turn: usize) -> Vec<T> {
    let at = turn.checked_rem(list.len()).unwrap_or(0);
    list.iter().skip(at).chain(list.iter().take(at)).cloned().collect()
}

fn send(setup: &mut Setup, job: &Job) -> Result<Way, String> {
    let mut why = "there is nobody to send it to".to_string();
    // the public nodes, by their API
    if let (Some(asker), Some(body)) = (setup.asker.clone(), push_body(&job.tx, job.fluff)) {
        // the user's own nodes, all of them, before the listed ones
        let (own, listed) = setup.sources.split_at(setup.own.min(setup.sources.len()));
        let mut order = own.to_vec();
        order.extend(from_turn(listed, job.turn).into_iter().take(TRIES));
        for source in &order {
            let at = match setup.dial.open(&source.host, source.port) {
                Ok(at) => at,
                Err(e) if e == "Tor did not come up" => return Err(e),
                Err(e) => {
                    why = e;
                    continue;
                }
            };
            match asker.call_at(source, &[at], &body, CALL_WITHIN).map_err(|e| e.to_string()).and_then(|answer| pushed(&answer)) {
                Ok(()) => {
                    return Ok(Way::Api {
                        host: source.host.clone(),
                    })
                }
                Err(e) => why = e,
            }
        }
    }
    // the nodes of the network, by their own network code
    for to in from_turn(&job.nodes, job.turn).iter().take(TRIES) {
        let at = match setup.dial.open(&to.ip().to_string(), to.port()) {
            Ok(at) => at,
            Err(e) if e == "Tor did not come up" => return Err(e),
            Err(e) => {
                why = e;
                continue;
            }
        };
        match stem(setup, at, &job.tx) {
            Ok(()) => return Ok(Way::Network { to: *to }),
            Err(e) => why = e,
        }
    }
    Err(why)
}

/// Hand `tx` as a stem transaction to the node behind `at`.
fn stem(setup: &Setup, at: SocketAddr, tx: &Transaction) -> Result<(), String> {
    let conn = TcpStream::connect_timeout(&at, REACH_WITHIN).map_err(|_| "no connection".to_string())?;
    let _ = conn.set_read_timeout(Some(CALL_WITHIN));
    // this process listens nowhere; it says so
    let nowhere = PeerAddr(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
    let peer = Peer::connect(conn, Capabilities::UNKNOWN, Difficulty::from_num(1), nowhere, &setup.handshake, setup.adapter.clone())
        .map_err(|_| "the node did not take the connection".to_string())?;
    let sent = peer.send_stem_transaction(tx).map_err(|_| "the transaction could not be written".to_string());
    // the network code writes on a thread of its own
    std::thread::sleep(LINGER);
    peer.stop("sent");
    sent
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn the_answers_of_a_node() {
        assert_eq!(pushed(br#"{"id":1,"jsonrpc":"2.0","result":{"Ok":null}}"#), Ok(()));
        let refused = pushed(br#"{"id":1,"jsonrpc":"2.0","result":{"Err":{"Internal":"tx pool: DuplicateCommitment"}}}"#);
        assert_eq!(refused, Err(r#"the node would not take it: {"Internal":"tx pool: DuplicateCommitment"}"#.to_string()));
        let rpc = pushed(br#"{"id":1,"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"}}"#);
        assert!(rpc.unwrap_err().starts_with("the node would not take it: "));
        for not in [&b""[..], b"<html>", b"{}", br#"{"result":{}}"#, br#"{"result":{"Ok":1}}"#, br#"{"result":{"Ok":"yes"}}"#] {
            assert!(pushed(not).is_err());
        }
        // what a node says is cut short and kept printable
        let long = format!(r#"{{"result":{{"Err":"{}\u0007"}}}}"#, "x".repeat(500));
        let said = pushed(long.as_bytes()).unwrap_err();
        assert!(said.len() < 160 && !said.contains('\u{7}'), "{said}");
    }

    #[test]
    fn a_second_try_starts_elsewhere() {
        let list = [1, 2, 3];
        assert_eq!(from_turn(&list, 0), vec![1, 2, 3]);
        assert_eq!(from_turn(&list, 1), vec![2, 3, 1]);
        assert_eq!(from_turn(&list, 5), vec![3, 1, 2]);
        assert!(from_turn::<u8>(&[], 3).is_empty());
    }
}

#[cfg(all(test, not(feature = "test-net")))]
mod bridge_tests {
    use super::*;
    use std::time::Instant;

    /// With Tor bridges chosen, a sending never goes round them: lines
    /// that are not bridge lines, a file the host could not use, or a
    /// transport whose program is not next to this one stop Tor before
    /// anything connects.
    #[test]
    fn bridges_that_cannot_be_used_stop_the_way_through_tor() {
        let obfs4 = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";
        // the third case holds where no program for bridges stands next to the test
        // program (a live run on the same machine may have put one there)
        let cases: &[&str] = if fly_chain_tor::own_program().is_file() { &["not a bridge line", "unusable"] } else { &["not a bridge line", "unusable", obfs4] };
        for &chosen in cases {
            let dir = std::env::temp_dir().join(format!("fly-chain-send-bridges-{}-{}", std::process::id(), chosen.len()));
            assert!(std::fs::create_dir_all(&dir).is_ok());
            let mut dial = Dial::of(dir.clone(), chosen.to_string());
            let began = Instant::now();
            let got = dial.open("example.com", 80);
            assert_eq!(got, Err("the Tor bridges cannot be used".to_string()), "{chosen}");
            assert!(began.elapsed() < Duration::from_secs(5));
            // Tor was not started at all: it left nothing behind
            assert!(!dir.join(fly_chain_tor::DIR).join("cache").join("dir.sqlite3").exists());
            assert!(matches!(dial, Dial::Tor { tor: None, .. }));
        }
    }
}
