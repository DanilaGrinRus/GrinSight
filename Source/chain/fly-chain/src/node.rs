//! The one thread that owns the header chain and decides what to ask of
//! whom.
//!
//! Peers are a source of headers, of claims and of pieces of the state. Headers are verified before
//! they count for anything; claims ("my chain has this much work") decide
//! only whom to ask next. A peer that sends a header no valid chain can
//! contain is dropped for the rest of the run, and so is a peer that sends
//! a piece of state that does not fit the verified header. Nothing a peer
//! says is passed on as a fact.
use crate::accept::{Accept, Block, Facts, History, Surveyed};
use crate::adapter::{Adapter, Event, OurTip, Watch};
use fly_chain_tips::Said;
use crate::follow::{Follow, Got};
use crate::old::{Came, Old};
use crate::post::{Do, Outbox, Trail};
use crate::schedule::Piece;
use crate::state::{Arrived, Fetch, Took};
use fly_chain_state::advance::Rejected;
use fly_chain_state::blocks::BlocksError;
use fly_paycore_chain_port::{Step, Tip, Unknown};
use fly_chain_state::store::{Store, StoreError};
use fly_chain_headers::chain::{HeaderChain, OpenError, Outcome, MAX_BATCH};
use fly_chain_headers::rules::Reject;
use fly_chain_headers::Net;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::BlockHeader;
use grin_core::global;
use grin_core::pow::Difficulty;
use grin_p2p::handshake::Handshake;
use grin_p2p::types::NetAdapter;
use grin_p2p::{Capabilities, P2PConfig, Peer, PeerAddr};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Peers kept connected.
pub const TARGET_PEERS: usize = 3;
/// Peers kept connected while there is much to fetch: the state, a long
/// run of blocks, the old outputs. A node is asked no faster for it -
/// there are more nodes to ask.
pub const BULK_PEERS: usize = 8;
/// Most addresses remembered from names and arguments.
const MAX_CANDIDATES: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// An answer shorter than a full one is over when nothing more of it has
/// come for this long. The network code hands an answer over in pieces and
/// does not say which piece is the last.
const REPLY_IDLE: Duration = Duration::from_secs(2);
const PING_EVERY: Duration = Duration::from_secs(10);
const RETRY_FIRST: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(300);
const TICK: Duration = Duration::from_millis(200);
/// Blocks looked at for the wallet's kernels in one round of housekeeping.
const MAX_LOOKED: usize = 64;
/// How long a remark about a dropped peer stays in the problem text.
const REMARK_FOR: Duration = Duration::from_secs(120);
/// How long a peer is not asked again after an answer that added nothing to
/// the chain; doubled every time in a row, up to [`ASK_AGAIN_MAX`]. A claim
/// of more work is not a reason to ask without end.
const ASK_AGAIN: Duration = Duration::from_secs(30);
const ASK_AGAIN_MAX: Duration = Duration::from_secs(600);
/// Answers in a row that fit nowhere before a peer is left.
const MAX_DETACHED: u32 = 3;
/// How long the state is wanted while every place is taken by a node that
/// does not give its state out, before one of them is left for another.
const NO_STATE_NODE_FOR: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 3 } else { 30 });

/// Names that list nodes of the main network. From the Grin node's source.
pub const MAIN_SEEDS: &[&str] = &[
    "mainnet-seed.grinnode.live",
    "grincoin.org",
    "main.gri.mw",
    "mainnet.grinffindor.org",
    "main-seed.grin.money",
    "mainnet.grin-coffee.com",
    "main.seed.grin.raubritter.org",
    "mainnet.fountainoffairfortune.it",
];
/// The same for the test network.
pub const TEST_SEEDS: &[&str] = &[
    "testnet.grincoin.org",
    "test.gri.mw",
    "testnet.grinffindor.org",
    "test-seed.grin.money",
    "testnet.grin-coffee.com",
    "test.seed.grin.raubritter.org",
    "testnet.fountainoffairfortune.it",
];

/// What the node is started with.
pub struct Settings {
    /// The network.
    pub net: Net,
    /// Directory for the header file.
    pub data_dir: PathBuf,
    /// Peers the user named, `host:port` or `host`. Empty: the network's
    /// seed names are asked.
    pub peers: Vec<String>,
    /// The record of the starting point.
    pub record: Vec<u8>,
    /// Who vouches for it.
    pub point: crate::PointKind,
    /// Whom to ask whether the tip is the network's.
    pub tips: crate::accept::Setup,
    /// The user agreed that a transaction Tor fails to send goes out from
    /// this computer's address.
    pub direct_post: bool,
    /// The user switched Tor off (K189): none is brought up, and a
    /// transaction goes out over this program's own connections.
    pub tor_off: bool,
    /// Tor bridges the user chose, one a line; empty for none.
    pub tor_bridges: String,
}

/// What the rest of the process may know about the node. A copy, renewed
/// several times a second.
#[derive(Clone, Debug, Default)]
pub struct View {
    /// The header file is open and verified.
    pub ready: bool,
    /// Why the node cannot work at all, if it cannot.
    pub failed: Option<String>,
    /// Height of the starting point.
    pub start: u64,
    /// Who vouches for it.
    pub point: crate::PointKind,
    /// What this build knows of the history before the starting point, in
    /// words; nothing in a build without the proof of history (0.4.6e).
    pub history: Option<&'static str>,
    /// Height of the starting point whose header file gave way to this
    /// one's when the program started.
    pub replaced: Option<u64>,
    /// Height of the last verified header.
    pub height: u64,
    /// Its hash.
    pub hash: [u8; 32],
    /// Total work up to it.
    pub work: u64,
    /// Its own time, Unix seconds.
    pub time: u64,
    /// Headers found in the file and verified again at opening.
    pub kept: u64,
    /// Bytes cut from the file at opening.
    pub cut_bytes: u64,
    /// Peers connected now.
    pub peers: usize,
    /// The greatest height a connected peer claims.
    pub best_seen: u64,
    /// At least one peer is connected and none claims more work than has
    /// been verified here.
    pub caught_up: bool,
    /// What stands in the way, in words for the user.
    pub problem: Option<String>,
    /// The state being collected, once it is known at which header.
    pub state: Option<StateView>,
    /// The blocks applied since the archive header, once the state is
    /// collected.
    pub blocks: Option<BlocksView>,
    /// The tip of the verified headers is selected: the time is
    /// confirmed, public nodes named this tip or one it is built on, and
    /// nothing stands against it.
    pub(crate) selected: bool,
    /// Evidence for the time, to be rechecked when a reader uses this view.
    pub(crate) clock: Option<fly_chain_tips::time::Time>,
    /// A claim of more work went unsettled not long ago.
    pub caveat: bool,
    /// Why the tip is not selected, in words.
    pub unselected: Option<String>,
    /// The signs that are up, in words.
    pub signs: Option<String>,
    /// Why a transaction the wallet handed over is not out, in words.
    pub unsent: Option<String>,
}

impl View {
    /// Reads the selected-header decision and the confirmed time at the same instant.
    pub fn selection(&self) -> (bool, Option<u64>) {
        self.selection_at(Instant::now(), clock_ms())
    }

    fn selection_at(&self, now: Instant, clock_ms: u64) -> (bool, Option<u64>) {
        let seconds = self.clock.and_then(|time| time.at(now, clock_ms))
            .and_then(|(low, _)| low.checked_div(1_000));
        (self.selected && seconds.is_some(), seconds)
    }
}

/// How far the blocks have come.
#[derive(Clone, Debug, Default)]
pub struct BlocksView {
    /// Height of the archive header, where the blocks begin.
    pub base: u64,
    /// Height of the last block applied.
    pub height: u64,
    /// Its hash.
    pub hash: [u8; 32],
    /// Outputs unspent after it.
    pub unspent: u64,
    /// Blocks found in the file and applied again at opening.
    pub kept: u64,
    /// Bytes cut from the file at opening.
    pub cut_bytes: u64,
    /// Length of the file.
    pub file_bytes: u64,
    /// The last block applied is the tip of the verified header chain, and
    /// no connected node claims more work.
    pub at_tip: bool,
}

/// How far collecting the state has come.
#[derive(Clone, Debug, Default)]
pub struct StateView {
    /// Height of the archive header the state is at.
    pub height: u64,
    /// Hash of that header.
    pub hash: [u8; 32],
    /// Segments it takes in all.
    pub segments: u64,
    /// Segments taken.
    pub done: u64,
    /// Everything is collected and checked.
    pub complete: bool,
    /// Unspent outputs in the state, once it is complete.
    pub unspent: u64,
    /// Segments found in the file and verified again at opening.
    pub kept: u64,
    /// Bytes cut from the file at opening.
    pub cut_bytes: u64,
    /// Length of the file.
    pub file_bytes: u64,
    /// Milliseconds this program spent checking segments that came before
    /// their turn, and taking segments in.
    pub work_ms: (u64, u64),
    /// The height at which collecting was given up for this one, if the
    /// network moved on to a newer archive header meanwhile.
    pub again_from: Option<u64>,
}

/// The view shared with the thread that answers the wallet.
pub type SharedView = Arc<Mutex<View>>;

/// This computer's clock, in milliseconds since 1970.
pub(crate) fn clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn later(at: Instant, by: Duration) -> Instant {
    at.checked_add(by).unwrap_or(at)
}

#[derive(PartialEq, Eq)]
enum Try {
    Idle,
    Pending,
    Connected,
}

struct Candidate {
    addr: SocketAddr,
    state: Try,
    next_try: Instant,
    wait: Duration,
    dropped: bool,
}

struct Link {
    addr: SocketAddr,
    peer: Arc<Peer>,
    work: u64,
    height: u64,
    last_ping: Instant,
    detached: u32,
    /// Not asked before this moment.
    rest_until: Instant,
    /// Answers in a row that added nothing to the chain.
    fruitless: u32,
    /// Whether the node says it gives its state out in segments.
    pibd: bool,
}

/// A request for headers that is out.
#[derive(Clone, Copy)]
struct Pending {
    addr: SocketAddr,
    at: Instant,
    /// When the last piece of the answer came.
    last: Instant,
    /// Headers received since the request.
    got: usize,
    /// Whether any of them made the chain longer or heavier.
    progress: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The answer may still be coming.
    Wait,
    /// As many headers as a node sends at once: there is more to ask for.
    Full,
    /// A shorter answer, and nothing more of it came: the node has no more.
    Done,
    /// No answer at all.
    Silent,
}

impl Pending {
    fn verdict(&self, now: Instant) -> Verdict {
        if self.got >= MAX_BATCH {
            Verdict::Full
        } else if self.got > 0 {
            if now.saturating_duration_since(self.last) >= REPLY_IDLE {
                Verdict::Done
            } else {
                Verdict::Wait
            }
        } else if now.saturating_duration_since(self.at) > REQUEST_TIMEOUT {
            Verdict::Silent
        } else {
            Verdict::Wait
        }
    }
}

struct Node {
    chain: HeaderChain,
    point: crate::PointKind,
    /// What this build knows of the history before the starting point.
    past: Option<&'static str>,
    /// Where transactions to be sent through Tor are handed over.
    sender: Option<SyncSender<crate::send::Job>>,
    /// The owner's switch, shared with the thread that sends through Tor.
    tor_off: Arc<AtomicBool>,
    /// How the last transaction went out.
    last_sent: Option<crate::send::Way>,
    /// Lines of the user's file of own nodes that named none.
    own_refused: usize,
    events: SyncSender<Event>,
    adapter: Arc<dyn NetAdapter>,
    handshake: Arc<Handshake>,
    tip: Arc<OurTip>,
    candidates: Vec<Candidate>,
    links: Vec<Link>,
    asked: Option<Pending>,
    names_left: usize,
    last_failure: Option<String>,
    remark: Option<(String, Instant)>,
    held: bool,
    file_trouble: bool,
    data_dir: PathBuf,
    fetch: Option<Fetch>,
    /// Whether the state file of an earlier run has been looked at.
    file_tried: bool,
    /// Why the state cannot be collected now, if it cannot.
    state_note: Option<String>,
    again_from: Option<u64>,
    /// Since when the state has been wanted with no node to ask.
    no_state_node_since: Option<Instant>,
    follow: Option<Follow>,
    /// Why the blocks cannot be followed, if they cannot.
    blocks_note: Option<String>,
    // Next local reopen and its backoff after an I/O failure.
    blocks_retry: Option<(Instant, Duration)>,
    /// The outputs older than the blocks, for a wallet that asks.
    old: Old,
    /// The block a wallet last named as the one it knew its outputs up
    /// to, with the number of leaves of the output MMR after it.
    old_since: Option<(Tip, u64)>,
    /// The wallet's transactions that were sent, and the blocks whose
    /// kernels were looked at for them.
    outbox: Outbox,
    trail: Trail,
    watch: Arc<Mutex<Watch>>,
    waiting_segments: Arc<AtomicUsize>,
    /// Whether the tip is called selected, and the asking behind that.
    accept: Accept,
    /// The last headers of the verified chain, for the asking.
    history: History,
    /// The time in the header of the starting point.
    start_time: u64,
}

/// The height of the header at which nodes give their state out when the
/// chain is `tip` high: so far below the tip, and on a round height.
pub fn archive_height(tip: u64) -> u64 {
    let below = tip.saturating_sub(u64::from(global::state_sync_threshold()));
    let odd = below.checked_rem(global::txhashset_archive_interval()).unwrap_or(0);
    below.saturating_sub(odd)
}

fn open_error(e: OpenError) -> String {
    match e {
        OpenError::Start(_) => "the starting point of this program does not pass its own check".to_string(),
        OpenError::Io(kind) => format!("the header file cannot be used ({kind})"),
        OpenError::Busy => "another chain process has the header file open".to_string(),
        OpenError::OtherStart => "the header file belongs to another starting point; it was left as it is".to_string(),
    }
}

fn handshake_error(e: &grin_p2p::Error) -> &'static str {
    match e {
        grin_p2p::Error::GenesisMismatch { .. } => "a node of another chain",
        grin_p2p::Error::Connection(_) | grin_p2p::Error::ConnectionClose => "the connection was closed",
        grin_p2p::Error::Timeout => "no answer in time",
        grin_p2p::Error::Serialization(_) | grin_p2p::Error::BadMessage | grin_p2p::Error::UnexpectedMessage => {
            "not a Grin node, or one this program cannot talk to"
        }
        grin_p2p::Error::Banned => "the node refuses this address",
        _ => "the handshake failed",
    }
}

fn reject_words(reject: Reject) -> &'static str {
    match reject {
        Reject::Height | Reject::Link => "does not follow the header before it",
        Reject::Unsupported => "is from before the fourth hard fork",
        Reject::Version => "has a version this program does not know - the chain may have changed its rules",
        Reject::Time => "is not later than the header before it",
        Reject::Sizes | Reject::Weight => "has impossible counts",
        Reject::EdgeBits | Reject::Pow => "has no valid proof of work",
        Reject::Work | Reject::Difficulty | Reject::Arithmetic => "claims work the rules do not give it",
        Reject::Root => "does not commit to the headers before it",
    }
}

/// The addresses of the nodes this program would connect to on `net`: of
/// the named `peers`, or - if none is named - of the network's seed names.
/// Looks names up, and waits for that.
pub fn addresses(net: Net, peers: &[String]) -> Vec<SocketAddr> {
    let (seeds, port): (&[&str], Option<u16>) = match net {
        Net::Main => (MAIN_SEEDS, Some(grin_p2p::types::MAINNET_PEER_PORT)),
        Net::Test => (TEST_SEEDS, Some(grin_p2p::types::TESTNET_PEER_PORT)),
        Net::Automated => (&[], None),
    };
    let names: Vec<String> = if peers.is_empty() { seeds.iter().map(|s| (*s).to_string()).collect() } else { peers.to_vec() };
    let mut all: Vec<SocketAddr> = Vec::new();
    for name in names {
        for addr in resolve(&name, port) {
            if !all.contains(&addr) && all.len() < MAX_CANDIDATES {
                all.push(addr);
            }
        }
    }
    all
}

/// Addresses of `text`, which is `host:port` or `host`.
fn resolve(text: &str, default_port: Option<u16>) -> Vec<SocketAddr> {
    crate::net::lookup(text, default_port)
}

impl Node {
    fn our_work(&self) -> u64 {
        self.chain.tip().total_work
    }

    fn candidate(&mut self, addr: SocketAddr) -> Option<&mut Candidate> {
        self.candidates.iter_mut().find(|c| c.addr == addr)
    }

    /// Leave a peer: now, and for the rest of the run if `for_good`.
    fn leave(&mut self, addr: SocketAddr, for_good: bool, why: &str) {
        if let Some(at) = self.links.iter().position(|l| l.addr == addr) {
            let link = self.links.swap_remove(at);
            link.peer.stop(why);
        }
        if self.asked.is_some_and(|asked| asked.addr == addr) {
            self.asked = None;
        }
        if let Some(fetch) = &mut self.fetch {
            fetch.forget(addr);
        }
        if let Some(follow) = &mut self.follow {
            follow.forget(addr);
        }
        self.old.forget(addr);
        let now = Instant::now();
        if let Some(c) = self.candidate(addr) {
            c.state = Try::Idle;
            c.dropped = c.dropped || for_good;
            c.next_try = later(now, c.wait);
            c.wait = c.wait.saturating_mul(2).min(RETRY_MAX);
        }
    }

    fn ask(&mut self, addr: SocketAddr) {
        let locator: Vec<Hash> = self.chain.locator().iter().map(|h| Hash::from_vec(h)).collect();
        let sent = self
            .links
            .iter()
            .find(|l| l.addr == addr)
            .map(|l| l.peer.send_header_request(locator).is_ok());
        match sent {
            Some(true) => {
                let now = Instant::now();
                self.asked = Some(Pending {
                    addr,
                    at: now,
                    last: now,
                    got: 0,
                    progress: false,
                });
            }
            Some(false) => self.leave(addr, false, "a request could not be sent"),
            None => {}
        }
    }

    /// The answer to the request that is out has ended: note what it was
    /// worth, and let the peer rest if it was worth nothing.
    fn close_request(&mut self) {
        let Some(pending) = self.asked.take() else {
            return;
        };
        if let Some(link) = self.links.iter_mut().find(|l| l.addr == pending.addr) {
            if pending.progress {
                link.fruitless = 0;
            } else {
                let rest = ASK_AGAIN.saturating_mul(1u32.checked_shl(link.fruitless).unwrap_or(u32::MAX)).min(ASK_AGAIN_MAX);
                link.rest_until = later(Instant::now(), rest);
                link.fruitless = link.fruitless.saturating_add(1);
            }
        }
    }

    fn take(&mut self, from: SocketAddr, headers: &[BlockHeader]) {
        if !self.links.iter().any(|l| l.addr == from) {
            return;
        }
        let offered = match self.chain.offer(headers, unix_now()) {
            Ok(offered) => offered,
            Err(_) => {
                self.file_trouble = true;
                return;
            }
        };
        self.file_trouble = false;
        self.held = offered.held;
        if let Some(reject) = offered.bad {
            self.remark = Some((
                format!("a node sent a header that {}; it was left", reject_words(reject)),
                Instant::now(),
            ));
            self.leave(from, true, "an invalid header");
            return;
        }
        let detached = match offered.outcome {
            Outcome::Detached => true,
            Outcome::TooDeep { depth } => {
                self.remark = Some((
                    format!("a node shows a branch that leaves the verified chain {depth} blocks back; it is not followed"),
                    Instant::now(),
                ));
                false
            }
            _ => false,
        };
        // a branch that only waits has not made the chain longer or heavier
        let progress = matches!(offered.outcome, Outcome::Extended { .. } | Outcome::Switched { .. });
        let mut strikes = 0;
        if let Some(link) = self.links.iter_mut().find(|l| l.addr == from) {
            link.detached = if detached { link.detached.saturating_add(1) } else { 0 };
            strikes = link.detached;
        }
        if strikes >= MAX_DETACHED {
            self.leave(from, false, "answers that fit nowhere");
            return;
        }
        let now = Instant::now();
        let mut full = false;
        if let Some(pending) = self.asked.as_mut().filter(|p| p.addr == from) {
            pending.got = pending.got.saturating_add(headers.len());
            pending.last = now;
            pending.progress = pending.progress || progress;
            full = pending.verdict(now) == Verdict::Full;
        }
        if full {
            // a full answer has more behind it
            let worth = self.asked.is_some_and(|p| p.progress);
            self.close_request();
            if worth && !offered.held {
                self.ask(from);
            }
        } else if detached && self.asked.is_none() {
            // news that hangs in the air: ask where it comes from
            self.ask(from);
        }
    }

    fn connect(&mut self, addr: SocketAddr) {
        let (events, adapter, handshake) = (self.events.clone(), self.adapter.clone(), self.handshake.clone());
        let work = self.our_work().max(1);
        let spawned = thread::Builder::new().name("fly-chain-connect".into()).spawn(move || {
            let peer = crate::net::connect(&addr, CONNECT_TIMEOUT)
                .map_err(|_| "no connection".to_string())
                .and_then(|conn| {
                    // this process listens nowhere; it says so
                    let nowhere = PeerAddr(SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0));
                    Peer::connect(conn, Capabilities::UNKNOWN, Difficulty::from_num(work), nowhere, &handshake, adapter)
                        .map(Arc::new)
                        .map_err(|e| handshake_error(&e).to_string())
                });
            let _ = events.send(Event::Connected { addr, peer });
        });
        if let Some(c) = self.candidate(addr) {
            c.state = if spawned.is_ok() { Try::Pending } else { Try::Idle };
        }
    }

    fn handle(&mut self, event: Event) {
        match event {
            Event::Resolved { text: _, addrs } => {
                self.names_left = self.names_left.saturating_sub(1);
                for addr in addrs {
                    if self.candidates.len() < MAX_CANDIDATES && !self.candidates.iter().any(|c| c.addr == addr) {
                        self.candidates.push(Candidate {
                            addr,
                            state: Try::Idle,
                            next_try: Instant::now(),
                            wait: RETRY_FIRST,
                            dropped: false,
                        });
                    }
                }
            }
            Event::Connected { addr, peer } => {
                let now = Instant::now();
                match peer {
                    Ok(peer) => {
                        let (work, height) = (peer.info.total_difficulty().to_num(), peer.info.height());
                        let pibd = peer.info.capabilities.contains(Capabilities::PIBD_HIST);
                        if let Some(c) = self.candidate(addr) {
                            c.state = Try::Connected;
                            c.wait = RETRY_FIRST;
                        }
                        self.links.push(Link {
                            addr,
                            peer,
                            work,
                            height,
                            last_ping: now,
                            detached: 0,
                            rest_until: now,
                            fruitless: 0,
                            pibd,
                        });
                    }
                    Err(why) => {
                        self.last_failure = Some(why);
                        if let Some(c) = self.candidate(addr) {
                            c.state = Try::Idle;
                            c.next_try = later(now, c.wait);
                            c.wait = c.wait.saturating_mul(2).min(RETRY_MAX);
                        }
                    }
                }
            }
            Event::Seen { from, work, height } => {
                if let Some(link) = self.links.iter_mut().find(|l| l.addr == from) {
                    link.work = work;
                    link.height = height;
                }
            }
            Event::Headers { from, headers } => self.take(from, &headers),
            Event::Block { from, block } => {
                crate::adapter::count_down(&self.waiting_segments);
                let (Some(follow), true) = (self.follow.as_mut(), self.links.iter().any(|l| l.addr == from)) else {
                    return;
                };
                match follow.arrived(from, *block, &self.chain) {
                    Got::Taken | Got::Unasked => {}
                    Got::Pushy => self.leave(from, false, "blocks nobody asked for"),
                    Got::Invalid => {
                        let what = match follow.refused() {
                            Some((height, Rejected::Body)) => format!("a node sent, for the verified header at {height}, a block that is not a valid block; it was left"),
                            Some((height, _)) => format!("a node sent a block that is not the block of the verified header at {height}; it was left"),
                            None => "a node sent a block under a header that is not the verified one; it was left".to_string(),
                        };
                        self.remark = Some((what, Instant::now()));
                        self.leave(from, true, "an invalid block");
                    }
                }
            }
            Event::Surveyed(news) => self.surveyed(&news),
            Event::Ask { at, reply } => {
                let at_tip = self.at_tip();
                let answer = match self.follow.as_mut() {
                    Some(follow) => follow.step(at, &self.chain, at_tip),
                    None => Err(Unknown),
                };
                let _ = reply.try_send(answer);
            }
            Event::AskOld { piece, since, reply } => {
                let known = since.and_then(|since| self.leaves_after(since));
                let answer = match self.follow.as_ref().filter(|follow| follow.on_chain(&self.chain)) {
                    Some(follow) => self.old.ask(piece, known, Instant::now(), follow.live()),
                    None => Err(Unknown),
                };
                let _ = reply.try_send(answer);
            }
            Event::Tor { off, reply } => {
                // the sending thread sees it at its next step; what waited
                // for Tor goes out over the program's own connections now
                self.tor_off.store(off, Ordering::SeqCst);
                let peers: Vec<SocketAddr> = self.links.iter().map(|l| l.addr).collect();
                let todo = self.outbox.tor_switched(off, Instant::now(), &peers);
                self.carry_out(todo);
                self.tell_watch();
                let _ = reply.try_send(true);
            }
            Event::Point { reply } => {
                let made = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs());
                let _ = reply.try_send(crate::point_from(&self.chain, made));
            }
            Event::Post { tx, direct, reply } => {
                if self.follow.as_ref().is_some_and(|follow| !follow.on_chain(&self.chain)) {
                    let _ = reply.try_send(fly_paycore_chain_port::Posted::Unknown);
                    return;
                }
                let at_tip = self.at_tip();
                let live = self.follow.as_ref().map(Follow::live);
                let (answer, todo) = self.outbox.post(&tx, Instant::now(), live, at_tip);
                if todo.is_some() && self.trail.at().is_none() {
                    // the blocks from here on are looked at for its kernels
                    if let Some(header) = self.follow.as_ref().map(Follow::header) {
                        self.trail.push(Tip {
                            height: header.height,
                            hash: fly_chain_headers::hash_bytes(header),
                        });
                    }
                }
                let mut todo: Vec<_> = todo.into_iter().collect();
                if direct {
                    let peers: Vec<SocketAddr> = self.links.iter().map(|l| l.addr).collect();
                    todo.extend(self.outbox.agree_direct(&tx, Instant::now(), &peers).1);
                }
                self.carry_out(todo);
                self.tell_watch();
                let _ = reply.try_send(answer);
            }
            Event::Sent { key, result } => {
                let peers: Vec<SocketAddr> = self.links.iter().map(|l| l.addr).collect();
                let done = match result {
                    Ok(way) => {
                        self.last_sent = Some(way);
                        Ok(())
                    }
                    Err(why) => Err(why),
                };
                let todo = self.outbox.sent(&key, done, Instant::now(), &peers);
                self.carry_out(todo.into_iter().collect());
                self.tell_watch();
            }
            Event::Heard { kernels } => {
                if self.outbox.heard(&kernels) {
                    self.tell_watch();
                }
            }
            Event::Segment { from, block, piece } => {
                crate::adapter::count_down(&self.waiting_segments);
                if !self.links.iter().any(|l| l.addr == from) {
                    return;
                }
                // once the state is collected, range proofs are for the wallet
                if let (Some(follow), Arrived::Rangeproof(_)) = (self.follow.as_ref(), &piece) {
                    let Arrived::Rangeproof(segment) = piece else {
                        return;
                    };
                    match self.old.arrived(from, block, segment, follow.live()) {
                        Came::Taken | Came::Unasked => {}
                        Came::Pushy => self.leave(from, false, "segments nobody asked for"),
                        Came::Invalid => {
                            self.remark = Some((
                                "a node sent range proofs that do not fit the verified header; it was left".to_string(),
                                Instant::now(),
                            ));
                            self.leave(from, true, "an invalid segment");
                        }
                    }
                    return;
                }
                let Some(fetch) = self.fetch.as_mut() else {
                    return;
                };
                match fetch.arrived(from, block, piece) {
                    Took::Taken | Took::Unasked | Took::Fault => {}
                    Took::Pushy => self.leave(from, false, "segments nobody asked for"),
                    Took::Invalid => {
                        self.remark = Some((
                            "a node sent a piece of the state that does not fit the verified header; it was left".to_string(),
                            Instant::now(),
                        ));
                        self.leave(from, true, "an invalid segment");
                    }
                }
            }
        }
    }

    /// No connected peer claims more work than is verified here.
    fn caught_up(&self) -> bool {
        let ours = self.our_work();
        self.links.iter().map(|l| l.work).max().is_some_and(|best| best <= ours)
    }

    /// Open the state file for the state at `header`. If the file holds
    /// the state at another header, it is started over when `over` says
    /// that state is of no use any more, and left alone otherwise.
    fn open_state(&mut self, header: BlockHeader, over: bool) {
        let opened = match Fetch::open(&self.data_dir, header.clone(), false) {
            Err(StoreError::Other(..)) if over => Fetch::open(&self.data_dir, header, true),
            other => other,
        };
        match opened {
            Ok(fetch) => {
                self.fetch = Some(fetch);
                self.state_note = None;
            }
            Err(StoreError::NotOurs) => {
                self.state_note = Some("the state file in the data directory is not this program's; it was left as it is".to_string());
            }
            Err(StoreError::Busy) => self.state_note = Some("another process has the state file open".to_string()),
            // an earlier run's state at a header that is not on this chain:
            // nothing to say until it is known what to collect instead
            Err(StoreError::Other(..)) => {}
            Err(StoreError::Io(e)) => self.state_note = Some(format!("the state file cannot be used ({})", e.kind())),
        }
    }

    /// The blocks applied reach the tip of the verified header chain, and
    /// no connected node claims more work than that chain has.
    fn at_tip(&self) -> bool {
        self.caught_up() && self.follow.as_ref().is_some_and(|follow| follow.header().height == self.chain.tip().height && follow.on_chain(&self.chain))
    }

    /// Follow the chain with blocks: from the collected state to the tip.
    fn tend_blocks(&mut self, now: Instant) {
        if self.follow.is_none() {
            let Some(fetch) = self.fetch.as_mut().filter(|fetch| fetch.complete()) else {
                return;
            };
            if self.blocks_retry.is_some_and(|(next, _)| now < next) {
                return;
            }
            if self.chain.hash_at(fetch.header().height) != Some(fly_chain_headers::hash_bytes(fetch.header())) {
                self.fetch = None;
                self.blocks_retry = None;
                self.blocks_note = None;
                return;
            }
            let dir = &self.data_dir;
            let opened = Follow::open_with_state(dir, || {
                if let Some(state) = fetch.take_state() {
                    return Ok(state);
                }
                // A disk error after handing over the state consumed it.
                // Re-verify the local archive only once the blocks file is locked.
                let (store, _) = Store::open(dir, fetch.header().clone()).map_err(|e| match e {
                    StoreError::Io(e) => BlocksError::Io(e),
                    StoreError::Busy => BlocksError::Busy,
                    StoreError::NotOurs | StoreError::Other(..) => BlocksError::State,
                })?;
                store.finish().ok_or(BlocksError::State)
            }, &self.chain);
            if opened.is_err() {
                let wait = self.blocks_retry.map_or(RETRY_FIRST, |(_, wait)| wait.saturating_mul(2).min(RETRY_MAX));
                self.blocks_retry = Some((later(now, wait), wait));
            } else {
                self.blocks_retry = None;
            }
            match opened {
                Ok(follow) => {
                    self.follow = Some(follow);
                    self.blocks_note = None;
                }
                Err(BlocksError::NotOurs) => self.blocks_note = Some("the file of blocks in the data directory is not this program's; it was left as it is".to_string()),
                Err(BlocksError::Busy) => self.blocks_note = Some("another process has the file of blocks open".to_string()),
                Err(BlocksError::Io(e)) => self.blocks_note = Some(format!("the file of blocks cannot be used ({})", e.kind())),
                Err(BlocksError::Other(..) | BlocksError::State) => self.blocks_note = Some("the collected state cannot be carried forward: a fault of this program".to_string()),
            }
        }
        let Some(follow) = self.follow.as_mut() else {
            return;
        };
        // the header chain may have moved to another branch
        if follow.rewind(&self.chain) > 0 {
            self.remark = Some(("the chain moved to another branch; the blocks of the old one were taken back".to_string(), now));
            self.old.taken_back();
        }
        for addr in follow.expire(now) {
            self.leave(addr, false, "no answer to requests for blocks");
        }
        let Some(follow) = self.follow.as_mut() else {
            return;
        };
        let peers: Vec<SocketAddr> = self.links.iter().map(|l| l.addr).collect();
        let plan = follow.plan(now, &self.chain, &peers);
        if plan.is_empty() && follow.header().height == self.chain.tip().height {
            follow.sync();
        }
        let mut failed = Vec::new();
        for (addr, _, hash) in plan {
            let Some(link) = self.links.iter().find(|l| l.addr == addr) else {
                continue;
            };
            if link.peer.send_block_request(Hash::from_vec(&hash), grin_chain::Options::SYNC).is_err() {
                failed.push(addr);
            }
        }
        for addr in failed {
            self.leave(addr, false, "a request could not be sent");
        }
    }

    /// How many peers to keep connected now. More while there is much to
    /// fetch; those connected for that are not sent away afterwards, but
    /// when they go they are not replaced.
    fn target_peers(&self, now: Instant) -> usize {
        let collecting = self.fetch.as_ref().is_some_and(|fetch| !fetch.complete());
        let tip = self.chain.tip().height;
        let behind = self.follow.as_ref().is_some_and(|follow| follow.header().height.saturating_add(crate::follow::WINDOW) < tip);
        if collecting || behind || self.old.wanted(now) {
            BULK_PEERS
        } else {
            TARGET_PEERS
        }
    }

    /// The connected nodes that give their state out. If there is none
    /// and every place is taken, after a while one node makes room for
    /// another.
    fn able(&mut self, now: Instant) -> Vec<SocketAddr> {
        let able: Vec<SocketAddr> = self.links.iter().filter(|l| l.pibd).map(|l| l.addr).collect();
        if !able.is_empty() {
            self.no_state_node_since = None;
            return able;
        }
        let since = *self.no_state_node_since.get_or_insert(now);
        let full = self.links.len() >= self.target_peers(now);
        if let (true, true, Some(addr)) = (full, now.saturating_duration_since(since) >= NO_STATE_NODE_FOR, self.links.first().map(|l| l.addr)) {
            self.no_state_node_since = None;
            self.leave(addr, false, "it does not give its state out");
        }
        able
    }

    /// How many leaves the output MMR had after the block a wallet names
    /// as the one it knew its outputs up to; see [`old::leaves_after`].
    fn leaves_after(&mut self, since: Tip) -> Option<u64> {
        let on_chain = self.chain.hash_at(since.height);
        let applied = self.follow.as_ref()?.live().header().height;
        // the header is read from the file: once for a block, not once
        // for every piece
        if let Some((known, leaves)) = self.old_since {
            if known == since && on_chain == Some(since.hash) && applied >= since.height {
                return Some(leaves);
            }
        }
        let leaves = crate::old::leaves_after(since, on_chain, applied, || self.chain.header_at(since.height).ok().flatten())?;
        self.old_since = Some((since, leaves));
        Some(leaves)
    }

    /// Fetch the outputs older than the blocks, while a wallet reads them.
    fn tend_old(&mut self, now: Instant) {
        let Some(follow) = self.follow.as_ref() else {
            return;
        };
        // nodes answer only for the archive header they have now, and
        // where that is is known once the headers have caught up
        if self.caught_up() {
            if let Ok(Some(header)) = self.chain.header_at(archive_height(self.chain.tip().height)) {
                self.old.serve_at(&header, follow.live());
            }
        }
        for addr in self.old.expire(now) {
            self.leave(addr, false, "no answer to requests for range proofs");
        }
        if !self.old.wanted(now) {
            // lets go of what is held
            self.old.plan(now, &[]);
            return;
        }
        let able = self.able(now);
        let mut failed = Vec::new();
        for (addr, block, id) in self.old.plan(now, &able) {
            let Some(link) = self.links.iter().find(|l| l.addr == addr) else {
                continue;
            };
            if link.peer.send_rangeproof_segment_request(block, id).is_err() {
                failed.push(addr);
            }
        }
        for addr in failed {
            self.leave(addr, false, "a request could not be sent");
        }
    }

    /// The wallet's transactions: the kernels of the blocks applied since
    /// the last look, and what is due with those not in a block.
    fn tend_post(&mut self, now: Instant) {
        if self.outbox.is_empty() {
            self.trail.clear();
            return;
        }
        let at_tip = self.at_tip();
        if let Some(follow) = self.follow.as_mut() {
            for _ in 0..MAX_LOOKED {
                match follow.step(self.trail.at(), &self.chain, at_tip) {
                    Ok(Step::Block(block)) => {
                        self.outbox.block(block.height, &block.kernels);
                        self.trail.push(Tip {
                            height: block.height,
                            hash: block.hash,
                        });
                    }
                    Ok(Step::Rollback { .. }) => {
                        // the chain has turned: back to the block where the branches part
                        let chain = &self.chain;
                        let parted = self.trail.back_to(|height| chain.hash_at(height));
                        self.outbox.taken_back(parted);
                    }
                    Ok(Step::Reanchor(tip) | Step::ReanchorExtending(tip)) => {
                        // the blocks kept begin above everything looked at
                        if self.trail.at().is_some() {
                            self.outbox.taken_back(None);
                        }
                        self.trail.clear();
                        self.trail.push(tip);
                    }
                    Ok(Step::Nothing) | Err(Unknown) => break,
                }
            }
        }
        let peers: Vec<SocketAddr> = self.links.iter().map(|l| l.addr).collect();
        let todo = self.outbox.tend(now, &peers);
        self.carry_out(todo);
        self.tell_watch();
    }

    /// Send what the outbox says is due.
    fn carry_out(&mut self, todo: Vec<Do>) {
        let mut failed = Vec::new();
        for item in todo {
            match item {
                Do::Stem { to, tx } => {
                    if let Some(link) = self.links.iter().find(|l| l.addr == to) {
                        if link.peer.send_stem_transaction(&tx).is_err() {
                            failed.push(to);
                        }
                    }
                }
                Do::Announce { to, tx } => {
                    for link in self.links.iter().filter(|l| to.contains(&l.addr)) {
                        if link.peer.send_transaction(&tx).is_err() {
                            failed.push(link.addr);
                        }
                    }
                }
                Do::Send { key, tx, fluff, turn } => {
                    // the nodes it may go to: those this program knows of
                    let mut nodes: Vec<SocketAddr> = self.links.iter().map(|l| l.addr).collect();
                    for c in &self.candidates {
                        if !nodes.contains(&c.addr) {
                            nodes.push(c.addr);
                        }
                    }
                    let job = crate::send::Job {
                        key: key.clone(),
                        tx,
                        fluff,
                        turn,
                        nodes,
                    };
                    let queued = self.sender.as_ref().is_some_and(|sender| sender.try_send(job).is_ok());
                    if !queued {
                        let peers: Vec<SocketAddr> = self.links.iter().map(|l| l.addr).collect();
                        let more = self.outbox.sent(&key, Err("the transaction could not be handed to the sending thread".to_string()), Instant::now(), &peers);
                        self.carry_out(more.into_iter().collect());
                    }
                }
                Do::Ask { to, kernel } => {
                    if let Some(link) = self.links.iter().find(|l| l.addr == to) {
                        if link.peer.send_tx_request(kernel).is_err() {
                            failed.push(to);
                        }
                    }
                }
            }
        }
        for addr in failed {
            self.leave(addr, false, "a transaction could not be sent");
        }
    }

    /// Tell the network code which kernels to look out for and which
    /// transactions it may give out.
    fn tell_watch(&self) {
        let fresh = Watch {
            kernels: self.outbox.watched(),
            announced: self.outbox.announced(),
        };
        match self.watch.lock() {
            Ok(mut slot) => *slot = fresh,
            Err(poisoned) => *poisoned.into_inner() = fresh,
        }
    }

    /// Collect the state: decide at which header, ask for what is wanted.
    fn tend_state(&mut self, now: Instant) {
        // what an earlier run left, if it is the state at a header of the
        // verified chain: no node needs to be asked whether to go on with
        // it. The file is opened for this chain's header at that height; if
        // it is for another header, opening says so and leaves it alone.
        if !self.file_tried {
            self.file_tried = true;
            if let Ok(Some((height, _))) = Store::peek(&self.data_dir) {
                if let Ok(Some(header)) = self.chain.header_at(height) {
                    self.open_state(header, false);
                }
            }
        }
        if self.fetch.as_ref().is_some_and(|fetch| fetch.complete()) {
            return;
        }
        // where nodes give their state out is known once the headers have
        // caught up with them
        if self.caught_up() {
            let (tip, start) = (self.chain.tip().height, self.chain.start().height());
            let archive = archive_height(tip);
            let collecting = self.fetch.as_ref().map(|fetch| fetch.header().height);
            if archive < start {
                let interval = global::txhashset_archive_interval().max(1);
                let first = start.div_ceil(interval).saturating_mul(interval);
                let at = first.saturating_add(u64::from(global::state_sync_threshold()));
                self.state_note = Some(format!(
                    "nodes give their state out at height {archive}, below this program's starting point ({start}); it can be collected in {} blocks",
                    at.saturating_sub(tip)
                ));
            } else if collecting.is_none_or(|height| height < archive) {
                // nothing yet, or the network has moved on: nodes answer
                // only for the archive header they have now
                if let Ok(Some(header)) = self.chain.header_at(archive) {
                    // the file is let go of before it is opened anew
                    self.fetch = None;
                    self.open_state(header, true);
                    if self.fetch.as_ref().is_some_and(|fetch| fetch.header().height == archive) {
                        self.again_from = collecting.or(self.again_from);
                    }
                }
            }
        }
        // whoever has left too much unanswered is left before anything
        // more is asked
        let Some(fetch) = self.fetch.as_mut().filter(|fetch| !fetch.complete()) else {
            return;
        };
        for addr in fetch.expire(now) {
            self.leave(addr, false, "no answer to requests for the state");
        }
        let able = self.able(now);
        if able.is_empty() {
            return;
        }
        let Some(fetch) = self.fetch.as_mut() else {
            return;
        };
        let block = fetch.header().hash();
        let plan = fetch.plan(now, &able);
        let mut failed = Vec::new();
        for (addr, piece) in plan {
            let Some(link) = self.links.iter().find(|l| l.addr == addr) else {
                continue;
            };
            let sent = match piece {
                Piece::Bitmap(id) => link.peer.send_bitmap_segment_request(block, id),
                Piece::Output(id) => link.peer.send_output_segment_request(block, id),
                Piece::RangeproofTail(id) => link.peer.send_rangeproof_segment_request(block, id),
                Piece::KernelTail(id) => link.peer.send_kernel_segment_request(block, id),
            };
            if sent.is_err() {
                failed.push(addr);
            }
        }
        for addr in failed {
            self.leave(addr, false, "a request could not be sent");
        }
    }

    fn keep_house(&mut self) {
        let now = Instant::now();
        // connections that ended by themselves
        let gone: Vec<SocketAddr> = self.links.iter().filter(|l| !l.peer.is_connected()).map(|l| l.addr).collect();
        for addr in gone {
            self.leave(addr, false, "the connection ended");
        }
        // the request that is out: answered in full, or not at all
        if let Some(pending) = self.asked {
            match pending.verdict(now) {
                Verdict::Done => self.close_request(),
                Verdict::Silent => self.leave(pending.addr, false, "no answer to a request"),
                Verdict::Full | Verdict::Wait => {}
            }
        }
        // more peers, if there are too few
        let busy = self.candidates.iter().filter(|c| c.state != Try::Idle).count();
        let wanted = self.target_peers(now).saturating_sub(busy);
        let next: Vec<SocketAddr> = self
            .candidates
            .iter()
            .filter(|c| c.state == Try::Idle && !c.dropped && c.next_try <= now)
            .take(wanted)
            .map(|c| c.addr)
            .collect();
        for addr in next {
            self.connect(addr);
        }
        // tell peers where this chain stands; their answer says where theirs does
        let tip = self.chain.tip();
        self.tip.work.store(tip.total_work, Ordering::Relaxed);
        self.tip.height.store(tip.height, Ordering::Relaxed);
        let mut failed = Vec::new();
        for link in &mut self.links {
            if now.saturating_duration_since(link.last_ping) >= PING_EVERY {
                link.last_ping = now;
                if link.peer.send_ping(Difficulty::from_num(tip.total_work.max(1)), tip.height).is_err() {
                    failed.push(link.addr);
                }
            }
        }
        for addr in failed {
            self.leave(addr, false, "a ping could not be sent");
        }
        // ask whoever claims the most work, if that is more than is verified
        if self.asked.is_none() {
            let best = self
                .links
                .iter()
                .filter(|l| l.rest_until <= now)
                .max_by_key(|l| l.work)
                .map(|l| (l.addr, l.work));
            if let Some((addr, work)) = best {
                if work > tip.total_work {
                    self.ask(addr);
                }
            }
        }
        self.tend_state(now);
        self.tend_blocks(now);
        self.tend_old(now);
        self.tend_post(now);
        self.tend_accept(now);
        if self.remark.as_ref().is_some_and(|(_, at)| now.saturating_duration_since(*at) > REMARK_FOR) {
            self.remark = None;
        }
    }

    /// What the asking is told about this moment.
    fn refresh_history(&mut self) {
        let chain = &self.chain;
        self.history.refresh(
            chain.start().height(),
            chain.tip().height,
            |height| chain.hash_at(height),
            |height| {
                let header = chain.header_at(height).ok().flatten()?;
                Some(Block {
                    said: Said {
                        height: header.height,
                        hash: chain.hash_at(height)?,
                        total_difficulty: header.pow.total_difficulty.to_num(),
                    },
                    time: u64::try_from(header.timestamp.timestamp()).ok()?,
                })
            },
        );
    }

    /// Whether the tip is called selected; starts an asking if one is due.
    fn tend_accept(&mut self, now: Instant) {
        self.refresh_history();
        let peers: Vec<std::net::IpAddr> = self.links.iter().map(|l| l.addr.ip()).collect();
        let facts = Facts {
            history: &self.history,
            start: (self.chain.start().height(), self.start_time),
            caught_up: self.caught_up(),
            peers: &peers,
            now,
            clock_ms: clock_ms(),
        };
        let events = self.events.clone();
        let started = self.accept.tend_and_start(&facts, |ask| {
            thread::Builder::new()
                .name("fly-chain-tips".into())
                .spawn(move || {
                    crate::accept::survey(ask, |news| events.send(Event::Surveyed(Box::new(news))).is_ok());
                })
                .map(|_| ())
        });
        if started.is_err() {
            self.remark = Some(("a thread for asking public nodes could not be started".to_string(), now));
        }
    }

    /// News of an asking.
    fn surveyed(&mut self, news: &Surveyed) {
        self.refresh_history();
        let peers: Vec<std::net::IpAddr> = self.links.iter().map(|l| l.addr.ip()).collect();
        let facts = Facts {
            history: &self.history,
            start: (self.chain.start().height(), self.start_time),
            caught_up: self.caught_up(),
            peers: &peers,
            now: Instant::now(),
            clock_ms: clock_ms(),
        };
        self.accept.took(news, &facts);
    }

    fn problem(&self) -> Option<String> {
        if self.file_trouble {
            return Some("verified headers could not be written to the disk".to_string());
        }
        if self.links.is_empty() {
            if let Some((remark, _)) = &self.remark {
                return Some(format!("{remark}; no other node is connected"));
            }
            if self.names_left > 0 && self.candidates.is_empty() {
                return Some("looking up nodes".to_string());
            }
            if self.candidates.is_empty() {
                return Some("no node address is known: the names of the network's nodes did not resolve".to_string());
            }
            let tried = self.candidates.len();
            return Some(match &self.last_failure {
                Some(why) => format!("no node is connected ({tried} known; last attempt: {why})"),
                None => format!("no node is connected yet ({tried} known)"),
            });
        }
        if let Some((remark, _)) = &self.remark {
            return Some(remark.clone());
        }
        if self.held {
            return Some("the newest headers are ahead of this computer's clock; check the clock".to_string());
        }
        if let Some(fetch) = &self.fetch {
            if fetch.fault() {
                return Some("a piece of the state passes the node's own check and this program cannot read it: a fault of this program".to_string());
            }
            if fetch.file_trouble() {
                return Some("the collected state could not be written to the disk".to_string());
            }
            if !fetch.complete() && !self.links.iter().any(|l| l.pibd) {
                return Some("no connected node gives its state out in segments".to_string());
            }
        }
        if let Some(follow) = &self.follow {
            if follow.file_trouble() {
                return Some("the blocks could not be written to the disk".to_string());
            }
        }
        if self.own_refused > 0 {
            return Some(format!(
                "{} line(s) of {} name no node (https://host[:port][/path]) or one too many; they are not used",
                self.own_refused,
                crate::accept::OWN_NODES_FILE
            ));
        }
        self.state_note.clone().or_else(|| self.blocks_note.clone())
    }

    fn blocks_view(&self) -> Option<BlocksView> {
        let follow = self.follow.as_ref()?;
        let reopened = follow.reopened();
        Some(BlocksView {
            base: follow.base(),
            height: follow.header().height,
            hash: fly_chain_headers::hash_bytes(follow.header()),
            unspent: u64::try_from(follow.unspent()).unwrap_or(u64::MAX),
            kept: reopened.kept,
            cut_bytes: reopened.cut_bytes,
            file_bytes: follow.file_len(),
            at_tip: self.at_tip(),
        })
    }

    fn state_view(&self) -> Option<StateView> {
        let fetch = self.fetch.as_ref()?;
        let (segments, done) = fetch.progress();
        let opened = fetch.opened();
        Some(StateView {
            height: fetch.header().height,
            hash: fly_chain_headers::hash_bytes(fetch.header()),
            segments,
            done,
            complete: fetch.complete(),
            unspent: fetch.unspent().unwrap_or(0),
            kept: opened.kept,
            cut_bytes: opened.cut_bytes,
            file_bytes: fetch.file_len(),
            work_ms: {
                let (check, take) = fetch.work();
                (u64::try_from(check.as_millis()).unwrap_or(u64::MAX), u64::try_from(take.as_millis()).unwrap_or(u64::MAX))
            },
            again_from: self.again_from,
        })
    }

    fn publish(&self, view: &SharedView, kept: u64, cut_bytes: u64) {
        let tip = self.chain.tip();
        let best = self.links.iter().map(|l| l.work).max();
        let fresh = View {
            ready: true,
            failed: None,
            start: self.chain.start().height(),
            point: self.point,
            history: self.past,
            replaced: self.chain.replaced(),
            height: tip.height,
            hash: tip.hash,
            work: tip.total_work,
            time: tip.time,
            kept,
            cut_bytes,
            peers: self.links.len(),
            best_seen: self.links.iter().map(|l| l.height).max().unwrap_or(0),
            caught_up: best.is_some_and(|work| work <= tip.total_work),
            problem: self.problem(),
            state: self.state_view(),
            blocks: self.blocks_view(),
            selected: self.accept.selected().is_some_and(|said| said.height == tip.height && said.hash == tip.hash),
            clock: self.accept.clock_evidence(),
            caveat: self.accept.caveat(),
            unselected: self.accept.note(),
            signs: self.accept.signs_note(),
            unsent: self.outbox.trouble().map(|why| {
                format!(
                    "a transaction is not sent: {why}; tried again{}",
                    if self.outbox.direct() { "" } else { ", never from this computer's address without your agreement" }
                )
            }),
        };
        match view.lock() {
            Ok(mut slot) => *slot = fresh,
            Err(poisoned) => *poisoned.into_inner() = fresh,
        }
    }
}

/// What this build knows of the history before the starting point of
/// `chain`, in the words the program says of itself; nothing in a build
/// without the proof of history. The check takes under a second.
#[cfg(feature = "history-proof")]
fn past_words(chain: &HeaderChain) -> Option<&'static str> {
    use fly_chain_headers::proof::{history_of, History, Refused};
    match history_of(chain.start()) {
        History::Sampled(_) => Some(HISTORY_SAMPLED),
        History::Extended(_) => Some(HISTORY_EXTENDED),
        // a network the program carries no proof for: nothing is said, as before
        History::Unproved => None,
        // the proof with the program is for the point the program carries;
        // a point that does not carry it has none
        History::Refused(Refused::Point) => Some(HISTORY_OTHER_POINT),
        History::Refused(_) => Some(HISTORY_REFUSED),
    }
}

#[cfg(not(feature = "history-proof"))]
fn past_words(_chain: &HeaderChain) -> Option<&'static str> {
    None
}

/// The history before the starting point answered for every point of its work.
pub const HISTORY_SAMPLED: &str = "history: sampled";
/// K202: the history up to the program's point answered by sampling; from
/// there to the point in use the wallet that made it vouches.
pub const HISTORY_EXTENDED: &str = "history: sampled to the program's point";
/// The program's proof is for another starting point than the one in use.
pub const HISTORY_OTHER_POINT: &str = "history: not proved for this point";
/// The program's proof did not pass.
pub const HISTORY_REFUSED: &str = "history: the proof did not pass";

/// Run the node until `stop` is set. Blocks; meant for a thread of its own.
/// The network must already be the process's global chain type: the
/// network code runs on threads of its own and reads it from there.
///
/// `events` and `inbox` are the two ends of the queue this thread reads:
/// the network code writes to it, and so does whoever answers the wallet.
pub fn run(settings: Settings, view: SharedView, stop: Arc<AtomicBool>, events: SyncSender<Event>, inbox: Receiver<Event>) {
    let net = settings.net;
    let (chain, opened) = match HeaderChain::open(&settings.data_dir, net, &settings.record) {
        Ok(opened) => opened,
        Err(e) => {
            let failed = View {
                failed: Some(open_error(e)),
                ..View::default()
            };
            match view.lock() {
                Ok(mut slot) => *slot = failed,
                Err(poisoned) => *poisoned.into_inner() = failed,
            }
            return;
        }
    };
    let tip = Arc::new(OurTip::default());
    let waiting_segments = Arc::new(AtomicUsize::new(0));
    let watch = Arc::new(Mutex::new(Watch::default()));
    let adapter: Arc<dyn NetAdapter> = Arc::new(Adapter::new(events.clone(), tip.clone(), waiting_segments.clone(), watch.clone()));
    let genesis = Hash::from_vec(&net.genesis_hash());
    let (names, default_port): (Vec<String>, Option<u16>) = {
        let port = match net {
            Net::Main => Some(grin_p2p::types::MAINNET_PEER_PORT),
            Net::Test => Some(grin_p2p::types::TESTNET_PEER_PORT),
            Net::Automated => None,
        };
        let seeds: &[&str] = match net {
            Net::Main => MAIN_SEEDS,
            Net::Test => TEST_SEEDS,
            Net::Automated => &[],
        };
        let names = if settings.peers.is_empty() {
            seeds.iter().map(|s| (*s).to_string()).collect()
        } else {
            settings.peers.clone()
        };
        (names, port)
    };
    let handshake = Arc::new(Handshake::new(genesis, P2PConfig::default()));
    let tor_off = Arc::new(AtomicBool::new(settings.tor_off));
    let sender = {
        let tips = crate::accept::Setup::for_posting(net, &settings.data_dir);
        // the user's own nodes first: a transaction goes to a third party
        // only when none of them takes it
        let mut sources = tips.sources;
        sources.rotate_right(tips.own);
        crate::send::start(
            crate::send::Setup {
                // the switch decides while the program runs; the way itself is always there
                dial: crate::send::Dial::of(settings.data_dir.clone(), settings.tor_bridges.clone(), false),
                off: tor_off.clone(),
                sources,
                own: tips.own,
                asker: tips.asker,
                handshake: handshake.clone(),
                adapter: adapter.clone(),
            },
            events.clone(),
        )
    };
    let past = past_words(&chain);
    let mut node = Node {
        chain,
        point: settings.point,
        past,
        sender,
        last_sent: None,
        own_refused: crate::accept::own_nodes(&settings.data_dir).1,
        adapter,
        handshake,
        tip,
        candidates: Vec::new(),
        links: Vec::new(),
        asked: None,
        names_left: names.len(),
        last_failure: None,
        remark: None,
        held: false,
        file_trouble: false,
        data_dir: settings.data_dir.clone(),
        fetch: None,
        file_tried: false,
        state_note: None,
        again_from: None,
        no_state_node_since: None,
        follow: None,
        blocks_note: None,
        blocks_retry: None,
        old: Old::new(),
        old_since: None,
        // with Tor switched off the direct way is the only one, and the user chose it
        outbox: Outbox::with_tor(settings.direct_post, settings.tor_off),
        tor_off,
        trail: Trail::default(),
        watch,
        waiting_segments,
        events: events.clone(),
        accept: Accept::open(settings.tips, &settings.data_dir),
        history: History::default(),
        start_time: 0,
    };
    node.start_time = node
        .chain
        .header_at(node.chain.start().height())
        .ok()
        .flatten()
        .and_then(|header| u64::try_from(header.timestamp.timestamp()).ok())
        .unwrap_or(0);
    node.publish(&view, opened.kept, opened.cut_bytes);
    // What earlier runs left - the state, the blocks - is taken up before
    // any node is looked for. Applying the blocks again can take a minute,
    // and this thread does nothing else meanwhile: a node connected during
    // that time would hear nothing from here and go away.
    let now = Instant::now();
    node.tend_state(now);
    node.tend_blocks(now);
    node.publish(&view, opened.kept, opened.cut_bytes);
    // looking names up can take as long as it likes: not on this thread
    let resolver = events;
    let _ = thread::Builder::new().name("fly-chain-names".into()).spawn(move || {
        for text in names {
            let addrs = resolve(&text, default_port);
            if resolver.send(Event::Resolved { text, addrs }).is_err() {
                return;
            }
        }
    });
    while !stop.load(Ordering::Relaxed) {
        match inbox.recv_timeout(TICK) {
            Ok(event) => node.handle(event),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        // whatever else is waiting, before the next round of housekeeping
        for event in inbox.try_iter().take(64) {
            node.handle(event);
        }
        node.keep_house();
        node.publish(&view, opened.kept, opened.cut_bytes);
    }
    for link in &node.links {
        link.peer.stop("shutting down");
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn a_published_views_clock_expires_even_if_the_worker_has_not_republished() {
        use fly_chain_tips::time::{Time, KEPT_FOR};
        let at = Instant::now();
        let ms = 1_000_000;
        let view = View {
            selected: true,
            clock: Some(Time { low_ms: ms, high_ms: ms, at }),
            ..View::default()
        };
        assert!(view.selection_at(at, ms).0);
        let later = KEPT_FOR + Duration::from_secs(1);
        let clock = ms + u64::try_from(later.as_millis()).unwrap();
        assert_eq!(view.selection_at(at + later, clock), (false, None));
        assert_eq!(view.selection_at(at, ms + 3_600_000), (false, None));
    }

    /// An answer comes in pieces, and the pieces do not say which is the
    /// last. It is over when it is as long as an answer can be, or when a
    /// shorter one has stopped coming - not at its first piece, which would
    /// send a second request while the first is still being answered.
    #[test]
    fn an_answer_is_over_when_it_is_full_or_has_stopped() {
        let t0 = Instant::now();
        let mut p = Pending {
            addr: "127.0.0.1:1".parse().unwrap(),
            at: t0,
            last: t0,
            got: 0,
            progress: false,
        };
        assert_eq!(p.verdict(t0), Verdict::Wait);
        assert_eq!(p.verdict(t0 + REQUEST_TIMEOUT), Verdict::Wait);
        assert_eq!(p.verdict(t0 + REQUEST_TIMEOUT + Duration::from_millis(1)), Verdict::Silent);
        // the first piece of thirty-two headers
        p.got = 32;
        p.last = t0 + Duration::from_secs(1);
        assert_eq!(p.verdict(p.last), Verdict::Wait, "more may be on the way");
        assert_eq!(p.verdict(p.last + REPLY_IDLE - Duration::from_millis(1)), Verdict::Wait);
        assert_eq!(p.verdict(p.last + REPLY_IDLE), Verdict::Done);
        assert_eq!(p.verdict(t0 + REQUEST_TIMEOUT * 2), Verdict::Done, "an answer that began is not 'no answer'");
        p.got = MAX_BATCH - 1;
        assert_eq!(p.verdict(p.last), Verdict::Wait);
        p.got = MAX_BATCH;
        assert_eq!(p.verdict(p.last), Verdict::Full, "no need to wait: there is more to ask for");
    }
}
