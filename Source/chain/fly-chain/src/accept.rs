//! Whether the tip of the verified chain is called *selected*.
//!
//! The program verifies every header itself, but it is shown only what
//! its connections bring. Before it tells the wallet that the tip is the
//! network's, it asks the operators of public nodes it knows by name
//! (`fly-chain-tips`). This module decides when to ask and what follows
//! from the answers; it touches no network itself - the node's thread
//! starts the asking it is told to start and hands the news back.
//!
//! The tip is selected while all of this holds: the time is confirmed;
//! no source's claim of more work stands unsettled; no connected node
//! claims more; and either a quorum of the sources named exactly this
//! tip, or a quorum named a block this tip is built on and no sign of
//! trouble is up. Whatever is missing is said in words.
//!
//! The sources are asked when the program has caught up after its start,
//! when the tip left the chain a quorum named, when the confirmed time
//! has run out, and - once for every new tip - while a sign is up.

use fly_chain_tips::claims::Noted;
use fly_chain_tips::generation::{Generation, Pace, Verdict};
use fly_chain_tips::memory::{Damaged, Memory};
use fly_chain_tips::signs::{self, Sign, Signs};
use fly_chain_tips::source::{self, Source};
use fly_chain_tips::time::{self, Stamp, Time, Unconfirmed};
use fly_chain_tips::{Asker, Said};
use std::collections::VecDeque;
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

/// The file of what is kept between runs, in the data directory.
pub const MEMORY_FILE: &str = "tips.state";

/// A test build reads its sources from this file in the data directory:
/// one `https://host:port operator network` a line.
pub const TEST_SOURCES_FILE: &str = "tips.txt";

/// And the authorities it trusts for them from this one.
pub const TEST_ROOTS_FILE: &str = "tips-ca.pem";

/// Name of the file in the data directory where the user lists public
/// nodes of their own, one `https://host[:port][/path]` per line.
pub const OWN_NODES_FILE: &str = "own-nodes.txt";

/// Most nodes of the user's own taken from that file.
pub const MAX_OWN_NODES: usize = 4;

/// Longest such file read.
const MAX_OWN_FILE: u64 = 4096;

/// The user's own nodes from `data_dir`, and how many lines named
/// something that is not one. Empty lines and lines starting with `#` are
/// not counted. A node of the user is asked like the listed ones, is
/// never an independent voice (K92) and is the first a transaction is
/// handed to.
pub fn own_nodes(data_dir: &Path) -> (Vec<Source>, usize) {
    use std::io::Read;
    let file = match std::fs::File::open(data_dir.join(OWN_NODES_FILE)) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), 0),
        Err(_) => return (Vec::new(), 1),
    };
    let mut bytes = Vec::new();
    if (&file).take(MAX_OWN_FILE).read_to_end(&mut bytes).is_err() {
        return (Vec::new(), 1);
    }
    let at_limit = u64::try_from(bytes.len()).ok() == Some(MAX_OWN_FILE);
    let partial = at_limit && !bytes.ends_with(b"\n")
        && file.metadata().map_or(true, |m| m.len() != MAX_OWN_FILE);
    if partial {
        let end = bytes.iter().rposition(|c| *c == b'\n').map_or(0, |p| p.saturating_add(1));
        bytes.truncate(end);
    }
    let Ok(text) = std::str::from_utf8(&bytes) else { return (Vec::new(), 1) };
    let (mut nodes, mut refused) = (Vec::new(), usize::from(partial));
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
        match Source::own(line) {
            Some(source) if nodes.len() < MAX_OWN_NODES && !nodes.iter().any(|n: &Source| n.host == source.host && n.port == source.port) => nodes.push(source),
            _ => refused = refused.saturating_add(1),
        }
    }
    (nodes, refused)
}

/// How many headers back the program looks: enough for the sign that
/// compares two days of difficulty.
pub const HISTORY: usize = 2 * signs::DROP_WINDOW + 1;

/// How many blocks below its tip the program names to tell a source that
/// is behind from one that is somewhere else.
pub const RECENT: usize = 64;

/// The sources are not asked more often than this.
pub const ASK_GAP: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 1 } else { 60 });

/// After a round without a quorum the wait doubles, up to this.
pub const ASK_GAP_MAX: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 4 } else { 600 });

/// What the asking is set up with.
pub struct Setup {
    /// Whom to ask.
    pub sources: Vec<Source>,
    /// How to reach them; nothing if the secure channel cannot be set up.
    pub asker: Option<Asker>,
    /// How many operators the list has to have for any quorum.
    pub least_groups: usize,
    /// How many of the user's own nodes are in `sources`, at their end.
    pub own: usize,
    /// Lines of the user's file that named no node.
    pub own_refused: usize,
}

impl Setup {
    /// The setup for `net`: the built-in list of a real network; for the
    /// network of automated tests, what a test left in the data directory.
    pub fn of(net: fly_chain_headers::Net, data_dir: &Path) -> Setup {
        Self::with_own_nodes(net, data_dir, false)
    }

    /// Keep the user's configured path and delivery priority when a listed host is preferred.
    pub fn for_posting(net: fly_chain_headers::Net, data_dir: &Path) -> Setup {
        Self::with_own_nodes(net, data_dir, true)
    }

    fn with_own_nodes(net: fly_chain_headers::Net, data_dir: &Path, posting: bool) -> Setup {
        let mut setup = Setup::listed(net, data_dir);
        let (mut own, refused) = own_nodes(data_dir);
        let same = |a: &Source, b: &Source| a.host == b.host && a.port == b.port;
        if posting {
            setup.sources.retain(|listed| !own.iter().any(|node| same(node, listed)));
        } else {
            own.retain(|node| !setup.sources.iter().any(|listed| same(node, listed)));
        }
        setup.own = own.len();
        setup.own_refused = refused;
        setup.sources.extend(own);
        setup
    }

    fn listed(net: fly_chain_headers::Net, data_dir: &Path) -> Setup {
        fn asker() -> Option<Asker> {
            Asker::new().ok()
        }
        use fly_chain_headers::Net;
        match net {
            Net::Main => Setup {
                sources: source::mainnet(),
                asker: asker(),
                least_groups: source::MAINNET_GROUPS,
                own: 0,
                own_refused: 0,
            },
            Net::Test => Setup {
                sources: source::testnet(),
                asker: asker(),
                least_groups: source::TESTNET_GROUPS,
                own: 0,
                own_refused: 0,
            },
            Net::Automated => {
                let listed = if cfg!(feature = "test-net") {
                    std::fs::read_to_string(data_dir.join(TEST_SOURCES_FILE)).unwrap_or_default()
                } else {
                    String::new()
                };
                let sources: Vec<Source> = listed.lines().filter_map(test_source).collect();
                let asker = std::fs::read(data_dir.join(TEST_ROOTS_FILE))
                    .ok()
                    .and_then(|pem| Asker::trusting_pem(&pem));
                Setup {
                    sources,
                    asker,
                    least_groups: source::MAINNET_GROUPS,
                    own: 0,
                    own_refused: 0,
                }
            }
        }
    }
}

fn test_source(line: &str) -> Option<Source> {
    let mut words = line.split_whitespace();
    let mut source = Source::own(words.next()?)?;
    source.group = words.next()?.to_string();
    source.asn = words.next()?.parse().ok();
    Some(source)
}

/// A block of the program's verified chain with its own time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    /// Its height, hash and the work up to it.
    pub said: Said,
    /// The time in its header, in seconds since 1970.
    pub time: u64,
}

/// The last headers of the program's verified chain, the tip last.
#[derive(Debug, Default)]
pub struct History {
    blocks: VecDeque<Block>,
}

impl History {
    /// Brings the history up to the chain whose tip is `tip` high.
    /// `hash_at` and `block_at` read the verified chain; `floor` is the
    /// lowest height it has.
    pub fn refresh(
        &mut self,
        floor: u64,
        tip: u64,
        hash_at: impl Fn(u64) -> Option<[u8; 32]>,
        mut block_at: impl FnMut(u64) -> Option<Block>,
    ) {
        // what the chain no longer has, or has another block for
        while let Some(last) = self.blocks.back() {
            if last.said.height <= tip && hash_at(last.said.height) == Some(last.said.hash) {
                break;
            }
            self.blocks.pop_back();
        }
        let deep = u64::try_from(HISTORY).unwrap_or(u64::MAX).saturating_sub(1);
        let lowest = tip.saturating_sub(deep).max(floor);
        let mut next = match self.blocks.back() {
            Some(last) if last.said.height >= lowest => last.said.height.saturating_add(1),
            _ => {
                self.blocks.clear();
                lowest
            }
        };
        while next <= tip {
            let Some(block) = block_at(next) else {
                // a hole in what could be read: nothing below it is of use
                self.blocks.clear();
                next = next.saturating_add(1);
                continue;
            };
            self.blocks.push_back(block);
            next = next.saturating_add(1);
        }
        while self.blocks.len() > HISTORY {
            self.blocks.pop_front();
        }
    }

    /// The tip.
    pub fn tip(&self) -> Option<Block> {
        self.blocks.back().copied()
    }

    /// Whether the chain has exactly this block.
    pub fn holds(&self, said: &Said) -> bool {
        self.blocks.iter().rev().any(|block| block.said == *said)
    }

    /// The blocks right below the tip, at most [`RECENT`].
    pub fn recent(&self) -> Vec<Said> {
        self.blocks.iter().rev().skip(1).take(RECENT).map(|block| block.said).collect()
    }

    fn times(&self) -> Vec<u64> {
        self.blocks.iter().map(|block| block.time).collect()
    }

    fn work(&self) -> Vec<u64> {
        self.blocks.iter().map(|block| block.said.total_difficulty).collect()
    }
}

/// What the node knows at this moment.
pub struct Facts<'a> {
    /// The last headers of the verified chain.
    pub history: &'a History,
    /// The height and time of the starting point.
    pub start: (u64, u64),
    /// Whether a node is connected and none claims more work than is
    /// verified.
    pub caught_up: bool,
    /// The addresses of the connected nodes.
    pub peers: &'a [IpAddr],
    /// This moment.
    pub now: Instant,
    /// The computer's clock at this moment, in milliseconds since 1970.
    pub clock_ms: u64,
}

/// An asking the node has to start.
pub struct Ask {
    /// The generation, opened and with its number on the disk.
    pub generation: Generation,
    /// Blocks of the program's chain below the tip.
    pub recent: Vec<Said>,
    /// How to reach the sources.
    pub asker: Asker,
}

/// News of an asking.
#[derive(Debug, Clone)]
pub struct Surveyed {
    /// The number of the generation.
    pub id: u64,
    /// What it adds up to so far.
    pub verdict: Verdict,
    /// The claims of more made in it, by the name of the source.
    pub claims: Vec<(String, Said)>,
    /// The times written on the answers counted.
    pub stamps: Vec<Stamp>,
    /// Whether an answer came after the deadline.
    pub late: bool,
    /// Whether nothing more will come.
    pub over: bool,
}

struct Round {
    id: u64,
    tip: Said,
    confirmed: bool,
}

/// What stands in the way of calling the tip selected.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Why {
    Memory(Damaged),
    NoSources,
    NoChannel,
    NotCaughtUp,
    Claim(String),
    Full,
    Time(Option<Unconfirmed>),
    Asking,
    NoQuorum(Verdict),
    NotAsked,
}

/// The state of the asking and of what it has established.
pub struct Accept {
    setup: Setup,
    memory: Result<Memory, Damaged>,
    pace: Pace,
    time: Option<Time>,
    pending_time: Option<Time>,
    last_claim_low: Option<u64>,
    time_trouble: Option<Unconfirmed>,
    /// The last tip a quorum named.
    confirmed: Option<Said>,
    round: Option<Round>,
    last_verdict: Option<Verdict>,
    next_ask: Option<Instant>,
    gap: Duration,
    selected: Option<Said>,
    caveat: bool,
    why: Option<Why>,
    signs: Option<Signs>,
}

impl Accept {
    /// Opens what earlier runs kept in `data_dir`.
    pub fn open(setup: Setup, data_dir: &Path) -> Accept {
        Accept {
            setup,
            memory: Memory::open(&data_dir.join(MEMORY_FILE)),
            pace: Pace::default(),
            time: None,
            pending_time: None,
            last_claim_low: None,
            time_trouble: None,
            confirmed: None,
            round: None,
            last_verdict: None,
            next_ask: None,
            gap: ASK_GAP,
            selected: None,
            caveat: false,
            why: Some(Why::NotAsked),
            signs: None,
        }
    }

    /// The tip, if it is selected.
    pub fn selected(&self) -> Option<Said> {
        self.selected
    }

    /// The interval a reader can independently recheck before showing a selected tip.
    pub(crate) fn clock_evidence(&self) -> Option<Time> {
        self.time
    }

    /// The lower bound of the confirmed time at `now`, in seconds.
    pub fn confirmed_time(&self, now: Instant, clock_ms: u64) -> Option<u64> {
        let (low, _) = self.time?.at(now, clock_ms)?;
        low.checked_div(1000)
    }

    /// Whether what is selected is selected with a caveat: a claim of
    /// more work went unsettled not long ago.
    pub fn caveat(&self) -> bool {
        self.caveat
    }

    /// The signs as last worked out; nothing while the time is not
    /// confirmed.
    pub fn signs(&self) -> Option<Signs> {
        self.signs
    }

    /// Takes in where the node stands. Returns an asking to start, if
    /// one is due.
    pub fn tend(&mut self, facts: &Facts) -> Option<Ask> {
        self.selected = None;
        self.caveat = false;
        self.signs = None;
        let Some(tip) = facts.history.tip() else {
            self.why = Some(Why::NotCaughtUp);
            return None;
        };
        let memory = match &mut self.memory {
            Ok(memory) => memory,
            Err(damaged) => {
                self.why = Some(Why::Memory(*damaged));
                return None;
            }
        };
        if self.setup.sources.is_empty() {
            self.why = Some(Why::NoSources);
            return None;
        }
        if self.setup.asker.is_none() {
            self.why = Some(Why::NoChannel);
            return None;
        }

        // the time, and what passes with it
        if let Some(time) = self.pending_time {
            if let Some((low, high)) = time.at(facts.now, facts.clock_ms) {
                if let Err(damaged) = memory.resume_clock(time.low_ms, high, self.last_claim_low) {
                    self.why = Some(Why::Memory(damaged));
                    return None;
                }
                self.time = Some(time);
                self.last_claim_low = Some(low);
                self.time_trouble = None;
            }
            self.pending_time = None;
        }
        let bounds = self.time.and_then(|time| time.at(facts.now, facts.clock_ms));
        if bounds.is_none() {
            self.time = None;
        } else if let Some((low, _)) = bounds {
            self.last_claim_low = Some(low);
        }
        let history = facts.history;
        let mut settled = 0;
        let kept = memory.change_claims(|claims| {
            settled = claims.settle(|said| history.holds(said));
            if let Some(bounds) = bounds {
                claims.tick(bounds);
            }
        });
        if let Err(damaged) = kept {
            self.why = Some(Why::Memory(damaged));
            return None;
        }
        if settled > 0 {
            // the block a source was ahead by has come: the sources may
            // be asked about the new tip without waiting
            self.gap = ASK_GAP;
            self.next_ask = Some(facts.now);
        }
        self.caveat = memory.claims().caveat();

        let signs = bounds.map(|bounds| Signs {
            lag: signs::lag(tip.time, bounds),
            deficit: signs::deficit(facts.start.0, facts.start.1, tip.said.height, bounds),
            drop: signs::drop(&history.work()),
            slow_hour: signs::slow_hour(&history.times(), bounds),
            peers: signs::peers(facts.peers),
        });
        self.signs = signs;
        let fired = signs.is_none_or(|signs| signs.fired());

        let on_chain = self.confirmed.filter(|named| history.holds(named));
        let exact = on_chain == Some(tip.said);
        let believed = exact || (on_chain.is_some() && !fired);

        // an asking of an older tip is no longer waited for
        let busy = self.round.as_ref().is_some_and(|round| round.tip == tip.said);
        if !busy {
            if let Some(round) = self.round.take() {
                self.pace.after(round.confirmed, false);
                // the tip moved under it: the new one may be asked about
                // without waiting
                self.next_ask = Some(facts.now);
            }
        }

        let blocked = memory.claims().blocks();
        self.why = if !facts.caught_up {
            Some(Why::NotCaughtUp)
        } else if blocked {
            let (list, full) = memory.claims().parts();
            match list.iter().find(|claim| claim.expired_ms.is_none()) {
                Some(claim) if !full => Some(Why::Claim(claim.host.clone())),
                _ => Some(Why::Full),
            }
        } else if bounds.is_none() && !busy {
            Some(Why::Time(self.time_trouble))
        } else if believed && bounds.is_some() {
            None
        } else if busy {
            Some(Why::Asking)
        } else {
            match self.last_verdict {
                Some(verdict) if !matches!(verdict, Verdict::Confirmed { .. }) => Some(Why::NoQuorum(verdict)),
                _ => Some(Why::NotAsked),
            }
        };
        if self.why.is_none() {
            self.selected = Some(tip.said);
        }

        // is it time to ask?
        let wanted = bounds.is_none() || on_chain.is_none() || (fired && !exact);
        let due = self.next_ask.is_none_or(|at| facts.now >= at);
        if !(facts.caught_up && wanted && due && !busy) {
            return None;
        }
        let id = match memory.next_generation() {
            Ok(id) => id,
            Err(damaged) => {
                self.why = Some(Why::Memory(damaged));
                self.selected = None;
                return None;
            }
        };
        let generation = Generation::open(
            id,
            tip.said,
            self.setup.sources.clone(),
            facts.now,
            self.pace.within(),
            self.setup.least_groups,
        );
        self.round = Some(Round {
            id,
            tip: tip.said,
            confirmed: false,
        });
        self.next_ask = facts.now.checked_add(self.gap);
        Some(Ask {
            generation,
            recent: history.recent(),
            asker: self.setup.asker.clone()?,
        })
    }

    /// [`Accept::tend`], and hands the asking that is due to `start`. An
    /// asking `start` could not start is closed here: no news of it will
    /// ever come, and waiting for them would keep the tip "being asked
    /// about" until the next block. Nothing was asked, so nothing is held
    /// against the sources, and the same tip is asked about again after
    /// the usual pause.
    pub fn tend_and_start<E>(&mut self, facts: &Facts, start: impl FnOnce(Ask) -> Result<(), E>) -> Result<(), E> {
        let Some(ask) = self.tend(facts) else {
            return Ok(());
        };
        let id = ask.generation.id();
        let started = start(ask);
        if started.is_err() && self.round.as_ref().is_some_and(|round| round.id == id) {
            self.round = None;
        }
        started
    }

    /// Takes in news of an asking.
    pub fn took(&mut self, news: &Surveyed, facts: &Facts) {
        // a claim of more is kept whichever asking it came from
        if !news.claims.is_empty() {
            let bounds = self.time.and_then(|time| time.at(facts.now, facts.clock_ms));
            let kept = match &mut self.memory {
                Ok(memory) => memory.change_claims(|claims| {
                    for (host, said) in &news.claims {
                        if claims.note(host, *said, bounds) == Noted::Full {
                            break;
                        }
                    }
                }),
                Err(_) => return,
            };
            // a claim that cannot be kept is not let go: nothing is
            // confirmed from here on
            if let Err(damaged) = kept {
                self.memory = Err(damaged);
                return;
            }
        }
        let Ok(memory) = &mut self.memory else {
            return;
        };
        let Some(round) = self.round.as_mut().filter(|round| round.id == news.id) else {
            return;
        };
        self.last_verdict = Some(news.verdict);

        // the time written on the answers
        match time::confirm(&news.stamps, &self.setup.sources, facts.now, facts.clock_ms, memory.floor_ms()) {
            Ok(time) => {
                self.pending_time = None;
                let continuous = self.time.and_then(|old| old.at(facts.now, facts.clock_ms));
                let stored = if continuous.is_some() {
                    memory.raise_floor(time.low_ms)
                } else {
                    memory.resume_clock(time.low_ms, time.high_ms, self.last_claim_low)
                };
                if let Err(damaged) = stored {
                    self.pending_time = Some(time);
                    self.time = None;
                    self.selected = None;
                    self.why = Some(Why::Memory(damaged));
                } else {
                    self.time = Some(time);
                    self.time_trouble = None;
                }
            }
            // too few so far says nothing against a time held already
            Err(Unconfirmed::TooFew) => {
                if news.over && self.time.is_none() {
                    self.time_trouble = Some(Unconfirmed::TooFew);
                }
            }
            Err(trouble) => {
                self.pending_time = None;
                self.time = None;
                self.time_trouble = Some(trouble);
            }
        }

        // a quorum counts for the tip it was asked about, and only while
        // that is still the tip
        let still = facts.history.tip().is_some_and(|tip| tip.said == round.tip);
        if matches!(news.verdict, Verdict::Confirmed { .. }) && still {
            round.confirmed = true;
            self.confirmed = Some(round.tip);
        } else if round.confirmed && !matches!(news.verdict, Verdict::Confirmed { .. }) {
            // a later answer took the confirmation away
            round.confirmed = false;
            if self.confirmed == Some(round.tip) {
                self.confirmed = None;
            }
        }
        if news.over {
            let confirmed = round.confirmed;
            self.pace.after(confirmed, news.late);
            self.round = None;
            if confirmed {
                self.gap = ASK_GAP;
                self.next_ask = facts.now.checked_add(self.gap);
            } else if still {
                self.gap = self.gap.saturating_mul(2).min(ASK_GAP_MAX);
                self.next_ask = facts.now.checked_add(self.gap);
            } else {
                // the tip moved before the answers came: nothing was
                // learnt about the new one, and nothing is held against
                // the sources
                self.next_ask = Some(facts.now);
            }
        }
    }

    /// Why the tip is not selected, in words; nothing when it is.
    pub fn note(&self) -> Option<String> {
        let why = self.why.as_ref()?;
        Some(match why {
            Why::Memory(Damaged::Spent) => "the numbers for asking public nodes ran out: no tip is confirmed".to_string(),
            Why::Memory(Damaged::Write) => format!("{MEMORY_FILE} cannot be written: no tip is confirmed"),
            Why::Memory(_) => format!("{MEMORY_FILE} cannot be read back: no tip is confirmed"),
            Why::NoSources => "no public nodes are listed for this network: no tip is confirmed".to_string(),
            Why::NoChannel => "no secure channel to public nodes: no tip is confirmed".to_string(),
            Why::NotCaughtUp => "not at the tip yet".to_string(),
            Why::Claim(host) => format!("public node {host} names more work than is verified here"),
            Why::Full => "too many unsettled claims of more work: no tip is confirmed".to_string(),
            Why::Time(None) => "the time is not confirmed yet".to_string(),
            Why::Time(Some(Unconfirmed::TooFew)) => "the time is not confirmed: too few public nodes answered".to_string(),
            Why::Time(Some(Unconfirmed::Disagree)) => "the time is not confirmed: public nodes disagree about it".to_string(),
            Why::Time(Some(Unconfirmed::Clock)) => "this computer's clock is far from the time of public nodes: check the clock".to_string(),
            Why::Time(Some(Unconfirmed::Before)) => "public nodes name a time before one confirmed earlier".to_string(),
            Why::Asking => "asking public nodes about the tip".to_string(),
            Why::NoQuorum(Verdict::NoQuorum {
                answered,
                needed,
                confirming,
            }) => format!("public nodes did not confirm the tip ({answered} answered, {needed} needed, {confirming} named it)"),
            Why::NoQuorum(Verdict::Ahead) => "a public node names more work than is verified here".to_string(),
            Why::NoQuorum(_) => "the list of public nodes is too small to confirm a tip".to_string(),
            Why::NotAsked => "public nodes have not been asked yet".to_string(),
        })
    }

    /// Which signs are up, in words; nothing if none is.
    pub fn signs_note(&self) -> Option<String> {
        let signs = self.signs?;
        let mut up = Vec::new();
        if signs.lag == Sign::Fired {
            up.push("the tip is old");
        }
        if signs.slow_hour == Some(Sign::Fired) {
            up.push("few blocks in the last hour");
        }
        if signs.deficit == Sign::Fired {
            up.push("the chain is shorter than a block a minute would make it");
        }
        if signs.drop == Some(Sign::Fired) {
            up.push("the difficulty fell");
        }
        if signs.peers == Sign::Fired {
            up.push("connected to nodes of fewer than three networks");
        }
        (!up.is_empty()).then(|| up.join(", "))
    }
}

/// Carries an asking out: asks every source, and after every answer
/// tells what the generation adds up to. Blocks until nothing more can
/// come; meant for a thread of its own. `tell` returns whether anybody
/// still listens.
pub fn survey(ask: Ask, mut tell: impl FnMut(Surveyed) -> bool) {
    use fly_chain_tips::survey::{Survey, GRACE};
    let id = ask.generation.id();
    let mut survey = Survey::start(&ask.asker, ask.generation, ask.recent, GRACE);
    let mut told: Option<(Verdict, usize, usize, bool)> = None;
    loop {
        let more = survey.step(Duration::from_millis(250));
        let generation = survey.generation();
        let claims: Vec<(String, Said)> = generation
            .claims()
            .into_iter()
            .filter_map(|(index, said)| Some((generation.sources().get(index)?.host.clone(), said)))
            .collect();
        let now = (generation.verdict(), claims.len(), survey.stamps().len(), generation.late());
        if told != Some(now) || !more {
            told = Some(now);
            let news = Surveyed {
                id,
                verdict: now.0,
                claims,
                stamps: survey.stamps().to_vec(),
                late: now.3,
                over: !more,
            };
            if !tell(news) {
                return;
            }
        }
        if !more {
            return;
        }
    }
}
