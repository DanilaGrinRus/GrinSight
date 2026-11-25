//! Handing the wallet's finished transactions to the network.
//!
//! A node does not say whether it took a transaction: the protocol has no
//! answer to one. What this program can know, and how:
//!
//! * before anything is sent, whether the transaction can be valid at all
//!   on the chain this program has verified: it is well formed, its
//!   signatures, range proofs and sums hold, every input is among the
//!   unspent outputs of the verified state, no output is there already,
//!   its fee is not below what nodes take, and it is not locked to a later
//!   height. A transaction that fails is not sent, and the wallet is told
//!   it was refused;
//! * after it was sent, whether nodes have it: a node that hands this
//!   program the transaction - by itself, as nodes pass transactions on,
//!   or when asked for it - holds it in its pool;
//! * whether it is in a block: the kernels of the blocks this program
//!   applies.
//!
//! A transaction goes out the way a Grin node sends its own: first to one
//! node only, as a stem transaction, which that node passes on along a
//! path before it is announced to everybody (Dandelion). This program
//! passes no transactions of others on, so the node the stem goes to could
//! tell whose it is from the address it came from. It therefore goes
//! through Tor (`send`): to a public node's API or to a node of the
//! network, never over the connections this program follows the chain on.
//! If it has not come back from the network when the stem's time is up,
//! it is sent through Tor once more, to be announced at once, and again
//! every so often until a node hands it back or it is in a block. Nothing
//! about it - neither the transaction nor a question for it - goes over
//! this program's own connections.
//!
//! Only if the user agreed to it does a transaction that cannot be sent
//! through Tor go out over those connections, from this computer's
//! address: as a stem to one of them, and when the stem's time is up
//! announced to all of them, after which one at a time is asked whether it
//! holds it.
//!
//! This program does not remember what it sent when it is started again:
//! a list of the wallet's transactions is not left on disk. The wallet
//! remembers, in its own journal, and hands a transaction over again. One
//! that is not in a block yet is new to this program and goes out as a
//! stem once more; one that is in the chain already is recognised by its
//! outputs and is not sent anywhere.
//!
//! Not checked here: that a coinbase input is mature. The verified state
//! does not keep the height of an output; the wallet does not spend an
//! immature output, and a node refuses one.
use fly_chain_state::advance::Live;
use fly_paycore_chain_port::{Posted, Tip};
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::transaction::{KernelFeatures, Transaction, Weighting};
use grin_core::core::CommitWrapper;
use grin_core::ser::{self, DeserializationMode, ProtocolVersion};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Transactions kept track of at a time. When there is no room, one that
/// is in a block makes way; if none is, a new transaction is not taken.
pub const MAX_SENT: usize = 16;
/// How long a stem transaction is given to come back from the network
/// before it is announced to every node: what a node gives its own.
pub const STEM_FOR: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 3 } else { 180 });
/// Between two questions to a node whether it holds an announced
/// transaction.
pub const ASK_EVERY: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 1 } else { 20 });
/// Between two announcements through Tor of a transaction no node has
/// handed back.
pub const RESEND_EVERY: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 2 } else { 300 });
/// After a try through Tor failed, before the next.
pub const RETRY_AFTER: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 1 } else { 60 });

/// The blocks whose kernels were last looked at, the newest last. When the
/// chain turns onto another branch, this is how the block where the two
/// part is found: nothing else remembers the hashes of the branch that is
/// gone.
pub const TRAIL: usize = 128;

/// See [`TRAIL`].
#[derive(Default)]
pub struct Trail(VecDeque<Tip>);

impl Trail {
    /// The block looked at last.
    pub fn at(&self) -> Option<Tip> {
        self.0.back().copied()
    }

    /// One more block was looked at.
    pub fn push(&mut self, tip: Tip) {
        if self.0.len() >= TRAIL {
            self.0.pop_front();
        }
        self.0.push_back(tip);
    }

    /// Start over: nothing was looked at.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// The chain has turned: `on_chain` gives the hash the verified chain
    /// has at a height now. Everything looked at that is not on it is
    /// dropped. The height of the newest block that is still on the chain,
    /// or `None` if none of the remembered ones is.
    pub fn back_to(&mut self, on_chain: impl Fn(u64) -> Option<[u8; 32]>) -> Option<u64> {
        while let Some(last) = self.0.back() {
            if on_chain(last.height) == Some(last.hash) {
                return Some(last.height);
            }
            self.0.pop_back();
        }
        None
    }
}

/// Why a transaction is not sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The bytes are not one transaction.
    Unreadable,
    /// It is not a valid transaction: structure, weight, signatures, range
    /// proofs or sums.
    Invalid,
    /// A kernel of a kind a wallet's payment does not have.
    Kernel,
    /// It may not be in a block yet.
    Locked,
    /// Its fee is below what nodes take.
    Fee,
    /// An input is not among the unspent outputs of the verified state.
    Input,
    /// An output is among the unspent outputs already.
    Output,
}

/// The commitments of the kernels, in order: what a transaction is known by.
fn excesses(tx: &Transaction) -> Vec<[u8; 33]> {
    let mut all: Vec<[u8; 33]> = tx.kernels().iter().map(|kernel| kernel.excess.0).collect();
    all.sort_unstable();
    all
}

/// Read the transaction the wallet handed over: exactly one, nothing after it.
pub fn read(bytes: &[u8]) -> Result<Transaction, Refusal> {
    let mut rest = bytes;
    let tx: Transaction = ser::deserialize(&mut rest, ProtocolVersion::local(), DeserializationMode::default()).map_err(|_| Refusal::Unreadable)?;
    if !rest.is_empty() || tx.kernels().is_empty() {
        return Err(Refusal::Unreadable);
    }
    Ok(tx)
}

/// Whether `tx` can be valid on top of the verified state `live`.
pub fn fits(tx: &Transaction, live: &Live) -> Result<(), Refusal> {
    tx.validate(Weighting::AsTransaction).map_err(|_| Refusal::Invalid)?;
    let next = live.header().height.saturating_add(1);
    for kernel in tx.kernels() {
        match kernel.features {
            KernelFeatures::Plain { .. } => {}
            KernelFeatures::HeightLocked { lock_height, .. } if lock_height <= next => {}
            KernelFeatures::HeightLocked { .. } => return Err(Refusal::Locked),
            KernelFeatures::Coinbase | KernelFeatures::NoRecentDuplicate { .. } => return Err(Refusal::Kernel),
        }
    }
    if tx.shifted_fee() < tx.accept_fee() {
        return Err(Refusal::Fee);
    }
    let inputs: Vec<CommitWrapper> = tx.inputs().into();
    if inputs.is_empty() || inputs.iter().any(|input| live.unspent(&input.commitment().0).is_none()) {
        return Err(Refusal::Input);
    }
    if tx.outputs().iter().any(|output| live.unspent(&output.commitment().0).is_some()) {
        return Err(Refusal::Output);
    }
    Ok(())
}

/// Whether `tx` is in the verified chain already, as far as the state
/// `live` can show it: every output it makes is unspent there, and none
/// of its inputs is. A transaction that was valid when it was signed and
/// looks like this now has been mined; this one, or one that made the
/// very same outputs.
pub fn in_chain(tx: &Transaction, live: &Live) -> bool {
    let inputs: Vec<CommitWrapper> = tx.inputs().into();
    !inputs.is_empty()
        && !tx.outputs().is_empty()
        && tx.outputs().iter().all(|output| live.unspent(&output.commitment().0).is_some())
        && inputs.iter().all(|input| live.unspent(&input.commitment().0).is_none())
}

/// Where a transaction that was sent stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Given to one node as a stem transaction.
    Stem { at: Instant },
    /// Announced by this program.
    Open { at: Instant, asked: Option<Instant> },
}

/// Which way a transaction goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// Through Tor.
    Tor {
        /// A try is under way.
        busy: bool,
        /// When the last try failed, if it did.
        failed: Option<Instant>,
        /// Tries made, to start each at another node.
        tries: usize,
    },
    /// Over this program's own connections: the user agreed to it, and Tor
    /// failed.
    Direct,
}

struct Sent {
    excesses: Vec<[u8; 33]>,
    tx: Transaction,
    stage: Stage,
    route: Route,
    /// A node handed it to this program: it is in that node's pool.
    seen: bool,
    /// The height of the block it is in.
    mined: Option<u64>,
    /// The owner agreed that this one transaction goes out from this
    /// computer's address if Tor fails to send it (K192).
    direct: bool,
}

impl Sent {
    /// From now on over this program's own connections, `peers`: the stem
    /// to one of them, or the announcement to all once the stem's time is
    /// up. Nothing if it is in a block, was seen in a node's pool, or there
    /// is nobody connected.
    fn go_direct(&mut self, now: Instant, peers: &[SocketAddr]) -> Option<Do> {
        if peers.is_empty() || self.mined.is_some() || self.seen {
            return None;
        }
        let spread = self.excesses.first().and_then(|excess| excess.last()).copied().map_or(0, usize::from);
        let to = spread.checked_rem(peers.len()).and_then(|at| peers.get(at)).copied()?;
        self.route = Route::Direct;
        Some(match self.stage {
            Stage::Stem { .. } => {
                self.stage = Stage::Stem { at: now };
                Do::Stem {
                    to,
                    tx: Box::new(self.tx.clone()),
                }
            }
            Stage::Open { .. } => {
                self.stage = Stage::Open { at: now, asked: None };
                Do::Announce {
                    to: peers.to_vec(),
                    tx: Box::new(self.tx.clone()),
                }
            }
        })
    }

    /// A try through Tor, now.
    fn through_tor(&mut self, fluff: bool) -> Do {
        let tries = match self.route {
            Route::Tor { tries, .. } => tries,
            Route::Direct => 0,
        };
        self.route = Route::Tor {
            busy: true,
            failed: None,
            tries: tries.saturating_add(1),
        };
        Do::Send {
            key: self.excesses.clone(),
            tx: Box::new(self.tx.clone()),
            fluff,
            turn: tries.saturating_add(usize::from(self.excesses.first().and_then(|e| e.last()).copied().unwrap_or(0))),
        }
    }
}

/// What is to be done with a transaction now.
#[derive(Debug)]
pub enum Do {
    /// Give it to this node as a stem transaction.
    Stem {
        /// The node.
        to: SocketAddr,
        /// The transaction.
        tx: Box<Transaction>,
    },
    /// Announce it to these nodes.
    Announce {
        /// The nodes.
        to: Vec<SocketAddr>,
        /// The transaction.
        tx: Box<Transaction>,
    },
    /// Send it through Tor.
    Send {
        /// Its kernels.
        key: Vec<[u8; 33]>,
        /// The transaction.
        tx: Box<Transaction>,
        /// To be announced at once.
        fluff: bool,
        /// Where among the nodes to start.
        turn: usize,
    },
    /// Ask this node for the transaction with this kernel.
    Ask {
        /// The node.
        to: SocketAddr,
        /// The hash of the kernel.
        kernel: Hash,
    },
}

/// The transactions this program has sent and what it knows of each.
#[derive(Default)]
pub struct Outbox {
    sent: Vec<Sent>,
    turn: usize,
    /// The user agreed that a transaction Tor fails to send goes out over
    /// this program's own connections.
    direct: bool,
    /// Why the last try through Tor failed, until one succeeds.
    trouble: Option<String>,
}

impl Outbox {
    /// Nothing sent yet. `direct`: the user agreed that a transaction Tor
    /// fails to send goes out from this computer's address.
    pub fn new(direct: bool) -> Outbox {
        Outbox {
            direct,
            ..Outbox::default()
        }
    }

    /// Whether the user agreed to the direct way.
    pub fn direct(&self) -> bool {
        self.direct
    }

    /// Why a transaction is not out, in words, while it is not.
    pub fn trouble(&self) -> Option<&str> {
        self.trouble.as_deref().filter(|_| self.sent.iter().any(|sent| matches!(sent.route, Route::Tor { .. }) && sent.mined.is_none() && !sent.seen))
    }

    /// Whether any transaction is kept track of that is not in a block.
    pub fn waiting(&self) -> bool {
        self.sent.iter().any(|sent| sent.mined.is_none())
    }

    /// Whether any transaction is kept track of at all.
    pub fn is_empty(&self) -> bool {
        self.sent.is_empty()
    }

    /// The kernels to look out for among what nodes send.
    pub fn watched(&self) -> Vec<([u8; 33], Hash)> {
        self.sent.iter().filter(|sent| sent.mined.is_none() && !sent.seen)
            .flat_map(|sent| sent.tx.kernels().iter().map(|kernel| (kernel.excess.0, kernel.hash()))).collect()
    }

    /// The transactions a node may ask this program for: those it has
    /// announced itself over its own connections, by the hash of each
    /// kernel. A stem transaction is given to nobody but the node it was
    /// sent to, and one sent through Tor to nobody over these connections.
    pub fn announced(&self) -> Vec<(Hash, Transaction)> {
        self.sent
            .iter()
            .filter(|sent| sent.mined.is_none() && sent.route == Route::Direct && matches!(sent.stage, Stage::Open { .. }))
            .flat_map(|sent| sent.tx.kernels().iter().map(|kernel| (kernel.hash(), sent.tx.clone())))
            .collect()
    }

    /// The wallet hands a transaction over. `live` is the verified state,
    /// if there is one; `at_tip` whether it stands at the tip of the header
    /// chain with no node claiming more; `peers` the nodes connected now.
    ///
    /// The answer is what is known at this moment. For a transaction this
    /// program has sent before it is "accepted" once a node was found to
    /// hold it or it is in a block, and "unknown" until then; it is not
    /// sent again. A new transaction is checked against the verified
    /// state: one that cannot be valid is "rejected" and not sent. One
    /// that can is sent through Tor as a stem transaction and is
    /// "unknown": whether a node took it is seen only when one hands it
    /// back or it is in a block. Without a verified state at the tip
    /// nothing is checked or sent, and the answer is "unknown".
    ///
    /// A transaction this program does not know that is in the verified
    /// chain already - handed over again after this program was started
    /// anew - is "accepted": it is in a block. It is sent nowhere and not
    /// kept track of; the wallet finds its kernel in the blocks.
    pub fn post(&mut self, bytes: &[u8], now: Instant, live: Option<&Live>, at_tip: bool) -> (Posted, Option<Do>) {
        let Ok(tx) = read(bytes) else {
            return (Posted::Rejected, None);
        };
        let known = excesses(&tx);
        if let Some(sent) = self.sent.iter().find(|sent| sent.excesses == known) {
            let accepted = sent.seen || sent.mined.is_some();
            return (if accepted { Posted::Accepted } else { Posted::Unknown }, None);
        }
        let (Some(live), true) = (live, at_tip) else {
            return (Posted::Unknown, None);
        };
        if tx.validate(Weighting::AsTransaction).is_ok() && in_chain(&tx, live) {
            return (Posted::Accepted, None);
        }
        if fits(&tx, live).is_err() {
            return (Posted::Rejected, None);
        }
        if self.sent.len() >= MAX_SENT {
            // the one longest in a block makes way
            let Some(oldest) = (0..self.sent.len()).filter(|at| self.sent.get(*at).is_some_and(|sent| sent.mined.is_some())).min_by_key(|at| self.sent.get(*at).and_then(|sent| sent.mined)) else {
                return (Posted::Unknown, None);
            };
            self.sent.remove(oldest);
        }
        let mut sent = Sent {
            excesses: known,
            tx,
            stage: Stage::Stem { at: now },
            route: Route::Tor {
                busy: false,
                failed: None,
                tries: 0,
            },
            seen: false,
            mined: None,
            direct: false,
        };
        let todo = sent.through_tor(false);
        self.sent.push(sent);
        (Posted::Unknown, Some(todo))
    }

    /// K192: the owner agrees that this one transaction - one this program
    /// keeps track of - goes out from this computer's address when Tor
    /// fails to send it. If a try through Tor has failed already and none
    /// is under way, it goes over the program's own connections at once;
    /// otherwise when the try under way fails. A transaction that Tor does
    /// send is not sent directly as well. Says whether the transaction is
    /// one this program keeps track of.
    pub fn agree_direct(&mut self, bytes: &[u8], now: Instant, peers: &[SocketAddr]) -> (bool, Option<Do>) {
        let Ok(tx) = read(bytes) else {
            return (false, None);
        };
        let known = excesses(&tx);
        let Some(sent) = self.sent.iter_mut().find(|sent| sent.excesses == known) else {
            return (false, None);
        };
        sent.direct = true;
        let todo = match sent.route {
            Route::Tor { busy: false, failed: Some(_), .. } => sent.go_direct(now, peers),
            _ => None,
        };
        (true, todo)
    }

    /// How a try through Tor for the transaction with these kernels went.
    /// When it failed and the user agreed, the transaction goes out over
    /// this program's own connections, `peers`, from then on.
    pub fn sent(&mut self, key: &[[u8; 33]], result: Result<(), String>, now: Instant, peers: &[SocketAddr]) -> Option<Do> {
        let direct = self.direct;
        let sent = self.sent.iter_mut().find(|sent| sent.excesses == key)?;
        let Route::Tor { tries, .. } = sent.route else {
            return None;
        };
        match result {
            Ok(()) => {
                self.trouble = None;
                sent.route = Route::Tor {
                    busy: false,
                    failed: None,
                    tries,
                };
                // the time of the stem runs from when it went
                if let Stage::Stem { .. } = sent.stage {
                    sent.stage = Stage::Stem { at: now };
                }
                None
            }
            Err(why) => {
                sent.route = Route::Tor {
                    busy: false,
                    failed: Some(now),
                    tries,
                };
                // the direct way: agreed to for everything, or for this one (K192)
                if direct || sent.direct {
                    if let Some(todo) = sent.go_direct(now, peers) {
                        return Some(todo);
                    }
                }
                self.trouble = Some(why);
                None
            }
        }
    }

    /// A node handed this program a transaction with these kernels, not as
    /// a stem: it holds it. True if one of the transactions kept track of
    /// is in it - alone, or joined with others on its way.
    pub fn heard(&mut self, kernels: &[Hash]) -> bool {
        let mut any = false;
        for sent in &mut self.sent {
            if !sent.seen && sent.mined.is_none() && sent.tx.kernels().iter().all(|kernel| kernels.contains(&kernel.hash())) {
                sent.seen = true;
                any = true;
            }
        }
        any
    }

    /// The block at `height` was applied, with these kernels.
    pub fn block(&mut self, height: u64, kernels: &[[u8; 33]]) {
        for sent in &mut self.sent {
            if sent.mined.is_none() && sent.excesses.iter().all(|excess| kernels.contains(excess)) {
                sent.mined = Some(height);
            }
        }
    }

    /// The chain turned onto another branch at the block `to` (`None`:
    /// somewhere below everything remembered): what was in a block above
    /// it is in no block until it is found in one again.
    pub fn taken_back(&mut self, to: Option<u64>) {
        for sent in &mut self.sent {
            if sent.mined.is_some_and(|height| to.is_none_or(|to| height > to)) {
                sent.mined = None;
                // Inclusion consumed the old pool observation. Await fresh evidence.
                sent.seen = false;
            }
        }
    }

    /// What is due at `now`. Through Tor: a try that failed is made again
    /// after a while; a stem whose time is up is sent once more to be
    /// announced, and so again every so often. Over this program's own
    /// connections `peers`: a stem whose time is up is announced to all of
    /// them; an announced transaction no node was found to hold is asked
    /// for, one node at a time.
    pub fn tend(&mut self, now: Instant, peers: &[SocketAddr]) -> Vec<Do> {
        let mut due = Vec::new();
        for sent in &mut self.sent {
            if sent.mined.is_some() || sent.seen {
                continue;
            }
            if let Route::Tor { busy, failed, .. } = sent.route {
                if busy {
                    continue;
                }
                let open = matches!(sent.stage, Stage::Open { .. });
                if let Some(failed) = failed {
                    if now.saturating_duration_since(failed) >= RETRY_AFTER {
                        due.push(sent.through_tor(open));
                    }
                    continue;
                }
                match sent.stage {
                    Stage::Stem { at } if now.saturating_duration_since(at) >= STEM_FOR => {
                        sent.stage = Stage::Open { at: now, asked: None };
                        due.push(sent.through_tor(true));
                    }
                    Stage::Open { at, asked } if now.saturating_duration_since(asked.unwrap_or(at)) >= RESEND_EVERY => {
                        sent.stage = Stage::Open { at, asked: Some(now) };
                        due.push(sent.through_tor(true));
                    }
                    Stage::Stem { .. } | Stage::Open { .. } => {}
                }
                continue;
            }
            if peers.is_empty() {
                continue;
            }
            match sent.stage {
                Stage::Stem { at } if now.saturating_duration_since(at) >= STEM_FOR => {
                    sent.stage = Stage::Open { at: now, asked: None };
                    due.push(Do::Announce {
                        to: peers.to_vec(),
                        tx: Box::new(sent.tx.clone()),
                    });
                }
                Stage::Open { at, asked } if now.saturating_duration_since(asked.unwrap_or(at)) >= ASK_EVERY => {
                    self.turn = self.turn.wrapping_add(1);
                    let to = self.turn.checked_rem(peers.len()).and_then(|at| peers.get(at)).copied();
                    let kernel = sent.tx.kernels().first().map(Hashed::hash);
                    if let (Some(to), Some(kernel)) = (to, kernel) {
                        sent.stage = Stage::Open { at, asked: Some(now) };
                        due.push(Do::Ask { to, kernel });
                    }
                }
                Stage::Stem { .. } | Stage::Open { .. } => {}
            }
        }
        due
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// The trail of blocks looked at: the newest is where to go on from;
    /// when the chain turns, everything that is not on it any more is
    /// dropped and the block where the branches part is found - or nothing
    /// is, when the turn is below everything remembered. Only so many
    /// blocks are remembered.
    #[test]
    fn the_trail_finds_where_the_branches_part() {
        let tip = |height: u64, branch: u8| Tip { height, hash: [branch; 32] };
        let mut trail = Trail::default();
        assert_eq!((trail.at(), trail.back_to(|_| Some([1; 32]))), (None, None));
        for height in 10..=15 {
            trail.push(tip(height, 1));
        }
        assert_eq!(trail.at(), Some(tip(15, 1)));
        // nothing turned
        assert_eq!(trail.back_to(|_| Some([1; 32])), Some(15));
        // the chain is another branch above 12
        let turned = |height: u64| Some(if height <= 12 { [1; 32] } else { [2; 32] });
        assert_eq!(trail.back_to(turned), Some(12));
        assert_eq!(trail.at(), Some(tip(12, 1)));
        trail.push(tip(13, 2));
        assert_eq!(trail.back_to(turned), Some(13));
        // a chain that is shorter now, and one that is another all the way down
        assert_eq!(trail.back_to(|height| (height <= 11).then_some([1; 32])), Some(11));
        assert_eq!((trail.back_to(|_| Some([3; 32])), trail.at()), (None, None));
        // no more than TRAIL blocks
        for height in 0..(TRAIL as u64 + 50) {
            trail.push(tip(height, 1));
        }
        assert_eq!(trail.back_to(|_| Some([1; 32])), Some(TRAIL as u64 + 49));
        let low = |height: u64| Some(if height < 50 { [1; 32] } else { [2; 32] });
        assert_eq!(trail.back_to(low), None, "the block where they part is not remembered any more");
        trail.push(tip(7, 1));
        trail.clear();
        assert_eq!(trail.at(), None);
    }
}
