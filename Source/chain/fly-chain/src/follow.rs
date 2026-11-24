//! Following the chain with blocks: from the archive header, where the
//! state was collected, to the tip of the verified header chain.
//!
//! Blocks are asked for by the hash of their verified header, a few ahead.
//! Each one is applied to the state under that header - the node's block
//! check, then the roots - and written down. When the header chain moves to
//! another branch, the blocks that are no longer on it are taken back.
//!
//! From what has been applied the wallet is answered: the block after its
//! position, or how far to go back, or where to start over.
use crate::schedule::Schedule;
use fly_chain_headers::chain::HeaderChain;
use fly_chain_headers::hash_bytes;
use fly_chain_state::advance::{Live, Rejected};
use fly_chain_state::archive::State;
use fly_chain_state::blocks::{AddError, Blocks, BlocksError, Reopened};
use fly_paycore_chain_port::{BlockFacts, OutputFact, Step, Tip, Unknown};
use grin_core::core::{pmmr, Block, BlockHeader, CommitWrapper, OutputFeatures};
use grin_core::global;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Instant;

/// Blocks asked for ahead of the one whose turn it is.
pub const WINDOW: u64 = 16;

/// How long the block whose turn it is may stay unanswered before it is
/// asked of a second node as well: everything after it waits for it, and
/// a node that keeps silent would otherwise hold all of them up until its
/// request times out.
pub const HEDGE_AFTER: std::time::Duration = std::time::Duration::from_secs(if cfg!(feature = "test-net") { 1 } else { 3 });

/// What became of a block that arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Got {
    /// It was applied, or it is the block of a verified header and waits
    /// for its turn.
    Taken,
    /// Nobody had asked this peer for it.
    Unasked,
    /// The same, and this peer has now sent too many of these in a row.
    Pushy,
    /// It is not the block its header is about, or not a valid block.
    Invalid,
}

/// The state, the blocks that led to it, and the requests for more.
pub struct Follow {
    blocks: Blocks,
    schedule: Schedule<u64>,
    ahead: BTreeMap<u64, Block>,
    reopened: Reopened,
    file_trouble: bool,
    /// The height of a block that was refused, and why.
    refused: Option<(u64, Rejected)>,
}

/// The heights to have asked for when the state is at `at` and the header
/// chain at `tip`: the next [`WINDOW`], less those that wait for their turn.
fn ask_ahead(at: u64, tip: u64, waiting: impl Fn(u64) -> bool) -> Vec<u64> {
    let first = at.saturating_add(1);
    let end = first.saturating_add(WINDOW).min(tip.saturating_add(1));
    (first..end).filter(|height| !waiting(*height)).collect()
}

/// The requests to send now when the state is at `at` and the header chain
/// at `tip`: the window ahead, and the block whose turn it is once more of
/// a second peer when the first has kept it for [`HEDGE_AFTER`].
fn asks(schedule: &mut Schedule<u64>, now: Instant, at: u64, tip: u64, waiting: impl Fn(u64) -> bool, peers: &[SocketAddr]) -> Vec<(SocketAddr, u64)> {
    // what everything waits on comes first
    let mut asks = Vec::new();
    let next = at.saturating_add(1);
    if next <= tip {
        if let Some(addr) = schedule.hedge(now, next, HEDGE_AFTER, peers) {
            asks.push((addr, next));
        }
    }
    let wanted = ask_ahead(at, tip, waiting);
    asks.extend(schedule.plan(now, &wanted, peers));
    asks
}

/// The header of the verified chain at `height`.
fn verified(chain: &HeaderChain, height: u64) -> Option<BlockHeader> {
    chain.header_at(height).ok().flatten()
}

/// What a block gives the wallet. `before` is the header of the block
/// before it: its output MMR ends where this block's outputs begin.
fn facts(block: &Block, before: &BlockHeader) -> Option<BlockFacts> {
    let first = before.output_mmr_count();
    let mut outputs = Vec::with_capacity(block.outputs().len());
    for (index, output) in block.outputs().iter().enumerate() {
        let proof = output.proof();
        outputs.push(OutputFact {
            commit: output.commitment().0,
            proof: proof.proof.get(..proof.plen)?.to_vec(),
            pos: pmmr::insertion_to_pmmr_index(first.checked_add(u64::try_from(index).ok()?)?),
            coinbase: output.features() == OutputFeatures::Coinbase,
        });
    }
    let inputs: Vec<CommitWrapper> = block.inputs().into();
    let facts = BlockFacts {
        height: block.header.height,
        hash: hash_bytes(&block.header),
        outputs,
        inputs: inputs.iter().map(|input| input.commitment().0).collect(),
        kernels: block.kernels().iter().map(|kernel| kernel.excess.0).collect(),
        v_delta: Vec::new(),
    };
    facts.within_limits().then_some(facts)
}

impl Follow {
    /// Open the file of blocks in `dir` for the state collected at the
    /// archive header, and apply what it holds under the verified headers.
    /// A file for another archive header is started over: its blocks lead
    /// to a state that is not this one.
    pub fn open(dir: &Path, state: State, chain: &HeaderChain) -> Result<Follow, BlocksError> {
        Self::open_with_state(dir, || Ok(state), chain)
    }

    pub(crate) fn open_with_state(
        dir: &Path,
        state: impl FnOnce() -> Result<State, BlocksError>,
        chain: &HeaderChain,
    ) -> Result<Follow, BlocksError> {
        let (blocks, reopened) = Blocks::open_with_state(dir, state, true, |height| verified(chain, height))?;
        Ok(Follow {
            blocks,
            schedule: Schedule::new(),
            ahead: BTreeMap::new(),
            reopened,
            file_trouble: false,
            refused: None,
        })
    }

    /// The header the state is at.
    pub fn header(&self) -> &BlockHeader {
        self.blocks.live().header()
    }

    /// Whether the applied state still belongs to the current header chain.
    pub(crate) fn on_chain(&self, chain: &HeaderChain) -> bool {
        chain.hash_at(self.header().height) == Some(hash_bytes(self.header()))
    }

    /// The state the blocks have led to.
    pub fn live(&self) -> &Live {
        self.blocks.live()
    }

    /// Height of the archive header.
    pub fn base(&self) -> u64 {
        self.blocks.base().height
    }

    /// How many outputs are unspent.
    pub fn unspent(&self) -> usize {
        self.blocks.live().unspent_count()
    }

    /// What the file held when it was opened.
    pub fn reopened(&self) -> Reopened {
        self.reopened
    }

    /// Length of the file.
    pub fn file_len(&self) -> u64 {
        self.blocks.file_len()
    }

    /// Whether a block could not be written to the file.
    pub fn file_trouble(&self) -> bool {
        self.file_trouble
    }

    /// The last block that was refused: its height and why.
    pub fn refused(&self) -> Option<(u64, Rejected)> {
        self.refused
    }

    /// Take back the blocks that are not on the verified chain any more.
    /// Returns how many.
    pub fn rewind(&mut self, chain: &HeaderChain) -> u64 {
        let mut undone = 0u64;
        loop {
            let at = self.blocks.live().header();
            if chain.hash_at(at.height) == Some(hash_bytes(at)) {
                break;
            }
            match self.blocks.back() {
                Ok(true) => undone = undone.saturating_add(1),
                Ok(false) => break,
                Err(_) => {
                    self.file_trouble = true;
                    break;
                }
            }
        }
        if undone > 0 {
            // what waited was for the branch that is gone
            self.ahead.clear();
        }
        undone
    }

    fn blocks_at(&self) -> u64 {
        self.header().height
    }

    /// The requests to send now: `(peer, height, hash of the verified
    /// header)`.
    pub fn plan(&mut self, now: Instant, chain: &HeaderChain, peers: &[SocketAddr]) -> Vec<(SocketAddr, u64, [u8; 32])> {
        let at = self.blocks_at();
        let ahead = &self.ahead;
        asks(&mut self.schedule, now, at, chain.tip().height, |height| ahead.contains_key(&height), peers)
            .into_iter()
            .filter_map(|(addr, height)| Some((addr, height, chain.hash_at(height)?)))
            .collect()
    }

    /// Give up on requests that were not answered in time; the peers that
    /// have left too many unanswered.
    pub fn expire(&mut self, now: Instant) -> Vec<SocketAddr> {
        self.schedule.expire(now)
    }

    /// A peer is gone.
    pub fn forget(&mut self, addr: SocketAddr) {
        self.schedule.forget(addr);
    }

    fn add(&mut self, block: &Block, chain: &HeaderChain) -> Got {
        let height = block.header.height;
        let Some(header) = verified(chain, height) else {
            return Got::Unasked;
        };
        // where the output MMR ended at the last height whose coinbase
        // outputs may be spent in this block - if the verified chain
        // reaches that far down
        let mature_below = height
            .checked_sub(global::coinbase_maturity())
            .and_then(|last| verified(chain, last))
            .map(|last| last.output_mmr_size);
        match self.blocks.add(block, &header, mature_below) {
            Ok(_) => Got::Taken,
            Err(AddError::Rejected(Rejected::NotNext)) => Got::Unasked,
            Err(AddError::Rejected(why)) => {
                self.refused = Some((height, why));
                Got::Invalid
            }
            Err(AddError::Io(_)) => {
                self.file_trouble = true;
                Got::Unasked
            }
        }
    }

    /// A block from `from`.
    pub fn arrived(&mut self, from: SocketAddr, block: Block, chain: &HeaderChain) -> Got {
        let height = block.header.height;
        if !self.schedule.answered(from, height) {
            return if self.schedule.stray(from) { Got::Pushy } else { Got::Unasked };
        }
        let next = self.header().height.saturating_add(1);
        if height == next {
            let got = self.add(&block, chain);
            if got == Got::Taken {
                // the ones that waited for it
                while let Some(waiting) = self.ahead.remove(&self.header().height.saturating_add(1)) {
                    if self.add(&waiting, chain) != Got::Taken {
                        break;
                    }
                }
            }
            got
        } else if height > next {
            // before its turn: it waits only if it comes under a verified
            // header - the header whole, not its hash
            if verified(chain, height).is_some_and(|header| header == block.header) {
                self.ahead.insert(height, block);
                Got::Taken
            } else {
                Got::Invalid
            }
        } else {
            Got::Unasked
        }
    }

    /// Make sure what was written is on disk.
    pub fn sync(&mut self) {
        if self.blocks.sync().is_err() {
            self.file_trouble = true;
        }
    }

    /// What comes after the wallet's position `at`. `at_tip` says whether
    /// the state stands at the tip of the header chain and no node claims
    /// more.
    pub fn step(&mut self, at: Option<Tip>, chain: &HeaderChain, at_tip: bool) -> Result<Step, Unknown> {
        if !self.on_chain(chain) {
            return Err(Unknown);
        }
        let base = self.blocks.base();
        let anchor = Tip {
            height: base.height,
            hash: hash_bytes(base),
        };
        let Some(at) = at else {
            return Ok(Step::Reanchor(anchor));
        };
        let ours = self.header().height;
        if at.height < anchor.height {
            return Ok(if chain.hash_at(at.height) == Some(at.hash) {
                Step::ReanchorExtending(anchor)
            } else {
                Step::Reanchor(anchor)
            });
        }
        if at.height > ours {
            // the wallet is ahead of what has been applied here
            return Err(Unknown);
        }
        if chain.hash_at(at.height) != Some(at.hash) {
            return Ok(match at.height.checked_sub(1) {
                Some(to) if at.height > anchor.height => Step::Rollback { to },
                _ => Step::Reanchor(anchor),
            });
        }
        if at.height == ours {
            // nothing new only at the tip; short of it, more is on the way
            return if at_tip { Ok(Step::Nothing) } else { Err(Unknown) };
        }
        let height = at.height.saturating_add(1);
        let before = verified(chain, at.height).ok_or(Unknown)?;
        let block = self.blocks.read(height).ok().flatten().ok_or(Unknown)?;
        facts(&block, &before).map(|facts| Step::Block(Box::new(facts))).ok_or(Unknown)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// Blocks are asked for a window ahead of the state, never past the
    /// tip of the header chain, and not those that already wait.
    #[test]
    fn blocks_are_asked_for_a_window_ahead() {
        let none = |_| false;
        assert_eq!(ask_ahead(100, 1000, none), (101..101 + WINDOW).collect::<Vec<u64>>());
        assert_eq!(ask_ahead(995, 1000, none), (996..=1000).collect::<Vec<u64>>(), "not past the tip");
        assert_eq!(ask_ahead(1000, 1000, none), Vec::<u64>::new());
        assert_eq!(ask_ahead(1005, 1000, none), Vec::<u64>::new(), "the header chain is shorter for a moment");
        let waiting = |height: u64| height == 102 || height == 103;
        assert_eq!(ask_ahead(100, 1000, waiting), (101..101 + WINDOW).filter(|h| *h != 102 && *h != 103).collect::<Vec<u64>>());
    }

    /// The block whose turn it is goes to a second peer when the first has
    /// kept it for a moment; no other block does, and not before.
    #[test]
    fn the_block_whose_turn_it_is_is_asked_twice() {
        let (a, b): (SocketAddr, SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
        let mut schedule = Schedule::new();
        let t0 = Instant::now();
        let first = asks(&mut schedule, t0, 100, 1000, |_| false, &[a]);
        assert_eq!(first, vec![(a, 101)], "one at a time to one node");
        // b comes; before the moment is up it gets what is next in the
        // window, and 101 stays with a alone
        let soon = t0 + HEDGE_AFTER / 2;
        let then = asks(&mut schedule, soon, 100, 1000, |_| false, &[a, b]);
        assert!(then.contains(&(b, 102)) && !then.iter().any(|(_, height)| *height == 101), "{then:?}");
        // once it is up, b is asked for 101 too - and only for that
        let later = t0 + HEDGE_AFTER + crate::schedule::ASK_GAP;
        let now = asks(&mut schedule, later, 100, 1000, |_| false, &[a, b]);
        assert!(now.contains(&(b, 101)), "{now:?}");
        assert_eq!(now.iter().filter(|(_, height)| *height == 101).count(), 1, "{now:?}");
        // and never a third time
        let much_later = later + HEDGE_AFTER * 10;
        assert!(!asks(&mut schedule, much_later, 100, 1000, |_| false, &[a, b]).iter().any(|(_, height)| *height == 101));
        // at the tip there is nothing whose turn it is
        let mut schedule = Schedule::new();
        assert!(asks(&mut schedule, t0, 1000, 1000, |_| false, &[a, b]).is_empty());
    }
}
