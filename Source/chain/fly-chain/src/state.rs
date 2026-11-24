//! Collecting the state at the archive header from peers.
//!
//! Nodes give their state out at one header at a time, the archive header,
//! in segments. This module asks for the segments, hands each one to the
//! collector - which checks it against the header from the verified header
//! chain - and keeps what was collected in a file. A peer whose segment
//! does not pass that check sent something that is not the state; it is
//! named to the caller, who leaves it.
//!
//! The collector takes segments in order. Segments of the output MMR are
//! asked for a few ahead; one that arrives before its turn is checked
//! against the header at once - that check does not depend on the order -
//! and waits for its turn.
//!
//! Nodes cut the output MMR into segments of 2048 leaves for one another
//! and give larger ones when asked. The output MMR is asked for in the
//! largest of those, sixteen times fewer requests for the same tree,
//! checked against the same root. A node is not bound to give them: when
//! the first that are asked for go unanswered, the small ones are asked
//! for instead, which every node gives.
use crate::schedule::{Piece, Schedule};
use fly_chain_state::archive::{Refused, State, Wanted, LARGE_OUTPUT_HEIGHT, SMALL_OUTPUT_HEIGHT};
use fly_chain_state::store::{AddError, Opened, Store, StoreError};
use grin_chain::txhashset::BitmapChunk;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{BlockHeader, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use grin_util::secp::pedersen::RangeProof;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

/// Segments of the output MMR asked for ahead of the one whose turn it is.
pub const WINDOW: u64 = 24;
/// The same of the large segments: one is sixteen small ones, and those
/// that wait for their turn wait in memory - some forty megabytes if
/// every one of them is as large as a node's message may be. Wide enough
/// that the peers that answer fast are not held up by the one that is
/// slow with the segment whose turn it is.
pub const WINDOW_LARGE: u64 = 16;

/// How many segments of this height are asked for ahead.
fn window(height: u8) -> u64 {
    if height > SMALL_OUTPUT_HEIGHT {
        WINDOW_LARGE
    } else {
        WINDOW
    }
}

/// A segment as a peer sent it.
pub enum Arrived {
    /// Of the bitmap MMR, with what the peer says the output root is.
    Bitmap {
        /// The claimed root of the output MMR.
        output_root: Hash,
        /// The segment.
        segment: Segment<BitmapChunk>,
    },
    /// Of the output MMR.
    Output(Segment<OutputIdentifier>),
    /// Of the rangeproof MMR.
    Rangeproof(Segment<RangeProof>),
    /// Of the kernel MMR.
    Kernel(Segment<TxKernel>),
}

/// What became of a segment that arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Took {
    /// It passed the check and was taken, or waits for its turn.
    Taken,
    /// Nobody had asked this peer for it, or not for this header.
    Unasked,
    /// The same, and this peer has now sent too many of these in a row.
    Pushy,
    /// It does not pass the check against the header: not the state.
    Invalid,
    /// It passes the node's check and this program cannot read it. That is
    /// a fault of this program; nothing is concluded about the peer.
    Fault,
}

/// Which segments of the output MMR to have asked for when the collector
/// waits for segment `next` of `segments`: that one and the ones after it,
/// `window` in all, less those that have arrived and wait for their turn.
/// The window keeps what waits in memory bounded.
fn ask_ahead(next: u64, segments: u64, window: u64, waiting: impl Fn(u64) -> bool) -> Vec<u64> {
    let end = next.saturating_add(window).min(segments);
    (next..end).filter(|idx| !waiting(*idx)).collect()
}

/// The collection of the state at one archive header.
pub struct Fetch {
    store: Option<Store>,
    state: Option<State>,
    header: BlockHeader,
    block: Hash,
    schedule: Schedule<Piece>,
    ahead: BTreeMap<u64, Segment<OutputIdentifier>>,
    opened: Opened,
    progress: (u64, u64),
    file_len: u64,
    last_gain: Instant,
    file_trouble: bool,
    fault: bool,
    /// Set when the state is complete: how many outputs are unspent in it.
    unspent: Option<u64>,
    /// How long the segments that came took here: checking those that
    /// came before their turn, and taking segments in (checked, read,
    /// written to the file).
    work: (Duration, Duration),
}

impl Fetch {
    /// Open the state file in `dir` for the state at `header`, which must
    /// come from the verified header chain; with `over`, start the file
    /// over whatever state it held. The output MMR is asked for in the
    /// largest segments nodes give.
    pub fn open(dir: &Path, header: BlockHeader, over: bool) -> Result<Fetch, StoreError> {
        Fetch::open_in(dir, header, over, LARGE_OUTPUT_HEIGHT)
    }

    /// The same, with the output MMR asked for in segments of the height
    /// `first` - unless the file already has the output MMR begun in
    /// segments of another height, which then stays.
    pub fn open_in(dir: &Path, header: BlockHeader, over: bool, first: u8) -> Result<Fetch, StoreError> {
        let (mut store, opened) = if over {
            (Store::begin(dir, header.clone())?, Opened { kept: 0, cut_bytes: 0 })
        } else {
            Store::open(dir, header.clone())?
        };
        store.set_output_height(first);
        let mut fetch = Fetch {
            progress: store.progress(),
            file_len: store.file_len(),
            store: Some(store),
            state: None,
            block: header.hash(),
            header,
            schedule: Schedule::new(),
            ahead: BTreeMap::new(),
            opened,
            last_gain: Instant::now(),
            file_trouble: false,
            fault: false,
            unspent: None,
            work: (Duration::ZERO, Duration::ZERO),
        };
        fetch.settle();
        Ok(fetch)
    }

    /// Note how far it has come; when nothing more is wanted, the state.
    fn settle(&mut self) {
        let Some(store) = &mut self.store else {
            return;
        };
        self.progress = store.progress();
        self.file_len = store.file_len();
        if store.wanted() == Wanted::Nothing {
            self.state = self.store.take().and_then(Store::finish);
            self.unspent = self.state.as_ref().map(|state| u64::try_from(state.unspent.len()).unwrap_or(u64::MAX));
            self.ahead.clear();
        }
    }

    /// The archive header.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// The collected state, once it is complete.
    pub fn state(&self) -> Option<&State> {
        self.state.as_ref()
    }

    /// Whether everything has been collected.
    pub fn complete(&self) -> bool {
        self.unspent.is_some()
    }

    /// How many outputs are unspent in the collected state.
    pub fn unspent(&self) -> Option<u64> {
        self.unspent
    }

    /// Hand the collected state over, to be carried forward by blocks. It
    /// is handed over once.
    pub fn take_state(&mut self) -> Option<State> {
        self.state.take()
    }

    /// What the file held when it was opened.
    pub fn opened(&self) -> Opened {
        self.opened
    }

    /// Segments in all, and segments taken.
    pub fn progress(&self) -> (u64, u64) {
        self.progress
    }

    /// Length of the file.
    pub fn file_len(&self) -> u64 {
        self.file_len
    }

    /// When a segment was last taken (or the file opened).
    pub fn last_gain(&self) -> Instant {
        self.last_gain
    }

    /// Whether a taken segment could not be written to the file.
    pub fn file_trouble(&self) -> bool {
        self.file_trouble
    }

    /// Whether a segment passed the node's check and could not be read.
    pub fn fault(&self) -> bool {
        self.fault
    }

    /// The pieces that are of use now, most urgent first.
    fn wanted(&self) -> Vec<Piece> {
        let Some(store) = &self.store else {
            return Vec::new();
        };
        match store.wanted() {
            Wanted::Bitmap(id) => vec![Piece::Bitmap(id)],
            Wanted::Output(next) => ask_ahead(next.idx, store.output_segments(), window(next.height), |idx| self.ahead.contains_key(&idx))
                .into_iter()
                .map(|idx| {
                    Piece::Output(SegmentIdentifier {
                        height: next.height,
                        idx,
                    })
                })
                .collect(),
            Wanted::RangeproofTail(id) => vec![Piece::RangeproofTail(id)],
            Wanted::KernelTail(id) => vec![Piece::KernelTail(id)],
            Wanted::Nothing => Vec::new(),
        }
    }

    /// The requests to send now to the given peers.
    pub fn plan(&mut self, now: Instant, peers: &[SocketAddr]) -> Vec<(SocketAddr, Piece)> {
        if self.fault {
            return Vec::new();
        }
        let wanted = self.wanted();
        self.schedule.plan(now, &wanted, peers)
    }

    /// How long the segments that came have taken this program, apart
    /// from waiting for them: checking those that came before their turn,
    /// and taking segments in. Only numbers of time.
    pub fn work(&self) -> (Duration, Duration) {
        self.work
    }

    /// The height of the segments the output MMR is collected in.
    pub fn output_height(&self) -> Option<u8> {
        self.store.as_ref().map(Store::output_height)
    }

    /// Collect the output MMR in the small segments, which every node
    /// gives. Only while none of the large ones has come: segments of two
    /// heights do not go together. The requests for the large ones are
    /// taken back, and no peer is held to have left them unanswered - a
    /// node is not bound to give them.
    fn small_segments(&mut self) -> bool {
        let Some(store) = &mut self.store else {
            return false;
        };
        if store.output_height() == SMALL_OUTPUT_HEIGHT || !self.ahead.is_empty() || !store.set_output_height(SMALL_OUTPUT_HEIGHT) {
            return false;
        }
        self.schedule.withdraw(|piece| matches!(piece, Piece::Output(_)));
        self.settle();
        true
    }

    /// Give up on requests that were not answered in time; the peers that
    /// have left too many unanswered. When a large segment of the output
    /// MMR was not answered in time and none has come from anybody yet,
    /// the small ones are asked for from here on.
    pub fn expire(&mut self, now: Instant) -> Vec<SocketAddr> {
        if self.schedule.overdue(now, |piece| matches!(piece, Piece::Output(id) if id.height > SMALL_OUTPUT_HEIGHT)) {
            self.small_segments();
        }
        self.schedule.expire(now)
    }

    /// A peer is gone.
    pub fn forget(&mut self, addr: SocketAddr) {
        self.schedule.forget(addr);
    }

    fn took(&mut self, result: Result<(), AddError>) -> Took {
        match result {
            Ok(()) => {
                self.last_gain = Instant::now();
                Took::Taken
            }
            Err(AddError::Io(_)) => {
                // the collector has it; only the file does not
                self.file_trouble = true;
                self.last_gain = Instant::now();
                Took::Taken
            }
            Err(AddError::Refused(Refused::Invalid)) => Took::Invalid,
            Err(AddError::Refused(Refused::NotWanted)) => Took::Unasked,
            Err(AddError::Refused(Refused::Unreadable)) => {
                self.fault = true;
                Took::Fault
            }
        }
    }

    /// A segment from `from` for the state at `block`.
    pub fn arrived(&mut self, from: SocketAddr, block: Hash, piece: Arrived) -> Took {
        match self.arrived_inner(from, block, piece) {
            Took::Unasked if self.schedule.stray(from) => Took::Pushy,
            took => took,
        }
    }

    fn arrived_inner(&mut self, from: SocketAddr, block: Hash, piece: Arrived) -> Took {
        if block != self.block || self.store.is_none() {
            return Took::Unasked;
        }
        let key = match &piece {
            Arrived::Bitmap { segment, .. } => Piece::Bitmap(segment.id()),
            Arrived::Output(segment) => Piece::Output(segment.id()),
            Arrived::Rangeproof(segment) => Piece::RangeproofTail(segment.id()),
            Arrived::Kernel(segment) => Piece::KernelTail(segment.id()),
        };
        if !self.schedule.answered(from, key) {
            return Took::Unasked;
        }
        let Some(store) = &mut self.store else {
            return Took::Unasked;
        };
        let began = Instant::now();
        let mut early = false;
        let took = match piece {
            Arrived::Bitmap { output_root, segment } => {
                let result = store.add_bitmap(segment, output_root);
                self.took(result)
            }
            Arrived::Rangeproof(segment) => {
                let result = store.add_rangeproof_tail(segment);
                self.took(result)
            }
            Arrived::Kernel(segment) => {
                let result = store.add_kernel_tail(segment);
                self.took(result)
            }
            Arrived::Output(segment) => {
                let idx = segment.id().idx;
                match store.wanted() {
                    Wanted::Output(next) if next.idx == idx => {
                        let result = store.add_output(segment);
                        let took = self.took(result);
                        if took == Took::Taken {
                            self.take_waiting();
                        }
                        took
                    }
                    Wanted::Output(next) if idx > next.idx => {
                        // before its turn: the check against the header
                        // does not wait
                        early = true;
                        if store.verifies_output(&segment) {
                            self.ahead.insert(idx, segment);
                            Took::Taken
                        } else {
                            Took::Invalid
                        }
                    }
                    _ => Took::Unasked,
                }
            }
        };
        let spent = began.elapsed();
        if early {
            self.work.0 = self.work.0.saturating_add(spent);
        } else {
            self.work.1 = self.work.1.saturating_add(spent);
        }
        self.settle();
        took
    }

    /// Hand over the segments that were waiting for the one just taken.
    fn take_waiting(&mut self) {
        loop {
            let Some(store) = &mut self.store else {
                return;
            };
            let Wanted::Output(next) = store.wanted() else {
                return;
            };
            let Some(segment) = self.ahead.remove(&next.idx) else {
                return;
            };
            let result = store.add_output(segment);
            if self.took(result) != Took::Taken {
                // it had passed the check: asked for again, nobody blamed
                return;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// Outputs are asked for a window ahead of the segment whose turn it
    /// is, never further: what arrives early waits in memory.
    #[test]
    fn outputs_are_asked_for_a_window_ahead() {
        let none = |_| false;
        assert_eq!(ask_ahead(0, 1000, WINDOW, none), (0..WINDOW).collect::<Vec<u64>>());
        assert_eq!(ask_ahead(500, 1000, WINDOW, none), (500..500 + WINDOW).collect::<Vec<u64>>());
        assert_eq!(ask_ahead(990, 1000, WINDOW, none), (990..1000).collect::<Vec<u64>>(), "not past the last");
        assert_eq!(ask_ahead(1000, 1000, WINDOW, none), Vec::<u64>::new());
        // the large segments: fewer at a time
        assert_eq!(window(11), WINDOW);
        assert_eq!(window(15), WINDOW_LARGE);
        assert_eq!(ask_ahead(280, 287, window(15), none), (280..287).collect::<Vec<u64>>());
        assert_eq!(ask_ahead(3, 287, window(15), none), (3..3 + WINDOW_LARGE).collect::<Vec<u64>>());
        // what has arrived is not asked for again, and does not widen the window
        let waiting = |idx: u64| idx % 2 == 1;
        let asked = ask_ahead(10, 1000, WINDOW, waiting);
        assert_eq!(asked, (10..10 + WINDOW).filter(|idx| idx % 2 == 0).collect::<Vec<u64>>());
    }
}
