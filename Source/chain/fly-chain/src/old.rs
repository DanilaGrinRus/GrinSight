//! The outputs that are older than the blocks.
//!
//! The blocks begin at the archive header where the state was collected. A
//! wallet restored from its seed has outputs from before that, and it can
//! find them only by trying its keys on the range proofs of everything
//! unspent. The state that was collected does not hold range proofs; they
//! are fetched here, when a wallet asks, and not kept.
//!
//! The range proofs are asked for the way the state was: in segments of the
//! rangeproof MMR at the archive header the nodes serve now, each put
//! through the node's check against the root in the verified header, with
//! the bitmap of unspent outputs at that header - the collected state,
//! carried there by the blocks. A segment is a piece for the wallet: of its
//! outputs, those still unspent after the last block applied here, each
//! with the proof the header commits to.
//!
//! A wallet that followed the chain and then missed blocks knew every
//! output of its own up to the block it stood at. In a stretch of the
//! output MMR that was full by that block it has nothing to find; it
//! only needs to learn which of its outputs are still unspent, and that
//! is in the state held here. Such a piece is given at once, without
//! range proofs, and nobody is asked for anything: all a node can see is
//! that the range proofs of the newest stretches are read.
use crate::schedule::Schedule;
use fly_chain_headers::hash_bytes;
use fly_chain_state::advance::Live;
use fly_chain_state::archive::{rangeproof_segments, rangeproofs_of, Refused};
use fly_chain_state::Bitmap;
use fly_paycore_chain_port::{OldOutputs, OutputFact, Tip, Unknown};
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{pmmr, BlockHeader, Segment, SegmentIdentifier};
use grin_util::secp::pedersen::RangeProof;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Pieces fetched ahead of the one the wallet asked for last.
pub const WINDOW: u64 = 32;
/// How long after the wallet's last question pieces are still fetched and
/// held. A wallet that reads asks every few seconds.
pub const ASKED_WITHIN: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 5 } else { 60 });
/// Height of a segment of the rangeproof MMR, as the nodes cut it.
const SEGMENT_HEIGHT: u8 = 11;

/// How long the piece the wallet waits for may stay unanswered before it
/// is asked of a second node as well. A piece holds two thousand range
/// proofs, over a megabyte: a node that is merely slow is given time.
pub const HEDGE_AFTER: Duration = Duration::from_secs(if cfg!(feature = "test-net") { 1 } else { 10 });

/// The requests to send now: the piece the wallet waits for, `first`, once
/// more of a second peer when the first peer has kept it for
/// [`HEDGE_AFTER`]; then the window `wanted`.
fn asks(schedule: &mut Schedule<u64>, now: Instant, first: Option<u64>, wanted: &[u64], peers: &[SocketAddr]) -> Vec<(SocketAddr, u64)> {
    let mut asks = Vec::new();
    if let Some(addr) = first.and_then(|first| schedule.hedge(now, first, HEDGE_AFTER, peers)) {
        asks.extend(first.map(|first| (addr, first)));
    }
    asks.extend(schedule.plan(now, wanted, peers));
    asks
}

/// What became of a segment that arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Came {
    /// It passed the check and is held for the wallet.
    Taken,
    /// Nobody had asked this peer for it, or not at this header.
    Unasked,
    /// The same, and this peer has now sent too many of these in a row.
    Pushy,
    /// It does not pass the check against the header.
    Invalid,
}

/// One output of a piece: position, commitment, coinbase, range proof.
struct Kept {
    pos: u64,
    commit: [u8; 33],
    coinbase: bool,
    proof: Vec<u8>,
}

/// A piece that passed the check: what was unspent in its stretch after the
/// last block applied when it came, complete up to the height `before`.
struct Piece {
    before: u64,
    outputs: Vec<Kept>,
}

/// The archive header pieces are asked at.
struct At {
    header: BlockHeader,
    hash: Hash,
    bitmap: Bitmap,
    pieces: u64,
}

/// Everything unspent after one block, in the order of the output MMR.
struct Unspent {
    /// Hash of the header of that block.
    at: Hash,
    /// Position, commitment, coinbase.
    all: Vec<(u64, [u8; 33], bool)>,
}

/// The pieces held for the wallet and the requests for more.
#[derive(Default)]
pub struct Old {
    at: Option<At>,
    schedule: Schedule<u64>,
    held: BTreeMap<u64, Piece>,
    /// The piece the wallet asked for last, and when.
    asked: Option<(u64, Instant)>,
    /// How many pieces, from the first, the wallet that asked last needs
    /// no range proofs for: they are not fetched.
    bare: u64,
    /// What bare pieces are cut from, kept while a wallet reads them.
    unspent: Option<Unspent>,
    /// The peers that have answered at this archive header.
    answered: Vec<SocketAddr>,
}

/// How many leaves the output MMR had after the block `since`, which a
/// wallet names as the one it knew its outputs up to. Only for a block of
/// the chain followed here - `on_chain` is the hash that chain has at
/// that height - that is not above the last block applied, `applied`;
/// `header` reads the chain's header at that height. A block this
/// program does not have, or one of another branch, gets no answer:
/// nothing is assumed about what a wallet that stood there has seen.
pub fn leaves_after(since: Tip, on_chain: Option<[u8; 32]>, applied: u64, header: impl FnOnce() -> Option<BlockHeader>) -> Option<u64> {
    if on_chain? != since.hash || applied < since.height {
        return None;
    }
    let header = header()?;
    if header.height != since.height || hash_bytes(&header) != since.hash {
        return None;
    }
    Some(pmmr::n_leaves(header.output_mmr_size))
}

/// How many pieces, from the first, were full when the output MMR had
/// `leaves` leaves: a wallet that knew its outputs up to then has nothing
/// to find in them.
pub fn full_pieces(leaves: u64) -> u64 {
    leaves >> SEGMENT_HEIGHT
}

/// The pieces to have asked for when the wallet asked for `piece` last, of
/// `pieces`: that one and the next [`WINDOW`], less those that are held.
fn ask_ahead(piece: u64, pieces: u64, held: impl Fn(u64) -> bool) -> Vec<u64> {
    let end = piece.saturating_add(WINDOW).saturating_add(1).min(pieces);
    (piece..end).filter(|idx| !held(*idx)).collect()
}

impl Old {
    /// Nothing held, nothing asked.
    pub fn new() -> Old {
        Old::default()
    }

    /// How many pieces are held.
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Whether a wallet is reading: it asked not long ago.
    pub fn wanted(&self, now: Instant) -> bool {
        self.asked.is_some_and(|(_, at)| now.saturating_duration_since(at) <= ASKED_WITHIN)
    }

    /// The archive header the nodes serve now is `header`, from the
    /// verified header chain, and `live` is the state the blocks have led
    /// to. Requests that are out were made at another header: no node will
    /// answer them, and nobody is blamed for that. What is held stays: a
    /// proof is the proof of its output at any later header as well.
    pub fn serve_at(&mut self, header: &BlockHeader, live: &Live) {
        let hash = header.hash();
        if self.at.as_ref().is_some_and(|at| at.hash == hash) {
            return;
        }
        self.schedule = Schedule::new();
        self.answered.clear();
        self.at = live.bitmap_at(header.height).map(|bitmap| At {
            pieces: rangeproof_segments(header),
            header: header.clone(),
            hash,
            bitmap,
        });
    }

    /// Blocks were taken back. A piece says what was unspent after the
    /// last block applied when it came; an output spent on the branch that
    /// is gone is not in it and may be alive on the other. Everything is
    /// fetched again.
    pub fn taken_back(&mut self) {
        self.held.clear();
        self.at = None;
        self.unspent = None;
        self.schedule = Schedule::new();
    }

    /// The requests to send now: `(peer, hash of the archive header,
    /// segment)`. Nothing is asked for unless a wallet is reading.
    pub fn plan(&mut self, now: Instant, peers: &[SocketAddr]) -> Vec<(SocketAddr, Hash, SegmentIdentifier)> {
        if !self.wanted(now) {
            // nobody reads: what is held is let go of
            self.held.clear();
            self.asked = None;
            self.unspent = None;
            return Vec::new();
        }
        let (Some(at), Some((piece, _))) = (&self.at, self.asked) else {
            return Vec::new();
        };
        // what the wallet gets without range proofs is not fetched
        let wanted = ask_ahead(piece.max(self.bare), at.pieces, |idx| self.held.contains_key(&idx));
        let hash = at.hash;
        // The first request at an archive header makes a node build its
        // state there, and that can take longer than an answer is waited
        // for. Until a node has answered at this header it is asked one
        // thing at a time: one unanswered request is not held against it,
        // several at once would be.
        let ready: Vec<SocketAddr> = peers
            .iter()
            .filter(|addr| self.answered.contains(addr) || self.schedule.out_to(**addr) == 0)
            .copied()
            .collect();
        // the piece the wallet waits for, if it is not here yet
        let first = Some(piece.max(self.bare)).filter(|idx| *idx < at.pieces && !self.held.contains_key(idx));
        asks(&mut self.schedule, now, first, &wanted, &ready)
            .into_iter()
            .map(|(addr, idx)| (addr, hash, SegmentIdentifier { height: SEGMENT_HEIGHT, idx }))
            .collect()
    }

    /// Give up on requests that have waited too long. Returns the peers
    /// that have left too many unanswered.
    pub fn expire(&mut self, now: Instant) -> Vec<SocketAddr> {
        self.schedule.expire(now)
    }

    /// A peer is gone.
    pub fn forget(&mut self, addr: SocketAddr) {
        self.schedule.forget(addr);
        self.answered.retain(|known| *known != addr);
    }

    /// A segment of the rangeproof MMR from `from`, for the header `block`.
    pub fn arrived(&mut self, from: SocketAddr, block: Hash, segment: Segment<RangeProof>, live: &Live) -> Came {
        match self.arrived_inner(from, block, segment, live) {
            Came::Unasked if self.schedule.stray(from) => Came::Pushy,
            came => came,
        }
    }

    fn arrived_inner(&mut self, from: SocketAddr, block: Hash, segment: Segment<RangeProof>, live: &Live) -> Came {
        let Some(at) = self.at.as_ref().filter(|at| at.hash == block) else {
            return Came::Unasked;
        };
        let idx = segment.id().idx;
        if segment.id().height != SEGMENT_HEIGHT || !self.schedule.answered(from, idx) {
            return Came::Unasked;
        }
        let (first, last) = segment.segment_pos_range(at.header.output_mmr_size);
        let proofs = match rangeproofs_of(segment, &at.header, &at.bitmap) {
            Ok(proofs) => proofs,
            Err(Refused::NotWanted) => return Came::Unasked,
            Err(Refused::Invalid | Refused::Unreadable) => return Came::Invalid,
        };
        // Each proof with the output it belongs to. An output that has
        // been spent since the archive header is not among the unspent
        // any more, and its proof is dropped.
        let unspent = live.unspent_between(first, last);
        let mut proofs = proofs.into_iter().peekable();
        let mut outputs = Vec::new();
        for (pos, commit, coinbase) in unspent {
            while proofs.next_if(|(proof_pos, _)| *proof_pos < pos).is_some() {}
            if let Some((_, proof)) = proofs.next_if(|(proof_pos, _)| *proof_pos == pos) {
                outputs.push(Kept {
                    pos,
                    commit,
                    coinbase,
                    proof: proof.proof.get(..proof.plen).map(<[u8]>::to_vec).unwrap_or_default(),
                });
            }
            // an unspent output without a proof here is younger than the
            // archive header: the wallet has it from its block
        }
        self.held.insert(
            idx,
            Piece {
                before: at.header.height,
                outputs,
            },
        );
        if !self.answered.contains(&from) {
            self.answered.push(from);
        }
        Came::Taken
    }

    /// The wallet asks for `piece`. It is given if it is held: of its
    /// outputs, those unspent in `live` now. Otherwise the answer is "I
    /// cannot say", and the piece is fetched for the next time.
    ///
    /// `known_leaves` is how many leaves the output MMR had after the
    /// block the wallet says it knew its outputs up to - given only when
    /// that block is of the chain followed here. A piece that was full by
    /// then is answered from `live`, without range proofs.
    pub fn ask(&mut self, piece: u64, known_leaves: Option<u64>, now: Instant, live: &Live) -> Result<OldOutputs, Unknown> {
        self.asked = Some((piece, now));
        // the wallet does not go back, except after blocks were taken
        // back, and then nothing is held
        self.held.retain(|idx, _| *idx >= piece);
        let pieces = self.at.as_ref().map(|at| at.pieces).ok_or(Unknown)?;
        self.bare = known_leaves.map_or(0, full_pieces).min(pieces);
        if piece < self.bare {
            return self.bare_piece(piece, live);
        }
        let held = self.held.get(&piece).ok_or(Unknown)?;
        let outputs = held
            .outputs
            .iter()
            .filter(|kept| live.unspent(&kept.commit).is_some_and(|unspent| unspent.pos == kept.pos))
            .map(|kept| OutputFact {
                commit: kept.commit,
                proof: kept.proof.clone(),
                pos: kept.pos,
                coinbase: kept.coinbase,
            })
            .collect();
        let old = OldOutputs {
            outputs,
            bare: false,
            at: Tip {
                height: live.header().height,
                hash: hash_bytes(live.header()),
            },
            before: held.before,
            next: piece.checked_add(1).filter(|next| *next < pieces),
            pieces,
        };
        // a piece that is not an answer in the terms of the port is not handed over
        old.answers(piece).then_some(old).ok_or(Unknown)
    }

    /// Piece `piece` without range proofs: everything in its stretch that
    /// is unspent in `live` now. It is complete up to the last block
    /// applied; it says "up to the archive header", as the pieces with
    /// range proofs do, so that the wallet reads all pieces alike.
    fn bare_piece(&mut self, piece: u64, live: &Live) -> Result<OldOutputs, Unknown> {
        let at = self.at.as_ref().ok_or(Unknown)?;
        let id = SegmentIdentifier {
            height: SEGMENT_HEIGHT,
            idx: piece,
        };
        let (first, last) = id.segment_pos_range(at.header.output_mmr_size);
        let tip = live.header().hash();
        let unspent = match self.unspent.take().filter(|unspent| unspent.at == tip) {
            Some(unspent) => unspent,
            // the order of the output MMR, once for every block applied
            None => Unspent {
                at: tip,
                all: live.unspent_between(0, u64::MAX),
            },
        };
        let from = unspent.all.partition_point(|(pos, _, _)| *pos < first);
        let outputs = unspent
            .all
            .get(from..)
            .unwrap_or_default()
            .iter()
            .take_while(|(pos, _, _)| *pos <= last)
            .map(|(pos, commit, coinbase)| OutputFact {
                commit: *commit,
                proof: Vec::new(),
                pos: *pos,
                coinbase: *coinbase,
            })
            .collect();
        self.unspent = Some(unspent);
        let old = OldOutputs {
            outputs,
            bare: true,
            at: Tip {
                height: live.header().height,
                hash: hash_bytes(live.header()),
            },
            before: at.header.height,
            next: piece.checked_add(1).filter(|next| *next < at.pieces),
            pieces: at.pieces,
        };
        old.answers_since(piece).then_some(old).ok_or(Unknown)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    /// Pieces are asked for from the one the wallet wants, a window ahead,
    /// never past the last, and not those already held.
    #[test]
    fn pieces_are_asked_for_a_window_ahead() {
        let none = |_| false;
        assert_eq!(ask_ahead(0, 1000, none), (0..=WINDOW).collect::<Vec<u64>>());
        assert_eq!(ask_ahead(500, 1000, none), (500..=500 + WINDOW).collect::<Vec<u64>>());
        assert_eq!(ask_ahead(995, 1000, none), (995..1000).collect::<Vec<u64>>(), "not past the last");
        assert_eq!(ask_ahead(1000, 1000, none), Vec::<u64>::new());
        assert_eq!(ask_ahead(u64::MAX, u64::MAX, none), Vec::<u64>::new());
        let held = |idx: u64| idx % 2 == 1;
        assert_eq!(ask_ahead(10, 1000, held), (10..=10 + WINDOW).filter(|idx| idx % 2 == 0).collect::<Vec<u64>>());
    }

    /// The piece the wallet waits for goes to a second node once the first
    /// has kept it for a while; nothing else does, and not before.
    #[test]
    fn the_piece_waited_for_is_asked_twice() {
        let (a, b): (SocketAddr, SocketAddr) = ("127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap());
        let mut schedule = Schedule::new();
        let t0 = Instant::now();
        assert_eq!(asks(&mut schedule, t0, Some(5), &[5, 6], &[a]), vec![(a, 5)]);
        let soon = t0 + HEDGE_AFTER / 2;
        let then = asks(&mut schedule, soon, Some(5), &[5, 6], &[a, b]);
        assert!(!then.iter().any(|(_, idx)| *idx == 5), "{then:?}");
        // once it is up, b is asked for 5 before anything else of the
        // window goes to it
        let later = t0 + HEDGE_AFTER + crate::schedule::ASK_GAP;
        let now = asks(&mut schedule, later, Some(5), &[5, 6, 7], &[b, a]);
        assert!(now.contains(&(b, 5)), "{now:?}");
        assert!(!asks(&mut schedule, later + HEDGE_AFTER * 10, Some(5), &[5, 6], &[a, b]).iter().any(|(_, idx)| *idx == 5));
        // nothing waited for: nothing asked twice
        let mut schedule = Schedule::new();
        assert_eq!(asks(&mut schedule, t0, None, &[5], &[a]), vec![(a, 5)]);
        assert!(!asks(&mut schedule, later, None, &[5], &[a, b]).iter().any(|(_, idx)| *idx == 5));
    }

    /// A piece needs no range proofs for a wallet only if its whole
    /// stretch was there by the block the wallet knew its outputs up to.
    #[test]
    fn only_stretches_that_were_full_come_bare() {
        assert_eq!(full_pieces(0), 0);
        assert_eq!(full_pieces(2047), 0);
        assert_eq!(full_pieces(2048), 1);
        assert_eq!(full_pieces(2049), 1, "the stretch that was begun is searched");
        assert_eq!(full_pieces(4592 * 2048 - 1), 4591);
        assert_eq!(full_pieces(u64::MAX), u64::MAX >> 11);
    }
}
