//! The state at a node's archive point, collected from segments.
//!
//! A node serves its state at one header at a time - the archive header -
//! in segments of four MMRs. Everything taken from a segment is checked
//! against a root in that header, with the node's own segment code; the
//! header itself comes from the verified header chain, never from the node
//! that sends the segments.
//!
//! What is collected is what verifying later blocks needs:
//!
//! * the bitmap of unspent outputs, complete;
//! * the identifiers of the unspent outputs with their positions, complete;
//! * the peaks of the output MMR, from the same segments;
//! * the peaks of the rangeproof MMR and of the kernel MMR, each from the
//!   one last segment of that MMR and its proof.
//!
//! The range proofs themselves and the history of kernels are not needed to
//! verify blocks and are not collected here.
use crate::mmr::{Builder, MmrError};
use croaring::Bitmap;
use grin_chain::pibd_params::{BITMAP_SEGMENT_HEIGHT, KERNEL_SEGMENT_HEIGHT, OUTPUT_SEGMENT_HEIGHT, RANGEPROOF_SEGMENT_HEIGHT};
use grin_chain::txhashset::{BitmapAccumulator, BitmapChunk};
use grin_core::core::hash::Hash;
use grin_core::core::pmmr;
use grin_core::core::{BlockHeader, OutputIdentifier, Segment, SegmentIdentifier, SegmentProof, TxKernel};
use grin_core::ser::{self, PMMRIndexHashable, ProtocolVersion};
use grin_util::secp::pedersen::RangeProof;
use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Bits in one chunk of the bitmap accumulator.
const CHUNK_BITS: u64 = 1024;

/// Why a segment was not taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not the segment that is wanted now. Nothing is wrong with the sender.
    NotWanted,
    /// The segment does not verify against the header. Whoever sent it sent
    /// data that is not the state at that header.
    Invalid,
    /// The segment verifies, but this code could not read the peaks out of
    /// it. Nothing is concluded about the sender.
    Unreadable,
}

/// What is asked for next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wanted {
    /// A segment of the bitmap MMR.
    Bitmap(SegmentIdentifier),
    /// A segment of the output MMR.
    Output(SegmentIdentifier),
    /// The last segment of the rangeproof MMR.
    RangeproofTail(SegmentIdentifier),
    /// The last segment of the kernel MMR.
    KernelTail(SegmentIdentifier),
    /// Everything has been collected.
    Nothing,
}

/// The collected state at the archive header.
pub struct State {
    /// The archive header.
    pub header: BlockHeader,
    /// The accumulator of the bitmap of unspent outputs.
    pub bitmap: BitmapAccumulator,
    /// The unspent outputs: position in the output MMR and identifier, in
    /// the order of their positions.
    pub unspent: Vec<(u64, OutputIdentifier)>,
    /// The peaks of the output MMR.
    pub outputs: Builder,
    /// The peaks of the rangeproof MMR.
    pub rangeproofs: Builder,
    /// The peaks of the kernel MMR.
    pub kernels: Builder,
}

/// The largest segments of the output MMR this program collects the state
/// in: 32768 leaves. Nodes cut the output MMR into segments of 2048 leaves
/// (height 11) for one another, but give larger ones when asked, up to
/// this height; a larger segment is checked against the same root in the
/// same way, and the whole tree takes sixteen times fewer requests.
pub const LARGE_OUTPUT_HEIGHT: u8 = 15;
/// The segments of the output MMR every node gives: 2048 leaves.
pub const SMALL_OUTPUT_HEIGHT: u8 = OUTPUT_SEGMENT_HEIGHT;

/// Collects the state at one archive header, segment by segment, in order.
pub struct Collector {
    header: BlockHeader,
    bitmap_chunks: u64,
    bitmap_mmr_size: u64,
    bitmap_segments: u64,
    /// The height of the segments the output MMR is collected in.
    output_height: u8,
    output_segments: u64,
    accumulator: BitmapAccumulator,
    chunks_taken: u64,
    next_bitmap: u64,
    claimed_output_root: Option<Hash>,
    bitmap: Option<Bitmap>,
    outputs: Builder,
    next_output: u64,
    unspent: Vec<(u64, OutputIdentifier)>,
    rangeproofs: Option<Builder>,
    kernels: Option<Builder>,
}

fn segments_for(mmr_size: u64, height: u8) -> u64 {
    u64::try_from(SegmentIdentifier::count_segments_required(mmr_size, height)).unwrap_or(u64::MAX)
}

/// Index of the leaf at position `pos` among the leaves.
fn leaf_index(pos: u64) -> u64 {
    pmmr::n_leaves(pos.saturating_add(1)).saturating_sub(1)
}

/// Run the node's segment check. That code was written for a node that
/// trusts its own data more than this process may: on a segment that makes
/// no sense it can panic. A panic is a segment that does not verify.
fn checked(check: impl FnOnce() -> bool) -> bool {
    catch_unwind(AssertUnwindSafe(check)).unwrap_or(false)
}

/// The hashes of a segment's proof. The proof keeps them to itself; its
/// serialized form is a count and the hashes.
fn proof_hashes<T>(segment: &Segment<T>) -> Option<Vec<Hash>> {
    let bytes = ser::ser_vec(segment.proof(), ProtocolVersion::local()).ok()?;
    let (count, rest) = bytes.split_first_chunk::<8>()?;
    let count = usize::try_from(u64::from_be_bytes(*count)).ok()?;
    if rest.len() != count.checked_mul(32)? {
        return None;
    }
    Some(rest.chunks_exact(32).map(Hash::from_vec).collect())
}

/// Whether the node's check needs the data of the leaf at `pos`: it does
/// if the leaf or its sibling is unspent, and for the very last node of the
/// range. Without a bitmap every leaf is needed.
fn leaf_needed(bitmap: Option<&Bitmap>, pos: u64, mmr_size: u64) -> bool {
    let Some(bitmap) = bitmap else {
        return true;
    };
    let index = leaf_index(pos);
    let sibling = if pmmr::is_left_sibling(pos) { index.checked_add(1) } else { index.checked_sub(1) };
    let set = |i: Option<u64>| i.and_then(|i| u32::try_from(i).ok()).is_some_and(|i| bitmap.contains(i));
    set(Some(index)) || set(sibling) || pos.checked_add(1) == Some(mmr_size)
}

/// Whether the subtree under the node at `top` holds no leaf the check
/// needs: no unspent output anywhere in it.
fn subtree_spent(bitmap: Option<&Bitmap>, top: u64, mmr_size: u64) -> bool {
    let Some(bitmap) = bitmap else {
        return false;
    };
    let height = pmmr::bintree_postorder_height(top);
    if top >= mmr_size || height == 0 || height >= 40 {
        return false;
    }
    let first = leaf_index(pmmr::bintree_leftmost(top));
    let end = first.saturating_add(1u64 << height);
    match (u32::try_from(first), u32::try_from(end)) {
        (Ok(first), Ok(end)) => bitmap.range_cardinality(first..end) == 0,
        _ => false,
    }
}

/// The largest subtree that begins at the leaf `at` and holds no unspent
/// output, if there is one.
fn largest_spent_from(bitmap: Option<&Bitmap>, at: u64, mmr_size: u64) -> Option<u64> {
    let mut top = at;
    let mut found = None;
    while pmmr::is_left_sibling(top) {
        let (parent, _) = pmmr::family(top);
        if !subtree_spent(bitmap, parent, mmr_size) {
            break;
        }
        top = parent;
        found = Some(parent);
    }
    found
}

/// Where a segment lies: the bitmap of its MMR (none for an MMR that is
/// never pruned), the segment's last position and the size of the MMR.
#[derive(Clone, Copy)]
struct Within<'a> {
    bitmap: Option<&'a Bitmap>,
    segment_last: u64,
    mmr_size: u64,
}

/// For a full segment that lies inside a subtree without unspent outputs
/// which an earlier segment has already brought: the hash the node's check
/// reads from this one - the lowest hash sent on the way from the segment's
/// root up, through subtrees that hold no unspent output.
fn covering_hash(hash_pos: &[u64], within: Within<'_>) -> Option<usize> {
    let Within { bitmap, segment_last, mmr_size } = within;
    let above = pmmr::family_branch(segment_last, mmr_size).into_iter().map(|(parent, _)| parent);
    for pos in std::iter::once(segment_last).chain(above) {
        if !subtree_spent(bitmap, pos, mmr_size) {
            return None;
        }
        if let Ok(index) = hash_pos.binary_search(&pos) {
            return Some(index);
        }
    }
    None
}

/// Which pieces of a segment were read: indexes into its hashes and into
/// its leaves, ascending.
struct Taken {
    hashes: Vec<usize>,
    leaves: Vec<usize>,
}

/// Keep the items at the given ascending indexes.
fn pick<X>(all: Vec<X>, which: &[usize]) -> Vec<X> {
    let mut which = which.iter().peekable();
    all.into_iter()
        .enumerate()
        .filter_map(|(i, item)| which.next_if(|w| **w == i).map(|_| item))
        .collect()
}

/// Feed a segment's hashes and leaves to a builder, taking exactly the
/// pieces the node's check has bound to the root - and no others.
///
/// The check reads the data of a leaf if the leaf or its sibling is
/// unspent. For a stretch without any unspent output it reads one hash:
/// that of the largest subtree without unspent outputs that begins there -
/// or, when that subtree is the whole segment or reaches beyond it, the
/// lowest hash sent on the way from the segment's root up to it. A node
/// that has not pruned its files sends more - every leaf and every hash -
/// and whatever is sent beyond what the check reads is not covered by the
/// check. Such pieces are not read here either: a peer could put anything
/// there.
fn feed<T: PMMRIndexHashable>(
    builder: &mut Builder,
    hash_pos: &[u64],
    hashes: &[Hash],
    leaf_pos: &[u64],
    leaves: &[T],
    within: Within<'_>,
) -> Result<Taken, MmrError> {
    let Within { bitmap, segment_last, mmr_size } = within;
    let ascending = |positions: &[u64]| positions.is_sorted_by(|a, b| a < b);
    if hash_pos.len() != hashes.len() || leaf_pos.len() != leaves.len() || !ascending(hash_pos) || !ascending(leaf_pos) {
        return Err(MmrError::Order);
    }
    let mut by_pos: BTreeMap<u64, (usize, &T)> = BTreeMap::new();
    for (index, (pos, leaf)) in leaf_pos.iter().zip(leaves).enumerate() {
        // an entry at a place where no leaf can be is one more piece the
        // check does not read
        if pmmr::bintree_postorder_height(*pos) == 0 {
            by_pos.insert(*pos, (index, leaf));
        }
    }
    // the hashes by the first position of their subtree
    let mut by_start: BTreeMap<u64, Vec<(u64, usize, Hash)>> = BTreeMap::new();
    for (index, (pos, hash)) in hash_pos.iter().zip(hashes).enumerate() {
        if pmmr::bintree_postorder_height(*pos) != 0 {
            by_start.entry(pmmr::bintree_leftmost(*pos)).or_default().push((*pos, index, *hash));
        }
    }
    let mut taken = Taken {
        hashes: Vec::new(),
        leaves: Vec::new(),
    };
    if builder.size() > segment_last {
        // The segment lies inside a subtree without unspent outputs that
        // came with an earlier segment: a node that has pruned sends the
        // same hash, of the subtree around them, for every segment in it.
        // There is nothing to add - but the check read that hash from this
        // segment too, and whoever keeps the segment must keep it.
        taken.hashes.push(covering_hash(hash_pos, within).ok_or(MmrError::Order)?);
        return Ok(taken);
    }
    loop {
        let at = builder.size();
        if at > segment_last || at >= mmr_size {
            return Ok(taken);
        }
        if leaf_needed(bitmap, at, mmr_size) {
            let (index, leaf) = by_pos.get(&at).ok_or(MmrError::Order)?;
            builder.push_leaf(*leaf)?;
            taken.leaves.push(*index);
            continue;
        }
        let largest = largest_spent_from(bitmap, at, mmr_size).ok_or(MmrError::Order)?;
        let lowest = largest.min(segment_last);
        let (pos, index, hash) = by_start
            .get(&at)
            .and_then(|sent| sent.iter().filter(|(pos, _, _)| *pos >= lowest && *pos <= largest).min_by_key(|(pos, _, _)| *pos))
            .ok_or(MmrError::Order)?;
        builder.push_subtree(*pos, *hash)?;
        taken.hashes.push(*index);
    }
}

/// A segment with only the pieces that were read.
fn slim<T>(id: SegmentIdentifier, hash_pos: Vec<u64>, hashes: Vec<Hash>, leaf_pos: Vec<u64>, leaves: Vec<T>, proof: SegmentProof, taken: &Taken) -> Segment<T> {
    Segment::from_parts(
        id,
        pick(hash_pos, &taken.hashes),
        pick(hashes, &taken.hashes),
        pick(leaf_pos, &taken.leaves),
        pick(leaves, &taken.leaves),
        proof,
    )
}

/// The peaks of a whole MMR, read from its last segment and that segment's
/// proof. The segment must already have passed the node's check against
/// `root` with the same `bitmap`; the result is accepted only if it hashes
/// to `root` again.
pub fn tail_peaks<T: PMMRIndexHashable>(segment: Segment<T>, mmr_size: u64, bitmap: Option<&Bitmap>, root: Hash) -> Result<Builder, Refused> {
    tail(segment, mmr_size, bitmap, root).map(|(peaks, _)| peaks)
}

/// [`tail_peaks`], and the segment with only the pieces that were read.
fn tail<T: PMMRIndexHashable>(segment: Segment<T>, mmr_size: u64, bitmap: Option<&Bitmap>, root: Hash) -> Result<(Builder, Segment<T>), Refused> {
    let id = segment.id();
    if mmr_size == 0 || id.idx.checked_add(1) != Some(segments_for(mmr_size, id.height)) {
        return Err(Refused::NotWanted);
    }
    // for a segment with all its leaves, `last` is the root of its subtree;
    // for a shorter one, the last node of the range
    let (first, last) = segment.segment_pos_range(mmr_size);
    let proof = proof_hashes(&segment).ok_or(Refused::Unreadable)?;
    let (_, hash_pos, hashes, leaf_pos, leaves, whole_proof) = segment.parts();
    let mut local = Builder::starting_at(first);
    let taken = feed(&mut local, &hash_pos, &hashes, &leaf_pos, &leaves, Within { bitmap, segment_last: last, mmr_size }).map_err(|_| Refused::Unreadable)?;
    let mut proof = proof.into_iter();
    let mut tail: Vec<(u64, Hash)> = local.peaks().to_vec();
    // a full segment is one node; its left siblings up to the peak of its
    // mountain come first in the proof
    let branch = pmmr::family_branch(last, mmr_size);
    if !branch.is_empty() {
        let [(pos, start)] = tail.as_slice() else {
            return Err(Refused::Unreadable);
        };
        if *pos != last {
            return Err(Refused::Unreadable);
        }
        let mut node = *start;
        let mut at = last;
        for (parent, sibling) in branch {
            if sibling >= at {
                // the last segment has nothing to its right
                return Err(Refused::Unreadable);
            }
            let left = proof.next().ok_or(Refused::Unreadable)?;
            node = (left, node).hash_with_index(parent);
            at = parent;
        }
        tail = vec![(at, node)];
    }
    if tail.last().and_then(|(pos, _)| pos.checked_add(1)) != Some(mmr_size) {
        return Err(Refused::Unreadable);
    }
    // then every peak to the left, nearest first
    let mut left: Vec<Hash> = Vec::new();
    for _ in pmmr::peaks(mmr_size).into_iter().filter(|pos| *pos < first) {
        left.push(proof.next().ok_or(Refused::Unreadable)?);
    }
    if proof.next().is_some() {
        return Err(Refused::Unreadable);
    }
    left.reverse();
    left.extend(tail.iter().map(|(_, hash)| *hash));
    let peaks = Builder::from_peaks(mmr_size, &left).ok_or(Refused::Unreadable)?;
    if peaks.root() != root {
        return Err(Refused::Unreadable);
    }
    Ok((peaks, slim(id, hash_pos, hashes, leaf_pos, leaves, whole_proof, &taken)))
}

/// The range proofs of the unspent outputs in one segment of the
/// rangeproof MMR at `header`: `(position, proof)`, in order. `header` must
/// come from the verified header chain, and `bitmap` must be the bitmap of
/// unspent outputs at that header - the state collected there, or carried
/// to there by blocks. The segment is put through the node's check against
/// the root in the header; only proofs that check has bound are given out,
/// and of those only the ones of outputs that are unspent.
pub fn rangeproofs_of(segment: Segment<RangeProof>, header: &BlockHeader, bitmap: &Bitmap) -> Result<Vec<(u64, RangeProof)>, Refused> {
    let id = segment.id();
    if id.height != RANGEPROOF_SEGMENT_HEIGHT || id.idx >= segments_for(header.output_mmr_size, RANGEPROOF_SEGMENT_HEIGHT) {
        return Err(Refused::NotWanted);
    }
    if !checked(|| segment.validate(header.output_mmr_size, Some(bitmap), header.range_proof_root).is_ok()) {
        return Err(Refused::Invalid);
    }
    let (first, last) = segment.segment_pos_range(header.output_mmr_size);
    let (_, _, _, leaf_pos, leaves, _) = segment.parts();
    Ok(leaf_pos
        .into_iter()
        .zip(leaves)
        .filter(|(pos, _)| (first..=last).contains(pos) && pmmr::bintree_postorder_height(*pos) == 0)
        .filter(|(pos, _)| u32::try_from(leaf_index(*pos)).is_ok_and(|index| bitmap.contains(index)))
        .collect())
}

/// Whether a segment of the rangeproof MMR - of any height, not only the
/// one this program asks for - holds under `header`, with `bitmap` the
/// verified bitmap of unspent outputs there. For trying what nodes give.
pub fn rangeproof_segment_holds(segment: &Segment<RangeProof>, header: &BlockHeader, bitmap: &Bitmap) -> bool {
    segment.id().idx < segments_for(header.output_mmr_size, segment.id().height)
        && checked(|| segment.validate(header.output_mmr_size, Some(bitmap), header.range_proof_root).is_ok())
}

/// The same for a segment of the output MMR. `bitmap_root` is the root of
/// the bitmap's accumulator as the node gave it with the segment: the
/// header commits to the two roots together, so a wrong one fails here.
pub fn output_segment_holds(segment: &Segment<OutputIdentifier>, header: &BlockHeader, bitmap: &Bitmap, bitmap_root: Hash) -> bool {
    segment.id().idx < segments_for(header.output_mmr_size, segment.id().height)
        && checked(|| {
            segment
                .validate_with(header.output_mmr_size, Some(bitmap), header.output_root, header.output_mmr_size, bitmap_root, false)
                .is_ok()
        })
}

/// How many segments of the given height an MMR of `mmr_size` has.
pub fn segments_of_height(mmr_size: u64, height: u8) -> u64 {
    segments_for(mmr_size, height)
}

/// How many segments the rangeproof MMR has at `header`.
pub fn rangeproof_segments(header: &BlockHeader) -> u64 {
    segments_for(header.output_mmr_size, RANGEPROOF_SEGMENT_HEIGHT)
}

impl Collector {
    /// Collect the state at `header`, which must come from the verified
    /// header chain.
    pub fn new(header: BlockHeader) -> Collector {
        let bitmap_chunks = header.output_mmr_count().div_ceil(CHUNK_BITS);
        let bitmap_mmr_size = pmmr::insertion_to_pmmr_index(bitmap_chunks);
        Collector {
            bitmap_segments: segments_for(bitmap_mmr_size, BITMAP_SEGMENT_HEIGHT),
            output_height: SMALL_OUTPUT_HEIGHT,
            output_segments: segments_for(header.output_mmr_size, SMALL_OUTPUT_HEIGHT),
            bitmap_chunks,
            bitmap_mmr_size,
            header,
            accumulator: BitmapAccumulator::new(),
            chunks_taken: 0,
            next_bitmap: 0,
            claimed_output_root: None,
            bitmap: None,
            outputs: Builder::new(),
            next_output: 0,
            unspent: Vec::new(),
            rangeproofs: None,
            kernels: None,
        }
    }

    /// The header the state is collected at.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// How many segments the output MMR has, at the height it is
    /// collected in.
    pub fn output_segments(&self) -> u64 {
        self.output_segments
    }

    /// The height of the segments the output MMR is collected in.
    pub fn output_height(&self) -> u8 {
        self.output_height
    }

    /// Collect the output MMR in segments of another height, from
    /// [`SMALL_OUTPUT_HEIGHT`] to [`LARGE_OUTPUT_HEIGHT`]. Only before the
    /// first of its segments is taken: segments of two heights do not go
    /// together. False if it is too late for that or the height is not one
    /// of those.
    pub fn set_output_height(&mut self, height: u8) -> bool {
        if self.next_output != 0 || !(SMALL_OUTPUT_HEIGHT..=LARGE_OUTPUT_HEIGHT).contains(&height) {
            return false;
        }
        self.output_height = height;
        self.output_segments = segments_for(self.header.output_mmr_size, height);
        true
    }

    /// How many segments it takes in all, and how many have been taken.
    pub fn progress(&self) -> (u64, u64) {
        let total = self.bitmap_segments.saturating_add(self.output_segments).saturating_add(2);
        let done = self
            .next_bitmap
            .saturating_add(self.next_output)
            .saturating_add(u64::from(self.rangeproofs.is_some()))
            .saturating_add(u64::from(self.kernels.is_some()));
        (total, done)
    }

    fn tail_id(mmr_size: u64, height: u8) -> SegmentIdentifier {
        SegmentIdentifier {
            height,
            idx: segments_for(mmr_size, height).saturating_sub(1),
        }
    }

    /// The segment to ask for now.
    pub fn wanted(&self) -> Wanted {
        if self.bitmap.is_none() {
            return Wanted::Bitmap(SegmentIdentifier {
                height: BITMAP_SEGMENT_HEIGHT,
                idx: self.next_bitmap,
            });
        }
        if self.next_output < self.output_segments {
            return Wanted::Output(SegmentIdentifier {
                height: self.output_height,
                idx: self.next_output,
            });
        }
        if self.rangeproofs.is_none() {
            return Wanted::RangeproofTail(Self::tail_id(self.header.output_mmr_size, RANGEPROOF_SEGMENT_HEIGHT));
        }
        if self.kernels.is_none() {
            return Wanted::KernelTail(Self::tail_id(self.header.kernel_mmr_size, KERNEL_SEGMENT_HEIGHT));
        }
        Wanted::Nothing
    }

    /// Take the next segment of the bitmap MMR. `output_root` is what the
    /// sender says the root of the output MMR is; the header binds it.
    pub fn add_bitmap(&mut self, segment: Segment<BitmapChunk>, output_root: Hash) -> Result<(), Refused> {
        self.take_bitmap(segment, output_root).map(|_| ())
    }

    /// [`Collector::add_bitmap`], giving back the segment as it is worth
    /// keeping: with only the pieces that were read.
    pub(crate) fn take_bitmap(&mut self, segment: Segment<BitmapChunk>, output_root: Hash) -> Result<Segment<BitmapChunk>, Refused> {
        if self.wanted() != Wanted::Bitmap(segment.id()) {
            return Err(Refused::NotWanted);
        }
        let header = &self.header;
        let size = self.bitmap_mmr_size;
        if !checked(|| {
            segment
                .validate_with(size, None, header.output_root, header.output_mmr_size, output_root, true)
                .is_ok()
        }) {
            return Err(Refused::Invalid);
        }
        // the check of an MMR that is never pruned reads no hash and every
        // leaf of the segment's range - and nothing sent beyond that range
        let (first, last) = segment.segment_pos_range(size);
        let (id, _, _, chunk_pos, chunks, proof) = segment.parts();
        let read: Vec<usize> = chunk_pos
            .iter()
            .enumerate()
            .filter(|(_, pos)| (first..=last).contains(*pos) && pmmr::bintree_postorder_height(**pos) == 0)
            .map(|(index, _)| index)
            .collect();
        let (chunk_pos, chunks) = (pick(chunk_pos, &read), pick(chunks, &read));
        for chunk in &chunks {
            self.accumulator.append_chunk(chunk.clone()).map_err(|_| Refused::Invalid)?;
            self.chunks_taken = self.chunks_taken.saturating_add(1);
        }
        let kept = Segment::from_parts(id, Vec::new(), Vec::new(), chunk_pos, chunks, proof);
        self.claimed_output_root = Some(output_root);
        self.next_bitmap = self.next_bitmap.saturating_add(1);
        if self.next_bitmap == self.bitmap_segments {
            // complete: the accumulator's own root must give the header's
            // root together with the claimed output root
            let whole = (output_root, self.accumulator.root()).hash_with_index(self.header.output_mmr_size);
            let bitmap = self.accumulator.as_bitmap().ok();
            if self.chunks_taken != self.bitmap_chunks || whole != self.header.output_root || bitmap.is_none() {
                // every segment verified and the whole does not: start the
                // bitmap again rather than go on from something inconsistent
                self.accumulator = BitmapAccumulator::new();
                self.chunks_taken = 0;
                self.next_bitmap = 0;
                self.claimed_output_root = None;
                return Err(Refused::Invalid);
            }
            self.bitmap = bitmap;
        }
        Ok(kept)
    }

    /// Whether a segment of the output MMR passes the node's check against
    /// the header - whichever segment it is, in turn or ahead of its turn.
    /// False before the bitmap is complete: there is nothing to check
    /// against yet.
    pub fn verifies_output(&self, segment: &Segment<OutputIdentifier>) -> bool {
        let Some(bitmap) = &self.bitmap else {
            return false;
        };
        if segment.id().height != self.output_height || segment.id().idx >= self.output_segments {
            return false;
        }
        let header = &self.header;
        let bitmap_root = self.accumulator.root();
        checked(|| {
            segment
                .validate_with(header.output_mmr_size, Some(bitmap), header.output_root, header.output_mmr_size, bitmap_root, false)
                .is_ok()
        })
    }

    /// Take the next segment of the output MMR.
    pub fn add_output(&mut self, segment: Segment<OutputIdentifier>) -> Result<(), Refused> {
        self.take_output(segment).map(|_| ())
    }

    pub(crate) fn take_output(&mut self, segment: Segment<OutputIdentifier>) -> Result<Segment<OutputIdentifier>, Refused> {
        if self.wanted() != Wanted::Output(segment.id()) {
            return Err(Refused::NotWanted);
        }
        let Some(bitmap) = &self.bitmap else {
            return Err(Refused::NotWanted);
        };
        if !self.verifies_output(&segment) {
            return Err(Refused::Invalid);
        }
        let header = &self.header;
        let (_, last) = segment.segment_pos_range(header.output_mmr_size);
        let (id, hash_pos, hashes, leaf_pos, leaves, proof) = segment.parts();
        // on a copy: a segment that cannot be read leaves nothing behind
        let mut outputs = self.outputs.clone();
        let taken = feed(&mut outputs, &hash_pos, &hashes, &leaf_pos, &leaves, Within { bitmap: Some(bitmap), segment_last: last, mmr_size: header.output_mmr_size }).map_err(|_| Refused::Unreadable)?;
        // a leaf is read if it or its sibling is unspent; the unspent ones
        // are those the bitmap names
        let found: Vec<(u64, OutputIdentifier)> = taken
            .leaves
            .iter()
            .filter_map(|index| Some((*leaf_pos.get(*index)?, *leaves.get(*index)?)))
            .filter(|(pos, _)| u32::try_from(leaf_index(*pos)).is_ok_and(|index| bitmap.contains(index)))
            .collect();
        if self.next_output.checked_add(1) == Some(self.output_segments) {
            let complete = outputs.size() == header.output_mmr_size
                && Some(outputs.root()) == self.claimed_output_root
                && u64::try_from(self.unspent.len().saturating_add(found.len())).is_ok_and(|n| n == bitmap.cardinality());
            if !complete {
                return Err(Refused::Unreadable);
            }
        }
        // what is kept must pass the check by itself, or the file would
        // not be taken back
        let kept = slim(id, hash_pos, hashes, leaf_pos, leaves, proof, &taken);
        if !self.verifies_output(&kept) {
            return Err(Refused::Unreadable);
        }
        self.outputs = outputs;
        self.unspent.extend(found);
        self.next_output = self.next_output.saturating_add(1);
        Ok(kept)
    }

    /// Take the last segment of the rangeproof MMR, for its peaks.
    pub fn add_rangeproof_tail(&mut self, segment: Segment<RangeProof>) -> Result<(), Refused> {
        self.take_rangeproof_tail(segment).map(|_| ())
    }

    pub(crate) fn take_rangeproof_tail(&mut self, segment: Segment<RangeProof>) -> Result<Segment<RangeProof>, Refused> {
        if self.wanted() != Wanted::RangeproofTail(segment.id()) {
            return Err(Refused::NotWanted);
        }
        let header = &self.header;
        let bitmap = self.bitmap.as_ref();
        if !checked(|| segment.validate(header.output_mmr_size, bitmap, header.range_proof_root).is_ok()) {
            return Err(Refused::Invalid);
        }
        let (peaks, kept) = tail(segment, header.output_mmr_size, bitmap, header.range_proof_root)?;
        self.rangeproofs = Some(peaks);
        Ok(kept)
    }

    /// Take the last segment of the kernel MMR, for its peaks.
    pub fn add_kernel_tail(&mut self, segment: Segment<TxKernel>) -> Result<(), Refused> {
        self.take_kernel_tail(segment).map(|_| ())
    }

    pub(crate) fn take_kernel_tail(&mut self, segment: Segment<TxKernel>) -> Result<Segment<TxKernel>, Refused> {
        if self.wanted() != Wanted::KernelTail(segment.id()) {
            return Err(Refused::NotWanted);
        }
        let header = &self.header;
        if !checked(|| segment.validate(header.kernel_mmr_size, None, header.kernel_root).is_ok()) {
            return Err(Refused::Invalid);
        }
        let (peaks, kept) = tail(segment, header.kernel_mmr_size, None, header.kernel_root)?;
        self.kernels = Some(peaks);
        Ok(kept)
    }

    /// The collected state, once nothing more is wanted.
    pub fn finish(self) -> Option<State> {
        if self.wanted() != Wanted::Nothing {
            return None;
        }
        Some(State {
            header: self.header,
            bitmap: self.accumulator,
            unspent: self.unspent,
            outputs: self.outputs,
            rangeproofs: self.rangeproofs?,
            kernels: self.kernels?,
        })
    }
}
