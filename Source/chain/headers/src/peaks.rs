//! The peaks of the header MMR.
//!
//! Every header commits, in `prev_root`, to all headers before it: the root
//! of a Merkle mountain range whose leaves are those headers. To check that
//! commitment for the next header, and to add a header to the range, the
//! peaks are enough - at most one hash per bit of the header count.
//!
//! The hashing is Grin's own (`hash_with_index`); this module only decides
//! which hashes meet. Its results are compared in the tests with the full
//! MMR of the Grin code for every size up to a few hundred leaves.
use grin_core::core::hash::{Hash, ZERO_HASH};
use grin_core::core::pmmr;
use grin_core::core::BlockHeader;
use grin_core::ser::PMMRIndexHashable;

/// More leaves than any chain will have; keeps every position far from the
/// edge of the integer type.
pub const MAX_LEAVES: u64 = 1 << 40;

/// Why peaks could not be built or extended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeaksError {
    /// The numbers do not describe a range (count of peaks, length of a path).
    Shape,
    /// The peaks do not hash to the root they were checked against.
    Root,
}

/// The peaks of an MMR with a known number of leaves, left to right.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Peaks {
    leaves: u64,
    hashes: Vec<Hash>,
}

/// Number of nodes of a range with this many leaves.
fn size_of(leaves: u64) -> u64 {
    pmmr::insertion_to_pmmr_index(leaves)
}

impl Peaks {
    /// The range without leaves.
    pub fn empty() -> Peaks {
        Peaks {
            leaves: 0,
            hashes: Vec::new(),
        }
    }

    /// Peaks taken on trust from the caller, checked only for their count.
    /// Whoever calls this must compare [`Peaks::root`] with a root it trusts.
    pub fn from_parts(leaves: u64, hashes: Vec<Hash>) -> Result<Peaks, PeaksError> {
        let expected = usize::try_from(leaves.count_ones()).map_err(|_| PeaksError::Shape)?;
        if leaves > MAX_LEAVES || hashes.len() != expected {
            return Err(PeaksError::Shape);
        }
        Ok(Peaks { leaves, hashes })
    }

    /// Number of leaves (headers) in the range.
    pub fn leaves(&self) -> u64 {
        self.leaves
    }

    /// Number of nodes in the range, the "MMR size" of the Grin code.
    pub fn size(&self) -> u64 {
        size_of(self.leaves)
    }

    /// The peaks, left to right.
    pub fn hashes(&self) -> &[Hash] {
        &self.hashes
    }

    /// The root: the peaks hashed together from the right, each time with
    /// the size of the range.
    pub fn root(&self) -> Hash {
        let size = self.size();
        let mut acc: Option<Hash> = None;
        for peak in self.hashes.iter().rev() {
            acc = Some(match acc {
                None => *peak,
                Some(right) => (*peak, right).hash_with_index(size),
            });
        }
        acc.unwrap_or(ZERO_HASH)
    }

    /// Add the next header as a leaf. On an error nothing has changed.
    pub fn append(&mut self, header: &BlockHeader) -> Result<(), PeaksError> {
        if self.leaves >= MAX_LEAVES {
            return Err(PeaksError::Shape);
        }
        let mut pos = self.size();
        let mut node = header.hash_with_index(pos);
        let mut hashes = self.hashes.clone();
        // one merge for every trailing one-bit of the leaf count: the new
        // leaf closes a mountain of that height
        let mut bit = 1u64;
        while self.leaves & bit != 0 {
            let left = hashes.pop().ok_or(PeaksError::Shape)?;
            pos = pos.checked_add(1).ok_or(PeaksError::Shape)?;
            node = (left, node).hash_with_index(pos);
            bit = bit.checked_mul(2).ok_or(PeaksError::Shape)?;
        }
        hashes.push(node);
        self.leaves = self.leaves.checked_add(1).ok_or(PeaksError::Shape)?;
        self.hashes = hashes;
        Ok(())
    }

    /// Rebuild all peaks of a range from the Merkle proof of its *last*
    /// leaf, and accept them only if they hash to `root`.
    ///
    /// The path of the last leaf holds its left siblings up to the peak of
    /// its mountain and then every other peak, right to left - so it
    /// determines the peaks completely. `leaves` is the number of leaves of
    /// the range, `last` the header that is its last leaf.
    pub fn from_last_leaf(leaves: u64, last: &BlockHeader, path: &[Hash], root: Hash) -> Result<Peaks, PeaksError> {
        if leaves == 0 || leaves > MAX_LEAVES {
            return Err(PeaksError::Shape);
        }
        let climb = usize::try_from(leaves.trailing_zeros()).map_err(|_| PeaksError::Shape)?;
        let others = usize::try_from(leaves.count_ones())
            .ok()
            .and_then(|n| n.checked_sub(1))
            .ok_or(PeaksError::Shape)?;
        if climb.checked_add(others) != Some(path.len()) {
            return Err(PeaksError::Shape);
        }
        let (up, left) = path.split_at(climb);
        let mut pos = size_of(leaves.checked_sub(1).ok_or(PeaksError::Shape)?);
        let mut node = last.hash_with_index(pos);
        for sibling in up {
            // the last leaf is a right child all the way up
            pos = pos.checked_add(1).ok_or(PeaksError::Shape)?;
            node = (*sibling, node).hash_with_index(pos);
        }
        let mut hashes: Vec<Hash> = left.iter().rev().copied().collect();
        hashes.push(node);
        let peaks = Peaks { leaves, hashes };
        if peaks.root() != root {
            return Err(PeaksError::Root);
        }
        Ok(peaks)
    }
}

/// One leaf followed through a range as the range grows (K202): the peaks,
/// and the siblings of that leaf from the bottom up to the peak of its
/// mountain. With them the Merkle proof of the leaf under the root of the
/// range can be given at any size, without keeping the range itself - this
/// is how a starting point made by the wallet carries the proof that the
/// point the program came with is in its history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Track {
    peaks: Peaks,
    target: u64,
    up: Vec<Hash>,
}

/// The mountain of the range with `leaves` leaves that holds leaf `target`:
/// its place among the peaks (left to right), its first leaf and its height.
fn mountain_of(leaves: u64, target: u64) -> Option<(usize, u64, u32)> {
    if target >= leaves {
        return None;
    }
    let mut first = 0u64;
    let mut place = 0usize;
    for level in (0..64u32).rev() {
        let size = 1u64.checked_shl(level)?;
        if leaves & size == 0 {
            continue;
        }
        let end = first.checked_add(size)?;
        if target < end {
            return Some((place, first, level));
        }
        first = end;
        place = place.checked_add(1)?;
    }
    None
}

impl Track {
    /// The range `before`, and `leaf` added to it as the leaf followed.
    pub fn begin(before: &Peaks, leaf: &BlockHeader) -> Result<Track, PeaksError> {
        let mut track = Track { peaks: before.clone(), target: before.leaves(), up: Vec::new() };
        track.append(leaf)?;
        Ok(track)
    }

    /// Takes up a leaf again from its Merkle proof in the range `peaks`
    /// (as [`Track::path`] gives it): the part of the path above the peak of
    /// its mountain has to be what those peaks give. Whether the path leads
    /// from the leaf to that peak is not known here: that is checked where
    /// the leaf itself is known (see [`crate::proof::history_of`]).
    pub fn from_path(peaks: &Peaks, target: u64, path: &[Hash]) -> Result<Track, PeaksError> {
        let (_, _, level) = mountain_of(peaks.leaves(), target).ok_or(PeaksError::Shape)?;
        let climb = usize::try_from(level).map_err(|_| PeaksError::Shape)?;
        if path.len() < climb {
            return Err(PeaksError::Shape);
        }
        let (up, above) = path.split_at(climb);
        let track = Track { peaks: peaks.clone(), target, up: up.to_vec() };
        if track.above() != Some(above.to_vec()) {
            return Err(PeaksError::Shape);
        }
        Ok(track)
    }

    /// The height (leaf index) of the leaf followed.
    pub fn target(&self) -> u64 {
        self.target
    }

    /// The range as it is now.
    pub fn peaks(&self) -> &Peaks {
        &self.peaks
    }

    /// Add the next header to the range. On an error nothing has changed.
    pub fn append(&mut self, header: &BlockHeader) -> Result<(), PeaksError> {
        let leaves = self.peaks.leaves();
        let mut peaks = self.peaks.clone();
        peaks.append(header)?;
        // the merges the new leaf made, again, to see which of them took in
        // the mountain of the leaf followed, and what it met there
        let mut up = self.up.clone();
        let mut hashes = self.peaks.hashes.clone();
        let mut pos = self.peaks.size();
        let mut node = header.hash_with_index(pos);
        let mut bit = 1u64;
        while leaves & bit != 0 {
            let left = hashes.pop().ok_or(PeaksError::Shape)?;
            // the right part ends with the new leaf and has `bit` leaves
            let right_first = leaves.checked_add(1).and_then(|n| n.checked_sub(bit)).ok_or(PeaksError::Shape)?;
            let left_first = right_first.checked_sub(bit).ok_or(PeaksError::Shape)?;
            if self.target >= right_first && self.target <= leaves {
                up.push(left);
            } else if self.target >= left_first && self.target < right_first {
                up.push(node);
            }
            pos = pos.checked_add(1).ok_or(PeaksError::Shape)?;
            node = (left, node).hash_with_index(pos);
            bit = bit.checked_mul(2).ok_or(PeaksError::Shape)?;
        }
        self.peaks = peaks;
        self.up = up;
        Ok(())
    }

    /// The part of the path above the peak of the leaf's mountain, as the
    /// Grin code gives it: the peaks to the right hashed together, then the
    /// peaks to the left, right to left.
    fn above(&self) -> Option<Vec<Hash>> {
        let (place, _, _) = mountain_of(self.peaks.leaves(), self.target)?;
        let size = self.peaks.size();
        let hashes = self.peaks.hashes();
        let mut right: Option<Hash> = None;
        for peak in hashes.get(place.checked_add(1)?..)?.iter().rev() {
            right = Some(match right {
                None => *peak,
                Some(r) => (*peak, r).hash_with_index(size),
            });
        }
        let mut out: Vec<Hash> = right.into_iter().collect();
        out.extend(hashes.get(..place)?.iter().rev().copied());
        Some(out)
    }

    /// The Merkle proof of the leaf followed under the root of the range,
    /// in the form of the Grin code's `MerkleProof::path`.
    pub fn path(&self) -> Option<Vec<Hash>> {
        let mut path = self.up.clone();
        path.extend(self.above()?);
        Some(path)
    }
}
