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
