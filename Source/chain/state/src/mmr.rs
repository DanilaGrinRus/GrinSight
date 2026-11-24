//! The peaks of an MMR, built from leaves and from the roots of pruned
//! subtrees.
//!
//! A node hands its output MMR over in segments: the unpruned leaves, and
//! for everything that was pruned the hash of the largest pruned subtree.
//! To go on adding leaves after the last one, the peaks are enough. This
//! builder takes the pieces in the order of their positions and keeps only
//! the peaks; the hashing is Grin's.
use grin_core::core::hash::{Hash, ZERO_HASH};
use grin_core::core::pmmr;
use grin_core::ser::PMMRIndexHashable;

/// Larger than any MMR will be; keeps positions away from the edge of `u64`.
pub const MAX_SIZE: u64 = 1 << 50;

/// Why a piece could not be added.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MmrError {
    /// The piece does not begin where the range ends.
    Order,
    /// A position that cannot be in an MMR, or beyond the supported size.
    Position,
}

/// An MMR of which only the peaks are kept: `(position, hash)`, left to right.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Builder {
    /// Number of nodes of the whole range so far: the next free position.
    size: u64,
    peaks: Vec<(u64, Hash)>,
}

impl Builder {
    /// The empty range.
    pub fn new() -> Builder {
        Builder::starting_at(0)
    }

    /// A range that begins at `first` - the first position of a segment.
    /// Nodes are merged only with nodes added to this builder: what lies
    /// left of `first` is somebody else's.
    pub fn starting_at(first: u64) -> Builder {
        Builder {
            size: first,
            peaks: Vec::new(),
        }
    }

    /// Peaks taken on trust, to go on from: whoever calls this must compare
    /// [`Builder::root`] with a root it trusts.
    pub fn from_peaks(size: u64, hashes: &[Hash]) -> Option<Builder> {
        if size > MAX_SIZE {
            return None;
        }
        let positions = pmmr::peaks(size);
        if positions.len() != hashes.len() || pmmr::peak_map_height(size).1 != 0 {
            return None;
        }
        Some(Builder {
            size,
            peaks: positions.into_iter().zip(hashes.iter().copied()).collect(),
        })
    }

    /// The next free position.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// The peaks, left to right.
    pub fn hashes(&self) -> Vec<Hash> {
        self.peaks.iter().map(|(_, h)| *h).collect()
    }

    /// The peaks with their positions.
    pub fn peaks(&self) -> &[(u64, Hash)] {
        &self.peaks
    }

    /// The root of the range as an MMR of `size` nodes: the peaks hashed
    /// together from the right.
    pub fn root(&self) -> Hash {
        let mut acc: Option<Hash> = None;
        for (_, peak) in self.peaks.iter().rev() {
            acc = Some(match acc {
                None => *peak,
                Some(right) => (*peak, right).hash_with_index(self.size),
            });
        }
        acc.unwrap_or(ZERO_HASH)
    }

    /// Add the leaf at the next free position.
    pub fn push_leaf(&mut self, leaf: &dyn PMMRIndexHashable) -> Result<u64, MmrError> {
        let pos = self.size;
        if pmmr::bintree_postorder_height(pos) != 0 {
            return Err(MmrError::Order);
        }
        self.push_node(pos, leaf.hash_with_index(pos))?;
        Ok(pos)
    }

    /// Add the root of a pruned subtree: the node at `pos` whose leftmost
    /// leaf is the next free position.
    pub fn push_subtree(&mut self, pos: u64, hash: Hash) -> Result<(), MmrError> {
        if pos >= MAX_SIZE {
            return Err(MmrError::Position);
        }
        if pmmr::bintree_leftmost(pos) != self.size {
            return Err(MmrError::Order);
        }
        self.push_node(pos, hash)
    }

    fn push_node(&mut self, mut pos: u64, mut hash: Hash) -> Result<(), MmrError> {
        if pos >= MAX_SIZE {
            return Err(MmrError::Position);
        }
        loop {
            // a node closes its parent if its sibling is the peak to its
            // left - which a left child's sibling never is, nor a sibling
            // from before this builder's start
            let (parent, sibling) = pmmr::family(pos);
            let closes = self.peaks.last().is_some_and(|(p, _)| *p == sibling);
            if !closes {
                break;
            }
            let Some((_, left)) = self.peaks.pop() else {
                break;
            };
            hash = (left, hash).hash_with_index(parent);
            pos = parent;
        }
        self.peaks.push((pos, hash));
        self.size = pos.checked_add(1).ok_or(MmrError::Position)?;
        Ok(())
    }
}

impl Default for Builder {
    fn default() -> Self {
        Builder::new()
    }
}
