//! The state carried forward block by block, and back.
//!
//! A header commits to the state after its block: the roots of the output,
//! rangeproof and kernel MMRs, the root of the bitmap of unspent outputs,
//! the sizes of the MMRs. From the state before a block and the block's
//! contents those are computed here and compared with the header - a header
//! of the verified header chain, handed in by the caller, never the copy
//! that travels with the block. A block whose contents give other roots is
//! not the block that header is about.
//!
//! The roots say that the contents are what the header commits to; they do
//! not say the contents are valid. That is the node's own block check -
//! weights, order, sums, range proofs, kernel signatures - and it is run on
//! every block when it first arrives. A block read back from this
//! program's own file was checked then; whatever happened to the file
//! since, the roots tell.
//!
//! What is not checked, because the state collected at the archive header
//! does not hold it: that the outputs unspent at the archive header add up
//! to the kernels before it, and the maturity of a coinbase output whose
//! height of creation lies below what the caller can tell.
use crate::archive::State;
use crate::mmr::Builder;
use croaring::Bitmap;
use grin_chain::txhashset::BitmapAccumulator;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::pmmr;
use grin_core::core::{Block, BlockHeader, CommitWrapper, OutputFeatures};
use grin_core::ser::{self, PMMRIndexHashable, ProtocolVersion};
use std::collections::{HashMap, VecDeque};

/// How much of a block is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    /// Everything: the node's block check, then the roots.
    Arrived,
    /// The roots only: for a block that passed [`Check::Arrived`] before
    /// and has been kept in this program's file since.
    Kept,
}

/// Why a block was not applied. The state is as it was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejected {
    /// Not the block that follows the state.
    NotNext,
    /// The header that came with the block is not the verified header.
    Header,
    /// The node's block check fails: the contents are not a valid block.
    Body,
    /// An input spends an output that is not unspent in the state.
    Input,
    /// An input spends a coinbase output that is too young.
    Immature,
    /// An output has the commitment of an output that is unspent.
    Duplicate,
    /// The contents do not give the roots the header commits to.
    Roots,
    /// A count or position beyond what this program handles.
    Range,
}

/// What a block did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Applied {
    /// Outputs spent.
    pub spent: usize,
    /// Outputs created.
    pub created: usize,
    /// Whether the maturity of spent coinbase outputs could be checked.
    pub maturity_checked: bool,
}

/// An unspent output: where it is in the output MMR and what kind it is.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Unspent {
    /// Position in the output MMR.
    pub pos: u64,
    /// Coinbase or plain.
    pub features: OutputFeatures,
}

/// What it takes to take a block back: the header and the peaks before it,
/// and what it spent and created. The accumulator of the bitmap is not
/// kept - it is megabytes, and there is a record like this for every block
/// since the archive header; it is rebuilt from the bitmap instead.
struct Undo {
    header: BlockHeader,
    outputs: Builder,
    rangeproofs: Builder,
    kernels: Builder,
    spent: Vec<([u8; 33], Unspent)>,
    created: Vec<([u8; 33], u64)>,
}

/// The state after some block, with the way back to the archive header.
pub struct Live {
    header: BlockHeader,
    accumulator: BitmapAccumulator,
    bitmap: Bitmap,
    unspent: HashMap<[u8; 33], Unspent>,
    outputs: Builder,
    rangeproofs: Builder,
    kernels: Builder,
    undo: VecDeque<Undo>,
}

fn leaf_index(pos: u64) -> Option<u32> {
    u32::try_from(pmmr::n_leaves(pos.checked_add(1)?).checked_sub(1)?).ok()
}

/// The bytes of a header, all of them. Two headers with the same hash can
/// differ: the hash of a header is the hash of its proof of work alone, and
/// it is the proof's validity that binds it to the rest.
fn header_bytes(header: &BlockHeader) -> Option<Vec<u8>> {
    ser::ser_vec(header, ProtocolVersion::local()).ok()
}

impl Live {
    /// The state collected at the archive header, ready to be carried
    /// forward.
    pub fn new(state: State) -> Option<Live> {
        let bitmap = state.bitmap.as_bitmap().ok()?;
        let unspent: HashMap<[u8; 33], Unspent> = state
            .unspent
            .iter()
            .map(|(pos, id)| {
                (
                    id.commit.0,
                    Unspent {
                        pos: *pos,
                        features: id.features,
                    },
                )
            })
            .collect();
        // two unspent outputs with one commitment cannot be
        if unspent.len() != state.unspent.len() {
            return None;
        }
        Some(Live {
            header: state.header,
            accumulator: state.bitmap,
            bitmap,
            unspent,
            outputs: state.outputs,
            rangeproofs: state.rangeproofs,
            kernels: state.kernels,
            undo: VecDeque::new(),
        })
    }

    /// The header the state is at.
    pub fn header(&self) -> &BlockHeader {
        &self.header
    }

    /// How many blocks can be taken back.
    pub fn depth(&self) -> usize {
        self.undo.len()
    }

    /// How many outputs are unspent.
    pub fn unspent_count(&self) -> usize {
        self.unspent.len()
    }

    /// The unspent output with this commitment, if there is one.
    pub fn unspent(&self, commitment: &[u8; 33]) -> Option<Unspent> {
        self.unspent.get(commitment).copied()
    }

    /// The bitmap of unspent outputs as it is now.
    pub fn bitmap(&self) -> &Bitmap {
        &self.bitmap
    }

    /// The bitmap of unspent outputs as it was after the block at
    /// `height`: the bitmap now, with what every later block spent put
    /// back and what it created taken out. `None` if `height` is above the
    /// state, or below what can still be taken back.
    pub fn bitmap_at(&self, height: u64) -> Option<Bitmap> {
        let depth = u64::try_from(self.undo.len()).ok()?;
        if height > self.header.height || height < self.header.height.checked_sub(depth)? {
            return None;
        }
        let mut bitmap = self.bitmap.clone();
        // each record holds the header before its block
        for undo in self.undo.iter().rev().take_while(|undo| undo.header.height >= height) {
            for (_, pos) in &undo.created {
                bitmap.remove(leaf_index(*pos)?);
            }
            for (_, unspent) in &undo.spent {
                bitmap.add(leaf_index(unspent.pos)?);
            }
        }
        Some(bitmap)
    }

    /// The unspent outputs now whose position is from `first` to `last`:
    /// `(position, commitment, coinbase)`, in order.
    pub fn unspent_between(&self, first: u64, last: u64) -> Vec<(u64, [u8; 33], bool)> {
        let mut all: Vec<(u64, [u8; 33], bool)> = self
            .unspent
            .iter()
            .filter(|(_, unspent)| (first..=last).contains(&unspent.pos))
            .map(|(commitment, unspent)| (unspent.pos, *commitment, unspent.features == OutputFeatures::Coinbase))
            .collect();
        all.sort_unstable_by_key(|(pos, _, _)| *pos);
        all
    }

    /// The roots the state gives: of the outputs together with the bitmap,
    /// of the range proofs, of the kernels.
    pub fn roots(&self) -> (Hash, Hash, Hash) {
        let outputs = (self.outputs.root(), self.accumulator.root()).hash_with_index(self.outputs.size());
        (outputs, self.rangeproofs.root(), self.kernels.root())
    }

    /// Apply the block that follows the state. `verified` is the header of
    /// that block from the verified header chain. `mature_below` is the
    /// size the output MMR had at the last height whose coinbase outputs
    /// may be spent in this block, if the caller knows it.
    pub fn apply(&mut self, block: &Block, verified: &BlockHeader, check: Check, mature_below: Option<u64>) -> Result<Applied, Rejected> {
        if verified.prev_hash != self.header.hash() || self.header.height.checked_add(1) != Some(verified.height) {
            return Err(Rejected::NotNext);
        }
        if header_bytes(&block.header).is_none_or(|bytes| Some(bytes) != header_bytes(verified)) {
            return Err(Rejected::Header);
        }
        // the inputs: every one an output that is unspent, none twice
        let inputs: Vec<CommitWrapper> = block.inputs().into();
        let mut spent: Vec<([u8; 33], Unspent)> = Vec::with_capacity(inputs.len());
        for input in &inputs {
            let commitment = input.commitment().0;
            let found = self.unspent.get(&commitment).ok_or(Rejected::Input)?;
            if spent.iter().any(|(seen, _)| *seen == commitment) {
                return Err(Rejected::Input);
            }
            if found.features == OutputFeatures::Coinbase && mature_below.is_some_and(|size| found.pos >= size) {
                return Err(Rejected::Immature);
            }
            spent.push((commitment, *found));
        }
        if check == Check::Arrived && block.validate(&self.header.total_kernel_offset).is_err() {
            return Err(Rejected::Body);
        }
        // the three MMRs, on copies
        let (mut outputs, mut rangeproofs, mut kernels) = (self.outputs.clone(), self.rangeproofs.clone(), self.kernels.clone());
        let mut bitmap = self.bitmap.clone();
        let mut touched: Vec<u64> = Vec::new();
        for (_, unspent) in &spent {
            let index = leaf_index(unspent.pos).ok_or(Rejected::Range)?;
            bitmap.remove(index);
            touched.push(u64::from(index));
        }
        let mut created: Vec<([u8; 33], Unspent)> = Vec::with_capacity(block.outputs().len());
        for output in block.outputs() {
            let pos = outputs.push_leaf(&output.identifier()).map_err(|_| Rejected::Range)?;
            if rangeproofs.push_leaf(&output.proof()).map_err(|_| Rejected::Range)? != pos {
                return Err(Rejected::Roots);
            }
            let index = leaf_index(pos).ok_or(Rejected::Range)?;
            bitmap.add(index);
            touched.push(u64::from(index));
            let commitment = output.commitment().0;
            // an output with the commitment of one that is unspent - before
            // this block or made in it - cannot be
            let taken = self.unspent.contains_key(&commitment) && !spent.iter().any(|(gone, _)| *gone == commitment);
            if taken || created.iter().any(|(seen, _)| *seen == commitment) {
                return Err(Rejected::Duplicate);
            }
            created.push((
                commitment,
                Unspent {
                    pos,
                    features: output.features(),
                },
            ));
        }
        for kernel in block.kernels() {
            kernels.push_leaf(kernel).map_err(|_| Rejected::Range)?;
        }
        // Compare the reconstructed lengths separately, as txhashset::validate_sizes does.
        // A tree root alone does not authenticate the separate size fields.
        if outputs.size() != verified.output_mmr_size
            || rangeproofs.size() != verified.output_mmr_size
            || kernels.size() != verified.kernel_mmr_size
        {
            return Err(Rejected::Roots);
        }
        if rangeproofs.root() != verified.range_proof_root || kernels.root() != verified.kernel_root {
            return Err(Rejected::Roots);
        }
        // the bitmap: its accumulator is rebuilt from the first chunk touched
        touched.sort_unstable();
        let mut accumulator = self.accumulator.clone();
        if let Some(first) = touched.first() {
            let from = BitmapAccumulator::chunk_start_idx(*first);
            let leaves = pmmr::n_leaves(outputs.size());
            accumulator
                .apply(touched.iter().copied(), bitmap.iter().map(u64::from).filter(|index| *index >= from), leaves)
                .map_err(|_| Rejected::Range)?;
        }
        if (outputs.root(), accumulator.root()).hash_with_index(outputs.size()) != verified.output_root {
            return Err(Rejected::Roots);
        }
        // everything fits: the state moves
        let applied = Applied {
            spent: spent.len(),
            created: created.len(),
            maturity_checked: mature_below.is_some(),
        };
        for (commitment, _) in &spent {
            self.unspent.remove(commitment);
        }
        for (commitment, unspent) in &created {
            self.unspent.insert(*commitment, *unspent);
        }
        self.undo.push_back(Undo {
            header: std::mem::replace(&mut self.header, verified.clone()),
            outputs: std::mem::replace(&mut self.outputs, outputs),
            rangeproofs: std::mem::replace(&mut self.rangeproofs, rangeproofs),
            kernels: std::mem::replace(&mut self.kernels, kernels),
            spent,
            created: created.into_iter().map(|(commitment, unspent)| (commitment, unspent.pos)).collect(),
        });
        self.accumulator = accumulator;
        self.bitmap = bitmap;
        Ok(applied)
    }

    /// Take the last block back. False if the state is at the archive
    /// header: there is nothing before it.
    pub fn undo(&mut self) -> bool {
        let Some(undo) = self.undo.pop_back() else {
            return false;
        };
        let mut touched: Vec<u64> = Vec::new();
        for (commitment, _) in &undo.created {
            if let Some(index) = self.unspent.remove(commitment).and_then(|gone| leaf_index(gone.pos)) {
                self.bitmap.remove(index);
                touched.push(u64::from(index));
            }
        }
        for (commitment, unspent) in undo.spent {
            if let Some(index) = leaf_index(unspent.pos) {
                self.bitmap.add(index);
                touched.push(u64::from(index));
            }
            self.unspent.insert(commitment, unspent);
        }
        self.header = undo.header;
        self.outputs = undo.outputs;
        self.rangeproofs = undo.rangeproofs;
        self.kernels = undo.kernels;
        // the accumulator, rebuilt from the first chunk the block touched,
        // for as many outputs as there were before it
        touched.sort_unstable();
        if let Some(first) = touched.first() {
            let from = BitmapAccumulator::chunk_start_idx(*first);
            let leaves = pmmr::n_leaves(self.outputs.size());
            let rebuilt = self
                .accumulator
                .apply(touched.iter().copied(), self.bitmap.iter().map(u64::from).filter(|index| *index >= from), leaves);
            if rebuilt.is_err() {
                // cannot be: the same was done going forward. If it is, the
                // roots will not fit the next block, and nothing is applied.
                self.accumulator = BitmapAccumulator::new();
            }
        }
        true
    }

    /// Forget how to take back all but the last `keep` blocks.
    pub fn forget_before(&mut self, keep: usize) {
        while self.undo.len() > keep {
            self.undo.pop_front();
        }
    }
}
