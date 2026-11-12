//! Synthetic chains for tests and fixtures (feature `testkit`): grin's own
//! PMMR structures produce headers, PIBD segments and block bodies to check
//! the core (and its C ABI) against. Never valid on a real network.
#![allow(dead_code)]

use crate::outputs::*;
use croaring::Bitmap;
#[cfg(feature = "web")]
use crate::bitmap::{BitmapAccumulator, BitmapChunk};
#[cfg(not(feature = "web"))]
use grin_chain::txhashset::{BitmapAccumulator, BitmapChunk};
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::pmmr::{self, ReadablePMMR, ReadonlyPMMR, VecBackend, PMMR};
use grin_core::core::{self, BlockHeader, HeaderVersion, Inputs, OutputFeatures, OutputIdentifier, Segment, SegmentIdentifier, TransactionBody};
use grin_core::ser::PMMRIndexHashable;
use grin_util::secp::pedersen::{Commitment, RangeProof};
use std::collections::{HashMap, HashSet};

/// Bitmap segments height a Grin node serves.
pub const BITMAP_SEGMENT_HEIGHT: u8 = 9;

pub fn id(i: u32) -> OutputIdentifier {
    let mut c = [0u8; 33];
    c[0] = 8;
    c[1..5].copy_from_slice(&i.to_be_bytes());
    OutputIdentifier { features: OutputFeatures::Plain, commit: Commitment::from_vec(c.to_vec()) }
}

pub struct Reference {
    backend: VecBackend<OutputIdentifier>,
    acc: BitmapAccumulator,
    leaves: Bitmap,
    pos: HashMap<[u8; 33], u64>,
}

impl Reference {
    pub fn new() -> Self {
        Reference { backend: VecBackend::new(), acc: BitmapAccumulator::new(), leaves: Bitmap::new(), pos: HashMap::new() }
    }
    pub fn size(&self) -> u64 {
        self.backend.size()
    }
    /// Apply like grin: outputs, then inputs, then accumulator.
    pub fn apply(&mut self, outs: &[OutputIdentifier], ins: &[OutputIdentifier]) {
        let mut affected = vec![];
        for o in outs {
            let size = self.backend.size();
            let pos0 = PMMR::at(&mut self.backend, size).push(o).unwrap();
            self.leaves.add(leaf_idx(pos0) as u32);
            self.pos.insert(o.commit.0, pos0);
            affected.push(leaf_idx(pos0));
        }
        for o in ins {
            let pos0 = self.pos.remove(&o.commit.0).unwrap();
            let size = self.backend.size();
            PMMR::at(&mut self.backend, size).prune(pos0).unwrap();
            self.leaves.remove(leaf_idx(pos0) as u32);
            affected.push(leaf_idx(pos0));
        }
        affected.sort_unstable();
        let start = BitmapAccumulator::chunk_start_idx(affected[0]);
        let n = pmmr::n_leaves(self.size());
        let it: Vec<u64> = self.leaves.iter().map(|x| x as u64).filter(|&x| x >= start).collect();
        self.acc.apply(affected, it, n).unwrap();
    }
    pub fn header(&self) -> BlockHeader {
        let mut h = BlockHeader::default();
        h.version = HeaderVersion(5);
        h.output_mmr_size = self.size();
        let root = ReadonlyPMMR::at(&self.backend, self.size()).root().unwrap();
        h.output_root = (root, self.acc.root()).hash_with_index(self.size());
        h
    }
    pub fn segments(&self, h: u8) -> (Vec<Segment<BitmapChunk>>, Vec<Segment<OutputIdentifier>>) {
        self.segments_from(h, false)
    }
    /// Segments as served by a node whose output PMMR was compacted with
    /// grin-5.5.2 store rules (`pos_to_rm` / `removed_excl_roots`).
    pub fn compacted_segments(&self, h: u8) -> (Vec<Segment<BitmapChunk>>, Vec<Segment<OutputIdentifier>>) {
        self.segments_from(h, true)
    }
    pub fn segments_from(&self, h: u8, compact: bool) -> (Vec<Segment<BitmapChunk>>, Vec<Segment<OutputIdentifier>>) {
        let size = self.size();
        let mut expanded: HashSet<u64> = HashSet::new();
        if compact {
            for pos0 in (0..size).filter(|&p| pmmr::is_leaf(p) && !self.leaves.contains(leaf_idx(p) as u32)) {
                expanded.insert(pos0);
                let mut cur = pos0;
                loop {
                    let (parent, sibling) = pmmr::family(cur);
                    if parent < size && expanded.contains(&sibling) {
                        expanded.insert(parent);
                        cur = parent;
                    } else {
                        break;
                    }
                }
            }
        }
        let gone: HashSet<u64> = expanded.iter().copied().filter(|&p| expanded.contains(&pmmr::family(p).0)).collect();
        let backend = Compacted { inner: &self.backend, gone };
        let ro = ReadonlyPMMR::at(&backend, size);
        let out = SegmentIdentifier::traversal_iter(size, h)
            .map(|id| Segment::from_pmmr(id, &ro, true).unwrap())
            .collect();
        let bro = self.acc.readonly_pmmr();
        let bsize = bro.unpruned_size();
        let bm = SegmentIdentifier::traversal_iter(bsize, BITMAP_SEGMENT_HEIGHT)
            .map(|id| Segment::from_pmmr(id, &bro, false).unwrap())
            .collect();
        (bm, out)
    }
}


pub struct Compacted<'a> {
    inner: &'a VecBackend<OutputIdentifier>,
    gone: HashSet<u64>,
}

impl<'a> pmmr::Backend<OutputIdentifier> for Compacted<'a> {
    fn append(&mut self, _: &OutputIdentifier, _: &[Hash]) -> Result<(), String> { unimplemented!() }
    fn append_pruned_subtree(&mut self, _: Hash, _: u64) -> Result<(), String> { unimplemented!() }
    fn append_hash(&mut self, _: Hash) -> Result<(), String> { unimplemented!() }
    fn rewind(&mut self, _: u64, _: &Bitmap) -> Result<(), String> { unimplemented!() }
    fn get_hash(&self, p: u64) -> Option<Hash> { self.get_from_file(p) }
    fn get_data(&self, p: u64) -> Option<OutputIdentifier> { self.get_data_from_file(p) }
    fn get_from_file(&self, p: u64) -> Option<Hash> { if self.gone.contains(&p) { None } else { self.inner.get_from_file(p) } }
    fn get_peak_from_file(&self, p: u64) -> Option<Hash> { self.get_from_file(p) }
    fn get_data_from_file(&self, p: u64) -> Option<OutputIdentifier> { if self.gone.contains(&p) { None } else { self.inner.get_data_from_file(p) } }
    fn leaf_pos_iter(&self) -> Box<dyn Iterator<Item = u64> + '_> { unimplemented!() }
    fn n_unpruned_leaves(&self) -> u64 { unimplemented!() }
    fn n_unpruned_leaves_to_index(&self, _: u64) -> u64 { unimplemented!() }
    fn leaf_idx_iter(&self, _: u64) -> Box<dyn Iterator<Item = u64> + '_> { unimplemented!() }
    fn remove(&mut self, _: u64) -> Result<(), String> { unimplemented!() }
    fn remove_from_leaf_set(&mut self, _: u64) { unimplemented!() }
    fn release_files(&mut self) {}
    fn reset_prune_list(&mut self) {}
    fn snapshot(&self, _: &BlockHeader) -> Result<(), String> { Ok(()) }
    fn dump_stats(&self) {}
}


pub fn block(h: &BlockHeader, outs: &[OutputIdentifier], ins: &[OutputIdentifier]) -> core::Block {
    use grin_core::core::{CommitWrapper, Output, TransactionBody};
    let outputs: Vec<Output> = outs.iter().map(|o| Output { identifier: *o, proof: {
        // Realistic length; content is irrelevant to output_root.
        let mut p = RangeProof::zero();
        p.plen = grin_util::secp::constants::SINGLE_BULLET_PROOF_SIZE;
        p
    } }).collect();
    let inputs: Vec<CommitWrapper> = ins.iter().map(|o| o.commit.into()).collect();
    let body = TransactionBody::init(Inputs::CommitOnly(inputs), &outputs, &[], false).unwrap();
    core::Block { header: h.clone(), body }
}

/// A chain with `n` outputs of which every `spend_every`-th is spent.
pub fn reference(n: u32, spend_every: u32) -> Reference {
    let mut r = Reference::new();
    let outs: Vec<_> = (0..n).map(id).collect();
    r.apply(&outs, &[]);
    let spend: Vec<_> = (0..n).filter(|i| i % spend_every == 0).map(id).collect();
    r.apply(&[id(n + 1_000_000)], &spend);
    r
}
