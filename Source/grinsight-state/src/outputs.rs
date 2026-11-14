//! Local output (UTXO) state rebuilt from PIBD segments and advanced by
//! block bodies; kernel MMR peaks; bundles for offline replay; proofs that a
//! block range hides or invents no spend. No networking: the P2P side only
//! fetches segments and blocks and hands them to these types.

use crate::mmr;
use croaring::{Bitmap, Portable};
#[cfg(feature = "web")]
use crate::bitmap::{BitmapAccumulator, BitmapChunk, BitmapSegment};
#[cfg(not(feature = "web"))]
use grin_chain::txhashset::{BitmapAccumulator, BitmapChunk, BitmapSegment};
use grin_core::core::hash::{Hash, Hashed};
use grin_core::global;
use grin_core::core::{self, committed::Committed, pmmr, BlockHeader, HeaderVersion, Inputs, Output, OutputIdentifier, Segment, SegmentIdentifier, TransactionBody, TxKernel};
use grin_core::ser::{self, PMMRIndexHashable, PMMRable, ProtocolVersion};
use grin_util::secp::pedersen::{Commitment, RangeProof};
use grin_util::static_secp_instance;
use std::collections::{BTreeMap, HashMap};
use std::io::Read;

/// Kernel segments: one (the last) is enough to learn every kernel MMR peak.
pub const KERNEL_SEGMENT_HEIGHT: u8 = 11;

pub const MAX_BUNDLE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub const MAX_GAP_HEADERS: usize = 20_000;

// ---------------------------------------------------------------------------
// Local output state: leaf set, UTXO index, PMMR peaks, bitmap accumulator
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct OutputState {
    pub size: u64,
    pub peaks: Vec<(u64, Hash)>, // (pos0, hash), left -> right
    pub leaves: Bitmap,          // unspent leaf insertion indices
    pub utxo: HashMap<[u8; 33], (u64, OutputIdentifier)>,
    pub acc: BitmapAccumulator,
    /// Maximal subtrees without any unspent leaf: (pos0, hash). Together
    /// with the unspent leaf data they determine every peak, so a saved
    /// state is checked against a header without trusting the file.
    pub pruned: BTreeMap<u64, Hash>,
    /// Kernel MMR peaks, when known (from the archive's last kernel segment).
    pub kern: Option<KernelPeaks>,
    /// Rangeproof MMR peaks (same size as the output MMR), checked against
    /// `range_proof_root` at the archive and after every block.
    pub rproof: Option<KernelPeaks>,
    /// The archive this state grew from passed the full-node archive check
    /// (`verify_archive_state`: every UTXO rangeproof, every kernel signature,
    /// kernel_root, emission). Kept in the saved file (`VFY1`); a state
    /// without it (older versions) is not reused: it is rebuilt once.
    pub verified: bool,
}

/// Append a leaf hash to an MMR given only by its peaks (grin PMMR::push).
pub fn mmr_append(peaks: &mut Vec<(u64, Hash)>, size: &mut u64, leaf_hash: Hash) -> u64 {
    let pos0 = *size;
    let mut node = (pos0, leaf_hash);
    *size += 1;
    loop {
        let ht = pmmr::bintree_postorder_height(node.0);
        match peaks.last() {
            Some(&(lp, lh)) if pmmr::bintree_postorder_height(lp) == ht => {
                peaks.pop();
                let parent = *size;
                node = (parent, (lh, node.1).hash_with_index(parent));
                *size += 1;
            }
            _ => break,
        }
    }
    peaks.push(node);
    pos0
}

/// Kernel MMR known only by its peaks, checked against `kernel_root`.
#[derive(Clone, Debug, PartialEq)]
pub struct KernelPeaks {
    pub size: u64,
    pub peaks: Vec<(u64, Hash)>,
}

impl KernelPeaks {
    pub fn root(&self) -> Hash {
        bag(&self.peaks, self.size)
    }
    pub fn append(&mut self, k: &TxKernel) {
        let pos0 = self.size;
        mmr_append(&mut self.peaks, &mut self.size, k.hash_with_index(pos0));
    }
    /// Append one rangeproof (the rangeproof MMR uses the same peak form).
    pub fn append_rproof(&mut self, p: &RangeProof) {
        let pos0 = self.size;
        mmr_append(&mut self.peaks, &mut self.size, p.hash_with_index(pos0));
    }
    /// Peaks read from a state file must sit exactly where an MMR of `size` has them.
    fn check_shape(&self, size: u64, root: Hash) -> bool {
        self.size == size && self.peaks.iter().map(|x| x.0).collect::<Vec<_>>() == pmmr::peaks(size) && self.root() == root
    }

    /// All peaks of the kernel MMR at `header`, from its LAST kernel segment.
    /// The segment is validated by grin (`Segment::validate` against
    /// `kernel_root`); its proof carries the sibling path to the enclosing peak
    /// and the hashes of every peak to the left. The rebuilt peaks must bag to
    /// `kernel_root` again, so a wrong reconstruction cannot pass.
    pub fn from_last_segment(header: &BlockHeader, seg: &Segment<TxKernel>) -> Result<Self, String> {
        let size = header.kernel_mmr_size;
        let id = seg.identifier();
        if id.height != KERNEL_SEGMENT_HEIGHT
            || id.idx + 1 != SegmentIdentifier::count_segments_required(size, KERNEL_SEGMENT_HEIGHT) as u64
        {
            return Err("not the last kernel segment".into());
        }
        seg.validate(size, None, header.kernel_root).map_err(|e| format!("kernel segment: {e:?}"))?;
        let (first, last) = seg.segment_pos_range(size);
        let data: HashMap<u64, &TxKernel> = seg.leaf_iter().collect();
        let mut nodes: HashMap<u64, Hash> = HashMap::new();
        let mut stack: Vec<Hash> = Vec::new();
        for pos0 in first..=last {
            let ht = pmmr::bintree_postorder_height(pos0);
            let h = if ht == 0 {
                data.get(&pos0).ok_or(format!("kernel leaf missing at {pos0}"))?.hash_with_index(pos0)
            } else {
                let r = stack.pop().ok_or("kernel stack")?;
                let l = stack.pop().ok_or("kernel stack")?;
                (l, r).hash_with_index(pos0)
            };
            nodes.insert(pos0, h);
            stack.push(h);
        }
        let pb = ser::ser_vec(seg.proof(), ProtocolVersion::local()).map_err(|e| format!("{e:?}"))?;
        if pb.len() < 8 {
            return Err("kernel proof too short".into());
        }
        let n = u64::from_be_bytes(pb[..8].try_into().unwrap()) as usize;
        if pb.len() != 8 + 32 * n {
            return Err("kernel proof length".into());
        }
        let mut proof = (0..n).map(|i| Hash::from_vec(&pb[8 + 32 * i..8 + 32 * i + 32]));
        let all = pmmr::peaks(size);
        let mut inner: Vec<(u64, Hash)> = all.iter().filter(|&&p| p >= first && p <= last).map(|&p| (p, nodes[&p])).collect();
        let fb = pmmr::family_branch(last, size);
        if !fb.is_empty() {
            let mut cur = nodes[&last];
            for &(parent, sib) in &fb {
                let sh = proof.next().ok_or("kernel proof: missing sibling")?;
                cur = if pmmr::is_left_sibling(sib) { (sh, cur) } else { (cur, sh) }.hash_with_index(parent);
            }
            inner.push((fb.last().unwrap().0, cur));
        }
        let mut left: Vec<(u64, Hash)> = Vec::new();
        for &p in all.iter().filter(|&&x| x < first).rev() {
            left.push((p, proof.next().ok_or("kernel proof: missing left peak")?));
        }
        if proof.next().is_some() {
            return Err("kernel proof has unexpected hashes (not the last segment?)".into());
        }
        left.reverse();
        left.extend(inner);
        let kp = KernelPeaks { size, peaks: left };
        if kp.peaks.iter().map(|x| x.0).collect::<Vec<_>>() != all || kp.root() != header.kernel_root {
            return Err("rebuilt kernel peaks do not match kernel_root".into());
        }
        Ok(kp)
    }
}

/// Height at which the output at `pos0` was created, from the output MMR
/// sizes of the verified headers. `Err(h)`: created at or before height `h`
/// (older than the first header available).
pub fn creation_height(pos0: u64, headers: &[BlockHeader]) -> Result<u64, u64> {
    let first = &headers[0];
    if pos0 < first.output_mmr_size {
        return Err(first.height);
    }
    let i = headers.partition_point(|h| h.output_mmr_size <= pos0);
    headers.get(i).map(|h| h.height).ok_or(u64::MAX)
}

pub fn tk<'a>(raw: &'a [u8], off: &mut usize, n: usize) -> Result<&'a [u8], String> {
    let end = off.checked_add(n).filter(|&e| e <= raw.len()).ok_or("state file truncated")?;
    let v = &raw[*off..end];
    *off = end;
    Ok(v)
}

/// Leaf-index range covered by the subtree rooted at `pos0`.
pub fn subtree_leaf_range(pos0: u64) -> (u64, u64) {
    (leaf_idx(pmmr::bintree_leftmost(pos0)), leaf_idx(pmmr::bintree_rightmost(pos0)))
}

/// Recompute a node hash from unspent leaf data and the pruned-subtree set.
pub fn node_hash(
    pos0: u64,
    leaves: &Bitmap,
    data: &dyn Fn(u64) -> Option<OutputIdentifier>,
    pruned: &BTreeMap<u64, Hash>,
) -> Result<Hash, String> {
    if let Some(h) = pruned.get(&pos0) {
        return Ok(*h);
    }
    let ht = pmmr::bintree_postorder_height(pos0);
    if ht == 0 {
        let li = leaf_idx(pos0);
        if li > u32::MAX as u64 || !leaves.contains(li as u32) {
            return Err(format!("spent leaf {pos0} without a pruned-subtree hash"));
        }
        return data(pos0).map(|d| d.hash_with_index(pos0)).ok_or(format!("leaf data missing at {pos0}"));
    }
    let l = node_hash(pos0 - (1 << ht), leaves, data, pruned)?;
    let r = node_hash(pos0 - 1, leaves, data, pruned)?;
    Ok((l, r).hash_with_index(pos0))
}

/// Maximal pruned subtrees under `pos0`, hashes taken from `nodes`.
pub fn collect_pruned(pos0: u64, leaves: &Bitmap, nodes: &HashMap<u64, Hash>, out: &mut BTreeMap<u64, Hash>) -> Result<(), String> {
    let (lo, hi) = subtree_leaf_range(pos0);
    if lo > u32::MAX as u64 || hi > u32::MAX as u64 {
        return Err("leaf index exceeds u32".into());
    }
    if leaves.range_cardinality(lo as u32..=hi as u32) == 0 {
        // Segments carry hashes up to their own root; higher pruned nodes
        // are recomputed from their children.
        fn hash_at(pos0: u64, nodes: &HashMap<u64, Hash>) -> Result<Hash, String> {
            if let Some(h) = nodes.get(&pos0) {
                return Ok(*h);
            }
            let ht = pmmr::bintree_postorder_height(pos0);
            if ht == 0 {
                return Err(format!("pruned subtree hash unavailable at {pos0}"));
            }
            Ok((hash_at(pos0 - (1 << ht), nodes)?, hash_at(pos0 - 1, nodes)?).hash_with_index(pos0))
        }
        out.insert(pos0, hash_at(pos0, nodes)?);
        return Ok(());
    }
    let ht = pmmr::bintree_postorder_height(pos0);
    if ht > 0 {
        collect_pruned(pos0 - (1 << ht), leaves, nodes, out)?;
        collect_pruned(pos0 - 1, leaves, nodes, out)?;
    }
    Ok(())
}

pub fn leaf_idx(pos0: u64) -> u64 {
    pmmr::n_leaves(pos0 + 1) - 1
}

pub fn bag(peaks: &[(u64, Hash)], size: u64) -> Hash {
    let mut res: Option<Hash> = None;
    for (_, peak) in peaks.iter().rev() {
        res = Some(match res {
            None => *peak,
            Some(r) => (*peak, r).hash_with_index(size),
        });
    }
    res.unwrap_or(grin_core::core::hash::ZERO_HASH)
}

/// Per-position hashes of one segment, computed exactly like
/// `Segment::root` in grin-5.5.2 (leaf data is hashed; a provided hash is
/// used only for a pruned sibling or a wholly pruned peak), but returning
/// every computed node instead of only the bagged root.
pub fn segment_nodes<T: PMMRable>(
    seg: &Segment<T>,
    mmr_size: u64,
    bitmap: &Bitmap,
) -> Result<HashMap<u64, Option<Hash>>, String> {
    let (first, last) = seg.segment_pos_range(mmr_size);
    let provided: HashMap<u64, Hash> = seg.hash_iter().collect();
    let data: HashMap<u64, &T> = seg.leaf_iter().collect();
    let get = |pos0: u64| provided.get(&pos0).copied().ok_or(format!("segment hash missing at {pos0}"));
    let mut out: HashMap<u64, Option<Hash>> = HashMap::new();
    let mut stack: Vec<Option<Hash>> = Vec::new();
    for pos0 in first..=last {
        let height = pmmr::bintree_postorder_height(pos0);
        let hash = if height == 0 {
            let idx1 = leaf_idx(pos0);
            let idx2 = if pmmr::is_left_sibling(pos0) { idx1 + 1 } else { idx1 - 1 };
            let needed = bitmap.contains(idx1 as u32) || bitmap.contains(idx2 as u32) || pos0 == mmr_size - 1;
            if needed {
                let d = data.get(&pos0).ok_or(format!("segment leaf missing at {pos0}"))?;
                Some(d.hash_with_index(pos0))
            } else {
                None
            }
        } else {
            let left = pos0 - (1 << height);
            let right = pos0 - 1;
            let r = stack.pop().ok_or("segment stack underflow")?;
            let l = stack.pop().ok_or("segment stack underflow")?;
            match (l, r) {
                (None, None) => None,
                (Some(l), Some(r)) => Some((l, r).hash_with_index(pos0)),
                (None, Some(r)) => Some((get(left)?, r).hash_with_index(pos0)),
                (Some(l), None) => Some((l, get(right)?).hash_with_index(pos0)),
            }
        };
        out.insert(pos0, hash);
        stack.push(hash);
    }
    // Wholly pruned peaks inside a partial segment come from provided hashes.
    for p in pmmr::peaks(mmr_size).into_iter().filter(|&p| p >= first && p <= last) {
        if out.get(&p).copied().flatten().is_none() {
            out.insert(p, Some(get(p)?));
        }
    }
    Ok(out)
}

/// Every peak of a pruned MMR (output or rangeproof MMR, leaf set `leaves`)
/// from ALL its segments, computed like `OutputState::from_segments` does
/// for the output MMR. The caller compares the bagged peaks with the root
/// in the header.
pub fn peaks_from_segments<T: PMMRable>(size: u64, segs: &[Segment<T>], leaves: &Bitmap) -> Result<Vec<(u64, Hash)>, String> {
    let h = segs.first().map(|s| s.identifier().height).ok_or("no segments")?;
    let count = SegmentIdentifier::count_segments_required(size, h) as u64;
    let mut by_idx: BTreeMap<u64, &Segment<T>> = BTreeMap::new();
    for s in segs {
        let id = s.identifier();
        if id.height != h || id.idx >= count || by_idx.insert(id.idx, s).is_some() {
            return Err("segments malformed, duplicated or out of range".into());
        }
    }
    if by_idx.len() as u64 != count {
        return Err(format!("segments {} != expected {count}", by_idx.len()));
    }
    let mut seg_roots: HashMap<u64, Hash> = HashMap::new();
    let mut provided: HashMap<u64, Hash> = HashMap::new();
    let mut low_peaks: HashMap<u64, Hash> = HashMap::new();
    for (_, s) in by_idx {
        let (first, last) = s.segment_pos_range(size);
        let nodes = segment_nodes(s, size, leaves)?;
        let full = pmmr::bintree_postorder_height(last) == h as u64 && last - first + 1 == (2u64 << h) - 1;
        if full {
            match nodes.get(&last).copied().flatten() {
                Some(root) => {
                    seg_roots.insert(last, root);
                }
                None => {
                    let (hash, pos1) = s.first_unpruned_parent(size, Some(leaves)).map_err(|e| format!("pruned segment: {e:?}"))?;
                    provided.insert(pos1 - 1, hash);
                }
            }
        } else {
            for p in pmmr::peaks(size).into_iter().filter(|&p| p >= first && p <= last) {
                low_peaks.insert(p, nodes.get(&p).copied().flatten().ok_or("partial segment peak missing")?);
            }
        }
    }
    fn compute(pos0: u64, h: u64, seg: &HashMap<u64, Hash>, prov: &HashMap<u64, Hash>) -> Result<Option<Hash>, String> {
        let ht = pmmr::bintree_postorder_height(pos0);
        if ht == h {
            return Ok(seg.get(&pos0).or(prov.get(&pos0)).copied());
        }
        if ht < h {
            return Err("peak below segment height outside the last segment".into());
        }
        let l = compute(pos0 - (1 << ht), h, seg, prov)?;
        let r = compute(pos0 - 1, h, seg, prov)?;
        match (l, r) {
            (Some(l), Some(r)) => Ok(Some((l, r).hash_with_index(pos0))),
            (None, None) => Ok(prov.get(&pos0).copied()),
            _ => Err(format!("missing pruned subtree hash under {pos0}")),
        }
    }
    let mut peaks = Vec::new();
    for p in pmmr::peaks(size) {
        let hash = if pmmr::bintree_postorder_height(p) >= h as u64 {
            compute(p, h as u64, &seg_roots, &provided)?.ok_or(format!("peak {p} unavailable"))?
        } else {
            *low_peaks.get(&p).ok_or(format!("peak {p} unavailable"))?
        };
        peaks.push((p, hash));
    }
    Ok(peaks)
}

/// Synthetic chains (tests, `testkit`): the placeholder rangeproof every
/// synthetic output carries, and the rangeproof MMR peaks of `size` such leaves.
#[cfg(any(test, feature = "testkit"))]
pub fn dummy_rangeproof() -> RangeProof {
    let mut p = RangeProof::zero();
    p.plen = grin_util::secp::constants::SINGLE_BULLET_PROOF_SIZE;
    p
}
#[cfg(any(test, feature = "testkit"))]
pub fn dummy_rproof_peaks(size: u64) -> KernelPeaks {
    let p = dummy_rangeproof();
    let mut r = KernelPeaks { size: 0, peaks: vec![] };
    while r.size < size {
        r.append_rproof(&p);
    }
    r
}

/// Rangeproof MMR peaks at `archive` from all its rangeproof segments; they
/// must bag to the header's `range_proof_root`.
pub fn rproof_peaks_at_archive(archive: &BlockHeader, segs: &[Segment<RangeProof>], leaves: &Bitmap) -> Result<KernelPeaks, String> {
    let rp = KernelPeaks { size: archive.output_mmr_size, peaks: peaks_from_segments(archive.output_mmr_size, segs, leaves)? };
    if rp.root() != archive.range_proof_root {
        return Err("rebuilt rangeproof peaks do not match range_proof_root".into());
    }
    Ok(rp)
}

impl OutputState {
    /// Rebuild state at `header` from bitmap and output segments. Fails unless
    /// the locally computed merged root equals `header.output_root`.
    pub fn from_segments(
        header: &BlockHeader,
        bitmap_segs: &[Segment<BitmapChunk>],
        output_segs: &[Segment<OutputIdentifier>],
    ) -> Result<Self, String> {
        if header.version < HeaderVersion(3) {
            return Err("header version < 3 does not commit to the bitmap".into());
        }
        let size = header.output_mmr_size;
        let n = pmmr::n_leaves(size);
        if n == 0 || n > u32::MAX as u64 {
            return Err("unsupported output MMR size".into());
        }

        // Bitmap: chunks must be contiguous from 0; appended raw, as PIBD does.
        let mut chunks: BTreeMap<u64, BitmapChunk> = BTreeMap::new();
        for s in bitmap_segs {
            for (pos0, c) in s.leaf_iter() {
                if !pmmr::is_leaf(pos0) || chunks.insert(leaf_idx(pos0), c.clone()).is_some() {
                    return Err("bitmap segments overlap or are malformed".into());
                }
            }
        }
        let want_chunks = n.div_ceil(1024);
        if chunks.len() as u64 != want_chunks || chunks.keys().enumerate().any(|(i, k)| i as u64 != *k) {
            return Err(format!("bitmap chunks {} != expected {want_chunks} or not contiguous", chunks.len()));
        }
        let mut acc = BitmapAccumulator::new();
        let mut leaves = Bitmap::new();
        for (ci, c) in &chunks {
            acc.append_chunk(c.clone()).map_err(|e| format!("bitmap append: {e:?}"))?;
            let bits: Vec<u32> = c.set_iter((*ci as usize) * 1024).collect();
            leaves.add_many(&bits);
        }
        if leaves.maximum().map_or(false, |m| m as u64 >= n) {
            return Err("bitmap sets bits beyond the output MMR".into());
        }

        // Output segments: uniform height, exactly 0..count.
        let h = output_segs.first().map(|s| s.identifier().height).ok_or("no output segments")?;
        let count = SegmentIdentifier::count_segments_required(size, h) as u64;
        let mut by_idx: BTreeMap<u64, &Segment<OutputIdentifier>> = BTreeMap::new();
        for s in output_segs {
            let id = s.identifier();
            if id.height != h || id.idx >= count || by_idx.insert(id.idx, s).is_some() {
                return Err("output segments malformed, duplicated or out of range".into());
            }
        }
        if by_idx.len() as u64 != count {
            return Err(format!("output segments {} != expected {count}", by_idx.len()));
        }

        let mut seg_roots: HashMap<u64, Hash> = HashMap::new();
        let mut provided: HashMap<u64, Hash> = HashMap::new();
        let mut low_peaks: HashMap<u64, Hash> = HashMap::new();
        let mut utxo: HashMap<[u8; 33], (u64, OutputIdentifier)> = HashMap::new();
        let mut all_nodes: HashMap<u64, Hash> = HashMap::new();
        for (_, s) in by_idx {
            let (first, last) = s.segment_pos_range(size);
            let nodes = segment_nodes(s, size, &leaves)?;
            all_nodes.extend(nodes.iter().filter_map(|(p, h)| h.map(|h| (*p, h))));
            all_nodes.extend(s.hash_iter());
            for (pos0, id) in s.leaf_iter() {
                if pos0 < first || pos0 > last {
                    return Err("segment leaf outside its range".into());
                }
                if leaves.contains(leaf_idx(pos0) as u32) && utxo.insert(id.commit.0, (pos0, *id)).is_some() {
                    return Err("duplicate unspent commitment".into());
                }
            }
            let full = pmmr::bintree_postorder_height(last) == h as u64 && last - first + 1 == (2u64 << h) - 1;
            if full {
                match nodes.get(&last).copied().flatten() {
                    Some(root) => {
                        seg_roots.insert(last, root);
                    }
                    None => {
                        let (hash, pos1) = s
                            .first_unpruned_parent(size, Some(&leaves))
                            .map_err(|e| format!("pruned segment: {e:?}"))?;
                        provided.insert(pos1 - 1, hash);
                        all_nodes.insert(pos1 - 1, hash);
                    }
                }
            } else {
                for p in pmmr::peaks(size).into_iter().filter(|&p| p >= first && p <= last) {
                    low_peaks.insert(p, nodes.get(&p).copied().flatten().ok_or("partial segment peak missing")?);
                }
            }
        }
        if utxo.len() as u64 != leaves.cardinality() {
            return Err(format!("unspent leaves {} but leaf data for {}", leaves.cardinality(), utxo.len()));
        }

        fn compute(pos0: u64, h: u64, seg: &HashMap<u64, Hash>, prov: &HashMap<u64, Hash>) -> Result<Option<Hash>, String> {
            let ht = pmmr::bintree_postorder_height(pos0);
            if ht == h {
                return Ok(seg.get(&pos0).or(prov.get(&pos0)).copied());
            }
            if ht < h {
                return Err("peak below segment height outside the last segment".into());
            }
            let l = compute(pos0 - (1 << ht), h, seg, prov)?;
            let r = compute(pos0 - 1, h, seg, prov)?;
            match (l, r) {
                (Some(l), Some(r)) => Ok(Some((l, r).hash_with_index(pos0))),
                (None, None) => Ok(prov.get(&pos0).copied()),
                _ => Err(format!("missing pruned subtree hash under {pos0}")),
            }
        }
        let mut peaks = Vec::new();
        for p in pmmr::peaks(size) {
            let hash = if pmmr::bintree_postorder_height(p) >= h as u64 {
                compute(p, h as u64, &seg_roots, &provided)?.ok_or(format!("peak {p} unavailable"))?
            } else {
                *low_peaks.get(&p).ok_or(format!("peak {p} unavailable"))?
            };
            peaks.push((p, hash));
        }
        let mut pruned = BTreeMap::new();
        for (p, _) in &peaks {
            collect_pruned(*p, &leaves, &all_nodes, &mut pruned)?;
        }
        let state = OutputState { size, peaks, leaves, utxo, acc, pruned, kern: None, rproof: None, verified: false };
        if state.output_root() != header.output_root {
            return Err("rebuilt output state does not match archive output_root".into());
        }
        // The compact form (leaf data + pruned subtrees) must reproduce the peaks.
        if state.peaks_from_parts()? != state.peaks {
            return Err("pruned-subtree set does not reproduce the peaks".into());
        }
        Ok(state)
    }

    pub fn data_by_pos(&self) -> HashMap<u64, OutputIdentifier> {
        self.utxo.values().map(|(p, id)| (*p, *id)).collect()
    }

    pub fn peaks_from_parts(&self) -> Result<Vec<(u64, Hash)>, String> {
        let by_pos = self.data_by_pos();
        let data = |p: u64| by_pos.get(&p).copied();
        pmmr::peaks(self.size)
            .into_iter()
            .map(|p| node_hash(p, &self.leaves, &data, &self.pruned).map(|h| (p, h)))
            .collect()
    }

    pub fn pruned_count(&self) -> usize {
        self.pruned.len()
    }

    // ---- persistence -----------------------------------------------------
    //
    // UST1 | header len u32 + bytes | size u64 | leaves (roaring, len u32 +
    // bytes) | leaf data: one 34-byte OutputIdentifier per set bit, in
    // index order | pruned: count u32 + (pos u64, hash 32)*. Everything is
    // re-derived and checked against `header.output_root` on load, so the
    // file itself is not trusted.

    pub fn save(&self, path: &str, header: &BlockHeader) -> Result<(), String> {
        let out = self.to_bytes(header)?;
        let tmp = format!("{path}.tmp");
        std::fs::write(&tmp, &out).map_err(|e| format!("write {tmp}: {e}"))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("rename {tmp}: {e}"))?;
        Ok(())
    }

    /// The state file contents (see `save`).
    pub fn to_bytes(&self, header: &BlockHeader) -> Result<Vec<u8>, String> {
        if header.output_mmr_size != self.size || header.output_root != self.output_root() {
            return Err("state does not match the header it is saved under".into());
        }
        let pv = ProtocolVersion::local();
        let mut out = b"UST1".to_vec();
        let hb = ser::ser_vec(header, pv).map_err(|e| format!("{e:?}"))?;
        out.extend_from_slice(&(hb.len() as u32).to_le_bytes());
        out.extend_from_slice(&hb);
        out.extend_from_slice(&self.size.to_le_bytes());
        let lb = self.leaves.serialize::<Portable>();
        out.extend_from_slice(&(lb.len() as u32).to_le_bytes());
        out.extend_from_slice(&lb);
        let by_pos = self.data_by_pos();
        for li in self.leaves.iter() {
            let id = by_pos.get(&pmmr::insertion_to_pmmr_index(li as u64)).ok_or("leaf data missing on save")?;
            let b = ser::ser_vec(id, pv).map_err(|e| format!("{e:?}"))?;
            if b.len() != 34 {
                return Err("unexpected output identifier size".into());
            }
            out.extend_from_slice(&b);
        }
        out.extend_from_slice(&(self.pruned.len() as u32).to_le_bytes());
        for (p, h) in &self.pruned {
            out.extend_from_slice(&p.to_le_bytes());
            out.extend_from_slice(h.as_bytes());
        }
        if let Some(k) = &self.kern {
            if k.size != header.kernel_mmr_size || k.root() != header.kernel_root {
                return Err("kernel peaks do not match the header they are saved under".into());
            }
            out.extend_from_slice(b"KRN1");
            out.extend_from_slice(&k.size.to_le_bytes());
            out.extend_from_slice(&(k.peaks.len() as u32).to_le_bytes());
            for (p, h) in &k.peaks {
                out.extend_from_slice(&p.to_le_bytes());
                out.extend_from_slice(h.as_bytes());
            }
            if let Some(r) = &self.rproof {
                if !r.check_shape(header.output_mmr_size, header.range_proof_root) {
                    return Err("rangeproof peaks do not match the header they are saved under".into());
                }
                out.extend_from_slice(b"RPF1");
                out.extend_from_slice(&r.size.to_le_bytes());
                out.extend_from_slice(&(r.peaks.len() as u32).to_le_bytes());
                for (p, h) in &r.peaks {
                    out.extend_from_slice(&p.to_le_bytes());
                    out.extend_from_slice(h.as_bytes());
                }
            }
            if self.verified && self.rproof.is_some() {
                out.extend_from_slice(b"VFY1");
            }
        }
        Ok(out)
    }

    /// Returns the header the state was saved under; the caller must check
    /// that header against its own trusted chain before using the state.
    pub fn load(path: &str) -> Result<(Self, BlockHeader), String> {
        let f = std::fs::File::open(path).map_err(|e| format!("open {path}: {e}"))?;
        let mut raw = Vec::new();
        f.take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut raw).map_err(|e| e.to_string())?;
        Self::from_bytes(&raw)
    }

    /// `load` from the file contents; the same checks.
    pub fn from_bytes(raw: &[u8]) -> Result<(Self, BlockHeader), String> {
        let raw = raw.to_vec();
        if raw.len() as u64 > MAX_BUNDLE_BYTES || raw.len() < 16 || &raw[..4] != b"UST1" {
            return Err("invalid state file".into());
        }
        let mut off = 4usize;
        let hl = u32::from_le_bytes(tk(&raw, &mut off, 4)?.try_into().unwrap()) as usize;
        if hl == 0 || hl > 4096 {
            return Err("state header length".into());
        }
        let hb = tk(&raw, &mut off, hl)?;
        let mut hi = hb;
        let header: BlockHeader = ser::deserialize_default(&mut hi).map_err(|e| format!("state header: {e:?}"))?;
        if !hi.is_empty() {
            return Err("state header trailing bytes".into());
        }
        let size = u64::from_le_bytes(tk(&raw, &mut off, 8)?.try_into().unwrap());
        if size != header.output_mmr_size {
            return Err("state size differs from header".into());
        }
        let n = pmmr::n_leaves(size);
        if n == 0 || n > u32::MAX as u64 {
            return Err("unsupported output MMR size".into());
        }
        let ll = u32::from_le_bytes(tk(&raw, &mut off, 4)?.try_into().unwrap()) as usize;
        let leaves = Bitmap::try_deserialize::<Portable>(tk(&raw, &mut off, ll)?).ok_or("state leaf bitmap")?;
        if leaves.maximum().map_or(false, |m| m as u64 >= n) {
            return Err("state bitmap exceeds MMR".into());
        }
        let count = leaves.cardinality() as usize;
        let mut utxo: HashMap<[u8; 33], (u64, OutputIdentifier)> = HashMap::with_capacity(count);
        for li in leaves.iter() {
            let mut b = tk(&raw, &mut off, 34)?;
            let id: OutputIdentifier = ser::deserialize_default(&mut b).map_err(|e| format!("state leaf: {e:?}"))?;
            let pos0 = pmmr::insertion_to_pmmr_index(li as u64);
            if utxo.insert(id.commit.0, (pos0, id)).is_some() {
                return Err("duplicate commitment in state".into());
            }
        }
        let pc = u32::from_le_bytes(tk(&raw, &mut off, 4)?.try_into().unwrap()) as usize;
        let mut pruned = BTreeMap::new();
        for _ in 0..pc {
            let p = u64::from_le_bytes(tk(&raw, &mut off, 8)?.try_into().unwrap());
            let h = Hash::from_vec(tk(&raw, &mut off, 32)?);
            if p >= size || pruned.insert(p, h).is_some() {
                return Err("state pruned set malformed".into());
            }
        }
        let mut kern = None;
        let mut rproof = None;
        let mut verified = false;
        if off < raw.len() {
            if tk(&raw, &mut off, 4)? != b"KRN1" {
                return Err("state file trailing bytes".into());
            }
            let ksize = u64::from_le_bytes(tk(&raw, &mut off, 8)?.try_into().unwrap());
            let kc = u32::from_le_bytes(tk(&raw, &mut off, 4)?.try_into().unwrap()) as usize;
            if kc > 64 {
                return Err("state kernel peaks malformed".into());
            }
            let mut peaks = Vec::with_capacity(kc);
            for _ in 0..kc {
                let p = u64::from_le_bytes(tk(&raw, &mut off, 8)?.try_into().unwrap());
                peaks.push((p, Hash::from_vec(tk(&raw, &mut off, 32)?)));
            }
            let k = KernelPeaks { size: ksize, peaks };
            if ksize != header.kernel_mmr_size
                || k.peaks.iter().map(|x| x.0).collect::<Vec<_>>() != pmmr::peaks(ksize)
                || k.root() != header.kernel_root
            {
                return Err("saved kernel peaks do not reproduce the header kernel_root".into());
            }
            kern = Some(k);
            let mut tag = if off < raw.len() { Some(tk(&raw, &mut off, 4)?) } else { None };
            if tag == Some(b"RPF1".as_slice()) {
                let rsize = u64::from_le_bytes(tk(&raw, &mut off, 8)?.try_into().unwrap());
                let rc = u32::from_le_bytes(tk(&raw, &mut off, 4)?.try_into().unwrap()) as usize;
                if rc > 64 {
                    return Err("state rangeproof peaks malformed".into());
                }
                let mut peaks = Vec::with_capacity(rc);
                for _ in 0..rc {
                    let p = u64::from_le_bytes(tk(&raw, &mut off, 8)?.try_into().unwrap());
                    peaks.push((p, Hash::from_vec(tk(&raw, &mut off, 32)?)));
                }
                let r = KernelPeaks { size: rsize, peaks };
                if !r.check_shape(header.output_mmr_size, header.range_proof_root) {
                    return Err("saved rangeproof peaks do not reproduce the header range_proof_root".into());
                }
                rproof = Some(r);
                tag = if off < raw.len() { Some(tk(&raw, &mut off, 4)?) } else { None };
            }
            match tag {
                None => {}
                // A state verified before rangeproof peaks were kept (0.4.1) is
                // not "verified" any more: it is rebuilt once.
                Some(t) if t == b"VFY1" => verified = rproof.is_some(),
                Some(_) => return Err("state file trailing bytes".into()),
            }
        }
        if off != raw.len() {
            return Err("state file trailing bytes".into());
        }
        let mut acc = BitmapAccumulator::new();
        acc.init(leaves.iter().map(|x| x as u64), n).map_err(|e| format!("bitmap init: {e:?}"))?;
        let mut st = OutputState { size, peaks: vec![], leaves, utxo, acc, pruned, kern, rproof, verified };
        st.peaks = st.peaks_from_parts()?;
        if st.output_root() != header.output_root {
            return Err("saved state does not reproduce the header output_root".into());
        }
        Ok((st, header))
    }

    pub fn output_root(&self) -> Hash {
        (bag(&self.peaks, self.size), self.acc.root()).hash_with_index(self.size)
    }

    pub fn utxo_count(&self) -> usize {
        self.utxo.len()
    }

    pub fn position(&self, commit: &[u8]) -> Option<u64> {
        let key: [u8; 33] = commit.try_into().ok()?;
        self.utxo.get(&key).map(|x| x.0)
    }

    pub fn push(&mut self, id: &OutputIdentifier) -> u64 {
        let pos0 = self.size;
        mmr_append(&mut self.peaks, &mut self.size, id.hash_with_index(pos0))
    }

    pub fn kernels_tracked(&self) -> bool {
        self.kern.is_some()
    }

    pub fn set_kernels(&mut self, k: KernelPeaks) {
        self.kern = Some(k);
    }

    /// Append a block's kernels (body order, as grin `apply_kernels`).
    pub fn apply_kernels(&mut self, ks: &[TxKernel]) {
        if let Some(k) = self.kern.as_mut() {
            for x in ks {
                k.append(x);
            }
        }
    }

    pub fn rproofs_tracked(&self) -> bool {
        self.rproof.is_some()
    }

    /// Append a block's rangeproofs (output order, as grin `apply_output`).
    pub fn apply_rproofs(&mut self, outs: &[Output]) {
        if let Some(r) = self.rproof.as_mut() {
            for o in outs {
                r.append_rproof(&o.proof);
            }
        }
    }

    /// The rangeproof MMR must match the header (size = output MMR size, root
    /// = range_proof_root). Fails closed without rangeproof peaks.
    pub fn rproofs_match(&self, h: &BlockHeader) -> bool {
        self.rproof.as_ref().map_or(false, |r| r.size == h.output_mmr_size && r.root() == h.range_proof_root)
    }

    /// The kernel MMR must match the header. Fails closed: a state without
    /// kernel peaks cannot show that a block hides or invents no kernel.
    pub fn kernels_match(&self, h: &BlockHeader) -> bool {
        self.kern.as_ref().map_or(false, |k| k.size == h.kernel_mmr_size && k.root() == h.kernel_root)
    }

    /// Grin `UTXOView::verify_coinbase_maturity`: a block at `height` may
    /// spend a coinbase output only if its MMR position (1-based) is at or
    /// below the output MMR size of the header `coinbase_maturity()` blocks
    /// earlier. `history` must hold that header (verified chain, sorted by
    /// height); if it does not, the block is rejected (fail closed).
    pub fn check_coinbase_maturity(&self, inputs: &[Commitment], height: u64, history: &[BlockHeader]) -> Result<(), String> {
        let max_pos1 = inputs
            .iter()
            .filter_map(|c| self.utxo.get(&c.0))
            .filter(|(_, id)| id.features.is_coinbase())
            .map(|(pos0, _)| pos0 + 1)
            .max();
        let Some(pos1) = max_pos1 else { return Ok(()) };
        let m = global::coinbase_maturity();
        if height < m {
            return Err(format!("height {height}: immature coinbase spend"));
        }
        let cutoff = height - m;
        let i = history.partition_point(|h| h.height < cutoff);
        let hdr = history
            .get(i)
            .filter(|h| h.height == cutoff)
            .ok_or_else(|| format!("height {height}: coinbase maturity needs header {cutoff}, not in the verified window"))?;
        if pos1 > hdr.output_mmr_size {
            return Err(format!("height {height}: immature coinbase spend"));
        }
        Ok(())
    }

    /// Apply a block body as grin-5.5.2 `apply_block` does: outputs first,
    /// then inputs (each must be in the UTXO set), then the bitmap
    /// accumulator from the lowest affected chunk.
    pub fn apply_body(&mut self, outputs: &[OutputIdentifier], inputs: &[Commitment]) -> Result<(), String> {
        let mut affected = Vec::with_capacity(outputs.len() + inputs.len());
        for id in outputs {
            if self.utxo.contains_key(&id.commit.0) {
                return Err("output duplicates an unspent commitment".into());
            }
            let pos0 = self.push(id);
            let li = leaf_idx(pos0);
            if li > u32::MAX as u64 {
                return Err("leaf index exceeds u32".into());
            }
            self.leaves.add(li as u32);
            self.utxo.insert(id.commit.0, (pos0, *id));
            affected.push(li);
        }
        for c in inputs {
            let (pos0, id) = self.utxo.remove(&c.0).ok_or("input is not in the UTXO set")?;
            let li = leaf_idx(pos0);
            self.leaves.remove(li as u32);
            affected.push(li);
            // Merge the now-pruned leaf upward while its sibling is pruned too.
            let mut cur = pos0;
            let mut h = id.hash_with_index(pos0);
            self.pruned.insert(cur, h);
            loop {
                let (parent, sib) = pmmr::family(cur);
                if parent >= self.size {
                    break;
                }
                let Some(sh) = self.pruned.remove(&sib) else { break };
                self.pruned.remove(&cur);
                h = if pmmr::is_left_sibling(sib) { (sh, h) } else { (h, sh) }.hash_with_index(parent);
                self.pruned.insert(parent, h);
                cur = parent;
            }
        }
        affected.sort_unstable();
        if let Some(&min) = affected.first() {
            let start = BitmapAccumulator::chunk_start_idx(min) as u32;
            let mut it = self.leaves.iter();
            it.reset_at_or_after(start);
            let n = pmmr::n_leaves(self.size);
            self.acc
                .apply(affected, it.map(|x| x as u64), n)
                .map_err(|e| format!("bitmap apply: {e:?}"))?;
        }
        Ok(())
    }
}

pub fn input_commits(b: &core::Block) -> Vec<Commitment> {
    match b.inputs() {
        Inputs::CommitOnly(v) => v.iter().map(|c| c.commitment()).collect(),
        Inputs::FeaturesAndCommit(v) => v.iter().map(|i| i.commitment()).collect(),
    }
}

pub fn output_ids(b: &core::Block) -> Vec<OutputIdentifier> {
    b.outputs().iter().map(|o| o.identifier).collect()
}

// ---------------------------------------------------------------------------
// Headers, blocks, rate limiting
// ---------------------------------------------------------------------------

pub fn read_headers(path: &str) -> Result<Vec<BlockHeader>, String> {
    let raw = std::fs::read(path).map_err(|e| format!("headers read: {e}"))?;
    if raw.len() < 4 || raw.len() > 64 * 1024 * 1024 {
        return Err("headers file size invalid".into());
    }
    let n = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
    let max = MAX_GAP_HEADERS + crate::balance::COINBASE_MATURITY as usize;
    if n < 2 || n > max {
        return Err(format!("headers count {n} not in 2..={max}"));
    }
    let mut off = 4usize;
    let mut out: Vec<BlockHeader> = Vec::with_capacity(n);
    for i in 0..n {
        let end = off.checked_add(4).filter(|&e| e <= raw.len()).ok_or("headers truncated")?;
        let len = u32::from_le_bytes(raw[off..end].try_into().unwrap()) as usize;
        off = end;
        if len == 0 || len > 4096 {
            return Err(format!("header {i}: bad length"));
        }
        let end = off.checked_add(len).filter(|&e| e <= raw.len()).ok_or("headers truncated")?;
        let h: BlockHeader = ser::deserialize_default(&mut &raw[off..end]).map_err(|e| format!("header {i}: {e:?}"))?;
        off = end;
        if let Some(p) = out.last() {
            if h.height != p.height + 1 || h.prev_hash != p.hash() {
                return Err(format!("header {} does not link to {}", h.height, p.height));
            }
        }
        out.push(h);
    }
    if off != raw.len() {
        return Err("headers file has trailing bytes".into());
    }
    Ok(out)
}


// ---------------------------------------------------------------------------
// Bundle (save / offline replay)
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Bundle {
    pub peers: Vec<String>,
    pub blocks: Vec<Vec<core::Block>>,
    pub bitmap: Vec<Segment<BitmapChunk>>,
    pub output: Vec<Segment<OutputIdentifier>>,
    pub kernel: Option<Segment<TxKernel>>,
    pub rangeproofs: Vec<Segment<RangeProof>>,
    pub kernels: Vec<Segment<TxKernel>>,
}

pub fn rec(out: &mut Vec<u8>, kind: u8, payload: &[u8]) {
    out.push(kind);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
}

pub fn write_bundle(path: &str, b: &Bundle) -> Result<(), String> {
    let pv = ProtocolVersion::local();
    let mut out = b"UGB1".to_vec();
    for (i, p) in b.peers.iter().enumerate() {
        let mut v = vec![i as u8];
        v.extend_from_slice(p.as_bytes());
        rec(&mut out, 4, &v);
        for blk in &b.blocks[i] {
            let mut v = vec![i as u8];
            v.extend(ser::ser_vec(blk, pv).map_err(|e| format!("{e:?}"))?);
            rec(&mut out, 3, &v);
        }
    }
    for s in &b.bitmap {
        rec(&mut out, 1, &ser::ser_vec(&BitmapSegment::from(s.clone()), pv).map_err(|e| format!("{e:?}"))?);
    }
    for s in &b.output {
        rec(&mut out, 2, &ser::ser_vec(s, pv).map_err(|e| format!("{e:?}"))?);
    }
    if let Some(k) = &b.kernel {
        rec(&mut out, 5, &ser::ser_vec(k, pv).map_err(|e| format!("{e:?}"))?);
    }
    for s in &b.rangeproofs {
        rec(&mut out, 6, &ser::ser_vec(s, pv).map_err(|e| format!("{e:?}"))?);
    }
    for s in &b.kernels {
        rec(&mut out, 7, &ser::ser_vec(s, pv).map_err(|e| format!("{e:?}"))?);
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, &out))
        .map_err(|e| format!("write bundle {path}: {e}"))?;
    println!("GAP_BUNDLE_SAVED={path} bytes={}", out.len());
    Ok(())
}

pub fn read_bundle(path: &str) -> Result<Bundle, String> {
    let f = std::fs::File::open(path).map_err(|e| format!("bundle open: {e}"))?;
    let mut raw = Vec::new();
    f.take(MAX_BUNDLE_BYTES + 1).read_to_end(&mut raw).map_err(|e| format!("bundle read: {e}"))?;
    if raw.len() as u64 > MAX_BUNDLE_BYTES || raw.len() < 4 || &raw[..4] != b"UGB1" {
        return Err("invalid gap bundle".into());
    }
    let mut b = Bundle::default();
    let mut off = 4usize;
    while off < raw.len() {
        let kind = raw[off];
        let end = off.checked_add(5).filter(|&e| e <= raw.len()).ok_or("bundle truncated")?;
        let len = u32::from_le_bytes(raw[off + 1..end].try_into().unwrap()) as usize;
        let pend = end.checked_add(len).filter(|&e| e <= raw.len()).ok_or("bundle truncated")?;
        let p = &raw[end..pend];
        off = pend;
        match kind {
            4 => {
                let i = *p.first().ok_or("bundle peer record empty")? as usize;
                if i != b.peers.len() {
                    return Err("bundle peer order".into());
                }
                b.peers.push(String::from_utf8_lossy(&p[1..]).into_owned());
                b.blocks.push(Vec::new());
            }
            3 => {
                let i = *p.first().ok_or("bundle block record empty")? as usize;
                let blk: core::Block = ser::deserialize_default(&mut &p[1..]).map_err(|e| format!("bundle block: {e:?}"))?;
                b.blocks.get_mut(i).ok_or("bundle block peer")?.push(blk);
            }
            1 => {
                let w: BitmapSegment = ser::deserialize_default(&mut &p[..]).map_err(|e| format!("bundle bitmap: {e:?}"))?;
                b.bitmap.push(w.into_segment().map_err(|e| format!("bundle bitmap shape: {e:?}"))?);
            }
            2 => b.output.push(ser::deserialize_default(&mut &p[..]).map_err(|e| format!("bundle output: {e:?}"))?),
            5 => b.kernel = Some(ser::deserialize_default(&mut &p[..]).map_err(|e| format!("bundle kernel: {e:?}"))?),
            6 => b.rangeproofs.push(ser::deserialize_default(&mut &p[..]).map_err(|e| format!("bundle rangeproof: {e:?}"))?),
            7 => b.kernels.push(ser::deserialize_default(&mut &p[..]).map_err(|e| format!("bundle kernels: {e:?}"))?),
            _ => return Err("unknown bundle record".into()),
        }
    }
    Ok(b)
}

// ---------------------------------------------------------------------------
// Analysis and entry point
// ---------------------------------------------------------------------------

pub fn body_digest(b: &core::Block) -> Hash {
    mmr::blake2b256(&ser::ser_vec(b, ProtocolVersion::local()).unwrap_or_default())
}

pub struct Proven {
    /// Per watched commitment: (spent height, created height, position at tip).
    pub per: Vec<(Option<u64>, Option<u64>, Option<u64>)>,
    /// Per watched kernel excess: height of the block holding it.
    pub kernels: Vec<Option<u64>>,
    /// Outputs unspent at the start and spent in the range: (height, commitment).
    pub sample: Vec<(u64, Commitment)>,
    pub state: OutputState,
}

/// Replay one peer's bodies on a copy of `start` (headers[0] is the start header).
pub fn prove_bodies(start: &OutputState, headers: &[BlockHeader], blocks: &[core::Block], commits: &[Vec<u8>]) -> Result<Proven, String> {
    prove_bodies_k(start, headers, blocks, commits, &[])
}

pub fn prove_bodies_k(start: &OutputState, headers: &[BlockHeader], blocks: &[core::Block], commits: &[Vec<u8>], excesses: &[Vec<u8>]) -> Result<Proven, String> {
    prove_bodies_hk(start, headers, headers, blocks, commits, excesses)
}

/// `prove_bodies_k` with the verified header `history` (a superset of
/// `headers` reaching `coinbase_maturity()` blocks below `headers[0]`) for the
/// coinbase maturity rule.
pub fn prove_bodies_hk(
    start: &OutputState,
    history: &[BlockHeader],
    headers: &[BlockHeader],
    blocks: &[core::Block],
    commits: &[Vec<u8>],
    excesses: &[Vec<u8>],
) -> Result<Proven, String> {
    let mut st = start.clone();
    let mut kernels: Vec<Option<u64>> = vec![None; excesses.len()];
    let mut per: Vec<(Option<u64>, Option<u64>, Option<u64>)> = vec![(None, None, None); commits.len()];
    let mut sample = Vec::new();
    for (b, h) in blocks.iter().zip(&headers[1..]) {
        if b.header.hash() != h.hash() {
            return Err(format!("block order mismatch at {}", h.height));
        }
        let ins = input_commits(b);
        let outs = output_ids(b);
        for c in &ins {
            if sample.len() < 5 && start.position(&c.0).is_some() {
                sample.push((h.height, *c));
            }
        }
        st.check_coinbase_maturity(&ins, h.height, history)?;
        st.apply_body(&outs, &ins).map_err(|e| format!("height {}: {e}", h.height))?;
        if st.size != h.output_mmr_size || st.output_root() != h.output_root {
            return Err(format!("height {}: output_root mismatch", h.height));
        }
        st.apply_kernels(b.kernels());
        if !st.kernels_match(h) {
            return Err(format!("height {}: kernel_root mismatch", h.height));
        }
        st.apply_rproofs(b.outputs());
        if !st.rproofs_match(h) {
            return Err(format!("height {}: range_proof_root mismatch", h.height));
        }
        for (i, e) in excesses.iter().enumerate() {
            if b.kernels().iter().any(|k| k.excess.0.as_slice() == e.as_slice()) {
                kernels[i] = Some(h.height);
            }
        }
        for (i, c) in commits.iter().enumerate() {
            if outs.iter().any(|o| o.commit.0.as_slice() == c.as_slice()) {
                per[i].1 = Some(h.height);
            }
            if ins.iter().any(|x| x.0.as_slice() == c.as_slice()) {
                per[i].0 = Some(h.height);
            }
        }
    }
    if blocks.len() != headers.len() - 1 {
        return Err("incomplete block range".into());
    }
    for (i, c) in commits.iter().enumerate() {
        per[i].2 = st.position(c);
    }
    Ok(Proven { per, kernels, sample, state: st })
}


/// Block hash (hex) of serialized header bytes, as in a session transcript.
/// `mainnet` selects the chain rules for this thread: header parsing asks
/// for the chain type and grin panics when none is set (the wallet service
/// never sets a global one).
pub fn header_hash_hex(bytes: &[u8], mainnet: bool) -> Option<String> {
    use grin_util::ToHex;
    grin_core::global::set_local_chain_type(if mainnet {
        grin_core::global::ChainTypes::Mainnet
    } else {
        grin_core::global::ChainTypes::Testnet
    });
    let mut r = bytes;
    let h: BlockHeader = ser::deserialize_default(&mut r).ok()?;
    Some(h.hash().to_hex())
}

pub fn header_bytes(h: &BlockHeader) -> Vec<u8> {
    ser::ser_vec(h, ProtocolVersion::local()).unwrap_or_default()
}

/// Height of the header a saved state file is saved under, read from its
/// first bytes only (`UST1`, u32 length, then the header: version u16,
/// height u64 big-endian). None if there is no readable state file.
pub fn saved_state_height(path: &std::path::Path) -> Option<u64> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut b = [0u8; 18];
    f.read_exact(&mut b).ok()?;
    if &b[..4] != b"UST1" {
        return None;
    }
    Some(u64::from_be_bytes(b[10..18].try_into().ok()?))
}

/// Try `state.ust`, then `state.prev.ust`. A state is usable only if the
/// header it was saved under is byte-identical to a header of the trusted
/// chain. Returns (state, index of that header in `headers`).
pub fn load_state(dir: &str, headers: &[BlockHeader]) -> Option<(OutputState, usize)> {
    for name in ["state.ust", "state.prev.ust"] {
        let path = format!("{dir}/{name}");
        if !std::path::Path::new(&path).exists() {
            continue;
        }
        match OutputState::load(&path) {
            Err(e) => println!("GAP_STATE_LOAD={name} REJECTED {e}"),
            Ok((st, _)) if !st.verified => {
                println!("GAP_STATE_LOAD={name} UNVERIFIED (saved before the full archive check; rebuilding once)");
            }
            Ok((st, h)) => {
                let want = header_bytes(&h);
                match headers.iter().position(|x| x.height == h.height && header_bytes(x) == want) {
                    Some(i) => {
                        println!("GAP_STATE_LOAD={name} OK height={} utxo={} pruned={}", h.height, st.utxo_count(), st.pruned_count());
                        return Some((st, i));
                    }
                    None => println!("GAP_STATE_LOAD={name} UNLINKED height={} (not on the verified chain: reorg, or chain window moved)", h.height),
                }
            }
        }
    }
    None
}

pub fn save_state(dir: &str, st: &OutputState, header: &BlockHeader) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("state dir: {e}"))?;
    let cur = format!("{dir}/state.ust");
    let prev = format!("{dir}/state.prev.ust");
    let fresh = format!("{dir}/state.new.ust");
    st.save(&fresh, header)?;
    // Keep the previous snapshot as a fallback for a reorg deeper than one run.
    if std::path::Path::new(&cur).exists() {
        let _ = std::fs::remove_file(&prev);
        std::fs::rename(&cur, &prev).map_err(|e| format!("rotate state: {e}"))?;
    }
    std::fs::rename(&fresh, &cur).map_err(|e| format!("install state: {e}"))?;
    println!("GAP_STATE_SAVED={cur} height={} utxo={} pruned={}", header.height, st.utxo_count(), st.pruned_count());
    Ok(())
}



/// Verifies every rangeproof segment against `range_proof_root` and then
/// verifies each proof against the commitment of its unspent output. This is
/// the archive-level check a full node performs for UTXO rangeproofs.
pub fn verify_archive_rangeproofs(
    archive: &BlockHeader,
    segments: &[Segment<RangeProof>],
    state: &OutputState,
) -> Result<usize, String> {
    const RPROOF_HEIGHT: u8 = 11;
    let expected = SegmentIdentifier::count_segments_required(archive.output_mmr_size, RPROOF_HEIGHT) as u64;
    if expected == 0 {
        return Err("archive has no rangeproof segments".into());
    }
    if segments.len() as u64 != expected {
        return Err(format!("rangeproof segments {} != expected {expected}", segments.len()));
    }

    let mut by_idx: HashMap<u64, &Segment<RangeProof>> = HashMap::new();
    for s in segments {
        let id = s.identifier();
        if id.height != RPROOF_HEIGHT || id.idx >= expected || by_idx.insert(id.idx, s).is_some() {
            return Err("rangeproof segments malformed, duplicated or out of range".into());
        }
        s.validate(archive.output_mmr_size, Some(&state.leaves), archive.range_proof_root)
            .map_err(|e| format!("rangeproof segment {} invalid: {e:?}", id.idx))?;
    }

    let mut proofs: HashMap<u64, RangeProof> = HashMap::new();
    for s in by_idx.values() {
        for (pos0, proof) in s.leaf_iter() {
            if proofs.insert(pos0, proof.clone()).is_some() {
                return Err("duplicate rangeproof leaf".into());
            }
        }
    }

    let mut commits = Vec::with_capacity(state.utxo.len());
    let mut items = Vec::with_capacity(state.utxo.len());
    for (_, (pos0, id)) in &state.utxo {
        let proof = proofs
            .get(pos0)
            .ok_or_else(|| format!("rangeproof missing for unspent output at {pos0}"))?;
        commits.push(id.commit);
        items.push(proof.clone());
    }
    if commits.is_empty() {
        return Err("archive has no unspent outputs to verify".into());
    }
    Output::batch_verify_proofs(&commits, &items)
        .map_err(|e| format!("rangeproof verification failed: {e:?}"))?;
    Ok(commits.len())
}

/// Verifies all kernel segments against `kernel_root`, every kernel signature,
/// and rebuilds the peak set from the last segment.
pub fn verify_archive_kernels(
    archive: &BlockHeader,
    segments: &[Segment<TxKernel>],
 ) -> Result<(KernelPeaks, usize, Commitment), String> {
    const KERNEL_HEIGHT: u8 = KERNEL_SEGMENT_HEIGHT;
    let expected = SegmentIdentifier::count_segments_required(archive.kernel_mmr_size, KERNEL_HEIGHT) as u64;
    if expected == 0 {
        return Err("archive has no kernel segments".into());
    }
    if segments.len() as u64 != expected {
        return Err(format!("kernel segments {} != expected {expected}", segments.len()));
    }

    let mut by_idx: HashMap<u64, &Segment<TxKernel>> = HashMap::new();
    let mut kernels = Vec::new();
    for s in segments {
        let id = s.identifier();
        if id.height != KERNEL_HEIGHT || id.idx >= expected || by_idx.insert(id.idx, s).is_some() {
            return Err("kernel segments malformed, duplicated or out of range".into());
        }
        s.validate(archive.kernel_mmr_size, None, archive.kernel_root)
            .map_err(|e| format!("kernel segment {} invalid: {e:?}", id.idx))?;
        kernels.extend(s.leaf_iter().map(|(_, k)| *k));
    }
    if kernels.is_empty() {
        return Err("archive has no kernels".into());
    }
    TxKernel::batch_sig_verify(&kernels)
        .map_err(|e| format!("kernel signature verification failed: {e:?}"))?;

    let last_idx = *by_idx.keys().max().ok_or("no kernel segments")?;
    let peaks = KernelPeaks::from_last_segment(archive, by_idx[&last_idx])?;
    let secp = static_secp_instance();
    let secp = secp.lock();
    let excess_sum = secp
        .commit_sum(kernels.iter().map(|k| k.excess).collect(), vec![])
        .map_err(|e| format!("kernel excess sum: {e:?}"))?;
    Ok((peaks, kernels.len(), excess_sum))
}


fn collect_rangeproof_leaves(segments: &[Segment<RangeProof>]) -> Result<HashMap<u64, RangeProof>, String> {
    let mut proofs = HashMap::new();
    for s in segments {
        for (pos0, proof) in s.leaf_iter() {
            if proofs.insert(pos0, proof.clone()).is_some() {
                return Err("duplicate rangeproof leaf".into());
            }
        }
    }
    Ok(proofs)
}

fn collect_kernel_leaves(segments: &[Segment<TxKernel>]) -> Vec<TxKernel> {
    let mut kernels = Vec::new();
    for s in segments {
        kernels.extend(s.leaf_iter().map(|(_, k)| *k));
    }
    kernels
}

/// Full-chain emission check at the archive height:
/// sum(UTXO commitments) + total_overage*H = sum(kernel excess) + offset*G.
pub fn verify_emission(
    archive: &BlockHeader,
    state: &OutputState,
    rangeproofs: &[Segment<RangeProof>],
    kernels: &[Segment<TxKernel>],
) -> Result<(), String> {
    let proofs = collect_rangeproof_leaves(rangeproofs)?;
    let mut outputs = Vec::with_capacity(state.utxo.len());
    for (_, (pos0, id)) in &state.utxo {
        let proof = proofs
            .get(pos0)
            .ok_or_else(|| format!("rangeproof missing for unspent output at {pos0}"))?;
        outputs.push(Output::new(id.features, id.commit, proof.clone()));
    }

    let body = TransactionBody {
        inputs: Inputs::default(),
        outputs,
        kernels: collect_kernel_leaves(kernels),
    };
    let genesis_had_reward = global::get_genesis_block().header.kernel_mmr_size > 0;
    let overage = archive.total_overage(genesis_had_reward);
    body.verify_kernel_sums(overage, archive.total_kernel_offset())
        .map_err(|e| format!("emission check failed: {e:?}"))?;
    Ok(())
}
/// Result of a full archive check: UTXO state with roots verified, every
/// rangeproof and kernel signature checked, and kernel peaks retained.
pub struct VerifiedArchive {
    pub state: OutputState,
    pub kernel_peaks: KernelPeaks,
    pub rangeproofs: usize,
    pub kernels: usize,
    pub kernel_excess_sum: Commitment,
}

/// Stage-1 bootstrap core: verifies output/kernel roots, every rangeproof
/// against its UTXO commitment, every kernel signature, and returns the state
/// that can be persisted as the helper's snapshot.
pub fn build_verified_archive_state(
    archive: &BlockHeader,
    bitmap: &[Segment<BitmapChunk>],
    output: &[Segment<OutputIdentifier>],
    rangeproofs: &[Segment<RangeProof>],
    kernels: &[Segment<TxKernel>],
) -> Result<VerifiedArchive, String> {
    let mut state = OutputState::from_segments(archive, bitmap, output)?;
    let rangeproofs_count = verify_archive_rangeproofs(archive, rangeproofs, &state)?;
    let (kernel_peaks, kernels_count, kernel_excess_sum) = verify_archive_kernels(archive, kernels)?;
    // Full-node emission check: the verified UTXO set plus the verified kernel
    // set must balance against the archive header's kernel offset/overage.
    verify_emission(archive, &state, rangeproofs, kernels)?;
    state.rproof = Some(rproof_peaks_at_archive(archive, rangeproofs, &state.leaves)?);
    state.set_kernels(kernel_peaks.clone());
    state.verified = true;
    Ok(VerifiedArchive {
        state,
        kernel_peaks,
        rangeproofs: rangeproofs_count,
        kernels: kernels_count,
        kernel_excess_sum,
    })
}
/// Commitments for the archive-wide emission check: every unspent output on
/// one side, the sum of every kernel excess on the other.
struct ArchiveSums<'a> {
    utxo: Vec<Commitment>,
    excess_sum: &'a Commitment,
}

impl Committed for ArchiveSums<'_> {
    fn inputs_committed(&self) -> Vec<Commitment> {
        Vec::new()
    }
    fn outputs_committed(&self) -> Vec<Commitment> {
        self.utxo.clone()
    }
    fn kernels_committed(&self) -> Vec<Commitment> {
        vec![*self.excess_sum]
    }
}

/// Full-node archive check of a state built from bitmap/output segments (whose
/// output_root is already verified): every UTXO rangeproof (segments against
/// range_proof_root, then each proof against its commitment), every kernel
/// segment against kernel_root and every kernel signature, and the emission
/// sum sum(UTXO) + overage*H = sum(kernel excess) + offset*G. On success the
/// state carries the kernel peaks and is marked verified.
pub fn verify_archive_state(
    archive: &BlockHeader,
    state: &mut OutputState,
    rangeproofs: &[Segment<RangeProof>],
    kernels: &[Segment<TxKernel>],
) -> Result<(usize, usize), String> {
    if state.size != archive.output_mmr_size || state.output_root() != archive.output_root {
        return Err("archive state does not match the archive header".into());
    }
    let n_rp = verify_archive_rangeproofs(archive, rangeproofs, state)?;
    let rp = rproof_peaks_at_archive(archive, rangeproofs, &state.leaves)?;
    let (peaks, n_k, excess_sum) = verify_archive_kernels(archive, kernels)?;
    verify_emission_sums(archive, state, &excess_sum)?;
    state.set_kernels(peaks);
    state.rproof = Some(rp);
    state.verified = true;
    Ok((n_rp, n_k))
}

/// Emission check with the kernel excesses already summed.
pub fn verify_emission_sums(archive: &BlockHeader, state: &OutputState, excess_sum: &Commitment) -> Result<(), String> {
    let sums = ArchiveSums { utxo: state.utxo.values().map(|(_, id)| id.commit).collect(), excess_sum };
    let genesis_had_reward = global::get_genesis_block().header.kernel_mmr_size > 0;
    let overage = archive.total_overage(genesis_had_reward);
    sums.verify_kernel_sums(overage, archive.total_kernel_offset())
        .map_err(|e| format!("emission check failed: {e:?}"))?;
    Ok(())
}

/// The archive UTXO state from its PIBD segments, checked against the archive
/// header's output_root (and kernel_root when the last kernel segment came).
pub fn build_archive_state(archive: &BlockHeader, bundle: &Bundle) -> Result<OutputState, String> {
    println!("GAP_PROVE_SEGMENTS_BITMAP={}\nGAP_PROVE_SEGMENTS_OUTPUT={}", bundle.bitmap.len(), bundle.output.len());
    let mut st = OutputState::from_segments(archive, &bundle.bitmap, &bundle.output)?;
    println!("GAP_PROVE_ARCHIVE_ROOT=VERIFIED height={} utxo={} pruned={}", archive.height, st.utxo_count(), st.pruned_count());
    match bundle.kernel.as_ref().map(|k| KernelPeaks::from_last_segment(archive, k)) {
        Some(Ok(k)) => {
            println!("GAP_PROVE_KERNEL_ROOT=VERIFIED height={} kernel_mmr_size={}", archive.height, archive.kernel_mmr_size);
            st.set_kernels(k);
        }
        Some(Err(e)) => return Err(format!("archive kernel segment: {e}")),
        None => println!("GAP_PROVE_KERNEL_ROOT=NOT_SERVED (kernels not tracked)"),
    }
    Ok(st)
}



/// A block body belongs to the validated header (all header bytes, not just
/// the hash, which in Grin commits only to the PoW nonces) and is valid by
/// consensus (`Block::validate`: rangeproofs, kernel signatures, sums).
pub fn bind_block(hdr: &BlockHeader, prev: Option<&BlockHeader>, b: &core::Block) -> Result<(), String> {
    let want = ser::ser_vec(hdr, ProtocolVersion::local()).map_err(|e| format!("ser header: {e:?}"))?;
    let have = ser::ser_vec(&b.header, ProtocolVersion::local()).map_err(|e| format!("ser header: {e:?}"))?;
    if want != have {
        return Err(format!(
            "block at height {} does not match the validated header (same hash, other fields)",
            b.header.height
        ));
    }
    match prev {
        Some(p) => b
            .validate(&p.total_kernel_offset)
            .map_err(|e| format!("block {} body invalid: {e:?}", b.header.height))?,
        None => b
            .validate_read()
            .map_err(|e| format!("block {} body invalid: {e:?}", b.header.height))?,
    }
    Ok(())
}

impl OutputState {
    /// Apply one block to a copy of the state and return it, only if the
    /// result reproduces the header's output (and, when tracked, kernel)
    /// root: a body that hides or invents a spend cannot pass. `bind_block`
    /// is the separate consensus check of the body itself.
    ///
    /// Without a header `history` (see `apply_block_h`) a coinbase spend
    /// cannot be shown mature, so it is rejected (fail closed).
    pub fn apply_block(&self, header: &BlockHeader, b: &core::Block) -> Result<OutputState, String> {
        self.apply_block_h(header, b, &[])
    }

    /// `apply_block` with the verified headers needed for coinbase maturity
    /// (from `header.height - coinbase_maturity()` on).
    pub fn apply_block_h(&self, header: &BlockHeader, b: &core::Block, history: &[BlockHeader]) -> Result<OutputState, String> {
        if header_bytes(&b.header) != header_bytes(header) {
            return Err(format!("block at height {} is not the given header", header.height));
        }
        let mut st = self.clone();
        st.check_coinbase_maturity(&input_commits(b), header.height, history)?;
        st.apply_body(&output_ids(b), &input_commits(b)).map_err(|e| format!("height {}: {e}", header.height))?;
        if st.size != header.output_mmr_size || st.output_root() != header.output_root {
            return Err(format!("height {}: output_root mismatch", header.height));
        }
        st.apply_kernels(b.kernels());
        if !st.kernels_match(header) {
            return Err(format!("height {}: kernel_root mismatch", header.height));
        }
        st.apply_rproofs(b.outputs());
        if !st.rproofs_match(header) {
            return Err(format!("height {}: range_proof_root mismatch", header.height));
        }
        Ok(st)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headers::*;
    use grin_core::global::{self, ChainTypes};
    use grin_core::pow::Difficulty;
    use std::collections::HashSet;
    use std::time::Instant;
    use grin_util::secp::pedersen::RangeProof;
    /// Same as header-sync gap.rs (bitmap segments a Grin node serves).
    const BITMAP_SEGMENT_HEIGHT: u8 = 9;
    use grin_core::core::pmmr::{ReadablePMMR, ReadonlyPMMR, VecBackend, PMMR};
    use grin_core::core::OutputFeatures;

    fn id(i: u32) -> OutputIdentifier {
        let mut c = [0u8; 33];
        c[0] = 8;
        c[1..5].copy_from_slice(&i.to_be_bytes());
        OutputIdentifier { features: OutputFeatures::Plain, commit: Commitment::from_vec(c.to_vec()) }
    }

    /// Reference chain kept with grin's own structures.
    struct Reference {
        backend: VecBackend<OutputIdentifier>,
        acc: BitmapAccumulator,
        leaves: Bitmap,
        pos: HashMap<[u8; 33], u64>,
    }

    impl Reference {
        fn new() -> Self {
            Reference { backend: VecBackend::new(), acc: BitmapAccumulator::new(), leaves: Bitmap::new(), pos: HashMap::new() }
        }
        fn size(&self) -> u64 {
            self.backend.size()
        }
        /// Apply like grin: outputs, then inputs, then accumulator.
        fn apply(&mut self, outs: &[OutputIdentifier], ins: &[OutputIdentifier]) {
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
        fn header(&self) -> BlockHeader {
            let mut h = BlockHeader::default();
            h.version = HeaderVersion(5);
            h.output_mmr_size = self.size();
            let root = ReadonlyPMMR::at(&self.backend, self.size()).root().unwrap();
            h.output_root = (root, self.acc.root()).hash_with_index(self.size());
            h.range_proof_root = crate::outputs::dummy_rproof_peaks(self.size()).root();
            h
        }
        fn segments(&self, h: u8) -> (Vec<Segment<BitmapChunk>>, Vec<Segment<OutputIdentifier>>) {
            self.segments_from(h, false)
        }
        /// Segments as served by a node whose output PMMR was compacted with
        /// grin-5.5.2 store rules (`pos_to_rm` / `removed_excl_roots`).
        fn compacted_segments(&self, h: u8) -> (Vec<Segment<BitmapChunk>>, Vec<Segment<OutputIdentifier>>) {
            self.segments_from(h, true)
        }
        fn segments_from(&self, h: u8, compact: bool) -> (Vec<Segment<BitmapChunk>>, Vec<Segment<OutputIdentifier>>) {
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

    struct Compacted<'a> {
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

    #[test]
    fn rebuild_matches_grin_after_compaction() {
        global::set_local_chain_type(ChainTypes::Testnet);
        for (n, every, h) in [(7u32, 3u32, 1u8), (3000, 7, 4), (4100, 2, 5), (5000, 1, 4), (6000, 1, 2), (2049, 3, 11)] {
            let r = reference(n, every);
            let (bm, out) = r.compacted_segments(h);
            // The emulated node data must be acceptable to grin's own PIBD check.
            let hd = r.header();
            for s in &out {
                s.validate_with(hd.output_mmr_size, Some(&r.leaves), hd.output_root, hd.output_mmr_size, r.acc.root(), false)
                    .unwrap_or_else(|e| panic!("grin rejects emulated segment n={n} h={h}: {e:?}"));
            }
            let st = OutputState::from_segments(&r.header(), &bm, &out).unwrap_or_else(|e| panic!("n={n} every={every} h={h}: {e}"));
            assert_eq!(st.utxo_count() as u64, r.leaves.cardinality());
        }
        // Mostly spent, long pruned runs: whole segments collapse into one
        // pruned root above segment level.
        let mut r = Reference::new();
        let outs: Vec<_> = (0..4096).map(id).collect();
        r.apply(&outs, &[]);
        let keep = [5u32, 4000];
        let spend: Vec<_> = (0..4096).filter(|i| !keep.contains(i)).map(id).collect();
        r.apply(&[id(77_777_777)], &spend);
        let (bm, out) = r.compacted_segments(3);
        assert!(out.iter().any(|s| s.leaf_iter().count() == 0), "expected fully pruned segments");
        let mut st = OutputState::from_segments(&r.header(), &bm, &out).unwrap();
        assert_eq!(st.utxo_count(), 3);
        // Spend one survivor and continue from the compacted state.
        r.apply(&[id(88_888_888)], &[id(5)]);
        st.apply_body(&[id(88_888_888)], &[id(5).commit]).unwrap();
        assert_eq!(st.output_root(), r.header().output_root);
    }

    fn reference(n: u32, spend_every: u32) -> Reference {
        let mut r = Reference::new();
        let outs: Vec<_> = (0..n).map(id).collect();
        r.apply(&outs, &[]);
        let spend: Vec<_> = (0..n).filter(|i| i % spend_every == 0).map(id).collect();
        r.apply(&[id(n + 1_000_000)], &spend);
        r
    }

    #[test]
    fn rebuild_matches_grin_for_many_shapes() {
        global::set_local_chain_type(ChainTypes::Testnet);
        for (n, every, h) in [(1u32, 2u32, 1u8), (7, 3, 1), (3000, 7, 4), (4100, 2, 5), (2500, 1_000_000, 3), (5000, 1, 4)] {
            let r = reference(n, every);
            let (bm, out) = r.segments(h);
            let st = OutputState::from_segments(&r.header(), &bm, &out).unwrap_or_else(|e| panic!("n={n} every={every} h={h}: {e}"));
            assert_eq!(st.utxo_count() as u64, r.leaves.cardinality(), "n={n}");
            assert_eq!(st.output_root(), r.header().output_root);
        }
    }

    #[test]
    fn applied_bodies_track_grin_roots() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let mut r = reference(3000, 5);
        let (bm, out) = r.segments(4);
        let mut st = OutputState::from_segments(&r.header(), &bm, &out).unwrap();
        // Several "blocks": spend old and fresh outputs, create new ones.
        let mut next = 2_000_000u32;
        for round in 0..20u32 {
            let outs: Vec<_> = (0..(1 + round % 4)).map(|_| { next += 1; id(next) }).collect();
            let candidates: Vec<u32> = (0..3000).filter(|i| i % 5 != 0 && i % 23 == round % 23).take(3).collect();
            let ins: Vec<_> = candidates.iter().map(|&i| id(i)).filter(|o| r.pos.contains_key(&o.commit.0)).collect();
            r.apply(&outs, &ins);
            let commits: Vec<Commitment> = ins.iter().map(|o| o.commit).collect();
            st.apply_body(&outs, &commits).unwrap();
            assert_eq!(st.size, r.size(), "round {round}");
            assert_eq!(st.output_root(), r.header().output_root, "round {round}");
        }
    }

    #[test]
    fn tampering_is_rejected() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let r = reference(3000, 4);
        let h = r.header();
        let (bm, out) = r.segments(4);
        // Changed unspent leaf data.
        let mut o2 = out.clone();
        let (sid, hp, hs, lp, mut ld, pf) = o2[3].clone().parts();
        let k = lp.iter().position(|&p| r.leaves.contains(leaf_idx(p) as u32)).unwrap();
        ld[k] = id(9_999_999);
        o2[3] = Segment::from_parts(sid, hp, hs, lp, ld, pf);
        assert!(OutputState::from_segments(&h, &bm, &o2).is_err());
        // Flipped bitmap bit.
        let mut b2 = bm.clone();
        let (sid, hp, hs, lp, mut ld, pf) = b2[0].clone().parts();
        let cur = ld[0].set_iter(0).any(|x| x == 1);
        ld[0].set(1, !cur);
        b2[0] = Segment::from_parts(sid, hp, hs, lp, ld, pf);
        assert!(OutputState::from_segments(&h, &b2, &out).is_err());
        // Missing segment.
        assert!(OutputState::from_segments(&h, &bm, &out[1..]).is_err());
        // Wrong header.
        let mut h2 = h.clone();
        h2.output_root = Hash::from_vec(&[7; 32]);
        assert!(OutputState::from_segments(&h2, &bm, &out).is_err());
    }

    fn block(h: &BlockHeader, outs: &[OutputIdentifier], ins: &[OutputIdentifier]) -> core::Block {
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

    #[test]
    fn prove_bodies_and_bundle_roundtrip() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let mut r = reference(3000, 4);
        let (bm, out) = r.compacted_segments(5);
        let mut st = OutputState::from_segments(&r.header(), &bm, &out).unwrap();
        // Synthetic bodies carry no kernels: an empty kernel MMR (kernels
        // must be tracked, see `kernels_match`).
        let no_kernels = KernelPeaks { size: 0, peaks: vec![] };
        assert!(st.kernels_match(&r.header()) == false);
        st.set_kernels(no_kernels.clone());
        st.rproof = Some(dummy_rproof_peaks(st.size));
        let mut headers = vec![r.header()];
        let mut honest = vec![];
        let watched = id(1); // unspent at archive (1 % 4 != 0)
        let script: Vec<(Vec<OutputIdentifier>, Vec<OutputIdentifier>)> = vec![
            (vec![id(5_000_001)], vec![id(2)]),
            (vec![id(5_000_002), id(5_000_003)], vec![watched, id(3)]),
            (vec![id(5_000_004)], vec![id(5_000_001)]),
        ];
        for (k, (o, i)) in script.iter().enumerate() {
            // Bodies are sorted on the wire; apply in body order, as grin does.
            let mut b = block(&BlockHeader::default(), o, i);
            let sorted_ins: Vec<OutputIdentifier> =
                input_commits(&b).iter().map(|c| *i.iter().find(|x| x.commit == *c).unwrap()).collect();
            r.apply(&output_ids(&b), &sorted_ins);
            let mut h = r.header();
            h.height = k as u64 + 1;
            h.pow.nonce = k as u64 + 1;
            b.header = h.clone();
            honest.push(b);
            headers.push(h);
        }
        let one = |c: &[u8]| vec![c.to_vec()];
        let p = prove_bodies(&st, &headers, &honest, &one(&watched.commit.0)).unwrap();
        assert_eq!(p.per[0], (Some(2), None, None));
        assert_eq!(p.state.output_root(), headers.last().unwrap().output_root);
        // Sample lists archive outputs spent in the gap, not ones created in it.
        let mut want = vec![(1, id(2).commit), (2, id(3).commit), (2, watched.commit)];
        want.sort_by_key(|x| (x.0, x.1));
        let mut got = p.sample.clone();
        got.sort_by_key(|x| (x.0, x.1));
        assert_eq!(got, want);
        let p = prove_bodies(&st, &headers, &honest, &vec![id(7).commit.0.to_vec(), id(5_000_002).commit.0.to_vec()]).unwrap();
        assert_eq!(p.per[0].0, None);
        assert!(p.per[0].2.is_some());
        assert_eq!((p.per[1].1, p.per[1].0), (Some(2), None));
        assert!(p.per[1].2.is_some());
        // A body hiding the spend of `watched` (replaced by another unspent output).
        let mut lying = honest.clone();
        lying[1] = block(&headers[2], &script[1].0, &[id(5), id(3)]);
        assert!(prove_bodies(&st, &headers, &lying, &one(&watched.commit.0)).err().unwrap().contains("output_root mismatch"));
        // The X+D / Z-D swap: inputs that are not unspent outputs.
        let mut swapped = honest.clone();
        swapped[1] = block(&headers[2], &script[1].0, &[id(9_000_001), id(9_000_002)]);
        assert!(prove_bodies(&st, &headers, &swapped, &one(&watched.commit.0)).err().unwrap().contains("not in the UTXO set"));
        // Missing block.
        assert!(prove_bodies(&st, &headers, &honest[..2], &one(&watched.commit.0)).is_err());

        // Bundle round-trip keeps everything needed for offline replay.
        let dir = std::env::temp_dir().join(format!("gap-bundle-{}", std::process::id()));
        let _ = std::fs::remove_file(&dir);
        let b = Bundle { peers: vec!["a".into(), "b".into()], blocks: vec![honest.clone(), lying.clone()], bitmap: bm.clone(), output: out.clone(), kernel: None, ..Default::default() };
        write_bundle(dir.to_str().unwrap(), &b).unwrap();
        assert!(write_bundle(dir.to_str().unwrap(), &b).is_err(), "must not overwrite");
        let back = read_bundle(dir.to_str().unwrap()).unwrap();
        std::fs::remove_file(&dir).unwrap();
        assert_eq!(back.peers, b.peers);
        assert_eq!(back.blocks[1].iter().map(body_digest).collect::<Vec<_>>(), lying.iter().map(body_digest).collect::<Vec<_>>());
        let mut st2 = OutputState::from_segments(&headers[0], &back.bitmap, &back.output).unwrap();
        st2.set_kernels(no_kernels);
        st2.rproof = Some(dummy_rproof_peaks(st2.size));
        assert_eq!(prove_bodies(&st2, &headers, &back.blocks[0], &one(&watched.commit.0)).unwrap().per[0].0, Some(2));
    }

    /// Floonet-sized timing check (run with --release --ignored).
    #[test]
    #[ignore]
    fn bench_floonet_sized_apply() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let n = 3_427_686u32;
        let mut st = OutputState { size: 0, peaks: vec![], leaves: Bitmap::new(), utxo: HashMap::new(), acc: BitmapAccumulator::new(), pruned: BTreeMap::new(), kern: None, rproof: None, verified: false };
        for i in 0..n {
            let o = id(i);
            let p = st.push(&o);
            if i % 12 == 0 {
                st.leaves.add(leaf_idx(p) as u32);
                st.utxo.insert(o.commit.0, (p, o));
            }
        }
        st.acc.init(st.leaves.iter().map(|x| x as u64), pmmr::n_leaves(st.size)).unwrap();
        let t = Instant::now();
        for k in 0..200u32 {
            // Worst case: every block spends one of the oldest outputs.
            st.apply_body(&[id(n + k)], &[id(k * 12).commit]).unwrap();
        }
        let per = t.elapsed().as_secs_f64() / 200.0;
        eprintln!("BENCH utxo={} per_block_ms={:.2} est_3358_blocks_s={:.0}", st.utxo_count(), per * 1000.0, per * 3358.0);
    }

    #[test]
    fn saved_state_roundtrip_incremental_equals_fresh_and_rejects_tampering() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let mut r = reference(3000, 4);
        let (bm, out) = r.compacted_segments(4);
        let mut st = OutputState::from_segments(&r.header(), &bm, &out).unwrap();
        // Incremental: many blocks with spends that merge pruned subtrees.
        let mut next = 7_000_000u32;
        for round in 0..40u32 {
            let outs: Vec<_> = (0..(1 + round % 3)).map(|_| { next += 1; id(next) }).collect();
            // Spend a disjoint slice of still-unspent outputs each round (75 per round).
            let ins: Vec<_> = (round * 75..round * 75 + 75).map(id).filter(|o| r.pos.contains_key(&o.commit.0)).collect();
            assert!(!ins.is_empty());
            r.apply(&outs, &ins);
            st.apply_body(&outs, &ins.iter().map(|o| o.commit).collect::<Vec<_>>()).unwrap();
        }
        let h = r.header();
        assert_eq!(st.output_root(), h.output_root);
        // Pruned set stays maximal and reproduces the peaks.
        assert_eq!(st.peaks_from_parts().unwrap(), st.peaks);
        for (&p, _) in &st.pruned {
            let (parent, sib) = pmmr::family(p);
            assert!(parent >= st.size || !st.pruned.contains_key(&sib), "non-maximal pruned pair at {p}");
        }
        // Fresh rebuild from segments at the new height has the same compact form.
        let (bm2, out2) = r.compacted_segments(5);
        let fresh = OutputState::from_segments(&h, &bm2, &out2).unwrap();
        assert_eq!(fresh.pruned, st.pruned);
        assert_eq!(fresh.leaves, st.leaves);
        assert_eq!(fresh.utxo_count(), st.utxo_count());

        // Save / load.
        let path = std::env::temp_dir().join(format!("gap-state-{}.ust", std::process::id()));
        let path = path.to_str().unwrap();
        st.save(path, &h).unwrap();
        let (back, hb) = OutputState::load(path).unwrap();
        assert_eq!(ser::ser_vec(&hb, ProtocolVersion::local()).unwrap(), ser::ser_vec(&h, ProtocolVersion::local()).unwrap());
        assert_eq!(back.output_root(), h.output_root);
        assert_eq!(back.pruned, st.pruned);
        assert_eq!(back.utxo_count(), st.utxo_count());
        assert_eq!(back.peaks, st.peaks);
        // Continue from the loaded state.
        let mut back = back;
        r.apply(&[id(9_000_001)], &[id(7_000_001)]);
        back.apply_body(&[id(9_000_001)], &[id(7_000_001).commit]).unwrap();
        assert_eq!(back.output_root(), r.header().output_root);
        // Saving under a header that does not match is refused.
        let mut wrong = h.clone();
        wrong.output_root = Hash::from_vec(&[1; 32]);
        assert!(st.save(path, &wrong).is_err());

        // Tampering: flip a byte in leaf data, in a pruned hash, in the bitmap.
        let raw = std::fs::read(path).unwrap();
        let hl = 4 + 4 + u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
        let ll = u32::from_le_bytes(raw[hl + 8..hl + 12].try_into().unwrap()) as usize;
        let leaf_data_start = hl + 12 + ll;
        for off in [leaf_data_start + 5, raw.len() - 1, hl + 12 + 3] {
            let mut t = raw.clone();
            t[off] ^= 0x01;
            std::fs::write(path, &t).unwrap();
            assert!(OutputState::load(path).is_err(), "tamper at {off} accepted");
        }
        // Truncation and trailing bytes.
        std::fs::write(path, &raw[..raw.len() - 10]).unwrap();
        assert!(OutputState::load(path).is_err());
        let mut t = raw.clone();
        t.push(0);
        std::fs::write(path, &t).unwrap();
        assert!(OutputState::load(path).is_err());
        std::fs::remove_file(path).unwrap();
    }

    fn kern(i: u64) -> TxKernel {
        let mut k = TxKernel::with_features(grin_core::core::KernelFeatures::Plain { fee: grin_core::core::FeeFields::new(0, 1000 + i).unwrap() });
        let mut c = [0u8; 33];
        c[0] = 9;
        c[1..9].copy_from_slice(&i.to_be_bytes());
        k.excess = Commitment::from_vec(c.to_vec());
        k
    }

    fn kernel_ref(n: u64) -> (VecBackend<TxKernel>, BlockHeader) {
        let mut be = VecBackend::<TxKernel>::new();
        for i in 0..n {
            let size = be.size();
            PMMR::at(&mut be, size).push(&kern(i)).unwrap();
        }
        let mut h = BlockHeader::default();
        h.kernel_mmr_size = be.size();
        h.kernel_root = ReadonlyPMMR::at(&be, be.size()).root().unwrap();
        (be, h)
    }

    fn last_kernel_segment(be: &VecBackend<TxKernel>) -> Segment<TxKernel> {
        let size = be.size();
        let idx = SegmentIdentifier::count_segments_required(size, KERNEL_SEGMENT_HEIGHT) as u64 - 1;
        Segment::from_pmmr(SegmentIdentifier { height: KERNEL_SEGMENT_HEIGHT, idx }, &ReadonlyPMMR::at(be, size), false).unwrap()
    }

    #[test]
    fn kernel_peaks_from_last_segment_match_grin() {
        global::set_local_chain_type(ChainTypes::Testnet);
        // Full and partial last segments, segment root a peak or not.
        for n in [1u64, 2, 3, 2047, 2048, 2049, 4096, 6144, 6145, 8192, 10_000, 12_288] {
            let (mut be, h) = kernel_ref(n);
            let seg = last_kernel_segment(&be);
            let mut kp = KernelPeaks::from_last_segment(&h, &seg).unwrap_or_else(|e| panic!("n={n}: {e}"));
            assert_eq!(kp.root(), h.kernel_root, "n={n}");
            // Appending further kernels tracks grin's root.
            for i in n..n + 7 {
                let size = be.size();
                PMMR::at(&mut be, size).push(&kern(i)).unwrap();
                kp.append(&kern(i));
                assert_eq!(kp.root(), ReadonlyPMMR::at(&be, be.size()).root().unwrap(), "n={n} i={i}");
            }
        }
        // Wrong header root, wrong segment, tampered kernel: rejected.
        let (be, h) = kernel_ref(5000);
        let seg = last_kernel_segment(&be);
        let mut bad = h.clone();
        bad.kernel_root = Hash::from_vec(&[3; 32]);
        assert!(KernelPeaks::from_last_segment(&bad, &seg).is_err());
        let first = Segment::from_pmmr(SegmentIdentifier { height: KERNEL_SEGMENT_HEIGHT, idx: 0 }, &ReadonlyPMMR::at(&be, be.size()), false).unwrap();
        assert!(KernelPeaks::from_last_segment(&h, &first).is_err());
        let (sid, hp, hs, lp, mut ld, pf) = seg.clone().parts();
        ld[0] = kern(999_999);
        assert!(KernelPeaks::from_last_segment(&h, &Segment::from_parts(sid, hp, hs, lp, ld, pf)).is_err());
    }

    #[test]
    fn kernels_bound_in_bodies_and_persisted() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let mut r = reference(3000, 4);
        let (bm, out) = r.compacted_segments(4);
        let (mut kbe, kh) = kernel_ref(3000);
        let mut h0 = r.header();
        h0.kernel_mmr_size = kh.kernel_mmr_size;
        h0.kernel_root = kh.kernel_root;
        let mut st = OutputState::from_segments(&h0, &bm, &out).unwrap();
        st.set_kernels(KernelPeaks::from_last_segment(&h0, &last_kernel_segment(&kbe)).unwrap());
        st.rproof = Some(dummy_rproof_peaks(st.size));
        // Two blocks, each with one kernel.
        let mut headers = vec![h0.clone()];
        let mut blocks = vec![];
        for k in 0..2u64 {
            let o = id(6_000_000 + k as u32);
            let mut b = block(&BlockHeader::default(), &[o], &[id(1 + k as u32)]);
            b.body.kernels = vec![kern(50_000 + k)];
            let ins: Vec<OutputIdentifier> = input_commits(&b).iter().map(|c| OutputIdentifier { features: OutputFeatures::Plain, commit: *c }).collect();
            r.apply(&output_ids(&b), &ins);
            let size = kbe.size();
            PMMR::at(&mut kbe, size).push(&kern(50_000 + k)).unwrap();
            let mut h = r.header();
            h.height = k + 1;
            h.pow.nonce = k + 1;
            h.kernel_mmr_size = kbe.size();
            h.kernel_root = ReadonlyPMMR::at(&kbe, kbe.size()).root().unwrap();
            b.header = h.clone();
            headers.push(h);
            blocks.push(b);
        }
        let ex = vec![kern(50_001).excess.0.to_vec(), kern(7).excess.0.to_vec()];
        let p = prove_bodies_k(&st, &headers, &blocks, &[], &ex).unwrap();
        assert_eq!(p.kernels, vec![Some(2), None]);
        // A body with a hidden/foreign kernel breaks kernel_root.
        let mut lying = blocks.clone();
        lying[1].body.kernels = vec![kern(77_777)];
        assert!(prove_bodies_k(&st, &headers, &lying, &[], &ex).err().unwrap().contains("kernel_root mismatch"));
        // Persisted with the KRN1 trailer and checked on load.
        let path = std::env::temp_dir().join(format!("gap-kern-{}.ust", std::process::id()));
        let path = path.to_str().unwrap();
        let fin = p.state;
        fin.save(path, &headers[2]).unwrap();
        let (back, _) = OutputState::load(path).unwrap();
        assert!(back.kernels_tracked());
        assert_eq!(back.kern, fin.kern);
        assert!(back.rproofs_tracked());
        let good = std::fs::read(path).unwrap();
        let rpf = good.windows(4).rposition(|w| w == b"RPF1").unwrap();
        let mut raw = good.clone();
        raw[rpf - 3] ^= 1; // inside the last kernel peak hash
        std::fs::write(path, &raw).unwrap();
        assert!(OutputState::load(path).err().unwrap().contains("kernel_root"));
        let mut raw = good.clone();
        let n = raw.len();
        raw[n - 3] ^= 1; // inside the last rangeproof peak hash
        std::fs::write(path, &raw).unwrap();
        assert!(OutputState::load(path).err().unwrap().contains("range_proof_root"));
        std::fs::remove_file(path).unwrap();
        // States saved without kernels still load (kernels not tracked).
        let mut plain = fin.clone();
        plain.kern = None;
        plain.save(path, &headers[2]).unwrap();
        assert!(!OutputState::load(path).unwrap().0.kernels_tracked());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn creation_height_from_output_mmr_sizes() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let hs: Vec<BlockHeader> = [(100u64, 50u64), (101, 60), (102, 60), (103, 75)]
            .iter()
            .map(|&(h, s)| {
                let mut x = BlockHeader::default();
                x.height = h;
                x.output_mmr_size = s;
                x
            })
            .collect();
        assert_eq!(creation_height(10, &hs), Err(100)); // before the window
        assert_eq!(creation_height(49, &hs), Err(100));
        assert_eq!(creation_height(50, &hs), Ok(101));
        assert_eq!(creation_height(59, &hs), Ok(101));
        assert_eq!(creation_height(60, &hs), Ok(103)); // 102 added nothing
        assert_eq!(creation_height(74, &hs), Ok(103));
        assert_eq!(creation_height(75, &hs), Err(u64::MAX));
    }

    #[test]
    fn hidden_or_invented_spend_breaks_output_root() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let mut r = reference(2000, 3);
        let (bm, out) = r.segments(4);
        let st0 = OutputState::from_segments(&r.header(), &bm, &out).unwrap();
        let x = id(1);
        let z = id(2);
        let new = id(3_000_000);
        r.apply(&[new], &[x, z]);
        let target = r.header();
        // Honest body.
        let mut st = st0.clone();
        st.apply_body(&[new], &[x.commit, z.commit]).unwrap();
        assert_eq!(st.output_root(), target.output_root);
        assert_eq!(st.position(&x.commit.0), None);
        // Hidden spend of x: replaced by another existing unspent output y.
        let y = id(4);
        let mut st = st0.clone();
        st.apply_body(&[new], &[y.commit, z.commit]).unwrap();
        assert_ne!(st.output_root(), target.output_root);
        // Input that is not in the UTXO set (X+D swap) is refused outright.
        let mut st = st0.clone();
        assert!(st.apply_body(&[new], &[id(7_777_777).commit, z.commit]).is_err());
        // Dropped input: root differs.
        let mut st = st0.clone();
        st.apply_body(&[new], &[z.commit]).unwrap();
        assert_ne!(st.output_root(), target.output_root);
    }

    #[test]
    fn verified_archive_rejects_missing_rangeproofs_and_kernels() {
        global::set_local_chain_type(ChainTypes::Mainnet);
        let header = BlockHeader::default();
        assert!(verify_archive_kernels(&header, &[]).is_err());
        let state = OutputState {
            size: 0,
            peaks: vec![],
            leaves: Bitmap::new(),
            utxo: HashMap::new(),
            acc: BitmapAccumulator::new(),
            pruned: BTreeMap::new(),
            kern: None,
            rproof: None,
            verified: false,
        };
        assert!(verify_archive_rangeproofs(&header, &[], &state).is_err());
        assert!(verify_emission(&header, &state, &[], &[]).is_err());
    }

    fn empty_state() -> OutputState {
        OutputState { size: 0, peaks: vec![], leaves: Bitmap::new(), utxo: HashMap::new(), acc: BitmapAccumulator::new(), pruned: BTreeMap::new(), kern: None, rproof: None, verified: false }
    }

    fn hdr_at(height: u64, output_mmr_size: u64) -> BlockHeader {
        let mut h = BlockHeader::default();
        h.height = height;
        h.output_mmr_size = output_mmr_size;
        h
    }

    /// Review finding 1: the normal sync must reject a block spending an
    /// immature coinbase, as grin `verify_coinbase_maturity` does.
    #[test]
    fn immature_coinbase_spend_is_rejected() {
        global::set_local_chain_type(ChainTypes::Mainnet);
        let m = global::coinbase_maturity();
        assert_eq!(m, 1440);
        let mut st = empty_state();
        let plain: Vec<OutputIdentifier> = (0..10).map(id).collect();
        st.apply_body(&plain, &[]).unwrap();
        let mut cb = id(77);
        cb.features = OutputFeatures::Coinbase;
        st.apply_body(&[cb], &[]).unwrap();
        let cb_pos1 = st.utxo[&cb.commit.0].0 + 1;
        // Created at height 5000: before it the MMR had cb_pos1 - 1 nodes.
        let history: Vec<BlockHeader> = (3000..=7000u64)
            .map(|h| hdr_at(h, if h < 5000 { cb_pos1 - 1 } else { cb_pos1 }))
            .collect();
        // Spend at 5000 + 1439: cutoff header 3561 predates it -> immature.
        let e = st.check_coinbase_maturity(&[cb.commit], 5000 + m - 1, &history).unwrap_err();
        assert!(e.contains("immature"), "{e}");
        // Spend at 5000 + 1440: cutoff header 5000 contains it -> mature.
        st.check_coinbase_maturity(&[cb.commit], 5000 + m, &history).unwrap();
        // A plain output is never subject to maturity.
        st.check_coinbase_maturity(&[id(3).commit], 5001, &history).unwrap();
        // Cutoff header not given: fail closed.
        let e = st.check_coinbase_maturity(&[cb.commit], 5000 + m, &history[2100..]).unwrap_err();
        assert!(e.contains("not in the verified window"), "{e}");
        // Below the maturity height nothing can be spent.
        assert!(st.check_coinbase_maturity(&[cb.commit], m - 1, &history).is_err());
    }

    /// Review finding 2: an archive UTXO set that does not balance against
    /// the header's overage and kernel offset (inflation) is rejected.
    #[test]
    fn inflated_archive_fails_emission_check() {
        global::set_local_chain_type(ChainTypes::Mainnet);
        let secp = static_secp_instance();
        let mut archive = BlockHeader::default();
        archive.height = 1000;
        let genesis_had_reward = global::get_genesis_block().header.kernel_mmr_size > 0;
        let supply = (-archive.total_overage(genesis_had_reward)) as u64;
        let (honest, excess, inflated) = {
            let secp = secp.lock();
            let blind = grin_util::secp::key::SecretKey::from_slice(&secp, &[7u8; 32]).unwrap();
            let honest = secp.commit(supply, blind.clone()).unwrap();
            let inflated = secp.commit(supply + 1, blind.clone()).unwrap();
            let excess = secp.commit(0, blind).unwrap();
            (honest, excess, inflated)
        };
        let mk = |c: Commitment| {
            let mut st = empty_state();
            st.utxo.insert(c.0, (0, OutputIdentifier { features: OutputFeatures::Coinbase, commit: c }));
            st
        };
        verify_emission_sums(&archive, &mk(honest), &excess).unwrap();
        let e = verify_emission_sums(&archive, &mk(inflated), &excess).unwrap_err();
        assert!(e.contains("emission"), "{e}");
    }

    /// Review finding 4: without kernel peaks a block cannot be checked
    /// against kernel_root, so it is rejected (fail closed).
    #[test]
    fn untracked_kernels_fail_closed() {
        global::set_local_chain_type(ChainTypes::Mainnet);
        let st = empty_state();
        assert!(!st.kernels_match(&BlockHeader::default()));
        let mut st = st;
        st.set_kernels(KernelPeaks { size: 0, peaks: vec![] });
        assert!(st.kernels_match(&BlockHeader::default()));
    }

    /// Review finding 3 (rollout): a state saved before the full archive
    /// check is not reused; the verified flag survives a save/load.
    #[test]
    fn unverified_saved_state_is_rebuilt() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let r = reference(300, 3);
        let (bm, out) = r.segments(5);
        let header = r.header();
        let mut st = OutputState::from_segments(&header, &bm, &out).unwrap();
        st.set_kernels(KernelPeaks { size: 0, peaks: vec![] });
        st.rproof = Some(dummy_rproof_peaks(st.size));
        let dir = std::env::temp_dir().join(format!("gs-vfy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.to_str().unwrap();
        save_state(d, &st, &header).unwrap();
        assert!(!OutputState::load(&format!("{d}/state.ust")).unwrap().0.verified);
        assert!(load_state(d, &[header.clone()]).is_none(), "older unverified state must not be reused");
        st.verified = true;
        save_state(d, &st, &header).unwrap();
        assert!(OutputState::load(&format!("{d}/state.ust")).unwrap().0.verified);
        let (back, i) = load_state(d, &[header.clone()]).unwrap();
        assert!(back.verified && i == 0);
        assert!(back.rproofs_tracked());
        // A 0.4.1 file (verified, but no rangeproof peaks) is rebuilt once.
        let mut old = st.clone();
        old.rproof = None;
        let mut raw = old.to_bytes(&header).unwrap();
        raw.extend_from_slice(b"VFY1");
        let (o, _) = OutputState::from_bytes(&raw).unwrap();
        assert!(!o.verified && !o.rproofs_tracked());
        // The flag is carried by every later state.
        assert!(back.clone().verified);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review finding 5: every block must reproduce the header's
    /// range_proof_root (a body with another valid-looking proof fails).
    #[test]
    fn per_block_range_proof_root_is_checked() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let mut r = reference(500, 3);
        let (bm, out) = r.compacted_segments(4);
        let mut st = OutputState::from_segments(&r.header(), &bm, &out).unwrap();
        st.set_kernels(KernelPeaks { size: 0, peaks: vec![] });
        let mut headers = vec![r.header()];
        let mut b = block(&BlockHeader::default(), &[id(7_000_001)], &[id(1)]);
        r.apply(&output_ids(&b), &[id(1)]);
        let mut h = r.header();
        h.height = 1;
        b.header = h.clone();
        headers.push(h.clone());
        // No rangeproof peaks: fail closed.
        let e = prove_bodies(&st, &headers, &[b.clone()], &[]).err().unwrap();
        assert!(e.contains("range_proof_root"), "{e}");
        st.rproof = Some(dummy_rproof_peaks(st.size));
        prove_bodies(&st, &headers, &[b.clone()], &[]).unwrap();
        st.apply_block(&h, &b).unwrap();
        // Same commitment, other proof bytes: output_root still matches,
        // range_proof_root does not.
        let mut lying = b.clone();
        let mut p = dummy_rangeproof();
        p.proof[0] = 1;
        lying.body.outputs[0].proof = p;
        let e = prove_bodies(&st, &headers, &[lying], &[]).err().unwrap();
        assert!(e.contains("range_proof_root mismatch"), "{e}");
    }

    /// The generic segment-peaks rebuild (used for the rangeproof MMR) agrees
    /// with the output-MMR rebuild already checked against grin.
    #[test]
    fn peaks_from_segments_match_output_rebuild() {
        global::set_local_chain_type(ChainTypes::Testnet);
        for (n, every, h) in [(3000u32, 4u32, 5u8), (2000, 3, 4), (777, 2, 3), (5000, 1, 6)] {
            let r = reference(n, every);
            for compact in [false, true] {
                let (bm, out) = if compact { r.compacted_segments(h) } else { r.segments(h) };
                let st = OutputState::from_segments(&r.header(), &bm, &out).unwrap();
                let peaks = peaks_from_segments(st.size, &out, &st.leaves).unwrap();
                assert_eq!(peaks, st.peaks, "n={n} every={every} h={h} compact={compact}");
            }
        }
    }
}
