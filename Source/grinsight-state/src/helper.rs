//! Helper-node snapshot format (UST2).
//!
//! UST2 carries the existing UST1 UTXO state plus what a light-client helper
//! must keep after the one-time full verification:
//! * rangeproofs by output-leaf position;
//! * creation heights for coinbase outputs;
//! * kernel excess sum and kernel offset sum;
//! * a header window (the checkpoint..tip headers used for reorg rollback).
//!
//! The old UST1 file is still accepted: `load` returns `legacy = true` and an
//! empty helper extension. UST1 files are never rewritten by this module.

use crate::outputs::{bind_block, OutputState};
use grin_core::core::{self, BlockHeader, OutputFeatures, OutputIdentifier, Segment, TxKernel};
use grin_core::core::hash::Hashed;
use grin_core::global;
use grin_core::ser::{self, ProtocolVersion};
use grin_util::secp::pedersen::Commitment;
use grin_util::static_secp_instance;
use grin_util::secp::pedersen::RangeProof;
use std::fs;
use std::path::Path;

const MAGIC: &[u8; 4] = b"UST2";
const VERSION: u32 = 4;

#[derive(Clone)]
pub struct HelperState {
    pub base: OutputState,
    pub header: BlockHeader,
    /// Rangeproofs keyed by their 0-based output-leaf position.
    pub rangeproofs: Vec<(u64, RangeProof)>,
    /// Coinbase outputs: (leaf position, creation height).
    pub coinbase_heights: Vec<(u64, u64)>,
    /// Serialized kernel excess sum (Commitment, 33 bytes).
    pub excess_sum: Vec<u8>,
    /// Serialized kernel offset sum (BlindingFactor, 32 bytes).
    pub offset_sum: Vec<u8>,
    /// Headers from the checkpoint to the snapshot height, oldest first.
    pub header_window: Vec<BlockHeader>,
    /// PIBD rangeproof segments as served by the archive node.
    pub rangeproof_segments: Vec<Segment<RangeProof>>,
    /// Last kernel segment (contains the kernel MMR peaks).
    pub kernel_last: Option<Segment<TxKernel>>,
    /// Optional PIBD output segments (adds ~2 GB; off by default).
    pub output_segments: Vec<Segment<OutputIdentifier>>,
    /// Data of spent leaves whose sibling is unspent (needed by Segment::root).
    pub spent_outputs: Vec<(u64, OutputIdentifier)>,
}

impl HelperState {
    pub fn save(&self, path: &str) -> Result<(), String> {
        let base = self.base.to_bytes(&self.header)?;
        let mut out = Vec::with_capacity(base.len() + 64 + self.rangeproofs.len() * 700);
        out.extend_from_slice(MAGIC);
        push_u32(&mut out, VERSION);
        push_bytes(&mut out, &base);
        push_u32(&mut out, self.rangeproofs.len() as u32);
        for (pos, proof) in &self.rangeproofs {
            push_u64(&mut out, *pos);
            let bytes = ser::ser_vec(proof, ProtocolVersion::local())
                .map_err(|e| format!("rangeproof ser: {e:?}"))?;
            push_bytes(&mut out, &bytes);
        }
        push_u32(&mut out, self.coinbase_heights.len() as u32);
        for (pos, height) in &self.coinbase_heights {
            push_u64(&mut out, *pos);
            push_u64(&mut out, *height);
        }
        push_bytes(&mut out, &self.excess_sum);
        push_bytes(&mut out, &self.offset_sum);
        push_u32(&mut out, self.header_window.len() as u32);
        for h in &self.header_window {
            let bytes = ser::ser_vec(h, ProtocolVersion::local())
                .map_err(|e| format!("header ser: {e:?}"))?;
            push_bytes(&mut out, &bytes);
        }

        push_u32(&mut out, self.rangeproof_segments.len() as u32);
        for s in &self.rangeproof_segments {
            let bytes = ser::ser_vec(s, ProtocolVersion::local())
                .map_err(|e| format!("rangeproof segment ser: {e:?}"))?;
            push_bytes(&mut out, &bytes);
        }
        push_u32(&mut out, if self.kernel_last.is_some() { 1 } else { 0 });
        if let Some(s) = &self.kernel_last {
            let bytes = ser::ser_vec(s, ProtocolVersion::local())
                .map_err(|e| format!("kernel segment ser: {e:?}"))?;
            push_bytes(&mut out, &bytes);
        }

        push_u32(&mut out, self.output_segments.len() as u32);
        for s in &self.output_segments {
            let bytes = ser::ser_vec(s, ProtocolVersion::local())
                .map_err(|e| format!("output segment ser: {e:?}"))?;
            push_bytes(&mut out, &bytes);
        }

        push_u32(&mut out, self.spent_outputs.len() as u32);
        for (pos, id) in &self.spent_outputs {
            push_u64(&mut out, *pos);
            let bytes = ser::ser_vec(id, ProtocolVersion::local())
                .map_err(|e| format!("spent output ser: {e:?}"))?;
            push_bytes(&mut out, &bytes);
        }

        let fresh = format!("{path}.new");
        fs::write(&fresh, &out).map_err(|e| format!("write {fresh}: {e}"))?;
        if Path::new(path).exists() {
            let prev = format!("{path}.prev");
            let _ = fs::remove_file(&prev);
            fs::rename(path, &prev).map_err(|e| format!("rotate {path}: {e}"))?;
        }
        fs::rename(&fresh, path).map_err(|e| format!("install {path}: {e}"))?;
        Ok(())
    }

    /// Sidecar path for the PIBD segments that are not part of the compact
    /// UST2 anymore. It is tied to the UST2 header and never loaded if the
    /// header hash differs.
    pub fn segments_path(path: &str) -> String {
        format!("{path}.segments")
    }

    /// Compact save: UST2 stores UTXO state, per-UTXO rangeproofs, coinbase
    /// heights, sums and headers only. Full archive segments live in a
    /// sidecar file next to it, so serving nodes still have them while a
    /// scan-only node can omit the sidecar.
    pub fn save_split(&self, path: &str) -> Result<(), String> {
        let mut compact = self.clone();
        compact.rangeproof_segments.clear();
        compact.kernel_last = None;
        compact.output_segments.clear();

        let sidecar = Self::segments_path(path);
        let mut out = Vec::with_capacity(
            self.rangeproof_segments.iter().map(|s| 64 * 1024).sum::<usize>()
                + self.output_segments.iter().map(|s| 64 * 1024).sum::<usize>()
                + 64,
        );
        out.extend_from_slice(b"USEG");
        push_u32(&mut out, 1);
        push_u64(&mut out, self.header.height);
        let hash_bytes = ser::ser_vec(&self.header.hash(), ProtocolVersion::local())
            .map_err(|e| format!("sidecar hash ser: {e:?}"))?;
        push_bytes(&mut out, &hash_bytes);
        push_u32(&mut out, self.rangeproof_segments.len() as u32);
        for s in &self.rangeproof_segments {
            let bytes = ser::ser_vec(s, ProtocolVersion::local())
                .map_err(|e| format!("rangeproof segment ser: {e:?}"))?;
            push_bytes(&mut out, &bytes);
        }
        push_u32(&mut out, if self.kernel_last.is_some() { 1 } else { 0 });
        if let Some(s) = &self.kernel_last {
            let bytes = ser::ser_vec(s, ProtocolVersion::local())
                .map_err(|e| format!("kernel segment ser: {e:?}"))?;
            push_bytes(&mut out, &bytes);
        }
        push_u32(&mut out, self.output_segments.len() as u32);
        for s in &self.output_segments {
            let bytes = ser::ser_vec(s, ProtocolVersion::local())
                .map_err(|e| format!("output segment ser: {e:?}"))?;
            push_bytes(&mut out, &bytes);
        }
        let fresh_sidecar = format!("{sidecar}.new");
        fs::write(&fresh_sidecar, &out).map_err(|e| format!("write {fresh_sidecar}: {e}"))?;
        if Path::new(&sidecar).exists() {
            let prev = format!("{sidecar}.prev");
            let _ = fs::remove_file(&prev);
            fs::rename(&sidecar, &prev).map_err(|e| format!("rotate {sidecar}: {e}"))?;
        }
        fs::rename(&fresh_sidecar, &sidecar).map_err(|e| format!("install {sidecar}: {e}"))?;

        // Publish the compact UST2 only after the sidecar it refers to exists.
        compact.save(path)
    }

    /// Loads an optional sidecar and verifies its header hash matches the UST2
    /// header. Missing sidecar on a compact state is not an error: segment
    /// serving then fails closed until bootstrap writes segments.
    fn load_sidecar(path: &str, header: &BlockHeader) -> Result<Option<(Vec<Segment<RangeProof>>, Option<Segment<TxKernel>>, Vec<Segment<OutputIdentifier>>)>, String> {
        let sidecar = Self::segments_path(path);
        if !Path::new(&sidecar).exists() {
            return Ok(None);
        }
        let raw = fs::read(&sidecar).map_err(|e| format!("read {sidecar}: {e}"))?;
        if raw.len() < 8 || &raw[..4] != b"USEG" {
            return Err("sidecar is not USEG".into());
        }
        let mut off = 4usize;
        let version = take_u32(&raw, &mut off)?;
        if version != 1 {
            return Err(format!("unsupported USEG version {version}"));
        }
        let height = take_u64(&raw, &mut off)?;
        let hash_bytes = take_bytes(&raw, &mut off)?;
        let hash: grin_core::core::hash::Hash = ser::deserialize_default(&mut &hash_bytes[..])
            .map_err(|e| format!("sidecar hash: {e:?}"))?;
        if height != header.height || hash != header.hash() {
            return Err("sidecar header does not match UST2 header".into());
        }
        let nr = take_u32(&raw, &mut off)? as usize;
        let mut rangeproof_segments = Vec::with_capacity(nr);
        for _ in 0..nr {
            let bytes = take_bytes(&raw, &mut off)?;
            let s: Segment<RangeProof> = ser::deserialize_default(&mut &bytes[..])
                .map_err(|e| format!("sidecar rangeproof segment: {e:?}"))?;
            rangeproof_segments.push(s);
        }
        let has = take_u32(&raw, &mut off)? != 0;
        let kernel_last = if has {
            let bytes = take_bytes(&raw, &mut off)?;
            Some(ser::deserialize_default(&mut &bytes[..]).map_err(|e| format!("sidecar kernel segment: {e:?}"))?)
        } else {
            None
        };
        let no = take_u32(&raw, &mut off)? as usize;
        let mut output_segments = Vec::with_capacity(no);
        for _ in 0..no {
            let bytes = take_bytes(&raw, &mut off)?;
            let s: Segment<OutputIdentifier> = ser::deserialize_default(&mut &bytes[..])
                .map_err(|e| format!("sidecar output segment: {e:?}"))?;
            output_segments.push(s);
        }
        if off != raw.len() {
            return Err("sidecar trailing bytes".into());
        }
        Ok(Some((rangeproof_segments, kernel_last, output_segments)))
    }
    /// Returns the state and whether the file was legacy UST1 (no extension).
    pub fn load(path: &str) -> Result<(Self, bool), String> {
        let raw = fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
        if raw.len() >= 4 && &raw[..4] == b"UST1" {
            let (base, header) = OutputState::from_bytes(&raw)?;
            return Ok((
                Self {
                    base,
                    header,
                    rangeproofs: Vec::new(),
                    coinbase_heights: Vec::new(),
                    excess_sum: Vec::new(),
                    offset_sum: Vec::new(),
                    header_window: Vec::new(),
                    rangeproof_segments: Vec::new(),
                    kernel_last: None,
                    output_segments: Vec::new(),
                    spent_outputs: Vec::new(),
                },
                true,
            ));
        }
        if raw.len() < 8 || &raw[..4] != MAGIC {
            return Err("not a UST1/UST2 state".into());
        }
        let mut off = 4usize;
        let version = take_u32(&raw, &mut off)?;
        if version != VERSION {
            return Err(format!("unsupported UST2 version {version}"));
        }
        let base_bytes = take_bytes(&raw, &mut off)?;
        let (base, header) = OutputState::from_bytes(base_bytes)?;

        let nr = take_u32(&raw, &mut off)? as usize;
        let mut rangeproofs = Vec::with_capacity(nr);
        for _ in 0..nr {
            let pos = take_u64(&raw, &mut off)?;
            let bytes = take_bytes(&raw, &mut off)?;
            let proof: RangeProof = ser::deserialize_default(&mut &bytes[..])
                .map_err(|e| format!("rangeproof: {e:?}"))?;
            rangeproofs.push((pos, proof));
        }
        let nc = take_u32(&raw, &mut off)? as usize;
        let mut coinbase_heights = Vec::with_capacity(nc);
        for _ in 0..nc {
            let pos = take_u64(&raw, &mut off)?;
            let height = take_u64(&raw, &mut off)?;
            coinbase_heights.push((pos, height));
        }
        let excess_sum = take_bytes(&raw, &mut off)?.to_vec();
        let offset_sum = take_bytes(&raw, &mut off)?.to_vec();
        let nh = take_u32(&raw, &mut off)? as usize;
        let mut header_window = Vec::with_capacity(nh);
        for _ in 0..nh {
            let bytes = take_bytes(&raw, &mut off)?;
            let h: BlockHeader = ser::deserialize_default(&mut &bytes[..])
                .map_err(|e| format!("header: {e:?}"))?;
            header_window.push(h);
        }
        let (rangeproof_segments, kernel_last) = if version >= 2 {
            let ns = take_u32(&raw, &mut off)? as usize;
            let mut segs = Vec::with_capacity(ns);
            for _ in 0..ns {
                let bytes = take_bytes(&raw, &mut off)?;
                let s: Segment<RangeProof> = ser::deserialize_default(&mut &bytes[..])
                    .map_err(|e| format!("rangeproof segment: {e:?}"))?;
                segs.push(s);
            }
            let has = take_u32(&raw, &mut off)? != 0;
            let k = if has {
                let bytes = take_bytes(&raw, &mut off)?;
                Some(ser::deserialize_default(&mut &bytes[..]).map_err(|e| format!("kernel segment: {e:?}"))?)
            } else {
                None
            };
            (segs, k)
        } else {
            (Vec::new(), None)
        };
        let output_segments = if version >= 3 {
            let no = take_u32(&raw, &mut off)? as usize;
            let mut segs = Vec::with_capacity(no);
            for _ in 0..no {
                let bytes = take_bytes(&raw, &mut off)?;
                let s: Segment<OutputIdentifier> = ser::deserialize_default(&mut &bytes[..])
                    .map_err(|e| format!("output segment: {e:?}"))?;
                segs.push(s);
            }
            segs
        } else {
            Vec::new()
        };
        let spent_outputs = if version >= 4 {
            let ns = take_u32(&raw, &mut off)? as usize;
            let mut v = Vec::with_capacity(ns);
            for _ in 0..ns {
                let pos = take_u64(&raw, &mut off)?;
                let bytes = take_bytes(&raw, &mut off)?;
                let id: OutputIdentifier = ser::deserialize_default(&mut &bytes[..])
                    .map_err(|e| format!("spent output: {e:?}"))?;
                v.push((pos, id));
            }
            v
        } else {
            Vec::new()
        };
        if off != raw.len() {
            return Err("UST2 trailing bytes".into());
        }
        let mut state = Self {
            base,
            header,
            rangeproofs,
            coinbase_heights,
            excess_sum,
            offset_sum,
            header_window,
            rangeproof_segments,
            kernel_last,
            output_segments,
            spent_outputs,
        };
        if let Some((r, k, o)) = Self::load_sidecar(path, &state.header)? {
            state.rangeproof_segments = r;
            state.kernel_last = k;
            state.output_segments = o;
        }
        Ok((state, false))
    }
}

fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}
fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    push_u32(out, bytes.len() as u32);
    out.extend_from_slice(bytes);
}
fn take_u32(raw: &[u8], off: &mut usize) -> Result<u32, String> {
    let end = off.checked_add(4).filter(|&e| e <= raw.len()).ok_or("UST2 truncated")?;
    let v = u32::from_le_bytes(raw[*off..end].try_into().unwrap());
    *off = end;
    Ok(v)
}
fn take_u64(raw: &[u8], off: &mut usize) -> Result<u64, String> {
    let end = off.checked_add(8).filter(|&e| e <= raw.len()).ok_or("UST2 truncated")?;
    let v = u64::from_le_bytes(raw[*off..end].try_into().unwrap());
    *off = end;
    Ok(v)
}
fn take_bytes<'a>(raw: &'a [u8], off: &mut usize) -> Result<&'a [u8], String> {
    let len = take_u32(raw, off)? as usize;
    let end = off.checked_add(len).filter(|&e| e <= raw.len()).ok_or("UST2 truncated")?;
    let bytes = &raw[*off..end];
    *off = end;
    Ok(bytes)
}


impl HelperState {
    /// Applies one new block on top of this snapshot. The block body is checked
    /// exactly like a full node (`bind_block`: rangeproofs, kernel signatures,
    /// sums, coinbase); coinbase maturity is checked against the stored
    /// creation heights. The UTXO/MMR roots must match the new header.
    pub fn apply_block(&mut self, block: &core::Block) -> Result<(), String> {
        let header = &block.header;
        if header.height != self.header.height + 1 {
            return Err(format!(
                "helper: block height {} does not follow snapshot height {}",
                header.height, self.header.height
            ));
        }
        bind_block(header, Some(&self.header), block)?;

        // Coinbase outputs may not be spent before their maturity. Creation
        // heights recorded since the snapshot give an early, exact answer;
        // the consensus rule itself (grin `verify_coinbase_maturity`, by MMR
        // position against the header `coinbase_maturity()` blocks back) is
        // checked by `OutputState::apply_block` below for every coinbase,
        // including those created before the snapshot.
        let heights: std::collections::HashMap<u64, u64> = self.coinbase_heights.iter().copied().collect();
        for commit in crate::outputs::input_commits(block) {
            if let Some((pos, id)) = self.base.utxo.get(&commit.0) {
                if let Some(&created) = heights.get(pos).filter(|_| id.features.is_coinbase()) {
                    if header.height < created.saturating_add(global::coinbase_maturity()) {
                        return Err(format!(
                            "helper: coinbase output at {pos} is immature at height {}",
                            header.height
                        ));
                    }
                }
            }
        }

        // Rangeproofs of spent leaves disappear from the helper set.
        for commit in crate::outputs::input_commits(block) {
            if let Some((pos, _)) = self.base.utxo.get(&commit.0) {
                self.rangeproofs.retain(|(p, _)| p != pos);
                self.coinbase_heights.retain(|(p, _)| p != pos);
            }
        }

        let new_state = self.base.apply_block_h(header, block, &self.header_window)?;
        for out in block.outputs() {
            let commit = out.commitment();
            let pos = new_state
                .utxo
                .get(&commit.0)
                .map(|(p, _)| *p)
                .ok_or("helper: new output missing from UTXO")?;
            self.rangeproofs.push((pos, out.proof()));
            if out.features().is_coinbase() {
                self.coinbase_heights.push((pos, header.height));
            }
        }

        self.base = new_state;
        self.header = header.clone();
        self.header_window.push(header.clone());
        Ok(())
    }
}

/// Helper chain with a reorg window. `base` is the snapshot at the start of
/// the retained block window; `state` is the current tip. A reorg inside the
/// window rebuilds from `base` and replays the retained blocks. Deeper reorgs
/// fail closed and require a new bootstrap.
pub struct HelperChain {
    pub state: HelperState,
    pub base: HelperState,
    pub blocks: Vec<core::Block>,
    pub window: usize,
}

impl HelperChain {
    pub fn new(snapshot: HelperState, window: usize) -> Self {
        Self { state: snapshot.clone(), base: snapshot, blocks: Vec::new(), window }
    }

    pub fn apply(&mut self, block: &core::Block) -> Result<(), String> {
        if self.blocks.len() >= self.window && !self.blocks.is_empty() {
            self.base = self.state.clone();
            self.blocks.clear();
        }
        self.state.apply_block(block)?;
        self.blocks.push(block.clone());
        Ok(())
    }

    /// Rolls the tip back to `height` by replaying retained blocks from the
    /// window base. Returns an error when `height` is below the window.
    pub fn rollback_to(&mut self, height: u64) -> Result<(), String> {
        if height < self.base.header.height {
            return Err(format!(
                "reorg below helper window: requested {height}, window starts at {}; bootstrap required",
                self.base.header.height
            ));
        }
        if height > self.state.header.height {
            return Err(format!("rollback target {height} is above tip {}", self.state.header.height));
        }
        let mut state = self.base.clone();
        let mut kept = Vec::new();
        for b in &self.blocks {
            if b.header.height > height {
                break;
            }
            state.apply_block(b)?;
            kept.push(b.clone());
        }
        if state.header.height != height {
            return Err(format!("rollback target {height} is not in the retained window"));
        }
        self.state = state;
        self.blocks = kept;
        Ok(())
    }
}

impl HelperChain {
    /// Headers following the first locator hash we know, up to `limit`.
    /// Empty when the locator already points at our tip.
    pub fn headers_from_locator(&self, locator: &[grin_core::core::hash::Hash], limit: usize) -> Vec<BlockHeader> {
        let mut all: Vec<BlockHeader> = self.state.header_window.clone();
        if all.last().map(|h| h.hash()) != Some(self.state.header.hash()) {
            all.push(self.state.header.clone());
        }
        for l in locator {
            if let Some(i) = all.iter().position(|h| h.hash() == *l) {
                return all[i + 1..].iter().take(limit).cloned().collect();
            }
        }
        Vec::new()
    }

    /// A recent block by hash (only the retained reorg window).
    pub fn block_by_hash(&self, hash: &grin_core::core::hash::Hash) -> Option<core::Block> {
        self.blocks.iter().find(|b| b.header.hash() == *hash).cloned()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorg_below_window_fails_closed() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
        let state = HelperState {
            base: OutputState {
                size: 0,
                peaks: vec![],
                leaves: croaring::Bitmap::new(),
                utxo: std::collections::HashMap::new(),
                acc: grin_chain::txhashset::BitmapAccumulator::new(),
                pruned: std::collections::BTreeMap::new(),
                kern: None,
                verified: false,
            },
            header: {
                let mut h = BlockHeader::default();
                h.height = 5;
                h
            },
            rangeproofs: vec![],
            coinbase_heights: vec![],
            excess_sum: vec![],
            offset_sum: vec![],
            header_window: vec![],
            rangeproof_segments: vec![],
            kernel_last: None,
            output_segments: vec![],
            spent_outputs: vec![],
        };
        let mut chain = HelperChain::new(state, 10);
        assert!(chain.rollback_to(4).is_err());
    }

    #[cfg(feature = "testkit")]
    #[test]
    fn split_save_keeps_segments_out_of_ust2() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
        let r = crate::testkit::reference(2000, 2);
        let h = r.header();
        let (bitmap, output) = r.segments(11);
        let state = OutputState::from_segments(&h, &bitmap, &output).unwrap();
        let helper = HelperState {
            base: state,
            header: h.clone(),
            rangeproofs: vec![],
            coinbase_heights: vec![],
            excess_sum: vec![],
            offset_sum: vec![],
            header_window: vec![h],
            rangeproof_segments: vec![],
            kernel_last: None,
            output_segments: vec![],
            spent_outputs: vec![],
        };
        let dir = std::env::temp_dir().join(format!("grinsight-helper-split-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helper.ust2");
        helper.save_split(path.to_str().unwrap()).unwrap();
        assert!(Path::new(&HelperState::segments_path(path.to_str().unwrap())).exists());
        let (loaded, legacy) = HelperState::load(path.to_str().unwrap()).unwrap();
        assert!(!legacy);
        assert!(loaded.rangeproof_segments.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn ust2_rejects_bad_magic_and_truncation() {
        let dir = std::env::temp_dir().join(format!("grinsight-helper-bad-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("bad.ust2");
        std::fs::write(&p, b"UST1").unwrap();
        assert!(HelperState::load(p.to_str().unwrap()).is_err());
        std::fs::write(&p, b"UST2\x01\x00\x00\x00\x05").unwrap();
        assert!(HelperState::load(p.to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}