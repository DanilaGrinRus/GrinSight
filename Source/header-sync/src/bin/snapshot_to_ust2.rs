//! Offline builder: Gplus TxHashSet snapshot -> helper UST2 + sidecar.
//! Usage: snapshot_to_ust2 <snapshot_dir> <verified-headers.bin> <height> <out_dir>

use croaring::{Bitmap, Portable};
use grin_chain::txhashset::{BitmapAccumulator, BitmapChunk, PMMRHandle};
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::pmmr::{self, ReadablePMMR, ReadonlyPMMR};
use grin_core::core::{BlockHeader, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use grin_core::ser::ProtocolVersion;
use grin_util::secp::pedersen::RangeProof;
use grinsight_state::helper::HelperState;
use grinsight_state::outputs::OutputState;
use std::collections::HashMap;
use std::fs;

fn main() -> Result<(), String> {
    grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
    let args: Vec<String> = std::env::args().skip(1).collect();
    let snap = args.get(0).ok_or("snapshot dir")?;
    let headers_path = args.get(1).ok_or("headers")?;
    let height: u64 = args.get(2).ok_or("height")?.parse().map_err(|_| "height")?;
    let out_dir = args.get(3).ok_or("out dir")?;

    let all = grinsight_state::outputs::read_headers(headers_path)?;
    let header: BlockHeader = all.iter().find(|h| h.height == height).ok_or("height not in headers")?.clone();
    eprintln!("HEADER height={} hash={} output_size={}", header.height, header.hash(), header.output_mmr_size);

    let out_path = format!("{snap}/output");
    let rp_path = format!("{snap}/rangeproof");
    let k_path = format!("{snap}/kernel");
    let op = PMMRHandle::<OutputIdentifier>::new(&out_path, true, ProtocolVersion(1), None).map_err(|e| format!("output pmmr: {e}"))?;
    let rp = PMMRHandle::<RangeProof>::new(&rp_path, true, ProtocolVersion(1), None).map_err(|e| format!("rangeproof pmmr: {e}"))?;
    let kp = PMMRHandle::<TxKernel>::new(&k_path, false, ProtocolVersion(2), None).map_err(|e| format!("kernel pmmr: {e}"))?;
    if op.size != header.output_mmr_size { return Err(format!("output size {} != header {}", op.size, header.output_mmr_size)); }
    let om = ReadonlyPMMR::at(&op.backend, op.size);
    let rm = ReadonlyPMMR::at(&rp.backend, rp.size);
    let n = pmmr::n_leaves(op.size);

    let short = header.hash().to_string();
    let leaf_path = format!("{snap}/output/pmmr_leaf.bin.{}", &short[..12]);
    let raw = fs::read(&leaf_path).or_else(|_| fs::read(format!("{snap}/output/pmmr_leafset.bin"))).map_err(|e| format!("leafset: {e}"))?;
    let unspent_positions: Vec<u64> = om.leaf_pos_iter().collect();
    let mut leaves = Bitmap::new();
    for pos0 in &unspent_positions {
        leaves.add(grinsight_state::outputs::leaf_idx(*pos0) as u32);
    }
    eprintln!("LEAVES={} POSITIONS={} MMR_SIZE={} RAW_BITS={}", leaves.cardinality(), unspent_positions.len(), op.size, raw.len());
    if leaves.maximum().map_or(false, |m| m as u64 >= n) { return Err("leafset beyond MMR".into()); }

    let unspent: std::collections::HashSet<u64> = unspent_positions.iter().copied().collect();
    let mut utxo: HashMap<[u8;33], (u64, OutputIdentifier)> = HashMap::new();
    let mut rangeproofs: Vec<(u64, RangeProof)> = Vec::new();
    let nout = SegmentIdentifier::count_segments_required(op.size, 11) as u64;
    for i in 0..nout {
        let id = SegmentIdentifier { height: 11, idx: i };
        if let Ok(s) = Segment::from_pmmr(id, &om, true) {
            for (p, oid) in s.leaf_iter() {
                if unspent.contains(&p) { utxo.insert(oid.commit.0, (p, *oid)); }
            }
        }
    }
    if utxo.len() != unspent.len() { return Err(format!("outputs found {} != unspent {}", utxo.len(), unspent.len())); }
    for i in 0..nout {
        let id = SegmentIdentifier { height: 11, idx: i };
        if let Ok(s) = Segment::from_pmmr(id, &rm, true) {
            for (p, proof) in s.leaf_iter() {
                if unspent.contains(&p) { rangeproofs.push((p, *proof)); }
            }
        }
    }
    if rangeproofs.len() != unspent.len() { return Err(format!("proofs found {} != unspent {}", rangeproofs.len(), unspent.len())); }

    let mut acc = BitmapAccumulator::new();
    let chunks = n.div_ceil(1024);
    for ci in 0..chunks {
        let mut c = BitmapChunk::new();
        let start = ci * 1024;
        for bit in 0..1024u64 {
            let li = start + bit;
            if li < n && leaves.contains(li as u32) { c.set(bit, true); }
        }
        acc.append_chunk(c).map_err(|e| format!("bitmap chunk {ci}: {e:?}"))?;
    }

    let peak_positions = pmmr::peaks(op.size);
    let peaks: Vec<(u64, Hash)> = peak_positions.iter().filter_map(|&p| om.get_hash(p).map(|h| (p, h))).collect();
    let mut state = OutputState { size: op.size, peaks, leaves: leaves.clone(), utxo, acc, pruned: Default::default(), kern: None, verified: false };
    if state.output_root() != header.output_root {
        return Err("output root mismatch after snapshot rebuild".into());
    }

    let nrp = SegmentIdentifier::count_segments_required(op.size, 11) as u64;
    let mut rangeproof_segments = Vec::new();
    for i in 0..nrp {
        let id = SegmentIdentifier { height: 11, idx: i };
        match Segment::from_pmmr(id, &rm, true) {
            Ok(s) => rangeproof_segments.push(s),
            Err(e) => { eprintln!("RPROOF_STOP={i}: {e:?}"); break; }
        }
        if i % 256 == 0 { eprintln!("RPROOF={i}/{nrp}"); }
    }
    let nk = SegmentIdentifier::count_segments_required(header.kernel_mmr_size, 11) as u64;
    let km = ReadonlyPMMR::at(&kp.backend, kp.size);
    let kernel_last = if nk > 0 { Segment::from_pmmr(SegmentIdentifier { height: 11, idx: nk - 1 }, &km, false).ok() } else { None };
    if let Some(k) = &kernel_last { state.set_kernels(grinsight_state::outputs::KernelPeaks::from_last_segment(&header, k)?); }

    let helper = HelperState {
        base: state,
        header: header.clone(),
        rangeproofs,
        coinbase_heights: vec![],
        excess_sum: vec![],
        offset_sum: vec![],
        header_window: vec![header],
        rangeproof_segments,
        kernel_last,
        output_segments: vec![],
        spent_outputs: vec![],
    };
    fs::create_dir_all(out_dir).map_err(|e| e.to_string())?;
    let path = format!("{out_dir}/helper.ust2");
    helper.save_split(&path)?;
    eprintln!("SAVED={path} UTXO={} RPROOFS={}", helper.rangeproofs.len(), helper.rangeproof_segments.len());
    Ok(())
}