//! Convert a GPF1 archive bundle into compact helper UST2 + sidecar.

use grin_chain::txhashset::BitmapSegment;
use grin_core::core::hash::Hashed;
use grin_core::core::{BlockHeader, OutputIdentifier, Segment, TxKernel};
use grin_core::ser::{self, DeserializationMode, ProtocolVersion};
use grin_util::secp::pedersen::RangeProof;
use grinsight_state::helper::HelperState;
use grinsight_state::outputs::OutputState;
use std::fs::File;
use std::io::Read;

fn blob<'a>(b: &'a [u8], off: &mut usize) -> Result<&'a [u8], String> {
    if *off + 4 > b.len() { return Err("truncated".into()); }
    let n = u32::from_le_bytes(b[*off..*off + 4].try_into().unwrap()) as usize;
    *off += 4;
    if *off + n > b.len() { return Err("truncated blob".into()); }
    let out = &b[*off..*off + n];
    *off += n;
    Ok(out)
}

fn main() -> Result<(), String> {
    grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
    let input = std::env::args().nth(1).ok_or("usage: gpf1_to_ust2 <full.gpf1> <out_dir>")?;
    let out_dir = std::env::args().nth(2).ok_or("out_dir")?;
    let mut raw = Vec::new();
    File::open(&input).map_err(|e| e.to_string())?.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    if raw.len() < 8 || &raw[..4] != b"GPF1" { return Err("not GPF1".into()); }
    let mut off = 4usize;
    let header_raw = blob(&raw, &mut off)?.to_vec();
    let header: BlockHeader = ser::deserialize(&mut &header_raw[..], ProtocolVersion::local(), DeserializationMode::default()).map_err(|e| format!("header: {e:?}"))?;
    eprintln!("GPF1 height={} hash={} out_size={}", header.height, header.hash(), header.output_mmr_size);
    let nbm = u32::from_le_bytes(raw[off..off+4].try_into().unwrap()) as usize; off += 4;
    let mut bitmaps = Vec::with_capacity(nbm);
    for _ in 0..nbm { let b = blob(&raw, &mut off)?; let w: BitmapSegment = ser::deserialize_default(&mut &b[..]).map_err(|e| format!("bitmap: {e:?}"))?; bitmaps.push(w.into_segment().map_err(|e| format!("bitmap seg: {e:?}"))?); }
    let nout = u32::from_le_bytes(raw[off..off+4].try_into().unwrap()) as usize; off += 4;
    let mut outputs = Vec::with_capacity(nout);
    for _ in 0..nout { let b = blob(&raw, &mut off)?; outputs.push(ser::deserialize_default::<Segment<OutputIdentifier>, _>(&mut &b[..]).map_err(|e| format!("output: {e:?}"))?); }
    let nrp = u32::from_le_bytes(raw[off..off+4].try_into().unwrap()) as usize; off += 4;
    let mut rps = Vec::with_capacity(nrp);
    for _ in 0..nrp { let b = blob(&raw, &mut off)?; rps.push(ser::deserialize_default::<Segment<RangeProof>, _>(&mut &b[..]).map_err(|e| format!("rproof: {e:?}"))?); }
    let nk = u32::from_le_bytes(raw[off..off+4].try_into().unwrap()) as usize; off += 4;
    let mut kernels = Vec::with_capacity(nk);
    for _ in 0..nk { let b = blob(&raw, &mut off)?; kernels.push(ser::deserialize_default::<Segment<TxKernel>, _>(&mut &b[..]).map_err(|e| format!("kernel: {e:?}"))?); }
    let state = OutputState::from_segments(&header, &bitmaps, &outputs)?;
    let wanted: std::collections::HashSet<u64> = state.utxo.values().map(|(p, _)| *p).collect();
    let mut rangeproofs = Vec::new();
    for s in &rps { for (p, proof) in s.leaf_iter() { if wanted.contains(&p) { rangeproofs.push((p, *proof)); } } }
    eprintln!("UTXO={} PROOFS={} SEGMENTS={} KERNELS={}", state.utxo_count(), rangeproofs.len(), rps.len(), kernels.len());
    let kernel_last = kernels.last().cloned();
    let helper = HelperState { base: state, header, rangeproofs, coinbase_heights: vec![], excess_sum: vec![], offset_sum: vec![], header_window: vec![], rangeproof_segments: rps, kernel_last, output_segments: outputs, spent_outputs: vec![] };
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let path = format!("{out_dir}/helper.ust2");
    helper.save_split(&path)?;
    eprintln!("SAVED={path}");
    Ok(())
}