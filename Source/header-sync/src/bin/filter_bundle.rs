use std::fs::File;
use std::io::{Read, Write};

use grin_core::core::Segment;
use grin_core::core::hash::Hashed;
use grin_core::core::{BlockHeader, OutputIdentifier, TxKernel};
use grin_core::ser::{self, DeserializationMode, ProtocolVersion};
use grin_util::secp::pedersen::RangeProof;
use grin_chain::txhashset::BitmapSegment;
use grinsight_state::outputs::OutputState;

fn read_blob<'a>(b: &'a [u8], off: &mut usize) -> Result<&'a [u8], String> {
    if *off + 4 > b.len() { return Err("truncated".into()); }
    let n = u32::from_le_bytes(b[*off..*off + 4].try_into().unwrap()) as usize;
    *off += 4;
    if *off + n > b.len() { return Err("truncated blob".into()); }
    let out = &b[*off..*off + n];
    *off += n;
    Ok(out)
}

fn put_blob(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_le_bytes());
    out.extend_from_slice(b);
}

fn main() -> Result<(), String> {
    grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
    let input = std::env::args().nth(1).ok_or("usage: filter_bundle <full.gpf1> <out.gpf1>")?;
    let output = std::env::args().nth(2).ok_or("missing output")?;
    let mut raw = Vec::new();
    File::open(&input).map_err(|e| e.to_string())?.read_to_end(&mut raw).map_err(|e| e.to_string())?;
    if raw.len() < 8 || &raw[..4] != b"GPF1" { return Err("not GPF1".into()); }
    let mut off = 4usize;
    let header_raw = read_blob(&raw, &mut off)?.to_vec();
    let header: BlockHeader = ser::deserialize(&mut &header_raw[..], ProtocolVersion::local(), DeserializationMode::default())
        .map_err(|e| format!("header: {e:?}"))?;
    let nbm = u32::from_le_bytes(raw[off..off+4].try_into().unwrap()) as usize; off += 4;
    let mut bitmap_raw = Vec::with_capacity(nbm);
    let mut bitmaps = Vec::with_capacity(nbm);
    for _ in 0..nbm {
        let b = read_blob(&raw, &mut off)?.to_vec();
        let wire: BitmapSegment = ser::deserialize_default(&mut &b[..]).map_err(|e| format!("bitmap: {e:?}"))?;
        bitmaps.push(wire.into_segment().map_err(|e| format!("bitmap seg: {e:?}"))?);
        bitmap_raw.push(b);
    }
    let nout = u32::from_le_bytes(raw[off..off+4].try_into().unwrap()) as usize; off += 4;
    let mut out_raw = Vec::with_capacity(nout);
    let mut outputs = Vec::with_capacity(nout);
    for _ in 0..nout {
        let b = read_blob(&raw, &mut off)?.to_vec();
        let s: Segment<OutputIdentifier> = ser::deserialize_default(&mut &b[..]).map_err(|e| format!("output: {e:?}"))?;
        outputs.push(s);
        out_raw.push(b);
    }
    let nrp = u32::from_le_bytes(raw[off..off+4].try_into().unwrap()) as usize; off += 4;
    let mut rp_raw = Vec::with_capacity(nrp);
    for _ in 0..nrp { rp_raw.push(read_blob(&raw, &mut off)?.to_vec()); }
    let nk = u32::from_le_bytes(raw[off..off+4].try_into().unwrap()) as usize; off += 4;
    let mut k_raw = Vec::with_capacity(nk);
    for _ in 0..nk { k_raw.push(read_blob(&raw, &mut off)?.to_vec()); }
    if off != raw.len() { return Err("trailing bytes".into()); }

    let state = OutputState::from_segments(&header, &bitmaps, &outputs).map_err(|e| format!("utxo: {e}"))?;
    let wanted: std::collections::HashSet<u64> = state.utxo.values().map(|(pos, _)| *pos).collect();
    let mut filtered: Vec<Vec<u8>> = Vec::new();
    let mut kept = 0usize;
    for b in &rp_raw {
        let seg: Segment<RangeProof> = ser::deserialize_default(&mut &b[..]).map_err(|e| format!("rproof: {e:?}"))?;
        let (id, hp, hs, lp, ld, proof) = seg.parts();
        let mut nlp = Vec::new();
        let mut nld = Vec::new();
        for (p, d) in lp.into_iter().zip(ld.into_iter()) {
            if wanted.contains(&p) { nlp.push(p); nld.push(d); }
        }
        if nlp.is_empty() { continue; }
        kept += nlp.len();
        let s = Segment::from_parts(id, hp, hs, nlp, nld, proof);
        let bytes = ser::ser_vec(&s, ProtocolVersion::local()).map_err(|e| format!("ser: {e:?}"))?;
        filtered.push(bytes);
    }
    eprintln!("FILTER_POSITIONS={} KEPT_PROOFS={} SEGMENTS={}/{}", wanted.len(), kept, filtered.len(), nrp);

    let mut out = b"GPF1".to_vec();
    put_blob(&mut out, &header_raw);
    out.extend_from_slice(&(bitmap_raw.len() as u32).to_le_bytes());
    for b in &bitmap_raw { put_blob(&mut out, b); }
    out.extend_from_slice(&(out_raw.len() as u32).to_le_bytes());
    for b in &out_raw { put_blob(&mut out, b); }
    out.extend_from_slice(&(filtered.len() as u32).to_le_bytes());
    for b in &filtered { put_blob(&mut out, b); }
    out.extend_from_slice(&(k_raw.len() as u32).to_le_bytes());
    for b in &k_raw { put_blob(&mut out, b); }
    let mut f = File::create(&output).map_err(|e| e.to_string())?;
    f.write_all(&out).map_err(|e| e.to_string())?;
    eprintln!("WROTE={} bytes", out.len());
    Ok(())
}
