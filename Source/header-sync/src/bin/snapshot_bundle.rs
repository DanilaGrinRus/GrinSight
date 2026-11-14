use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use grin_chain::txhashset::PMMRHandle;
use grin_core::core::hash::Hashed;
use grin_core::core::pmmr::{self, ReadablePMMR, ReadonlyPMMR};
use grin_core::core::Segment;
use grin_core::core::{BlockHeader, OutputIdentifier, SegmentIdentifier, TxKernel};
use grin_core::ser::{self, DeserializationMode, ProtocolVersion};
use grin_util::secp::pedersen::RangeProof;

const GPF1: &[u8; 4] = b"GPF1";

fn read_u32(b: &[u8], off: &mut usize) -> Result<u32, String> {
    if *off + 4 > b.len() {
        return Err("truncated u32".into());
    }
    let n = u32::from_le_bytes(b[*off..*off + 4].try_into().unwrap());
    *off += 4;
    Ok(n)
}

fn take<'a>(b: &'a [u8], off: &mut usize) -> Result<&'a [u8], String> {
    let n = read_u32(b, off)? as usize;
    if *off + n > b.len() {
        return Err("truncated blob".into());
    }
    let out = &b[*off..*off + n];
    *off += n;
    Ok(out)
}

fn write_blob(out: &mut File, b: &[u8]) -> Result<(), String> {
    out.write_all(&(b.len() as u32).to_le_bytes()).map_err(|e| e.to_string())?;
    out.write_all(b).map_err(|e| e.to_string())
}

/// Copy header/bitmap/output from the tested gateway bundle, then append
/// rangeproof and kernel segments from the full archive snapshot.
fn main() -> Result<(), String> {
    grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
    let base = std::env::args().nth(1).ok_or("usage: snapshot_bundle <snapshot_dir> <gateway.gpf1> <out.gpf1>")?;
    let gateway = std::env::args().nth(2).ok_or("missing gateway gpf1")?;
    let out = std::env::args().nth(3).ok_or("missing output gpf1")?;

    let mut gb = Vec::new();
    File::open(&gateway).map_err(|e| e.to_string())?.read_to_end(&mut gb).map_err(|e| e.to_string())?;
    if gb.len() < 8 || &gb[..4] != GPF1 {
        return Err("gateway bundle has no GPF1 magic".into());
    }
    let mut off = 4usize;
    let header_raw = take(&gb, &mut off)?.to_vec();
    let header: BlockHeader = ser::deserialize_default(&mut &header_raw[..]).map_err(|e| format!("header: {e:?}"))?;
    let nbm = read_u32(&gb, &mut off)? as usize;
    let mut bm_raw = Vec::new();
    for _ in 0..nbm {
        bm_raw.push(take(&gb, &mut off)?.to_vec());
    }
    let nout = read_u32(&gb, &mut off)? as usize;
    let mut output_raw = Vec::new();
    for _ in 0..nout {
        output_raw.push(take(&gb, &mut off)?.to_vec());
    }
    let nrp_gateway = read_u32(&gb, &mut off)?;
    for _ in 0..nrp_gateway {
        take(&gb, &mut off)?;
    }
    let nk_gateway = read_u32(&gb, &mut off)?;
    for _ in 0..nk_gateway {
        take(&gb, &mut off)?;
    }

    let root = Path::new(&base).join("chain_data");
    let out_path = root.join("txhashset").join("output");
    let op = PMMRHandle::<OutputIdentifier>::new(&out_path, true, ProtocolVersion(1), None)
        .map_err(|e| format!("output pmmr: {e}"))?;
    eprintln!("SNAPSHOT_OUTPUT_SIZE={} LEAVES={}", op.size, pmmr::n_leaves(op.size));

    let rp_path = root.join("txhashset").join("rangeproof");
    let rp = PMMRHandle::<RangeProof>::new(&rp_path, true, ProtocolVersion(1), None)
        .map_err(|e| format!("rangeproof pmmr: {e}"))?;
    let rpmmr = ReadonlyPMMR::at(&rp.backend, rp.size);

    let k_path = root.join("txhashset").join("kernel");
    let kp = PMMRHandle::<TxKernel>::new(&k_path, false, ProtocolVersion(2), None)
        .map_err(|e| format!("kernel pmmr: {e}"))?;
    let kpmmr = ReadonlyPMMR::at(&kp.backend, kp.size);

    let nrp = SegmentIdentifier::count_segments_required(header.output_mmr_size, 11);
    let nk = SegmentIdentifier::count_segments_required(header.kernel_mmr_size, 11);
    eprintln!("OUTPUT={nout} RPROOF={nrp} KERNEL={nk} RPSIZE={} KSIZE={}", rp.size, kp.size);
    let mut out_f = File::create(&out).map_err(|e| e.to_string())?;
    out_f.write_all(GPF1).map_err(|e| e.to_string())?;
    write_blob(&mut out_f, &header_raw)?;
    out_f.write_all(&(bm_raw.len() as u32).to_le_bytes()).map_err(|e| e.to_string())?;
    for b in &bm_raw { write_blob(&mut out_f, b)?; }
    out_f.write_all(&(output_raw.len() as u32).to_le_bytes()).map_err(|e| e.to_string())?;
    for b in &output_raw { write_blob(&mut out_f, b)?; }
    let nrp_pos = out_f.stream_position().map_err(|e| e.to_string())?;
    out_f.write_all(&(nrp as u32).to_le_bytes()).map_err(|e| e.to_string())?;
    let mut nrp_written = 0u32;
    for i in 0..nrp as u64 {
        let id = SegmentIdentifier { height: 11, idx: i };
        let seg = match Segment::from_pmmr(id, &rpmmr, true) { Ok(s) => s, Err(e) => { eprintln!("RPROOF_STOP={i}: {e:?}"); break; } };
        let raw = ser::ser_vec(&seg, ProtocolVersion::local()).map_err(|e| format!("rproof ser {i}: {e:?}"))?;
        write_blob(&mut out_f, &raw)?;
        nrp_written += 1;
        if i % 256 == 0 { eprintln!("RPROOF_PROGRESS={i}/{nrp}"); }
    }
    let nk_pos = out_f.stream_position().map_err(|e| e.to_string())?;
    out_f.seek(SeekFrom::Start(nrp_pos)).map_err(|e| e.to_string())?;
    out_f.write_all(&nrp_written.to_le_bytes()).map_err(|e| e.to_string())?;
    out_f.seek(SeekFrom::Start(nk_pos)).map_err(|e| e.to_string())?;
    out_f.write_all(&(nk as u32).to_le_bytes()).map_err(|e| e.to_string())?;
    for i in 0..nk as u64 {
        let id = SegmentIdentifier { height: 11, idx: i };
        let seg = Segment::from_pmmr(id, &kpmmr, false).map_err(|e| format!("kernel {i}: {e:?}"))?;
        let raw = ser::ser_vec(&seg, ProtocolVersion::local()).map_err(|e| format!("kernel ser {i}: {e:?}"))?;
        write_blob(&mut out_f, &raw)?;
        if i % 256 == 0 { eprintln!("KERNEL_PROGRESS={i}/{nk}"); }
    }
    out_f.flush().map_err(|e| e.to_string())?;
    eprintln!("WROTE={out}");
    Ok(())
}





