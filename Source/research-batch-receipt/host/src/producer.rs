use super::{
    batch_height, bounded, image_bytes, verified, verify, BATCH_ID, MAX_POINT, MAX_RECEIPT,
};
use anyhow::{ensure, Context, Result};
use risc0_binfmt::{compute_image_id, ProgramBinary};
use risc0_zkvm::{ExecutorEnv, ExternalProver, Prover, ProverOpts};
use std::{fs, path::Path, time::Instant};

const H2_ID: &str = include_str!("../../../research-linked-receipt/image-id.hex");
const HEADER_LEN: usize = 400;
const MAX_BATCH: usize = 8;

pub fn pack(raw: &Path, out: &Path) -> Result<()> {
    let raw = bounded(raw, 4 * 1024 * 1024)?;
    let binary = ProgramBinary::new(&raw, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let image = compute_image_id(&binary)?;
    fs::write(out, binary)?;
    println!("{image}");
    Ok(())
}

pub fn prove(parent_file: &Path, proof_file: &Path, headers_file: &Path, out: &Path) -> Result<()> {
    ensure!(!out.exists(), "output directory already exists");
    let parent = bounded(parent_file, MAX_POINT)?;
    let (height, parent_image) = if parent.len() == 1104 && parent.starts_with(b"GSZ2MH02") {
        ensure!(
            u64::from_be_bytes(parent[8..16].try_into()?) == 2,
            "bad H2 parent height"
        );
        (2, H2_ID)
    } else {
        (batch_height(&parent)?, BATCH_ID)
    };
    let prior = verified(&bounded(proof_file, MAX_RECEIPT)?, parent_image, &parent)?;
    let headers = bounded(headers_file, MAX_BATCH * HEADER_LEN)?;
    ensure!(
        !headers.is_empty() && headers.len() % HEADER_LEN == 0,
        "expected 1..8 complete C29 headers"
    );
    let count = (headers.len() / HEADER_LEN) as u8;
    let tip = height + u64::from(count);
    ensure!(tip <= 1000, "batch exceeds supported height");
    let elf = bounded(
        std::env::var_os("BATCH_GUEST_ELF")
            .context("BATCH_GUEST_ELF required")?
            .as_ref(),
        4 * 1024 * 1024,
    )?;
    ensure!(
        compute_image_id(&elf)?.to_string() == BATCH_ID.trim(),
        "unknown guest image"
    );
    let mut builder = ExecutorEnv::builder();
    builder
        .segment_limit_po2(20)
        .write_slice(&image_bytes(BATCH_ID)?)
        .write_slice(&(parent.len() as u32).to_be_bytes())
        .write_slice(&parent)
        .write_slice(&[count])
        .write_slice(&headers)
        .add_assumption(prior);
    let server = std::env::var_os("RISC0_SERVER_PATH").unwrap_or_else(|| "r0vm".into());
    let prover = ExternalProver::new("local-r0vm", server);
    let start = Instant::now();
    let info = prover.prove_with_opts(builder.build()?, &elf, &ProverOpts::succinct())?;
    let duration = start.elapsed();
    let point = &info.receipt.journal.bytes;
    let proof = bincode::serialize(&info.receipt)?;
    ensure!(proof.len() <= MAX_RECEIPT, "receipt exceeds size limit");
    verify("main", point, &proof)?;
    ensure!(
        batch_height(point)? == tip && point[80..480] == headers[headers.len() - HEADER_LEN..],
        "output does not bind the requested tip"
    );
    let parent_dir = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp = tempfile::tempdir_in(parent_dir)?;
    fs::write(tmp.path().join("checkpoint.bin"), point)?;
    fs::write(tmp.path().join("history.receipt"), &proof)?;
    fs::rename(tmp.path(), out)?;
    let stats = &info.stats;
    println!("parent_height={height} headers={count} elapsed_s={:.3} segments={} total_cycles={} user_cycles={} paging_cycles={} reserved_cycles={} point_bytes={} receipt_bytes={}",
        duration.as_secs_f64(), stats.segments, stats.total_cycles, stats.user_cycles, stats.paging_cycles,
        stats.reserved_cycles, point.len(), proof.len());
    Ok(())
}
