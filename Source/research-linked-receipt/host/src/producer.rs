use super::{bounded, verified, verify, LINKED_ID, MAX_RECEIPT};
use anyhow::{ensure, Context, Result};
use risc0_binfmt::{compute_image_id, ProgramBinary};
use risc0_zkvm::{ExecutorEnv, ExternalProver, Prover, ProverOpts};
use std::{fs, path::Path};

const H1_ID: &str = "401af3666aa946a7e03427dd74b376ef6b5bfbfdd0bfef157e6afcb0d957271a";

pub fn pack(raw: &Path, out: &Path) -> Result<()> {
    let user = bounded(raw, 4 * 1024 * 1024)?;
    let binary = ProgramBinary::new(&user, risc0_zkos_v1compat::V1COMPAT_ELF).encode();
    let image = compute_image_id(&binary)?;
    fs::write(out, binary)?;
    println!("{image}");
    Ok(())
}

pub fn prove(h1: &Path, prior: &Path, header: &Path, out: &Path) -> Result<()> {
    ensure!(!out.exists(), "output directory already exists");
    let parent = bounded(h1, 520)?;
    ensure!(
        parent.len() == 520 && &parent[..8] == b"GSZ1MH01",
        "bad parent schema"
    );
    let proof = verified(&bounded(prior, MAX_RECEIPT)?, H1_ID, &parent)?;
    let header = bounded(header, 400)?;
    ensure!(header.len() == 400, "bad C29 header length");
    let elf_path = std::env::var_os("LINKED_GUEST_ELF").context("LINKED_GUEST_ELF required")?;
    let elf = bounded(elf_path.as_ref(), 4 * 1024 * 1024)?;
    ensure!(
        compute_image_id(&elf)?.to_string() == LINKED_ID.trim(),
        "unknown guest image"
    );
    let mut builder = ExecutorEnv::builder();
    builder
        .write_slice(&parent)
        .write_slice(&header)
        .add_assumption(proof);
    let server = std::env::var_os("RISC0_SERVER_PATH").unwrap_or_else(|| "r0vm".into());
    let prover = ExternalProver::new("local-r0vm", server);
    let info = prover.prove_with_opts(builder.build()?, &elf, &ProverOpts::succinct())?;
    let point = &info.receipt.journal.bytes;
    let receipt = bincode::serialize(&info.receipt)?;
    ensure!(receipt.len() <= MAX_RECEIPT, "proof exceeds size limit");
    verify("main", point, &receipt)?;
    ensure!(
        point[48..448] == header && point[584..] == parent,
        "guest output does not correspond to the supplied inputs"
    );
    let parent_dir = out
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let tmp = tempfile::tempdir_in(parent_dir)?;
    fs::write(tmp.path().join("checkpoint.bin"), point)?;
    fs::write(tmp.path().join("history.receipt"), receipt)?;
    fs::rename(tmp.path(), out)?;
    Ok(())
}
