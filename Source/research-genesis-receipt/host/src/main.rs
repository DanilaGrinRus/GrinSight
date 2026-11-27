use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{InnerReceipt, Receipt};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, ExitCode};

const IMAGE_ID: [u32; 8] = include!(concat!(env!("OUT_DIR"), "/image-id.rs"));
const ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/grin-genesis.elf"));
const GENESIS: &[u8; 400] = include_bytes!("../../guest/src/mainnet-genesis.bin");
const POINT_LEN: usize = 520;
const MAX_RECEIPT: usize = 2 * 1024 * 1024;

fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input exceeds size limit");
    Ok(bytes)
}

fn strict_receipt(bytes: &[u8]) -> Result<Receipt> {
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding().with_limit(MAX_RECEIPT as u64).reject_trailing_bytes()
        .deserialize(bytes).context("unrecognized proof encoding")?;
    ensure!(matches!(receipt.inner, InnerReceipt::Succinct(_)), "expected succinct proof");
    receipt.verify(IMAGE_ID).context("cryptographic verification failed")?;
    Ok(receipt)
}

fn verify(net: &str, point_file: &Path, proof_file: &Path) -> Result<()> {
    ensure!(net == "main", "unsupported network");
    let point = bounded(point_file, POINT_LEN)?;
    ensure!(point.len() == POINT_LEN && &point[..8] == b"GSZ1MH01", "bad checkpoint schema");
    let proof = strict_receipt(&bounded(proof_file, MAX_RECEIPT)?)?;
    ensure!(proof.journal.bytes == point, "proof does not bind the supplied checkpoint");
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    println!("network=main height={} hash={} total_difficulty={} header_pmmr_root={} freshness=unknown",
        u64::from_be_bytes(point[8..16].try_into()?),
        hex(&point[448..480]), u64::from_be_bytes(point[480..488].try_into()?),
        hex(&point[488..520]));
    Ok(())
}

fn frame(reader: &mut File) -> Result<[u8; 400]> {
    let mut len = [0; 2];
    reader.read_exact(&mut len)?;
    ensure!(u16::from_be_bytes(len) == 400, "wrong frame size for Mainnet C29");
    let mut header = [0; 400];
    reader.read_exact(&mut header)?;
    Ok(header)
}

fn prove(input: &Path, out: &Path) -> Result<()> {
    ensure!(!out.exists(), "output directory already exists");
    let mut source = File::open(input)?;
    ensure!(&frame(&mut source)? == GENESIS, "fixture starts at a different genesis");
    let witness = frame(&mut source)?;
    // This bounded first-block experiment intentionally ignores subsequent frames.
    let parent = out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let tmp = tempfile::tempdir_in(parent)?;
    let work = tmp.path();
    let elf = work.join("guest.elf");
    let header = work.join("header.bin");
    let proof = work.join("history.receipt");
    let point = work.join("checkpoint.bin");
    fs::write(&elf, ELF)?;
    fs::write(&header, witness)?;
    let status = Command::new("r0vm").env_remove("RISC0_DEV_MODE")
        .arg("--elf").arg(&elf).arg("--initial-input").arg(&header)
        .arg("--receipt-kind").arg("succinct").arg("--receipt").arg(&proof).status()?;
    ensure!(status.success(), "local r0vm prover failed");
    let receipt = strict_receipt(&bounded(&proof, MAX_RECEIPT)?)?;
    let mut file = File::create(&point)?;
    file.write_all(&receipt.journal.bytes)?;
    file.sync_all()?;
    drop(file);
    verify("main", &point, &proof)?;
    fs::remove_file(elf)?;
    fs::remove_file(header)?;
    fs::rename(work, out)?;
    Ok(())
}

fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.as_slice() {
        [v, network, p, r] if v == "verify" => verify(network, p.as_ref(), r.as_ref()),
        [v, input, out] if v == "prove" => prove(input.as_ref(), out.as_ref()),
        _ => bail!("usage: research-grin-receipt prove HEADER_DUMP NEW_DIRECTORY | verify main CHECKPOINT RECEIPT"),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => { eprintln!("refused: {e:#}"); ExitCode::FAILURE }
    }
}

