use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{InnerReceipt, Receipt};
use std::{fs::File, io::Read, path::Path, process::ExitCode};

#[cfg(all(feature = "producer", target_os = "linux"))]
mod producer;

const BATCH_ID: &str = include_str!("../../image-id.hex");
const MAX_POINT: usize = 4096;
const MAX_RECEIPT: usize = 2 * 1024 * 1024;

fn bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open {}", path.display()))?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= limit, "input exceeds size limit");
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn image_bytes(id: &str) -> Result<[u8; 32]> {
    let id = id.trim();
    ensure!(id.len() == 64 && id.is_ascii(), "invalid pinned image");
    let mut image = [0u8; 32];
    for (i, byte) in image.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&id[2 * i..2 * i + 2], 16)?;
    }
    Ok(image)
}

fn verified(proof: &[u8], expected: &str, journal: &[u8]) -> Result<Receipt> {
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT as u64)
        .reject_trailing_bytes()
        .deserialize(proof)
        .context("unrecognized proof encoding")?;
    ensure!(
        matches!(receipt.inner, InnerReceipt::Succinct(_)),
        "expected succinct proof"
    );
    let bytes = image_bytes(expected)?;
    let id: [u32; 8] =
        std::array::from_fn(|i| u32::from_le_bytes(bytes[4 * i..4 * i + 4].try_into().unwrap()));
    receipt
        .verify(id)
        .context("cryptographic verification failed")?;
    ensure!(
        receipt.journal.bytes == journal,
        "proof does not bind the supplied checkpoint"
    );
    Ok(receipt)
}

fn batch_height(point: &[u8]) -> Result<u64> {
    ensure!(
        point.len() > 561 && point.len() <= MAX_POINT && &point[..8] == b"GSZBMH01",
        "bad batch schema"
    );
    ensure!(
        point[8..40] == image_bytes(BATCH_ID)?,
        "checkpoint names another program"
    );
    let h = u64::from_be_bytes(point[40..48].try_into()?);
    ensure!((3..=1000).contains(&h), "unsupported height");
    let rows = usize::from(point[560]);
    ensure!(rows == (h + 1).min(61) as usize, "incorrect DAA row count");
    let peaks_offset = 561 + 21 * rows;
    ensure!(point.len() > peaks_offset, "incomplete DAA context");
    let peaks = u32::from(point[peaks_offset]);
    ensure!(
        peaks == (h + 1).count_ones() && point.len() == peaks_offset + 1 + 32 * peaks as usize,
        "incorrect PMMR frontier length"
    );
    Ok(h)
}

fn verify(net: &str, point: &[u8], proof: &[u8]) -> Result<()> {
    ensure!(net == "main", "unsupported network");
    let h = batch_height(point)?;
    verified(proof, BATCH_ID, point)?;
    println!(
        "network=main height={h} hash={} total_difficulty={} header_pmmr_root={} freshness=unknown",
        hex(&point[480..512]),
        u64::from_be_bytes(point[512..520].try_into()?),
        hex(&point[528..560])
    );
    Ok(())
}

fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.as_slice() {
        [cmd, net, point, receipt] if cmd == "verify" =>
            verify(net, &bounded(point.as_ref(), MAX_POINT)?, &bounded(receipt.as_ref(), MAX_RECEIPT)?),
        #[cfg(all(feature = "producer", target_os = "linux"))]
        [cmd, parent, receipt, raw, out] if cmd == "prove" =>
            producer::prove(parent.as_ref(), receipt.as_ref(), raw.as_ref(), out.as_ref()),
        #[cfg(all(feature = "producer", target_os = "linux"))]
        [cmd, raw, out] if cmd == "pack-elf" => producer::pack(raw.as_ref(), out.as_ref()),
        _ => bail!("usage: verify main CHECKPOINT RECEIPT | prove PARENT_CHECKPOINT PARENT_RECEIPT RAW_HEADERS NEW_DIRECTORY"),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("refused: {e:#}");
            ExitCode::FAILURE
        }
    }
}
