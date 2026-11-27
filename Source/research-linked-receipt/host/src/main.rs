use anyhow::{bail, ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::{InnerReceipt, Receipt};
use std::{fs::File, io::Read, path::Path, process::ExitCode};

#[cfg(all(feature = "producer", target_os = "linux"))]
mod producer;

const LINKED_ID: &str = include_str!("../../image-id.hex");
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
    let expected = expected.trim();
    ensure!(
        expected.len() == 64 && expected.is_ascii(),
        "invalid pinned image"
    );
    let mut image_id = [0u32; 8];
    for (i, word) in image_id.iter_mut().enumerate() {
        *word = u32::from_str_radix(&expected[8 * i..8 * i + 8], 16)?.swap_bytes();
    }
    receipt
        .verify(image_id)
        .context("cryptographic verification failed")?;
    ensure!(
        receipt.journal.bytes == journal,
        "proof does not bind the supplied checkpoint"
    );
    Ok(receipt)
}

fn verify(net: &str, point: &[u8], proof: &[u8]) -> Result<()> {
    ensure!(net == "main", "unsupported network");
    ensure!(
        point.len() == 1104
            && &point[..8] == b"GSZ2MH02"
            && u64::from_be_bytes(point[8..16].try_into()?) == 2,
        "bad checkpoint schema"
    );
    verified(proof, LINKED_ID, point)?;
    println!(
        "network=main height=2 hash={} total_difficulty={} header_pmmr_root={} freshness=unknown",
        hex(&point[448..480]),
        u64::from_be_bytes(point[480..488].try_into()?),
        hex(&point[488..520])
    );
    Ok(())
}

fn run() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.as_slice() {
        [cmd, net, point, proof] if cmd == "verify" =>
            verify(net, &bounded(point.as_ref(), 1104)?, &bounded(proof.as_ref(), MAX_RECEIPT)?),
        #[cfg(all(feature = "producer", target_os = "linux"))]
        [cmd, h1, prior, header, out] if cmd == "prove" =>
            producer::prove(h1.as_ref(), prior.as_ref(), header.as_ref(), out.as_ref()),
        #[cfg(all(feature = "producer", target_os = "linux"))]
        [cmd, raw, out] if cmd == "pack-elf" => producer::pack(raw.as_ref(), out.as_ref()),
        _ => bail!("usage: verify main CHECKPOINT RECEIPT | prove H1_CHECKPOINT H1_RECEIPT H2_HEADER NEW_DIRECTORY"),
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

#[cfg(test)]
mod tests {
    use super::*;

    const POINT: &[u8] = include_bytes!("../../testdata/checkpoint.bin");
    const PROOF: &[u8] = include_bytes!("../../testdata/history.receipt");

    #[test]
    fn standalone_verifier_accepts_complete_two_file_checkpoint() {
        verify("main", POINT, PROOF).unwrap();
    }

    #[test]
    fn verifier_checks_network_exact_journal_pinned_image_and_complete_encoding() {
        assert!(verify("test", POINT, PROOF).is_err());
        let mut changed = POINT.to_vec();
        changed[519] ^= 1;
        assert!(verify("main", &changed, PROOF).is_err());
        let old = include_bytes!("../../../research-genesis-receipt/testdata/history.receipt");
        assert!(verify("main", POINT, old).is_err());
        let mut trailing = PROOF.to_vec();
        trailing.push(0);
        assert!(verify("main", POINT, &trailing).is_err());
    }
}
