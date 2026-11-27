//! Independent native oracle for the fixed Mainnet H2 experiment.
//! export reads genesis and three successors from a framed public fixture.
//! resume takes only the authenticated H2 point and one raw successor.
use fly_chain_headers::{genesis::GenesisVerifier, hash_bytes, read_header, write_header, Net};
use grin_core::core::BlockHeader;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

const HEADER: usize = 400;
const H1_LEN: usize = 520;
const H2_BASE: usize = 584;
const H2_LEN: usize = H2_BASE + H1_LEN;
// A fixed historical observation time well after the three January 2019 headers.
const OBSERVED_AT: u64 = 1_548_979_200;

fn error(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

fn decode(raw: &[u8]) -> io::Result<BlockHeader> {
    let h = read_header(raw).ok_or_else(|| error("invalid header"))?;
    if raw.len() != HEADER || write_header(&h).as_deref() != Some(raw) {
        return Err(error("noncanonical header"));
    }
    Ok(h)
}

fn push(chain: &mut GenesisVerifier, raw: &[u8]) -> io::Result<()> {
    chain
        .push(&decode(raw)?, OBSERVED_AT)
        .map_err(|e| error(&format!("{e:?}")))
}

fn point(chain: &GenesisVerifier, previous: Option<&[u8]>) -> io::Result<Vec<u8>> {
    let header = chain.tip();
    let mut out = Vec::new();
    match (header.height, previous) {
        (1, None) => out.extend_from_slice(b"GSZ1MH01"),
        (2, Some(prior)) if prior.len() == H1_LEN => out.extend_from_slice(b"GSZ2MH02"),
        _ => return Err(error("unsupported point height")),
    }
    out.extend_from_slice(&header.height.to_be_bytes());
    out.extend_from_slice(&Net::Main.genesis_hash());
    out.extend_from_slice(&write_header(header).ok_or_else(|| error("header serialization"))?);
    out.extend_from_slice(&hash_bytes(header));
    out.extend_from_slice(&header.total_difficulty().to_num().to_be_bytes());
    out.extend_from_slice(chain.peaks().root().as_bytes());
    if let Some(prior) = previous {
        if chain.peaks().hashes().len() != 2 {
            return Err(error("expected two peaks after H2"));
        }
        for peak in chain.peaks().hashes() {
            out.extend_from_slice(peak.as_bytes());
        }
        out.extend_from_slice(prior);
    }
    Ok(out)
}

fn report(chain: &GenesisVerifier) {
    let h = chain.tip();
    println!("height={} timestamp={} hash={} td={} achieved={} scaling={} edge_bits={} pmmr_size={} root={}",
        h.height, h.timestamp.timestamp(), hex(&hash_bytes(h)), h.total_difficulty().to_num(),
        h.pow.to_difficulty(h.height).to_num(), h.pow.secondary_scaling, h.pow.edge_bits(),
        chain.peaks().size(), hex(chain.peaks().root().as_bytes()));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fixed_file(path: &Path, size: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(size + 1);
    File::open(path)?
        .take(size as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() != size {
        return Err(error("unexpected file size"));
    }
    Ok(bytes)
}

fn frame(reader: &mut File) -> io::Result<[u8; HEADER]> {
    let mut length = [0; 2];
    reader.read_exact(&mut length)?;
    if usize::from(u16::from_be_bytes(length)) != HEADER {
        return Err(error("unexpected frame"));
    }
    let mut raw = [0; HEADER];
    reader.read_exact(&mut raw)?;
    Ok(raw)
}

fn export(source: &Path, out: &Path, mut chain: GenesisVerifier) -> io::Result<()> {
    let mut reader = File::open(source)?;
    chain
        .check_genesis(&decode(&frame(&mut reader)?)?)
        .map_err(|_| error("wrong genesis"))?;
    push(&mut chain, &frame(&mut reader)?)?;
    let h1 = point(&chain, None)?;
    report(&chain);
    push(&mut chain, &frame(&mut reader)?)?;
    let h2 = point(&chain, Some(&h1))?;
    report(&chain);
    let next = frame(&mut reader)?;
    push(&mut chain, &next)?;
    report(&chain);
    fs::create_dir(out)?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join("checkpoint.bin"))?
        .write_all(&h2)?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(out.join("next-header.bin"))?
        .write_all(&next)?;
    Ok(())
}

fn resume(path: &Path, next: &Path, mut chain: GenesisVerifier) -> io::Result<()> {
    let supplied = fixed_file(path, H2_LEN)?;
    // The prior point carries H1 in full. Recompute each boundary from exact
    // compiled genesis and canonical headers using the independent native code.
    push(&mut chain, &supplied[H2_BASE + 48..H2_BASE + 48 + HEADER])?;
    let h1 = point(&chain, None)?;
    push(&mut chain, &supplied[48..48 + HEADER])?;
    let h2 = point(&chain, Some(&h1))?;
    if h2 != supplied {
        return Err(error("H2 full boundary mismatch"));
    }
    push(&mut chain, &fixed_file(next, HEADER)?)?;
    report(&chain);
    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [mode, input, out] = args.as_slice() else {
        return Err(error(
            "export FRAMED NEW_DIRECTORY | resume H2_POINT H3_RAW",
        ));
    };
    let chain =
        GenesisVerifier::new(Net::Main).map_err(|_| error("native genesis initialization"))?;
    if mode == "export" {
        export(input.as_ref(), out.as_ref(), chain)
    } else if mode == "resume" {
        resume(input.as_ref(), out.as_ref(), chain)
    } else {
        Err(error("unknown mode"))
    }
}
