use super::Result;
use fly_chain_headers::{genesis::GenesisVerifier, proof, read_header, Net, MAX_HEADER_LEN};
use std::cell::RefCell;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// An operator-side allocation budget; this is unrelated to chain consensus.
// Regenerate the provider with a larger budget if history outgrows it.
const MAX_HEIGHT: u64 = 16_000_000;

fn next(reader: &mut impl Read) -> Result<Vec<u8>> {
    let mut prefix = [0u8; 2];
    reader.read_exact(&mut prefix)?;
    let len = usize::from(u16::from_be_bytes(prefix));
    if len == 0 || len > MAX_HEADER_LEN {
        return Err("invalid header frame length".into());
    }
    let mut raw = vec![0; len];
    reader.read_exact(&mut raw)?;
    Ok(raw)
}

pub(super) fn from_dump(net: Net, path: &Path, height: u64) -> Result<(Vec<u8>, Vec<u8>)> {
    if !(3..=MAX_HEIGHT).contains(&height) {
        return Err("point is outside provider generator bounds".into());
    }
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let mut chain = GenesisVerifier::new(net).map_err(|e| format!("genesis: {e:?}"))?;
    let mut reader = BufReader::with_capacity(1 << 20, File::open(path)?);
    if !reader.get_ref().metadata()?.is_file() {
        return Err("expected completed header export".into());
    }
    let mut offsets = Vec::new();
    let mut at = 0u64;
    for h in 0..=height {
        let bytes = next(&mut reader)?;
        let header = read_header(&bytes).ok_or("invalid serialized header")?;
        if h == 0 {
            chain
                .check_genesis(&header)
                .map_err(|e| format!("genesis: {e:?}"))?;
        } else {
            chain
                .push(&header, now)
                .map_err(|e| format!("header {h}: {e:?}"))?;
        }
        offsets.push(at);
        at = at
            .checked_add(2 + bytes.len() as u64)
            .ok_or("offset overflow")?;
    }
    let checkpoint = chain
        .record(0)
        .ok_or("point needs a complete supported difficulty context")?;
    let reader = RefCell::new((reader, at));
    let load = |h| {
        let offset = *offsets.get(usize::try_from(h).ok()?)?;
        let mut cursor = reader.borrow_mut();
        let (read, position) = &mut *cursor;
        if *position != offset {
            read.seek(SeekFrom::Start(offset)).ok()?;
        }
        let bytes = next(read).ok()?;
        *position = offset.checked_add(2 + bytes.len() as u64)?;
        read_header(&bytes)
    };
    let candidate =
        proof::build(&load, height, net, proof::POINTS).ok_or("proof generation failed")?;
    let history = proof::write(&candidate, net).ok_or("proof serialization failed")?;
    Ok((checkpoint, history))
}
