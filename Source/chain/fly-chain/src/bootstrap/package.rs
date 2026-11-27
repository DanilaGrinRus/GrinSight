//! GSHPACK1: eight magic/version bytes, two u32 lengths in network byte
//! order, then the unchanged checkpoint JSON and the unchanged GSHP1 proof.
use super::export::{self, VerifiedPair, POINT, PROOF};
use super::invalid;
use fly_chain_headers::{checkpoint, proof, Net};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

const MAGIC: &[u8; 8] = b"GSHPACK1";
const HEADER_SIZE: u64 = 16;

fn read_count(reader: &mut File, limit: usize) -> io::Result<usize> {
    let mut word = [0; 4];
    reader.read_exact(&mut word)?;
    usize::try_from(u32::from_be_bytes(word)).ok()
        .filter(|&n| n > 0 && n <= limit)
        .ok_or_else(|| invalid("invalid checkpoint package length"))
}

pub(super) fn read_file(net: Net, file: &Path) -> io::Result<VerifiedPair> {
    if file.extension().and_then(|ext| ext.to_str()).is_some_and(|ext| ext.eq_ignore_ascii_case("json")) {
        return VerifiedPair::read(net, file, &file.with_file_name(PROOF));
    }
    if !fs::metadata(file)?.is_file() {
        return Err(invalid("expected a checkpoint package file"));
    }
    let mut reader = File::open(file)?;
    let mut magic = [0; 8];
    reader.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(invalid("unsupported checkpoint package format or version"));
    }
    let point_len = read_count(&mut reader, checkpoint::MAX_RECORD_LEN)?;
    let proof_len = read_count(&mut reader, proof::MAX_PROOF)?;
    let expected = HEADER_SIZE.checked_add(point_len as u64).and_then(|n| n.checked_add(proof_len as u64));
    if Some(reader.metadata()?.len()) != expected {
        return Err(invalid("checkpoint package size differs from its header"));
    }
    let mut point = vec![0; point_len];
    let mut history = vec![0; proof_len];
    reader.read_exact(&mut point)?;
    reader.read_exact(&mut history)?;
    if reader.read(&mut [0])? != 0 {
        return Err(invalid("unexpected data after checkpoint package"));
    }
    VerifiedPair::verify(net, point, history)
}

fn write_package(pair: &VerifiedPair, destination: &Path) -> io::Result<proof::Passed> {
    let folder = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut staged = tempfile::NamedTempFile::new_in(folder)?;
    staged.write_all(MAGIC)?;
    for length in [pair.point.len(), pair.history.len()] {
        let n = u32::try_from(length).map_err(|_| invalid("checkpoint package is too large"))?;
        staged.write_all(&n.to_be_bytes())?;
    }
    staged.write_all(&pair.point)?;
    staged.write_all(&pair.history)?;
    staged.as_file().sync_all()?;
    staged.persist_noclobber(destination).map_err(|err| err.error)?;
    Ok(pair.passed)
}

/// Export a byte-exact verified pair as one file, without overwriting an existing file.
pub fn pack_checkpoint(net: Net, point: &Path, history: &Path, destination: &Path) -> io::Result<proof::Passed> {
    write_package(&VerifiedPair::read(net, point, history)?, destination)
}

/// Import a package, or an exported JSON file with history.proof next to it.
pub fn import_checkpoint_file(net: Net, root: &Path, file: &Path) -> io::Result<proof::Passed> {
    export::install(net, root, read_file(net, file)?)
}

/// Export only the active local or imported anchor. Returns None if the
/// profile has not produced or adopted a transferable point.
pub fn pack_profile_checkpoint(net: Net, root: &Path, destination: &Path) -> io::Result<Option<proof::Passed>> {
    let pair = if fly_paycore_chain_port::bootstrap::selected(root, net.tag())? || super::has_autonomous_state(root)? {
        let slot = super::active_slot(root, false)?;
        if super::pending_slot(root, slot, false)?.is_some() {
            return Ok(None);
        }
        let Some(saved) = super::compact::State::read(&super::generation(root, slot), net)? else { return Ok(None) };
        let start = checkpoint::check(&saved.anchor.bytes, net).map_err(|_| invalid("invalid active checkpoint"))?;
        let dir = root.join("history-exports").join(export::export_name(net, start.height(), start.hash()));
        let pair = VerifiedPair::read(net, &dir.join(POINT), &dir.join(PROOF))?;
        if pair.point != saved.anchor.bytes {
            return Err(invalid("published export differs from the active checkpoint"));
        }
        pair
    } else {
        let dir = root.join(export::IMPORT);
        if !super::compact::exists(&dir)? { return Ok(None); }
        VerifiedPair::read(net, &dir.join(POINT), &dir.join(PROOF))?
    };
    let parent = destination.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    if parent.canonicalize()?.starts_with(root.canonicalize()?) {
        return Err(invalid("choose a destination outside the wallet chain directory"));
    }
    write_package(&pair, destination).map(Some)
}
