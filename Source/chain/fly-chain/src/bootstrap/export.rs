//! Export an independently checkable GSHP1 sample before discarding the verified journal.
use super::invalid;
use fly_chain_headers::{checkpoint, proof, read_header, Net, MAX_HEADER_LEN};
use std::cell::RefCell;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub(super) const POINT: &str = "checkpoint.json";
pub(super) const PROOF: &str = "history.proof";

fn read_limited(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    if !fs::metadata(path)?.is_file() {
        return Err(invalid("expected a regular checkpoint or proof file"));
    }
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(invalid("checkpoint export exceeds its format limit"));
    }
    Ok(bytes)
}

/// Check the exact pair as a recipient would, without changing a wallet.
pub fn check(net: Net, dir: &Path) -> io::Result<proof::Passed> {
    if !fs::metadata(dir)?.is_dir() {
        return super::package::read_file(net, dir).map(|pair| pair.passed);
    }
    VerifiedPair::read(net, &dir.join(POINT), &dir.join(PROOF)).map(|pair| pair.passed)
}

pub(super) struct VerifiedPair {
    pub(super) point: Vec<u8>,
    pub(super) history: Vec<u8>,
    pub(super) passed: proof::Passed,
}

impl VerifiedPair {
    pub(super) fn read(net: Net, point: &Path, history: &Path) -> io::Result<Self> {
        Self::verify(net, read_limited(point, checkpoint::MAX_RECORD_LEN)?, read_limited(history, proof::MAX_PROOF)?)
    }

    pub(super) fn verify(net: Net, point: Vec<u8>, history: Vec<u8>) -> io::Result<Self> {
        let start = checkpoint::check(&point, net).map_err(|_| invalid("invalid exported checkpoint"))?;
        match proof::check_for(&start, &history) {
            proof::History::Sampled(passed) => Ok(Self { point, history, passed }),
            _ => Err(invalid("GSHP1 does not verify for the exact exported checkpoint")),
        }
    }
}

pub(super) const IMPORT: &str = "imported-gshp1-v1";

pub(crate) fn cache(root: &Path) -> std::path::PathBuf {
    root.join(IMPORT).join("cache")
}

pub(crate) fn imported(net: Net, root: &Path) -> io::Result<Option<Vec<u8>>> {
    let dir = root.join(IMPORT);
    if !super::compact::exists(&dir)? {
        return Ok(None);
    }
    Ok(Some(VerifiedPair::read(net, &dir.join(POINT), &dir.join(PROOF))?.point))
}

/// Verify two independently selected files and install their exact bytes in a
/// stopped wallet's chain directory. Publication is one directory rename. The
/// receiver rechecks the pair on startup, including after a lock or restart.
pub fn import_checkpoint(net: Net, root: &Path, point_path: &Path, proof_path: &Path) -> io::Result<proof::Passed> {
    install(net, root, VerifiedPair::read(net, point_path, proof_path)?)
}

pub(super) fn install(net: Net, root: &Path, pair: VerifiedPair) -> io::Result<proof::Passed> {
    let VerifiedPair { point, history, passed } = pair;
    fs::create_dir_all(root)?;
    let lock = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(root.join("import-gshp1.lock"))?;
    lock.try_lock().map_err(|_| io::Error::other("another checkpoint import is in progress"))?;
    if fly_paycore_chain_port::bootstrap::selected(root, net.tag())?
        || super::has_autonomous_state(root)?
        || super::compact::exists(&root.join(crate::OWN_POINT_FILE))?
    {
        return Err(invalid("chain folder already uses a local or user-supplied starting point"));
    }
    let target = root.join(IMPORT);
    if let Some(existing) = imported(net, root)? {
        return if existing == point && read_limited(&target.join(PROOF), proof::MAX_PROOF)? == history {
            Ok(passed)
        } else {
            Err(invalid("a different verified pair is already installed in this chain folder"))
        };
    }
    let stage = root.join("import-gshp1.partial");
    fs::create_dir_all(&stage)?;
    for entry in fs::read_dir(&stage)? {
        let name = entry?.file_name();
        if name != POINT && name != PROOF {
            return Err(invalid("unexpected file in checkpoint import staging directory"));
        }
    }
    write_stage(&stage.join(POINT), &point)?;
    write_stage(&stage.join(PROOF), &history)?;
    fs::rename(&stage, target)?;
    Ok(passed)
}

// proof::build requests the whole prefix in order, then revisits a small set of
// sampled heights. Retain frame offsets, leaving the 1.7 GB journal on disk.
fn sample(journal: &Path, net: Net, height: u64) -> io::Result<Vec<u8>> {
    let file = File::open(journal)?;
    let mut offsets = Vec::<u64>::new();
    let mut reader = BufReader::with_capacity(1 << 20, file);
    let mut next_offset = 0;
    let mut position = 0;
    let mut raw = [0u8; MAX_HEADER_LEN];
    let load = RefCell::new(|h: u64| {
        let index = usize::try_from(h).ok()?;
        let sequential = index == offsets.len();
        let offset = if sequential {
            next_offset
        } else {
            *offsets.get(index)?
        };
        if position != offset {
            reader.seek(SeekFrom::Start(offset)).ok()?;
        }
        let mut prefix = [0u8; 2];
        reader.read_exact(&mut prefix).ok()?;
        let frame = raw.get_mut(..usize::from(u16::from_be_bytes(prefix)))?;
        reader.read_exact(frame).ok()?;
        position = offset.checked_add(2 + frame.len() as u64)?;
        if sequential {
            offsets.push(offset);
            next_offset = position;
        }
        read_header(frame)
    });
    let proof = proof::build(&|h| load.borrow_mut()(h), height, net, proof::POINTS)
        .ok_or_else(|| invalid("could not build GSHP1 from the verified header journal"))?;
    proof::write(&proof, net).ok_or_else(|| invalid("could not serialize GSHP1"))
}

fn write_stage(path: &Path, data: &[u8]) -> io::Result<()> {
    // A previous interrupted write can only leave these two staging names.
    // Remove a regular staging file before recreating it; never truncate a
    // linked file in place or touch the already published pair.
    super::compact::unlink_file(path)?;
    let mut file = File::create_new(path)?;
    file.write_all(data)?;
    file.sync_all()
}

pub(super) fn export_name(net: Net, height: u64, hash: [u8; 32]) -> String {
    let network = match net {
        Net::Main => "main",
        Net::Test => "test",
        Net::Automated => "automated",
    };
    let hash = hash
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    format!("{network}-{height}-{hash}")
}

pub(super) fn publish(net: Net, journal: &Path, record: &[u8], root: &Path) -> io::Result<()> {
    let start =
        checkpoint::check(record, net).map_err(|_| invalid("invalid local export point"))?;
    let name = export_name(net, start.height(), start.hash());
    let exports = root.join("history-exports");
    let target = exports.join(&name);
    fs::create_dir_all(&exports)?;
    let verify = |dir: &Path| -> io::Result<()> {
        if read_limited(&dir.join(POINT), checkpoint::MAX_RECORD_LEN)? != record {
            return Err(invalid(
                "published point differs from the verified local point",
            ));
        }
        check(net, dir).map(|_| ())
    };
    if target.try_exists()? {
        return verify(&target);
    }
    // The bootstrap lock is held. An interrupted build can reuse its staging
    // directory. A recipient sees the two finished files together after rename.
    let stage = exports.join(format!(".{name}.partial"));
    fs::create_dir_all(&stage)?;
    for entry in fs::read_dir(&stage)? {
        let name = entry?.file_name();
        if name != POINT && name != PROOF {
            return Err(invalid(
                "unexpected file in checkpoint export staging directory",
            ));
        }
    }
    let history = sample(journal, net, start.height())?;
    write_stage(&stage.join(POINT), record)?;
    write_stage(&stage.join(PROOF), &history)?;
    verify(&stage)?;
    fs::rename(&stage, &target)?;
    Ok(())
}
