//! Local device state after this installation verified headers from its own genesis.
use super::{atomic, invalid, Anchor};
use fly_chain_headers::{
    chain::{HeaderChain, OpenError},
    checkpoint, Net,
};
use grin_core::{core::hash::HashWriter, ser::Writer};
use std::{
    fs,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

pub(super) const NAME: &str = "autonomous-compact-v1.bin";
pub(super) const SEAL: &str = "autonomous-compact-required-v1";
const MAGIC: &[u8; 8] = b"GSLOCAL1";
const HEADER: usize = 8 + 1 + 32 + 1 + 8 + 32;
const LIMIT: usize = HEADER + checkpoint::MAX_RECORD_LEN + 32;

pub(super) struct State {
    pub(super) slot: bool,
    pub(super) anchor: Anchor,
    pub(super) work: u64,
    pub(super) hash: [u8; 32],
}

fn digest(bytes: &[u8]) -> io::Result<[u8; 32]> {
    let mut writer = HashWriter::default();
    writer.write_fixed_bytes(bytes).map_err(io::Error::other)?;
    writer
        .into_hash()
        .as_bytes()
        .try_into()
        .map_err(|_| invalid("invalid digest length"))
}

pub(super) fn exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

pub(super) fn unlink_file(path: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        other => other?,
    };
    let parent = path
        .parent()
        .ok_or_else(|| invalid("missing generation directory"))?;
    let dir = fs::symlink_metadata(parent)?;
    if !dir.is_dir() || !meta.is_file() {
        return Err(invalid("unexpected bootstrap data path"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (dir.file_attributes() | meta.file_attributes()) & 0x400 != 0 {
            return Err(invalid("bootstrap data path is a reparse point"));
        }
    }
    fs::remove_file(path)
}

pub(super) fn tail(dir: &Path, slot: bool) -> PathBuf {
    dir.join(if slot {
        "autonomous-live-b"
    } else {
        "autonomous-live"
    })
}

impl State {
    pub(super) fn read(dir: &Path, net: Net) -> io::Result<Option<Self>> {
        let path = dir.join(NAME);
        let raw = match File::open(&path) {
            Ok(mut f) => {
                let mut raw = Vec::new();
                (&mut f).take(LIMIT as u64 + 1).read_to_end(&mut raw)?;
                raw
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                if exists(&path)? || exists(&dir.join(SEAL))? {
                    return Err(invalid("published local checkpoint is missing"));
                }
                if !exists(&dir.join(super::LOG))? {
                    for slot in [false, true] {
                        if exists(&tail(dir, slot).join(fly_chain_headers::chain::FILE_NAME))? {
                            return Err(invalid(
                                "local checkpoint for an existing header tail is missing",
                            ));
                        }
                    }
                }
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        if raw.len() <= HEADER + 32
            || raw.len() > LIMIT
            || raw[..8] != *MAGIC
            || raw[8] != net.tag()
            || raw[9..41] != net.genesis_hash()
            || raw[41] > 1
        {
            return Err(invalid("local checkpoint schema or network mismatch"));
        }
        let end = raw.len() - 32;
        if raw[end..] != digest(&raw[..end])? {
            return Err(invalid("local checkpoint integrity mismatch"));
        }
        let work = u64::from_be_bytes(
            raw[42..50]
                .try_into()
                .map_err(|_| invalid("invalid work"))?,
        );
        let hash = raw[50..82]
            .try_into()
            .map_err(|_| invalid("invalid tip hash"))?;
        let bytes = raw[HEADER..end].to_vec();
        let checked =
            checkpoint::check(&bytes, net).map_err(|_| invalid("invalid local checkpoint"))?;
        if work < checked.anchor.total_difficulty().to_num() {
            return Err(invalid("invalid published work"));
        }
        Ok(Some(Self {
            slot: raw[41] != 0,
            work,
            hash,
            anchor: Anchor {
                height: checked.height(),
                bytes,
            },
        }))
    }

    pub(super) fn open(
        &self,
        dir: &Path,
        net: Net,
    ) -> Result<(HeaderChain, fly_chain_headers::chain::Opened), OpenError> {
        HeaderChain::open_published(
            &tail(dir, self.slot),
            net,
            &self.anchor.bytes,
            self.work,
            self.hash,
        )
    }

    pub(super) fn publish(&self, dir: &Path, net: Net) -> io::Result<()> {
        let start = checkpoint::check(&self.anchor.bytes, net)
            .map_err(|_| invalid("invalid checkpoint at publication"))?;
        if start.height() != self.anchor.height
            || self.work < start.anchor.total_difficulty().to_num()
        {
            return Err(invalid("inconsistent local anchor at publication"));
        }
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(net.tag());
        bytes.extend_from_slice(&net.genesis_hash());
        bytes.push(u8::from(self.slot));
        bytes.extend_from_slice(&self.work.to_be_bytes());
        bytes.extend_from_slice(&self.hash);
        bytes.extend_from_slice(&self.anchor.bytes);
        bytes.extend_from_slice(&digest(&bytes)?);
        atomic(dir, NAME, &bytes)?;
        let stored =
            Self::read(dir, net)?.ok_or_else(|| invalid("missing checkpoint after publication"))?;
        if stored.hash != self.hash
            || stored.work != self.work
            || stored.anchor.bytes != self.anchor.bytes
            || stored.slot != self.slot
        {
            return Err(invalid("published checkpoint readback mismatch"));
        }
        Self::ensure_seal(dir)
    }

    pub(super) fn ensure_seal(dir: &Path) -> io::Result<()> {
        match super::small(&dir.join(SEAL))? {
            Some(data) if data == MAGIC => Ok(()),
            Some(_) => Err(invalid("invalid checkpoint publication marker")),
            None => atomic(dir, SEAL, MAGIC),
        }
    }
}
