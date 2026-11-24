//! The blocks since the archive header, kept in a file, and the state they
//! lead to.
//!
//! Carrying the state forward takes the blocks; fetching a few thousand of
//! them again at every start would be slow and would lean on peers for
//! nothing. So each block is written down once it has been applied.
//!
//! The file is not trusted. Every time it is opened the blocks in it are
//! applied again to the state collected at the archive header, each under
//! its header from the verified header chain: a block whose contents do
//! not give the roots its header commits to - or whose header is no longer
//! in the verified chain - ends the file there. What the roots cannot
//! tell, whether the contents are a valid block, was checked when the
//! block arrived and cannot have changed without the roots changing.
use crate::advance::{Applied, Check, Live, Rejected};
use crate::archive::State;
use grin_core::core::hash::{Hash, Hashed, HashWriter};
use grin_core::core::{Block, BlockHeader};
use grin_core::ser::{self, DeserializationMode, ProtocolVersion, Writer};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// The name of the file in the data directory.
pub const FILE_NAME: &str = "blocks.dat";

const MAGIC: &[u8; 8] = b"FLYBLK1\n";
/// Magic, height, hash of the archive header.
const START_LEN: u64 = 48;
/// No block is larger.
const MAX_RECORD: u32 = 8 * 1024 * 1024;
/// The file is synced to disk after this many blocks.
const SYNC_EVERY: u32 = 64;

/// Why the file could not be opened.
#[derive(Debug)]
pub enum BlocksError {
    /// The file system refused.
    Io(io::Error),
    /// Another process has the file.
    Busy,
    /// The file is not a file of blocks. It is left alone.
    NotOurs,
    /// The file holds the blocks after another archive header: its height
    /// and hash. It is left alone unless opening was told to start over.
    Other(u64, Hash),
    /// The state handed in cannot be carried forward.
    State,
}

/// Why a block was not added.
#[derive(Debug)]
pub enum AddError {
    /// It was not applied.
    Rejected(Rejected),
    /// It could not be written down, and was taken back: the file and the
    /// state stay together.
    Io(io::Error),
}

/// What was found in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reopened {
    /// Blocks that were in the file and were applied again.
    pub kept: u64,
    /// Bytes cut off the end.
    pub cut_bytes: u64,
}

struct Record {
    end: u64,
    digest: Hash,
}

fn record_digest(bytes: &[u8]) -> io::Result<Hash> {
    let mut writer = HashWriter::default();
    writer.write_fixed_bytes(bytes).map_err(io::Error::other)?;
    Ok(writer.into_hash())
}

/// The state and the file of the blocks that led to it.
pub struct Blocks {
    file: File,
    live: Live,
    /// Positions and digests rebuilt from verified records after every open.
    records: Vec<Record>,
    unsynced: u32,
    base: BlockHeader,
}

fn start_bytes(header: &BlockHeader) -> Vec<u8> {
    let mut start = Vec::with_capacity(48);
    start.extend_from_slice(MAGIC);
    start.extend_from_slice(&header.height.to_be_bytes());
    start.extend_from_slice(header.hash().as_bytes());
    start
}

fn read_start(start: &[u8]) -> Option<(u64, Hash)> {
    let (magic, rest) = start.split_first_chunk::<8>()?;
    let (height, hash) = rest.split_first_chunk::<8>()?;
    if magic != MAGIC || hash.len() != 32 {
        return None;
    }
    Some((u64::from_be_bytes(*height), Hash::from_vec(hash)))
}

fn read_up_to(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while let Some(rest) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) {
        match file.read(rest)? {
            0 => break,
            n => filled = filled.saturating_add(n),
        }
    }
    Ok(filled)
}

fn decode(mut bytes: &[u8]) -> Option<Block> {
    let block = ser::deserialize(&mut bytes, ProtocolVersion::local(), DeserializationMode::default()).ok()?;
    bytes.is_empty().then_some(block)
}

impl Blocks {
    /// Open the file in `dir` for the blocks after the header `state` is
    /// at, and apply what it holds. `verified` gives the header of the
    /// verified chain at a height, if there is one. With `over`, a file for
    /// another archive header is started over.
    pub fn open(dir: &Path, state: State, over: bool, verified: impl Fn(u64) -> Option<BlockHeader>) -> Result<(Blocks, Reopened), BlocksError> {
        Self::open_with_state(dir, || Ok(state), over, verified)
    }

    /// Acquire the block file before consuming the caller's archive state.
    /// A busy file leaves the state available for a later attempt.
    pub fn open_with_state(
        dir: &Path,
        state: impl FnOnce() -> Result<State, BlocksError>,
        over: bool,
        verified: impl Fn(u64) -> Option<BlockHeader>,
    ) -> Result<(Blocks, Reopened), BlocksError> {
        std::fs::create_dir_all(dir).map_err(BlocksError::Io)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(FILE_NAME))
            .map_err(BlocksError::Io)?;
        if file.try_lock().is_err() {
            return Err(BlocksError::Busy);
        }
        let total = file.metadata().map_err(BlocksError::Io)?.len();
        let state = state()?;
        let ours = start_bytes(&state.header);
        let mut start = [0u8; 48];
        let n = read_up_to(&mut file, &mut start).map_err(BlocksError::Io)?;
        let found = start.get(..n).unwrap_or_default();
        let unfinished = total < START_LEN && (MAGIC.starts_with(found) || found.starts_with(MAGIC));
        let fresh = if total == 0 || unfinished {
            true
        } else {
            match read_start(found) {
                None => return Err(BlocksError::NotOurs),
                Some(_) if found == ours.as_slice() => false,
                Some(_) if over => true,
                Some((height, hash)) => return Err(BlocksError::Other(height, hash)),
            }
        };
        let mut blocks = Blocks {
            file,
            base: state.header.clone(),
            live: Live::new(state).ok_or(BlocksError::State)?,
            records: Vec::new(),
            unsynced: 0,
        };
        if fresh {
            blocks.file.set_len(0).map_err(BlocksError::Io)?;
            blocks.file.seek(SeekFrom::Start(0)).map_err(BlocksError::Io)?;
            blocks.file.write_all(&ours).map_err(BlocksError::Io)?;
            blocks.file.sync_data().map_err(BlocksError::Io)?;
            return Ok((blocks, Reopened { kept: 0, cut_bytes: 0 }));
        }
        blocks.replay(verified).map_err(BlocksError::Io)?;
        let len = blocks.len();
        let cut_bytes = total.saturating_sub(len);
        if cut_bytes > 0 {
            blocks.file.set_len(len).map_err(BlocksError::Io)?;
            blocks.file.sync_data().map_err(BlocksError::Io)?;
        }
        let kept = u64::try_from(blocks.records.len()).unwrap_or(u64::MAX);
        Ok((blocks, Reopened { kept, cut_bytes }))
    }

    /// Length of the file up to the last whole block.
    fn len(&self) -> u64 {
        self.records.last().map(|record| record.end).unwrap_or(START_LEN)
    }

    fn replay(&mut self, verified: impl Fn(u64) -> Option<BlockHeader>) -> io::Result<()> {
        loop {
            let mut head = [0u8; 4];
            if read_up_to(&mut self.file, &mut head)? != head.len() {
                return Ok(());
            }
            let length = u32::from_be_bytes(head);
            let Some(size) = usize::try_from(length).ok().filter(|_| length <= MAX_RECORD) else {
                return Ok(());
            };
            let mut body = vec![0u8; size];
            if read_up_to(&mut self.file, &mut body)? != size {
                return Ok(());
            }
            let next = self.live.header().height.saturating_add(1);
            let applied = decode(&body).zip(verified(next)).is_some_and(|(block, header)| {
                // the block was checked when it arrived; here the roots say
                // whether it is still that block
                self.live.apply(&block, &header, Check::Kept, None).is_ok()
            });
            if !applied {
                return Ok(());
            }
            self.records.push(Record {
                end: self.len().saturating_add(4).saturating_add(u64::from(length)),
                digest: record_digest(&body)?,
            });
        }
    }

    /// The state.
    pub fn live(&self) -> &Live {
        &self.live
    }

    /// The archive header: where the blocks begin.
    pub fn base(&self) -> &BlockHeader {
        &self.base
    }

    /// The block at `height`, read back from the file, if it is one of the
    /// blocks applied since the archive header.
    pub fn read(&mut self, height: u64) -> io::Result<Option<Block>> {
        let Some(index) = height.checked_sub(self.base.height).and_then(|n| n.checked_sub(1)).and_then(|n| usize::try_from(n).ok()) else {
            return Ok(None);
        };
        let Some(record) = self.records.get(index) else {
            return Ok(None);
        };
        let start = index.checked_sub(1).and_then(|before| self.records.get(before).map(|record| record.end)).unwrap_or(START_LEN);
        let Some(size) = record.end.checked_sub(start).and_then(|n| n.checked_sub(4)).and_then(|n| usize::try_from(n).ok()) else {
            return Ok(None);
        };
        let mut body = vec![0u8; size];
        self.file.seek(SeekFrom::Start(start.saturating_add(4)))?;
        self.file.read_exact(&mut body)?;
        if record_digest(&body)? != record.digest {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "cached block changed since verification"));
        }
        Ok(decode(&body).filter(|block| block.header.height == height))
    }

    /// Length of the file.
    pub fn file_len(&self) -> u64 {
        self.len()
    }

    /// Apply the block that follows the state, with every check, and write
    /// it down. `verified` and `mature_below` as for [`Live::apply`].
    pub fn add(&mut self, block: &Block, verified: &BlockHeader, mature_below: Option<u64>) -> Result<Applied, AddError> {
        let applied = self.live.apply(block, verified, Check::Arrived, mature_below).map_err(AddError::Rejected)?;
        match self.write(block, File::sync_data) {
            Ok(()) => Ok(applied),
            Err(e) => {
                self.live.undo();
                Err(AddError::Io(e))
            }
        }
    }

    fn write(&mut self, block: &Block, sync_data: impl FnOnce(&File) -> io::Result<()>) -> io::Result<()> {
        let bytes = ser::ser_vec(block, ProtocolVersion::local()).map_err(|_| io::Error::other("a block could not be written out"))?;
        let Some(length) = u32::try_from(bytes.len()).ok().filter(|n| *n <= MAX_RECORD) else {
            return Err(io::Error::other("a block too large to keep"));
        };
        let digest = record_digest(&bytes)?;
        let at = self.len();
        self.file.seek(SeekFrom::Start(at))?;
        let pending = self.unsynced.saturating_add(1);
        let flush = pending >= SYNC_EVERY;
        let stored = self.file.write_all(&length.to_be_bytes())
            .and_then(|()| self.file.write_all(&bytes))
            .and_then(|()| if flush { sync_data(&self.file) } else { Ok(()) });
        if let Err(error) = stored {
            self.file.set_len(at)?;
            return Err(error);
        }
        self.records.push(Record {
            end: at.saturating_add(4).saturating_add(u64::from(length)),
            digest,
        });
        self.unsynced = if flush { 0 } else { pending };
        Ok(())
    }

    /// Make sure what was written is on disk.
    pub fn sync(&mut self) -> io::Result<()> {
        self.file.sync_data()?;
        self.unsynced = 0;
        Ok(())
    }

    /// Take the last block back, in the state and in the file. False if
    /// the state is at the archive header.
    pub fn back(&mut self) -> io::Result<bool> {
        if self.records.is_empty() || !self.live.undo() {
            return Ok(false);
        }
        self.records.pop();
        self.file.set_len(self.len())?;
        self.sync()?;
        Ok(true)
    }
}

#[cfg(all(test, feature = "testkit"))]
mod write_tests {
    use super::*;
    use crate::mmr::Builder;
    use crate::testkit::Temp;
    use grin_chain::txhashset::BitmapAccumulator;

    #[test]
    #[allow(clippy::unwrap_used)]
    fn a_disk_read_must_still_match_the_verified_record() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
        let mut block = grin_core::genesis::genesis_main();
        let state = State {
            header: block.header.clone(),
            bitmap: BitmapAccumulator::new(),
            unspent: Vec::new(),
            outputs: Builder::new(),
            rangeproofs: Builder::new(),
            kernels: Builder::new(),
        };
        let tmp = Temp::new("cached-read-integrity");
        let (mut blocks, _) = Blocks::open(&tmp.0, state, false, |_| None).unwrap();
        block.header.height = 1;
        blocks.write(&block, File::sync_data).unwrap();
        assert_eq!(blocks.read(1).unwrap().unwrap().header, block.header);
        // Simulate a storage error after indexing, independently of the decoder.
        let pos = blocks.file_len().checked_sub(1).unwrap();
        let mut byte = [0; 1];
        blocks.file.seek(SeekFrom::Start(pos)).unwrap();
        blocks.file.read_exact(&mut byte).unwrap();
        byte.iter_mut().for_each(|b| *b ^= 1);
        blocks.file.seek(SeekFrom::Start(pos)).unwrap();
        blocks.file.write_all(&byte).unwrap();
        let outcome = match blocks.read(1) {
            Ok(Some(_)) => "returned a block",
            Ok(None) => "no block",
            Err(error) if error.kind() == io::ErrorKind::InvalidData => "integrity error",
            Err(_) => "other I/O error",
        };
        assert_eq!(outcome, "integrity error");
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn retry_after_a_flush_error_keeps_one_record() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
        let block = grin_core::genesis::genesis_main();
        let state = State {
            header: block.header.clone(),
            bitmap: BitmapAccumulator::new(),
            unspent: Vec::new(),
            outputs: Builder::new(),
            rangeproofs: Builder::new(),
            kernels: Builder::new(),
        };
        let tmp = Temp::new("flush-retry");
        let (mut blocks, _) = Blocks::open(&tmp.0, state, false, |_| None).unwrap();
        let previous_len = blocks.file_len();
        blocks.unsynced = SYNC_EVERY.saturating_sub(1);
        let previous_count = blocks.unsynced;
        assert!(blocks.write(&block, |_| Err(io::Error::other("test flush"))).is_err());
        assert_eq!(blocks.file_len(), previous_len);
        assert_eq!(blocks.unsynced, previous_count);
        let mut flushed = false;
        blocks.write(&block, |file| { flushed = true; file.sync_data() }).unwrap();
        assert!(flushed);
        assert_eq!(blocks.records.len(), 1);
        assert_eq!(blocks.unsynced, 0);
        assert_eq!(blocks.file.metadata().unwrap().len(), blocks.file_len());
    }
}
