//! The collected segments, kept in a file so that collecting goes on after
//! a restart.
//!
//! The file is not trusted. Every time it is opened, each segment in it is
//! put through the collector again - the node's check against the header,
//! then the reading - exactly as when it came from a peer. Whatever does
//! not pass, and everything after it, is cut off and asked for again.
//!
//! What is kept of a segment is only what was read from it: the pieces the
//! node's check covers. A node that has not pruned its files sends every
//! leaf and every hash; most of that is neither checked nor read, and it
//! is not written.
use crate::archive::{Collector, Refused, State, Wanted};
use grin_chain::txhashset::{BitmapChunk, BitmapSegment};
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{BlockHeader, OutputIdentifier, Segment, TxKernel};
use grin_core::ser::{self, DeserializationMode, ProtocolVersion, Readable, Writeable};
use grin_util::secp::pedersen::RangeProof;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// The name of the file in the data directory.
pub const FILE_NAME: &str = "state.dat";

const MAGIC: &[u8; 8] = b"FLYSTA1\n";
/// Magic, height, hash of the archive header.
const START_LEN: u64 = 48;
/// Kind and length of a record.
const RECORD_HEAD: u64 = 5;
/// No segment is larger: a node's message with one is at most this.
const MAX_RECORD: u32 = 16 * 1024 * 1024;
/// The file is synced to disk after this many segments.
const SYNC_EVERY: u32 = 64;

const KIND_BITMAP: u8 = 1;
const KIND_OUTPUT: u8 = 2;
const KIND_RANGEPROOF_TAIL: u8 = 3;
const KIND_KERNEL_TAIL: u8 = 4;

/// Why the file could not be opened.
#[derive(Debug)]
pub enum StoreError {
    /// The file system refused.
    Io(io::Error),
    /// Another process has the file.
    Busy,
    /// The file is not a state file. It is left alone.
    NotOurs,
    /// The file holds the state at another header: its height and hash. It
    /// is left alone; [`Store::begin`] starts it over.
    Other(u64, Hash),
}

/// Why a segment was not kept.
#[derive(Debug)]
pub enum AddError {
    /// The collector did not take it.
    Refused(Refused),
    /// It was taken, and writing it down failed. The collector has it; the
    /// file does not, and after a restart it will be asked for again.
    Io(io::Error),
}

/// What was found in the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    /// Segments that were in the file and passed again.
    pub kept: u64,
    /// Bytes cut off the end: what did not pass, and what followed it.
    pub cut_bytes: u64,
}

/// The collector together with its file.
pub struct Store {
    file: File,
    collector: Collector,
    /// Length of the file up to the last whole record.
    len: u64,
    unsynced: u32,
}

fn start_bytes(header: &BlockHeader) -> Vec<u8> {
    let mut start = Vec::with_capacity(48);
    start.extend_from_slice(MAGIC);
    start.extend_from_slice(&header.height.to_be_bytes());
    start.extend_from_slice(header.hash().as_bytes());
    start
}

/// The header a start names, if it is a start.
fn read_start(start: &[u8]) -> Option<(u64, Hash)> {
    let (magic, rest) = start.split_first_chunk::<8>()?;
    let (height, hash) = rest.split_first_chunk::<8>()?;
    if magic != MAGIC || hash.len() != 32 {
        return None;
    }
    Some((u64::from_be_bytes(*height), Hash::from_vec(hash)))
}

fn decode<T: Readable>(mut bytes: &[u8]) -> Option<T> {
    let value = ser::deserialize(&mut bytes, ProtocolVersion::local(), DeserializationMode::default()).ok()?;
    // nothing may follow
    bytes.is_empty().then_some(value)
}

fn encode<T: Writeable>(thing: &T) -> io::Result<Vec<u8>> {
    ser::ser_vec(thing, ProtocolVersion::local()).map_err(|_| io::Error::other("a segment could not be written out"))
}

/// Read up to `buf.len()` bytes; fewer only at the end of the file.
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

impl Store {
    /// Which header the file in `dir` holds the state of, if there is a
    /// state file there.
    pub fn peek(dir: &Path) -> io::Result<Option<(u64, Hash)>> {
        let mut file = match File::open(dir.join(FILE_NAME)) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let mut start = [0u8; 48];
        let n = read_up_to(&mut file, &mut start)?;
        Ok(start.get(..n).and_then(read_start))
    }

    /// Open the file in `dir` for the state at `header`, which must come
    /// from the verified header chain, and put what the file holds through
    /// the collector again.
    pub fn open(dir: &Path, header: BlockHeader) -> Result<(Store, Opened), StoreError> {
        Self::open_inner(dir, header, false)
    }

    /// Start the file in `dir` over for the state at `header`, whatever
    /// state it held.
    pub fn begin(dir: &Path, header: BlockHeader) -> Result<Store, StoreError> {
        Self::open_inner(dir, header, true).map(|(store, _)| store)
    }

    fn open_inner(dir: &Path, header: BlockHeader, over: bool) -> Result<(Store, Opened), StoreError> {
        std::fs::create_dir_all(dir).map_err(StoreError::Io)?;
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(FILE_NAME))
            .map_err(StoreError::Io)?;
        if file.try_lock().is_err() {
            return Err(StoreError::Busy);
        }
        let total = file.metadata().map_err(StoreError::Io)?.len();
        let ours = start_bytes(&header);
        let mut start = [0u8; 48];
        let n = read_up_to(&mut file, &mut start).map_err(StoreError::Io)?;
        let found = start.get(..n).unwrap_or_default();
        let mut store = Store {
            file,
            collector: Collector::new(header),
            len: START_LEN,
            unsynced: 0,
        };
        // a start that was never finished - ours as far as it goes - is no
        // start; anything else that is not a start is somebody else's file
        let unfinished = total < START_LEN && (MAGIC.starts_with(found) || found.starts_with(MAGIC));
        let fresh = if total == 0 || unfinished {
            true
        } else {
            match read_start(found) {
                None => return Err(StoreError::NotOurs),
                Some(_) if over => true,
                Some((height, hash)) if found != ours.as_slice() => return Err(StoreError::Other(height, hash)),
                Some(_) => false,
            }
        };
        if fresh {
            store.file.set_len(0).map_err(StoreError::Io)?;
            store.file.seek(SeekFrom::Start(0)).map_err(StoreError::Io)?;
            store.file.write_all(&ours).map_err(StoreError::Io)?;
            store.file.sync_data().map_err(StoreError::Io)?;
            return Ok((store, Opened { kept: 0, cut_bytes: 0 }));
        }
        let kept = store.replay().map_err(StoreError::Io)?;
        let cut_bytes = total.saturating_sub(store.len);
        if cut_bytes > 0 {
            store.file.set_len(store.len).map_err(StoreError::Io)?;
            store.file.sync_data().map_err(StoreError::Io)?;
        }
        store.file.seek(SeekFrom::Start(store.len)).map_err(StoreError::Io)?;
        Ok((store, Opened { kept, cut_bytes }))
    }

    /// Put the records through the collector, as far as they pass.
    fn replay(&mut self) -> io::Result<u64> {
        let mut kept = 0u64;
        loop {
            let mut head = [0u8; 5];
            if read_up_to(&mut self.file, &mut head)? != head.len() {
                return Ok(kept);
            }
            let [kind, length @ ..] = head;
            let length = u32::from_be_bytes(length);
            if length > MAX_RECORD {
                return Ok(kept);
            }
            let Ok(size) = usize::try_from(length) else {
                return Ok(kept);
            };
            let mut body = vec![0u8; size];
            if read_up_to(&mut self.file, &mut body)? != size {
                return Ok(kept);
            }
            let taken = match kind {
                KIND_BITMAP => body.split_first_chunk::<32>().and_then(|(root, segment)| {
                    // the form a bitmap segment has between nodes; the
                    // chunks alone cannot be read back
                    let segment = decode::<BitmapSegment>(segment)?.into_segment().ok()?;
                    self.collector.add_bitmap(segment, Hash::from_vec(root)).ok()
                }),
                KIND_OUTPUT => decode::<Segment<OutputIdentifier>>(&body).and_then(|s| {
                    // the file says in which segments its output MMR was
                    // collected: the first of them has the height
                    if s.id().height != self.collector.output_height() && !self.collector.set_output_height(s.id().height) {
                        return None;
                    }
                    self.collector.add_output(s).ok()
                }),
                KIND_RANGEPROOF_TAIL => decode::<Segment<RangeProof>>(&body).and_then(|s| self.collector.add_rangeproof_tail(s).ok()),
                KIND_KERNEL_TAIL => decode::<Segment<TxKernel>>(&body).and_then(|s| self.collector.add_kernel_tail(s).ok()),
                _ => None,
            };
            if taken.is_none() {
                return Ok(kept);
            }
            self.len = self.len.saturating_add(RECORD_HEAD).saturating_add(u64::from(length));
            kept = kept.saturating_add(1);
        }
    }

    fn write(&mut self, kind: u8, prefix: &[u8], segment: &[u8]) -> io::Result<()> {
        let length = prefix.len().checked_add(segment.len()).and_then(|n| u32::try_from(n).ok()).filter(|n| *n <= MAX_RECORD);
        let Some(length) = length else {
            return Err(io::Error::other("a segment too large to keep"));
        };
        let mut record = Vec::with_capacity(prefix.len().saturating_add(segment.len()).saturating_add(5));
        record.push(kind);
        record.extend_from_slice(&length.to_be_bytes());
        record.extend_from_slice(prefix);
        record.extend_from_slice(segment);
        // always from the end of the last whole record: a write that failed
        // half way is written over
        self.file.seek(SeekFrom::Start(self.len))?;
        self.file.write_all(&record)?;
        self.len = self.len.saturating_add(RECORD_HEAD).saturating_add(u64::from(length));
        self.unsynced = self.unsynced.saturating_add(1);
        if self.unsynced >= SYNC_EVERY || self.collector.wanted() == Wanted::Nothing {
            self.sync()?;
        }
        Ok(())
    }

    /// Make sure what was written is on disk.
    pub fn sync(&mut self) -> io::Result<()> {
        self.unsynced = 0;
        self.file.sync_data()
    }

    /// The header the state is collected at.
    pub fn header(&self) -> &BlockHeader {
        self.collector.header()
    }

    /// The segment to ask for now.
    pub fn wanted(&self) -> Wanted {
        self.collector.wanted()
    }

    /// How many segments it takes in all, and how many have been taken.
    pub fn progress(&self) -> (u64, u64) {
        self.collector.progress()
    }

    /// How many segments the output MMR has, at the height it is
    /// collected in.
    pub fn output_segments(&self) -> u64 {
        self.collector.output_segments()
    }

    /// The height of the segments the output MMR is collected in.
    pub fn output_height(&self) -> u8 {
        self.collector.output_height()
    }

    /// Collect the output MMR in segments of another height; see
    /// [`Collector::set_output_height`]. Nothing of it is in the file yet
    /// when this is allowed, so the file needs no change.
    pub fn set_output_height(&mut self, height: u8) -> bool {
        self.collector.set_output_height(height)
    }

    /// Length of the file.
    pub fn file_len(&self) -> u64 {
        self.len
    }

    /// Take the next segment of the bitmap MMR and keep it.
    pub fn add_bitmap(&mut self, segment: Segment<BitmapChunk>, output_root: Hash) -> Result<(), AddError> {
        let before = self.collector.progress().1;
        match self.collector.take_bitmap(segment, output_root) {
            Ok(kept) => {
                let bytes = encode(&BitmapSegment::from(kept)).map_err(AddError::Io)?;
                self.write(KIND_BITMAP, output_root.as_bytes(), &bytes).map_err(AddError::Io)
            }
            Err(refused) => {
                if self.collector.progress().1 < before {
                    // the collector began the bitmap again: so does the file
                    self.len = START_LEN;
                    self.file.set_len(START_LEN).map_err(AddError::Io)?;
                    self.sync().map_err(AddError::Io)?;
                }
                Err(AddError::Refused(refused))
            }
        }
    }

    /// [`Collector::verifies_output`].
    pub fn verifies_output(&self, segment: &Segment<OutputIdentifier>) -> bool {
        self.collector.verifies_output(segment)
    }

    /// Take the next segment of the output MMR and keep it.
    pub fn add_output(&mut self, segment: Segment<OutputIdentifier>) -> Result<(), AddError> {
        let kept = self.collector.take_output(segment).map_err(AddError::Refused)?;
        let bytes = encode(&kept).map_err(AddError::Io)?;
        self.write(KIND_OUTPUT, &[], &bytes).map_err(AddError::Io)
    }

    /// Take the last segment of the rangeproof MMR and keep it.
    pub fn add_rangeproof_tail(&mut self, segment: Segment<RangeProof>) -> Result<(), AddError> {
        let kept = self.collector.take_rangeproof_tail(segment).map_err(AddError::Refused)?;
        let bytes = encode(&kept).map_err(AddError::Io)?;
        self.write(KIND_RANGEPROOF_TAIL, &[], &bytes).map_err(AddError::Io)
    }

    /// Take the last segment of the kernel MMR and keep it.
    pub fn add_kernel_tail(&mut self, segment: Segment<TxKernel>) -> Result<(), AddError> {
        let kept = self.collector.take_kernel_tail(segment).map_err(AddError::Refused)?;
        let bytes = encode(&kept).map_err(AddError::Io)?;
        self.write(KIND_KERNEL_TAIL, &[], &bytes).map_err(AddError::Io)
    }

    /// The collected state, once nothing more is wanted.
    pub fn finish(self) -> Option<State> {
        self.collector.finish()
    }
}
