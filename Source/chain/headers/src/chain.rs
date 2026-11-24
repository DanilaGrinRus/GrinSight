//! The verified header chain, kept in a file.
//!
//! The file holds a starting point's identity and then the headers after
//! it, in order. Nothing in the file is believed: whenever it is opened,
//! every header in it is verified again from the starting point, and the
//! file is cut at the first header that does not follow. What remains is a
//! chain this code has verified in this run.
//!
//! A file of another starting point of the same network is replaced: the
//! headers in it above the new point are offered to a chain from that
//! point - verified like any others - and the file then takes their place.
//! A file of another network, or one that is no header file, is not used
//! and not touched.
//!
//! Headers offered later are verified the same way before they are written.
//! A branch that leaves the chain at an earlier header is verified from that
//! header and replaces the chain only when it carries more total work; until
//! then it waits in memory.
use crate::checkpoint::{self, CheckError, Start};
use crate::peaks::Peaks;
use crate::rules::{self, Reject};
use crate::{hash_bytes, read_header, write_header, Net, MAX_HEADER_LEN};
use grin_core::core::hash::{Hash, HashWriter};
use grin_core::core::BlockHeader;
use grin_core::ser::Writer;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Name of the file inside the directory given to [`HeaderChain::open`].
pub const FILE_NAME: &str = "headers.dat";
/// Name of the file a chain from a new starting point is built in before
/// it replaces the file of the old one.
pub const NEXT_FILE_NAME: &str = "headers.next";
/// Most headers taken from one offer; what a node sends at once.
pub const MAX_BATCH: usize = 512;
/// Deepest change of branch that is followed. A heavier branch that leaves
/// the chain further back is reported and not followed.
pub const MAX_REORG: u64 = 1440;
/// Longest branch kept waiting in memory.
const MAX_SIDE: usize = 4096;
/// Distance between remembered sets of peaks.
const SNAP: u64 = 1024;
/// Most hashes in a locator; what a node reads.
const MAX_LOCATOR: usize = 20;

const MAGIC: &[u8; 8] = b"FLYHDR1\n";
const HEAD_LEN: u64 = 8 + 1 + 8 + 32;

/// Why the chain could not be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The starting point's record did not pass its check.
    Start(CheckError),
    /// The directory or the file could not be used.
    Io(io::ErrorKind),
    /// Another process has the file open.
    Busy,
    /// The file belongs to another network or is no header file. It is
    /// left as it is.
    OtherStart,
}

/// What opening found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    /// Headers after the starting point that verified again.
    pub kept: u64,
    /// Bytes cut from the end of the file: a torn write, or headers that
    /// did not verify.
    pub cut_bytes: u64,
}

/// What became of offered headers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing new that fits: all known already, or none usable.
    Nothing,
    /// The chain grew by this many headers.
    Extended {
        /// Headers added.
        added: u64,
    },
    /// A heavier branch replaced the end of the chain.
    Switched {
        /// Height of the last header both branches share.
        from: u64,
        /// Headers taken off.
        removed: u64,
        /// Headers put on.
        added: u64,
    },
    /// A valid branch with no more work than the chain; it waits.
    Side {
        /// Height of its last header.
        height: u64,
    },
    /// The first new header names a parent that is not known here.
    Detached,
    /// A branch that leaves the chain deeper than [`MAX_REORG`].
    TooDeep {
        /// How many headers back it leaves.
        depth: u64,
    },
}

/// The result of an offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offered {
    /// What happened to the headers that were usable.
    pub outcome: Outcome,
    /// The rule the first unusable header broke. Whoever sent it sent a
    /// header that cannot be on any valid chain.
    pub bad: Option<Reject>,
    /// A header claimed a time ahead of the clock; it and those after it
    /// were left for later.
    pub held: bool,
}

/// The end of the chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TipInfo {
    /// Height.
    pub height: u64,
    /// Header hash.
    pub hash: [u8; 32],
    /// Total work up to and including this header.
    pub total_work: u64,
    /// The header's own time, Unix seconds.
    pub time: u64,
}

/// Everything needed to verify the next header.
#[derive(Clone)]
struct State {
    prev: BlockHeader,
    last: BlockHeader,
    peaks: Peaks,
}

impl State {
    fn of(start: &Start) -> State {
        State {
            prev: start.prev.clone(),
            last: start.anchor.clone(),
            peaks: start.peaks.clone(),
        }
    }
    /// Verify `header` as the next one and move on to it. On an error
    /// nothing has changed.
    fn step(&mut self, header: &BlockHeader) -> Result<(), Reject> {
        rules::check_step(&self.prev, &self.last, header)?;
        if header.prev_root != self.peaks.root() {
            return Err(Reject::Root);
        }
        self.peaks.append(header).map_err(|_| Reject::Root)?;
        self.prev = std::mem::replace(&mut self.last, header.clone());
        Ok(())
    }
    fn work(&self) -> u64 {
        self.last.total_difficulty().to_num()
    }
}

struct Entry {
    hash: [u8; 32],
    // The consensus ID covers the proof, while cached reads rely on every field.
    record_digest: Hash,
    /// Where this header's record ends in the file.
    end: u64,
}

struct Side {
    /// Height of the last header shared with the chain.
    base: u64,
    headers: Vec<BlockHeader>,
    state: State,
}

/// The verified header chain of one network from one starting point.
pub struct HeaderChain {
    net: Net,
    file: File,
    start: Start,
    entries: Vec<Entry>,
    tip: State,
    /// `snaps[k]` are the peaks after the header `k * SNAP` above the start.
    snaps: Vec<Peaks>,
    side: Option<Side>,
    max_reorg: u64,
    /// Height of the starting point whose file this chain replaced when it
    /// was opened.
    replaced: Option<u64>,
}

fn io_error(e: io::Error) -> OpenError {
    OpenError::Io(e.kind())
}

/// The file at `path`, open for reading and writing and locked against
/// other processes; emptied first if `fresh`.
fn locked(path: &Path, fresh: bool) -> Result<File, OpenError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(io_error)?;
    if file.try_lock().is_err() {
        return Err(OpenError::Busy);
    }
    if fresh {
        file.set_len(0).map_err(io_error)?;
    }
    Ok(file)
}

/// What a header file of `start` begins with.
fn head_of(start: &Start) -> Vec<u8> {
    let mut head = Vec::with_capacity(49);
    head.extend_from_slice(MAGIC);
    head.push(start.net.tag());
    head.extend_from_slice(&start.height().to_le_bytes());
    head.extend_from_slice(&start.hash());
    head
}

/// A short record ends the verified prefix. Device and filesystem errors
/// must reach the caller before it can truncate or replace the cache.
fn read_complete(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    match reader.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

fn cache_digest(raw: &[u8]) -> io::Result<Hash> {
    let mut writer = HashWriter::default();
    writer.write_fixed_bytes(raw).map_err(io::Error::other)?;
    Ok(writer.into_hash())
}

fn read_record(reader: &mut impl Read) -> io::Result<Option<(BlockHeader, u64, Hash)>> {
    let mut len = [0u8; 2];
    if !read_complete(reader, &mut len)? {
        return Ok(None);
    }
    let len = u16::from_le_bytes(len);
    if len == 0 || usize::from(len) > MAX_HEADER_LEN {
        return Ok(None);
    }
    let mut raw = vec![0u8; usize::from(len)];
    if !read_complete(reader, &mut raw)? {
        return Ok(None);
    }
    let size = u64::from(len).saturating_add(2);
    let Some(header) = read_header(&raw) else {
        return Ok(None);
    };
    Ok(Some((header, size, cache_digest(&raw)?)))
}

fn reorg_limit(depth: u64, limit: u64) -> Option<Outcome> {
    (depth > limit).then_some(Outcome::TooDeep { depth })
}

impl HeaderChain {
    /// Open the chain in `dir` for the starting point in `record`, creating
    /// the file if there is none. Every stored header is verified again.
    ///
    /// A file of another starting point of this network is replaced by a
    /// chain from this one; the headers it holds above this point are kept
    /// if they verify from it. [`HeaderChain::replaced`] says it happened.
    pub fn open(dir: &Path, net: Net, record: &[u8]) -> Result<(HeaderChain, Opened), OpenError> {
        let start = checkpoint::check(record, net).map_err(OpenError::Start)?;
        net.enter();
        std::fs::create_dir_all(dir).map_err(io_error)?;
        let mut file = locked(&dir.join(FILE_NAME), false)?;
        let head = head_of(&start);
        let len = file.metadata().map_err(io_error)?.len();
        if len == 0 {
            file.write_all(&head).map_err(io_error)?;
            file.sync_all().map_err(io_error)?;
        } else {
            let mut found = vec![0u8; head.len()];
            file.seek(SeekFrom::Start(0)).map_err(io_error)?;
            let read = read_complete(&mut file, &mut found).map_err(io_error)?;
            if !read || found != head {
                // the magic and the network agree: another point of this network
                let ours = head.get(..9).zip(found.get(..9)).is_some_and(|(a, b)| a == b);
                if !read || !ours {
                    return Err(OpenError::OtherStart);
                }
                let mut height = [0u8; 8];
                for (to, from) in height.iter_mut().zip(found.iter().skip(9)) {
                    *to = *from;
                }
                return Self::replace(dir, net, record, start, file, u64::from_le_bytes(height));
            }
        }
        let mut chain = Self::on(file, net, start);
        let cut_bytes = chain.load(len.max(HEAD_LEN)).map_err(io_error)?;
        let kept = u64::try_from(chain.entries.len()).unwrap_or(u64::MAX);
        Ok((chain, Opened { kept, cut_bytes }))
    }

    fn on(file: File, net: Net, start: Start) -> HeaderChain {
        HeaderChain {
            net,
            tip: State::of(&start),
            snaps: vec![start.peaks.clone()],
            start,
            file,
            entries: Vec::new(),
            side: None,
            max_reorg: MAX_REORG,
            replaced: None,
        }
    }

    /// Build a chain from `start` in a file of its own out of the headers
    /// in `old` - the file of the starting point at `old_height` - and
    /// put it in the place of `old`.
    fn replace(dir: &Path, net: Net, record: &[u8], start: Start, old: File, old_height: u64) -> Result<(HeaderChain, Opened), OpenError> {
        let next_path = dir.join(NEXT_FILE_NAME);
        {
            // whatever an earlier attempt left there goes
            let mut next = locked(&next_path, true)?;
            next.write_all(&head_of(&start)).map_err(io_error)?;
            next.sync_all().map_err(io_error)?;
            let mut chain = Self::on(next, net, start);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            let from = chain.start.height();
            let mut reader = BufReader::with_capacity(1 << 16, &old);
            reader.seek(SeekFrom::Start(HEAD_LEN)).map_err(io_error)?;
            let mut batch = Vec::with_capacity(MAX_BATCH);
            loop {
                let header = read_record(&mut reader).map_err(io_error)?.map(|(header, _, _)| header);
                let more = header.is_some();
                if let Some(header) = header.filter(|h| h.height > from) {
                    batch.push(header);
                }
                if batch.len() == MAX_BATCH || (!more && !batch.is_empty()) {
                    let offered = chain.offer(&batch, now).map_err(io_error)?;
                    batch.clear();
                    // only what follows the new point is kept, in one piece
                    if !matches!(offered.outcome, Outcome::Extended { .. }) || offered.bad.is_some() || offered.held {
                        break;
                    }
                }
                if !more {
                    break;
                }
            }
            chain.file.sync_all().map_err(io_error)?;
        }
        // both files are closed before one takes the other's name
        drop(old);
        std::fs::rename(&next_path, dir.join(FILE_NAME)).map_err(io_error)?;
        let (mut chain, opened) = Self::open(dir, net, record)?;
        chain.replaced = Some(old_height);
        Ok((chain, opened))
    }

    /// Height of the starting point whose file this chain replaced when it
    /// was opened; nothing if it opened a file of its own point or none.
    pub fn replaced(&self) -> Option<u64> {
        self.replaced
    }

    /// Verify the stored headers and cut the file where they stop
    /// following. Returns the number of bytes cut.
    fn load(&mut self, len: u64) -> io::Result<u64> {
        self.file.seek(SeekFrom::Start(HEAD_LEN))?;
        let mut end = HEAD_LEN;
        {
            let mut reader = BufReader::with_capacity(1 << 16, &self.file);
            let mut state = self.tip.clone();
            while let Some((header, size, record_digest)) = read_record(&mut reader)? {
                if state.step(&header).is_err() {
                    break;
                }
                end = end.saturating_add(size);
                self.entries.push(Entry {
                    hash: hash_bytes(&header),
                    record_digest,
                    end,
                });
                if header.height.saturating_sub(self.start.height()) % SNAP == 0 {
                    self.snaps.push(state.peaks.clone());
                }
            }
            self.tip = state;
        }
        if end < len {
            self.file.set_len(end)?;
            self.file.sync_all()?;
        }
        Ok(len.saturating_sub(end))
    }

    /// Follow changes of branch only to this depth. The depth can be
    /// lowered, never raised above [`MAX_REORG`].
    pub fn set_max_reorg(&mut self, depth: u64) {
        self.max_reorg = depth.min(MAX_REORG);
    }

    /// The network of this chain.
    pub fn net(&self) -> Net {
        self.net
    }

    /// The starting point.
    pub fn start(&self) -> &Start {
        &self.start
    }

    /// The end of the chain.
    pub fn tip(&self) -> TipInfo {
        TipInfo {
            height: self.tip.last.height,
            hash: hash_bytes(&self.tip.last),
            total_work: self.tip.work(),
            time: u64::try_from(self.tip.last.timestamp.timestamp()).unwrap_or(0),
        }
    }

    /// The header at the end of the chain.
    pub fn tip_header(&self) -> &BlockHeader {
        &self.tip.last
    }

    fn index_of(&self, height: u64) -> Option<usize> {
        let above = height.checked_sub(self.start.height())?.checked_sub(1)?;
        usize::try_from(above).ok().filter(|i| *i < self.entries.len())
    }

    /// The hash of the chain's header at `height`, from the starting point up.
    pub fn hash_at(&self, height: u64) -> Option<[u8; 32]> {
        if height == self.start.height() {
            return Some(self.start.hash());
        }
        self.entries.get(self.index_of(height)?).map(|e| e.hash)
    }

    /// The chain's header at `height`, read from the file. `Ok(None)` for a
    /// height outside the chain.
    pub fn header_at(&self, height: u64) -> io::Result<Option<BlockHeader>> {
        if height == self.start.height() {
            return Ok(Some(self.start.anchor.clone()));
        }
        let Some(index) = self.index_of(height) else {
            return Ok(None);
        };
        let begin = match index.checked_sub(1) {
            Some(before) => self.entries.get(before).map(|e| e.end),
            None => Some(HEAD_LEN),
        };
        let (Some(begin), Some(entry)) = (begin, self.entries.get(index)) else {
            return Ok(None);
        };
        let damaged = || io::Error::new(io::ErrorKind::InvalidData, "the header file changed under this process");
        let mut file = &self.file;
        file.seek(SeekFrom::Start(begin))?;
        let (header, size, record_digest) = read_record(&mut file)?.ok_or_else(damaged)?;
        if begin.checked_add(size) != Some(entry.end) || record_digest != entry.record_digest {
            return Err(damaged());
        }
        Ok(Some(header))
    }

    /// The record of a starting point at the chain's header at `height`,
    /// for a later start from there; `release_time` is written into it.
    ///
    /// `Ok(None)` for a height this chain cannot make a point of: the two
    /// headers before it and the peaks they were added to have to be in
    /// the chain, so the lowest is three above the chain's own starting
    /// point. The record says nothing about how final the header is; that
    /// is for the caller to decide.
    pub fn record_at(&self, height: u64, release_time: u64) -> io::Result<Option<Vec<u8>>> {
        self.net.enter();
        let lowest = height.checked_sub(3).filter(|low| *low >= self.start.height());
        let Some(lowest) = lowest.filter(|_| height <= self.tip.last.height) else {
            return Ok(None);
        };
        let lost = || io::Error::new(io::ErrorKind::InvalidData, "a header of the chain is missing");
        let header = |at: Option<u64>| -> io::Result<BlockHeader> {
            let at = at.ok_or_else(lost)?;
            self.header_at(at)?.ok_or_else(lost)
        };
        let before_older = self.state_at(lowest)?.peaks;
        let older = header(height.checked_sub(2))?;
        let prev = header(height.checked_sub(1))?;
        let anchor = header(Some(height))?;
        let mut before_prev = before_older.clone();
        before_prev.append(&older).map_err(|_| lost())?;
        Ok(checkpoint::write(&checkpoint::Parts {
            net: self.net,
            anchor: &anchor,
            prev: &prev,
            older: &older,
            before_prev: &before_prev,
            before_older: &before_older,
            release_time,
        }))
    }

    /// Hashes that tell a node where this chain stands: the newest first,
    /// then ever further back, ending with the starting point. If a branch
    /// is waiting, its end comes first, so that whoever is on that branch
    /// continues it.
    pub fn locator(&self) -> Vec<[u8; 32]> {
        let mut out = Vec::new();
        if let Some(side) = &self.side {
            out.push(hash_bytes(&side.state.last));
        }
        let (start, mut height, mut back) = (self.start.height(), self.tip.last.height, 1u64);
        while height > start && out.len() < MAX_LOCATOR.saturating_sub(1) {
            if let Some(hash) = self.hash_at(height) {
                out.push(hash);
            }
            height = height.saturating_sub(back).max(start);
            back = back.saturating_mul(2);
        }
        out.push(self.start.hash());
        out
    }

    /// The state after the chain's header at `height`.
    fn state_at(&self, height: u64) -> io::Result<State> {
        let start = self.start.height();
        let lost = || io::Error::new(io::ErrorKind::InvalidData, "a header of the chain is missing");
        let above = height.checked_sub(start).ok_or_else(lost)?;
        let snap = above / SNAP;
        let mut peaks = usize::try_from(snap)
            .ok()
            .and_then(|k| self.snaps.get(k))
            .cloned()
            .ok_or_else(lost)?;
        let mut at = start.saturating_add(snap.saturating_mul(SNAP));
        while at < height {
            at = at.saturating_add(1);
            let header = self.header_at(at)?.ok_or_else(lost)?;
            peaks.append(&header).map_err(|_| lost())?;
        }
        let last = self.header_at(height)?.ok_or_else(lost)?;
        let prev = match height.checked_sub(1).filter(|h| *h >= start) {
            Some(h) => self.header_at(h)?.ok_or_else(lost)?,
            None => self.start.prev.clone(),
        };
        Ok(State { prev, last, peaks })
    }

    fn end(&self) -> u64 {
        self.entries.last().map_or(HEAD_LEN, |e| e.end)
    }

    /// Write verified headers after the end of the chain and make `state`
    /// the tip. The memory is changed only after the file is.
    fn append(&mut self, headers: &[BlockHeader], state: State) -> io::Result<()> {
        if headers.is_empty() {
            return Ok(());
        }
        let unusable = || io::Error::new(io::ErrorKind::InvalidData, "a header that cannot be stored");
        let mut bytes = Vec::new();
        let mut ends = Vec::with_capacity(headers.len());
        let mut end = self.end();
        for header in headers {
            let raw = write_header(header).ok_or_else(unusable)?;
            let len = u16::try_from(raw.len()).map_err(|_| unusable())?;
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(&raw);
            end = end.saturating_add(u64::from(len)).saturating_add(2);
            ends.push(Entry {
                hash: hash_bytes(header),
                record_digest: cache_digest(&raw)?,
                end,
            });
        }
        // whatever an earlier failed write left behind goes first
        self.file.set_len(self.end())?;
        self.file.seek(SeekFrom::Start(self.end()))?;
        self.file.write_all(&bytes)?;
        self.file.sync_data()?;
        let mut peaks = self.tip.peaks.clone();
        for header in headers {
            peaks.append(header).map_err(|_| unusable())?;
            if header.height.saturating_sub(self.start.height()) % SNAP == 0 {
                self.snaps.push(peaks.clone());
            }
        }
        self.entries.extend(ends);
        self.tip = state;
        Ok(())
    }

    /// Take the headers above `height` off the chain. Only the memory
    /// changes here: whatever the file holds past the end of the chain is
    /// cut by the next write, and until then it is a valid older branch
    /// that a restart would verify again.
    fn truncate(&mut self, height: u64) -> io::Result<()> {
        let state = self.state_at(height)?;
        let keep = usize::try_from(height.saturating_sub(self.start.height())).unwrap_or(usize::MAX);
        self.entries.truncate(keep);
        let snaps = usize::try_from(height.saturating_sub(self.start.height()) / SNAP)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        self.snaps.truncate(snaps);
        self.tip = state;
        Ok(())
    }

    /// Verify headers one after another on `state`; stop at the first that
    /// is ahead of the clock or breaks a rule.
    fn verify(state: &mut State, headers: &[BlockHeader], now: u64) -> (Vec<BlockHeader>, Option<Reject>, bool) {
        let mut good = Vec::new();
        for header in headers {
            if rules::ahead_of(header, now) {
                return (good, None, true);
            }
            if let Err(reject) = state.step(header) {
                return (good, Some(reject), false);
            }
            good.push(header.clone());
        }
        (good, None, false)
    }

    /// Replace the end of the chain by the waiting branch if that branch
    /// carries more work.
    fn settle(&mut self) -> io::Result<Outcome> {
        let Some(side) = self.side.take() else {
            return Ok(Outcome::Nothing);
        };
        let height = side.state.last.height;
        let removed = self.tip.last.height.saturating_sub(side.base);
        if let Some(outcome) = reorg_limit(removed, self.max_reorg) {
            return Ok(outcome);
        }
        if side.state.work() <= self.tip.work() {
            if side.headers.len() <= MAX_SIDE {
                self.side = Some(side);
            }
            return Ok(Outcome::Side { height });
        }
        self.truncate(side.base)?;
        self.append(&side.headers, side.state)?;
        Ok(Outcome::Switched {
            from: side.base,
            removed,
            added: u64::try_from(side.headers.len()).unwrap_or(u64::MAX),
        })
    }

    /// Offer headers from anybody: consecutive, oldest first. `now` is the
    /// clock in Unix seconds, used only to leave headers "from the future"
    /// for later. An error is a failure of the file, never of the headers.
    pub fn offer(&mut self, headers: &[BlockHeader], now: u64) -> io::Result<Offered> {
        self.net.enter();
        let mut fresh = headers.get(..headers.len().min(MAX_BATCH)).unwrap_or(headers);
        // what the chain already has is not news
        while let Some((first, rest)) = fresh.split_first() {
            if self.hash_at(first.height) != Some(hash_bytes(first)) {
                break;
            }
            fresh = rest;
        }
        let nothing = Offered {
            outcome: Outcome::Nothing,
            bad: None,
            held: false,
        };
        let Some(first) = fresh.first() else {
            return Ok(nothing);
        };
        let Some(parent_height) = first.height.checked_sub(1) else {
            return Ok(Offered {
                bad: Some(Reject::Height),
                ..nothing
            });
        };
        let parent = {
            let mut bytes = [0u8; 32];
            for (to, from) in bytes.iter_mut().zip(first.prev_hash.as_bytes()) {
                *to = *from;
            }
            bytes
        };
        // on top of the chain
        if parent_height == self.tip.last.height && parent == hash_bytes(&self.tip.last) {
            let mut state = self.tip.clone();
            let (good, bad, held) = Self::verify(&mut state, fresh, now);
            self.append(&good, state)?;
            let added = u64::try_from(good.len()).unwrap_or(u64::MAX);
            let outcome = if added == 0 { Outcome::Nothing } else { Outcome::Extended { added } };
            return Ok(Offered { outcome, bad, held });
        }
        // on top of the waiting branch
        if let Some(side) = &mut self.side {
            if parent_height == side.state.last.height && parent == hash_bytes(&side.state.last) {
                let mut state = side.state.clone();
                let (good, bad, held) = Self::verify(&mut state, fresh, now);
                side.headers.extend(good);
                side.state = state;
                let outcome = self.settle()?;
                return Ok(Offered { outcome, bad, held });
            }
        }
        // a branch from an earlier header of the chain
        if self.hash_at(parent_height) == Some(parent) {
            let depth = self.tip.last.height.saturating_sub(parent_height);
            if let Some(outcome) = reorg_limit(depth, self.max_reorg) {
                return Ok(Offered {
                    outcome,
                    ..nothing
                });
            }
            let mut state = self.state_at(parent_height)?;
            let (good, bad, held) = Self::verify(&mut state, fresh, now);
            if good.is_empty() {
                return Ok(Offered { bad, held, ..nothing });
            }
            self.side = Some(Side {
                base: parent_height,
                headers: good,
                state,
            });
            let outcome = self.settle()?;
            return Ok(Offered { outcome, bad, held });
        }
        Ok(Offered {
            outcome: Outcome::Detached,
            ..nothing
        })
    }
}


#[cfg(test)]
mod depth_policy_tests {
    use super::{reorg_limit, Outcome};

    #[test]
    fn reorg_limit_includes_its_boundary() {
        assert_eq!(reorg_limit(0, 0), None);
        assert_eq!(reorg_limit(2, 2), None);
        assert_eq!(reorg_limit(3, 2), Some(Outcome::TooDeep { depth: 3 }));
    }
}

#[cfg(test)]
mod cache_io_tests {
    use super::*;

    #[test]
    fn unreadable_storage_keeps_its_existing_bytes() -> io::Result<()> {
        let net = Net::Main;
        let start = checkpoint::check(include_bytes!("../points/main.json"), net)
            .map_err(|_| io::Error::other("bundled checkpoint"))?;
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).map_err(|_| io::Error::other("randomness"))?;
        let path = std::env::temp_dir().join(format!("fly-header-io-{}", u64::from_le_bytes(random)));
        // A write-only handle makes reading fail before the first record.
        let file = OpenOptions::new().write(true).create_new(true).open(&path)?;
        let initial = HEAD_LEN.saturating_add(16);
        file.set_len(initial)?;
        let mut chain = HeaderChain::on(file, net, start);
        let replay = chain.load(initial);
        let remaining = chain.file.metadata()?.len();
        drop(chain);
        std::fs::remove_file(path)?;
        assert_eq!(remaining, initial, "a storage read failure must preserve the cache");
        assert!(replay.is_err(), "the caller must learn that reading failed");
        Ok(())
    }
    #[cfg(feature = "testkit")]
    #[test]
    fn disk_round_trip_preserves_the_complete_verified_header() -> io::Result<()> {
        let net = Net::Automated;
        let mut source = crate::testkit::TestChain::new();
        source.mine(8, 60);
        let anchor = crate::testkit::FIRST_START;
        let start = checkpoint::check(&source.record(anchor), net)
            .map_err(|_| io::Error::other("test checkpoint"))?;
        let mut random = [0u8; 8];
        getrandom::getrandom(&mut random).map_err(|_| io::Error::other("randomness"))?;
        let path = std::env::temp_dir().join(format!("fly-header-roundtrip-{}", u64::from_le_bytes(random)));
        let file = OpenOptions::new().read(true).write(true).create_new(true).open(&path)?;
        let mut chain = HeaderChain::on(file, net, start);
        chain.offer(source.after(anchor), u64::MAX)?;
        let height = anchor.saturating_add(1);
        assert!(chain.header_at(height)?.is_some());
        // Simulate one media bit error through the owned test file handle.
        let offset = HEAD_LEN.saturating_add(2);
        chain.file.seek(SeekFrom::Start(offset))?;
        let mut byte = [0u8; 1];
        chain.file.read_exact(&mut byte)?;
        for value in &mut byte { *value ^= 1; }
        chain.file.seek(SeekFrom::Start(offset))?;
        chain.file.write_all(&byte)?;
        let detected = chain.header_at(height).err().map(|e| e.kind());
        drop(chain);
        std::fs::remove_file(path)?;
        assert_eq!(detected, Some(io::ErrorKind::InvalidData));
        Ok(())
    }

}
