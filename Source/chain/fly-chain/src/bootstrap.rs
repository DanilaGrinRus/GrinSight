//! Initial replay starts at the exact network genesis. Once the local anchor and
//! its verified tail have been durably installed, this device can resume there.
mod compact;
mod export;
mod package;
pub use export::check as check_exported_pair;
pub use export::import_checkpoint;
pub use package::{import_checkpoint_file, pack_checkpoint, pack_profile_checkpoint};
pub(crate) use export::{cache as imported_cache, imported};
use crate::node::{addresses, archive_height, SharedView, View};
use crate::probe::Session;
use fly_chain_headers::chain::{HeaderChain, Outcome, MAX_BATCH};
use fly_chain_headers::genesis::GenesisVerifier;
use fly_chain_headers::{hash_bytes, read_header, write_header, Net};
use grin_core::core::BlockHeader;
use grin_core::global;
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

const LOG: &str = "autonomous-headers-v1.bin";
const LOCK: &str = "autonomous-headers.lock";
const SLOTS: u64 = 3;

fn invalid(why: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, why)
}

fn exact_record(raw: &[u8], header: &BlockHeader) -> bool {
    write_header(header).is_some_and(|canonical| canonical == raw)
}

fn write_frame(writer: &mut impl Write, header: &BlockHeader) -> io::Result<()> {
    let bytes = write_header(header).ok_or_else(|| invalid("header serialization failed"))?;
    let size = u16::try_from(bytes.len()).map_err(|_| invalid("oversized header"))?;
    writer.write_all(&size.to_be_bytes())?;
    writer.write_all(&bytes)
}

fn read_frame(reader: &mut impl Read) -> io::Result<Option<(BlockHeader, u64)>> {
    let mut size = [0u8; 2];
    if reader.read(size.get_mut(..1).ok_or_else(|| invalid("length"))?)? == 0 {
        return Ok(None);
    }
    reader.read_exact(size.get_mut(1..).ok_or_else(|| invalid("length"))?)?;
    let size = u16::from_be_bytes(size);
    let mut raw = vec![0; usize::from(size)];
    reader.read_exact(&mut raw)?;
    let header = read_header(&raw)
        .filter(|h| exact_record(&raw, h))
        .ok_or_else(|| invalid("invalid header frame"))?;
    Ok(Some((header, u64::from(size).saturating_add(2))))
}

#[derive(Clone)]
struct Anchor {
    height: u64,
    bytes: Vec<u8>,
}

struct Replay {
    verifier: GenesisVerifier,
    net: Net,
    anchors: VecDeque<Anchor>,
    tail: VecDeque<BlockHeader>,
    end: u64,
}

impl Replay {
    fn new(net: Net) -> io::Result<Self> {
        let verifier = GenesisVerifier::new(net).map_err(|e| invalid(&format!("genesis: {e:?}")))?;
        Ok(Self {
            verifier,
            net,
            anchors: VecDeque::new(),
            tail: VecDeque::new(),
            end: 0,
        })
    }

    // Only mutate the replay after verification. On a peer's invalid suffix the
    // journal is kept at the end of the last fully accepted batch.
    fn push(&mut self, h: &BlockHeader, now: u64, frame_size: u64) -> io::Result<()> {
        self.verifier.push(h, now).map_err(|e| match e {
            fly_chain_headers::genesis::GenesisError::Future => io::Error::new(
                io::ErrorKind::WouldBlock,
                "a verified journal header is ahead of this clock; retaining the journal",
            ),
            _ => invalid(&format!("invalid history at {}: {e:?}", h.height)),
        })?;
        self.end = self
            .end
            .checked_add(frame_size)
            .ok_or_else(|| invalid("file size overflow"))?;
        self.tail.push_back(h.clone());
        let interval = global::txhashset_archive_interval().max(1);
        let horizon = u64::from(global::state_sync_threshold()).saturating_add(interval.saturating_mul(2));
        while self
            .tail
            .front()
            .is_some_and(|old| h.height.saturating_sub(old.height) > horizon)
        {
            self.tail.pop_front();
        }
        if h.height.is_multiple_of(interval) {
            // A stable timestamp makes a reconstructed record byte-identical.
            let stamp = u64::try_from(h.timestamp.timestamp()).unwrap_or(0);
            if let Some(bytes) = self
                .verifier
                .record(stamp)
                .filter(|b| fly_chain_headers::checkpoint::check(b, self.net).is_ok())
            {
                self.anchors.push_back(Anchor {
                    height: h.height,
                    bytes,
                });
                while self
                    .anchors
                    .front()
                    .is_some_and(|old| h.height.saturating_sub(old.height) > horizon)
                {
                    self.anchors.pop_front();
                }
            }
        }
        Ok(())
    }

    fn anchor(&self) -> Option<&Anchor> {
        let height = archive_height(self.verifier.tip().height);
        self.anchors.iter().rev().find(|a| a.height <= height)
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn status(view: &SharedView, replay: &Replay, note: &str) {
    let tip = replay.verifier.tip();
    *view.lock().unwrap_or_else(|p| p.into_inner()) = View {
        height: tip.height,
        hash: hash_bytes(tip),
        work: tip.total_difficulty().to_num(),
        point: crate::PointKind::Genesis,
        problem: Some(note.to_string()),
        ..View::default()
    };
}

fn replay(file: &mut File, net: Net, view: &SharedView, stop: &AtomicBool) -> io::Result<Replay> {
    replay_at(file, net, view, stop, now())
}

fn replay_at(file: &mut File, net: Net, view: &SharedView, stop: &AtomicBool, clock: u64) -> io::Result<Replay> {
    let mut data = Replay::new(net)?;
    let mut reader = BufReader::new(&mut *file);
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let read = read_frame(&mut reader).and_then(|frame| match frame {
            Some((ref header, size)) if data.end == 0 => {
                data.verifier.check_genesis(header).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "wrong network genesis in the header journal; original retained",
                    )
                })?;
                data.end = size;
                Ok(true)
            }
            Some((ref header, size)) => data.push(header, clock, size).map(|_| true),
            None => Ok(false),
        });
        match read {
            Ok(true) => {
                if data.verifier.tip().height % 512 == 0 {
                    status(view, &data, "rechecking the saved header history");
                }
            }
            Ok(false) => break,
            Err(e) if matches!(e.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::InvalidData) => break,
            Err(e) => return Err(e),
        }
    }
    drop(reader);
    if file.metadata()?.len() != data.end {
        file.set_len(data.end)?;
        file.sync_data()?;
    }
    file.seek(SeekFrom::End(0))?;
    if data.end == 0 {
        write_frame(file, data.verifier.tip())?;
        file.sync_data()?;
        data.end = file.stream_position()?;
    }
    Ok(data)
}

// A previous build stored a disposable checkpoint hint at an archive slot.

// The active pointer is only local routing metadata. Each chosen generation
// is independently re-verified; the pointer cannot invent chainwork.
const ACTIVE: &str = "autonomous-active-v1";
const PENDING: &str = "autonomous-recheck-v1";

fn small(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match File::open(path) {
        Ok(f) => {
            let mut b = Vec::new();
            f.take(129).read_to_end(&mut b)?;
            if b.len() > 128 {
                return Err(invalid("bootstrap metadata oversized"));
            }
            Ok(Some(b))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn atomic(root: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    let next = root.join(format!("{name}.next"));
    let mut f = File::create(&next)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    fs::rename(next, root.join(name))
}

// Both copies are atomically replaced only after the underlying generation
// is usable. During a crash the primary is authoritative; an unreadable or
// absent primary can be reconstructed from the secondary. Ambiguous damage
// to both copies never picks a generation based on a remote assertion.
fn routing<T: Copy>(root: &Path, name: &str, repair: bool, parse: impl Fn(&[u8]) -> io::Result<T>) -> io::Result<Option<T>> {
    let primary = small(&root.join(name)).and_then(|v| v.map(|b| parse(&b)).transpose());
    if let Ok(Some(v)) = primary {
        return Ok(Some(v));
    }
    let mirror = format!("{name}.copy");
    match small(&root.join(mirror))?
        .map(|raw| parse(&raw).map(|value| (value, raw)))
        .transpose()?
    {
        Some((value, raw)) => {
            if repair { atomic(root, name, &raw)?; }
            Ok(Some(value))
        }
        None => primary,
    }
}
fn write_routing(root: &Path, name: &str, data: &[u8]) -> io::Result<()> {
    atomic(root, &format!("{name}.copy"), data)?;
    atomic(root, name, data)
}
fn active(root: &Path) -> io::Result<bool> {
    active_slot(root, true)
}
fn active_slot(root: &Path, repair: bool) -> io::Result<bool> {
    let selected = routing(root, ACTIVE, repair, |b| match b {
        b"0" => Ok(false),
        b"1" => Ok(true),
        _ => Err(invalid("invalid bootstrap generation")),
    })?;
    if selected.is_none()
        && compact::exists(&generation(root, true).join(compact::NAME))?
        && pending_slot(root, false, repair)?.is_none()
    {
        return Err(invalid("active generation is missing for the published alternative"));
    }
    Ok(selected.unwrap_or(false))
}
fn generation(root: &Path, second: bool) -> PathBuf {
    if second {
        root.join("autonomous-alternative")
    } else {
        root.to_path_buf()
    }
}

fn pending(root: &Path, active: bool) -> io::Result<Option<u64>> {
    pending_slot(root, active, true)
}
fn pending_slot(root: &Path, active: bool, repair: bool) -> io::Result<Option<u64>> {
    let recorded = routing(root, PENDING, repair, |raw| {
        let data = std::str::from_utf8(raw).map_err(|_| invalid("invalid recheck record"))?;
        let (slot, floor) = data.split_once(' ').ok_or_else(|| invalid("invalid recheck record"))?;
        let source = match slot {
            "0" => false,
            "1" => true,
            _ => return Err(invalid("invalid recheck generation")),
        };
        let floor = floor
            .parse::<u64>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| invalid("invalid recheck work"))?;
        Ok((source, floor))
    })?;
    // If a crash followed the active pointer write, activation is complete.
    Ok(recorded.filter(|(source, _)| *source == active).map(|(_, work)| work))
}

pub(crate) fn has_autonomous_state(root: &Path) -> io::Result<bool> {
    for name in [
        LOCK,
        ACTIVE,
        PENDING,
        "autonomous-active-v1.copy",
        "autonomous-recheck-v1.copy",
    ] {
        if compact::exists(&root.join(name))? {
            return Ok(true);
        }
    }
    for second in [false, true] {
        let dir = generation(root, second);
        for name in [LOG, compact::NAME, compact::SEAL] {
            if compact::exists(&dir.join(name))? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

pub(crate) struct History {
    _lock: File,
    dir: PathBuf,
    root: PathBuf,
    second: bool,
    slot: bool,
    committed_hash: [u8; 32],
    committed: u64,
    net: Net,
}

pub(crate) struct Handoff {
    pub(crate) record: Vec<u8>,
    history: History,
    saved: Option<compact::State>,
    tail: VecDeque<BlockHeader>,
    candidate_floor: Option<u64>,
    // Close the Windows handle before retiring the replay journal.
    journal: Option<File>,
}

fn open_error(e: fly_chain_headers::chain::OpenError) -> io::Error {
    io::Error::other(format!("open verified local tail: {e:?}"))
}

fn offer_tail(chain: &mut HeaderChain, batch: &[BlockHeader]) -> io::Result<()> {
    let result = chain.offer(batch, now())?;
    if result.bad.is_some()
        || result.held
        || !matches!(result.outcome, Outcome::Nothing | Outcome::Extended { .. })
        || batch
            .last()
            .is_some_and(|h| chain.hash_at(h.height) != Some(hash_bytes(h)))
    {
        return Err(invalid("verified history and local tail differ"));
    }
    Ok(())
}

impl Handoff {
    pub(crate) fn reopened_compact(&self) -> bool {
        self.saved.is_some()
    }

    pub(crate) fn open_chain(
        &self,
        net: Net,
    ) -> Result<(HeaderChain, fly_chain_headers::chain::Opened), fly_chain_headers::chain::OpenError>
    {
        if let Some(saved) = &self.saved {
            return saved.open(&self.history.dir, net);
        }
        use fly_chain_headers::chain::{OpenError, FILE_NAME};
        let dir = compact::tail(&self.history.dir, self.history.slot);
        let (mut chain, opened) = match HeaderChain::open(&dir, net, &self.record) {
            Err(
                OpenError::OtherStart
                | OpenError::Io(io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof),
            ) => {
                // This is a legacy migration or an unpublished staging directory.
                // The complete history has just been independently replayed.
                fs::rename(dir.join(FILE_NAME), dir.join("headers.invalid"))
                    .map_err(|e| OpenError::Io(e.kind()))?;
                HeaderChain::open(&dir, net, &self.record)
            }
            result => result,
        }?;
        let tail: Vec<_> = self
            .tail
            .iter()
            .filter(|h| h.height > self.history.committed)
            .cloned()
            .collect();
        for batch in tail.chunks(MAX_BATCH) {
            offer_tail(&mut chain, batch).map_err(|e| OpenError::Io(e.kind()))?;
        }
        let tip = chain.tip();
        drop(chain);
        let (chain, _) =
            HeaderChain::open_published(&dir, net, &self.record, tip.total_work, tip.hash)?;
        Ok((chain, opened))
    }

    pub(crate) fn install(self, chain: &mut HeaderChain) -> io::Result<History> {
        if chain.net() != self.history.net || chain.start().hash() != self.history.committed_hash {
            return Err(invalid("local tail does not start at verified anchor"));
        }
        let tip = chain.tip();
        if self
            .candidate_floor
            .is_some_and(|work| tip.total_work <= work)
        {
            return Err(invalid(
                "verified alternative does not exceed the active chainwork",
            ));
        }
        if self.saved.is_none() {
            export::publish(
                self.history.net,
                &self.history.dir.join(LOG),
                &self.record,
                &self.history.root,
            )?;
            compact::State {
                slot: self.history.slot,
                work: tip.total_work,
                hash: tip.hash,
                anchor: Anchor {
                    height: self.history.committed,
                    bytes: self.record,
                },
            }
            .publish(&self.history.dir, self.history.net)?;
        } else {
            compact::State::ensure_seal(&self.history.dir)?;
        }
        chain.protect_reorg(&compact::tail(&self.history.dir, self.history.slot));
        if self.candidate_floor.is_some() {
            write_routing(
                &self.history.root,
                ACTIVE,
                if self.history.second { b"1" } else { b"0" },
            )?;
        }
        drop(self.journal);
        self.history.retire()?;
        Ok(self.history)
    }
}

impl History {
    fn retire(&self) -> io::Result<()> {
        // Only generated replay artifacts are eligible. A restart retries any
        // retirement interrupted after durable publication.
        for name in [LOG, "autonomous-prefix.next"] {
            compact::unlink_file(&self.dir.join(name))?;
        }
        let inactive = compact::tail(&self.dir, !self.slot);
        compact::unlink_file(&inactive.join(fly_chain_headers::chain::FILE_NAME))?;
        Ok(())
    }

    pub(crate) fn challenge(&self, floor: u64) -> io::Result<()> {
        let target = generation(&self.root, !self.second);
        fs::create_dir_all(&target)?;
        // Prior inactive material can never stand in for this independent challenge.
        for name in [compact::NAME, compact::SEAL, LOG, "autonomous-prefix.next"] {
            compact::unlink_file(&target.join(name))?;
        }
        for slot in [false, true] {
            compact::unlink_file(
                &compact::tail(&target, slot).join(fly_chain_headers::chain::FILE_NAME),
            )?;
        }
        write_routing(
            &self.root,
            PENDING,
            format!("{} {floor}", u8::from(self.second)).as_bytes(),
        )
    }

    pub(crate) fn still_on(&self, chain: &HeaderChain) -> bool {
        chain.hash_at(self.committed) == Some(self.committed_hash)
    }

    pub(crate) fn advance(&mut self, chain: &mut HeaderChain) -> io::Result<()> {
        let target = archive_height(chain.tip().height);
        if target < self.committed.saturating_add(3) {
            return Ok(());
        }
        let stamp = chain
            .header_at(target)?
            .and_then(|h| u64::try_from(h.timestamp.timestamp()).ok())
            .ok_or_else(|| invalid("archive header missing during local rotation"))?;
        let bytes = chain
            .record_at(target, stamp)?
            .ok_or_else(|| invalid("cannot form next local archive checkpoint"))?;
        let old_tip = chain.tip();
        let slot = !self.slot;
        let dir = compact::tail(&self.dir, slot);
        compact::unlink_file(&dir.join(fly_chain_headers::chain::FILE_NAME))?;
        let (mut next, _) = HeaderChain::open(&dir, self.net, &bytes).map_err(open_error)?;
        if chain.hash_at(target) != Some(next.start().hash()) {
            return Err(invalid("local archive moved during rotation"));
        }
        let mut batch = Vec::with_capacity(MAX_BATCH);
        for height in (target + 1)..=old_tip.height {
            batch.push(
                chain
                    .header_at(height)?
                    .ok_or_else(|| invalid("missing tail during rotation"))?,
            );
            if batch.len() == MAX_BATCH {
                offer_tail(&mut next, &batch)?;
                batch.clear();
            }
        }
        offer_tail(&mut next, &batch)?;
        if next.tip().hash != old_tip.hash || next.tip().total_work != old_tip.total_work {
            return Err(invalid("rotated tail does not reproduce the previous tip"));
        }
        let saved = compact::State {
            slot,
            work: old_tip.total_work,
            hash: old_tip.hash,
            anchor: Anchor {
                height: target,
                bytes,
            },
        };
        drop(next);
        let (next, _) = saved.open(&self.dir, self.net).map_err(open_error)?;
        saved.publish(&self.dir, self.net)?;
        self.committed = target;
        self.committed_hash = next.start().hash();
        self.slot = slot;
        *chain = next;
        self.retire()
    }
}

// A stale cursor below the first usable WTEMA point cannot be handed to the
// regular branch follower. Keep its evidence and independently stream a
// competing prefix from exact genesis; replace the old file only after more
// work has actually been verified. One bounded staging file per generation.
fn compete(
    session: &mut Session,
    net: Net,
    dir: &Path,
    current: &mut Replay,
    file: &mut File,
    view: &SharedView,
    stop: &AtomicBool,
) -> io::Result<bool> {
    let floor = current.verifier.tip().total_difficulty().to_num();
    if session.remote_work <= floor || current.verifier.tip().height == 0 {
        return Ok(false);
    }
    let mut alt = Replay::new(net)?;
    let path = dir.join("autonomous-prefix.next");
    let mut stage = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)?;
    write_frame(&mut stage, alt.verifier.tip())?;
    alt.end = stage.stream_position()?;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let Ok(Some(batch)) = session.next_headers(alt.verifier.tip()) else {
            return Ok(false);
        };
        if batch.is_empty() {
            return Ok(false);
        }
        status(
            view,
            &alt,
            "checking a competing historical prefix from genesis; original retained",
        );
        for h in batch {
            let bytes = write_header(&h).ok_or_else(|| invalid("header serialization"))?;
            let size = u64::try_from(bytes.len())
                .map_err(|_| invalid("frame length"))?
                .saturating_add(2);
            if alt.push(&h, now(), size).is_err() {
                return Ok(false);
            }
            write_frame(&mut stage, &h)?;
        }
        if alt.verifier.tip().total_difficulty().to_num() > floor {
            stage.sync_all()?;
            fs::rename(&path, dir.join(LOG))?;
            *file = stage;
            *current = alt;
            return Ok(true);
        }
    }
}

pub(crate) fn prepare(
    net: Net,
    root: &Path,
    peers: &[String],
    view: &SharedView,
    stop: &AtomicBool,
) -> io::Result<Handoff> {
    fs::create_dir_all(root)?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(LOCK))?;
    lock.try_lock()
        .map_err(|e| io::Error::other(format!("autonomous history is busy: {e}")))?;
    let original = active(root)?;
    let floor = pending(root, original)?;
    let second = if floor.is_some() { !original } else { original };
    let dir = generation(root, second);
    fs::create_dir_all(&dir)?;
    if let Some(saved) = compact::State::read(&dir, net)? {
        let checked = fly_chain_headers::checkpoint::check(&saved.anchor.bytes, net)
            .map_err(|_| invalid("invalid local anchor"))?;
        let history = History {
            _lock: lock,
            root: root.to_owned(),
            dir,
            second,
            net,
            committed: checked.height(),
            committed_hash: checked.hash(),
            slot: saved.slot,
        };
        return Ok(Handoff {
            record: saved.anchor.bytes.clone(),
            history,
            saved: Some(saved),
            tail: VecDeque::new(),
            candidate_floor: floor,
            journal: None,
        });
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(LOG))?;
    let mut data = replay(&mut file, net, view, stop)?;
    // A prior run may already have compacted its stable archive prefix. A
    // verified local anchor is enough to let the normal network path catch up.
    let tip = data.verifier.tip().height;
    let mut ready = data
        .anchors
        .back()
        .filter(|a| {
            if floor.is_some() || a.height != tip {
                return false;
            }
            let interval = global::txhashset_archive_interval().max(1);
            let slot = a.height.checked_div(interval).unwrap_or(0) % SLOTS;
            let path = dir.join(format!("autonomous-point-{slot}.json"));
            // Cached slot is only a hint that initialization finished, not trusted
            // evidence. The selected record is always created by the verifier.
            fs::metadata(&path).is_ok_and(|m| m.len() <= fly_chain_headers::checkpoint::MAX_RECORD_LEN as u64)
                && fs::read(path)
                    .ok()
                    .and_then(|b| fly_chain_headers::checkpoint::check(&b, net).ok())
                    .is_some_and(|p| p.height() == tip && p.hash() == hash_bytes(data.verifier.tip()))
        })
        .cloned();
    let mut retry = Duration::from_secs(2);
    while ready.is_none() {
        if stop.load(Ordering::Relaxed) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        status(view, &data, "finding a Grin peer for GetHeaders");
        let addrs = addresses(net, peers);
        for peer in addrs {
            if stop.load(Ordering::Relaxed) {
                return Err(io::ErrorKind::Interrupted.into());
            }
            let tip = data.verifier.tip();
            let Ok(mut s) = Session::connect(peer, net.genesis_hash(), tip.total_difficulty().to_num(), tip.height)
            else {
                continue;
            };
            loop {
                if stop.load(Ordering::Relaxed) {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                status(view, &data, "checking historical headers from a Grin peer");
                let Ok(Some(batch)) = s.next_headers(data.verifier.tip()) else {
                    break;
                };
                if batch.is_empty() {
                    if floor.is_none_or(|w| data.verifier.tip().total_difficulty().to_num() > w) {
                        ready = data.anchor().cloned();
                    }
                    if ready.is_none() && compete(&mut s, net, &dir, &mut data, &mut file, view, stop)? {
                        continue;
                    }
                    break;
                }
                let short = batch.len() < MAX_BATCH;
                // Preserve valid prefix even if the peer ends its batch badly.
                let mut bytes = Vec::new();
                let mut valid = true;
                for header in batch {
                    let from = bytes.len();
                    write_frame(&mut bytes, &header)?;
                    let size = u64::try_from(bytes.len().saturating_sub(from)).map_err(|_| invalid("frame length"))?;
                    if data.push(&header, now(), size).is_err() {
                        bytes.truncate(from);
                        valid = false;
                        break;
                    }
                }
                file.write_all(&bytes)?;
                file.sync_data()?;
                if !valid {
                    break;
                }
                if short && floor.is_none_or(|w| data.verifier.tip().total_difficulty().to_num() > w) {
                    ready = data.anchor().cloned();
                    if ready.is_some() {
                        break;
                    }
                }
            }
            if ready.is_some() {
                break;
            }
        }
        if ready.is_none() {
            status(view, &data, "waiting for a Grin peer with the next headers");
            for _ in 0..retry.as_secs() {
                if stop.load(Ordering::Relaxed) {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            retry = retry.saturating_mul(2).min(Duration::from_secs(60));
        }
    }
    let anchor = ready.ok_or_else(|| invalid("no verified archive checkpoint"))?;
    let checked = fly_chain_headers::checkpoint::check(&anchor.bytes, net).map_err(|_| invalid("invalid handoff"))?;
    let history = History {
        _lock: lock,
        dir,
        root: root.to_path_buf(),
        second,
        slot: false,
        net,
        committed_hash: checked.hash(),
        committed: anchor.height,
    };
    Ok(Handoff {
        record: anchor.bytes,
        history,
        saved: None,
        tail: data.tail,
        candidate_floor: floor,
        journal: Some(file),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use fly_chain_state::testkit::Temp;
    use std::sync::{Arc, Mutex};

    fn installed(root: &Path, headers: &[BlockHeader], anchor_at: usize) -> (History, HeaderChain) {
        let net = Net::Automated;
        let mut replay = Replay::new(net).unwrap();
        for h in &headers[1..=anchor_at] {
            replay.push(h, now(), 1).unwrap();
        }
        let anchor = Anchor {
            height: anchor_at as u64,
            bytes: replay.verifier.record(1).unwrap(),
        };
        let target = compact::tail(root, false);
        let (mut chain, _) = HeaderChain::open(&target, net, &anchor.bytes).unwrap();
        offer_tail(&mut chain, &headers[anchor_at + 1..]).unwrap();
        let tip = chain.tip();
        let saved = compact::State {
            anchor,
            hash: tip.hash,
            work: tip.total_work,
            slot: false,
        };
        saved.publish(root, net).unwrap();
        let history = History {
            _lock: File::create(root.join(LOCK)).unwrap(),
            dir: root.to_owned(),
            root: root.to_owned(),
            second: false,
            slot: false,
            committed: chain.start().height(),
            committed_hash: chain.start().hash(),
            net,
        };
        chain.protect_reorg(&target);
        (history, chain)
    }

    #[test]
    fn rotate_then_reopen_uses_selected_bounded_tail_and_retires_only_after_publication() {
        let headers = fly_chain_state::testkit::Source::thin(60).headers();
        let dir = Temp::new("compact-tail-rotation");
        let (mut history, mut chain) = installed(&dir.0, &headers[..=40], 20);
        // A killed rotation may leave an incomplete file in the inactive slot.
        let stage = compact::tail(&dir.0, true);
        fs::create_dir_all(&stage).unwrap();
        fs::write(
            stage.join(fly_chain_headers::chain::FILE_NAME),
            b"incomplete",
        )
        .unwrap();
        fs::write(dir.0.join(LOG), b"previously published").unwrap();
        offer_tail(&mut chain, &headers[41..]).unwrap();
        history.advance(&mut chain).unwrap();
        assert_eq!(chain.start().height(), archive_height(60));
        assert!(history.slot);
        assert!(!dir.0.join(LOG).exists());
        assert!(!compact::tail(&dir.0, false)
            .join(fly_chain_headers::chain::FILE_NAME)
            .exists());
        let selected = compact::State::read(&dir.0, Net::Automated)
            .unwrap()
            .unwrap();
        drop(chain);
        drop(history);
        let (reopened, _) = selected.open(&dir.0, Net::Automated).unwrap();
        assert_eq!(reopened.tip().hash, hash_bytes(&headers[60]));
        assert_eq!(reopened.start().height(), archive_height(60));
        assert!(compact::State::read(&dir.0, Net::Test).is_err());
        let path = dir.0.join(compact::NAME);
        let mut bad = fs::read(&path).unwrap();
        bad[42] ^= 1;
        fs::write(&path, bad).unwrap();
        assert!(compact::State::read(&dir.0, Net::Automated).is_err());
        fs::remove_file(path).unwrap();
        assert!(compact::State::read(&dir.0, Net::Automated).is_err());
    }

    #[test]
    fn published_tail_recovers_torn_append_and_reopens_a_strictly_heavier_switch() {
        let headers = fly_chain_state::testkit::Source::thin(40).headers();
        let dir = Temp::new("compact-tail-reorg");
        let (history, mut chain) = installed(&dir.0, &headers, 20);
        let mut fork = fly_chain_headers::testkit::TestChain::from_headers(headers).fork_at(35);
        fork.mine_salted(12, 60, 401);
        let offered = chain.offer(&fork.headers[36..], now()).unwrap();
        assert!(matches!(offered.outcome, Outcome::Switched { .. }));
        let end = chain.tip();
        drop(chain);
        drop(history);
        let path = compact::tail(&dir.0, false).join(fly_chain_headers::chain::FILE_NAME);
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[42])
            .unwrap();
        let saved = compact::State::read(&dir.0, Net::Automated)
            .unwrap()
            .unwrap();
        let (restored, opened) = saved.open(&dir.0, Net::Automated).unwrap();
        assert_eq!(opened.cut_bytes, 1);
        assert_eq!(restored.tip(), end);
        drop(restored);
        let original = fs::read(&path).unwrap();
        let mut bad = original.clone();
        bad[100] ^= 1;
        fs::write(&path, &bad).unwrap();
        assert!(saved.open(&dir.0, Net::Automated).is_err());
        assert_eq!(fs::read(&path).unwrap(), bad);
    }

    #[test]
    fn each_generation_metadata_record_survives_a_damaged_primary_and_fails_closed_if_both_are_bad() {
        let dir = Temp::new("autonomous-routing");
        write_routing(&dir.0, ACTIVE, b"1").unwrap();
        write_routing(&dir.0, PENDING, b"1 12345").unwrap();
        for name in [ACTIVE, PENDING] {
            fs::write(dir.0.join(name), b"damaged").unwrap();
        }
        assert!(active(&dir.0).unwrap());
        assert_eq!(pending(&dir.0, true).unwrap(), Some(12345));
        assert_eq!(pending(&dir.0, false).unwrap(), None);
        assert_eq!(fs::read(dir.0.join(ACTIVE)).unwrap(), b"1");
        fs::write(dir.0.join(ACTIVE), b"broken").unwrap();
        fs::write(dir.0.join("autonomous-active-v1.copy"), b"bad").unwrap();
        assert!(active(&dir.0).is_err());
        for name in [ACTIVE, "autonomous-active-v1.copy"] {
            fs::remove_file(dir.0.join(name)).unwrap();
        }
        let alt = generation(&dir.0, true);
        fs::create_dir(&alt).unwrap();
        fs::write(alt.join(compact::NAME), b"existing publication").unwrap();
        assert!(active(&dir.0).is_err(), "an ambiguous active generation must be refused");
    }

    #[test]
    fn an_earlier_clock_retains_the_entire_valid_journal() {
        use fly_chain_state::testkit::Source;
        let dir = Temp::new("autonomous-earlier-clock");
        let path = dir.0.join(LOG);
        let source = Source::thin(3);
        let mut file = File::create(&path).unwrap();
        for header in source.headers() {
            write_frame(&mut file, &header).unwrap();
        }
        drop(file);
        let before = fs::read(&path).unwrap();
        let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let view = Arc::new(Mutex::new(View::default()));
        let err = replay_at(&mut file, Net::Automated, &view, &AtomicBool::new(false), 0)
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn a_wrong_genesis_journal_never_overwrites_the_other_network() {
        let dir = Temp::new("autonomous-other-net");
        let path = dir.0.join(LOG);
        let mut f = File::create(&path).unwrap();
        Net::Main.enter();
        write_frame(&mut f, &grin_core::genesis::genesis_main().header).unwrap();
        drop(f);
        let before = fs::read(&path).unwrap();
        let mut f = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let view = Arc::new(Mutex::new(View::default()));
        assert!(replay(&mut f, Net::Test, &view, &AtomicBool::new(false)).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
}
