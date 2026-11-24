//! The journal store: create, open (with torn-tail handling and the guard
//! check), commit, checkpoint.
use crate::crypto::{ct_eq, Keys, RootKey};
use crate::error::{CommitError, NotWritten, OpenError};
use crate::format::{
    decode_header, decode_rotate, decode_snapshot, encode_frame, encode_header, encode_rotate,
    encode_snapshot, journal_name, parse_frame, parse_journal_name, snapshot_name,
    valid_frame_follows, EncodeError, Header, HeaderError, Identity, Parsed, RawFrame, Rotate,
    HEADER_LEN, KIND_RECOVERY, KIND_ROTATE, MAX_FILE_LEN, MAX_USER_KIND, ROTATE_FRAME_LEN,
};
use crate::io::{Dir, Guard, GuardValue, Medium};
use zeroize::Zeroizing;

/// One committed frame as returned by [`Store::open`].
pub struct Frame {
    /// Position in the journal, counted from the wallet's creation.
    pub seq: u64,
    /// Caller-defined kind, or [`KIND_RECOVERY`].
    pub kind: u8,
    /// Decrypted body. Wiped when dropped.
    pub body: Zeroizing<Vec<u8>>,
}

/// Result of comparing the journal tail with the tail guard at open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuardCheck {
    /// The guard points at the journal tail.
    Match,
    /// The journal was ahead of the guard (a frame survived a crash before
    /// its guard update); the guard has been advanced to the tail.
    CaughtUp,
    /// The journal is older than the guard or on a different history: it was
    /// rolled back or replaced. Recovery is required.
    RolledBack,
    /// This device holds no guard for a journal that has frames: it was moved
    /// here or the application was reinstalled. Recovery is required.
    Missing,
}

impl GuardCheck {
    /// Whether a recovery frame must be committed before anything else.
    pub fn recovery_required(self) -> bool {
        matches!(self, GuardCheck::RolledBack | GuardCheck::Missing)
    }
}

/// Proof that a frame is durable. Cannot be constructed outside this crate.
#[derive(Debug)]
pub struct Receipt {
    seq: u64,
    hash: [u8; 32],
}

/// Proof that a frame is durable **and** the tail guard covers it. Actions
/// that sign or disclose must demand this type, so that the order
/// "durable, guard, then act" is enforced by the compiler. Cannot be
/// constructed outside this crate.
#[derive(Debug)]
pub struct Sealed {
    seq: u64,
    hash: [u8; 32],
}

impl Receipt {
    /// Sequence number of the frame.
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// Hash of the frame.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

impl Sealed {
    /// Sequence number of the frame.
    pub fn seq(&self) -> u64 {
        self.seq
    }
    /// Hash of the frame.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

/// What [`Store::open`] returns.
pub struct Opened<D: Dir, G: Guard> {
    /// The store, ready for commits (or for the recovery frame only, see
    /// [`GuardCheck::recovery_required`]).
    pub store: Store<D, G>,
    /// State saved by the last checkpoint, if there was one.
    pub snapshot: Option<Zeroizing<Vec<u8>>>,
    /// Frames committed after that checkpoint, in order.
    pub frames: Vec<Frame>,
    /// Outcome of the guard check.
    pub guard: GuardCheck,
}

/// An open journal. Dropping it releases the single-writer lock.
pub struct Store<D: Dir, G: Guard> {
    dir: D,
    _lock: D::Lock,
    guard: G,
    keys: Keys,
    id: Identity,
    journal: D::File,
    journal_len: usize,
    header: Header,
    next_seq: u64,
    tail: [u8; 32],
    poisoned: bool,
    recovery: bool,
}

enum End {
    Clean,
    Torn,
    Corrupt,
}

struct Loaded<F> {
    file: F,
    header: Header,
    frames: Vec<RawFrame>,
    /// Length of the valid prefix of the file.
    valid_len: usize,
    end: End,
}

impl<F> Loaded<F> {
    /// Tail hash at journal position `pos` (the hash a frame with sequence
    /// number `pos` must name as its predecessor), if `pos` is in this file.
    fn hash_at(&self, pos: u64) -> Option<[u8; 32]> {
        if pos == self.header.base_seq {
            return Some(self.header.hash);
        }
        let seq = pos.checked_sub(1)?;
        self.frames.iter().find(|f| f.seq == seq).map(|f| f.hash)
    }

    fn next_seq(&self) -> Option<u64> {
        self.header
            .base_seq
            .checked_add(u64::try_from(self.frames.len()).ok()?)
    }

    fn tail(&self) -> [u8; 32] {
        self.frames
            .last()
            .map(|f| f.hash)
            .unwrap_or(self.header.hash)
    }
}

fn header_err(e: HeaderError) -> OpenError {
    match e {
        HeaderError::Malformed => OpenError::BadHeader,
        HeaderError::WrongIdentity => OpenError::WrongIdentity,
        HeaderError::Crypto => OpenError::Crypto,
    }
}

fn load<D: Dir>(
    dir: &D,
    keys: &Keys,
    id: &Identity,
    generation: u64,
) -> Result<Loaded<D::File>, OpenError> {
    let mut file = dir.open(&journal_name(generation))?;
    if file.len()? > MAX_FILE_LEN {
        return Err(OpenError::TooLarge);
    }
    let bytes = file.read_all()?;
    let header = decode_header(keys, id, &bytes).map_err(header_err)?;
    if header.generation != generation {
        return Err(OpenError::Corrupt);
    }
    let mut frames = Vec::new();
    let mut offset = HEADER_LEN;
    let mut seq = header.base_seq;
    let mut prev = header.hash;
    let end = loop {
        let rest = bytes.get(offset..).ok_or(OpenError::Corrupt)?;
        match parse_frame(keys, &header.hash, seq, &prev, rest) {
            Parsed::End => break End::Clean,
            Parsed::Invalid => {
                // An append that never became durable is the last thing in
                // the file, whatever the crash left there (a cut frame, zeros,
                // stale blocks). If a valid frame follows, this is damage.
                break if valid_frame_follows(keys, &header.hash, seq, rest) {
                    End::Corrupt
                } else {
                    End::Torn
                };
            }
            Parsed::Frame(f, used) => {
                offset = offset.checked_add(used).ok_or(OpenError::Corrupt)?;
                seq = seq.checked_add(1).ok_or(OpenError::Corrupt)?;
                prev = f.hash;
                frames.push(f);
            }
        }
    };
    Ok(Loaded {
        file,
        header,
        frames,
        valid_len: offset,
        end,
    })
}

fn remove_if_present<D: Dir>(dir: &D, name: &str) -> std::io::Result<()> {
    match dir.remove(name) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn parse_snapshot_name(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("snapshot-")?;
    parse_journal_name(&format!("journal-{}", rest))
}

impl<D: Dir, G: Guard> Store<D, G> {
    /// Create a new, empty journal. The caller starts a new key branch.
    pub fn create(
        dir: D,
        guard: G,
        root: &RootKey,
        id: Identity,
    ) -> Result<Store<D, G>, OpenError> {
        let lock = dir.lock()?;
        let keys = Keys::derive(root, &id).map_err(|_| OpenError::Crypto)?;
        for name in dir.list()? {
            match parse_journal_name(&name) {
                // A crash while the very first header was being written leaves
                // a file that holds no frame and no valid header. It carries
                // no state and is replaced.
                Some(0) if Self::is_failed_creation(&dir, &keys, &id, &name)? => {
                    dir.remove(&name)?;
                    dir.sync()?;
                }
                Some(_) => return Err(OpenError::AlreadyExists),
                None => {}
            }
        }
        let (bytes, header) =
            encode_header(&keys, &id, 0, 0, &[0u8; 32], &[0u8; 32]).map_err(header_err)?;
        let mut journal = dir.create_new(&journal_name(0))?;
        journal.append(&bytes)?;
        journal.sync()?;
        dir.sync()?;
        let tail = header.hash;
        guard
            .store(&GuardValue { next_seq: 0, tail })
            .map_err(|e| OpenError::Guard(e.kind()))?;
        Ok(Store {
            dir,
            _lock: lock,
            guard,
            keys,
            id,
            journal,
            journal_len: bytes.len(),
            header,
            next_seq: 0,
            tail,
            poisoned: false,
            recovery: false,
        })
    }

    fn is_failed_creation(
        dir: &D,
        keys: &Keys,
        id: &Identity,
        name: &str,
    ) -> Result<bool, OpenError> {
        let mut f = dir.open(name)?;
        let len = usize::try_from(f.len()?).map_err(|_| OpenError::TooLarge)?;
        if len > HEADER_LEN {
            return Ok(false);
        }
        Ok(len < HEADER_LEN || decode_header(keys, id, &f.read_all()?).is_err())
    }

    /// Open an existing journal: verify every frame, drop an un-synced last
    /// frame, and compare the tail with the guard.
    pub fn open(dir: D, guard: G, root: &RootKey, id: Identity) -> Result<Opened<D, G>, OpenError> {
        let lock = dir.lock()?;
        let keys = Keys::derive(root, &id).map_err(|_| OpenError::Crypto)?;
        let names = dir.list()?;
        let mut generations: Vec<u64> =
            names.iter().filter_map(|n| parse_journal_name(n)).collect();
        generations.sort_unstable();
        let latest = *generations.last().ok_or(OpenError::NotFound)?;

        // The newest file is current only if its predecessor, when still
        // present, ends in a rotate frame naming it. Otherwise the checkpoint
        // that was creating it never committed and the file is discarded.
        let previous_gen = latest.checked_sub(1).filter(|g| generations.contains(g));
        let mut previous = match previous_gen {
            Some(g) => Some(load(&dir, &keys, &id, g)?),
            None => None,
        };
        let mut current = None;
        if let Some(prev) = previous.as_ref() {
            if matches!(prev.end, End::Corrupt) {
                return Err(OpenError::Corrupt);
            }
            let rotate = prev
                .frames
                .last()
                .filter(|f| f.kind == KIND_ROTATE)
                .map(|f| (f.seq, decode_rotate(&f.body)));
            match rotate {
                Some((seq, Some(rot))) if rot.generation == latest => {
                    let cur = load(&dir, &keys, &id, latest)?;
                    let base = seq.checked_add(1).ok_or(OpenError::Corrupt)?;
                    // position `seq` is where the rotate frame sits; the new
                    // file must name the history that led up to it
                    let before_rotate = prev.hash_at(seq).ok_or(OpenError::Corrupt)?;
                    if cur.header.base_seq != base
                        || !ct_eq(&cur.header.hash, &rot.header)
                        || !ct_eq(&cur.header.snapshot, &rot.snapshot)
                        || !ct_eq(&cur.header.prev_tail, &before_rotate)
                    {
                        return Err(OpenError::Corrupt);
                    }
                    current = Some(cur);
                }
                Some(_) => return Err(OpenError::Corrupt),
                None => {
                    remove_if_present(&dir, &journal_name(latest))?;
                    remove_if_present(&dir, &snapshot_name(latest))?;
                    dir.sync()?;
                }
            }
        }
        let mut cur = match current {
            Some(c) => c,
            None => match previous.take() {
                Some(p) => p,
                None => load(&dir, &keys, &id, latest)?,
            },
        };

        match cur.end {
            End::Corrupt => return Err(OpenError::Corrupt),
            End::Torn => {
                // Never durable, so nothing was signed or disclosed on its
                // strength. Remove it so that later frames follow valid ones.
                let len = u64::try_from(cur.valid_len).map_err(|_| OpenError::Corrupt)?;
                cur.file.truncate(len)?;
                cur.file.sync()?;
            }
            End::Clean => {}
        }
        // A rotate frame is always preceded by a durable next generation.
        if cur.frames.last().map(|f| f.kind) == Some(KIND_ROTATE) {
            return Err(OpenError::Corrupt);
        }

        let generation = cur.header.generation;
        let snapshot = if generation > 0 {
            let mut f = dir.open(&snapshot_name(generation))?;
            if f.len()? > MAX_FILE_LEN {
                return Err(OpenError::TooLarge);
            }
            let bytes = f.read_all()?;
            Some(
                decode_snapshot(&keys, &id, generation, &cur.header.snapshot, &bytes)
                    .ok_or(OpenError::Corrupt)?,
            )
        } else {
            None
        };

        // Files of generations other than the current and the one before it
        // are leftovers of interrupted or completed checkpoints.
        let keep_from = generation.saturating_sub(1);
        for name in &names {
            let g = parse_journal_name(name).or_else(|| parse_snapshot_name(name));
            if let Some(g) = g {
                if g > generation || g < keep_from {
                    remove_if_present(&dir, name)?;
                }
            }
        }

        let next_seq = cur.next_seq().ok_or(OpenError::Corrupt)?;
        let tail = cur.tail();
        let here = GuardValue { next_seq, tail };
        let guard_err = |e: std::io::Error| OpenError::Guard(e.kind());
        let check = match guard.load().map_err(guard_err)? {
            None if next_seq == 0 => {
                guard.store(&here).map_err(guard_err)?;
                GuardCheck::CaughtUp
            }
            None => GuardCheck::Missing,
            Some(g) if g.next_seq == next_seq => {
                if ct_eq(&g.tail, &tail) {
                    GuardCheck::Match
                } else {
                    GuardCheck::RolledBack
                }
            }
            Some(g) if g.next_seq > next_seq => GuardCheck::RolledBack,
            Some(g) => {
                // The journal is ahead. It may only be caught up with if it
                // extends the very history the guard recorded.
                let recorded = if g.next_seq >= cur.header.base_seq {
                    cur.hash_at(g.next_seq)
                } else {
                    // The guard still points into the previous generation: a
                    // crash between the rotate frame and the guard update.
                    previous.as_ref().and_then(|p| p.hash_at(g.next_seq))
                };
                match recorded {
                    Some(h) if ct_eq(&h, &g.tail) => {
                        guard.store(&here).map_err(guard_err)?;
                        GuardCheck::CaughtUp
                    }
                    _ => GuardCheck::RolledBack,
                }
            }
        };

        let frames = cur
            .frames
            .into_iter()
            .map(|f| Frame {
                seq: f.seq,
                kind: f.kind,
                body: f.body,
            })
            .collect();
        Ok(Opened {
            store: Store {
                dir,
                _lock: lock,
                guard,
                keys,
                id,
                journal: cur.file,
                journal_len: cur.valid_len,
                header: cur.header,
                next_seq,
                tail,
                poisoned: false,
                recovery: check.recovery_required(),
            },
            snapshot,
            frames,
            guard: check,
        })
    }

    /// Current tail position.
    pub fn tail(&self) -> GuardValue {
        GuardValue {
            next_seq: self.next_seq,
            tail: self.tail,
        }
    }

    /// Generation of the journal file in use.
    pub fn generation(&self) -> u64 {
        self.header.generation
    }

    /// Whether only a recovery frame is accepted.
    pub fn recovery_required(&self) -> bool {
        self.recovery
    }

    fn ready(&self, kind: u8) -> Result<(), CommitError> {
        if self.poisoned {
            return Err(CommitError::Poisoned);
        }
        if self.recovery {
            return Err(CommitError::RecoveryRequired);
        }
        if kind > MAX_USER_KIND {
            return Err(CommitError::NotWritten(NotWritten::ReservedKind));
        }
        Ok(())
    }

    fn journal_end(&self, added: usize, reserve: usize) -> Result<usize, CommitError> {
        let cap = usize::try_from(MAX_FILE_LEN).unwrap_or(usize::MAX);
        self.journal_len
            .checked_add(added)
            .filter(|end| *end <= cap.saturating_sub(reserve))
            .ok_or(CommitError::NotWritten(NotWritten::TooLarge))
    }

    /// Append one frame and make it durable. With `seal`, also advance the
    /// guard. State changes only if every step succeeded.
    fn append(
        &mut self,
        kind: u8,
        body: &[u8],
        seal: bool,
    ) -> Result<(u64, [u8; 32]), CommitError> {
        let seq = self.next_seq;
        let next = seq
            .checked_add(1)
            .ok_or(CommitError::NotWritten(NotWritten::SequenceExhausted))?;
        let (bytes, hash) =
            encode_frame(&self.keys, &self.header.hash, seq, &self.tail, kind, body).map_err(
                |e| {
                    CommitError::NotWritten(match e {
                        EncodeError::TooLarge => NotWritten::TooLarge,
                        EncodeError::Crypto => NotWritten::Crypto,
                    })
                },
            )?;
        // Every ordinary commit leaves room for a future checkpoint. The
        // rotate frame itself may consume that reserve.
        let reserve = if kind == KIND_ROTATE {
            0
        } else {
            ROTATE_FRAME_LEN
        };
        let end = self.journal_end(bytes.len(), reserve)?;
        // From the first byte written the outcome is unknown until every
        // remaining step has succeeded.
        self.poisoned = true;
        self.journal
            .append(&bytes)
            .map_err(|_| CommitError::Unknown)?;
        self.journal.sync().map_err(|_| CommitError::Unknown)?;
        if seal {
            self.guard
                .store(&GuardValue {
                    next_seq: next,
                    tail: hash,
                })
                .map_err(|_| CommitError::Unknown)?;
        }
        self.journal_len = end;
        self.next_seq = next;
        self.tail = hash;
        self.poisoned = false;
        Ok((seq, hash))
    }

    /// Commit a frame. On `Ok` it is durable.
    pub fn commit(&mut self, kind: u8, body: &[u8]) -> Result<Receipt, CommitError> {
        self.ready(kind)?;
        let (seq, hash) = self.append(kind, body, false)?;
        Ok(Receipt { seq, hash })
    }

    /// Commit a frame that will allow something to be signed or disclosed.
    /// On `Ok` it is durable and the tail guard covers it.
    pub fn commit_sealed(&mut self, kind: u8, body: &[u8]) -> Result<Sealed, CommitError> {
        self.ready(kind)?;
        let (seq, hash) = self.append(kind, body, true)?;
        Ok(Sealed { seq, hash })
    }

    /// Commit the recovery frame demanded by the guard check. The body is the
    /// caller's record of what it did (new branch, locked operations).
    pub fn commit_recovery(&mut self, body: &[u8]) -> Result<Sealed, CommitError> {
        if self.poisoned {
            return Err(CommitError::Poisoned);
        }
        if !self.recovery {
            return Err(CommitError::NotWritten(NotWritten::NoRecoveryPending));
        }
        let (seq, hash) = self.append(KIND_RECOVERY, body, true)?;
        self.recovery = false;
        Ok(Sealed { seq, hash })
    }

    /// Frames written to the current generation: what the next fold
    /// (5.5) takes off the journal.
    pub fn frames_in_generation(&self) -> u64 {
        self.next_seq.saturating_sub(self.header.base_seq)
    }

    /// Save `state` as a snapshot and continue in a new journal generation.
    /// `state` must be the fold of everything committed so far.
    pub fn checkpoint(&mut self, state: &[u8]) -> Result<Sealed, CommitError> {
        self.ready(0)?;
        // An older writer may already have used the space reserved for rotate.
        self.journal_end(ROTATE_FRAME_LEN, 0)?;
        let io = |_: std::io::Error| CommitError::NotWritten(NotWritten::Io);
        let generation = self
            .header
            .generation
            .checked_add(1)
            .ok_or(CommitError::NotWritten(NotWritten::SequenceExhausted))?;
        let rotate_seq = self.next_seq;
        let base = rotate_seq
            .checked_add(1)
            .ok_or(CommitError::NotWritten(NotWritten::SequenceExhausted))?;

        // 1. Snapshot and next journal file, both durable, neither yet
        //    referenced. A crash here leaves files that open() discards.
        let (snap_bytes, snap_hash) = encode_snapshot(&self.keys, &self.id, generation, state)
            .map_err(|e| {
                CommitError::NotWritten(match e {
                    EncodeError::TooLarge => NotWritten::TooLarge,
                    EncodeError::Crypto => NotWritten::Crypto,
                })
            })?;
        remove_if_present(&self.dir, &snapshot_name(generation)).map_err(io)?;
        remove_if_present(&self.dir, &journal_name(generation)).map_err(io)?;
        let mut snap = self
            .dir
            .create_new(&snapshot_name(generation))
            .map_err(io)?;
        snap.append(&snap_bytes).map_err(io)?;
        snap.sync().map_err(io)?;
        let (head_bytes, header) = encode_header(
            &self.keys, &self.id, generation, base, &self.tail, &snap_hash,
        )
        .map_err(|_| CommitError::NotWritten(NotWritten::Crypto))?;
        let mut journal = self.dir.create_new(&journal_name(generation)).map_err(io)?;
        journal.append(&head_bytes).map_err(io)?;
        journal.sync().map_err(io)?;
        self.dir.sync().map_err(io)?;

        // 2. The rotate frame in the current file is the commit point.
        let body = encode_rotate(&Rotate {
            generation,
            snapshot: snap_hash,
            header: header.hash,
        });
        let (seq, _) = self.append(KIND_ROTATE, &body, false)?;

        // 3. Switch, then let the guard follow.
        self.poisoned = true;
        self.journal = journal;
        self.journal_len = head_bytes.len();
        self.tail = header.hash;
        self.next_seq = base;
        self.header = header;
        self.guard
            .store(&GuardValue {
                next_seq: self.next_seq,
                tail: self.tail,
            })
            .map_err(|_| CommitError::Unknown)?;
        self.poisoned = false;

        // 4. Two generations are kept; older ones go. Failure to delete is
        //    harmless and retried at the next open.
        if let Some(old) = generation.checked_sub(2) {
            let _ = remove_if_present(&self.dir, &journal_name(old));
            let _ = remove_if_present(&self.dir, &snapshot_name(old));
        }
        Ok(Sealed {
            seq,
            hash: self.tail,
        })
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod file_limit_tests {
    use super::*;
    use crate::sim::Sim;

    fn id() -> Identity {
        Identity {
            network: 2,
            instance: [3; 16],
            genesis: [4; 32],
        }
    }

    #[test]
    fn checkpoint_at_file_limit_reopens_and_next_byte_is_refused() {
        let sim = Sim::new();
        let key = RootKey::new([21; 32]);
        let mut store = Store::create(sim.dir(), sim.guard(), &key, id()).unwrap();
        // Snapshot header: magic, generation and nonce; ciphertext adds a tag.
        let at_limit = vec![3; MAX_FILE_LEN as usize - (8 + 8 + 24 + 16)];
        store.checkpoint(&at_limit).unwrap();
        let tail = store.tail();
        let too_large = vec![4; at_limit.len() + 1];
        assert!(matches!(
            store.checkpoint(&too_large),
            Err(CommitError::NotWritten(NotWritten::TooLarge))
        ));
        assert_eq!(store.tail(), tail);
        drop(store);
        let opened = Store::open(sim.dir(), sim.guard(), &key, id()).unwrap();
        assert_eq!(opened.snapshot.unwrap().as_slice(), at_limit.as_slice());
    }

    #[test]
    fn near_limit_journal_reserves_space_for_rotation_across_reopen() {
        let sim = Sim::new();
        let key = RootKey::new([22; 32]);
        let mut store = Store::create(sim.dir(), sim.guard(), &key, id()).unwrap();
        // Each frame adds 85 bytes; the rotate body is 72 bytes.
        let body = vec![5; MAX_FILE_LEN as usize - HEADER_LEN - 85 - (85 + 72)];
        store.commit(1, &body).unwrap();
        drop(store);
        let mut store = Store::open(sim.dir(), sim.guard(), &key, id())
            .unwrap()
            .store;
        let tail = store.tail();
        assert!(matches!(
            store.commit_sealed(2, b"x"),
            Err(CommitError::NotWritten(NotWritten::TooLarge))
        ));
        assert_eq!(store.tail(), tail);
        store.checkpoint(b"fold").unwrap();
        store.commit(1, b"later").unwrap();
        drop(store);
        let opened = Store::open(sim.dir(), sim.guard(), &key, id()).unwrap();
        assert_eq!(opened.snapshot.unwrap().as_slice(), b"fold");
        assert_eq!(opened.frames.len(), 1);
    }

    #[test]
    fn legacy_journal_without_rotate_space_still_reopens_unchanged() {
        let sim = Sim::new();
        let key = RootKey::new([23; 32]);
        let store = Store::create(sim.dir(), sim.guard(), &key, id()).unwrap();
        // A valid old-format frame, ending exactly at the reader's limit.
        let body = vec![6; MAX_FILE_LEN as usize - HEADER_LEN - 85];
        let (frame, _) = encode_frame(
            &store.keys,
            &store.header.hash,
            store.next_seq,
            &store.tail,
            1,
            &body,
        )
        .ok()
        .unwrap();
        drop(store);
        let name = journal_name(0);
        let mut bytes = sim.file(&name).unwrap();
        bytes.extend_from_slice(&frame);
        sim.set_file(&name, &bytes);
        let opened = Store::open(sim.dir(), sim.guard(), &key, id()).unwrap();
        assert_eq!(opened.frames.len(), 1);
        let mut store = opened.store;
        assert!(matches!(
            store.checkpoint(b"fold"),
            Err(CommitError::NotWritten(NotWritten::TooLarge))
        ));
        drop(store);
        assert_eq!(sim.file(&name).unwrap(), bytes);
        let opened = Store::open(sim.dir(), sim.guard(), &key, id()).unwrap();
        assert_eq!(opened.frames.len(), 1);
        assert!(opened.snapshot.is_none());
    }
}
