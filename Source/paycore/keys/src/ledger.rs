//! The instance branch and its counter, kept in the journal.
//!
//! A path `m/a/0/branch/index` is handed out together with a [`Sealed`]
//! receipt: the journal frame recording it is durable and the tail guard
//! covers it. Only then may the output it derives be shown to anyone. A path
//! whose frame was lost in a crash was never returned, so its index may be
//! handed out again; a path that was returned is never handed out twice
//! (invariant K7), because a journal that lost the frame afterwards is caught
//! by the guard and continues on a new random branch (K15, K16).
use crate::path::KeyPath;
use fly_paycore_store::{
    CommitError, Dir, Frame, Guard, GuardCheck, Identity, OpenError, RootKey, Sealed, Store,
    KIND_RECOVERY,
};

/// Frame kind: a new branch was opened. Body: branch id.
pub const KIND_BRANCH_OPEN: u8 = 0x10;
/// Frame kind: a path was handed out. Body: branch id, index, account, tag.
pub const KIND_PATH_ISSUED: u8 = 0x11;
/// Longest caller tag stored with an issued path.
pub const MAX_TAG_LEN: usize = 64;
/// Branches one journal will open before refusing. The specification budgets
/// about a hundred per seed; this is a hard stop far above that.
pub const MAX_BRANCHES: usize = 4096;
/// Branch count from which [`PathLedger::branch_budget_exceeded`] reports true
/// (Level 5: collision risk budget of k <= 100 branches per seed).
pub const BRANCH_BUDGET: usize = 100;

/// Why the ledger refused.
#[derive(Debug)]
pub enum LedgerError {
    /// The journal could not be opened or created.
    Open(OpenError),
    /// A frame could not be committed.
    Commit(CommitError),
    /// The journal content does not follow the ledger's rules.
    Corrupt,
    /// The random generator of the operating system failed.
    Rng,
    /// The branch has no indices left; reopen the wallet on a new branch.
    BranchExhausted,
    /// The journal already opened [`MAX_BRANCHES`] branches.
    TooManyBranches,
    /// The tag is longer than [`MAX_TAG_LEN`].
    TagTooLong,
}

impl From<OpenError> for LedgerError {
    fn from(e: OpenError) -> Self {
        LedgerError::Open(e)
    }
}
impl From<CommitError> for LedgerError {
    fn from(e: CommitError) -> Self {
        LedgerError::Commit(e)
    }
}

/// Branch state: every branch this journal ever opened, oldest first, and the
/// next free index of the last one.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BranchState {
    branches: Vec<u32>,
    next_index: u32,
}

impl BranchState {
    /// The branch paths are currently handed out from.
    pub fn current(&self) -> Option<u32> {
        self.branches.last().copied()
    }

    /// Every branch opened by this journal, oldest first.
    pub fn branches(&self) -> &[u32] {
        &self.branches
    }

    /// Index the next issued path will get.
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// The `(branch, index)` the next issued path will have.
    pub fn peek(&self) -> Option<(u32, u32)> {
        let branch = self.current()?;
        if self.next_index == u32::MAX {
            return None;
        }
        Some((branch, self.next_index))
    }

    /// A random branch identifier this journal has not used.
    pub fn fresh_branch(&self) -> Result<u32, LedgerError> {
        if self.branches.len() >= MAX_BRANCHES {
            return Err(LedgerError::TooManyBranches);
        }
        random_branch(&self.branches)
    }

    /// Record that a branch was opened (for a layer that embeds the ledger
    /// in its own frames).
    pub fn note_branch(&mut self, branch: u32) -> Result<(), LedgerError> {
        self.open_branch(branch)
    }

    /// Record that `(branch, index)` was handed out.
    pub fn note_issued(&mut self, branch: u32, index: u32) -> Result<(), LedgerError> {
        self.issued(branch, index)
    }

    fn open_branch(&mut self, branch: u32) -> Result<(), LedgerError> {
        if self.branches.contains(&branch) || self.branches.len() >= MAX_BRANCHES {
            return Err(LedgerError::Corrupt);
        }
        self.branches.push(branch);
        self.next_index = 0;
        Ok(())
    }

    fn issued(&mut self, branch: u32, index: u32) -> Result<(), LedgerError> {
        if self.current() != Some(branch) || index != self.next_index {
            return Err(LedgerError::Corrupt);
        }
        self.next_index = index.checked_add(1).ok_or(LedgerError::Corrupt)?;
        Ok(())
    }

    /// Apply one journal frame. Frames of kinds the ledger does not own are
    /// reported as `Ok(false)` and left to the caller.
    pub fn apply(&mut self, frame: &Frame) -> Result<bool, LedgerError> {
        let mut r = Bytes(&frame.body);
        match frame.kind {
            KIND_BRANCH_OPEN | KIND_RECOVERY => {
                let branch = r.u32().ok_or(LedgerError::Corrupt)?;
                if !r.is_empty() {
                    return Err(LedgerError::Corrupt);
                }
                self.open_branch(branch)?;
                Ok(true)
            }
            KIND_PATH_ISSUED => {
                let branch = r.u32().ok_or(LedgerError::Corrupt)?;
                let index = r.u32().ok_or(LedgerError::Corrupt)?;
                let _account = r.u32().ok_or(LedgerError::Corrupt)?;
                if r.len() > MAX_TAG_LEN {
                    return Err(LedgerError::Corrupt);
                }
                self.issued(branch, index)?;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    /// Serialise for a checkpoint.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // bounded by MAX_BRANCHES, so the count always fits
        out.extend_from_slice(
            &u32::try_from(self.branches.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for b in &self.branches {
            out.extend_from_slice(&b.to_le_bytes());
        }
        out.extend_from_slice(&self.next_index.to_le_bytes());
        out
    }

    /// Parse a checkpoint. Trailing bytes, duplicate branches and absurd
    /// counts are rejected.
    pub fn decode(bytes: &[u8]) -> Result<BranchState, LedgerError> {
        let mut r = Bytes(bytes);
        let n = usize::try_from(r.u32().ok_or(LedgerError::Corrupt)?)
            .map_err(|_| LedgerError::Corrupt)?;
        if n > MAX_BRANCHES {
            return Err(LedgerError::Corrupt);
        }
        let mut s = BranchState::default();
        for _ in 0..n {
            s.open_branch(r.u32().ok_or(LedgerError::Corrupt)?)?;
        }
        s.next_index = r.u32().ok_or(LedgerError::Corrupt)?;
        if !r.is_empty() {
            return Err(LedgerError::Corrupt);
        }
        Ok(s)
    }
}

struct Bytes<'a>(&'a [u8]);
impl Bytes<'_> {
    fn u32(&mut self) -> Option<u32> {
        let (head, rest) = self.0.split_first_chunk::<4>()?;
        self.0 = rest;
        Some(u32::from_le_bytes(*head))
    }
    fn len(&self) -> usize {
        self.0.len()
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A path that may now be used: its record is durable and guarded.
#[derive(Debug)]
pub struct Issued {
    /// The path.
    pub path: KeyPath,
    /// Proof of the durable, guarded journal frame.
    pub sealed: Sealed,
}

/// What happened while opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenReport {
    /// Outcome of the tail-guard check.
    pub guard: GuardCheck,
    /// Whether a new branch was opened during this call (rollback, move, or
    /// a creation that had not got as far as its first branch).
    pub new_branch: bool,
}

/// The journal with the branch ledger on top.
pub struct PathLedger<D: Dir, G: Guard> {
    store: Store<D, G>,
    state: BranchState,
}

fn random_branch(taken: &[u32]) -> Result<u32, LedgerError> {
    // 32 bits from the operating system; a value this journal already used is
    // drawn again. Sixteen consecutive repeats do not happen with a working
    // generator.
    for _ in 0..16 {
        let mut b = [0u8; 4];
        getrandom::getrandom(&mut b).map_err(|_| LedgerError::Rng)?;
        let v = u32::from_le_bytes(b);
        if !taken.contains(&v) {
            return Ok(v);
        }
    }
    Err(LedgerError::Rng)
}

impl<D: Dir, G: Guard> PathLedger<D, G> {
    /// Create a wallet journal and open its first branch.
    pub fn create(dir: D, guard: G, root: &RootKey, id: Identity) -> Result<Self, LedgerError> {
        let store = Store::create(dir, guard, root, id)?;
        let mut ledger = PathLedger {
            store,
            state: BranchState::default(),
        };
        ledger.open_new_branch(false)?;
        Ok(ledger)
    }

    /// Open a wallet journal. After a detected rollback or move, and when no
    /// branch exists yet, a new random branch is opened before returning.
    pub fn open(
        dir: D,
        guard: G,
        root: &RootKey,
        id: Identity,
    ) -> Result<(Self, OpenReport), LedgerError> {
        let opened = Store::open(dir, guard, root, id)?;
        let mut state = match opened.snapshot {
            Some(s) => BranchState::decode(&s)?,
            None => BranchState::default(),
        };
        for frame in &opened.frames {
            // Until later stages add their own kinds, every frame is the ledger's.
            if !state.apply(frame)? {
                return Err(LedgerError::Corrupt);
            }
        }
        let mut ledger = PathLedger {
            store: opened.store,
            state,
        };
        let recovery = opened.guard.recovery_required();
        let new_branch = recovery || ledger.state.current().is_none();
        if new_branch {
            ledger.open_new_branch(recovery)?;
        }
        Ok((
            ledger,
            OpenReport {
                guard: opened.guard,
                new_branch,
            },
        ))
    }

    fn open_new_branch(&mut self, recovery: bool) -> Result<(), LedgerError> {
        if self.state.branches.len() >= MAX_BRANCHES {
            return Err(LedgerError::TooManyBranches);
        }
        let branch = random_branch(&self.state.branches)?;
        let body = branch.to_le_bytes();
        if recovery {
            self.store.commit_recovery(&body)?;
        } else {
            self.store.commit_sealed(KIND_BRANCH_OPEN, &body)?;
        }
        self.state.open_branch(branch)
    }

    /// Hand out the next path of the current branch for `account`. `tag` is
    /// stored with the record (for example an operation identifier); it must
    /// not contain secrets beyond what the journal already protects.
    pub fn issue(&mut self, account: u32, tag: &[u8]) -> Result<Issued, LedgerError> {
        if tag.len() > MAX_TAG_LEN {
            return Err(LedgerError::TagTooLong);
        }
        let branch = self.state.current().ok_or(LedgerError::Corrupt)?;
        let index = self.state.next_index;
        if index == u32::MAX {
            return Err(LedgerError::BranchExhausted);
        }
        let mut body = Vec::with_capacity(12usize.saturating_add(tag.len()));
        body.extend_from_slice(&branch.to_le_bytes());
        body.extend_from_slice(&index.to_le_bytes());
        body.extend_from_slice(&account.to_le_bytes());
        body.extend_from_slice(tag);
        let sealed = self.store.commit_sealed(KIND_PATH_ISSUED, &body)?;
        self.state.issued(branch, index)?;
        Ok(Issued {
            path: KeyPath::Branch {
                account,
                branch,
                index,
            },
            sealed,
        })
    }

    /// Fold the journal into a snapshot and start a new generation.
    pub fn checkpoint(&mut self) -> Result<Sealed, LedgerError> {
        Ok(self.store.checkpoint(&self.state.encode())?)
    }

    /// Branch state.
    pub fn state(&self) -> &BranchState {
        &self.state
    }

    /// Whether this journal opened more branches than the risk budget allows.
    pub fn branch_budget_exceeded(&self) -> bool {
        self.state.branches.len() > BRANCH_BUDGET
    }
}
