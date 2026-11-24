//! Error types. They carry codes, never key material or frame contents.
use std::fmt;

/// Why a journal could not be opened or created.
#[derive(Debug)]
pub enum OpenError {
    /// Another process or handle holds the journal lock.
    Locked,
    /// No journal exists in the directory.
    NotFound,
    /// A journal already exists where a new one was to be created.
    AlreadyExists,
    /// The file header is malformed, of an unknown version, or its MAC does
    /// not verify under the supplied key.
    BadHeader,
    /// The journal belongs to a different network, genesis or wallet instance.
    WrongIdentity,
    /// A frame that is not the last one fails verification, or generations do
    /// not link up. Nothing was changed on disk.
    Corrupt,
    /// The file is larger than this implementation accepts.
    TooLarge,
    /// The operating system random generator or a key derivation failed.
    Crypto,
    /// An input/output error.
    Io(std::io::ErrorKind),
    /// The tail guard could not be read or written.
    Guard(std::io::ErrorKind),
}

/// Why a frame was not committed.
#[derive(Debug, PartialEq, Eq)]
pub enum CommitError {
    /// Nothing was written; the journal is unchanged and stays usable.
    NotWritten(NotWritten),
    /// The write or the guard update failed part-way. Whether the frame is on
    /// disk is unknown. The store is poisoned: reopen it to find out.
    Unknown,
    /// An earlier commit ended in [`CommitError::Unknown`].
    Poisoned,
    /// The guard check at open found a rollback or a moved journal. Only a
    /// frame of kind [`crate::KIND_RECOVERY`] is accepted until then.
    RecoveryRequired,
}

/// Reasons for [`CommitError::NotWritten`].
#[derive(Debug, PartialEq, Eq)]
pub enum NotWritten {
    /// The frame body or resulting journal/snapshot file exceeds its limit.
    TooLarge,
    /// The frame kind is reserved for the store itself.
    ReservedKind,
    /// A recovery frame was offered while no recovery is pending.
    NoRecoveryPending,
    /// The sequence counter is exhausted.
    SequenceExhausted,
    /// The operating system random generator or the cipher failed.
    Crypto,
    /// Preparing a checkpoint failed before the journal was touched.
    Io,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "journal open failed: {:?}", self)
    }
}
impl std::error::Error for OpenError {}

impl fmt::Display for CommitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "journal commit failed: {:?}", self)
    }
}
impl std::error::Error for CommitError {}

impl From<std::io::Error> for OpenError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::WouldBlock {
            OpenError::Locked
        } else {
            OpenError::Io(e.kind())
        }
    }
}
