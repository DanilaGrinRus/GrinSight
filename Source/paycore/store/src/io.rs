//! Storage abstractions. The real implementation is [`crate::FsDir`]; tests
//! use `sim::SimDir`, which can fail or "lose power" at any operation.
use std::io;

/// One file opened for reading and appending.
#[allow(clippy::len_without_is_empty)]
pub trait Medium {
    /// Current length in bytes.
    fn len(&mut self) -> io::Result<u64>;
    /// Whole content.
    fn read_all(&mut self) -> io::Result<Vec<u8>>;
    /// Append at the end. Not durable until [`Medium::sync`] returns.
    fn append(&mut self, data: &[u8]) -> io::Result<()>;
    /// Make everything appended so far durable.
    fn sync(&mut self) -> io::Result<()>;
    /// Cut the file to `len` bytes. Not durable until [`Medium::sync`].
    fn truncate(&mut self, len: u64) -> io::Result<()>;
}

/// The directory holding one wallet's journal files.
pub trait Dir {
    /// File handle type.
    type File: Medium;
    /// Held for as long as the store is open.
    type Lock;
    /// Take the single-writer lock. `ErrorKind::WouldBlock` if already held.
    fn lock(&self) -> io::Result<Self::Lock>;
    /// Names of all files.
    fn list(&self) -> io::Result<Vec<String>>;
    /// Open an existing file.
    fn open(&self, name: &str) -> io::Result<Self::File>;
    /// Create a file that must not exist yet.
    fn create_new(&self, name: &str) -> io::Result<Self::File>;
    /// Remove a file.
    fn remove(&self, name: &str) -> io::Result<()>;
    /// Make creations and removals durable.
    fn sync(&self) -> io::Result<()>;
}

/// Position of the journal tail: number of frames ever committed and the
/// hash of the last one (or of the file header if there is none).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardValue {
    /// Sequence number the next frame will get.
    pub next_seq: u64,
    /// Hash of the last frame.
    pub tail: [u8; 32],
}

/// Tail guard: a small value kept by the operating system outside the wallet
/// directory (DPAPI, Android Keystore). Supplied by the platform layer.
pub trait Guard {
    /// Stored value, or `None` if this device has none for this wallet.
    fn load(&self) -> io::Result<Option<GuardValue>>;
    /// Replace the stored value. Must be durable on return.
    fn store(&self, value: &GuardValue) -> io::Result<()>;
}
