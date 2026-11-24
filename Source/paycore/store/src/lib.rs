//! Journal store of the payment core (specification rev. 0.3, section 5, stage E1).
//!
//! One append-only file of encrypted, hash-chained frames is the only atomic
//! boundary. A frame counts as written only after `fsync` returned; for frames
//! that allow something to be signed or disclosed, the tail guard in OS-held
//! storage is advanced before the caller receives the receipt that unlocks
//! that action.
//!
//! This crate knows nothing about wallets, slates or the chain: frame bodies
//! are opaque. It contains no `unsafe`, does not panic on any input read from
//! disk, and holds no network code.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

mod crypto;
mod error;
mod format;
mod fs;
mod guard_file;
mod io;
mod store;

#[cfg(any(test, feature = "sim"))]
pub mod sim;

pub use crypto::RootKey;
pub use error::{CommitError, OpenError};
pub use format::{Identity, KIND_RECOVERY, MAX_BODY_LEN, MAX_USER_KIND};
pub use fs::{FsDir, FsFile, FsLock};
pub use guard_file::FileGuard;
pub use io::{Dir, Guard, GuardValue, Medium};
pub use store::{Frame, GuardCheck, Opened, Receipt, Sealed, Store};
