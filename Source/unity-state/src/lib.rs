//! Unity core, no networking (stage 1 of PLAN_VERIFIED_LIGHT_MODE_RU.md).
//!
//! * [`headers`]: header chain verification (PoW, difficulty, linkage, header
//!   MMR), checkpoints and their history, chain choice among peers;
//! * [`mmr`]: header MMR peaks and checkpoint files;
//! * [`release`]: signed release checkpoints;
//! * [`outputs`]: UTXO state from PIBD segments, block application, kernel
//!   MMR peaks, bundles, body proofs;
//! * [`wallet`]: keys from seed phrases, own-output discovery (rangeproof
//!   rewind), self-spends;
//! * [`receive`]: slatepacks: receive, send, finalize, invoices, payment proofs.
//!
//! The P2P side (fetching headers, blocks, segments) stays in `header-sync`
//! and only feeds data into these types.

pub mod headers;
pub mod mmr;
pub mod outputs;
pub mod receive;
pub mod wallet;
pub mod release;
pub mod session;
pub mod balance;

/// Synthetic chains (tests and the C ABI fixture). Not for releases.
#[cfg(feature = "testkit")]
pub mod testkit;

/// Robustness fuzzing of every parser of foreign / on-disk data (tests only).
#[cfg(all(test, feature = "testkit"))]
mod fuzz;
