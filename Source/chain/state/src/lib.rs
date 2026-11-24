//! The state of the Grin chain at a node's archive point.
//!
//! To hand the wallet a block as *verified*, the block's contents must be
//! checked against its header, and the header commits to the state after
//! the block: the roots of the output, rangeproof and kernel MMRs and of the
//! bitmap of unspent outputs. Those roots can be recomputed for a block only
//! from the state before it. A node gives that state out in segments for one
//! header at a time, its archive header.
//!
//! This crate collects the state from segments and checks every segment
//! against the roots in the archive header with the node's own segment code.
//! It speaks to nobody: the segments and the header are handed to it.
//! What it has collected it keeps in a file, and trusts that file no more
//! than it trusts a peer.
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

pub mod advance;
pub mod archive;
pub mod blocks;
pub mod mmr;
pub mod store;
#[cfg(feature = "testkit")]
pub mod testkit;

/// The bitmap of unspent outputs, by leaf number.
pub use croaring::Bitmap;
