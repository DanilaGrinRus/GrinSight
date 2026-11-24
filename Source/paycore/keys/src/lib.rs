//! Key paths of the payment core (specification rev. 0.3, section 4, stage E2).
//!
//! * [`path`] - the three disjoint classes of output key paths and their
//!   mapping to Grin identifiers.
//! * [`ledger`] - the instance branch and its counter, kept in the journal so
//!   that a path is handed out at most once (invariant K7), with a new branch
//!   after a detected rollback or move (K15).
//! * [`scan`] - rewinding a range proof with the wallet seed and classifying
//!   the output it belongs to.
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

pub mod ledger;
pub mod path;
pub mod scan;
