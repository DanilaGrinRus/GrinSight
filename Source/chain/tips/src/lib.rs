//! What named operators say the tip of the chain is.
//!
//! The chain process verifies every header itself, but what it is shown
//! comes from the nodes it happens to be connected to, and whoever stands
//! between the program and the network chooses those. This crate asks a
//! different kind of witness: public Grin nodes of operators known by
//! name, each reached over HTTPS under its own name, which somebody on the
//! way cannot answer for. Each is asked the one question every node
//! answers - what is your tip - and the answer comes with the time the
//! operator's server wrote on it.
//!
//! Nothing here decides anything. An answer is a statement by one
//! operator; how many statements, from whom and how fresh make the
//! program believe its own tip is decided by the caller.
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

pub mod ask;
pub mod asked;
pub mod claims;
pub mod date;
pub mod generation;
pub mod http;
pub mod memory;
pub mod point;
pub mod round;
pub mod said;
pub mod signs;
pub mod source;
pub mod survey;
pub mod time;
pub mod verdict;

pub use ask::{Answer, Asker, Failure};
pub use said::Said;
pub use source::Source;
