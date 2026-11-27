//! The rules one more header must satisfy.
//!
//! The checks are those of the node (`grin_chain::pipe::validate_header` and
//! the reader of untrusted headers in `grin_core`), in the same order, made
//! with the same functions of `grin_core`: header version, proof of work,
//! difficulty. This module adds no rule of its own and leaves none out,
//! with three exceptions that are stated where they occur:
//!
//! * only headers after the fourth hard fork are supported - the starting
//!   point is always later, and the older difficulty rule needs an hour of
//!   earlier headers;
//! * the commitment to earlier headers (`prev_root`) is checked by the
//!   caller, who holds the peaks;
//! * "not too far in the future" is a separate question ([`ahead_of`]),
//!   because it depends on a clock and is no property of the header.
//!
//! The network must have been entered ([`crate::Net::enter`]).
use grin_core::consensus::{self, HeaderDifficultyInfo, BLOCK_TIME_SEC, WTEMA_HALF_LIFE};
use grin_core::core::block::HeaderVersion;
use grin_core::core::hash::Hashed;
use grin_core::core::{BlockHeader, Transaction};
use grin_core::global;
use grin_core::pow::{self, Difficulty};

/// Why a header is not the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reject {
    /// Not one above the header before it.
    Height,
    /// Does not name the header before it.
    Link,
    /// From before the fourth hard fork: not supported here.
    Unsupported,
    /// A header version this code does not know for that height. A chain
    /// that changed its rules is not followed.
    Version,
    /// Not later than the header before it.
    Time,
    /// The output and kernel counts do not grow by at least one each.
    Sizes,
    /// Heavier than any block may be.
    Weight,
    /// A proof-of-work graph that is not allowed.
    EdgeBits,
    /// The proof of work is not valid.
    Pow,
    /// The proof of work does not pay for the claimed increase of work.
    Work,
    /// The increase of total work is not the difficulty the rules give.
    Difficulty,
    /// Numbers on which the difficulty formula would overflow.
    Arithmetic,
    /// Does not commit to the headers before it.
    Root,
}

fn seconds(header: &BlockHeader) -> Result<u64, Reject> {
    u64::try_from(header.timestamp.timestamp()).map_err(|_| Reject::Time)
}

/// What can be said about a header without any other header: its version
/// for its height, its proof of work, an upper bound on its counts.
pub fn check_alone(header: &BlockHeader) -> Result<(), Reject> {
    if consensus::header_version(header.height) < HeaderVersion(5) {
        return Err(Reject::Unsupported);
    }
    check_any_era(header)
}

/// The time-independent checks of an untrusted header; used after genesis
/// when its predecessors are available for the DAA of its own epoch.
pub(crate) fn check_any_era(header: &BlockHeader) -> Result<(), Reject> {
    if !consensus::valid_header_version(header.height, header.version) {
        return Err(Reject::Version);
    }
    if !(1..=63).contains(&header.pow.edge_bits())
        || (!header.pow.is_primary() && !header.pow.is_secondary())
    {
        return Err(Reject::EdgeBits);
    }
    if header.pow.proof.nonces.len() != global::proofsize() {
        return Err(Reject::Pow);
    }
    pow::verify_size(header).map_err(|_| Reject::Pow)?;
    // the counts of the whole chain cannot exceed full blocks at every height
    let weight = Transaction::weight_by_iok(0, header.output_mmr_count(), header.kernel_mmr_count());
    let limit = header
        .height
        .checked_add(1)
        .and_then(|blocks| blocks.checked_mul(global::max_block_weight()))
        .ok_or(Reject::Weight)?;
    if weight > limit {
        return Err(Reject::Weight);
    }
    Ok(())
}

/// Whether `header` follows `prev`, which followed `older`. Both earlier
/// headers must already be verified; the difficulty rule reads their times
/// and the work between them.
///
/// Not checked here: `prev_root` (the caller holds the peaks) and the clock.
pub fn check_step(older: &BlockHeader, prev: &BlockHeader, header: &BlockHeader) -> Result<(), Reject> {
    if prev.height.checked_add(1) != Some(header.height) || older.height.checked_add(1) != Some(prev.height) {
        return Err(Reject::Height);
    }
    if header.prev_hash != prev.hash() || prev.prev_hash != older.hash() {
        return Err(Reject::Link);
    }
    check_alone(header)?;
    let target = linked_work(prev, header)?;
    check_wtema(older, prev, header, target)
}

pub(crate) fn linked_work(prev: &BlockHeader, header: &BlockHeader) -> Result<u64, Reject> {
    // strict progress of time: no time warp
    if header.timestamp <= prev.timestamp {
        return Err(Reject::Time);
    }
    // every block has at least the reward's output and kernel
    let outputs = header.output_mmr_count().saturating_sub(prev.output_mmr_count());
    let kernels = header.kernel_mmr_count().saturating_sub(prev.kernel_mmr_count());
    if outputs == 0 || kernels == 0 {
        return Err(Reject::Sizes);
    }
    if Transaction::weight_by_iok(0, outputs, kernels) > global::max_block_weight() {
        return Err(Reject::Weight);
    }
    // the work this header adds
    let target = header
        .total_difficulty()
        .to_num()
        .checked_sub(prev.total_difficulty().to_num())
        .filter(|added| *added > 0)
        .ok_or(Reject::Work)?;
    if header.pow.to_difficulty(header.height).to_num() < target {
        return Err(Reject::Work);
    }
    Ok(target)
}

fn check_wtema(older: &BlockHeader, prev: &BlockHeader, header: &BlockHeader, target: u64) -> Result<(), Reject> {
    // ... must be exactly what the difficulty rule gives. The rule is the
    // node's function; its inputs are checked first so that it cannot
    // overflow on a chain no node would have accepted.
    let last_time = seconds(prev)?;
    let before_time = seconds(older)?;
    let block_time = last_time.checked_sub(before_time).filter(|t| *t > 0).ok_or(Reject::Time)?;
    let last_work = prev
        .total_difficulty()
        .to_num()
        .checked_sub(older.total_difficulty().to_num())
        .filter(|added| *added > 0)
        .ok_or(Reject::Work)?;
    last_work.checked_mul(WTEMA_HALF_LIFE).ok_or(Reject::Arithmetic)?;
    WTEMA_HALF_LIFE
        .checked_sub(BLOCK_TIME_SEC)
        .and_then(|d| d.checked_add(block_time))
        .filter(|d| *d > 0)
        .ok_or(Reject::Arithmetic)?;
    let window = vec![
        HeaderDifficultyInfo::new(
            None,
            last_time,
            Difficulty::from_num(last_work),
            prev.pow.secondary_scaling,
            prev.pow.is_secondary(),
        ),
        // of the header before, the rule reads the time only
        HeaderDifficultyInfo::new(
            None,
            before_time,
            Difficulty::zero(),
            older.pow.secondary_scaling,
            older.pow.is_secondary(),
        ),
    ];
    let next = consensus::next_difficulty(header.height, window);
    if target != next.difficulty.to_num() {
        return Err(Reject::Difficulty);
    }
    Ok(())
}

/// Whether a header claims a time later than `now` (Unix seconds) by more
/// than the node's own allowance. Such a header is not invalid - the clock
/// here may be the one that is wrong - but it is not applied until its time
/// has come.
pub fn ahead_of(header: &BlockHeader, now: u64) -> bool {
    let limit = now.saturating_add(global::get_future_time_limit());
    match u64::try_from(header.timestamp.timestamp()) {
        Ok(time) => time > limit,
        Err(_) => false,
    }
}
