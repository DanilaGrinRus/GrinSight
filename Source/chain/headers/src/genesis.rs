//! Sequential header validation from the exact genesis of one network.
//! The local clock only supplies an upper admission bound; passing this
//! verifier does not establish freshness or validate historical block bodies.
use std::collections::VecDeque;

use crate::checkpoint::{self, Parts};
use crate::peaks::Peaks;
use crate::{rules, Net};
use grin_core::consensus::{self, HeaderDifficultyInfo, BLOCK_TIME_SEC, DMA_WINDOW};
use grin_core::core::block::HeaderVersion;
use grin_core::core::hash::Hashed;
use grin_core::core::BlockHeader;
use grin_core::pow::Difficulty;

/// A malformed input or a locally unavailable clock/number range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisError {
    /// The supplied genesis differs from the full network genesis header.
    WrongGenesis,
    /// A consensus or structural check failed.
    Header(rules::Reject),
    /// The timestamp is too far ahead of the clock supplied by the caller.
    Future,
}

impl From<rules::Reject> for GenesisError {
    fn from(error: rules::Reject) -> Self {
        Self::Header(error)
    }
}

fn genesis(net: Net) -> BlockHeader {
    net.enter();
    match net {
        Net::Main => grin_core::genesis::genesis_main(),
        Net::Test => grin_core::genesis::genesis_test(),
        Net::Automated => grin_core::genesis::genesis_dev(),
    }
    .header
}

#[derive(Clone, Debug)]
struct Entry {
    header: BlockHeader,
    before: Peaks,
}

/// Owns a verified prefix. Holds the DAA window, three headers and their
/// peak frontiers; RAM usage is independent of the length of the input
/// apart from logarithmic header-PMMR frontiers.
#[derive(Clone, Debug)]
pub struct GenesisVerifier {
    net: Net,
    tip: Entry,
    previous: VecDeque<Entry>,
    peaks: Peaks,
    difficulty: VecDeque<HeaderDifficultyInfo>,
}

impl GenesisVerifier {
    /// Start at the canonical header compiled into the Grin consensus crate.
    pub fn new(net: Net) -> Result<Self, GenesisError> {
        let header = genesis(net);
        let mut peaks = Peaks::empty();
        peaks.append(&header).map_err(|_| rules::Reject::Root)?;
        let work = header.total_difficulty();
        let info = difficulty_info(&header, work)?;
        Ok(Self {
            net,
            tip: Entry {
                header,
                before: Peaks::empty(),
            },
            previous: VecDeque::new(),
            peaks,
            difficulty: VecDeque::from([info]),
        })
    }

    /// Compare every serialized field. Grin's header hash alone is the
    /// hash of the PoW solution and is insufficient for pinning genesis.
    pub fn check_genesis(&self, header: &BlockHeader) -> Result<(), GenesisError> {
        let exact = genesis(self.net);
        if header != &exact {
            return Err(GenesisError::WrongGenesis);
        }
        Ok(())
    }

    /// Last verified header, with cumulative work.
    pub fn tip(&self) -> &BlockHeader {
        &self.tip.header
    }

    /// Header PMMR up to and including the tip.
    pub fn peaks(&self) -> &Peaks {
        &self.peaks
    }

    /// Validate the next header and atomically advance in-memory state.
    /// A failed check leaves all frontiers and difficulty inputs untouched.
    pub fn push(&mut self, header: &BlockHeader, now: u64) -> Result<(), GenesisError> {
        self.net.enter();
        let prev = self.tip();
        if prev.height.checked_add(1) != Some(header.height) {
            return Err(rules::Reject::Height.into());
        }
        if header.prev_hash != prev.hash() {
            return Err(rules::Reject::Link.into());
        }
        if header.prev_root != self.peaks.root() {
            return Err(rules::Reject::Root.into());
        }
        if rules::ahead_of(header, now) {
            return Err(GenesisError::Future);
        }
        let work = if consensus::header_version(header.height) < HeaderVersion(5) {
            rules::check_any_era(header)?;
            let work = rules::linked_work(prev, header)?;
            // Reproduce DifficultyIter, newest first including the genesis
            // difficulty. The Grin function performs the early-history padding.
            // Check the arithmetic on the exact padded window before dispatch.
            if prev.total_difficulty().to_num() > u64::MAX / (DMA_WINDOW * BLOCK_TIME_SEC) {
                let padded =
                    grin_core::global::difficulty_data_to_vector(self.difficulty.iter().cloned());
                padded
                    .iter()
                    .skip(1)
                    .try_fold(0u64, |total, row| {
                        total.checked_add(row.difficulty.to_num())
                    })
                    .and_then(|sum| sum.checked_mul(BLOCK_TIME_SEC))
                    .ok_or(rules::Reject::Arithmetic)?;
            }
            let next = consensus::next_difficulty(header.height, self.difficulty.iter().cloned());
            if next.difficulty.to_num() != work
                || header.pow.secondary_scaling != next.secondary_scaling
            {
                return Err(rules::Reject::Difficulty.into());
            }
            work
        } else {
            // Select WTEMA by *child* height, including the first two v5 headers.
            let older = &self.previous.back().ok_or(rules::Reject::Height)?.header;
            rules::check_step(older, prev, header)?;
            header
                .total_difficulty()
                .to_num()
                .checked_sub(prev.total_difficulty().to_num())
                .ok_or(rules::Reject::Work)?
        };
        let info = difficulty_info(header, Difficulty::from_num(work))?;
        let mut next = self.peaks.clone();
        next.append(header).map_err(|_| rules::Reject::Root)?;
        let before = std::mem::replace(&mut self.peaks, next);
        let last = std::mem::replace(
            &mut self.tip,
            Entry {
                header: header.clone(),
                before,
            },
        );
        self.previous.push_back(last);
        if self.previous.len() > 2 {
            self.previous.pop_front();
        }
        self.difficulty.push_front(info);
        self.difficulty.truncate(
            usize::try_from(DMA_WINDOW)
                .unwrap_or(usize::MAX)
                .saturating_add(1),
        );
        Ok(())
    }

    /// Emit the regular resumable post-HF4 point at this tip. The bytes
    /// carry the checked context, not a stand-alone proof of prior history.
    pub fn record(&self, release_time: u64) -> Option<Vec<u8>> {
        let older = self.previous.front()?;
        let prev = self.previous.back()?;
        checkpoint::write(&Parts {
            net: self.net,
            anchor: self.tip(),
            prev: &prev.header,
            older: &older.header,
            before_prev: &prev.before,
            before_older: &older.before,
            release_time,
            base: None,
        })
    }
}

fn difficulty_info(
    header: &BlockHeader,
    work: Difficulty,
) -> Result<HeaderDifficultyInfo, GenesisError> {
    let seconds = u64::try_from(header.timestamp.timestamp()).map_err(|_| rules::Reject::Time)?;
    Ok(HeaderDifficultyInfo::new(
        None,
        seconds,
        work,
        header.pow.secondary_scaling,
        header.pow.is_secondary(),
    ))
}
