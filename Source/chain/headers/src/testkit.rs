//! Short chains on the automated-testing network, for tests (feature
//! "testkit"). Never part of a product build.
//!
//! The network of automated tests has tiny proofs of work and reaches the
//! rules of the fourth hard fork at height 12, so a chain that the real
//! rules accept can be mined in a test. The first headers of such a chain
//! (below [`FIRST_MINED`]) are filler: they are only ever hashed into the
//! header MMR, as the headers below a starting point are.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs,
    clippy::field_reassign_with_default
)]
use crate::peaks::Peaks;
use crate::{write_header, Net};
use grin_core::consensus::{self, HeaderDifficultyInfo};
use grin_core::core::hash::Hashed;
use grin_core::core::pmmr::{self, ReadablePMMR, VecBackend, PMMR};
use grin_core::core::BlockHeader;
use grin_core::global;
use grin_core::pow::{self, Difficulty};

/// Height from which headers are mined by the rules.
pub const FIRST_MINED: u64 = 10;
/// Lowest height a starting point can have in such a chain.
pub const FIRST_START: u64 = 14;

/// A chain from genesis, every header kept.
#[derive(Clone)]
pub struct TestChain {
    pub headers: Vec<BlockHeader>,
    /// Work of each header mined before the difficulty rule takes over.
    base: Difficulty,
}

fn peaks_of(headers: &[BlockHeader]) -> Peaks {
    let mut peaks = Peaks::empty();
    for h in headers {
        peaks.append(h).unwrap();
    }
    peaks
}

impl TestChain {
    /// Genesis and filler up to the first mined height, at the lowest
    /// difficulty: any proof found is enough, so mining is quick - and the
    /// difficulty never moves, because it cannot go lower and is too small
    /// for the rule's rounding to raise it.
    pub fn new() -> TestChain {
        Net::Automated.enter();
        TestChain::with_work(Difficulty::min_wtema().to_num())
    }

    /// The same with a higher starting difficulty. From about 280 up the
    /// difficulty follows the pace of the blocks; mining takes that many
    /// times longer.
    pub fn with_work(work: u64) -> TestChain {
        Net::Automated.enter();
        let base = Difficulty::from_num(work);
        let mut headers = vec![grin_core::genesis::genesis_dev().header];
        for height in 1..FIRST_MINED {
            let prev = headers.last().unwrap();
            let mut h = BlockHeader::default();
            h.height = height;
            h.version = consensus::header_version(height);
            h.prev_hash = prev.hash();
            h.timestamp = prev.timestamp + chrono::Duration::seconds(60);
            h.pow.total_difficulty = prev.pow.total_difficulty + base;
            h.pow.nonce = height;
            // a hash of its own: the hash of a header is the hash of its proof
            h.pow.proof.nonces = (0..global::proofsize() as u64).map(|k| height * 1000 + k).collect();
            headers.push(h);
        }
        TestChain { headers, base }
    }

    /// A chain mined elsewhere - by a node's own code, say - from its
    /// genesis header on, to cut starting points from.
    pub fn from_headers(headers: Vec<BlockHeader>) -> TestChain {
        Net::Automated.enter();
        TestChain {
            headers,
            base: Difficulty::min_wtema(),
        }
    }

    pub fn tip(&self) -> &BlockHeader {
        self.headers.last().unwrap()
    }

    /// The header that would follow `self.headers[..=parent]`, mined.
    /// `seconds` is its distance in time from the parent; `salt` makes
    /// different headers for the same parent.
    pub fn next_after(&self, parent: usize, seconds: i64, salt: u64) -> BlockHeader {
        Net::Automated.enter();
        let (older, prev) = (&self.headers[parent - 1], &self.headers[parent]);
        let mut h = BlockHeader::default();
        h.height = prev.height + 1;
        h.version = consensus::header_version(h.height);
        h.prev_hash = prev.hash();
        h.prev_root = peaks_of(&self.headers[..=parent]).root();
        h.timestamp = prev.timestamp + chrono::Duration::seconds(seconds);
        h.output_mmr_size = pmmr::insertion_to_pmmr_index(prev.output_mmr_count() + 1);
        h.kernel_mmr_size = pmmr::insertion_to_pmmr_index(prev.kernel_mmr_count() + 1);
        let work = if h.height >= 12 {
            let last = prev.total_difficulty() - older.total_difficulty();
            let window = vec![
                HeaderDifficultyInfo::new(None, prev.timestamp.timestamp() as u64, last, 0, false),
                HeaderDifficultyInfo::new(None, older.timestamp.timestamp() as u64, Difficulty::zero(), 0, false),
            ];
            consensus::next_difficulty(h.height, window).difficulty
        } else {
            self.base
        };
        h.pow.total_difficulty = prev.total_difficulty() + work;
        h.pow.nonce = salt.wrapping_mul(1_000_003);
        pow::pow_size(&mut h, work, global::proofsize(), global::min_edge_bits()).unwrap();
        h
    }

    /// Find a new proof of work for a header that was changed after mining.
    pub fn remine(header: &mut BlockHeader, work: Difficulty) {
        Net::Automated.enter();
        pow::pow_size(header, work, global::proofsize(), global::min_edge_bits()).unwrap();
    }

    /// Mine `count` more headers, each `seconds` after the one before.
    pub fn mine(&mut self, count: usize, seconds: i64) -> &mut TestChain {
        for _ in 0..count {
            let next = self.next_after(self.headers.len() - 1, seconds, 0);
            self.headers.push(next);
        }
        self
    }

    /// The same chain up to `height`, to grow another branch from there.
    pub fn fork_at(&self, height: u64) -> TestChain {
        TestChain {
            headers: self.headers[..=height as usize].to_vec(),
            base: self.base,
        }
    }

    /// Mine `count` headers of a branch that differs from any other.
    pub fn mine_salted(&mut self, count: usize, seconds: i64, salt: u64) -> &mut TestChain {
        for i in 0..count {
            let next = self.next_after(self.headers.len() - 1, seconds, salt + i as u64);
            self.headers.push(next);
        }
        self
    }

    /// The headers above `height`.
    pub fn after(&self, height: u64) -> &[BlockHeader] {
        &self.headers[height as usize + 1..]
    }

    /// The record of a starting point at `height`, built with the full MMR
    /// of the Grin code - independently of the peaks code under test.
    pub fn record(&self, height: u64) -> Vec<u8> {
        serde_json::to_vec(&self.record_value(height)).unwrap()
    }

    /// The same record as a value a test can damage.
    pub fn record_value(&self, height: u64) -> serde_json::Value {
        Net::Automated.enter();
        assert!(height >= FIRST_START);
        let s = height as usize;
        let proof_of = |leaf: usize| -> Vec<Vec<u8>> {
            // the range that header `leaf + 1` commits to: leaves 0..=leaf
            let mut backend = VecBackend::<BlockHeader>::new();
            let mut mmr = PMMR::new(&mut backend);
            for h in &self.headers[..=leaf] {
                mmr.push(h).unwrap();
            }
            let pos = pmmr::insertion_to_pmmr_index(leaf as u64);
            let proof = mmr.merkle_proof(pos).unwrap();
            assert_eq!(mmr.root().unwrap(), self.headers[leaf + 1].prev_root);
            proof.verify(mmr.root().unwrap(), &self.headers[leaf], pos).unwrap();
            proof.path.iter().map(|h| h.to_vec()).collect()
        };
        let peaks = peaks_of(&self.headers[..=s]);
        let raw = |h: &BlockHeader| write_header(h).unwrap();
        serde_json::json!({
            "version": 1,
            "network": Net::Automated.tag(),
            "genesis": Net::Automated.genesis_hash().to_vec(),
            "height": height,
            "header_hash": self.headers[s].hash().to_vec(),
            "total_work": self.headers[s].total_difficulty().to_num(),
            "context": [raw(&self.headers[s]), raw(&self.headers[s - 1]), raw(&self.headers[s - 2])],
            "mmr_size": peaks.size(),
            "peaks": peaks.hashes().iter().map(|h| h.to_vec()).collect::<Vec<_>>(),
            "previous_path": proof_of(s - 1),
            "release_time": 1_700_000_000u64,
            "older_context_path": proof_of(s - 2),
        })
    }
}

impl Default for TestChain {
    fn default() -> Self {
        TestChain::new()
    }
}
