//! A node with a chain, for tests (feature "testkit"). Never part of a
//! product build.
//!
//! The chain is a real one of the Grin node's own code
//! (`grin_chain::Chain`) on the network of automated tests, mined here with
//! spending transactions; its segments are cut by the node's segmenter.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]
use crate::archive::{Collector, Refused, State, Wanted};
use crate::store::{AddError, Store};
use grin_chain::types::NoopAdapter;
use grin_chain::{Chain, Options};
use grin_core::consensus;
use grin_core::core::hash::Hashed;
use grin_core::core::{Block, BlockHeader, KernelFeatures, OutputIdentifier, Transaction};
use grin_core::global::{self, ChainTypes};
use grin_core::libtx::{self, build, ProofBuilder};
use grin_core::pow;
use grin_keychain::{ExtKeychain, ExtKeychainPath, Keychain};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const GRIN: u64 = 1_000_000_000;
const FEE: u32 = 20_000;
/// The seed of the keychain [`Source::grow_paying`] pays its rewards to.
pub const PAID_SEED: [u8; 32] = [0x51; 32];

/// A directory of its own, removed when dropped.
pub struct Temp(pub PathBuf);
impl Temp {
    /// A new empty directory.
    pub fn new(tag: &str) -> Temp {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("fly-state-{tag}-{}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(&p).unwrap();
        Temp(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn key(a: u32, b: u32) -> grin_keychain::Identifier {
    ExtKeychainPath::new(2, a, b, 0, 0).to_identifier()
}

/// A node with a chain: every block from height 5 on spends an old reward
/// into eight outputs, and later blocks spend some of those, singly and in
/// sibling pairs, so that the output MMR has every kind of pruning.
pub struct Source {
    /// The node's chain.
    pub chain: Chain,
    /// Every block, by height.
    pub blocks: Vec<Block>,
    _dir: Temp,
}
fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &to.join(entry.file_name()));
        } else {
            std::fs::copy(entry.path(), to.join(entry.file_name())).unwrap();
        }
    }
}

impl Source {
    /// A node with a chain of `length` blocks, mined here. Mining takes a
    /// minute or two; if `FLY_STATE_TEST_CHAINS` names a directory, the
    /// node's files are kept there and the next run starts a node on a copy
    /// of them instead - for running these tests many times over.
    pub fn mine(length: u64) -> Source {
        Source::mine_from(length, true)
    }

    /// The same; with `reward` false the chain grows from the plain
    /// genesis block of the test network, the one whose hash nodes of that
    /// network exchange when they meet.
    pub fn mine_from(length: u64, reward: bool) -> Source {
        Source::mined(length, reward, false, false)
    }

    /// A chain with few outputs, from the plain genesis block: every block
    /// from height 5 on spends the reward of four blocks ago, and what the
    /// block before it made of the one before that, into a single output.
    /// At any height five outputs are unspent.
    ///
    /// For tests that speak to the node over the network: on the test
    /// network the node's network code carries only small messages (the
    /// limit follows the block weight, which is tiny there) - fifteen
    /// kilobytes for a segment, which is some twenty range proofs.
    pub fn thin(length: u64) -> Source {
        Source::mined(length, false, true, false)
    }

    /// The thin chain, except that each of the blocks 6 to 10 also makes
    /// an output that is never spent: five outputs that stay, whatever
    /// the height.
    pub fn thin_with_old(length: u64) -> Source {
        Source::mined(length, false, true, true)
    }

    fn mined(length: u64, reward: bool, thin: bool, old: bool) -> Source {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let version = grin_core::ser::ProtocolVersion::local();
        let name = format!("chain-{length}{}{}{}", if reward { "" } else { "-plain" }, if thin { "-thin" } else { "" }, if old { "-old" } else { "" });
        let kept = std::env::var_os("FLY_STATE_TEST_CHAINS").map(|dir| PathBuf::from(dir).join(&name));
        let dir = Temp::new("node");
        let genesis = match kept.as_ref().filter(|kept| kept.join("done").exists()) {
            Some(kept) => {
                copy_dir(&kept.join("node"), &dir.0);
                let bytes = std::fs::read(kept.join("genesis")).unwrap();
                grin_core::ser::deserialize(&mut &bytes[..], version, grin_core::ser::DeserializationMode::default()).unwrap()
            }
            None => {
                let genesis = Self::mine_into(&dir.0, length, reward, thin, old);
                if let Some(kept) = &kept {
                    // Written aside and put in place in one step. Tests
                    // run side by side and may mine the same chain at the
                    // same time: whoever finds the chain there must find
                    // all of it, and nobody writes where another reads.
                    let mut r = [0u8; 8];
                    getrandom::getrandom(&mut r).unwrap();
                    let aside = kept.with_file_name(format!("{name}.part-{}", u64::from_le_bytes(r)));
                    copy_dir(&dir.0, &aside.join("node"));
                    std::fs::write(aside.join("genesis"), grin_core::ser::ser_vec(&genesis, version).unwrap()).unwrap();
                    std::fs::write(aside.join("done"), b"").unwrap();
                    if std::fs::rename(&aside, kept).is_err() {
                        // another test was first with the same chain
                        let _ = std::fs::remove_dir_all(&aside);
                    }
                }
                genesis
            }
        };
        // either way the node is started on files a node left behind
        let chain = Chain::init(dir.0.to_str().unwrap().to_string(), Arc::new(NoopAdapter {}), genesis.clone(), pow::verify_size, false, None).unwrap();
        assert_eq!(chain.head().unwrap().height, length);
        let mut blocks = vec![genesis];
        for height in 1..=length {
            blocks.push(chain.get_block(&chain.get_header_by_height(height).unwrap().hash()).unwrap());
        }
        Source { chain, blocks, _dir: dir }
    }

    /// Mine the chain in `dir`, stop the node, and give its genesis block.
    fn mine_into(dir: &Path, length: u64, with_reward: bool, thin: bool, old_kept: bool) -> Block {
        let kc = ExtKeychain::from_random_seed(false).unwrap();
        let pb = ProofBuilder::new(&kc);
        let reward = libtx::reward::output(&kc, &pb, &key(0, 0), 0, false).unwrap();
        let genesis = if with_reward {
            grin_core::genesis::genesis_dev().with_reward(reward.0, reward.1)
        } else {
            grin_core::genesis::genesis_dev()
        };
        let chain = Chain::init(dir.to_str().unwrap().to_string(), Arc::new(NoopAdapter {}), genesis.clone(), pow::verify_size, false, None).unwrap();
        // what each block's reward output is worth: the reward and the fees
        let mut rewards: Vec<u64> = vec![consensus::REWARD];
        // what the single output of the thin pattern is worth
        let mut carried: u64 = 0;
        for n in 1..=length {
            let prev = chain.head_header().unwrap();
            let h = u32::try_from(n).unwrap();
            let mut txs: Vec<Transaction> = Vec::new();
            if thin && n >= 5 {
                // the reward of four blocks ago and the output of the block
                // before this one, into one output
                let old = rewards[n as usize - 4];
                let mut parts = vec![build::coinbase_input(old, key(0, h - 4))];
                if n >= 6 {
                    parts.push(build::input(carried, key(h - 1, 0)));
                }
                carried = carried + old - u64::from(FEE);
                if old_kept && (6..=10).contains(&n) {
                    // one that stays
                    carried -= GRIN;
                    parts.push(build::output(GRIN, key(h, 1)));
                }
                parts.push(build::output(carried, key(h, 0)));
                txs.push(build::transaction(KernelFeatures::Plain { fee: FEE.into() }, &parts, &kc, &pb).unwrap());
            }
            if !thin && n >= 5 {
                // the reward of four blocks ago, into eight outputs
                let old = rewards[n as usize - 4];
                let mut parts = vec![build::coinbase_input(old, key(0, h - 4))];
                for j in 0..7 {
                    parts.push(build::output(GRIN, key(h, j)));
                }
                parts.push(build::output(old - 7 * GRIN - u64::from(FEE), key(h, 7)));
                txs.push(build::transaction(KernelFeatures::Plain { fee: FEE.into() }, &parts, &kc, &pb).unwrap());
            }
            if !thin && n >= 8 {
                // one of them, three blocks later
                let parts = vec![build::input(GRIN, key(h - 3, 0)), build::output(GRIN - u64::from(FEE), key(h, 8))];
                txs.push(build::transaction(KernelFeatures::Plain { fee: FEE.into() }, &parts, &kc, &pb).unwrap());
            }
            if !thin && n >= 9 {
                // two more of them together, four blocks later
                let parts = vec![
                    build::input(GRIN, key(h - 4, 1)),
                    build::input(GRIN, key(h - 4, 2)),
                    build::output(2 * GRIN - u64::from(FEE), key(h, 9)),
                ];
                txs.push(build::transaction(KernelFeatures::Plain { fee: FEE.into() }, &parts, &kc, &pb).unwrap());
            }
            let next = consensus::next_difficulty(prev.height + 1, chain.difficulty_iter().unwrap());
            let fees: u64 = txs.iter().map(|tx| tx.fee()).sum();
            rewards.push(consensus::REWARD + fees);
            let reward = libtx::reward::output(&kc, &pb, &key(0, h), fees, false).unwrap();
            let mut b = Block::new(&prev, &txs, next.difficulty, reward).unwrap();
            b.header.timestamp = prev.timestamp + chrono::Duration::seconds(60);
            b.header.pow.secondary_scaling = next.secondary_scaling;
            chain.set_txhashset_roots(&mut b).unwrap();
            b.header.pow.proof.edge_bits = global::min_edge_bits();
            pow::pow_size(&mut b.header, next.difficulty, global::proofsize(), global::min_edge_bits()).unwrap();
            chain.process_block(b, Options::MINE).unwrap();
        }
        genesis
    }
    /// The header the node gives its state out at.
    pub fn archive(&self) -> BlockHeader {
        // on whatever thread this is asked
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        self.chain.txhashset_archive_header().unwrap()
    }
    /// Answer whatever the collector wants, as a node would.
    pub fn serve(&self, collector: &mut Collector) -> Result<(), Refused> {
        let segmenter = self.chain.segmenter().unwrap();
        match collector.wanted() {
            Wanted::Bitmap(id) => {
                let (segment, output_root) = segmenter.bitmap_segment(id).unwrap();
                collector.add_bitmap(segment, output_root)
            }
            Wanted::Output(id) => collector.add_output(segmenter.output_segment(id).unwrap().0),
            Wanted::RangeproofTail(id) => collector.add_rangeproof_tail(segmenter.rangeproof_segment(id).unwrap()),
            Wanted::KernelTail(id) => collector.add_kernel_tail(segmenter.kernel_segment(id).unwrap()),
            Wanted::Nothing => Ok(()),
        }
    }
    /// The same for a collector that keeps a file.
    pub fn serve_store(&self, store: &mut Store) -> Result<(), AddError> {
        let segmenter = self.chain.segmenter().unwrap();
        match store.wanted() {
            Wanted::Bitmap(id) => {
                let (segment, output_root) = segmenter.bitmap_segment(id).unwrap();
                store.add_bitmap(segment, output_root)
            }
            Wanted::Output(id) => store.add_output(segmenter.output_segment(id).unwrap().0),
            Wanted::RangeproofTail(id) => store.add_rangeproof_tail(segmenter.rangeproof_segment(id).unwrap()),
            Wanted::KernelTail(id) => store.add_kernel_tail(segmenter.kernel_segment(id).unwrap()),
            Wanted::Nothing => Ok(()),
        }
    }
    /// Everything the collector asks for, to the end.
    pub fn collect(&self) -> State {
        let mut collector = Collector::new(self.archive());
        let (total, _) = collector.progress();
        for done in 0..total {
            assert_eq!(collector.progress(), (total, done));
            self.serve(&mut collector).unwrap();
        }
        assert_eq!(collector.wanted(), Wanted::Nothing);
        collector.finish().unwrap()
    }
    /// The unspent outputs after the block at `height`, from the blocks
    /// themselves: every output, less every input - and less the output of
    /// the genesis block, which the node's bitmap never names.
    pub fn unspent_at(&self, height: u64) -> BTreeMap<Vec<u8>, OutputIdentifier> {
        let mut set = BTreeMap::new();
        let genesis = self.blocks[0].outputs().first().map(|o| o.commitment().0.to_vec());
        for b in &self.blocks[..=height as usize] {
            for o in b.outputs() {
                set.insert(o.commitment().0.to_vec(), o.identifier());
            }
            let inputs: Vec<grin_core::core::CommitWrapper> = b.inputs().into();
            for i in inputs {
                assert!(set.remove(i.commitment().0.as_slice()).is_some());
            }
        }
        if let Some(genesis) = genesis {
            assert!(set.remove(&genesis).is_some());
        }
        set
    }

    /// The headers of the chain, by height.
    pub fn headers(&self) -> Vec<BlockHeader> {
        self.blocks.iter().map(|b| b.header.clone()).collect()
    }

    /// Let the node prune what it may: everything spent before its
    /// horizon. A node does this from time to time; after it, its segments
    /// carry hashes in place of what was pruned. The chain must end at a
    /// height that is a multiple of ten, where the node's horizon is its
    /// archive header.
    pub fn compact(&self) {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        assert_eq!(self.chain.head().unwrap().height % 10, 0);
        self.chain.compact().unwrap();
    }

    /// A block on top of the chain that no node would take: its reward
    /// output is worth more than a block may pay. Its header is in order -
    /// the roots set by the node's own code, the proof of work real - so
    /// only checking the contents themselves tells. Not added to the chain.
    pub fn forged_next(&self) -> Block {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let kc = ExtKeychain::from_random_seed(false).unwrap();
        let pb = ProofBuilder::new(&kc);
        let prev = self.chain.head_header().unwrap();
        let next = consensus::next_difficulty(prev.height + 1, self.chain.difficulty_iter().unwrap());
        let reward = libtx::reward::output(&kc, &pb, &key(1, u32::try_from(prev.height + 1).unwrap()), GRIN, false).unwrap();
        let mut b = Block::new(&prev, &[], next.difficulty, reward).unwrap();
        b.header.timestamp = prev.timestamp + chrono::Duration::seconds(60);
        b.header.pow.secondary_scaling = next.secondary_scaling;
        self.chain.set_txhashset_roots(&mut b).unwrap();
        b.header.pow.proof.edge_bits = global::min_edge_bits();
        pow::pow_size(&mut b.header, next.difficulty, global::proofsize(), global::min_edge_bits()).unwrap();
        b
    }

    /// Mine `count` blocks, each with its reward and nothing else, on top
    /// of the block at `from` - another branch. With more blocks than the
    /// chain has above `from`, the node moves to it.
    pub fn branch(&mut self, from: u64, count: u64) {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let kc = ExtKeychain::from_random_seed(false).unwrap();
        let pb = ProofBuilder::new(&kc);
        self.blocks.truncate(from as usize + 1);
        for _ in 0..count {
            let (older, prev) = (self.blocks[self.blocks.len() - 2].header.clone(), self.blocks[self.blocks.len() - 1].header.clone());
            // the rule of difficulty looks at the two headers before
            let last = prev.total_difficulty() - older.total_difficulty();
            let window = vec![
                consensus::HeaderDifficultyInfo::new(None, prev.timestamp.timestamp() as u64, last, 0, false),
                consensus::HeaderDifficultyInfo::new(None, older.timestamp.timestamp() as u64, grin_core::pow::Difficulty::zero(), 0, false),
            ];
            let next = consensus::next_difficulty(prev.height + 1, window);
            let reward = libtx::reward::output(&kc, &pb, &key(2, u32::try_from(prev.height + 1).unwrap()), 0, false).unwrap();
            let mut b = Block::new(&prev, &[], next.difficulty, reward).unwrap();
            b.header.timestamp = prev.timestamp + chrono::Duration::seconds(60);
            b.header.pow.secondary_scaling = next.secondary_scaling;
            self.chain.set_txhashset_roots(&mut b).unwrap();
            b.header.pow.proof.edge_bits = global::min_edge_bits();
            pow::pow_size(&mut b.header, next.difficulty, global::proofsize(), global::min_edge_bits()).unwrap();
            self.chain.process_block(b.clone(), Options::MINE).unwrap();
            self.blocks.push(b);
        }
        assert_eq!(self.chain.head().unwrap().last_block_h, self.blocks.last().unwrap().hash(), "the node moved to the branch");
    }

    /// Mine `count` more blocks, each with its reward and nothing else.
    pub fn grow(&mut self, count: u64) {
        let kc = ExtKeychain::from_random_seed(false).unwrap();
        self.grow_with(count, &kc, &[]);
    }

    /// Mine `count` more blocks whose rewards go to a keychain the tests
    /// have ([`PAID_SEED`]): outputs that [`Source::paid_tx`] can spend,
    /// each once it is mature.
    pub fn grow_paying(&mut self, count: u64) {
        let kc = ExtKeychain::from_seed(&PAID_SEED, false).unwrap();
        self.grow_with(count, &kc, &[]);
    }

    /// Mine one more block with these transactions in it.
    pub fn mine_with(&mut self, txs: &[Transaction]) {
        let kc = ExtKeychain::from_random_seed(false).unwrap();
        self.grow_with(1, &kc, txs);
    }

    /// A transaction of the keychain [`Source::grow_paying`] pays to. It
    /// spends the rewards of the blocks at the heights `spend` and makes
    /// the outputs `outputs` - value and the two numbers of a key - with
    /// the fee `fee`; locked to the height `lock`, if one is given. Whether
    /// the amounts add up is for the caller to see to: a transaction where
    /// they do not is refused by whoever checks it.
    pub fn paid_tx(spend: &[u64], outputs: &[(u64, u32, u32)], fee: u32, lock: Option<u64>) -> Transaction {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let kc = ExtKeychain::from_seed(&PAID_SEED, false).unwrap();
        let pb = ProofBuilder::new(&kc);
        let mut parts = Vec::new();
        for height in spend {
            parts.push(build::coinbase_input(consensus::REWARD, key(1, u32::try_from(*height).unwrap())));
        }
        for (value, a, b) in outputs {
            parts.push(build::output(*value, key(*a, *b)));
        }
        let features = match lock {
            Some(lock_height) => KernelFeatures::HeightLocked { fee: fee.into(), lock_height },
            None => KernelFeatures::Plain { fee: fee.into() },
        };
        build::transaction(features, &parts, &kc, &pb).unwrap()
    }

    /// The reward of the block at `height` mined by [`Source::grow_paying`],
    /// less `fee`, into one output.
    pub fn spend_paid(height: u64, fee: u32) -> Transaction {
        Self::paid_tx(&[height], &[(consensus::REWARD - u64::from(fee), 3, u32::try_from(height).unwrap())], fee, None)
    }

    fn grow_with(&mut self, count: u64, kc: &ExtKeychain, txs: &[Transaction]) {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let pb = ProofBuilder::new(kc);
        for n in 0..count {
            let txs = if n == 0 { txs } else { &[] };
            let fees: u64 = txs.iter().map(|tx| tx.fee()).sum();
            let prev = self.chain.head_header().unwrap();
            let next = consensus::next_difficulty(prev.height + 1, self.chain.difficulty_iter().unwrap());
            let reward = libtx::reward::output(kc, &pb, &key(1, u32::try_from(prev.height + 1).unwrap()), fees, false).unwrap();
            let mut b = Block::new(&prev, txs, next.difficulty, reward).unwrap();
            b.header.timestamp = prev.timestamp + chrono::Duration::seconds(60);
            b.header.pow.secondary_scaling = next.secondary_scaling;
            self.chain.set_txhashset_roots(&mut b).unwrap();
            b.header.pow.proof.edge_bits = global::min_edge_bits();
            pow::pow_size(&mut b.header, next.difficulty, global::proofsize(), global::min_edge_bits()).unwrap();
            self.chain.process_block(b.clone(), Options::MINE).unwrap();
            self.blocks.push(b);
        }
    }
}
