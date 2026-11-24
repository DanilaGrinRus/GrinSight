//! What the tests of the program share: nodes to talk to - the Grin node's
//! own network code with headers, and if wanted a real chain, behind it -
//! and the program run as a process.
#![allow(dead_code)]
use chrono::{DateTime, Utc};
use fly_chain_headers::Net;
use fly_chain_state::testkit::Source;
use grin_chain as chain;
use grin_chain::txhashset::BitmapChunk;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{self, BlockHeader, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use grin_core::global::{self, ChainTypes};
use grin_core::pow::Difficulty;
use grin_p2p::handshake::Handshake;
use grin_p2p::types::NetAdapter;
use grin_p2p::types::{HeaderSegmentAcceptance, TxHashSetRead};
use grin_p2p::{Capabilities, ChainAdapter, P2PConfig, Peer, PeerAddr, PeerInfo};
use grin_util::secp::pedersen::RangeProof;
use std::fs::File;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

pub const FLY: &str = env!("CARGO_BIN_EXE_fly-chain");

pub struct Temp(pub PathBuf);
impl Temp {
    pub fn new(tag: &str) -> Temp {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("fly-chain-{tag}-{}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(&p).unwrap();
        Temp(p)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// What the node's network code is given in these tests: a list of
/// headers and, for a node that gives its state out, the chain behind them.
pub struct Served {
    pub headers: Mutex<Vec<BlockHeader>>,
    pub requests: AtomicUsize,
    /// Work claimed in the handshake and in pongs, if not the chain's own.
    pub boast: Option<u64>,
    /// The node's chain, if it gives its state out in segments.
    pub source: Option<Arc<RwLock<Source>>>,
    /// Requests for segments received.
    pub asked: AtomicUsize,
    /// Requests for segments answered.
    pub answered: AtomicUsize,
    /// How many requests for segments are answered at all; the rest get
    /// silence, as a node gives when it cannot answer.
    pub limit: AtomicUsize,
    /// Send segments of the output MMR with every output changed.
    pub bend: AtomicBool,
    /// The largest segments of the output MMR this node gives; a request
    /// for a larger one gets silence.
    pub max_output_height: AtomicU8,
    /// The heights of the segments of the output MMR it was asked for.
    pub output_heights: Mutex<Vec<u8>>,
    /// Requests for blocks received.
    pub blocks_asked: AtomicUsize,
    /// Send blocks with a range proof changed.
    pub bend_blocks: AtomicBool,
    /// Answer no request for a block.
    pub mute_blocks: AtomicBool,
    /// Requests for segments of the rangeproof MMR received.
    pub proofs_asked: AtomicUsize,
    /// Send segments of the rangeproof MMR with a proof changed.
    pub bend_proofs: AtomicBool,
    /// Header proofs: 1 - a field of the first header changed (its place
    /// in the header MMR is not affected by that), 2 - a hash of the first
    /// path changed.
    pub bend_header_proofs: AtomicUsize,
    /// Requests for header proofs received.
    pub header_proofs_asked: AtomicUsize,
    /// Stem transactions received: somebody's, on their way.
    pub stems: Mutex<Vec<core::Transaction>>,
    /// The transactions the node holds, as a node holds what it was sent
    /// and found valid.
    pub pool: Mutex<Vec<core::Transaction>>,
    /// Kernels of transactions it was told of and has yet to ask for.
    pub told: Mutex<Vec<Hash>>,
    /// Requests for a transaction received.
    pub txs_asked: AtomicUsize,
}
impl Served {
    /// The node's segmenter for the state at `hash`, as a node's adapter
    /// finds it: an error - which the network code turns into silence - if
    /// the node's archive header is another one.
    fn segmenter(&self, hash: Hash) -> Result<chain::txhashset::Segmenter, chain::Error> {
        self.asked.fetch_add(1, Ordering::Relaxed);
        let none = || chain::Error::Other("none".into());
        let source = self.source.as_ref().ok_or_else(none)?.read().unwrap();
        let segmenter = source.chain.segmenter()?;
        if segmenter.header().hash() != hash || self.answered.load(Ordering::Relaxed) >= self.limit.load(Ordering::Relaxed) {
            return Err(none());
        }
        self.answered.fetch_add(1, Ordering::Relaxed);
        Ok(segmenter)
    }
}
impl ChainAdapter for Served {
    fn total_difficulty(&self) -> Result<Difficulty, chain::Error> {
        let own = self.headers.lock().unwrap().last().unwrap().total_difficulty();
        Ok(self.boast.map_or(own, Difficulty::from_num))
    }
    fn total_height(&self) -> Result<u64, chain::Error> {
        Ok(self.headers.lock().unwrap().last().unwrap().height)
    }
    fn locate_headers(&self, locator: &[Hash]) -> Result<Vec<BlockHeader>, chain::Error> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let headers = self.headers.lock().unwrap();
        // as a node does: the first hash it has on its chain, and what follows
        let known = locator.iter().find_map(|hash| headers.iter().position(|h| h.hash() == *hash));
        Ok(match known {
            Some(at) => headers[at + 1..].iter().take(512).cloned().collect(),
            None => Vec::new(),
        })
    }
    fn transaction_received(&self, tx: core::Transaction, stem: bool) -> Result<bool, chain::Error> {
        if stem {
            self.stems.lock().unwrap().push(tx);
        } else {
            self.pool.lock().unwrap().push(tx);
        }
        Ok(true)
    }
    fn get_transaction(&self, kernel: Hash) -> Option<core::Transaction> {
        // as a node does: from its pool, never a stem transaction
        self.txs_asked.fetch_add(1, Ordering::Relaxed);
        self.pool.lock().unwrap().iter().find(|tx| tx.kernels().iter().any(|k| k.hash() == kernel)).cloned()
    }
    fn tx_kernel_received(&self, kernel: Hash, _: &PeerInfo) -> Result<bool, chain::Error> {
        // a node asks whoever told it for the transaction; see `Node::start_with`
        self.told.lock().unwrap().push(kernel);
        Ok(true)
    }
    fn block_received(&self, _: core::Block, _: &PeerInfo, _: chain::Options) -> Result<bool, chain::Error> {
        Ok(true)
    }
    fn compact_block_received(&self, _: core::CompactBlock, _: &PeerInfo) -> Result<bool, chain::Error> {
        Ok(true)
    }
    fn header_received(&self, _: BlockHeader, _: &PeerInfo) -> Result<bool, chain::Error> {
        Ok(true)
    }
    fn headers_received(&self, _: &[BlockHeader], _: &PeerInfo) -> Result<bool, chain::Error> {
        Ok(true)
    }
    fn locate_header_segment(&self, _: SegmentIdentifier, _: &PeerInfo) -> Result<Option<Vec<BlockHeader>>, chain::Error> {
        Ok(None)
    }
    fn get_block(&self, hash: Hash, _: &PeerInfo) -> Option<core::Block> {
        self.blocks_asked.fetch_add(1, Ordering::Relaxed);
        if self.mute_blocks.load(Ordering::Relaxed) {
            return None;
        }
        let source = self.source.as_ref()?.read().unwrap();
        let mut block = source.chain.get_block(&hash).ok()?;
        if self.bend_blocks.load(Ordering::Relaxed) {
            // not the block the header is about: one range proof changed
            block.body.outputs[0].proof.proof[30] ^= 1;
        }
        Some(block)
    }
    fn get_header_proofs(&self, anchor: Hash, heights: &[u64], _: &PeerInfo) -> Result<Option<grin_p2p::msg::HeaderProofs>, chain::Error> {
        // as a node with the HEADER_PROOF_HIST extension does: the header
        // MMR up to the anchor, and a path in it for every header asked for
        self.header_proofs_asked.fetch_add(1, Ordering::Relaxed);
        if self.source.is_none() {
            return Ok(None);
        }
        let headers = self.headers.lock().unwrap();
        let Some(anchor) = headers.iter().find(|h| h.hash() == anchor) else {
            return Ok(None);
        };
        let mut backend = core::pmmr::VecBackend::<BlockHeader>::new();
        {
            let mut mmr = core::pmmr::PMMR::new(&mut backend);
            for header in headers.iter().take(anchor.height as usize) {
                mmr.push(header).unwrap();
            }
        }
        let wanted: Vec<BlockHeader> = heights.iter().filter_map(|height| headers.get(*height as usize).cloned()).collect();
        if wanted.len() != heights.len() {
            return Ok(None);
        }
        let Ok(mut proofs) = grin_p2p::header_proof::build_header_proofs(&backend, anchor, &wanted) else {
            return Ok(None);
        };
        match self.bend_header_proofs.load(Ordering::Relaxed) {
            1 => proofs.items[0].header.output_mmr_size += 1,
            2 => proofs.items[0].path[0] = Hash::from_vec(&[7; 32]),
            _ => {}
        }
        Ok(Some(proofs))
    }
    fn txhashset_read(&self, _: Hash) -> Option<TxHashSetRead> {
        None
    }
    fn txhashset_archive_header(&self) -> Result<BlockHeader, chain::Error> {
        Err(chain::Error::Other("none".into()))
    }
    fn txhashset_receive_ready(&self) -> bool {
        false
    }
    fn txhashset_download_update(&self, _: DateTime<Utc>, _: u64, _: u64) -> bool {
        false
    }
    fn txhashset_write(&self, _: Hash, _: File, _: &PeerInfo) -> Result<bool, chain::Error> {
        Ok(false)
    }
    fn get_tmp_dir(&self) -> PathBuf {
        std::env::temp_dir()
    }
    fn get_tmpfile_pathname(&self, name: String) -> PathBuf {
        std::env::temp_dir().join(name)
    }
    fn get_kernel_segment(&self, hash: Hash, id: SegmentIdentifier) -> Result<Segment<TxKernel>, chain::Error> {
        self.segmenter(hash)?.kernel_segment(id)
    }
    fn get_bitmap_segment(&self, hash: Hash, id: SegmentIdentifier) -> Result<(Segment<BitmapChunk>, Hash), chain::Error> {
        self.segmenter(hash)?.bitmap_segment(id)
    }
    fn get_output_segment(&self, hash: Hash, id: SegmentIdentifier) -> Result<(Segment<OutputIdentifier>, Hash), chain::Error> {
        self.output_heights.lock().unwrap().push(id.height);
        if id.height > self.max_output_height.load(Ordering::Relaxed) {
            self.asked.fetch_add(1, Ordering::Relaxed);
            return Err(chain::Error::InvalidSegmentHeight);
        }
        let (segment, bitmap_root) = self.segmenter(hash)?.output_segment(id)?;
        if !self.bend.load(Ordering::Relaxed) {
            return Ok((segment, bitmap_root));
        }
        let (id, hash_pos, hashes, leaf_pos, mut leaves, proof) = segment.parts();
        for leaf in &mut leaves {
            leaf.commit.0[9] ^= 1;
        }
        Ok((Segment::from_parts(id, hash_pos, hashes, leaf_pos, leaves, proof), bitmap_root))
    }
    fn get_rangeproof_segment(&self, hash: Hash, id: SegmentIdentifier) -> Result<Segment<RangeProof>, chain::Error> {
        self.proofs_asked.fetch_add(1, Ordering::Relaxed);
        let segment = self.segmenter(hash)?.rangeproof_segment(id)?;
        if !self.bend_proofs.load(Ordering::Relaxed) {
            return Ok(segment);
        }
        let (id, hash_pos, hashes, leaf_pos, mut leaves, proof) = segment.parts();
        if let Some(leaf) = leaves.last_mut() {
            leaf.proof[9] ^= 1;
        }
        Ok(Segment::from_parts(id, hash_pos, hashes, leaf_pos, leaves, proof))
    }
    fn receive_bitmap_segment(&self, _: Hash, _: Hash, _: Segment<BitmapChunk>, _: &PeerInfo) -> Result<bool, chain::Error> {
        Ok(true)
    }
    fn receive_output_segment(&self, _: Hash, _: Hash, _: Segment<OutputIdentifier>, _: &PeerInfo) -> Result<bool, chain::Error> {
        Ok(true)
    }
    fn receive_rangeproof_segment(&self, _: Hash, _: Segment<RangeProof>, _: &PeerInfo) -> Result<bool, chain::Error> {
        Ok(true)
    }
    fn receive_kernel_segment(&self, _: Hash, _: Segment<TxKernel>, _: &PeerInfo) -> Result<bool, chain::Error> {
        Ok(true)
    }
    fn receive_header_segment(&self, _: SegmentIdentifier, _: &[BlockHeader], _: &PeerInfo) -> Result<HeaderSegmentAcceptance, chain::Error> {
        Ok(HeaderSegmentAcceptance::Accepted)
    }
}
impl NetAdapter for Served {
    fn find_peer_addrs(&self, _: Capabilities) -> Vec<PeerAddr> {
        Vec::new()
    }
    fn peer_addrs_received(&self, _: Vec<PeerAddr>) {}
    fn peer_difficulty(&self, _: PeerAddr, _: Difficulty, _: u64) {}
    fn is_banned(&self, _: PeerAddr) -> bool {
        false
    }
}

/// A node: its headers and, if it has a chain behind them, its state.
pub struct Node {
    pub addr: SocketAddr,
    pub served: Arc<Served>,
    pub peers: Arc<Mutex<Vec<Peer>>>,
}
impl Node {
    pub fn start(headers: &[BlockHeader]) -> Node {
        Node::start_as(headers, Net::Automated.genesis_hash(), None)
    }
    pub fn start_as(headers: &[BlockHeader], genesis: [u8; 32], boast: Option<u64>) -> Node {
        Node::start_with(headers, genesis, boast, None)
    }
    /// A node that gives out the state of `source`'s chain.
    pub fn with_state(source: &Arc<RwLock<Source>>) -> Node {
        let headers = source.read().unwrap().headers();
        Node::start_with(&headers, Net::Automated.genesis_hash(), None, Some(source.clone()))
    }
    fn start_with(headers: &[BlockHeader], genesis: [u8; 32], boast: Option<u64>, source: Option<Arc<RwLock<Source>>>) -> Node {
        global::init_global_chain_type(ChainTypes::AutomatedTesting);
        let capabilities = if source.is_some() {
            Capabilities::TXHASHSET_HIST | Capabilities::PIBD_HIST | Capabilities::HEADER_PROOF_HIST | Capabilities::TX_KERNEL_HASH
        } else {
            Capabilities::TXHASHSET_HIST
        };
        let served = Arc::new(Served {
            headers: Mutex::new(headers.to_vec()),
            requests: AtomicUsize::new(0),
            boast,
            source,
            asked: AtomicUsize::new(0),
            answered: AtomicUsize::new(0),
            limit: AtomicUsize::new(usize::MAX),
            bend: AtomicBool::new(false),
            max_output_height: AtomicU8::new(u8::MAX),
            output_heights: Mutex::new(Vec::new()),
            blocks_asked: AtomicUsize::new(0),
            bend_blocks: AtomicBool::new(false),
            mute_blocks: AtomicBool::new(false),
            proofs_asked: AtomicUsize::new(0),
            bend_proofs: AtomicBool::new(false),
            bend_header_proofs: AtomicUsize::new(0),
            header_proofs_asked: AtomicUsize::new(0),
            stems: Mutex::new(Vec::new()),
            pool: Mutex::new(Vec::new()),
            told: Mutex::new(Vec::new()),
            txs_asked: AtomicUsize::new(0),
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let peers = Arc::new(Mutex::new(Vec::new()));
        let (adapter, kept) = (served.clone(), peers.clone());
        std::thread::spawn(move || {
            let handshake = Handshake::new(Hash::from_vec(&genesis), P2PConfig::default());
            for conn in listener.incoming().flatten() {
                let work = adapter.total_difficulty().unwrap();
                let net: Arc<dyn NetAdapter> = adapter.clone();
                if let Ok(peer) = Peer::accept(conn, capabilities, work, &handshake, net) {
                    kept.lock().unwrap().push(peer);
                }
            }
        });
        // told of a transaction by its kernel, a node asks for it
        let (adapter, kept) = (served.clone(), peers.clone());
        std::thread::spawn(move || loop {
            let told: Vec<Hash> = adapter.told.lock().unwrap().drain(..).collect();
            for kernel in told {
                for peer in kept.lock().unwrap().iter() {
                    let _ = peer.send_tx_request(kernel);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        });
        Node { addr, served, peers }
    }
    /// Pass a transaction on to everybody connected, as a node does with
    /// one it holds.
    pub fn relay(&self, tx: &core::Transaction) {
        self.served.pool.lock().unwrap().push(tx.clone());
        for peer in self.peers.lock().unwrap().iter() {
            let _ = peer.send_transaction(tx);
        }
    }
    pub fn stems(&self) -> usize {
        self.served.stems.lock().unwrap().len()
    }
    pub fn pooled(&self) -> usize {
        self.served.pool.lock().unwrap().len()
    }
    pub fn set(&self, headers: &[BlockHeader]) {
        *self.served.headers.lock().unwrap() = headers.to_vec();
    }
    pub fn requests(&self) -> usize {
        self.served.requests.load(Ordering::Relaxed)
    }
    /// Tell everybody connected about the newest header, as a node does.
    pub fn announce(&self) {
        let tip = self.served.headers.lock().unwrap().last().unwrap().clone();
        for peer in self.peers.lock().unwrap().iter() {
            let _ = peer.send_header(&tip);
        }
    }
}

pub struct Run {
    pub code: i32,
    pub out: String,
}
impl Run {
    /// The value of `key=` in the last line that starts with `line`.
    pub fn field(&self, line: &str, key: &str) -> String {
        let found = self.out.lines().rev().find(|l| l.contains(line)).unwrap_or_else(|| panic!("no '{line}' in:\n{}", self.out));
        let at = found.find(&format!("{key}=")).unwrap_or_else(|| panic!("no {key} in: {found}")) + key.len() + 1;
        found[at..].split(' ').next().unwrap().to_string()
    }
}
/// `fly-chain headers ...`: follow the headers of the given nodes.
pub fn follow(data: &Temp, peers: &[SocketAddr], seconds: u64) -> Run {
    trial("headers", data, peers, seconds)
}
/// `fly-chain blocks ...`: go on to apply the blocks to the tip.
pub fn apply(data: &Temp, peers: &[SocketAddr], seconds: u64) -> Run {
    trial("blocks", data, peers, seconds)
}
/// `fly-chain select ...`: follow the blocks to the tip and wait until
/// the tip is selected.
#[allow(dead_code)]
pub fn select(data: &Temp, peers: &[SocketAddr], seconds: u64) -> Run {
    trial("select", data, peers, seconds)
}
/// `fly-chain point ...`: follow the headers and make a starting point.
#[allow(dead_code)]
pub fn point(data: &Temp, peers: &[SocketAddr], extra: &[&str]) -> Run {
    let mut command = Command::new(FLY);
    command.args(["point", "--network", "automated", "--data"]).arg(&data.0);
    for peer in peers {
        command.args(["--peer", &peer.to_string()]);
    }
    let output = command.args(["--seconds", "60", "--steady", "6"]).args(extra).output().unwrap();
    Run {
        code: output.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr),
    }
}
/// `fly-chain proofs ...`: follow the headers, then ask the nodes for
/// header proofs, each request twice.
pub fn proofs(data: &Temp, peers: &[SocketAddr], seconds: u64) -> Run {
    let mut command = Command::new(FLY);
    command.args(["proofs", "--network", "automated", "--data"]).arg(&data.0);
    for peer in peers {
        command.args(["--peer", &peer.to_string()]);
    }
    let output = command.args(["--seconds", &seconds.to_string(), "--steady", "6", "--rounds", "2"]).output().unwrap();
    Run {
        code: output.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr),
    }
}
/// `fly-chain proofs ... --sample N`: proofs for heights drawn over the history.
pub fn proofs_sample(data: &Temp, peers: &[SocketAddr], seconds: u64, sample: usize) -> Run {
    let mut command = Command::new(FLY);
    command.args(["proofs", "--network", "automated", "--data"]).arg(&data.0);
    for peer in peers {
        command.args(["--peer", &peer.to_string()]);
    }
    let output = command.args(["--seconds", &seconds.to_string(), "--steady", "6", "--sample", &sample.to_string()]).output().unwrap();
    Run {
        code: output.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr),
    }
}
/// `fly-chain old ...`: go on to read the outputs older than the blocks.
pub fn read_old(data: &Temp, peers: &[SocketAddr], seconds: u64) -> Run {
    trial("old", data, peers, seconds)
}
/// `fly-chain segments ...`: collect the state, then try segments of other heights.
pub fn segments(data: &Temp, peers: &[SocketAddr], seconds: u64) -> Run {
    trial("segments", data, peers, seconds)
}
/// `fly-chain state ...`: go on to collect the state.
pub fn collect(data: &Temp, peers: &[SocketAddr], seconds: u64) -> Run {
    trial("state", data, peers, seconds)
}
fn trial(what: &str, data: &Temp, peers: &[SocketAddr], seconds: u64) -> Run {
    let mut command = Command::new(FLY);
    command.args([what, "--network", "automated", "--data"]).arg(&data.0);
    for peer in peers {
        command.args(["--peer", &peer.to_string()]);
    }
    let output = command.args(["--seconds", &seconds.to_string(), "--steady", "6"]).output().unwrap();
    Run {
        code: output.status.code().unwrap_or(-1),
        out: String::from_utf8_lossy(&output.stdout).into_owned() + &String::from_utf8_lossy(&output.stderr),
    }
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn wait_for(what: &str, mut ready: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(40);
    while !ready() {
        assert!(Instant::now() < until, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

