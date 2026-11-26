//! What the Grin network code is given to talk to.
//!
//! The network code of the node expects a whole node behind it: something
//! that takes blocks and transactions and can serve history. This process is
//! not a node. It takes headers, how much work peers claim and the segments
//! of state it asked for, and it serves nothing: every request for data is answered with an error, never with a
//! panic and never with made-up data.
use chrono::{DateTime, Utc};
use grin_chain as chain;
use grin_chain::txhashset::BitmapChunk;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{self, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use grin_core::pow::Difficulty;
use grin_p2p::types::{HeaderSegmentAcceptance, TxHashSetRead};
use grin_p2p::types::NetAdapter;
use grin_p2p::{Capabilities, ChainAdapter, PeerAddr, PeerInfo};
use grin_util::secp::pedersen::RangeProof;
use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use crate::state::Arrived;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};

/// What reaches the one thread that owns the header chain.
pub enum Event {
    /// Headers from a peer: an answer to a request, or an announcement.
    Headers {
        /// Who sent them.
        from: SocketAddr,
        /// The headers, as the network code parsed them.
        headers: Vec<core::BlockHeader>,
    },
    /// What a peer says about its own chain.
    Seen {
        /// The peer.
        from: SocketAddr,
        /// Total work it claims.
        work: u64,
        /// Height it claims.
        height: u64,
    },
    /// A connection attempt ended.
    Connected {
        /// The address tried.
        addr: SocketAddr,
        /// The peer, or why not.
        peer: Result<Arc<grin_p2p::Peer>, String>,
    },
    /// A segment of the state from a peer.
    Segment {
        /// Who sent it.
        from: SocketAddr,
        /// The header it says the state is at.
        block: Hash,
        /// The segment.
        piece: Arrived,
    },
    /// A block from a peer.
    Block {
        /// Who sent it.
        from: SocketAddr,
        /// The block.
        block: Box<core::Block>,
    },
    /// News of an asking of the public nodes about the tip.
    Surveyed(Box<crate::accept::Surveyed>),
    /// The wallet asks what comes after its position.
    Ask {
        /// The wallet's position, if it has one.
        at: Option<fly_paycore_chain_port::Tip>,
        /// Where the answer goes.
        reply: SyncSender<Result<fly_paycore_chain_port::Step, fly_paycore_chain_port::Unknown>>,
    },
    /// The wallet asks for a piece of the outputs older than the blocks.
    AskOld {
        /// Number of the piece.
        piece: u64,
        /// The block the wallet says it knew its outputs up to, if it
        /// named one.
        since: Option<fly_paycore_chain_port::Tip>,
        /// Where the answer goes.
        reply: SyncSender<Result<fly_paycore_chain_port::OldOutputs, fly_paycore_chain_port::Unknown>>,
    },
    /// The wallet asks for a starting point made from this chain (K188).
    Point {
        /// Where the record, or why there is none, goes.
        reply: SyncSender<Result<Vec<u8>, String>>,
    },
    /// The owner switched Tor off or back on (K193).
    Tor {
        /// Off.
        off: bool,
        /// Where "taken up" goes.
        reply: SyncSender<bool>,
    },
    /// The wallet hands a finished transaction over.
    Post {
        /// The transaction, as the wallet serialized it.
        tx: Vec<u8>,
        /// The owner agreed that this one goes out from this computer's
        /// address if Tor fails to send it (K192).
        direct: bool,
        /// Where the answer goes.
        reply: SyncSender<fly_paycore_chain_port::Posted>,
    },
    /// A node handed over a transaction that has a kernel this program
    /// looks out for.
    Heard {
        /// Full hashes of the watched kernels in the checked transaction.
        kernels: Vec<Hash>,
    },
    /// A try at sending a transaction through Tor ended.
    Sent {
        /// The kernels of the transaction.
        key: Vec<[u8; 33]>,
        /// Which way it went, or why it did not.
        result: Result<crate::send::Way, String>,
    },
    /// A name was looked up.
    Resolved {
        /// The text that was resolved.
        text: String,
        /// The addresses found; empty if none.
        addrs: Vec<SocketAddr>,
    },
}

/// The end of our verified chain, as peers are told it.
#[derive(Default)]
pub struct OurTip {
    /// Total work.
    pub work: AtomicU64,
    /// Height.
    pub height: AtomicU64,
}

/// Segments and blocks that may wait in the queue at once. One can be a
/// few megabytes; more than were asked for are not kept waiting.
pub const MAX_WAITING_SEGMENTS: usize = 64;

/// Count one more, unless `limit` are counted already.
fn count_up(counter: &AtomicUsize, limit: usize) -> bool {
    let mut seen = counter.load(Ordering::Relaxed);
    while seen < limit {
        match counter.compare_exchange_weak(seen, seen.saturating_add(1), Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(now) => seen = now,
        }
    }
    false
}

/// Count one less; never below nothing.
pub fn count_down(counter: &AtomicUsize) {
    let mut seen = counter.load(Ordering::Relaxed);
    while let Some(less) = seen.checked_sub(1) {
        match counter.compare_exchange_weak(seen, less, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(now) => seen = now,
        }
    }
}

/// The adapter handed to every peer connection.
pub struct Adapter {
    events: SyncSender<Event>,
    tip: Arc<OurTip>,
    waiting: Arc<AtomicUsize>,
    watch: Arc<Mutex<Watch>>,
}

/// What the wallet's own transactions need of the network code, kept by
/// the thread that owns the chain and read here.
#[derive(Default)]
pub struct Watch {
    /// The kernels of the transactions this program has sent and has not
    /// seen in a block: a transaction from a node that has one of them is
    /// passed on, every other transaction of the network is dropped.
    pub kernels: Vec<([u8; 33], Hash)>,
    /// The transactions this program has announced itself, by the hash of
    /// each kernel: a node that was told of one may ask for it.
    pub announced: Vec<(Hash, core::Transaction)>,
}

impl Adapter {
    /// An adapter that reports to `events` and tells peers `tip`.
    /// `waiting` counts the segments in the queue: whoever takes one out
    /// counts it down.
    pub fn new(events: SyncSender<Event>, tip: Arc<OurTip>, waiting: Arc<AtomicUsize>, watch: Arc<Mutex<Watch>>) -> Adapter {
        Adapter { events, tip, waiting, watch }
    }
    /// Pass a segment on, unless too many are waiting already: then it is
    /// dropped, and asked for again when its time is up.
    fn tell_segment(&self, peer: &PeerInfo, block: Hash, piece: Arrived) {
        if !count_up(&self.waiting, MAX_WAITING_SEGMENTS) {
            return;
        }
        let event = Event::Segment {
            from: peer.addr.0,
            block,
            piece,
        };
        if self.events.try_send(event).is_err() {
            count_down(&self.waiting);
        }
    }
    /// Pass an event on. A full queue drops it: a peer that floods is not
    /// allowed to fill the memory, and whatever was dropped is asked for again.
    fn tell(&self, event: Event) {
        let _ = self.events.try_send(event);
    }
}

fn not_served<T>() -> Result<T, chain::Error> {
    Err(chain::Error::Other("this peer serves no chain data".to_string()))
}

impl ChainAdapter for Adapter {
    fn total_difficulty(&self) -> Result<Difficulty, chain::Error> {
        Ok(Difficulty::from_num(self.tip.work.load(Ordering::Relaxed).max(1)))
    }
    fn total_height(&self) -> Result<u64, chain::Error> {
        Ok(self.tip.height.load(Ordering::Relaxed))
    }
    fn transaction_received(&self, tx: core::Transaction, stem: bool) -> Result<bool, chain::Error> {
        // A transaction a node passes on is in its pool. Only one that
        // holds a kernel of the wallet's own is of any interest here; a
        // stem transaction is somebody's on its way and says nothing.
        if stem {
            return Ok(true);
        }
        let Ok(watch) = self.watch.lock() else { return Ok(true) };
        if watch.kernels.is_empty() {
            return Ok(true);
        }
        let kernels: Vec<Hash> = tx.kernels().iter().filter_map(|kernel| {
            // Compare the cheap public commitment first, then bind the complete signed kernel.
            if !watch.kernels.iter().any(|(excess, _)| *excess == kernel.excess.0) {
                return None;
            }
            let hash = kernel.hash();
            watch.kernels.iter().any(|(_, expected)| *expected == hash).then_some(hash)
        }).collect();
        drop(watch);
        if !kernels.is_empty() {
            // P2P decoding does only lightweight structure checks. Aggregation is
            // allowed, but the received transaction must still verify in its own right.
            tx.validate(core::transaction::Weighting::AsTransaction)
                .map_err(|_| chain::Error::Other("invalid transaction observation".to_string()))?;
            self.tell(Event::Heard { kernels });
        }
        Ok(true)
    }
    fn get_transaction(&self, kernel: Hash) -> Option<core::Transaction> {
        // only what this program has announced itself
        let watch = self.watch.lock().ok()?;
        watch.announced.iter().find(|(hash, _)| *hash == kernel).map(|(_, tx)| tx.clone())
    }
    fn tx_kernel_received(&self, _: Hash, _: &PeerInfo) -> Result<bool, chain::Error> {
        Ok(true)
    }
    fn block_received(&self, block: core::Block, peer: &PeerInfo, _: chain::Options) -> Result<bool, chain::Error> {
        // its header first, as news about the chain; then the block itself,
        // unless too much is waiting already
        self.tell(Event::Headers {
            from: peer.addr.0,
            headers: vec![block.header.clone()],
        });
        if count_up(&self.waiting, MAX_WAITING_SEGMENTS) {
            let event = Event::Block {
                from: peer.addr.0,
                block: Box::new(block),
            };
            if self.events.try_send(event).is_err() {
                count_down(&self.waiting);
            }
        }
        Ok(true)
    }
    fn compact_block_received(&self, block: core::CompactBlock, peer: &PeerInfo) -> Result<bool, chain::Error> {
        self.tell(Event::Headers {
            from: peer.addr.0,
            headers: vec![block.header],
        });
        Ok(true)
    }
    fn header_received(&self, header: core::BlockHeader, peer: &PeerInfo) -> Result<bool, chain::Error> {
        self.tell(Event::Headers {
            from: peer.addr.0,
            headers: vec![header],
        });
        Ok(true)
    }
    fn headers_received(&self, headers: &[core::BlockHeader], peer: &PeerInfo) -> Result<bool, chain::Error> {
        self.tell(Event::Headers {
            from: peer.addr.0,
            headers: headers.to_vec(),
        });
        Ok(true)
    }
    fn locate_headers(&self, _: &[Hash]) -> Result<Vec<core::BlockHeader>, chain::Error> {
        Ok(Vec::new())
    }
    fn locate_header_segment(&self, _: SegmentIdentifier, _: &PeerInfo) -> Result<Option<Vec<core::BlockHeader>>, chain::Error> {
        Ok(None)
    }
    fn get_block(&self, _: Hash, _: &PeerInfo) -> Option<core::Block> {
        None
    }
    fn txhashset_read(&self, _: Hash) -> Option<TxHashSetRead> {
        None
    }
    fn txhashset_archive_header(&self) -> Result<core::BlockHeader, chain::Error> {
        not_served()
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
        // never written to: no archive is ever accepted
        std::env::temp_dir().join(name.replace(['/', '\\', ':'], "_"))
    }
    fn get_kernel_segment(&self, _: Hash, _: SegmentIdentifier) -> Result<Segment<TxKernel>, chain::Error> {
        not_served()
    }
    fn get_bitmap_segment(&self, _: Hash, _: SegmentIdentifier) -> Result<(Segment<BitmapChunk>, Hash), chain::Error> {
        not_served()
    }
    fn get_output_segment(&self, _: Hash, _: SegmentIdentifier) -> Result<(Segment<OutputIdentifier>, Hash), chain::Error> {
        not_served()
    }
    fn get_rangeproof_segment(&self, _: Hash, _: SegmentIdentifier) -> Result<Segment<RangeProof>, chain::Error> {
        not_served()
    }
    fn receive_bitmap_segment(&self, block: Hash, output_root: Hash, segment: Segment<BitmapChunk>, peer: &PeerInfo) -> Result<bool, chain::Error> {
        self.tell_segment(peer, block, Arrived::Bitmap { output_root, segment });
        Ok(true)
    }
    fn receive_output_segment(&self, block: Hash, _bitmap_root: Hash, segment: Segment<OutputIdentifier>, peer: &PeerInfo) -> Result<bool, chain::Error> {
        // the root of the bitmap the peer names is not used: the bitmap
        // collected here has its own, bound to the header
        self.tell_segment(peer, block, Arrived::Output(segment));
        Ok(true)
    }
    fn receive_rangeproof_segment(&self, block: Hash, segment: Segment<RangeProof>, peer: &PeerInfo) -> Result<bool, chain::Error> {
        self.tell_segment(peer, block, Arrived::Rangeproof(segment));
        Ok(true)
    }
    fn receive_kernel_segment(&self, block: Hash, segment: Segment<TxKernel>, peer: &PeerInfo) -> Result<bool, chain::Error> {
        self.tell_segment(peer, block, Arrived::Kernel(segment));
        Ok(true)
    }
    fn receive_header_segment(&self, _: SegmentIdentifier, _: &[core::BlockHeader], _: &PeerInfo) -> Result<HeaderSegmentAcceptance, chain::Error> {
        Ok(HeaderSegmentAcceptance::Accepted)
    }
}

impl NetAdapter for Adapter {
    fn find_peer_addrs(&self, _: Capabilities) -> Vec<PeerAddr> {
        Vec::new()
    }
    fn peer_addrs_received(&self, _: Vec<PeerAddr>) {}
    fn peer_difficulty(&self, addr: PeerAddr, work: Difficulty, height: u64) {
        self.tell(Event::Seen {
            from: addr.0,
            work: work.to_num(),
            height,
        });
    }
    fn is_banned(&self, _: PeerAddr) -> bool {
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use grin_core::ser::{self, DeserializationMode, ProtocolVersion};
    use grin_p2p::types::{Direction, PeerLiveInfo};
    use grin_util::RwLock;
    use std::sync::mpsc;

    /// A peer may send segments faster than they are looked at, asked for
    /// or not. No more than a fixed number wait at once; the rest are
    /// dropped, and what was wanted among them is asked for again.
    #[test]
    fn segments_do_not_pile_up() {
        let (events, inbox) = mpsc::sync_channel::<Event>(256);
        let waiting = Arc::new(AtomicUsize::new(0));
        let adapter = Adapter::new(events, Arc::new(OurTip::default()), waiting.clone(), Arc::new(Mutex::new(Watch::default())));
        let peer = PeerInfo {
            capabilities: Capabilities::UNKNOWN,
            user_agent: String::new(),
            version: ProtocolVersion::local(),
            addr: PeerAddr("127.0.0.1:9".parse().unwrap()),
            direction: Direction::Outbound,
            live_info: Arc::new(RwLock::new(PeerLiveInfo::new(Difficulty::min_dma()))),
        };
        // a segment with nothing in it: an identifier, two empty lists, an empty proof
        let empty = || -> Segment<TxKernel> {
            let mut bytes = vec![11u8];
            bytes.extend_from_slice(&[0u8; 8 + 8 + 8 + 8]);
            ser::deserialize(&mut &bytes[..], ProtocolVersion::local(), DeserializationMode::default()).unwrap()
        };
        let block = Hash::from_vec(&[7; 32]);
        for _ in 0..MAX_WAITING_SEGMENTS + 30 {
            adapter.receive_kernel_segment(block, empty(), &peer).unwrap();
        }
        assert_eq!(waiting.load(Ordering::Relaxed), MAX_WAITING_SEGMENTS);
        assert_eq!(inbox.try_iter().count(), MAX_WAITING_SEGMENTS);
        // once they are taken out and counted down there is room again
        waiting.store(MAX_WAITING_SEGMENTS - 1, Ordering::Relaxed);
        adapter.receive_kernel_segment(block, empty(), &peer).unwrap();
        adapter.receive_kernel_segment(block, empty(), &peer).unwrap();
        assert_eq!(inbox.try_iter().count(), 1);

        // when the queue itself is full - of anything - a segment that
        // found no place in it is not counted as waiting
        let (events, inbox) = mpsc::sync_channel::<Event>(3);
        let waiting = Arc::new(AtomicUsize::new(0));
        let adapter = Adapter::new(events, Arc::new(OurTip::default()), waiting.clone(), Arc::new(Mutex::new(Watch::default())));
        for _ in 0..10 {
            adapter.receive_kernel_segment(block, empty(), &peer).unwrap();
        }
        assert_eq!((waiting.load(Ordering::Relaxed), inbox.try_iter().count()), (3, 3));
    }
}
