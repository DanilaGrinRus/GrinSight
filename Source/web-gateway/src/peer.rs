//! Minimal Grin P2P header fetcher for the gateway prototype.
//! The gateway does not trust these headers; the browser verifies them.

use chrono::{DateTime, Utc};
use grin_chain::Options;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{self, BlockHeader, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use grin_chain::txhashset::BitmapSegment;
use grin_core::ser::{self, ProtocolVersion};
use grin_core::global;
use grin_core::pow::Difficulty;
use grin_p2p::handshake::Handshake;
use grin_p2p::types::{
    Capabilities, ChainAdapter, NetAdapter, P2PConfig, PeerAddr, PeerInfo, TxHashSetRead,
};
use grin_p2p::Peer;
use grin_util::secp::pedersen::RangeProof;
use std::fs::File;
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Adapter {
    headers: Arc<Mutex<Vec<BlockHeader>>>,
    peer_claim: Arc<Mutex<(u64, u64)>>,
    wanted: Arc<Mutex<Option<(Hash, SegmentIdentifier, SegmentIdentifier)>>>,
    bitmap: Arc<Mutex<Option<(Hash, Hash, Segment<grin_chain::txhashset::BitmapChunk>)>>>,
    output: Arc<Mutex<Option<(Hash, Hash, Segment<OutputIdentifier>)>>>,
    blocks: Arc<Mutex<Vec<core::Block>>>,
    want_block: Arc<Mutex<Option<Hash>>>,
}

fn not_served() -> grin_chain::Error {
    grin_chain::Error::Other("gateway does not serve this".into())
}

impl ChainAdapter for Adapter {
    fn total_difficulty(&self) -> Result<Difficulty, grin_chain::Error> { Ok(Difficulty::min_dma()) }
    fn total_height(&self) -> Result<u64, grin_chain::Error> { Ok(0) }
    fn get_transaction(&self, _h: Hash) -> Option<core::Transaction> { None }
    fn tx_kernel_received(&self, _h: Hash, _p: &PeerInfo) -> Result<bool, grin_chain::Error> { Ok(true) }
    fn transaction_received(&self, _t: core::Transaction, _stem: bool) -> Result<bool, grin_chain::Error> { Ok(true) }
    fn compact_block_received(&self, _b: core::CompactBlock, _p: &PeerInfo) -> Result<bool, grin_chain::Error> { Ok(true) }
    fn header_received(&self, _h: BlockHeader, _p: &PeerInfo) -> Result<bool, grin_chain::Error> { Ok(true) }
    fn block_received(&self, b: core::Block, _p: &PeerInfo, _o: Options) -> Result<bool, grin_chain::Error> {
        self.blocks.lock().map_err(|_| not_served())?.push(b);
        Ok(true)
    }
    fn headers_received(&self, hs: &[BlockHeader], _p: &PeerInfo) -> Result<bool, grin_chain::Error> {
        self.headers.lock().unwrap().extend(hs.iter().cloned());
        Ok(true)
    }
    fn locate_headers(&self, _l: &[Hash]) -> Result<Vec<BlockHeader>, grin_chain::Error> { Ok(vec![]) }
    fn get_block(&self, _h: Hash, _p: &PeerInfo) -> Option<core::Block> { None }
    fn txhashset_read(&self, _h: Hash) -> Option<TxHashSetRead> { None }
    fn txhashset_archive_header(&self) -> Result<BlockHeader, grin_chain::Error> { Err(not_served()) }
    fn txhashset_receive_ready(&self) -> bool { false }
    fn txhashset_write(&self, _h: Hash, _f: File, _p: &PeerInfo) -> Result<bool, grin_chain::Error> { Ok(false) }
    fn txhashset_download_update(&self, _s: DateTime<Utc>, _d: u64, _t: u64) -> bool { false }
    fn get_tmp_dir(&self) -> PathBuf { PathBuf::from(".") }
    fn get_tmpfile_pathname(&self, n: String) -> PathBuf { PathBuf::from(n) }
    fn get_kernel_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<Segment<TxKernel>, grin_chain::Error> { Err(not_served()) }
    fn get_bitmap_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<(Segment<grin_chain::txhashset::BitmapChunk>, Hash), grin_chain::Error> { Err(not_served()) }
    fn get_output_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<(Segment<OutputIdentifier>, Hash), grin_chain::Error> { Err(not_served()) }
    fn get_rangeproof_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<Segment<RangeProof>, grin_chain::Error> { Err(not_served()) }
    fn receive_bitmap_segment(&self, b: Hash, o: Hash, s: Segment<grin_chain::txhashset::BitmapChunk>) -> Result<bool, grin_chain::Error> {
        let want = self.wanted.lock().map_err(|_| not_served())?;
        if let Some((h, bid, _)) = *want { if h == b && bid == s.identifier() { *self.bitmap.lock().map_err(|_| not_served())? = Some((b, o, s)); return Ok(true); } }
        Ok(false)
    }
    fn receive_output_segment(&self, b: Hash, r: Hash, s: Segment<OutputIdentifier>) -> Result<bool, grin_chain::Error> {
        let want = self.wanted.lock().map_err(|_| not_served())?;
        if let Some((h, _, oid)) = *want { if h == b && oid == s.identifier() { *self.output.lock().map_err(|_| not_served())? = Some((b, r, s)); return Ok(true); } }
        Ok(false)
    }
    fn receive_rangeproof_segment(&self, _b: Hash, _s: Segment<RangeProof>) -> Result<bool, grin_chain::Error> { Ok(false) }
    fn receive_kernel_segment(&self, _b: Hash, _s: Segment<TxKernel>) -> Result<bool, grin_chain::Error> { Ok(false) }
}

impl NetAdapter for Adapter {
    fn find_peer_addrs(&self, _c: Capabilities) -> Vec<PeerAddr> { vec![] }
    fn peer_addrs_received(&self, _p: Vec<PeerAddr>) {}
    fn peer_difficulty(&self, _a: PeerAddr, d: Difficulty, h: u64) { *self.peer_claim.lock().unwrap() = (h, d.to_num()); }
    fn is_banned(&self, _a: PeerAddr) -> bool { false }
}

/// Short PIBD probe: handshake only, return the peer's capabilities.
pub fn probe(peer_arg: &str, timeout: Duration) -> Result<Capabilities, String> {
    let conn = TcpStream::connect_timeout(
        &peer_arg.parse().map_err(|_| format!("peer must be IP:PORT, got {peer_arg}"))?,
        timeout,
    ).map_err(|e| format!("connect {e}"))?;
    let local = conn.local_addr().map_err(|e| format!("local addr {e}"))?;
    let hs = Handshake::new(global::get_genesis_block().header.hash(), P2PConfig::default());
    let adapter = Arc::new(Adapter {
        headers: Arc::new(Mutex::new(Vec::new())),
        peer_claim: Arc::new(Mutex::new((0, 0))),
        wanted: Arc::new(Mutex::new(None)),
        bitmap: Arc::new(Mutex::new(None)),
        output: Arc::new(Mutex::new(None)),
        blocks: Arc::new(Mutex::new(Vec::new())),
        want_block: Arc::new(Mutex::new(None)),
    });
    let peer = Peer::connect(
        conn,
        Capabilities::default() | Capabilities::PIBD_HIST | Capabilities::PIBD_HIST_1,
        Difficulty::min_dma(),
        PeerAddr(local),
        &hs,
        adapter,
    ).map_err(|e| format!("handshake {e:?}"))?;
    let caps = peer.info.capabilities;
    peer.stop();
    let _ = peer.wait();
    Ok(caps)
}

/// Fetch headers starting at the checkpoint locator. Returns raw headers; the
/// gateway deliberately does not validate them.
pub fn fetch_headers(peer_arg: &str, locator: Hash, max_wait: Duration) -> Result<Vec<BlockHeader>, String> {
    // See fetch_pibd: no immediate reconnects, rotate peers in the caller.
    fetch_headers_once(peer_arg, locator, max_wait)
}

fn fetch_headers_once(peer_arg: &str, locator: Hash, max_wait: Duration) -> Result<Vec<BlockHeader>, String> {
    let conn = TcpStream::connect_timeout(
        &peer_arg.parse().map_err(|_| format!("peer must be IP:PORT, got {peer_arg}"))?,
        Duration::from_secs(15),
    ).map_err(|e| format!("connect {e}"))?;
    let local = conn.local_addr().map_err(|e| format!("local addr {e}"))?;
    let hs = Handshake::new(global::get_genesis_block().header.hash(), P2PConfig::default());
    let headers = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(Adapter {
        headers: headers.clone(),
        peer_claim: Arc::new(Mutex::new((0, 0))),
        wanted: Arc::new(Mutex::new(None)),
        bitmap: Arc::new(Mutex::new(None)),
        output: Arc::new(Mutex::new(None)),
        blocks: Arc::new(Mutex::new(Vec::new())),
        want_block: Arc::new(Mutex::new(None)),
    });
    let peer = Peer::connect(conn, Capabilities::default(), Difficulty::min_dma(), PeerAddr(local), &hs, adapter)
        .map_err(|e| format!("handshake {e:?}"))?;
    if let Err(e) = peer.send_header_request(vec![locator]) {
        peer.stop();
        let _ = peer.wait();
        return Err(format!("getheaders: {e:?}"));
    }
    let start = Instant::now();
    let mut last_len = 0usize;
    let mut last_change = Instant::now();
    loop {
        let len = headers.lock().unwrap().len();
        if len != last_len {
            last_len = len;
            last_change = Instant::now();
        }
        if len > 0 && last_change.elapsed() > Duration::from_secs(2) { break; }
        if start.elapsed() > max_wait { break; }
        std::thread::sleep(Duration::from_millis(100));
    }
    peer.stop();
    let _ = peer.wait();
    let out = headers.lock().unwrap().clone();
    if out.is_empty() {
        return Err("peer returned no headers".into());
    }
    Ok(out)
}




/// Fetch headers archive→tip and all blocks in one persistent P2P connection.
/// Returns a BLK1 packet: headers then blocks, each length-prefixed.
pub fn fetch_block_bundle(peer_arg: &str, archive: Hash, max_wait: Duration) -> Result<Vec<u8>, String> {
    let conn = TcpStream::connect_timeout(
        &peer_arg.parse().map_err(|_| format!("peer must be IP:PORT, got {peer_arg}"))?,
        Duration::from_secs(15),
    ).map_err(|e| format!("connect {e}"))?;
    let local = conn.local_addr().map_err(|e| format!("local addr {e}"))?;
    let hs = Handshake::new(global::get_genesis_block().header.hash(), P2PConfig::default());
    let headers = Arc::new(Mutex::new(Vec::new()));
    let blocks = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(Adapter {
        headers: headers.clone(),
        peer_claim: Arc::new(Mutex::new((0, 0))),
        wanted: Arc::new(Mutex::new(None)),
        bitmap: Arc::new(Mutex::new(None)),
        output: Arc::new(Mutex::new(None)),
        blocks: blocks.clone(),
        want_block: Arc::new(Mutex::new(None)),
    });
    let peer = Peer::connect(conn, Capabilities::default() | Capabilities::BLOCK_HIST,
        Difficulty::min_dma(), PeerAddr(local), &hs, adapter).map_err(|e| format!("handshake {e:?}"))?;
    let result = (|| {
        let mut locator = archive;
        for _ in 0..24 {
            let before = headers.lock().map_err(|_| "headers lock")?.len();
            peer.send_header_request(vec![locator]).map_err(|e| format!("getheaders: {e:?}"))?;
            let start = Instant::now();
            let mut last = before;
            loop {
                let n = headers.lock().map_err(|_| "headers lock")?.len();
                if n != last { last = n; }
                if last > before && start.elapsed() > Duration::from_secs(2) { break; }
                if start.elapsed() > Duration::from_secs(20) { break; }
                std::thread::sleep(Duration::from_millis(100));
            }
            let now = headers.lock().map_err(|_| "headers lock")?.len();
            if now == before { break; }
            let batch = now - before;
            let hs_now = headers.lock().map_err(|_| "headers lock")?.clone();
            locator = hs_now[now - 1].hash();
            if batch < 512 { break; }
        }
        let hs_now = headers.lock().map_err(|_| "headers lock")?.clone();
        if hs_now.is_empty() { return Err("no headers".into()); }
        let hashes: Vec<_> = hs_now.iter().map(|h| h.hash()).collect();
        // Blocks on a fresh connection: mixing header and block phases on one
        // peer connection stalls public nodes after the first block window.
        peer.stop();
        let _ = peer.wait();
        let blks = fetch_blocks(peer_arg, &hashes, Duration::from_secs(900))?;
        let mut out = b"BLK1".to_vec();
        out.extend_from_slice(&(hs_now.len() as u32).to_le_bytes());
        for h in &hs_now {
            let raw = ser::ser_vec(h, ProtocolVersion::local()).map_err(|e| format!("header ser: {e:?}"))?;
            out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            out.extend_from_slice(&raw);
        }
        out.extend_from_slice(&(blks.len() as u32).to_le_bytes());
        for b in &blks {
            let raw = ser::ser_vec(b, ProtocolVersion::local()).map_err(|e| format!("block ser: {e:?}"))?;
            out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            out.extend_from_slice(&raw);
        }
        Ok(out)
    })();
    peer.stop();
    let _ = peer.wait();
    result
}

/// Fetch several blocks over one persistent connection. Public peers ban
/// clients that open a new connection per block.
pub fn fetch_blocks(peer_arg: &str, hashes: &[Hash], max_wait: Duration) -> Result<Vec<core::Block>, String> {
    let conn = TcpStream::connect_timeout(
        &peer_arg.parse().map_err(|_| format!("peer must be IP:PORT, got {peer_arg}"))?,
        Duration::from_secs(15),
    ).map_err(|e| format!("connect {e}"))?;
    let local = conn.local_addr().map_err(|e| format!("local addr {e}"))?;
    let hs = Handshake::new(global::get_genesis_block().header.hash(), P2PConfig::default());
    let blocks = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(Adapter {
        headers: Arc::new(Mutex::new(Vec::new())),
        peer_claim: Arc::new(Mutex::new((0, 0))),
        wanted: Arc::new(Mutex::new(None)),
        bitmap: Arc::new(Mutex::new(None)),
        output: Arc::new(Mutex::new(None)),
        blocks: blocks.clone(),
        want_block: Arc::new(Mutex::new(None)),
    });
    let peer = Peer::connect(conn, Capabilities::default() | Capabilities::BLOCK_HIST,
        Difficulty::min_dma(), PeerAddr(local), &hs, adapter).map_err(|e| format!("handshake {e:?}"))?;
    let result = (|| {
        for h in hashes {
            peer.send_block_request(*h, Options::NONE).map_err(|e| format!("getblock: {e:?}"))?;
            std::thread::sleep(Duration::from_millis(80));
        }
        let start = Instant::now();
        loop {
            let have = blocks.lock().map_err(|_| "blocks lock")?.len();
            if have >= hashes.len() { break; }
            if start.elapsed() > max_wait { return Err(format!("block timeout {have}/{}", hashes.len())); }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(blocks.lock().map_err(|_| "blocks lock")?.clone())
    })();
    peer.stop();
    let _ = peer.wait();
    result
}

/// Fetch one block by hash from a peer that advertises BLOCK_HIST.
pub fn fetch_block(peer_arg: &str, hash: Hash, max_wait: Duration) -> Result<core::Block, String> {
    let conn = TcpStream::connect_timeout(
        &peer_arg.parse().map_err(|_| format!("peer must be IP:PORT, got {peer_arg}"))?,
        Duration::from_secs(15),
    ).map_err(|e| format!("connect {e}"))?;
    let local = conn.local_addr().map_err(|e| format!("local addr {e}"))?;
    let hs = Handshake::new(global::get_genesis_block().header.hash(), P2PConfig::default());
    let blocks = Arc::new(Mutex::new(Vec::new()));
    let adapter = Arc::new(Adapter {
        headers: Arc::new(Mutex::new(Vec::new())),
        peer_claim: Arc::new(Mutex::new((0, 0))),
        wanted: Arc::new(Mutex::new(None)),
        bitmap: Arc::new(Mutex::new(None)),
        output: Arc::new(Mutex::new(None)),
        blocks: blocks.clone(),
        want_block: Arc::new(Mutex::new(Some(hash))),
    });
    let peer = Peer::connect(conn, Capabilities::default() | Capabilities::BLOCK_HIST,
        Difficulty::min_dma(), PeerAddr(local), &hs, adapter).map_err(|e| format!("handshake {e:?}"))?;
    if let Err(e) = peer.send_block_request(hash, Options::NONE) {
        peer.stop(); let _ = peer.wait();
        return Err(format!("getblock: {e:?}"));
    }
    let start = Instant::now();
    loop {
        if let Some(b) = blocks.lock().unwrap().first().cloned() {
            peer.stop(); let _ = peer.wait();
            return Ok(b);
        }
        if start.elapsed() > max_wait {
            peer.stop(); let _ = peer.wait();
            return Err("block timeout".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Fetch one bitmap + one output PIBD segment and return a UPB1 bundle.
/// Public peers frequently close the first handshake; retry like header-sync.
pub fn fetch_pibd(peer_arg: &str, archive: Hash, leaf: u64) -> Result<Vec<u8>, String> {
    // One connection per request. Reconnect storms make Grin nodes ban the
    // source IP; the caller rotates peers instead.
    fetch_pibd_once(peer_arg, archive, leaf)
}

fn fetch_pibd_once(peer_arg: &str, archive: Hash, leaf: u64) -> Result<Vec<u8>, String> {
    let bid = SegmentIdentifier { height: 9, idx: leaf / (1024 * 512) };
    let oid = SegmentIdentifier { height: 11, idx: leaf / 2048 };
    let conn = TcpStream::connect_timeout(
        &peer_arg.parse().map_err(|_| format!("peer must be IP:PORT, got {peer_arg}"))?,
        Duration::from_secs(15),
    ).map_err(|e| format!("connect {e}"))?;
    let local = conn.local_addr().map_err(|e| format!("local addr {e}"))?;
    let hs = Handshake::new(global::get_genesis_block().header.hash(), P2PConfig::default());
    let adapter = Arc::new(Adapter {
        headers: Arc::new(Mutex::new(Vec::new())),
        peer_claim: Arc::new(Mutex::new((0, 0))),
        wanted: Arc::new(Mutex::new(Some((archive, bid, oid)))),
        bitmap: Arc::new(Mutex::new(None)),
        output: Arc::new(Mutex::new(None)),
        blocks: Arc::new(Mutex::new(Vec::new())),
        want_block: Arc::new(Mutex::new(None)),
    });
    let peer = Peer::connect(conn, Capabilities::default() | Capabilities::PIBD_HIST | Capabilities::PIBD_HIST_1,
        Difficulty::min_dma(), PeerAddr(local), &hs, adapter.clone()).map_err(|e| format!("handshake {e:?}"))?;
    let result = (|| {
        peer.send_bitmap_segment_request(archive, bid).map_err(|e| format!("bitmap request {e:?}"))?;
        peer.send_output_segment_request(archive, oid).map_err(|e| format!("output request {e:?}"))?;
        let start = Instant::now();
        loop {
            let b = adapter.bitmap.lock().map_err(|_| "bitmap lock")?.clone();
            let o = adapter.output.lock().map_err(|_| "output lock")?.clone();
            if let (Some((_, raw, bitmap)), Some((_, other, output))) = (b, o) {
                let bmb = ser::ser_vec(&BitmapSegment::from(bitmap), ProtocolVersion::local()).map_err(|e| format!("bitmap ser {e:?}"))?;
                let outb = ser::ser_vec(&output, ProtocolVersion::local()).map_err(|e| format!("output ser {e:?}"))?;
                let mut data = b"UPB1".to_vec();
                data.extend_from_slice(raw.as_bytes());
                data.extend_from_slice(other.as_bytes());
                for x in [&bmb, &outb] {
                    let n = u32::try_from(x.len()).map_err(|_| "segment too large")?;
                    data.extend_from_slice(&n.to_le_bytes());
                    data.extend_from_slice(x);
                }
                return Ok(data);
            }
            if start.elapsed() > Duration::from_secs(20) { return Err("segment timeout".into()); }
            std::thread::sleep(Duration::from_millis(50));
        }
    })();
    peer.stop();
    let _ = peer.wait();
    result
}

