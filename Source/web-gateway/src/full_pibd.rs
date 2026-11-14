//! Full archive PIBD bundle fetch: one persistent peer connection, all
//! bitmap/output/rangeproof/kernel segments, serialized as GPF1.
//!
//! The gateway does not validate the result; the browser/Wasm checks every
//! segment root and `output_root` before using it.

use chrono::{DateTime, Utc};
use grin_chain::txhashset::{BitmapChunk, BitmapSegment};
use grin_chain::Options;
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{self, BlockHeader, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use grin_core::global;
use grin_core::pow::Difficulty;
use grin_core::ser::{self, ProtocolVersion};
use grin_p2p::handshake::Handshake;
use grin_p2p::types::{
    Capabilities, ChainAdapter, NetAdapter, P2PConfig, PeerAddr, PeerInfo, TxHashSetRead,
};
use grin_p2p::Peer;
use grin_util::secp::pedersen::RangeProof;
use std::collections::BTreeMap;
use std::fs::File;
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MSG_INTERVAL: Duration = Duration::from_millis(28); // below 2000/min
const FETCH_TIMEOUT: Duration = Duration::from_secs(1800);

struct FullAdapter {
    archive: Hash,
    peer_claim: Arc<Mutex<(u64, u64)>>,
    bitmap: Mutex<BTreeMap<u64, Segment<BitmapChunk>>>,
    output: Mutex<BTreeMap<u64, Segment<OutputIdentifier>>>,
    rproof: Mutex<BTreeMap<u64, Segment<RangeProof>>>,
    kernel: Mutex<BTreeMap<u64, Segment<TxKernel>>>,
}

fn not_served() -> grin_chain::Error {
    grin_chain::Error::Other("gateway full PIBD does not serve this".into())
}

impl ChainAdapter for FullAdapter {
    fn total_difficulty(&self) -> Result<Difficulty, grin_chain::Error> { Ok(Difficulty::min_dma()) }
    fn total_height(&self) -> Result<u64, grin_chain::Error> { Ok(0) }
    fn get_transaction(&self, _h: Hash) -> Option<core::Transaction> { None }
    fn tx_kernel_received(&self, _h: Hash, _p: &PeerInfo) -> Result<bool, grin_chain::Error> { Ok(true) }
    fn transaction_received(&self, _t: core::Transaction, _stem: bool) -> Result<bool, grin_chain::Error> { Ok(true) }
    fn compact_block_received(&self, _b: core::CompactBlock, _p: &PeerInfo) -> Result<bool, grin_chain::Error> { Ok(true) }
    fn header_received(&self, _h: BlockHeader, _p: &PeerInfo) -> Result<bool, grin_chain::Error> { Ok(true) }
    fn block_received(&self, _b: core::Block, _p: &PeerInfo, _o: Options) -> Result<bool, grin_chain::Error> { Ok(true) }
    fn headers_received(&self, _hs: &[BlockHeader], _p: &PeerInfo) -> Result<bool, grin_chain::Error> { Ok(true) }
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
    fn get_bitmap_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<(Segment<BitmapChunk>, Hash), grin_chain::Error> { Err(not_served()) }
    fn get_output_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<(Segment<OutputIdentifier>, Hash), grin_chain::Error> { Err(not_served()) }
    fn get_rangeproof_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<Segment<RangeProof>, grin_chain::Error> { Err(not_served()) }

    fn receive_bitmap_segment(&self, b: Hash, _o: Hash, s: Segment<BitmapChunk>) -> Result<bool, grin_chain::Error> {
        if b == self.archive {
            self.bitmap.lock().map_err(|_| not_served())?.insert(s.identifier().idx, s);
            return Ok(true);
        }
        Ok(false)
    }
    fn receive_output_segment(&self, b: Hash, _r: Hash, s: Segment<OutputIdentifier>) -> Result<bool, grin_chain::Error> {
        if b == self.archive {
            self.output.lock().map_err(|_| not_served())?.insert(s.identifier().idx, s);
            return Ok(true);
        }
        Ok(false)
    }
    fn receive_rangeproof_segment(&self, b: Hash, s: Segment<RangeProof>) -> Result<bool, grin_chain::Error> {
        if b == self.archive {
            self.rproof.lock().map_err(|_| not_served())?.insert(s.identifier().idx, s);
            return Ok(true);
        }
        Ok(false)
    }
    fn receive_kernel_segment(&self, b: Hash, s: Segment<TxKernel>) -> Result<bool, grin_chain::Error> {
        if b == self.archive {
            self.kernel.lock().map_err(|_| not_served())?.insert(s.identifier().idx, s);
            return Ok(true);
        }
        Ok(false)
    }
}

impl NetAdapter for FullAdapter {
    fn find_peer_addrs(&self, _c: Capabilities) -> Vec<PeerAddr> { vec![] }
    fn peer_addrs_received(&self, _p: Vec<PeerAddr>) {}
    fn peer_difficulty(&self, _a: PeerAddr, d: Difficulty, h: u64) {
        *self.peer_claim.lock().unwrap() = (h, d.to_num());
    }
    fn is_banned(&self, _a: PeerAddr) -> bool { false }
}

fn put_seg(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    let n = u32::try_from(bytes.len()).map_err(|_| "segment too large".to_string())?;
    out.extend_from_slice(&n.to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Fetch the complete archive state and return a GPF1 container.
pub fn fetch_full(
    peer_arg: &str,
    archive: Hash,
    header: &BlockHeader,
    bitmap_count: u64,
    output_count: u64,
    rproof_count: u64,
    kernel_count: u64,
) -> Result<Vec<u8>, String> {
    eprintln!("FULL_PIBD_START peer={peer_arg} bitmap={bitmap_count} output={output_count} rproof={rproof_count} kernel={kernel_count}");
    let conn = TcpStream::connect_timeout(
        &peer_arg.parse().map_err(|_| format!("peer must be IP:PORT, got {peer_arg}"))?,
        Duration::from_secs(15),
    ).map_err(|e| format!("connect {e}"))?;
    let local = conn.local_addr().map_err(|e| format!("local addr {e}"))?;
    let hs = Handshake::new(global::get_genesis_block().header.hash(), P2PConfig::default());
    let adapter = Arc::new(FullAdapter {
        archive,
        peer_claim: Arc::new(Mutex::new((0, 0))),
        bitmap: Mutex::new(BTreeMap::new()),
        output: Mutex::new(BTreeMap::new()),
        rproof: Mutex::new(BTreeMap::new()),
        kernel: Mutex::new(BTreeMap::new()),
    });
    let peer = Peer::connect(
        conn,
        Capabilities::default() | Capabilities::PIBD_HIST | Capabilities::PIBD_HIST_1,
        Difficulty::min_dma(),
        PeerAddr(local),
        &hs,
        adapter.clone(),
    ).map_err(|e| format!("handshake {e:?}"))?;

    eprintln!("FULL_PIBD_CONNECTED");
    let result = (|| {
        const WINDOW: u64 = 32;
        const WINDOW_TIMEOUT: Duration = Duration::from_secs(300);
        let mut sent = 0u64;
        while sent < bitmap_count {
            let end = (sent + WINDOW).min(bitmap_count);
            for idx in sent..end {
                peer.send_bitmap_segment_request(archive, SegmentIdentifier { height: 9, idx })
                    .map_err(|e| format!("bitmap request {idx}: {e:?}"))?;
                std::thread::sleep(MSG_INTERVAL);
            }
            sent = end;
            let _ = peer.send_ping(Difficulty::min_dma(), 0);
            let ws = Instant::now();
            loop {
                let n = adapter.bitmap.lock().map_err(|_| "bitmap lock")?.len() as u64;
                if n >= sent { break; }
                if ws.elapsed() > WINDOW_TIMEOUT {
                    return Err(format!("bitmap window timeout at {n}/{sent}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        let mut sent = 0u64;
        while sent < output_count {
            let end = (sent + WINDOW).min(output_count);
            for idx in sent..end {
                peer.send_output_segment_request(archive, SegmentIdentifier { height: 11, idx })
                    .map_err(|e| format!("output request {idx}: {e:?}"))?;
                std::thread::sleep(MSG_INTERVAL);
            }
            sent = end;
            let _ = peer.send_ping(Difficulty::min_dma(), 0);
            let ws = Instant::now();
            loop {
                let n = adapter.output.lock().map_err(|_| "output lock")?.len() as u64;
                if n >= sent { break; }
                if ws.elapsed() > WINDOW_TIMEOUT {
                    return Err(format!("output window timeout at {n}/{sent}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if sent % 32 == 0 {
                let got = adapter.output.lock().map_err(|_| "output lock")?.len();
                eprintln!("FULL_PIBD_OUTPUT_PROGRESS sent={sent}/{output_count} got={got}");
            }
        }
        let mut sent = 0u64;
        while sent < rproof_count {
            let end = (sent + WINDOW).min(rproof_count);
            for idx in sent..end {
                peer.send_rangeproof_segment_request(archive, SegmentIdentifier { height: 11, idx })
                    .map_err(|e| format!("rangeproof request {idx}: {e:?}"))?;
                std::thread::sleep(MSG_INTERVAL);
            }
            sent = end;
            let _ = peer.send_ping(Difficulty::min_dma(), 0);
            let ws = Instant::now();
            loop {
                let n = adapter.rproof.lock().map_err(|_| "rproof lock")?.len() as u64;
                if n >= sent { break; }
                if ws.elapsed() > WINDOW_TIMEOUT {
                    return Err(format!("rproof window timeout at {n}/{sent}"));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if sent % 32 == 0 {
                let got = adapter.rproof.lock().map_err(|_| "rproof lock")?.len();
                eprintln!("FULL_PIBD_RPROOF_PROGRESS sent={sent}/{rproof_count} got={got}");
            }
        }
        if kernel_count > 0 {
            peer.send_kernel_segment_request(archive, SegmentIdentifier { height: 11, idx: kernel_count - 1 })
                .map_err(|e| format!("kernel request: {e:?}"))?;
        }

        let start = Instant::now();
        loop {
            let b = adapter.bitmap.lock().map_err(|_| "bitmap lock")?.len() as u64;
            let o = adapter.output.lock().map_err(|_| "output lock")?.len() as u64;
            let r = adapter.rproof.lock().map_err(|_| "rproof lock")?.len() as u64;
            let k = adapter.kernel.lock().map_err(|_| "kernel lock")?.len() as u64;
            if (b + o + r).wrapping_sub(0) % 1000 == 0 { eprintln!("FULL_PIBD_PROGRESS b={b} o={o} r={r} k={k}"); }
            if b >= bitmap_count && o >= output_count && r >= rproof_count && k >= kernel_count.min(1) {
                break;
            }
            if start.elapsed() > FETCH_TIMEOUT {
                return Err(format!(
                    "segment timeout: bitmap {b}/{bitmap_count}, output {o}/{output_count}, rproof {r}/{rproof_count}, kernel {k}/{kernel_count}"
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let hraw = ser::ser_vec(header, ProtocolVersion::local()).map_err(|e| format!("header ser {e:?}"))?;
        let mut out = b"GPF1".to_vec();
        put_seg(&mut out, &hraw)?;
        out.extend_from_slice(&(bitmap_count as u32).to_le_bytes());
        {
            let m = adapter.bitmap.lock().map_err(|_| "bitmap lock")?;
            for idx in 0..bitmap_count {
                let s = m.get(&idx).ok_or(format!("bitmap {idx} missing"))?;
                let wire = BitmapSegment::from(s.clone());
                let bytes = ser::ser_vec(&wire, ProtocolVersion::local()).map_err(|e| format!("bitmap ser {e:?}"))?;
                put_seg(&mut out, &bytes)?;
            }
        }
        out.extend_from_slice(&(output_count as u32).to_le_bytes());
        {
            let m = adapter.output.lock().map_err(|_| "output lock")?;
            eprintln!("FULL_PIBD_OUTPUT_REQUESTS");
        for idx in 0..output_count {
                let s = m.get(&idx).ok_or(format!("output {idx} missing"))?;
                let bytes = ser::ser_vec(s, ProtocolVersion::local()).map_err(|e| format!("output ser {e:?}"))?;
                put_seg(&mut out, &bytes)?;
            }
        }
        out.extend_from_slice(&(rproof_count as u32).to_le_bytes());
        {
            let m = adapter.rproof.lock().map_err(|_| "rproof lock")?;
            eprintln!("FULL_PIBD_RPROOF_REQUESTS");
        for idx in 0..rproof_count {
                let s = m.get(&idx).ok_or(format!("rproof {idx} missing"))?;
                let bytes = ser::ser_vec(s, ProtocolVersion::local()).map_err(|e| format!("rproof ser {e:?}"))?;
                put_seg(&mut out, &bytes)?;
            }
        }
        out.extend_from_slice(&(kernel_count as u32).to_le_bytes());
        {
            let m = adapter.kernel.lock().map_err(|_| "kernel lock")?;
            for idx in 0..kernel_count {
                if let Some(s) = m.get(&idx) {
                    let bytes = ser::ser_vec(s, ProtocolVersion::local()).map_err(|e| format!("kernel ser {e:?}"))?;
                    put_seg(&mut out, &bytes)?;
                } else {
                    put_seg(&mut out, &[])?;
                }
            }
        }
        Ok(out)
    })();
    peer.stop();
    let _ = peer.wait();
    result
}
