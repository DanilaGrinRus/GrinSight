//! Archive -> tip gap experiment (RESEARCH / NOT VERIFIED).
//!
//! Two independent checks over the blocks between a PIBD archive header `A`
//! and the verified session tip:
//!
//! * scan  - fetch every block `A+1..=tip` from each peer, bind it to the
//!           validated header (full bytes), check output/kernel counts against
//!           the header MMR sizes and `Block::validate` (sums, signatures,
//!           rangeproofs). Look for the commitment among inputs/outputs and
//!           compare block bodies across peers. NOT bound to `output_root`:
//!           Grin 5 inputs are bare commitments, so a peer can swap inputs
//!           (X -> X+D, Z -> Z-D) without breaking sums. Result is a hint.
//! * prove - download the whole output bitmap and output PMMR at `A` through
//!           ordinary PIBD segments, rebuild the leaf set, the UTXO index and
//!           the PMMR peaks locally, require the merged root to equal
//!           `A.output_root`, then apply every block body and require
//!           `output_mmr_size` and `output_root` to equal each header up to
//!           the tip. A body that hides or invents a spend cannot pass.
//!
//! Header authentication is the caller's job: the headers file must come from
//! a pinned, validated session transcript. This module re-checks linkage only.

use super::*;
use grinsight_state::outputs::*;
use grinsight_state::helper::HelperState;
use croaring::Bitmap;
use grin_chain::txhashset::BitmapSegment;
use grin_core::core::TxKernel;
use grin_util::secp::pedersen::Commitment;
use std::collections::BTreeMap;

const BITMAP_SEGMENT_HEIGHT: u8 = 9;
/// Largest rangeproof segment a Grin 5.5.2 node serves (7..12) that also
/// fits the 2*max_block_size message limit (2048 * 675 B).
const RPROOF_SEGMENT_HEIGHT: u8 = 11;
const BLOCK_WINDOW: usize = 32;

// ---------------------------------------------------------------------------
// Segment inbox used by `prove` (wired into SyncAdapter in main.rs)
// ---------------------------------------------------------------------------

pub(super) struct BulkInbox {
    hash: Hash,
    bitmap_height: u8,
    output_height: u8,
    want_bitmap: HashSet<u64>,
    want_output: HashSet<u64>,
    bitmap: Vec<(Hash, Segment<BitmapChunk>)>,
    output: Vec<(Hash, Segment<OutputIdentifier>)>,
    bytes: u64,
    want_rproof: HashSet<u64>,
    rproof: Vec<Segment<RangeProof>>,
    want_kernel: Option<u64>,
    kernel: Option<Segment<TxKernel>>,
    want_kernels: HashSet<u64>,
    kernels: Vec<Segment<TxKernel>>,
}

impl BulkInbox {
    pub(super) fn accept_bitmap(&mut self, b: Hash, root: Hash, s: Segment<BitmapChunk>) -> bool {
        let id = s.identifier();
        if b != self.hash || id.height != self.bitmap_height || !self.want_bitmap.remove(&id.idx) {
            return false;
        }
        self.bytes += ser::ser_vec(&BitmapSegment::from(s.clone()), ProtocolVersion::local())
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        self.bitmap.push((root, s));
        true
    }
    pub(super) fn accept_kernel(&mut self, b: Hash, s: Segment<TxKernel>) -> bool {
        let id = s.identifier();
        if b != self.hash || id.height != KERNEL_SEGMENT_HEIGHT {
            return false;
        }
        let wanted_one = self.want_kernel == Some(id.idx);
        let wanted_many = self.want_kernels.remove(&id.idx);
        if !wanted_one && !wanted_many {
            return false;
        }
        if wanted_one {
            self.want_kernel = None;
            self.kernel = Some(s.clone());
        }
        self.kernels.push(s);
        true
    }
    pub(super) fn accept_rproof(&mut self, b: Hash, s: Segment<RangeProof>) -> bool {
        let id = s.identifier();
        if b != self.hash || id.height != RPROOF_SEGMENT_HEIGHT || !self.want_rproof.remove(&id.idx) {
            return false;
        }
        self.bytes += ser::ser_vec(&s, ProtocolVersion::local()).map(|v| v.len() as u64).unwrap_or(0);
        self.rproof.push(s);
        true
    }
    pub(super) fn accept_output(&mut self, b: Hash, root: Hash, s: Segment<OutputIdentifier>) -> bool {
        let id = s.identifier();
        if b != self.hash || id.height != self.output_height || !self.want_output.remove(&id.idx) {
            return false;
        }
        self.bytes += ser::ser_vec(&s, ProtocolVersion::local()).map(|v| v.len() as u64).unwrap_or(0);
        self.output.push((root, s));
        true
    }
}

struct Rate {
    interval: Duration,
    next: Instant,
}

impl Rate {
    fn new(per_min: u64) -> Self {
        Rate { interval: Duration::from_millis(60_000 / per_min.max(1)), next: Instant::now() }
    }
    fn wait(&mut self) {
        let now = Instant::now();
        if self.next > now {
            std::thread::sleep(self.next - now);
        }
        self.next = self.next.max(now) + self.interval;
    }
}

/// `Conn::open_or_abort` gave up because the work was already done elsewhere.
const ABORTED: &str = "aborted: work finished by other peers";

struct Conn {
    peer: Peer,
    blocks: Arc<Mutex<Vec<core::Block>>>,
    wanted: Arc<Mutex<HashSet<Hash>>>,
    segments: Arc<Mutex<SegmentInbox>>,
}

impl Conn {
    /// A Grin node refuses an inbound connection from an IP it still lists as
    /// connected (`check_undesirable`, port ignored for non-loopback). Right
    /// after a previous connection to the same node (sync, block fetch) that
    /// shows up as EOF during the handshake, so retry with a pause.
    fn open(peer_arg: &str, caps: Capabilities) -> Result<Self, String> {
        Self::open_or_abort(peer_arg, caps, &|| false)
    }
    /// Like `open`, but stops waiting between retries as soon as `abort()`
    /// is true (the shared work pool was finished by other peers): a peer
    /// that still refuses our reconnect must not hold the whole step.
    fn open_or_abort(peer_arg: &str, caps: Capabilities, abort: &dyn Fn() -> bool) -> Result<Self, String> {
        let mut last = String::new();
        for attempt in 0..6 {
            if attempt > 0 {
                // A refused/unreachable TCP connect (node down) is retried once;
                // only a handshake refusal (still-listed previous connection)
                // needs the full series of pauses.
                if last.starts_with("connect") && attempt >= 2 {
                    break;
                }
                println!("GAP_RECONNECT={peer_arg} attempt={} after: {last}", attempt + 1);
                // A Grin node forgets a closed connection at its next peer clean-up
                // (every 20 s): retry every 7 s three times, then every 20 s.
                let pause = Duration::from_secs(if last.starts_with("connect") { 5 } else if attempt <= 3 { 7 } else { 20 });
                let until = Instant::now() + pause;
                while Instant::now() < until {
                    if abort() {
                        return Err(ABORTED.into());
                    }
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
            match Self::open_once(peer_arg, caps) {
                Ok(c) => return Ok(c),
                Err(e) => last = e,
            }
        }
        Err(last)
    }
    fn open_once(peer_arg: &str, caps: Capabilities) -> Result<Self, String> {
        Self::open_once_t(peer_arg, caps, Duration::from_secs(15))
    }
    fn open_once_t(peer_arg: &str, caps: Capabilities, timeout: Duration) -> Result<Self, String> {
        let conn = TcpStream::connect_timeout(
            &peer_arg.parse().map_err(|_| format!("peer must be IP:PORT, got {peer_arg}"))?,
            timeout,
        )
        .map_err(|e| format!("connect {e}"))?;
        let local = conn.local_addr().map_err(|e| format!("local addr {e}"))?;
        let hs = Handshake::new(global::get_genesis_block().header.hash(), P2PConfig::default());
        let blocks = Arc::new(Mutex::new(Vec::new()));
        let wanted = Arc::new(Mutex::new(HashSet::new()));
        let segments = Arc::new(Mutex::new(SegmentInbox::default()));
        let adapter = Arc::new(SyncAdapter {
            peer_claim: Arc::new(Mutex::new((0, 0))),
            headers: Arc::new(Mutex::new(Vec::new())),
            blocks: blocks.clone(),
            wanted: wanted.clone(),
            segments: segments.clone(),
            outgoing_tx: Arc::new(Mutex::new(None)),
        });
        let peer = Peer::connect(conn, caps, Difficulty::min_dma(), PeerAddr(local), &hs, adapter)
            .map_err(|e| format!("handshake {e:?}"))?;
        Ok(Conn { peer, blocks, wanted, segments })
    }
    /// Open a connection for PIBD segment requests. A peer that does not
    /// advertise PIBD_HIST in its handshake (e.g. Grin++ on mainnet) silently
    /// ignores segment requests, so fail at once instead of waiting for a
    /// timeout; the callers then fall back to the next peer.
    fn open_pibd_or_abort(peer_arg: &str, abort: &dyn Fn() -> bool) -> Result<Self, String> {
        let c = Self::open_or_abort(peer_arg, Capabilities::default() | Capabilities::PIBD_HIST | Capabilities::PIBD_HIST_1, abort)?;
        let caps = c.peer.info.capabilities;
        if !caps.contains(Capabilities::PIBD_HIST) {
            let agent = c.peer.info.user_agent.clone();
            c.close();
            return Err(format!("peer does not advertise PIBD_HIST (caps=0x{:x}, agent={agent})", caps.bits()));
        }
        Ok(c)
    }
    fn close(self) {
        self.peer.stop();
        let _ = self.peer.wait();
    }
}


#[cfg(test)]
static SKIP_BODY_VALIDATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn check_block(prev: &BlockHeader, hdr: &BlockHeader, b: &core::Block) -> Result<(), String> {
    
#[cfg(test)]
    if SKIP_BODY_VALIDATE.load(std::sync::atomic::Ordering::Relaxed) {
        // Synthetic test bodies have no real rangeproofs/kernels; keep the
        // header-bytes binding, skip `Block::validate`.
        if header_bytes(hdr) != header_bytes(&b.header) {
            return Err("test: header bytes differ".into());
        }
    } else {
        bind_block(hdr, Some(prev), b)?;
    }
    #[cfg(not(test))]
    bind_block(hdr, Some(prev), b)?;
    let outs = hdr.output_mmr_count().saturating_sub(prev.output_mmr_count());
    let kerns = hdr.kernel_mmr_count().saturating_sub(prev.kernel_mmr_count());
    if b.outputs().len() as u64 != outs || b.kernels().len() as u64 != kerns {
        return Err(format!("block {} output/kernel counts differ from header MMR sizes", hdr.height));
    }
    Ok(())
}

/// One HEADER_PROOF_HIST peer found by DNS-seed discovery.
pub struct HeaderProofPeer {
    pub addr: String,
    pub agent: String,
    pub height: u64,
}

/// Resolve the network seeds, handshake in parallel, and keep peers that set
/// the raw HEADER_PROOF_HIST bit 0x100. Empty list is not an error.
pub fn find_header_proof_peers(mainnet: bool, extra: &[String]) -> (usize, Vec<HeaderProofPeer>) {
    use grinsight_state::session::{dns_resolve, seed_peers, FLOONET_DNS_SEEDS, MAINNET_DNS_SEEDS};
    let (seeds, port) = if mainnet {
        (MAINNET_DNS_SEEDS, 3414u16)
    } else {
        (FLOONET_DNS_SEEDS, 13414u16)
    };
    let answers: Vec<Vec<std::net::IpAddr>> = seeds
        .iter()
        .map(|s| dns_resolve(s, port).unwrap_or_default())
        .collect();
    let mut candidates = seed_peers(&answers, port, 64);
    for p in extra {
        if !candidates.contains(p) {
            candidates.push(p.clone());
        }
    }
    let found = std::sync::Mutex::new(Vec::new());
    let checked = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for addr in &candidates {
            let addr = addr.clone();
            let found = &found;
            let checked = &checked;
            scope.spawn(move || {
                let Ok(c) = Conn::open_once_t(&addr, Capabilities::default() | Capabilities::PIBD_HIST, PROBE_CONNECT_TIMEOUT) else { return };
                checked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let info = &c.peer.info;
                if (info.capabilities.bits() & 0x100) != 0 {
                    found.lock().unwrap().push(HeaderProofPeer {
                        addr,
                        agent: info.user_agent.clone(),
                        height: info.height(),
                    });
                }
                c.close();
            });
        }
    });
    (checked.load(std::sync::atomic::Ordering::Relaxed), found.into_inner().unwrap())
}

/// Handshake with each peer and print what it advertises: user agent,
/// protocol version, capabilities and whether it can serve PIBD segments
/// (needed for `--prove` and the wallet rangeproof scan) and blocks.
pub fn probe(peers: &[String], discover: bool) -> bool {
    if discover {
        super::DISCOVERED.lock().unwrap().clear();
    }
    // All peers at once (one thread each, short connect timeout): a dead
    // address costs PROBE_CONNECT_TIMEOUT once instead of per peer.
    let results: Vec<(String, bool)> = std::thread::scope(|sc| {
        let hs: Vec<_> = peers.iter().map(|p| sc.spawn(move || probe_one(p, discover))).collect();
        hs.into_iter().map(|h| h.join().unwrap_or_else(|_| ("PROBE_PEER=? FAIL panic".into(), false))).collect()
    });
    let mut any_pibd = false;
    for (line, pibd) in &results {
        println!("{line}");
        any_pibd |= *pibd;
    }
    print_discovered(peers, discover);
    any_pibd
}

const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(6);

fn probe_one(p: &str, discover: bool) -> (String, bool) {
    {
        match Conn::open_once_t(p, Capabilities::default() | Capabilities::PIBD_HIST | Capabilities::PIBD_HIST_1, PROBE_CONNECT_TIMEOUT) {
            Ok(c) => {
                let i = &c.peer.info;
                let pibd = i.capabilities.contains(Capabilities::PIBD_HIST);
                let blocks = i.capabilities.contains(Capabilities::BLOCK_HIST);
                // HEADER_PROOF_HIST (bit 0x100) is not in the stock grin_p2p
                // Capabilities enum (it is our fork's PR #3963), so read the
                // raw bit: nodes with our patch advertise it.
                let header_proof = (i.capabilities.bits() & 0x100) != 0;
                let line = format!(
                    "PROBE_PEER={p} OK agent={:?} version={:?} caps=0x{:x} pibd={} block_hist={} header_proof={} total_difficulty={}",
                    i.user_agent,
                    i.version,
                    i.capabilities.bits(),
                    if pibd { "yes" } else { "no" },
                    if blocks { "yes" } else { "no" },
                    if header_proof { "yes" } else { "no" },
                    i.total_difficulty().to_num()
                );
                if discover {
                    // Ask for addresses of peers that serve PIBD; answers land in DISCOVERED.
                    let _ = c.peer.send_peer_request(Capabilities::PIBD_HIST);
                    // Fixed wait: probes run in parallel, so it is paid once per run.
                    std::thread::sleep(Duration::from_secs(3));
                }
                c.close();
                (line, pibd)
            }
            Err(e) => (format!("PROBE_PEER={p} FAIL {e}"), false),
        }
    }
}

fn print_discovered(peers: &[String], discover: bool) {
    if discover {
        let mut seen: Vec<String> = Vec::new();
        for a in super::DISCOVERED.lock().unwrap().iter() {
            let ip = a.0.ip();
            let public = match ip {
                std::net::IpAddr::V4(v) => !(v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified() || v.is_broadcast()),
                std::net::IpAddr::V6(v) => !(v.is_loopback() || v.is_unspecified() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80),
            };
            let t = a.0.to_string();
            if public && a.0.port() != 0 && !peers.contains(&t) && !seen.contains(&t) {
                seen.push(t);
            }
        }
        for t in &seen {
            println!("DISCOVERED_PEER={t}");
        }
        println!("PROBE_DISCOVERED={}", seen.len());
    }
}

/// Fetch and check blocks `headers[1..]` (headers[0] is the archive header).
fn fetch_blocks(peer_arg: &str, headers: &[BlockHeader], rate: &mut Rate) -> Result<Vec<core::Block>, String> {
    let c = Conn::open(peer_arg, Capabilities::default() | Capabilities::BLOCK_HIST)?;
    let result = (|| {
        let mut out: Vec<core::Block> = Vec::with_capacity(headers.len() - 1);
        for window in headers[1..].chunks(BLOCK_WINDOW) {
            c.blocks.lock().unwrap().clear();
            {
                let mut w = c.wanted.lock().unwrap();
                w.clear();
                w.extend(window.iter().map(|h| h.hash()));
            }
            for h in window {
                rate.wait();
                c.peer
                    .send_block_request(h.hash(), grin_chain::Options::NONE)
                    .map_err(|e| format!("getblock {}: {e:?}", h.height))?;
            }
            let deadline = Instant::now() + Duration::from_secs(60);
            while !c.wanted.lock().unwrap().is_empty() {
                if Instant::now() > deadline {
                    return Err(format!("block timeout near height {}", window[0].height));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let got: Vec<core::Block> = std::mem::take(&mut *c.blocks.lock().unwrap());
            for h in window {
                let b = got.iter().find(|b| b.header.hash() == h.hash()).ok_or(format!("block {} missing", h.height))?;
                let prev = if out.is_empty() { &headers[0] } else { &out.last().unwrap().header };
                check_block(prev, h, b)?;
                out.push(b.clone());
            }
        }
        Ok(out)
    })();
    c.close();
    result
}

/// Shared work pool for parallel downloads. Peers pull items one at a time
/// (each keeps only a small window in flight), so a slow peer holds back at
/// most its window. When no fresh item is left, an idle peer re-requests an
/// item still outstanding elsewhere (endgame); the first delivery wins.
struct WorkPool {
    total: usize,
    st: Mutex<PoolState>,
}

struct PoolState {
    queue: std::collections::VecDeque<u64>,
    all: Vec<u64>,
    done: HashSet<u64>,
}

impl WorkPool {
    fn new(items: Vec<u64>) -> Self {
        WorkPool {
            total: items.len(),
            st: Mutex::new(PoolState { queue: items.iter().copied().collect(), all: items, done: HashSet::new() }),
        }
    }
    /// Next item for a peer that has already asked for `asked`: a fresh item,
    /// else (endgame) an outstanding item this peer has not asked for yet.
    fn take(&self, asked: &HashSet<u64>) -> Option<u64> {
        let mut s = self.st.lock().unwrap();
        while let Some(i) = s.queue.pop_front() {
            if !s.done.contains(&i) && !asked.contains(&i) {
                return Some(i);
            }
        }
        s.all.iter().copied().find(|i| !s.done.contains(i) && !asked.contains(i))
    }
    /// Mark delivered; true only for the first delivery.
    fn complete(&self, i: u64) -> bool {
        self.st.lock().unwrap().done.insert(i)
    }
    fn finished(&self) -> bool {
        self.st.lock().unwrap().done.len() >= self.total
    }
    fn missing(&self) -> usize {
        self.total - self.st.lock().unwrap().done.len()
    }
}

/// Fetch blocks `headers[1..]` from several peers through a shared pool of
/// BLOCK_WINDOW-sized windows. Every block is bound to its validated header
/// (`check_block`) and later to output_root/kernel_root, so one source per
/// block suffices. Returns the blocks in height order.
fn fetch_blocks_split(peers: &[String], headers: &[BlockHeader], per_min: u64) -> Result<Vec<core::Block>, String> {
    let total = headers.len() - 1;
    let windows: Vec<(usize, usize)> = (0..total).step_by(BLOCK_WINDOW).map(|a| (a, (a + BLOCK_WINDOW).min(total))).collect();
    let pool = WorkPool::new((0..windows.len() as u64).collect());
    let got: Mutex<Vec<Option<core::Block>>> = Mutex::new(vec![None; total]);
    let results: Vec<(String, usize, Option<String>)> = std::thread::scope(|sc| {
        let hs: Vec<_> = peers
            .iter()
            .map(|p| {
                let (pool, got, windows) = (&pool, &got, &windows);
                sc.spawn(move || {
                    let (n, err) = fetch_block_windows(p, headers, windows, pool, got, &mut Rate::new(per_min));
                    (p.clone(), n, err)
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap_or_else(|_| ("?".into(), 0, Some("thread panic".into())))).collect()
    });
    for (p, n, err) in &results {
        println!("GAP_PEER_BLOCKS={p} n={n}{}", err.as_ref().map(|e| format!(" FAIL {e}")).unwrap_or_else(|| " OK".into()));
    }
    if !pool.finished() {
        let why: Vec<String> = results.iter().filter_map(|(p, _, e)| e.as_ref().map(|e| format!("{p}: {e}"))).take(4).collect();
        return Err(format!("{} block windows missing (all peers failed) [{}]", pool.missing(), why.join("; ")));
    }
    Ok(got.into_inner().unwrap().into_iter().map(|x| x.unwrap()).collect())
}

/// One peer's loop for `fetch_blocks_split`. Returns blocks delivered first
/// by this peer and the error that stopped it, if any.
fn fetch_block_windows(
    peer_arg: &str,
    headers: &[BlockHeader],
    windows: &[(usize, usize)],
    pool: &WorkPool,
    got: &Mutex<Vec<Option<core::Block>>>,
    rate: &mut Rate,
) -> (usize, Option<String>) {
    if pool.finished() {
        return (0, None);
    }
    let c = match Conn::open_or_abort(peer_arg, Capabilities::default() | Capabilities::BLOCK_HIST, &|| pool.finished()) {
        Ok(c) => c,
        Err(e) if e == ABORTED => return (0, None),
        Err(e) => return (0, Some(e)),
    };
    let (delivered, result) = block_windows_on(&c, headers, windows, pool, got, rate);
    c.close();
    (delivered, result.err())
}

/// `fetch_block_windows` on an open connection (kept open by the caller).
fn block_windows_on(
    c: &Conn,
    headers: &[BlockHeader],
    windows: &[(usize, usize)],
    pool: &WorkPool,
    got: &Mutex<Vec<Option<core::Block>>>,
    rate: &mut Rate,
) -> (usize, Result<(), String>) {
    let mut delivered = 0usize;
    let mut asked: HashSet<u64> = HashSet::new();
    let result: Result<(), String> = (|| {
        loop {
            if pool.finished() {
                return Ok(());
            }
            let Some(wi) = pool.take(&asked) else {
                // Everything left is in flight at other peers and this peer
                // already asked for it: nothing more to do here.
                return Ok(());
            };
            asked.insert(wi);
            let (a, b) = windows[wi as usize];
            let window = &headers[a + 1..b + 1];
            c.blocks.lock().unwrap().clear();
            {
                let mut w = c.wanted.lock().unwrap();
                w.clear();
                w.extend(window.iter().map(|h| h.hash()));
            }
            for h in window {
                rate.wait();
                c.peer
                    .send_block_request(h.hash(), grin_chain::Options::NONE)
                    .map_err(|e| format!("getblock {}: {e:?}", h.height))?;
            }
            let deadline = Instant::now() + Duration::from_secs(60);
            while !c.wanted.lock().unwrap().is_empty() {
                if Instant::now() > deadline {
                    return Err(format!("block timeout near height {}", window[0].height));
                }
                if pool.finished() {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            let recv: Vec<core::Block> = std::mem::take(&mut *c.blocks.lock().unwrap());
            let mut checked = Vec::with_capacity(window.len());
            for (j, h) in window.iter().enumerate() {
                let blk = recv.iter().find(|x| x.header.hash() == h.hash()).ok_or(format!("block {} missing", h.height))?;
                check_block(&headers[a + j], h, blk)?;
                checked.push(blk.clone());
            }
            if pool.complete(wi) {
                let mut g = got.lock().unwrap();
                for (j, blk) in checked.into_iter().enumerate() {
                    g[a + j] = Some(blk);
                }
                delivered += b - a;
            }
        }
    })();
    (delivered, result)
}

/// Use the next archive when the current one stops being served within this
/// many blocks: a full rebuild (blocks + segments + rangeproofs) takes ~10 min.
const ARCHIVE_SWITCH_MARGIN: u64 = 25;

/// Wait (up to 30 min) until at least one peer serves `archive` (bitmap
/// segment 0 answered).
fn wait_archive_served(peers: &[String], archive: &BlockHeader, output_height: u8, per_min: u64) -> Result<(), String> {
    let (nb, _) = segment_counts(archive, output_height);
    let t0 = Instant::now();
    loop {
        for p in peers {
            let pool = WorkPool::new(vec![0]);
            let store: Mutex<SegStore> = Mutex::new(SegStore::default());
            let (n, _) = fetch_segments(p, archive, output_height, nb, &pool, &store, false, &mut Rate::new(per_min));
            if n > 0 {
                println!("GAP_ARCHIVE_SERVED={} by {p} after {} s", archive.height, t0.elapsed().as_secs());
                return Ok(());
            }
        }
        if t0.elapsed() > Duration::from_secs(1800) {
            return Err(format!("no peer serves archive {} after 30 min", archive.height));
        }
        println!("GAP_ARCHIVE_WAIT={} not served yet ({} s)", archive.height, t0.elapsed().as_secs());
        std::thread::sleep(Duration::from_secs(30));
    }
}

/// Number of bitmap and output segments of the archive.
fn segment_counts(archive: &BlockHeader, output_height: u8) -> (u64, u64) {
    let n = pmmr::n_leaves(archive.output_mmr_size);
    let bitmap_size = pmmr::insertion_to_pmmr_index(n.div_ceil(1024));
    let nb = SegmentIdentifier::count_segments_required(bitmap_size, BITMAP_SEGMENT_HEIGHT) as u64;
    let no = SegmentIdentifier::count_segments_required(archive.output_mmr_size, output_height) as u64;
    (nb, no)
}

/// Archive segments collected from all peers (merged freely: they are checked
/// later against the archive header roots).
#[derive(Default)]
struct SegStore {
    bitmap: BTreeMap<u64, Segment<BitmapChunk>>,
    output: BTreeMap<u64, Segment<OutputIdentifier>>,
    kernel: Option<Segment<TxKernel>>,
    bytes: u64,
}

/// Fetch the archive segments from several peers through a shared pool.
/// Pool items: bitmap segment `i` -> `i`, output segment `j` -> `nb + j`.
/// The last kernel segment (all kernel MMR peaks) comes from the first peer
/// that serves it.
fn fetch_segments_split(
    peers: &[String],
    archive: &BlockHeader,
    output_height: u8,
    per_min: u64,
) -> Result<(Vec<Segment<BitmapChunk>>, Vec<Segment<OutputIdentifier>>, u64, Option<Segment<TxKernel>>), String> {
    let (nb, no) = segment_counts(archive, output_height);
    let pool = WorkPool::new((0..nb + no).collect());
    let store: Mutex<SegStore> = Mutex::new(SegStore::default());
    let results: Vec<(String, usize, Option<String>)> = std::thread::scope(|sc| {
        let hs: Vec<_> = peers
            .iter()
            .enumerate()
            .map(|(k, p)| {
                let (pool, store) = (&pool, &store);
                sc.spawn(move || {
                    let (n, err) = fetch_segments(p, archive, output_height, nb, pool, store, k == 0, &mut Rate::new(per_min));
                    (p.clone(), n, err)
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap_or_else(|_| ("?".into(), 0, Some("thread panic".into())))).collect()
    });
    for (p, n, err) in &results {
        println!("GAP_PROVE_SEGMENT_PEER={p} segments={n}{}", err.as_ref().map(|e| format!(" FAIL {e}")).unwrap_or_else(|| " OK".into()));
    }
    if !pool.finished() {
        if pool.missing() == pool.total {
            // Not a single segment from any peer: they no longer (or do not
            // yet) serve this archive header.
            return Err(format!("ARCHIVE_NOT_SERVED {} archive segments missing", pool.missing()));
        }
        return Err(format!("{} archive segments missing (all peers failed)", pool.missing()));
    }
    // Kernel segment not served by the first peer: ask the others in turn.
    if store.lock().unwrap().kernel.is_none() {
        let done = WorkPool::new(Vec::new());
        for (p, _, err) in &results {
            if err.is_some() {
                continue;
            }
            let _ = fetch_segments(p, archive, output_height, nb, &done, &store, true, &mut Rate::new(per_min));
            if store.lock().unwrap().kernel.is_some() {
                break;
            }
        }
    }
    let s = store.into_inner().unwrap();
    Ok((s.bitmap.into_values().collect(), s.output.into_values().collect(), s.bytes, s.kernel))
}

/// One peer's loop for `fetch_segments_split`: keep up to 16 segment requests
/// in flight from the shared pool; with `want_kernel`, also fetch the last
/// kernel segment at the end. Returns segments delivered first by this peer.
#[allow(clippy::too_many_arguments)]
fn fetch_segments(
    peer_arg: &str,
    archive: &BlockHeader,
    output_height: u8,
    nb: u64,
    pool: &WorkPool,
    store: &Mutex<SegStore>,
    want_kernel: bool,
    rate: &mut Rate,
) -> (usize, Option<String>) {
    eprintln!("DBG seg open {peer_arg}");
    let c = match Conn::open_pibd_or_abort(peer_arg, &|| pool.finished()) {
        Ok(c) => c,
        Err(e) if e == ABORTED => return (0, None),
        Err(e) => { eprintln!("DBG seg open err {peer_arg}: {e}"); return (0, Some(e)); }
    };
    eprintln!("DBG seg opened {peer_arg}");
    let (delivered, result) = segments_on(&c, archive, output_height, nb, pool, store, want_kernel, rate);
    c.close();
    (delivered, result.err())
}

/// `fetch_segments` on an open connection (kept open by the caller).
#[allow(clippy::too_many_arguments)]
fn segments_on(
    c: &Conn,
    archive: &BlockHeader,
    output_height: u8,
    nb: u64,
    pool: &WorkPool,
    store: &Mutex<SegStore>,
    want_kernel: bool,
    rate: &mut Rate,
) -> (usize, Result<(), String>) {
    let hash = archive.hash();
    {
        let mut inbox = c.segments.lock().unwrap();
        inbox.bulk = Some(BulkInbox {
            hash,
            bitmap_height: BITMAP_SEGMENT_HEIGHT,
            output_height,
            want_bitmap: HashSet::new(),
            want_output: HashSet::new(),
            bitmap: Vec::new(),
            output: Vec::new(),
            bytes: 0,
            want_rproof: HashSet::new(),
            rproof: Vec::new(),
            want_kernel: None,
            kernel: None,
            want_kernels: HashSet::new(),
            kernels: Vec::new(),
        });
    }
    let mut delivered = 0usize;
    let mut received_any = false;
    let result: Result<(), String> = (|| {
        let mut asked: HashSet<u64> = HashSet::new();
        let mut last_progress = Instant::now();
        loop {
            // Drain what arrived into the shared store.
            let (bm, out, pending, bytes) = {
                let mut i = c.segments.lock().unwrap();
                let b = i.bulk.as_mut().unwrap();
                let bytes = std::mem::take(&mut b.bytes);
                (std::mem::take(&mut b.bitmap), std::mem::take(&mut b.output), b.want_bitmap.len() + b.want_output.len(), bytes)
            };
            if !bm.is_empty() || !out.is_empty() {
                received_any = true;
                last_progress = Instant::now();
            }
            {
                let mut st = store.lock().unwrap();
                st.bytes += bytes;
                for (_, sgm) in bm {
                    let idx = sgm.identifier().idx;
                    if pool.complete(idx) {
                        st.bitmap.insert(idx, sgm);
                        delivered += 1;
                    }
                }
                for (_, sgm) in out {
                    let idx = sgm.identifier().idx;
                    if pool.complete(nb + idx) {
                        st.output.insert(idx, sgm);
                        delivered += 1;
                    }
                }
            }
            if pool.finished() {
                break;
            }
            let mut pending = pending;
            while pending < 16 {
                let Some(item) = pool.take(&asked) else { break };
                asked.insert(item);
                rate.wait();
                let r = if item < nb {
                    c.segments.lock().unwrap().bulk.as_mut().unwrap().want_bitmap.insert(item);
                    c.peer.send_bitmap_segment_request(hash, SegmentIdentifier { height: BITMAP_SEGMENT_HEIGHT, idx: item })
                } else {
                    c.segments.lock().unwrap().bulk.as_mut().unwrap().want_output.insert(item - nb);
                    c.peer.send_output_segment_request(hash, SegmentIdentifier { height: output_height, idx: item - nb })
                };
                r.map_err(|e| format!("segment request: {e:?}"))?;
                pending += 1;
            }
            if pending == 0 {
                // Everything left is in flight at other peers.
                break;
            }
            if !received_any && last_progress.elapsed() > Duration::from_secs(30) {
                return Err(format!("nothing received in 30 s ({pending} pending; archive not served)"));
            }
            if last_progress.elapsed() > Duration::from_secs(60) {
                return Err(format!("segments stalled ({pending} pending)"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Last kernel segment: gives every kernel MMR peak at the archive.
        if want_kernel && store.lock().unwrap().kernel.is_none() {
            let kidx = SegmentIdentifier::count_segments_required(archive.kernel_mmr_size, KERNEL_SEGMENT_HEIGHT) as u64 - 1;
            c.segments.lock().unwrap().bulk.as_mut().unwrap().want_kernel = Some(kidx);
            rate.wait();
            let sent_k = c.peer.send_kernel_segment_request(hash, SegmentIdentifier { height: KERNEL_SEGMENT_HEIGHT, idx: kidx }).is_ok();
            let deadline = Instant::now() + Duration::from_secs(30);
            while sent_k && Instant::now() < deadline && c.segments.lock().unwrap().bulk.as_ref().unwrap().kernel.is_none() {
                std::thread::sleep(Duration::from_millis(50));
            }
            let k = c.segments.lock().unwrap().bulk.as_mut().unwrap().kernel.take();
            let mut st = store.lock().unwrap();
            if st.kernel.is_none() {
                st.kernel = k;
            }
        }
        Ok(())
    })();
    (delivered, result)
}

/// One peer's loop of the rangeproof scan: pull rangeproof segment indexes
/// for `archive` from the shared pool (up to 8 in flight), validate each
/// against `archive.range_proof_root` with the archive leaf set, and hand the
/// first delivery of each segment to `sink` (2 GB on Floonet: streamed, never
/// held in full). Returns (bytes received, segments delivered first).
fn fetch_rproofs(
    peer_arg: &str,
    archive: &BlockHeader,
    leaves: &Bitmap,
    pool: &WorkPool,
    rate: &mut Rate,
    sink: &(dyn Fn(u64, Vec<(u64, RangeProof)>) + Sync),
    collect: Option<&Mutex<Vec<Segment<RangeProof>>>>,
) -> Result<(u64, usize), String> {
    if pool.finished() {
        return Ok((0, 0));
    }
    let c = match Conn::open_pibd_or_abort(peer_arg, &|| pool.finished()) {
        Ok(c) => c,
        Err(e) if e == ABORTED => return Ok((0, 0)),
        Err(e) => return Err(e),
    };
    let r = rproofs_on(&c, peer_arg, archive, leaves, pool, rate, sink, collect);
    c.close();
    r
}

/// `fetch_rproofs` on an open connection (kept open by the caller).
fn rproofs_on(
    c: &Conn,
    peer_arg: &str,
    archive: &BlockHeader,
    leaves: &Bitmap,
    pool: &WorkPool,
    rate: &mut Rate,
    sink: &(dyn Fn(u64, Vec<(u64, RangeProof)>) + Sync),
    collect: Option<&Mutex<Vec<Segment<RangeProof>>>>,
) -> Result<(u64, usize), String> {
    if pool.finished() {
        return Ok((0, 0));
    }
    let hash = archive.hash();
    {
        let mut inbox = c.segments.lock().unwrap();
        inbox.bulk = Some(BulkInbox {
            hash,
            bitmap_height: 0,
            output_height: 0,
            want_bitmap: HashSet::new(),
            want_output: HashSet::new(),
            bitmap: Vec::new(),
            output: Vec::new(),
            bytes: 0,
            want_rproof: HashSet::new(),
            rproof: Vec::new(),
            want_kernel: None,
            kernel: None,
            want_kernels: HashSet::new(),
            kernels: Vec::new(),
        });
    }
    let result = (|| {
        let mut asked: HashSet<u64> = HashSet::new();
        let mut delivered = 0usize;
        let mut received = 0usize;
        let mut last_progress = Instant::now();
        loop {
            let (got, pending) = {
                let mut i = c.segments.lock().unwrap();
                let b = i.bulk.as_mut().unwrap();
                (std::mem::take(&mut b.rproof), b.want_rproof.len())
            };
            for s in got {
                s.validate(archive.output_mmr_size, Some(leaves), archive.range_proof_root)
                    .map_err(|e| format!("rangeproof segment {} invalid: {e:?}", s.identifier().idx))?;
                if let Some(c) = collect {
                    c.lock().unwrap().push(s.clone());
                }
                received += 1;
                last_progress = Instant::now();
                if pool.complete(s.identifier().idx) {
                    sink(s.identifier().idx, s.leaf_iter().map(|(p, rp)| (p, *rp)).collect());
                    delivered += 1;
                    if delivered % 100 == 0 {
                        println!("GAP_SCAN_RPROOF_PROGRESS={peer_arg} {delivered} (left {})", pool.missing());
                    }
                }
            }
            if pool.finished() {
                break;
            }
            let mut pending = pending;
            while pending < 8 {
                let Some(idx) = pool.take(&asked) else { break };
                asked.insert(idx);
                c.segments.lock().unwrap().bulk.as_mut().unwrap().want_rproof.insert(idx);
                rate.wait();
                c.peer
                    .send_rangeproof_segment_request(hash, SegmentIdentifier { height: RPROOF_SEGMENT_HEIGHT, idx })
                    .map_err(|e| format!("rangeproof request: {e:?}"))?;
                pending += 1;
            }
            if pending == 0 {
                // Everything left is in flight at other peers.
                break;
            }
            if received == 0 && last_progress.elapsed() > Duration::from_secs(30) {
                return Err(format!("rangeproof segments: nothing received in 30 s ({pending} pending)"));
            }
            if last_progress.elapsed() > Duration::from_secs(60) {
                return Err(format!("rangeproof segments stalled ({pending} pending)"));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let i = c.segments.lock().unwrap();
        Ok((i.bulk.as_ref().unwrap().bytes, delivered))
    })();
    result
}


/// Fetch every kernel segment of the archive from one peer and validate each
/// against `kernel_root`. Used by the helper bootstrap, not by `--prove`
/// (which needs only the last segment for peaks).
fn fetch_all_kernels(peer_arg: &str, archive: &BlockHeader, per_min: u64) -> Result<Vec<Segment<TxKernel>>, String> {
    let count = SegmentIdentifier::count_segments_required(archive.kernel_mmr_size, KERNEL_SEGMENT_HEIGHT) as u64;
    if count == 0 {
        return Err("archive has no kernel segments".into());
    }
    let c = Conn::open_pibd_or_abort(peer_arg, &|| false)?;
    let result = (|| {
        {
            let mut inbox = c.segments.lock().unwrap();
            inbox.bulk = Some(BulkInbox {
                hash: archive.hash(),
                bitmap_height: 0,
                output_height: 0,
                want_bitmap: HashSet::new(),
                want_output: HashSet::new(),
                bitmap: Vec::new(),
                output: Vec::new(),
                bytes: 0,
                want_rproof: HashSet::new(),
                rproof: Vec::new(),
                want_kernel: None,
                kernel: None,
                want_kernels: HashSet::new(),
                kernels: Vec::new(),
            });
        }
        let mut asked: HashSet<u64> = HashSet::new();
        let mut got: BTreeMap<u64, Segment<TxKernel>> = BTreeMap::new();
        let mut rate = Rate::new(per_min);
        let mut last_progress = Instant::now();
        loop {
            let (batch, pending) = {
                let mut inbox = c.segments.lock().unwrap();
                let b = inbox.bulk.as_mut().unwrap();
                (std::mem::take(&mut b.kernels), b.want_kernels.len())
            };
            for s in batch {
                got.insert(s.identifier().idx, s);
                last_progress = Instant::now();
            }
            if got.len() as u64 >= count {
                break;
            }
            let mut pending = pending;
            while pending < 8 {
                let Some(idx) = (0..count).find(|i| !asked.contains(i) && !got.contains_key(i)) else { break };
                asked.insert(idx);
                c.segments.lock().unwrap().bulk.as_mut().unwrap().want_kernels.insert(idx);
                rate.wait();
                c.peer
                    .send_kernel_segment_request(archive.hash(), SegmentIdentifier { height: KERNEL_SEGMENT_HEIGHT, idx })
                    .map_err(|e| format!("kernel segment request: {e:?}"))?;
                pending += 1;
            }
            if pending == 0 {
                break;
            }
            if last_progress.elapsed() > Duration::from_secs(60) {
                return Err(format!("kernel segments stalled ({}/{} received)", got.len(), count));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if got.len() as u64 != count {
            return Err(format!("kernel segments {} != expected {count}", got.len()));
        }
        let segments: Vec<_> = got.into_values().collect();
        for s in &segments {
            s.validate(archive.kernel_mmr_size, None, archive.kernel_root)
                .map_err(|e| format!("kernel segment {} invalid: {e:?}", s.identifier().idx))?;
        }
        Ok(segments)
    })();
    c.close();
    result
}

/// Fetch every rangeproof segment from one peer and keep the segments so the
/// archive verifier can check `range_proof_root` and each proof.
fn fetch_all_rproofs(peer_arg: &str, archive: &BlockHeader, leaves: &Bitmap, per_min: u64) -> Result<Vec<Segment<RangeProof>>, String> {
    let count = SegmentIdentifier::count_segments_required(archive.output_mmr_size, RPROOF_SEGMENT_HEIGHT) as u64;
    if count == 0 {
        return Err("archive has no rangeproof segments".into());
    }
    let pool = WorkPool::new((0..count).collect());
    let collected: Mutex<Vec<Segment<RangeProof>>> = Mutex::new(Vec::new());
    fetch_rproofs(peer_arg, archive, leaves, &pool, &mut Rate::new(per_min), &|_, _| {}, Some(&collected))?;
    if pool.finished() {
        Ok(collected.into_inner().unwrap())
    } else {
        Err(format!("{} rangeproof segments missing", pool.missing()))
    }
}

/// Stage-1 helper bootstrap: fetch bitmap/output/all rangeproofs/all kernels
/// for `archive` and run the full `grinsight-state` archive verification.
pub(super) fn bootstrap_verified_archive(
    peers: &[String],
    archive: &BlockHeader,
    output_height: u8,
    per_min: u64,
  ) -> Result<(VerifiedArchive, Vec<Segment<RangeProof>>, Option<Segment<TxKernel>>, Vec<Segment<OutputIdentifier>>), String> {
    eprintln!("DBG bootstrap peers={} archive={} hash={}", peers.len(), archive.height, archive.hash());
    let peer = peers.first().ok_or("at least one --peer is required")?;
    eprintln!("DBG bootstrap fetching segments from {}", peer);
    let (bitmap, output, _, _) = fetch_segments_split(peers, archive, output_height, per_min)?;
    eprintln!("DBG bootstrap segments ok bitmap={} output={}", bitmap.len(), output.len());
    let state0 = OutputState::from_segments(archive, &bitmap, &output)?;
    let rangeproofs = fetch_all_rproofs(peer, archive, &state0.leaves, per_min)?;
    let kernels = fetch_all_kernels(peer, archive, per_min)?;
    let verified = build_verified_archive_state(archive, &bitmap, &output, &rangeproofs, &kernels)?;
    let kernel_last = kernels.last().cloned();
    println!(
        "HELPER_BOOTSTRAP=VERIFIED height={} utxo={} kernels={} rangeproofs={}",
        archive.height, verified.state.utxo_count(), verified.kernels, verified.rangeproofs
    );
    println!("NODE_SUPPLY=VERIFIED height={}", archive.height);
    Ok((verified, rangeproofs, kernel_last, output))
}
pub(super) struct Opts<'a> {
    pub headers: &'a str,
    pub commitments: Vec<String>,
    pub peers: Vec<String>,
    pub prove: bool,
    pub out: Option<&'a str>,
    pub replay: Option<&'a str>,
    pub segment_height: u8,
    pub per_min: u64,
    /// Height of the PIBD archive header inside `headers` (default: first header).
    pub archive: Option<u64>,
    /// Directory holding `state.ust` (+ `state.prev.ust`); needs `prove`.
    pub state_dir: Option<&'a str>,
    /// Seed phrase file: discover own outputs (rangeproof rewind).
    pub seeds: Option<&'a str>,
    pub wallet_out: Option<&'a str>,
    /// Known own outputs (a previous --gap-wallet-out at the saved state's
    /// height): with a saved state, only new blocks are scanned for own outputs
    /// (no rangeproof download): the everyday "open the wallet" path.
    pub wallet_in: Option<&'a str>,
    /// Pending receives (keys promised to senders, not yet seen on chain):
    /// a self-spend never reuses their keys.
    pub pending: Option<&'a str>,
    /// Pay to a slatepack address instead of a self-transfer: amount in
    /// nanogrin, the S1 slatepack and the sender context (signing secrets of
    /// this one transaction) are written to these files.
    pub send_to: Option<&'a str>,
    pub send_amount: Option<u64>,
    pub slatepack_out: Option<&'a str>,
    pub context_out: Option<&'a str>,
    /// Pay an invoice (I1 slatepack file); the I2 answer goes to slatepack_out.
    pub pay_invoice: Option<&'a str>,
    /// `auto:N` (wallet N, 1-based) or an own commitment hex.
    pub spend: Option<&'a str>,
    pub broadcast: bool,
    pub allow_mainnet_spend: bool,
    pub tx_out: Option<&'a str>,
    /// Kernel excesses to look for in the proven blocks.
    pub kernels: Vec<String>,
    /// `HEIGHT:HASH` of blocks confirmed in earlier runs: checked against the
    /// verified header chain of THIS session (a reorg may have removed them).
    pub check_blocks: Vec<String>,
    /// Fetch every block from every peer (cross-peer comparison) instead of
    /// splitting the range across peers.
    pub blocks_all_peers: bool,
    /// Stage-1 helper bootstrap: fetch all archive segments and verify them.
    pub bootstrap: bool,
    /// Store output segments too (adds ~2 GB; off by default).
    pub helper_output_segments: bool,
}

/// Returns the process exit code.
pub(super) fn run(o: Opts) -> Result<i32, String> {
    let run_start = Instant::now();
    let mut commits: Vec<Vec<u8>> = Vec::new();
    for c in &o.commitments {
        let b = grin_util::from_hex(c).map_err(|_| "invalid commitment hex")?;
        if b.len() != 33 {
            return Err("commitment must be 33 bytes".into());
        }
        commits.push(b);
    }
    if commits.is_empty() && !o.bootstrap {
        return Err("at least one --commitment is required".into());
    }
    if o.state_dir.is_some() && !o.prove && !o.bootstrap {
        return Err("--gap-state needs --prove".into());
    }
    let all = read_headers(o.headers)?;
    let tip = all.last().unwrap();
    let mut archive_idx = match o.archive {
        None => 0,
        Some(h) => all.iter().position(|x| x.height == h).ok_or("archive height not in headers")?,
    };
    let mut archive = &all[archive_idx];
    if o.bootstrap {
        let (verified, rangeproof_segments, kernel_last, output_segments) =
            bootstrap_verified_archive(&o.peers, archive, o.segment_height, o.per_min)?;
        let rangeproofs: Vec<(u64, RangeProof)> = rangeproof_segments
            .iter()
            .flat_map(|s| s.leaf_iter().map(|(p, rp)| (p, *rp)))
            .collect();
        let spent_outputs: Vec<(u64, OutputIdentifier)> = output_segments
            .iter()
            .flat_map(|s| s.leaf_iter())
            .filter(|(_, id)| !verified.state.utxo.contains_key(&id.commit.0))
            .map(|(p, id)| (p, *id))
            .collect();
        let utxo_count = verified.state.utxo_count();
        let kernel_count = verified.kernels;
        let rproof_count = verified.rangeproofs;
        if let Some(dir) = o.state_dir {
            std::fs::create_dir_all(dir).map_err(|e| format!("helper state dir: {e}"))?;
            let helper = HelperState {
                base: verified.state,
                header: archive.clone(),
                rangeproofs,
                coinbase_heights: Vec::new(),
                excess_sum: Vec::new(),
                offset_sum: Vec::new(),
                header_window: all[archive_idx..].to_vec(),
                rangeproof_segments,
                kernel_last,
                output_segments: if o.helper_output_segments {
                    output_segments
                } else {
                    Vec::new()
                },
                spent_outputs,
            };
            let path = format!("{dir}/helper.ust2");
            helper.save_split(&path)?;
            println!("HELPER_STATE_SAVED={path} height={}", archive.height);
        }
        println!(
            "HELPER_BOOTSTRAP_UTXO={} KERNELS={} RANGEPROOFS={}",
            utxo_count,
            kernel_count,
            rproof_count
        );
        return Ok(0);
    }
    println!("GAP_ARCHIVE_HEIGHT={}\nGAP_TIP_HEIGHT={}", archive.height, tip.height);
    for cb in &o.check_blocks {
        println!("GAP_BLOCK_CHECK={cb} {}", check_block_on_chain(&all, cb));
    }

    let wallets = match o.seeds {
        Some(path) => {
            if !o.prove {
                return Err("--gap-seeds needs --prove".into());
            }
            if o.replay.is_some() {
                return Err("--gap-seeds needs live peers (rangeproof segments are not in bundles)".into());
            }
            let w = wallet::Wallets::from_file(path)?;
            println!("GAP_WALLETS={}", w.len());
            Some(w)
        }
        None => None,
    };
    if o.spend.is_some() && wallets.is_none() {
        return Err("--gap-spend needs --gap-seeds".into());
    }
    if o.spend.is_some() && !global::is_testnet() && !o.allow_mainnet_spend {
        return Err("--gap-spend on mainnet needs --allow-mainnet-spend".into());
    }
    // Start point: a saved state on this chain, else the archive header.
    // A seed scan always starts at the archive: its rangeproofs are only
    // served there, and every later block must be rewound too.
    let loaded = match (o.state_dir, &wallets) {
        (Some(dir), Some(_)) if o.wallet_in.is_some() => {
            let l = load_state(dir, &all);
            if l.is_none() {
                println!("GAP_STATE_LOAD=NONE (quick wallet: full scan from the archive instead)");
            }
            l
        }
        (Some(_), Some(_)) => {
            println!("GAP_STATE_LOAD=SKIPPED (seed scan starts at the archive)");
            None
        }
        (Some(dir), None) => load_state(dir, &all),
        _ => None,
    };
    // A rebuild from the archive takes ~10 min (blocks, segments, rangeproofs)
    // and peers serve only the archive of their current tip, which moves every
    // 720 blocks. If the move is close, use the next archive right away (its
    // header is already in the session) and wait until peers serve it, so the
    // whole download happens on one archive.
    if loaded.is_none() && o.prove && o.replay.is_none() && !o.peers.is_empty() {
        let interval = global::txhashset_archive_interval();
        let switch_at = archive.height + interval + global::state_sync_threshold() as u64;
        let left = switch_at.saturating_sub(tip.height);
        if left <= ARCHIVE_SWITCH_MARGIN {
            if let Some(ni) = all.iter().position(|x| x.height == archive.height + interval) {
                archive_idx = ni;
                archive = &all[archive_idx];
                println!("GAP_ARCHIVE_NEXT={} (peers switch to it in ~{left} blocks; waiting for them)", archive.height);
                wait_archive_served(&o.peers, archive, o.segment_height, o.per_min)?;
            }
        }
    }
    let quick_wallet = o.wallet_in.is_some() && loaded.is_some();
    let mut start_idx = loaded.as_ref().map_or(archive_idx, |(_, i)| *i);
    let mut headers = &all[start_idx..];
    println!(
        "GAP_START_HEIGHT={}\nGAP_START_SOURCE={}\nGAP_BLOCKS={}",
        headers[0].height,
        if loaded.is_some() { "SAVED_STATE" } else { "ARCHIVE_SEGMENTS" },
        headers.len() - 1
    );

    let parallel_install = loaded.is_none()
        && o.prove
        && o.replay.is_none()
        && !o.peers.is_empty()
        && !o.blocks_all_peers
        && headers.len() > 1;
    let mut pre_state: Option<OutputState> = None;
    let mut prescanned: Option<Vec<wallet::Found>> = None;
    let mut first_seg_err: Option<String> = None;
    let mut bundle = if headers.len() == 1 {
        // Already at the tip: nothing to fetch.
        Bundle::default()
    } else if let Some(path) = o.replay {
        let b = read_bundle(path)?;
        for (i, p) in b.peers.iter().enumerate() {
            let mut prev = &headers[0];
            if b.blocks[i].len() != headers.len() - 1 {
                return Err(format!("bundle peer {p}: {} blocks, expected {} from height {}", b.blocks[i].len(), headers.len() - 1, headers[0].height));
            }
            for (blk, h) in b.blocks[i].iter().zip(&headers[1..]) {
                check_block(prev, h, blk).map_err(|e| format!("bundle peer {p}: {e}"))?;
                prev = h;
            }
        }
        println!("GAP_SOURCE=OFFLINE_BUNDLE");
        b
    } else {
        if o.peers.is_empty() {
            return Err("at least one --peer is required".into());
        }
        let t0 = Instant::now();
        if parallel_install {
            // Install: blocks, archive segments and (with seeds) the rangeproof
            // scan at once, one connection per peer for the whole download.
            println!("GAP_INSTALL_MODE=PARALLEL peers={}", o.peers.len());
            let inst = install_parallel(&o, archive, headers, wallets.as_ref(), run_start)?;
            let mut b = inst.parts;
            b.peers.push(format!("split:{}", o.peers.join("+")));
            b.blocks.push(inst.blocks);
            println!("GAP_BLOCKS_MODE=SPLIT_ACROSS_PEERS\nGAP_SOURCE=STANDARD_GRIN_P2P");
            match inst.state {
                Ok(st) => {
                    pre_state = Some(st);
                    prescanned = inst.found;
                }
                Err(e) => {
                    // e.g. ARCHIVE_NOT_SERVED: the sequential path below moves
                    // to the next archive and fetches its segments.
                    println!("GAP_PROVE_SEGMENTS=FAIL {e}");
                    first_seg_err = Some(e);
                }
            }
            b
        } else if !o.blocks_all_peers && headers.len() > 1 {
            // Default: each block from one peer (split by windows); every block
            // is bound to its header and to the roots, so this is enough.
            let blocks = fetch_blocks_split(&o.peers, headers, o.per_min)?;
            let mut b = Bundle::default();
            b.peers.push(format!("split:{}", o.peers.join("+")));
            b.blocks.push(blocks);
            println!("GAP_BLOCKS_MODE=SPLIT_ACROSS_PEERS\nGAP_SOURCE=STANDARD_GRIN_P2P\nGAP_BLOCKS_SECONDS={}", t0.elapsed().as_secs());
            b
        } else {
        println!("GAP_BLOCKS_MODE=ALL_FROM_EVERY_PEER");
        let results: Vec<Result<Vec<core::Block>, String>> = std::thread::scope(|s| {
            let hs = headers;
            let handles: Vec<_> = o
                .peers
                .iter()
                .map(|p| s.spawn(move || fetch_blocks(p, hs, &mut Rate::new(o.per_min))))
                .collect();
            handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err("thread panic".into()))).collect()
        });
        let mut b = Bundle::default();
        for (p, r) in o.peers.iter().zip(results) {
            match r {
                Ok(blocks) => {
                    println!("GAP_PEER_BLOCKS={p} OK n={}", blocks.len());
                    b.peers.push(p.clone());
                    b.blocks.push(blocks);
                }
                Err(e) => println!("GAP_PEER_BLOCKS={p} FAIL {e}"),
            }
        }
        println!("GAP_SOURCE=STANDARD_GRIN_P2P\nGAP_BLOCKS_SECONDS={}", t0.elapsed().as_secs());
        b
        }
    };
    if headers.len() > 1 && bundle.peers.is_empty() {
        return Err("no peer returned the full block range".into());
    }
    if headers.len() == 1 && bundle.peers.is_empty() {
        // Make the scan/prove loops below uniform: one empty "peer".
        bundle.peers.push("none".into());
        bundle.blocks.push(Vec::new());
    }

    // ---- scan (hint) ----
    let digests: Vec<Vec<Hash>> = bundle.blocks.iter().map(|bs| bs.iter().map(body_digest).collect()).collect();
    let mut agree = true;
    for d in &digests[1..] {
        if let Some(i) = d.iter().zip(&digests[0]).position(|(a, b)| a != b) {
            agree = false;
            println!("GAP_SCAN_BODY_DIFFERS_AT={}", headers[i + 1].height);
        }
    }
    println!("GAP_SCAN_PEERS={}", bundle.peers.len());
    println!("GAP_SCAN_PEERS_AGREE={agree}");
    let mut any_spent_hint = false;
    for (c, hex) in commits.iter().zip(&o.commitments) {
        let spent = bundle.blocks[0].iter().find(|b| input_commits(b).iter().any(|x| x.0.as_slice() == c.as_slice())).map(|b| b.header.height);
        let created = bundle.blocks[0].iter().find(|b| b.outputs().iter().any(|x| x.identifier.commit.0.as_slice() == c.as_slice())).map(|b| b.header.height);
        any_spent_hint |= spent.is_some();
        if commits.len() == 1 {
            println!("GAP_SCAN_SPENT_HEIGHT={}", spent.map_or("none".into(), |h| h.to_string()));
            println!("GAP_SCAN_CREATED_HEIGHT={}", created.map_or("none".into(), |h| h.to_string()));
        } else {
            println!("GAP_SCAN_COMMITMENT={hex} spent={} created={}", spent.map_or("none".into(), |h| h.to_string()), created.map_or("none".into(), |h| h.to_string()));
        }
    }
    println!(
        "GAP_SCAN_VERDICT={}",
        if !agree { "PEERS_DISAGREE" } else if any_spent_hint { "SPENT_SEEN_HINT" } else { "NO_SPEND_SEEN_HINT" }
    );
    println!("GAP_SCAN_AUTHENTICATION=HEADER_BYTES_COUNTS_SUMS_ONLY (not bound to output_root)");

    let mut code = if agree { 0 } else { 1 };

    // ---- prove ----
    if o.prove {
        let state = match (loaded, pre_state) {
            (Some((st, _)), _) => st,
            (None, Some(st)) => st,
            (None, None) => {
                if o.replay.is_none() {
                    let t0 = Instant::now();
                    let mut last_err = String::new();
                    // Peers serve only the archive of their *current* tip. If
                    // the network crossed the next 720-block boundary since our
                    // session sync, they moved to archive + 720: switch to it
                    // (its header is in our session; its blocks are a suffix of
                    // the blocks already fetched and checked).
                    for attempt in 0..2 {
                        let got = match (attempt, first_seg_err.take()) {
                            (0, Some(e)) => Err(e),
                            _ => fetch_segments_split(&o.peers, archive, o.segment_height, o.per_min),
                        };
                        match got {
                            Ok((bm, out, bytes, kseg)) => {
                                bundle.kernel = kseg;
                                println!("GAP_PROVE_DOWNLOAD_BYTES={bytes}\nGAP_PROVE_SEGMENTS_SECONDS={}", t0.elapsed().as_secs());
                                bundle.bitmap = bm;
                                bundle.output = out;
                                last_err.clear();
                                break;
                            }
                            Err(e) => {
                                println!("GAP_PROVE_SEGMENTS=FAIL {e}");
                                let next = all.iter().position(|x| x.height == archive.height + global::txhashset_archive_interval());
                                match next {
                                    Some(ni) if attempt == 0 && e.starts_with("ARCHIVE_NOT_SERVED") && start_idx == archive_idx => {
                                        let shift = ni - archive_idx;
                                        for blocks in bundle.blocks.iter_mut() {
                                            if blocks.len() >= shift {
                                                blocks.drain(0..shift);
                                            }
                                        }
                                        archive_idx = ni;
                                        start_idx = ni;
                                        archive = &all[archive_idx];
                                        headers = &all[start_idx..];
                                        println!("GAP_ARCHIVE_MOVED={} (peers moved to the next archive)\nGAP_BLOCKS={}", archive.height, headers.len() - 1);
                                    }
                                    _ => {
                                        last_err = e;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if !last_err.is_empty() {
                        if let Some(path) = o.out {
                            write_bundle(path, &bundle)?;
                        }
                        return Err(format!("archive segments unavailable: {last_err}"));
                    }
                }
                build_archive_state(archive, &bundle)?
            }
        };
        for (c, hex) in commits.iter().zip(&o.commitments) {
            let line = match state.position(c) {
                Some(p) => format!("UNSPENT leaf_index={}", leaf_idx(p)),
                None => "NOT_IN_UTXO".into(),
            };
            if commits.len() == 1 {
                println!("GAP_PROVE_START_STATE={line}");
                if loaded_is_none(start_idx, archive_idx) {
                    println!("GAP_PROVE_ARCHIVE_STATE={line}");
                }
            } else {
                println!("GAP_PROVE_START_STATE={hex} {line}");
            }
        }
        let mut excesses: Vec<Vec<u8>> = Vec::new();
        for k in &o.kernels {
            let b = grin_util::from_hex(k).map_err(|_| "invalid kernel excess hex")?;
            if b.len() != 33 {
                return Err("kernel excess must be 33 bytes".into());
            }
            excesses.push(b);
        }
        if !excesses.is_empty() && !state.kernels_tracked() {
            return Err("--gap-kernel needs kernel tracking (state saved without kernel peaks; rebuild from the archive)".into());
        }
        println!("GAP_PROVE_KERNELS={}", if state.kernels_tracked() { "TRACKED_KERNEL_ROOT_EVERY_BLOCK" } else { "NOT_TRACKED" });
        let t0 = Instant::now();
        let mut proven: Option<Proven> = None;
        let mut ok_peer: Option<usize> = None;
        for (i, p) in bundle.peers.iter().enumerate() {
            match prove_bodies_k(&state, headers, &bundle.blocks[i], &commits, &excesses) {
                Ok(r) => {
                    println!("GAP_PROVE_PEER_BODIES={p} ROOTS_OK {}/{}", headers.len() - 1, headers.len() - 1);
                    proven.get_or_insert(r);
                    ok_peer.get_or_insert(i);
                }
                Err(e) => println!("GAP_PROVE_PEER_BODIES={p} REJECTED {e}"),
            }
        }
        match proven {
            None => {
                println!("GAP_PROVE_VERDICT=NO_VALID_BODIES");
                code = 1;
            }
            Some(Proven { per, kernels, sample, state: final_state }) => {
                println!("GAP_PROVE_VERIFY_SECONDS={}", t0.elapsed().as_secs());
                for (k, h) in o.kernels.iter().zip(&kernels) {
                    println!(
                        "GAP_KERNEL={k} {}",
                        h.map_or("NOT_FOUND_IN_RANGE".to_string(), |h| {
                            let hash = all.iter().find(|x| x.height == h).map_or("?".to_string(), |x| x.hash().to_hex());
                            format!("FOUND height={h} hash={hash} (bound to kernel_root)")
                        })
                    );
                }
                for (h, c) in &sample {
                    println!("GAP_PROVE_SPENT_SAMPLE={h}:{}", c.0.to_hex());
                }
                println!("GAP_PROVE_TIP_HEIGHT={}", tip.height);
                let mut worst = 0;
                for ((spent, created, pos), hex) in per.iter().zip(&o.commitments) {
                    let (verdict, c) = match (pos, spent) {
                        (Some(_), _) => (if created.is_some() { "CREATED_IN_GAP_UNSPENT_AT_TIP" } else { "UNSPENT_AT_TIP" }, 0),
                        (None, Some(_)) => ("SPENT_IN_GAP", 5),
                        (None, None) => ("NOT_IN_UTXO_AT_TIP", 3),
                    };
                    worst = match (worst, c) { (5, _) | (_, 5) => 5, (3, _) | (_, 3) => 3, _ => 0 };
                    if o.commitments.len() == 1 {
                        if let Some(p) = pos {
                            println!("GAP_PROVE_TIP_LEAF_INDEX={}", leaf_idx(*p));
                        }
                        if let Some(h) = spent {
                            println!("GAP_PROVE_SPENT_HEIGHT={h}");
                        }
                        println!("GAP_PROVE_VERDICT={verdict}");
                    } else {
                        println!(
                            "GAP_PROVE_COMMITMENT={hex} verdict={verdict}{}{}",
                            pos.map_or(String::new(), |p| format!(" leaf_index={}", leaf_idx(p))),
                            spent.map_or(String::new(), |h| format!(" spent_height={h}"))
                        );
                    }
                }
                if o.commitments.len() > 1 {
                    println!("GAP_PROVE_VERDICT=MULTI worst_exit={worst}");
                }
                code = worst;
                println!("GAP_PROVE_AUTHENTICATION=OUTPUT_ROOT_EVERY_BLOCK (headers: caller-pinned session)");
                if let Some(dir) = o.state_dir {
                    save_state(dir, &final_state, tip)?;
                }
                if let Some(w) = &wallets {
                    let wcode = wallet_report(&o, w, archive, &state, &final_state, headers, &all, &bundle, ok_peer.unwrap_or(0), quick_wallet, prescanned.take())?;
                    code = code.max(wcode);
                }
            }
        }
    }
    if let Some(path) = o.out {
        if o.replay.is_none() && headers.len() > 1 {
            write_bundle(path, &bundle)?;
        }
    }
    Ok(code)
}

/// What `install_parallel` brings back.
struct Install {
    blocks: Vec<core::Block>,
    /// Archive bitmap/output/kernel segments (for `--gap-out` bundles).
    parts: Bundle,
    /// Archive UTXO state checked against output_root, or why it failed
    /// (e.g. ARCHIVE_NOT_SERVED: the caller falls back to the next archive).
    state: Result<OutputState, String>,
    /// Own outputs at the archive height (seeds given and state built).
    found: Option<Vec<wallet::Found>>,
}

/// First run on a computer (no saved state): gap blocks, archive segments and
/// the rangeproof scan in one pass. A Grin node accepts one connection per IP
/// and remembers a closed one for up to 20 s, so each peer gets ONE connection
/// for the whole run and works through the tasks in turn:
///   segment peers: archive segments -> rangeproofs -> help with blocks
///   block peers:   blocks -> rangeproofs (once the archive state is built)
/// All tasks are shared pools (first delivery wins, endgame duplicates), so
/// a slow or dead peer only costs its own share.
fn install_parallel(o: &Opts, archive: &BlockHeader, headers: &[BlockHeader], w: Option<&wallet::Wallets>, run_start: Instant) -> Result<Install, String> {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::SeqCst};
    let peers = &o.peers;
    let n = peers.len();
    // Blocks are about a third of all requests (one per block; segments carry
    // thousands of leaves): a third of the peers start with blocks. They are
    // the FIRST peers of the list: the script lists the header-sync peers
    // last, and those may refuse us for up to 20 s (short segment phase).
    let n_block = if n == 1 { 0 } else { (n * 3).div_ceil(8).clamp(1, n - 1) };
    let total = headers.len() - 1;
    let windows: Vec<(usize, usize)> = (0..total).step_by(BLOCK_WINDOW).map(|a| (a, (a + BLOCK_WINDOW).min(total))).collect();
    let bpool = WorkPool::new((0..windows.len() as u64).collect());
    let got: Mutex<Vec<Option<core::Block>>> = Mutex::new(vec![None; total]);
    let (nb, no) = segment_counts(archive, o.segment_height);
    let spool = WorkPool::new((0..nb + no).collect());
    let store: Mutex<SegStore> = Mutex::new(SegStore::default());
    let nr = SegmentIdentifier::count_segments_required(archive.output_mmr_size, RPROOF_SEGMENT_HEIGHT) as u64;
    let rpool = WorkPool::new((0..nr).collect());
    let seg_left = AtomicUsize::new(n - n_block);
    let workers_left = AtomicUsize::new(n);
    // Archive state, published once built: None = not yet.
    let state_cell: Mutex<Option<Result<Arc<OutputState>, String>>> = Mutex::new(None);
    let by_pos: std::sync::OnceLock<HashMap<u64, OutputIdentifier>> = std::sync::OnceLock::new();
    let parts_cell: Mutex<Option<Bundle>> = Mutex::new(None);
    let found: Mutex<Vec<wallet::Found>> = Mutex::new(Vec::new());
    let checked = AtomicU64::new(0);
    let scan_err: Mutex<Option<String>> = Mutex::new(None);
    let done_r: Mutex<HashSet<u64>> = Mutex::new(HashSet::new());
    // Segments fully processed by `sink` (discovery finished, not just received).
    let sunk = AtomicU64::new(0);
    let blocks_secs = AtomicU64::new(u64::MAX);
    let t0 = Instant::now();
    let state_failed = || matches!(&*state_cell.lock().unwrap(), Some(Err(_)));
    let sink = |idx: u64, items: Vec<(u64, RangeProof)>| {
        if !done_r.lock().unwrap().insert(idx) {
            return;
        }
        let Some(w) = w else { return };
        let bp = by_pos.get().expect("state built before rangeproofs");
        let rows: Vec<(u64, OutputIdentifier, RangeProof)> = items.into_iter().filter_map(|(p, rp)| bp.get(&p).map(|id| (p, *id, rp))).collect();
        // Counted as checked only AFTER discovery succeeded: a failed scan
        // leaves the count short, so the run fails instead of showing a
        // partial balance.
        match w.discover(&rows) {
            Ok(f) => {
                found.lock().unwrap().extend(f);
                checked.fetch_add(rows.len() as u64, SeqCst);
            }
            Err(e) => *scan_err.lock().unwrap() = Some(e),
        }
        sunk.fetch_add(1, SeqCst);
    };
    let mark_blocks = || {
        if bpool.finished() && blocks_secs.load(SeqCst) == u64::MAX {
            blocks_secs.store(t0.elapsed().as_secs(), SeqCst);
        }
    };

    struct Report {
        peer: String,
        blocks: usize,
        segments: usize,
        rproofs: usize,
        rbytes: u64,
        err: Vec<String>,
    }
    let reports: Vec<Report> = std::thread::scope(|sc| {
        // Builder: archive state as soon as every segment is in, then the
        // early balance as soon as every rangeproof is scanned.
        let builder = sc.spawn(|| {
            loop {
                let fin = spool.finished();
                let kernel = store.lock().unwrap().kernel.is_some();
                let left = seg_left.load(SeqCst);
                if fin && (kernel || left == 0) {
                    break;
                }
                if !fin && left == 0 {
                    let e = if spool.missing() == spool.total {
                        format!("ARCHIVE_NOT_SERVED {} archive segments missing", spool.missing())
                    } else {
                        format!("{} archive segments missing (all peers failed)", spool.missing())
                    };
                    *state_cell.lock().unwrap() = Some(Err(e));
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            let (parts, bytes) = {
                let mut st = store.lock().unwrap();
                let b = Bundle {
                    bitmap: std::mem::take(&mut st.bitmap).into_values().collect(),
                    output: std::mem::take(&mut st.output).into_values().collect(),
                    kernel: st.kernel.take(),
                    ..Bundle::default()
                };
                (b, st.bytes)
            };
            println!("GAP_PROVE_DOWNLOAD_BYTES={bytes}\nGAP_PROVE_SEGMENTS_SECONDS={}", t0.elapsed().as_secs());
            let r = build_archive_state(archive, &parts);
            *parts_cell.lock().unwrap() = Some(parts);
            match r {
                Ok(st) => {
                    let _ = by_pos.set(st.data_by_pos());
                    *state_cell.lock().unwrap() = Some(Ok(Arc::new(st)));
                }
                Err(e) => {
                    *state_cell.lock().unwrap() = Some(Err(e));
                    return;
                }
            }
            if let Some(w) = w {
                while !rpool.finished() && workers_left.load(SeqCst) > 0 {
                    std::thread::sleep(Duration::from_millis(200));
                }
                while rpool.finished() && sunk.load(SeqCst) < nr && workers_left.load(SeqCst) > 0 {
                    std::thread::sleep(Duration::from_millis(50));
                }
                if rpool.finished() && sunk.load(SeqCst) == nr && scan_err.lock().unwrap().is_none() {
                    println!("GAP_SCAN_RPROOF_SECONDS={}", t0.elapsed().as_secs());
                    // If the blocks after the archive are in too, apply them
                    // (own outputs created / spent) so the first number is
                    // already the current one; their roots are checked next.
                    let mut f = found.lock().unwrap().clone();
                    let with_blocks = bpool.finished();
                    if with_blocks {
                        let g = got.lock().unwrap();
                        for b in g.iter().flatten() {
                            let spent = input_commits(b);
                            f.retain(|k| !spent.contains(&k.commit));
                            // Early (unverified) display only; a failure here
                            // is reported by the verified pass below.
                            for x in w.discover(&wallet::outputs_of_block(b)).unwrap_or_default() {
                                if !f.iter().any(|k| k.commit == x.commit) {
                                    f.push(x);
                                }
                            }
                        }
                    }
                    print_early_balance(w, &f, if with_blocks { headers.last().unwrap() } else { archive }, with_blocks, run_start);
                }
            }
        });
        let handles: Vec<_> = peers
            .iter()
            .enumerate()
            .map(|(k, p)| {
                let block_role = k < n_block;
                let (bpool, spool, rpool, got, store, windows) = (&bpool, &spool, &rpool, &got, &store, &windows);
                let (seg_left, workers_left, state_cell, sink, mark_blocks, state_failed) = (&seg_left, &workers_left, &state_cell, &sink, &mark_blocks, &state_failed);
                sc.spawn(move || {
                    let mut rep = Report { peer: p.clone(), blocks: 0, segments: 0, rproofs: 0, rbytes: 0, err: Vec::new() };
                    let mut seg_counted = block_role;
                    let all_done = || bpool.finished() && spool.finished() && (w.is_none() || rpool.finished() || state_failed());
                    let caps = Capabilities::default() | Capabilities::BLOCK_HIST | Capabilities::PIBD_HIST | Capabilities::PIBD_HIST_1;
                    let c = match Conn::open_or_abort(p, caps, &all_done) {
                        Ok(c) => Some(c),
                        Err(e) => {
                            if e != ABORTED {
                                rep.err.push(e);
                            }
                            None
                        }
                    };
                    if let Some(c) = c {
                        let pibd = c.peer.info.capabilities.contains(Capabilities::PIBD_HIST);
                        let mut rate = Rate::new(o.per_min);
                        if !block_role && pibd {
                            let (d, r) = segments_on(&c, archive, o.segment_height, nb, spool, store, true, &mut rate);
                            rep.segments = d;
                            if let Err(e) = r {
                                rep.err.push(format!("segments: {e}"));
                            }
                        } else {
                            let (d, r) = block_windows_on(&c, headers, windows, bpool, got, &mut rate);
                            rep.blocks += d;
                            mark_blocks();
                            if let Err(e) = r {
                                rep.err.push(format!("blocks: {e}"));
                            }
                        }
                        if !seg_counted {
                            seg_left.fetch_sub(1, SeqCst);
                            seg_counted = true;
                        }
                        if w.is_some() && pibd {
                            // Wait for the archive state (built by the builder thread).
                            let st = loop {
                                if let Some(r) = &*state_cell.lock().unwrap() {
                                    break r.as_ref().ok().cloned();
                                }
                                std::thread::sleep(Duration::from_millis(200));
                            };
                            if let Some(st) = st {
                                match rproofs_on(&c, p, archive, &st.leaves, rpool, &mut rate, sink, None) {
                                    Ok((b, d)) => {
                                        rep.rproofs = d;
                                        rep.rbytes = b;
                                    }
                                    Err(e) => rep.err.push(format!("rangeproofs: {e}")),
                                }
                            }
                        }
                        if !bpool.finished() {
                            let (d, r) = block_windows_on(&c, headers, windows, bpool, got, &mut rate);
                            rep.blocks += d;
                            mark_blocks();
                            if let Err(e) = r {
                                rep.err.push(format!("blocks: {e}"));
                            }
                        }
                        c.close();
                    }
                    if !seg_counted {
                        seg_left.fetch_sub(1, SeqCst);
                    }
                    workers_left.fetch_sub(1, SeqCst);
                    rep
                })
            })
            .collect();
        let reps = handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|_| Report { peer: "?".into(), blocks: 0, segments: 0, rproofs: 0, rbytes: 0, err: vec!["thread panic".into()] }))
            .collect();
        let _ = builder.join();
        reps
    });
    let mut rbytes = 0;
    for r in &reports {
        println!(
            "GAP_INSTALL_PEER={} blocks={} segments={} rangeproof_segments={} {}",
            r.peer,
            r.blocks,
            r.segments,
            r.rproofs,
            if r.err.is_empty() { "OK".to_string() } else { format!("ERR {}", r.err.join(" | ")) }
        );
        rbytes += r.rbytes;
    }
    if !bpool.finished() {
        // Say why: the first error of each peer (connect, refused, timeout ...).
        let why: Vec<String> = reports.iter().filter_map(|r| r.err.first().map(|e| format!("{}: {e}", r.peer))).take(4).collect();
        return Err(format!("{} block windows missing (all peers failed) [{}]", bpool.missing(), why.join("; ")));
    }
    let bs = blocks_secs.load(SeqCst);
    println!("GAP_BLOCKS_SECONDS={}", if bs == u64::MAX { t0.elapsed().as_secs() } else { bs });
    let blocks: Vec<core::Block> = got.into_inner().unwrap().into_iter().map(|x| x.unwrap()).collect();
    let parts = parts_cell.into_inner().unwrap().unwrap_or_default();
    let state = match state_cell.into_inner().unwrap() {
        Some(Ok(a)) => Ok(Arc::try_unwrap(a).map_err(|_| "archive state still shared".to_string())?),
        Some(Err(e)) => Err(e),
        None => Err("archive state not built".into()),
    };
    let found = match (w, &state) {
        (Some(_), Ok(st)) => {
            if !rpool.finished() {
                return Err(format!("rangeproof scan incomplete: {} segments missing (all peers failed)", rpool.missing()));
            }
            if let Some(e) = scan_err.lock().unwrap().take() {
                return Err(e);
            }
            let total_checked = checked.load(SeqCst);
            if total_checked != st.utxo_count() as u64 {
                return Err(format!("rangeproofs for {total_checked} of {} unspent outputs", st.utxo_count()));
            }
            println!(
                "GAP_SCAN_RPROOF_SEGMENTS={nr}\nGAP_SCAN_RPROOF_BYTES={rbytes}\nGAP_SCAN_RPROOFS_CHECKED={total_checked}\nGAP_SCAN_RPROOF_AUTHENTICATION=RANGE_PROOF_ROOT_OF_ARCHIVE_HEADER"
            );
            Some(found.into_inner().unwrap())
        }
        _ => None,
    };
    Ok(Install { blocks, parts, state, found })
}

/// Print the balance at the archive height as soon as the rangeproof scan is
/// done, before the gap blocks are proven: a first number for the user. The
/// final, verified balance (GAP_WALLET=) follows once every block is applied.
fn print_early_balance(w: &wallet::Wallets, found: &[wallet::Found], at: &BlockHeader, with_blocks: bool, since: Instant) {
    for wi in 0..w.len() {
        let mine: Vec<_> = found.iter().filter(|f| f.wallet == wi).collect();
        let bal: u64 = mine.iter().map(|f| f.amount).sum();
        println!(
            "GAP_WALLET_EARLY=wallet={} outputs={} balance_nanogrin={bal} at_height={} seconds={} ({})",
            wi + 1,
            mine.len(),
            at.height,
            since.elapsed().as_secs(),
            if with_blocks {
                "UNVERIFIED: blocks after the archive applied, their roots not checked yet"
            } else {
                "UNVERIFIED: archive height only, blocks after it still downloading"
            }
        );
    }
}

/// Reads a `--gap-wallet-out` file (one JSON object per line, written by this
/// tool) back into own outputs. Returns (outputs, creation heights, tip height
/// of the file, tip header hash from the meta line if present). The records
/// are NOT trusted here: `wallet_report` re-derives every commitment from its
/// key and amount, checks features against the verified UTXO state and binds
/// the file to the verified header chain by the tip hash.
/// The last line `{"mac":...}` covers every byte before it; it is returned as
/// (body, mac) in `KnownFile` and checked with the seeds by `check_known_file`.
#[derive(Debug)]
struct KnownFile {
    outputs: Vec<wallet::Found>,
    created: HashMap<[u8; 33], u64>,
    tip: u64,
    tip_hash: Option<String>,
    body: String,
    mac: Option<String>,
}

fn load_known_outputs(path: &str, position_of: &dyn Fn(&[u8]) -> Option<u64>) -> Result<KnownFile, String> {
    fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
        let pat = format!("\"{key}\":");
        let i = line.find(&pat)? + pat.len();
        let rest = &line[i..];
        let rest = rest.strip_prefix('"').map_or(rest, |r| r);
        let end = rest.find(|c| c == '"' || c == ',' || c == '}').unwrap_or(rest.len());
        Some(&rest[..end])
    }
    let text = std::fs::read_to_string(path).map_err(|e| format!("wallet file {path}: {e}"))?;
    let mut out = Vec::new();
    let mut created = HashMap::new();
    let mut tip: Option<u64> = None;
    let mut tip_hash: Option<String> = None;
    let mut mac: Option<String> = None;
    let mut body = String::new();
    let mut seen: HashSet<[u8; 33]> = HashSet::new();
    for (n, raw) in text.split_inclusive('\n').enumerate() {
        let line = raw.trim();
        if mac.is_some() && !line.is_empty() {
            return Err(format!("wallet file {path} line {}: data after the mac line", n + 1));
        }
        if line.starts_with("{\"mac\":") {
            mac = Some(field(line, "mac").ok_or(format!("wallet file {path}: bad mac line"))?.to_string());
            continue;
        }
        body.push_str(raw);
        if line.is_empty() {
            continue;
        }
        if line.contains("\"meta\":") {
            // {"meta":"grinsight-wallet","tip_height":N}: height of the whole file.
            if let Some(h) = field(line, "tip_height").and_then(|v| v.parse::<u64>().ok()) {
                tip = Some(tip.map_or(h, |t: u64| t.min(h)));
            }
            if let Some(hh) = field(line, "tip_hash") {
                tip_hash = Some(hh.to_string());
            }
            continue;
        }
        let bad = |what: &str| format!("wallet file {path} line {}: bad {what}", n + 1);
        let wallet: usize = field(line, "wallet").and_then(|v| v.parse().ok()).ok_or_else(|| bad("wallet"))?;
        let commit_hex = field(line, "commit").ok_or_else(|| bad("commit"))?;
        let commit_bytes = grin_util::from_hex(commit_hex).map_err(|_| bad("commit"))?;
        if commit_bytes.len() != 33 || wallet == 0 {
            return Err(bad("commit/wallet"));
        }
        let amount: u64 = field(line, "amount").and_then(|v| v.parse().ok()).ok_or_else(|| bad("amount"))?;
        let id = super::receive::key_id_from_hex(field(line, "key_id").ok_or_else(|| bad("key_id"))?).ok_or_else(|| bad("key_id"))?;
        let features = match field(line, "features") {
            Some("Plain") => core::OutputFeatures::Plain,
            Some("Coinbase") => core::OutputFeatures::Coinbase,
            _ => return Err(bad("features")),
        };
        let line_tip: u64 = field(line, "tip_height").and_then(|v| v.parse().ok()).ok_or_else(|| bad("tip_height"))?;
        tip = Some(tip.map_or(line_tip, |t: u64| t.min(line_tip)));
        let commit = Commitment::from_vec(commit_bytes);
        if !seen.insert(commit.0) {
            return Err(format!("wallet file {path} line {}: duplicate commitment {commit_hex}", n + 1));
        }
        if let Some(h) = field(line, "created").and_then(|v| v.parse::<u64>().ok()) {
            created.insert(commit.0, h);
        }
        out.push(wallet::Found {
            wallet: wallet - 1,
            pos0: position_of(&commit.0).unwrap_or(u64::MAX),
            commit,
            features,
            amount,
            id,
            switch: grin_keychain::SwitchCommitmentType::Regular,
        });
    }
    // The meta line (or the outputs) give the height the file is valid at; a
    // file without any is refused rather than trusted.
    let tip = tip.ok_or(format!("wallet file {path} has no height (run a full scan)"))?;
    Ok(KnownFile { outputs: out, created, tip, tip_hash, body, mac })
}

/// Is the block `HEIGHT:HASH` (confirmed in an earlier run) a header of the
/// verified chain of this session? A reorg that replaced it gives
/// NOT_ON_VERIFIED_CHAIN; heights outside the session range say so instead of
/// guessing.
fn check_block_on_chain(all: &[BlockHeader], spec: &str) -> String {
    let Some((h, hash)) = spec.split_once(':') else { return "BAD_SPEC (HEIGHT:HASH)".into() };
    let Ok(h) = h.parse::<u64>() else { return "BAD_SPEC (HEIGHT:HASH)".into() };
    let (first, last) = (all.first().map_or(0, |x| x.height), all.last().map_or(0, |x| x.height));
    match all.iter().find(|x| x.height == h) {
        Some(x) if x.hash().to_hex() == hash.to_ascii_lowercase() => format!("ON_VERIFIED_CHAIN depth={}", last - h + 1),
        Some(x) => format!("NOT_ON_VERIFIED_CHAIN (height {h} is now {})", x.hash().to_hex()),
        None if h < first => format!("BELOW_VERIFIED_RANGE (session starts at {first}; not re-checked)"),
        None => format!("ABOVE_VERIFIED_TIP (tip {last})"),
    }
}

/// The wallet file's tip (height + header hash) must be a header of the
/// verified chain of this session.
fn known_tip_on_chain(all: &[BlockHeader], known_tip: u64, known_hash: Option<&str>) -> Result<(), String> {
    let h = known_hash.ok_or("no tip hash in the file (older format)")?;
    match all.iter().find(|x| x.height == known_tip) {
        Some(x) if x.hash().to_hex() == h => Ok(()),
        Some(_) => Err(format!("its tip {known_tip} is on another branch (reorg or a file from another chain)")),
        None => Err(format!("its tip {known_tip} is outside the verified headers")),
    }
}

/// Checks a loaded wallet file before quick mode uses it (see
/// `load_known_outputs`): tip hash on the verified chain, every record
/// re-derivable from the seeds, features equal to the verified UTXO state.
fn check_known_file(w: &wallet::Wallets, start: &OutputState, all: &[BlockHeader], kf: &KnownFile) -> Result<(), String> {
    let mac = kf.mac.as_deref().ok_or("no mac line (older format)")?;
    if w.file_mac(kf.body.as_bytes()) != mac {
        return Err("mac mismatch: the file was changed, shortened or written with other seeds".into());
    }
    known_tip_on_chain(all, kf.tip, kf.tip_hash.as_deref())?;
    for f in &kf.outputs {
        w.verify_known(f)?;
        if let Some((pos0, id)) = start.utxo.get(&f.commit.0) {
            if id.features != f.features {
                return Err(format!("features of {} differ from the verified UTXO state", f.commit.0.to_hex()));
            }
            // Creation height (coinbase maturity) from the verified output MMR
            // sizes of the headers, not from the file.
            if let Some(&h) = kf.created.get(&f.commit.0) {
                let ok = match creation_height(*pos0, all) {
                    Ok(c) => c == h,
                    Err(first) => h <= first,
                };
                if !ok {
                    return Err(format!("creation height {h} of {} does not match the chain", f.commit.0.to_hex()));
                }
            }
        }
    }
    Ok(())
}

/// Discover own outputs (archive UTXO via rangeproof segments + outputs of
/// every proven block), report their state at the tip, optionally spend one.
#[allow(clippy::too_many_arguments)]
/// Download every rangeproof segment of the archive (all peers share one pool)
/// and rewind each unspent output's proof with the seeds: own outputs at the
/// archive height. Segments are checked against the archive header's
/// range_proof_root and the archive UTXO bitmap of `start`.
fn scan_rproofs(o: &Opts, w: &wallet::Wallets, archive: &BlockHeader, start: &OutputState) -> Result<Vec<wallet::Found>, String> {
    let by_pos = start.data_by_pos();
    let found: Mutex<Vec<wallet::Found>> = Mutex::new(Vec::new());
    let checked = std::sync::atomic::AtomicU64::new(0);
    let scan_err: Mutex<Option<String>> = Mutex::new(None);
    // Each segment is processed once even if a retry fetches it again.
    let done: Mutex<HashSet<u64>> = Mutex::new(HashSet::new());
    let sink = |idx: u64, items: Vec<(u64, RangeProof)>| {
        if !done.lock().unwrap().insert(idx) {
            return;
        }
        let rows: Vec<(u64, OutputIdentifier, RangeProof)> =
            items.into_iter().filter_map(|(p, rp)| by_pos.get(&p).map(|id| (p, *id, rp))).collect();
        match w.discover(&rows) {
            Ok(f) => {
                found.lock().unwrap().extend(f);
                checked.fetch_add(rows.len() as u64, std::sync::atomic::Ordering::Relaxed);
            }
            Err(e) => *scan_err.lock().unwrap() = Some(e),
        }
    };
    // Rangeproof segments of the archive: all peers pull from one shared pool.
    let n = SegmentIdentifier::count_segments_required(archive.output_mmr_size, RPROOF_SEGMENT_HEIGHT) as u64;
    let t0 = Instant::now();
    let peers = &o.peers;
    let pool = WorkPool::new((0..n).collect());
    let results: Vec<(String, Result<(u64, usize), String>)> = std::thread::scope(|s| {
        let handles: Vec<_> = peers
            .iter()
            .map(|p| {
                let sink = &sink;
                let leaves = &start.leaves;
                let pool = &pool;
                s.spawn(move || (p.clone(), fetch_rproofs(p, archive, leaves, pool, &mut Rate::new(o.per_min), sink, None)))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or_else(|_| ("?".into(), Err("thread panic".into())))).collect()
    });
    let mut bytes = 0;
    for (p, r) in &results {
        match r {
            Ok((b, d)) => {
                bytes += b;
                println!("GAP_SCAN_RPROOF_PEER={p} OK segments={d} bytes={b}");
            }
            Err(e) => println!("GAP_SCAN_RPROOF_PEER={p} FAIL {e}"),
        }
    }
    if !pool.finished() {
        return Err(format!("rangeproof scan incomplete: {} segments missing (all peers failed)", pool.missing()));
    }
    if let Some(e) = scan_err.into_inner().unwrap() {
        return Err(e);
    }
    let total_checked = checked.load(std::sync::atomic::Ordering::Relaxed);
    if total_checked != start.utxo_count() as u64 {
        return Err(format!("rangeproofs for {total_checked} of {} unspent outputs", start.utxo_count()));
    }
    println!(
        "GAP_SCAN_RPROOF_SEGMENTS={n}\nGAP_SCAN_RPROOF_BYTES={bytes}\nGAP_SCAN_RPROOFS_CHECKED={total_checked}\nGAP_SCAN_RPROOF_SECONDS={}\nGAP_SCAN_RPROOF_AUTHENTICATION=RANGE_PROOF_ROOT_OF_ARCHIVE_HEADER",
        t0.elapsed().as_secs()
    );
    Ok(found.into_inner().unwrap())
}

#[allow(clippy::too_many_arguments)]
fn wallet_report(
    o: &Opts,
    w: &wallet::Wallets,
    archive: &BlockHeader,
    start: &OutputState,
    tip_state: &OutputState,
    headers: &[BlockHeader],
    all: &[BlockHeader],
    bundle: &Bundle,
    peer_idx: usize,
    quick: bool,
    prescanned: Option<Vec<wallet::Found>>,
) -> Result<i32, String> {
    let tip = headers.last().unwrap();
    let mut created_at: HashMap<[u8; 33], u64> = HashMap::new();
    let mut found: Vec<wallet::Found> = if quick {
        // Everyday path: own outputs known from the previous run (at the saved
        // state's height); only the new blocks are scanned below.
        let path = o.wallet_in.unwrap();
        let t0 = Instant::now();
        // A damaged file (unreadable, duplicate, malformed) is not an error of
        // the run: it is not used and the wallet is rebuilt by a full scan.
        let kf = match load_known_outputs(path, &|c: &[u8]| start.position(c)) {
            Ok(kf) => kf,
            Err(e) => {
                let msg = format!("wallet file {path} not used: {e}; run a full scan");
                if o.spend.is_some() {
                    return Err(msg);
                }
                println!("GAP_WALLET_STALE={msg}");
                return Ok(0);
            }
        };
        // The file must be complete and unchanged (MAC with the seeds), belong
        // to the verified chain (tip hash) and every record must be
        // re-derivable from the seeds; otherwise it is not used.
        let rejected = check_known_file(w, start, all, &kf);
        let KnownFile { outputs: known, created, tip: known_tip, .. } = kf;
        if let Err(why) = rejected {
            let msg = format!("wallet file {path} not used: {why}; run a full scan");
            if o.spend.is_some() {
                return Err(msg);
            }
            println!("GAP_WALLET_STALE={msg}");
            return Ok(0);
        }
        if known_tip < headers[0].height {
            // The state moved on without the wallet (e.g. a run without seeds):
            // own outputs created in between would be missed. The proof above
            // still stands; the wallet needs one full scan.
            let msg = format!(
                "wallet file {path} is at height {known_tip}, the saved state at {}: run a full scan",
                headers[0].height
            );
            if o.spend.is_some() {
                return Err(msg);
            }
            println!("GAP_WALLET_STALE={msg}");
            return Ok(0);
        }
        created_at = created;
        println!(
            "GAP_WALLET_SOURCE=KNOWN_OUTPUTS file={path} outputs={} wallet_tip={known_tip} state_height={} seconds={}",
            known.len(),
            headers[0].height,
            t0.elapsed().as_secs()
        );
        known
    } else if let Some(f) = prescanned {
        // Install path: the archive rangeproofs were scanned while the gap
        // blocks were still downloading (see `run`).
        f
    } else {
        scan_rproofs(o, w, archive, start)?
    };
    // Outputs created in the gap: rewind the proofs in the proven block bodies.
    let t_blocks = Instant::now();
    let mut new_outputs = 0usize;
    for b in &bundle.blocks[peer_idx] {
        let f = w.discover(&wallet::outputs_of_block(b))?;
        for x in f {
            if found.iter().any(|k| k.commit == x.commit) {
                continue; // already known (e.g. after a fallback to the previous state)
            }
            created_at.insert(x.commit.0, b.header.height);
            found.push(x);
            new_outputs += 1;
        }
    }
    println!(
        "GAP_WALLET_NEW_BLOCKS_SCANNED={} new_own_outputs={new_outputs} seconds={}",
        bundle.blocks[peer_idx].len(),
        t_blocks.elapsed().as_secs()
    );
    let commits: Vec<Vec<u8>> = found.iter().map(|f| f.commit.0.to_vec()).collect();
    let proof = prove_bodies(start, headers, &bundle.blocks[peer_idx], &commits)?;
    let mut code = 0;
    for wi in 0..w.len() {
        let mut outs = 0;
        let mut unspent = 0;
        let mut balance: u64 = 0;
        for (f, (spent, _created, pos)) in found.iter().zip(&proof.per) {
            if f.wallet != wi {
                continue;
            }
            outs += 1;
            let status = match (pos, spent) {
                (Some(_), _) => {
                    unspent += 1;
                    balance += f.amount;
                    "UNSPENT_AT_TIP".to_string()
                }
                (None, Some(h)) => format!("SPENT_IN_GAP height={h}"),
                (None, None) => "NOT_IN_UTXO_AT_TIP".into(),
            };
            let created = match created_at.get(&f.commit.0) {
                Some(h) => format!("{h}"),
                None => match creation_height(f.pos0, all) {
                    Ok(h) => format!("{h}"),
                    Err(h) => format!("<={h}"),
                },
            };
            println!(
                "GAP_WALLET_OUTPUT=wallet={} commit={} amount={} features={:?} origin={} created={created} status={status}",
                wi + 1,
                f.commit.0.to_hex(),
                f.amount,
                f.features,
                created_at.get(&f.commit.0).map_or("archive".to_string(), |h| format!("block:{h}")),
            );
        }
        println!("GAP_WALLET=wallet={} outputs={outs} unspent_at_tip={unspent} balance_nanogrin={balance}", wi + 1);
    }
    println!("GAP_WALLET_BALANCE_AUTHENTICATION=OUTPUT_ROOT_AT_TIP (headers: caller-pinned session; discovery: range_proof_root at archive + proven block bodies)");
    if let Some(path) = o.wallet_out {
        let mut text = format!("{{\"meta\":\"grinsight-wallet\",\"tip_height\":{},\"tip_hash\":\"{}\"}}\n", tip.height, tip.hash().to_hex());
        for (f, (spent, _c, pos)) in found.iter().zip(&proof.per) {
            text.push_str(&format!(
                "{{\"wallet\":{},\"commit\":\"{}\",\"amount\":{},\"key_id\":\"{}\",\"features\":\"{:?}\",\"created\":{},\"unspent_at_tip\":{},\"spent_height\":{},\"tip_height\":{}}}\n",
                f.wallet + 1,
                f.commit.0.to_hex(),
                f.amount,
                f.id.to_hex(),
                f.features,
                created_at.get(&f.commit.0).map_or("null".to_string(), |h| h.to_string()),
                pos.is_some(),
                spent.map_or("null".to_string(), |h| h.to_string()),
                tip.height
            ));
        }
        let mac = w.file_mac(text.as_bytes());
        text.push_str(&format!("{{\"mac\":\"{mac}\",\"records\":{}}}\n", found.len()));
        super::receive::write_atomic(path, text.as_bytes()).map_err(|e| format!("wallet out: {e}"))?;
        println!("GAP_WALLET_OUT={path}");
    }

    // ---- spend ----
    if let Some(sel) = o.spend {
        // Every spend reserves the key it hands out in the pending file, under
        // its lock, BEFORE the slatepack / answer / transaction leaves; without
        // that file a second spend could pick the same fresh key.
        let pending = o.pending.ok_or("spending needs --pending FILE (keys handed out but not yet on chain)")?;
        let _lock = super::receive::lock_pending(pending)?;
        // An invoice paid before: hand out the saved answer FIRST, before any
        // coin selection (its inputs may be spent by now and nothing else may
        // be spendable; the saved answer is still the one to give back).
        if let (Some(i1_path), Some(wi)) = (o.pay_invoice, spend_wallet(&found, sel)) {
            let i1 = std::fs::read_to_string(i1_path).map_err(|e| format!("invoice file: {e}"))?;
            let out = o.slatepack_out.ok_or("needs --gap-slatepack-out")?;
            if super::receive::resend_paid_invoice(w, wi, pending, &i1, out, Some(tip.height))?.is_some() {
                return Ok(code);
            }
        }
        let reserved = super::receive::reserved_inputs(pending)?;
        if !reserved.is_empty() {
            println!("GAP_RESERVED_INPUTS={}", reserved.len());
        }
        let pick = select_spend(&found, &proof.per, tip_state, &created_at, all, tip.height, sel, &reserved)?;
        let mut used: Vec<_> = found.iter().filter(|f| f.wallet == pick.wallet).map(|f| f.id.clone()).collect();
        used.extend(super::receive::read_key_ids(pending, pick.wallet + 1)?);
        if o.send_to.is_some() || o.pay_invoice.is_some() {
            // Every spendable own output of this wallet (same rules as a single pick).
            let cands: Vec<super::receive::InputSel> = (0..found.len())
                .filter(|&i| found[i].wallet == pick.wallet)
                .filter_map(|i| {
                    let h = found[i].commit.0.to_hex();
                    select_spend(&found, &proof.per, tip_state, &created_at, all, tip.height, &h, &reserved).ok()
                })
                .map(|f| super::receive::InputSel::new(&f.id, f.amount, f.features.is_coinbase(), &f.commit))
                .collect();
            println!("GAP_SPENDABLE_OUTPUTS={} total_nanogrin={}", cands.len(), cands.iter().map(|c| c.amount).sum::<u64>());
            let out = o.slatepack_out.ok_or("needs --gap-slatepack-out")?;
            if let Some(dest) = o.send_to {
                let amount = o.send_amount.ok_or("--gap-send-to needs --gap-send-amount")?;
                let ctx_out = o.context_out.ok_or("--gap-send-to needs --gap-context-out")?;
                // Context -> ONE reservation record (inputs + change) -> S1.
                super::receive::start_send(w, pick.wallet, &cands, &used, amount, dest, pending, out, ctx_out, tip.height, None)?;
            } else if let Some(i1_path) = o.pay_invoice {
                let i1 = std::fs::read_to_string(i1_path).map_err(|e| format!("invoice file: {e}"))?;
                if super::receive::resend_paid_invoice(w, pick.wallet, pending, &i1, out, Some(tip.height))?.is_some() {
                    return Ok(code);
                }
                let paid = super::receive::start_invoice_payment(w, pick.wallet, &cands, &used, &i1, pending, out, tip.height, None)?;
                let issuer = paid.issuer.clone().unwrap_or_else(|| "(no address given)".into());
                println!(
                    "PAY_INVOICE_SLATE_ID={}\nPAY_INVOICE_TO={issuer}\nPAY_INVOICE_AMOUNT={}\nPAY_INVOICE_FEE={}\nPAY_INVOICE_INPUTS={}\nPAY_INVOICE_CHANGE={}\nPAY_INVOICE_CHANGE_OUTPUT={}\nPAY_INVOICE_ANSWER={out}\nPAY_INVOICE=I2_READY (give the answer back to the issuer; it finalizes and broadcasts)",
                    paid.slate_id,
                    paid.amount,
                    paid.fee,
                    paid.inputs.iter().map(|i| i.commit.clone()).collect::<Vec<_>>().join(","),
                    paid.change,
                    paid.change_commit.0.to_hex()
                );
            }
            return Ok(code);
        }
        let (tx, new_commit, excess, new_id) = w.self_spend(&pick, &used)?;
        super::receive::reserve_payment(
            pending,
            pick.wallet + 1,
            &format!("self-spend-{}", excess.0.to_hex()),
            "self",
            &[pick.commit.0.to_hex()],
            tip.height,
            pick.amount - tx.fee(),
            &new_id,
            &new_commit.0.to_hex(),
            "self",
        )?;
        println!(
            "GAP_SPEND_WALLET={}\nGAP_SPEND_INPUT={}\nGAP_SPEND_INPUT_AMOUNT={}\nGAP_SPEND_NEW_OUTPUT={}\nGAP_SPEND_FEE={}\nGAP_SPEND_KERNEL_EXCESS={}\nGAP_SPEND_TX_VALIDATED=true",
            pick.wallet + 1,
            pick.commit.0.to_hex(),
            pick.amount,
            new_commit.0.to_hex(),
            tx.fee(),
            excess.0.to_hex()
        );
        if let Some(path) = o.tx_out {
            let b = ser::ser_vec(&tx, ProtocolVersion::local()).map_err(|e| format!("{e:?}"))?;
            std::fs::write(path, b.to_hex()).map_err(|e| format!("tx out: {e}"))?;
            println!("GAP_SPEND_TX_OUT={path}");
        }
        if o.broadcast {
            let mut ok = 0;
            for p in &o.peers {
                match wallet::broadcast(p, &tx) {
                    Ok(()) => {
                        ok += 1;
                        println!("GAP_SPEND_BROADCAST={p} SENT");
                    }
                    Err(e) => println!("GAP_SPEND_BROADCAST={p} FAIL {e}"),
                }
            }
            if ok == 0 {
                return Err("transaction was not sent to any peer".into());
            }
            println!("GAP_SPEND_NEXT=run gap again later with --commitment {} --commitment {}", pick.commit.0.to_hex(), new_commit.0.to_hex());
        } else {
            println!("GAP_SPEND_BROADCAST=SKIPPED (no --gap-broadcast)");
        }
        code = code.max(0);
    }
    Ok(code)
}

/// grin `verify_coinbase_maturity`: a coinbase output created at `created`
/// may be spent in block `tip + 1` when `created + maturity <= tip + 1`.
fn coinbase_mature(created: u64, tip: u64) -> bool {
    created.saturating_add(global::coinbase_maturity()) <= tip.saturating_add(1)
}

/// Pick the output to spend. The same eligibility rules apply to `auto`,
/// `auto:N` and an explicit commitment: own, unspent at the verified tip,
/// and, for coinbase, mature. Creation height comes from the proven block
/// that created it, else from the verified headers' output MMR sizes ("at or
/// before h" counts as h, i.e. the youngest it could be).
fn select_spend(
    found: &[wallet::Found],
    per: &[(Option<u64>, Option<u64>, Option<u64>)],
    tip_state: &OutputState,
    created_at: &HashMap<[u8; 33], u64>,
    all: &[BlockHeader],
    tip: u64,
    sel: &str,
    reserved: &HashMap<String, String>,
) -> Result<wallet::Found, String> {
    let created = |f: &wallet::Found| -> u64 {
        match created_at.get(&f.commit.0) {
            Some(h) => *h,
            None => match creation_height(f.pos0, all) {
                Ok(h) | Err(h) => h,
            },
        }
    };
    let eligible = |i: usize| -> Result<(), String> {
        let f = &found[i];
        if per[i].2.is_none() || tip_state.position(&f.commit.0).is_none() {
            return Err("not unspent at the verified tip".into());
        }
        if let Some(sid) = reserved.get(&f.commit.0.to_hex()) {
            return Err(format!(
                "reserved by the unfinished payment {sid} (until it is on chain or released with --release-inputs)"
            ));
        }
        if f.features.is_coinbase() && !coinbase_mature(created(f), tip) {
            return Err(format!(
                "immature coinbase (created {}, spendable from block {})",
                created(f),
                created(f) + global::coinbase_maturity()
            ));
        }
        Ok(())
    };
    if sel == "auto" || sel.starts_with("auto:") {
        let wn: Option<usize> = match sel.strip_prefix("auto:") {
            None => None,
            Some(n) => Some(n.parse().map_err(|_| "--gap-spend auto:N needs a wallet number")?),
        };
        (0..found.len())
            .filter(|&i| wn.map_or(true, |n| found[i].wallet + 1 == n))
            .filter(|&i| eligible(i).is_ok())
            .max_by_key(|&i| found[i].amount)
            .map(|i| found[i].clone())
            .ok_or(format!("no spendable own output at the tip ({sel})"))
    } else {
        let i = (0..found.len())
            .find(|&i| found[i].commit.0.to_hex() == sel)
            .ok_or("--gap-spend commitment is not an own output")?;
        eligible(i).map_err(|e| format!("--gap-spend {sel}: {e}"))?;
        Ok(found[i].clone())
    }
}

/// Wallet (0-based) a `--gap-spend` selector refers to, without choosing coins:
/// `auto:N` -> N-1, a commitment -> the wallet owning it, `auto` -> None.
fn spend_wallet(found: &[wallet::Found], sel: &str) -> Option<usize> {
    if let Some(n) = sel.strip_prefix("auto:") {
        return n.parse::<usize>().ok().filter(|&n| n > 0).map(|n| n - 1);
    }
    found.iter().find(|f| f.commit.0.to_hex() == sel).map(|f| f.wallet)
}

fn loaded_is_none(start_idx: usize, archive_idx: usize) -> bool {
    start_idx == archive_idx
}

// ---------------------------------------------------------------------------
// Tests: differential against grin-5.5.2 PMMR / BitmapAccumulator
// ---------------------------------------------------------------------------


#[cfg(test)]
mod tests {

    #[test]
    fn known_outputs_file_roundtrip_and_height_guard() {
        let dir = std::env::temp_dir().join(format!("grinsight-known-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("w.jsonl");
        let commit = "08".to_string() + &"11".repeat(32);
        let text = format!(
            "{{\"meta\":\"grinsight-wallet\",\"tip_height\":4100448}}\n{{\"wallet\":4,\"commit\":\"{commit}\",\"amount\":6475000000,\"key_id\":\"0300000000000000000000000200000000\",\"features\":\"Plain\",\"created\":4100442,\"unspent_at_tip\":true,\"spent_height\":null,\"tip_height\":4100448}}\n"
        );
        std::fs::write(&path, text).unwrap();
        let kf = load_known_outputs(path.to_str().unwrap(), &|_| Some(42)).unwrap();
        let (outs, created, tip) = (kf.outputs, kf.created, kf.tip);
        assert_eq!(kf.tip_hash, None);
        assert_eq!(kf.mac, None);
        assert_eq!(tip, 4100448);
        assert_eq!(outs.len(), 1);
        assert_eq!(outs[0].wallet, 3);
        assert_eq!(outs[0].amount, 6475000000);
        assert_eq!(outs[0].pos0, 42);
        assert_eq!(outs[0].commit.0.to_vec(), grin_util::from_hex(&commit).unwrap());
        assert_eq!(created.get(&outs[0].commit.0), Some(&4100442));
        // Empty wallet with only the meta line keeps its height.
        std::fs::write(&path, "{\"meta\":\"grinsight-wallet\",\"tip_height\":7}\n").unwrap();
        let kf = load_known_outputs(path.to_str().unwrap(), &|_| None).unwrap();
        let (outs, tip) = (kf.outputs, kf.tip);
        assert!(outs.is_empty());
        assert_eq!(tip, 7);
        // No height at all: refused.
        std::fs::write(&path, "").unwrap();
        assert!(load_known_outputs(path.to_str().unwrap(), &|_| None).is_err());
        // Meta line with the tip hash (new format).
        std::fs::write(&path, "{\"meta\":\"grinsight-wallet\",\"tip_height\":7,\"tip_hash\":\"00ab\"}\n").unwrap();
        let kf = load_known_outputs(path.to_str().unwrap(), &|_| None).unwrap();
        assert_eq!((kf.tip, kf.tip_hash.as_deref()), (7, Some("00ab")));
        // Duplicate commitment: refused.
        let rec = format!("{{\"wallet\":4,\"commit\":\"{commit}\",\"amount\":5,\"key_id\":\"0300000000000000000000000200000000\",\"features\":\"Plain\",\"tip_height\":7}}\n");
        std::fs::write(&path, format!("{{\"meta\":\"grinsight-wallet\",\"tip_height\":7}}\n{rec}{rec}")).unwrap();
        assert!(load_known_outputs(path.to_str().unwrap(), &|_| None).unwrap_err().contains("duplicate"));
        // mac line: body is every byte before it; nothing may follow it.
        let body = format!("{{\"meta\":\"grinsight-wallet\",\"tip_height\":7}}\n{rec}");
        std::fs::write(&path, format!("{body}{{\"mac\":\"abcd\",\"records\":1}}\n")).unwrap();
        let kf = load_known_outputs(path.to_str().unwrap(), &|_| None).unwrap();
        assert_eq!((kf.body.as_str(), kf.mac.as_deref()), (body.as_str(), Some("abcd")));
        std::fs::write(&path, format!("{body}{{\"mac\":\"abcd\",\"records\":1}}\n{rec}")).unwrap();
        assert!(load_known_outputs(path.to_str().unwrap(), &|_| None).is_err());
        // Broken line: refused.
        std::fs::write(&path, "{\"meta\":\"grinsight-wallet\",\"tip_height\":7}\n{\"wallet\":1,\"commit\":\"zz\"}\n").unwrap();
        assert!(load_known_outputs(path.to_str().unwrap(), &|_| None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn spend_wallet_without_coin_selection() {
        assert_eq!(spend_wallet(&[], "auto:4"), Some(3));
        assert_eq!(spend_wallet(&[], "auto:0"), None);
        assert_eq!(spend_wallet(&[], "auto"), None);
        assert_eq!(spend_wallet(&[], "08aa"), None);
    }

    /// Robustness fuzzing of what PEERS send: headers, blocks, PIBD segments
    /// and P2P handshake / segment messages, in every protocol version we
    /// speak. Property: decoding returns Ok or an error, never panics.
    /// Iterations: GRINSIGHT_FUZZ_ITERS (default 2000 per type).
    #[test]
    fn fuzz_peer_messages() {
        use grin_core::ser::{deserialize, DeserializationMode, ProtocolVersion};
        global::set_local_chain_type(ChainTypes::Testnet);
        let r = reference(400, 3);
        let (bm, out) = r.compacted_segments(4);
        let blk = block(&r.header(), &[id(9_000_001)], &[id(1)]);
        let v = ProtocolVersion::local();
        let mut seeds: Vec<Vec<u8>> = vec![
            ser::ser_vec(&r.header(), v).unwrap(),
            ser::ser_vec(&blk, v).unwrap(),
            ser::ser_vec(&bm[0], v).unwrap(),
            ser::ser_vec(&out[0], v).unwrap(),
            ser::ser_vec(&grin_core::genesis::genesis_test(), v).unwrap(),
        ];
        // a Hand as a peer sends it (version, capabilities, nonce, difficulty,
        // two addresses, user agent, genesis)
        let mut hand = Vec::new();
        hand.extend_from_slice(&3u32.to_be_bytes());
        hand.extend_from_slice(&0x0fu32.to_be_bytes());
        hand.extend_from_slice(&7u64.to_be_bytes());
        hand.extend_from_slice(&1u64.to_be_bytes());
        for _ in 0..2 {
            hand.push(0); // ipv4
            hand.extend_from_slice(&[127, 0, 0, 1]);
            hand.extend_from_slice(&3414u16.to_be_bytes());
        }
        hand.extend_from_slice(&5u64.to_be_bytes());
        hand.extend_from_slice(b"MW/x");
        hand.extend_from_slice(&[0u8; 32]);
        seeds.push(hand);
        let iters: usize = std::env::var("GRINSIGHT_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
        let mut st = 0x9e3779b97f4a7c15u64;
        let mut rnd = move || { st ^= st << 13; st ^= st >> 7; st ^= st << 17; st };
        for i in 0..iters {
            let mut d = seeds[(rnd() as usize) % seeds.len()].clone();
            for _ in 0..1 + rnd() % 4 {
                let n = d.len().max(1);
                match rnd() % 6 {
                    0 => { let k = rnd() as usize % n; if k < d.len() { d[k] ^= 1 << (rnd() % 8); } }
                    1 => { let k = rnd() as usize % n; d.truncate(k); }
                    2 => { let k = rnd() as usize % (d.len() + 1); for _ in 0..1 + rnd() % 8 { d.insert(k, rnd() as u8); } }
                    3 => { let k = rnd() as usize % n; if k + 8 <= d.len() { d[k..k + 8].copy_from_slice(&(rnd() | 0xff00_0000_0000_0000).to_be_bytes()); } } // huge length prefix
                    4 => { let k = rnd() as usize % n; if k < d.len() { d[k] = 0xff; } }
                    _ => { let a = rnd() as usize % n; let b = (a + 1 + rnd() as usize % 128).min(d.len()); if a < b { let x = d[a..b].to_vec(); d.extend_from_slice(&x); } }
                }
            }
            let res = std::panic::catch_unwind(|| {
                for ver in [ProtocolVersion(1), ProtocolVersion(2), ProtocolVersion(3)] {
                    let m = DeserializationMode::default();
                    let _ = deserialize::<BlockHeader, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<core::Block, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<core::Transaction, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<Segment<BitmapChunk>, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<Segment<OutputIdentifier>, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<Segment<RangeProof>, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<Segment<TxKernel>, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<grin_p2p::msg::Hand, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<grin_p2p::msg::Shake, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<grin_p2p::msg::PeerAddrs, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<grin_p2p::msg::OutputSegmentResponse, _>(&mut &d[..], ver, m);
                    let _ = deserialize::<grin_p2p::msg::OutputBitmapSegmentResponse, _>(&mut &d[..], ver, m);
                }
            });
            if res.is_err() {
                let p = std::env::temp_dir().join("grinsight-fuzz-peer-message.bin");
                let _ = std::fs::write(&p, &d);
                panic!("peer message decoding PANIC on mutation {i}; input saved to {}", p.display());
            }
        }
    }

    #[test]
    fn confirmed_block_rechecked_against_the_chain() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
        let mk = |height: u64, n: u64| {
            let mut h = BlockHeader::default();
            h.height = height;
            h.pow.proof.nonces = vec![n; 42];
            h
        };
        let all = vec![mk(100, 1), mk(101, 2), mk(102, 3)];
        let ok = format!("101:{}", all[1].hash().to_hex());
        assert!(check_block_on_chain(&all, &ok).starts_with("ON_VERIFIED_CHAIN depth=2"));
        let reorged = format!("101:{}", mk(101, 77).hash().to_hex());
        assert!(check_block_on_chain(&all, &reorged).starts_with("NOT_ON_VERIFIED_CHAIN"));
        assert!(check_block_on_chain(&all, "99:00").starts_with("BELOW_VERIFIED_RANGE"));
        assert!(check_block_on_chain(&all, "200:00").starts_with("ABOVE_VERIFIED_TIP"));
        assert!(check_block_on_chain(&all, "x").starts_with("BAD_SPEC"));
    }

    #[test]
    fn wallet_file_tip_must_be_on_the_verified_chain() {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Mainnet);
        let mk = |height: u64, nonce: u64| {
            let mut h = BlockHeader::default();
            h.height = height;
            h.pow.proof.nonces = vec![nonce; 42];
            h
        };
        let all = vec![mk(10, 1), mk(11, 2), mk(12, 3)];
        let good = all[1].hash().to_hex();
        assert!(known_tip_on_chain(&all, 11, Some(&good)).is_ok());
        // same height, other branch
        let fork = mk(11, 99).hash().to_hex();
        assert!(known_tip_on_chain(&all, 11, Some(&fork)).unwrap_err().contains("another branch"));
        // outside the verified headers, or no hash (old format): refused
        assert!(known_tip_on_chain(&all, 13, Some(&good)).is_err());
        assert!(known_tip_on_chain(&all, 11, None).unwrap_err().contains("older format"));
    }

    #[test]
    fn work_pool_fresh_items_then_endgame() {
        let pool = WorkPool::new(vec![0, 1, 2]);
        let mut slow: HashSet<u64> = HashSet::new();
        let mut fast: HashSet<u64> = HashSet::new();
        // Fresh items are dealt once.
        for _ in 0..2 {
            let i = pool.take(&slow).unwrap();
            slow.insert(i);
        }
        let i = pool.take(&fast).unwrap();
        fast.insert(i);
        assert_eq!(slow.len() + fast.len(), 3);
        assert!(pool.complete(i));
        // Endgame: the fast peer gets the items still outstanding at the slow one.
        let mut stolen = Vec::new();
        while let Some(i) = pool.take(&fast) {
            fast.insert(i);
            stolen.push(i);
        }
        stolen.sort();
        let mut want: Vec<u64> = slow.iter().copied().collect();
        want.sort();
        assert_eq!(stolen, want);
        for i in &stolen {
            assert!(pool.complete(*i));
        }
        // The slow peer's late copies are not counted twice.
        for i in &want {
            assert!(!pool.complete(*i));
        }
        assert!(pool.finished());
        assert_eq!(pool.missing(), 0);
        assert!(WorkPool::new(Vec::new()).finished());
    }
    use super::*;
    use grin_chain::txhashset::BitmapAccumulator;
    use grin_core::ser::PMMRIndexHashable;
    use grin_core::core::Inputs;
    use grin_core::core::pmmr::{ReadablePMMR, ReadonlyPMMR, VecBackend, PMMR};
    use grin_core::core::OutputFeatures;

    fn id(i: u32) -> OutputIdentifier {
        let mut c = [0u8; 33];
        c[0] = 8;
        c[1..5].copy_from_slice(&i.to_be_bytes());
        OutputIdentifier { features: OutputFeatures::Plain, commit: Commitment::from_vec(c.to_vec()) }
    }

    /// Reference chain kept with grin's own structures.
    struct Reference {
        backend: VecBackend<OutputIdentifier>,
        acc: BitmapAccumulator,
        leaves: Bitmap,
        pos: HashMap<[u8; 33], u64>,
    }

    impl Reference {
        fn new() -> Self {
            Reference { backend: VecBackend::new(), acc: BitmapAccumulator::new(), leaves: Bitmap::new(), pos: HashMap::new() }
        }
        fn size(&self) -> u64 {
            self.backend.size()
        }
        /// Apply like grin: outputs, then inputs, then accumulator.
        fn apply(&mut self, outs: &[OutputIdentifier], ins: &[OutputIdentifier]) {
            let mut affected = vec![];
            for o in outs {
                let size = self.backend.size();
                let pos0 = PMMR::at(&mut self.backend, size).push(o).unwrap();
                self.leaves.add(leaf_idx(pos0) as u32);
                self.pos.insert(o.commit.0, pos0);
                affected.push(leaf_idx(pos0));
            }
            for o in ins {
                let pos0 = self.pos.remove(&o.commit.0).unwrap();
                let size = self.backend.size();
                PMMR::at(&mut self.backend, size).prune(pos0).unwrap();
                self.leaves.remove(leaf_idx(pos0) as u32);
                affected.push(leaf_idx(pos0));
            }
            affected.sort_unstable();
            let start = BitmapAccumulator::chunk_start_idx(affected[0]);
            let n = pmmr::n_leaves(self.size());
            let it: Vec<u64> = self.leaves.iter().map(|x| x as u64).filter(|&x| x >= start).collect();
            self.acc.apply(affected, it, n).unwrap();
        }
        fn header(&self) -> BlockHeader {
            let mut h = BlockHeader::default();
            h.version = HeaderVersion(5);
            h.output_mmr_size = self.size();
            let root = ReadonlyPMMR::at(&self.backend, self.size()).root().unwrap();
            h.output_root = (root, self.acc.root()).hash_with_index(self.size());
            h
        }
        fn segments(&self, h: u8) -> (Vec<Segment<BitmapChunk>>, Vec<Segment<OutputIdentifier>>) {
            self.segments_from(h, false)
        }
        /// Segments as served by a node whose output PMMR was compacted with
        /// grin-5.5.2 store rules (`pos_to_rm` / `removed_excl_roots`).
        fn compacted_segments(&self, h: u8) -> (Vec<Segment<BitmapChunk>>, Vec<Segment<OutputIdentifier>>) {
            self.segments_from(h, true)
        }
        fn segments_from(&self, h: u8, compact: bool) -> (Vec<Segment<BitmapChunk>>, Vec<Segment<OutputIdentifier>>) {
            let size = self.size();
            let mut expanded: HashSet<u64> = HashSet::new();
            if compact {
                for pos0 in (0..size).filter(|&p| pmmr::is_leaf(p) && !self.leaves.contains(leaf_idx(p) as u32)) {
                    expanded.insert(pos0);
                    let mut cur = pos0;
                    loop {
                        let (parent, sibling) = pmmr::family(cur);
                        if parent < size && expanded.contains(&sibling) {
                            expanded.insert(parent);
                            cur = parent;
                        } else {
                            break;
                        }
                    }
                }
            }
            let gone: HashSet<u64> = expanded.iter().copied().filter(|&p| expanded.contains(&pmmr::family(p).0)).collect();
            let backend = Compacted { inner: &self.backend, gone };
            let ro = ReadonlyPMMR::at(&backend, size);
            let out = SegmentIdentifier::traversal_iter(size, h)
                .map(|id| Segment::from_pmmr(id, &ro, true).unwrap())
                .collect();
            let bro = self.acc.readonly_pmmr();
            let bsize = bro.unpruned_size();
            let bm = SegmentIdentifier::traversal_iter(bsize, BITMAP_SEGMENT_HEIGHT)
                .map(|id| Segment::from_pmmr(id, &bro, false).unwrap())
                .collect();
            (bm, out)
        }
    }

    struct Compacted<'a> {
        inner: &'a VecBackend<OutputIdentifier>,
        gone: HashSet<u64>,
    }

    impl<'a> pmmr::Backend<OutputIdentifier> for Compacted<'a> {
        fn append(&mut self, _: &OutputIdentifier, _: &[Hash]) -> Result<(), String> { unimplemented!() }
        fn append_pruned_subtree(&mut self, _: Hash, _: u64) -> Result<(), String> { unimplemented!() }
        fn append_hash(&mut self, _: Hash) -> Result<(), String> { unimplemented!() }
        fn rewind(&mut self, _: u64, _: &Bitmap) -> Result<(), String> { unimplemented!() }
        fn get_hash(&self, p: u64) -> Option<Hash> { self.get_from_file(p) }
        fn get_data(&self, p: u64) -> Option<OutputIdentifier> { self.get_data_from_file(p) }
        fn get_from_file(&self, p: u64) -> Option<Hash> { if self.gone.contains(&p) { None } else { self.inner.get_from_file(p) } }
        fn get_peak_from_file(&self, p: u64) -> Option<Hash> { self.get_from_file(p) }
        fn get_data_from_file(&self, p: u64) -> Option<OutputIdentifier> { if self.gone.contains(&p) { None } else { self.inner.get_data_from_file(p) } }
        fn leaf_pos_iter(&self) -> Box<dyn Iterator<Item = u64> + '_> { unimplemented!() }
        fn n_unpruned_leaves(&self) -> u64 { unimplemented!() }
        fn n_unpruned_leaves_to_index(&self, _: u64) -> u64 { unimplemented!() }
        fn leaf_idx_iter(&self, _: u64) -> Box<dyn Iterator<Item = u64> + '_> { unimplemented!() }
        fn remove(&mut self, _: u64) -> Result<(), String> { unimplemented!() }
        fn remove_from_leaf_set(&mut self, _: u64) { unimplemented!() }
        fn release_files(&mut self) {}
        fn reset_prune_list(&mut self) {}
        fn snapshot(&self, _: &BlockHeader) -> Result<(), String> { Ok(()) }
        fn dump_stats(&self) {}
    }

    fn reference(n: u32, spend_every: u32) -> Reference {
        let mut r = Reference::new();
        let outs: Vec<_> = (0..n).map(id).collect();
        r.apply(&outs, &[]);
        let spend: Vec<_> = (0..n).filter(|i| i % spend_every == 0).map(id).collect();
        r.apply(&[id(n + 1_000_000)], &spend);
        r
    }

    fn block(h: &BlockHeader, outs: &[OutputIdentifier], ins: &[OutputIdentifier]) -> core::Block {
        use grin_core::core::{CommitWrapper, Output, TransactionBody};
        let outputs: Vec<Output> = outs.iter().map(|o| Output { identifier: *o, proof: {
            // Realistic length; content is irrelevant to output_root.
            let mut p = RangeProof::zero();
            p.plen = grin_util::secp::constants::SINGLE_BULLET_PROOF_SIZE;
            p
        } }).collect();
        let inputs: Vec<CommitWrapper> = ins.iter().map(|o| o.commit.into()).collect();
        let body = TransactionBody::init(Inputs::CommitOnly(inputs), &outputs, &[], false).unwrap();
        core::Block { header: h.clone(), body }
    }

    fn write_headers_file(path: &str, hs: &[BlockHeader]) {
        let mut out = (hs.len() as u32).to_le_bytes().to_vec();
        for h in hs {
            let b = header_bytes(h);
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(&b);
        }
        std::fs::write(path, out).unwrap();
    }

    /// Full `run()` cycle with a state directory, offline through bundles:
    /// run 1 builds from archive segments and saves; run 2 starts from the
    /// saved state and only needs the new blocks; run 3 sees a reorg of the
    /// last block, falls back to the previous snapshot and re-applies.
    #[test]
    fn run_with_state_dir_incremental_and_reorg_fallback() {
        global::set_local_chain_type(ChainTypes::Testnet);
        SKIP_BODY_VALIDATE.store(true, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("gap-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = |n: &str| dir.join(n).to_str().unwrap().to_string();
        let state_dir = d("state");

        let mut r = reference(2000, 3);
        let (bm, out) = r.compacted_segments(4);
        let mut headers = vec![r.header()];
        headers[0].height = 720;
        let mut blocks: Vec<core::Block> = vec![];
        let mut next = 5_000_000u32;
        let mut mk = |r: &mut Reference, headers: &mut Vec<BlockHeader>, blocks: &mut Vec<core::Block>, spend: Vec<OutputIdentifier>| {
            next += 1;
            let outs = vec![id(next)];
            let mut b = block(&BlockHeader::default(), &outs, &spend);
            let sorted: Vec<OutputIdentifier> = input_commits(&b).iter().map(|c| *spend.iter().find(|x| x.commit == *c).unwrap()).collect();
            r.apply(&output_ids(&b), &sorted);
            let mut h = r.header();
            h.height = headers.last().unwrap().height + 1;
            h.prev_hash = headers.last().unwrap().hash();
            h.pow.nonce = h.height;
            // The header hash covers only the PoW proof: make it unique per
            // block, so blocks of two branches at one height differ.
            h.pow.proof.nonces = vec![next as u64; 42];
            b.header = h.clone();
            headers.push(h);
            blocks.push(b);
        };
        // Run 1: archive -> tip over 3 blocks; watched id(1) spent in block 2.
        mk(&mut r, &mut headers, &mut blocks, vec![id(2)]);
        mk(&mut r, &mut headers, &mut blocks, vec![id(1), id(4)]);
        mk(&mut r, &mut headers, &mut blocks, vec![id(5)]);
        write_headers_file(&d("h1.bin"), &headers);
        write_bundle(&d("b1.ugb"), &Bundle { peers: vec!["p".into()], blocks: vec![blocks.clone()], bitmap: bm.clone(), output: out.clone(), kernel: None, ..Default::default() }).unwrap();
        let opts = |headers: String, replay: String, commits: Vec<&str>| Opts {
            headers: Box::leak(headers.into_boxed_str()),
            commitments: commits.into_iter().map(String::from).collect(),
            peers: vec![],
            prove: true,
            out: None,
            replay: Some(Box::leak(replay.into_boxed_str())),
            segment_height: 11,
            per_min: 400,
            archive: Some(720),
            state_dir: Some(Box::leak(state_dir.clone().into_boxed_str())),
            seeds: None,
            wallet_out: None,
            wallet_in: None,
            pending: None,
            send_to: None,
            send_amount: None,
            slatepack_out: None,
            context_out: None,
            pay_invoice: None,
            spend: None,
            broadcast: false,
            allow_mainnet_spend: false,
            tx_out: None,
            kernels: vec![],
            check_blocks: vec![],
            blocks_all_peers: true,
            bootstrap: false,
            helper_output_segments: false,
        };
        let w = id(1).commit.0.to_hex();
        let u = id(7).commit.0.to_hex();
        assert_eq!(run(opts(d("h1.bin"), d("b1.ugb"), vec![&w])).unwrap(), 5);
        assert!(dir.join("state/state.ust").exists());
        let (st1, h1) = OutputState::load(&d("state/state.ust")).unwrap();
        assert_eq!(h1.height, 723);
        assert_eq!(st1.output_root(), headers[3].output_root);

        // Run 2: two more blocks; bundle holds only blocks 724..725.
        let n_before = blocks.len();
        mk(&mut r, &mut headers, &mut blocks, vec![id(8)]);
        mk(&mut r, &mut headers, &mut blocks, vec![id(10)]);
        write_headers_file(&d("h2.bin"), &headers);
        write_bundle(&d("b2.ugb"), &Bundle { peers: vec!["p".into()], blocks: vec![blocks[n_before..].to_vec()], ..Default::default() }).unwrap();
        // Two commitments: id(1) spent earlier (not in UTXO now), id(7) unspent.
        assert_eq!(run(opts(d("h2.bin"), d("b2.ugb"), vec![&w, &u])).unwrap(), 3);
        let (st2, h2) = OutputState::load(&d("state/state.ust")).unwrap();
        assert_eq!(h2.height, 725);
        assert_eq!(st2.output_root(), headers[5].output_root);
        assert!(dir.join("state/state.prev.ust").exists());
        // Fresh rebuild at 725 equals the incrementally maintained state.
        let (bm2, out2) = r.compacted_segments(3);
        let fresh = OutputState::from_segments(&r.header(), &bm2, &out2).unwrap();
        assert_eq!(fresh.pruned, st2.pruned);
        assert_eq!(fresh.leaves, st2.leaves);

        // Run 3: reorg replaces block 725 (different spend); state.ust is
        // unlinked, state.prev.ust (723) is on the chain and is used.
        let mut r3 = Reference::new();
        // Rebuild reference up to 724 deterministically by replaying bodies.
        {
            let outs: Vec<_> = (0..2000).map(id).collect();
            r3.apply(&outs, &[]);
            let spend: Vec<_> = (0..2000).filter(|i| i % 3 == 0).map(id).collect();
            r3.apply(&[id(2000 + 1_000_000)], &spend);
            for b in &blocks[..4] {
                let ins: Vec<OutputIdentifier> = input_commits(b).iter().map(|c| OutputIdentifier { features: OutputFeatures::Plain, commit: *c }).collect();
                r3.apply(&output_ids(b), &ins);
            }
            assert_eq!(r3.header().output_root, headers[4].output_root);
        }
        let mut headers3 = headers[..5].to_vec();
        let mut blocks3 = blocks[..4].to_vec();
        mk(&mut r3, &mut headers3, &mut blocks3, vec![id(11)]);
        assert_ne!(headers3[5].output_root, headers[5].output_root);
        write_headers_file(&d("h3.bin"), &headers3);
        write_bundle(&d("b3.ugb"), &Bundle { peers: vec!["p".into()], blocks: vec![blocks3[3..].to_vec()], ..Default::default() }).unwrap();
        assert_eq!(run(opts(d("h3.bin"), d("b3.ugb"), vec![&u])).unwrap(), 0);
        let (st3, h3) = OutputState::load(&d("state/state.ust")).unwrap();
        assert_eq!(h3.height, 725);
        assert_eq!(st3.output_root(), headers3[5].output_root);
        assert!(st3.position(&id(10).commit.0).is_some(), "id(10) is unspent again on the new branch");
        assert!(st3.position(&id(11).commit.0).is_none());

        // Run 4: nothing new; state at tip, no blocks needed, bundle ignored.
        assert_eq!(run(opts(d("h3.bin"), d("b3.ugb"), vec![&u])).unwrap(), 0);
        assert_eq!(run(opts(d("h3.bin"), d("b3.ugb"), vec![&id(11).commit.0.to_hex()])).unwrap(), 3);
        // A state file that is tampered with is ignored, not trusted.
        let path = d("state/state.ust");
        let mut raw = std::fs::read(&path).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 1;
        std::fs::write(&path, raw).unwrap();
        assert_eq!(run(opts(d("h3.bin"), d("b3.ugb"), vec![&u])).unwrap(), 0); // falls back to prev (723) + bundle
        let (st4, h4) = OutputState::load(&path).unwrap();
        assert_eq!((h4.height, st4.output_root()), (725, headers3[5].output_root));

        // ACCEPTANCE (reorg + payment confirmation): "our payment" spent id(10)
        // and was confirmed in block 725 of branch A (run 2). -Confirm keeps
        // HEIGHT:HASH of that block and re-checks it with --gap-check-block.
        let pay = id(10).commit.0.to_hex();
        let old725 = format!("725:{}", headers[5].hash().to_hex());
        assert!(check_block_on_chain(&headers[..6], &old725).starts_with("ON_VERIFIED_CHAIN depth=1"));
        // After the switch to branch B the confirming block is gone and the
        // payment's input is unspent again: the payment is NOT confirmed.
        assert!(check_block_on_chain(&headers3, &old725).starts_with("NOT_ON_VERIFIED_CHAIN"));
        let mut o = opts(d("h3.bin"), d("b3.ugb"), vec![&pay]);
        o.check_blocks = vec![old725.clone()];
        assert_eq!(run(o).unwrap(), 0, "id(10) unspent at the tip of branch B");
        // The same payment is mined again on branch B (block 726): the state
        // follows and the new block confirms it.
        mk(&mut r3, &mut headers3, &mut blocks3, vec![id(10)]);
        write_headers_file(&d("h5.bin"), &headers3);
        write_bundle(&d("b5.ugb"), &Bundle { peers: vec!["p".into()], blocks: vec![blocks3[5..].to_vec()], ..Default::default() }).unwrap();
        let new726 = format!("726:{}", headers3[6].hash().to_hex());
        let mut o = opts(d("h5.bin"), d("b5.ugb"), vec![&pay]);
        o.check_blocks = vec![old725.clone(), new726.clone()];
        assert_eq!(run(o).unwrap(), 5, "spent in the new block");
        let (st5, h5) = OutputState::load(&d("state/state.ust")).unwrap();
        assert_eq!((h5.height, st5.output_root()), (726, headers3[6].output_root));
        assert!(st5.position(&id(10).commit.0).is_none());
        assert!(check_block_on_chain(&headers3, &new726).starts_with("ON_VERIFIED_CHAIN depth=1"));
        assert!(check_block_on_chain(&headers3, &old725).starts_with("NOT_ON_VERIFIED_CHAIN"));
        std::fs::remove_dir_all(&dir).unwrap();
        SKIP_BODY_VALIDATE.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    #[test]
    fn spend_selection_applies_coinbase_maturity_to_every_path() {
        global::set_local_chain_type(ChainTypes::Mainnet); // maturity 1440
        let m = global::coinbase_maturity();
        assert!(coinbase_mature(100, 100 + m - 1));
        assert!(!coinbase_mature(100, 100 + m - 2));
        let r = reference(3000, 4);
        let (bm, out) = r.compacted_segments(4);
        let st = OutputState::from_segments(&r.header(), &bm, &out).unwrap();
        let mk = |c: OutputIdentifier, features, amount| wallet::Found {
            wallet: 0,
            pos0: st.position(&c.commit.0).unwrap(),
            commit: c.commit,
            features,
            amount,
            id: grin_keychain::ExtKeychainPath::new(3, 0, 0, 1, 0).to_identifier(),
            switch: grin_keychain::SwitchCommitmentType::Regular,
        };
        // Largest output is a coinbase created at the tip: immature.
        let found = vec![mk(id(1), OutputFeatures::Coinbase, 900), mk(id(2), OutputFeatures::Plain, 100)];
        let per = vec![(None, None, Some(1)), (None, None, Some(2))];
        let tip = 5000u64;
        let mut created_at = HashMap::new();
        created_at.insert(id(1).commit.0, tip);
        let hs = vec![BlockHeader::default()];
        let auto = select_spend(&found, &per, &st, &created_at, &hs, tip, "auto", &HashMap::new()).unwrap();
        assert_eq!(auto.commit, id(2).commit, "auto skips the immature coinbase");
        let direct = select_spend(&found, &per, &st, &created_at, &hs, tip, &id(1).commit.0.to_hex(), &HashMap::new());
        assert!(direct.unwrap_err().contains("immature coinbase"), "explicit commitment must not bypass maturity");
        // Mature once tip has advanced far enough.
        let later = select_spend(&found, &per, &st, &created_at, &hs, tip + m - 1, &id(1).commit.0.to_hex(), &HashMap::new()).unwrap();
        assert_eq!(later.commit, id(1).commit);
        // Not unspent at tip: refused on the explicit path too.
        let per_spent = vec![(Some(4999), None, None), (None, None, Some(2))];
        assert!(select_spend(&found, &per_spent, &st, &created_at, &hs, tip + m, &id(1).commit.0.to_hex(), &HashMap::new()).is_err());
        // Reserved by an unfinished payment: skipped by auto, refused explicitly.
        let mut res = HashMap::new();
        res.insert(id(2).commit.0.to_hex(), "slate-x".to_string());
        assert!(select_spend(&found, &per, &st, &created_at, &hs, tip, "auto", &res).is_err(), "only the immature coinbase is left");
        assert!(select_spend(&found, &per, &st, &created_at, &hs, tip, &id(2).commit.0.to_hex(), &res).unwrap_err().contains("slate-x"));
        global::set_local_chain_type(ChainTypes::Testnet);
    }
}

/// Ask a peer for the legacy TxHashSet archive at a specific header. The node
/// snapshots its current txhashset into its temp directory and streams it.
pub(super) fn request_txhashset(peer_arg: &str, hash_hex: &str, height: u64) -> Result<(), String> {
    use grin_core::core::hash::Hash;
    let hash = Hash::from_hex(hash_hex).map_err(|_| "bad header hash")?;
    let c = Conn::open(peer_arg, Capabilities::default() | Capabilities::TXHASHSET_HIST | Capabilities::BLOCK_HIST)?;
    c.peer.send_txhashset_request(height, hash).map_err(|e| format!("txhashset request: {e:?}"))?;
    std::thread::sleep(Duration::from_secs(60));
    c.close();
    Ok(())
}