//! Header sync over standard Grin P2P (`Hand`/`Shake` + `GetHeaders`).
//!
//! RESEARCH / NOT VERIFIED. No consensus change; no mainnet.
//!
//! The client fetches headers from an existing peer and verifies PoW, linkage
//! and post-HF4 WTEMA locally. It does not trust a prover or run its own server.
//! MMR-prefix verification needs a checkpoint prefix; this prototype reports it
//! as PENDING rather than claiming it.

use chrono::{DateTime, Utc};
use grin_chain::txhashset::BitmapChunk;
use grin_core::core::hash::{Hash, Hashed};

use grin_core::core::{pmmr, BlockHeader, HeaderVersion, OutputIdentifier, Segment, SegmentIdentifier, TxKernel};
use grin_core::global::{self, ChainTypes};
use grin_core::pow::Difficulty;
use grin_core::ser::{self, ProtocolVersion};
use grin_core::core;
use grin_p2p::handshake::Handshake;
use grin_p2p::types::{
    Capabilities, ChainAdapter, NetAdapter, P2PConfig, PeerAddr, PeerInfo, TxHashSetRead,
};
use grin_p2p::Peer;
use grin_util::secp::pedersen::RangeProof;
use grin_util::ToHex;
use std::fs::File;
use std::net::TcpStream;
use std::path::PathBuf;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
// Network-free core (stage 1): header verification, header MMR, checkpoints,
// signed releases, chain choice.
use grinsight_state::headers::*;
use grinsight_state::{mmr, release};
use grinsight_state::outputs::bind_block;

mod pibd;
mod gap;
mod helper_p2p;
mod wallet;
mod receive;

/// Load a recent verified tip bound to this wallet's authenticated output file.
/// Never accept the numeric height from the output file as proof by itself.
fn verified_profile_tip(profile: &std::path::Path, seeds: &str, mainnet: bool) -> Result<u64, String> {
    use grinsight_state::session::{header_age, now_unix, Freshness, Network, Session, DEFAULT_MAX_TIP_AGE_SEC};
    let last: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(profile.join("last-open.json")).map_err(|_| "verified session is unavailable")?).map_err(|_| "invalid verified session pointer")?;
    let folder = last["session"].as_str().ok_or("verified session folder missing")?;
    let pin = last["manifest_sha256"].as_str().ok_or("verified session pin missing")?;
    let session = Session::open(std::path::Path::new(folder), pin)?;
    let expected = if mainnet { Network::Mainnet } else { Network::Floonet };
    if session.manifest.network != expected { return Err("verified session belongs to a different network".into()); }
    session.spend_gate(now_unix())?;
    if header_age(session.tip_header(), DEFAULT_MAX_TIP_AGE_SEC, now_unix())?.0 != Freshness::Fresh {
        return Err("verified session tip is too old; refresh before accepting a timed payment".into());
    }
    let height = session.tip_height();
    if last["tip_height"].as_u64() != Some(height) { return Err("session height mismatch".into()); }
    let hash = session.tip_hash().ok_or("cannot read verified tip header")?;
    let known = std::fs::read_to_string(profile.join("wallet-outputs.jsonl")).map_err(|_| "verified wallet outputs unavailable")?;
    let wallets = grinsight_state::wallet::Wallets::from_file(seeds)?;
    let mut entropy = zeroize::Zeroizing::new(Vec::new());
    for i in 0..wallets.len() { entropy.push(wallets.entropy(i).ok_or("wallet entropy unavailable")?.to_vec()); }
    grinsight_state::balance::check_binding(&known, &entropy, Some((height, hash.as_str())))?;
    Ok(height)
}

struct SyncAdapter {
    peer_claim: Arc<Mutex<(u64, u64)>>,
    headers: Arc<Mutex<Vec<BlockHeader>>>,
    blocks: Arc<Mutex<Vec<core::Block>>>,
    /// AUDIT R2 N-2/N-7: hashes we actually requested. Anything else a peer
    /// pushes (unsolicited blocks) is dropped, and the buffer is bounded.
    wanted: Arc<Mutex<HashSet<Hash>>>,
    segments: Arc<Mutex<SegmentInbox>>,
    /// Transaction we are relaying; answered to GetTransaction by kernel hash.
    outgoing_tx: Arc<Mutex<Option<core::Transaction>>>,
}

#[derive(Default)]
struct SegmentInbox {
    wanted: Option<(Hash, SegmentIdentifier, SegmentIdentifier)>,
    bitmap: Option<(Hash, Hash, Segment<BitmapChunk>)>,
    output: Option<(Hash, Hash, Segment<OutputIdentifier>)>,
    /// Bulk mode for `--gap-headers --prove` (every archive segment).
    bulk: Option<gap::BulkInbox>,
}

/// Checkpoint generation from genesis: keep a 32-byte digest of every
/// validated header instead of the header itself (4M+ headers on mainnet),
/// and compare peers by those digests.
/// Peer addresses gossiped to us (GetPeerAddrs answers), used by `--probe-peer --discover`.
static DISCOVERED: Mutex<Vec<PeerAddr>> = Mutex::new(Vec::new());
static DIGEST_RUN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Stop syncing at this height (0 = no limit), so a checkpoint is cut below the tip.
static STOP_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// --stop-below-tip N: stop at floor((peer tip - N) / 720) * 720, decided from
/// the first peer that tells its height (a checkpoint below the PIBD archive).
static STOP_BELOW_TIP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// --progress-dir: periodic resumable snapshots of a long (genesis) sync.
static PROGRESS_DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();
const PROGRESS_EVERY: u64 = 100_000;
/// --snapshot-at H --snapshot-dir D: keep the verifier state at height H of
/// every peer's chain; the chosen chain's one is written as a new (rolling)
/// checkpoint, so the next sync starts there instead of at the old one.
static SNAPSHOT_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn snapshots() -> &'static Mutex<HashMap<String, Verifier>> {
    static S: std::sync::OnceLock<Mutex<HashMap<String, Verifier>>> = std::sync::OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}
/// --check-header HEIGHT:HASH: report whether the validated chain has this
/// header (e.g. the signed release checkpoint, seen from one's own chain).
static CHECK_HEADER: std::sync::OnceLock<(u64, String)> = std::sync::OnceLock::new();

/// Two alternating snapshot slots; `complete` is written last, so a crash
/// mid-write leaves the other slot usable.
fn save_progress(v: &Verifier, dir: &str) {
    let slot = |i: u8| std::path::Path::new(dir).join(format!("progress-{i}"));
    let height_of = |i: u8| -> u64 {
        std::fs::read_to_string(slot(i).join("complete")).ok().and_then(|t| t.trim().parse().ok()).unwrap_or(0)
    };
    let done = |i: u8| slot(i).join("complete").exists();
    let i = if !done(0) { 0 } else if !done(1) { 1 } else if height_of(0) <= height_of(1) { 0 } else { 1 };
    let d = slot(i);
    let _ = std::fs::remove_file(d.join("complete"));
    if std::fs::create_dir_all(&d).is_err() {
        return;
    }
    write_checkpoint_to_quiet(v, d.join("checkpoint.rwm").to_str().unwrap_or_default());
    let mut out = Vec::new();
    out.extend_from_slice(&(v.recent.len() as u32).to_le_bytes());
    for h in &v.recent {
        if let Ok(b) = ser::ser_vec(h, ProtocolVersion::local()) {
            out.extend_from_slice(&(b.len() as u32).to_le_bytes());
            out.extend_from_slice(&b);
        }
    }
    if std::fs::write(d.join("recent-headers.bin"), out).is_ok() {
        let _ = std::fs::write(d.join("complete"), v.tip.height.to_string());
        println!("HEADER_SYNC_SAVED_PROGRESS height={}", v.tip.height);
    }
}

/// The newest complete progress slot that loads and checks like any
/// checkpoint; a broken newest slot falls back to the other one.
fn load_progress(dir: &str) -> Option<Verifier> {
    let mut slots: Vec<(u64, std::path::PathBuf)> = (0..2u8)
        .filter_map(|i| {
            let d = std::path::Path::new(dir).join(format!("progress-{i}"));
            let h = std::fs::read_to_string(d.join("complete")).ok()?.trim().parse::<u64>().ok()?;
            Some((h, d))
        })
        .collect();
    slots.sort_by_key(|(h, _)| std::cmp::Reverse(*h));
    for (h, d) in slots {
        let loaded = load_checkpoint(d.join("checkpoint.rwm").to_str()?, None).and_then(|mut v| {
            let hs = read_state_headers(d.to_str().unwrap_or_default())?.ok_or("no recent headers")?;
            v.restore_recent(hs)?;
            Ok(v)
        });
        match loaded {
            Ok(v) => {
                println!("HEADER_SYNC_RESUMED_AT={h}");
                return Some(v);
            }
            Err(e) => println!("HEADER_SYNC_PROGRESS_IGNORED {} ({e})", d.display()),
        }
    }
    None
}

/// AUDIT R2 N-7: max blocks buffered at once (one request window is 64).
const MAX_PENDING_BLOCKS: usize = 128;

/// AUDIT R2 N-2/N-7: keep a block only if we requested its hash (each hash
/// once) and the buffer is not full. Returns whether it was kept.
fn accept_requested_block(
    wanted: &Mutex<HashSet<Hash>>,
    blocks: &Mutex<Vec<core::Block>>,
    b: core::Block,
) -> bool {
    let mut bs = blocks.lock().unwrap();
    if bs.len() >= MAX_PENDING_BLOCKS {
        return false;
    }
    if !wanted.lock().unwrap().remove(&b.header.hash()) {
        return false;
    }
    bs.push(b);
    true
}

/// AUDIT: was `unimplemented!()`, i.e. a remote peer could panic us with a
/// PIBD/archive request. A light client simply does not serve these.
fn not_served() -> grin_chain::Error {
    grin_chain::Error::Other("light client does not serve this".into())
}

impl ChainAdapter for SyncAdapter {
    fn total_difficulty(&self) -> Result<Difficulty, grin_chain::Error> {
        Ok(Difficulty::min_dma())
    }
    fn total_height(&self) -> Result<u64, grin_chain::Error> {
        Ok(0)
    }
    fn get_transaction(&self, h: Hash) -> Option<core::Transaction> {
        let tx = self.outgoing_tx.lock().ok()?.clone()?;
        if tx.kernels().first().map(|k| k.hash()) == Some(h) { Some(tx) } else { None }
    }
    fn tx_kernel_received(&self, _h: Hash, _p: &PeerInfo) -> Result<bool, grin_chain::Error> {
        Ok(true)
    }
    fn transaction_received(&self, _t: core::Transaction, _stem: bool) -> Result<bool, grin_chain::Error> {
        Ok(true)
    }
    fn compact_block_received(&self, _b: core::CompactBlock, _p: &PeerInfo) -> Result<bool, grin_chain::Error> {
        Ok(true)
    }
    fn header_received(&self, _h: core::BlockHeader, _p: &PeerInfo) -> Result<bool, grin_chain::Error> {
        // AUDIT: unsolicited header announcements used to be appended to the
        // same buffer as GetHeaders responses and break linkage. Ignore them.
        Ok(true)
    }
    fn block_received(&self, b: core::Block, _p: &PeerInfo, _o: grin_chain::Options) -> Result<bool, grin_chain::Error> {
        accept_requested_block(&self.wanted, &self.blocks, b);
        Ok(true)
    }
    fn headers_received(&self, hs: &[core::BlockHeader], _p: &PeerInfo) -> Result<bool, grin_chain::Error> {
        self.headers.lock().unwrap().extend(hs.iter().cloned());
        Ok(true)
    }
    fn locate_headers(&self, _l: &[Hash]) -> Result<Vec<core::BlockHeader>, grin_chain::Error> {
        Ok(vec![])
    }
    fn get_block(&self, _h: Hash, _p: &PeerInfo) -> Option<core::Block> {
        None
    }
    fn txhashset_read(&self, _h: Hash) -> Option<TxHashSetRead> {
        None
    }
    fn txhashset_archive_header(&self) -> Result<core::BlockHeader, grin_chain::Error> {
        Err(not_served())
    }
    fn txhashset_receive_ready(&self) -> bool {
        false
    }
    fn txhashset_write(&self, _h: Hash, _f: File, _p: &PeerInfo) -> Result<bool, grin_chain::Error> {
        Ok(false)
    }
    fn txhashset_download_update(&self, _s: DateTime<Utc>, _d: u64, _t: u64) -> bool {
        false
    }
    fn get_tmp_dir(&self) -> PathBuf {
        PathBuf::from(".")
    }
    fn get_tmpfile_pathname(&self, n: String) -> PathBuf {
        PathBuf::from(n)
    }
    fn get_kernel_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<Segment<TxKernel>, grin_chain::Error> {
        Err(not_served())
    }
    fn get_bitmap_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<(Segment<BitmapChunk>, Hash), grin_chain::Error> {
        Err(not_served())
    }
    fn get_output_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<(Segment<OutputIdentifier>, Hash), grin_chain::Error> {
        Err(not_served())
    }
    fn get_rangeproof_segment(&self, _h: Hash, _i: SegmentIdentifier) -> Result<Segment<RangeProof>, grin_chain::Error> {
        Err(not_served())
    }
    fn receive_bitmap_segment(&self, b: Hash, o: Hash, s: Segment<BitmapChunk>) -> Result<bool, grin_chain::Error> {
        let mut inbox=self.segments.lock().map_err(|_|not_served())?;
        if let Some(bulk)=inbox.bulk.as_mut(){return Ok(bulk.accept_bitmap(b,o,s))}
        if inbox.wanted.as_ref().map(|w|(w.0,w.1))==Some((b,s.identifier())) && inbox.bitmap.is_none(){inbox.bitmap=Some((b,o,s));return Ok(true)}
        Ok(false)
    }
    fn receive_output_segment(&self, b: Hash, r: Hash, s: Segment<OutputIdentifier>) -> Result<bool, grin_chain::Error> {
        let mut inbox=self.segments.lock().map_err(|_|not_served())?;
        if let Some(bulk)=inbox.bulk.as_mut(){return Ok(bulk.accept_output(b,r,s))}
        if inbox.wanted.as_ref().map(|w|(w.0,w.2))==Some((b,s.identifier())) && inbox.output.is_none(){inbox.output=Some((b,r,s));return Ok(true)}
        Ok(false)
    }
    fn receive_rangeproof_segment(&self, b: Hash, s: Segment<RangeProof>) -> Result<bool, grin_chain::Error> {
        let mut inbox=self.segments.lock().map_err(|_|not_served())?;
        if let Some(bulk)=inbox.bulk.as_mut(){return Ok(bulk.accept_rproof(b,s))}
        Ok(false)
    }
    fn receive_kernel_segment(&self, b: Hash, s: Segment<TxKernel>) -> Result<bool, grin_chain::Error> {
        let mut inbox=self.segments.lock().map_err(|_|not_served())?;
        if let Some(bulk)=inbox.bulk.as_mut(){return Ok(bulk.accept_kernel(b,s))}
        Ok(false)
    }
}

impl NetAdapter for SyncAdapter {
    fn find_peer_addrs(&self, _c: Capabilities) -> Vec<PeerAddr> {
        vec![]
    }
    fn peer_addrs_received(&self, p: Vec<PeerAddr>) {
        let mut d = DISCOVERED.lock().unwrap();
        for a in p {
            if d.len() >= 512 { break; }
            if !d.contains(&a) { d.push(a); }
        }
    }
    fn peer_difficulty(&self, _a: PeerAddr, d: Difficulty, h: u64) { *self.peer_claim.lock().unwrap() = (h, d.to_num()); }
    fn is_banned(&self, _a: PeerAddr) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Sync from one peer
// ---------------------------------------------------------------------------

fn sync_from_peer(peer_arg: &str, mut v: Verifier, batches: usize, tail_blocks: usize, blocks_dir: &str, fetch_all: bool) -> Result<(Verifier, u64, u64), String> {
    let initial_header = v.tip.clone();
    let genesis = global::get_genesis_block().header.hash();
    let hs = Handshake::new(genesis, P2PConfig::default());
    let buf = Arc::new(Mutex::new(Vec::new()));
    let blocks = Arc::new(Mutex::new(Vec::new()));
    let wanted = Arc::new(Mutex::new(HashSet::new()));
    let peer_claim = Arc::new(Mutex::new((0, 0)));
    let caps = Capabilities::default() | Capabilities::BLOCK_HIST;
    // A node refuses a new connection from an IP it still lists as connected
    // (another tool of ours talking to it a moment ago): retry with a pause.
    let mut last_err = String::new();
    let mut connected = None;
    for attempt in 0..6 {
        if attempt > 0 {
            println!("HEADER_SYNC_RECONNECT={peer_arg} attempt={} after: {last_err}", attempt + 1);
            std::thread::sleep(Duration::from_secs(if attempt <= 3 { 7 } else { 20 }));
        }
        let conn = match TcpStream::connect(peer_arg) {
            Ok(c) => c,
            Err(e) => { last_err = format!("connect {e}"); continue; }
        };
        let local = match conn.local_addr() {
            Ok(l) => l,
            Err(e) => { last_err = format!("local addr {e}"); continue; }
        };
        let adapter = Arc::new(SyncAdapter { peer_claim: peer_claim.clone(), headers: buf.clone(), blocks: blocks.clone(), wanted: wanted.clone(), segments: Arc::new(Mutex::new(SegmentInbox::default())), outgoing_tx: Arc::new(Mutex::new(None)) });
        match Peer::connect(conn, caps, Difficulty::min_dma(), PeerAddr(local), &hs, adapter) {
            Ok(p) => { connected = Some(p); break; }
            Err(e) => last_err = format!("handshake {e:?}"),
        }
    }
    let peer = connected.ok_or(last_err)?;

    let _ = peer.send_ping(v.tip.total_difficulty(), v.tip.height);
    let mut fetched: Vec<BlockHeader> = Vec::new();
    let digest_run = DIGEST_RUN.load(std::sync::atomic::Ordering::Relaxed);
    let mut stop_at = STOP_AT.load(std::sync::atomic::Ordering::Relaxed);
    let start_height = initial_header.height;
    let mut last_saved = initial_header.height;
    let mut digests: Vec<Hash> = Vec::new();
    let progress = Instant::now();
    // Grin bans a peer that sends more than 500 messages/min; stay at <= 300
    // header requests per minute (one every 200 ms) with a wide margin.
    let mut last_request = Instant::now() - Duration::from_secs(1);
    let mut silent_retries = 0u32;
    let result = (|| {
        for batch in 0..batches {
            let below = STOP_BELOW_TIP.load(std::sync::atomic::Ordering::Relaxed);
            if below > 0 && stop_at == 0 {
                let claimed = peer_claim.lock().unwrap().0;
                // A peer could claim a huge tip to push the stop height out of
                // reach: a claim cannot exceed what time since genesis allows.
                let max_plausible = max_plausible_height(Utc::now());
                if claimed > max_plausible {
                    println!("HEADER_SYNC_IMPLAUSIBLE_TIP peer={peer_arg} claimed={claimed} max={max_plausible} (ignored)");
                } else if claimed > below {
                    let want = (claimed - below) / 720 * 720;
                    let _ = STOP_AT.compare_exchange(0, want, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst);
                    stop_at = STOP_AT.load(std::sync::atomic::Ordering::Relaxed);
                    println!("HEADER_SYNC_STOP_AT={stop_at} (peer {peer_arg} tip {claimed} - {below}, aligned to 720)");
                }
            } else if stop_at == 0 {
                stop_at = STOP_AT.load(std::sync::atomic::Ordering::Relaxed);
            }
            let since = last_request.elapsed();
            if since < HEADER_REQUEST_INTERVAL {
                std::thread::sleep(HEADER_REQUEST_INTERVAL - since);
            }
            last_request = Instant::now();
            buf.lock().unwrap().clear();
            // Reorg-aware locator: newest first, a few ancestors. The peer
            // answers with headers after its highest common ancestor.
            let locators: Vec<Hash> = v
                .snapshots
                .iter()
                .rev()
                .take(16)
                .map(|s| s.tip.hash())
                .collect();
            peer.send_header_request(locators)
                .map_err(|e| format!("getheaders batch {batch}: {e:?}"))?;
            // AUDIT: Grin streams a Headers response in chunks of 32. Wait for
            // the full response (512 headers, or 2s of silence) before sending
            // the next locator, otherwise chunks of two batches interleave.
            let start = Instant::now();
            let mut last_len = 0usize;
            let mut last_change = Instant::now();
            loop {
                std::thread::sleep(Duration::from_millis(50));
                let n = buf.lock().unwrap().len();
                if n != last_len {
                    last_len = n;
                    last_change = Instant::now();
                }
                if n >= MAX_BLOCK_HEADERS {
                    break;
                }
                if n > 0 && last_change.elapsed() > Duration::from_secs(2) {
                    break;
                }
                if n == 0 && start.elapsed() > Duration::from_secs(15) {
                    break;
                }
            }
            let mut got: Vec<BlockHeader> = std::mem::take(&mut *buf.lock().unwrap());
            let response_len = got.len();
            got.sort_by_key(|h| h.height);
            got.dedup_by_key(|h| h.hash());
            // AUDIT R2 N-3: headers we already hold are not a fork.
            got.retain(|h| !v.is_known(h));
            if got.is_empty() {
                if response_len == 0 && stop_at != 0 && v.tip.height < stop_at {
                    // Silence below the requested height is not "end of chain":
                    // the peer dropped us (ban, restart). Report it.
                    return Err(format!("peer stopped answering at height {} (below --stop-at {stop_at})", v.tip.height));
                }
                // No answer at all while the peer claims (or has not yet said)
                // a higher tip: a slow or busy peer, not the end of its chain.
                // Ask again a few times before concluding.
                let claimed = peer_claim.lock().unwrap().0;
                if response_len == 0 && silent_retries < 3 && (claimed == 0 || claimed > v.tip.height) {
                    silent_retries += 1;
                    println!("HEADER_SYNC_RETRY={peer_arg} height={} claimed={claimed} attempt={silent_retries}", v.tip.height);
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
                if response_len < MAX_BLOCK_HEADERS {
                    break; // peer has nothing beyond our tip
                }
                continue;
            }
            let first_height = got[0].height;
            if first_height > v.tip.height + 1 {
                return Err(format!(
                    "peer response starts at {first_height}, above our tip {} + 1",
                    v.tip.height
                ));
            }
            // AUDIT R2 N-3: a fork is validated on a copy and adopted only if
            // it ends with strictly more total work than the branch we had.
            let mut fork_base: Option<(Verifier, Vec<BlockHeader>, Vec<Hash>)> = None;
            if first_height <= v.tip.height {
                let common = got[0].prev_hash;
                let old_height = v.tip.height;
                let before = (v.clone(), fetched.clone(), digests.clone());
                let depth = v
                    .rollback_to(&common)
                    .map_err(|e| format!("reorg rollback: {e}"))?;
                let base = v.tip.height;
                fetched.retain(|h| h.height <= base);
                digests.truncate(base.saturating_sub(start_height) as usize);
                println!(
                    "HEADER_SYNC_REORG_CANDIDATE old_height={old_height} new_base={base} depth={depth}"
                );
                fork_base = Some(before);
            }
            let fresh: Vec<&BlockHeader> = got
                .iter()
                .filter(|h| h.height > v.tip.height && (stop_at == 0 || h.height <= stop_at))
                .collect();
            if fresh.is_empty() {
                if let Some((before, _, _)) = fork_base.take() {
                    v = before; // nothing usable on the fork: keep our branch
                }
                break;
            }
            if fresh[0].height != v.tip.height + 1 {
                return Err(format!(
                    "peer response starts at {}, expected {}",
                    fresh[0].height,
                    v.tip.height + 1
                ));
            }
            let mut fork_err: Option<String> = None;
            for h in &fresh {
                if let Err(e) = v.validate_and_append(h) {
                    if fork_base.is_some() {
                        fork_err = Some(e);
                        break;
                    }
                    return Err(e);
                }
                let snap_at = SNAPSHOT_AT.load(std::sync::atomic::Ordering::Relaxed);
                if snap_at != 0 && h.height == snap_at {
                    snapshots().lock().unwrap().insert(peer_arg.to_string(), v.clone());
                }
                if let Some((ch, want)) = CHECK_HEADER.get() {
                    if h.height == *ch {
                        let got = h.hash().to_hex();
                        println!("HEADER_SYNC_CHECK_HEADER={} height={ch} ours={got} expected={want}", if &got == want { "MATCH" } else { "MISMATCH" });
                    }
                }
                if digest_run {
                    digests.push(header_digest(h));
                } else {
                    fetched.push((*h).clone());
                }
            }
            if let Some((before, before_fetched, before_digests)) = fork_base.take() {
                let old_work = before.tip.total_difficulty();
                let new_work = v.tip.total_difficulty();
                if !fork_wins(old_work, new_work, fork_err.is_none()) {
                    println!(
                        "HEADER_SYNC_REORG_REJECTED reason={} old_work={} new_work={}",
                        fork_err.as_deref().unwrap_or("not more work"),
                        old_work.to_num(),
                        new_work.to_num()
                    );
                    // Restore our branch exactly as it was before the fork.
                    v = before;
                    fetched = before_fetched;
                    digests = before_digests;
                    break; // stop syncing from a peer that offered a weaker fork
                }
                println!(
                    "HEADER_SYNC_REORG_ACCEPTED old_work={} new_work={} tip={}",
                    old_work.to_num(),
                    new_work.to_num(),
                    v.tip.height
                );
            }
            if let Some(dir) = PROGRESS_DIR.get() {
                if v.tip.height >= last_saved + PROGRESS_EVERY {
                    save_progress(&v, dir);
                    last_saved = v.tip.height;
                }
            }
            if digest_run && batch % 200 == 0 {
                println!(
                    "HEADER_SYNC_PROGRESS={peer_arg} height={} elapsed_s={}",
                    v.tip.height,
                    progress.elapsed().as_secs()
                );
            }
            if stop_at != 0 && v.tip.height >= stop_at {
                break; // reached the requested checkpoint height
            }
            if response_len < MAX_BLOCK_HEADERS {
                break; // short response: peer reached its tip
            }
        }
        if tail_blocks > 0 || fetch_all {
            // AUDIT R2 N-2: every requested block must match a header this
            // run has validated (full serialized bytes, not just the hash,
            // which in Grin commits only to the PoW nonces).
            let validated: HashMap<Hash, BlockHeader> = fetched
                .iter()
                .chain(v.recent.iter())
                .filter(|h| h.height <= v.tip.height)
                .map(|h| (h.hash(), h.clone()))
                .collect();
            let hashes: Vec<Hash> = if fetch_all {
                fetched.iter().map(|h| h.hash()).collect()
            } else {
                v.recent
                    .iter()
                    .rev()
                    .take(tail_blocks)
                    .map(|h| h.hash())
                    .collect()
            };
            let total = hashes.len();
            let mut cursor = 0usize;
            let mut stored = 0usize;
            while cursor < total {
                let end = (cursor + 64).min(total);
                blocks.lock().unwrap().clear();
                {
                    let mut w = wanted.lock().unwrap();
                    w.clear();
                    w.extend(hashes[cursor..end].iter().cloned());
                }
                for hash in &hashes[cursor..end] {
                    peer.send_block_request(*hash, grin_chain::Options::NONE)
                        .map_err(|e| format!("getblock {hash:?}: {e:?}"))?;
                }
                let deadline = Instant::now() + Duration::from_secs(45);
                loop {
                    if wanted.lock().unwrap().is_empty() {
                        break;
                    }
                    if Instant::now() > deadline {
                        return Err(format!("getblock batch timeout at {cursor}/{total}"));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                let got_blocks: Vec<core::Block> = std::mem::take(&mut *blocks.lock().unwrap());
                for hash in &hashes[cursor..end] {
                    let b = got_blocks
                        .iter()
                        .find(|b| b.header.hash() == *hash)
                        .ok_or_else(|| format!("block {hash:?} missing"))?;
                    let hdr = validated
                        .get(hash)
                        .ok_or_else(|| format!("block {hash:?} has no validated header"))?;
                    let prev = validated.get(&hdr.prev_hash);
                    bind_block(hdr, prev, b)?;
                    if !blocks_dir.is_empty() {
                        let bytes = ser::ser_vec(b, ProtocolVersion::local())
                            .map_err(|e| format!("serialize block: {e:?}"))?;
                        std::fs::create_dir_all(blocks_dir)
                            .map_err(|e| format!("create blocks dir: {e}"))?;
                        // Name by height *and* hash so a later fork cannot
                        // silently overwrite a block of another branch.
                        let path = std::path::Path::new(blocks_dir)
                            .join(format!("{}-{}.bin", b.header.height, &hash.to_hex()[..16]));
                        std::fs::write(&path, &bytes).map_err(|e| format!("write block: {e}"))?;
                    }
                    stored += 1;
                }
                cursor = end;
                println!("HEADER_SYNC_BLOCK_BATCH={cursor}/{total}");
            }
            println!("HEADER_SYNC_BLOCKS={stored}");
            println!("HEADER_SYNC_BLOCKS_HEADER_BOUND={stored}");
            println!("HEADER_SYNC_BLOCKS_ROOTS_CHECKED=0 (needs state; use node-adapter --payment)");
        }
        Ok(())
    })();
    let (advertised_height, pong_work) = *peer_claim.lock().unwrap();
    let advertised_work = pong_work.max(peer.info.total_difficulty().to_num());
    peer.stop();
    let _ = peer.wait();
    result.map(|_| {
        v.validated_run = vec![initial_header];
        v.validated_run.extend(fetched);
        v.run_digests = digests;
        (v, advertised_height, advertised_work)
    })
}

/// AUDIT R2 N-2: bind a fetched block to a header validated by this run.
///
/// * The serialized header must equal the validated header byte for byte.
///   `header.hash()` alone is not enough: in Grin it covers only the PoW
///   nonces, so a peer could pair a valid hash with other header fields.
/// * The body must be self-consistent (`Block::validate`: kernel sums against
///   the previous header's offset, rangeproofs, signatures, weight, cut-through)
///   when the previous header is known; otherwise `validate_read`.
///
/// This does NOT check output/kernel MMR roots (that needs chain state), so a
/// peer can still fabricate a consistent body. Payment acceptance must go
/// through `node-adapter verify-output --payment`.

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn usage() -> ! {
    eprintln!(
        "usage:\n  \
         sync:  reverse-wtema-header-sync --peer IP:PORT [--peer IP:PORT ...] \
         (--checkpoint genesis | --checkpoint-file FILE [--expect-hash HEX] | --state-dir DIR [--expect-hash HEX]) \
         [--state-dir DIR] [--batches N] [--write-checkpoint FILE] \
         [--tail-blocks N | --fetch-all-blocks] [--blocks-dir DIR] [--digest-run] [--stop-at HEIGHT] [--confirm-peer IP:PORT ...] [--mainnet]\n  \
         describe: reverse-wtema-header-sync [--mainnet] --describe-checkpoint FILE   (validate + print header fields)\n  \
         header-proof-peers: reverse-wtema-header-sync [--mainnet] --header-proof-peers   (DNS seeds; print patched peers)\n  probe:    reverse-wtema-header-sync [--mainnet] --probe-peer IP:PORT ...   (handshake; print agent, capabilities, PIBD support)\n  \
         address:  reverse-wtema-header-sync [--mainnet] --slatepack-address --seeds FILE\n  \
         receive:  reverse-wtema-header-sync [--mainnet] --receive-slatepack S1.txt --seeds FILE [--wallet N] --response-out S2.txt --pending FILE [--known-outputs FILE] [--tip-height H]\n  \
         finalize: reverse-wtema-header-sync [--mainnet] --finalize-slatepack S2.txt --seeds FILE --send-context FILE --tx-out FILE   (sender side; then --broadcast-tx)\n  \
         invoice:  reverse-wtema-header-sync [--mainnet] --issue-invoice NANOGRIN --seeds FILE [--wallet N] [--payer ADDR] --pending FILE [--known-outputs FILE] --slatepack-out I1.txt --context-out FILE\n  \
         finalize-invoice: reverse-wtema-header-sync [--mainnet] --finalize-invoice I2.txt --seeds FILE --invoice-context FILE --tx-out FILE\n  \
         fetch: reverse-wtema-header-sync --fetch-block-hash HEX --peer IP:PORT --out FILE   (unverified)\n  \
         watch: reverse-wtema-header-sync --watch-commit HEX|list --blocks-dir DIR           (diagnostic; exit 4 = candidate, never acceptance)\n  \
         gap:   reverse-wtema-header-sync --gap-headers FILE --commitment HEX [--commitment HEX ...] (--peer IP:PORT ... | --gap-replay FILE) \
         [--prove] [--gap-archive HEIGHT] [--gap-state DIR] [--gap-out FILE] [--segment-height 11..15] [--max-msgs-per-min 1..450] \
         [--gap-kernel HEX ...] [--gap-blocks-all-peers] [--gap-seeds FILE [--gap-wallet-out FILE] [--gap-wallet-in FILE] [--gap-spend auto|auto:N|HEX [--gap-broadcast] [--gap-tx-out FILE]]]"
    );
    std::process::exit(2);
}

/// AUDIT R4 N-10: one strict parser for every mode.
/// `spec` = (flag, takes_value, repeatable). Unknown flags, missing values,
/// values that look like flags, and repeated single-use flags are errors.
/// Flags of another mode are unknown here, so modes cannot be mixed.
fn parse_flags(
    args: &[String],
    spec: &[(&'static str, bool, bool)],
) -> Result<HashMap<&'static str, Vec<String>>, String> {
    let mut out: HashMap<&'static str, Vec<String>> = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let &(name, takes_value, repeatable) = spec
            .iter()
            .find(|(n, _, _)| *n == a)
            .ok_or_else(|| format!("unknown or misplaced argument {a}"))?;
        let val = if takes_value {
            let v = args.get(i + 1).ok_or_else(|| format!("{name} needs a value"))?;
            if v.starts_with("--") {
                return Err(format!("{name} needs a value, got {v}"));
            }
            i += 2;
            v.clone()
        } else {
            i += 1;
            String::new()
        };
        let slot = out.entry(name).or_default();
        if !repeatable && !slot.is_empty() {
            return Err(format!("{name} given more than once"));
        }
        slot.push(val);
    }
    Ok(out)
}

const FETCH_SPEC: &[(&str, bool, bool)] = &[
    ("--fetch-block-hash", true, false),
    ("--peer", true, false),
    ("--out", true, false),
];
const PIBD_SPEC: &[(&str, bool, bool)] = &[
    ("--pibd-header",true,false), ("--peer",true,false),
    ("--leaf-index",true,false), ("--commitment",true,false),
    ("--pibd-out",true,false), ("--pibd-replay",true,false),
];
const GAP_SPEC: &[(&str, bool, bool)] = &[
    ("--gap-headers", true, false),
    ("--commitment", true, true),
    ("--gap-archive", true, false),
    ("--gap-state", true, false),
    ("--gap-seeds", true, false),
    ("--gap-wallet-out", true, false),
    ("--gap-wallet-in", true, false),
    ("--gap-pending", true, false),
    ("--gap-send-to", true, false),
    ("--gap-send-amount", true, false),
    ("--gap-slatepack-out", true, false),
    ("--gap-context-out", true, false),
    ("--gap-pay-invoice", true, false),
    ("--gap-spend", true, false),
    ("--gap-broadcast", false, false),
    ("--gap-tx-out", true, false),
    ("--gap-kernel", true, true),
    ("--gap-check-block", true, true),
    ("--gap-blocks-all-peers", false, false),
    ("--gap-bootstrap", false, false),
    ("--helper-output-segments", false, false),
    ("--allow-mainnet-spend", false, false),
    ("--peer", true, true),
    ("--prove", false, false),
    ("--gap-out", true, false),
    ("--gap-replay", true, false),
    ("--segment-height", true, false),
    ("--max-msgs-per-min", true, false),
];
const WATCH_SPEC: &[(&str, bool, bool)] = &[("--watch-commit", true, false), ("--blocks-dir", true, false)];
const HEADER_REQUEST_INTERVAL: Duration = Duration::from_millis(200);

/// Ask a peer whether its chain contains `tip`: a header request with `tip`
/// as the only locator is answered with the headers after the highest common
/// ancestor. If the peer's chain contains `tip`, the first header returned is
/// tip.height + 1 and links to tip.hash(); since a hash commits to the whole
/// history, agreement on `tip` is agreement on every header below it.
/// Err(true, ..) = the peer answered with a different chain.
fn confirm_peer(peer_arg: &str, base: &Verifier) -> Result<u64, (bool, String)> {
    let tip = &base.tip;
    let genesis = global::get_genesis_block().header.hash();
    let hs = Handshake::new(genesis, P2PConfig::default());
    let buf = Arc::new(Mutex::new(Vec::new()));
    let mut last_err = String::new();
    let mut connected = None;
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_secs(20));
        }
        let conn = match TcpStream::connect_timeout(
            &peer_arg.parse().map_err(|_| (false, format!("peer must be IP:PORT, got {peer_arg}")))?,
            Duration::from_secs(15),
        ) {
            Ok(c) => c,
            Err(e) => { last_err = format!("connect {e}"); continue; }
        };
        let local = match conn.local_addr() {
            Ok(l) => l,
            Err(e) => { last_err = format!("local addr {e}"); continue; }
        };
        let adapter = Arc::new(SyncAdapter { peer_claim: Arc::new(Mutex::new((0, 0))), headers: buf.clone(), blocks: Arc::new(Mutex::new(Vec::new())), wanted: Arc::new(Mutex::new(HashSet::new())), segments: Arc::new(Mutex::new(SegmentInbox::default())), outgoing_tx: Arc::new(Mutex::new(None)) });
        match Peer::connect(conn, Capabilities::default(), Difficulty::min_dma(), PeerAddr(local), &hs, adapter) {
            Ok(p) => { connected = Some(p); break; }
            Err(e) => last_err = format!("handshake {e:?}"),
        }
    }
    let peer = connected.ok_or((false, last_err))?;
    let result = (|| {
        peer.send_header_request(vec![tip.hash()]).map_err(|e| (false, format!("getheaders: {e:?}")))?;
        let start = Instant::now();
        let mut last_len = 0;
        let mut last_change = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(50));
            let n = buf.lock().unwrap().len();
            if n != last_len { last_len = n; last_change = Instant::now(); }
            if n >= MAX_BLOCK_HEADERS || (n > 0 && last_change.elapsed() > Duration::from_secs(2)) { break; }
            if n == 0 && start.elapsed() > Duration::from_secs(30) {
                return Err((false, "no headers within 30 s".to_string()));
            }
        }
        let got: Vec<BlockHeader> = std::mem::take(&mut *buf.lock().unwrap());
        // Agreement only for a fully validated continuation (PoW, target,
        // network difficulty, MMR root), not for a bare height/prev_hash match.
        check_continuation(base, &got).map_err(|e| (true, e))
    })();
    peer.stop();
    let _ = peer.wait();
    result
}

const SYNC_SPEC: &[(&str, bool, bool)] = &[
    ("--peer", true, true),
    ("--confirm-peer", true, true),
    ("--checkpoint", true, false),
    ("--checkpoint-file", true, false),
    ("--expect-hash", true, false),
    ("--write-checkpoint", true, false),
    ("--state-dir", true, false),
    ("--batches", true, false),
    ("--tail-blocks", true, false),
    ("--blocks-dir", true, false),
    ("--fetch-all-blocks", false, false),
    ("--digest-run", false, false),
    ("--stop-at", true, false),
    ("--stop-below-tip", true, false),
    ("--progress-dir", true, false),
    ("--failover", false, false),
    ("--check-header", true, false),
    ("--snapshot-at", true, false),
    ("--snapshot-dir", true, false),
];

fn parse_or_usage(args: &[String], spec: &[(&'static str, bool, bool)]) -> HashMap<&'static str, Vec<String>> {
    parse_flags(args, spec).unwrap_or_else(|e| {
        eprintln!("argument error: {e}");
        usage()
    })
}

fn one<'a>(m: &'a HashMap<&'static str, Vec<String>>, k: &str) -> Option<&'a str> {
    m.get(k).and_then(|v| v.first()).map(|s| s.as_str())
}

/// AUDIT R2 N-2: diagnostic scan only. Files in `blocks_dir` are not bound
/// to any validated chain here, and a block body cannot be checked against
/// output/kernel roots without state. The sender of a payment knows the
/// receiver's output and rangeproof (they are in the slate), so a fake but
/// self-consistent block containing them is easy to build. This mode therefore
/// never reports acceptance; use `node-adapter verify-output --payment`.
fn run_payment_watch(blocks_dir: &str, watch_hex: &str) -> ! {
    let watch_hex = watch_hex.strip_prefix("0x").unwrap_or(watch_hex).to_lowercase();
    let mut blocks = Vec::new();
    if let Ok(rd) = std::fs::read_dir(blocks_dir) {
        for ent in rd.flatten() {
            let path = ent.path();
            if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }
            if let Ok(raw) = std::fs::read(&path) {
                if let Ok(b) = ser::deserialize(
                    &mut &raw[..],
                    ProtocolVersion::local(),
                    ser::DeserializationMode::default(),
                ) {
                    blocks.push(b);
                }
            }
        }
    }
    println!("PAYMENT_WATCH_MODE=diagnostic (unverified files; not a payment decision)");
    println!("PAYMENT_ACCEPTED=false");
    if blocks.is_empty() {
        eprintln!("PAYMENT_WATCH=FAIL no blocks in {blocks_dir}");
        std::process::exit(1);
    }
    blocks.sort_by_key(|b: &core::Block| b.header.height);
    if watch_hex == "list" {
        for b in &blocks {
            for o in &b.body.outputs {
                println!(
                    "PAYMENT_CANDIDATE_OUTPUT height={} commit={}",
                    b.header.height,
                    o.identifier.commit.to_hex()
                );
            }
        }
        std::process::exit(0);
    }
    let mut found = false;
    for b in &blocks {
        if b.body.outputs.iter().any(|o| o.identifier.commit.to_hex() == watch_hex) {
            found = true;
            println!(
                "PAYMENT_CANDIDATE height={} hash={}",
                b.header.height,
                b.header.hash().to_hex()
            );
        }
    }
    println!("PAYMENT_WATCH_COMMIT={watch_hex}");
    println!("PAYMENT_CANDIDATE_FOUND={found}");
    println!("PAYMENT_BLOCKS_SCANNED={}", blocks.len());
    println!("PAYMENT_NEXT_STEP=node-adapter verify-output --payment --min-confirmations N");
    println!("PAYMENT_WATCH_EXIT_CODES=4 candidate (not accepted), 3 not found");
    // AUDIT R4: a found candidate must never look like success to a script
    // that only checks the exit status. 4 = candidate found (NOT accepted),
    // 3 = not found, 1 = no blocks, 2 = usage.
    std::process::exit(if found { 4 } else { 3 });
}

fn fetch_one_block(peer_arg: &str, hash_hex: &str, out: &str) -> Result<(), String> {
    let hash = hex_hash(hash_hex)?;
    let conn = TcpStream::connect(peer_arg).map_err(|e| format!("connect {e}"))?;
    let local = conn.local_addr().map_err(|e| format!("local {e}"))?;
    let genesis = global::get_genesis_block().header.hash();
    let hs = Handshake::new(genesis, P2PConfig::default());
    let buf = Arc::new(Mutex::new(Vec::new()));
    let blocks = Arc::new(Mutex::new(Vec::new()));
    let wanted = Arc::new(Mutex::new(HashSet::from([hash])));
    let adapter = Arc::new(SyncAdapter { peer_claim: Arc::new(Mutex::new((0, 0))), headers: buf.clone(), blocks: blocks.clone(), wanted, segments: Arc::new(Mutex::new(SegmentInbox::default())), outgoing_tx: Arc::new(Mutex::new(None)) });
    let caps = Capabilities::default() | Capabilities::BLOCK_HIST;
    let peer = Peer::connect(conn, caps, Difficulty::min_dma(), PeerAddr(local), &hs, adapter)
        .map_err(|e| format!("handshake {e:?}"))?;
    // AUDIT R2 N-2: no validated header here, only the hash; the body is
    // stored for node-adapter, which checks it against chain state.
    println!("FETCHED_BLOCK_UNVERIFIED=true (header bytes and roots are checked by node-adapter --payment --block)");
    peer.send_block_request(hash, grin_chain::Options::NONE)
        .map_err(|e| format!("getblock {hash:?}: {e:?}"))?;
    let start = Instant::now();
    loop {
        let found = blocks.lock().unwrap().iter().find(|b| b.header.hash() == hash).cloned();
        if let Some(b) = found {
            let bytes = ser::ser_vec(&b, ProtocolVersion::local()).map_err(|e| format!("serialize: {e:?}"))?;
            std::fs::write(out, &bytes).map_err(|e| format!("write: {e}"))?;
            println!("FETCHED_BLOCK height={} hash={hash:?} out={out}", b.header.height);
            peer.stop();
            let _ = peer.wait();
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(30) {
            peer.stop();
            let _ = peer.wait();
            return Err("getblock timeout".into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
/// Validate a checkpoint file (header bytes, hash, PoW, MMR peaks) and print
/// its header fields under the names the Grin node Foreign API uses, so they
/// can be compared with independent sources.
fn describe_checkpoint(path: &str) -> Result<(), String> {
    let cp = mmr::CheckpointFile::from_text(path)?;
    let v = load_checkpoint(path, None)?;
    let h = &v.tip;
    println!("CHECKPOINT_FILE_VALID=true");
    println!("height={}", h.height);
    println!("hash={}", h.hash().to_hex());
    println!("version={}", h.version.0);
    println!("previous={}", h.prev_hash.to_hex());
    println!("prev_root={}", h.prev_root.to_hex());
    println!("timestamp={}", h.timestamp.to_rfc3339());
    println!("timestamp_unix={}", h.timestamp.timestamp());
    println!("output_root={}", h.output_root.to_hex());
    println!("output_mmr_size={}", h.output_mmr_size);
    println!("range_proof_root={}", h.range_proof_root.to_hex());
    println!("kernel_root={}", h.kernel_root.to_hex());
    println!("kernel_mmr_size={}", h.kernel_mmr_size);
    println!("total_kernel_offset={}", h.total_kernel_offset.to_hex());
    println!("total_difficulty={}", h.total_difficulty().to_num());
    println!("secondary_scaling={}", h.pow.secondary_scaling);
    println!("nonce={}", h.pow.nonce);
    println!("edge_bits={}", h.pow.edge_bits());
    println!("cuckoo_solution={}", h.pow.proof.nonces.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(","));
    println!("header_mmr_root={}", cp.root.to_hex());
    println!("header_mmr_leaves={}", cp.acc.leaves);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Network selection: Floonet unless --mainnet is given (anywhere).
    let mainnet = args.iter().any(|a| a == "--mainnet");
    let chain = if mainnet { ChainTypes::Mainnet } else { ChainTypes::Testnet };
    global::set_local_chain_type(chain);
    global::set_global_chain_type(chain);
    println!("NETWORK={}", if mainnet { "MAINNET" } else { "FLOONET" });
    let rest_owned: Vec<String> = args[1..].iter().filter(|a| a.as_str() != "--mainnet").cloned().collect();
    let rest = &rest_owned[..];
    if rest.iter().any(|a| a == "--txhashset-request") {
        let m = parse_or_usage(rest, &[
            ("--txhashset-request", false, false),
            ("--txhashset-peer", true, false),
            ("--txhashset-hash", true, false),
            ("--txhashset-height", true, false),
        ]);
        let (Some(peer), Some(hash), Some(height)) = (one(&m, "--txhashset-peer"), one(&m, "--txhashset-hash"), one(&m, "--txhashset-height")) else { usage() };
        let height: u64 = height.parse().unwrap_or_else(|_| usage());
        match gap::request_txhashset(peer, hash, height) {
            Ok(()) => { println!("TXHASHSET_REQUEST=SENT"); std::process::exit(0); }
            Err(e) => { eprintln!("TXHASHSET_REQUEST=FAIL {e}"); std::process::exit(1); }
        }
    }    if rest.iter().any(|a| a == "--broadcast-tx") {
        let m = parse_or_usage(rest, &[("--broadcast-tx", true, false), ("--peer", true, true), ("--allow-mainnet-spend", false, false)]);
        if mainnet && !m.contains_key("--allow-mainnet-spend") {
            eprintln!("BROADCAST_TX=FAIL mainnet needs --allow-mainnet-spend");
            std::process::exit(2);
        }
        let (Some(path), Some(peers)) = (one(&m, "--broadcast-tx"), m.get("--peer")) else { usage() };
        match wallet::broadcast_file(path, peers) {
            Ok(()) => std::process::exit(0),
            Err(e) => { eprintln!("BROADCAST_TX=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--slatepack-info") {
        let m = parse_or_usage(rest, &[("--slatepack-info", true, false), ("--seeds", true, false), ("--wallet", true, false)]);
        let (Some(path), Some(seeds)) = (one(&m, "--slatepack-info"), one(&m, "--seeds")) else { usage() };
        let wallet: usize = one(&m, "--wallet").and_then(|x| x.parse().ok()).unwrap_or(1);
        match receive::print_slatepack_info(seeds, wallet, path) {
            Ok(()) => std::process::exit(0),
            Err(e) => { eprintln!("SLATE_INFO=FAIL {e}"); println!("SLATE_INFO=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--release-keygen") {
        let m = parse_or_usage(rest, &[("--release-keygen", true, false)]);
        let Some(out) = one(&m, "--release-keygen") else { usage() };
        match release::keygen(std::path::Path::new(out)) {
            Ok(pk) => {
                println!("RELEASE_KEY_SEED={out} (keep it secret, outside the app folder)");
                println!("RELEASE_PUBKEY={pk}");
                std::process::exit(0)
            }
            Err(e) => { eprintln!("RELEASE=FAIL {e}"); println!("RELEASE=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--sign-release") {
        let m = parse_or_usage(rest, &[("--sign-release", true, false), ("--seed", true, false), ("--key-id", true, false), ("--sequence", true, false)]);
        let (Some(dir), Some(seed)) = (one(&m, "--sign-release"), one(&m, "--seed")) else { usage() };
        let key_id: u32 = one(&m, "--key-id").and_then(|x| x.parse().ok()).unwrap_or(1);
        let seq: u64 = one(&m, "--sequence").and_then(|x| x.parse().ok()).unwrap_or_else(|| {
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
        });
        match release::sign_dir(std::path::Path::new(dir), std::path::Path::new(seed), key_id, seq) {
            Ok(r) => { release::print(&r); println!("RELEASE=SIGNED"); std::process::exit(0) }
            Err(e) => { eprintln!("RELEASE=FAIL {e}"); println!("RELEASE=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--verify-release") {
        let m = parse_or_usage(rest, &[("--verify-release", true, false), ("--accepted", true, false)]);
        let Some(dir) = one(&m, "--verify-release") else { usage() };
        let accepted = one(&m, "--accepted").map(std::path::Path::new);
        let r = release::compiled_keys().and_then(|k| release::verify_dir(std::path::Path::new(dir), accepted, &k));
        match r {
            Ok(r) => { release::print(&r); println!("RELEASE=VERIFIED"); std::process::exit(0) }
            Err(e) => { eprintln!("RELEASE=FAIL {e}"); println!("RELEASE=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--tor-keys") {
        let m = parse_or_usage(rest, &[("--tor-keys", false, false), ("--seeds", true, false), ("--wallet", true, false)]);
        let Some(seeds) = one(&m, "--seeds") else { usage() };
        let wallet: usize = one(&m, "--wallet").and_then(|x| x.parse().ok()).unwrap_or(1);
        match receive::print_tor_keys(seeds, wallet) {
            Ok(()) => std::process::exit(0),
            Err(e) => { eprintln!("TOR_KEYS=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--bench-build-send") {
        // FLOONET ONLY: an S1 from a made-up input, to test slatepack
        // transports (Tor / messenger) without coins. Never valid on chain.
        if mainnet {
            eprintln!("BENCH=FAIL --bench-build-send is testnet only");
            std::process::exit(2);
        }
        let m = parse_or_usage(rest, &[
            ("--bench-build-send", false, false), ("--seeds", true, false), ("--wallet", true, false), ("--to", true, false),
            ("--amount", true, false), ("--slatepack-out", true, false), ("--context-out", true, false),
        ]);
        let (Some(seeds), Some(to), Some(amount), Some(out), Some(ctx)) = (
            one(&m, "--seeds"), one(&m, "--to"), one(&m, "--amount").and_then(|x| x.parse::<u64>().ok()), one(&m, "--slatepack-out"), one(&m, "--context-out"),
        ) else { usage() };
        let wallet: usize = one(&m, "--wallet").and_then(|x| x.parse().ok()).unwrap_or(1);
        let r = (|| -> Result<(), String> {
            let w = wallet::Wallets::from_file(seeds)?;
            let k = w.keychain(wallet - 1).ok_or("no such wallet")?;
            let id = <grin_keychain::ExtKeychain as grin_keychain::Keychain>::derive_key_id(3, 0, 0, 900, 0);
            let in_amount = amount + 1_000_000_000;
            let c = grin_keychain::Keychain::commit(k, in_amount, &id, grin_keychain::SwitchCommitmentType::Regular).map_err(|e| format!("{e:?}"))?;
            let inp = receive::InputSel::new(&id, in_amount, false, &c);
            let built = receive::build_send(&w, wallet - 1, &[inp], &[id], amount, to)?;
            receive::send_file(&built, out, ctx)
        })();
        match r {
            Ok(()) => std::process::exit(0),
            Err(e) => { eprintln!("BENCH=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--slatepack-address") {
        let m = parse_or_usage(rest, &[("--slatepack-address", false, false), ("--seeds", true, false)]);
        let Some(seeds) = one(&m, "--seeds") else { usage() };
        match receive::print_addresses(seeds) {
            Ok(()) => std::process::exit(0),
            Err(e) => { eprintln!("SLATEPACK_ADDRESS=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--finalize-slatepack") {
        let m = parse_or_usage(rest, &[("--finalize-slatepack", true, false), ("--seeds", true, false), ("--send-context", true, false), ("--tx-out", true, false), ("--proof-out", true, false)]);
        let (Some(s2), Some(seeds), Some(ctx), Some(out)) = (one(&m, "--finalize-slatepack"), one(&m, "--seeds"), one(&m, "--send-context"), one(&m, "--tx-out")) else { usage() };
        match receive::finalize_file(seeds, ctx, s2, out, one(&m, "--proof-out")) {
            Ok(()) => std::process::exit(0),
            Err(e) => { eprintln!("FINALIZE=FAIL {e}"); println!("FINALIZE=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--issue-invoice") {
        let m = parse_or_usage(rest, &[
            ("--issue-invoice", true, false), ("--seeds", true, false), ("--wallet", true, false), ("--payer", true, false),
            ("--known-outputs", true, false), ("--pending", true, false), ("--slatepack-out", true, false), ("--context-out", true, false),
        ]);
        let (Some(amount), Some(seeds), Some(pending), Some(out), Some(ctx)) = (
            one(&m, "--issue-invoice").and_then(|x| x.parse::<u64>().ok()), one(&m, "--seeds"), one(&m, "--pending"), one(&m, "--slatepack-out"), one(&m, "--context-out"),
        ) else { usage() };
        let wallet: usize = one(&m, "--wallet").and_then(|x| x.parse().ok()).unwrap_or(1);
        match receive::issue_invoice_file(seeds, wallet, amount, one(&m, "--payer"), one(&m, "--known-outputs"), pending, out, ctx) {
            Ok(()) => std::process::exit(0),
            Err(e) => { eprintln!("INVOICE=FAIL {e}"); println!("INVOICE=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--finalize-invoice") {
        let m = parse_or_usage(rest, &[("--finalize-invoice", true, false), ("--seeds", true, false), ("--invoice-context", true, false), ("--tx-out", true, false), ("--slate-json-out", true, false)]);
        let (Some(i2), Some(seeds), Some(ctx), Some(out)) = (one(&m, "--finalize-invoice"), one(&m, "--seeds"), one(&m, "--invoice-context"), one(&m, "--tx-out")) else { usage() };
        match receive::finalize_invoice_file(seeds, ctx, i2, out, one(&m, "--slate-json-out")) {
            Ok(()) => std::process::exit(0),
            Err(e) => { eprintln!("FINALIZE=FAIL {e}"); println!("FINALIZE=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--repair-pending") {
        let m = parse_or_usage(rest, &[("--repair-pending", true, false)]);
        let Some(pending) = one(&m, "--repair-pending") else { usage() };
        match receive::repair_pending(pending) {
            Ok(r) => { println!("{r}"); std::process::exit(0) }
            Err(e) => { eprintln!("PENDING_REPAIR=FAIL {e}"); println!("PENDING_REPAIR=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--release-inputs") {
        let m = parse_or_usage(rest, &[("--release-inputs", true, false), ("--pending", true, false), ("--send-context", true, false), ("--force", false, false)]);
        let (Some(sid), Some(pending)) = (one(&m, "--release-inputs"), one(&m, "--pending")) else { usage() };
        match receive::release_inputs(pending, sid, one(&m, "--send-context"), m.contains_key("--force")) {
            Ok(how) => {
                println!("RELEASE_INPUTS={sid} ({how})");
                std::process::exit(0)
            }
            Err(e) => { eprintln!("RELEASE_INPUTS=FAIL {e}"); println!("RELEASE_INPUTS=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--receive-slatepack") {
        let m = parse_or_usage(rest, &[
            ("--receive-slatepack", true, false), ("--seeds", true, false), ("--wallet", true, false),
            ("--response-out", true, false), ("--known-outputs", true, false), ("--pending", true, false),
            ("--tip-height", true, false), ("--verified-profile-dir", true, false), ("--armor-out", true, false),
        ]);
        let (Some(input), Some(seeds), Some(out), Some(pending)) =
            (one(&m, "--receive-slatepack"), one(&m, "--seeds"), one(&m, "--response-out"), one(&m, "--pending")) else { usage() };
        let wallet: usize = one(&m, "--wallet").and_then(|x| x.parse().ok()).unwrap_or(1);
        let tip = if let Some(profile) = one(&m, "--verified-profile-dir") {
            // Failure remains None: cutoff-bearing slates fail closed; legacy
            // slates without a cutoff can still be accepted.
            verified_profile_tip(std::path::Path::new(profile), seeds, mainnet).ok()
        } else { one(&m, "--tip-height").and_then(|x| x.parse().ok()) };
        match receive::receive_file(seeds, wallet, input, out, one(&m, "--known-outputs"), pending, tip, one(&m, "--armor-out")) {
            Ok(()) => std::process::exit(0),
            Err(e) => { eprintln!("RECEIVE=FAIL {e}"); println!("RECEIVE=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--header-proof-peers") {
        let m = parse_or_usage(rest, &[("--header-proof-peers", false, false), ("--header-proof-peer", true, true)]);
        let extra = m.get("--header-proof-peer").cloned().unwrap_or_default();
        let (checked, peers) = gap::find_header_proof_peers(mainnet, &extra);
        for p in &peers {
            println!("HEADER_PROOF_PEER={} agent={:?} height={}", p.addr, p.agent, p.height);
        }
        println!("HEADER_PROOF_CHECKED={checked}");
        println!("HEADER_PROOF_PATCHED={}", peers.len());
        std::process::exit(if peers.is_empty() { 3 } else { 0 });
    }
    if rest.iter().any(|a| a == "--probe-peer") {
        let m = parse_or_usage(rest, &[("--probe-peer", true, true), ("--discover", false, false)]);
        let Some(peers) = m.get("--probe-peer") else { usage() };
        let pibd = gap::probe(peers, m.contains_key("--discover"));
        println!("PROBE_ANY_PIBD={}", if pibd { "yes" } else { "no" });
        std::process::exit(if pibd { 0 } else { 3 });
    }
    if rest.iter().any(|a| a == "--describe-checkpoint") {
        let Some(path) = rest.iter().position(|a| a == "--describe-checkpoint").and_then(|i| rest.get(i + 1)) else { usage() };
        match describe_checkpoint(path) {
            Ok(()) => std::process::exit(0),
            Err(e) => { eprintln!("DESCRIBE=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a| a == "--gap-headers") {
        let m = parse_or_usage(rest, GAP_SPEC);
        let Some(headers) = one(&m, "--gap-headers") else { usage() };
        let commitments = m.get("--commitment").cloned().unwrap_or_default();
        let bootstrap = m.contains_key("--gap-bootstrap");
    if (commitments.is_empty() && !bootstrap) || commitments.len() > 64 { eprintln!("argument error: 1..64 --commitment values"); usage() }
        let small = |k: &str, d: u64, lo: u64, hi: u64| -> u64 {
            let v = one(&m, k).map_or(Some(d), |v| v.parse::<u64>().ok());
            match v { Some(v) if (lo..=hi).contains(&v) => v, _ => { eprintln!("argument error: {k} must be {lo}..={hi}"); usage() } }
        };
        let replay = one(&m, "--gap-replay");
        let peers = m.get("--peer").cloned().unwrap_or_default();
        if replay.is_some() == !peers.is_empty() {
            eprintln!("argument error: give either --peer (one or more) or --gap-replay");
            usage();
        }
        let archive = match one(&m, "--gap-archive") {
            None => None,
            Some(v) => Some(v.parse::<u64>().unwrap_or_else(|_| { eprintln!("argument error: --gap-archive must be a height"); usage() })),
        };
        let opts = gap::Opts {
            headers,
            commitments,
            peers,
            archive,
            state_dir: one(&m, "--gap-state"),
            seeds: one(&m, "--gap-seeds"),
            wallet_out: one(&m, "--gap-wallet-out"),
            wallet_in: one(&m, "--gap-wallet-in"),
            pending: one(&m, "--gap-pending"),
            send_to: one(&m, "--gap-send-to"),
            send_amount: one(&m, "--gap-send-amount").and_then(|x| x.parse().ok()),
            slatepack_out: one(&m, "--gap-slatepack-out"),
            context_out: one(&m, "--gap-context-out"),
            pay_invoice: one(&m, "--gap-pay-invoice"),
            spend: one(&m, "--gap-spend"),
            allow_mainnet_spend: m.contains_key("--allow-mainnet-spend"),
            broadcast: m.contains_key("--gap-broadcast"),
            tx_out: one(&m, "--gap-tx-out"),
            kernels: m.get("--gap-kernel").cloned().unwrap_or_default(),
            check_blocks: m.get("--gap-check-block").cloned().unwrap_or_default(),
            blocks_all_peers: m.contains_key("--gap-blocks-all-peers"),
            bootstrap: m.contains_key("--gap-bootstrap"),
            helper_output_segments: m.contains_key("--helper-output-segments"),
            prove: m.contains_key("--prove"),
            out: one(&m, "--gap-out"),
            replay,
            segment_height: small("--segment-height", 11, 11, 15) as u8,
            per_min: small("--max-msgs-per-min", 400, 1, 450),
        };
        match gap::run(opts) {
            Ok(code) => std::process::exit(code),
            Err(e) => { eprintln!("GAP=FAIL {e}"); std::process::exit(1) }
        }
    }
    if rest.iter().any(|a|a=="--pibd-header") {
        let m=parse_or_usage(rest,PIBD_SPEC);
        let (Some(header),Some(leaf),Some(commit))=(one(&m,"--pibd-header"),one(&m,"--leaf-index"),one(&m,"--commitment")) else {usage()};
        let leaf=leaf.parse::<u64>().unwrap_or_else(|_|usage());
        let result=match (one(&m,"--peer"),one(&m,"--pibd-replay"),one(&m,"--pibd-out")) {
            (Some(peer),None,out)=>pibd::run(header,peer,leaf,commit,out),
            (None,Some(proof),None)=>pibd::replay(header,proof,leaf,commit),
            _=>usage(),
        };
        match result{Ok(())=>std::process::exit(0),Err(e)=>{eprintln!("PIBD_VERDICT=UNKNOWN_OR_INVALID\nreason={e}");std::process::exit(1)}}
    }
    if rest.iter().any(|a| a == "--fetch-block-hash") {
        let m = parse_or_usage(rest, FETCH_SPEC);
        let (Some(peer_arg), Some(hash_hex), Some(out)) =
            (one(&m, "--peer"), one(&m, "--fetch-block-hash"), one(&m, "--out"))
        else {
            usage()
        };
        match fetch_one_block(peer_arg, hash_hex, out) {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                eprintln!("FETCH_BLOCK=FAIL {e}");
                std::process::exit(1);
            }
        }
    }
    if rest.iter().any(|a| a == "--watch-commit") {
        let m = parse_or_usage(rest, WATCH_SPEC);
        let (Some(watch), Some(dir)) = (one(&m, "--watch-commit"), one(&m, "--blocks-dir")) else {
            usage()
        };
        run_payment_watch(dir, watch);
    }
    let m = parse_or_usage(rest, SYNC_SPEC);
    let peers: Vec<String> = m.get("--peer").cloned().unwrap_or_default();
    let confirm_peers: Vec<String> = m.get("--confirm-peer").cloned().unwrap_or_default();
    let cp_arg = one(&m, "--checkpoint").unwrap_or("").to_string();
    let mut checkpoint_file = one(&m, "--checkpoint-file").unwrap_or("").to_string();
    let expect_hash: Option<Hash> = one(&m, "--expect-hash").map(|v| {
        hex_hash(v).unwrap_or_else(|e| {
            eprintln!("HEADER_SYNC=FAIL expect-hash {e}");
            std::process::exit(2)
        })
    });
    let write_checkpoint = one(&m, "--write-checkpoint").unwrap_or("").to_string();
    let state_dir = one(&m, "--state-dir").unwrap_or("").to_string();
    let blocks_dir = one(&m, "--blocks-dir").unwrap_or("").to_string();
    let fetch_all_blocks = m.contains_key("--fetch-all-blocks");
    let num = |k: &str, d: usize| -> usize {
        one(&m, k).map_or(d, |v| v.parse().unwrap_or_else(|_| {
            eprintln!("argument error: {k} must be a non-negative integer");
            usage()
        }))
    };
    let batches = num("--batches", 1);
    let tail_blocks = num("--tail-blocks", 0);
    let stop_at = num("--stop-at", 0) as u64;
    STOP_AT.store(stop_at, std::sync::atomic::Ordering::Relaxed);
    STOP_BELOW_TIP.store(num("--stop-below-tip", 0) as u64, std::sync::atomic::Ordering::Relaxed);
    let progress_dir = one(&m, "--progress-dir").unwrap_or("").to_string();
    if !progress_dir.is_empty() {
        let _ = PROGRESS_DIR.set(progress_dir.clone());
    }
    let failover = m.contains_key("--failover");
    SNAPSHOT_AT.store(num("--snapshot-at", 0) as u64, std::sync::atomic::Ordering::Relaxed);
    let snapshot_dir = one(&m, "--snapshot-dir").unwrap_or("").to_string();
    if let Some((h, hash)) = one(&m, "--check-header").and_then(|x| x.split_once(':')) {
        if let Ok(h) = h.parse::<u64>() {
            let _ = CHECK_HEADER.set((h, hash.to_lowercase()));
        }
    }
    if m.contains_key("--digest-run") {
        if tail_blocks > 0 || fetch_all_blocks {
            eprintln!("argument error: --digest-run cannot fetch blocks");
            usage();
        }
        DIGEST_RUN.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    if !cp_arg.is_empty() && !checkpoint_file.is_empty() {
        eprintln!("argument error: --checkpoint and --checkpoint-file are mutually exclusive");
        usage();
    }
    if fetch_all_blocks && tail_blocks > 0 {
        eprintln!("argument error: --fetch-all-blocks and --tail-blocks are mutually exclusive");
        usage();
    }
    if peers.is_empty() || (cp_arg.is_empty() && checkpoint_file.is_empty() && state_dir.is_empty()) {
        usage();
    }
    if checkpoint_file.is_empty() && cp_arg.is_empty() && !state_dir.is_empty() {
        let p = std::path::Path::new(&state_dir).join("checkpoint.rwm");
        if p.exists() {
            checkpoint_file = p.to_string_lossy().to_string();
            println!("HEADER_SYNC_RESUME_FROM={checkpoint_file}");
            // AUDIT R3 N-5: a checkpoint written by a previous run is only as
            // trustworthy as the disk it sits on; pin it when it matters.
            if expect_hash.is_none() {
                println!("HEADER_SYNC_WARNING=state checkpoint not pinned; pass --expect-hash HEX");
            }
        }
    }

    let mut start = if !checkpoint_file.is_empty() {
        match load_checkpoint(&checkpoint_file, expect_hash) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("HEADER_SYNC=FAIL checkpoint {e}");
                std::process::exit(1);
            }
        }
    } else if cp_arg.eq_ignore_ascii_case("genesis") {
        // A long genesis sync continues from its last snapshot (own disk,
        // made by this same validation; reloaded and checked again).
        match (!progress_dir.is_empty()).then(|| load_progress(&progress_dir)).flatten() {
            Some(v) => v,
            None => Verifier::from_genesis(),
        }
    } else {
        // AUDIT: a bare hash cannot be verified (no header, no MMR peaks).
        eprintln!("HEADER_SYNC=FAIL non-genesis start requires --checkpoint-file");
        std::process::exit(2);
    };
    if !state_dir.is_empty() {
        match read_state_headers(&state_dir) {
            Ok(Some(hs)) => {
                if let Err(e) = start.restore_recent(hs) {
                    eprintln!("HEADER_SYNC=FAIL state recent headers: {e}");
                    std::process::exit(1);
                }
                println!("HEADER_SYNC_STATE_RESTORED=1");
            }
            Ok(None) => println!("HEADER_SYNC_STATE_RESTORED=0 (no recent-headers.bin)"),
            Err(e) => {
                eprintln!("HEADER_SYNC=FAIL state recent headers: {e}");
                std::process::exit(1);
            }
        }
    }
    let start_height = start.tip.height;

    // Compare complete serialized headers at the common height: header.hash()
    // commits only to nonces and is insufficient for comparing header fields.
    let mut verified: Vec<(String, Verifier, u64, u64)> = Vec::new();
    // Peers are synced in parallel; results are reported in argument order.
    let results: Vec<Result<(Verifier, u64, u64), String>> = if failover {
        // One chain, peers one after another: each continues where the
        // previous one stopped (every header is validated whatever its source),
        // a failing peer costs at most the headers since the last snapshot.
        let mut cur = start.clone();
        let mut out: Vec<Result<(Verifier, u64, u64), String>> = peers.iter().map(|_| Err("not used".to_string())).collect();
        'rounds: for round in 0..3 {
            for (i, p) in peers.iter().enumerate() {
                let target = STOP_AT.load(std::sync::atomic::Ordering::Relaxed);
                if target != 0 && cur.tip.height >= target {
                    break 'rounds;
                }
                println!("HEADER_SYNC_FAILOVER peer={p} round={round} from_height={}", cur.tip.height);
                match sync_from_peer(p, cur.clone(), batches, tail_blocks, &blocks_dir, fetch_all_blocks) {
                    Ok((v, h, w)) => {
                        cur = v.clone();
                        out[i] = Ok((v, h, w));
                    }
                    Err(e) => {
                        println!("HEADER_SYNC_FAILOVER_ERROR peer={p} {e}");
                        if let Some(v) = (!progress_dir.is_empty()).then(|| load_progress(&progress_dir)).flatten() {
                            if v.tip.height > cur.tip.height {
                                cur = v;
                            }
                        }
                        out[i] = Err(e);
                    }
                }
            }
            let target = STOP_AT.load(std::sync::atomic::Ordering::Relaxed);
            if target == 0 || cur.tip.height >= target {
                break;
            }
        }
        // Only the peer that ended the chain reports it; earlier ones are partial.
        let last_ok = out.iter().rposition(|r| r.as_ref().map_or(false, |(v, _, _)| v.tip.height == cur.tip.height));
        for (i, r) in out.iter_mut().enumerate() {
            if Some(i) != last_ok && r.is_ok() {
                *r = Err("partial (continued by the next peer)".into());
            }
        }
        if let Some(i) = last_ok {
            if let Ok((v, _, _)) = &mut out[i] {
                v.run_digests.clear(); // digests of a resumed run are partial: single chain, no comparison
            }
        }
        out
    } else { std::thread::scope(|sc| {
        let handles: Vec<_> = peers
            .iter()
            .map(|p| {
                let st = start.clone();
                let bd = blocks_dir.clone();
                sc.spawn(move || sync_from_peer(p, st, batches, tail_blocks, &bd, fetch_all_blocks))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or_else(|_| Err("thread panic".into()))).collect()
    }) };
    for (p, r) in peers.iter().zip(results) {
        match r {
            Ok((v, advertised_height, advertised_work)) if v.tip.height > start_height => {
                println!("HEADER_SYNC_PEER_RESULT={p} OK height={} total_difficulty={} advertised_height={} advertised_work={}",
                    v.tip.height, v.tip.total_difficulty().to_num(), advertised_height, advertised_work);
                verified.push((p.clone(), v, advertised_height, advertised_work));
            }
            Ok(_) => println!("HEADER_SYNC_PEER_RESULT={p} FAIL no progress"),
            Err(e) => println!("HEADER_SYNC_PEER_RESULT={p} FAIL {e}"),
        }
    }
    if failover {
        let target = STOP_AT.load(std::sync::atomic::Ordering::Relaxed);
        let best = verified.iter().map(|x| x.1.tip.height).max().unwrap_or(0);
        if target != 0 && best < target {
            eprintln!("HEADER_SYNC=FAIL reached height {best} of {target}; run again: it continues from the last snapshot");
            std::process::exit(1);
        }
    }
    let ok_peers = verified.len();
    // --confirm-peer: independent peers that only confirm the final tip of the
    // best synced chain (cheap: one request), instead of a second full sync.
    let mut confirmed = 0usize;
    let mut confirm_agreed: Vec<String> = Vec::new();
    if !confirm_peers.is_empty() && !verified.is_empty() {
        let best = verified.iter().max_by_key(|(_, v, _, _)| v.tip.total_difficulty().to_num()).unwrap();
        let base = best.1.clone();
        let tip = base.tip.clone();
        for p in &confirm_peers {
            match confirm_peer(p, &base) {
                Ok(h) => {
                    confirmed += 1;
                    confirm_agreed.push(p.clone());
                    println!("HEADER_SYNC_CONFIRM={p} AGREE tip={} {} peer_returned_up_to={h}", tip.height, tip.hash().to_hex());
                }
                // Not fatal: a peer on another chain is outvoted by work and
                // simply does not count as a confirmation.
                Err((true, e)) => println!("HEADER_SYNC_CONFIRM={p} DISAGREE {e}"),
                Err((false, e)) => println!("HEADER_SYNC_CONFIRM={p} UNREACHABLE {e}"),
            }
        }
        println!("HEADER_SYNC_CONFIRMED_BY={confirmed}/{}", confirm_peers.len());
    }
    if ok_peers < 1 || ok_peers + confirmed < 2 {
        eprintln!("HEADER_SYNC=FAIL fewer than two peers returned validated headers or confirmed the tip");
        std::process::exit(1);
    }
    let choice = match choose_chain(&verified.iter().map(|x| &x.1).collect::<Vec<_>>()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("HEADER_SYNC=FAIL {e}");
            std::process::exit(1);
        }
    };
    for (i, why) in &choice.rejected {
        println!("HEADER_SYNC_FORK_REJECTED={} {why}", verified[*i].0);
    }
    // Independence: supporters (and confirming peers) from distinct networks.
    let mut nets: Vec<String> = choice.supporters.iter().map(|&i| net_group(&verified[i].0)).collect();
    nets.extend(confirm_agreed.iter().map(|p| net_group(p)));
    nets.sort();
    nets.dedup();
    println!("HEADER_SYNC_CHAIN_SUPPORT={}/{}", choice.supporters.len(), verified.len());
    println!("HEADER_SYNC_INDEPENDENT_NETS={} ({})", nets.len(), nets.join(","));
    if choice.supporters.len() + confirmed < 2 || nets.len() < 2 {
        eprintln!(
            "HEADER_SYNC=FAIL the most-work chain is backed by {} peer(s) from {} network(s); need two from different /16 networks (add peers)",
            choice.supporters.len() + confirmed,
            nets.len()
        );
        std::process::exit(1);
    }
    let caught_up = choice
        .supporters
        .iter()
        .filter(|&&i| {
            let (_, v, height, work) = &verified[i];
            *height > 0 && v.tip.height >= *height && v.tip.total_difficulty().to_num() >= *work
        })
        .count();
    {
        let best = &verified[choice.best].1;
        let cp_td = start.tip.total_difficulty().to_num();
        let per = start
            .recent
            .iter()
            .rev()
            .find(|h| h.height + 1 == start.tip.height)
            .map(|p| cp_td.saturating_sub(p.total_difficulty().to_num()))
            .unwrap_or(0);
        let blocks = best.tip.height.saturating_sub(start.tip.height);
        let actual = best.tip.total_difficulty().to_num().saturating_sub(cp_td);
        let (ratio, ok) = work_check(per, blocks, actual);
        println!("HEADER_SYNC_WORK_RATIO={ratio:.3} blocks={blocks} per_block_at_checkpoint={per}");
        if !ok {
            eprintln!(
                "HEADER_SYNC=FAIL work since the checkpoint is {ratio:.2} of what its difficulty implies (< {WORK_RATIO_MIN}): possible fake low-difficulty chain (eclipse); check with public sources"
            );
            std::process::exit(1);
        }
    }
    // Rolling checkpoint: the chosen chain's state at --snapshot-at, only if
    // that header really is on the chosen chain (full bytes compared).
    let snap_at = SNAPSHOT_AT.load(std::sync::atomic::Ordering::Relaxed);
    if snap_at != 0 && !snapshot_dir.is_empty() {
        let (bp, best, _, _) = &verified[choice.best];
        let snap = snapshots().lock().unwrap().remove(bp);
        let on_chain = |s: &Verifier| {
            best.validated_run.iter().find(|h| h.height == snap_at).map_or(false, |h| {
                ser::ser_vec(h, ProtocolVersion::local()).ok() == ser::ser_vec(&s.tip, ProtocolVersion::local()).ok()
            })
        };
        match snap {
            Some(s) if s.tip.height == snap_at && on_chain(&s) => {
                let d = std::path::Path::new(&snapshot_dir);
                let _ = std::fs::create_dir_all(d);
                write_checkpoint_to_quiet(&s, d.join("checkpoint.rwm").to_str().unwrap_or_default());
                let mut out = Vec::new();
                out.extend_from_slice(&(s.recent.len() as u32).to_le_bytes());
                for h in &s.recent {
                    if let Ok(b) = ser::ser_vec(h, ProtocolVersion::local()) {
                        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
                        out.extend_from_slice(&b);
                    }
                }
                if std::fs::write(d.join("recent-headers.bin"), out).is_ok() {
                    println!("HEADER_SYNC_SNAPSHOT height={snap_at} hash={} dir={snapshot_dir}", s.tip.hash().to_hex());
                }
            }
            Some(_) => println!("HEADER_SYNC_SNAPSHOT=SKIPPED (not on the chosen chain)"),
            None => println!("HEADER_SYNC_SNAPSHOT=SKIPPED (height {snap_at} not reached by the chosen peer)"),
        }
    }
    let (best_peer, v, _, _) = verified.swap_remove(choice.best);
    if choice.rejected.is_empty() {
        println!("HEADER_SYNC_COMMON_HEADERS=AGREE_FULL_BYTES");
    } else {
        println!("HEADER_SYNC_COMMON_HEADERS=MOST_WORK_CHOSEN rejected={}", choice.rejected.len());
    }
    println!("HEADER_SYNC_CAUGHT_UP_PEERS={caught_up}");
    // Fail closed BEFORE anything is written: a chain with headers whose
    // network difficulty could not be checked (checkpoint without enough
    // history) is never reported as PASS and never saved as state/checkpoint.
    if let Err(e) = difficulty_verdict(v.stats.diff_checked, v.stats.diff_unchecked_no_history) {
        println!("HEADER_SYNC_NETWORK_DIFFICULTY_CHECKED={}", v.stats.diff_checked);
        println!("HEADER_SYNC_NETWORK_DIFFICULTY_UNCHECKED_NO_HISTORY={}", v.stats.diff_unchecked_no_history);
        eprintln!("HEADER_SYNC=FAIL {e}");
        std::process::exit(1);
    }

    if !write_checkpoint.is_empty() {
        write_checkpoint_to(&v, &write_checkpoint);
    }
    if !state_dir.is_empty() {
        write_state(&v, &state_dir);
        println!("HEADER_SYNC_STATE_DIR={state_dir}");
    }
    println!("HEADER_SYNC_PEERS_OK={ok_peers}/{}", peers.len());
    if peers.len() < 2 && confirmed < 2 {
        println!("HEADER_SYNC_WARNING=single peer: no most-work comparison and fewer than two confirmations, eclipse not mitigated");
    }
    println!("HEADER_SYNC_BEST_PEER={best_peer}");
    println!("HEADER_SYNC_HEADERS={}", v.stats.headers);
    println!("HEADER_SYNC_FIRST_HEIGHT={}", start_height + 1);
    println!("HEADER_SYNC_LAST_HEIGHT={}", v.tip.height);
    println!("HEADER_SYNC_TOTAL_DIFFICULTY={}", v.tip.total_difficulty().to_num());
    println!("HEADER_SYNC_POW_TARGET_CHECKED={}", v.stats.pow);
    println!("HEADER_SYNC_NETWORK_DIFFICULTY_CHECKED={}", v.stats.diff_checked);
    println!("HEADER_SYNC_NETWORK_DIFFICULTY_UNCHECKED_NO_HISTORY={}", v.stats.diff_unchecked_no_history);
    println!("HEADER_SYNC_MMR_CHECKED={}", v.stats.mmr);
    println!("HEADER_SYNC=PASS");
}

/// PASS needs every new header's network difficulty to have been checked.
fn difficulty_verdict(checked: usize, unchecked: usize) -> Result<(), String> {
    if unchecked > 0 {
        return Err(format!(
            "network difficulty not checked for {unchecked} header(s) (checked {checked}): the checkpoint lacks difficulty history; use a checkpoint with history"
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Offline regression tests for the audit findings (no network needed).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        global::set_local_chain_type(ChainTypes::Testnet);
    }

    #[test]
    fn progress_snapshots_resume() {
        setup();
        let dir = std::env::temp_dir().join(format!("grinsight-progress-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let d = dir.to_str().unwrap();
        assert!(load_progress(d).is_none());
        let v = Verifier::from_genesis();
        save_progress(&v, d);
        save_progress(&v, d); // second slot
        let r = load_progress(d).expect("resumes");
        assert_eq!(r.tip.hash(), v.tip.hash());
        // A broken slot is ignored, the other one still works.
        std::fs::write(dir.join("progress-0").join("checkpoint.rwm"), "garbage").unwrap();
        std::fs::write(dir.join("progress-0").join("complete"), "5").unwrap();
        assert_eq!(load_progress(d).expect("falls back to the good slot").tip.height, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn describe_real_floonet_checkpoint() {
        setup();
        let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../evidence/floonet-checkpoint.rwm");
        if std::path::Path::new(p).exists() {
            describe_checkpoint(p).unwrap();
            assert_eq!(load_checkpoint(p, None).unwrap().tip.height, 3318854);
        }
    }

    #[test]
    #[ignore]
    fn load_real_floonet_checkpoint() {
        setup();
        let p = std::env::var("RW_CP").unwrap();
        let v = load_checkpoint(&p, None).unwrap();
        println!("loaded height {}", v.tip.height);
    }

    // --- AUDIT R2 regression tests ------------------------------------

    /// N-2: Grin's header hash covers only the PoW nonces, so a block can carry
    /// the right hash with different header fields. bind_block must catch it.
    #[test]
    fn block_with_same_hash_but_other_fields_rejected() {
        setup();
        let g = grin_core::genesis::genesis_test();
        let mut forged = g.clone();
        forged.header.output_root = Hash::from_vec(&[0x42u8; 32]);
        assert_eq!(forged.header.hash(), g.header.hash(), "hash is nonce-only");
        let err = bind_block(&g.header, None, &forged).unwrap_err();
        assert!(err.contains("does not match the validated header"), "{err}");
        bind_block(&g.header, None, &g).expect("honest genesis block binds");
    }

    /// N-2 on real data: set RW_BLOCK to a serialized Floonet block
    /// (e.g. data/floonet-tail-block-3318342.bin).
    #[test]
    #[ignore]
    fn real_block_binding() {
        setup();
        let raw = std::fs::read(std::env::var("RW_BLOCK").unwrap()).unwrap();
        let b: core::Block = ser::deserialize(
            &mut &raw[..],
            ProtocolVersion::local(),
            ser::DeserializationMode::default(),
        )
        .unwrap();
        bind_block(&b.header, None, &b).expect("real block binds and body is consistent");
        let mut forged = b.clone();
        forged.header.kernel_root = Hash::from_vec(&[7u8; 32]);
        assert_eq!(forged.header.hash(), b.header.hash());
        assert!(bind_block(&b.header, None, &forged).is_err());
        println!("real block {} outputs={} kernels={}", b.header.height, b.body.outputs.len(), b.body.kernels.len());
    }

    /// N-2/N-7: unsolicited blocks are dropped, each hash is taken once, and
    /// the buffer is bounded.
    #[test]
    fn only_requested_blocks_are_buffered() {
        setup();
        let g = grin_core::genesis::genesis_test();
        let wanted = Mutex::new(HashSet::new());
        let blocks = Mutex::new(Vec::new());
        assert!(!accept_requested_block(&wanted, &blocks, g.clone()));
        wanted.lock().unwrap().insert(g.header.hash());
        assert!(accept_requested_block(&wanted, &blocks, g.clone()));
        assert!(!accept_requested_block(&wanted, &blocks, g.clone()), "duplicate");
        assert_eq!(blocks.lock().unwrap().len(), 1);
        let full = Mutex::new(vec![g.clone(); MAX_PENDING_BLOCKS]);
        let w2 = Mutex::new(HashSet::from([g.header.hash()]));
        assert!(!accept_requested_block(&w2, &full, g));
    }

    // --- AUDIT R3 N-5 ------------------------------------------------

    // --- AUDIT R4 N-10 -----------------------------------------------

    fn sv(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn flag_without_value_does_not_swallow_next_argument() {
        // Old loop treated --fetch-all-blocks as taking a value and silently
        // swallowed the following --peer.
        let m = parse_flags(&sv(&["--fetch-all-blocks", "--peer", "a:1", "--checkpoint", "genesis"]), SYNC_SPEC).unwrap();
        assert!(m.contains_key("--fetch-all-blocks"));
        assert_eq!(m["--peer"], sv(&["a:1"]));
    }

    #[test]
    fn unchecked_difficulty_is_never_pass() {
        assert!(difficulty_verdict(0, 1).is_err());
        assert!(difficulty_verdict(1000, 1).is_err());
        assert!(difficulty_verdict(1000, 0).is_ok());
    }

    #[test]
    fn strict_parsing_rejects_bad_input() {
        // unknown flag
        assert!(parse_flags(&sv(&["--peer", "a:1", "--bogus", "x"]), SYNC_SPEC).is_err());
        // missing value / value that is a flag
        assert!(parse_flags(&sv(&["--peer"]), SYNC_SPEC).is_err());
        assert!(parse_flags(&sv(&["--batches", "--peer", "a:1"]), SYNC_SPEC).is_err());
        // single-use flag repeated
        assert!(parse_flags(&sv(&["--batches", "1", "--batches", "2"]), SYNC_SPEC).is_err());
        // repeatable flag
        let m = parse_flags(&sv(&["--peer", "a:1", "--peer", "b:2"]), SYNC_SPEC).unwrap();
        assert_eq!(m["--peer"].len(), 2);
        // mixing modes: watch mode does not accept sync/fetch flags
        assert!(parse_flags(&sv(&["--watch-commit", "ab", "--blocks-dir", "d", "--peer", "a:1"]), WATCH_SPEC).is_err());
        assert!(parse_flags(&sv(&["--fetch-block-hash", "ab", "--peer", "a:1", "--out", "f", "--blocks-dir", "d"]), FETCH_SPEC).is_err());
        // fetch mode takes exactly one peer
        assert!(parse_flags(&sv(&["--fetch-block-hash", "ab", "--peer", "a:1", "--peer", "b:2", "--out", "f"]), FETCH_SPEC).is_err());
    }

}

#[cfg(test)]
mod verified_tip_regression {
    use super::*;
    use grinsight_state::session::{encode_transcript, sha256_hex, now_unix, MANIFEST_FILE, TRANSCRIPT_FILE};

    fn fixture(age: i64, max_age: i64) -> (std::path::PathBuf, String, u64) {
        grin_core::global::set_local_chain_type(grin_core::global::ChainTypes::Testnet);
        static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let base = std::env::temp_dir().join(format!("gs-verified-tip-{}-{}", std::process::id(), SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        std::fs::create_dir_all(&base).unwrap();
        let checkpoint = include_str!("../../checkpoints/floonet/checkpoint.rwm");
        let hex = checkpoint.lines().find_map(|l| l.strip_prefix("header ")).unwrap().trim();
        let mut raw = grin_util::from_hex(hex).unwrap();
        let height = u64::from_be_bytes(raw[2..10].try_into().unwrap());
        raw[10..18].copy_from_slice(&(now_unix()-age).to_be_bytes());
        let hash = grinsight_state::outputs::header_hash_hex(&raw, false).unwrap();
        let transcript = encode_transcript([raw.as_slice()]);
        std::fs::write(base.join(TRANSCRIPT_FILE), &transcript).unwrap();
        let manifest = serde_json::json!({"version":1,"network":"FLOONET","transcript_sha256":sha256_hex(&transcript),"tip_header_sha256":sha256_hex(&raw),"tip_height":height,"sync_status":"PASS","max_tip_age_sec":max_age}).to_string();
        std::fs::write(base.join(MANIFEST_FILE), &manifest).unwrap();
        std::fs::write(base.join("last-open.json"), serde_json::json!({"session":base.display().to_string(),"manifest_sha256":sha256_hex(manifest.as_bytes()),"tip_height":height}).to_string()).unwrap();
        let phrase = grin_keychain::mnemonic::from_entropy(&[7;32]).unwrap();
        let seeds = base.join("seeds.txt");
        std::fs::write(&seeds, phrase).unwrap();
        let wallets = grinsight_state::wallet::Wallets::from_file(seeds.to_str().unwrap()).unwrap();
        let body = format!("{{\"meta\":\"grinsight-wallet\",\"tip_height\":{height},\"tip_hash\":\"{hash}\"}}\n");
        let mac = wallets.file_mac(body.as_bytes());
        std::fs::write(base.join("wallet-outputs.jsonl"), format!("{body}{{\"mac\":\"{mac}\",\"records\":0}}\n")).unwrap();
        (base, seeds.display().to_string(), height)
    }

    #[test]
    fn verifies_fresh_session_network_and_wallet_binding() {
        let (base, seeds, height) = fixture(5, 10800);
        assert_eq!(verified_profile_tip(&base, &seeds, false).unwrap(), height);
        assert!(verified_profile_tip(&base, &seeds, true).is_err());
        let known = base.join("wallet-outputs.jsonl");
        let original = std::fs::read_to_string(&known).unwrap();
        std::fs::write(&known, original.replace(&height.to_string(), &(height+1).to_string())).unwrap();
        assert!(verified_profile_tip(&base, &seeds, false).is_err());
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn stale_session_does_not_authorize_a_tip() {
        // A manipulated or overly permissive manifest must not extend the
        // acceptance window for time-limited payments beyond our cap.
        let (base, seeds, _) = fixture(20_000, 604_800);
        assert!(verified_profile_tip(&base, &seeds, false).is_err());
        let _ = std::fs::remove_dir_all(base);
    }
}

