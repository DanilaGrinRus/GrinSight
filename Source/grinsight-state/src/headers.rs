//! Header chain verification, mirrors grin-5.5.2 chain/src/pipe.rs
//! validate_header; checkpoints, their difficulty history; chain choice.

use crate::mmr;
use chrono::{DateTime, Utc};
use grin_core::consensus::{self, HeaderDifficultyInfo};
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{self, pmmr, BlockHeader, HeaderVersion};
use grin_core::global;
use grin_core::pow::{self, Difficulty};
use grin_core::ser::{self, ProtocolVersion};
use grin_util::ToHex;

pub fn header_digest(h: &BlockHeader) -> Hash {
    mmr::blake2b256(&ser::ser_vec(h, ProtocolVersion::local()).unwrap_or_default())
}


/// AUDIT R2 N-3: a fork replaces our branch only if it validated completely
/// and carries strictly more total work (ties keep the branch we saw first,
/// as a Grin node does).
pub fn fork_wins(old_work: Difficulty, new_work: Difficulty, fork_valid: bool) -> bool {
    fork_valid && new_work > old_work
}


pub fn hex_hash(s: &str) -> Result<Hash, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 || !s.is_ascii() {
        return Err("hash must be 64 hex chars".into());
    }
    let mut v = vec![0u8; 32];
    for i in 0..32 {
        v[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(Hash::from_vec(&v))
}

// ---------------------------------------------------------------------------
// Header validation (AUDIT: mirrors grin-5.5.2 chain/src/pipe.rs validate_header)
// ---------------------------------------------------------------------------

/// Future-time limit used by Grin nodes for incoming blocks (12 block times).
pub const FTL_SEC: i64 = 12 * consensus::BLOCK_TIME_SEC as i64;
/// Max headers per `Headers` response (grin_p2p::types::MAX_BLOCK_HEADERS).
pub const MAX_BLOCK_HEADERS: usize = 512;
/// History kept for the pre-HF4 DMA window (DMA_WINDOW + 1) plus slack.
pub const HIST_KEEP: usize = consensus::DMA_WINDOW as usize + 2;

#[derive(Clone, Default, Debug)]
pub struct Stats {
    pub headers: usize,
    pub pow: usize,
    pub diff_checked: usize,
    pub diff_unchecked_no_history: usize,
    pub mmr: usize,
}

#[derive(Clone)]
pub struct Snapshot {
    pub tip: BlockHeader,
    pub mmr: mmr::PeakAccum,
    pub hist: Vec<HeaderDifficultyInfo>,
}

#[derive(Clone)]
pub struct Verifier {
    pub tip: BlockHeader,
    pub mmr: mmr::PeakAccum,
    /// Difficulty info oldest -> newest, last entry is `tip` (when known).
    pub hist: Vec<HeaderDifficultyInfo>,
    /// Recent headers for state resume (oldest -> tip).
    pub recent: Vec<BlockHeader>,
    /// This run's checkpoint and selected fully validated branch, not a proof
    /// of pre-checkpoint history. Exported only after the run succeeds.
    pub validated_run: Vec<BlockHeader>,
    /// Digest mode: digests of headers start+1.. (see DIGEST_RUN).
    pub run_digests: Vec<Hash>,
    /// Snapshots for reorg rollback (last 64 headers).
    pub snapshots: Vec<Snapshot>,
    /// True when `hist` reaches genesis, so Grin's own pre-genesis padding in
    /// `difficulty_data_to_vector` is correct. False after a checkpoint start.
    pub hist_from_genesis: bool,
    pub stats: Stats,
    /// Strict mode (C API): a header whose network difficulty cannot be
    /// checked for lack of history is REJECTED instead of being counted in
    /// `stats.diff_unchecked_no_history`. The CLI keeps the counter and fails
    /// the whole sync if it is not 0 (grinsight.py).
    pub require_difficulty: bool,
}

/// Difficulty-history entries needed to check the network difficulty of the
/// header at `height` (DMA window before HF4, two headers after).
pub fn history_needed(height: u64) -> usize {
    if consensus::header_version(height) < HeaderVersion(5) {
        consensus::DMA_WINDOW as usize + 1
    } else {
        2
    }
}

pub fn diff_info(h: &BlockHeader, parent_total: Difficulty) -> HeaderDifficultyInfo {
    // Same as grin_chain::store::DifficultyIter: per-block difficulty is
    // total(h) - total(parent). AUDIT: the old check_wtema passed the *total*
    // difficulty here, which is wrong for WTEMA (it never ran on the tested
    // heights, see AUDIT.md).
    HeaderDifficultyInfo::new(
        Some(h.hash()),
        h.timestamp.timestamp() as u64,
        h.total_difficulty() - parent_total,
        h.pow.secondary_scaling,
        h.pow.is_secondary(),
    )
}

impl Verifier {
    pub fn from_genesis() -> Self {
        let g = global::get_genesis_block().header;
        let mut acc = mmr::PeakAccum { peaks: vec![], size: 0, leaves: 0 };
        acc.append(&g).expect("genesis peak append");
        let info = diff_info(&g, Difficulty::zero());
        Verifier { tip: g.clone(), mmr: acc.clone(), hist: vec![info.clone()], recent: vec![g.clone()], validated_run: vec![g.clone()], run_digests: vec![], snapshots: vec![Snapshot { tip: g, mmr: acc, hist: vec![info] }], hist_from_genesis: true, stats: Stats::default(), require_difficulty: false }
    }

    /// Enough difficulty history to check the header at `height`.
    pub fn can_check_difficulty(&self, height: u64) -> bool {
        self.hist_from_genesis || self.hist.len() >= history_needed(height)
    }

    pub fn from_checkpoint(cp: BlockHeader, acc: mmr::PeakAccum) -> Self {
        // The checkpoint's own block difficulty needs its parent's total, which
        // the file does not carry, so history starts with the first synced header.
        Verifier { tip: cp.clone(), mmr: acc.clone(), hist: vec![], recent: vec![cp.clone()], validated_run: vec![cp.clone()], run_digests: vec![], snapshots: vec![Snapshot { tip: cp, mmr: acc, hist: vec![] }], hist_from_genesis: false, stats: Stats::default(), require_difficulty: false }
    }

    /// AUDIT R2 N-3: a header we already hold (same height and same hash).
    /// Peers resend these when the locator matches below our tip; they are
    /// not a fork and must not trigger a rollback.
    pub fn is_known(&self, h: &BlockHeader) -> bool {
        self.snapshots
            .iter()
            .any(|s| s.tip.height == h.height && s.tip.hash() == h.hash())
            || self.recent.iter().any(|r| r.height == h.height && r.hash() == h.hash())
    }

    pub fn rollback_to(&mut self, hash: &Hash) -> Result<u64, String> {
        let pos = self
            .snapshots
            .iter()
            .rposition(|s| s.tip.hash() == *hash)
            .ok_or_else(|| format!("no snapshot for reorg common ancestor {hash:?}"))?;
        let snap = self.snapshots[pos].clone();
        let old_height = self.tip.height;
        self.tip = snap.tip.clone();
        self.mmr = snap.mmr;
        self.hist = snap.hist;
        self.hist_from_genesis = self.tip.height == 0;
        self.recent.retain(|h| h.height <= self.tip.height);
        if self.recent.last().map(|h| h.hash()) != Some(self.tip.hash()) {
            self.recent.push(self.tip.clone());
        }
        self.snapshots.truncate(pos + 1);
        Ok(old_height.saturating_sub(self.tip.height))
    }

    pub fn validate_and_append(&mut self, h: &BlockHeader) -> Result<(), String> {
        let prev = &self.tip;
        let ht = h.height;
        if ht != prev.height + 1 {
            return Err(format!("height {} != {}", ht, prev.height + 1));
        }
        if self.require_difficulty && !self.can_check_difficulty(ht) {
            return Err(format!(
                "network difficulty at {ht} cannot be checked: difficulty history has {} of {} headers (open with the checkpoint's recent headers)",
                self.hist.len(),
                history_needed(ht)
            ));
        }
        if h.prev_hash != prev.hash() {
            return Err(format!("prev_hash mismatch at {ht}"));
        }
        if h.prev_root != self.mmr.root() {
            return Err(format!("MMR prev_root mismatch at {ht}"));
        }
        // AUDIT: without this, version<5 silently disabled the WTEMA check.
        if !consensus::valid_header_version(ht, h.version) {
            return Err(format!("invalid header version {:?} at {ht}", h.version));
        }
        if h.timestamp <= prev.timestamp {
            return Err(format!("timestamp not increasing at {ht}"));
        }
        if h.timestamp > Utc::now() + chrono::Duration::seconds(FTL_SEC) {
            return Err(format!("timestamp too far in the future at {ht}"));
        }
        let outs = h.output_mmr_count().saturating_sub(prev.output_mmr_count());
        let kerns = h.kernel_mmr_count().saturating_sub(prev.kernel_mmr_count());
        if outs == 0 || kerns == 0 {
            return Err(format!("invalid MMR sizes at {ht}"));
        }
        if core::TransactionBody::weight_by_iok(0, outs, kerns) > global::max_block_weight() {
            return Err(format!("block too heavy at {ht}"));
        }
        if !h.pow.is_primary() && !h.pow.is_secondary() {
            return Err(format!("low edge bits at {ht}"));
        }
        if pow::verify_size(h).is_err() {
            return Err(format!("PoW invalid at {ht}"));
        }
        // AUDIT: a valid cycle is not enough; it must meet the target.
        if h.total_difficulty() <= prev.total_difficulty() {
            return Err(format!("total difficulty not increasing at {ht}"));
        }
        let target = h.total_difficulty() - prev.total_difficulty();
        if h.pow.to_difficulty(ht) < target {
            return Err(format!("PoW below target difficulty at {ht}"));
        }
        self.stats.pow += 1;

        // Network difficulty (DMA before HF4, WTEMA after) and secondary scaling.
        if self.can_check_difficulty(ht) {
            let next = consensus::next_difficulty(ht, self.hist.iter().rev().cloned());
            if target != next.difficulty {
                return Err(format!(
                    "wrong network difficulty at {ht}: claimed {} expected {}",
                    target.to_num(),
                    next.difficulty.to_num()
                ));
            }
            if h.version < HeaderVersion(5) && h.pow.secondary_scaling != next.secondary_scaling {
                return Err(format!("wrong secondary scaling at {ht}"));
            }
            self.stats.diff_checked += 1;
        } else {
            self.stats.diff_unchecked_no_history += 1;
        }

        let info = diff_info(h, prev.total_difficulty());
        self.mmr.append(h)?;
        self.stats.mmr += 1;
        self.hist.push(info);
        if self.hist.len() > HIST_KEEP {
            let drop = self.hist.len() - HIST_KEEP;
            self.hist.drain(..drop);
        }
        self.tip = h.clone();
        self.recent.push(h.clone());
        if self.recent.len() > HIST_KEEP {
            let drop = self.recent.len() - HIST_KEEP;
            self.recent.drain(..drop);
        }
        self.snapshots.push(Snapshot {
            tip: self.tip.clone(),
            mmr: self.mmr.clone(),
            hist: self.hist.clone(),
        });
        if self.snapshots.len() > 64 {
            let drop = self.snapshots.len() - 64;
            self.snapshots.drain(..drop);
        }
        self.stats.headers += 1;
        Ok(())
    }
}

/// `--confirm-peer`: a confirming peer's answer counts only if the headers it
/// returned after `base.tip` form a chain that passes the FULL validation
/// (PoW, target, network difficulty, MMR root, timestamps), not just a
/// matching height/prev_hash. Returns the last validated height.
pub fn check_continuation(base: &Verifier, got: &[BlockHeader]) -> Result<u64, String> {
    let mut hs: Vec<&BlockHeader> = got.iter().collect();
    hs.sort_by_key(|h| h.height);
    let first = hs.first().ok_or("no headers")?;
    if first.height != base.tip.height + 1 || first.prev_hash != base.tip.hash() {
        return Err(format!(
            "peer answered from height {} (prev {}), not after our {} {}",
            first.height,
            first.prev_hash.to_hex(),
            base.tip.height,
            base.tip.hash().to_hex()
        ));
    }
    let mut v = base.clone();
    v.require_difficulty = true;
    v.validated_run.clear();
    v.run_digests.clear();
    for h in hs {
        v.validate_and_append(h).map_err(|e| format!("continuation header invalid: {e}"))?;
    }
    Ok(v.tip.height)
}

/// AUDIT R3 N-5: check headers restored from `recent-headers.bin`.
///
/// Requires: non-empty; last header byte-identical to `tip`; every header has
/// valid edge bits, a valid cuckoo cycle and a version valid for its height;
/// consecutive headers link by height/prev_hash, have increasing timestamps
/// and total difficulty, and meet their target difficulty. Where the restored
/// window itself holds enough history, the network difficulty (WTEMA after
/// HF4, DMA before) is recomputed and must match. Returns the difficulty
/// history in the same form `validate_and_append` maintains.
pub fn validate_restored_history(
    headers: &[BlockHeader],
    tip: &BlockHeader,
) -> Result<Vec<HeaderDifficultyInfo>, String> {
    let last = headers.last().ok_or("restored history is empty")?;
    let want = ser::ser_vec(tip, ProtocolVersion::local()).map_err(|e| format!("{e:?}"))?;
    let have = ser::ser_vec(last, ProtocolVersion::local()).map_err(|e| format!("{e:?}"))?;
    if want != have {
        return Err("restored history does not end at the checkpoint header".into());
    }
    for h in headers {
        let ht = h.height;
        if !consensus::valid_header_version(ht, h.version) {
            return Err(format!("restored header {ht}: invalid version"));
        }
        if !h.pow.is_primary() && !h.pow.is_secondary() {
            return Err(format!("restored header {ht}: low edge bits"));
        }
        if pow::verify_size(h).is_err() {
            return Err(format!("restored header {ht}: PoW invalid"));
        }
    }
    let mut hist: Vec<HeaderDifficultyInfo> = Vec::new();
    for w in headers.windows(2) {
        let (p, h) = (&w[0], &w[1]);
        let ht = h.height;
        if ht != p.height + 1 || h.prev_hash != p.hash() {
            return Err(format!("restored header {ht}: does not link to {}", p.height));
        }
        if h.timestamp <= p.timestamp {
            return Err(format!("restored header {ht}: timestamp not increasing"));
        }
        if h.total_difficulty() <= p.total_difficulty() {
            return Err(format!("restored header {ht}: total difficulty not increasing"));
        }
        let target = h.total_difficulty() - p.total_difficulty();
        if h.pow.to_difficulty(ht) < target {
            return Err(format!("restored header {ht}: PoW below target"));
        }
        let needed = if consensus::header_version(ht) < HeaderVersion(5) {
            consensus::DMA_WINDOW as usize + 1
        } else {
            2
        };
        if hist.len() >= needed {
            let next = consensus::next_difficulty(ht, hist.iter().rev().cloned());
            if target != next.difficulty {
                return Err(format!("restored header {ht}: wrong network difficulty"));
            }
        }
        hist.push(diff_info(h, p.total_difficulty()));
    }
    Ok(hist)
}

// ---------------------------------------------------------------------------
// Checkpoint file (AUDIT: every field is now cross-checked, fail closed)
// ---------------------------------------------------------------------------

pub fn load_checkpoint(path: &str, expect_hash: Option<Hash>) -> Result<Verifier, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("checkpoint read: {e}"))?;
    load_checkpoint_text(&text, expect_hash)
}

/// `load_checkpoint` from the checkpoint file contents (no file system).
pub fn load_checkpoint_text(text: &str, expect_hash: Option<Hash>) -> Result<Verifier, String> {
    let cp = mmr::CheckpointFile::parse(text)?;
    let bytes = cp.header_bytes.as_ref().ok_or("checkpoint has no header line")?;
    let header: BlockHeader =
        ser::deserialize(&mut &bytes[..], ProtocolVersion::local(), ser::DeserializationMode::default())
            .map_err(|e| format!("checkpoint header does not deserialize: {e}"))?;
    if header.hash() != cp.hash {
        return Err("checkpoint header bytes do not hash to `hash`".into());
    }
    if let Some(h) = expect_hash {
        if h != cp.hash {
            return Err("checkpoint hash differs from --expect-hash".into());
        }
    }
    if header.height != cp.height {
        return Err("checkpoint header height differs from `height`".into());
    }
    if cp.acc.leaves != cp.height + 1 {
        return Err("checkpoint leaves != height + 1".into());
    }
    if cp.acc.size != pmmr::insertion_to_pmmr_index(cp.acc.leaves) {
        return Err("checkpoint size inconsistent with leaves".into());
    }
    let want: Vec<u64> = pmmr::peaks(cp.acc.size);
    let got: Vec<u64> = cp.acc.peaks.iter().map(|p| p.0).collect();
    if want != got {
        return Err(format!("checkpoint peak positions {got:?} != {want:?}"));
    }
    if cp.acc.peaks.iter().any(|p| p.1 != pmmr::bintree_postorder_height(p.0)) {
        return Err("checkpoint peak heights inconsistent".into());
    }
    if cp.acc.root() != cp.root {
        return Err("checkpoint peaks do not bag to `root`".into());
    }
    // The genesis checkpoint IS the start of the chain: its difficulty history
    // is the genesis itself (as `from_genesis`), so the next header is fully
    // checked without a recent-headers file.
    if header.height == 0 && header.hash() == global::get_genesis_block().header.hash() {
        let v = Verifier::from_genesis();
        if v.mmr.root() != cp.root {
            return Err("genesis checkpoint root differs from the genesis header MMR".into());
        }
        return Ok(v);
    }
    if pow::verify_size(&header).is_err() {
        return Err("checkpoint header PoW invalid".into());
    }
    Ok(Verifier::from_checkpoint(header, cp.acc))
}


pub fn write_checkpoint_to(v: &Verifier, path: &str) {
    write_checkpoint_to_quiet(v, path);
    println!("HEADER_SYNC_CHECKPOINT={path}");
    println!("HEADER_SYNC_CHECKPOINT_HEIGHT={}", v.tip.height);
    println!("HEADER_SYNC_CHECKPOINT_ROOT={}", v.mmr.root().to_hex());
}
/// Serialize the checkpoint format (same text as `write_checkpoint_to`).
pub fn checkpoint_text(v: &Verifier) -> String {
    let last = &v.tip;
    let hdr_bytes = ser::ser_vec(last, ProtocolVersion::local()).expect("serialize header");
    let hdr_hex: String = hdr_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let root = v.mmr.root();
    let mut text = String::new();
    text.push_str("RWM1\n");
    text.push_str(&format!("height {}\n", last.height));
    text.push_str(&format!("hash {}\n", last.hash().to_hex()));
    text.push_str(&format!("header {hdr_hex}\n"));
    text.push_str(&format!("leaves {}\n", v.mmr.leaves));
    text.push_str(&format!("size {}\n", v.mmr.size));
    text.push_str(&format!("root {}\n", root.to_hex()));
    for (pos, height, hash) in &v.mmr.peaks {
        text.push_str(&format!("peak {pos} {height} {}\n", hash.to_hex()));
    }
    text
}

pub fn write_checkpoint_to_quiet(v: &Verifier, path: &str) {
    std::fs::write(path, checkpoint_text(v)).expect("write checkpoint");
}

/// Storage-backed checkpoint load: the browser path must not touch `std::fs`.
pub fn load_checkpoint_storage(
    storage: &dyn crate::storage::Storage,
    key: &str,
    expect_hash: Option<Hash>,
) -> Result<Verifier, String> {
    let raw = storage
        .get(key)?
        .ok_or_else(|| format!("checkpoint {key} not found in storage"))?;
    let text = String::from_utf8(raw).map_err(|e| format!("checkpoint {key} is not UTF-8: {e}"))?;
    load_checkpoint_text(&text, expect_hash)
}

pub fn write_checkpoint_storage(
    storage: &mut dyn crate::storage::Storage,
    key: &str,
    v: &Verifier,
) -> Result<(), String> {
    storage.put(key, checkpoint_text(v).as_bytes())
}

pub fn read_state_headers_storage(
    storage: &dyn crate::storage::Storage,
    key: &str,
) -> Result<Option<Vec<BlockHeader>>, String> {
    match storage.get(key)? {
        None => Ok(None),
        Some(raw) => parse_state_headers(&raw).map(Some),
    }
}
pub fn write_state(v: &Verifier, dir: &str) {
    std::fs::create_dir_all(dir).expect("create state dir");
    let cp = std::path::Path::new(dir).join("checkpoint.rwm");
    write_checkpoint_to(v, cp.to_str().expect("checkpoint path"));
    let hdr_path = std::path::Path::new(dir).join("recent-headers.bin");
    let mut out = Vec::new();
    out.extend_from_slice(&(v.recent.len() as u32).to_le_bytes());
    for h in &v.recent {
        let b = ser::ser_vec(h, ProtocolVersion::local()).expect("serialize recent");
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(&b);
    }
    std::fs::write(&hdr_path, out).expect("write recent headers");
    if !v.run_digests.is_empty() {
        println!("HEADER_SYNC_TRANSCRIPT=SKIPPED (digest run)");
        println!("HEADER_SYNC_STATE_HEADERS={}", v.recent.len());
        return;
    }
    let mut verified = Vec::new();
    verified.extend_from_slice(&(v.validated_run.len() as u32).to_le_bytes());
    for h in &v.validated_run {
        let b = ser::ser_vec(h, ProtocolVersion::local()).expect("serialize verified header");
        verified.extend_from_slice(&(b.len() as u32).to_le_bytes());
        verified.extend_from_slice(&b);
    }
    std::fs::write(std::path::Path::new(dir).join("verified-headers.bin"), verified).expect("write verified headers");
    println!("HEADER_SYNC_STATE_HEADERS={}", v.recent.len());
}

/// AUDIT R3 N-5: `Ok(None)` if the state dir has no recent-headers file,
/// `Err` if it exists but is malformed (was: silently treated as absent, so
/// a corrupt file just disabled difficulty history).
pub fn read_state_headers(dir: &str) -> Result<Option<Vec<BlockHeader>>, String> {
    let path = std::path::Path::new(dir).join("recent-headers.bin");
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    parse_state_headers(&raw).map(Some)
}

/// The recent-headers.bin format (count u32, then length-prefixed headers).
pub fn parse_state_headers(raw: &[u8]) -> Result<Vec<BlockHeader>, String> {
    if raw.len() < 4 {
        return Err("recent-headers.bin too short".into());
    }
    let n = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
    if n == 0 || n > HIST_KEEP {
        return Err(format!("recent-headers.bin count {n} not in 1..={HIST_KEEP}"));
    }
    let mut off = 4usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let end = off.checked_add(4).filter(|&e| e <= raw.len()).ok_or("recent-headers.bin truncated")?;
        let len = u32::from_le_bytes(raw[off..end].try_into().unwrap()) as usize;
        off = end;
        if len == 0 || len > 4096 {
            return Err(format!("recent header {i}: bad length {len}"));
        }
        let end = off.checked_add(len).filter(|&e| e <= raw.len()).ok_or("recent-headers.bin truncated")?;
        let h: BlockHeader = ser::deserialize(
            &mut &raw[off..end],
            ProtocolVersion::local(),
            ser::DeserializationMode::default(),
        )
        .map_err(|e| format!("recent header {i}: {e:?}"))?;
        off = end;
        out.push(h);
    }
    if off != raw.len() {
        return Err("recent-headers.bin has trailing bytes".into());
    }
    Ok(out)
}

impl Verifier {
    pub fn restore_recent(&mut self, headers: Vec<BlockHeader>) -> Result<(), String> {
        // AUDIT R3 N-5: the file is local but not trusted. Before its headers
        // become difficulty history they must form a valid chain ending
        // exactly (all bytes, not just the nonce hash) at the checkpoint.
        let hist = validate_restored_history(&headers, &self.tip)?;
        self.recent = headers;
        self.hist = hist;
        self.snapshots = vec![Snapshot {
            tip: self.tip.clone(),
            mmr: self.mmr.clone(),
            hist: self.hist.clone(),
        }];
        self.hist_from_genesis = false;
        Ok(())
    }
}

pub fn compare_peer_chains(a: &Verifier, b: &Verifier) -> Result<(), String> {
    let common_height = a.tip.height.min(b.tip.height);
    if !a.run_digests.is_empty() || !b.run_digests.is_empty() {
        // Digest mode: both runs start at the same header; entry i is height start+1+i.
        let start = a.validated_run.first().map(|h| h.height).ok_or("empty run")?;
        if b.validated_run.first().map(|h| h.height) != Some(start) {
            return Err("peer runs start at different heights".into());
        }
        let n = (common_height - start) as usize;
        if a.run_digests.len() < n || b.run_digests.len() < n {
            return Err(format!("missing digests up to common height {common_height}"));
        }
        if let Some(i) = (0..n).find(|&i| a.run_digests[i] != b.run_digests[i]) {
            return Err(format!("full headers differ at height {}", start + 1 + i as u64));
        }
        return Ok(());
    }
    let mut compared = 0;
    for (x, y) in a.validated_run.iter().zip(&b.validated_run) {
        let xb = ser::ser_vec(x, ProtocolVersion::local()).map_err(|e| format!("serialize header: {e:?}"))?;
        let yb = ser::ser_vec(y, ProtocolVersion::local()).map_err(|e| format!("serialize header: {e:?}"))?;
        if x.height != y.height || xb != yb {
            return Err(format!("full headers differ at height {}", x.height));
        }
        compared += 1;
        if x.height == common_height { return Ok(()); }
    }
    Err(format!("missing common header at height {common_height} (compared {compared})"))
}

/// Highest height the chain can have at `now`: one block per minute since
/// genesis plus a day of slack (real blocks come slightly slower than that).
pub fn max_plausible_height(now: DateTime<Utc>) -> u64 {
    let g = global::get_genesis_block().header.timestamp;
    let mins = (now - g).num_seconds().max(0) as u64 / 60;
    mins + 1440
}

/// Eclipse check (plan 5.1): the work added since the checkpoint must be in
/// line with the checkpoint's own per-block difficulty. A chain made with a
/// collapsed difficulty (stretched timestamps) has far less work per block.
/// Returns (ratio actual/expected, ok).
pub fn work_check(per_block_at_cp: u64, blocks: u64, actual_work: u64) -> (f64, bool) {
    if blocks < 100 || per_block_at_cp == 0 {
        return (1.0, true); // too short to judge
    }
    let expected = per_block_at_cp as f64 * blocks as f64;
    let ratio = actual_work as f64 / expected;
    (ratio, ratio >= WORK_RATIO_MIN)
}
/// Network hash rate can fall over months, but not to a quarter in days.
pub const WORK_RATIO_MIN: f64 = 0.25;

/// Network group of a peer for independence: IPv4 /16, IPv6 /32.
pub fn net_group(peer: &str) -> String {
    match peer.parse::<std::net::SocketAddr>().map(|a| a.ip()) {
        Ok(std::net::IpAddr::V4(v)) => {
            let o = v.octets();
            format!("{}.{}/16", o[0], o[1])
        }
        Ok(std::net::IpAddr::V6(v)) => {
            let s = v.segments();
            format!("{:x}:{:x}::/32", s[0], s[1])
        }
        Err(_) => peer.to_string(),
    }
}

/// Which of the peers' validated chains to follow.
#[derive(Debug)]
pub struct ChainChoice {
    /// Index of the peer with the most work on the chosen chain.
    pub best: usize,
    /// Peers whose chain is the chosen one (same headers up to their tip).
    pub supporters: Vec<usize>,
    /// Peers on another chain, with the reason.
    pub rejected: Vec<(usize, String)>,
}

/// Most-work rule over the peers' chains. Every chain was already fully
/// validated (PoW, difficulty, linkage, MMR), so work cannot be faked: peers
/// are grouped by chain (one is a prefix of the other), the group of the
/// heaviest chain wins, and the peers on other chains are reported instead of
/// aborting the sync (one lying or stuck peer must not stop the wallet).
pub fn choose_chain(vs: &[&Verifier]) -> Result<ChainChoice, String> {
    if vs.is_empty() {
        return Err("no validated chains".into());
    }
    let mut order: Vec<usize> = (0..vs.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(vs[i].tip.total_difficulty().to_num()));
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for &i in &order {
        match groups.iter_mut().find(|g| compare_peer_chains(vs[g[0]], vs[i]).is_ok()) {
            Some(g) => g.push(i),
            None => groups.push(vec![i]),
        }
    }
    let best = groups[0][0];
    let best_work = vs[best].tip.total_difficulty().to_num();
    let mut rejected = Vec::new();
    for g in &groups[1..] {
        for &i in g {
            let why = compare_peer_chains(vs[best], vs[i]).err().unwrap_or_default();
            rejected.push((
                i,
                format!(
                    "other chain: work {} at height {} < {} ({why})",
                    vs[i].tip.total_difficulty().to_num(),
                    vs[i].tip.height,
                    best_work
                ),
            ));
        }
    }
    Ok(ChainChoice { best, supporters: groups[0].clone(), rejected })
}


#[cfg(test)]
mod tests {
    use super::*;
    use grin_core::global::ChainTypes;

    fn setup() {
        global::set_local_chain_type(ChainTypes::Testnet);
    }

    /// A child of genesis with correct linkage/MMR but whatever else we set.
    fn child(v: &Verifier) -> BlockHeader {
        let mut h = v.tip.clone();
        h.height = v.tip.height + 1;
        h.prev_hash = v.tip.hash();
        h.prev_root = v.mmr.root();
        h.timestamp = v.tip.timestamp + chrono::Duration::seconds(60);
        h.output_mmr_size = v.tip.output_mmr_size + 1;
        h.kernel_mmr_size = v.tip.kernel_mmr_size + 1;
        h
    }

    #[test]
    fn peer_comparison_rejects_hidden_field_mutation_and_allows_shorter_tip() {
        setup();
        let mut a = Verifier::from_genesis();
        let mut b = a.clone();
        let h = child(&a);
        a.tip = h.clone(); a.validated_run.push(h.clone());
        b.tip = h.clone(); b.validated_run.push(h.clone());
        assert!(compare_peer_chains(&a, &b).is_ok());
        b.validated_run[1].timestamp += chrono::Duration::seconds(1);
        assert_eq!(a.validated_run[1].hash(), b.validated_run[1].hash());
        assert!(compare_peer_chains(&a, &b).is_err());
        b.validated_run.pop(); b.tip = b.validated_run[0].clone();
        assert!(compare_peer_chains(&a, &b).is_ok());
    }
    #[test]
    fn wrong_version_rejected_before_pow() {
        setup();
        let v = Verifier::from_genesis();
        let mut h = child(&v);
        h.version = HeaderVersion(5); // height 1 on testnet must be version 1
        let err = v.clone().validate_and_append(&h).unwrap_err();
        assert!(err.contains("invalid header version"), "{err}");
    }

    #[test]
    fn reorg_snapshot_rollback() {
        setup();
        let mut v = Verifier::from_genesis();
        let genesis = v.tip.clone();
        let mut fake = genesis.clone();
        fake.height = 5;
        fake.timestamp = genesis.timestamp + chrono::Duration::seconds(1);
        fake.pow.nonce = fake.pow.nonce.wrapping_add(1);
        if let Some(n) = fake.pow.proof.nonces.first_mut() {
            *n = n.wrapping_add(1);
        }
        fake.prev_hash = genesis.hash();
        fake.prev_root = v.mmr.root();
        v.snapshots.push(Snapshot {
            tip: fake.clone(),
            mmr: v.mmr.clone(),
            hist: v.hist.clone(),
        });
        v.tip = fake;
        let depth = v.rollback_to(&genesis.hash()).expect("rollback");
        assert_eq!(depth, 5);
        assert_eq!(v.tip.height, 0);
        assert_eq!(v.tip.hash(), genesis.hash());
    }

    /// Real mined headers (AutomatedTesting: tiny cuckoo graph): a header with
    /// a VALID proof of work that meets its own claimed target, but claims a
    /// network difficulty other than the one the history gives, is rejected.
    #[test]
    fn valid_pow_but_wrong_network_difficulty_rejected() {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let mut v = Verifier::from_genesis();
        v.require_difficulty = true;
        let mine = |v: &Verifier, extra: u64| -> BlockHeader {
            let mut h = child(v);
            h.version = consensus::header_version(h.height);
            let next = consensus::next_difficulty(h.height, v.hist.iter().rev().cloned());
            let target = next.difficulty.to_num() + extra;
            h.pow.secondary_scaling = next.secondary_scaling;
            h.pow.total_difficulty = v.tip.total_difficulty() + Difficulty::from_num(target);
            pow::pow_size(&mut h, Difficulty::from_num(target), global::proofsize(), global::min_edge_bits()).unwrap();
            h
        };
        let good = mine(&v, 0);
        v.validate_and_append(&good).expect("correctly mined header");
        assert_eq!(v.stats.diff_checked, 1);
        let bad = mine(&v, 1);
        assert!(pow::verify_size(&bad).is_ok(), "the proof itself is valid");
        let err = v.clone().validate_and_append(&bad).unwrap_err();
        assert!(err.contains("wrong network difficulty"), "{err}");
    }

    /// --confirm-peer: a continuation that only links by height/prev_hash
    /// but has no valid PoW / wrong difficulty does not count as agreement.
    #[test]
    fn confirm_continuation_needs_valid_pow_and_difficulty() {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let v = Verifier::from_genesis();
        let mine = |v: &Verifier, extra: u64| -> BlockHeader {
            let mut h = child(v);
            h.version = consensus::header_version(h.height);
            let next = consensus::next_difficulty(h.height, v.hist.iter().rev().cloned());
            let target = next.difficulty.to_num() + extra;
            h.pow.secondary_scaling = next.secondary_scaling;
            h.pow.total_difficulty = v.tip.total_difficulty() + Difficulty::from_num(target);
            pow::pow_size(&mut h, Difficulty::from_num(target), global::proofsize(), global::min_edge_bits()).unwrap();
            h
        };
        let h1 = mine(&v, 0);
        let mut v1 = v.clone();
        v1.validate_and_append(&h1).unwrap();
        let h2 = mine(&v1, 0);
        assert_eq!(check_continuation(&v, &[h2.clone(), h1.clone()]).unwrap(), 2, "valid chain, any order");
        // Links by height + prev_hash but the proof of work is broken.
        let mut forged = h1.clone();
        forged.pow.proof.nonces[0] ^= 1;
        assert_eq!(forged.prev_hash, v.tip.hash());
        assert!(check_continuation(&v, &[forged]).unwrap_err().contains("invalid"));
        // Valid PoW but wrong network difficulty.
        let bad = mine(&v, 1);
        assert!(check_continuation(&v, &[bad]).unwrap_err().contains("difficulty"));
        // A valid first header followed by a broken one is rejected as a whole.
        let mut h2bad = h2.clone();
        h2bad.timestamp = h1.timestamp;
        assert!(check_continuation(&v, &[h1.clone(), h2bad]).is_err());
        // Not after our tip.
        assert!(check_continuation(&v1, &[h1]).unwrap_err().contains("not after"));
    }

    /// Strict mode: a checkpoint start without history cannot check the
    /// network difficulty, so the header is refused (not counted and accepted).
    #[test]
    fn strict_mode_refuses_unchecked_difficulty() {
        setup();
        let g = Verifier::from_genesis();
        let mut v = Verifier::from_checkpoint(g.tip.clone(), g.mmr.clone());
        let h = child(&v);
        let lax = v.clone().validate_and_append(&h).unwrap_err();
        assert!(!lax.contains("cannot be checked"), "lax mode reaches the later checks: {lax}");
        v.require_difficulty = true;
        let err = v.clone().validate_and_append(&h).unwrap_err();
        assert!(err.contains("cannot be checked"), "{err}");
        assert_eq!(v.stats.diff_unchecked_no_history, 0);
    }

    #[test]
    fn non_increasing_timestamp_rejected() {
        setup();
        let v = Verifier::from_genesis();
        let mut h = child(&v);
        h.timestamp = v.tip.timestamp;
        let err = v.clone().validate_and_append(&h).unwrap_err();
        assert!(err.contains("timestamp"), "{err}");
    }

    #[test]
    fn future_timestamp_rejected() {
        setup();
        let v = Verifier::from_genesis();
        let mut h = child(&v);
        h.timestamp = Utc::now() + chrono::Duration::seconds(FTL_SEC + 60);
        let err = v.clone().validate_and_append(&h).unwrap_err();
        assert!(err.contains("future"), "{err}");
    }

    #[test]
    fn invalid_pow_rejected() {
        setup();
        let v = Verifier::from_genesis();
        let h = child(&v); // genesis proof, but pre-pow changed -> cycle invalid
        let err = v.clone().validate_and_append(&h).unwrap_err();
        assert!(err.contains("PoW") || err.contains("edge"), "{err}");
    }

    #[test]
    fn mmr_and_linkage_rejected() {
        setup();
        let v = Verifier::from_genesis();
        let mut h = child(&v);
        h.prev_root = Hash::from_vec(&[7u8; 32]);
        assert!(v.clone().validate_and_append(&h).unwrap_err().contains("prev_root"));
        let mut h = child(&v);
        h.height += 1;
        assert!(v.clone().validate_and_append(&h).unwrap_err().contains("height"));
    }

    fn write_genesis_checkpoint(path: &std::path::Path, tweak: impl Fn(&mut String)) {
        let v = Verifier::from_genesis();
        let g = &v.tip;
        let bytes = ser::ser_vec(g, ProtocolVersion::local()).unwrap();
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let mut t = format!(
            "RWM1\nheight 0\nhash {}\nheader {hex}\nleaves {}\nsize {}\nroot {}\n",
            g.hash().to_hex(),
            v.mmr.leaves,
            v.mmr.size,
            v.mmr.root().to_hex()
        );
        for (pos, height, hash) in &v.mmr.peaks {
            t.push_str(&format!("peak {pos} {height} {}\n", hash.to_hex()));
        }
        tweak(&mut t);
        std::fs::write(path, t).unwrap();
    }

    /// A peer chain in digest mode: `n` headers after genesis with digests
    /// `d[..n]` and the given total work.
    fn chain_of(d: &[Hash], n: usize, work: u64) -> Verifier {
        let mut v = Verifier::from_genesis();
        v.run_digests = d[..n].to_vec();
        v.tip.height = global::get_genesis_block().header.height + n as u64;
        v.tip.pow.total_difficulty = Difficulty::from_num(work);
        v
    }

    #[test]
    fn most_work_chain_wins_and_a_lying_peer_is_outvoted() {
        setup();
        let honest: Vec<Hash> = (0..10u8).map(|i| Hash::from_vec(&[i; 32])).collect();
        let mut fork = honest.clone();
        for x in fork.iter_mut().skip(6) {
            *x = Hash::from_vec(&[0xee; 32]);
        }
        let a = chain_of(&honest, 10, 1000);
        let b = chain_of(&honest, 9, 990); // one block behind, same chain
        let c = chain_of(&honest, 10, 1000);
        let liar = chain_of(&fork, 10, 700); // forks at height 7, less work
        let ch = choose_chain(&[&liar, &a, &b, &c]).unwrap();
        assert_eq!(ch.supporters.len(), 3);
        assert!(ch.supporters.contains(&1) && ch.supporters.contains(&2) && ch.supporters.contains(&3));
        assert!([1, 3].contains(&ch.best));
        assert_eq!(ch.rejected.len(), 1);
        assert_eq!(ch.rejected[0].0, 0);
        assert!(ch.rejected[0].1.contains("differ at height 7"), "{}", ch.rejected[0].1);
    }

    #[test]
    fn heavier_chain_from_one_peer_is_chosen_but_has_one_supporter() {
        setup();
        let honest: Vec<Hash> = (0..10u8).map(|i| Hash::from_vec(&[i; 32])).collect();
        let mut fork = honest.clone();
        fork[9] = Hash::from_vec(&[0xab; 32]);
        let a = chain_of(&honest, 10, 1000);
        let b = chain_of(&honest, 10, 1000);
        let heavy = chain_of(&fork, 10, 1001);
        let ch = choose_chain(&[&a, &b, &heavy]).unwrap();
        // Work decides (headers are PoW-validated), but one supporter is not
        // enough: sync() then fails and asks for more peers.
        assert_eq!(ch.best, 2);
        assert_eq!(ch.supporters, vec![2]);
        assert_eq!(ch.rejected.len(), 2);
    }

    #[test]
    fn work_check_flags_collapsed_difficulty() {
        assert!(work_check(1000, 50, 1).1, "too short to judge");
        assert!(work_check(1000, 5000, 5_000_000).1);
        assert!(work_check(1000, 5000, 3_000_000).1, "hash rate may drop some");
        let (r, ok) = work_check(1000, 5000, 500_000);
        assert!(!ok && (r - 0.1).abs() < 1e-9);
    }

    #[test]
    fn implausible_tip_bound() {
        global::set_local_chain_type(ChainTypes::Mainnet);
        use chrono::TimeZone;
        let now = Utc.with_ymd_and_hms(2026, 11, 10, 15, 0, 0).unwrap();
        let m = max_plausible_height(now);
        assert!(m > 4_100_899 && m < 4_200_000, "{m}");
        global::set_local_chain_type(ChainTypes::Testnet);
    }

    #[test]
    fn net_groups() {
        assert_eq!(net_group("185.177.219.185:3414"), "185.177/16");
        assert_eq!(net_group("185.177.1.2:3414"), net_group("185.177.219.185:3414"));
        assert_ne!(net_group("91.97.173.156:3414"), net_group("185.177.219.185:3414"));
        assert_eq!(net_group("[2001:db8:1::5]:3414"), "2001:db8::/32");
    }

    #[test]
    fn digest_run_comparison() {
        setup();
        let g = global::get_genesis_block().header;
        let mut a = Verifier::from_genesis();
        let mut b = Verifier::from_genesis();
        let d: Vec<Hash> = (0..10u8).map(|i| Hash::from_vec(&[i; 32])).collect();
        a.run_digests = d.clone();
        b.run_digests = d[..7].to_vec();
        a.tip.height = g.height + 10;
        b.tip.height = g.height + 7;
        assert!(compare_peer_chains(&a, &b).is_ok(), "shorter tip on the same chain is fine");
        b.run_digests[3] = Hash::from_vec(&[99; 32]);
        assert!(compare_peer_chains(&a, &b).unwrap_err().contains("differ at height 4"));
        b.run_digests = d[..5].to_vec(); // claims height 7 but only 5 digests
        assert!(compare_peer_chains(&a, &b).is_err());
    }

    #[test]
    fn mainnet_genesis_is_selected() {
        global::set_local_chain_type(ChainTypes::Mainnet);
        let h = global::get_genesis_block().header.hash().to_hex();
        global::set_local_chain_type(ChainTypes::Testnet);
        let t = global::get_genesis_block().header.hash().to_hex();
        eprintln!("GENESIS mainnet={h} floonet={t}");
        assert_ne!(h, t);
    }

    #[test]
    fn checkpoint_file_cross_checks() {
        setup();
        let dir = std::env::temp_dir();
        let p = dir.join("rw_cp_ok.rwm");
        write_genesis_checkpoint(&p, |_| {});
        assert!(load_checkpoint(p.to_str().unwrap(), None).is_ok());

        let g = grin_core::genesis::genesis_test().header.hash().to_hex();
        let cases: Vec<(&str, Box<dyn Fn(&mut String)>)> = vec![
            ("root", Box::new(|t: &mut String| {
                let i = t.find("root ").unwrap();
                t.replace_range(i + 5..i + 7, "00");
            })),
            ("height", Box::new(|t: &mut String| *t = t.replace("height 0", "height 5"))),
            ("leaves", Box::new(|t: &mut String| *t = t.replace("leaves 1", "leaves 2"))),
            ("dup", Box::new(|t: &mut String| t.push_str("height 0\n"))),
            ("unknown", Box::new(|t: &mut String| t.push_str("bogus 1\n"))),
            ("no-header", Box::new(|t: &mut String| {
                *t = t.lines().filter(|l| !l.starts_with("header ")).collect::<Vec<_>>().join("\n")
            })),
        ];
        for (name, f) in cases {
            let p = dir.join(format!("rw_cp_{name}.rwm"));
            write_genesis_checkpoint(&p, |t| f(t));
            assert!(load_checkpoint(p.to_str().unwrap(), None).is_err(), "case {name} accepted");
        }
        // --expect-hash pins the trust anchor out of band
        let other = Hash::from_vec(&[1u8; 32]);
        assert!(load_checkpoint(p.to_str().unwrap(), Some(other)).is_err());
        assert!(load_checkpoint(p.to_str().unwrap(), Some(hex_hash(&g).unwrap())).is_ok());
    }

    /// N-3: lower or equal work never replaces our branch; invalid forks never do.
    #[test]
    fn fork_needs_strictly_more_work() {
        let d = Difficulty::from_num;
        assert!(!fork_wins(d(100), d(90), true));
        assert!(!fork_wins(d(100), d(100), true));
        assert!(!fork_wins(d(100), d(200), false));
        assert!(fork_wins(d(100), d(101), true));
    }

    /// N-3: re-sent headers we already hold are recognised and not treated
    /// as a fork.
    #[test]
    fn known_headers_are_not_a_fork() {
        setup();
        let v = Verifier::from_genesis();
        assert!(v.is_known(&v.tip));
        let mut other = v.tip.clone();
        other.height = 1;
        assert!(!v.is_known(&other));
    }

    #[test]
    fn restored_history_must_end_at_tip_bytes() {
        setup();
        let v = Verifier::from_genesis();
        let g = v.tip.clone();
        assert!(validate_restored_history(&[g.clone()], &g).is_ok());
        assert!(validate_restored_history(&[], &g).is_err());
        // Same nonce hash, other field: must not count as the checkpoint.
        let mut forged = g.clone();
        forged.output_root = Hash::from_vec(&[9u8; 32]);
        assert_eq!(forged.hash(), g.hash());
        let err = validate_restored_history(&[forged], &g).unwrap_err();
        assert!(err.contains("does not end at the checkpoint"), "{err}");
    }

    #[test]
    fn restored_history_rejects_invalid_pow_and_broken_links() {
        setup();
        let g = grin_core::genesis::genesis_test().header;
        // A "tip" at height 1 that links to genesis but has no valid PoW.
        let mut h1 = g.clone();
        h1.height = 1;
        h1.prev_hash = g.hash();
        h1.timestamp = g.timestamp + chrono::Duration::seconds(60);
        let err = validate_restored_history(&[g.clone(), h1.clone()], &h1).unwrap_err();
        assert!(err.contains("PoW") || err.contains("edge") || err.contains("version"), "{err}");
        // Broken link: genesis followed by itself.
        let err = validate_restored_history(&[g.clone(), g.clone()], &g).unwrap_err();
        assert!(err.contains("does not link"), "{err}");
    }

    #[test]
    fn malformed_state_file_is_an_error_not_absent() {
        setup();
        let dir = std::env::temp_dir().join("rw_state_n5");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.to_str().unwrap();
        assert!(matches!(read_state_headers(d), Ok(None)));
        std::fs::write(dir.join("recent-headers.bin"), [1u8, 0, 0, 0, 9]).unwrap();
        assert!(read_state_headers(d).is_err());
        std::fs::write(dir.join("recent-headers.bin"), u32::MAX.to_le_bytes()).unwrap();
        assert!(read_state_headers(d).is_err());
        // round trip of a valid single-header file
        let g = grin_core::genesis::genesis_test().header;
        let b = ser::ser_vec(&g, ProtocolVersion::local()).unwrap();
        let mut f = 1u32.to_le_bytes().to_vec();
        f.extend_from_slice(&(b.len() as u32).to_le_bytes());
        f.extend_from_slice(&b);
        std::fs::write(dir.join("recent-headers.bin"), &f).unwrap();
        let hs = read_state_headers(d).unwrap().unwrap();
        assert_eq!(hs.len(), 1);
        let mut v = Verifier::from_genesis();
        v.restore_recent(hs).unwrap();
    }

    #[test]
    fn difficulty_info_uses_block_not_total_difficulty() {
        setup();
        let g = grin_core::genesis::genesis_test().header;
        let mut h = g.clone();
        h.pow.total_difficulty = g.total_difficulty() + Difficulty::from_num(1000);
        let info = diff_info(&h, g.total_difficulty());
        assert_eq!(info.difficulty.to_num(), 1000);
    }
}
