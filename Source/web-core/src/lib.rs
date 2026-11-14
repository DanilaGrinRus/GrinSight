//! Spike: expose a tiny, testable part of GrinSight's local core over a raw
//! C ABI, so a browser (or Node) can prove that the Wasm build is the same
//! code as the native one. This is not the final wallet API.
//!
//! Build:
//!   emsdk_env
//!   cargo build --release --target wasm32-unknown-emscripten
//! The resulting `.wasm`/`.js` are consumed by `web/test-wasm.mjs`.

use grin_core::core::{BlockHeader, OutputIdentifier, Segment};
use grin_core::core::hash::Hashed;
use grin_core::global::{self, ChainTypes};
use grin_core::ser::{self, DeserializationMode, ProtocolVersion};
use grin_core::genesis;
use grin_keychain::{mnemonic, ExtKeychain, Keychain, SwitchCommitmentType};
use grin_util::secp::pedersen::RangeProof;
use grinsight_state::headers::{header_digest, load_checkpoint_storage, parse_state_headers};
use grinsight_state::storage::{MemoryStorage, Storage};
use grinsight_state::bitmap::BitmapSegment;
use grinsight_state::outputs::OutputState;
#[cfg(target_os = "emscripten")]
use crate::browser_storage::BrowserStorage;
use grinsight_state::receive::{build_send, parent_key_id, slatepack_address, InputSel};
use grinsight_state::wallet::Wallets;
use std::slice;
use std::sync::Mutex;

#[cfg(target_os = "emscripten")]
mod browser_storage;

const SEED: [u8; 32] = [7u8; 32];
static INIT: std::sync::Once = std::sync::Once::new();
static MAINNET: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static CHAIN: Mutex<Option<grinsight_state::headers::Verifier>> = Mutex::new(None);
static WALLET: Mutex<Option<ExtKeychain>> = Mutex::new(None);
static CHAIN_HEADERS: Mutex<Vec<BlockHeader>> = Mutex::new(Vec::new());

fn init() {
    INIT.call_once(|| {
        let t = if MAINNET.load(std::sync::atomic::Ordering::Relaxed) { ChainTypes::Mainnet } else { ChainTypes::Testnet };
        global::set_global_chain_type(t);
    });
}

fn cp_text() -> &'static str {
    if MAINNET.load(std::sync::atomic::Ordering::Relaxed) {
        include_str!("../../release/checkpoint.rwm")
    } else {
        include_str!("../../checkpoints/floonet/checkpoint.rwm")
    }
}

fn recent_bytes() -> &'static [u8] {
    if MAINNET.load(std::sync::atomic::Ordering::Relaxed) {
        include_bytes!("../../release/recent-headers.bin")
    } else {
        include_bytes!("../../checkpoints/floonet/recent-headers.bin")
    }
}

/// Select mainnet (1) or Floonet (0) for the next calls.
#[no_mangle]
pub extern "C" fn gs_set_network(mainnet: i32) -> i32 {
    MAINNET.store(mainnet != 0, std::sync::atomic::Ordering::Relaxed);
    global::set_global_chain_type(if mainnet != 0 { ChainTypes::Mainnet } else { ChainTypes::Testnet });
    0
}

fn copy_out(data: &[u8], out: *mut u8, cap: usize) -> i32 {
    if out.is_null() || data.len() > cap {
        return -1;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len());
    }
    data.len() as i32
}

/// Blake2b hash of the test genesis header, 32 bytes.
#[no_mangle]
pub extern "C" fn gs_header_hash(out: *mut u8, cap: usize) -> i32 {
    init();
    let h = genesis::genesis_test().header;
    let digest = header_digest(&h);
    copy_out(digest.as_bytes(), out, cap)
}

/// Slatepack address derived from a fixed test seed (Floonet).
/// This exercises the real keychain and secp256k1-zkp path in Wasm.
#[no_mangle]
pub extern "C" fn gs_test_address(out: *mut u8, cap: usize) -> i32 {
    init();
    let keychain = match ExtKeychain::from_seed(&SEED, true) {
        Ok(k) => k,
        Err(_) => return -2,
    };
    match slatepack_address(&keychain) {
        Ok(addr) => copy_out(addr.as_bytes(), out, cap),
        Err(_) => return -3,
    }
}

/// Build a real S1 from a fixed test seed. Returns the armored S1 length.
#[no_mangle]
pub extern "C" fn gs_test_s1(out: *mut u8, cap: usize) -> i32 {
    init();
    let k1 = match ExtKeychain::from_seed(&SEED, true) { Ok(k) => k, Err(_) => return -2 };
    let k2 = match ExtKeychain::from_seed(&[8u8; 32], true) { Ok(k) => k, Err(_) => return -2 };
    let parent = parent_key_id();
    let input_amount = 300_000_000u64;
    let send_amount = 100_000_000u64;
    let commit = match k1.commit(input_amount, &parent, SwitchCommitmentType::Regular) { Ok(c) => c, Err(_) => return -4 };
    let input = InputSel::new(&parent, input_amount, false, &commit);
    let dest = match slatepack_address(&k2) { Ok(a) => a, Err(_) => return -3 };
    let wallets = Wallets::from_keychains(vec![k1]);
    match build_send(&wallets, 0, &[input], &[], send_amount, &dest) {
        Ok(built) => copy_out(built.s1.as_bytes(), out, cap),
        Err(_) => -5,
    }
}


/// Load a wallet keychain from a BIP39 phrase. The phrase is validated here;
/// it is never stored by this ABI. Returns 0 or a negative error.
#[no_mangle]
pub extern "C" fn gs_wallet_set_phrase(ptr: *const u8, len: usize) -> i32 {
    init();
    if ptr.is_null() || len == 0 || len > 4096 {
        return -1;
    }
    let raw = unsafe { slice::from_raw_parts(ptr, len) };
    let phrase = match std::str::from_utf8(raw) {
        Ok(s) => s.trim(),
        Err(_) => return -2,
    };
    let entropy = match mnemonic::to_entropy(phrase) {
        Ok(e) => e,
        Err(_) => return -3,
    };
    let is_test = !MAINNET.load(std::sync::atomic::Ordering::Relaxed);
    let keychain = match ExtKeychain::from_seed(&entropy, is_test) {
        Ok(k) => k,
        Err(_) => return -4,
    };
    *WALLET.lock().unwrap() = Some(keychain);
    0
}

#[no_mangle]
pub extern "C" fn gs_wallet_clear() -> i32 {
    *WALLET.lock().unwrap() = None;
    0
}

/// Slatepack address of the loaded wallet (no keys cross the ABI).
#[no_mangle]
pub extern "C" fn gs_wallet_address(out: *mut u8, cap: usize) -> i32 {
    let guard = WALLET.lock().unwrap();
    let Some(keychain) = guard.as_ref() else { return -1; };
    match slatepack_address(keychain) {
        Ok(addr) => copy_out(addr.as_bytes(), out, cap),
        Err(_) => -2,
    }
}

/// Generate a fresh BIP39 phrase using the platform CSPRNG.
/// 12/15/18/21/24 words. Returns phrase length or a negative error.
#[no_mangle]
pub extern "C" fn gs_wallet_new_phrase(words: i32, out: *mut u8, cap: usize) -> i32 {
    init();
    let entropy_len = match words {
        12 => 16,
        15 => 20,
        18 => 24,
        21 => 28,
        24 => 32,
        _ => return -1,
    };
    let mut entropy = [0u8; 32];
    #[cfg(target_os = "emscripten")]
    {
        if getrandom03::fill(&mut entropy[..entropy_len]).is_err() {
            return -2;
        }
    }
    #[cfg(not(target_os = "emscripten"))]
    {
        return -2;
    }
    let phrase = match mnemonic::from_entropy(&entropy[..entropy_len]) {
        Ok(p) => p,
        Err(_) => return -3,
    };
    copy_out(phrase.as_bytes(), out, cap)
}

/// Verify the shipped Floonet checkpoint without touching the file system.
/// Returns the tip height, or a negative error code.
#[no_mangle]
pub extern "C" fn gs_checkpoint_height() -> i64 {
    init();
    let checkpoint = cp_text();
    let mut storage = MemoryStorage::new();
    if storage.put("checkpoints/floonet/checkpoint.rwm", checkpoint.as_bytes()).is_err() {
        return -2;
    }
    match load_checkpoint_storage(&storage, "checkpoints/floonet/checkpoint.rwm", None) {
        Ok(v) => v.tip.height as i64,
        Err(_) => -1,
    }
}

/// Load the checkpoint, then restore and validate the shipped recent-header
/// history from `release/recent-headers.bin` (no filesystem).
/// Returns the number of restored headers, or a negative error code.
#[no_mangle]
pub extern "C" fn gs_restore_recent() -> i64 {
    init();
    let checkpoint = cp_text();
    let recent_raw = recent_bytes();
    let mut storage = MemoryStorage::new();
    if storage.put("checkpoints/floonet/checkpoint.rwm", checkpoint.as_bytes()).is_err() {
        return -2;
    }
    let mut v = match load_checkpoint_storage(&storage, "checkpoints/floonet/checkpoint.rwm", None) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let headers = match parse_state_headers(recent_raw) {
        Ok(h) => h,
        Err(_) => return -3,
    };
    match v.restore_recent(headers) {
        Ok(()) => v.recent.len() as i64,
        Err(_) => -4,
    }
}

/// Host-storage roundtrip: localStorage put/get/remove for a small value.
#[cfg(target_os = "emscripten")]
#[no_mangle]
pub extern "C" fn gs_storage_selftest(out: *mut u8, cap: usize) -> i32 {
    let mut s = BrowserStorage;
    if s.put("grinsight/selftest", b"storage-ok").is_err() {
        return -2;
    }
    let got = match s.get("grinsight/selftest") {
        Ok(Some(v)) => v,
        _ => return -3,
    };
    if s.remove("grinsight/selftest").is_err() {
        return -4;
    }
    copy_out(&got, out, cap)
}

/// Verify a `recent-headers.bin`-shaped packet of live headers against the
/// Floonet checkpoint plus its shipped recent history. Returns the new tip
/// height, or a negative error code. The packet is untrusted.
#[no_mangle]
pub extern "C" fn gs_verify_headers(ptr: *const u8, len: usize) -> i64 {
    init();
    if ptr.is_null() || len == 0 || len > 8 * 1024 * 1024 {
        return -1;
    }
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    let headers = match parse_state_headers(bytes) {
        Ok(h) => h,
        Err(_) => return -2,
    };
    let checkpoint = cp_text();
    let recent_raw = recent_bytes();
    let mut storage = MemoryStorage::new();
    if storage.put("checkpoints/floonet/checkpoint.rwm", checkpoint.as_bytes()).is_err() {
        return -3;
    }
    let mut v = match load_checkpoint_storage(&storage, "checkpoints/floonet/checkpoint.rwm", None) {
        Ok(v) => v,
        Err(_) => return -4,
    };
    let recent = match parse_state_headers(recent_raw) {
        Ok(h) => h,
        Err(_) => return -5,
    };
    if v.restore_recent(recent).is_err() {
        return -6;
    }
    for h in &headers {
        if v.validate_and_append(h).is_err() {
            return -7;
        }
    }
    v.tip.height as i64
}

fn parse_any_headers(bytes: &[u8]) -> Result<Vec<BlockHeader>, String> {
    if bytes.len() < 4 {
        return Err("packet too short".into());
    }
    let n = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if n == 0 || n > 1_000_000 {
        return Err("bad header count".into());
    }
    let mut off = 4usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let end = off.checked_add(4).filter(|&e| e <= bytes.len()).ok_or("truncated")?;
        let len = u32::from_le_bytes(bytes[off..end].try_into().unwrap()) as usize;
        off = end;
        if len == 0 || len > 4096 {
            return Err("bad header length".into());
        }
        let end = off.checked_add(len).filter(|&e| e <= bytes.len()).ok_or("truncated")?;
        let h: BlockHeader = ser::deserialize(&mut &bytes[off..end], ProtocolVersion::local(), DeserializationMode::default())
            .map_err(|e| format!("header deserialize: {e:?}"))?;
        out.push(h);
        off = end;
    }
    if off != bytes.len() { return Err("trailing packet bytes".into()); }
    Ok(out)
}

/// Start a stateful live-chain verifier at the Floonet checkpoint.
#[no_mangle]
pub extern "C" fn gs_chain_start() -> i64 {
    init();
    let checkpoint = cp_text();
    let recent_raw = recent_bytes();
    let mut storage = MemoryStorage::new();
    if storage.put("checkpoints/floonet/checkpoint.rwm", checkpoint.as_bytes()).is_err() { return -1; }
    let mut v = match load_checkpoint_storage(&storage, "checkpoints/floonet/checkpoint.rwm", None) { Ok(v) => v, Err(_) => return -2 };
    let recent = match parse_state_headers(recent_raw) { Ok(h) => h, Err(_) => return -3 };
    if v.restore_recent(recent).is_err() { return -4; }
    let h = v.tip.height as i64;
    CHAIN_HEADERS.lock().unwrap().clear();
    CHAIN_HEADERS.lock().unwrap().push(v.tip.clone());
    *CHAIN.lock().unwrap() = Some(v);
    h
}

/// Append a batch of raw headers to the stateful verifier.
#[no_mangle]
pub extern "C" fn gs_chain_append(ptr: *const u8, len: usize) -> i64 {
    init();
    if ptr.is_null() || len == 0 || len > 16 * 1024 * 1024 { return -1; }
    let bytes = unsafe { slice::from_raw_parts(ptr, len) };
    let headers = match parse_any_headers(bytes) { Ok(h) => h, Err(_) => return -2 };
    let mut guard = CHAIN.lock().unwrap();
    let Some(v) = guard.as_mut() else { return -3 };
    for h in &headers {
        if v.validate_and_append(h).is_err() { return -4; }
    }
    CHAIN_HEADERS.lock().unwrap().extend(headers.into_iter());
    v.tip.height as i64
}

/// Current stateful verifier tip, or -1 if not started.
#[no_mangle]
pub extern "C" fn gs_chain_tip() -> i64 {
    CHAIN.lock().unwrap().as_ref().map(|v| v.tip.height as i64).unwrap_or(-1)
}

/// Synthetic PIBD fixture: archive header + bitmap segment + output segments.
/// Rebuilds the UTXO state and checks the merged output root. Returns UTXO count.
#[no_mangle]
pub extern "C" fn gs_utxo_fixture() -> i64 {
    init();
    const FIX: &[u8] = include_bytes!("../test/pibd_fixture.bin");
    if FIX.len() < 8 || &FIX[..4] != b"GPF1" { return -1; }
    let mut off = 4usize;
    fn take<'a>(b: &'a [u8], off: &mut usize) -> Result<&'a [u8], ()> {
        if *off + 4 > b.len() { return Err(()); }
        let n = u32::from_le_bytes(b[*off..*off + 4].try_into().unwrap()) as usize;
        *off += 4;
        if *off + n > b.len() { return Err(()); }
        let out = &b[*off..*off + n];
        *off += n;
        Ok(out)
    }
    let header: BlockHeader = match take(FIX, &mut off)
        .and_then(|x| ser::deserialize_default(&mut &x[..]).map_err(|_| ())) {
        Ok(h) => h, Err(_) => return -2,
    };
    let nbm = match FIX.get(off..off + 4) { Some(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize, None => return -3 };
    off += 4;
    let mut bitmaps = Vec::new();
    for _ in 0..nbm {
        let raw = match take(FIX, &mut off) { Ok(x) => x, Err(_) => return -4 };
        let wire: BitmapSegment = match ser::deserialize_default(&mut &raw[..]) { Ok(x) => x, Err(_) => return -5 };
        bitmaps.push(match wire.into_segment() { Ok(x) => x, Err(_) => return -6 });
    }
    let nout = match FIX.get(off..off + 4) { Some(b) => u32::from_le_bytes(b.try_into().unwrap()) as usize, None => return -7 };
    off += 4;
    let mut outputs = Vec::new();
    for _ in 0..nout {
        let raw = match take(FIX, &mut off) { Ok(x) => x, Err(_) => return -8 };
        let seg: Segment<OutputIdentifier> = match ser::deserialize_default(&mut &raw[..]) { Ok(x) => x, Err(_) => return -9 };
        outputs.push(seg);
    }
    if off != FIX.len() { return -10; }
    match OutputState::from_segments(&header, &bitmaps, &outputs) {
        Ok(st) => st.utxo_count() as i64,
        Err(_) => -11,
    }
}

/// Rebuild UTXO state from a full GPF1 PIBD container.
/// Format: GPF1, header, bitmap_count + bitmap segments, output_count +
/// output segments, rproof_count + rproof segments, kernel_count + kernels.
/// The header must have been verified by the caller; output_root is checked here.
#[no_mangle]
pub extern "C" fn gs_utxo_bundle(ptr: *const u8, len: usize) -> i64 {
    init();
    if ptr.is_null() || len < 8 || len > 1024 * 1024 * 1024 {
        return -1;
    }
    let b = unsafe { slice::from_raw_parts(ptr, len) };
    if &b[..4] != b"GPF1" {
        return -2;
    }
    let mut off = 4usize;
    fn take<'a>(b: &'a [u8], off: &mut usize) -> Result<&'a [u8], ()> {
        if *off + 4 > b.len() { return Err(()); }
        let n = u32::from_le_bytes(b[*off..*off + 4].try_into().unwrap()) as usize;
        *off += 4;
        if n > b.len().saturating_sub(*off) { return Err(()); }
        let out = &b[*off..*off + n];
        *off += n;
        Ok(out)
    }
    let header: BlockHeader = match take(b, &mut off)
        .and_then(|x| ser::deserialize_default(&mut &x[..]).map_err(|_| ())) {
        Ok(h) => h,
        Err(_) => return -3,
    };
    let nbm = match b.get(off..off + 4) { Some(x) => u32::from_le_bytes(x.try_into().unwrap()) as usize, None => return -4 };
    off += 4;
    let mut bitmaps = Vec::with_capacity(nbm.min(1024));
    for _ in 0..nbm {
        let raw = match take(b, &mut off) { Ok(x) => x, Err(_) => return -5 };
        let wire: BitmapSegment = match ser::deserialize_default(&mut &raw[..]) { Ok(x) => x, Err(_) => return -6 };
        match wire.into_segment() { Ok(x) => bitmaps.push(x), Err(_) => return -7 }
    }
    let nout = match b.get(off..off + 4) { Some(x) => u32::from_le_bytes(x.try_into().unwrap()) as usize, None => return -8 };
    off += 4;
    let mut outputs = Vec::with_capacity(nout.min(16384));
    for _ in 0..nout {
        let raw = match take(b, &mut off) { Ok(x) => x, Err(_) => return -9 };
        let seg: Result<Segment<OutputIdentifier>, _> = ser::deserialize_default(&mut &raw[..]);
        match seg {
            Ok(x) => outputs.push(x),
            Err(_) => return -10,
        }
    }
    let nrp = match b.get(off..off + 4) { Some(x) => u32::from_le_bytes(x.try_into().unwrap()) as usize, None => return -11 };
    off += 4;
    for _ in 0..nrp { if take(b, &mut off).is_err() { return -12; } }
    let nk = match b.get(off..off + 4) { Some(x) => u32::from_le_bytes(x.try_into().unwrap()) as usize, None => return -13 };
    off += 4;
    for _ in 0..nk { if take(b, &mut off).is_err() { return -14; } }
    if off != b.len() { return -15; }
    match OutputState::from_segments(&header, &bitmaps, &outputs) {
        Ok(st) => st.utxo_count() as i64,
        Err(_) => -16,
    }
}


/// Scan a GPF1 bundle (bitmap+output+rproof) against the loaded wallet.
/// Streams rproof segments; never keeps all proofs in memory.
/// Returns total discovered amount (nanogrin) and writes the output count.
#[no_mangle]
pub extern "C" fn gs_wallet_scan_bundle(ptr: *const u8, len: usize, out_count: *mut u64) -> i64 {
    init();
    if ptr.is_null() || len < 8 || len > 1024 * 1024 * 1024 || out_count.is_null() {
        return -1;
    }
    let b = unsafe { slice::from_raw_parts(ptr, len) };
    if &b[..4] != b"GPF1" { return -2; }
    let mut off = 4usize;
    fn take<'a>(b: &'a [u8], off: &mut usize) -> Result<&'a [u8], ()> {
        if *off + 4 > b.len() { return Err(()); }
        let n = u32::from_le_bytes(b[*off..*off + 4].try_into().unwrap()) as usize;
        *off += 4;
        if n > b.len().saturating_sub(*off) { return Err(()); }
        let out = &b[*off..*off + n];
        *off += n;
        Ok(out)
    }
    let header: BlockHeader = match take(b, &mut off)
        .and_then(|x| ser::deserialize_default(&mut &x[..]).map_err(|_| ())) {
        Ok(h) => h, Err(_) => return -3,
    };
    let nbm = match b.get(off..off + 4) { Some(x) => u32::from_le_bytes(x.try_into().unwrap()) as usize, None => return -4 };
    off += 4;
    let mut bitmaps = Vec::with_capacity(nbm.min(1024));
    for _ in 0..nbm {
        let raw = match take(b, &mut off) { Ok(x) => x, Err(_) => return -5 };
        let wire: BitmapSegment = match ser::deserialize_default(&mut &raw[..]) { Ok(x) => x, Err(_) => return -6 };
        match wire.into_segment() { Ok(x) => bitmaps.push(x), Err(_) => return -7 }
    }
    let nout = match b.get(off..off + 4) { Some(x) => u32::from_le_bytes(x.try_into().unwrap()) as usize, None => return -8 };
    off += 4;
    let mut outputs = Vec::with_capacity(nout.min(16384));
    for _ in 0..nout {
        let raw = match take(b, &mut off) { Ok(x) => x, Err(_) => return -9 };
        let seg: Result<Segment<OutputIdentifier>, _> = ser::deserialize_default(&mut &raw[..]);
        match seg { Ok(x) => outputs.push(x), Err(_) => return -10 }
    }
    let nrp = match b.get(off..off + 4) { Some(x) => u32::from_le_bytes(x.try_into().unwrap()) as usize, None => return -11 };
    off += 4;
    let state = match OutputState::from_segments(&header, &bitmaps, &outputs) {
        Ok(s) => s,
        Err(_) => return -17,
    };
    let keychain = match WALLET.lock().unwrap().clone() { Some(k) => k, None => return -18 };
    let wallets = Wallets::from_keychains(vec![keychain]);
    let mut by_pos = std::collections::HashMap::with_capacity(state.utxo.len());
    for (_, (pos, id)) in &state.utxo { by_pos.insert(*pos, *id); }
    let mut total: i64 = 0;
    let mut found_count: u64 = 0;
    for _ in 0..nrp {
        let raw = match take(b, &mut off) { Ok(x) => x, Err(_) => return -12 };
        let seg: Result<Segment<RangeProof>, _> = ser::deserialize_default(&mut &raw[..]);
        let seg = match seg { Ok(s) => s, Err(_) => return -13 };
        let mut items: Vec<(u64, OutputIdentifier, RangeProof)> = Vec::new();
        for (pos, rp) in seg.leaf_iter() {
            if let Some(id) = by_pos.get(&pos) { items.push((pos, *id, *rp)); }
        }
        if items.is_empty() { continue; }
        let found = match wallets.discover_single(&items) { Ok(f) => f, Err(_) => return -20 };
        for f in &found {
            total = match total.checked_add(f.amount as i64) { Some(x) => x, None => return -21 };
        }
        found_count += found.len() as u64;
    }
    let nk = match b.get(off..off + 4) { Some(x) => u32::from_le_bytes(x.try_into().unwrap()) as usize, None => return -14 };
    off += 4;
    for _ in 0..nk { if take(b, &mut off).is_err() { return -15; } }
    if off != b.len() { return -16; }
    unsafe { *out_count = found_count };
    total
}
/// Return the verified header at `height` as raw bytes.
#[no_mangle]
pub extern "C" fn gs_chain_header(height: u64, out: *mut u8, cap: usize) -> i32 {
    let hs = CHAIN_HEADERS.lock().unwrap();
    let Some(h) = hs.iter().find(|h| h.height == height) else { return -1 };
    let raw = match ser::ser_vec(h, ProtocolVersion::local()) { Ok(b) => b, Err(_) => return -2 };
    copy_out(&raw, out, cap)
}

/// Return the hash of the verified header at `height` (32 bytes).
#[no_mangle]
pub extern "C" fn gs_chain_header_hash(height: u64, out: *mut u8, cap: usize) -> i32 {
    let hs = CHAIN_HEADERS.lock().unwrap();
    let Some(h) = hs.iter().find(|h| h.height == height) else { return -1 };
    match copy_out(h.hash().as_bytes(), out, cap) { n if n > 0 => n, _ => -2 }
}

/// Copy bytes from a pointer; used by JS tests only.
#[no_mangle]
pub extern "C" fn gs_copy(src: *const u8, len: usize, out: *mut u8, cap: usize) -> i32 {
    if src.is_null() || out.is_null() || len > cap {
        return -1;
    }
    let s = unsafe { slice::from_raw_parts(src, len) };
    copy_out(s, out, cap)
}

/// ABI marker for the web client.
#[no_mangle]
pub extern "C" fn gs_abi_version() -> i32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use grin_keychain::SwitchCommitmentType;
    use grinsight_state::receive::{build_send, parent_key_id, InputSel};
    use grinsight_state::wallet::Wallets;

    #[test]
    fn native_address_is_stable() {
        init();
        let k = ExtKeychain::from_seed(&SEED, true).unwrap();
        let addr = slatepack_address(&k).unwrap();
        assert_eq!(addr.len(), 64);
        let h = header_digest(&genesis::genesis_test().header);
        println!("HEADER_HASH={}", h.as_bytes().iter().map(|b| format!("{b:02x}")).collect::<String>());
        println!("ADDRESS={addr}");
        let p = parent_key_id();
        let c = k.commit(300_000_000, &p, grin_keychain::SwitchCommitmentType::Regular).unwrap();
        let inp = InputSel::new(&p, 300_000_000, false, &c);
        let k2 = ExtKeychain::from_seed(&[8u8; 32], true).unwrap();
        let dest = slatepack_address(&k2).unwrap();
        let w = Wallets::from_keychains(vec![k]);
        let s1 = build_send(&w, 0, &[inp], &[], 100_000_000, &dest).unwrap();
        println!("S1_LEN={}", s1.s1.len());
        println!("S1_PREFIX={}", &s1.s1[..s1.s1.len().min(20)]);
        println!("CHECKPOINT_HEIGHT={}", gs_checkpoint_height());
        println!("RECENT_HEADERS={}", gs_restore_recent());
        println!("UTXO_FIXTURE={}", gs_utxo_fixture());
    }
}








