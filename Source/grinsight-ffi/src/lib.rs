//! C ABI of the GrinSight core (stage 2 of PLAN_VERIFIED_LIGHT_MODE_RU.md).
//!
//! The host (Grin++, a phone app, ...) does networking, peer choice, files
//! and clocks; this module does every check that decides what is true:
//! header chain (PoW, difficulty, linkage, header MMR), the UTXO state from
//! PIBD segments, blocks applied only if they reproduce the header roots.
//!
//! Conventions (see include/grinsight_state.h):
//! * return codes: 0 ok, 1 not found, <0 error; `us_last_error` gives the
//!   message of the last error on the calling thread;
//! * all byte formats are Grin's own serialization (ProtocolVersion local):
//!   headers, blocks, segments; checkpoints are the RWM1 text file;
//! * buffers returned by the module are freed with `us_free_buf`, handles
//!   with their `*_free`;
//! * the network (mainnet / testnet) is per thread: call `us_set_network`
//!   in every thread that uses the module;
//! * a panic never crosses the boundary: it becomes `US_ERR_PANIC`.

use grin_core::core::{self, BlockHeader, OutputIdentifier, Segment};
use grin_core::global::{self, ChainTypes};
use grin_core::ser::{self, ProtocolVersion};
use std::cell::RefCell;
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use grinsight_state::headers::{load_checkpoint_text, parse_state_headers, Verifier};
use grinsight_state::outputs::{bind_block, OutputState};
use grinsight_state::session::Session;
use std::ffi::CStr;

pub const US_OK: c_int = 0;
pub const US_NOT_FOUND: c_int = 1;
pub const US_ERR_ARG: c_int = -1;
pub const US_ERR_REJECT: c_int = -2;
pub const US_ERR_PANIC: c_int = -3;

thread_local! {
    static LAST_ERROR: RefCell<String> = const { RefCell::new(String::new()) };
}

fn fail(code: c_int, msg: impl Into<String>) -> c_int {
    LAST_ERROR.with(|e| *e.borrow_mut() = msg.into());
    code
}

/// Run `f`, turning a panic into US_ERR_PANIC.
fn guard(f: impl FnOnce() -> c_int) -> c_int {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(c) => c,
        Err(_) => fail(US_ERR_PANIC, "internal panic"),
    }
}

unsafe fn slice<'a>(p: *const u8, n: usize) -> Option<&'a [u8]> {
    if p.is_null() {
        return if n == 0 { Some(&[]) } else { None };
    }
    Some(std::slice::from_raw_parts(p, n))
}

fn give(v: Vec<u8>, out: *mut *mut u8, n: *mut usize) -> c_int {
    if out.is_null() || n.is_null() {
        return fail(US_ERR_ARG, "null output pointer");
    }
    let b = v.into_boxed_slice();
    unsafe {
        *n = b.len();
        *out = Box::into_raw(b) as *mut u8;
    }
    US_OK
}

fn de<T: ser::Readable>(b: &[u8], what: &str) -> Result<T, String> {
    let mut r = b;
    let v: T = ser::deserialize(&mut r, ProtocolVersion::local(), ser::DeserializationMode::default())
        .map_err(|e| format!("{what}: {e:?}"))?;
    if !r.is_empty() {
        return Err(format!("{what}: trailing bytes"));
    }
    Ok(v)
}

fn ser_out<T: ser::Writeable>(v: &T) -> Result<Vec<u8>, String> {
    ser::ser_vec(v, ProtocolVersion::local()).map_err(|e| format!("serialize: {e:?}"))
}

/// A byte buffer passed in by the host.
#[repr(C)]
pub struct UsBytes {
    pub ptr: *const u8,
    pub len: usize,
}

pub struct UsHeaders(Verifier);
pub struct UsSession(Session);
pub struct UsState(OutputState);

// ---------------------------------------------------------------------------
// General
// ---------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn us_version() -> *const c_char {
    concat!("grinsight-state ", env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// 1 = mainnet, 0 = testnet (floonet). Per calling thread.
#[no_mangle]
pub extern "C" fn us_set_network(mainnet: c_int) -> c_int {
    guard(|| {
        global::set_local_chain_type(if mainnet != 0 { ChainTypes::Mainnet } else { ChainTypes::Testnet });
        US_OK
    })
}

/// Copy the last error message of this thread (NUL-terminated, truncated
/// to `cap`); returns its full length.
#[no_mangle]
pub unsafe extern "C" fn us_last_error(buf: *mut c_char, cap: usize) -> usize {
    LAST_ERROR.with(|e| {
        let s = e.borrow();
        if !buf.is_null() && cap > 0 {
            let n = s.len().min(cap - 1);
            std::ptr::copy_nonoverlapping(s.as_ptr(), buf as *mut u8, n);
            *buf.add(n) = 0;
        }
        s.len()
    })
}

#[no_mangle]
pub unsafe extern "C" fn us_free_buf(p: *mut u8, n: usize) {
    if !p.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(p, n)));
    }
}

// ---------------------------------------------------------------------------
// Header chain
// ---------------------------------------------------------------------------

/// Start a header chain at a checkpoint (RWM1 text) with its difficulty
/// history (recent-headers.bin contents). The history may be empty only for
/// the genesis checkpoint: otherwise it must cover the difficulty window of
/// the next header (US_ERR_REJECT), because every appended header has its
/// network difficulty checked (strict mode, never "unchecked").
#[no_mangle]
pub unsafe extern "C" fn us_headers_open(rwm: *const u8, n: usize, history: *const u8, hn: usize, out: *mut *mut UsHeaders) -> c_int {
    guard(|| {
        let (Some(rwm), Some(hist)) = (slice(rwm, n), slice(history, hn)) else { return fail(US_ERR_ARG, "null input") };
        if out.is_null() {
            return fail(US_ERR_ARG, "null output");
        }
        let Ok(text) = std::str::from_utf8(rwm) else { return fail(US_ERR_ARG, "checkpoint is not text") };
        let mut v = match load_checkpoint_text(text, None) {
            Ok(v) => v,
            Err(e) => return fail(US_ERR_REJECT, e),
        };
        if !hist.is_empty() {
            let hs = match parse_state_headers(hist) {
                Ok(h) => h,
                Err(e) => return fail(US_ERR_REJECT, e),
            };
            if let Err(e) = v.restore_recent(hs) {
                return fail(US_ERR_REJECT, e);
            }
        }
        v.require_difficulty = true;
        if !v.can_check_difficulty(v.tip.height + 1) {
            return fail(
                US_ERR_REJECT,
                format!(
                    "difficulty history too short: {} headers, {} needed to check the next header (pass the checkpoint's recent headers)",
                    v.hist.len(),
                    grinsight_state::headers::history_needed(v.tip.height + 1)
                ),
            );
        }
        *out = Box::into_raw(Box::new(UsHeaders(v)));
        US_OK
    })
}

/// Validate and append the next header: PoW, network difficulty (always:
/// a header whose difficulty cannot be checked is rejected), linkage,
/// header MMR, timestamps, version. US_ERR_REJECT leaves the chain unchanged.
#[no_mangle]
pub unsafe extern "C" fn us_headers_append(h: *mut UsHeaders, header: *const u8, n: usize) -> c_int {
    guard(|| {
        let (Some(h), Some(b)) = (h.as_mut(), slice(header, n)) else { return fail(US_ERR_ARG, "null input") };
        let hdr: BlockHeader = match de(b, "header") {
            Ok(x) => x,
            Err(e) => return fail(US_ERR_REJECT, e),
        };
        let mut next = h.0.clone();
        match next.validate_and_append(&hdr) {
            Ok(()) => {
                h.0 = next;
                US_OK
            }
            Err(e) => fail(US_ERR_REJECT, e),
        }
    })
}

/// The tip header (Grin serialization); free with us_free_buf.
#[no_mangle]
pub unsafe extern "C" fn us_headers_tip(h: *const UsHeaders, out: *mut *mut u8, n: *mut usize) -> c_int {
    guard(|| {
        let Some(h) = h.as_ref() else { return fail(US_ERR_ARG, "null handle") };
        match ser_out(&h.0.tip) {
            Ok(v) => give(v, out, n),
            Err(e) => fail(US_ERR_ARG, e),
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn us_headers_height(h: *const UsHeaders) -> u64 {
    h.as_ref().map_or(0, |h| h.0.tip.height)
}

#[no_mangle]
pub unsafe extern "C" fn us_headers_free(h: *mut UsHeaders) {
    if !h.is_null() {
        drop(Box::from_raw(h));
    }
}

// ---------------------------------------------------------------------------
// UTXO state
// ---------------------------------------------------------------------------

/// Build the state of the archive header from its PIBD bitmap and output
/// segments; US_ERR_REJECT unless they reproduce the header output_root.
#[no_mangle]
pub unsafe extern "C" fn us_state_from_segments(
    archive_header: *const u8,
    n: usize,
    bitmap: *const UsBytes,
    nb: usize,
    output: *const UsBytes,
    no: usize,
    out: *mut *mut UsState,
) -> c_int {
    guard(|| {
        let Some(hb) = slice(archive_header, n) else { return fail(US_ERR_ARG, "null header") };
        if out.is_null() || (bitmap.is_null() && nb > 0) || (output.is_null() && no > 0) {
            return fail(US_ERR_ARG, "null input");
        }
        let header: BlockHeader = match de(hb, "archive header") {
            Ok(x) => x,
            Err(e) => return fail(US_ERR_REJECT, e),
        };
        let mut bms = Vec::with_capacity(nb);
        for i in 0..nb {
            let b = &*bitmap.add(i);
            let Some(s) = slice(b.ptr, b.len) else { return fail(US_ERR_ARG, "null segment") };
            // Wire format of bitmap segments (as a node sends them).
            match de::<grin_chain::txhashset::BitmapSegment>(s, "bitmap segment") {
                Ok(x) => match x.into_segment() {
                    Ok(seg) => bms.push(seg),
                    Err(e) => return fail(US_ERR_REJECT, format!("bitmap segment shape: {e:?}")),
                },
                Err(e) => return fail(US_ERR_REJECT, e),
            }
        }
        let mut outs = Vec::with_capacity(no);
        for i in 0..no {
            let b = &*output.add(i);
            let Some(s) = slice(b.ptr, b.len) else { return fail(US_ERR_ARG, "null segment") };
            match de::<Segment<OutputIdentifier>>(s, "output segment") {
                Ok(x) => outs.push(x),
                Err(e) => return fail(US_ERR_REJECT, e),
            }
        }
        match OutputState::from_segments(&header, &bms, &outs) {
            Ok(st) => {
                *out = Box::into_raw(Box::new(UsState(st)));
                US_OK
            }
            Err(e) => fail(US_ERR_REJECT, e),
        }
    })
}

/// Load a saved state (state.ust contents). The header it was saved under is
/// returned: the host must check it is on its validated chain before use.
#[no_mangle]
pub unsafe extern "C" fn us_state_load(file: *const u8, n: usize, out: *mut *mut UsState, header: *mut *mut u8, hn: *mut usize) -> c_int {
    guard(|| {
        let Some(b) = slice(file, n) else { return fail(US_ERR_ARG, "null input") };
        if out.is_null() {
            return fail(US_ERR_ARG, "null output");
        }
        match OutputState::from_bytes(b) {
            Ok((st, h)) => {
                let hv = match ser_out(&h) {
                    Ok(v) => v,
                    Err(e) => return fail(US_ERR_ARG, e),
                };
                let c = give(hv, header, hn);
                if c != US_OK {
                    return c;
                }
                *out = Box::into_raw(Box::new(UsState(st)));
                US_OK
            }
            Err(e) => fail(US_ERR_REJECT, e),
        }
    })
}

/// Serialize the state under `header` (must match it); free with us_free_buf.
#[no_mangle]
pub unsafe extern "C" fn us_state_save(st: *const UsState, header: *const u8, hn: usize, out: *mut *mut u8, n: *mut usize) -> c_int {
    guard(|| {
        let (Some(st), Some(hb)) = (st.as_ref(), slice(header, hn)) else { return fail(US_ERR_ARG, "null input") };
        let h: BlockHeader = match de(hb, "header") {
            Ok(x) => x,
            Err(e) => return fail(US_ERR_ARG, e),
        };
        match st.0.to_bytes(&h) {
            Ok(v) => give(v, out, n),
            Err(e) => fail(US_ERR_REJECT, e),
        }
    })
}

/// Apply the block of `header` (its body, Grin serialization). Only if the
/// result reproduces the header's output (and tracked kernel) root is the
/// state changed; otherwise US_ERR_REJECT and the state stays as it was.
/// Consensus validity of the body itself: `us_block_validate`.
#[no_mangle]
pub unsafe extern "C" fn us_state_apply_block(st: *mut UsState, header: *const u8, hn: usize, block: *const u8, bn: usize) -> c_int {
    guard(|| {
        let (Some(st), Some(hb), Some(bb)) = (st.as_mut(), slice(header, hn), slice(block, bn)) else {
            return fail(US_ERR_ARG, "null input");
        };
        let h: BlockHeader = match de(hb, "header") {
            Ok(x) => x,
            Err(e) => return fail(US_ERR_REJECT, e),
        };
        let b: core::Block = match de(bb, "block") {
            Ok(x) => x,
            Err(e) => return fail(US_ERR_REJECT, e),
        };
        match st.0.apply_block(&h, &b) {
            Ok(next) => {
                st.0 = next;
                US_OK
            }
            Err(e) => fail(US_ERR_REJECT, e),
        }
    })
}

/// Consensus check of a block body against its validated header: all header
/// bytes equal, `Block::validate` (rangeproofs, kernel signatures, sums).
#[no_mangle]
pub unsafe extern "C" fn us_block_validate(prev_header: *const u8, pn: usize, header: *const u8, hn: usize, block: *const u8, bn: usize) -> c_int {
    guard(|| {
        let (Some(pb), Some(hb), Some(bb)) = (slice(prev_header, pn), slice(header, hn), slice(block, bn)) else {
            return fail(US_ERR_ARG, "null input");
        };
        let prev: Option<BlockHeader> = if pb.is_empty() {
            None
        } else {
            match de(pb, "prev header") {
                Ok(x) => Some(x),
                Err(e) => return fail(US_ERR_REJECT, e),
            }
        };
        let (h, b): (BlockHeader, core::Block) = match (de(hb, "header"), de(bb, "block")) {
            (Ok(h), Ok(b)) => (h, b),
            (Err(e), _) | (_, Err(e)) => return fail(US_ERR_REJECT, e),
        };
        match bind_block(&h, prev.as_ref(), &b) {
            Ok(()) => US_OK,
            Err(e) => fail(US_ERR_REJECT, e),
        }
    })
}

/// Position (MMR index, 0-based) of an unspent output; US_NOT_FOUND if the
/// commitment is not in the UTXO set.
#[no_mangle]
pub unsafe extern "C" fn us_state_lookup(st: *const UsState, commit: *const u8, pos: *mut u64) -> c_int {
    guard(|| {
        let (Some(st), Some(c)) = (st.as_ref(), slice(commit, 33)) else { return fail(US_ERR_ARG, "null input") };
        match st.0.position(c) {
            Some(p) => {
                if !pos.is_null() {
                    *pos = p;
                }
                US_OK
            }
            None => US_NOT_FOUND,
        }
    })
}

#[no_mangle]
pub unsafe extern "C" fn us_state_utxo_count(st: *const UsState) -> u64 {
    st.as_ref().map_or(0, |s| s.0.utxo_count() as u64)
}

#[no_mangle]
pub unsafe extern "C" fn us_state_mmr_size(st: *const UsState) -> u64 {
    st.as_ref().map_or(0, |s| s.0.size)
}

#[no_mangle]
pub unsafe extern "C" fn us_state_output_root(st: *const UsState, out: *mut u8) -> c_int {
    guard(|| {
        let Some(st) = st.as_ref() else { return fail(US_ERR_ARG, "null handle") };
        if out.is_null() {
            return fail(US_ERR_ARG, "null output");
        }
        std::ptr::copy_nonoverlapping(st.0.output_root().as_bytes().as_ptr(), out, 32);
        US_OK
    })
}

#[no_mangle]
pub unsafe extern "C" fn us_state_free(st: *mut UsState) {
    if !st.is_null() {
        drop(Box::from_raw(st));
    }
}

// ---------------------------------------------------------------------------
// Session and wallet policy (was grinsight.py)
// ---------------------------------------------------------------------------

unsafe fn cstr<'a>(p: *const c_char, what: &str) -> Result<&'a str, String> {
    if p.is_null() {
        return Err(format!("{what}: null"));
    }
    CStr::from_ptr(p).to_str().map_err(|_| format!("{what}: not UTF-8"))
}

/// Open a verified session folder by the SHA-256 (hex) of its manifest. The
/// transcript is checked against the manifest (hash, contiguity, tip).
/// US_ERR_REJECT: wrong pin, damaged or inconsistent files.
#[no_mangle]
pub unsafe extern "C" fn us_session_open(folder: *const c_char, manifest_sha256: *const c_char, out: *mut *mut UsSession) -> c_int {
    guard(|| {
        if out.is_null() {
            return fail(US_ERR_ARG, "null output pointer");
        }
        *out = std::ptr::null_mut();
        let (f, pin) = match (cstr(folder, "folder"), cstr(manifest_sha256, "manifest_sha256")) {
            (Ok(f), Ok(p)) => (f, p),
            (Err(e), _) | (_, Err(e)) => return fail(US_ERR_ARG, e),
        };
        match Session::open(std::path::Path::new(f), pin) {
            Ok(s) => {
                *out = Box::into_raw(Box::new(UsSession(s)));
                US_OK
            }
            Err(e) => fail(US_ERR_REJECT, e),
        }
    })
}

/// JSON (UTF-8, not NUL-terminated): network, tip_height, sync_status,
/// freshness, tip_age_seconds, can_spend, default_archive_height.
/// `now_unix` comes from the host clock.
#[no_mangle]
pub unsafe extern "C" fn us_session_summary(s: *const UsSession, now_unix: i64, out: *mut *mut u8, n: *mut usize) -> c_int {
    guard(|| match s.as_ref() {
        Some(s) => give(s.0.summary_json(now_unix).into_bytes(), out, n),
        None => fail(US_ERR_ARG, "null session"),
    })
}

/// US_OK if money may move now (PASS session, tip fresh at `now_unix`);
/// US_ERR_REJECT with the reason otherwise. Check right before every send.
#[no_mangle]
pub unsafe extern "C" fn us_session_spend_gate(s: *const UsSession, now_unix: i64) -> c_int {
    guard(|| match s.as_ref() {
        Some(s) => match s.0.spend_gate(now_unix) {
            Ok(()) => US_OK,
            Err(e) => fail(US_ERR_REJECT, e),
        },
        None => fail(US_ERR_ARG, "null session"),
    })
}

#[no_mangle]
pub unsafe extern "C" fn us_session_tip_height(s: *const UsSession) -> u64 {
    s.as_ref().map_or(0, |s| s.0.tip_height())
}

/// Raw header at `height` from the validated transcript (US_NOT_FOUND outside it).
#[no_mangle]
pub unsafe extern "C" fn us_session_header_at(s: *const UsSession, height: u64, out: *mut *mut u8, n: *mut usize) -> c_int {
    guard(|| match s.as_ref() {
        Some(s) => match s.0.header_at(height) {
            Some(h) => give(h.to_vec(), out, n),
            None => fail(US_NOT_FOUND, format!("height {height} not in the session")),
        },
        None => fail(US_ERR_ARG, "null session"),
    })
}

#[no_mangle]
pub unsafe extern "C" fn us_session_free(s: *mut UsSession) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

/// Balance of wallet `wallet` (1-based) for the screen, from the contents of
/// the known-outputs file and the pending journal (either may be empty).
/// JSON: available / reserved / incoming / immature / total (nanogrin),
/// payments_in_flight, incoming items. Display only: the known file's MAC is
/// checked by the spend path. US_ERR_REJECT: a damaged file.
#[no_mangle]
pub unsafe extern "C" fn us_wallet_balance(
    known: *const u8,
    kn: usize,
    pending: *const u8,
    pn: usize,
    wallet: u32,
    out: *mut *mut u8,
    n: *mut usize,
) -> c_int {
    guard(|| {
        let (Some(k), Some(p)) = (slice(known, kn), slice(pending, pn)) else {
            return fail(US_ERR_ARG, "null input");
        };
        let (Ok(k), Ok(p)) = (std::str::from_utf8(k), std::str::from_utf8(p)) else {
            return fail(US_ERR_REJECT, "files are not UTF-8");
        };
        if wallet == 0 {
            return fail(US_ERR_ARG, "wallet is 1-based");
        }
        match grinsight_state::balance::balance(k, p, wallet as usize) {
            Ok(b) => give(b.to_json().into_bytes(), out, n),
            Err(e) => fail(US_ERR_REJECT, e),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use grin_core::consensus;
    use grin_core::core::hash::Hashed;
    use grin_core::pow::{self, Difficulty};
    use grinsight_state::headers::{write_state, Verifier};

    /// A real (mined) next header; `extra` makes it claim a network
    /// difficulty that is wrong by that much while its PoW still meets it.
    fn mine(v: &Verifier, extra: u64) -> BlockHeader {
        let mut h = v.tip.clone();
        h.height = v.tip.height + 1;
        h.prev_hash = v.tip.hash();
        h.prev_root = v.mmr.root();
        h.timestamp = v.tip.timestamp + chrono::Duration::seconds(60);
        // one more output and kernel: MMR size for (leaves + 1) leaves
        let size = |leaves: u64| grin_core::core::pmmr::insertion_to_pmmr_index(leaves);
        h.output_mmr_size = size(v.tip.output_mmr_count() + 1);
        h.kernel_mmr_size = size(v.tip.kernel_mmr_count() + 1);
        h.version = consensus::header_version(h.height);
        let next = consensus::next_difficulty(h.height, v.hist.iter().rev().cloned());
        let target = next.difficulty.to_num() + extra;
        h.pow.secondary_scaling = next.secondary_scaling;
        h.pow.total_difficulty = v.tip.total_difficulty() + Difficulty::from_num(target);
        pow::pow_size(&mut h, Difficulty::from_num(target), global::proofsize(), global::min_edge_bits()).unwrap();
        h
    }

    fn bytes(h: &BlockHeader) -> Vec<u8> {
        grin_core::ser::ser_vec(h, grin_core::ser::ProtocolVersion::local()).unwrap()
    }

    /// C API: never accepts a header whose network difficulty is unchecked.
    #[test]
    fn c_api_checks_network_difficulty() {
        global::set_local_chain_type(ChainTypes::AutomatedTesting);
        let mut v = Verifier::from_genesis();
        for _ in 0..(grinsight_state::headers::history_needed(1) + 2) {
            let h = mine(&v, 0);
            v.validate_and_append(&h).unwrap();
        }
        let dir = std::env::temp_dir().join(format!("us-ffi-diff-{}", std::process::id()));
        let d = dir.to_str().unwrap();
        write_state(&v, d);
        let rwm = std::fs::read(dir.join("checkpoint.rwm")).unwrap();
        let hist = std::fs::read(dir.join("recent-headers.bin")).unwrap();
        unsafe {
            // Not genesis and no history: refused at open.
            let mut hc: *mut UsHeaders = std::ptr::null_mut();
            assert_eq!(us_headers_open(rwm.as_ptr(), rwm.len(), [].as_ptr(), 0, &mut hc), US_ERR_REJECT);
            assert!(hc.is_null());
            // With the checkpoint's recent headers: opens.
            assert_eq!(us_headers_open(rwm.as_ptr(), rwm.len(), hist.as_ptr(), hist.len(), &mut hc), US_OK);
            let h0 = us_headers_height(hc);
            // Valid PoW, wrong network difficulty: rejected, chain unchanged.
            let bad = bytes(&mine(&v, 1));
            assert_eq!(us_headers_append(hc, bad.as_ptr(), bad.len()), US_ERR_REJECT);
            assert_eq!(us_headers_height(hc), h0);
            // The correct next header: accepted.
            let good = bytes(&mine(&v, 0));
            assert_eq!(us_headers_append(hc, good.as_ptr(), good.len()), US_OK);
            assert_eq!(us_headers_height(hc), h0 + 1);
            us_headers_free(hc);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Session and balance through the C ABI.
    #[test]
    fn c_api_session_and_balance() {
        use std::ffi::CString;
        use grinsight_state::session::{encode_transcript, sha256_hex};
        let dir = std::env::temp_dir().join(format!("us-ffi-session-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let now = 1_800_000_000i64;
        let hdr = |h: u64, ts: i64| {
            let mut v = 5u16.to_be_bytes().to_vec();
            v.extend(h.to_be_bytes());
            v.extend(ts.to_be_bytes());
            v.extend([0u8; 16]);
            v
        };
        let hs: Vec<Vec<u8>> = (100..=110u64).map(|h| hdr(h, now - (110 - h as i64) * 60)).collect();
        let raw = encode_transcript(hs.iter().map(Vec::as_slice));
        std::fs::write(dir.join("verified-headers.bin"), &raw).unwrap();
        let m = format!(
            "{{\"max_tip_age_sec\":10800,\"sync_status\":\"PASS\",\"tip_header_sha256\":\"{}\",\"tip_height\":110,\"transcript_sha256\":\"{}\",\"version\":1}}",
            sha256_hex(&hs[10]),
            sha256_hex(&raw)
        );
        std::fs::write(dir.join("verified-manifest.json"), &m).unwrap();
        let folder = CString::new(dir.to_str().unwrap()).unwrap();
        let pin = CString::new(sha256_hex(m.as_bytes())).unwrap();
        let bad = CString::new("00".repeat(32)).unwrap();
        unsafe {
            let mut s: *mut UsSession = std::ptr::null_mut();
            assert_eq!(us_session_open(folder.as_ptr(), bad.as_ptr(), &mut s), US_ERR_REJECT);
            assert!(s.is_null());
            assert_eq!(us_session_open(folder.as_ptr(), std::ptr::null(), &mut s), US_ERR_ARG);
            assert_eq!(us_session_open(folder.as_ptr(), pin.as_ptr(), &mut s), US_OK);
            assert_eq!(us_session_tip_height(s), 110);
            assert_eq!(us_session_spend_gate(s, now), US_OK);
            assert_eq!(us_session_spend_gate(s, now + 20_000), US_ERR_REJECT, "stale tip");
            let (mut p, mut n) = (std::ptr::null_mut(), 0usize);
            assert_eq!(us_session_summary(s, now, &mut p, &mut n), US_OK);
            let j = String::from_utf8(std::slice::from_raw_parts(p, n).to_vec()).unwrap();
            us_free_buf(p, n);
            assert!(j.contains("\"can_spend\":true") && j.contains("\"tip_height\":110"), "{j}");
            assert_eq!(us_session_header_at(s, 105, &mut p, &mut n), US_OK);
            assert_eq!(std::slice::from_raw_parts(p, n), hs[5].as_slice());
            us_free_buf(p, n);
            assert_eq!(us_session_header_at(s, 111, &mut p, &mut n), US_NOT_FOUND);
            us_session_free(s);

            let known = format!("{{\"meta\":\"grinsight-wallet\",\"tip_height\":110,\"tip_hash\":\"ab\"}}\n{{\"wallet\":1,\"commit\":\"09{}\",\"amount\":5,\"key_id\":\"03\",\"features\":\"Plain\",\"created\":100,\"unspent_at_tip\":true,\"spent_height\":null,\"tip_height\":110}}\n", "11".repeat(32));
            assert_eq!(us_wallet_balance(known.as_ptr(), known.len(), std::ptr::null(), 0, 1, &mut p, &mut n), US_OK);
            let j = String::from_utf8(std::slice::from_raw_parts(p, n).to_vec()).unwrap();
            us_free_buf(p, n);
            assert!(j.contains("\"available_nanogrin\":5"), "{j}");
            let torn = "{\"kind\":";
            assert_eq!(us_wallet_balance(known.as_ptr(), known.len(), torn.as_ptr(), torn.len(), 1, &mut p, &mut n), US_ERR_REJECT);
            assert_eq!(us_wallet_balance(known.as_ptr(), known.len(), std::ptr::null(), 0, 0, &mut p, &mut n), US_ERR_ARG);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
