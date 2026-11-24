//! On-disk layout: file header, frames, snapshot files. All parsing is
//! bounds-checked and never panics.
use crate::crypto::{ct_eq, sha256, Keys, NONCE_LEN, TAG_LEN};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"FLYJRNL1";
const SNAP_MAGIC: &[u8; 8] = b"FLYSNAP1";
const VERSION: u16 = 1;

/// Size of the journal file header.
pub(crate) const HEADER_LEN: usize = 176;
const HEADER_SIGNED_LEN: usize = 144;
/// Frame bytes after the length field that are not ciphertext: seq, prev, kind, nonce.
const FRAME_FIXED: usize = 8 + 32 + 1 + NONCE_LEN;
const ROTATE_BODY_LEN: usize = 8 + 32 + 32;
pub(crate) const ROTATE_FRAME_LEN: usize = 4 + FRAME_FIXED + TAG_LEN + ROTATE_BODY_LEN;
/// Largest frame body accepted, checked before any allocation.
pub const MAX_BODY_LEN: usize = 16 * 1024 * 1024;
/// Largest journal or snapshot file read into memory.
#[cfg(not(test))]
pub(crate) const MAX_FILE_LEN: u64 = 512 * 1024 * 1024;
// Exercise the actual writer and reader at their boundary in unit tests.
#[cfg(test)]
pub(crate) const MAX_FILE_LEN: u64 = 2048;
/// Highest frame kind callers may use; higher values belong to the store.
pub const MAX_USER_KIND: u8 = 0xEF;
/// Frame the caller must commit after the guard check reported a rollback or
/// a moved journal (new key branch, locked operations) before anything else.
pub const KIND_RECOVERY: u8 = 0xFE;
/// Written by the store when a checkpoint switches to a new generation.
pub(crate) const KIND_ROTATE: u8 = 0xFF;

/// What a journal is bound to. A mismatch at open is an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Network tag chosen by the caller (for example 1 mainnet, 2 testnet).
    pub network: u8,
    /// Hash of the genesis block.
    pub genesis: [u8; 32],
    /// Random identifier of this wallet instance.
    pub instance: [u8; 16],
}

/// Bounds-checked cursor.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(u8::from_le_bytes)
    }
    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }
    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }
    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }
    pub(crate) fn rest(&mut self) -> &'a [u8] {
        let s = self.buf.get(self.pos..).unwrap_or(&[]);
        self.pos = self.buf.len();
        s
    }
}

/// Parsed and authenticated file header.
#[derive(Clone, Debug)]
pub(crate) struct Header {
    pub(crate) generation: u64,
    /// Sequence number of the first frame in this file.
    pub(crate) base_seq: u64,
    /// Hash of the last frame of the previous generation before its rotate
    /// frame; all zero for generation 0.
    pub(crate) prev_tail: [u8; 32],
    /// Hash of the snapshot file this generation starts from; all zero for
    /// generation 0.
    pub(crate) snapshot: [u8; 32],
    /// Hash of the encoded header: the `prev` of this file's first frame.
    pub(crate) hash: [u8; 32],
}

pub(crate) enum HeaderError {
    Malformed,
    WrongIdentity,
    Crypto,
}

pub(crate) fn encode_header(
    keys: &Keys,
    id: &Identity,
    generation: u64,
    base_seq: u64,
    prev_tail: &[u8; 32],
    snapshot: &[u8; 32],
) -> Result<(Vec<u8>, Header), HeaderError> {
    let mut b = Vec::with_capacity(HEADER_LEN);
    b.extend_from_slice(MAGIC);
    b.extend_from_slice(&VERSION.to_le_bytes());
    b.push(id.network);
    b.push(0);
    b.extend_from_slice(&id.genesis);
    b.extend_from_slice(&id.instance);
    b.extend_from_slice(&[0u8; 4]);
    b.extend_from_slice(&generation.to_le_bytes());
    b.extend_from_slice(&base_seq.to_le_bytes());
    b.extend_from_slice(prev_tail);
    b.extend_from_slice(snapshot);
    debug_assert_eq!(b.len(), HEADER_SIGNED_LEN);
    let mac = keys.header_mac(&b).map_err(|_| HeaderError::Crypto)?;
    b.extend_from_slice(&mac);
    let hash = sha256(&[&b]);
    Ok((
        b,
        Header {
            generation,
            base_seq,
            prev_tail: *prev_tail,
            snapshot: *snapshot,
            hash,
        },
    ))
}

pub(crate) fn decode_header(
    keys: &Keys,
    id: &Identity,
    file: &[u8],
) -> Result<Header, HeaderError> {
    let raw = file.get(..HEADER_LEN).ok_or(HeaderError::Malformed)?;
    let signed = raw.get(..HEADER_SIGNED_LEN).ok_or(HeaderError::Malformed)?;
    let mut r = Reader::new(raw);
    let magic: [u8; 8] = r.array().ok_or(HeaderError::Malformed)?;
    let version = r.u16().ok_or(HeaderError::Malformed)?;
    if &magic != MAGIC || version != VERSION {
        return Err(HeaderError::Malformed);
    }
    let network = r.u8().ok_or(HeaderError::Malformed)?;
    let flags = r.u8().ok_or(HeaderError::Malformed)?;
    let genesis: [u8; 32] = r.array().ok_or(HeaderError::Malformed)?;
    let instance: [u8; 16] = r.array().ok_or(HeaderError::Malformed)?;
    let reserved: [u8; 4] = r.array().ok_or(HeaderError::Malformed)?;
    let generation = r.u64().ok_or(HeaderError::Malformed)?;
    let base_seq = r.u64().ok_or(HeaderError::Malformed)?;
    let prev_tail: [u8; 32] = r.array().ok_or(HeaderError::Malformed)?;
    let snapshot: [u8; 32] = r.array().ok_or(HeaderError::Malformed)?;
    let mac: [u8; 32] = r.array().ok_or(HeaderError::Malformed)?;
    // The keys are derived from the expected identity, so a journal of another
    // wallet or network fails the MAC. Check the plain fields first only to
    // report the more useful error.
    if network != id.network || genesis != id.genesis || instance != id.instance {
        return Err(HeaderError::WrongIdentity);
    }
    let expect = keys.header_mac(signed).map_err(|_| HeaderError::Crypto)?;
    if !ct_eq(&expect, &mac) || flags != 0 || reserved != [0u8; 4] {
        return Err(HeaderError::Malformed);
    }
    Ok(Header {
        generation,
        base_seq,
        prev_tail,
        snapshot,
        hash: sha256(&[raw]),
    })
}

fn frame_aad(header_hash: &[u8; 32], seq: u64, prev: &[u8; 32], kind: u8, len: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 8 + 32 + 1 + 4);
    aad.extend_from_slice(header_hash);
    aad.extend_from_slice(&seq.to_le_bytes());
    aad.extend_from_slice(prev);
    aad.push(kind);
    aad.extend_from_slice(&len.to_le_bytes());
    aad
}

pub(crate) enum EncodeError {
    TooLarge,
    Crypto,
}

/// Encode one frame. Returns the bytes to append and the frame hash.
pub(crate) fn encode_frame(
    keys: &Keys,
    header_hash: &[u8; 32],
    seq: u64,
    prev: &[u8; 32],
    kind: u8,
    body: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), EncodeError> {
    if body.len() > MAX_BODY_LEN {
        return Err(EncodeError::TooLarge);
    }
    let len = FRAME_FIXED
        .checked_add(body.len())
        .and_then(|n| n.checked_add(TAG_LEN))
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(EncodeError::TooLarge)?;
    let aad = frame_aad(header_hash, seq, prev, kind, len);
    let (nonce, ct) = keys
        .seal_frame(&aad, body)
        .map_err(|_| EncodeError::Crypto)?;
    let mut f = Vec::with_capacity(4usize.saturating_add(FRAME_FIXED).saturating_add(ct.len()));
    f.extend_from_slice(&len.to_le_bytes());
    f.extend_from_slice(&seq.to_le_bytes());
    f.extend_from_slice(prev);
    f.push(kind);
    f.extend_from_slice(&nonce);
    f.extend_from_slice(&ct);
    let hash = sha256(&[&f]);
    Ok((f, hash))
}

pub(crate) struct RawFrame {
    pub(crate) seq: u64,
    pub(crate) kind: u8,
    pub(crate) body: Zeroizing<Vec<u8>>,
    pub(crate) hash: [u8; 32],
}

pub(crate) enum Parsed {
    /// A valid frame occupying `len` bytes.
    Frame(RawFrame, usize),
    /// Nothing more to read.
    End,
    /// No valid frame starts here. Whether this is an append that never
    /// became durable or damage is decided by [`valid_frame_follows`].
    Invalid,
}

/// Parse the frame starting at `tail` (the bytes from the current offset to
/// the end of the file).
pub(crate) fn parse_frame(
    keys: &Keys,
    header_hash: &[u8; 32],
    expect_seq: u64,
    expect_prev: &[u8; 32],
    tail: &[u8],
) -> Parsed {
    if tail.is_empty() {
        return Parsed::End;
    }
    match parse_valid(keys, header_hash, expect_seq, expect_prev, tail) {
        Some((f, used)) => Parsed::Frame(f, used),
        None => Parsed::Invalid,
    }
}

fn parse_valid(
    keys: &Keys,
    header_hash: &[u8; 32],
    expect_seq: u64,
    expect_prev: &[u8; 32],
    tail: &[u8],
) -> Option<(RawFrame, usize)> {
    let mut r = Reader::new(tail);
    let len = r.u32()?;
    let len_usize = usize::try_from(len).ok()?;
    let min = FRAME_FIXED.saturating_add(TAG_LEN);
    if len_usize < min || len_usize > min.saturating_add(MAX_BODY_LEN) {
        return None;
    }
    let total = len_usize.checked_add(4)?;
    let whole = tail.get(..total)?;
    let seq = r.u64()?;
    let prev: [u8; 32] = r.array()?;
    let kind = r.u8()?;
    let nonce: [u8; NONCE_LEN] = r.array()?;
    let ct = r.take(len_usize.checked_sub(FRAME_FIXED)?)?;
    if seq != expect_seq || !ct_eq(&prev, expect_prev) {
        return None;
    }
    let aad = frame_aad(header_hash, seq, &prev, kind, len);
    let body = keys.open_frame(&nonce, &aad, ct).ok()?;
    Some((
        RawFrame {
            seq,
            kind,
            body,
            hash: sha256(&[whole]),
        },
        total,
    ))
}

/// Whether a frame that verifies on its own terms starts anywhere in `tail`
/// after its first byte. Used to tell a write that never completed (nothing
/// valid can follow it) from damage in the middle of the journal.
pub(crate) fn valid_frame_follows(
    keys: &Keys,
    header_hash: &[u8; 32],
    after_seq: u64,
    tail: &[u8],
) -> bool {
    let min = FRAME_FIXED.saturating_add(TAG_LEN);
    // No more frames can follow than fit into the remaining bytes.
    let room = tail.len().checked_div(min).unwrap_or(0);
    let max_seq = after_seq.saturating_add(u64::try_from(room).unwrap_or(u64::MAX));
    for start in 1..tail.len() {
        let Some(candidate) = tail.get(start..) else {
            break;
        };
        let mut r = Reader::new(candidate);
        let (Some(len), Some(seq)) = (r.u32(), r.u64()) else {
            break;
        };
        if seq <= after_seq || seq > max_seq {
            continue;
        }
        let Ok(len_usize) = usize::try_from(len) else {
            continue;
        };
        if len_usize < min || len_usize > min.saturating_add(MAX_BODY_LEN) {
            continue;
        }
        let (Some(prev), Some(kind), Some(nonce)) =
            (r.array::<32>(), r.u8(), r.array::<NONCE_LEN>())
        else {
            continue;
        };
        let Some(ct) = len_usize.checked_sub(FRAME_FIXED).and_then(|n| r.take(n)) else {
            continue;
        };
        let aad = frame_aad(header_hash, seq, &prev, kind, len);
        if keys.open_frame(&nonce, &aad, ct).is_ok() {
            return true;
        }
    }
    false
}

/// Body of a rotate frame.
pub(crate) struct Rotate {
    pub(crate) generation: u64,
    pub(crate) snapshot: [u8; 32],
    pub(crate) header: [u8; 32],
}

pub(crate) fn encode_rotate(r: &Rotate) -> Vec<u8> {
    let mut b = Vec::with_capacity(ROTATE_BODY_LEN);
    b.extend_from_slice(&r.generation.to_le_bytes());
    b.extend_from_slice(&r.snapshot);
    b.extend_from_slice(&r.header);
    b
}

pub(crate) fn decode_rotate(body: &[u8]) -> Option<Rotate> {
    let mut r = Reader::new(body);
    let out = Rotate {
        generation: r.u64()?,
        snapshot: r.array()?,
        header: r.array()?,
    };
    if r.rest().is_empty() {
        Some(out)
    } else {
        None
    }
}

fn snapshot_aad(id: &Identity, generation: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 8 + 1 + 32 + 16);
    aad.extend_from_slice(SNAP_MAGIC);
    aad.extend_from_slice(&generation.to_le_bytes());
    aad.push(id.network);
    aad.extend_from_slice(&id.genesis);
    aad.extend_from_slice(&id.instance);
    aad
}

/// Encode a snapshot file. Returns the file bytes and their hash.
pub(crate) fn encode_snapshot(
    keys: &Keys,
    id: &Identity,
    generation: u64,
    state: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), EncodeError> {
    // The reader counts the complete encrypted file, including its header and tag.
    let cap = usize::try_from(MAX_FILE_LEN).unwrap_or(usize::MAX);
    if state.len() > cap.saturating_sub(16 + NONCE_LEN + TAG_LEN) {
        return Err(EncodeError::TooLarge);
    }
    let (nonce, ct) = keys
        .seal_snapshot(&snapshot_aad(id, generation), state)
        .map_err(|_| EncodeError::Crypto)?;
    let mut f = Vec::with_capacity(16usize.saturating_add(NONCE_LEN).saturating_add(ct.len()));
    f.extend_from_slice(SNAP_MAGIC);
    f.extend_from_slice(&generation.to_le_bytes());
    f.extend_from_slice(&nonce);
    f.extend_from_slice(&ct);
    let hash = sha256(&[&f]);
    Ok((f, hash))
}

/// Verify a snapshot file against the hash recorded in the journal and
/// decrypt it.
pub(crate) fn decode_snapshot(
    keys: &Keys,
    id: &Identity,
    generation: u64,
    expect_hash: &[u8; 32],
    file: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    if !ct_eq(&sha256(&[file]), expect_hash) {
        return None;
    }
    let mut r = Reader::new(file);
    let magic: [u8; 8] = r.array()?;
    let g = r.u64()?;
    let nonce: [u8; NONCE_LEN] = r.array()?;
    if &magic != SNAP_MAGIC || g != generation {
        return None;
    }
    keys.open_snapshot(&nonce, &snapshot_aad(id, generation), r.rest())
        .ok()
}

pub(crate) fn journal_name(generation: u64) -> String {
    format!("journal-{:016x}.fly", generation)
}

pub(crate) fn snapshot_name(generation: u64) -> String {
    format!("snapshot-{:016x}.fly", generation)
}

/// Generation encoded in a journal file name, if it is one.
pub(crate) fn parse_journal_name(name: &str) -> Option<u64> {
    let hex = name.strip_prefix("journal-")?.strip_suffix(".fly")?;
    if hex.len() != 16
        || !hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}
