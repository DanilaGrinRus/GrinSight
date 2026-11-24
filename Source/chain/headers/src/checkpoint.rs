//! The record of a starting point.
//!
//! A starting point is a header S that somebody vouches for. To go on from
//! it three things are needed besides S: the header before it and the one
//! before that (the difficulty rule reads them), and the peaks of the header
//! MMR after S (the next header commits to them).
//!
//! The record carries all of that, and [`check`] makes all of it hang on the
//! one hash of S: the two earlier headers are named by hash from S down, and
//! the peaks are rebuilt from the Merkle proof of S-1 under the root that S
//! itself commits to. After a successful check the only thing taken on trust
//! is that the hash of S is the right one - that is what "vouching for the
//! point" means, and nothing in this module can replace it.
//!
//! The format is version 1 of the record used by the Fly core
//! (`CheckpointRecord`), so that points prepared there can be read here.
use crate::peaks::Peaks;
use crate::{hash_bytes, read_header, rules, Net, MAX_HEADER_LEN};
use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::BlockHeader;
use serde::{Deserialize, Serialize};

/// Longest record read.
pub const MAX_RECORD_LEN: usize = 64 * 1024;
/// Longest Merkle path and largest number of peaks in a record.
const MAX_HASHES: usize = 64;

/// Why a record is not a usable starting point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckError {
    /// Not a record of this format: size, JSON, version, counts.
    Format,
    /// For another network or another genesis.
    Network,
    /// The headers are not three consecutive headers ending in the one the
    /// record names, or one of them fails the rules.
    Headers(rules::Reject),
    /// The peaks do not follow from the root the starting header commits to.
    Peaks,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    network: u8,
    genesis: [u8; 32],
    height: u64,
    header_hash: [u8; 32],
    total_work: u64,
    /// S, S-1, S-2 - newest first.
    context: Vec<Vec<u8>>,
    mmr_size: u64,
    peaks: Vec<[u8; 32]>,
    /// Merkle proof of S-1 under the root S commits to.
    previous_path: Vec<[u8; 32]>,
    release_time: u64,
    /// Merkle proof of S-2 under the root S-1 commits to.
    #[serde(default)]
    older_context_path: Option<Vec<[u8; 32]>>,
}

/// A checked starting point: everything needed to verify the header after it.
#[derive(Clone, Debug)]
pub struct Start {
    /// The network.
    pub net: Net,
    /// The starting header S.
    pub anchor: BlockHeader,
    /// The header before it.
    pub prev: BlockHeader,
    /// The peaks of the header MMR with S as its last leaf.
    pub peaks: Peaks,
    /// When the record was made for a release, in Unix seconds, as the
    /// record says. Not checked against anything.
    pub release_time: u64,
}

impl Start {
    /// Height of the starting header.
    pub fn height(&self) -> u64 {
        self.anchor.height
    }
    /// Hash of the starting header.
    pub fn hash(&self) -> [u8; 32] {
        hash_bytes(&self.anchor)
    }
}

fn hashes(list: &[[u8; 32]]) -> Vec<Hash> {
    list.iter().map(|h| Hash::from_vec(h)).collect()
}

/// Check a record for `net`. Enters the network on the calling thread.
pub fn check(bytes: &[u8], net: Net) -> Result<Start, CheckError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_LEN {
        return Err(CheckError::Format);
    }
    let record: Record = serde_json::from_slice(bytes).map_err(|_| CheckError::Format)?;
    let paths_fit = record.previous_path.len() <= MAX_HASHES
        && record.peaks.len() <= MAX_HASHES
        && record.older_context_path.as_ref().is_none_or(|p| p.len() <= MAX_HASHES);
    if record.version != 1
        || record.context.len() != 3
        || record.context.iter().any(|raw| raw.is_empty() || raw.len() > MAX_HEADER_LEN)
        || !paths_fit
        || record.height < 2
    {
        return Err(CheckError::Format);
    }
    if record.network != net.tag() || record.genesis != net.genesis_hash() {
        return Err(CheckError::Network);
    }
    net.enter();
    let mut headers = Vec::with_capacity(3);
    for raw in &record.context {
        headers.push(read_header(raw).ok_or(CheckError::Format)?);
    }
    let [anchor, prev, older] = <[BlockHeader; 3]>::try_from(headers).map_err(|_| CheckError::Format)?;
    if anchor.height != record.height
        || hash_bytes(&anchor) != record.header_hash
        || anchor.total_difficulty().to_num() != record.total_work
    {
        return Err(CheckError::Format);
    }
    // S follows S-1 and S-2 by every rule; the two earlier ones are checked
    // as far as a header can be checked without its own predecessors
    rules::check_alone(&older).map_err(CheckError::Headers)?;
    rules::check_alone(&prev).map_err(CheckError::Headers)?;
    rules::check_step(&older, &prev, &anchor).map_err(CheckError::Headers)?;
    // the peaks before S, from the proof of S-1 under the root in S ...
    let before = Peaks::from_last_leaf(record.height, &prev, &hashes(&record.previous_path), anchor.prev_root)
        .map_err(|_| CheckError::Peaks)?;
    // ... and S on top of them
    let mut peaks = before;
    peaks.append(&anchor).map_err(|_| CheckError::Peaks)?;
    // what the record says about the result must agree with it
    if peaks.size() != record.mmr_size || peaks.hashes() != hashes(&record.peaks).as_slice() {
        return Err(CheckError::Peaks);
    }
    // the same for S-2 under S-1, when the record carries that proof
    if let Some(path) = &record.older_context_path {
        let leaves = record.height.checked_sub(1).ok_or(CheckError::Format)?;
        Peaks::from_last_leaf(leaves, &older, &hashes(path), prev.prev_root).map_err(|_| CheckError::Peaks)?;
    }
    debug_assert_eq!(anchor.prev_hash, prev.hash());
    Ok(Start {
        net,
        anchor,
        prev,
        peaks,
        release_time: record.release_time,
    })
}

/// What a record of a starting point is written from.
pub struct Parts<'a> {
    /// The network.
    pub net: Net,
    /// The starting header S.
    pub anchor: &'a BlockHeader,
    /// The header before it, S-1.
    pub prev: &'a BlockHeader,
    /// The header before that, S-2.
    pub older: &'a BlockHeader,
    /// The peaks of the range that ends with S-2: what S-1 is added to.
    pub before_prev: &'a Peaks,
    /// The peaks of the range that ends with S-3: what S-2 is added to.
    pub before_older: &'a Peaks,
    /// When the record is made, in Unix seconds.
    pub release_time: u64,
}

fn plain(hashes: &[Hash]) -> Vec<[u8; 32]> {
    hashes
        .iter()
        .map(|hash| {
            let mut out = [0u8; 32];
            for (to, from) in out.iter_mut().zip(hash.as_bytes()) {
                *to = *from;
            }
            out
        })
        .collect()
}

/// The path of a range's last leaf: the peaks the leaf was added to, from
/// the right. The nearest ones are its siblings on the way up, the rest
/// are the other peaks - see [`Peaks::from_last_leaf`].
fn last_leaf_path(before: &Peaks) -> Vec<[u8; 32]> {
    let mut path = plain(before.hashes());
    path.reverse();
    path
}

/// Write the record of a starting point at the header `anchor`.
///
/// The caller hands over headers and peaks it has verified; nothing here
/// vouches for them. The record is returned only if [`check`] reads it
/// back to the very header and peaks it was written from - a record this
/// program could not start from is never written.
pub fn write(parts: &Parts<'_>) -> Option<Vec<u8>> {
    parts.net.enter();
    // headers of another network cannot even be hashed by this one's rules
    let proof_size = grin_core::global::proofsize();
    if [parts.anchor, parts.prev, parts.older].iter().any(|header| header.pow.proof.proof_size() != proof_size) {
        return None;
    }
    // peaks of another size give paths of another length or another root:
    // the reading back below refuses them
    let height = parts.anchor.height;
    let mut peaks = parts.before_prev.clone();
    peaks.append(parts.prev).ok()?;
    peaks.append(parts.anchor).ok()?;
    let record = Record {
        version: 1,
        network: parts.net.tag(),
        genesis: parts.net.genesis_hash(),
        height,
        header_hash: hash_bytes(parts.anchor),
        total_work: parts.anchor.total_difficulty().to_num(),
        context: vec![
            crate::write_header(parts.anchor)?,
            crate::write_header(parts.prev)?,
            crate::write_header(parts.older)?,
        ],
        mmr_size: peaks.size(),
        peaks: plain(peaks.hashes()),
        previous_path: last_leaf_path(parts.before_prev),
        release_time: parts.release_time,
        older_context_path: Some(last_leaf_path(parts.before_older)),
    };
    let bytes = serde_json::to_vec(&record).ok()?;
    let read = check(&bytes, parts.net).ok()?;
    (read.hash() == hash_bytes(parts.anchor) && read.peaks == peaks && read.prev.hash() == parts.prev.hash()).then_some(bytes)
}
