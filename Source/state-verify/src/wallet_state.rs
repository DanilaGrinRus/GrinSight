//! Wallet state-proof verifier API (research prototype).
//!
//! Verifies an output inclusion proof plus a bitmap inclusion proof against a
//! v3+ header:
//!
//! ```text
//! header.output_root = H(output_mmr_size || output_pmmr_root || bitmap_root)
//! ```
//!
//! Bit semantics (source-verified): set bit = output still in the leaf set
//! (unspent); clear bit = spent/removed. A proof for an unspent output therefore
//! needs a set bit; a historical spent proof uses a clear bit at the tip plus a
//! historical set-bit proof.
//!
//! No consensus change; no network.

use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::merkle_proof::MerkleProof;
use grin_core::core::pmmr::{self, insertion_to_pmmr_index, ReadablePMMR};
use grin_core::core::{BlockHeader, HeaderVersion, OutputIdentifier};
use grin_core::ser::PMMRIndexHashable;
use grin_chain::txhashset::BitmapChunk;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputState {
    Unspent,
    Spent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    UnsupportedHeaderVersion,
    MismatchedOutputSize,
    MergedRootMismatch,
    OutputProof,
    BitmapProof,
    BitIndexMismatch,
    InvalidBitmapChunk,
}

#[derive(Debug, Clone)]
pub struct StateProof {
    pub output_mmr_size: u64,
    pub pmmr_root: Hash,
    pub bitmap_root: Hash,
    pub output: OutputIdentifier,
    pub output_pos: u64,
    pub output_proof: MerkleProof,
    pub bit_index: u64,
    pub chunk_index: u64,
    pub chunk_bits: [u8; 128],
    pub bitmap_mmr_size: u64,
    pub bitmap_path: Vec<Hash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedState {
    pub height: u64,
    pub header_hash: Hash,
    pub state: OutputState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshnessPolicy {
    pub tip_hash: Hash,
    pub tip_height: u64,
    pub max_age: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessError {
    StaleTip,
    FutureHeight,
    TooOld,
}

fn bit_of(bytes: &[u8; 128], bit: u64) -> bool {
    let b = bit as usize;
    bytes[b / 8] & (1u8 << (b % 8)) != 0
}

fn chunk_from_bytes(bytes: &[u8; 128]) -> BitmapChunk {
    let mut chunk = BitmapChunk::new();
    for i in 0..1024 {
        if bit_of(bytes, i) {
            chunk.set(i, true);
        }
    }
    chunk
}

/// Verify the proof against a header. Returns Unspent when the bitmap bit is
/// set, Spent when clear. For a current output inclusion proof the output data
/// must still exist; spent history requires a separate historical proof.
pub fn verify(header: &BlockHeader, proof: &StateProof) -> Result<VerifiedState, VerifyError> {
    if header.version < HeaderVersion(3) {
        return Err(VerifyError::UnsupportedHeaderVersion);
    }
    if header.output_mmr_size != proof.output_mmr_size {
        return Err(VerifyError::MismatchedOutputSize);
    }
    let merged = (proof.pmmr_root, proof.bitmap_root).hash_with_index(header.output_mmr_size);
    if merged != header.output_root {
        return Err(VerifyError::MergedRootMismatch);
    }
    proof
        .output_proof
        .verify(proof.pmmr_root, &proof.output, proof.output_pos)
        .map_err(|_| VerifyError::OutputProof)?;

    if proof.bit_index != pmmr::pmmr_leaf_to_insertion_index(proof.output_pos)
        .ok_or(VerifyError::BitIndexMismatch)?
    {
        return Err(VerifyError::BitIndexMismatch);
    }
    if proof.chunk_index != proof.bit_index / 1024 {
        return Err(VerifyError::BitIndexMismatch);
    }
    if proof.chunk_bits.len() != 128 {
        return Err(VerifyError::InvalidBitmapChunk);
    }
    let chunk = chunk_from_bytes(&proof.chunk_bits);
    let leaf_pos = insertion_to_pmmr_index(proof.chunk_index);
    let bitmap_proof = MerkleProof {
        mmr_size: proof.bitmap_mmr_size,
        path: proof.bitmap_path.clone(),
    };
    bitmap_proof
        .verify(proof.bitmap_root, &chunk, leaf_pos)
        .map_err(|_| VerifyError::BitmapProof)?;

    let state = if bit_of(&proof.chunk_bits, proof.bit_index % 1024) {
        OutputState::Unspent
    } else {
        OutputState::Spent
    };
    Ok(VerifiedState {
        height: header.height,
        header_hash: header.hash(),
        state,
    })
}

/// Fail-closed freshness / reorg policy: the proof must be for the current
/// policy tip and not older than max_age blocks.
pub fn check_freshness(
    verified: &VerifiedState,
    policy: &FreshnessPolicy,
) -> Result<(), FreshnessError> {
    if verified.header_hash != policy.tip_hash {
        return Err(FreshnessError::StaleTip);
    }
    if verified.height > policy.tip_height {
        return Err(FreshnessError::FutureHeight);
    }
    if policy.tip_height.saturating_sub(verified.height) > policy.max_age {
        return Err(FreshnessError::TooOld);
    }
    Ok(())
}

/// Recompute the merged output root, exposed for independent checks.
pub fn merged_output_root(size: u64, pmmr_root: Hash, bitmap_root: Hash) -> Hash {
    (pmmr_root, bitmap_root).hash_with_index(size)
}
