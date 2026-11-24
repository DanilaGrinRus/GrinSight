//! Recognising the wallet's own outputs.
//!
//! An output is the wallet's if its range proof rewinds under the wallet
//! seed. Rewinding yields the amount and the key path; the path tells how the
//! output came to be. Nothing here proves that the output is in the chain,
//! unspent or mature: that is the business of the verified state (Level 5).
use crate::ledger::BranchState;
use crate::path::{classify, KeyPath};
use grin_core::libtx::proof::{self, ProofBuilder};
use grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use grin_util::secp::pedersen::{Commitment, RangeProof};

/// How a found output relates to this wallet instance. This is a statement
/// about the key path only. In particular [`Origin::CurrentBranch`] does not
/// make a record `fresh`: that also needs the local record written before the
/// output was disclosed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Path in the branch this instance is handing out from.
    CurrentBranch,
    /// Path in a branch this journal opened earlier (before a rollback or move).
    EarlierBranch,
    /// Path in a branch this journal never opened: another device, or an
    /// installation before a restore.
    ForeignBranch,
    /// Received without state (grin-wallet issue 844); no deal record exists.
    Stateless,
    /// Sequential key of grin-wallet or of v0.1.
    Legacy,
}

/// An output of this wallet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Found {
    /// Amount committed to.
    pub amount: u64,
    /// Identifier recovered from the proof.
    pub key_id: Identifier,
    /// The path, if it is of a known class.
    pub path: Option<KeyPath>,
}

/// Rewinding failed for a reason other than "not ours".
#[derive(Debug, PartialEq, Eq)]
pub struct ScanError;

/// Try to rewind `proof` with the wallet seed. `Ok(None)` means the output is
/// not this wallet's. Outputs with a switch commitment type other than the
/// regular one are not produced by any supported wallet and are treated as
/// not ours.
pub fn rewind<K: Keychain>(
    keychain: &K,
    commit: Commitment,
    proof: RangeProof,
) -> Result<Option<Found>, ScanError> {
    let builder = ProofBuilder::new(keychain);
    let info =
        proof::rewind(keychain.secp(), &builder, commit, None, proof).map_err(|_| ScanError)?;
    let (amount, key_id, switch) = match info {
        Some(i) => i,
        None => return Ok(None),
    };
    if switch != SwitchCommitmentType::Regular {
        return Ok(None);
    }
    // The proof authenticates the message, but make sure the commitment
    // really is the one this path and amount produce.
    let expect = keychain
        .commit(amount, &key_id, switch)
        .map_err(|_| ScanError)?;
    if expect != commit {
        return Ok(None);
    }
    let path = classify(&key_id);
    Ok(Some(Found {
        amount,
        key_id,
        path,
    }))
}

/// Relate a known-class path to this instance's branches.
pub fn origin(path: &KeyPath, state: &BranchState) -> Origin {
    match *path {
        KeyPath::Stateless { .. } => Origin::Stateless,
        KeyPath::Legacy { .. } => Origin::Legacy,
        KeyPath::Branch { branch, .. } => {
            if state.current() == Some(branch) {
                Origin::CurrentBranch
            } else if state.branches().contains(&branch) {
                Origin::EarlierBranch
            } else {
                Origin::ForeignBranch
            }
        }
    }
}
