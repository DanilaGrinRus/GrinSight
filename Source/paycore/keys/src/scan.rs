//! Recognising the wallet's own outputs.
//!
//! An output is the wallet's if its range proof rewinds under the wallet
//! seed. Rewinding yields the amount and the key path; the path tells how the
//! output came to be. Nothing here proves that the output is in the chain,
//! unspent or mature: that is the business of the verified state (Level 5).
use crate::ledger::BranchState;
use crate::path::{classify, KeyPath};
use grin_core::consensus::{
    HARD_FORK_INTERVAL, TESTING_HARD_FORK_INTERVAL, TESTNET_FIRST_HARD_FORK, WEEK_HEIGHT,
};
use grin_core::libtx::proof::{self, LegacyProofBuilder, ProofBuilder};
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
    OutputRewinder::new(keychain, None).rewind(commit, proof)
}

/// Reuse key derivation while scanning outputs from one block or archive piece.
pub struct OutputRewinder<'a, K: Keychain> {
    keychain: &'a K,
    modern: ProofBuilder<'a, K>,
    legacy: Option<LegacyProofBuilder<'a, K>>,
    legacy_first: bool,
}

impl<'a, K: Keychain> OutputRewinder<'a, K> {
    /// Use the upstream legacy window for a known (journal network, creation height). An archival
    /// output may predate its anchor by years; without a birth height, try both.
    pub fn new(keychain: &'a K, birth: Option<(u8, u64)>) -> Self {
        // Network tags come from the wallet journal identity (host Network::tag).
        // An independent wallet worker need not have Grin thread-local state.
        let early = birth.and_then(|(network, height)| {
            let fork = match network {
                1 => HARD_FORK_INTERVAL,
                2 => TESTNET_FIRST_HARD_FORK,
                3 => TESTING_HARD_FORK_INTERVAL,
                _ => return None,
            };
            Some(height.saturating_sub(2 * WEEK_HEIGHT) < fork)
        });
        let legacy_first = early == Some(true);
        Self {
            keychain,
            modern: ProofBuilder::new(keychain),
            legacy: (early != Some(false)).then(|| LegacyProofBuilder::new(keychain)),
            legacy_first,
        }
    }

    /// A successful rewind still requires the path and amount to open this commitment.
    pub fn rewind(
        &self,
        commit: Commitment,
        proof: RangeProof,
    ) -> Result<Option<Found>, ScanError> {
        let secp = self.keychain.secp();
        let modern =
            || proof::rewind(secp, &self.modern, commit, None, proof).map_err(|_| ScanError);
        let legacy = || match &self.legacy {
            Some(builder) => {
                proof::rewind(secp, builder, commit, None, proof).map_err(|_| ScanError)
            }
            None => Ok(None),
        };
        let info = if self.legacy_first {
            match legacy()? {
                Some(v) => Some(v),
                None => modern()?,
            }
        } else {
            match modern()? {
                Some(v) => Some(v),
                None => legacy()?,
            }
        };
        self.found(commit, info)
    }

    fn found(
        &self,
        commit: Commitment,
        info: Option<(u64, Identifier, SwitchCommitmentType)>,
    ) -> Result<Option<Found>, ScanError> {
        let (amount, key_id, switch) = match info {
            Some(i) => i,
            None => return Ok(None),
        };
        if switch != SwitchCommitmentType::Regular {
            return Ok(None);
        }
        // The proof authenticates the message, but make sure the commitment
        // really is the one this path and amount produce.
        let expect = self
            .keychain
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
