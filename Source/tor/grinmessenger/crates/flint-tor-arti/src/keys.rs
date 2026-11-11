// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Adapted from grin-wallet's Tor integration (`impls/src/tor/config.rs`,
// Apache-2.0, https://github.com/mimblewimble/grin-wallet) and Flint's
// `crates/core/src/onion.rs`.

//! Helpers for Tor hidden-service key material.

use ed25519_dalek::hazmat::ExpandedSecretKey;
use sha2::{Digest, Sha512};

/// Expand an ed25519 seed into the 64-byte expanded secret key format Arti's
/// keystore expects: clamped scalar (32 bytes) followed by the hash prefix.
///
/// This is the same transformation Tor applies to `hs_ed25519_secret_key` and
/// the same one the grin-wallet/Flint integration used.
pub(crate) fn expanded_from_seed(seed: &[u8; 32]) -> ExpandedSecretKey {
    let digest: [u8; 64] = Sha512::digest(seed).into();
    ExpandedSecretKey::from_bytes(&digest)
}

/// Serialise an expanded secret key into the `scalar || hash_prefix` layout.
pub(crate) fn exp_sec_key_bytes(expanded_sk: ExpandedSecretKey) -> [u8; 64] {
    let mut sk_bytes = [0_u8; 64];
    sk_bytes[0..32].copy_from_slice(&expanded_sk.scalar.to_bytes());
    sk_bytes[32..64].copy_from_slice(&expanded_sk.hash_prefix);
    sk_bytes
}
