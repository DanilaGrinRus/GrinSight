// SPDX-License-Identifier: MIT OR Apache-2.0

//! Errors for the in-process Tor layer.

use thiserror::Error;

/// Result alias used by this crate.
pub type Result<T> = std::result::Result<T, TorError>;

/// Errors raised while deriving onion addresses, publishing an onion service or
/// performing HTTP requests through Tor/Arti.
#[derive(Debug, Error)]
pub enum TorError {
    /// Filesystem/directory errors (state dir, cache dir, keystore).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Invalid configuration or unsupported input.
    #[error("tor config: {0}")]
    Config(String),
    /// Failure while talking to the Tor network or Arti runtime.
    #[error("tor: {0}")]
    Tor(String),
    /// Invalid or unverifiable onion address / slatepack address.
    #[error("onion address: {0}")]
    Onion(String),
}
