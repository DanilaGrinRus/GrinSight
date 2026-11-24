//! Native shared embedded Tor foundation, not yet connected to a wallet.
//!
//! No direct-network fallback is provided. These functions do not supply an
//! onion service, bridge transports, Nostr framing, or Android lifecycle. The
//! caller must own a stable application data directory and share one instance.
//! Host OS Tor connections see the client's IP; Tor bootstrap and live routing
//! have not yet been tested. This crate is unsupported on browser targets.

#[cfg(not(target_arch = "wasm32"))]
mod native;

#[cfg(not(target_arch = "wasm32"))]
pub use native::{SharedTor, TorError};
