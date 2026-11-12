// SPDX-License-Identifier: MIT OR Apache-2.0
//
//! glaux-tor-arti — in-process Tor layer for GlauxMessenger.
//!
//! This crate adapts the Tor/Arti integration that shipped with the pinned
//! grin-wallet fork used by Glaux (`third_party/grin-wallet/impls/src/tor/arti.rs`,
//! Apache-2.0) and the Glaux onion wrapper (`crates/core/src/onion.rs`), so the
//! messenger can publish an onion service and make HTTP requests over Tor without
//! an external `tor.exe` or a SOCKS proxy.
//!
//! Main API:
//! * [`onion_address`] / [`onion_from_address`] / [`parse_onion`] — Tor v3 onion
//!   address derived from the same ed25519 seed as the messenger identity;
//! * [`OnionService`] — publish `onion:80` → a local loopback address;
//! * [`TorHttpClient`] — blocking HTTP/1.1 GET/POST through the Arti client;
//! * [`TorConfig`] — state directory, bootstrap/request timeouts and optional
//!   bridge line.
//!
//! The Arti client itself is cached per process and per configuration; starting
//! an [`OnionService`] and then bootstrapping a [`TorHttpClient`] with the same
//! [`TorConfig`] reuses one Tor client.

#![forbid(unsafe_code)]

mod arti;
mod error;
mod keys;
mod onion;

pub use arti::{OnionService, TorConfig, TorHttpClient};
pub use error::{Result, TorError};
pub use onion::{address_from_key, onion_address, onion_from_address, parse_onion};

/// Default number of seconds allowed for an initial Arti bootstrap.
pub const DEFAULT_BOOTSTRAP_TIMEOUT_SECS: u64 = 120;
/// Default number of seconds allowed for one HTTP request through Tor.
pub const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 60;
