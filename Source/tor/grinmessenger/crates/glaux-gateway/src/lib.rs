// SPDX-License-Identifier: MIT OR Apache-2.0
//! glaux-gateway — standalone store-and-forward relay for opaque envelopes.
//!
//! Extracted from the Glaux wallet gateway (`crates/core/src/gateway.rs`): the
//! wallet RPC proxy, the wallet configuration fields and the `reqwest` HTTP
//! client are removed. The message API, quotas, TTL, proof-of-work and signed
//! acknowledgement checks are preserved unchanged.

pub mod error;
pub mod gateway;

pub use error::{Error, Result};
pub use gateway::{wait_ready, Gateway, GatewayConfig, Message};
