// SPDX-License-Identifier: MIT OR Apache-2.0
//! Wallet integration layer for GrinMessenger.
//!
//! Two supported integration styles for a Grin wallet:
//!
//! 1. **Embedded**: link `glaux-messenger-wallet`, supply a 32-byte messaging
//!    seed, call [`WalletService::open`] + [`WalletService::start_network`] and
//!    use the typed methods directly (Rust wallets such as `grin-wallet`).
//! 2. **Sidecar**: run the `glauxmsg-walletd` binary and talk to its loopback
//!    JSON API ([`server`]). This is language-independent and fits C++/Qt
//!    wallets such as Grin++.
//!
//! Identity model: the messenger address is `bech32(ed25519 public key)`, the
//! same format as a Grin slatepack address. The seed is a 32-byte ed25519 seed.
//! Wallets SHOULD derive a dedicated messaging seed with
//! [`derive_messaging_seed`] instead of reusing the wallet master seed or the
//! spending key. The wallet's normal slatepack address keeps being used for
//! payments; the messenger address is shown next to it for chat/Slatepack
//! transport.

mod deferred;
pub mod identity;
#[doc(hidden)]
pub mod i2p_identity;
pub mod payment_outbox;
pub mod read_state;
pub mod server;
pub mod service;

pub use identity::{
    derive_messaging_seed, identity_from_seed, load_identity_file, network_hrp, read_seed_file,
    save_generated_identity, storage_key, IdentityFile,
};
pub use read_state::ReadState;
pub use server::{serve, AuthToken};
pub use service::{
    capabilities, ActiveTransport, Capabilities, MessageView, MessagesPage, NetworkMode,
    ServiceConfig, ServiceStatus, WalletEvent, WalletService, API_VERSION, MAX_ARMOR_BYTES,
    MAX_TEXT_BYTES,
};
