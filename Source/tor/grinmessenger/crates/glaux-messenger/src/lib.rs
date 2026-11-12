// SPDX-License-Identifier: MIT OR Apache-2.0
//! Glaux messenger — M1 protocol.
//!
//! The wallet already has an identity: the slatepack address is an ed25519
//! public key. This crate uses it to (a) encrypt a message to the recipient and
//! (b) sign the envelope with the sender key. The relay only learns the
//! recipient address, size and timestamps; the sender address and the payload
//! live inside the ciphertext.
//!
//! Security model for v1:
//! * sender authenticity is verified by the **recipient after decryption**
//!   (the relay cannot verify it and must not be trusted for that);
//! * `plaintext-slatepack` (armor without age encryption) is refused, so a
//!   relay never carries a readable transaction;
//! * TTL is enforced twice: by the mailbox and by the recipient.

pub mod ack;
pub mod address;
pub mod contacts;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod filestore;
pub mod history;
pub mod keywrap;
pub mod nostr;
pub mod store;
pub mod transport;

pub use ack::AckProof;
pub use address::Address;
pub use contacts::{Contact, ContactBook};
pub use envelope::{Envelope, Identity, MessageKind, Opened, Payload};
pub use error::{Error, Result};
pub use filestore::FileMailbox;
pub use history::{Direction, History, MessageRecord};
pub use keywrap::{
    create as create_history_key, rewrap as rewrap_history_key, unwrap as unwrap_history_key,
    WrappedKey,
};
pub use nostr::{ContactDirectory, NostrKeys, NostrTransport, RelayFilter, WsRelay};
pub use store::{FailedEnvelope, MemoryMailbox, Messenger, ReceiveBatch, Store, Transport};
pub use transport::{DirectOnionTransport, GatewayTransport, HttpConnector, TcpConnector};

/// Default message lifetime: 26 hours (a slate survives ~24h, plus delivery).
pub const DEFAULT_TTL_SECS: u64 = 26 * 60 * 60;
/// Hard upper bound accepted by this implementation.
pub const MAX_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Current envelope version. v2 moves sender authentication inside the
/// encrypted payload so a relay cannot test a candidate sender against the
/// public transcript.
pub const VERSION: u8 = 2;
/// Legacy envelope version still accepted by [`Envelope::open`].
pub const LEGACY_VERSION: u8 = 1;
