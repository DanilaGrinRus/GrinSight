// SPDX-License-Identifier: MIT OR Apache-2.0
//! Nostr transport (NIP-44 v2 payloads inside NIP-59 gift wraps, kind 1059).
//!
//! Contract: `docs/PROTOCOL.md` (транспорты, Nostr) and `docs/ARCHITECTURE.md`. The transport carries the existing signed/encrypted
//! Flint envelope unchanged; Nostr adds delivery, not a second money protocol.
//! It is off by default, uses a transport key that never touches funds, and has
//! no forward secrecy — see the contract before enabling it.

pub mod event;
pub mod keys;
pub mod nip44;
pub mod relay;
pub mod transport;
pub mod wrap;
pub mod ws;

pub use event::Event;
pub use keys::NostrKeys;
pub use relay::{MemoryRelay, Relay, RelayFilter};
pub use transport::{ContactDirectory, Directory, NostrTransport};
pub use wrap::{gift_wrap, unwrap, Rumor};
pub use ws::WsRelay;

use secp256k1::XOnlyPublicKey;

use crate::error::{Error, Result};

/// Current time in seconds since the Unix epoch.
pub(crate) fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase hex encoding used by Nostr identifiers and signatures.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Parse lowercase or uppercase hex; odd lengths and bad digits are rejected.
pub(crate) fn hex_decode(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(Error::Crypto("nostr: нечётная hex-строка".into()));
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::Crypto("nostr: недопустимый hex-символ".into())),
    }
}

/// Cryptographically secure random bytes; failure is explicit, never zeroes.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out)
        .map_err(|error| Error::Crypto(format!("nostr: rng: {error}")))?;
    Ok(out)
}

/// Parse an x-only transport public key in hex (64 characters).
pub fn parse_public_hex(value: &str) -> Result<XOnlyPublicKey> {
    let bytes = hex_decode(value.trim())?;
    let array: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("nostr: transport key must be 32 bytes".into()))?;
    XOnlyPublicKey::from_byte_array(array)
        .map_err(|_| Error::Crypto("nostr: invalid x-only transport key".into()))
}
