//! Authenticated queue-record codec. This module never writes to disk.
//! Identity, storage secret and filesystem safety remain caller responsibilities.
use chacha20poly1305::{aead::{Aead, KeyInit, Payload}, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use nostr_sdk::{Event, JsonUtil, Kind, PublicKey};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};
use super::{contact_session::PreparedMessage, protocol};

const MAGIC: &[u8; 8] = b"FLYQ0001";
const HISTORY_MAGIC: &[u8; 8] = b"FLYQ0002";
const ACK_MAGIC: &[u8; 8] = b"FLYA0001";
const INBOX_MAGIC: &[u8; 8] = b"FLYI0001";
const BOUND_REPLY_MAGIC: &[u8; 8] = b"FLYB0001";
const RECOVERABLE_MAGIC: &[u8; 8] = b"FLYR0001";
const CORRELATED_MAGIC: &[u8; 8] = b"FLYR0002";
const MAX_JSON: usize = 128 * 1024;
pub(super) const MAX_RECORD: usize = 8 + 24 + 8 + MAX_JSON + protocol::MAX_RUMOR_CONTENT + 16 + 112;
/// Maximum lifetime for explicitly requested offline payment delivery.
/// Expiration is a relay policy hint, not proof that an event was deleted.
pub(super) const MAX_DELIVERY_TTL: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network { Mainnet, Floonet }
impl Network { fn byte(self) -> u8 { match self { Self::Mainnet => 1, Self::Floonet => 2 } } }

/// Every field must come from an authenticated wallet/contact store.
#[derive(Clone, Copy)]
pub struct QueueIdentity {
    pub network: Network,
    pub wallet_id: [u8; 32],
    /// Stable, random operation slot; it is not a payment or wallet key.
    pub slot: [u8; 16],
    pub sender: PublicKey,
    pub recipient: PublicKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueError;

/// Derive from a separately protected wallet storage secret, never an address.
/// Reusing the secret for a different purpose without domain separation is forbidden.
pub struct QueueKey(Zeroizing<[u8; 32]>);
impl QueueKey {
    /// Derive a purpose-specific storage key from authenticated wallet entropy.
    /// This API does not read a vault, verify the wallet ID, or establish that
    /// the caller supplied the correct wallet. The entropy must never be logged.
    pub fn derive_from_wallet_entropy(entropy: &[u8], identity: &QueueIdentity) -> Result<Self, QueueError> {
        if identity.slot.iter().all(|x| *x == 0) || identity.sender == identity.recipient { return Err(QueueError); }
        Self::derive_for_wallet_entropy(entropy, identity.network, &identity.wallet_id)
    }

    /// Reopen a wallet-scoped queue without knowing the counterparty. Wallet
    /// identity and entropy must come from the same authenticated profile.
    pub fn derive_for_wallet_entropy(entropy: &[u8], network: Network, wallet_id: &[u8; 32]) -> Result<Self, QueueError> {
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) { return Err(QueueError); }
        if wallet_id.iter().all(|x| *x == 0) { return Err(QueueError); }
        let mut salt = [0u8; 33]; salt[0] = network.byte();
        salt[1..].copy_from_slice(wallet_id);
        let hk = Hkdf::<Sha256>::new(Some(&salt), entropy);
        let mut root = Zeroizing::new([0u8; 32]);
        hk.expand(b"GrinSight Fly wallet entropy to queue root v1", &mut *root).map_err(|_| QueueError)?;
        let key_hk = Hkdf::<Sha256>::new(Some(&salt), &*root);
        let mut key = Zeroizing::new([0u8; 32]);
        key_hk.expand(b"GrinSight Fly Nostr queue key v1", &mut *key).map_err(|_| QueueError)?;
        salt.zeroize();
        Ok(Self(key))
    }

    pub fn derive(storage_secret: &[u8; 32], identity: &QueueIdentity) -> Result<Self, QueueError> {
        if storage_secret.iter().all(|x| *x == 0) || identity.wallet_id.iter().all(|x| *x == 0) || identity.slot.iter().all(|x| *x == 0)
            || identity.sender == identity.recipient { return Err(QueueError); }
        let mut salt = [0u8; 33];
        salt[0] = identity.network.byte();
        salt[1..].copy_from_slice(&identity.wallet_id);
        let hk = Hkdf::<Sha256>::new(Some(&salt), storage_secret);
        let mut key = Zeroizing::new([0; 32]);
        hk.expand(b"GrinSight Fly Nostr queue key v1", &mut *key).map_err(|_| QueueError)?;
        salt.zeroize();
        Ok(Self(key))
    }
}

fn recoverable_aad(magic: &[u8;8], network: Network, wallet_id: &[u8; 32], slot: &[u8; 16], sender: &PublicKey) -> Result<Vec<u8>, QueueError> {
    if wallet_id.iter().all(|b| *b == 0) || slot.iter().all(|b| *b == 0) { return Err(QueueError); }
    let mut aad = Vec::with_capacity(8 + 1 + 32 + 16 + 32);
    aad.extend_from_slice(magic); aad.push(network.byte());
    aad.extend_from_slice(wallet_id); aad.extend_from_slice(slot); aad.extend_from_slice(sender.as_bytes());
    Ok(aad)
}

/// A single atomic outgoing record containing its encrypted recipient and the
/// original encrypted event. No inbound S1 or payment operation is stored.
pub fn seal_recoverable(key: &QueueKey, identity: &QueueIdentity, prepared: &PreparedMessage, now: u64) -> Result<Vec<u8>, QueueError> {
    seal_recoverable_inner(key, identity, prepared, now, None)
}

/// Bind a temporary outgoing reply to one authenticated incoming Nostr event.
/// The encrypted source ID is transport metadata, not a wallet transaction.
pub fn seal_correlated_recoverable(key: &QueueKey, identity: &QueueIdentity, prepared: &PreparedMessage,
    now: u64, source: &[u8;32]) -> Result<Vec<u8>, QueueError> {
    if source.iter().all(|b| *b == 0) { return Err(QueueError); }
    seal_recoverable_inner(key, identity, prepared, now, Some(source))
}

fn seal_recoverable_inner(key: &QueueKey, identity: &QueueIdentity, prepared: &PreparedMessage,
    now: u64, source: Option<&[u8;32]>) -> Result<Vec<u8>, QueueError> {
    if identity.sender == identity.recipient { return Err(QueueError); }
    let magic = if source.is_some() { CORRELATED_MAGIC } else { RECOVERABLE_MAGIC };
    let aad = recoverable_aad(magic, identity.network, &identity.wallet_id, &identity.slot, &identity.sender)?;
    let inner = Zeroizing::new(seal(key, identity, prepared, now)?);
    let mut plaintext = Zeroizing::new(Vec::with_capacity(64 + inner.len()));
    plaintext.extend_from_slice(identity.recipient.as_bytes());
    if let Some(source) = source { plaintext.extend_from_slice(source); }
    plaintext.extend_from_slice(&inner);
    let mut nonce = [0u8; 24]; getrandom::getrandom(&mut nonce).map_err(|_| QueueError)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    let encrypted = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &aad }).map_err(|_| QueueError)?;
    let mut record = Vec::with_capacity(8 + 24 + encrypted.len());
    record.extend_from_slice(magic); record.extend_from_slice(&nonce); record.extend_from_slice(&encrypted);
    if record.len() > MAX_RECORD { return Err(QueueError); }
    Ok(record)
}

/// Recover the counterparty only inside authenticated ciphertext. The caller
/// must authenticate network, wallet, slot and its own messaging key, and may
/// not treat a failed open as permission to generate a replacement event.
pub fn open_recoverable(key: &QueueKey, network: Network, wallet_id: &[u8; 32], slot: &[u8; 16],
    sender: PublicKey, record: &[u8], now: u64) -> Result<(QueueIdentity, PreparedMessage), QueueError> {
    let (identity, plaintext, offset) = decode_recoverable(key, network, wallet_id, slot, sender, record)?;
    let prepared = open(key, &identity, &plaintext[offset..], now)?;
    Ok((identity, prepared))
}

/// Reconcile only with the exact authenticated incoming event; a changed ID,
/// older uncorrelated record, wrong peer or corrupt record must fail closed.
pub fn open_correlated_recoverable(key: &QueueKey, network: Network, wallet_id: &[u8;32], slot: &[u8;16],
    sender: PublicKey, source: &[u8;32], record: &[u8], now: u64) -> Result<(QueueIdentity, PreparedMessage), QueueError> {
    let (identity, plaintext, offset) = decode_recoverable(key, network, wallet_id, slot, sender, record)?;
    if offset != 64 || plaintext[32..64] != source[..] { return Err(QueueError); }
    let prepared = open(key, &identity, &plaintext[offset..], now)?;
    Ok((identity, prepared))
}

pub(super) fn recoverable_metadata(key: &QueueKey, network: Network, wallet_id: &[u8; 32], slot: &[u8; 16],
    sender: PublicKey, record: &[u8]) -> Result<(QueueIdentity, OutgoingMetadata), QueueError> {
    let (identity, plaintext, offset) = decode_recoverable(key, network, wallet_id, slot, sender, record)?;
    let metadata = open_metadata(key, &identity, &plaintext[offset..])?;
    Ok((identity, metadata))
}

/// Recover explicitly retained outgoing text even after relay expiry. This
/// does not return a publishable event, a signing nonce or a payment decision.
pub fn open_recoverable_history(key: &QueueKey, network: Network, wallet_id: &[u8;32], slot: &[u8;16],
    sender: PublicKey, record: &[u8]) -> Result<(QueueIdentity, OutgoingHistory), QueueError> {
    let (identity, plaintext, offset) = decode_recoverable(key, network, wallet_id, slot, sender, record)?;
    let history = open_history(key, &identity, &plaintext[offset..])?;
    Ok((identity, history))
}

fn decode_recoverable(key: &QueueKey, network: Network, wallet_id: &[u8; 32], slot: &[u8; 16],
    sender: PublicKey, record: &[u8]) -> Result<(QueueIdentity, Zeroizing<Vec<u8>>, usize), QueueError> {
    if record.len() < 8 + 24 + 32 + 16 || record.len() > MAX_RECORD { return Err(QueueError); }
    let (magic, offset) = if &record[..8] == RECOVERABLE_MAGIC { (RECOVERABLE_MAGIC, 32) }
        else if &record[..8] == CORRELATED_MAGIC { (CORRELATED_MAGIC, 64) } else { return Err(QueueError); };
    let aad = recoverable_aad(magic, network, wallet_id, slot, &sender)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    let plaintext = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&record[8..32]),
        Payload { msg: &record[32..], aad: &aad }).map_err(|_| QueueError)?);
    if plaintext.len() < offset { return Err(QueueError); }
    let recipient = PublicKey::from_slice(&plaintext[..32]).map_err(|_| QueueError)?;
    if recipient == sender { return Err(QueueError); }
    let identity = QueueIdentity { network, wallet_id: *wallet_id, slot: *slot, sender, recipient };
    Ok((identity, plaintext, offset))
}

/// A stable private slot for one wallet, slate and stage across all contacts.
///
/// The caller must parse the slate and authenticate the sender before using
/// this as an operation hint. The persisted operation must separately bind
/// and compare the authenticated sender and exact S1. This does not compare
/// content, persist a result, protect against rollback, or authorize payment.
/// The same slot must be reused after an indeterminate write, in one shared
/// wallet-level operation directory rather than separate contact directories.
pub fn payment_operation_slot(key: &QueueKey, identity: &QueueIdentity,
    slate_id: &[u8; 16], stage: PaymentStage) -> Result<[u8; 16], QueueError> {
    use hkdf::hmac::{Hmac, Mac};
    if slate_id.iter().all(|b| *b == 0) || identity.wallet_id.iter().all(|b| *b == 0)
        || identity.sender == identity.recipient {
        return Err(QueueError);
    }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    mac.update(b"GrinSight Fly payment operation slot v1\0");
    mac.update(&[identity.network.byte(), stage as u8]);
    mac.update(&identity.wallet_id);
    mac.update(slate_id);
    let digest = mac.finalize().into_bytes();
    let mut slot = [0u8; 16];
    slot.copy_from_slice(&digest[..16]);
    if slot.iter().all(|b| *b == 0) { return Err(QueueError); }
    Ok(slot)
}

/// Private deterministic transport slot for a reply to one Nostr envelope.
/// A rewrapped S1 has a different source ID and deliberately gets a new slot.
/// This is not a wallet transaction record, an identity proof, or an S2 gate.
pub fn incoming_event_reply_slot(key: &QueueKey, network: Network, wallet_id: &[u8;32],
    local_sender: PublicKey, source: &[u8;32]) -> Result<[u8;16], QueueError> {
    use hkdf::hmac::{Hmac, Mac};
    if wallet_id.iter().all(|b| *b == 0) || source.iter().all(|b| *b == 0) { return Err(QueueError); }
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    mac.update(b"GrinSight Fly incoming envelope reply slot v1\0");
    mac.update(&[network.byte()]); mac.update(wallet_id); mac.update(local_sender.as_bytes()); mac.update(source);
    let digest = mac.finalize().into_bytes();
    let mut slot = [0u8;16]; slot.copy_from_slice(&digest[..16]);
    if slot.iter().all(|b| *b == 0) { return Err(QueueError); }
    Ok(slot)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PaymentStage { Standard1 = 1, Standard2 = 2, Invoice1 = 3, Invoice2 = 4 }

fn request_digest(request: &str) -> Result<[u8; 32], QueueError> {
    use sha2::Digest;
    let text = request.trim();
    if protocol::extract_slatepack(text).as_deref() != Some(text) { return Err(QueueError); }
    Ok(Sha256::digest(text.as_bytes()).into())
}

/// Encrypt the exact S1 binding and the already-prepared reply as one record.
/// The sender, slate ID and S1 must have been authenticated and parsed by the
/// caller. This is storage only: it does not authorize receive or signing.
pub fn seal_bound_reply(key: &QueueKey, identity: &QueueIdentity, slate_id: &[u8; 16],
    request: &str, prepared: &PreparedMessage, now: u64) -> Result<Vec<u8>, QueueError> {
    if identity.slot != payment_operation_slot(key, identity, slate_id, PaymentStage::Standard1)? {
        return Err(QueueError);
    }
    let digest = request_digest(request)?;
    let inner = Zeroizing::new(seal(key, identity, prepared, now)?);
    let mut plaintext = Zeroizing::new(Vec::with_capacity(32 + inner.len()));
    plaintext.extend_from_slice(&digest);
    plaintext.extend_from_slice(&inner);
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| QueueError)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    let mut context = aad(identity);
    context.extend_from_slice(BOUND_REPLY_MAGIC);
    let encrypted = cipher.encrypt(XNonce::from_slice(&nonce),
        Payload { msg: &plaintext, aad: &context }).map_err(|_| QueueError)?;
    let mut record = Vec::with_capacity(8 + 24 + encrypted.len());
    record.extend_from_slice(BOUND_REPLY_MAGIC);
    record.extend_from_slice(&nonce);
    record.extend_from_slice(&encrypted);
    if record.len() > MAX_RECORD { return Err(QueueError); }
    Ok(record)
}

/// Reopen only for the original wallet, authenticated peer, slate ID and S1.
/// Unknown/corrupt/mismatched state must not be treated as a fresh operation.
pub fn open_bound_reply(key: &QueueKey, identity: &QueueIdentity, slate_id: &[u8; 16],
    request: &str, record: &[u8], now: u64) -> Result<PreparedMessage, QueueError> {
    let plaintext = decode_bound_reply(key, identity, slate_id, request, record)?;
    open(key, identity, &plaintext[32..], now)
}

pub(super) fn open_bound_metadata(key: &QueueKey, identity: &QueueIdentity, slate_id: &[u8; 16],
    request: &str, record: &[u8]) -> Result<OutgoingMetadata, QueueError> {
    let plaintext = decode_bound_reply(key, identity, slate_id, request, record)?;
    open_metadata(key, identity, &plaintext[32..])
}

fn decode_bound_reply(key: &QueueKey, identity: &QueueIdentity, slate_id: &[u8; 16],
    request: &str, record: &[u8]) -> Result<Zeroizing<Vec<u8>>, QueueError> {
    if record.len() < 8 + 24 + 32 + 16 || record.len() > MAX_RECORD
        || &record[..8] != BOUND_REPLY_MAGIC
        || identity.slot != payment_operation_slot(key, identity, slate_id, PaymentStage::Standard1)? {
        return Err(QueueError);
    }
    let digest = request_digest(request)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    let mut context = aad(identity);
    context.extend_from_slice(BOUND_REPLY_MAGIC);
    let plaintext = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&record[8..32]),
        Payload { msg: &record[32..], aad: &context }).map_err(|_| QueueError)?);
    if plaintext.len() < 32 || plaintext[..32] != digest { return Err(QueueError); }
    Ok(plaintext)
}

fn aad(identity: &QueueIdentity) -> Vec<u8> {
    let mut aad = Vec::with_capacity(8 + 1 + 32 * 3 + 16);
    aad.extend_from_slice(MAGIC);
    aad.push(identity.network.byte());
    aad.extend_from_slice(&identity.wallet_id);
    aad.extend_from_slice(&identity.slot);
    aad.extend_from_slice(identity.sender.as_bytes());
    aad.extend_from_slice(identity.recipient.as_bytes());
    aad
}

fn incoming_event_valid(event: &Event, identity: &QueueIdentity) -> bool {
    if event.kind != Kind::GiftWrap || event.content.len() > protocol::MAX_WRAP_CONTENT
        || event.id.as_bytes()[..16] != identity.slot { return false; }
    let count = event.tags.iter().filter(|tag| tag.as_slice().first().map(String::as_str) == Some("p")).count();
    let mut recipients = event.tags.public_keys();
    count == 1 && recipients.next() == Some(&identity.recipient) && recipients.next().is_none() && event.verify().is_ok()
}

// Caller has already authenticated the decrypted sender. This record keeps
// only the signed encrypted outer event; sender is rechecked when reopening.
pub(super) fn seal_incoming(key: &QueueKey, identity: &QueueIdentity, event: &Event) -> Result<Vec<u8>, QueueError> {
    if !incoming_event_valid(event, identity) { return Err(QueueError); }
    let json = Zeroizing::new(event.as_json());
    if json.len() > MAX_JSON { return Err(QueueError); }
    let mut nonce = [0u8; 24]; getrandom::getrandom(&mut nonce).map_err(|_| QueueError)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    let mut context = aad(identity); context.extend_from_slice(INBOX_MAGIC);
    let encrypted = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: json.as_bytes(), aad: &context }).map_err(|_| QueueError)?;
    let mut result = Vec::with_capacity(8 + 24 + encrypted.len());
    result.extend_from_slice(INBOX_MAGIC); result.extend_from_slice(&nonce); result.extend_from_slice(&encrypted);
    Ok(result)
}

pub(super) fn open_incoming(key: &QueueKey, identity: &QueueIdentity, bytes: &[u8]) -> Result<Event, QueueError> {
    if bytes.len() < 8 + 24 + 16 || bytes.len() > MAX_RECORD || &bytes[..8] != INBOX_MAGIC { return Err(QueueError); }
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    let mut context = aad(identity); context.extend_from_slice(INBOX_MAGIC);
    let json = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&bytes[8..32]), Payload { msg: &bytes[32..], aad: &context }).map_err(|_| QueueError)?);
    let event = Event::from_json(&*json).map_err(|_| QueueError)?;
    if !incoming_event_valid(&event, identity) { return Err(QueueError); }
    Ok(event)
}

pub(super) fn seal_ack(key: &QueueKey, identity: &QueueIdentity, event_id: &[u8; 32]) -> Result<Vec<u8>, QueueError> {
    let mut nonce = [0u8; 24]; getrandom::getrandom(&mut nonce).map_err(|_| QueueError)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    let mut context = aad(identity); context.extend_from_slice(ACK_MAGIC);
    let encrypted = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: event_id, aad: &context }).map_err(|_| QueueError)?;
    let mut record = Vec::with_capacity(8 + 24 + 32 + 16);
    record.extend_from_slice(ACK_MAGIC); record.extend_from_slice(&nonce); record.extend_from_slice(&encrypted);
    Ok(record)
}

pub(super) fn verify_ack(key: &QueueKey, identity: &QueueIdentity, record: &[u8], event_id: &[u8; 32]) -> Result<(), QueueError> {
    if record.len() != 8 + 24 + 32 + 16 || &record[..8] != ACK_MAGIC { return Err(QueueError); }
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    let mut context = aad(identity); context.extend_from_slice(ACK_MAGIC);
    let value = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&record[8..32]), Payload { msg: &record[32..], aad: &context }).map_err(|_| QueueError)?);
    if value.as_slice() != event_id { return Err(QueueError); }
    Ok(())
}

fn validate_shape(event: &Event, identity: &QueueIdentity) -> Result<u64, QueueError> {
    if event.kind != Kind::GiftWrap || event.content.len() > protocol::MAX_WRAP_CONTENT { return Err(QueueError); }
    event.verify().map_err(|_| QueueError)?;
    let count = |name: &str| event.tags.iter().filter(|tag| tag.as_slice().first().map(String::as_str) == Some(name)).count();
    if count("p") != 1 || count("expiration") != 1 { return Err(QueueError); }
    let mut recipients = event.tags.public_keys();
    if recipients.next() != Some(&identity.recipient) || recipients.next().is_some() { return Err(QueueError); }
    let expiry = event.tags.expiration().ok_or(QueueError)?.as_secs();
    Ok(expiry)
}

fn validate(event: &Event, identity: &QueueIdentity, now: u64) -> Result<u64, QueueError> {
    let expiry = validate_shape(event, identity)?;
    if expiry <= now || expiry > now.checked_add(MAX_DELIVERY_TTL).ok_or(QueueError)? { return Err(QueueError); }
    Ok(expiry)
}

/// Locally retained text only; it cannot be submitted as a network event.
pub struct OutgoingHistory {
    pub event_id: nostr_sdk::EventId,
    pub expires_at: u64,
    text: Zeroizing<String>,
}
impl OutgoingHistory { pub fn text(&self) -> &str { &self.text } }

/// Authenticated local record metadata; never a capability to send an event.
pub(super) struct OutgoingMetadata { pub event_id: nostr_sdk::EventId, pub expires_at: u64 }

/// Seal a prepared event before its first publication. The caller must persist
/// the returned bytes durably before publishing; this function does not do so.
pub fn seal(key: &QueueKey, identity: &QueueIdentity, prepared: &PreparedMessage, now: u64) -> Result<Vec<u8>, QueueError> {
    if prepared.sender != identity.sender || prepared.recipient != identity.recipient { return Err(QueueError); }
    let expiry = validate(&prepared.event, identity, now)?;
    if expiry != prepared.expires_at { return Err(QueueError); }
    let json = Zeroizing::new(prepared.event.as_json());
    if json.len() > MAX_JSON { return Err(QueueError); }
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|_| QueueError)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    let mut context = aad(identity);
    let magic = if prepared.local_history.is_some() { HISTORY_MAGIC } else { MAGIC };
    let plaintext = if let Some(history) = &prepared.local_history {
        if history.is_empty() || history.len() > protocol::MAX_RUMOR_CONTENT { return Err(QueueError); }
        context.extend_from_slice(HISTORY_MAGIC);
        let mut bytes = Zeroizing::new(Vec::with_capacity(8 + json.len() + history.len()));
        bytes.extend_from_slice(&(json.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&(history.len() as u32).to_be_bytes());
        bytes.extend_from_slice(json.as_bytes());
        bytes.extend_from_slice(history.as_bytes());
        bytes
    } else { Zeroizing::new(json.as_bytes().to_vec()) };
    let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &context }).map_err(|_| QueueError)?;
    let mut record = Vec::with_capacity(8 + 24 + ciphertext.len());
    record.extend_from_slice(magic); record.extend_from_slice(&nonce); record.extend_from_slice(&ciphertext);
    Ok(record)
}

/// Recover exactly the same signed event. A failed read does not authorize a new one.
pub fn open(key: &QueueKey, identity: &QueueIdentity, record: &[u8], now: u64) -> Result<PreparedMessage, QueueError> {
    let (event, local_history) = decode_event(key, identity, record)?;
    let expires_at = validate(&event, identity, now)?;
    Ok(PreparedMessage { event, sender: identity.sender, recipient: identity.recipient, expires_at, local_history })
}

fn decode_event(key: &QueueKey, identity: &QueueIdentity, record: &[u8]) -> Result<(Event, Option<Zeroizing<String>>), QueueError> {
    if record.len() < 8 + 24 + 16 || record.len() > MAX_RECORD { return Err(QueueError); }
    let history = &record[..8] == HISTORY_MAGIC;
    if !history && &record[..8] != MAGIC { return Err(QueueError); }
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| QueueError)?;
    let mut context = aad(identity); if history { context.extend_from_slice(HISTORY_MAGIC); }
    let plaintext = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&record[8..32]), Payload { msg: &record[32..], aad: &context }).map_err(|_| QueueError)?);
    let (json, retained) = if history {
        if plaintext.len() < 8 { return Err(QueueError); }
        let json_len = u32::from_be_bytes(plaintext[0..4].try_into().map_err(|_| QueueError)?) as usize;
        let text_len = u32::from_be_bytes(plaintext[4..8].try_into().map_err(|_| QueueError)?) as usize;
        let split = 8usize.checked_add(json_len).ok_or(QueueError)?;
        if json_len > MAX_JSON || text_len == 0 || text_len > protocol::MAX_RUMOR_CONTENT
            || split.checked_add(text_len) != Some(plaintext.len()) { return Err(QueueError); }
        let text = std::str::from_utf8(&plaintext[split..]).map_err(|_| QueueError)?;
        (&plaintext[8..split], Some(Zeroizing::new(text.to_owned())))
    } else {
        if plaintext.len() > MAX_JSON { return Err(QueueError); }
        (plaintext.as_slice(), None)
    };
    Ok((Event::from_json(json).map_err(|_| QueueError)?, retained))
}

pub(super) fn open_metadata(key: &QueueKey, identity: &QueueIdentity, record: &[u8]) -> Result<OutgoingMetadata, QueueError> {
    let (event, _retained) = decode_event(key, identity, record)?;
    let expires_at = validate_shape(&event, identity)?;
    Ok(OutgoingMetadata { event_id:event.id, expires_at })
}

/// Recover explicitly retained text after delivery expiry. This result cannot
/// be published, and does not claim relay acceptance or recipient delivery.
pub fn open_history(key: &QueueKey, identity: &QueueIdentity, record: &[u8]) -> Result<OutgoingHistory, QueueError> {
    let (event, text) = decode_event(key, identity, record)?;
    let expires_at = validate_shape(&event, identity)?;
    Ok(OutgoingHistory { event_id: event.id, expires_at, text: text.ok_or(QueueError)? })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::{EventBuilder, Keys, Tag, Timestamp};

    async fn fixture() -> (QueueIdentity, PreparedMessage) {
        let alice = Keys::generate(); let bob = Keys::generate();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot: [3; 16], sender: alice.public_key(), recipient: bob.public_key() };
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "FLY_SYNTHETIC_PLAINTEXT")
            .tag(Tag::public_key(bob.public_key())).build(alice.public_key());
        let event = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor, [Tag::expiration(Timestamp::from(1900))]).await.unwrap();
        let prepared = PreparedMessage { event, sender: identity.sender, recipient: identity.recipient, expires_at: 1900, local_history: None };
        (identity, prepared)
    }

    #[tokio::test]
    async fn recoverable_record_binds_wallet_slot_sender_and_encrypted_recipient() {
        let (identity, prepared) = fixture().await;
        let entropy = [0x41; 32];
        let key = QueueKey::derive_from_wallet_entropy(&entropy, &identity).unwrap();
        let recovered_key = QueueKey::derive_for_wallet_entropy(&entropy, identity.network, &identity.wallet_id).unwrap();
        let record = seal_recoverable(&key, &identity, &prepared, 1000).unwrap();
        assert!(!record.windows(32).any(|w| w == identity.recipient.as_bytes()));
        let (recovered, event) = open_recoverable(&recovered_key, identity.network, &identity.wallet_id,
            &identity.slot, identity.sender, &record, 1000).unwrap();
        assert_eq!(recovered.recipient, identity.recipient);
        assert_eq!(event.event.id, prepared.event.id);
        assert!(open_recoverable(&recovered_key, Network::Mainnet, &identity.wallet_id, &identity.slot, identity.sender, &record, 1000).is_err());
        assert!(open_recoverable(&recovered_key, identity.network, &[8; 32], &identity.slot, identity.sender, &record, 1000).is_err());
        assert!(open_recoverable(&recovered_key, identity.network, &identity.wallet_id, &[4; 16], identity.sender, &record, 1000).is_err());
        assert!(open_recoverable(&recovered_key, identity.network, &identity.wallet_id, &identity.slot, Keys::generate().public_key(), &record, 1000).is_err());
        assert!(open_recoverable(&recovered_key, identity.network, &identity.wallet_id, &identity.slot, identity.sender, &record, 1900).is_err());
        let mut damaged = record; *damaged.last_mut().unwrap() ^= 1;
        assert!(open_recoverable(&recovered_key, identity.network, &identity.wallet_id, &identity.slot, identity.sender, &damaged, 1000).is_err());
    }

    #[tokio::test]
    async fn correlated_reply_requires_original_event_and_preserves_old_formats() {
        let (identity, prepared) = fixture().await;
        let key = QueueKey::derive(&[9;32], &identity).unwrap();
        let source = [0x51;32];
        let slot = incoming_event_reply_slot(&key, identity.network, &identity.wallet_id, identity.sender, &source).unwrap();
        assert_eq!(slot, incoming_event_reply_slot(&key, identity.network, &identity.wallet_id, identity.sender, &source).unwrap());
        assert_ne!(slot, incoming_event_reply_slot(&key, identity.network, &identity.wallet_id, identity.sender, &[0x52;32]).unwrap());
        assert_ne!(slot, incoming_event_reply_slot(&key, Network::Mainnet, &identity.wallet_id, identity.sender, &source).unwrap());
        let record = seal_correlated_recoverable(&key, &identity, &prepared, 1000, &source).unwrap();
        assert!(!record.windows(32).any(|part| part == source));
        assert_eq!(open_correlated_recoverable(&key, identity.network, &identity.wallet_id, &identity.slot,
            identity.sender, &source, &record, 1000).unwrap().1.event.id, prepared.event.id);
        assert_eq!(open_recoverable(&key, identity.network, &identity.wallet_id, &identity.slot,
            identity.sender, &record, 1000).unwrap().1.event.id, prepared.event.id);
        assert!(open_correlated_recoverable(&key, identity.network, &identity.wallet_id, &identity.slot,
            identity.sender, &[0x52;32], &record, 1000).is_err());
        let old = seal_recoverable(&key, &identity, &prepared, 1000).unwrap();
        assert!(open_correlated_recoverable(&key, identity.network, &identity.wallet_id, &identity.slot,
            identity.sender, &source, &old, 1000).is_err());
        assert!(seal_correlated_recoverable(&key, &identity, &prepared, 1000, &[0;32]).is_err());
    }

    #[tokio::test]
    async fn payment_operation_slots_are_stable_across_contacts_and_bound_to_wallet_and_stage() {
        let (identity, _) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let slate_id = [10; 16];
        let first = payment_operation_slot(&key, &identity, &slate_id, PaymentStage::Standard1).unwrap();
        let mut different_transport_slot = identity;
        different_transport_slot.slot = [11; 16];
        assert_eq!(first, payment_operation_slot(&key, &different_transport_slot,
            &slate_id, PaymentStage::Standard1).unwrap());
        assert_ne!(first, payment_operation_slot(&key, &identity, &slate_id, PaymentStage::Standard2).unwrap());
        assert_ne!(first, payment_operation_slot(&key, &identity, &[12; 16], PaymentStage::Standard1).unwrap());
        let mut other = identity;
        other.recipient = Keys::generate().public_key();
        assert_eq!(first, payment_operation_slot(&key, &other, &slate_id, PaymentStage::Standard1).unwrap());
        other = identity;
        other.network = Network::Mainnet;
        assert_ne!(first, payment_operation_slot(&key, &other, &slate_id, PaymentStage::Standard1).unwrap());
        other = identity;
        other.wallet_id[0] ^= 1;
        assert_ne!(first, payment_operation_slot(&key, &other, &slate_id, PaymentStage::Standard1).unwrap());
        let other_key = QueueKey::derive(&[8; 32], &identity).unwrap();
        assert_ne!(first, payment_operation_slot(&other_key, &identity, &slate_id, PaymentStage::Standard1).unwrap());
        assert!(payment_operation_slot(&key, &identity, &[0; 16], PaymentStage::Standard1).is_err());
    }

    #[tokio::test]
    async fn bound_reply_refuses_modified_request_peer_and_storage_corruption() {
        let (mut identity, prepared) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let slate_id = [10; 16];
        identity.slot = payment_operation_slot(&key, &identity, &slate_id, PaymentStage::Standard1).unwrap();
        let request = "BEGINSLATEPACK. synthetic ENDSLATEPACK.";
        let record = seal_bound_reply(&key, &identity, &slate_id, request, &prepared, 1000).unwrap();
        assert!(!record.windows(request.len()).any(|window| window == request.as_bytes()));
        assert_eq!(open_bound_reply(&key, &identity, &slate_id, request, &record, 1000).unwrap().event.id,
            prepared.event.id);
        assert!(open_bound_reply(&key, &identity, &slate_id,
            "BEGINSLATEPACK. modified ENDSLATEPACK.", &record, 1000).is_err());
        assert!(open_bound_reply(&key, &identity, &[11; 16], request, &record, 1000).is_err());
        let mut other = identity;
        other.recipient = Keys::generate().public_key();
        assert!(open_bound_reply(&key, &other, &slate_id, request, &record, 1000).is_err());
        let mut corrupt = record.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(open_bound_reply(&key, &identity, &slate_id, request, &corrupt, 1000).is_err());
        assert!(open_bound_reply(&key, &identity, &slate_id, request, &record, 1900).is_err());
    }

    #[tokio::test]
    async fn offline_window_limit_is_enforced_by_the_record_codec() {
        let alice = Keys::generate();
        let bob = Keys::generate();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot: [3; 16],
            sender: alice.public_key(), recipient: bob.public_key() };
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        for (extra, valid) in [(MAX_DELIVERY_TTL, true), (MAX_DELIVERY_TTL + 1, false)] {
            let expiry = 1000 + extra;
            let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
                .tag(Tag::public_key(identity.recipient)).build(identity.sender);
            let event = EventBuilder::gift_wrap(&alice, &identity.recipient, rumor,
                [Tag::expiration(Timestamp::from(expiry))]).await.unwrap();
            let prepared = PreparedMessage { event, sender: identity.sender, recipient: identity.recipient,
                expires_at: expiry, local_history: None };
            let record = seal(&key, &identity, &prepared, 1000);
            assert_eq!(record.is_ok(), valid);
            if let Ok(record) = record {
                assert_eq!(open(&key, &identity, &record, 1000 + 3600).unwrap().event.id, prepared.event.id);
                assert!(open(&key, &identity, &record, expiry).is_err());
            }
        }
    }

    #[tokio::test]
    async fn encrypted_roundtrip_preserves_event_id_and_refuses_tampering() {
        let (identity, prepared) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let record = seal(&key, &identity, &prepared, 1000).unwrap();
        let other = seal(&key, &identity, &prepared, 1000).unwrap();
        assert_ne!(record, other);
        assert!(!record.windows(b"FLY_SYNTHETIC_PLAINTEXT".len()).any(|s| s == b"FLY_SYNTHETIC_PLAINTEXT"));
        assert!(!record.windows(32).any(|s| s == identity.recipient.as_bytes()));
        let recovered = open(&key, &identity, &record, 1000).unwrap();
        assert_eq!(recovered.event.id, prepared.event.id);
        assert_eq!(recovered.event.as_json(), prepared.event.as_json());
        for index in [0, 8, 31, record.len() - 1] {
            let mut corrupt = record.clone(); corrupt[index] ^= 1;
            assert!(open(&key, &identity, &corrupt, 1000).is_err());
        }
        for n in [0, 8, 31, record.len() - 1] { assert!(open(&key, &identity, &record[..n], 1000).is_err()); }
        assert!(open(&key, &identity, &record, 1900).is_err());
        assert!(open_history(&key, &identity, &record).is_err());
    }

    #[tokio::test]
    async fn optional_outgoing_history_survives_expiry_without_enabling_resend() {
        let (identity, mut prepared) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        prepared.local_history = Some(Zeroizing::new("FLY_SYNTHETIC_PLAINTEXT".to_owned()));
        let record = seal(&key, &identity, &prepared, 1000).unwrap();
        assert!(!record.windows(b"FLY_SYNTHETIC_PLAINTEXT".len()).any(|v| v == b"FLY_SYNTHETIC_PLAINTEXT"));
        assert_eq!(open(&key, &identity, &record, 1000).unwrap().event.id, prepared.event.id);
        assert!(open(&key, &identity, &record, 1900).is_err());
        let history = open_history(&key, &identity, &record).unwrap();
        assert_eq!(history.event_id, prepared.event.id);
        assert_eq!(history.expires_at, 1900);
        assert_eq!(history.text(), "FLY_SYNTHETIC_PLAINTEXT");
        let wrong_key = QueueKey::derive(&[8; 32], &identity).unwrap();
        assert!(open_history(&wrong_key, &identity, &record).is_err());
        let mut corrupt = record.clone(); let last = corrupt.len()-1; corrupt[last] ^= 1;
        assert!(open_history(&key, &identity, &corrupt).is_err());
    }

    #[tokio::test]
    async fn wrong_wallet_network_contact_or_key_is_rejected() {
        let (identity, prepared) = fixture().await;
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let record = seal(&key, &identity, &prepared, 1000).unwrap();
        let wrong_key = QueueKey::derive(&[8; 32], &identity).unwrap();
        assert!(open(&wrong_key, &identity, &record, 1000).is_err());
        let mut changed = identity; changed.network = Network::Mainnet;
        assert!(open(&key, &changed, &record, 1000).is_err());
        changed = identity; changed.wallet_id[0] ^= 1;
        assert!(open(&key, &changed, &record, 1000).is_err());
        changed = identity; changed.slot[0] ^= 1;
        assert!(open(&key, &changed, &record, 1000).is_err());
        changed = identity; changed.recipient = Keys::generate().public_key();
        assert!(open(&key, &changed, &record, 1000).is_err());
        assert!(seal(&key, &changed, &prepared, 1000).is_err());
        assert!(QueueKey::derive(&[0; 32], &identity).is_err());
    }

    #[tokio::test]
    async fn wallet_entropy_derives_stable_scoped_key_without_storing_entropy() {
        let (identity, prepared) = fixture().await;
        let seed = [0x42; 16];
        let first = QueueKey::derive_from_wallet_entropy(&seed, &identity).unwrap();
        let again = QueueKey::derive_from_wallet_entropy(&seed, &identity).unwrap();
        let record = seal(&first, &identity, &prepared, 1000).unwrap();
        assert_eq!(open(&again, &identity, &record, 1000).unwrap().event.id, prepared.event.id);
        assert!(!record.windows(seed.len()).any(|window| window == seed));
        let wrong = QueueKey::derive_from_wallet_entropy(&[0x43; 16], &identity).unwrap();
        assert!(open(&wrong, &identity, &record, 1000).is_err());
        assert!(QueueKey::derive_from_wallet_entropy(&[1; 15], &identity).is_err());
        let mut other = identity; other.wallet_id[0] ^= 1;
        let other_key = QueueKey::derive_from_wallet_entropy(&seed, &other).unwrap();
        assert!(open(&other_key, &identity, &record, 1000).is_err());
    }

    #[cfg(windows)]
    #[cfg(feature = "repo-linked-tests")]
    #[tokio::test]
    async fn vault_opened_synthetic_wallet_recovers_queue_key() {
        use fly_vault_research::{Network as VaultNetwork, WalletIdentity};
        let (identity, prepared) = fixture().await;
        let vault_id = WalletIdentity { network: VaultNetwork::Floonet, wallet_id: identity.wallet_id };
        let seed = Zeroizing::new([0x42u8; 16]);
        let container = fly_vault_research::seal(&*seed, "synthetic-password", &vault_id).unwrap();
        assert!(fly_vault_research::open(&container, "wrong-password", &vault_id).is_err());
        let unlocked = fly_vault_research::open(&container, "synthetic-password", &vault_id).unwrap();
        let key = QueueKey::derive_from_wallet_entropy(&unlocked, &identity).unwrap();
        let record = seal(&key, &identity, &prepared, 1000).unwrap();
        drop(key); drop(unlocked);
        let reopened = fly_vault_research::open(&container, "synthetic-password", &vault_id).unwrap();
        let key = QueueKey::derive_from_wallet_entropy(&reopened, &identity).unwrap();
        assert_eq!(open(&key, &identity, &record, 1000).unwrap().event.id, prepared.event.id);
    }
}
