//! Single-contact research session with experimental encrypted event storage.
//! It is not a production inbox, payment processor or user interface.
use std::{collections::{HashSet, VecDeque}, time::Duration};
use fly_tor::SharedTor;
use nostr_sdk::{Client, Event, EventId, EventBuilder, Filter, Keys, Kind, PublicKey, RelayMessage,
    SubscriptionId, Tag, Timestamp, UnsignedEvent, Url, pool::RelayPoolNotification};
use tokio::sync::broadcast;
use super::{protocol, tor_transport, verified_unwrap::unwrap_from_contact};

const MAX_WAIT: Duration = Duration::from_secs(120);
const DELIVERY_TTL_SECS: u64 = 15 * 60;
const MAX_PENDING: usize = 256;
const MAX_SEEN: usize = 4096;
// Research defaults. A budget must be shared across all inbox connections;
// it is not durable across process restarts and does not prevent starvation.
const MAX_UNKNOWN_OPENS: usize = 16;
const UNKNOWN_OPEN_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError { InvalidInput, Expired, ConnectionFailed, SubscriptionFailed, Timeout, Closed, EncryptionFailed, StorageUnavailable, StorageFull, StorageBusy, RateLimited }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Publication { RelayAccepted, Unknown }

/// Where a session leaves, for the user, how far it got and what the relay
/// answered. Empty when nothing is wrong. The relay's words are untrusted:
/// they are cut to plain printable characters and a short length, shown,
/// and never acted on.
pub type Note = std::sync::Mutex<String>;

/// After a relay asked for authentication, the subscription is sent again
/// after this pause, then after twice that, up to the limit, for as long as
/// the connection attempt lasts.
const AUTH_RESUBSCRIBE: Duration = Duration::from_millis(300);
const AUTH_RESUBSCRIBE_MAX: Duration = Duration::from_secs(3);

/// Longest part of a relay's own words kept in a [`Note`].
pub const MAX_RELAY_WORDS: usize = 120;

fn set_note(note: Option<&Note>, what: &str, relay_words: &str) {
    let Some(note) = note else { return };
    let mut text = String::from(what);
    if !relay_words.is_empty() {
        text.push_str(": ");
        text.extend(relay_words.chars().take(MAX_RELAY_WORDS)
            .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' }));
    }
    if let Ok(mut slot) = note.lock() { *slot = text; }
}

/// A create-only queue slot can be occupied even if the caller did not see a
/// successful return. Inspect that same slot; never choose another and resend.
#[cfg(any(windows, target_os = "linux", target_os = "android"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueWrite { Stored, Indeterminate }

/// Authenticated contact message. Tags and rumor ID are retained for later
/// protocol classification; neither they nor the outer ID authorize payments.
/// The IDs alone do not provide durable or cross-envelope replay protection.
#[derive(Clone)]
pub struct ReceivedMessage {
    envelope_id: EventId,
    sender: PublicKey,
    rumor: UnsignedEvent,
    event: Event,
}

impl ReceivedMessage {
    /// Whether the authenticated envelope may still be offered for delivery.
    /// Historical records remain readable after their delivery window.
    pub fn deliverable_at(&self, now: u64) -> bool {
        not_expired(&self.event, now) && tags_not_expired(&self.rumor.tags, now)
    }
    pub fn envelope_id(&self) -> EventId { self.envelope_id }
    pub fn sender(&self) -> PublicKey { self.sender }
    pub fn rumor(&self) -> &UnsignedEvent { &self.rumor }
    /// Deterministic research slot for this outer event; the file name leaks
    /// a truncated event identifier. Cross-envelope replays are not deduped.
    pub fn storage_slot(&self) -> [u8; 16] {
        let mut slot = [0u8; 16]; slot.copy_from_slice(&self.envelope_id.as_bytes()[..16]); slot
    }

    /// Inspect a single armor block only after the contact was authenticated.
    /// This never validates recipient, payment intent, S1/S2 correspondence,
    /// signatures in the slate, chain, or authorization to process it.
    #[cfg(feature = "slatepack-inspection-research")]
    pub fn inspect_slatepack(&self, network: fly_wallet::address::Network)
        -> Result<fly_wallet::slatepack_inspection_research::PacketInspection, fly_wallet::slatepack_inspection_research::InspectError> {
        let armor = protocol::extract_slatepack(&self.rumor.content)
            .ok_or(fly_wallet::slatepack_inspection_research::InspectError)?;
        fly_wallet::slatepack_inspection_research::inspect(&armor, network)
    }

    /// Check the authenticated message's S1 shape and addressed proof without
    /// signing. Entropy and height must come from native trusted profile/state;
    /// this helper cannot prove selected-chain status or authorize a response.
    #[cfg(feature = "slatepack-inspection-research")]
    pub fn preflight_standard_receive(&self, entropy: &[u8], network: fly_wallet::address::Network,
        minimum_amount: u64, observed_height: Option<u64>)
        -> Result<fly_wallet::slatepack_inspection_research::ReceivePreflight, fly_wallet::slatepack_inspection_research::InspectError> {
        let armor = zeroize::Zeroizing::new(protocol::extract_slatepack(&self.rumor.content)
            .ok_or(fly_wallet::slatepack_inspection_research::InspectError)?);
        fly_wallet::slatepack_inspection_research::preflight_standard_receive(
            &armor, entropy, network, minimum_amount, observed_height)
    }

    /// Extract one block only when this authenticated sender matches the
    /// wallet operation's pinned Nostr contact. The caller must then invoke
    /// wallet checks with the very same authenticated operation context.
    /// This does not authenticate the mapping to a Slatepack address, persist
    /// a selection, prevent replay or authorize a payment.
    #[cfg(feature = "slatepack-inspection-research")]
    pub fn slatepack_for_pinned_contact(&self, context: &fly_wallet::slatepack_inspection_research::ReplyContext)
        -> Result<String, fly_wallet::slatepack_inspection_research::InspectError> {
        if self.sender.as_bytes() != &context.pinned_contact {
            return Err(fly_wallet::slatepack_inspection_research::InspectError);
        }
        protocol::extract_slatepack(&self.rumor.content)
            .ok_or(fly_wallet::slatepack_inspection_research::InspectError)
    }

    /// Bind the authenticated message sender and the wallet's S2 checks to
    /// one borrowed context. This still does not authenticate the context,
    /// select a response durably, or authorize a signature or payment.
    #[cfg(feature = "slatepack-inspection-research")]
    pub fn fingerprint_standard_reply(&self, saved_s1: &str, entropy: &[u8],
        context: &fly_wallet::slatepack_inspection_research::ReplyContext)
        -> Result<fly_wallet::slatepack_inspection_research::ReplyFingerprint,
            fly_wallet::slatepack_inspection_research::InspectError> {
        let armor = zeroize::Zeroizing::new(self.slatepack_for_pinned_contact(context)?);
        fly_wallet::slatepack_inspection_research::fingerprint_encrypted_standard_reply(
            saved_s1, &armor, entropy, context)
    }
}

/// Created once and retained by the caller for an identical retry. It does not
/// contain plaintext; the encrypted event is not yet a persistent queue.
pub struct PreparedMessage {
    pub(super) event: Event,
    pub(super) sender: PublicKey,
    pub(super) recipient: PublicKey,
    pub(super) expires_at: u64,
    pub(super) local_history: Option<zeroize::Zeroizing<String>>,
}

pub struct ContactSession {
    client: Client,
    keys: Keys,
    contact: PublicKey,
    relay: Url,
    subscription: SubscriptionId,
    incoming: broadcast::Receiver<RelayPoolNotification>,
    pending: VecDeque<Event>,
    uncommitted: Option<ReceivedMessage>,
    seen: HashSet<EventId>,
    seen_order: VecDeque<EventId>,
}

/// Shared, in-memory cap on expensive opens. The application must retain one
/// instance for the entire process and pass clones to all inboxes. It is not a
/// cross-process or restart-resistant limit and cannot ensure fair delivery.
#[derive(Clone, Default)]
pub struct UnsolicitedBudget { times: std::sync::Arc<std::sync::Mutex<VecDeque<std::time::Instant>>> }

impl UnsolicitedBudget {
    pub fn new() -> Self { Self::default() }
    fn acquire(&self) -> Result<(), SessionError> {
        let mut times = self.times.lock().map_err(|_| SessionError::StorageUnavailable)?;
        let now = std::time::Instant::now();
        while times.front().is_some_and(|old| now.duration_since(*old) >= UNKNOWN_OPEN_WINDOW) { times.pop_front(); }
        if times.len() >= MAX_UNKNOWN_OPENS { return Err(SessionError::RateLimited); }
        times.push_back(now);
        Ok(())
    }
}

/// Experimental mailbox for unknown senders. Authentication establishes only
/// the Nostr key on each message, not identity or permission to process a
/// payment. Bounded in-memory replay filtering is not durable; the caller
/// must impose rate limits and explicitly handle the possibility of replay.
pub struct UnsolicitedInbox { inner: ContactSession, budget: UnsolicitedBudget }

impl UnsolicitedInbox {
    pub async fn connect(tor: SharedTor, keys: Keys, relay: &str, timeout: Duration, budget: UnsolicitedBudget) -> Result<Self, SessionError> {
        if !valid_timeout(timeout) { return Err(SessionError::InvalidInput); }
        let relay = Url::parse(relay).map_err(|_| SessionError::InvalidInput)?;
        tor_transport::destination(&relay, timeout).map_err(|_| SessionError::InvalidInput)?;
        let client = tor_transport::client(tor, keys.clone());
        Self::connect_client(client, keys, relay, timeout, budget).await
    }

    async fn connect_client(client: Client, keys: Keys, relay: Url, timeout: Duration, budget: UnsolicitedBudget) -> Result<Self, SessionError> {
        if !valid_timeout(timeout) { return Err(SessionError::InvalidInput); }
        let placeholder = keys.public_key();
        let inner = ContactSession::connect_client(client, keys, placeholder, relay, timeout).await?;
        Ok(Self { inner, budget })
    }

    /// Hold one message until the caller explicitly completes or discards it.
    /// No persistent wallet state or incoming operation is created here.
    pub async fn receive_pending(&mut self, timeout: Duration) -> Result<ReceivedMessage, SessionError> {
        self.inner.receive_pending_with_policy(timeout, Some(&self.budget)).await
    }

    /// Save a previously authorized and constructed reply before releasing
    /// the received envelope. The caller owns wallet authorization, must
    /// retain the same slot on uncertainty, and must not regenerate a response
    /// after Indeterminate. This does not store an S1 wallet operation, prove
    /// directory durability, protect against rollback, or authorize signing.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn persist_reply_then_complete(&mut self, outgoing: &ContactSession,
        dir: &std::path::Path, key: &super::queue_record::QueueKey,
        identity: &super::queue_record::QueueIdentity, reply: &str, delivery_window: Duration)
        -> Result<QueueWrite, SessionError> {
        let message = self.inner.uncommitted.as_ref().ok_or(SessionError::InvalidInput)?;
        if identity.sender != self.inner.keys.public_key() || identity.recipient != message.sender
            || outgoing.keys.public_key() != identity.sender || outgoing.contact != identity.recipient {
            return Err(SessionError::InvalidInput);
        }
        let id = message.envelope_id;
        let slot = super::queue_record::incoming_event_reply_slot(key, identity.network, &identity.wallet_id,
            identity.sender, id.as_bytes()).map_err(|_| SessionError::InvalidInput)?;
        if identity.slot != slot { return Err(SessionError::InvalidInput); }
        let prepared = outgoing.prepare_payment_for(reply, None, false, delivery_window).await?;
        match super::queue_store::persist_correlated_recoverable(dir, key, identity, &prepared,
            Timestamp::now().as_secs(), id.as_bytes()) {
            Ok(()) => {
                self.inner.acknowledge_received(id)?;
                Ok(QueueWrite::Stored)
            }
            Err(super::queue_store::StoreError::Indeterminate) => {
                if self.reconcile_pending_reply(dir, key, identity).is_ok() { Ok(QueueWrite::Stored) }
                else { Ok(QueueWrite::Indeterminate) }
            }
            Err(super::queue_store::StoreError::InvalidRecord) => Err(SessionError::InvalidInput),
            Err(super::queue_store::StoreError::BeforePublication) => Err(SessionError::StorageUnavailable),
            Err(super::queue_store::StoreError::Capacity) => Err(SessionError::StorageFull),
            Err(super::queue_store::StoreError::Busy) => Err(SessionError::StorageBusy),
        }
    }

    /// Resolve only an already stored reply to this exact authenticated event.
    /// Call before constructing a new S2 after an uncertain write. Failed or
    /// expired records leave the message pending and do not authorize signing.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub fn reconcile_pending_reply(&mut self, dir: &std::path::Path, key: &super::queue_record::QueueKey,
        identity: &super::queue_record::QueueIdentity) -> Result<(), SessionError> {
        let message = self.inner.uncommitted.as_ref().ok_or(SessionError::InvalidInput)?;
        if identity.sender != self.inner.keys.public_key() || identity.recipient != message.sender {
            return Err(SessionError::InvalidInput);
        }
        let id = message.envelope_id;
        let slot = super::queue_record::incoming_event_reply_slot(key, identity.network, &identity.wallet_id,
            identity.sender, id.as_bytes()).map_err(|_| SessionError::InvalidInput)?;
        if identity.slot != slot { return Err(SessionError::InvalidInput); }
        let now = Timestamp::now().as_secs();
        let load = || super::queue_store::load_correlated_recoverable(dir, key, identity.network,
            &identity.wallet_id, &identity.slot, identity.sender, id.as_bytes(), now);
        let (recovered, _) = match load() {
            Ok(record) => record,
            Err(_) => {
                super::queue_store::recover_correlated_stage(dir, key, identity, id.as_bytes(), now)
                    .map_err(|_| SessionError::StorageUnavailable)?;
                load().map_err(|_| SessionError::StorageUnavailable)?
            }
        };
        if recovered.recipient != message.sender { return Err(SessionError::StorageUnavailable); }
        self.inner.acknowledge_received(id)
    }

    /// Release the in-memory message; it can reappear after restart or in a
    /// different envelope. This does not assert payment or durable delivery.
    pub fn complete_or_discard(&mut self, id: EventId) -> Result<(), SessionError> {
        self.inner.acknowledge_received(id)
    }

    pub async fn close(self) { self.inner.close().await; }
}

fn valid_timeout(timeout: Duration) -> bool { !timeout.is_zero() && timeout <= MAX_WAIT }

// NIP-40 expiration is optional for interoperable messages. If supplied,
// refuse ambiguous/malformed or expired events even when a relay serves them.
// This is a delivery policy based on the local clock, not a guarantee that
// other relays have deleted the event or that the sender's clock was correct.
fn not_expired(event: &Event, now: u64) -> bool { tags_not_expired(&event.tags, now) }

fn tags_not_expired(tags: &nostr_sdk::Tags, now: u64) -> bool {
    let count = tags.iter().filter(|tag| tag.as_slice().first().map(String::as_str) == Some("expiration")).count();
    match count {
        0 => true,
        1 => tags.expiration().is_some_and(|timestamp| timestamp.as_secs() > now),
        _ => false,
    }
}

fn validate_publication(prepared: &PreparedMessage, sender: PublicKey, contact: PublicKey, now: u64, timeout: Duration)
    -> Result<(), SessionError> {
    if !valid_timeout(timeout) || prepared.sender != sender || prepared.recipient != contact {
        return Err(SessionError::InvalidInput);
    }
    if now >= prepared.expires_at { return Err(SessionError::Expired); }
    Ok(())
}

impl ContactSession {
    /// Contact identity must already be authenticated by the caller.
    pub async fn connect(tor: SharedTor, keys: Keys, contact: PublicKey, relay: &str, timeout: Duration)
        -> Result<Self, SessionError> {
        if !valid_timeout(timeout) || contact == keys.public_key() { return Err(SessionError::InvalidInput); }
        let relay = Url::parse(relay).map_err(|_| SessionError::InvalidInput)?;
        tor_transport::destination(&relay, timeout).map_err(|_| SessionError::InvalidInput)?;
        let client = tor_transport::client(tor, keys.clone());
        Self::connect_client(client, keys, contact, relay, timeout).await
    }

    /// [`ContactSession::connect`] that also leaves in `note` how far it
    /// got and what the relay said (see [`Note`]).
    pub async fn connect_noted(tor: SharedTor, keys: Keys, contact: PublicKey, relay: &str, timeout: Duration, note: &Note)
        -> Result<Self, SessionError> {
        if !valid_timeout(timeout) || contact == keys.public_key() { return Err(SessionError::InvalidInput); }
        let relay = Url::parse(relay).map_err(|_| SessionError::InvalidInput)?;
        tor_transport::destination(&relay, timeout).map_err(|_| SessionError::InvalidInput)?;
        let client = tor_transport::client(tor, keys.clone());
        Self::connect_client_noted(client, keys, contact, relay, timeout, Some(note)).await
    }

    /// Resolve an authenticated contact-book record before connecting. The
    /// book identity, directory and key must already come from a trusted
    /// unlocked profile; a stored Nostr key alone is not a person's identity.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn connect_saved(tor: SharedTor, keys: Keys, relay: &str, timeout: Duration,
        dir: &std::path::Path, book_key: &super::contact_book_research::BookKey,
        book: &super::contact_book_research::BookIdentity, slot: &[u8;16]) -> Result<Self, SessionError> {
        let relay = Url::parse(relay).map_err(|_| SessionError::InvalidInput)?;
        tor_transport::destination(&relay, timeout).map_err(|_| SessionError::InvalidInput)?;
        let client = tor_transport::client(tor, keys.clone());
        Self::connect_client_saved(client, keys, relay, timeout, dir, book_key, book, slot).await
    }

    /// Experimental Windows-only composition: unlock the profile inside Rust,
    /// then connect through Tor using a contact from its fixed contacts folder.
    /// Directory ancestry and wallet identity must be trusted by the caller.
    #[cfg(all(windows, feature = "windows-vault-queue-research", feature = "messaging-identity-research"))]
    pub async fn connect_saved_profile(tor: SharedTor, profile: &std::path::Path, password: &str,
        book: &super::contact_book_research::BookIdentity, slot: &[u8;16], relay: &str, timeout: Duration)
        -> Result<Self, SessionError> {
        let parsed=Url::parse(relay).map_err(|_|SessionError::InvalidInput)?;
        tor_transport::destination(&parsed,timeout).map_err(|_|SessionError::InvalidInput)?;
        let (keys,book_key)=super::windows_vault_queue_research::open_messaging_and_book_async(profile,password,book).await
            .map_err(|error|match error {
                super::windows_vault_queue_research::AsyncProfileError::Busy=>SessionError::StorageBusy,
                super::windows_vault_queue_research::AsyncProfileError::Unavailable=>SessionError::StorageUnavailable,
            })?;
        Self::connect_saved(tor,keys,relay,timeout,&profile.join("contacts"),&book_key,book,slot).await
    }

    /// Catalog-ID entry point for trusted native callers. It never accepts a
    /// contact directory from the UI; path ancestry must remain stable while
    /// the session is opened. No chain or payment authority is established.
    #[cfg(all(windows, feature = "windows-vault-queue-research", feature = "messaging-identity-research"))]
    pub async fn connect_catalog_contact(tor:SharedTor,catalog_root:&std::path::Path,profile_id:&str,password:&str,
        slot:&[u8;16],relay:&str,timeout:Duration)->Result<Self,SessionError> {
        let parsed=Url::parse(relay).map_err(|_|SessionError::InvalidInput)?;
        tor_transport::destination(&parsed,timeout).map_err(|_|SessionError::InvalidInput)?;
        let (profile,book)=super::windows_vault_queue_research::resolve_catalog_profile(catalog_root,profile_id)
            .map_err(|_|SessionError::StorageUnavailable)?;
        Self::connect_saved_profile(tor,&profile,password,&book,slot,relay,timeout).await
    }

    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    async fn connect_client_saved(client: Client, keys: Keys, relay: Url, timeout: Duration,
        dir: &std::path::Path, book_key: &super::contact_book_research::BookKey,
        book: &super::contact_book_research::BookIdentity, slot: &[u8;16]) -> Result<Self, SessionError> {
        if !valid_timeout(timeout) { return Err(SessionError::InvalidInput); }
        let contact = super::contact_book_research::read(dir, book_key, book, slot)
            .map_err(|_| SessionError::StorageUnavailable)?.public_key;
        if contact == keys.public_key() { return Err(SessionError::InvalidInput); }
        Self::connect_client(client, keys, contact, relay, timeout).await
    }

    async fn connect_client(client: Client, keys: Keys, contact: PublicKey, relay: Url, timeout: Duration)
        -> Result<Self, SessionError> {
        Self::connect_client_noted(client, keys, contact, relay, timeout, None).await
    }

    /// `connect_client` that also says, in `note`, how far it got and what
    /// the relay answered. A relay that closes the subscription asking for
    /// authentication (NIP-42) is not a failure yet: the client answers the
    /// challenge with the profile's key and sends the subscription again,
    /// so the wait goes on until the stored events end or the time is up.
    async fn connect_client_noted(client: Client, keys: Keys, contact: PublicKey, relay: Url, timeout: Duration,
        note: Option<&Note>) -> Result<Self, SessionError> {
        let mut incoming = client.notifications();
        client.add_relay(relay.clone()).await.map_err(|_| SessionError::ConnectionFailed)?;
        set_note(note, "connecting to the relay", "");
        tokio::time::timeout(timeout, client.try_connect_relay(relay.clone(), timeout)).await
            .map_err(|_| SessionError::Timeout)?.map_err(|_| SessionError::ConnectionFailed)?;
        set_note(note, "subscribing", "");
        let filter = Filter::new().kind(Kind::GiftWrap).pubkey(keys.public_key());
        let output = tokio::time::timeout(timeout, client.subscribe_to([relay.clone()], filter.clone(), None)).await
            .map_err(|_| SessionError::Timeout)?.map_err(|_| SessionError::SubscriptionFailed)?;
        if output.success.len() != 1 {
            set_note(note, "the relay did not take the subscription", output.failed.values().next().map_or("", String::as_str));
            return Err(SessionError::SubscriptionFailed);
        }
        set_note(note, "waiting for the relay's stored events", "");
        let subscription = output.val;
        let mut pending: VecDeque<Event> = VecDeque::new();
        // Set once the relay has asked for authentication: when to send the
        // subscription again, and the pause that led there. The client
        // answers the challenge by itself; whether it also repeats the
        // subscription is not relied on.
        let mut again: Option<(tokio::time::Instant, Duration)> = None;
        tokio::time::timeout(timeout, async {
            loop {
                let received = match again {
                    None => incoming.recv().await,
                    Some((at, pause)) => match tokio::time::timeout_at(at, incoming.recv()).await {
                        Ok(received) => received,
                        Err(_) => {
                            let next = pause.saturating_mul(2).min(AUTH_RESUBSCRIBE_MAX);
                            again = Some((tokio::time::Instant::now() + next, next));
                            // the relay starts over; so does the backlog
                            pending.clear();
                            let _ = client.subscribe_with_id_to([relay.clone()], subscription.clone(), filter.clone(), None).await;
                            continue;
                        }
                    },
                };
                match received.map_err(|_| SessionError::Closed)? {
                    RelayPoolNotification::Message { message: RelayMessage::EndOfStoredEvents(id), .. }
                        if id.as_ref() == &subscription => return Ok(()),
                    RelayPoolNotification::Message { message: RelayMessage::Event { subscription_id, event }, .. }
                        if subscription_id.as_ref() == &subscription => {
                        if !not_expired(&event, Timestamp::now().as_secs()) { continue; }
                        if pending.len() >= MAX_PENDING { return Err(SessionError::SubscriptionFailed); }
                        pending.push_back(event.into_owned());
                    },
                    RelayPoolNotification::Message { message: RelayMessage::Closed { subscription_id, message }, .. }
                        if subscription_id.as_ref() == &subscription => {
                        if message.starts_with("auth-required:") {
                            set_note(note, "the relay asked for authentication and has not reopened the subscription", &message);
                            if again.is_none() {
                                again = Some((tokio::time::Instant::now() + AUTH_RESUBSCRIBE, AUTH_RESUBSCRIBE));
                            }
                            continue;
                        }
                        set_note(note, "the relay closed the subscription", &message);
                        return Err(SessionError::SubscriptionFailed);
                    },
                    RelayPoolNotification::Shutdown => return Err(SessionError::Closed),
                    _ => (),
                }
            }
        }).await.map_err(|_| SessionError::Timeout)??;
        set_note(note, "", "");
        Ok(Self { client, keys, contact, relay, subscription, incoming, pending, uncommitted: None,
            seen: HashSet::new(), seen_order: VecDeque::new() })
    }

    /// Create an encrypted v2 envelope; no network request is made here.
    pub async fn prepare(&self, text: &str) -> Result<PreparedMessage, SessionError> {
        self.prepare_rumor(text, vec![], false).await
    }

    /// Opt in to retaining outgoing text encrypted in the same queue record.
    /// The caller must still persist the result before publication.
    pub async fn prepare_with_history(&self, text: &str) -> Result<PreparedMessage, SessionError> {
        self.prepare_rumor(text, vec![], true).await
    }

    /// Format a Goblin-compatible rumor around one supplied armor block.
    /// This checks only its textual framing, not slate validity, recipient,
    /// wallet authorization or replay safety. It performs no network I/O and
    /// must not be used to enable payments without those independent checks.
    pub async fn prepare_payment_rumor(&self, armor: &str, note: Option<&str>) -> Result<PreparedMessage, SessionError> {
        self.prepare_payment_rumor_with_retention(armor, note, false).await
    }

    /// Opt in to keeping the full payment-shaped content under local
    /// encryption. It still does not validate or authorize the Slatepack.
    pub async fn prepare_payment_rumor_with_history(&self, armor: &str, note: Option<&str>) -> Result<PreparedMessage, SessionError> {
        self.prepare_payment_rumor_with_retention(armor, note, true).await
    }

    async fn prepare_payment_rumor_with_retention(&self, armor: &str, note: Option<&str>, retain: bool) -> Result<PreparedMessage, SessionError> {
        self.prepare_payment_for(armor, note, retain, Duration::from_secs(DELIVERY_TTL_SECS)).await
    }

    /// Prepare one payment envelope for an explicitly bounded offline window.
    /// A relay may discard it earlier; this does not change the slate's cutoff.
    pub async fn prepare_payment_for(&self, armor: &str, note: Option<&str>, retain: bool,
        delivery_window: Duration) -> Result<PreparedMessage, SessionError> {
        let trimmed = armor.trim();
        if protocol::extract_slatepack(trimmed).as_deref() != Some(trimmed) { return Err(SessionError::InvalidInput); }
        let content = protocol::build_payment_content(trimmed);
        self.prepare_rumor_for(&content, protocol::build_rumor_tags(note), retain, delivery_window).await
    }

    /// Stage a payment-shaped rumor in the caller's create-only slot. This
    /// does not publish or validate the slate. An indeterminate outcome may
    /// mean the slot already contains an event, and must not trigger an
    /// automatic retry or a fresh slot. Directory durability and rollback
    /// remain caller responsibilities as in `queue_store`.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn prepare_payment_stored(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        armor: &str, note: Option<&str>) -> Result<QueueWrite, SessionError> {
        self.prepare_payment_stored_with_retention(dir, key, identity, armor, note, false).await
    }

    /// Store a payment-shaped message with opt-in encrypted local history.
    /// It is still not a validated transaction or a signing capability.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn prepare_payment_stored_with_history(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        armor: &str, note: Option<&str>) -> Result<QueueWrite, SessionError> {
        self.prepare_payment_stored_with_retention(dir, key, identity, armor, note, true).await
    }

    /// Persist the exact envelope for an explicit offline window before publishing.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn prepare_payment_stored_for(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        armor: &str, note: Option<&str>, retain: bool, delivery_window: Duration)
        -> Result<QueueWrite, SessionError> {
        self.persist_payment(dir, key, identity, armor, note, retain, delivery_window).await
    }

    /// Prepare one outgoing event whose recipient can be recovered after a
    /// restart without retaining an incoming payment request or contact entry.
    /// This does not authorize creation of a payment response.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn prepare_recoverable_payment(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        armor: &str, delivery_window: Duration) -> Result<QueueWrite, SessionError> {
        self.prepare_recoverable_payment_with_history(dir, key, identity, armor, false, delivery_window).await
    }

    /// Optionally keep the outgoing payment text encrypted for native recovery.
    /// It is not the sender's private signing context and does not authorize
    /// finalization or prove that the chain has accepted the payment.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn prepare_recoverable_payment_with_history(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        armor: &str, retain_history: bool, delivery_window: Duration) -> Result<QueueWrite, SessionError> {
        use super::queue_store::StoreError;
        if identity.sender != self.keys.public_key() || identity.recipient != self.contact { return Err(SessionError::InvalidInput); }
        let prepared = self.prepare_payment_for(armor, None, retain_history, delivery_window).await?;
        match super::queue_store::persist_recoverable(dir, key, identity, &prepared, Timestamp::now().as_secs()) {
            Ok(()) => Ok(QueueWrite::Stored),
            Err(StoreError::Indeterminate) => Ok(QueueWrite::Indeterminate),
            Err(StoreError::InvalidRecord) => Err(SessionError::InvalidInput),
            Err(StoreError::BeforePublication) => Err(SessionError::StorageUnavailable),
            Err(StoreError::Capacity) => Err(SessionError::StorageFull),
            Err(StoreError::Busy) => Err(SessionError::StorageBusy),
        }
    }

    /// Publish a previously recovered event, never regenerating it. An expired
    /// authenticated record returns Expired; damaged or missing state fails closed.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn publish_recoverable_payment(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, network: super::queue_record::Network,
        wallet_id: &[u8; 32], slot: &[u8; 16], timeout: Duration) -> Result<Publication, SessionError> {
        if !valid_timeout(timeout) { return Err(SessionError::InvalidInput); }
        let now = Timestamp::now().as_secs();
        let (identity, prepared) = match super::queue_store::load_recoverable(dir, key, network, wallet_id,
            slot, self.keys.public_key(), now) {
            Ok(record) => record,
            Err(_) => match super::queue_store::recoverable_status(dir, key, network, wallet_id, slot, self.keys.public_key(), now) {
                Ok((identity, super::queue_store::OutgoingStatus::RelayAccepted { delivery_window_expired: true }
                    | super::queue_store::OutgoingStatus::Unacknowledged { delivery_window_expired: true }))
                    if identity.recipient == self.contact => return Err(SessionError::Expired),
                _ => return Err(SessionError::StorageUnavailable),
            },
        };
        if identity.recipient != self.contact { return Err(SessionError::InvalidInput); }
        self.publish_loaded(dir, key, &identity, &prepared, timeout, false).await
    }

    /// Bind an already-generated reply to an authenticated S1 before sending.
    /// This helper is not a signing capability or proof of chain state.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn prepare_bound_reply(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        slate_id: &[u8; 16], request: &str, reply: &str, delivery_window: Duration)
        -> Result<QueueWrite, SessionError> {
        use super::queue_store::StoreError;
        if identity.sender != self.keys.public_key() || identity.recipient != self.contact {
            return Err(SessionError::InvalidInput);
        }
        let prepared = self.prepare_payment_for(reply, None, false, delivery_window).await?;
        match super::queue_store::persist_bound_reply(dir, key, identity, slate_id, request,
            &prepared, Timestamp::now().as_secs()) {
            Ok(()) => Ok(QueueWrite::Stored),
            Err(StoreError::Indeterminate) => Ok(QueueWrite::Indeterminate),
            Err(StoreError::InvalidRecord) => Err(SessionError::InvalidInput),
            Err(StoreError::BeforePublication) => Err(SessionError::StorageUnavailable),
            Err(StoreError::Capacity) => Err(SessionError::StorageFull),
            Err(StoreError::Busy) => Err(SessionError::StorageBusy),
        }
    }

    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    async fn prepare_payment_stored_with_retention(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        armor: &str, note: Option<&str>, retain: bool) -> Result<QueueWrite, SessionError> {
        self.persist_payment(dir, key, identity, armor, note, retain,
            Duration::from_secs(DELIVERY_TTL_SECS)).await
    }

    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    async fn persist_payment(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        armor: &str, note: Option<&str>, retain: bool, delivery_window: Duration)
        -> Result<QueueWrite, SessionError> {
        use super::queue_store::StoreError;
        if identity.sender != self.keys.public_key() || identity.recipient != self.contact {
            return Err(SessionError::InvalidInput);
        }
        let prepared = self.prepare_payment_for(armor, note, retain, delivery_window).await?;
        match super::queue_store::persist(dir, key, identity, &prepared, Timestamp::now().as_secs()) {
            Ok(()) => Ok(QueueWrite::Stored),
            Err(StoreError::Indeterminate) => Ok(QueueWrite::Indeterminate),
            Err(StoreError::InvalidRecord) => Err(SessionError::InvalidInput),
            Err(StoreError::BeforePublication) => Err(SessionError::StorageUnavailable),
            Err(StoreError::Capacity) => Err(SessionError::StorageFull),
            Err(StoreError::Busy) => Err(SessionError::StorageBusy),
        }
    }

    async fn prepare_rumor(&self, text: &str, tags: Vec<Tag>, retain_history: bool) -> Result<PreparedMessage, SessionError> {
        self.prepare_rumor_for(text, tags, retain_history, Duration::from_secs(DELIVERY_TTL_SECS)).await
    }

    async fn prepare_rumor_for(&self, text: &str, tags: Vec<Tag>, retain_history: bool,
        delivery_window: Duration) -> Result<PreparedMessage, SessionError> {
        if text.is_empty() || text.len() > protocol::MAX_RUMOR_CONTENT { return Err(SessionError::InvalidInput); }
        if delivery_window.subsec_nanos() != 0 || delivery_window.is_zero()
            || delivery_window.as_secs() > super::queue_record::MAX_DELIVERY_TTL {
            return Err(SessionError::InvalidInput);
        }
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, text)
            .tag(Tag::public_key(self.contact)).tags(tags).build(self.keys.public_key());
        let expiry = Timestamp::now().as_secs().checked_add(delivery_window.as_secs()).ok_or(SessionError::InvalidInput)?;
        let event = EventBuilder::gift_wrap(&self.keys, &self.contact, rumor, [Tag::expiration(Timestamp::from(expiry))])
            .await.map_err(|_| SessionError::EncryptionFailed)?;
        if event.content.len() > protocol::MAX_WRAP_CONTENT { return Err(SessionError::InvalidInput); }
        Ok(PreparedMessage { event, sender: self.keys.public_key(), recipient: self.contact, expires_at: expiry,
            local_history: retain_history.then(|| zeroize::Zeroizing::new(text.to_owned())) })
    }

    /// Acknowledgement means acceptance by this relay, not delivery to a user.
    /// Unknown covers all send errors and timeouts: the caller must retain the
    /// same prepared envelope when retrying.
    async fn publish(&self, prepared: &PreparedMessage, timeout: Duration) -> Result<Publication, SessionError> {
        let now = Timestamp::now().as_secs();
        validate_publication(prepared, self.keys.public_key(), self.contact, now, timeout)?;
        let bounded = timeout.min(Duration::from_secs(prepared.expires_at - now));
        let result = tokio::time::timeout(bounded, self.client.send_event_to([self.relay.clone()], &prepared.event)).await;
        Ok(match result { Ok(Ok(output)) if output.success.len() == 1 => Publication::RelayAccepted, _ => Publication::Unknown })
    }

    /// Reloads and authenticates the same create-only record before each send.
    /// The caller must provision a stable trusted directory and storage key.
    /// This does not guarantee directory durability or rollback resistance.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn publish_stored(&self, dir: &std::path::Path, key: &super::queue_record::QueueKey,
        identity: &super::queue_record::QueueIdentity, timeout: Duration) -> Result<Publication, SessionError> {
        if identity.sender != self.keys.public_key() || identity.recipient != self.contact || !valid_timeout(timeout) {
            return Err(SessionError::InvalidInput);
        }
        let now = Timestamp::now().as_secs();
        let prepared = match super::queue_store::load(dir, key, identity, now) {
            Ok(prepared) => prepared,
            Err(_) => match super::queue_store::outgoing_status(dir, key, identity, now) {
                Ok(super::queue_store::OutgoingStatus::RelayAccepted { delivery_window_expired: true }
                    | super::queue_store::OutgoingStatus::Unacknowledged { delivery_window_expired: true })
                    => return Err(SessionError::Expired),
                _ => return Err(SessionError::StorageUnavailable),
            },
        };
        self.publish_loaded(dir, key, identity, &prepared, timeout, false).await
    }

    /// Retry the same persisted signed event after an uncertain relay response.
    /// Cancellation leaves the queue untouched and can be resumed after restart.
    /// Relay acceptance does not establish receipt by the counterparty.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn retry_stored(&self, dir: &std::path::Path, key: &super::queue_record::QueueKey,
        identity: &super::queue_record::QueueIdentity, timeout: Duration,
        delay: Duration, max_attempts: u8) -> Result<Publication, SessionError> {
        if max_attempts == 0 || max_attempts > 16 || delay.is_zero()
            || delay > Duration::from_secs(600) || !valid_timeout(timeout) {
            return Err(SessionError::InvalidInput);
        }
        for attempt in 0..max_attempts {
            match self.publish_stored(dir, key, identity, timeout).await? {
                Publication::RelayAccepted => return Ok(Publication::RelayAccepted),
                Publication::Unknown if attempt + 1 < max_attempts => tokio::time::sleep(delay).await,
                Publication::Unknown => return Ok(Publication::Unknown),
            }
        }
        Err(SessionError::InvalidInput)
    }

    /// Publish only the reply bound to the exact authenticated original S1.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn publish_bound_reply(&self, dir: &std::path::Path, key: &super::queue_record::QueueKey,
        identity: &super::queue_record::QueueIdentity, slate_id: &[u8; 16], request: &str,
        timeout: Duration) -> Result<Publication, SessionError> {
        if identity.sender != self.keys.public_key() || identity.recipient != self.contact || !valid_timeout(timeout) {
            return Err(SessionError::InvalidInput);
        }
        let now = Timestamp::now().as_secs();
        let prepared = match super::queue_store::load_bound_reply(dir, key, identity, slate_id, request, now) {
            Ok(prepared) => prepared,
            Err(_) => match super::queue_store::bound_reply_status(dir, key, identity, slate_id, request, now) {
                Ok(super::queue_store::OutgoingStatus::RelayAccepted { delivery_window_expired: true }
                    | super::queue_store::OutgoingStatus::Unacknowledged { delivery_window_expired: true })
                    => return Err(SessionError::Expired),
                _ => return Err(SessionError::StorageUnavailable),
            },
        };
        self.publish_loaded(dir, key, identity, &prepared, timeout, false).await
    }

    /// Retry only the persisted reply that matches the original request.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn retry_bound_reply(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        slate_id: &[u8; 16], request: &str, timeout: Duration, delay: Duration,
        max_attempts: u8) -> Result<Publication, SessionError> {
        if max_attempts == 0 || max_attempts > 16 || delay.is_zero()
            || delay > Duration::from_secs(600) || !valid_timeout(timeout) {
            return Err(SessionError::InvalidInput);
        }
        for attempt in 0..max_attempts {
            match self.publish_bound_reply(dir, key, identity, slate_id, request, timeout).await? {
                Publication::RelayAccepted => return Ok(Publication::RelayAccepted),
                Publication::Unknown if attempt + 1 < max_attempts => tokio::time::sleep(delay).await,
                Publication::Unknown => return Ok(Publication::Unknown),
            }
        }
        Err(SessionError::InvalidInput)
    }

    /// Explicitly send the same stored event to this session's relay even when
    /// another relay acknowledged it. Sharing an event across relays makes
    /// the event ID linkable; callers choose whether redundancy is acceptable.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn publish_stored_redundantly(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        timeout: Duration) -> Result<Publication, SessionError> {
        if identity.sender != self.keys.public_key() || identity.recipient != self.contact || !valid_timeout(timeout) {
            return Err(SessionError::InvalidInput);
        }
        let now = Timestamp::now().as_secs();
        let prepared = match super::queue_store::load(dir, key, identity, now) {
            Ok(prepared) => prepared,
            Err(_) => match super::queue_store::outgoing_status(dir, key, identity, now) {
                Ok(super::queue_store::OutgoingStatus::RelayAccepted { delivery_window_expired: true }
                    | super::queue_store::OutgoingStatus::Unacknowledged { delivery_window_expired: true })
                    => return Err(SessionError::Expired),
                _ => return Err(SessionError::StorageUnavailable),
            },
        };
        self.publish_loaded(dir, key, identity, &prepared, timeout, true).await
    }

    /// Explicit redundant send of the S1-bound reply, after authenticating it.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn publish_bound_reply_redundantly(&self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity,
        slate_id: &[u8; 16], request: &str, timeout: Duration) -> Result<Publication, SessionError> {
        if identity.sender != self.keys.public_key() || identity.recipient != self.contact || !valid_timeout(timeout) {
            return Err(SessionError::InvalidInput);
        }
        let now = Timestamp::now().as_secs();
        let prepared = match super::queue_store::load_bound_reply(dir, key, identity, slate_id, request, now) {
            Ok(prepared) => prepared,
            Err(_) => match super::queue_store::bound_reply_status(dir, key, identity, slate_id, request, now) {
                Ok(super::queue_store::OutgoingStatus::RelayAccepted { delivery_window_expired: true }
                    | super::queue_store::OutgoingStatus::Unacknowledged { delivery_window_expired: true })
                    => return Err(SessionError::Expired),
                _ => return Err(SessionError::StorageUnavailable),
            },
        };
        self.publish_loaded(dir, key, identity, &prepared, timeout, true).await
    }

    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    async fn publish_loaded(&self, dir: &std::path::Path, key: &super::queue_record::QueueKey,
        identity: &super::queue_record::QueueIdentity, prepared: &PreparedMessage,
        timeout: Duration, resend_acknowledged: bool) -> Result<Publication, SessionError> {
        match super::queue_store::acknowledged(dir, key, identity, &prepared) {
            Ok(true) if !resend_acknowledged => return Ok(Publication::RelayAccepted),
            Ok(_) => (),
            Err(_) => return Err(SessionError::StorageUnavailable),
        }
        match self.publish(&prepared, timeout).await? {
            Publication::Unknown => Ok(Publication::Unknown),
            Publication::RelayAccepted => {
                if super::queue_store::mark_acknowledged(dir, key, identity, &prepared).is_ok() {
                    Ok(Publication::RelayAccepted)
                } else {
                    // The relay may have accepted the event. Do not report
                    // durable acknowledgement if its marker failed to commit.
                    Ok(Publication::Unknown)
                }
            }
        }
    }

    /// Convenience for text-only experiments. This immediately acknowledges in
    /// memory and must not be used to process or persist incoming payments.
    pub async fn receive(&mut self, timeout: Duration) -> Result<String, SessionError> {
        Ok(self.receive_message(timeout).await?.rumor.content)
    }

    /// Text-only convenience; immediately acknowledges in memory. Payment
    /// processing must use `receive_pending` and durably store before ack.
    pub async fn receive_message(&mut self, timeout: Duration) -> Result<ReceivedMessage, SessionError> {
        let message = self.receive_pending(timeout).await?;
        self.acknowledge_received(message.envelope_id)?;
        Ok(message)
    }

    /// Return one authenticated message repeatedly until explicitly acked.
    /// The caller must first durably store it and its processing identity. This
    /// in-memory retry is not persistence, exactly-once delivery, anti-rollback
    /// or permission to sign. A relay may delete an event while disconnected.
    pub async fn receive_pending(&mut self, timeout: Duration) -> Result<ReceivedMessage, SessionError> {
        self.receive_pending_with_policy(timeout, None).await
    }

    async fn receive_pending_with_policy(&mut self, timeout: Duration, budget: Option<&UnsolicitedBudget>) -> Result<ReceivedMessage, SessionError> {
        if !valid_timeout(timeout) { return Err(SessionError::InvalidInput); }
        if let Some(message) = &self.uncommitted { return Ok(message.clone()); }
        tokio::time::timeout(timeout, async {
            loop {
                // Do not remove an event across an await: cancellation while
                // decrypting must leave it available for another attempt.
                if let Some(event) = self.pending.front().cloned() {
                    if let Some(budget) = budget { budget.acquire()?; }
                    let message = self.accept_event_with_policy(&event, budget.is_some()).await;
                    self.pending.pop_front();
                    if let Some(message) = message {
                        self.uncommitted = Some(message.clone());
                        return Ok(message);
                    }
                    continue;
                }
                match self.incoming.recv().await.map_err(|_| SessionError::Closed)? {
                    RelayPoolNotification::Message { message: RelayMessage::Event { subscription_id, event }, .. }
                        if subscription_id.as_ref() == &self.subscription => {
                        self.pending.push_back(event.into_owned());
                    },
                    RelayPoolNotification::Message { message: RelayMessage::Closed { subscription_id, .. }, .. }
                        if subscription_id.as_ref() == &self.subscription => return Err(SessionError::SubscriptionFailed),
                    RelayPoolNotification::Shutdown => return Err(SessionError::Closed),
                    _ => (),
                }
            }
        }).await.map_err(|_| SessionError::Timeout)?
    }

    #[cfg(test)]
    async fn accept_event(&mut self, event: &Event) -> Option<ReceivedMessage> {
        self.accept_event_with_policy(event, false).await
    }

    async fn accept_event_with_policy(&mut self, event: &Event, unknown_sender: bool) -> Option<ReceivedMessage> {
        if self.seen.contains(&event.id) || !not_expired(event, Timestamp::now().as_secs()) { return None; }
        let opened = if unknown_sender {
            super::verified_unwrap::unwrap_verified_sender(&self.keys, event).await.ok()?
        } else { unwrap_from_contact(&self.keys, event, &self.contact).await.ok()? };
        // a deadline the sender put inside the sealed part (see `seal_payment`)
        if !tags_not_expired(&opened.rumor.tags, Timestamp::now().as_secs()) { return None; }
        Some(ReceivedMessage { envelope_id: event.id, sender: opened.sender, rumor: opened.rumor, event: event.clone() })
    }

    /// Create-only encrypted inbox record; does not automatically acknowledge.
    /// An indeterminate result requires inspection of the same slot. This is
    /// not a durable-directory, rollback-resistant or production inbox.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub fn persist_pending(&self, dir: &std::path::Path, key: &super::queue_record::QueueKey,
        identity: &super::queue_record::QueueIdentity) -> Result<QueueWrite, SessionError> {
        use super::queue_store::StoreError;
        let message = self.uncommitted.as_ref().ok_or(SessionError::InvalidInput)?;
        if identity.sender != self.contact || identity.recipient != self.keys.public_key()
            || identity.slot != message.storage_slot() { return Err(SessionError::InvalidInput); }
        match super::queue_store::persist_incoming(dir, key, identity, &message.event) {
            Ok(()) => Ok(QueueWrite::Stored),
            Err(StoreError::Indeterminate) => Ok(QueueWrite::Indeterminate),
            Err(StoreError::InvalidRecord) => Err(SessionError::InvalidInput),
            Err(StoreError::BeforePublication) => Err(SessionError::StorageUnavailable),
            Err(StoreError::Capacity) => Err(SessionError::StorageFull),
            Err(StoreError::Busy) => Err(SessionError::StorageBusy),
        }
    }

    /// Persist the current authenticated event before acknowledging it in
    /// memory. An uncertain write must leave the same event pending so the
    /// caller can inspect its slot; it must not be treated as a fresh message.
    /// This does not prove directory durability, processing completion or
    /// protection against rollback, and does not authorize a payment.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub fn persist_pending_and_acknowledge(&mut self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity)
        -> Result<QueueWrite, SessionError> {
        let id = self.uncommitted.as_ref().ok_or(SessionError::InvalidInput)?.envelope_id;
        match self.persist_pending(dir, key, identity)? {
            QueueWrite::Stored => {
                self.acknowledge_received(id)?;
                Ok(QueueWrite::Stored)
            }
            QueueWrite::Indeterminate => Ok(QueueWrite::Indeterminate),
        }
    }

    /// Resolve an uncertain inbox create by reopening the same slot and
    /// reauthenticating the complete event ID, recipient and pinned sender.
    /// A missing/corrupt record leaves the current message pending. This is
    /// only an in-memory acknowledgement after readback, not proof of durable
    /// directory metadata, completed payment processing or anti-rollback.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn reconcile_pending_and_acknowledge(&mut self, dir: &std::path::Path,
        key: &super::queue_record::QueueKey, identity: &super::queue_record::QueueIdentity)
        -> Result<(), SessionError> {
        let expected = self.uncommitted.as_ref().ok_or(SessionError::InvalidInput)?.envelope_id;
        self.restore_received(dir, key, identity, expected).await?;
        self.acknowledge_received(expected)
    }

    /// Re-authenticate a saved outer event and pinned sender. The full expected
    /// ID prevents accepting a collision in the truncated on-disk slot. An
    /// already-received message remains readable after its relay expiry.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn restore_received(&self, dir: &std::path::Path, key: &super::queue_record::QueueKey,
        identity: &super::queue_record::QueueIdentity, expected: EventId) -> Result<ReceivedMessage, SessionError> {
        if identity.slot != expected.as_bytes()[..16] { return Err(SessionError::InvalidInput); }
        let restored = self.restore_discovered(dir, key, identity).await?;
        if restored.envelope_id != expected { return Err(SessionError::StorageUnavailable); }
        Ok(restored)
    }

    /// Reopen a discovered slot without a pre-existing full event ID. The ID,
    /// encrypted record, recipient and pinned sender are all reauthenticated;
    /// this still does not prove completeness or protect against rollback.
    #[cfg(any(windows, target_os = "linux", target_os = "android"))]
    pub async fn restore_discovered(&self, dir: &std::path::Path, key: &super::queue_record::QueueKey,
        identity: &super::queue_record::QueueIdentity) -> Result<ReceivedMessage, SessionError> {
        if identity.sender != self.contact || identity.recipient != self.keys.public_key() { return Err(SessionError::InvalidInput); }
        let event = super::queue_store::load_incoming(dir, key, identity).map_err(|_| SessionError::StorageUnavailable)?;
        let opened = unwrap_from_contact(&self.keys, &event, &self.contact).await.map_err(|_| SessionError::StorageUnavailable)?;
        Ok(ReceivedMessage { envelope_id: event.id, sender: opened.sender, rumor: opened.rumor, event })
    }

    /// Call only after the exact message has been committed to durable storage.
    /// This API cannot verify that commitment or prevent storage rollback.
    pub fn acknowledge_received(&mut self, id: EventId) -> Result<(), SessionError> {
        if self.uncommitted.as_ref().map(|message| message.envelope_id) != Some(id) {
            return Err(SessionError::InvalidInput);
        }
        self.uncommitted = None;
        if self.seen.len() == MAX_SEEN {
            if let Some(oldest) = self.seen_order.pop_front() { self.seen.remove(&oldest); }
        }
        self.seen.insert(id);
        self.seen_order.push_back(id);
        Ok(())
    }

    pub async fn close(self) { self.client.unsubscribe(&self.subscription).await; self.client.disconnect().await; }
}

// ---- GrinSight Fly v0.2: envelopes kept by the payment core ---------------
// Added in the core-v0.2 working copy on 2026-11-21; nothing above is changed.
// The payment core stores the sealed envelope in its own journal, in the same
// frame as the payment and its reserve, and hands back the exact bytes for
// every publication. These entry points give it that without the file queue.

/// Largest envelope accepted for publication, as JSON text.
pub const MAX_ENVELOPE_JSON: usize = 128 * 1024;

impl PreparedMessage {
    /// What the caller keeps: the event id, the gift wrap as JSON and the
    /// delivery deadline in Unix seconds. Contains no plaintext.
    pub fn envelope(&self) -> ([u8; 32], String, u64) {
        use nostr_sdk::JsonUtil;
        (*self.event.id.as_bytes(), self.event.as_json(), self.expires_at)
    }
}

/// Seal one payment message for `contact` using keys only: no session, no
/// relay and no network. The same checks as `prepare_payment_for`; nothing is
/// stored here, the caller must make the result durable before publishing it.
///
/// The gift wrap carries nothing but its addressee, like any private message:
/// relays that refuse an expiration on gift wraps take it, and it does not
/// stand out among other wallets' messages. The delivery deadline is inside
/// the sealed part, where only the recipient reads it, and in what the
/// caller keeps ([`PreparedMessage::envelope`]). A relay therefore does not
/// drop the message when the deadline passes; the recipient does.
pub async fn seal_payment(keys: &Keys, contact: PublicKey, armor: &str, note: Option<&str>,
    delivery_window: Duration) -> Result<PreparedMessage, SessionError> {
    if contact == keys.public_key() { return Err(SessionError::InvalidInput); }
    let trimmed = armor.trim();
    if protocol::extract_slatepack(trimmed).as_deref() != Some(trimmed) { return Err(SessionError::InvalidInput); }
    let content = protocol::build_payment_content(trimmed);
    if content.is_empty() || content.len() > protocol::MAX_RUMOR_CONTENT { return Err(SessionError::InvalidInput); }
    if delivery_window.subsec_nanos() != 0 || delivery_window.is_zero()
        || delivery_window.as_secs() > super::queue_record::MAX_DELIVERY_TTL {
        return Err(SessionError::InvalidInput);
    }
    let expiry = Timestamp::now().as_secs().checked_add(delivery_window.as_secs()).ok_or(SessionError::InvalidInput)?;
    let rumor = EventBuilder::new(Kind::PrivateDirectMessage, content)
        .tag(Tag::public_key(contact)).tags(protocol::build_rumor_tags(note))
        .tag(Tag::expiration(Timestamp::from(expiry))).build(keys.public_key());
    let event = EventBuilder::gift_wrap(keys, &contact, rumor, [])
        .await.map_err(|_| SessionError::EncryptionFailed)?;
    if event.content.len() > protocol::MAX_WRAP_CONTENT { return Err(SessionError::InvalidInput); }
    Ok(PreparedMessage { event, sender: keys.public_key(), recipient: contact, expires_at: expiry, local_history: None })
}

/// Checks on an envelope read back from the caller's storage before it is
/// sent: a correctly signed gift wrap of bounded size that carries its one
/// addressee, this contact, and nothing else.
pub fn checked_envelope(envelope_json: &str, contact: PublicKey) -> Result<Event, SessionError> {
    use nostr_sdk::JsonUtil;
    if envelope_json.len() > MAX_ENVELOPE_JSON { return Err(SessionError::InvalidInput); }
    let event = Event::from_json(envelope_json).map_err(|_| SessionError::InvalidInput)?;
    if event.kind != Kind::GiftWrap || event.content.len() > protocol::MAX_WRAP_CONTENT || event.verify().is_err() {
        return Err(SessionError::InvalidInput);
    }
    if event.tags.len() != 1 || event.tags.public_keys().next() != Some(&contact) { return Err(SessionError::InvalidInput); }
    Ok(event)
}

impl ContactSession {
    /// Publish an envelope the caller stored, byte for byte: the event is
    /// parsed and checked, never rebuilt, so every retry carries the same
    /// event id. `RelayAccepted` means acceptance by this relay, not delivery
    /// and not payment; `Unknown` covers every send error and timeout.
    pub async fn publish_envelope(&self, envelope_json: &str, deadline: u64, timeout: Duration) -> Result<Publication, SessionError> {
        self.publish_envelope_noted(envelope_json, deadline, timeout, None).await
    }

    /// `deadline` (Unix seconds) is the one the caller kept with the
    /// envelope; the envelope itself does not show it.
    ///
    /// [`ContactSession::publish_envelope`] that also leaves in `note` why
    /// the relay did not accept: its own answer, or that there was none.
    pub async fn publish_envelope_noted(&self, envelope_json: &str, deadline: u64, timeout: Duration, note: Option<&Note>)
        -> Result<Publication, SessionError> {
        if !valid_timeout(timeout) { return Err(SessionError::InvalidInput); }
        let event = checked_envelope(envelope_json, self.contact)?;
        let now = Timestamp::now().as_secs();
        if now >= deadline { return Err(SessionError::Expired); }
        let bounded = timeout.min(Duration::from_secs(deadline - now));
        let result = tokio::time::timeout(bounded, self.client.send_event_to([self.relay.clone()], &event)).await;
        Ok(match result {
            Ok(Ok(output)) if output.success.len() == 1 => { set_note(note, "", ""); Publication::RelayAccepted },
            Ok(Ok(output)) => {
                set_note(note, "the relay did not accept the message", output.failed.values().next().map_or("", String::as_str));
                Publication::Unknown
            },
            Ok(Err(_)) => { set_note(note, "the message could not be sent to the relay", ""); Publication::Unknown },
            Err(_) => { set_note(note, "the relay did not answer in time", ""); Publication::Unknown },
        })
    }

    /// The contact this session talks to.
    pub fn contact(&self) -> PublicKey { self.contact }

    /// A session without Tor to a relay on this machine: `ws://` and a
    /// numeric loopback address, nothing else. Exists only with the feature
    /// "loopback-testing"; it cannot be pointed at the network.
    #[cfg(feature = "loopback-testing")]
    pub async fn connect_loopback(keys: Keys, contact: PublicKey, relay: &str, timeout: Duration)
        -> Result<Self, SessionError> {
        if !valid_timeout(timeout) || contact == keys.public_key() { return Err(SessionError::InvalidInput); }
        let relay = Url::parse(relay).map_err(|_| SessionError::InvalidInput)?;
        let loopback = relay.host_str().and_then(|h| h.parse::<std::net::IpAddr>().ok()).is_some_and(|ip| ip.is_loopback());
        if relay.scheme() != "ws" || !loopback { return Err(SessionError::InvalidInput); }
        let client = nostr_sdk::ClientBuilder::new().build();
        Self::connect_client(client, keys, contact, relay, timeout).await
    }

    /// [`ContactSession::connect_loopback`] with the client built as the
    /// product builds it (it signs with the profile's key, so it can answer
    /// a relay's authentication challenge) and with a [`Note`].
    #[cfg(feature = "loopback-testing")]
    pub async fn connect_loopback_noted(keys: Keys, contact: PublicKey, relay: &str, timeout: Duration, note: &Note)
        -> Result<Self, SessionError> {
        if !valid_timeout(timeout) || contact == keys.public_key() { return Err(SessionError::InvalidInput); }
        let relay = Url::parse(relay).map_err(|_| SessionError::InvalidInput)?;
        let loopback = relay.host_str().and_then(|h| h.parse::<std::net::IpAddr>().ok()).is_some_and(|ip| ip.is_loopback());
        if relay.scheme() != "ws" || !loopback { return Err(SessionError::InvalidInput); }
        let client = nostr_sdk::ClientBuilder::new().signer(keys.clone()).build();
        Self::connect_client_noted(client, keys, contact, relay, timeout, Some(note)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fmt, pin::Pin, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}, task::{Context, Poll}};
    use async_wsocket::{ConnectionMode, Message};
    use futures_util::Sink;
    use nostr_sdk::{ClientBuilder, ClientMessage, JsonUtil, nostr::util::BoxedFuture,
        pool::transport::{error::TransportError, websocket::{WebSocketSink, WebSocketStream, WebSocketTransport}}};
    use tokio::sync::mpsc::{self, UnboundedSender};

    #[derive(Clone, Default)]
    struct FakeRelay {
        backlog: Vec<Event>,
        published: Arc<Mutex<Vec<String>>>,
        published_events: Arc<Mutex<Vec<String>>>,
        acknowledge: Arc<AtomicBool>,
    }
    impl fmt::Debug for FakeRelay { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("FakeRelay") } }
    struct FakeSink { relay: FakeRelay, tx: UnboundedSender<Message> }
    impl Sink<Message> for FakeSink {
        type Error = TransportError;
        fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { Poll::Ready(Ok(())) }
        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            if let Message::Text(text) = item {
                match ClientMessage::from_json(&text) {
                    Ok(ClientMessage::Req { subscription_id, .. }) => {
                        for event in &self.relay.backlog {
                            let json = format!("[\"EVENT\",\"{}\",{}]", subscription_id, event.as_json());
                            self.tx.send(Message::Text(json)).unwrap();
                        }
                        self.tx.send(Message::Text(format!("[\"EOSE\",\"{}\"]", subscription_id))).unwrap();
                    },
                    Ok(ClientMessage::Event(event)) => {
                        self.relay.published.lock().unwrap().push(event.id.to_string());
                        self.relay.published_events.lock().unwrap().push(event.as_json());
                        if self.relay.acknowledge.load(Ordering::SeqCst) {
                            self.tx.send(Message::Text(format!("[\"OK\",\"{}\",true,\"\"]", event.id))).unwrap();
                        }
                    },
                    _ => (),
                }
            }
            Ok(())
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { Poll::Ready(Ok(())) }
        fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { Poll::Ready(Ok(())) }
    }
    impl WebSocketTransport for FakeRelay {
        fn support_ping(&self) -> bool { false }
        fn connect<'a>(&'a self, _: &'a Url, _: &'a ConnectionMode, _: Duration)
            -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), TransportError>> {
            Box::pin(async move {
                let (tx, rx) = mpsc::unbounded_channel();
                let sink: WebSocketSink = Box::new(FakeSink { relay: self.clone(), tx });
                let stream: WebSocketStream = Box::pin(futures_util::stream::unfold(rx, |mut rx| async {
                    rx.recv().await.map(|message| (Ok(message), rx))
                }));
                Ok((sink, stream))
            })
        }
    }
    #[cfg(windows)]
    async fn chain_loopback_relay() -> (Url, tokio::task::JoinHandle<()>, Arc<Mutex<Vec<String>>>, Arc<AtomicBool>, Arc<Mutex<Vec<Event>>>) {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as WireMessage;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap(); assert!(address.ip().is_loopback());
        let events = Arc::new(Mutex::new(Vec::<String>::new()));
        let acknowledge = Arc::new(AtomicBool::new(false));
        let stored: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
        let task_events = events.clone(); let task_ack = acknowledge.clone(); let task_stored = stored.clone();
        let server = tokio::spawn(async move {
            loop {
                let (socket, peer) = listener.accept().await.unwrap(); assert!(peer.ip().is_loopback());
                let stored = task_stored.clone(); let events = task_events.clone(); let ack = task_ack.clone();
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else { return; };
                    while let Some(Ok(frame)) = ws.next().await {
                        let WireMessage::Text(text) = frame else { continue; };
                        match ClientMessage::from_json(text.as_str()) {
                            Ok(ClientMessage::Req { subscription_id, .. }) => {
                                let backlog = stored.lock().unwrap().clone();
                                for event in backlog {
                                    let msg = format!("[\"EVENT\",\"{}\",{}]", subscription_id, event.as_json());
                                    if ws.send(WireMessage::Text(msg.into())).await.is_err() { return; }
                                }
                                if ws.send(WireMessage::Text(format!("[\"EOSE\",\"{}\"]", subscription_id).into())).await.is_err() { return; }
                            }
                            Ok(ClientMessage::Event(event)) => {
                                if event.verify().is_err() { return; }
                                events.lock().unwrap().push(event.as_json());
                                { let mut saved = stored.lock().unwrap();
                                  if !saved.iter().any(|item| item.id == event.id) { saved.push(event.as_ref().clone()); } }
                                if ack.load(Ordering::SeqCst) {
                                    let msg = format!("[\"OK\",\"{}\",true,\"\"]", event.id);
                                    if ws.send(WireMessage::Text(msg.into())).await.is_err() { return; }
                                }
                            }
                            _ => (),
                        }
                    }
                });
            }
        });
        (Url::parse(&format!("ws://{address}")).unwrap(), server, events, acknowledge, stored)
    }
    // Invoked only by the isolated chain fixture. Loopback and test keys only.
    // This is a test bridge, not an application API or a signing authority.
    #[cfg(windows)]
    #[tokio::test]
    async fn chain_transport_child() {
        if std::env::var_os("FLY_CHAIN_TRANSPORT_CHILD").is_none() { return; }
        use std::io::{Read, Write};
        use super::super::queue_record::{Network, QueueIdentity, QueueKey};
        let mut armor = String::new();
        std::io::stdin().take(1_000_001).read_to_string(&mut armor).unwrap();
        assert!(armor.len() <= 1_000_000);
        let one = Keys::parse("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let two = Keys::parse("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        let reverse = std::env::var_os("FLY_CHAIN_TRANSPORT_REVERSE").is_some();
        let (sender, receiver) = if reverse { (two, one) } else { (one, two) };
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-chain-relay-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let mut identity = QueueIdentity { network: Network::Floonet, wallet_id: [1;32], slot: [2;16],
            sender: sender.public_key(), recipient: receiver.public_key() };
        let decode_hex = |s: &str| -> Vec<u8> {
            assert!(s.is_ascii() && s.len() % 2 == 0);
            (0..s.len()).step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
        };
        let journal_mode = std::env::var("FLY_TEST_JOURNAL_MODE").ok();
        if journal_mode.is_some() {
            assert!(!reverse);
            identity.slot = decode_hex(&std::env::var("FLY_TEST_JOURNAL_SLOT").unwrap()).try_into().unwrap();
        }
        let key = QueueKey::derive(&[3;32], &identity).unwrap();
        let (url, server, events, ack, stored) = chain_loopback_relay().await;
        let mut incoming = if reverse {
            let encoded = std::env::var("FLY_CHAIN_ORIGINAL_EVENT").unwrap();
            assert!(encoded.len() <= 60_000 && encoded.len() % 2 == 0);
            let bytes: Vec<u8> = encoded.as_bytes().chunks_exact(2).map(|pair| {
                let digit = |b:u8| match b { b'0'..=b'9' => b-b'0', b'a'..=b'f' => b-b'a'+10, _ => panic!("bad synthetic event") };
                digit(pair[0]) * 16 + digit(pair[1])
            }).collect();
            let source = Event::from_json(&bytes).unwrap(); source.verify().unwrap();
            identity.slot = super::super::queue_record::incoming_event_reply_slot(&key, identity.network,
                &identity.wallet_id, identity.sender, source.id.as_bytes()).unwrap();
            stored.lock().unwrap().push(source.clone());
            let client = ClientBuilder::new().build();
            let mut inbox = UnsolicitedInbox::connect_client(client, sender.clone(), url.clone(),
                Duration::from_secs(3), UnsolicitedBudget::new()).await.unwrap();
            let pending = inbox.receive_pending(Duration::from_secs(3)).await.unwrap();
            assert_eq!(pending.envelope_id(), source.id); assert_eq!(pending.sender(), receiver.public_key());
            Some(inbox)
        } else { None };
        let client = ClientBuilder::new().build();
        let session = ContactSession::connect_client(client, sender.clone(), receiver.public_key(),
            url.clone(), Duration::from_secs(3)).await.unwrap();
        let now = Timestamp::now().as_secs();
        let recovered = match journal_mode.as_deref() {
            Some("seal") => {
                let prepared = session.prepare_payment_for(&armor, None, true, Duration::from_secs(3600)).await.unwrap();
                let bytes = super::super::queue_record::seal_recoverable(&key, &identity, &prepared, now).unwrap();
                let encoded: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
                writeln!(std::io::stdout(), "FLY_SEALED={encoded}").unwrap();
                writeln!(std::io::stdout(), "FLY_EVENT_ID={}", prepared.event.id).unwrap();
                assert!(events.lock().unwrap().is_empty());
                session.close().await;
                server.abort();
                return;
            }
            Some("replay") => {
                let bytes = decode_hex(armor.trim());
                let (peer, saved) = super::super::queue_record::open_recoverable(&key, identity.network,
                    &identity.wallet_id, &identity.slot, identity.sender, &bytes, now).unwrap();
                assert_eq!(peer.recipient, identity.recipient);
                let (_, history) = super::super::queue_record::open_recoverable_history(&key, identity.network,
                    &identity.wallet_id, &identity.slot, identity.sender, &bytes).unwrap();
                armor = protocol::extract_slatepack(history.text()).unwrap();
                assert_eq!(history.event_id, saved.event.id);
                Some((saved, bytes))
            }
            None => None,
            _ => panic!("unknown fixture mode"),
        };
        if reverse {
            let inbox = incoming.as_mut().unwrap();
            assert_eq!(inbox.persist_reply_then_complete(&session, &dir, &key, &identity, &armor,
                Duration::from_secs(3600)).await, Ok(QueueWrite::Stored));
            assert_eq!(session.publish_recoverable_payment(&dir, &key, identity.network, &identity.wallet_id,
                &identity.slot, Duration::from_millis(100)).await, Ok(Publication::Unknown));
        } else {
            if let Some((_, bytes)) = &recovered {
                for _ in 0..2 {
                    super::super::queue_store::restore_committed_outgoing(&dir, &key, &identity, bytes, now).unwrap();
                }
            } else {
                assert_eq!(session.prepare_recoverable_payment_with_history(&dir, &key, &identity, &armor, true,
                    Duration::from_secs(3600)).await, Ok(QueueWrite::Stored));
            }
            assert_eq!(session.publish_recoverable_payment(&dir, &key, identity.network, &identity.wallet_id,
                &identity.slot, Duration::from_millis(100)).await,
                Ok(Publication::Unknown));
        }
        session.close().await;
        if let Some(inbox) = incoming { inbox.close().await; }
        if reverse {
            let client = ClientBuilder::new().build();
            let mut reopened = UnsolicitedInbox::connect_client(client, sender.clone(), url.clone(),
                Duration::from_secs(3), UnsolicitedBudget::new()).await.unwrap();
            let pending = reopened.receive_pending(Duration::from_secs(3)).await.unwrap();
            assert_eq!(pending.sender(), receiver.public_key());
            reopened.reconcile_pending_reply(&dir, &key, &identity).unwrap();
            reopened.close().await;
        }
        let client = ClientBuilder::new().build();
        let session = ContactSession::connect_client(client, sender.clone(), receiver.public_key(),
            url.clone(), Duration::from_secs(3)).await.unwrap();
        ack.store(true, Ordering::SeqCst);
        if reverse {
            let (recovered, _) = super::super::queue_store::load_recoverable(&dir, &key, identity.network,
                &identity.wallet_id, &identity.slot, sender.public_key(), Timestamp::now().as_secs()).unwrap();
            assert_eq!(recovered.recipient, receiver.public_key());
            assert_eq!(session.publish_recoverable_payment(&dir, &key, identity.network, &identity.wallet_id,
                &identity.slot, Duration::from_secs(3)).await, Ok(Publication::RelayAccepted));
        } else {
            let (_, history) = super::super::queue_store::load_recoverable_history(&dir, &key, identity.network,
                &identity.wallet_id, &identity.slot, sender.public_key()).unwrap();
            assert_eq!(protocol::extract_slatepack(history.text()).as_deref(), Some(armor.trim()));
            assert_eq!(session.publish_recoverable_payment(&dir, &key, identity.network, &identity.wallet_id,
                &identity.slot, Duration::from_secs(3)).await,
                Ok(Publication::RelayAccepted));
        }
        session.close().await;
        let sent = events.lock().unwrap().clone();
        assert_eq!(sent.len(), 2);
        let event = Event::from_json(&sent[0]).unwrap();
        if let Some(exe) = std::env::var_os("FLY_TEST_GOBLIN_EXE") {
            use std::process::{Command, Stdio};
            let mut child = Command::new(exe)
                .args(["--exact", "chain_slatepack_interop_peer", "--nocapture"])
                .env("FLY_TEST_GOBLIN_DIRECTION", if reverse { "s2" } else { "s1" })
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
            child.stdin.take().unwrap().write_all(event.as_json().as_bytes()).unwrap();
            let result = child.wait_with_output().unwrap();
            assert!(result.status.success(), "interop peer failed");
            let output = std::str::from_utf8(&result.stdout).unwrap();
            let encoded = output.split_whitespace().find_map(|word| word.strip_prefix("FLY_GOBLIN_EVENT=")).unwrap();
            let other = Event::from_json(decode_hex(encoded)).unwrap();
            let opened = super::super::verified_unwrap::unwrap_from_contact(&receiver, &other,
                &sender.public_key()).await.unwrap();
            assert!(protocol::extract_slatepack(&opened.rumor.content).as_deref() == Some(armor.trim()));
        }
        if let Some((saved, _)) = recovered {
            assert_eq!(saved.event.id, event.id);
            writeln!(std::io::stdout(), "FLY_EVENT_ID={}", event.id).unwrap();
        }
        assert_eq!(event.id, Event::from_json(&sent[1]).unwrap().id);
        let client = ClientBuilder::new().build();
        let received = if reverse {
            let mut session = ContactSession::connect_client(client, receiver, sender.public_key(),
                url.clone(), Duration::from_secs(3)).await.unwrap();
            let message = session.receive_pending(Duration::from_secs(3)).await.unwrap();
            session.close().await;
            message
        } else {
            let mut inbox = UnsolicitedInbox::connect_client(client, receiver,
                url, Duration::from_secs(3), UnsolicitedBudget::new()).await.unwrap();
            let message = inbox.receive_pending(Duration::from_secs(3)).await.unwrap();
            assert_eq!(message.sender(), sender.public_key());
            #[cfg(feature = "slatepack-inspection-research")]
            {
                let preflight = message.preflight_standard_receive(&[0x42;32], fly_wallet::address::Network::Floonet, 1, None).unwrap();
                assert!(preflight.amount > 0);
            }
            inbox.complete_or_discard(message.envelope_id()).unwrap();
            inbox.close().await;
            message
        };
        let received_armor = protocol::extract_slatepack(&received.rumor().content).unwrap();
        assert_eq!(received_armor, armor.trim());
        let encoded: String = received_armor.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        if !reverse {
            let source = event.as_json();
            let encoded_source: String = source.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
            writeln!(std::io::stdout(), "FLY_SOURCE_EVENT={encoded_source}").unwrap();
        }
        server.abort();
        writeln!(std::io::stdout(), "FLY_SYNTHETIC_SPACK={encoded}").unwrap();
    }
    #[tokio::test]
    async fn prepared_envelope_rejects_expiry_identity_and_bad_timeouts() {
        let alice = Keys::generate(); let bob = Keys::generate(); let other = Keys::generate();
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
            .tag(Tag::public_key(bob.public_key())).build(alice.public_key());
        let event = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor, [Tag::expiration(Timestamp::from(100))]).await.unwrap();
        let prepared = PreparedMessage { event, sender: alice.public_key(), recipient: bob.public_key(), expires_at: 100, local_history: None };
        let wait = Duration::from_secs(1);
        assert_eq!(validate_publication(&prepared, alice.public_key(), bob.public_key(), 99, wait), Ok(()));
        assert_eq!(validate_publication(&prepared, alice.public_key(), bob.public_key(), 100, wait), Err(SessionError::Expired));
        assert_eq!(validate_publication(&prepared, other.public_key(), bob.public_key(), 99, wait), Err(SessionError::InvalidInput));
        assert_eq!(validate_publication(&prepared, alice.public_key(), other.public_key(), 99, wait), Err(SessionError::InvalidInput));
        assert_eq!(validate_publication(&prepared, alice.public_key(), bob.public_key(), 99, Duration::ZERO), Err(SessionError::InvalidInput));
    }

    #[tokio::test]
    async fn backlog_before_eose_survives_and_filters_other_senders() {
        let alice = Keys::generate(); let bob = Keys::generate(); let mallory = Keys::generate();
        let make = |sender: &Keys, text: &str| {
            super::super::wrapv3::wrap(sender, &bob.public_key(), text.to_owned(), vec![]).unwrap()
        };
        let relay = FakeRelay { backlog: vec![make(&mallory, "unknown"), make(&alice, "known")], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert_eq!(session.receive(Duration::from_secs(3)).await, Ok("known".to_owned()));
        session.close().await;
    }

    #[tokio::test]
    async fn local_websocket_relay_stores_and_delivers_to_later_client() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as WireMessage;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        assert!(address.ip().is_loopback());
        let stored: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
        let relay_store = stored.clone();
        let server = tokio::spawn(async move {
            loop {
                let (socket, peer) = listener.accept().await.unwrap();
                assert!(peer.ip().is_loopback());
                let relay_store = relay_store.clone();
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(socket).await else { return; };
                    while let Some(Ok(frame)) = ws.next().await {
                        let WireMessage::Text(text) = frame else { continue; };
                        match ClientMessage::from_json(text.as_str()) {
                            Ok(ClientMessage::Req { subscription_id, .. }) => {
                                let events = relay_store.lock().unwrap().clone();
                                for event in events {
                                    let msg = format!("[\"EVENT\",\"{}\",{}]", subscription_id, event.as_json());
                                    if ws.send(WireMessage::Text(msg.into())).await.is_err() { return; }
                                }
                                let msg = format!("[\"EOSE\",\"{}\"]", subscription_id);
                                if ws.send(WireMessage::Text(msg.into())).await.is_err() { return; }
                            }
                            Ok(ClientMessage::Event(event)) => {
                                if event.verify().is_err() { return; }
                                { let mut events = relay_store.lock().unwrap();
                                  if !events.iter().any(|saved| saved.id == event.id) { events.push(event.as_ref().clone()); } }
                                let msg = format!("[\"OK\",\"{}\",true,\"\"]", event.id);
                                if ws.send(WireMessage::Text(msg.into())).await.is_err() { return; }
                            }
                            _ => (),
                        }
                    }
                });
            }
        });
        let alice = Keys::generate(); let bob = Keys::generate();
        let url = Url::parse(&format!("ws://{address}")).unwrap();
        let client = ClientBuilder::new().build();
        let sender = ContactSession::connect_client(client, alice.clone(), bob.public_key(), url.clone(), Duration::from_secs(5)).await.unwrap();
        let prepared = sender.prepare("synthetic local relay only").await.unwrap();
        assert_eq!(sender.publish(&prepared, Duration::from_secs(5)).await, Ok(Publication::RelayAccepted));
        sender.close().await;
        let client = ClientBuilder::new().build();
        let mut recipient = ContactSession::connect_client(client, bob, alice.public_key(), url, Duration::from_secs(5)).await.unwrap();
        assert_eq!(recipient.receive(Duration::from_secs(5)).await.unwrap(), "synthetic local relay only");
        assert_eq!(stored.lock().unwrap().len(), 1);
        recipient.close().await;
        server.abort();
    }

    #[tokio::test]
    async fn unsolicited_mailbox_authenticates_each_sender_and_bounds_replay() {
        let alice = Keys::generate(); let bob = Keys::generate(); let carol = Keys::generate(); let outsider = Keys::generate();
        let first = super::super::wrapv3::wrap(&alice, &bob.public_key(), "request one".into(), vec![]).unwrap();
        let second = super::super::wrapv3::wrap(&carol, &bob.public_key(), "request two".into(), vec![]).unwrap();
        let unrelated = super::super::wrapv3::wrap(&alice, &outsider.public_key(), "wrong recipient".into(), vec![]).unwrap();
        let mut forged = second.clone(); forged.created_at = Timestamp::from(0);
        let relay = FakeRelay { backlog: vec![unrelated, forged, first.clone(), first, second], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut inbox = UnsolicitedInbox::connect_client(client, bob, Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3), UnsolicitedBudget::new()).await.unwrap();
        let a = inbox.receive_pending(Duration::from_secs(3)).await.unwrap();
        assert_eq!(a.sender(), alice.public_key());
        assert_eq!(inbox.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), a.envelope_id());
        assert_eq!(inbox.complete_or_discard(EventId::from_hex(&"00".repeat(32)).unwrap()), Err(SessionError::InvalidInput));
        inbox.complete_or_discard(a.envelope_id()).unwrap();
        let b = inbox.receive_pending(Duration::from_secs(3)).await.unwrap();
        assert_eq!(b.sender(), carol.public_key());
        inbox.complete_or_discard(b.envelope_id()).unwrap();
        assert!(matches!(inbox.receive_pending(Duration::from_millis(100)).await, Err(SessionError::Timeout)));
        inbox.close().await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn unsolicited_reply_is_saved_before_incoming_message_is_released() {
        use super::super::queue_record::{Network, QueueIdentity, QueueKey};
        let alice = Keys::generate(); let bob = Keys::generate(); let carol = Keys::generate();
        let first = super::super::wrapv3::wrap(&alice, &bob.public_key(), "first".into(), vec![]).unwrap();
        let second = super::super::wrapv3::wrap(&alice, &bob.public_key(), "second".into(), vec![]).unwrap();
        let client = ClientBuilder::new().websocket_transport(FakeRelay { backlog:vec![first.clone(),second.clone()], ..Default::default() }).build();
        let mut inbox = UnsolicitedInbox::connect_client(client, bob.clone(), Url::parse("wss://relay.example").unwrap(),
            Duration::from_secs(3), UnsolicitedBudget::new()).await.unwrap();
        assert_eq!(inbox.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), first.id);
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-unsolicited-reply-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let mut identity = QueueIdentity { network:Network::Floonet, wallet_id:[7;32], slot:[8;16],
            sender:bob.public_key(), recipient:alice.public_key() };
        let key = QueueKey::derive_from_wallet_entropy(&[9;32], &identity).unwrap();
        identity.slot = super::super::queue_record::incoming_event_reply_slot(&key, identity.network,
            &identity.wallet_id, identity.sender, first.id.as_bytes()).unwrap();
        let relay = FakeRelay::default(); relay.acknowledge.store(true, Ordering::SeqCst);
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let outgoing = ContactSession::connect_client(client, bob.clone(), alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let client = ClientBuilder::new().websocket_transport(FakeRelay::default()).build();
        let wrong = ContactSession::connect_client(client, bob.clone(), carol.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let armor = "BEGINSLATEPACK. synthetic ENDSLATEPACK.";
        let window = Duration::from_secs(3600);
        assert_eq!(inbox.persist_reply_then_complete(&wrong, &dir, &key, &identity, armor, window).await,
            Err(SessionError::InvalidInput));
        assert_eq!(inbox.persist_reply_then_complete(&outgoing, &dir.join("missing"), &key, &identity, armor, window).await,
            Err(SessionError::StorageUnavailable));
        assert_eq!(inbox.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), first.id);
        assert_eq!(inbox.persist_reply_then_complete(&outgoing, &dir, &key, &identity, armor, window).await,
            Ok(QueueWrite::Stored));
        let (recovered, _) = super::super::queue_store::load_recoverable(&dir, &key, identity.network, &identity.wallet_id,
            &identity.slot, identity.sender, Timestamp::now().as_secs()).unwrap();
        assert_eq!(recovered.recipient, alice.public_key());
        assert_eq!(outgoing.publish_recoverable_payment(&dir, &key, identity.network, &identity.wallet_id,
            &identity.slot, Duration::from_secs(3)).await, Ok(Publication::RelayAccepted));
        // Reconnect as a fresh inbox: the exact same source event can be
        // reconciled to the existing response without another signature.
        let client = ClientBuilder::new().websocket_transport(FakeRelay { backlog:vec![first.clone()], ..Default::default() }).build();
        let mut reopened = UnsolicitedInbox::connect_client(client, bob.clone(), Url::parse("wss://relay.example").unwrap(),
            Duration::from_secs(3), UnsolicitedBudget::new()).await.unwrap();
        assert_eq!(reopened.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), first.id);
        reopened.reconcile_pending_reply(&dir, &key, &identity).unwrap();
        assert!(matches!(reopened.receive_pending(Duration::from_millis(100)).await, Err(SessionError::Timeout)));
        reopened.close().await;
        assert_eq!(inbox.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), second.id);
        assert!(inbox.reconcile_pending_reply(&dir, &key, &identity).is_err());
        let mut occupied = identity;
        occupied.slot = super::super::queue_record::incoming_event_reply_slot(&key, identity.network,
            &identity.wallet_id, identity.sender, second.id.as_bytes()).unwrap();
        assert_ne!(occupied.slot, identity.slot);
        let mismatch = outgoing.prepare_payment_for(armor, None, false, window).await.unwrap();
        super::super::queue_store::persist_correlated_recoverable(&dir, &key, &occupied, &mismatch,
            Timestamp::now().as_secs(), first.id.as_bytes()).unwrap();
        assert_eq!(inbox.persist_reply_then_complete(&outgoing, &dir, &key, &occupied, armor, window).await,
            Ok(QueueWrite::Indeterminate));
        assert_eq!(inbox.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), second.id);
        wrong.close().await; outgoing.close().await; inbox.close().await;
    }

    #[tokio::test]
    async fn unsolicited_open_budget_holds_next_event_until_window_expires() {
        let alice = Keys::generate(); let bob = Keys::generate();
        let repeated = super::super::wrapv3::wrap(&alice, &bob.public_key(), "repeat".into(), vec![]).unwrap();
        let last = super::super::wrapv3::wrap(&alice, &bob.public_key(), "later".into(), vec![]).unwrap();
        let mut backlog = vec![repeated; MAX_UNKNOWN_OPENS]; backlog.push(last.clone());
        let client = ClientBuilder::new().websocket_transport(FakeRelay { backlog, ..Default::default() }).build();
        let mut inbox = UnsolicitedInbox::connect_client(client, bob, Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3), UnsolicitedBudget::new()).await.unwrap();
        let message = inbox.receive_pending(Duration::from_secs(3)).await.unwrap();
        inbox.complete_or_discard(message.envelope_id()).unwrap();
        assert!(matches!(inbox.receive_pending(Duration::from_secs(3)).await, Err(SessionError::RateLimited)));
        assert_eq!(inbox.inner.pending.front().unwrap().id, last.id);
        let earlier = std::time::Instant::now().checked_sub(UNKNOWN_OPEN_WINDOW).unwrap();
        for instant in &mut *inbox.budget.times.lock().unwrap() { *instant = earlier; }
        let resumed = inbox.receive_pending(Duration::from_secs(3)).await.unwrap();
        assert_eq!(resumed.envelope_id(), last.id);
        inbox.close().await;
    }

    #[tokio::test]
    async fn unsolicited_budget_is_shared_across_connections_and_reconnects() {
        let alice = Keys::generate(); let bob = Keys::generate();
        let first = super::super::wrapv3::wrap(&alice, &bob.public_key(), "first".into(), vec![]).unwrap();
        let second = super::super::wrapv3::wrap(&alice, &bob.public_key(), "second".into(), vec![]).unwrap();
        let budget = UnsolicitedBudget::new();
        for _ in 0..MAX_UNKNOWN_OPENS-1 { budget.acquire().unwrap(); }
        let client = ClientBuilder::new().websocket_transport(FakeRelay { backlog: vec![first], ..Default::default() }).build();
        let mut a = UnsolicitedInbox::connect_client(client, bob.clone(), Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3), budget.clone()).await.unwrap();
        let first = a.receive_pending(Duration::from_secs(3)).await.unwrap();
        a.complete_or_discard(first.envelope_id()).unwrap(); a.close().await;
        let client = ClientBuilder::new().websocket_transport(FakeRelay { backlog: vec![second.clone()], ..Default::default() }).build();
        let mut b = UnsolicitedInbox::connect_client(client, bob, Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3), budget.clone()).await.unwrap();
        assert!(matches!(b.receive_pending(Duration::from_secs(3)).await, Err(SessionError::RateLimited)));
        let earlier = std::time::Instant::now().checked_sub(UNKNOWN_OPEN_WINDOW).unwrap();
        for instant in &mut *budget.times.lock().unwrap() { *instant = earlier; }
        assert_eq!(b.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), second.id);
        b.close().await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn unknown_recipient_and_exact_event_recover_after_session_restart() {
        use super::super::queue_record::{Network, QueueIdentity, QueueKey};
        let sender = Keys::generate(); let recipient = Keys::generate(); let other = Keys::generate();
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-recoverable-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7;32], slot: [8;16],
            sender: sender.public_key(), recipient: recipient.public_key() };
        let entropy = [9;32]; let key = QueueKey::derive_from_wallet_entropy(&entropy, &identity).unwrap();
        let event_log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let ack = std::sync::Arc::new(AtomicBool::new(false));
        let relay = FakeRelay { published_events: event_log.clone(), acknowledge: ack.clone(), ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let session = ContactSession::connect_client(client, sender.clone(), recipient.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let armor = "BEGINSLATEPACK. synthetic ENDSLATEPACK.";
        assert_eq!(session.prepare_recoverable_payment(&dir, &key, &identity, armor, Duration::from_secs(3600)).await, Ok(QueueWrite::Stored));
        assert_eq!(session.publish_recoverable_payment(&dir, &key, identity.network, &identity.wallet_id,
            &identity.slot, Duration::from_millis(100)).await, Ok(Publication::Unknown));
        session.close().await;
        drop(key);
        let reopened_key = QueueKey::derive_for_wallet_entropy(&entropy, Network::Floonet, &[7;32]).unwrap();
        let slots = super::super::queue_store::discover_outgoing(&dir).unwrap(); assert_eq!(slots, vec![identity.slot]);
        let (recovered, _) = super::super::queue_store::load_recoverable(&dir, &reopened_key, Network::Floonet,
            &[7;32], &slots[0], sender.public_key(), Timestamp::now().as_secs()).unwrap();
        assert_eq!(recovered.recipient, recipient.public_key());
        let wrong_client = ClientBuilder::new().websocket_transport(FakeRelay::default()).build();
        let wrong = ContactSession::connect_client(wrong_client, sender.clone(), other.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert_eq!(wrong.publish_recoverable_payment(&dir, &reopened_key, Network::Floonet, &[7;32],
            &slots[0], Duration::from_secs(3)).await, Err(SessionError::InvalidInput));
        wrong.close().await;
        let relay = FakeRelay { published_events: event_log.clone(), acknowledge: ack.clone(), ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let session = ContactSession::connect_client(client, sender, recovered.recipient,
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        ack.store(true, Ordering::SeqCst);
        assert_eq!(session.publish_recoverable_payment(&dir, &reopened_key, Network::Floonet, &[7;32],
            &slots[0], Duration::from_secs(3)).await, Ok(Publication::RelayAccepted));
        let events = event_log.lock().unwrap().clone(); assert_eq!(events.len(), 2);
        assert_eq!(Event::from_json(&events[0]).unwrap().id, Event::from_json(&events[1]).unwrap().id);
        assert_eq!(session.publish_recoverable_payment(&dir, &reopened_key, Network::Floonet, &[7;32],
            &slots[0], Duration::from_secs(3)).await, Ok(Publication::RelayAccepted));
        assert_eq!(event_log.lock().unwrap().len(), 2);
        session.close().await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn resume_pass_handles_ack_expiry_corruption_and_budget_without_new_events() {
        use super::super::{outgoing_resume_research::{resume_with, ResumeEntry, ResumeState},
            queue_record::{Network, QueueIdentity, QueueKey}, queue_store};
        let sender = Keys::generate(); let recipient = Keys::generate();
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-resume-pass-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let base = QueueIdentity { network: Network::Floonet, wallet_id: [7;32], slot: [1;16],
            sender: sender.public_key(), recipient: recipient.public_key() };
        let key = QueueKey::derive_from_wallet_entropy(&[9;32], &base).unwrap();
        let now = Timestamp::now().as_secs();
        for index in [1u8, 2, 3, 5] {
            let identity = QueueIdentity { slot: [index;16], ..base };
            let expiry = if index == 3 { now - 1 } else { now + 3600 };
            let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
                .tag(Tag::public_key(recipient.public_key())).build(sender.public_key());
            let event = EventBuilder::gift_wrap(&sender, &recipient.public_key(), rumor,
                [Tag::expiration(Timestamp::from(expiry))]).await.unwrap();
            let prepared = PreparedMessage { event, sender: sender.public_key(), recipient: recipient.public_key(),
                expires_at: expiry, local_history: None };
            queue_store::persist_recoverable(&dir, &key, &identity, &prepared, if index == 3 { now - 2 } else { now }).unwrap();
            if index == 2 { queue_store::mark_acknowledged(&dir, &key, &identity, &prepared).unwrap(); }
        }
        std::fs::write(dir.join(format!("out-{}.flyq", "04".repeat(16))), [0u8;48]).unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let ack = std::sync::Arc::new(AtomicBool::new(true));
        let connector = |peer| {
            let sender = sender.clone(); let events = events.clone(); let ack = ack.clone();
            async move {
                let relay = FakeRelay { published_events: events, acknowledge: ack, ..Default::default() };
                let client = ClientBuilder::new().websocket_transport(relay).build();
                ContactSession::connect_client(client, sender, peer, Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await
            }
        };
        let first = resume_with(&dir, &key, Network::Floonet, &[7;32], sender.public_key(), Duration::from_secs(3), 1, None, None, connector).await.unwrap();
        assert_eq!(first.entries, vec![
            ResumeEntry { slot:[1;16], state:ResumeState::RelayAccepted { delivery_window_expired:false } },
            ResumeEntry { slot:[2;16], state:ResumeState::RelayAccepted { delivery_window_expired:false } },
            ResumeEntry { slot:[3;16], state:ResumeState::Expired },
            ResumeEntry { slot:[4;16], state:ResumeState::Unavailable },
            ResumeEntry { slot:[5;16], state:ResumeState::Deferred },
        ]);
        assert_eq!(events.lock().unwrap().len(), 1);
        let connector = |peer| {
            let sender = sender.clone(); let events = events.clone(); let ack = ack.clone();
            async move {
                let relay = FakeRelay { published_events: events, acknowledge: ack, ..Default::default() };
                let client = ClientBuilder::new().websocket_transport(relay).build();
                ContactSession::connect_client(client, sender, peer, Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await
            }
        };
        let second = resume_with(&dir, &key, Network::Floonet, &[7;32], sender.public_key(), Duration::from_secs(3), 1, first.next_after, None, connector).await.unwrap();
        assert_eq!(second.entries.iter().find(|entry| entry.slot == [5;16]).unwrap().state, ResumeState::RelayAccepted { delivery_window_expired:false });
        assert_eq!(events.lock().unwrap().len(), 2);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn resume_pass_retries_same_envelope_after_unknown_relay_response() {
        use super::super::{outgoing_resume_research::{resume_with, ResumeState}, queue_record::{Network, QueueIdentity, QueueKey}, queue_store};
        let sender = Keys::generate(); let recipient = Keys::generate();
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-resume-unknown-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7;32], slot: [1;16],
            sender: sender.public_key(), recipient: recipient.public_key() };
        let key = QueueKey::derive_from_wallet_entropy(&[9;32], &identity).unwrap();
        let now = Timestamp::now().as_secs();
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
            .tag(Tag::public_key(recipient.public_key())).build(sender.public_key());
        let event = EventBuilder::gift_wrap(&sender, &recipient.public_key(), rumor,
            [Tag::expiration(Timestamp::from(now + 3600))]).await.unwrap();
        let prepared = PreparedMessage { event, sender: sender.public_key(), recipient: recipient.public_key(),
            expires_at: now + 3600, local_history: None };
        queue_store::persist_recoverable(&dir, &key, &identity, &prepared, now).unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let ack = std::sync::Arc::new(AtomicBool::new(false));
        let connector = |peer| {
            let sender = sender.clone(); let events = events.clone(); let ack = ack.clone();
            async move {
                let relay = FakeRelay { published_events: events, acknowledge: ack, ..Default::default() };
                let client = ClientBuilder::new().websocket_transport(relay).build();
                ContactSession::connect_client(client, sender, peer, Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await
            }
        };
        let first = resume_with(&dir, &key, Network::Floonet, &[7;32], sender.public_key(), Duration::from_millis(100), 1, None, None, connector).await.unwrap();
        assert_eq!(first.entries[0].state, ResumeState::Pending);
        ack.store(true, Ordering::SeqCst);
        let connector = |peer| {
            let sender = sender.clone(); let events = events.clone(); let ack = ack.clone();
            async move {
                let relay = FakeRelay { published_events: events, acknowledge: ack, ..Default::default() };
                let client = ClientBuilder::new().websocket_transport(relay).build();
                ContactSession::connect_client(client, sender, peer, Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await
            }
        };
        let second = resume_with(&dir, &key, Network::Floonet, &[7;32], sender.public_key(), Duration::from_secs(3), 1, first.next_after, None, connector).await.unwrap();
        assert_eq!(second.entries[0].state, ResumeState::RelayAccepted { delivery_window_expired: false });
        let sent = events.lock().unwrap(); assert_eq!(sent.len(), 2);
        assert_eq!(Event::from_json(&sent[0]).unwrap().id, Event::from_json(&sent[1]).unwrap().id);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn resume_rotation_prevents_failed_first_slot_starving_next() {
        use super::super::{outgoing_resume_research::{resume_with, ResumeState}, queue_record::{Network, QueueIdentity, QueueKey}, queue_store};
        let sender = Keys::generate(); let recipient = Keys::generate();
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-resume-fair-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let base = QueueIdentity { network: Network::Floonet, wallet_id: [7;32], slot: [1;16], sender: sender.public_key(), recipient: recipient.public_key() };
        let key = QueueKey::derive_from_wallet_entropy(&[9;32], &base).unwrap();
        let now = Timestamp::now().as_secs();
        for index in [1u8, 2] {
            let identity = QueueIdentity { slot: [index;16], ..base };
            let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
                .tag(Tag::public_key(recipient.public_key())).build(sender.public_key());
            let event = EventBuilder::gift_wrap(&sender, &recipient.public_key(), rumor,
                [Tag::expiration(Timestamp::from(now + 3600))]).await.unwrap();
            let prepared = PreparedMessage { event, sender: sender.public_key(), recipient: recipient.public_key(), expires_at: now + 3600, local_history: None };
            queue_store::persist_recoverable(&dir, &key, &identity, &prepared, now).unwrap();
        }
        let fail = |_| async { Err(SessionError::ConnectionFailed) };
        let first = resume_with(&dir, &key, Network::Floonet, &[7;32], sender.public_key(), Duration::from_secs(1), 1, None, None, fail).await.unwrap();
        assert_eq!(first.entries[0].state, ResumeState::Pending);
        assert_eq!(first.entries[1].state, ResumeState::Deferred);
        let fail = |_| async { Err(SessionError::ConnectionFailed) };
        let second = resume_with(&dir, &key, Network::Floonet, &[7;32], sender.public_key(), Duration::from_secs(1), 1, first.next_after, None, fail).await.unwrap();
        assert_eq!(second.entries[0].slot, [2;16]);
        assert_eq!(second.entries[0].state, ResumeState::Pending);
        assert_eq!(second.entries[1].state, ResumeState::Deferred);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn supervisor_blocks_parallel_pass_and_waits_for_stop() {
        use super::super::{outgoing_resume_research::{ResumeState, ResumeSupervisor}, queue_record::{Network, QueueIdentity, QueueKey}, queue_store};
        let sender = Keys::generate(); let recipient = Keys::generate();
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-resume-stop-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7;32], slot: [1;16], sender: sender.public_key(), recipient: recipient.public_key() };
        let key = QueueKey::derive_from_wallet_entropy(&[9;32], &identity).unwrap();
        let now = Timestamp::now().as_secs();
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
            .tag(Tag::public_key(recipient.public_key())).build(sender.public_key());
        let event = EventBuilder::gift_wrap(&sender, &recipient.public_key(), rumor,
            [Tag::expiration(Timestamp::from(now + 3600))]).await.unwrap();
        let prepared = PreparedMessage { event, sender: sender.public_key(), recipient: recipient.public_key(), expires_at: now + 3600, local_history: None };
        queue_store::persist_recoverable(&dir, &key, &identity, &prepared, now).unwrap();
        let supervisor = ResumeSupervisor::new(Network::Floonet, [7;32], sender.public_key()).unwrap();
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let send_log = events.clone(); let sender_for_connector = sender.clone();
        let connect = move |peer| {
            let events = send_log.clone(); let sender = sender_for_connector.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                let relay = FakeRelay { published_events: events, acknowledge: std::sync::Arc::new(AtomicBool::new(true)), ..Default::default() };
                let client = ClientBuilder::new().websocket_transport(relay).build();
                ContactSession::connect_client(client, sender, peer, Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await
            }
        };
        let running = supervisor.run_with(&dir, &key, Duration::from_secs(3), 1, connect);
        let stop = async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            let fail = |_| async { Err(SessionError::ConnectionFailed) };
            assert!(matches!(supervisor.run_with(&dir, &key, Duration::from_secs(1), 1, fail).await, Err(SessionError::StorageBusy)));
            supervisor.stop_and_wait().await;
        };
        let (batch, ()) = tokio::join!(running, stop);
        assert_eq!(batch.unwrap().entries[0].state, ResumeState::Deferred);
        assert!(events.lock().unwrap().is_empty());
        let fail = |_| async { Err(SessionError::ConnectionFailed) };
        assert!(matches!(supervisor.run_with(&dir, &key, Duration::from_secs(1), 1, fail).await, Err(SessionError::Closed)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn periodic_recovery_retries_same_event_and_stops() {
        use super::super::{outgoing_resume_research::{worker_loop, RecoveryWorkerState, ResumeSupervisor}, queue_record::{Network, QueueIdentity, QueueKey}, queue_store};
        let sender = Keys::generate(); let recipient = Keys::generate();
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-periodic-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7;32], slot: [1;16], sender: sender.public_key(), recipient: recipient.public_key() };
        let key = std::sync::Arc::new(QueueKey::derive_from_wallet_entropy(&[9;32], &identity).unwrap());
        let now = Timestamp::now().as_secs();
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, "synthetic")
            .tag(Tag::public_key(recipient.public_key())).build(sender.public_key());
        let event = EventBuilder::gift_wrap(&sender, &recipient.public_key(), rumor,
            [Tag::expiration(Timestamp::from(now + 3600))]).await.unwrap();
        let prepared = PreparedMessage { event, sender: sender.public_key(), recipient: recipient.public_key(), expires_at: now + 3600, local_history: None };
        queue_store::persist_recoverable(&dir, &key, &identity, &prepared, now).unwrap();
        let supervisor = std::sync::Arc::new(ResumeSupervisor::new(Network::Floonet, [7;32], sender.public_key()).unwrap());
        let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let ack = std::sync::Arc::new(AtomicBool::new(false));
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let (state, state_rx) = tokio::sync::watch::channel(RecoveryWorkerState::Starting);
        let task_supervisor = supervisor.clone(); let task_events = events.clone(); let task_ack = ack.clone();
        let worker = tokio::spawn(async move {
            worker_loop(stop_rx, state, Duration::from_millis(20), move || {
                let supervisor = task_supervisor.clone(); let events = task_events.clone(); let ack = task_ack.clone();
                let key = key.clone(); let dir = dir.clone(); let sender = sender.clone();
                async move {
                    supervisor.run_with(&dir, &key, Duration::from_millis(100), 1, |peer| {
                        let events = events.clone(); let ack = ack.clone(); let sender = sender.clone();
                        async move {
                            let relay = FakeRelay { published_events: events, acknowledge: ack, ..Default::default() };
                            let client = ClientBuilder::new().websocket_transport(relay).build();
                            ContactSession::connect_client(client, sender, peer, Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await
                        }
                    }).await
                }
            }).await;
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while events.lock().unwrap().is_empty() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        ack.store(true, Ordering::SeqCst);
        while events.lock().unwrap().len() < 2 {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        stop.send_replace(true);
        supervisor.stop_and_wait().await;
        tokio::time::timeout(Duration::from_secs(3), worker).await.unwrap().unwrap();
        assert_eq!(*state_rx.borrow(), RecoveryWorkerState::Stopped);
        let sent = events.lock().unwrap(); assert_eq!(sent.len(), 2);
        assert_eq!(Event::from_json(&sent[0]).unwrap().id, Event::from_json(&sent[1]).unwrap().id);
    }

    #[test]
    fn unsolicited_budget_limits_concurrent_workers() {
        let budget = UnsolicitedBudget::new();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(64));
        let workers: Vec<_> = (0..64).map(|_| {
            let budget = budget.clone(); let barrier = barrier.clone();
            std::thread::spawn(move || { barrier.wait(); budget.acquire() })
        }).collect();
        let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), MAX_UNKNOWN_OPENS);
        assert_eq!(results.iter().filter(|result| **result == Err(SessionError::RateLimited)).count(), 64 - MAX_UNKNOWN_OPENS);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn saved_contact_session_uses_authenticated_book_key() {
        use super::super::{contact_book_research::{self,BookIdentity,BookKey,Contact},queue_record::Network};
        use std::{fs,path::PathBuf};
        let root=PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(),fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp=root.join(".tmp"); assert_eq!(fs::canonicalize(std::env::temp_dir()).unwrap(),fs::canonicalize(&tmp).unwrap());
        let mut random=[0u8;16]; getrandom::getrandom(&mut random).unwrap();
        let suffix:String=random.iter().map(|b|format!("{b:02x}")).collect();
        let dir=tmp.join(format!("fly-contact-session-synthetic-{suffix}")); fs::create_dir(&dir).unwrap();
        let alice=Keys::generate(); let bob=Keys::generate(); let mallory=Keys::generate();
        let identity=BookIdentity { network:Network::Floonet,wallet_id:[7;32] };
        let key=BookKey::derive_from_wallet_entropy(&[9;16],&identity).unwrap();
        let wrong=BookKey::derive_from_wallet_entropy(&[8;16],&identity).unwrap();
        let contact=Contact::new("Synthetic",alice.public_key()).unwrap();
        contact_book_research::create(&dir,&key,&identity,&[3;16],&contact).unwrap();
        let make=|sender:&Keys,text:&str| super::super::wrapv3::wrap(sender,&bob.public_key(),text.to_owned(),vec![]).unwrap();
        let relay=FakeRelay { backlog:vec![make(&mallory,"untrusted"),make(&alice,"known")],..Default::default() };
        let url=Url::parse("wss://relay.example").unwrap();
        let client=ClientBuilder::new().websocket_transport(relay.clone()).build();
        assert!(matches!(ContactSession::connect_client_saved(client,bob.clone(),url.clone(),Duration::from_secs(3),
            &dir,&wrong,&identity,&[3;16]).await,Err(SessionError::StorageUnavailable)));
        let client=ClientBuilder::new().websocket_transport(relay).build();
        let mut session=ContactSession::connect_client_saved(client,bob,url,Duration::from_secs(3),
            &dir,&key,&identity,&[3;16]).await.unwrap();
        assert_eq!(session.receive(Duration::from_secs(3)).await,Ok("known".to_owned()));
        session.close().await;
    }

    #[cfg(all(windows, feature = "windows-vault-queue-research", feature = "messaging-identity-research"))]
    #[tokio::test]
    async fn unlocked_profile_opens_saved_contact_session() {
        use std::{fs,path::PathBuf};
        use fly_wallet::{address::Network as WalletNetwork,windows_catalog_research::Catalog,windows_profile_research::prepare_generated};
        use super::super::{contact_book_research::{self,Contact},windows_vault_queue_research as profile};
        let root=PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(),fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp=root.join(".tmp"); assert_eq!(fs::canonicalize(std::env::temp_dir()).unwrap(),fs::canonicalize(&tmp).unwrap());
        let mut random=[0u8;16];getrandom::getrandom(&mut random).unwrap();
        let suffix:String=random.iter().map(|b|format!("{b:02x}")).collect();
        let dir=tmp.join(format!("fly-profile-contact-synthetic-{suffix}"));fs::create_dir(&dir).unwrap();
        let catalog=Catalog::new(&dir).unwrap();
        let pending=prepare_generated(WalletNetwork::Floonet,12).unwrap();
        let created=catalog.create("Synthetic",pending.confirm_backup(),"synthetic-password").unwrap();
        let (profile_dir,identity)=profile::resolve_catalog_profile(&dir,&created.id).unwrap();
        assert!(profile::resolve_catalog_profile(&dir,"../outside").is_err());
        let bob_public=profile::create_messaging_identity(&profile_dir,"synthetic-password",&identity).unwrap();
        let alice=Keys::generate(); let mallory=Keys::generate();
        let book=profile::open_book_key(&profile_dir,"synthetic-password",&identity).unwrap();
        let contacts=profile_dir.join("contacts");fs::create_dir(&contacts).unwrap();
        contact_book_research::create(&contacts,&book,&identity,&[3;16],&Contact::new("Synthetic",alice.public_key()).unwrap()).unwrap();
        drop(book);
        assert!(profile::open_messaging_and_book_async(&profile_dir,"wrong",&identity).await.is_err());
        let (bob,book)=profile::open_messaging_and_book_async(&profile_dir,"synthetic-password",&identity).await.unwrap();
        assert_eq!(bob.public_key(),bob_public);
        let make=|sender:&Keys,text:&str|super::super::wrapv3::wrap(sender,&bob_public,text.to_owned(),vec![]).unwrap();
        let relay=FakeRelay { backlog:vec![make(&mallory,"untrusted"),make(&alice,"known")],..Default::default() };
        let client=ClientBuilder::new().websocket_transport(relay).build();
        let mut session=ContactSession::connect_client_saved(client,bob,Url::parse("wss://relay.example").unwrap(),
            Duration::from_secs(3),&contacts,&book,&identity,&[3;16]).await.unwrap();
        assert_eq!(session.receive(Duration::from_secs(3)).await,Ok("known".to_owned()));
        session.close().await;
    }

    #[tokio::test]
    async fn authenticated_rumor_keeps_payment_tags_and_envelope_identity() {
        let alice = Keys::generate(); let bob = Keys::generate();
        let event = super::super::wrapv3::wrap(&alice, &bob.public_key(),
            "synthetic payment content".to_owned(), protocol::build_rumor_tags(Some("test note"))).unwrap();
        let expected_id = event.id;
        let relay = FakeRelay { backlog: vec![event], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let message = session.receive_message(Duration::from_secs(3)).await.unwrap();
        assert_eq!(message.envelope_id, expected_id);
        assert_eq!(message.sender, alice.public_key());
        assert_eq!(message.rumor.pubkey, alice.public_key());
        assert_eq!(message.rumor.content, "synthetic payment content");
        assert_eq!(protocol::extract_subject(&message.rumor.tags).as_deref(), Some("test note"));
        assert!(message.rumor.tags.iter().any(|tag| tag.as_slice().first().map(String::as_str) == Some("goblin")));
        session.close().await;
    }

    #[cfg(all(windows, feature = "slatepack-inspection-research"))]
    #[tokio::test]
    async fn synthetic_stateless_slatepack_roundtrip_over_authenticated_nostr() {
        synthetic_slatepack_roundtrip_over_authenticated_nostr(true).await;
    }

    #[cfg(all(windows, feature = "slatepack-inspection-research"))]
    #[tokio::test]
    async fn synthetic_stateful_slatepack_roundtrip_with_bound_reply() {
        synthetic_slatepack_roundtrip_over_authenticated_nostr(false).await;
    }

    #[cfg(all(windows, feature = "slatepack-inspection-research"))]
    async fn synthetic_slatepack_roundtrip_over_authenticated_nostr(stateless: bool) {
        use fly_wallet::{address::Network, node_client_research::UnreadyNodeClient,
            slatepack_inspection_research::{check_public_standard_reply, PacketInspection, SlateStage}};
        use super::super::queue_record::{payment_operation_slot, Network as QueueNetwork,
            PaymentStage, QueueIdentity, QueueKey};
        use grin_core::{core::{FeeFields, Weighting}, libtx::{build, tx_fee, ProofBuilder}};
        use grin_keychain::{ExtKeychain, Keychain};
        use grin_wallet_libwallet::{api_impl::foreign, Context as WalletContext,
            Slate, SlateState, Slatepacker, SlatepackerArgs, WalletBackend};

        // Synthetic keys and a private temporary backend. This exercises the
        // low-level receive primitive, not the closed application boundary.
        let previous = grin_core::global::CHAIN_TYPE.with(|value|
            value.replace(Some(grin_core::global::ChainTypes::Testnet)));
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .unwrap().as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "fly-nostr-stateless-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let sender = ExtKeychain::from_seed(&[0x41;32], true).unwrap();
        let receiver = ExtKeychain::from_seed(&[0x42;32], true).unwrap();
        let parent = WalletBackend::<UnreadyNodeClient, ExtKeychain>::default_path();
        let sender_secret = grin_wallet_libwallet::address::address_from_derivation_path(&sender, &parent, 0).unwrap();
        let receiver_secret = grin_wallet_libwallet::address::address_from_derivation_path(&receiver, &parent, 0).unwrap();
        let sender_address = grin_wallet_libwallet::SlatepackAddress::try_from(&sender_secret).unwrap().pub_key;
        let receiver_address = grin_wallet_libwallet::SlatepackAddress::try_from(&receiver_secret).unwrap().pub_key;
        let mut wallet = WalletBackend::new(directory.to_str().unwrap(), UnreadyNodeClient).unwrap();
        wallet.set_keychain(receiver, false, false).unwrap();
        let input = ExtKeychain::derive_key_id(3, 0, 0, 1, 0);
        let change = ExtKeychain::derive_key_id(3, 0, 0, 2, 0);
        let amount = 1_000_000_000;
        let change_amount = 2_000_000_000;
        let fee = tx_fee(1, 2, 1);
        let input_amount = amount + change_amount + fee;
        let mut s1 = Slate::blank(2, false);
        s1.amount = amount;
        s1.fee_fields = FeeFields::new(0, fee).unwrap();
        s1.payment_proof = Some(grin_wallet_libwallet::PaymentInfo {
            sender_address, receiver_address, receiver_signature: None,
        });
        s1.add_transaction_elements(&sender, &ProofBuilder::new(&sender),
            vec![build::input(input_amount, input.clone()),
                 build::output(change_amount, change.clone())]).unwrap();
        let mut sender_context = WalletContext::new(sender.secp(), &parent, false, true);
        sender_context.add_input(&input, &None, input_amount);
        sender_context.add_output(&change, &None, change_amount);
        sender_context.amount = amount;
        sender_context.fee = Some(s1.fee_fields);
        s1.fill_round_1(&sender, &mut sender_context).unwrap();
        let packer = Slatepacker::new(SlatepackerArgs { sender: None, recipients: vec![], dec_key: None });
        let s1_armor = packer.armor_slatepack(&packer.create_slatepack(&s1).unwrap()).unwrap();

        let alice = Keys::generate();
        let bob = Keys::generate();
        let outgoing_dir = directory.join("outgoing");
        let incoming_dir = directory.join("incoming");
        std::fs::create_dir(&outgoing_dir).unwrap();
        std::fs::create_dir(&incoming_dir).unwrap();
        let identity = QueueIdentity { network: QueueNetwork::Floonet, wallet_id: [1;32], slot: [2;16],
            sender: alice.public_key(), recipient: bob.public_key() };
        let queue_key = QueueKey::derive(&[3;32], &identity).unwrap();
        let outbound_relay = FakeRelay::default();
        let sent_events = outbound_relay.published_events.clone();
        let relay_ack = outbound_relay.acknowledge.clone();
        let client = ClientBuilder::new().websocket_transport(outbound_relay).build();
        let sender_session = ContactSession::connect_client(client, alice.clone(), bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert_eq!(sender_session.prepare_payment_stored_for(&outgoing_dir, &queue_key, &identity,
            &s1_armor, None, false, Duration::from_secs(86_400)).await, Ok(QueueWrite::Stored));
        assert_eq!(sender_session.publish_stored(&outgoing_dir, &queue_key, &identity,
            Duration::from_millis(100)).await, Ok(Publication::Unknown));
        sender_session.close().await;
        // Reopen the same queue after an uncertain publication and resend
        // exactly the same signed event, never regenerate a new S1.
        let outbound_relay = FakeRelay { published_events: sent_events.clone(),
            acknowledge: relay_ack.clone(), ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(outbound_relay).build();
        let sender_session = ContactSession::connect_client(client, alice.clone(), bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        relay_ack.store(true, Ordering::SeqCst);
        assert_eq!(sender_session.publish_stored(&outgoing_dir, &queue_key, &identity,
            Duration::from_secs(3)).await, Ok(Publication::RelayAccepted));
        sender_session.close().await;
        let sent = sent_events.lock().unwrap().clone();
        assert_eq!(sent.len(), 2);
        let incoming = Event::from_json(&sent[0]).unwrap();
        assert_eq!(incoming.id, Event::from_json(&sent[1]).unwrap().id);
        let relay = FakeRelay { backlog: vec![incoming], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut receiver_session = ContactSession::connect_client(client, bob.clone(), alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let message = receiver_session.receive_pending(Duration::from_secs(3)).await.unwrap();
        assert_eq!(message.sender(), alice.public_key());
        assert_eq!(message.inspect_slatepack(Network::Floonet), Ok(PacketInspection::Plain {
            slate_id: s1.id.to_string(), stage: SlateStage::Standard1,
        }));
        let inbox_identity = QueueIdentity { network: QueueNetwork::Floonet, wallet_id: [4;32],
            slot: message.storage_slot(), sender: alice.public_key(), recipient: bob.public_key() };
        let inbox_key = QueueKey::derive(&[5;32], &inbox_identity).unwrap();
        assert_eq!(receiver_session.persist_pending_and_acknowledge(&incoming_dir, &inbox_key,
            &inbox_identity), Ok(QueueWrite::Stored));
        receiver_session.close().await;
        let client = ClientBuilder::new().websocket_transport(FakeRelay::default()).build();
        let receiver_session = ContactSession::connect_client(client, bob.clone(), alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let restored = receiver_session.restore_received(&incoming_dir, &inbox_key, &inbox_identity,
            message.envelope_id()).await.unwrap();
        let received_s1 = protocol::extract_slatepack(&restored.rumor().content).unwrap();
        let packet = packer.deser_slatepack(received_s1.as_bytes(), true).unwrap();
        let parsed_s1 = packer.get_slate(&packet).unwrap();
        let received = if stateless {
            foreign::receive_tx_stateless(&mut wallet, None, &parsed_s1, None, None, false).unwrap()
        } else {
            foreign::receive_tx(&mut wallet, None, &parsed_s1, None, false).unwrap()
        };
        assert_eq!(received.state, SlateState::Standard2);
        if stateless {
            assert_eq!(wallet.iter().unwrap().count(), 0);
            assert_eq!(wallet.tx_log_iter().unwrap().count(), 0);
        } else {
            assert_eq!(wallet.iter().unwrap().count(), 1);
            assert_eq!(wallet.tx_log_iter().unwrap().count(), 1);
            assert!(foreign::receive_tx(&mut wallet, None, &parsed_s1, None, false).is_err());
        }
        let s2_armor = packer.armor_slatepack(&packer.create_slatepack(&received).unwrap()).unwrap();
        check_public_standard_reply(&s1_armor, &s2_armor, Network::Floonet).unwrap();

        receiver_session.close().await;
        let reply_dir = directory.join("reply");
        std::fs::create_dir(&reply_dir).unwrap();
        let mut reply_identity = QueueIdentity { network: QueueNetwork::Floonet, wallet_id: [4;32],
            slot: [6;16], sender: bob.public_key(), recipient: alice.public_key() };
        let reply_key = QueueKey::derive(&[7;32], &reply_identity).unwrap();
        if !stateless {
            reply_identity.slot = payment_operation_slot(&reply_key, &reply_identity,
                parsed_s1.id.as_bytes(), PaymentStage::Standard1).unwrap();
        }
        let reply_relay = FakeRelay::default();
        let reply_events = reply_relay.published_events.clone();
        reply_relay.acknowledge.store(true, Ordering::SeqCst);
        let client = ClientBuilder::new().websocket_transport(reply_relay).build();
        let receiver_session = ContactSession::connect_client(client, bob.clone(), alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        if stateless {
            assert_eq!(receiver_session.prepare_payment_stored_for(&reply_dir, &reply_key, &reply_identity,
                &s2_armor, None, false, Duration::from_secs(86_400)).await, Ok(QueueWrite::Stored));
            assert_eq!(receiver_session.publish_stored(&reply_dir, &reply_key, &reply_identity,
                Duration::from_secs(3)).await, Ok(Publication::RelayAccepted));
        } else {
            assert_eq!(receiver_session.prepare_bound_reply(&reply_dir, &reply_key, &reply_identity,
                parsed_s1.id.as_bytes(), &received_s1, &s2_armor, Duration::from_secs(86_400)).await,
                Ok(QueueWrite::Stored));
            assert_eq!(receiver_session.publish_bound_reply(&reply_dir, &reply_key, &reply_identity,
                parsed_s1.id.as_bytes(), &received_s1, Duration::from_secs(3)).await, Ok(Publication::RelayAccepted));
        }
        let reply = Event::from_json(&reply_events.lock().unwrap()[0]).unwrap();
        let relay = FakeRelay { backlog: vec![reply], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut sender_session = ContactSession::connect_client(client, alice, bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let response = sender_session.receive_message(Duration::from_secs(3)).await.unwrap();
        assert_eq!(response.sender(), bob.public_key());
        let received_armor = protocol::extract_slatepack(&response.rumor().content).unwrap();
        check_public_standard_reply(&s1_armor, &received_armor, Network::Floonet).unwrap();
        // Test-only synthetic input: this verifies the assembled transaction
        // cryptographically, without asserting that the input exists on chain.
        let packet = packer.deser_slatepack(received_armor.as_bytes(), true).unwrap();
        let mut final_slate = packer.get_slate(&packet).unwrap();
        final_slate.adjust_offset(&sender, &sender_context).unwrap();
        final_slate.amount = amount;
        final_slate.fee_fields = sender_context.fee.unwrap();
        final_slate.update_kernel().unwrap();
        final_slate.add_participant_info(&sender, &sender_context, None).unwrap();
        final_slate.add_transaction_elements(&sender, &ProofBuilder::new(&sender),
            vec![build::input(input_amount, input), build::output(change_amount, change)]).unwrap();
        let offset = final_slate.offset.clone();
        final_slate.tx_or_err_mut().unwrap().offset = offset;
        final_slate.fill_round_2(&sender, &sender_context.sec_key, &sender_context.sec_nonce).unwrap();
        final_slate.finalize(&sender).unwrap();
        let transaction = final_slate.tx_or_err().unwrap();
        transaction.validate(Weighting::AsTransaction).unwrap();
        assert_eq!((transaction.inputs().len(), transaction.outputs().len(), transaction.kernels().len()), (1, 2, 1));
        sender_session.close().await;
        receiver_session.close().await;
        drop(wallet);
        std::fs::remove_dir_all(directory).unwrap();
        grin_core::global::CHAIN_TYPE.with(|value| value.set(previous));
    }

    #[cfg(all(windows, feature = "slatepack-inspection-research"))]
    #[tokio::test]
    async fn same_s1_in_two_valid_envelopes_is_not_deduplicated_by_event_id() {
        use fly_wallet::{address::Network, slatepack_inspection_research::{PacketInspection, SlateStage}};
        use grin_wallet_libwallet::{Slate, Slatepacker, SlatepackerArgs};
        let previous = grin_core::global::CHAIN_TYPE.with(|value|
            value.replace(Some(grin_core::global::ChainTypes::Testnet)));
        let slate = Slate::blank(2, false);
        let packer = Slatepacker::new(SlatepackerArgs { sender: None, recipients: vec![], dec_key: None });
        let armor = packer.armor_slatepack(&packer.create_slatepack(&slate).unwrap()).unwrap();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let first = super::super::wrapv3::wrap(&alice, &bob.public_key(),
            protocol::build_payment_content(&armor), protocol::build_rumor_tags(None)).unwrap();
        let second = super::super::wrapv3::wrap(&alice, &bob.public_key(),
            protocol::build_payment_content(&armor), protocol::build_rumor_tags(None)).unwrap();
        assert_ne!(first.id, second.id);
        let relay = FakeRelay { backlog: vec![first, second], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        for _ in 0..2 {
            let message = session.receive_message(Duration::from_secs(3)).await.unwrap();
            assert_eq!(message.inspect_slatepack(Network::Floonet), Ok(PacketInspection::Plain {
                slate_id: slate.id.to_string(), stage: SlateStage::Standard1,
            }));
        }
        session.close().await;
        grin_core::global::CHAIN_TYPE.with(|value| value.set(previous));
    }

    #[cfg(all(windows, feature = "slatepack-inspection-research"))]
    #[tokio::test]
    async fn authenticated_nostr_message_inspects_real_upstream_slatepack() {
        use fly_wallet::{address::Network, slatepack_inspection_research::{PacketInspection, SlateStage}};
        use grin_wallet_libwallet::{Slate, SlatepackAddress, Slatepacker, SlatepackerArgs};
        let previous = grin_core::global::CHAIN_TYPE.with(|value| value.replace(Some(grin_core::global::ChainTypes::Testnet)));
        let slate = Slate::blank(2, false);
        let packer = Slatepacker::new(SlatepackerArgs { sender: None, recipients: vec![], dec_key: None });
        let armor = packer.armor_slatepack(&packer.create_slatepack(&slate).unwrap()).unwrap();
        let entropy = [7u8; 16];
        let address = fly_wallet::address::default_address(&entropy, Network::Floonet).unwrap();
        let recipient = SlatepackAddress::try_from(address.as_str()).unwrap();
        let encrypted_packer = Slatepacker::new(SlatepackerArgs { sender: None, recipients: vec![recipient], dec_key: None });
        let encrypted_armor = encrypted_packer.armor_slatepack(&encrypted_packer.create_slatepack(&slate).unwrap()).unwrap();
        grin_core::global::CHAIN_TYPE.with(|value| value.set(previous));
        let alice = Keys::generate(); let bob = Keys::generate();
        let event = super::super::wrapv3::wrap(&alice, &bob.public_key(),
            protocol::build_payment_content(&armor), protocol::build_rumor_tags(None)).unwrap();
        let fake = super::super::wrapv3::wrap(&alice, &bob.public_key(),
            protocol::build_payment_content("BEGINSLATEPACK. synthetic ENDSLATEPACK."), protocol::build_rumor_tags(None)).unwrap();
        let encrypted = super::super::wrapv3::wrap(&alice, &bob.public_key(),
            protocol::build_payment_content(&encrypted_armor), protocol::build_rumor_tags(None)).unwrap();
        let relay = FakeRelay { backlog: vec![event, fake, encrypted], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let msg = session.receive_message(Duration::from_secs(3)).await.unwrap();
        assert_eq!(msg.sender(), alice.public_key());
        assert_eq!(msg.inspect_slatepack(Network::Floonet), Ok(PacketInspection::Plain {
            slate_id: slate.id.to_string(), stage: SlateStage::Standard1,
        }));
        let msg = session.receive_message(Duration::from_secs(3)).await.unwrap();
        assert!(msg.inspect_slatepack(Network::Floonet).is_err());
        let msg = session.receive_message(Duration::from_secs(3)).await.unwrap();
        assert_eq!(msg.inspect_slatepack(Network::Floonet), Ok(PacketInspection::Encrypted));
        let armor = protocol::extract_slatepack(&msg.rumor().content).unwrap();
        assert_eq!(fly_wallet::slatepack_inspection_research::inspect_encrypted_for_default_wallet(
            &armor, &entropy, Network::Floonet), Ok(PacketInspection::Decrypted {
                slate_id: slate.id.to_string(), stage: SlateStage::Standard1,
            }));
        assert!(fly_wallet::slatepack_inspection_research::inspect_encrypted_for_default_wallet(
            &armor, &[8; 16], Network::Floonet).is_err());
        session.close().await;
    }

    #[cfg(all(windows, feature = "slatepack-inspection-research"))]
    #[tokio::test]
    async fn authenticated_contact_is_bound_to_encrypted_s2_fingerprint() {
        use fly_wallet::{address::Network, slatepack_inspection_research::{self as inspector, ReplyContext}};
        use grin_core::{core::FeeFields, libtx::{aggsig, build, proof::ProofBuilder, tx_fee}};
        use grin_keychain::{ExtKeychain, Keychain};
        use grin_wallet_libwallet::{address, Context, Slate, SlateState, SlatepackAddress, Slatepacker, SlatepackerArgs};
        let previous = grin_core::global::CHAIN_TYPE.with(|value| value.replace(Some(grin_core::global::ChainTypes::Testnet)));
        let sender = ExtKeychain::from_seed(&[17; 32], true).unwrap();
        let receiver = ExtKeychain::from_seed(&[29; 32], true).unwrap();
        let parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0);
        let input = ExtKeychain::derive_key_id(3, 0, 0, 1, 0);
        let change = ExtKeychain::derive_key_id(3, 0, 0, 2, 0);
        let output = ExtKeychain::derive_key_id(3, 0, 0, 3, 0);
        let amount = 1_000_000_000; let fee = tx_fee(1, 2, 1);
        let mut sender_ctx = Context::new(sender.secp(), &parent, false, true);
        sender_ctx.add_input(&input, &None, amount + fee + 2_000_000_000);
        sender_ctx.add_output(&change, &None, 2_000_000_000);
        sender_ctx.amount = amount; sender_ctx.fee = Some(FeeFields::new(0, fee).unwrap());
        let mut s1 = Slate::blank(2, false); s1.amount = amount; s1.fee_fields = FeeFields::new(0, fee).unwrap(); s1.ttl_cutoff_height = 100;
        s1.fill_round_1(&sender, &mut sender_ctx).unwrap(); s1.compact().unwrap();
        let packer = Slatepacker::new(SlatepackerArgs { sender: None, recipients: vec![], dec_key: None });
        let s1_armor = packer.armor_slatepack(&packer.create_slatepack(&s1).unwrap()).unwrap();
        let mut s2 = s1.clone(); s2.tx = Some(Slate::empty_transaction());
        s2.add_transaction_elements(&receiver, &ProofBuilder::new(&receiver), vec![build::output(amount, output.clone())]).unwrap();
        let mut rx = Context::new(receiver.secp(), &parent, false, false); rx.add_output(&output, &None, amount);
        s2.fill_round_1(&receiver, &mut rx).unwrap();
        // Synthetic fixture only; the application's signer remains disabled.
        let part = aggsig::calculate_partial_sig(receiver.secp(), &rx.sec_key, &rx.sec_nonce,
            &s2.pub_nonce_sum(receiver.secp()).unwrap(), Some(&s2.pub_blind_sum(receiver.secp()).unwrap()),
            &s2.msg_to_sign().unwrap()).unwrap();
        s2.participant_data.last_mut().unwrap().part_sig = Some(part);
        s2.adjust_offset(&receiver, &rx).unwrap(); s2.remove_other_sigdata(&receiver, &rx.sec_nonce, &rx.sec_key).unwrap();
        s2.amount = 0; s2.fee_fields = FeeFields::zero(); s2.state = SlateState::Standard2;
        let secret = address::address_from_derivation_path(&sender, &parent, 0).unwrap();
        let recipient = SlatepackAddress::try_from(&secret).unwrap();
        let mut packet = packer.create_slatepack(&s2).unwrap(); packet.try_encrypt_payload(vec![recipient]).unwrap();
        let encrypted = packer.armor_slatepack(&packet).unwrap();
        grin_core::global::CHAIN_TYPE.with(|value| value.set(previous));

        let alice = Keys::generate(); let bob = Keys::generate(); let mallory = Keys::generate();
        let make = |key: &Keys| super::super::wrapv3::wrap(key, &bob.public_key(),
            protocol::build_payment_content(&encrypted), protocol::build_rumor_tags(None)).unwrap();
        let relay = FakeRelay { backlog: vec![make(&mallory), make(&alice)], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let message = session.receive_message(Duration::from_secs(3)).await.unwrap();
        let context = ReplyContext { network: Network::Floonet, wallet_id: [1; 32], operation_id: [2; 16],
            pinned_contact: *alice.public_key().as_bytes(), observed_height: Some(99) };
        let wrong = ReplyContext { pinned_contact: *mallory.public_key().as_bytes(), ..context };
        assert!(message.slatepack_for_pinned_contact(&wrong).is_err());
        assert!(message.fingerprint_standard_reply(&s1_armor, &[17; 32], &wrong).is_err());
        let extracted = message.slatepack_for_pinned_contact(&context).unwrap();
        assert!(inspector::fingerprint_encrypted_standard_reply(&s1_armor, &extracted, &[17; 32], &context).is_ok());
        assert!(message.fingerprint_standard_reply(&s1_armor, &[17; 32], &context).is_ok());
        let unknown_height = ReplyContext { observed_height: None, ..context };
        let expired = ReplyContext { observed_height: Some(100), ..context };
        assert!(inspector::fingerprint_encrypted_standard_reply(&s1_armor, &extracted, &[17; 32], &unknown_height).is_err());
        assert!(inspector::fingerprint_encrypted_standard_reply(&s1_armor, &extracted, &[17; 32], &expired).is_err());
        assert!(message.fingerprint_standard_reply(&s1_armor, &[17; 32], &unknown_height).is_err());
        assert!(message.fingerprint_standard_reply(&s1_armor, &[17; 32], &expired).is_err());
        assert!(message.fingerprint_standard_reply(&s1_armor, &[18; 32], &context).is_err());
        assert!(inspector::fingerprint_encrypted_standard_reply(&s1_armor, &extracted, &[18; 32], &context).is_err());
        session.close().await;
    }

    #[tokio::test]
    async fn bound_reply_reopens_only_for_original_request_before_publication() {
        use super::super::queue_record::{payment_operation_slot, Network, PaymentStage, QueueIdentity, QueueKey};
        use super::super::queue_store::{bound_reply_status, OutgoingStatus};
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-bound-reply-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let relay = FakeRelay::default();
        let sent = relay.published.clone();
        let acknowledgement = relay.acknowledge.clone();
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let session = ContactSession::connect_client(client, bob.clone(), alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let mut identity = QueueIdentity { network: Network::Floonet, wallet_id: [4;32], slot: [6;16],
            sender: bob.public_key(), recipient: alice.public_key() };
        let key = QueueKey::derive(&[7;32], &identity).unwrap();
        let slate_id = [8;16];
        identity.slot = payment_operation_slot(&key, &identity, &slate_id, PaymentStage::Standard1).unwrap();
        let request = "BEGINSLATEPACK. original ENDSLATEPACK.";
        let reply = "BEGINSLATEPACK. reply ENDSLATEPACK.";
        assert_eq!(session.prepare_bound_reply(&dir, &key, &identity, &slate_id,
            request, reply, Duration::from_secs(3600)).await, Ok(QueueWrite::Stored));
        let now = Timestamp::now().as_secs();
        assert_eq!(bound_reply_status(&dir, &key, &identity, &slate_id, request, now),
            Ok(OutgoingStatus::Unacknowledged { delivery_window_expired: false }));
        session.close().await;
        let relay = FakeRelay { published: sent.clone(), acknowledge: acknowledgement.clone(),
            ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert_eq!(session.publish_bound_reply(&dir, &key, &identity, &slate_id,
            "BEGINSLATEPACK. altered ENDSLATEPACK.", Duration::from_secs(3)).await,
            Err(SessionError::StorageUnavailable));
        assert!(sent.lock().unwrap().is_empty());
        assert_eq!(session.prepare_bound_reply(&dir, &key, &identity, &slate_id,
            request, reply, Duration::from_secs(3600)).await, Ok(QueueWrite::Indeterminate));
        assert_eq!(session.retry_bound_reply(&dir, &key, &identity, &slate_id,
            request, Duration::from_millis(100), Duration::from_millis(10), 2).await, Ok(Publication::Unknown));
        acknowledgement.store(true, Ordering::SeqCst);
        assert_eq!(session.retry_bound_reply(&dir, &key, &identity, &slate_id,
            request, Duration::from_secs(3), Duration::from_millis(10), 2).await, Ok(Publication::RelayAccepted));
        assert_eq!(sent.lock().unwrap().len(), 3);
        assert_eq!(session.publish_bound_reply_redundantly(&dir, &key, &identity, &slate_id,
            "BEGINSLATEPACK. altered ENDSLATEPACK.", Duration::from_secs(3)).await,
            Err(SessionError::StorageUnavailable));
        assert_eq!(session.publish_bound_reply_redundantly(&dir, &key, &identity, &slate_id,
            request, Duration::from_secs(3)).await, Ok(Publication::RelayAccepted));
        let copies = sent.lock().unwrap().clone();
        assert_eq!(copies.len(), 4);
        assert!(copies.iter().all(|id| id == &copies[0]));
        assert_eq!(bound_reply_status(&dir, &key, &identity, &slate_id, request, now + 3601),
            Ok(OutgoingStatus::RelayAccepted { delivery_window_expired: true }));
        assert!(bound_reply_status(&dir, &key, &identity, &slate_id,
            "BEGINSLATEPACK. altered ENDSLATEPACK.", now).is_err());
        session.close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn expired_saved_payment_is_distinguished_from_unavailable_storage() {
        use super::super::queue_record::{payment_operation_slot, Network, PaymentStage, QueueIdentity, QueueKey};
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-expired-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let relay = FakeRelay::default();
        let sent = relay.published.clone();
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let session = ContactSession::connect_client(client, alice.clone(), bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let mut identity = QueueIdentity { network: Network::Floonet, wallet_id: [1;32], slot: [2;16],
            sender: alice.public_key(), recipient: bob.public_key() };
        let key = QueueKey::derive(&[3;32], &identity).unwrap();
        let slate_id = [4;16];
        let request = "BEGINSLATEPACK. request ENDSLATEPACK.";
        let reply = "BEGINSLATEPACK. reply ENDSLATEPACK.";
        assert_eq!(session.prepare_payment_stored_for(&dir, &key, &identity, reply, None, false,
            Duration::from_secs(3)).await, Ok(QueueWrite::Stored));
        identity.slot = payment_operation_slot(&key, &identity, &slate_id, PaymentStage::Standard1).unwrap();
        assert_eq!(session.prepare_bound_reply(&dir, &key, &identity, &slate_id, request, reply,
            Duration::from_secs(3)).await, Ok(QueueWrite::Stored));
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(session.publish_bound_reply(&dir, &key, &identity, &slate_id, request,
            Duration::from_secs(1)).await, Err(SessionError::Expired));
        assert_eq!(session.publish_bound_reply_redundantly(&dir, &key, &identity, &slate_id, request,
            Duration::from_secs(1)).await, Err(SessionError::Expired));
        identity.slot = [2;16];
        assert_eq!(session.publish_stored(&dir, &key, &identity, Duration::from_secs(1)).await,
            Err(SessionError::Expired));
        assert_eq!(session.publish_stored_redundantly(&dir, &key, &identity, Duration::from_secs(1)).await,
            Err(SessionError::Expired));
        assert!(sent.lock().unwrap().is_empty());
        session.close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn retry_worker_keeps_one_event_through_uncertain_sends_and_reconnect() {
        use super::super::queue_record::{Network, QueueIdentity, QueueKey};
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-retry-worker-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [1;32], slot: [2;16],
            sender: alice.public_key(), recipient: bob.public_key() };
        let key = QueueKey::derive(&[3;32], &identity).unwrap();
        let relay = FakeRelay::default();
        let sent = relay.published.clone();
        let acknowledgement = relay.acknowledge.clone();
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let session = ContactSession::connect_client(client, alice.clone(), bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert_eq!(session.prepare_payment_stored(&dir, &key, &identity,
            "BEGINSLATEPACK. synthetic ENDSLATEPACK.", None).await, Ok(QueueWrite::Stored));
        assert_eq!(session.retry_stored(&dir, &key, &identity, Duration::from_millis(100),
            Duration::from_millis(10), 2).await, Ok(Publication::Unknown));
        assert_eq!(session.retry_stored(&dir, &key, &identity, Duration::from_millis(100),
            Duration::from_millis(10), 0).await, Err(SessionError::InvalidInput));
        session.close().await;
        let relay = FakeRelay { published: sent.clone(), acknowledge: acknowledgement.clone(), ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let session = ContactSession::connect_client(client, alice, bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        acknowledgement.store(true, Ordering::SeqCst);
        assert_eq!(session.retry_stored(&dir, &key, &identity, Duration::from_secs(3),
            Duration::from_millis(10), 2).await, Ok(Publication::RelayAccepted));
        let sent = sent.lock().unwrap().clone();
        assert_eq!(sent.len(), 3);
        assert!(sent.iter().all(|id| id == &sent[0]));
        session.close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn explicit_second_relay_reuses_the_same_saved_event() {
        use super::super::queue_record::{Network, QueueIdentity, QueueKey};
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir().join(format!("fly-redundant-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let alice = Keys::generate();
        let bob = Keys::generate();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [1;32], slot: [2;16],
            sender: alice.public_key(), recipient: bob.public_key() };
        let key = QueueKey::derive(&[3;32], &identity).unwrap();
        let first_relay = FakeRelay::default();
        first_relay.acknowledge.store(true, Ordering::SeqCst);
        let first_events = first_relay.published.clone();
        let client = ClientBuilder::new().websocket_transport(first_relay).build();
        let first = ContactSession::connect_client(client, alice.clone(), bob.public_key(),
            Url::parse("wss://one.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert_eq!(first.prepare_payment_stored(&dir, &key, &identity,
            "BEGINSLATEPACK. synthetic ENDSLATEPACK.", None).await, Ok(QueueWrite::Stored));
        assert_eq!(first.publish_stored(&dir, &key, &identity, Duration::from_secs(3)).await,
            Ok(Publication::RelayAccepted));
        first.close().await;

        let second_relay = FakeRelay::default();
        let second_ack = second_relay.acknowledge.clone();
        let second_events = second_relay.published.clone();
        let client = ClientBuilder::new().websocket_transport(second_relay).build();
        let second = ContactSession::connect_client(client, alice, bob.public_key(),
            Url::parse("wss://two.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert_eq!(second.publish_stored_redundantly(&dir, &key, &identity, Duration::from_millis(100)).await,
            Ok(Publication::Unknown));
        second_ack.store(true, Ordering::SeqCst);
        assert_eq!(second.publish_stored_redundantly(&dir, &key, &identity, Duration::from_secs(3)).await,
            Ok(Publication::RelayAccepted));
        let first_id = first_events.lock().unwrap()[0].clone();
        let retried = second_events.lock().unwrap().clone();
        assert_eq!(retried, vec![first_id.clone(), first_id]);
        second.close().await;
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[tokio::test]
    async fn payment_offline_window_is_bounded_and_survives_a_late_reopen() {
        use super::super::queue_record::{Network, QueueIdentity, QueueKey};
        let alice = Keys::generate();
        let bob = Keys::generate();
        let client = ClientBuilder::new().websocket_transport(FakeRelay::default()).build();
        let session = ContactSession::connect_client(client, alice.clone(), bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let armor = "BEGINSLATEPACK. synthetic ENDSLATEPACK.";
        assert!(matches!(session.prepare_payment_for(armor, None, false, Duration::ZERO).await,
            Err(SessionError::InvalidInput)));
        assert!(matches!(session.prepare_payment_for(armor, None, false, Duration::from_secs(604_801)).await,
            Err(SessionError::InvalidInput)));
        assert!(matches!(session.prepare_payment_for(armor, None, false, Duration::from_millis(1500)).await,
            Err(SessionError::InvalidInput)));
        let before = Timestamp::now().as_secs();
        let prepared = session.prepare_payment_for(armor, None, false, Duration::from_secs(86_400)).await.unwrap();
        assert!(prepared.expires_at >= before + 86_400);
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [1;32], slot: [2;16],
            sender: alice.public_key(), recipient: bob.public_key() };
        let key = QueueKey::derive(&[3;32], &identity).unwrap();
        let record = super::super::queue_record::seal(&key, &identity, &prepared, before).unwrap();
        let reopened = super::super::queue_record::open(&key, &identity, &record, before + 3600).unwrap();
        assert_eq!(reopened.event.id, prepared.event.id);
        assert!(super::super::queue_record::open(&key, &identity, &record, prepared.expires_at).is_err());
        session.close().await;
    }

    #[tokio::test]
    async fn prepares_payment_message_with_tags_without_claiming_slate_validity() {
        let alice = Keys::generate(); let bob = Keys::generate();
        let client = ClientBuilder::new().websocket_transport(FakeRelay::default()).build();
        let session = ContactSession::connect_client(client, alice.clone(), bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let armor = "BEGINSLATEPACK. synthetic ENDSLATEPACK.";
        assert!(matches!(session.prepare_payment_rumor("not armor", None).await, Err(SessionError::InvalidInput)));
        assert!(matches!(session.prepare_payment_rumor(&format!("{armor} {armor}"), None).await, Err(SessionError::InvalidInput)));
        let prepared = session.prepare_payment_rumor(armor, Some("memo")).await.unwrap();
        let opened = unwrap_from_contact(&bob, &prepared.event, &alice.public_key()).await.unwrap();
        assert_eq!(protocol::extract_slatepack(&opened.rumor.content).as_deref(), Some(armor));
        assert_eq!(protocol::extract_subject(&opened.rumor.tags).as_deref(), Some("memo"));
        assert!(opened.rumor.tags.iter().any(|tag| tag.as_slice().first().map(String::as_str) == Some("goblin")));
        assert!(prepared.expires_at > Timestamp::now().as_secs());
        session.close().await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn optional_text_history_is_stored_with_event_and_readable_after_expiry() {
        use std::{fs, path::PathBuf};
        use super::super::queue_record::{Network, QueueIdentity, QueueKey};
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        let tmp = root.join(".tmp");
        assert_eq!(fs::canonicalize(std::env::temp_dir()).unwrap(), fs::canonicalize(&tmp).unwrap());
        let mut random = [0u8; 16]; getrandom::getrandom(&mut random).unwrap();
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let dir = tmp.join(format!("fly-outbox-history-synthetic-{suffix}")); fs::create_dir(&dir).unwrap();
        let alice = Keys::generate(); let bob = Keys::generate();
        let client = ClientBuilder::new().websocket_transport(FakeRelay::default()).build();
        let session = ContactSession::connect_client(client, alice.clone(), bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let event = session.prepare_with_history("SYNTHETIC_OUTGOING_HISTORY").await.unwrap();
        let identity = QueueIdentity { network:Network::Floonet, wallet_id:[7;32], slot:[3;16],
            sender:alice.public_key(), recipient:bob.public_key() };
        let key = QueueKey::derive(&[9;32], &identity).unwrap();
        super::super::queue_store::persist(&dir, &key, &identity, &event, Timestamp::now().as_secs()).unwrap();
        let restored = super::super::queue_store::load_history(&dir, &key, &identity).unwrap();
        assert_eq!(restored.text(), "SYNTHETIC_OUTGOING_HISTORY");
        assert_eq!(restored.event_id, event.event.id);
        assert!(super::super::queue_store::load(&dir, &key, &identity, event.expires_at).is_err());
        let path = dir.join(format!("out-{}.flyq", identity.slot.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        let bytes = fs::read(path).unwrap();
        assert!(!bytes.windows(b"SYNTHETIC_OUTGOING_HISTORY".len()).any(|s| s == b"SYNTHETIC_OUTGOING_HISTORY"));
        let armor = "BEGINSLATEPACK. synthetic ENDSLATEPACK.";
        let payment_identity = QueueIdentity { slot:[4;16], ..identity };
        let payment_key = QueueKey::derive(&[9;32], &payment_identity).unwrap();
        assert_eq!(session.prepare_payment_stored_with_history(&dir, &payment_key, &payment_identity, armor, None).await,
            Ok(QueueWrite::Stored));
        let payment = super::super::queue_store::load_history(&dir, &payment_key, &payment_identity).unwrap();
        assert_eq!(protocol::extract_slatepack(payment.text()).as_deref(), Some(armor));
        assert!(super::super::queue_store::load(&dir, &payment_key, &payment_identity,
            Timestamp::now().as_secs() + 3600).is_err());
        let transient_identity = QueueIdentity { slot:[5;16], ..identity };
        let transient_key = QueueKey::derive(&[9;32], &transient_identity).unwrap();
        assert_eq!(session.prepare_payment_stored(&dir, &transient_key, &transient_identity, armor, None).await,
            Ok(QueueWrite::Stored));
        assert!(super::super::queue_store::load_history(&dir, &transient_key, &transient_identity).is_err());
        session.close().await;
    }

    #[tokio::test]
    async fn backlog_discards_expired_and_ambiguous_expiration_without_rejecting_unlimited_messages() {
        let alice = Keys::generate(); let bob = Keys::generate();
        let now = Timestamp::now().as_secs();
        let rumor = |text: &str| EventBuilder::new(Kind::PrivateDirectMessage, text)
            .tag(Tag::public_key(bob.public_key())).build(alice.public_key());
        let expired = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor("expired"),
            [Tag::expiration(Timestamp::from(now))]).await.unwrap();
        let ambiguous = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor("ambiguous"),
            [Tag::expiration(Timestamp::from(now + 60)), Tag::expiration(Timestamp::from(now + 120))]).await.unwrap();
        let active = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor("active"),
            [Tag::expiration(Timestamp::from(now + 60))]).await.unwrap();
        let unlimited = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor("unlimited"), []).await.unwrap();
        assert!(!not_expired(&expired, now));
        assert!(!not_expired(&ambiguous, now));
        assert!(not_expired(&active, now));
        assert!(not_expired(&unlimited, now));
        let mut backlog = vec![expired; 2];
        backlog.extend([ambiguous, active, unlimited]);
        let relay = FakeRelay { backlog, ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert_eq!(session.receive(Duration::from_secs(3)).await, Ok("active".to_owned()));
        assert_eq!(session.receive(Duration::from_secs(3)).await, Ok("unlimited".to_owned()));
        session.close().await;
    }

    #[tokio::test]
    async fn duplicate_event_is_suppressed_only_after_authentication() {
        let alice = Keys::generate(); let bob = Keys::generate();
        let valid = super::super::wrapv3::wrap(&alice, &bob.public_key(), "known".to_owned(), vec![]).unwrap();
        let mut tampered = valid.clone(); tampered.content.push('x');
        let relay = FakeRelay { backlog: vec![valid.clone(), valid], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert!(session.accept_event(&tampered).await.is_none());
        assert_eq!(session.receive(Duration::from_secs(3)).await, Ok("known".to_owned()));
        assert_eq!(session.receive(Duration::from_millis(100)).await, Err(SessionError::Timeout));
        session.close().await;
    }

    #[tokio::test]
    async fn pending_message_is_repeated_until_the_matching_acknowledgement() {
        let alice = Keys::generate(); let bob = Keys::generate();
        let first = super::super::wrapv3::wrap(&alice, &bob.public_key(), "first".to_owned(), vec![]).unwrap();
        let second = super::super::wrapv3::wrap(&alice, &bob.public_key(), "second".to_owned(), vec![]).unwrap();
        let first_id = first.id; let second_id = second.id;
        let relay = FakeRelay { backlog: vec![first.clone(), first, second], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert_eq!(session.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), first_id);
        assert_eq!(session.acknowledge_received(second_id), Err(SessionError::InvalidInput));
        assert_eq!(session.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), first_id);
        assert_eq!(session.acknowledge_received(first_id), Ok(()));
        assert_eq!(session.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), second_id);
        assert_eq!(session.acknowledge_received(second_id), Ok(()));
        assert_eq!(session.receive_pending(Duration::from_millis(100)).await.err(), Some(SessionError::Timeout));
        session.close().await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn inbox_reopen_child() {
        use std::{fs, os::windows::fs::MetadataExt, path::PathBuf};
        use super::super::queue_record::{Network, QueueIdentity, QueueKey};
        let Some(dir) = std::env::var_os("FLY_RESEARCH_INBOX_CHILD") else { return; };
        let dir = PathBuf::from(dir);
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(), fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp = root.join(".tmp");
        assert_eq!(fs::canonicalize(dir.parent().unwrap()).unwrap(), fs::canonicalize(&tmp).unwrap());
        assert_eq!(fs::symlink_metadata(&dir).unwrap().file_attributes() & 0x400, 0);
        assert!(dir.file_name().unwrap().to_string_lossy().starts_with("fly-inbox-synthetic-"));
        let alice = Keys::parse(&"01".repeat(32)).unwrap(); let bob = Keys::parse(&"02".repeat(32)).unwrap();
        let expected = EventId::parse(&std::env::var("FLY_RESEARCH_INBOX_EVENT").unwrap()).unwrap();
        let slots = super::super::queue_store::discover_incoming(&dir).unwrap();
        assert_eq!(slots.len(), 1);
        let slot = slots[0];
        assert_eq!(slot, expected.as_bytes()[..16]);
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot,
            sender: alice.public_key(), recipient: bob.public_key() };
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let client = ClientBuilder::new().websocket_transport(FakeRelay::default()).build();
        let session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let restored = session.restore_discovered(&dir, &key, &identity).await.unwrap();
        assert_eq!(restored.envelope_id(), expected);
        assert_eq!(restored.rumor().content, "INBOX_SYNTHETIC_PRIVATE");
        session.close().await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn pending_inbox_survives_new_session_and_refuses_tampering() {
        use std::{fs, os::windows::fs::MetadataExt, path::PathBuf};
        use super::super::queue_record::{Network, QueueIdentity, QueueKey};
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(), fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp = root.join(".tmp");
        assert_eq!(fs::canonicalize(std::env::temp_dir()).unwrap(), fs::canonicalize(&tmp).unwrap());
        for path in [&root, &tmp] { assert_eq!(fs::symlink_metadata(path).unwrap().file_attributes() & 0x400, 0); }
        let mut random = [0u8; 16]; getrandom::getrandom(&mut random).unwrap();
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let dir = tmp.join(format!("fly-inbox-synthetic-{suffix}")); fs::create_dir(&dir).unwrap();
        let alice = Keys::parse(&"01".repeat(32)).unwrap(); let bob = Keys::parse(&"02".repeat(32)).unwrap(); let other = Keys::generate();
        let event = super::super::wrapv3::wrap(&alice, &bob.public_key(), "INBOX_SYNTHETIC_PRIVATE".to_owned(), vec![]).unwrap();
        let expected = event.id;
        let relay = FakeRelay { backlog: vec![event], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let mut session = ContactSession::connect_client(client, bob.clone(), alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let message = session.receive_pending(Duration::from_secs(3)).await.unwrap();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot: message.storage_slot(),
            sender: alice.public_key(), recipient: bob.public_key() };
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let mut wrong = identity; wrong.sender = other.public_key();
        assert_eq!(session.persist_pending_and_acknowledge(&dir, &key, &wrong), Err(SessionError::InvalidInput));
        assert_eq!(session.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), expected);
        assert_eq!(session.persist_pending(&dir, &key, &identity), Ok(QueueWrite::Stored));
        assert_eq!(session.persist_pending_and_acknowledge(&dir, &key, &identity), Ok(QueueWrite::Indeterminate));
        assert_eq!(session.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), expected);
        let filename: String = identity.slot.iter().map(|b| format!("{b:02x}")).collect();
        let path = dir.join(format!("in-{filename}.flyi"));
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes.windows(b"INBOX_SYNTHETIC_PRIVATE".len()).any(|v| v == b"INBOX_SYNTHETIC_PRIVATE"));
        let wrong_key = QueueKey::derive(&[8; 32], &identity).unwrap();
        assert!(session.reconcile_pending_and_acknowledge(&dir, &wrong_key, &identity).await.is_err());
        assert_eq!(session.receive_pending(Duration::from_secs(3)).await.unwrap().envelope_id(), expected);
        assert_eq!(session.reconcile_pending_and_acknowledge(&dir, &key, &identity).await, Ok(()));
        assert!(session.uncommitted.is_none());
        session.close().await;
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["nostr::contact_session::tests::inbox_reopen_child", "--exact", "--test-threads=1"])
            .env("FLY_RESEARCH_INBOX_CHILD", &dir).env("FLY_RESEARCH_INBOX_EVENT", expected.to_string())
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped())
            .spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(20);
        loop {
            if child.try_wait().unwrap().is_some() { break; }
            if std::time::Instant::now() >= deadline { let _ = child.kill(); let _ = child.wait(); panic!("synthetic inbox child timed out"); }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        let client = ClientBuilder::new().websocket_transport(FakeRelay::default()).build();
        let restored_session = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let restored = restored_session.restore_received(&dir, &key, &identity, expected).await.unwrap();
        assert_eq!(restored.envelope_id(), expected);
        assert_eq!(restored.rumor().content, "INBOX_SYNTHETIC_PRIVATE");
        let wrong_key = QueueKey::derive(&[8; 32], &identity).unwrap();
        assert!(restored_session.restore_received(&dir, &wrong_key, &identity, expected).await.is_err());
        let mut damaged = bytes; let end = damaged.len() - 1; damaged[end] ^= 1; fs::write(path, damaged).unwrap();
        assert!(restored_session.restore_received(&dir, &key, &identity, expected).await.is_err());
        restored_session.close().await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn persist_then_acknowledge_keeps_only_successful_commit() {
        use std::{fs, path::PathBuf};
        use super::super::queue_record::{Network, QueueIdentity, QueueKey};
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        let tmp = root.join(".tmp");
        assert_eq!(fs::canonicalize(std::env::temp_dir()).unwrap(), fs::canonicalize(&tmp).unwrap());
        let mut random = [0u8; 16]; getrandom::getrandom(&mut random).unwrap();
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let dir = tmp.join(format!("fly-inbox-ack-synthetic-{suffix}")); fs::create_dir(&dir).unwrap();
        let alice = Keys::generate(); let bob = Keys::generate();
        let event = super::super::wrapv3::wrap(&alice, &bob.public_key(), "SYNTHETIC".to_owned(), vec![]).unwrap();
        let id = event.id;
        let client = ClientBuilder::new().websocket_transport(FakeRelay { backlog: vec![event], ..Default::default() }).build();
        let mut session = ContactSession::connect_client(client, bob.clone(), alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let message = session.receive_pending(Duration::from_secs(3)).await.unwrap();
        let identity = QueueIdentity { network:Network::Floonet, wallet_id:[7;32], slot:message.storage_slot(),
            sender:alice.public_key(), recipient:bob.public_key() };
        let key = QueueKey::derive(&[9;32], &identity).unwrap();
        assert_eq!(session.persist_pending_and_acknowledge(&dir, &key, &identity), Ok(QueueWrite::Stored));
        assert!(session.uncommitted.is_none());
        assert!(session.seen.contains(&id));
        assert_eq!(session.restore_received(&dir, &key, &identity, id).await.unwrap().envelope_id(), id);
        assert_eq!(session.persist_pending_and_acknowledge(&dir, &key, &identity), Err(SessionError::InvalidInput));
        session.close().await;
    }

    #[tokio::test]
    async fn oversized_backlog_does_not_produce_a_ready_session() {
        let alice = Keys::generate(); let bob = Keys::generate();
        let event = super::super::wrapv3::wrap(&alice, &bob.public_key(), "synthetic".to_owned(), vec![]).unwrap();
        let relay = FakeRelay { backlog: vec![event; MAX_PENDING + 1], ..Default::default() };
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let result = ContactSession::connect_client(client, bob, alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await;
        assert!(matches!(result, Err(SessionError::SubscriptionFailed | SessionError::Closed)));
    }

    #[tokio::test]
    async fn uncertain_send_retries_same_event_and_id() {
        let alice = Keys::generate(); let bob = Keys::generate();
        let relay = FakeRelay::default();
        let ids = relay.published.clone(); let ack = relay.acknowledge.clone();
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let session = ContactSession::connect_client(client, alice, bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let prepared = session.prepare("synthetic").await.unwrap();
        assert_eq!(session.publish(&prepared, Duration::from_millis(100)).await, Ok(Publication::Unknown));
        ack.store(true, Ordering::SeqCst);
        assert_eq!(session.publish(&prepared, Duration::from_secs(3)).await, Ok(Publication::RelayAccepted));
        let ids = ids.lock().unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], ids[1]);
        drop(ids);
        session.close().await;
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn stored_send_refuses_missing_wrong_identity_and_corruption_before_network() {
        use std::{fs, os::windows::fs::MetadataExt, path::PathBuf};
        use super::super::{queue_record::{Network, QueueIdentity, QueueKey}, queue_store};
        let root = PathBuf::from(std::env::var_os("FLY_ROOT").unwrap());
        assert_eq!(fs::canonicalize(&root).unwrap(), fs::canonicalize(r"C:\DHW\GrinSight\FlyClient").unwrap());
        let tmp = root.join(".tmp");
        assert_eq!(fs::canonicalize(std::env::temp_dir()).unwrap(), fs::canonicalize(&tmp).unwrap());
        for p in [&root, &tmp] { assert_eq!(fs::symlink_metadata(p).unwrap().file_attributes() & 0x400, 0); }
        let mut random = [0u8; 16]; getrandom::getrandom(&mut random).unwrap();
        let suffix: String = random.iter().map(|b| format!("{b:02x}")).collect();
        let dir = tmp.join(format!("fly-queue-session-test-{suffix}")); fs::create_dir(&dir).unwrap();
        let alice = Keys::generate(); let bob = Keys::generate();
        let identity = QueueIdentity { network: Network::Floonet, wallet_id: [7; 32], slot: [3; 16],
            sender: alice.public_key(), recipient: bob.public_key() };
        let key = QueueKey::derive(&[9; 32], &identity).unwrap();
        let relay = FakeRelay::default();
        let ack = relay.acknowledge.clone();
        let ids = relay.published.clone();
        let client = ClientBuilder::new().websocket_transport(relay).build();
        let session = ContactSession::connect_client(client, alice, bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let wait = Duration::from_secs(3);
        assert_eq!(session.publish_stored(&dir, &key, &identity, wait).await, Err(SessionError::StorageUnavailable));
        assert!(ids.lock().unwrap().is_empty());
        let armor = "BEGINSLATEPACK. synthetic ENDSLATEPACK.";
        assert_eq!(session.prepare_payment_stored(&dir, &key, &identity, "bad armor", None).await, Err(SessionError::InvalidInput));
        assert_eq!(session.prepare_payment_stored(&dir, &key, &identity, armor, Some("memo")).await, Ok(QueueWrite::Stored));
        let original = queue_store::load(&dir, &key, &identity, Timestamp::now().as_secs()).unwrap().event.id;
        assert_eq!(session.prepare_payment_stored(&dir, &key, &identity, armor, Some("other")).await, Ok(QueueWrite::Indeterminate));
        assert_eq!(queue_store::load(&dir, &key, &identity, Timestamp::now().as_secs()).unwrap().event.id, original);
        assert!(ids.lock().unwrap().is_empty(), "preparation must not publish");
        let mut wrong = identity; wrong.recipient = Keys::generate().public_key();
        assert_eq!(session.publish_stored(&dir, &key, &wrong, wait).await, Err(SessionError::InvalidInput));
        assert!(ids.lock().unwrap().is_empty());
        assert_eq!(session.publish_stored(&dir, &key, &identity, Duration::from_millis(100)).await, Ok(Publication::Unknown));
        assert_eq!(ids.lock().unwrap().as_slice(), [original.to_string()]);
        ack.store(true, Ordering::SeqCst);
        assert_eq!(session.publish_stored(&dir, &key, &identity, wait).await, Ok(Publication::RelayAccepted));
        assert_eq!(session.publish_stored(&dir, &key, &identity, wait).await, Ok(Publication::RelayAccepted));
        assert_eq!(ids.lock().unwrap().as_slice(), [original.to_string(), original.to_string()],
            "only the saved event may be retried; an acknowledged event must not be republished");
        let path = dir.join(format!("out-{}.flyq", "03".repeat(16)));
        let mut bytes = fs::read(&path).unwrap(); let last = bytes.len() - 1; bytes[last] ^= 1;
        fs::write(path, bytes).unwrap();
        assert_eq!(session.publish_stored(&dir, &key, &identity, wait).await, Err(SessionError::StorageUnavailable));
        assert_eq!(ids.lock().unwrap().len(), 2);
        session.close().await;
    }

    // ---- GrinSight Fly v0.2: envelopes kept by the payment core -----------
    const FLY_ARMOR: &str = "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY GWmtgsneoXf7N4D uVWuyZSamPhfF1u AHRaYWvhF7jQvKx wNJAc7qmVm9JVcm NJLEw4k5BU7jY6S eb. ENDSLATEPACK.";

    #[tokio::test]
    async fn fly_envelope_is_sealed_offline_and_published_byte_for_byte() {
        let alice = Keys::generate(); let bob = Keys::generate(); let mallory = Keys::generate();
        let window = Duration::from_secs(900);
        // sealing needs keys only
        let prepared = seal_payment(&alice, bob.public_key(), FLY_ARMOR, None, window).await.unwrap();
        let (id, json, deadline) = prepared.envelope();
        assert!(json.len() <= MAX_ENVELOPE_JSON);
        assert!(!json.contains("BEGINSLATEPACK"), "the envelope holds the slatepack in the clear");
        let now = Timestamp::now().as_secs();
        assert!(deadline > now && deadline <= now + 901);
        // on the outside: the addressee and nothing else; no deadline for a
        // relay to object to or an observer to tell our messages by
        let outside = Event::from_json(&json).unwrap();
        assert_eq!(outside.tags.len(), 1);
        assert_eq!(outside.tags.public_keys().next(), Some(&bob.public_key()));
        assert!(!json.contains("expiration"));
        // sealing again gives another message: the stored one must be reused
        let again = seal_payment(&alice, bob.public_key(), FLY_ARMOR, None, window).await.unwrap();
        assert_ne!(again.envelope().0, id);
        // what cannot be sealed
        assert_eq!(seal_payment(&alice, alice.public_key(), FLY_ARMOR, None, window).await.err(), Some(SessionError::InvalidInput));
        assert_eq!(seal_payment(&alice, bob.public_key(), "{\"not\":\"armor\"}", None, window).await.err(), Some(SessionError::InvalidInput));
        assert_eq!(seal_payment(&alice, bob.public_key(), FLY_ARMOR, None, Duration::ZERO).await.err(), Some(SessionError::InvalidInput));
        assert_eq!(seal_payment(&alice, bob.public_key(), FLY_ARMOR, None, Duration::from_secs(8 * 24 * 3600)).await.err(), Some(SessionError::InvalidInput));

        // the recipient opens it and sees who sent it
        let opened = unwrap_from_contact(&bob, &Event::from_json(&json).unwrap(), &alice.public_key()).await.unwrap();
        assert_eq!(opened.sender, alice.public_key());
        assert_eq!(protocol::extract_slatepack(&opened.rumor.content).as_deref(), Some(FLY_ARMOR));
        // the deadline travels inside, where only the recipient reads it
        assert_eq!(opened.rumor.tags.expiration().map(|t| t.as_secs()), Some(deadline));
        assert!(tags_not_expired(&opened.rumor.tags, deadline - 1));
        assert!(!tags_not_expired(&opened.rumor.tags, deadline));

        // published twice from the stored text: the relay sees the same event both times
        let relay = FakeRelay::default();
        relay.acknowledge.store(true, Ordering::SeqCst);
        let published = relay.published.clone(); let events = relay.published_events.clone();
        let client = ClientBuilder::new().websocket_transport(relay.clone()).build();
        let session = ContactSession::connect_client(client, alice.clone(), bob.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        let wait = Duration::from_secs(3);
        assert_eq!(session.publish_envelope(&json, deadline, wait).await, Ok(Publication::RelayAccepted));
        assert_eq!(session.publish_envelope(&json, deadline, wait).await, Ok(Publication::RelayAccepted));
        {
            let ids = published.lock().unwrap();
            assert_eq!(ids.len(), 2);
            assert!(ids.iter().all(|sent| *sent == EventId::from_slice(&id).unwrap().to_string()));
            let sent: Vec<Event> = events.lock().unwrap().iter().map(|e| Event::from_json(e).unwrap()).collect();
            assert!(sent.iter().all(|e| *e == Event::from_json(&json).unwrap()));
        }
        // a relay that does not acknowledge is "unknown", never "accepted"
        relay.acknowledge.store(false, Ordering::SeqCst);
        assert_eq!(session.publish_envelope(&json, deadline, Duration::from_secs(1)).await, Ok(Publication::Unknown));

        // what is refused before anything reaches the relay
        let before = published.lock().unwrap().len();
        let for_mallory = seal_payment(&alice, mallory.public_key(), FLY_ARMOR, None, window).await.unwrap().envelope().1;
        assert_eq!(session.publish_envelope(&for_mallory, deadline, wait).await, Err(SessionError::InvalidInput));
        let mut tampered = json.clone();
        let at = tampered.find("\"content\":\"").unwrap() + 14;
        tampered.replace_range(at..at + 1, if &tampered[at..at + 1] == "A" { "B" } else { "A" });
        assert_eq!(session.publish_envelope(&tampered, deadline, wait).await, Err(SessionError::InvalidInput));
        assert_eq!(session.publish_envelope("{}", deadline, wait).await, Err(SessionError::InvalidInput));
        assert_eq!(session.publish_envelope(&"x".repeat(MAX_ENVELOPE_JSON + 1), deadline, wait).await, Err(SessionError::InvalidInput));
        assert_eq!(session.publish_envelope(&json, deadline, Duration::ZERO).await, Err(SessionError::InvalidInput));
        let plain = EventBuilder::new(Kind::TextNote, "hello").tag(Tag::public_key(bob.public_key()))
            .tag(Tag::expiration(Timestamp::from(now + 60))).sign_with_keys(&alice).unwrap();
        assert_eq!(session.publish_envelope(&plain.as_json(), deadline, wait).await, Err(SessionError::InvalidInput));
        // a gift wrap with anything more on it than its addressee is not ours
        let marked = session.prepare("hello").await.unwrap().envelope().1;
        assert!(marked.contains("expiration"));
        assert_eq!(session.publish_envelope(&marked, deadline, wait).await, Err(SessionError::InvalidInput));
        // past the deadline the caller kept, nothing is sent
        let (_, short, short_deadline) = seal_payment(&alice, bob.public_key(), FLY_ARMOR, None, Duration::from_secs(1)).await.unwrap().envelope();
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert_eq!(session.publish_envelope(&short, short_deadline, wait).await, Err(SessionError::Expired));
        assert_eq!(session.publish_envelope(&json, now, wait).await, Err(SessionError::Expired));
        // and the recipient does not take a message whose inner deadline has passed
        let client = ClientBuilder::new().websocket_transport(FakeRelay::default()).build();
        let mut bobs = ContactSession::connect_client(client, bob.clone(), alice.public_key(),
            Url::parse("wss://relay.example").unwrap(), Duration::from_secs(3)).await.unwrap();
        assert!(bobs.accept_event(&Event::from_json(&json).unwrap()).await.is_some());
        assert!(bobs.accept_event(&Event::from_json(&short).unwrap()).await.is_none(), "a message past its deadline was taken");
        bobs.close().await;
        assert_eq!(published.lock().unwrap().len(), before, "a refused envelope reached the relay");
        session.close().await;
    }
}
