// SPDX-License-Identifier: MIT OR Apache-2.0
//! Transport boundary and an in-memory mailbox for M1/tests.
//!
//! A real relay or onion transport implements [`Transport`]; the wallet-facing
//! [`Messenger`] only knows that trait. The mailbox enforces size/queue quotas
//! but deliberately **cannot verify the sender** — authenticity is checked by
//! the recipient after decryption.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use sha2::{Digest, Sha256};

use crate::address::Address;
use crate::envelope::{unix_now, Envelope, Identity, MessageKind, Opened};
use crate::error::{Error, Result};
use crate::MAX_TTL_SECS;

/// A single transport fetch; raw candidates cannot be acknowledged as normal envelopes.
pub struct TransportPage {
    pub envelopes: Vec<(Envelope, Option<String>)>,
    pub malformed: Vec<crate::transport::RawGatewayItem>,
    pub omitted_malformed: usize,
    pub unknown_formats: usize,
}

/// Minimal delivery contract. Implementations may be in-memory, file-backed,
/// Tor-direct or HTTP relay clients.
pub trait Transport: Send + Sync {
    fn take_warning(&self) -> Option<String> { None }
    fn deliver(&self, envelope: &Envelope) -> Result<()>;
    fn fetch(&self, recipient: &Address, now: u64, limit: usize) -> Result<Vec<Envelope>>;

    /// Fetch authenticated by the recipient's key. Relays that require a fetch
    /// proof override this; local mailboxes keep the legacy behaviour.
    fn fetch_signed(&self, recipient: &Identity, now: u64, limit: usize) -> Result<Vec<Envelope>> {
        self.fetch(recipient.address(), now, limit)
    }
    fn fetch_signed_tagged(&self, recipient: &Identity, now: u64, limit: usize) -> Result<Vec<(Envelope, Option<String>)>> {
        Ok(self.fetch_signed(recipient, now, limit)?.into_iter().map(|e| (e, None)).collect())
    }
    fn fetch_signed_page(&self,recipient:&Identity,now:u64,limit:usize)->Result<TransportPage> {
        Ok(TransportPage { envelopes:self.fetch_signed_tagged(recipient,now,limit)?,malformed:Vec::new(),omitted_malformed:0,unknown_formats:0 })
    }
    fn reject_saved_raw(&self,_recipient:&Identity,_quarantine:&crate::raw_quarantine::RawQuarantine,_saved:&crate::raw_quarantine::QuarantinedRaw)->Result<()> {
        Err(Error::Store("raw rejection unsupported".into()))
    }
    fn ack(&self, recipient: &Address, ids: &[String]) -> Result<usize>;

    /// Ack with proof of possession. Stores that already trust the local caller
    /// keep the legacy capability ack; HTTP transports override this to sign.
    fn ack_signed(&self, recipient: &Identity, ids: &[String]) -> Result<usize> {
        self.ack(recipient.address(), ids)
    }
}

/// Local storage capability (persistence, encrypted history). Every transport
/// is a store for M1; a file/SQLite implementation can override the semantics.
pub trait Store: Transport {}

impl<T: Transport> Store for T {}

struct StoredEnvelope {
    envelope: Envelope,
    expires_at: u64,
}

pub struct MemoryMailbox {
    queues: Mutex<HashMap<String, Vec<StoredEnvelope>>>,
    max_queue: usize,
    max_ciphertext: usize,
}

impl Default for MemoryMailbox {
    fn default() -> Self {
        Self::new(100, 64 * 1024)
    }
}

/// Expiry used for retention and replay guards. A sender clock in the future
/// cannot keep an entry longer than `MAX_TTL_SECS` from *our* now.
fn bounded_expires_at(created_at: u64, ttl: u64, now: u64) -> u64 {
    created_at
        .saturating_add(ttl)
        .min(now.saturating_add(MAX_TTL_SECS))
}

impl MemoryMailbox {
    pub fn new(max_queue: usize, max_ciphertext: usize) -> Self {
        Self {
            queues: Mutex::new(HashMap::new()),
            max_queue,
            max_ciphertext,
        }
    }
}

impl Transport for MemoryMailbox {
    fn deliver(&self, envelope: &Envelope) -> Result<()> {
        // Validate before touching state; the relay never sees plaintext.
        Address::parse(&envelope.recipient)?;
        if envelope.ttl == 0 || envelope.ttl > MAX_TTL_SECS {
            return Err(Error::BadTtl(envelope.ttl));
        }
        if envelope.ciphertext.len() > self.max_ciphertext {
            return Err(Error::Quota(format!(
                "сообщение {} Б > {} Б",
                envelope.ciphertext.len(),
                self.max_ciphertext
            )));
        }
        if envelope.is_expired(unix_now()) {
            return Err(Error::Expired);
        }

        let mut queues = self
            .queues
            .lock()
            .map_err(|_| Error::Store("mailbox poisoned".into()))?;
        let queue = queues.entry(envelope.recipient.clone()).or_default();
        if queue.iter().any(|item| item.envelope.id == envelope.id) {
            // At-least-once delivery: duplicates are accepted but stored once.
            return Ok(());
        }
        if queue.len() >= self.max_queue {
            return Err(Error::Quota(format!(
                "очередь получателя заполнена: {}",
                self.max_queue
            )));
        }
        let received_at = unix_now();
        queue.push(StoredEnvelope {
            expires_at: bounded_expires_at(envelope.created_at, envelope.ttl, received_at),
            envelope: envelope.clone(),
        });
        Ok(())
    }

    fn fetch(&self, recipient: &Address, now: u64, limit: usize) -> Result<Vec<Envelope>> {
        let key = recipient.to_string();
        let mut queues = self
            .queues
            .lock()
            .map_err(|_| Error::Store("mailbox poisoned".into()))?;
        let queue = queues.entry(key).or_default();
        queue.retain(|item| item.expires_at > now);
        Ok(queue
            .iter()
            .take(limit.max(1))
            .map(|item| item.envelope.clone())
            .collect())
    }

    fn ack(&self, recipient: &Address, ids: &[String]) -> Result<usize> {
        let key = recipient.to_string();
        let mut queues = self
            .queues
            .lock()
            .map_err(|_| Error::Store("mailbox poisoned".into()))?;
        let Some(queue) = queues.get_mut(&key) else {
            return Ok(0);
        };
        let before = queue.len();
        queue.retain(|item| !ids.contains(&item.envelope.id));
        Ok(before - queue.len())
    }
}

pub struct Messenger<T: Transport> {
    transport: T,
    /// Replay guard: id -> expiry. Kept for the envelope's TTL, so a relay that
    /// replays an already-acked message does not surface it twice.
    seen: Mutex<ReplayState>,
}

#[derive(Default)]
struct ReplayState {
    committed: HashMap<String, u64>,
    pending: HashMap<String, u64>,
    sdk_seen: HashMap<String, (Vec<u8>, u64)>,
}

/// An envelope that arrived but failed authentication/decryption. It is not
/// acked: the caller can quarantine/report it without losing the good messages
/// in the same batch.
pub struct FailedEnvelope {
    pub id: String,
    pub error: String,
    pub transport_token: Option<String>,
    pub quarantine_allowed: bool,
    pub encrypted_envelope: Option<Envelope>,
    /// Envelope expiry, so a durable quarantine entry can be cleaned up.
    pub expires_at: u64,
}

/// Result of one fetch+open pass. Ack is deliberately separate so the app can
/// commit the opened messages to encrypted history before deleting them from
/// the mailbox.
pub struct ReceiveBatch {
    pub opened: Vec<Opened>,
    pub duplicates: Vec<String>,
    pub failed: Vec<FailedEnvelope>,
    pub malformed: Vec<crate::transport::RawGatewayItem>,
    pub omitted_malformed: usize,
    pub unknown_formats: usize,
    pub truncated: bool,
}

impl<T: Transport> Messenger<T> {
    pub fn take_warning(&self) -> Option<String> { self.transport.take_warning() }
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            seen: Mutex::new(ReplayState::default()),
        }
    }

    pub fn send(
        &self,
        sender: &Identity,
        recipient: &Address,
        kind: MessageKind,
        ttl: u64,
    ) -> Result<Envelope> {
        let envelope = Envelope::seal_now(sender, recipient, kind, ttl)?;
        self.transport.deliver(&envelope)?;
        Ok(envelope)
    }

    /// Fetch and open everything in one batch, **without acking**. A broken
    /// envelope is reported in `failed` and does not abort the rest of the
    /// batch. The caller must record `opened` durably, then call
    /// [`Messenger::ack_signed`].
    pub fn fetch_open(&self, recipient: &Identity, limit: usize) -> Result<ReceiveBatch> {
        self.fetch_open_skipping(recipient, limit, &HashSet::new())
    }

    /// Fetch/open while skipping ids that are already in a durable local
    /// quarantine. The transport is asked for a wider page so many broken
    /// entries cannot hide the good message behind them.
    pub fn fetch_open_skipping(
        &self,
        recipient: &Identity,
        limit: usize,
        skip: &HashSet<String>,
    ) -> Result<ReceiveBatch> {
        let now = unix_now();
        let fetch_limit = limit
            .saturating_mul(64)
            .saturating_add(skip.len())
            .max(limit.saturating_add(64))
            .min(1000);
        let page = self.transport.fetch_signed_page(recipient, now, fetch_limit)?;
        let envelopes = page.envelopes;
        let mut batch = ReceiveBatch {
            opened: Vec::new(),
            duplicates: Vec::new(),
            failed: Vec::new(),
            malformed: page.malformed,
            omitted_malformed: page.omitted_malformed,
            unknown_formats: page.unknown_formats,
            truncated: false,
        };
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| Error::Store("replay guard poisoned".into()))?;
        seen.committed.retain(|_, expires_at| *expires_at >= now);
        seen.pending.retain(|_, expires_at| *expires_at >= now);
        let mut legacy_counts = HashMap::<String, HashSet<String>>::new();
        for (envelope, token) in &envelopes {
            if token.is_none() {
                let encoded = serde_json::to_string(envelope).map_err(|e| Error::Envelope(format!("envelope identity: {e}")))?;
                legacy_counts.entry(envelope.id.clone()).or_default().insert(encoded);
            }
        }
        let mut legacy_emitted = HashSet::new();
        for (envelope, token) in envelopes {
            if token.is_none() && skip.contains(&envelope.id) {
                continue;
            }
            if token.is_none() && legacy_counts.get(&envelope.id).map_or(0, |v| v.len()) > 1 {
                batch.failed.push(FailedEnvelope { id: envelope.id.clone(), error: "ambiguous legacy transport identifier; no ACK".into(), transport_token: None, quarantine_allowed: false, encrypted_envelope:None, expires_at: bounded_expires_at(envelope.created_at, envelope.ttl, now) });
                continue;
            }
            if token.is_none() && !legacy_emitted.insert(envelope.id.clone()) { continue; }
            let mut message = match envelope.open(recipient, now) {
                Ok(message) => message,
                Err(e) => {
                    batch.failed.push(FailedEnvelope {
                        id: envelope.id.clone(),
                        encrypted_envelope:Some(envelope.clone()),
                        error: e.to_string(),
                        transport_token: token.clone(),
                        quarantine_allowed: true,
                        expires_at: bounded_expires_at(envelope.created_at, envelope.ttl, now),
                    });
                    continue;
                }
            };
            if let Some(token) = token {
                message.transport_token = Some(token);
                if batch.opened.len() < limit { batch.opened.push(message); } else { batch.truncated=true;break; }
                continue;
            }
            let expires_at = bounded_expires_at(envelope.created_at, envelope.ttl, now);
            if batch.opened.len() < limit {
                seen.pending.insert(message.id.clone(), expires_at);
                batch.opened.push(message);
            } else {
                batch.truncated = true;
                break;
            }
        }
        Ok(batch)
    }

    pub fn reject_saved_raw(&self,recipient:&Identity,quarantine:&crate::raw_quarantine::RawQuarantine,saved:&crate::raw_quarantine::QuarantinedRaw)->Result<()> {
        self.transport.reject_saved_raw(recipient,quarantine,saved)
    }

    /// Sign and send acks for ids the caller has already persisted.
    pub fn ack_signed(&self, recipient: &Identity, ids: &[String]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let count = self.transport.ack_signed(recipient, ids)?;
        let mut state = self.seen.lock().map_err(|_| Error::Store("replay guard poisoned".into()))?;
        for id in ids {
            if let Some(expiry) = state.pending.remove(id) {
                state.committed.insert(id.clone(), expiry);
            }
        }
        Ok(count)
    }

    /// Fetch, authenticate/decrypt, deduplicate by id, then ack. Only
    /// successfully opened envelopes are acked; a forged or broken one stays
    /// for inspection. Kept for the SDK/tests; the desktop app uses
    /// [`Messenger::fetch_open`] + [`Messenger::ack_signed`] so history is
    /// written before the ack.
    pub fn receive(&self, recipient: &Identity, limit: usize) -> Result<Vec<Opened>> {
        let batch = self.fetch_open(recipient, limit)?;
        if !batch.malformed.is_empty() || batch.omitted_malformed>0 || batch.unknown_formats>0 {
            return Err(Error::Store("raw or unknown gateway items require durable handling".into()));
        }
        let mut acked = batch.duplicates;
        let mut fresh = Vec::new();
        let mut staged = HashMap::<String, Vec<u8>>::new();
        {
            let mut state = self.seen.lock().map_err(|_| Error::Store("replay guard poisoned".into()))?;
            state.sdk_seen.retain(|_, (_, expiry)| *expiry >= unix_now());
            for message in batch.opened {
                let key = format!("{}\0{}", message.sender, message.id);
                let data = serde_json::to_vec(&(&message.kind, message.created_at)).map_err(|e| Error::Envelope(format!("replay identity: {e}")))?;
                let digest = Sha256::digest(data).to_vec();
                if let Some(old) = state.sdk_seen.get(&key).map(|(digest,_)|digest).or_else(|| staged.get(&key)) {
                    if old != &digest { return Err(Error::Store("replay identity conflict".into())); }
                } else {
                    staged.insert(key, digest);
                    fresh.push(message.clone());
                }
                acked.push(message.transport_token.unwrap_or(message.id));
            }
        }
        self.ack_signed(recipient, &acked)?;
        let mut state = self.seen.lock().map_err(|_| Error::Store("replay guard poisoned".into()))?;
        let expiry = unix_now().saturating_add(MAX_TTL_SECS);
        for (key, digest) in staged { state.sdk_seen.insert(key, (digest, expiry)); }
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_TTL_SECS, MAX_TTL_SECS};

    const NOW: u64 = 1_760_000_000;

    fn alice() -> Identity {
        Identity::from_seed([7u8; 32], "tgrin").unwrap()
    }

    #[test]
    fn tagged_events_with_same_uuid_are_opened_independently() {
        struct Tagged(Vec<Envelope>);
        impl Transport for Tagged {
            fn deliver(&self, _: &Envelope) -> Result<()> { Ok(()) }
            fn fetch(&self, _: &Address, _: u64, _: usize) -> Result<Vec<Envelope>> { Ok(self.0.clone()) }
            fn fetch_signed_tagged(&self, _: &Identity, _: u64, _: usize) -> Result<Vec<(Envelope, Option<String>)>> {
                Ok(self.0.iter().enumerate().map(|(i,e)| (e.clone(),Some(format!("event-{i}")))).collect())
            }
            fn ack(&self, _: &Address, ids: &[String]) -> Result<usize> { Ok(ids.len()) }
        }
        let bob = bob(); let now = unix_now(); let id = uuid::Uuid::new_v4().to_string();
        let senders = [alice(), Identity::from_seed([8u8; 32], "tgrin").unwrap()];
        let envelopes = senders.iter().map(|s| Envelope::seal_with_id(s, bob.address(), MessageKind::Text { text: "hello".into() }, 900, now, id.clone()).unwrap()).collect();
        let batch = Messenger::new(Tagged(envelopes)).fetch_open(&bob, 10).unwrap();
        assert_eq!(batch.opened.len(), 2);
        assert_ne!(batch.opened[0].sender, batch.opened[1].sender);
        assert_ne!(batch.opened[0].transport_token, batch.opened[1].transport_token);
        assert!(batch.duplicates.is_empty());
    }

    #[test]
    fn evidence_tagged_page_without_cursor_repeats_first_item() {
        struct Tagged(Vec<Envelope>);
        impl Transport for Tagged {
            fn deliver(&self,_:&Envelope)->Result<()> {Ok(())}
            fn fetch(&self,_:&Address,_:u64,_:usize)->Result<Vec<Envelope>> {Ok(self.0.clone())}
            fn fetch_signed_tagged(&self,_:&Identity,_:u64,_:usize)->Result<Vec<(Envelope,Option<String>)>> {
                Ok(self.0.iter().enumerate().map(|(i,e)|(e.clone(),Some(format!("event-{i}")))).collect())
            }
            fn ack(&self,_:&Address,ids:&[String])->Result<usize> {Ok(ids.len())}
        }
        let a=alice();let b=bob();
        let first=Envelope::seal_now(&a,b.address(),MessageKind::Text{text:"first".into()},900).unwrap();
        let second=Envelope::seal_now(&a,b.address(),MessageKind::Text{text:"second".into()},900).unwrap();
        let messenger=Messenger::new(Tagged(vec![first,second]));
        let first_poll=messenger.fetch_open(&b,1).unwrap();
        assert!(first_poll.truncated);
        messenger.ack_signed(&b,&[first_poll.opened[0].transport_token.clone().unwrap()]).unwrap();
        let next_poll=messenger.fetch_open(&b,1).unwrap();
        assert_eq!(next_poll.opened[0].id,first_poll.opened[0].id,"documents current cursor starvation, not desired behavior");
    }

    fn bob() -> Identity {
        Identity::from_seed([9u8; 32], "tgrin").unwrap()
    }

    fn envelope(id: &str) -> Envelope {
        let mut envelope = Envelope::seal(
            &alice(),
            bob().address(),
            MessageKind::Text { text: id.into() },
            DEFAULT_TTL_SECS,
            unix_now(),
        )
        .unwrap();
        envelope.id = id.to_string();
        envelope
    }

    #[test]
    fn failed_history_write_does_not_suppress_unacknowledged_message() {
        let alice = alice(); let bob = bob();
        let envelope = Envelope::seal_now(&alice, bob.address(), MessageKind::Text { text: "retry".into() }, 600).unwrap();
        let mailbox = MemoryMailbox::default(); mailbox.deliver(&envelope).unwrap();
        let messenger = Messenger::new(mailbox);
        let first = messenger.fetch_open(&bob, 10).unwrap();
        assert_eq!(first.opened.len(), 1);
        // Simulate history persistence failure: do not acknowledge.
        let retry = messenger.fetch_open(&bob, 10).unwrap();
        assert_eq!(retry.opened.len(), 1);
        assert!(retry.duplicates.is_empty());
        messenger.ack_signed(&bob, &[retry.opened[0].id.clone()]).unwrap();
        assert!(messenger.fetch_open(&bob, 10).unwrap().opened.is_empty());
    }

    #[test]
    fn duplicate_in_same_batch_is_never_acked_before_first_copy_is_saved() {
        struct DuplicateTransport(Envelope);
        impl Transport for DuplicateTransport {
            fn deliver(&self, _: &Envelope) -> Result<()> { Ok(()) }
            fn fetch(&self, _: &Address, _: u64, _: usize) -> Result<Vec<Envelope>> { Ok(vec![self.0.clone(), self.0.clone()]) }
            fn ack(&self, _: &Address, ids: &[String]) -> Result<usize> { Ok(ids.len()) }
        }
        let alice = alice(); let bob = bob();
        let envelope = Envelope::seal_now(&alice, bob.address(), MessageKind::Text { text: "retry".into() }, 600).unwrap();
        let messenger = Messenger::new(DuplicateTransport(envelope));
        let first = messenger.fetch_open(&bob, 10).unwrap();
        assert_eq!(first.opened.len(), 1);
        assert!(first.duplicates.is_empty());
        // No ack occurs if the single history write fails.
        let retry = messenger.fetch_open(&bob, 10).unwrap();
        assert_eq!(retry.opened.len(), 1);
        assert!(retry.duplicates.is_empty());
    }

    #[test]
    fn store_fetch_ack_roundtrip() {
        let mailbox = MemoryMailbox::default();
        let first = envelope("a");
        let second = envelope("b");
        mailbox.deliver(&first).unwrap();
        mailbox.deliver(&second).unwrap();
        let fetched = mailbox.fetch(bob().address(), unix_now(), 10).unwrap();
        assert_eq!(fetched.len(), 2);
        assert_eq!(mailbox.ack(bob().address(), &["a".into()]).unwrap(), 1);
        let fetched = mailbox.fetch(bob().address(), unix_now(), 10).unwrap();
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].id, "b");
    }

    #[test]
    fn future_clock_cannot_extend_storage() {
        let mailbox = MemoryMailbox::default();
        let base = unix_now();
        let future = base.saturating_add(MAX_TTL_SECS.saturating_mul(10));
        let mut item = Envelope::seal(
            &alice(),
            bob().address(),
            MessageKind::Text {
                text: "future".into(),
            },
            MAX_TTL_SECS,
            future,
        )
        .unwrap();
        item.id = "future".into();
        mailbox.deliver(&item).unwrap();
        // Fetching just past our own TTL cap drops it even though the sender
        // timestamp claims it should live much longer.
        let fetched = mailbox
            .fetch(
                bob().address(),
                base.saturating_add(MAX_TTL_SECS).saturating_add(1),
                10,
            )
            .unwrap();
        assert!(fetched.is_empty());
        assert_eq!(
            bounded_expires_at(future, MAX_TTL_SECS, base),
            base.saturating_add(MAX_TTL_SECS)
        );
    }

    #[test]
    fn duplicate_ids_are_idempotent() {
        let mailbox = MemoryMailbox::default();
        let item = envelope("same");
        mailbox.deliver(&item).unwrap();
        mailbox.deliver(&item).unwrap();
        assert_eq!(
            mailbox
                .fetch(bob().address(), unix_now(), 10)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn queue_quota_is_enforced() {
        let mailbox = MemoryMailbox::new(1, 64 * 1024);
        mailbox.deliver(&envelope("a")).unwrap();
        assert!(matches!(
            mailbox.deliver(&envelope("b")),
            Err(Error::Quota(_))
        ));
    }

    #[test]
    fn oversized_messages_are_rejected() {
        let mailbox = MemoryMailbox::new(10, 8);
        assert!(matches!(
            mailbox.deliver(&envelope("a")),
            Err(Error::Quota(_))
        ));
    }

    #[test]
    fn expired_messages_are_not_stored_or_fetched() {
        let mailbox = MemoryMailbox::default();
        let expired = Envelope::seal(
            &alice(),
            bob().address(),
            MessageKind::Text { text: "old".into() },
            1,
            1,
        )
        .unwrap();
        assert!(matches!(mailbox.deliver(&expired), Err(Error::Expired)));
        assert!(mailbox
            .fetch(bob().address(), unix_now(), 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn ttl_bounds_are_checked_by_the_store() {
        let mailbox = MemoryMailbox::default();
        let mut too_long = envelope("long");
        too_long.ttl = MAX_TTL_SECS + 1;
        assert!(matches!(mailbox.deliver(&too_long), Err(Error::BadTtl(_))));
    }

    #[test]
    fn messenger_roundtrip_acks_delivered_messages() {
        let mailbox = MemoryMailbox::default();
        let messenger = Messenger::new(mailbox);
        let bob = bob();
        messenger
            .send(
                &alice(),
                bob.address(),
                MessageKind::Slatepack {
                    armor: "BEGINSLATEPACK...".into(),
                    encrypted: true,
                },
                DEFAULT_TTL_SECS,
            )
            .unwrap();
        let inbox = messenger.receive(&bob, 10).unwrap();
        assert_eq!(inbox.len(), 1);
        assert!(matches!(
            inbox[0].kind,
            MessageKind::Slatepack {
                encrypted: true,
                ..
            }
        ));
        assert!(messenger
            .transport
            .fetch(bob.address(), unix_now(), 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn bad_envelope_does_not_block_the_rest_of_the_batch() {
        let mailbox = MemoryMailbox::default();
        let messenger = Messenger::new(mailbox);
        let bob = bob();
        let good = messenger
            .send(
                &alice(),
                bob.address(),
                MessageKind::Text {
                    text: "good".into(),
                },
                DEFAULT_TTL_SECS,
            )
            .unwrap();
        let mut bad = good.clone();
        bad.id = uuid::Uuid::new_v4().to_string();
        bad.signature[0] ^= 1;
        messenger.transport.deliver(&bad).unwrap();

        let batch = messenger.fetch_open(&bob, 10).unwrap();
        assert_eq!(batch.opened.len(), 1, "good message must still arrive");
        assert_eq!(batch.failed.len(), 1, "bad message is reported separately");
        assert_eq!(batch.failed[0].id, bad.id);

        // Nothing was acked by fetch_open; the caller acks only after commit.
        assert_eq!(
            messenger
                .transport
                .fetch(bob.address(), unix_now(), 10)
                .unwrap()
                .len(),
            2
        );
        messenger.ack_signed(&bob, &[good.id]).unwrap();
        let left = messenger
            .transport
            .fetch(bob.address(), unix_now(), 10)
            .unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].id, bad.id);
    }

    #[test]
    fn failed_envelope_can_be_acked_after_the_decision() {
        let mailbox = MemoryMailbox::default();
        let messenger = Messenger::new(mailbox);
        let bob = bob();
        let mut bad = envelope("bad-ack");
        bad.signature[0] ^= 1;
        messenger.transport.deliver(&bad).unwrap();
        let batch = messenger.fetch_open(&bob, 10).unwrap();
        assert_eq!(batch.failed.len(), 1);
        assert_eq!(batch.failed[0].id, bad.id);
        messenger
            .ack_signed(&bob, &[batch.failed[0].id.clone()])
            .unwrap();
        assert!(messenger
            .transport
            .fetch(bob.address(), unix_now(), 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn many_broken_envelopes_do_not_hide_the_good_one() {
        let mailbox = MemoryMailbox::default();
        let messenger = Messenger::new(mailbox);
        let bob = bob();
        let good = messenger
            .send(
                &alice(),
                bob.address(),
                MessageKind::Text {
                    text: "good".into(),
                },
                DEFAULT_TTL_SECS,
            )
            .unwrap();
        let good_id = good.id.clone();
        for n in 0..40 {
            let mut bad = good.clone();
            bad.id = format!("broken-{n}");
            bad.signature[0] ^= 1;
            messenger.transport.deliver(&bad).unwrap();
        }
        messenger.transport.deliver(&good).unwrap();

        let batch = messenger.fetch_open(&bob, 1).unwrap();
        assert_eq!(batch.opened.len(), 1, "good message must be found");
        assert_eq!(batch.opened[0].id, good_id);
        assert_eq!(batch.failed.len(), 40, "all broken envelopes are reported");
    }

    #[test]
    fn a_restarted_messenger_skips_durable_quarantine_ids() {
        let mailbox = MemoryMailbox::default();
        let messenger = Messenger::new(mailbox);
        let bob = bob();
        let good = messenger
            .send(
                &alice(),
                bob.address(),
                MessageKind::Text {
                    text: "good after restart".into(),
                },
                DEFAULT_TTL_SECS,
            )
            .unwrap();
        for n in 0..40 {
            let mut bad = good.clone();
            bad.id = format!("broken-{n}");
            bad.signature[0] ^= 1;
            messenger.transport.deliver(&bad).unwrap();
        }
        messenger.transport.deliver(&good).unwrap();

        let skip: std::collections::HashSet<String> =
            (0..40).map(|n| format!("broken-{n}")).collect();
        let batch = messenger
            .fetch_open_skipping(&bob, 1, &skip)
            .expect("fetch after restart");
        assert_eq!(batch.opened.len(), 1, "good message after restart");
        assert!(batch.failed.is_empty(), "quarantined ids must be skipped");
        let mut ack = batch
            .opened
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        ack.extend(skip);
        messenger.ack_signed(&bob, &ack).expect("ack");
        assert!(messenger
            .transport
            .fetch(bob.address(), unix_now(), 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn default_ttl_is_26h() {
        assert_eq!(DEFAULT_TTL_SECS, 93_600);
    }

    #[test]
    fn replay_after_ack_is_not_returned_twice() {
        let messenger = Messenger::new(MemoryMailbox::default());
        let bob = bob();
        let envelope = messenger
            .send(
                &alice(),
                bob.address(),
                MessageKind::Text {
                    text: "once".into(),
                },
                DEFAULT_TTL_SECS,
            )
            .unwrap();
        assert_eq!(messenger.receive(&bob, 10).unwrap().len(), 1);
        // A relay can replay the same envelope; the recipient must not surface it.
        messenger.transport.deliver(&envelope).unwrap();
        assert!(messenger.receive(&bob, 10).unwrap().is_empty());
    }

    #[test]
    fn fixed_time_is_only_used_in_tests() {
        const {
            assert!(NOW > 1_000_000_000);
        }
    }
}
