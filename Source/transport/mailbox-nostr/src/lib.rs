//! The payment core's `Mailbox` port over the Nostr transport.
//!
//! One [`NostrMailbox`] belongs to one unlocked profile and lives on that
//! profile's worker thread. It keeps a session per contact, seals payment
//! messages with the profile's Nostr keys, publishes the envelopes the core
//! hands back byte for byte, and stores replies to incoming payments so that
//! a retry sends the same reply.
//!
//! What it does not decide: whether a slate is valid, whether a payment is
//! made, whether anything is signed. It moves text between contacts.
//!
//! The port is synchronous and the transport is not, so the mailbox owns a
//! small tokio runtime and must be used from a plain thread, never from
//! inside another runtime.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod store;

use fly_nostr_research::nostr::contact_session::{
    seal_payment, ContactSession, Note, Publication, SessionError,
};
use fly_nostr_research::nostr::protocol;
use fly_paycore_mailbox::{Envelope, Incoming, Mailbox, Published};
use nostr_sdk::{Event, EventId, JsonUtil, Keys, PublicKey, Timestamp};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};
use store::{ReplyStore, StoreError, StoredReply};

/// Contacts one mailbox talks to; each has its own relay connection.
pub const MAX_CONTACTS: usize = 64;
/// Pause before a contact whose relay connection failed is tried again.
pub const RECONNECT_AFTER: Duration = Duration::from_secs(5);
/// The pause doubles with every failed attempt, up to this: a relay that
/// turns us away is not knocked on every few seconds for hours.
pub const RECONNECT_MAX: Duration = Duration::from_secs(300);

/// A future that yields a connected session.
pub type Connecting<'a> = Pin<Box<dyn Future<Output = Result<ContactSession, SessionError>> + 'a>>;

/// How sessions are made. The product connects through Tor; tests connect
/// to a relay on the same machine.
pub trait Connector {
    /// Open a session with `contact` for the profile's `keys`.
    /// `note` is where the session leaves how far it got and what the
    /// relay said, for the user.
    fn connect<'a>(&'a mut self, keys: &'a Keys, contact: PublicKey, note: &'a Note) -> Connecting<'a>;
}

/// Sessions through the shared Tor client to one relay.
pub struct TorConnector {
    /// The profile's bootstrapped Tor client.
    pub tor: fly_tor::SharedTor,
    /// `wss://` address of the relay; never an IP address.
    pub relay: String,
    /// Longest wait for the connection and the subscription.
    pub timeout: Duration,
}

impl Connector for TorConnector {
    fn connect<'a>(&'a mut self, keys: &'a Keys, contact: PublicKey, note: &'a Note) -> Connecting<'a> {
        Box::pin(ContactSession::connect_noted(
            self.tor.clone(),
            keys.clone(),
            contact,
            &self.relay,
            self.timeout,
            note,
        ))
    }
}

/// Timing of a mailbox.
#[derive(Clone, Copy, Debug)]
pub struct Timing {
    /// How long a sealed message may wait at relays (whole seconds).
    pub delivery_window: Duration,
    /// Longest wait for a relay to acknowledge a publication.
    pub publish_timeout: Duration,
    /// How long one contact's session is asked for a new message.
    pub poll: Duration,
    /// Pause before a session that failed to open is tried again; it
    /// doubles with every failure up to `reconnect_max`.
    pub reconnect: Duration,
    /// Longest pause between two attempts to open a session.
    pub reconnect_max: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            delivery_window: Duration::from_secs(15 * 60),
            publish_timeout: Duration::from_secs(20),
            poll: Duration::from_millis(100),
            reconnect: RECONNECT_AFTER,
            reconnect_max: RECONNECT_MAX,
        }
    }
}

/// The `Mailbox` of one profile.
pub struct NostrMailbox<C: Connector> {
    rt: tokio::runtime::Runtime,
    keys: Keys,
    connector: C,
    timing: Timing,
    contacts: Vec<[u8; 32]>,
    sessions: BTreeMap<[u8; 32], ContactSession>,
    /// When a session that failed to open may be tried again, and the pause
    /// that led there.
    retry_at: BTreeMap<[u8; 32], (Instant, Duration)>,
    /// Filled by a session with what the relay answered.
    note: Note,
    /// What is in the way right now, in words for the user.
    problem: Option<String>,
    /// Received and not yet marked done: message id -> contact.
    held: BTreeMap<[u8; 32], [u8; 32]>,
    /// Handed out since the last "nothing more".
    round: BTreeSet<[u8; 32]>,
    replies: ReplyStore,
}

/// Build the mailbox a transport process serves, from the start-up message
/// of the pipe. `connect` makes the connector on the mailbox's runtime.
/// Replies are kept in `<data_dir>/replies`.
pub fn from_config<C, F>(config: &fly_paycore_mailbox_pipe::Config, connect: F) -> Result<NostrMailbox<C>, String>
where
    C: Connector,
    F: FnOnce(&tokio::runtime::Runtime) -> Result<C, String>,
{
    let secret = nostr_sdk::SecretKey::from_slice(&config.identity_secret)
        .map_err(|_| "the identity key is not usable".to_string())?;
    let keys = Keys::new(secret);
    if keys.public_key().to_bytes() != config.identity_public {
        return Err("the identity key is not usable".into());
    }
    let data = std::path::Path::new(&config.data_dir);
    if !data.is_absolute() || !data.is_dir() {
        return Err("the data directory must exist and be given in full".into());
    }
    let replies = ReplyStore::open(&data.join("replies"), config.store_key)
        .map_err(|_| "the reply store could not be opened".to_string())?;
    let timing = Timing {
        delivery_window: Duration::from_secs(u64::from(config.delivery_window_secs)),
        publish_timeout: Duration::from_millis(u64::from(config.publish_timeout_ms)),
        poll: Duration::from_millis(u64::from(config.poll_ms)),
        ..Timing::default()
    };
    NostrMailbox::start(keys, &config.contacts, replies, timing, connect)
}

fn now() -> u64 {
    Timestamp::now().as_secs()
}

impl<C: Connector> NostrMailbox<C> {
    /// A mailbox for `keys` that talks to `contacts` and nobody else.
    /// `replies` is where replies to incoming payments are kept. Nothing is
    /// connected here; sessions are opened when first needed.
    pub fn new(
        keys: Keys,
        contacts: &[[u8; 32]],
        connector: C,
        replies: ReplyStore,
        timing: Timing,
    ) -> Result<Self, String> {
        Self::start(keys, contacts, replies, timing, move |_| Ok(connector))
    }

    /// Like [`NostrMailbox::new`], for a connector that has to be made on
    /// the mailbox's own runtime (the Tor client is one: it lives on the
    /// runtime that bootstrapped it).
    pub fn start<F>(
        keys: Keys,
        contacts: &[[u8; 32]],
        replies: ReplyStore,
        timing: Timing,
        connect: F,
    ) -> Result<Self, String>
    where
        F: FnOnce(&tokio::runtime::Runtime) -> Result<C, String>,
    {
        if contacts.len() > MAX_CONTACTS {
            return Err("too many contacts".into());
        }
        let me = keys.public_key().to_bytes();
        let mut list = Vec::new();
        for c in contacts {
            if *c == me || PublicKey::from_slice(c).is_err() {
                return Err("a contact key is not usable".into());
            }
            if !list.contains(c) {
                list.push(*c);
            }
        }
        if timing.delivery_window.subsec_nanos() != 0
            || timing.delivery_window.is_zero()
            || timing.publish_timeout.is_zero()
            || timing.poll.is_zero()
        {
            return Err("timing is not usable".into());
        }
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| "the runtime could not be started".to_string())?;
        let connector = connect(&rt)?;
        // replies whose delivery window has closed can never be needed again
        let at = now();
        let _ = replies.purge(|r| r.deadline <= at);
        Ok(NostrMailbox {
            rt,
            keys,
            connector,
            timing,
            contacts: list,
            sessions: BTreeMap::new(),
            retry_at: BTreeMap::new(),
            note: Note::default(),
            problem: None,
            held: BTreeMap::new(),
            round: BTreeSet::new(),
            replies,
        })
    }

    /// The session with a contact, opened if needed. `None` while the relay
    /// cannot be reached; the next attempt waits [`RECONNECT_AFTER`].
    fn session(&mut self, contact: &[u8; 32]) -> Option<&mut ContactSession> {
        if !self.contacts.contains(contact) {
            return None;
        }
        if !self.sessions.contains_key(contact) {
            if self.retry_at.get(contact).is_some_and(|(t, _)| Instant::now() < *t) {
                return None;
            }
            let key = PublicKey::from_slice(contact).ok()?;
            self.clear_note();
            match self.rt.block_on(self.connector.connect(&self.keys, key, &self.note)) {
                Ok(s) => {
                    self.retry_at.remove(contact);
                    self.sessions.insert(*contact, s);
                    self.problem = None;
                }
                Err(e) => {
                    self.problem = Some(self.describe(Some(e)));
                    let pause = match self.retry_at.get(contact) {
                        Some((_, last)) => last.saturating_mul(2).min(self.timing.reconnect_max),
                        None => self.timing.reconnect,
                    };
                    let at = Instant::now().checked_add(pause)?;
                    self.retry_at.insert(*contact, (at, pause));
                    return None;
                }
            }
        }
        self.sessions.get_mut(contact)
    }

    fn clear_note(&self) {
        if let Ok(mut note) = self.note.lock() {
            note.clear();
        }
    }

    /// What went wrong, for the user: the kind of failure and, if the
    /// session left any, how far it got and what the relay said.
    fn describe(&self, error: Option<SessionError>) -> String {
        let kind = match error {
            None => "",
            Some(SessionError::ConnectionFailed) => "the relay could not be reached",
            Some(SessionError::Timeout) => "the relay did not answer in time",
            Some(SessionError::SubscriptionFailed) => "the relay refused the subscription",
            Some(SessionError::Closed) => "the connection to the relay closed",
            Some(SessionError::InvalidInput) => "the relay address or the contact is not usable",
            Some(_) => "the session with the relay failed",
        };
        let note = self.note.lock().map(|n| n.clone()).unwrap_or_default();
        let text = match (kind.is_empty(), note.is_empty()) {
            (false, false) => format!("{kind} ({note})"),
            (false, true) => kind.to_string(),
            (true, false) => note,
            (true, true) => "the relay did not accept the message".to_string(),
        };
        fly_paycore_mailbox::plain_problem(&text)
    }

    /// Close a session whose connection failed; it is reopened on demand.
    fn drop_session(&mut self, contact: &[u8; 32]) {
        if let Some(s) = self.sessions.remove(contact) {
            self.rt.block_on(s.close());
        }
        // what it held in memory is gone with it; the relay sends it again
        self.held.retain(|_, c| c != contact);
    }

    fn publish_json(&mut self, contact: &[u8; 32], json: &str, deadline: u64) -> Published {
        let timeout = self.timing.publish_timeout;
        let outcome = match self.session(contact) {
            None => return Published::Unknown,
            Some(_) => {
                // borrow again so the runtime and the session are both at hand
                let Some(session) = self.sessions.get(contact) else {
                    return Published::Unknown;
                };
                self.clear_note();
                self.rt.block_on(session.publish_envelope_noted(json, deadline, timeout, Some(&self.note)))
            }
        };
        match outcome {
            Ok(Publication::RelayAccepted) => {
                self.problem = None;
                Published::Accepted
            }
            Ok(Publication::Unknown) => {
                self.problem = Some(self.describe(None));
                Published::Unknown
            }
            Err(SessionError::Expired) => Published::Expired,
            Err(SessionError::InvalidInput) => Published::Unknown,
            Err(e) => {
                self.problem = Some(self.describe(Some(e)));
                self.drop_session(contact);
                Published::Unknown
            }
        }
    }
}

impl<C: Connector> Mailbox for NostrMailbox<C> {
    fn seal(&mut self, to: &[u8; 32], text: &str) -> Result<Envelope, String> {
        if !self.contacts.contains(to) {
            return Err("not a contact".into());
        }
        let contact = PublicKey::from_slice(to).map_err(|_| "not a contact".to_string())?;
        let prepared = self
            .rt
            .block_on(seal_payment(&self.keys, contact, text, None, self.timing.delivery_window))
            .map_err(|_| "the message could not be sealed".to_string())?;
        let (event_id, json, expires_at) = prepared.envelope();
        Ok(Envelope {
            event_id,
            bytes: json.into_bytes(),
            expires_at,
        })
    }

    fn publish(&mut self, envelope: &Envelope) -> Published {
        let Ok(json) = std::str::from_utf8(&envelope.bytes) else {
            return Published::Unknown;
        };
        // the addressee is read from the envelope itself; the session checks
        // the signature, the size and the deadline before sending
        let Some(contact) = Event::from_json(json)
            .ok()
            .and_then(|e| e.tags.public_keys().next().map(|k| k.to_bytes()))
        else {
            return Published::Unknown;
        };
        // the deadline is the one the core kept with the envelope: the
        // envelope itself does not show it
        self.publish_json(&contact, json, envelope.expires_at)
    }

    fn next_incoming(&mut self) -> Option<Incoming> {
        let poll = self.timing.poll;
        for contact in self.contacts.clone() {
            // a message of this contact that was handed out and is not done
            // yet blocks the contact until the next round
            loop {
                if self.session(&contact).is_none() {
                    break;
                }
                let Some(session) = self.sessions.get_mut(&contact) else {
                    break;
                };
                let message = match self.rt.block_on(session.receive_pending(poll)) {
                    Ok(m) => m,
                    Err(SessionError::Timeout) => break,
                    Err(_) => {
                        self.drop_session(&contact);
                        break;
                    }
                };
                let id = *message.envelope_id().as_bytes();
                if !message.deliverable_at(now()) {
                    if session.acknowledge_received(message.envelope_id()).is_err() {
                        break;
                    }
                    self.held.remove(&id);
                    self.round.remove(&id);
                    continue;
                }
                if self.round.contains(&id) {
                    break;
                }
                let text = protocol::extract_slatepack(&message.rumor().content);
                match text {
                    Some(text) if message.sender().to_bytes() == contact => {
                        self.held.insert(id, contact);
                        self.round.insert(id);
                        return Some(Incoming { id, from: contact, text });
                    }
                    _ => {
                        // not a payment message: nothing for the core, and
                        // nothing this session needs to see again
                        if session.acknowledge_received(message.envelope_id()).is_err() {
                            break;
                        }
                    }
                }
            }
        }
        self.round.clear();
        None
    }

    fn resend_reply(&mut self, incoming: &[u8; 32]) -> Option<Published> {
        match self.replies.get(incoming) {
            Ok(Some(reply)) => Some(self.publish_json(&reply.contact, &reply.envelope, reply.deadline)),
            Ok(None) => None,
            // a stored reply that cannot be read must not be replaced by a
            // new one; report it as not sent
            Err(_) => Some(Published::Busy),
        }
    }

    fn reply(&mut self, incoming: &[u8; 32], text: &str) -> Published {
        if let Some(outcome) = self.resend_reply(incoming) {
            return outcome;
        }
        let Some(contact) = self.held.get(incoming).copied() else {
            return Published::Unknown;
        };
        let Ok(key) = PublicKey::from_slice(&contact) else {
            return Published::Unknown;
        };
        let Ok(prepared) = self
            .rt
            .block_on(seal_payment(&self.keys, key, text, None, self.timing.delivery_window))
        else {
            return Published::Unknown;
        };
        let (_, envelope, deadline) = prepared.envelope();
        // durable first, then the network
        match self.replies.put(incoming, &StoredReply { contact, deadline, envelope: envelope.clone() }) {
            Ok(()) => self.publish_json(&contact, &envelope, deadline),
            Err(StoreError::Full) => Published::Full,
            Err(StoreError::Io(_)) => Published::Busy,
        }
    }

    fn done(&mut self, incoming: &[u8; 32]) {
        let Some(contact) = self.held.remove(incoming) else {
            return;
        };
        if let (Some(session), Ok(id)) = (self.sessions.get_mut(&contact), EventId::from_slice(incoming)) {
            let _ = session.acknowledge_received(id);
        }
    }

    fn problem(&mut self) -> Option<String> {
        self.problem.clone()
    }
}

impl<C: Connector> Drop for NostrMailbox<C> {
    fn drop(&mut self) {
        for (_, session) in std::mem::take(&mut self.sessions) {
            self.rt.block_on(session.close());
        }
    }
}
