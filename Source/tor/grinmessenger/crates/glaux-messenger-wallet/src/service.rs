// SPDX-License-Identifier: MIT OR Apache-2.0
//! Embedded wallet-facing service: identity, encrypted local storage, network
//! thread (relay or direct onion), message index, events and unread counters.
//!
//! The service is intentionally UI-free. A Rust wallet can embed it directly;
//! a non-Rust wallet talks to `glauxmsg-walletd`, which is a thin HTTP shell
//! around this service (see [`crate::server`]).

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use glaux_gateway::{wait_ready, Gateway, GatewayConfig};
use glaux_messenger::envelope::unix_now;
use glaux_messenger::history::{Direction, History, MessageRecord};
use glaux_messenger::transport::{DirectOnionTransport, GatewayTransport, HttpConnector};
use glaux_messenger::{
    Address, Contact, ContactBook, Envelope, Identity, MessageKind, Messenger, Opened, Transport,
    MAX_TTL_SECS,
};
use glaux_tor_arti::{OnionService, TorConfig, TorHttpClient};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::identity::{network_hrp, storage_key};
use crate::read_state::ReadState;

/// Integrations protocol/API version.
pub const API_VERSION: u8 = 1;
/// Maximum plain text length accepted by the API (bytes, UTF-8).
pub const MAX_TEXT_BYTES: usize = 8 * 1024;
/// Maximum Slatepack armor length accepted by the API (bytes).
pub const MAX_ARMOR_BYTES: usize = 32 * 1024;
const MAX_HISTORY_MESSAGES: usize = 10_000;
const MAX_EVENTS: usize = 2_000;
const MAX_CONTACTS: usize = 500;
const MAX_CONTACT_NAME: usize = 64;

/// How the wallet daemon reaches peers.
#[derive(Clone, Debug)]
pub enum NetworkMode {
    /// Store-and-forward relay. `plain = true` uses plain TCP (loopback tests,
    /// local relay); otherwise every request is routed through in-process Arti
    /// (needed for `.onion` relays and for hiding the wallet IP).
    Relay { url: String, plain: bool },
    /// Direct onion delivery: publish the wallet's onion and post envelopes to
    /// the recipient's onion. Takes 30–150 s on first bootstrap.
    Direct,
}

impl NetworkMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Relay { .. } => "relay",
            Self::Direct => "direct",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub data_dir: PathBuf,
    pub network: String,
    pub mode: NetworkMode,
    pub poll_secs: u64,
    pub fetch_limit: usize,
    pub ttl_secs: u64,
    /// Arti state/cache directory; defaults to `<data_dir>/arti-state`.
    pub tor_state: Option<PathBuf>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("glauxmsg-wallet"),
            network: "tgrin".into(),
            mode: NetworkMode::Direct,
            // Fast direct-mode drain so a cheap flood cannot hold the queue
            // between polls; relay mode is fine with the same cadence.
            poll_secs: 1,
            fetch_limit: 100,
            ttl_secs: 12 * 60 * 60,
            tor_state: None,
        }
    }
}

/// One delivery backend built from a [`TransportSpec`].
pub enum ActiveTransport {
    Relay(GatewayTransport),
    Direct(DirectOnionTransport),
}

impl Transport for ActiveTransport {
    fn deliver(&self, envelope: &Envelope) -> glaux_messenger::Result<()> {
        match self {
            Self::Relay(t) => t.deliver(envelope),
            Self::Direct(t) => t.deliver(envelope),
        }
    }
    fn fetch(
        &self,
        recipient: &Address,
        now: u64,
        limit: usize,
    ) -> glaux_messenger::Result<Vec<Envelope>> {
        match self {
            Self::Relay(t) => t.fetch(recipient, now, limit),
            Self::Direct(t) => t.fetch(recipient, now, limit),
        }
    }
    fn ack(&self, recipient: &Address, ids: &[String]) -> glaux_messenger::Result<usize> {
        match self {
            Self::Relay(t) => t.ack(recipient, ids),
            Self::Direct(t) => t.ack(recipient, ids),
        }
    }
    // GrinSight patch: forward the signed fetch too. Without it the trait's default
    // (unsigned) fetch is used, and a relay that requires a fetch proof
    // (glaux-relay's default) answers 401 "fetch proof required".
    fn fetch_signed(&self, recipient: &Identity, now: u64, limit: usize) -> glaux_messenger::Result<Vec<Envelope>> {
        match self {
            Self::Relay(t) => t.fetch_signed(recipient, now, limit),
            Self::Direct(t) => t.fetch_signed(recipient, now, limit),
        }
    }
    fn ack_signed(&self, recipient: &Identity, ids: &[String]) -> glaux_messenger::Result<usize> {
        match self {
            Self::Relay(t) => t.ack_signed(recipient, ids),
            Self::Direct(t) => t.ack_signed(recipient, ids),
        }
    }
}

#[derive(Clone)]
enum TransportSpec {
    RelayPlain {
        url: String,
    },
    RelayArti {
        url: String,
        connector: Arc<dyn HttpConnector>,
    },
    Direct {
        local_url: String,
        connector: Arc<dyn HttpConnector>,
    },
}

impl TransportSpec {
    fn build(&self) -> Result<ActiveTransport, String> {
        match self {
            Self::RelayPlain { url } => GatewayTransport::new(url)
                .map(ActiveTransport::Relay)
                .map_err(|e| format!("relay transport {url}: {e}")),
            Self::RelayArti { url, connector } => {
                GatewayTransport::with_connector(url, connector.clone())
                    .map(ActiveTransport::Relay)
                    .map_err(|e| format!("relay transport {url}: {e}"))
            }
            Self::Direct {
                local_url,
                connector,
            } => DirectOnionTransport::with_connector(local_url, connector.clone())
                .map(ActiveTransport::Direct)
                .map_err(|e| format!("direct transport: {e}")),
        }
    }
}

struct ArtiConnector {
    client: TorHttpClient,
}

impl HttpConnector for ArtiConnector {
    fn request(
        &self,
        method: &str,
        url: &str,
        body: &[u8],
    ) -> glaux_messenger::Result<(u16, Vec<u8>)> {
        self.client
            .request(method, url, body)
            .map_err(|e| glaux_messenger::Error::Store(format!("arti: {e}")))
    }
}

/// A message as seen by the wallet (history + live index).
#[derive(Clone, Debug, Serialize)]
pub struct MessageView {
    /// Monotonic cursor within the current daemon `epoch`.
    pub seq: u64,
    pub id: String,
    /// Peer address: sender for incoming, recipient for outgoing.
    pub peer: String,
    /// `incoming` or `outgoing`.
    pub direction: String,
    /// `text` or `slatepack`.
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub armor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    pub created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
}

impl MessageView {
    fn from_record(peer: &Address, record: MessageRecord, seq: u64) -> Self {
        let direction = match record.direction {
            Direction::Incoming => "incoming",
            Direction::Outgoing => "outgoing",
        };
        let mut view = Self {
            seq,
            id: record.id,
            peer: peer.to_string(),
            direction: direction.to_string(),
            kind: "text".to_string(),
            text: None,
            armor: None,
            encrypted: None,
            created_at: record.created_at,
            expires_at: record.expires_at,
        };
        match record.kind {
            MessageKind::Text { text } => {
                view.kind = "text".to_string();
                view.text = Some(text);
            }
            MessageKind::Slatepack { armor, encrypted } => {
                view.kind = "slatepack".to_string();
                view.armor = Some(armor);
                view.encrypted = Some(encrypted);
            }
        }
        view
    }

    fn from_opened(opened: Opened, seq: u64) -> Self {
        let mut view = Self {
            seq,
            id: opened.id,
            peer: opened.sender.to_string(),
            direction: "incoming".to_string(),
            kind: "text".to_string(),
            text: None,
            armor: None,
            encrypted: None,
            created_at: opened.created_at,
            expires_at: None,
        };
        match opened.kind {
            MessageKind::Text { text } => view.text = Some(text),
            MessageKind::Slatepack { armor, encrypted } => {
                view.kind = "slatepack".to_string();
                view.armor = Some(armor);
                view.encrypted = Some(encrypted);
            }
        }
        view
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct WalletEvent {
    pub seq: u64,
    #[serde(flatten)]
    pub event: EventKind,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    Message { message: MessageView },
    Rejected { id: String, error: String },
    Status { phase: String, detail: String },
    Error { message: String },
}

#[derive(Clone, Debug, Serialize)]
pub struct MessagesPage {
    pub epoch: String,
    pub next: u64,
    pub messages: Vec<MessageView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EventsPage {
    pub epoch: String,
    pub next: u64,
    pub events: Vec<WalletEvent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceStatus {
    pub phase: String,
    pub detail: String,
    pub mode: String,
    pub network: String,
    pub address: String,
    pub onion: String,
    pub onion_url: String,
    pub last_error: Option<String>,
    pub last_poll_unix: u64,
    pub unread: u64,
    pub unread_by_peer: BTreeMap<String, u64>,
    pub api_version: u8,
}

#[derive(Clone, Debug, Serialize)]
pub struct Capabilities {
    pub api_version: u8,
    pub protocol_version: u8,
    pub kinds: Vec<String>,
    pub transports: Vec<String>,
    pub slatepack_plaintext: bool,
    pub max_text_bytes: usize,
    pub max_armor_bytes: usize,
    pub auth: String,
    pub bind: String,
}

pub fn capabilities() -> Capabilities {
    Capabilities {
        api_version: API_VERSION,
        protocol_version: glaux_messenger::VERSION,
        kinds: vec!["text".into(), "slatepack".into()],
        transports: vec!["relay".into(), "direct".into()],
        slatepack_plaintext: false,
        max_text_bytes: MAX_TEXT_BYTES,
        max_armor_bytes: MAX_ARMOR_BYTES,
        auth: "bearer".into(),
        bind: "loopback".into(),
    }
}

struct State {
    phase: String,
    detail: String,
    last_error: Option<String>,
    last_poll_unix: u64,
    next_seq: u64,
    epoch: String,
    messages: Vec<MessageView>,
    events: VecDeque<WalletEvent>,
}

/// Wallet-facing messenger service.
///
/// Create with [`WalletService::open`], then call [`WalletService::start_network`]
/// (non-blocking). Use [`WalletService::wait_ready`] or [`WalletService::status`]
/// to observe startup. All methods are thread-safe; the HTTP daemon calls them
/// from connection threads.
pub struct WalletService {
    config: ServiceConfig,
    seed: Zeroizing<[u8; 32]>,
    identity: Identity,
    address: String,
    onion: String,
    history: History,
    contacts: ContactBook,
    read_state: ReadState,
    transport: Mutex<Option<TransportSpec>>,
    state: Mutex<State>,
    cv: Condvar,
    stop: AtomicBool,
}

impl WalletService {
    /// Open local storage and derive all keys. Does not touch the network.
    pub fn open(config: ServiceConfig, seed: Zeroizing<[u8; 32]>) -> Result<Self, String> {
        fs::create_dir_all(&config.data_dir)
            .map_err(|e| format!("data dir {}: {e}", config.data_dir.display()))?;
        let key = storage_key(&seed, &config.network);
        let identity = crate::identity::identity_from_seed(*seed, &config.network)
            .map_err(|e| format!("identity: {e}"))?;
        let address = identity.address().to_string();
        let onion = identity.address().onion();
        let history = History::open(config.data_dir.join("history"), key)
            .map_err(|e| format!("history: {e}"))?;
        let contacts = ContactBook::open(config.data_dir.join("contacts"), key)
            .map_err(|e| format!("contacts: {e}"))?;
        let read_state = ReadState::open(config.data_dir.join("state"), key)?;
        let epoch = crate::identity::generate_token()
            .map(|token| token[..32].to_string())
            .unwrap_or_else(|_| "epoch".to_string());
        let messages = load_history(&history);
        let next_seq = messages.len() as u64;
        Ok(Self {
            config,
            seed,
            identity,
            address,
            onion,
            history,
            contacts,
            read_state,
            transport: Mutex::new(None),
            state: Mutex::new(State {
                phase: "starting".into(),
                detail: "network not started".into(),
                last_error: None,
                last_poll_unix: 0,
                next_seq,
                epoch,
                messages,
                events: VecDeque::new(),
            }),
            cv: Condvar::new(),
            stop: AtomicBool::new(false),
        })
    }

    pub fn config(&self) -> &ServiceConfig {
        &self.config
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn onion(&self) -> &str {
        &self.onion
    }

    pub fn capabilities(&self) -> Capabilities {
        capabilities()
    }

    /// Start the network thread. Returns immediately; use [`Self::status`] /
    /// [`Self::wait_ready`] to observe bootstrap.
    pub fn start_network(self: &Arc<Self>) {
        let service = self.clone();
        let spawned = std::thread::Builder::new()
            .name("grinmessenger-wallet-network".into())
            .spawn(move || service.network_loop());
        if spawned.is_err() {
            self.set_error("cannot spawn network thread");
        }
    }

    /// Wait until the transport is ready or fails. Returns the final status.
    pub fn wait_ready(&self, timeout: Duration) -> ServiceStatus {
        let deadline = Instant::now() + timeout;
        let mut state = self.lock_state();
        loop {
            if state.phase == "ready" || state.phase == "error" {
                return self.status_locked(&state);
            }
            let now = Instant::now();
            if now >= deadline {
                return self.status_locked(&state);
            }
            let (guard, _) = self
                .cv
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = guard;
        }
    }

    pub fn status(&self) -> ServiceStatus {
        let state = self.lock_state();
        self.status_locked(&state)
    }

    pub fn messages(&self, after: u64, limit: usize) -> MessagesPage {
        let state = self.lock_state();
        let limit = limit.clamp(1, 1_000);
        let mut messages: Vec<MessageView> = state
            .messages
            .iter()
            .filter(|message| message.seq > after)
            .take(limit)
            .cloned()
            .collect();
        let next = messages.last().map(|message| message.seq).unwrap_or(after);
        // Keep the JSON shape stable even for an empty page.
        messages.shrink_to_fit();
        MessagesPage {
            epoch: state.epoch.clone(),
            next,
            messages,
        }
    }

    /// Long-poll events after `since`. Blocks up to `wait` for a new event.
    pub fn events(&self, since: u64, wait: Duration) -> EventsPage {
        let deadline = Instant::now() + wait;
        let mut state = self.lock_state();
        loop {
            let events: Vec<WalletEvent> = state
                .events
                .iter()
                .filter(|event| event.seq > since)
                .cloned()
                .collect();
            if !events.is_empty() || self.stop.load(Ordering::Relaxed) {
                return EventsPage {
                    epoch: state.epoch.clone(),
                    next: state.next_seq,
                    events,
                };
            }
            let now = Instant::now();
            if now >= deadline {
                return EventsPage {
                    epoch: state.epoch.clone(),
                    next: state.next_seq,
                    events,
                };
            }
            let (guard, _) = self
                .cv
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = guard;
        }
    }

    pub fn contacts(&self) -> Result<Vec<Contact>, String> {
        self.contacts.list().map_err(|e| format!("contacts: {e}"))
    }

    pub fn add_contact(&self, address: &str, name: &str) -> Result<Contact, String> {
        let parsed = Address::parse(address).map_err(|e| format!("contact address: {e}"))?;
        if parsed.hrp() != network_hrp(&self.config.network) {
            return Err(format!(
                "contact {} is {} but this service is {}",
                parsed,
                parsed.hrp(),
                network_hrp(&self.config.network)
            ));
        }
        let name = name.trim();
        if name.is_empty() {
            return Err("contact name is empty".into());
        }
        if name.chars().count() > MAX_CONTACT_NAME {
            return Err(format!(
                "contact name is longer than {MAX_CONTACT_NAME} characters"
            ));
        }
        if self.contacts.list().map(|list| list.len()).unwrap_or(0) >= MAX_CONTACTS {
            return Err(format!("contact limit ({MAX_CONTACTS}) reached"));
        }
        self.contacts
            .save(&parsed.to_string(), name)
            .map_err(|e| format!("contacts: {e}"))
    }

    pub fn remove_contact(&self, address: &str) -> Result<bool, String> {
        self.contacts
            .delete(address)
            .map_err(|e| format!("contacts: {e}"))
    }

    pub fn unread(&self) -> (BTreeMap<String, u64>, u64) {
        let state = self.lock_state();
        let markers = self.read_state.snapshot();
        let mut per_peer = BTreeMap::new();
        let mut total = 0u64;
        for message in &state.messages {
            if message.direction != "incoming" {
                continue;
            }
            let marker = markers.get(&message.peer).copied().unwrap_or(0);
            if message.created_at > marker {
                *per_peer.entry(message.peer.clone()).or_insert(0) += 1;
                total += 1;
            }
        }
        (per_peer, total)
    }

    /// Mark a peer's incoming messages as read up to the newest known one.
    pub fn mark_read(&self, peer: &str) -> Result<u64, String> {
        let parsed = Address::parse(peer).map_err(|e| format!("peer address: {e}"))?;
        let key = parsed.to_string();
        let cutoff = {
            let state = self.lock_state();
            state
                .messages
                .iter()
                .filter(|message| message.peer == key && message.direction == "incoming")
                .map(|message| message.created_at)
                .max()
                .unwrap_or_else(unix_now)
        };
        self.read_state.mark_read(&key, cutoff)?;
        Ok(cutoff)
    }

    pub fn send_text(
        &self,
        to: &str,
        text: &str,
        ttl_secs: Option<u64>,
    ) -> Result<MessageView, String> {
        if text.is_empty() {
            return Err("text is empty".into());
        }
        if text.len() > MAX_TEXT_BYTES {
            return Err(format!("text is longer than {MAX_TEXT_BYTES} bytes"));
        }
        self.send_kind(
            to,
            MessageKind::Text {
                text: text.to_string(),
            },
            ttl_secs,
        )
    }

    /// Send encrypted Slatepack armor. Plaintext Slatepack is refused by the
    /// protocol; wallets must call their `slatepack` encoder with encryption on.
    pub fn send_slatepack(
        &self,
        to: &str,
        armor: &str,
        ttl_secs: Option<u64>,
    ) -> Result<MessageView, String> {
        let armor = armor.trim();
        if armor.is_empty() {
            return Err("slatepack armor is empty".into());
        }
        if armor.len() > MAX_ARMOR_BYTES {
            return Err(format!(
                "slatepack armor is longer than {MAX_ARMOR_BYTES} bytes"
            ));
        }
        self.send_kind(
            to,
            MessageKind::Slatepack {
                armor: armor.to_string(),
                encrypted: true,
            },
            ttl_secs,
        )
    }

    fn send_kind(
        &self,
        to: &str,
        kind: MessageKind,
        ttl_secs: Option<u64>,
    ) -> Result<MessageView, String> {
        let peer = Address::parse(to).map_err(|e| format!("recipient address: {e}"))?;
        if peer.hrp() != network_hrp(&self.config.network) {
            return Err(format!(
                "recipient {} is {} but this service is {}",
                peer,
                peer.hrp(),
                network_hrp(&self.config.network)
            ));
        }
        let spec = self
            .transport
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
            .ok_or_else(|| "network is not ready".to_string())?;
        let transport = spec.build()?;
        let messenger = Messenger::new(transport);
        let ttl = ttl_secs
            .unwrap_or(self.config.ttl_secs)
            .clamp(1, MAX_TTL_SECS);
        let envelope = messenger
            .send(&self.identity, &peer, kind.clone(), ttl)
            .map_err(|e| format!("send: {e}"))?;
        let record = MessageRecord {
            id: envelope.id.clone(),
            direction: Direction::Outgoing,
            kind: kind.clone(),
            created_at: envelope.created_at,
            expires_at: Some(envelope.created_at.saturating_add(ttl)),
        };
        if let Err(e) = self.history.record(&peer, &record) {
            return Err(format!("message sent but local history write failed: {e}"));
        }
        let mut view = MessageView::from_record(&peer, record, 0);
        view.seq = self.push_message(view.clone());
        Ok(view)
    }

    /// Stop polling. The process may exit afterwards; direct-mode handles are
    /// dropped when the network thread returns.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.cv.notify_all();
    }

    // ---------- internals ----------

    fn lock_state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn status_locked(&self, state: &State) -> ServiceStatus {
        let markers = self.read_state.snapshot();
        let mut per_peer = BTreeMap::new();
        let mut unread = 0u64;
        for message in &state.messages {
            if message.direction != "incoming" {
                continue;
            }
            if message.created_at > markers.get(&message.peer).copied().unwrap_or(0) {
                *per_peer.entry(message.peer.clone()).or_insert(0) += 1;
                unread += 1;
            }
        }
        ServiceStatus {
            phase: state.phase.clone(),
            detail: state.detail.clone(),
            mode: self.config.mode.label().to_string(),
            network: network_hrp(&self.config.network).to_string(),
            address: self.address.clone(),
            onion: self.onion.clone(),
            onion_url: format!("http://{}.onion", self.onion),
            last_error: state.last_error.clone(),
            last_poll_unix: state.last_poll_unix,
            unread,
            unread_by_peer: per_peer,
            api_version: API_VERSION,
        }
    }

    fn set_spec(&self, spec: TransportSpec) {
        *self
            .transport
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(spec);
    }

    fn set_phase(&self, phase: &str, detail: impl Into<String>) {
        let mut state = self.lock_state();
        state.phase = phase.to_string();
        state.detail = detail.into();
        if phase == "ready" {
            state.last_error = None;
        }
        let detail = state.detail.clone();
        push_event_locked(
            &mut state,
            EventKind::Status {
                phase: phase.to_string(),
                detail,
            },
        );
        self.cv.notify_all();
    }

    fn set_ready(&self, detail: impl Into<String>) {
        let mut state = self.lock_state();
        state.phase = "ready".into();
        state.detail = detail.into();
        state.last_error = None;
        let detail = state.detail.clone();
        push_event_locked(
            &mut state,
            EventKind::Status {
                phase: "ready".into(),
                detail,
            },
        );
        self.cv.notify_all();
    }

    fn set_error(&self, error: impl Into<String>) {
        let message = error.into();
        let mut state = self.lock_state();
        state.phase = "error".into();
        state.detail = message.clone();
        state.last_error = Some(message.clone());
        push_event_locked(&mut state, EventKind::Error { message });
        self.cv.notify_all();
    }

    fn note_poll_error(&self, error: impl Into<String>) {
        let message = error.into();
        let mut state = self.lock_state();
        let changed = state.last_error.as_deref() != Some(message.as_str());
        state.last_error = Some(message.clone());
        if changed {
            push_event_locked(&mut state, EventKind::Error { message });
            self.cv.notify_all();
        }
    }

    /// Assign a sequence number and append a live message + event.
    fn push_message(&self, mut view: MessageView) -> u64 {
        let mut state = self.lock_state();
        let seq = state.next_seq + 1;
        state.next_seq = seq;
        view.seq = seq;
        state.events.push_back(WalletEvent {
            seq,
            event: EventKind::Message {
                message: view.clone(),
            },
        });
        while state.events.len() > MAX_EVENTS {
            state.events.pop_front();
        }
        state.messages.push(view);
        if state.messages.len() > MAX_HISTORY_MESSAGES {
            let overflow = state.messages.len() - MAX_HISTORY_MESSAGES;
            state.messages.drain(0..overflow);
        }
        self.cv.notify_all();
        seq
    }

    fn tor_config(&self) -> TorConfig {
        let state_dir = self
            .config
            .tor_state
            .clone()
            .unwrap_or_else(|| self.config.data_dir.join("arti-state"));
        let mut config = TorConfig::new(state_dir);
        config.bootstrap_timeout = Duration::from_secs(150);
        config.request_timeout = Duration::from_secs(60);
        config
    }

    fn network_loop(&self) {
        let result = self.run_network();
        if let Err(error) = result {
            self.set_error(error);
        }
    }

    fn run_network(&self) -> Result<(), String> {
        match self.config.mode.clone() {
            NetworkMode::Relay { url, plain } => {
                if plain {
                    let spec = TransportSpec::RelayPlain { url: url.clone() };
                    self.set_spec(spec.clone());
                    self.set_ready(format!("relay {url} (plain TCP)"));
                    self.poll_loop(spec);
                } else {
                    self.set_phase("tor", "Arti bootstrap for relay transport…");
                    let config = self.tor_config();
                    let client = TorHttpClient::bootstrap(&config)
                        .map_err(|e| format!("Tor/Arti bootstrap: {e}"))?;
                    let connector: Arc<dyn HttpConnector> = Arc::new(ArtiConnector { client });
                    let spec = TransportSpec::RelayArti {
                        url: url.clone(),
                        connector,
                    };
                    self.set_spec(spec.clone());
                    self.set_ready(format!("relay {url} over Arti"));
                    self.poll_loop(spec);
                }
            }
            NetworkMode::Direct => {
                self.set_phase("tor", "starting loopback gateway and Arti onion service…");
                let mailbox = self.config.data_dir.join("mailbox");
                fs::create_dir_all(&mailbox).map_err(|e| format!("mailbox: {e}"))?;
                let gateway = Gateway::start(GatewayConfig {
                    bind: "127.0.0.1:0".parse().expect("gateway bind"),
                    store_dir: Some(mailbox),
                    require_signed_ack: true,
                    require_pow: true,
                    ttl_secs: self.config.ttl_secs,
                    max_per_recipient: 500,
                    max_total: 5_000,
                    max_payload: MAX_ARMOR_BYTES,
                    max_posts_per_minute: 30,
                    // Tor forwards every sender from 127.0.0.1; a shared rate
                    // bucket lets one cheap attacker block all peers. Use the
                    // larger queue + PoW + the poll/ack drain loop instead.
                    enforce_post_rate: false,
                    ..GatewayConfig::default()
                })
                .map_err(|e| format!("gateway: {e}"))?;
                if !wait_ready(&gateway, Duration::from_secs(5)) {
                    return Err("loopback gateway did not pass its health check".into());
                }
                let onion = OnionService::start(
                    &self.seed,
                    &gateway.addr().to_string(),
                    &self.tor_config(),
                )
                .map_err(|e| format!("onion service: {e}"))?;
                let client = TorHttpClient::bootstrap(&self.tor_config())
                    .map_err(|e| format!("Tor/Arti bootstrap: {e}"))?;
                let connector: Arc<dyn HttpConnector> = Arc::new(ArtiConnector { client });
                let spec = TransportSpec::Direct {
                    local_url: gateway.url(),
                    connector,
                };
                self.set_spec(spec.clone());
                self.set_ready(format!("direct onion {}.onion", self.onion));
                self.poll_loop(spec);
                // Keep the gateway and onion service alive for the whole loop.
                drop(gateway);
                drop(onion);
            }
        }
        Ok(())
    }

    fn poll_loop(&self, spec: TransportSpec) {
        let transport = match spec.build() {
            Ok(transport) => transport,
            Err(error) => {
                self.set_error(error);
                return;
            }
        };
        let messenger: Messenger<ActiveTransport> = Messenger::new(transport);
        let mut last_error: Option<String> = None;
        loop {
            if self.stop.load(Ordering::Relaxed) {
                self.set_phase("stopped", "network loop stopped");
                return;
            }
            match messenger.fetch_open(&self.identity, self.config.fetch_limit) {
                Ok(batch) => {
                    self.handle_batch(&messenger, batch);
                    let mut state = self.lock_state();
                    state.last_poll_unix = unix_now();
                    if state
                        .last_error
                        .as_deref()
                        .map(|error| error.starts_with("fetch:"))
                        .unwrap_or(false)
                    {
                        // A successful poll clears a transient fetch error;
                        // history/ACK errors keep being reported until fixed.
                        state.last_error = None;
                    }
                }
                Err(error) => {
                    let message = format!("fetch: {error}");
                    if last_error.as_deref() != Some(message.as_str()) {
                        last_error = Some(message.clone());
                        self.note_poll_error(message);
                    }
                }
            }
            std::thread::sleep(Duration::from_secs(self.config.poll_secs.max(1)));
        }
    }

    fn handle_batch(
        &self,
        messenger: &Messenger<ActiveTransport>,
        batch: glaux_messenger::ReceiveBatch,
    ) {
        let mut ack_ids = batch.duplicates;
        for opened in batch.opened {
            let peer = opened.sender.clone();
            let already = self.history.contains(&peer, &opened.id).unwrap_or(false);
            if !already {
                let record = MessageRecord {
                    id: opened.id.clone(),
                    direction: Direction::Incoming,
                    kind: opened.kind.clone(),
                    created_at: opened.created_at,
                    expires_at: None,
                };
                if let Err(error) = self.history.record(&peer, &record) {
                    self.note_poll_error(format!(
                        "history write for {} failed: {error}",
                        opened.id
                    ));
                    continue; // Not acked: delivery is retried on the next poll.
                }
                let view = MessageView::from_opened(opened.clone(), 0);
                self.push_message(view);
            }
            ack_ids.push(opened.id);
        }
        for failed in batch.failed {
            let error = format!("rejected envelope {}: {}", failed.id, failed.error);
            self.note_poll_error(error.clone());
            let mut state = self.lock_state();
            push_event_locked(
                &mut state,
                EventKind::Rejected {
                    id: failed.id,
                    error,
                },
            );
            self.cv.notify_all();
        }
        if !ack_ids.is_empty() {
            if let Err(error) = messenger.ack_signed(&self.identity, &ack_ids) {
                self.note_poll_error(format!("ACK: {error}"));
            }
        }
    }
}

fn push_event_locked(state: &mut State, event: EventKind) -> u64 {
    let seq = state.next_seq + 1;
    state.next_seq = seq;
    state.events.push_back(WalletEvent { seq, event });
    while state.events.len() > MAX_EVENTS {
        state.events.pop_front();
    }
    seq
}

fn load_history(history: &History) -> Vec<MessageView> {
    let mut out = Vec::new();
    let conversations = history.conversations().unwrap_or_default();
    for peer in conversations {
        let records = history.list(&peer, 2_000).unwrap_or_default();
        for record in records {
            out.push(MessageView::from_record(&peer, record, 0));
        }
    }
    out.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.id.cmp(&right.id))
    });
    for (index, message) in out.iter_mut().enumerate() {
        message.seq = index as u64 + 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "glaux-wallet-service-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn relay_mode(dir: PathBuf) -> ServiceConfig {
        ServiceConfig {
            data_dir: dir,
            network: "tgrin".into(),
            mode: NetworkMode::Relay {
                url: "http://127.0.0.1:9".into(),
                plain: true,
            },
            poll_secs: 1,
            fetch_limit: 20,
            ttl_secs: 600,
            tor_state: None,
        }
    }

    #[test]
    fn service_opens_with_empty_encrypted_storage() {
        let dir = temp_dir("open");
        let seed = Zeroizing::new([11u8; 32]);
        let service = WalletService::open(relay_mode(dir.clone()), seed).unwrap();
        assert!(service.address().starts_with("tgrin1"));
        assert_eq!(service.onion().len(), 56);
        assert!(service.messages(0, 100).messages.is_empty());
        assert_eq!(service.unread().1, 0);
        assert!(service.contacts().unwrap().is_empty());
        assert!(dir.join("history").exists());
        assert!(dir.join("contacts").exists());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn wrong_network_addresses_are_rejected() {
        let dir = temp_dir("network");
        let seed = Zeroizing::new([12u8; 32]);
        let service = WalletService::open(relay_mode(dir.clone()), seed).unwrap();
        let mainnet = Identity::from_seed([1u8; 32], "grin").unwrap();
        let error = service
            .send_text(&mainnet.address().to_string(), "hi", None)
            .unwrap_err();
        assert!(
            error.contains("mainnet") || error.contains("grin"),
            "{error}"
        );
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn capabilities_are_stable() {
        let caps = capabilities();
        assert_eq!(caps.api_version, 1);
        assert!(caps.kinds.iter().any(|kind| kind == "slatepack"));
        assert!(!caps.slatepack_plaintext);
        assert_eq!(caps.bind, "loopback");
    }
}
