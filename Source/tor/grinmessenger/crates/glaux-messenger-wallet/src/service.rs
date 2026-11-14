// SPDX-License-Identifier: MIT OR Apache-2.0
//! Embedded wallet-facing service: identity, encrypted local storage, network
//! thread (relay or direct onion), message index, events and unread counters.
//!
//! The service is intentionally UI-free. A Rust wallet can embed it directly;
//! a non-Rust wallet talks to `glauxmsg-walletd`, which is a thin HTTP shell
//! around this service (see [`crate::server`]).

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use glaux_gateway::{wait_ready, Gateway, GatewayConfig};
use glaux_messenger::envelope::unix_now;
use glaux_messenger::nostr::{ContactDirectory, NostrKeys, NostrTransport, WsRelay};
use glaux_messenger::nostr::binding::NostrBinding;
use glaux_messenger::i2p_binding::Binding as I2pBinding;
use glaux_messenger::i2p_sam::Destination as I2pDestination;
use glaux_messenger::i2p_transport::{I2pEndpoint, I2pTransport};
use glaux_messenger::FileMailbox;
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

fn delivery_ttl(requested:Option<u64>,configured:u64,is_nostr:bool)->u64 {
    if is_nostr {15*60} else {requested.unwrap_or(configured).clamp(1,MAX_TTL_SECS)}
}

fn local_history_expiry(kind:&MessageKind,days:u32)->Option<u64> {
    if days==0 || !matches!(kind,MessageKind::Text {..}) {return None}
    Some(unix_now().saturating_add(u64::from(days).saturating_mul(86_400)))
}

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
    /// Experimental I2P-only Nostr mode. Callers must verify and durably
    /// retain prior bindings before passing them here; no mode switch is automatic.
    NostrI2p { relay: String, socks: SocketAddr, expiration_tag: bool },
    /// Direct WSS reveals the user's IP to the server. Explicit consent is required.
    NostrDirect { relay: String, consent: bool, expiration_tag: bool },
    /// Direct communication over an explicitly configured local I2P router.
    I2p { sam: SocketAddr },
}

impl NetworkMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Relay { .. } => "relay",
            Self::Direct => "direct",
            Self::NostrI2p { .. } => "nostr_i2p",
            Self::NostrDirect { .. } => "nostr_direct",
            Self::I2p { .. } => "i2p_direct",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServiceConfig {
    pub data_dir: PathBuf,
    pub network: String,
    pub mode: NetworkMode,
    /// Stable route identity for a managed local router; never supplied by RPC.
    pub logical_proxy: Option<String>,
    pub poll_secs: u64,
    pub fetch_limit: usize,
    pub ttl_secs: u64,
    /// 0: keep local text; 30: retain newly recorded text for 30 days.
    pub history_days: u32,
    /// Arti state/cache directory; defaults to `<data_dir>/arti-state`.
    pub tor_state: Option<PathBuf>,
    pub bridge_line: Option<String>,
    pub bridge_binary: Option<PathBuf>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("glauxmsg-wallet"),
            network: "tgrin".into(),
            mode: NetworkMode::Direct,
            logical_proxy: None,
            // Fast direct-mode drain so a cheap flood cannot hold the queue
            // between polls; relay mode is fine with the same cadence.
            poll_secs: 1,
            fetch_limit: 100,
            ttl_secs: 12 * 60 * 60,
            history_days: 0,
            tor_state: None,
            bridge_line: None,
            bridge_binary: None,
        }
    }
}

/// One delivery backend built from a [`TransportSpec`].
pub enum ActiveTransport {
    Relay(GatewayTransport),
    Direct(DirectOnionTransport),
    Nostr(NostrTransport<WsRelay, ContactDirectory>),
    I2p(I2pTransport),
}

impl Transport for ActiveTransport {
    fn take_warning(&self) -> Option<String> {
        match self { Self::Relay(t)=>t.take_warning(),Self::Direct(t)=>t.take_warning(),Self::Nostr(t)=>t.take_warning(),Self::I2p(t)=>t.take_warning() }
    }
    fn fetch_signed_tagged(&self, recipient: &Identity, now: u64, limit: usize) -> glaux_messenger::Result<Vec<(Envelope, Option<String>)>> {
        match self {
            Self::Relay(t) => t.fetch_signed_tagged(recipient, now, limit),
            Self::Direct(t) => t.fetch_signed_tagged(recipient, now, limit),
            Self::Nostr(t) => t.fetch_signed_tagged(recipient, now, limit),
            Self::I2p(t) => t.fetch_signed_tagged(recipient, now, limit),
        }
    }
    fn fetch_signed_page(&self,recipient:&Identity,now:u64,limit:usize)->glaux_messenger::Result<glaux_messenger::store::TransportPage> {
        match self {Self::Relay(t)=>t.fetch_signed_page(recipient,now,limit),Self::Direct(t)=>t.fetch_signed_page(recipient,now,limit),Self::Nostr(t)=>t.fetch_signed_page(recipient,now,limit),Self::I2p(t)=>t.fetch_signed_page(recipient,now,limit)}
    }
    fn reject_saved_raw(&self,recipient:&Identity,quarantine:&glaux_messenger::raw_quarantine::RawQuarantine,saved:&glaux_messenger::raw_quarantine::QuarantinedRaw)->glaux_messenger::Result<()> {
        match self {Self::Relay(t)=>t.reject_saved_raw(recipient,quarantine,saved),Self::Direct(t)=>t.reject_saved_raw(recipient,quarantine,saved),_=>Err(glaux_messenger::Error::Store("raw rejection unsupported".into()))}
    }
    fn deliver(&self, envelope: &Envelope) -> glaux_messenger::Result<()> {
        match self {
            Self::Relay(t) => t.deliver(envelope),
            Self::Direct(t) => t.deliver(envelope),
            Self::Nostr(t) => t.deliver(envelope),
            Self::I2p(t) => t.deliver(envelope),
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
            Self::Nostr(t) => t.fetch(recipient, now, limit),
            Self::I2p(t) => t.fetch(recipient, now, limit),
        }
    }
    fn ack(&self, recipient: &Address, ids: &[String]) -> glaux_messenger::Result<usize> {
        match self {
            Self::Relay(t) => t.ack(recipient, ids),
            Self::Direct(t) => t.ack(recipient, ids),
            Self::Nostr(t) => t.ack(recipient, ids),
            Self::I2p(t) => t.ack(recipient, ids),
        }
    }
    // GrinSight patch: forward the signed fetch too. Without it the trait's default
    // (unsigned) fetch is used, and a relay that requires a fetch proof
    // (glaux-relay's default) answers 401 "fetch proof required".
    fn fetch_signed(&self, recipient: &Identity, now: u64, limit: usize) -> glaux_messenger::Result<Vec<Envelope>> {
        match self {
            Self::Relay(t) => t.fetch_signed(recipient, now, limit),
            Self::Direct(t) => t.fetch_signed(recipient, now, limit),
            Self::Nostr(t) => t.fetch_signed(recipient, now, limit),
            Self::I2p(t) => t.fetch_signed(recipient, now, limit),
        }
    }
    fn ack_signed(&self, recipient: &Identity, ids: &[String]) -> glaux_messenger::Result<usize> {
        match self {
            Self::Relay(t) => t.ack_signed(recipient, ids),
            Self::Direct(t) => t.ack_signed(recipient, ids),
            Self::Nostr(t) => t.ack_signed(recipient, ids),
            Self::I2p(t) => t.ack_signed(recipient, ids),
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
    NostrI2p { relay: String, socks: SocketAddr, keys: NostrKeys, directory: ContactDirectory, ttl: u64, expiration_tag: bool },
    NostrDirect { relay: String, keys: NostrKeys, directory: ContactDirectory, ttl: u64, expiration_tag: bool },
    I2p { transport: I2pTransport },
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
            Self::NostrI2p { relay, socks, keys, directory, ttl, expiration_tag } => {
                let ws = WsRelay::new_i2p(relay, keys.clone(), *socks).map_err(|_| "invalid I2P Nostr route".to_string())?;
                Ok(ActiveTransport::Nostr(NostrTransport::new(ws, keys.clone(), directory.clone()).with_ttl(*ttl).with_expiration_tag(*expiration_tag)))
            },
            Self::NostrDirect { relay, keys, directory, ttl, expiration_tag } => {
                if !relay.starts_with("wss://") { return Err("direct Nostr requires wss".into()); }
                let ws = WsRelay::new_direct(relay, keys.clone()).map_err(|_| "invalid direct Nostr route".to_string())?;
                Ok(ActiveTransport::Nostr(NostrTransport::new(ws, keys.clone(), directory.clone()).with_ttl(*ttl).with_expiration_tag(*expiration_tag)))
            },
            Self::I2p { transport } => Ok(ActiveTransport::I2p(transport.clone())),
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
    /// Incoming sender signature was verified before this message was stored.
    pub verified: bool,
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
            verified: record.signature_verified && direction == "incoming",
            direction: direction.to_string(),
            kind: "text".to_string(),
            text: None,
            armor: None,
            encrypted: None,
            created_at: record.created_at,
            expires_at: if record.local_expiry_opt_in {record.expires_at} else {None},
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
            verified: true,
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

pub type PaymentWatch=(u64,u64,[u8;32],u64,[u8;32]);
/// Return only the contiguous, generation-accounted live payment events.
/// A gap or inconsistent watermark forces a durable full scan.
pub fn incremental_payment_events(page:&EventsPage,since:u64,before:&PaymentWatch,after:&PaymentWatch)->Option<Vec<MessageView>> {
    if before.1!=after.1 || before.2!=after.2 || before.3!=after.3 || before.4!=after.4 {return None;}
    let mut expected=since.checked_add(1)?;let mut out=Vec::new();
    for item in &page.events {
        if item.seq!=expected{return None;}expected=expected.checked_add(1)?;
        if let EventKind::Message{message}=&item.event {
            if message.direction=="incoming" && message.kind=="slatepack" {out.push(message.clone());}
        }
    }
    if page.next!=expected.saturating_sub(1) || after.0.checked_sub(before.0)?!=out.len() as u64 {return None;}
    Some(out)
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
    raw_quarantine: glaux_messenger::raw_quarantine::RawQuarantine,
    contacts: ContactBook,
    read_state: ReadState,
    payment_outbox: crate::payment_outbox::PaymentOutbox,
    payment_send_lock: Mutex<()>,
    transport: Mutex<Option<TransportSpec>>,
    i2p_binding: Mutex<Option<I2pBinding>>,
    state: Mutex<State>,
    cv: Condvar,
    stop: AtomicBool,
    network_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    channel_gate: Mutex<Option<glaux_messenger::channel_drain::ChannelDrain>>,
}

fn new_i2p_session_id() -> Result<String, String> {
    use std::fmt::Write as _;
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|_| "I2P session randomness unavailable")?;
    let mut id = String::with_capacity(67);
    id.push_str("gs-");
    for byte in random { write!(&mut id, "{byte:02x}").expect("write to String"); }
    Ok(id)
}

impl WalletService {
    /// Open local storage and derive all keys. Does not touch the network.
    pub fn open(config: ServiceConfig, seed: Zeroizing<[u8; 32]>) -> Result<Self, String> {
        if !matches!(config.history_days,0|30) {return Err("invalid local history retention".into())}
        fs::create_dir_all(&config.data_dir)
            .map_err(|e| format!("data dir {}: {e}", config.data_dir.display()))?;
        let key = storage_key(&seed, &config.network);
        let identity = crate::identity::identity_from_seed(*seed, &config.network)
            .map_err(|e| format!("identity: {e}"))?;
        let address = identity.address().to_string();
        let onion = identity.address().onion();
        let history = History::open(config.data_dir.join("history"), key)
            .map_err(|e| format!("history: {e}"))?;
        let mut raw_key = Zeroizing::new([0u8; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(b"grinsight/raw-quarantine/v1"), &key)
            .expand(config.network.as_bytes(), &mut *raw_key).map_err(|_| "raw quarantine key derivation failed")?;
        let raw_quarantine = glaux_messenger::raw_quarantine::RawQuarantine::open(config.data_dir.join("raw-quarantine"),identity.address().clone(),*raw_key)
            .map_err(|e|format!("raw quarantine: {e}"))?;
        let contacts = ContactBook::open(config.data_dir.join("contacts"), key)
            .map_err(|e| format!("contacts: {e}"))?;
        let read_state = ReadState::open(config.data_dir.join("state"), key)?;
        let payment_outbox = crate::payment_outbox::PaymentOutbox::open(config.data_dir.join("payment-outbox"), &seed, &config.network)?;
        let epoch = crate::identity::generate_token()
            .map(|token| token[..32].to_string())
            .unwrap_or_else(|_| "epoch".to_string());
        let messages = load_history(&history)?;
        let existing: Vec<_> = messages.iter().filter(|m| m.direction == "incoming").map(|m| (m.peer.clone(), m.id.clone(), m.created_at)).collect();
        read_state.migrate_legacy(&existing)?;
        let next_seq = messages.len() as u64;
        Ok(Self {
            config,
            seed,
            identity,
            address,
            onion,
            history,
            raw_quarantine,
            contacts,
            read_state,
            payment_outbox,
            payment_send_lock: Mutex::new(()),
            transport: Mutex::new(None),
            i2p_binding: Mutex::new(None),
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
            network_thread: Mutex::new(None),
            channel_gate: Mutex::new(None),
        })
    }

    /// Configure the admission gate before starting any network worker.
    pub fn set_channel_gate(&self, gate: glaux_messenger::channel_drain::ChannelDrain) {
        *self.channel_gate.lock().unwrap_or_else(|p| p.into_inner()) = Some(gate);
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
        // Refuse a second worker: otherwise its handle could be lost and a
        // later drain could incorrectly report that the network had stopped.
        let mut handle = self.network_thread.lock().unwrap_or_else(|p| p.into_inner());
        if handle.is_some() || self.stop.load(Ordering::Acquire) { return; }
        let service = self.clone();
        let spawned = std::thread::Builder::new()
            .name("grinmessenger-wallet-network".into())
            .spawn(move || service.network_loop());
        match spawned {
            Ok(thread) => *handle = Some(thread),
            Err(_) => self.set_error("cannot spawn network thread"),
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

    pub fn initialize_payment_checkpoint(&self)->Result<(),String> {self.history.initialize_payment_checkpoint().map_err(|e|format!("payment recovery initialization: {e}"))}
    pub fn payment_watch(&self)->Result<(u64,u64,[u8;32],u64,[u8;32]),String> {self.history.payment_watch().map_err(|e|format!("payment watch: {e}"))}
    pub fn payment_generation(&self)->Result<u64,String> {self.history.payment_generation().map_err(|e|format!("payment generation: {e}"))}
    pub fn begin_payment_scan(&self)->Result<glaux_messenger::history::PaymentScan,String> {self.history.begin_payment_scan().map_err(|e|format!("payment scan: {e}"))}
    pub fn next_payment_scan(&self,scan:&mut glaux_messenger::history::PaymentScan,limit:usize)->Result<(Vec<(MessageView,bool)>,bool),String> {
        let (rows,done)=self.history.next_payment_scan(scan,limit).map_err(|e|format!("payment scan: {e}"))?;
        let views=rows.into_iter().map(|(p,r,review)| {let peer=Address::parse(&p).map_err(|e|format!("payment peer: {e}"))?;Ok((MessageView::from_record(&peer,r,0),review))}).collect::<Result<Vec<_>,String>>()?;
        Ok((views,done))
    }
    pub fn pending_payment_page(&self,after:Option<(&str,&str)>,limit:usize)->Result<Vec<(MessageView,bool)>,String> {
        self.history.payment_page(after,limit).map_err(|e|format!("payment recovery scan: {e}"))?.into_iter().map(|(p,r,review)| {
            let peer=Address::parse(&p).map_err(|e|format!("payment recovery peer: {e}"))?;
            Ok((MessageView::from_record(&peer,r,0),review))
        }).collect()
    }
    pub fn payment_event_candidate(&self,scan:&glaux_messenger::history::PaymentScan,peer:&str,id:&str)->Result<Option<MessageView>,String> {
        let found=self.history.payment_event_candidate(scan,peer,id).map_err(|e|format!("payment event: {e}"))?;
        let peer=Address::parse(peer).map_err(|e|format!("payment peer: {e}"))?;
        Ok(found.map(|record|MessageView::from_record(&peer,record,0)))
    }
    /// Trusted daemon integration: call only after the handler persisted and synced its result.
    /// No remote endpoint exposes this operation.
    #[doc(hidden)]
    pub fn mark_payment_processed_after_durable_handler(&self,scan:&mut glaux_messenger::history::PaymentScan,peer:&str,id:&str)->Result<(),String> {self.history.mark_payment_processed_after_durable_handler(scan,peer,id).map_err(|e|format!("payment checkpoint: {e}"))}

    pub fn recovery_page(&self,offset:usize,limit:usize)->Result<(Vec<MessageView>,usize,bool),String> {
        let (rows,next,more)=self.history.legacy_review_page(offset,limit).map_err(|e|format!("payment recovery: {e}"))?;
        let rows=rows.into_iter().map(|(p,r)| {let peer=Address::parse(&p).map_err(|e|format!("payment peer: {e}"))?;Ok(MessageView::from_record(&peer,r,0))}).collect::<Result<Vec<_>,String>>()?;
        Ok((rows,next,more))
    }

    pub fn messages(&self, after: u64, limit: usize) -> MessagesPage {
        let state = self.lock_state();
        let limit = limit.clamp(1, 1_000);
        let mut messages: Vec<MessageView> = state
            .messages
            .iter()
            .filter(|message| message.seq > after && !message.expires_at.is_some_and(|at| at <= unix_now()))
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
                .filter(|event| event.seq > since && match &event.event {
                    EventKind::Message{message} => !message.expires_at.is_some_and(|at| at<=unix_now()),
                    _ => true,
                })
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

    /// Signed transport address for manual exchange. This proves the Glaux
    /// key controls the Nostr key; it does not establish a person's identity.
    pub fn nostr_binding(&self) -> Result<NostrBinding, String> {
        let keys = crate::identity::nostr_keys_from_messaging_seed(&self.seed, &self.config.network)?;
        let day = unix_now() / 86_400;
        let issued = day.saturating_mul(86_400);
        NostrBinding::create(&self.identity, &keys.public_hex(), day, issued, issued.saturating_add(7 * 86_400))
            .map_err(|_| "failed to create Nostr binding".into())
    }

    fn catalogue_relay(&self) -> Result<WsRelay, String> {
        let spec = self.transport.lock().map_err(|_| "transport unavailable")?;
        match spec.as_ref() {
            Some(TransportSpec::NostrDirect { relay, keys, .. }) => WsRelay::new_direct(relay, keys.clone()).map_err(|_| "invalid Nostr route".into()),
            Some(TransportSpec::NostrI2p { relay, socks, keys, .. }) => WsRelay::new_i2p(relay, keys.clone(), *socks).map_err(|_| "invalid I2P route".into()),
            _ => Err("catalogue requires an enabled Nostr route".into()),
        }
    }

    fn catalogue_route(&self) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        let (mode,url,proxy) = match &self.config.mode {
            NetworkMode::NostrDirect { relay, consent: true, .. } => ("nostr_direct", relay.as_str(), String::new()),
            NetworkMode::NostrI2p { relay, socks, .. } => ("nostr_i2p", relay.as_str(), self.config.logical_proxy.clone().unwrap_or_else(|| socks.to_string())),
            _ => return Err("catalogue requires an enabled Nostr route".into()),
        };
        let mut hash=Sha256::new(); hash.update(b"grinsight-payment-route-v1\0"); hash.update(mode.as_bytes()); hash.update(b"\0"); hash.update(url.as_bytes()); hash.update(b"\0"); hash.update(proxy.as_bytes());
        Ok(data_encoding::HEXLOWER.encode(&hash.finalize()))
    }

    fn require_catalogue_route(&self, expected: &str) -> Result<(), String> {
        if expected.len()!=64 || self.catalogue_route()?.as_str()!=expected { return Err("catalogue route changed; review and retry".into()); }
        Ok(())
    }

    /// Produces only a bounded structured signing request, never a private key.
    pub fn catalogue_draft(&self, name: &str, wallet_address: &str, sequence: u64, revoked: bool) -> Result<serde_json::Value, String> {
        use glaux_messenger::nostr::catalog::{Profile, ProfileClaims, comparison_code, normalize_name, wallet_transcript};
        let wallet = Address::parse(wallet_address).map_err(|_| "invalid wallet address")?;
        if wallet.hrp() != network_hrp(&self.config.network) { return Err("wrong wallet network".into()); }
        let claims = ProfileClaims { version: 1, name: normalize_name(name).map_err(|_| "invalid public name")?, wallet_address: wallet.to_string(), binding: self.nostr_binding()?, sequence, revoked };
        let transcript = wallet_transcript(&claims).map_err(|_| "invalid profile")?;
        let code = comparison_code(&Profile { claims: claims.clone(), wallet_signature: String::new() }).map_err(|_| "cannot calculate comparison code")?;
        let search_phrase = glaux_messenger::nostr::catalog::public_search_phrase(&claims.wallet_address).map_err(|_| "cannot calculate contact phrase")?;
        Ok(serde_json::json!({"claims": claims, "transcript_hex": data_encoding::HEXLOWER.encode(&transcript), "comparison_code": code, "search_phrase": search_phrase, "route":self.catalogue_route().ok()}))
    }

    pub fn catalogue_publish(&self, profile: &glaux_messenger::nostr::catalog::Profile, expected_route: &str) -> Result<String, String> {
        use glaux_messenger::nostr::{catalog, Relay};
        self.require_catalogue_route(expected_route)?;
        let keys = crate::identity::nostr_keys_from_messaging_seed(&self.seed, &self.config.network)?;
        let event = catalog::signed_event(&keys, profile, unix_now()).map_err(|_| "invalid signed public profile")?;
        self.catalogue_relay()?.publish(&event).map_err(|_| "catalogue server rejected or did not confirm publication")?;
        catalog::comparison_code(profile).map_err(|_| "cannot calculate comparison code".into())
    }

    pub fn catalogue_search(&self, name: &str, expected_route: &str) -> Result<Vec<serde_json::Value>, String> {
        use glaux_messenger::nostr::catalog;
        self.require_catalogue_route(expected_route)?;
        let profiles = catalog::search(&self.catalogue_relay()?, name, unix_now()).map_err(|_| "catalogue search failed")?;
        Ok(profiles.into_iter().filter(|p| Address::parse(&p.claims.wallet_address).map(|a| a.hrp() == network_hrp(&self.config.network)).unwrap_or(false)).map(|p| {
            serde_json::json!({"comparison_code":catalog::comparison_code(&p).unwrap_or_default(), "profile":p, "verified_identity":false})
        }).collect())
    }

    pub fn catalogue_add(&self, profile: &glaux_messenger::nostr::catalog::Profile, name: &str, identity_checked: bool) -> Result<Contact, String> {
        let owner = Address::parse(&profile.claims.binding.owner).map_err(|_| "invalid profile owner")?;
        if owner.hrp() != network_hrp(&self.config.network) { return Err("wrong contact network".into()); }
        let contact=self.contacts.save_catalog_profile(profile,name,unix_now(),identity_checked).map_err(|_| "invalid, changed or stale profile")?;
        let updated=self.verified_nostr_directory()?;
        if let Some(TransportSpec::NostrI2p { directory, .. } | TransportSpec::NostrDirect { directory, .. }) = self.transport.lock().unwrap_or_else(|p| p.into_inner()).as_mut() { *directory=updated; }
        Ok(contact)
    }

    fn verified_nostr_directory(&self) -> Result<ContactDirectory, String> {
        let mut directory = ContactDirectory::default();
        for contact in self.contacts.list().map_err(|_| "cannot read contacts")? {
            let Some(binding) = &contact.nostr_binding else { continue };
            let owner = Address::parse(&contact.address).map_err(|_| "invalid contact address")?;
            if owner.hrp() != network_hrp(&self.config.network) { continue; }
            if binding.verify_update(&owner, unix_now(), None).is_err() { continue; }
            directory.insert_hex(&contact.address, &binding.transport_key).map_err(|_| "invalid Nostr key")?;
        }
        Ok(directory)
    }

    /// Store only a signature-verified binding; rollback checks survive restart.
    pub fn add_nostr_binding(&self, binding: &NostrBinding, name: &str) -> Result<Contact, String> {
        let owner = Address::parse(&binding.owner).map_err(|_| "invalid contact address")?;
        if owner.hrp() != network_hrp(&self.config.network) { return Err("wrong contact network".into()); }
        let contact = self.contacts.save_nostr_binding(binding, name, unix_now()).map_err(|_| "invalid or stale Nostr binding")?;
        let updated = self.verified_nostr_directory()?;
        if let Some(TransportSpec::NostrI2p { directory, .. } | TransportSpec::NostrDirect { directory, .. }) = self.transport.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
            *directory = updated;
        }
        Ok(contact)
    }

    /// Public signed I2P destination; available once the local session starts.
    pub fn i2p_binding(&self) -> Result<I2pBinding, String> {
        let mut current=self.i2p_binding.lock().unwrap_or_else(|p| p.into_inner());
        let existing=current.as_ref().ok_or("I2P session is not ready")?;
        if existing.expires <= unix_now() {
            let day=unix_now()/86_400; let issued=day.saturating_mul(86_400);
            let renewed=I2pBinding::create(&self.identity,&existing.destination,day,issued,issued.saturating_add(7*86_400)).map_err(|_|"cannot refresh I2P binding")?;
            *current=Some(renewed);
        }
        current.clone().ok_or_else(|| "I2P session is not ready".into())
    }

    fn verified_i2p_directory(&self) -> Result<std::collections::HashMap<String, I2pBinding>, String> {
        let mut result = std::collections::HashMap::new();
        for contact in self.contacts.list().map_err(|_| "cannot read contacts")? {
            let Some(binding) = contact.i2p_binding else { continue };
            let owner = Address::parse(&contact.address).map_err(|_| "invalid contact address")?;
            if owner.hrp() != network_hrp(&self.config.network) { continue; }
            if binding.verify_update(&owner, unix_now(), None).is_ok() { result.insert(contact.address, binding); }
        }
        Ok(result)
    }

    pub fn add_i2p_binding(&self, binding: &I2pBinding, name: &str) -> Result<Contact, String> {
        let owner = Address::parse(&binding.owner).map_err(|_| "invalid contact address")?;
        if owner.hrp() != network_hrp(&self.config.network) { return Err("wrong contact network".into()); }
        self.contacts.save_i2p_binding(binding, name, unix_now()).map_err(|_| "invalid or stale I2P binding".to_string())
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
            if !markers.is_read(&message.peer, &message.id) {
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
        let state = self.lock_state();
        let cutoff = {
            state
                .messages
                .iter()
                .filter(|message| message.peer == key && message.direction == "incoming")
                .map(|message| message.created_at)
                .max()
                .unwrap_or_else(unix_now)
        };
        let ids: Vec<String> = state.messages.iter().filter(|m| m.peer == key && m.direction == "incoming").map(|m| m.id.clone()).collect();
        self.read_state.mark_read(&key, &ids)?;
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
        if self.stop.load(Ordering::Acquire) { return Err("network is stopping".into()); }
        let backup_route = match &self.config.mode {
            NetworkMode::NostrI2p { relay, socks, .. } => Some(format!("nostr-i2p:{relay}:{}", self.config.logical_proxy.clone().unwrap_or_else(|| socks.to_string()))),
            NetworkMode::NostrDirect { relay, .. } => Some(format!("nostr-direct:{relay}")),
            NetworkMode::I2p { sam } => Some(format!("i2p-direct:{}", self.config.logical_proxy.clone().unwrap_or_else(|| sam.to_string()))),
            _ => None,
        };
        let payment = matches!(&kind, MessageKind::Slatepack { .. }) && backup_route.is_some();
        let _payment_guard = if payment { Some(self.payment_send_lock.lock().map_err(|_| "payment send lock failed")?) } else { None };
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
        let mut spec = spec;
        if let TransportSpec::NostrI2p { directory, .. } | TransportSpec::NostrDirect { directory, .. } = &mut spec {
            *directory = self.verified_nostr_directory()?;
        }
        if let TransportSpec::I2p { transport } = &mut spec {
            *transport = transport.with_bindings(self.verified_i2p_directory()?);
        }
        let transport = spec.build()?;
        // Delivery TTL is independent of the Slatepack's own validity.
        let is_nostr=matches!(&self.config.mode,NetworkMode::NostrI2p{..}|NetworkMode::NostrDirect{..});
        let ttl = delivery_ttl(ttl_secs,self.config.ttl_secs,is_nostr);
        let envelope = if let (Some(route), MessageKind::Slatepack { armor, .. }) = (&backup_route, &kind) {
            let envelope = self.payment_outbox.envelope(&self.identity, &peer, armor, route, ttl)?;
            transport.deliver(&envelope).map_err(|e| format!("send outcome may be unknown: {e}"))?;
            envelope
        } else {
            Messenger::new(transport).send(&self.identity, &peer, kind.clone(), ttl).map_err(|e| format!("send: {e}"))?
        };
        let record = MessageRecord {
            id: envelope.id.clone(),
            direction: Direction::Outgoing,
            signature_verified: false,
            kind: kind.clone(),
            created_at: envelope.created_at,
            expires_at: local_history_expiry(&kind,self.config.history_days),
            local_expiry_opt_in: self.config.history_days>0 && matches!(&kind,MessageKind::Text{..}),
        };
        let already_saved = self.history.contains(&peer, &record.id).map_err(|e| format!("history check failed: {e}"))?;
        if !already_saved {
            if let Err(e) = self.history.record(&peer, &record) {
                return Err(format!("message sent but local history write failed: {e}"));
            }
        } else {
            let records = self.history.list(&peer, 2000).map_err(|e| format!("history verification failed: {e}"))?;
            let existing = records.iter().find(|item| item.id == record.id).ok_or("saved payment history is unreadable or unavailable")?;
            if existing.direction != record.direction || existing.kind != record.kind || existing.created_at != record.created_at {
                return Err("saved payment history conflicts with this message".into());
            }
        }
        let mut view = MessageView::from_record(&peer, record, 0);
        if !already_saved { view.seq = self.push_message(view.clone()); }
        Ok(view)
    }

    /// Stop polling. The process may exit afterwards; direct-mode handles are
    /// dropped when the network thread returns.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Release);
        *self.transport.lock().unwrap_or_else(|p| p.into_inner()) = None;
        self.cv.notify_all();
    }

    /// Request shutdown and await the network worker without force-killing it.
    /// A timeout is NOT an acknowledgement that process termination is safe.
    pub fn shutdown_and_wait(&self, timeout: Duration) -> Result<(), String> {
        self.shutdown();
        let deadline = Instant::now().checked_add(timeout).ok_or("invalid shutdown timeout")?;
        loop {
            let mut worker = self.network_thread.lock().map_err(|_| "network thread lock poisoned")?;
            if worker.as_ref().map_or(true, std::thread::JoinHandle::is_finished) {
                if let Some(thread) = worker.take() {
                    thread.join().map_err(|_| "network thread panicked")?;
                }
                *self.transport.lock().unwrap_or_else(|p| p.into_inner()) = None;
                return Ok(());
            }
            drop(worker);
            if Instant::now() >= deadline { return Err("network thread did not stop before timeout".into()); }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Restart only after the prior worker was conclusively joined.
    pub fn restart_network_after_shutdown(self: &Arc<Self>) {
        let handle=self.network_thread.lock().unwrap_or_else(|p| p.into_inner());
        if handle.is_some() { return; }
        self.stop.store(false, Ordering::Release);
        drop(handle);
        self.start_network();
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
            if !markers.is_read(&message.peer, &message.id) {
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
        if let Some(line) = &self.config.bridge_line {
            config = config.with_bridge(line.clone(), self.config.bridge_binary.clone());
        }
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

    fn wait_for_i2p<T>(&self, timeout: Duration, mut operation: impl FnMut() -> std::io::Result<T>) -> Result<T, String> {
        let deadline = Instant::now() + timeout;
        loop {
            if self.stop.load(Ordering::Relaxed) { return Err("I2P startup stopped".into()); }
            if let Ok(value) = operation() { return Ok(value); }
            if Instant::now() >= deadline { return Err("I2P router did not become available".into()); }
            std::thread::sleep(Duration::from_secs(2));
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
                        .map_err(|e| if self.config.bridge_line.is_some() { "Tor bridge bootstrap failed".to_string() } else { format!("Tor/Arti bootstrap: {e}") })?;
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
            NetworkMode::NostrI2p { relay, socks, expiration_tag } => {
                self.set_phase("connecting", "connecting to Nostr through I2P");
                let keys = crate::identity::nostr_keys_from_messaging_seed(&self.seed, &self.config.network)?;
                let directory = self.verified_nostr_directory()?;
                let spec = TransportSpec::NostrI2p { relay, socks, keys, directory, ttl: self.config.ttl_secs, expiration_tag };
                // Validate the route before exposing it; no direct route exists.
                spec.build()?;
                self.set_spec(spec.clone());
                self.poll_loop(spec);
            }
            NetworkMode::NostrDirect { relay, consent, expiration_tag } => {
                if !consent { return Err("direct Nostr requires explicit IP disclosure consent".into()); }
                self.set_phase("connecting", "connecting directly to Nostr; the server sees the IP address");
                let keys = crate::identity::nostr_keys_from_messaging_seed(&self.seed, &self.config.network)?;
                let directory = self.verified_nostr_directory()?;
                let spec = TransportSpec::NostrDirect { relay, keys, directory, ttl: self.config.ttl_secs, expiration_tag };
                spec.build()?;
                self.set_spec(spec.clone());
                self.poll_loop(spec);
            }
            NetworkMode::I2p { sam } => {
                if !sam.ip().is_loopback() || sam.port() == 0 { return Err("I2P SAM must be local".into()); }
                self.set_phase("connecting", "starting I2P session");
                let dir = self.config.data_dir.join("i2p");
                fs::create_dir_all(&dir).map_err(|_| "cannot create I2P data directory")?;
                let path = dir.join("destination.enc");
                let destination = if path.exists() {
                    crate::i2p_identity::load(&path, &self.seed, &self.config.network)?
                } else {
                    let generated = self.wait_for_i2p(Duration::from_secs(180), || I2pDestination::generate(sam))?;
                    crate::i2p_identity::save_new(&path, &self.seed, &self.config.network, &generated)?;
                    generated
                };
                let day = unix_now() / 86_400; let issued = day.saturating_mul(86_400);
                let binding = I2pBinding::create(&self.identity, destination.public(), day, issued, issued.saturating_add(7 * 86_400)).map_err(|_| "I2P binding creation failed")?;
                let session_id = new_i2p_session_id()?;
                let session = self.wait_for_i2p(Duration::from_secs(180), || destination.open_session(sam, &session_id))?;
                let mailbox = FileMailbox::open(dir.join("mailbox")).map_err(|_| "I2P mailbox unavailable")?;
                let endpoint = I2pEndpoint::start_guarded(session, self.identity.address().clone(), mailbox, self.channel_gate.lock().unwrap_or_else(|p| p.into_inner()).clone()).map_err(|_| "I2P listener unavailable")?;
                *self.i2p_binding.lock().unwrap_or_else(|p| p.into_inner()) = Some(binding);
                let spec = TransportSpec::I2p { transport: endpoint.transport(self.verified_i2p_directory()?) };
                self.set_spec(spec.clone());
                self.set_ready("I2P local session started; remote reachability not verified");
                self.poll_loop(spec);
                drop(endpoint);
            }
            NetworkMode::Direct => {
                self.set_phase("tor", "starting loopback gateway and Arti onion service…");
                let mailbox = self.config.data_dir.join("mailbox");
                fs::create_dir_all(&mailbox).map_err(|e| format!("mailbox: {e}"))?;
                let gateway = Gateway::start_guarded(GatewayConfig {
                    bind: "127.0.0.1:0".parse().expect("gateway bind"),
                    store_dir: Some(mailbox),
                    require_signed_ack: true,
                    require_v2_ack: true,
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
                }, self.channel_gate.lock().unwrap_or_else(|p| p.into_inner()).clone())
                .map_err(|e| format!("gateway: {e}"))?;
                if !wait_ready(&gateway, Duration::from_secs(5)) {
                    return Err("loopback gateway did not pass its health check".into());
                }
                let onion = OnionService::start(
                    &self.seed,
                    &gateway.addr().to_string(),
                    &self.tor_config(),
                )
                .map_err(|e| if self.config.bridge_line.is_some() { "Tor bridge onion service failed".to_string() } else { format!("onion service: {e}") })?;
                let client = TorHttpClient::bootstrap(&self.tor_config())
                    .map_err(|e| if self.config.bridge_line.is_some() { "Tor bridge bootstrap failed".to_string() } else { format!("Tor/Arti bootstrap: {e}") })?;
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
        let mut deferred_runtime:Option<(Arc<crate::deferred::Deferred>,NostrKeys)>=None;
        let transport = match transport {
            ActiveTransport::Nostr(t) => {
                let store=match self.open_nostr_cursor(&spec) {Ok(s)=>s,Err(e)=>{self.set_error(format!("nostr cursor: {e}"));return;}};
                let deferred=Arc::new(crate::deferred::Deferred::from_store(store.clone()));
                let keys=match &spec {TransportSpec::NostrDirect{keys,..}|TransportSpec::NostrI2p{keys,..}=>keys.clone(),_=>unreachable!()};
                deferred_runtime=Some((deferred.clone(),keys));
                match t.with_deferred(deferred).with_cursor(store) {Ok(t)=>ActiveTransport::Nostr(t),Err(e)=>{self.set_error(format!("nostr cursor: {e}"));return;}}
            },
            other=>other,
        };
        let messenger: Messenger<ActiveTransport> = Messenger::new(transport);
        let mut last_error: Option<String> = None;
        let mut next_deferred_replay=0u64;
        loop {
            if self.stop.load(Ordering::Relaxed) {
                self.set_phase("stopped", "network loop stopped");
                return;
            }
            let gate = self.channel_gate.lock().unwrap_or_else(|p| p.into_inner()).clone();
            let permit = match gate { Some(ref g) => match g.enter() { Some(p) => Some(p), None => { std::thread::sleep(Duration::from_millis(50)); continue; } }, None => None };
            if let Some((_,ref keys))=deferred_runtime {let now=unix_now();if now>=next_deferred_replay {
                match self.all_deferred_queues() {Ok(queues)=>for (_,queue) in queues {if let Err(e)=self.replay_deferred(&queue,keys,now) {self.note_poll_error(format!("nostr deferred replay: {e}"));}},Err(e)=>self.note_poll_error(format!("nostr deferred routes: {e}"))};
                next_deferred_replay=now.saturating_add(60);
            }}
            match messenger.fetch_open(&self.identity, self.config.fetch_limit) {
                Ok(batch) => {
                    let truncated = batch.truncated && matches!(&self.config.mode, NetworkMode::NostrI2p { .. } | NetworkMode::NostrDirect { .. });
                    if matches!(&self.config.mode, NetworkMode::NostrI2p { .. } | NetworkMode::NostrDirect { .. }) && self.lock_state().phase != "ready" {
                        let detail = if matches!(&self.config.mode, NetworkMode::NostrI2p { .. }) { "Nostr relay reachable through I2P" } else { "Nostr relay reachable directly; server sees IP" };
                        self.set_ready(detail);
                    }
                    self.handle_batch(&messenger, batch);
                    let warning = messenger.take_warning();
                    if let Some(ref warning) = warning { self.note_poll_error(warning.clone()); }
                    if truncated { self.note_poll_error("Nostr receive page is full; delivery may be incomplete"); }
                    let mut state = self.lock_state();
                    state.last_poll_unix = unix_now();
                    if warning.is_none() && !truncated && state
                        .last_error
                        .as_deref()
                        .map(|error| error.starts_with("fetch:") || error.starts_with("Nostr receive page is full"))
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
            drop(permit);
            std::thread::sleep(Duration::from_secs(self.config.poll_secs.max(1)));
        }
    }

    fn open_nostr_cursor(&self,spec:&TransportSpec)->Result<glaux_messenger::nostr::cursor::CursorStore,String> {
        let route=match spec {
            TransportSpec::NostrDirect{relay,..}=>format!("direct:{relay}"),
            TransportSpec::NostrI2p{relay,socks,..}=>format!("i2p:{relay}:{}",self.config.logical_proxy.as_deref().map(str::to_owned).unwrap_or_else(||socks.to_string())),
            _=>return Err("Nostr channel must be running".into()),
        };
        // Old experimental split queues cannot be silently orphaned.
        let old=self.config.data_dir.join("nostr-deferred");
        if old.exists() && std::fs::read_dir(&old).map_err(|_|"legacy queue cannot be read")?.next().is_some() {return Err("legacy deferred queue requires explicit migration".into());}
        // Serialize the baseline sentinel and registry creation across processes.
        let _baseline_lock={
            let file=std::fs::OpenOptions::new().read(true).write(true).create(true).open(self.config.data_dir.join("nostr-baseline.lock")).map_err(|_|"cursor baseline lock failed")?;
            let started=std::time::Instant::now();loop {match file.try_lock() {
                Ok(())=>break file,
                Err(std::fs::TryLockError::WouldBlock) if started.elapsed()<std::time::Duration::from_secs(3)=>std::thread::sleep(std::time::Duration::from_millis(20)),
                _=>return Err("cursor baseline lock failed".into()),
            }}
        };
        let root=self.config.data_dir.join("nostr-cursors");
        let sentinel=self.config.data_dir.join("nostr-cursor-baseline-v2");
        let existing=root.join("route-registry.enc").exists() || root.join("route-registry.initialized").exists();
        const PENDING:&[u8]=b"grinsight-cursor-v2:pending";
        const READY:&[u8]=b"grinsight-cursor-v2:ready";
        let pending=if sentinel.exists() {
            let metadata=std::fs::symlink_metadata(&sentinel).map_err(|_|"cursor baseline unreadable")?;
            if !metadata.file_type().is_file() || metadata.len()>64 {return Err("cursor baseline invalid".into());}
            let value=std::fs::read(&sentinel).map_err(|_|"cursor baseline unreadable")?;
            if value==PENDING {true} else if value==READY {false} else {return Err("cursor baseline invalid".into());}
        } else {
            if existing {return Err("cursor baseline migration required".into());}
            use std::io::Write;
            let mut file=std::fs::OpenOptions::new().write(true).create_new(true).open(&sentinel).map_err(|_|"cursor baseline initialization failed")?;
            file.write_all(PENDING).and_then(|_|file.sync_all()).map_err(|_|"cursor baseline write failed")?;
            #[cfg(unix)] std::fs::File::open(&self.config.data_dir).and_then(|f|f.sync_all()).map_err(|_|"cursor baseline directory sync failed")?;
            true
        };
        let registry=glaux_messenger::nostr::cursor::Registry::new(root,storage_key(&self.seed,&self.config.network),&self.address).map_err(|e|e.to_string())?.with_profile_lock(self.config.data_dir.join("nostr-cursor.lock"));
        if pending {registry.resume_empty_baseline().map_err(|e|e.to_string())?;}
        let store=registry.ensure_route(&route,false).map_err(|e|e.to_string())?;
        if pending {
            use std::io::Write;
            let tmp=self.config.data_dir.join(format!(".nostr-baseline-{}-{}.tmp",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_|"clock")?.as_nanos()));
            let mut f=std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|_|"cursor baseline commit failed")?;
            f.write_all(READY).and_then(|_|f.sync_all()).map_err(|_|"cursor baseline commit failed")?;drop(f);
            std::fs::rename(&tmp,&sentinel).map_err(|_|"cursor baseline commit failed")?;
            #[cfg(unix)] std::fs::File::open(&self.config.data_dir).and_then(|f|f.sync_all()).map_err(|_|"cursor baseline directory sync failed")?;
        }
        Ok(store)
    }
    #[cfg(test)] pub(crate) fn test_enable_nostr(&self) {
        let keys=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        *self.transport.lock().unwrap()=Some(TransportSpec::NostrDirect{relay:"wss://test.invalid".into(),keys,directory:ContactDirectory::default(),ttl:900,expiration_tag:true});
    }
    fn open_deferred_queue(&self)->Result<crate::deferred::Deferred,String> {
        let spec=self.transport.lock().map_err(|_|"transport state lock poisoned")?.clone().ok_or("Nostr channel must be running")?;
        Ok(crate::deferred::Deferred::from_store(self.open_nostr_cursor(&spec)?))
    }

    fn all_deferred_queues(&self)->Result<Vec<(String,crate::deferred::Deferred)>,String> {
        let root=self.config.data_dir.join("nostr-cursors");let sentinel=self.config.data_dir.join("nostr-cursor-baseline-v2");
        if !sentinel.exists() && !root.exists() {return Ok(Vec::new());}
        let metadata=std::fs::symlink_metadata(&sentinel).map_err(|_|"cursor baseline missing")?;
        if !metadata.file_type().is_file() || metadata.len()>64 || std::fs::read(&sentinel).map_err(|_|"cursor baseline unreadable")?!=b"grinsight-cursor-v2:ready" {return Err("cursor baseline invalid".into());}
        let registry=glaux_messenger::nostr::cursor::Registry::new(root,storage_key(&self.seed,&self.config.network),&self.address).map_err(|e|e.to_string())?.with_profile_lock(self.config.data_dir.join("nostr-cursor.lock"));
        Ok(registry.all_routes().map_err(|e|e.to_string())?.into_iter().map(|(route,store)|(route,crate::deferred::Deferred::from_store(store))).collect())
    }
    pub fn deferred_status(&self)->Result<(Vec<(String,u64,String)>,bool),String> {
        let mut out=Vec::new();for (route,queue) in self.all_deferred_queues()? {for i in queue.list()? {
            if out.len()==1000 {return Ok((out,true));}out.push((i.event_id,i.received_at,route.clone()));
        }}Ok((out,false))
    }
    /// Discard is bound to the exact authenticated route and explicitly confirmed.
    pub fn discard_deferred(&self,id:&str,route:&str,confirmed:bool)->Result<(),String> {
        if !confirmed {return Err("explicit confirmation required; saved event will be permanently deleted".into());}
        let queue=self.all_deferred_queues()?.into_iter().find(|(token,_)|token==route).map(|(_,q)|q).ok_or("unknown deferred route")?;queue.delete(id)
    }
    pub fn retry_deferred(&self,route:&str)->Result<(),String> {
        let queue=self.all_deferred_queues()?.into_iter().find(|(token,_)|token==route).map(|(_,q)|q).ok_or("unknown deferred route")?;
        let keys=crate::identity::nostr_keys_from_messaging_seed(&self.seed,&self.config.network)?;
        self.replay_deferred(&queue,&keys,unix_now())
    }
    /// Opaque authenticated quarantine metadata; never marks a payment received.
    pub fn quarantined_envelopes(&self)->Result<Vec<(String,String,String,bool,Option<String>)>,String> {
        Ok(self.raw_quarantine.list_status().map_err(|e|e.to_string())?.into_iter().map(|item|(item.id,item.digest,item.kind.to_owned(),item.corrupt,item.name_token)).collect())
    }
    pub fn export_quarantined_envelope(&self,id:&str,digest:&str)->Result<String,String> {
        self.raw_quarantine.recover_envelope_by_parts(id,digest).map_err(|e|e.to_string())
    }
    pub fn discard_quarantined_envelope(&self,id:&str,digest:&str,confirmed:bool,allow_corrupt:bool)->Result<(),String> {
        if !confirmed {return Err("explicit permanent deletion confirmation required".into());}
        self.raw_quarantine.delete_by_parts(id,digest,allow_corrupt).map_err(|e|e.to_string())
    }
    pub fn export_quarantined_invalid_envelope(&self,token:&str)->Result<String,String> {self.raw_quarantine.export_invalid_envelope(token).map_err(|e|e.to_string())}
    pub fn discard_quarantined_invalid_name(&self,token:&str,confirmed:bool)->Result<(),String> {
        if !confirmed{return Err("explicit permanent deletion confirmation required".into());}
        self.raw_quarantine.delete_invalid_name(token).map_err(|e|e.to_string())
    }
    pub fn cleanup_quarantine_temps(&self,confirmed:bool)->Result<usize,String> {
        if !confirmed{return Err("explicit cleanup confirmation required".into());}
        self.raw_quarantine.cleanup_abandoned_temps().map_err(|e|e.to_string())
    }
    fn replay_deferred(&self,deferred:&crate::deferred::Deferred,keys:&NostrKeys,now:u64)->Result<(),String> {
        self.replay_deferred_with(deferred,keys,now,|content|serde_json::from_str::<Envelope>(content).ok())
    }
    fn replay_deferred_with(&self,deferred:&crate::deferred::Deferred,keys:&NostrKeys,now:u64,decode:impl Fn(&str)->Option<Envelope>)->Result<(),String> {
        let result=deferred.process_all(|item| {
                let event=serde_json::from_str::<glaux_messenger::nostr::Event>(&item.event_json).map_err(|_|"nostr deferred invalid event".to_string())?;
                if event.id!=item.event_id || event.verify().is_err() {return Err("nostr deferred invalid signature".into());}
                let (_,rumor)=match keys.unwrap_event(&event){Ok(x)=>x,Err(_)=>return Ok(false)};
                let envelope=match decode(&rumor.content){Some(e)=>e,None=>return Ok(false)};
                if envelope.ttl==0 || envelope.ttl>glaux_messenger::MAX_TTL_SECS || envelope.created_at>now.saturating_add(300) || envelope.created_at.saturating_add(envelope.ttl)<=now {return Ok(false);}
                let opened=match envelope.open(&self.identity,now){Ok(o)=>o,Err(_)=>return Ok(false)};
                let peer=opened.sender.clone();
                let record=MessageRecord{id:opened.id.clone(),direction:Direction::Incoming,signature_verified:true,kind:opened.kind.clone(),created_at:opened.created_at,expires_at:local_history_expiry(&opened.kind,self.config.history_days),local_expiry_opt_in:self.config.history_days>0 && matches!(&opened.kind,MessageKind::Text{..})};
                let already=self.history.contains_record(&peer,&record).map_err(|e|format!("nostr deferred history: {e}"))?;
                if !already {self.history.record(&peer,&record).map_err(|e|format!("nostr deferred history: {e}"))?;self.push_message(MessageView::from_record(&peer,record,0));}
                #[cfg(test)]
                if std::env::var_os("GS_TEST_DEFERRED_EXIT_AFTER_HISTORY").is_some() {std::process::exit(91);}
                Ok(true)
        });
        let errors=result?;if !errors.is_empty(){return Err(errors.join("; "));}
        if !deferred.list()?.is_empty(){self.note_poll_error("Nostr events are preserved but cannot yet be processed; storage is limited");}
        Ok(())
    }

    fn handle_batch(
        &self,
        messenger: &Messenger<ActiveTransport>,
        batch: glaux_messenger::ReceiveBatch,
    ) {
        let mut ack_ids = batch.duplicates;
        for opened in batch.opened {
            let peer = opened.sender.clone();
            let record = MessageRecord {
                id: opened.id.clone(),
                direction: Direction::Incoming,
                signature_verified: true,
                kind: opened.kind.clone(),
                created_at: opened.created_at,
                expires_at: local_history_expiry(&opened.kind,self.config.history_days),
                local_expiry_opt_in: self.config.history_days>0 && matches!(&opened.kind,MessageKind::Text{..}),
            };
            let already = match self.history.contains_record(&peer,&record) {
                Ok(found)=>found,
                Err(error)=>{self.note_poll_error(format!("history replay check: {error}"));continue;}
            };
            if !already {
                if let Err(error) = self.history.record(&peer, &record) {
                    self.note_poll_error(format!(
                        "history write for {} failed: {error}",
                        opened.id
                    ));
                    continue; // Not acked: delivery is retried on the next poll.
                }
                let view = MessageView::from_record(&peer, record, 0);
                self.push_message(view);
            }
            ack_ids.push(opened.transport_token.unwrap_or(opened.id));
        }
        if batch.omitted_malformed>0 || batch.unknown_formats>0 {
            self.note_poll_error("gateway page has unprocessed or unknown items; delivery may be incomplete");
        }
        for item in batch.malformed {
            match self.raw_quarantine.save(&item.id,&item.payload) {
                Ok(saved) => if let Err(error)=messenger.reject_saved_raw(&self.identity,&self.raw_quarantine,&saved) {
                    self.note_poll_error(format!("raw quarantine saved; reject failed: {error}"));
                },
                Err(error) => self.note_poll_error(format!("raw quarantine failed; no reject sent: {error}")),
            }
        }
        for failed in batch.failed {
            let mut error = format!("rejected envelope {}: {}; no ACK sent", failed.id, failed.error);
            if failed.quarantine_allowed {
                if let (Some(token),Some(envelope))=(&failed.transport_token,&failed.encrypted_envelope) {
                    if let Ok(digest)=glaux_messenger::ack::envelope_digest(envelope) {
                        if token==&format!("{}:{digest}",failed.id) {
                            if let Ok(raw)=serde_json::to_string(envelope) {
                                match self.raw_quarantine.save_envelope(&failed.id,&raw) {
                                    Ok(saved)=>match self.raw_quarantine.with_saved(&saved,||messenger.ack_signed(&self.identity,&[token.clone()]).map(|_|())) {
                                        Ok(())=>error=format!("rejected envelope {}; encrypted copy preserved",failed.id),
                                        Err(e)=>error=format!("quarantine saved; no ACK: {e}"),
                                    },
                                    Err(e)=>error=format!("quarantine failed; no ACK: {e}"),
                                }
                            }
                        }
                    }
                }
            }
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

fn load_history(history: &History) -> Result<Vec<MessageView>, String> {
    let mut out = Vec::new();
    let conversations = history.conversations().map_err(|e| format!("Cannot load message history: {e}"))?;
    for peer in conversations {
        let records = history.list(&peer, 2_000).map_err(|e| format!("Cannot load message history for {peer}: {e}"))?;
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
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn late_and_same_second_messages_are_unread_after_restart() {
        use super::*;
        let dir=temp_dir("late-same-second"); let seed=[21u8;32];
        let peer=glaux_messenger::Identity::from_seed([22;32],"tgrin").unwrap().address().clone();
        let record=|id:&str,created_at|MessageRecord{id:id.into(),direction:Direction::Incoming,signature_verified:true,kind:MessageKind::Text{text:"x".into()},created_at,expires_at:None,local_expiry_opt_in:false};
        {
            let svc=WalletService::open(relay_mode(dir.clone()),Zeroizing::new(seed)).unwrap();
            let a=record("00000000-0000-4000-8000-000000000001",100);
            svc.history.record(&peer,&a).unwrap();svc.push_message(MessageView::from_record(&peer,a,0));
            svc.mark_read(&peer.to_string()).unwrap();assert_eq!(svc.unread().1,0);
            for (id,ts) in [("00000000-0000-4000-8000-000000000002",100),("00000000-0000-4000-8000-000000000003",99)] {
                let r=record(id,ts);svc.history.record(&peer,&r).unwrap();svc.push_message(MessageView::from_record(&peer,r,0));
            }
            assert_eq!(svc.unread().1,2);
        }
        let reopened=WalletService::open(relay_mode(dir.clone()),Zeroizing::new(seed)).unwrap();
        assert_eq!(reopened.unread().1,2);drop(reopened);std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn corrupt_history_prevents_start_without_altering_read_state() {
        use super::*;
        let dir = temp_dir("corrupt-history-read-marks");
        let seed = [11u8; 32];
        let peer = glaux_messenger::Identity::from_seed([9;32], "tgrin").unwrap().address().clone();
        let id = "00000000-0000-4000-8000-000000000001";
        let record = MessageRecord { id: id.into(), direction: Direction::Incoming, signature_verified: true,
            kind: MessageKind::Text { text: "hello".into() }, created_at: 1, expires_at: None, local_expiry_opt_in: false };
        {
            let svc = WalletService::open(relay_mode(dir.clone()), Zeroizing::new(seed)).unwrap();
            svc.history.record(&peer, &record).unwrap();
            svc.read_state.mark_read(&peer.to_string(), &[id.into()]).unwrap();
        }
        let marks = std::fs::read(dir.join("state/read_state.enc")).unwrap();
        let path = dir.join("history").join(peer.to_string()).join(format!("{id}.msg"));
        std::fs::write(&path, b"corrupt").unwrap();
        let error = match WalletService::open(relay_mode(dir.clone()), Zeroizing::new(seed)) { Ok(_) => panic!("corrupt history accepted"), Err(e) => e };
        assert!(error.contains("Cannot load message history"), "{error}");
        assert_eq!(std::fs::read(dir.join("state/read_state.enc")).unwrap(), marks);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn catalogue_route_is_explicit_and_rejects_changes() {
        use super::*;
        let dir=std::env::temp_dir().join(format!("gs-catalog-route-{}",std::process::id()));
        let cfg=ServiceConfig { data_dir:dir, mode:NetworkMode::NostrDirect {relay:"wss://relay.example".into(),consent:true,expiration_tag:false}, ..Default::default() };
        let service=WalletService::open(cfg,Zeroizing::new([8;32])).unwrap();
        let route=service.catalogue_route().unwrap();
        assert_eq!(route,"a17d971cda8df9b709f186a50812bc7831a508eaa3598e966ab9521a1563594f");
        assert!(service.require_catalogue_route(&"0".repeat(64)).is_err());
        assert!(service.require_catalogue_route(&route).is_ok());
        let address = service.identity.address().to_string();
        let draft = service.catalogue_draft("viewer", &address, 1, false).unwrap();
        assert_eq!(draft["search_phrase"].as_str().unwrap(), glaux_messenger::nostr::catalog::public_search_phrase(&address).unwrap());
        assert_ne!(draft["search_phrase"], draft["comparison_code"]);
    }
    #[test]
    fn i2p_session_id_is_random_and_valid() {
        let first = super::new_i2p_session_id().unwrap();
        let second = super::new_i2p_session_id().unwrap();
        assert_ne!(first, second);
        assert_eq!(first.len(), 67);
        assert!(first.starts_with("gs-"));
        assert!(first[3..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }
    use super::*;

    #[test] #[ignore = "subprocess for deferred crash test"]
    fn deferred_replay_crash_child() {
        let dir=PathBuf::from(std::env::var_os("GS_TEST_DEFERRED_DIR").unwrap());
        let svc=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),..Default::default()},Zeroizing::new([9;32])).unwrap();
        let receiver=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        let queue=crate::deferred::Deferred::open(dir.join("deferred-test"),dir.join("deferred-test.lock"),[4;32]).unwrap();
        svc.replay_deferred(&queue,&receiver,unix_now()).unwrap();panic!("crash hook not reached");
    }
    #[test]
    fn deferred_process_crash_after_history_before_delete_replays_once() {
        let dir=std::env::temp_dir().join(format!("gs-deferred-kill-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let svc=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),..Default::default()},Zeroizing::new([9;32])).unwrap();
        let receiver=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        let sender=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let alice=Identity::from_seed([11;32],"tgrin").unwrap();let now=unix_now();
        let envelope=Envelope::seal(&alice,svc.identity.address(),MessageKind::Text{text:"crash replay".into()},900,now).unwrap();
        let event=sender.wrap_event(&receiver.public(),serde_json::to_string(&envelope).unwrap(),now).unwrap();
        let queue=crate::deferred::Deferred::open(dir.join("deferred-test"),dir.join("deferred-test.lock"),[4;32]).unwrap();
        queue.save(&event.id,&serde_json::to_string(&event).unwrap(),now).unwrap();drop(queue);drop(svc);
        let status=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","service::tests::deferred_replay_crash_child","--ignored"]).env("GS_TEST_DEFERRED_DIR",&dir).env("GS_TEST_DEFERRED_EXIT_AFTER_HISTORY","1").status().unwrap();
        assert_eq!(status.code(),Some(91));
        let svc=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),..Default::default()},Zeroizing::new([9;32])).unwrap();
        let queue=crate::deferred::Deferred::open(dir.join("deferred-test"),dir.join("deferred-test.lock"),[4;32]).unwrap();
        assert_eq!(queue.list().unwrap().len(),1);svc.replay_deferred(&queue,&receiver,unix_now()).unwrap();
        assert!(queue.list().unwrap().is_empty());assert_eq!(svc.history.list(alice.address(),10).unwrap().len(),1);
        drop(queue);drop(svc);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn deferred_status_exposes_more_and_allows_progress_past_thousand() {
        let dir=std::env::temp_dir().join(format!("gs-cursor-page-{}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let svc=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),..Default::default()},Zeroizing::new([9;32])).unwrap();
        let keys=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        for route in 0..4 {
            let spec=TransportSpec::NostrDirect{relay:format!("wss://test-{route}.invalid"),keys:keys.clone(),directory:ContactDirectory::default(),ttl:900,expiration_tag:true};
            let store=svc.open_nostr_cursor(&spec).unwrap();
            store.update(|s| {for i in 0..if route==3 {251} else {250} {s.deferred.push(glaux_messenger::nostr::cursor::DeferredEvent{id:format!("{:064x}",route*1000+i),json:"{}".into(),received_at:0});}Ok(())}).unwrap();
        }
        let (items,more)=svc.deferred_status().unwrap();assert_eq!(items.len(),1000);assert!(more);
        svc.discard_deferred(&items[0].0,&items[0].2,true).unwrap();let (items,more)=svc.deferred_status().unwrap();assert_eq!(items.len(),1000);assert!(!more);
        drop(svc);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn deferred_routes_survive_switch_and_discard_is_route_bound() {
        let dir=std::env::temp_dir().join(format!("gs-cursor-routes-{}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let svc=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),..Default::default()},Zeroizing::new([9;32])).unwrap();
        let receiver=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        let sender=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let event=sender.wrap_event(&receiver.public(),"synthetic".into(),123).unwrap();
        svc.test_enable_nostr();let first=svc.open_deferred_queue().unwrap();first.save(&event.id,&serde_json::to_string(&event).unwrap(),123).unwrap();
        let first_route=svc.deferred_status().unwrap().0[0].2.clone();
        *svc.transport.lock().unwrap()=Some(TransportSpec::NostrDirect{relay:"wss://second.invalid".into(),keys:receiver.clone(),directory:ContactDirectory::default(),ttl:900,expiration_tag:true});
        let second=svc.open_deferred_queue().unwrap();second.save(&event.id,&serde_json::to_string(&event).unwrap(),123).unwrap();
        let all=svc.deferred_status().unwrap().0;assert_eq!(all.len(),2);assert_ne!(all[0].2,all[1].2);
        svc.discard_deferred(&event.id,&first_route,true).unwrap();let remain=svc.deferred_status().unwrap().0;assert_eq!(remain.len(),1);assert_ne!(remain[0].2,first_route);
        drop(first);drop(second);drop(svc);
        let reopened=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),..Default::default()},Zeroizing::new([9;32])).unwrap();
        assert_eq!(reopened.deferred_status().unwrap().0.len(),1);drop(reopened);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn retry_does_not_report_success_when_state_is_corrupt() {
        let dir=std::env::temp_dir().join(format!("gs-cursor-corrupt-{}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let svc=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),..Default::default()},Zeroizing::new([9;32])).unwrap();svc.test_enable_nostr();
        let queue=svc.open_deferred_queue().unwrap();let a=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let b=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap();let e=a.wrap_event(&b.public(),"synthetic".into(),123).unwrap();
        queue.save(&e.id,&serde_json::to_string(&e).unwrap(),123).unwrap();let route=svc.deferred_status().unwrap().0[0].2.clone();
        let path=dir.join("nostr-cursors").join(format!("route-{route}.enc"));std::fs::write(path,b"damaged").unwrap();
        assert!(svc.retry_deferred(&route).is_err());drop(queue);drop(svc);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn interrupted_empty_first_initialization_resumes() {
        let dir=std::env::temp_dir().join(format!("gs-cursor-resume-{}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let svc=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),..Default::default()},Zeroizing::new([9;32])).unwrap();
        svc.test_enable_nostr();std::fs::write(dir.join("nostr-cursor-baseline-v2"),b"grinsight-cursor-v2:pending").unwrap();
        let queue=svc.open_deferred_queue().unwrap();assert!(queue.list().unwrap().is_empty());
        assert_eq!(std::fs::read(dir.join("nostr-cursor-baseline-v2")).unwrap(),b"grinsight-cursor-v2:ready");
        drop(queue);drop(svc);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn missing_registry_after_initialization_never_recreates_baseline() {
        let dir=std::env::temp_dir().join(format!("gs-cursor-sentinel-{}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let svc=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),..Default::default()},Zeroizing::new([9;32])).unwrap();
        svc.test_enable_nostr();let queue=svc.open_deferred_queue().unwrap();drop(queue);
        std::fs::remove_file(dir.join("nostr-cursors").join("route-registry.enc")).unwrap();
        std::fs::remove_file(dir.join("nostr-cursors").join("route-registry.initialized")).unwrap();
        assert!(svc.open_deferred_queue().is_err());
        assert!(!dir.join("nostr-cursors").join("route-registry.enc").exists());
        drop(svc);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn deferred_replay_authenticates_persists_and_removes_only_after_history() {
        let dir=std::env::temp_dir().join(format!("gs-deferred-replay-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let svc=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),..Default::default()},Zeroizing::new([9;32])).unwrap();
        let receiver=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000002").unwrap();
        let sender=NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
        let alice=Identity::from_seed([11;32],"tgrin").unwrap();let now=unix_now();
        let envelope=Envelope::seal(&alice,svc.identity.address(),MessageKind::Text{text:"replayed".into()},900,now).unwrap();
        let event=sender.wrap_event(&receiver.public(),serde_json::to_string(&envelope).unwrap(),now).unwrap();
        svc.test_enable_nostr();
        let queue=svc.open_deferred_queue().unwrap();
        queue.save(&event.id,&serde_json::to_string(&event).unwrap(),now).unwrap();
        // Simulate an old decoder unable to parse a future format, then an
        // upgraded decoder that understands exactly the same signed event.
        svc.replay_deferred_with(&queue,&receiver,now,|_|None).unwrap();assert_eq!(queue.list().unwrap().len(),1);
        svc.replay_deferred_with(&queue,&receiver,now,|s|serde_json::from_str::<Envelope>(s).ok()).unwrap();assert!(queue.list().unwrap().is_empty());
        assert_eq!(svc.history.list(alice.address(),10).unwrap().len(),1);
        queue.save(&event.id,&serde_json::to_string(&event).unwrap(),now).unwrap();svc.replay_deferred(&queue,&receiver,now).unwrap();
        assert!(queue.list().unwrap().is_empty());assert_eq!(svc.history.list(alice.address(),10).unwrap().len(),1);
        queue.save(&event.id,&serde_json::to_string(&event).unwrap(),now).unwrap();svc.replay_deferred(&queue,&receiver,now+900).unwrap();
        assert_eq!(queue.list().unwrap().len(),1);assert_eq!(svc.deferred_status().unwrap().0.len(),1);
        let token=svc.deferred_status().unwrap().0[0].2.clone();
        assert!(svc.discard_deferred(&event.id,&token,false).is_err());assert_eq!(queue.list().unwrap().len(),1);
        svc.discard_deferred(&event.id,&token,true).unwrap();assert!(svc.deferred_status().unwrap().0.is_empty());
        drop(queue);drop(svc);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn new_nostr_delivery_expires_at_15_minutes_for_text_and_payments() {
        let slate=MessageKind::Slatepack{armor:"synthetic".into(),encrypted:true};
        let text=MessageKind::Text{text:"test".into()};
        assert_eq!(delivery_ttl(None,13*3600,true),900);
        assert_eq!(delivery_ttl(Some(13*3600),13*3600,true),900);
        assert_eq!(delivery_ttl(None,13*3600,false),13*3600);
        let a=Identity::from_seed([7;32],"tgrin").unwrap();let b=Identity::from_seed([9;32],"tgrin").unwrap();let now=1_760_000_000;
        for kind in [slate.clone(),text.clone()] {
            let envelope=Envelope::seal(&a,b.address(),kind,delivery_ttl(None,13*3600,true),now).unwrap();
            assert!(envelope.open(&b,now+899).is_ok());
            // Envelope v2 itself uses an inclusive boundary; Nostr fetch
            // independently enforces expiry at the exact deadline.
            assert!(envelope.open(&b,now+901).is_err());
        }
        assert_eq!(local_history_expiry(&slate,30),None);
        let now=unix_now(); assert!(local_history_expiry(&text,30).unwrap()>=now+30*86400);
    }

    #[test] #[ignore = "requires separately built v1 relay"]
    fn v2_client_against_actual_v1_gateway_keeps_message_on_unsupported_ack() {
        use std::process::{Command,Stdio};
        #[cfg(windows)] use std::os::windows::process::CommandExt;
        struct Guard(std::process::Child);impl Drop for Guard {fn drop(&mut self){let _=self.0.kill();let _=self.0.wait();}}
        let listener=std::net::TcpListener::bind("127.0.0.1:0").unwrap();let addr=listener.local_addr().unwrap();drop(listener);
        let dir=temp_dir("actual-v1-mixed");std::fs::create_dir_all(&dir).unwrap();let exe=std::env::var_os("GS_TEST_V1_RELAY").expect("v1 relay");
        let mut cmd=Command::new(exe);cmd.arg("--listen").arg(addr.to_string()).arg("--store").arg(&dir).arg("--allow-unsigned-fetch").stdout(Stdio::null()).stderr(Stdio::null());
        #[cfg(windows)] cmd.creation_flags(0x08000000);
        let child=Guard(cmd.spawn().unwrap());let deadline=std::time::Instant::now()+Duration::from_secs(10);
        while std::net::TcpStream::connect(addr).is_err(){assert!(std::time::Instant::now()<deadline);std::thread::sleep(Duration::from_millis(50));}
        let alice=Identity::from_seed([7;32],"tgrin").unwrap();let bob=Identity::from_seed([9;32],"tgrin").unwrap();
        let envelope=Envelope::seal_now(&alice,bob.address(),MessageKind::Text{text:"legacy gateway".into()},600).unwrap();let client=GatewayTransport::new(&format!("http://{addr}")).unwrap();
        client.deliver(&envelope).unwrap();let page=client.fetch_signed_tagged(&bob,unix_now(),10).unwrap();assert_eq!(page.len(),1);let token=page[0].1.clone().unwrap();
        assert!(client.ack_signed(&bob,&[token]).is_err());let page=client.fetch_signed_tagged(&bob,unix_now(),10).unwrap();assert_eq!(page.len(),1);assert_eq!(page[0].0.id,envelope.id);
        drop(child);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn mixed_gateway_service_preserves_then_rejects_raw_and_keeps_valid() {
        let gateway=Gateway::start(GatewayConfig {require_fetch_proof:true,require_signed_ack:true,require_v2_ack:true,..GatewayConfig::default()}).unwrap();
        assert!(wait_ready(&gateway,Duration::from_secs(3)));
        let dir=temp_dir("raw-service");let service=WalletService::open(relay_mode(dir.clone()),Zeroizing::new([9u8;32])).unwrap();
        let client=GatewayTransport::new(&gateway.url()).unwrap();
        let bad_id="11111111-2222-4333-8444-555555555555";
        let raw=serde_json::json!({"id":bad_id,"to":service.address,"payload":"{broken","ttl_secs":600});
        let http=glaux_messenger::transport::TcpConnector::new();
        let (code,_)=http.request("POST",&format!("{}/glaux/v1/msg",gateway.url()),raw.to_string().as_bytes()).unwrap();assert_eq!(code,200);
        let alice=Identity::from_seed([7;32],"tgrin").unwrap();
        let good=Envelope::seal_now(&alice,service.identity.address(),MessageKind::Text{text:"synthetic".into()},600).unwrap();
        client.deliver(&good).unwrap();
        let messenger=Messenger::new(ActiveTransport::Relay(client));
        let batch=messenger.fetch_open(&service.identity,100).unwrap();assert_eq!(batch.malformed.len(),1);assert_eq!(batch.opened.len(),1);
        service.handle_batch(&messenger,batch);
        let page=messenger.fetch_open(&service.identity,100).unwrap();assert!(page.malformed.is_empty());assert!(page.opened.is_empty());
        assert_eq!(service.history.list(alice.address(),100).unwrap().len(),1);
        let count=std::fs::read_dir(dir.join("raw-quarantine")).unwrap().filter(|e|e.as_ref().unwrap().path().extension().and_then(|s|s.to_str())==Some("raw")).count();assert_eq!(count,1);
        drop(gateway);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn corrupt_signed_envelope_is_saved_before_exact_ack_and_recoverable() {
        let gateway=Gateway::start(GatewayConfig {require_fetch_proof:true,require_signed_ack:true,require_v2_ack:true,..GatewayConfig::default()}).unwrap();
        assert!(wait_ready(&gateway,Duration::from_secs(3)));let dir=temp_dir("bad-signature-no-ack");
        let service=WalletService::open(relay_mode(dir.clone()),Zeroizing::new([9u8;32])).unwrap();let client=GatewayTransport::new(&gateway.url()).unwrap();
        let alice=Identity::from_seed([7;32],"tgrin").unwrap();
        let good=Envelope::seal_now(&alice,service.identity.address(),MessageKind::Text{text:"valid".into()},600).unwrap();
        let mut bad=Envelope::seal_now(&alice,service.identity.address(),MessageKind::Text{text:"corrupt".into()},600).unwrap();bad.ciphertext.push(1);bad.pow_bits=0;
        let mut bad_pow=Envelope::seal_now(&alice,service.identity.address(),MessageKind::Text{text:"bad-pow".into()},600).unwrap();bad_pow.ciphertext.push(1);
        client.deliver(&bad).unwrap();client.deliver(&bad_pow).unwrap();client.deliver(&good).unwrap();let messenger=Messenger::new(ActiveTransport::Relay(client));
        let batch=messenger.fetch_open(&service.identity,100).unwrap();assert_eq!(batch.opened.len(),1);assert_eq!(batch.failed.len(),2);
        service.handle_batch(&messenger,batch);let restarted=Messenger::new(ActiveTransport::Relay(GatewayTransport::new(&gateway.url()).unwrap()));
        let batch=restarted.fetch_open(&service.identity,100).unwrap();assert!(batch.opened.is_empty());assert!(batch.failed.is_empty(), "status: {:?}",service.status().last_error);
        let raw=serde_json::to_string(&bad).unwrap();let saved=service.raw_quarantine.save_envelope(&bad.id,&raw).unwrap();
        assert_eq!(service.raw_quarantine.recover_saved(&saved).unwrap(),raw);
        let list=service.quarantined_envelopes().unwrap();assert_eq!(list.len(),2);
        assert_eq!(service.export_quarantined_envelope(&bad.id,saved.digest()).unwrap(),raw);
        assert!(service.export_quarantined_envelope(&bad.id,&"00".repeat(32)).is_err());
        assert_eq!(service.history.list(alice.address(),100).unwrap().len(),1);drop(restarted);drop(service);drop(gateway);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn full_quarantine_never_acks_failed_signed_envelope() {
        let gateway=Gateway::start(GatewayConfig {require_fetch_proof:true,require_signed_ack:true,require_v2_ack:true,..GatewayConfig::default()}).unwrap();
        assert!(wait_ready(&gateway,Duration::from_secs(3)));let dir=temp_dir("bad-signature-quota");let service=WalletService::open(relay_mode(dir.clone()),Zeroizing::new([9u8;32])).unwrap();
        for n in 0..1000 {std::fs::write(dir.join("raw-quarantine").join(format!("{n}.tmp")),b"x").unwrap();}
        let client=GatewayTransport::new(&gateway.url()).unwrap();let alice=Identity::from_seed([7;32],"tgrin").unwrap();
        let mut bad=Envelope::seal_now(&alice,service.identity.address(),MessageKind::Text{text:"corrupt".into()},600).unwrap();bad.ciphertext.push(1);bad.pow_bits=0;client.deliver(&bad).unwrap();
        let messenger=Messenger::new(ActiveTransport::Relay(client));let batch=messenger.fetch_open(&service.identity,100).unwrap();assert_eq!(batch.failed.len(),1);service.handle_batch(&messenger,batch);
        assert!(service.status().last_error.unwrap().contains("no ACK"));assert_eq!(messenger.fetch_open(&service.identity,100).unwrap().failed.len(),1);
        drop(service);drop(gateway);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn full_raw_quarantine_never_rejects_poison() {
        let gateway=Gateway::start(GatewayConfig {require_fetch_proof:true,require_signed_ack:true,require_v2_ack:true,..GatewayConfig::default()}).unwrap();
        assert!(wait_ready(&gateway,Duration::from_secs(3)));
        let dir=temp_dir("raw-full");let service=WalletService::open(relay_mode(dir.clone()),Zeroizing::new([9u8;32])).unwrap();
        for n in 0..1000 {std::fs::write(dir.join("raw-quarantine").join(format!("{n}.tmp")),b"x").unwrap();}
        let bad_id="11111111-2222-4333-8444-555555555555";
        let raw=serde_json::json!({"id":bad_id,"to":service.address,"payload":"{broken","ttl_secs":600});
        let http=glaux_messenger::transport::TcpConnector::new();let (code,_)=http.request("POST",&format!("{}/glaux/v1/msg",gateway.url()),raw.to_string().as_bytes()).unwrap();assert_eq!(code,200);
        let messenger=Messenger::new(ActiveTransport::Relay(GatewayTransport::new(&gateway.url()).unwrap()));
        let batch=messenger.fetch_open(&service.identity,100).unwrap();assert_eq!(batch.malformed.len(),1);service.handle_batch(&messenger,batch);
        assert!(service.status().last_error.unwrap().contains("no reject sent"));
        assert_eq!(messenger.fetch_open(&service.identity,100).unwrap().malformed.len(),1);
        drop(gateway);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_text_is_verified_before_a_trusted_view_exists() {
        let alice = glaux_messenger::Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let bob = glaux_messenger::Identity::from_seed([9u8; 32], "tgrin").unwrap();
        let now = 1_760_000_000;
        let envelope = glaux_messenger::Envelope::seal(&alice, bob.address(), MessageKind::Text { text: "hello".into() }, 600, now).unwrap();
        let opened = envelope.open(&bob, now + 1).unwrap();
        let view = MessageView::from_opened(opened, 1);
        assert_eq!(view.peer, alice.address().to_string());
        assert_eq!(view.text.as_deref(), Some("hello"));
        assert!(view.verified);
        let mut tampered = envelope;
        tampered.ciphertext[0] ^= 1;
        assert!(tampered.open(&bob, now + 1).is_err());
    }

    #[test]
    fn history_trust_is_explicit_and_incoming_only() {
        let peer = glaux_messenger::Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let legacy = serde_json::json!({"id":"old", "direction":"incoming", "kind":{"type":"text", "text":"hello"}, "created_at":1});
        let old: MessageRecord = serde_json::from_value(legacy.clone()).unwrap();
        assert!(!MessageView::from_record(peer.address(), old, 1).verified);
        let mut new = legacy.clone();
        new["signature_verified"] = serde_json::json!(true);
        let valid: MessageRecord = serde_json::from_value(new.clone()).unwrap();
        assert!(MessageView::from_record(peer.address(), valid, 2).verified);
        new["direction"] = serde_json::json!("outgoing");
        let outgoing: MessageRecord = serde_json::from_value(new).unwrap();
        assert!(!MessageView::from_record(peer.address(), outgoing, 3).verified);
    }

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

    #[test]
    fn shutdown_wait_times_out_without_claiming_worker_stopped() {
        let svc = WalletService::open(relay_mode(temp_dir("drain-test")), Zeroizing::new([9u8; 32])).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        *svc.network_thread.lock().unwrap() = Some(std::thread::spawn(move || { rx.recv().unwrap(); }));
        assert!(svc.shutdown_and_wait(Duration::from_millis(5)).is_err());
        assert!(svc.network_thread.lock().unwrap().is_some());
        tx.send(()).unwrap();
        assert!(svc.shutdown_and_wait(Duration::from_secs(1)).is_ok());
        assert!(svc.network_thread.lock().unwrap().is_none());
    }

    fn relay_mode(dir: PathBuf) -> ServiceConfig {
        ServiceConfig {
            data_dir: dir,
            network: "tgrin".into(),
            mode: NetworkMode::Relay {
                url: "http://127.0.0.1:9".into(),
                plain: true,
            },
            logical_proxy: None,
            poll_secs: 1,
            fetch_limit: 20,
            ttl_secs: 600,
            history_days: 0,
            tor_state: None,
            bridge_line: None,
            bridge_binary: None,
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn thousand_real_history_events_use_one_full_scan() {
        use std::sync::atomic::Ordering;
        let dir=temp_dir("payment-events-1000");let svc=WalletService::open(relay_mode(dir.clone()),Zeroizing::new([11;32])).unwrap();svc.initialize_payment_checkpoint().unwrap();
        let peers:Vec<_>=(0..4).map(|n|glaux_messenger::Identity::from_seed([50+n;32],"tgrin").unwrap().address().clone()).collect();
        let mut scan=svc.begin_payment_scan().unwrap();let scans=svc.history.payment_full_scans.load(Ordering::Relaxed);let mut watch=svc.payment_watch().unwrap();let mut since=0;let start=std::time::Instant::now();
        for n in 0..1000u64 {
            let peer=&peers[n as usize%peers.len()];
            let record=MessageRecord{id:format!("00000000-0000-4000-8000-{n:012}"),direction:Direction::Incoming,signature_verified:true,kind:MessageKind::Slatepack{armor:format!("synthetic-{n}"),encrypted:true},created_at:n,expires_at:None,local_expiry_opt_in:false};
            svc.history.record(peer,&record).unwrap();svc.push_message(MessageView::from_record(peer,record,0));
            let events=svc.events(since,Duration::ZERO);let after=svc.payment_watch().unwrap();let items=incremental_payment_events(&events,since,&watch,&after).unwrap();assert_eq!(items.len(),1);
            let candidate=svc.payment_event_candidate(&scan,&items[0].peer,&items[0].id).unwrap().unwrap();
            // Simulated handler outcome; real handler crash path is tested by daemon test.
            svc.mark_payment_processed_after_durable_handler(&mut scan,&candidate.peer,&candidate.id).unwrap();
            since=events.next;watch=svc.payment_watch().unwrap();
        }
        eprintln!("REAL_HISTORY_EVENTS_1000_MS={}",start.elapsed().as_millis());
        assert_eq!(svc.history.payment_full_scans.load(Ordering::Relaxed),scans,"incremental path must not reopen full scan");
        let mut reopened=svc.begin_payment_scan().unwrap();let mut pending=0;loop {let (page,done)=svc.next_payment_scan(&mut reopened,100).unwrap();pending+=page.len();if done{break;}}assert_eq!(pending,0);
        let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_review_api_is_bounded_and_missing_file_is_error() {
        let dir=temp_dir("payment-review-api");let svc=WalletService::open(relay_mode(dir.clone()),Zeroizing::new([11;32])).unwrap();
        let peer=glaux_messenger::Identity::from_seed([9;32],"tgrin").unwrap().address().clone();
        for n in 1..=3 { let record=MessageRecord{id:format!("00000000-0000-4000-8000-{n:012}"),direction:Direction::Incoming,signature_verified:true,kind:MessageKind::Slatepack{armor:format!("old-{n}"),encrypted:true},created_at:n,expires_at:None,local_expiry_opt_in:false};svc.history.record(&peer,&record).unwrap(); }
        svc.initialize_payment_checkpoint().unwrap();
        let (a,next,more)=svc.recovery_page(0,2).unwrap();assert_eq!((a.len(),next,more),(2,2,true));
        let (b,next,more)=svc.recovery_page(next,2).unwrap();assert_eq!((b.len(),next,more),(1,3,false));
        let path=dir.join("history").join(peer.to_string()).join(format!("{}.msg",b[0].id));std::fs::remove_file(path).unwrap();
        assert!(svc.recovery_page(2,1).is_err());let _=std::fs::remove_dir_all(dir);
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

#[cfg(test)]
mod nostr_i2p_mode_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use serde_json::{json, Value};
    use tungstenite::{accept, Message};

    #[test]
    fn direct_nostr_requires_consent_and_tls() {
        let root=std::env::temp_dir().join(format!("gs-nostr-consent-{}-{}",std::process::id(),unix_now()));
        let cfg=|relay:&str,consent:bool| ServiceConfig { data_dir:root.clone(), network:"tgrin".into(),
            mode:NetworkMode::NostrDirect {relay:relay.into(),consent,expiration_tag:false}, ..ServiceConfig::default() };
        let no_consent=WalletService::open(cfg("wss://relay.example.com",false),Zeroizing::new([11;32])).unwrap();
        assert!(no_consent.run_network().unwrap_err().contains("consent"));
        let no_tls=WalletService::open(cfg("ws://localhost:1234",true),Zeroizing::new([11;32])).unwrap();
        assert!(no_tls.run_network().unwrap_err().contains("wss"));
    }

    #[test] #[ignore = "requires separately built synthetic helper and grinsight-tor"]
    fn two_real_daemons_exchange_via_local_test_relay() {
        use std::process::{Child,Command,Stdio};
        #[cfg(windows)] use std::os::windows::process::CommandExt;
        struct ChildGuard(Child);
        impl Drop for ChildGuard {fn drop(&mut self){let _=self.0.kill();let _=self.0.wait();}}
        fn http(port:u16,token:&str,method:&str,path:&str,body:Value)->Value {
            let bytes=if method=="GET" {Vec::new()} else {serde_json::to_vec(&body).unwrap()};
            let mut stream=TcpStream::connect(("127.0.0.1",port)).unwrap();
            stream.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
            write!(stream,"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",bytes.len()).unwrap();
            stream.write_all(&bytes).unwrap();let mut reply=String::new();stream.read_to_string(&mut reply).unwrap();
            let (head,data)=reply.split_once("\r\n\r\n").unwrap();assert!(head.starts_with("HTTP/1.1 200"),"daemon {method} {path} returned {head}: {data}");serde_json::from_str(data).unwrap()
        }
        let daemon=std::env::var_os("GS_TEST_REAL_DAEMON").expect("daemon path");
        let helper=std::env::var_os("GS_TEST_REAL_HELPER").expect("synthetic helper path");
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();listener.set_nonblocking(true).unwrap();let proxy=listener.local_addr().unwrap();
        let events=Arc::new(Mutex::new(Vec::new()));let stop=Arc::new(AtomicBool::new(false));let drop_ack=Arc::new(AtomicBool::new(false));
        let flag=stop.clone();let stored=events.clone();let failure=drop_ack.clone();
        let worker=std::thread::spawn(move ||while !flag.load(Ordering::Relaxed) {match listener.accept(){Ok((stream,_))=>{let e=stored.clone();let f=failure.clone();std::thread::spawn(move||serve(stream,e,f,Arc::new(AtomicBool::new(false))));},Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(10)),Err(_)=>break}});
        let root=std::env::temp_dir().join(format!("gs-real-daemons-{}-{}",std::process::id(),unix_now()));std::fs::create_dir_all(&root).unwrap();
        let start=|role:&str| {
            let dir=root.join(role);std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("settings.json"),json!({"messenger_nostr_mode":"i2p","messenger_nostr_url":"ws://relay.test.i2p","messenger_nostr_proxy":proxy.to_string()}).to_string()).unwrap();
            let seeds=dir.join("synthetic-seeds");
            let seed_source=if role=="b" {PathBuf::from(std::env::var_os("GS_TEST_B_SEED").expect("independent receiver seed"))} else {PathBuf::from(std::env::var_os("GS_TEST_I1_DIR").unwrap()).join("seed.txt")};
            std::fs::copy(seed_source,&seeds).unwrap();
            std::fs::OpenOptions::new().create(true).append(true).open(dir.join("pending-receives.jsonl.lock")).unwrap();
            let mut cmd=Command::new(&daemon);cmd.arg("serve").arg("--exe").arg(&helper).arg("--seeds").arg(&seeds).arg("--user-dir").arg(&dir).arg("--no-tor").arg("--port").arg("0").env("GS_SYNTHETIC_SEED",if role=="a" {"1f".repeat(32)} else {"20".repeat(32)}).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            #[cfg(windows)] cmd.creation_flags(0x08000000);
            ChildGuard(cmd.spawn().unwrap())
        };
        let mut da=start("a");let mut db=start("b");
        let credentials=|role:&str| {
            let work=root.join(role).join("tor-wallet-1");let deadline=Instant::now()+Duration::from_secs(25);
            loop { if let (Ok(raw),Ok(token))=(std::fs::read(work.join("status.json")),std::fs::read_to_string(work.join("chat-api.token"))) {
                if let Ok(status)=serde_json::from_slice::<Value>(&raw) {if let Some(p)=status["chat_port"].as_u64(){return (p as u16,token.trim().to_owned())}}
            } assert!(Instant::now()<deadline,"daemon {role} did not start");std::thread::sleep(Duration::from_millis(50)); }
        };
        let (pa,ta)=credentials("a");let (pb,tb)=credentials("b");
        let ba=http(pa,&ta,"GET","/v1/nostr/binding",Value::Null)["binding"].clone();
        let bb=http(pb,&tb,"GET","/v1/nostr/binding",Value::Null)["binding"].clone();
        http(pa,&ta,"POST","/v1/nostr/contact",json!({"binding":bb,"name":"B"}));
        http(pb,&tb,"POST","/v1/nostr/contact",json!({"binding":ba,"name":"A"}));
        // Signed/decryptable gift-wrap with unsupported inner content: preserve it,
        // restart, then prove a later valid message can still be delivered.
        let attacker=glaux_messenger::nostr::NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000003").unwrap();
        let recipient_key=glaux_messenger::nostr::parse_public_hex(bb["transport_key"].as_str().unwrap()).unwrap();
        let poison=attacker.wrap_event(&recipient_key,"synthetic unsupported envelope".into(),unix_now()).unwrap();
        events.lock().unwrap().push(serde_json::to_value(&poison).unwrap());
        let limit=Instant::now()+Duration::from_secs(20);
        loop {let response=http(pb,&tb,"GET","/v1/nostr/deferred",Value::Null);
            if response["items"].as_array().unwrap().iter().any(|item|item["id"]==poison.id) {break}
            assert!(Instant::now()<limit,"poison event was not preserved");std::thread::sleep(Duration::from_millis(100));}
        let _=db.0.kill();let _=db.0.wait();drop(db);let _=std::fs::remove_file(root.join("b").join("tor-wallet-1").join("status.json"));
        let mut db=start("b");let (pb,tb)=credentials("b");
        let persisted=http(pb,&tb,"GET","/v1/nostr/deferred",Value::Null);assert!(persisted["items"].as_array().unwrap().iter().any(|item|item["id"]==poison.id));
        let id="c2e4b989-d6b0-4b41-9186-2707c9c275c0";
        let deadline=Instant::now()+Duration::from_secs(15);
        loop {let status=http(pa,&ta,"GET","/v1/status",Value::Null);if status["phase"]=="ready" {break} assert!(Instant::now()<deadline,"sender not ready: {status}");std::thread::sleep(Duration::from_millis(100));}
        http(pa,&ta,"POST","/v1/send",json!({"to":bb["owner"],"text":"real daemon test","request_id":id}));
        let deadline=Instant::now()+Duration::from_secs(20);
        loop {let messages=http(pb,&tb,"GET","/v1/messages",Value::Null);
            if messages["messages"].as_array().unwrap().iter().any(|m|m["text"]=="real daemon test" && m["verified"]==true) {break}
            assert!(Instant::now()<deadline,"text did not reach recipient");std::thread::sleep(Duration::from_millis(200));}
        // Stop the recipient, queue a genuine synthetic Floonet invoice,
        // retry the same guarded operation, then restart the recipient.
        let _=db.0.kill();let _=db.0.wait();drop(db);
        let _=std::fs::remove_file(root.join("b").join("tor-wallet-1").join("status.json"));
        let fixture=PathBuf::from(std::env::var_os("GS_TEST_I1_DIR").unwrap());
        let armor=std::fs::read_to_string(fixture.join("i1.txt")).unwrap();
        let sid="87b3b340-1297-4a61-9b79-50fe06545d5e";
        let work=root.join("a").join("tor-wallet-1");let folder=root.join("a").join("synthetic-invoice");std::fs::create_dir_all(&folder).unwrap();
        let armor_path=folder.join("i1.txt");std::fs::write(&armor_path,&armor).unwrap();
        std::fs::write(folder.join("meta.json"),json!({"slate_id":sid,"kind":"invoice","stage":"waiting_payer"}).to_string()).unwrap();
        let status:Value=serde_json::from_slice(&std::fs::read(work.join("status.json")).unwrap()).unwrap();let route=status["glaux_route"].as_str().expect("active route").to_owned();
        use sha2::{Digest,Sha256};let digest=data_encoding::HEXLOWER.encode(&Sha256::digest(armor.trim().as_bytes()));
        std::fs::write(folder.join("backup-route.json"),json!({"peer":bb["owner"],"mode":"nostr_i2p","route":route,"armor_sha256":digest}).to_string()).unwrap();
        let context=folder.join("invoice-context.json");std::fs::copy(fixture.join("context.json"),&context).unwrap();let wallet_dir=root.join("a");
        let queue=|retry:bool| {let mut cmd=Command::new(&daemon);cmd.arg("queue").arg("--user-dir").arg(&wallet_dir).arg("--kind").arg("invoice").arg("--slate-id").arg(sid).arg("--to").arg("synthetic").arg("--armor").arg(&armor_path).arg("--context").arg(&context).arg("--tx-folder").arg(&folder).arg("--messenger").arg(bb["owner"].as_str().unwrap()).arg("--messenger-only").arg("--expected-mode").arg("nostr_i2p").arg("--expected-route").arg(&route).stdout(Stdio::piped()).stderr(Stdio::piped());if retry {cmd.arg("--retry");} #[cfg(windows)] cmd.creation_flags(0x08000000);cmd.output().unwrap()};
        let queued=queue(false);assert!(queued.status.success(),"queue failed: {}",String::from_utf8_lossy(&queued.stderr));
        let limit=Instant::now()+Duration::from_secs(20);loop {let retry=queue(true);if retry.status.success(){break}assert!(Instant::now()<limit,"manual retry not queued");std::thread::sleep(Duration::from_millis(200));}
        let db2=start("b");let (pb2,tb2)=credentials("b");let deadline=Instant::now()+Duration::from_secs(30);
        loop {let result=http(pb2,&tb2,"GET","/v1/messages",Value::Null);if result["messages"].as_array().unwrap().iter().any(|m|m["armor"].as_str()==Some(armor.trim())) {break}assert!(Instant::now()<deadline,"invoice did not reach durable history");std::thread::sleep(Duration::from_millis(200));}
        let invoice=root.join("b").join("tor-wallet-1").join("inbox").join(format!("invoice-{sid}.txt"));
        let deadline=Instant::now()+Duration::from_secs(30);while !invoice.exists(){assert!(Instant::now()<deadline,"invoice was not saved to wallet inbox");std::thread::sleep(Duration::from_millis(200));}
        assert_eq!(std::fs::read_to_string(&invoice).unwrap().trim(),armor.trim());
        drop(db2);let _=std::fs::remove_file(root.join("b").join("tor-wallet-1").join("status.json"));
        let db3=start("b");let (pb3,tb3)=credentials("b");let after_restart=http(pb3,&tb3,"GET","/v1/messages",Value::Null);
        assert_eq!(after_restart["messages"].as_array().unwrap().iter().filter(|m|m["armor"].as_str()==Some(armor.trim())).count(),1);
        assert_eq!(std::fs::read_to_string(&invoice).unwrap().trim(),armor.trim());
        // Build a separate bench-only synthetic S1 (fake input, never valid on
        // chain), approve it at the receiver and run the real finalizer.
        let s1_fixture=PathBuf::from(std::env::var_os("GS_TEST_S1_DIR").expect("synthetic S1 fixture"));
        let s1=std::fs::read_to_string(s1_fixture.join("s1.txt")).unwrap();
        let send_id=std::fs::read_to_string(s1_fixture.join("id.txt")).unwrap();let send_id=send_id.trim();
        let send_folder=root.join("a").join("synthetic-send");std::fs::create_dir_all(&send_folder).unwrap();
        let s1_path=send_folder.join("s1.txt");std::fs::write(&s1_path,&s1).unwrap();
        let send_context=send_folder.join("send-context.json");std::fs::copy(s1_fixture.join("send-context.json"),&send_context).unwrap();
        std::fs::write(send_folder.join("meta.json"),json!({"slate_id":send_id,"kind":"send","stage":"waiting_answer"}).to_string()).unwrap();
        let s1_digest=data_encoding::HEXLOWER.encode(&Sha256::digest(s1.trim().as_bytes()));
        std::fs::write(send_folder.join("backup-route.json"),json!({"peer":bb["owner"],"mode":"nostr_i2p","route":route,"armor_sha256":s1_digest}).to_string()).unwrap();
        let journal=root.join("a").join("pending-receives.jsonl");
        std::fs::write(&journal,format!("{}\n",json!({"kind":"payment","what":"send","wallet":1,"slate_id":send_id,"tip_height":0,"commits":"02".repeat(33)}))).unwrap();
        std::fs::write(root.join("a").join("peers.txt"),"127.0.0.1:9\n").unwrap();
        let mut command=Command::new(&daemon);command.arg("queue").arg("--user-dir").arg(&wallet_dir).arg("--kind").arg("send").arg("--slate-id").arg(send_id).arg("--to").arg("synthetic").arg("--armor").arg(&s1_path).arg("--context").arg(&send_context).arg("--tx-folder").arg(&send_folder).arg("--messenger").arg(bb["owner"].as_str().unwrap()).arg("--messenger-only").arg("--expected-mode").arg("nostr_i2p").arg("--expected-route").arg(&route).stdout(Stdio::piped()).stderr(Stdio::piped());#[cfg(windows)] command.creation_flags(0x08000000);
        let queued=command.output().unwrap();assert!(queued.status.success(),"S1 queue failed: {}",String::from_utf8_lossy(&queued.stderr));
        let pending=root.join("b").join("tor-wallet-1").join("pending").join(format!("{send_id}.json"));let deadline=Instant::now()+Duration::from_secs(35);
        while !pending.exists(){assert!(Instant::now()<deadline,"S1 did not reach manual approval");std::thread::sleep(Duration::from_millis(200));}
        let decision=root.join("b").join("tor-wallet-1").join("decisions").join(format!("{send_id}.json"));
        std::fs::write(&decision,json!({"slate_id":send_id,"accept":true,"add_contact":false,"name":""}).to_string()).unwrap();
        let deadline=Instant::now()+Duration::from_secs(40);while !send_folder.join("FINALIZED").exists(){assert!(Instant::now()<deadline,"synthetic S1 did not finalize after S2");std::thread::sleep(Duration::from_millis(200));}
        let tx=std::fs::read(send_folder.join("spend-tx.hex")).expect("finalized transaction");
        let mut command=Command::new(&daemon);command.arg("queue").arg("--retry").arg("--user-dir").arg(&wallet_dir).arg("--kind").arg("send").arg("--slate-id").arg(send_id).arg("--to").arg("synthetic").arg("--armor").arg(&s1_path).arg("--context").arg(&send_context).arg("--tx-folder").arg(&send_folder).arg("--messenger").arg(bb["owner"].as_str().unwrap()).arg("--messenger-only").arg("--expected-mode").arg("nostr_i2p").arg("--expected-route").arg(&route).stdout(Stdio::piped()).stderr(Stdio::piped());#[cfg(windows)] command.creation_flags(0x08000000);
        assert!(!command.output().unwrap().status.success(),"finalized payment retry should be refused");
        assert_eq!(std::fs::read(send_folder.join("spend-tx.hex")).unwrap(),tx);
        // A real I2 is built ahead of time by grinsight-state using a synthetic
        // input. Relay it through payer's guarded reply path to issuer A.
        let i2dir=PathBuf::from(std::env::var_os("GS_TEST_I2_DIR").expect("synthetic I2 fixture"));
        let i2=std::fs::read_to_string(i2dir.join("i2.txt")).unwrap();
        let pay_folder=root.join("b").join("synthetic-pay-invoice");std::fs::create_dir_all(&pay_folder).unwrap();
        let i2_path=pay_folder.join("i2.txt");std::fs::write(&i2_path,&i2).unwrap();
        let pay_context=pay_folder.join("test-context");std::fs::write(&pay_context,b"synthetic only").unwrap();
        std::fs::write(pay_folder.join("meta.json"),json!({"slate_id":sid,"kind":"pay_invoice","stage":"waiting_issuer"}).to_string()).unwrap();
        let digest=data_encoding::HEXLOWER.encode(&Sha256::digest(i2.trim().as_bytes()));
        std::fs::write(pay_folder.join("backup-route.json"),json!({"peer":ba["owner"],"mode":"nostr_i2p","route":route,"armor_sha256":digest}).to_string()).unwrap();
        let lock_path=root.join("b").join("pending-receives.jsonl.lock");let lock=std::fs::OpenOptions::new().read(true).write(true).create(true).open(lock_path).unwrap();lock.lock().unwrap();
        let mut journal=std::fs::OpenOptions::new().create(true).append(true).open(root.join("b").join("pending-receives.jsonl")).unwrap();
        writeln!(journal,"{}",json!({"kind":"payment","what":"invoice","wallet":1,"slate_id":sid,"tip_height":0,"commits":"02".repeat(33)})).unwrap();journal.sync_all().unwrap();drop(journal);drop(lock);
        let mut command=Command::new(&daemon);command.arg("queue").arg("--user-dir").arg(root.join("b")).arg("--kind").arg("reply").arg("--slate-id").arg(sid).arg("--to").arg("synthetic").arg("--armor").arg(&i2_path).arg("--context").arg(&pay_context).arg("--tx-folder").arg(&pay_folder).arg("--messenger").arg(ba["owner"].as_str().unwrap()).arg("--messenger-only").arg("--expected-mode").arg("nostr_i2p").arg("--expected-route").arg(&route).stdout(Stdio::piped()).stderr(Stdio::piped());#[cfg(windows)] command.creation_flags(0x08000000);
        let queued=command.output().unwrap();assert!(queued.status.success(),"I2 queue failed: {}",String::from_utf8_lossy(&queued.stderr));
        let deadline=Instant::now()+Duration::from_secs(40);while !folder.join("FINALIZED").exists(){assert!(Instant::now()<deadline,"synthetic invoice did not finalize after I2");std::thread::sleep(Duration::from_millis(200));}
        assert!(folder.join("spend-tx.hex").is_file());assert!(folder.join("invoice-i3.json").is_file());
        drop(db3);
        let _=da.0.kill();let _=da.0.wait();drop(da);let _=std::fs::remove_file(root.join("a").join("tor-wallet-1").join("status.json"));
        let _da2=start("a");let (pa2,ta2)=credentials("a");

        drop(_da2);stop.store(true,Ordering::Relaxed);worker.join().unwrap();let _=std::fs::remove_dir_all(root);
    }

    fn serve(mut stream: TcpStream, events: Arc<Mutex<Vec<Value>>>, drop_ack: Arc<AtomicBool>, drop_before: Arc<AtomicBool>) {
        stream.set_nonblocking(false).unwrap();
        let mut hello=[0;3]; if stream.read_exact(&mut hello).is_err() || hello != [5,1,0] {eprintln!("mock socks greeting failed");return}
        if let Err(e)=stream.write_all(&[5,0]) {eprintln!("mock greeting write failed {e}");return}
        let mut h=[0;5]; if let Err(err)=stream.read_exact(&mut h) {eprintln!("mock socks request read failed: {err}");return} if h[..4] != [5,1,0,3] {eprintln!("mock socks request mismatch: {h:?}");return}
        let mut domain=vec![0; h[4] as usize]; if stream.read_exact(&mut domain).is_err() {return}
        let mut port=[0;2]; if stream.read_exact(&mut port).is_err() || domain != b"relay.test.i2p" {eprintln!("mock socks unexpected destination {}", String::from_utf8_lossy(&domain));return}
        if stream.write_all(&[5,0,0,1,127,0,0,1,0,0]).is_err() {return}
        let Ok(mut ws)=accept(stream) else {return};
        let Ok(Message::Text(body))=ws.read() else {return};
        let Ok(v)=serde_json::from_str::<Value>(&body) else {return};
        match v[0].as_str() {
            Some("EVENT") => {
                if drop_before.swap(false,Ordering::SeqCst) { return; }
                let e=v[1].clone(); let id=e["id"].as_str().unwrap_or("").to_owned();
                events.lock().unwrap().push(e);
                if drop_ack.swap(false, Ordering::SeqCst) { return; }
                let _=ws.send(Message::Text(json!(["OK",id,true,""]).to_string().into()));
            }
            Some("REQ") => {
                let sub=v[1].as_str().unwrap_or("");
                let filter=&v[2];let since=filter["since"].as_u64().unwrap_or(0);let until=filter["until"].as_u64().unwrap_or(u64::MAX);
                let p=filter["#p"].as_array().and_then(|v|v.first()).and_then(Value::as_str);
                let mut selected:Vec<Value>=events.lock().unwrap().iter().filter(|e| {
                    let ts=e["created_at"].as_u64().unwrap_or(0);
                    ts>=since && ts<=until && p.is_none_or(|p| e["tags"].as_array().is_some_and(|tags|tags.iter().any(|tag|tag[0]=="p" && tag[1]==p)))
                }).cloned().collect();
                selected.sort_by_key(|e|std::cmp::Reverse(e["created_at"].as_u64().unwrap_or(0)));
                let limit=filter["limit"].as_u64().unwrap_or(1000) as usize;
                for event in selected.iter().take(limit) {
                    let _=ws.send(Message::Text(json!(["EVENT",sub,event]).to_string().into()));
                }
                let _=ws.send(Message::Text(json!(["EOSE",sub]).to_string().into()));
            }
            _=>{}
        }
    }

    #[test]
    fn two_wallets_send_signed_text_via_anonymous_nostr_route() {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let proxy=listener.local_addr().unwrap();
        let events=Arc::new(Mutex::new(Vec::new()));
        let stop=Arc::new(AtomicBool::new(false));
        let drop_ack=Arc::new(AtomicBool::new(false));
        let drop_before=Arc::new(AtomicBool::new(false));
        let s=stop.clone(); let e=events.clone(); let failure=drop_ack.clone();let offline=drop_before.clone();
        let worker=std::thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream,_))=>{let e=e.clone();let failure=failure.clone();let offline=offline.clone();std::thread::spawn(move||serve(stream,e,failure,offline));}
                    Err(err) if err.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(10)),
                    Err(_)=>break,
                }
            }
        });
        let seed_a=[31u8;32]; let seed_b=[32u8;32];
        let a=Identity::from_seed(seed_a,"tgrin").unwrap();
        let b=Identity::from_seed(seed_b,"tgrin").unwrap();
        let nostr_a=crate::identity::nostr_keys_from_messaging_seed(&seed_a,"tgrin").unwrap();
        let nostr_b=crate::identity::nostr_keys_from_messaging_seed(&seed_b,"tgrin").unwrap();
        let now=unix_now();
        let bind_a=NostrBinding::create(&a,&nostr_a.public_hex(),1,now,now+3600).unwrap();
        let bind_b=NostrBinding::create(&b,&nostr_b.public_hex(),1,now,now+3600).unwrap();
        let root=std::env::temp_dir().join(format!("glaux-nostr-service-{}-{now}",std::process::id()));
        let config=|dir:PathBuf| ServiceConfig {
            data_dir:dir,network:"tgrin".into(),
            mode:NetworkMode::NostrI2p {relay:"ws://relay.test.i2p".into(),socks:proxy,expiration_tag:true},
            logical_proxy:None,poll_secs:1,fetch_limit:20,ttl_secs:13*60*60,history_days:0,tor_state:None,bridge_line:None,bridge_binary:None,
        };
        let wa=Arc::new(WalletService::open(config(root.join("a")),Zeroizing::new(seed_a)).unwrap());
        let wb=Arc::new(WalletService::open(config(root.join("b")),Zeroizing::new(seed_b)).unwrap());
        wa.add_nostr_binding(&bind_b,"Bob").unwrap(); wb.add_nostr_binding(&bind_a,"Alice").unwrap();
        wa.start_network(); wb.start_network();
        let status_a=wa.wait_ready(Duration::from_secs(10));
        assert_eq!(status_a.phase,"ready", "{:?}", status_a.last_error);
        let status_b=wb.wait_ready(Duration::from_secs(10));
        assert_eq!(status_b.phase,"ready", "{:?}", status_b.last_error);
        let sent=wa.send_text(wb.address(),"encrypted test",None).unwrap();
        assert_eq!(sent.direction,"outgoing");
        let before=MessageKind::Slatepack {armor:"offline before relay accepts".into(),encrypted:true};
        drop_before.store(true,Ordering::SeqCst);
        assert!(wa.send_kind(wb.address(),before.clone(),None).is_err(),"network loss before publish must be visible");
        let first_saved=wa.payment_outbox.envelope(&wa.identity,wb.identity.address(),"offline before relay accepts",&format!("nostr-i2p:ws://relay.test.i2p:{proxy}"),900).unwrap();
        let retry=wa.send_kind(wb.address(),before,None).unwrap();assert_eq!(retry.id,first_saved.id);
        let kind=MessageKind::Slatepack {armor:"synthetic encrypted slatepack".into(),encrypted:true};
        drop_ack.store(true,Ordering::SeqCst);
        assert!(wa.send_kind(wb.address(),kind.clone(),None).is_err(), "lost confirmation must be unknown");
        let saved=wa.payment_outbox.envelope(&wa.identity,wb.identity.address(),"synthetic encrypted slatepack",&format!("nostr-i2p:ws://relay.test.i2p:{proxy}"),13*60*60).unwrap();
        let second=wa.send_kind(wb.address(),kind,None).unwrap();
        assert_eq!(saved.id, second.id, "retry must reuse the signed envelope");
        assert_eq!(wa.messages(0,50).messages.iter().filter(|m|m.id==saved.id).count(),1);
        let deadline=Instant::now()+Duration::from_secs(8);
        loop {
            let messages=wb.messages(0,50).messages;
            if messages.iter().any(|m|m.text.as_deref()==Some("encrypted test") && m.verified)
                && messages.iter().filter(|m|m.id==saved.id && m.armor.as_deref()==Some("synthetic encrypted slatepack") && m.verified).count()==1 {break}
            assert!(Instant::now()<deadline,"receiver did not verify exactly one message");
            std::thread::sleep(Duration::from_millis(50));
        }
        if let Ok(dir)=std::env::var("GS_REAL_SLATE_FIXTURE") {
            let read=|name:&str| std::fs::read_to_string(std::path::Path::new(&dir).join(name)).unwrap().trim().to_string();
            let phase=std::env::var("GS_REAL_SLATE_PHASE").expect("request or reply phase");
            let (a_name,b_name)=if phase=="request" {("s1.txt","i1.txt")} else {("i2.txt","s2.txt")};
            let a_text=read(a_name);let b_text=read(b_name);
            let to_b=wa.send_slatepack(wb.address(),&a_text,None).unwrap();
            let to_a=wb.send_slatepack(wa.address(),&b_text,None).unwrap();
            let limit=Instant::now()+Duration::from_secs(10);
            loop {
                let a=wa.messages(0,100).messages;let b=wb.messages(0,100).messages;
                let received_b=b.iter().find(|m|m.id==to_b.id && m.verified && m.peer==wa.address() && m.armor.as_deref()==Some(a_text.as_str()));
                let received_a=a.iter().find(|m|m.id==to_a.id && m.verified && m.peer==wb.address() && m.armor.as_deref()==Some(b_text.as_str()));
                if let (Some(rb),Some(ra))=(received_b,received_a) {
                    std::fs::write(std::path::Path::new(&dir).join(format!("delivered-{a_name}")),rb.armor.as_ref().unwrap()).unwrap();
                    std::fs::write(std::path::Path::new(&dir).join(format!("delivered-{b_name}")),ra.armor.as_ref().unwrap()).unwrap(); break;
                }
                assert!(Instant::now()<limit,"real Slatepack absent from local Nostr relay");std::thread::sleep(Duration::from_millis(50));
            }
            let route=format!("nostr-i2p:ws://relay.test.i2p:{proxy}");
            for (svc,dest,text) in [(&wa,wb.address(),a_text.as_str()),(&wb,wa.address(),b_text.as_str())] {
                let e=svc.payment_outbox.envelope(&svc.identity,&Address::parse(dest).unwrap(),text,&route,900).unwrap(); assert_eq!(e.ttl,900);
            }
        }
        wa.shutdown(); wb.shutdown(); stop.store(true,Ordering::Relaxed); worker.join().unwrap();
    }

    #[test] #[ignore = "large synthetic local relay runtime"]
    fn runtime_drains_over_thousand_nostr_events() {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();listener.set_nonblocking(true).unwrap();let proxy=listener.local_addr().unwrap();
        let events=Arc::new(Mutex::new(Vec::new()));let stop=Arc::new(AtomicBool::new(false));let lost=Arc::new(AtomicBool::new(false));let before=Arc::new(AtomicBool::new(false));
        let flag=stop.clone();let store=events.clone();let l=lost.clone();let b=before.clone();
        let worker=std::thread::spawn(move||while !flag.load(Ordering::Relaxed){match listener.accept(){Ok((stream,_))=>{let(e,l,b)=(store.clone(),l.clone(),b.clone());std::thread::spawn(move||serve(stream,e,l,b));},Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(10)),Err(_)=>break}});
        let a=Identity::from_seed([31u8;32],"tgrin").unwrap();let b=Identity::from_seed([32u8;32],"tgrin").unwrap();
        let ka=crate::identity::nostr_keys_from_messaging_seed(&[31u8;32],"tgrin").unwrap();let kb=crate::identity::nostr_keys_from_messaging_seed(&[32u8;32],"tgrin").unwrap();let now=unix_now();
        for i in 0..1005 {let env=Envelope::seal(&a,b.address(),MessageKind::Text{text:format!("synthetic-{i}")},13*3600,now).unwrap();
            let event=ka.wrap_event(&kb.public(),serde_json::to_string(&env).unwrap(),now).unwrap();events.lock().unwrap().push(serde_json::to_value(event).unwrap());}
        let root=std::env::temp_dir().join(format!("gs-over-thousand-{}-{}",std::process::id(),now));
        let cfg=ServiceConfig{data_dir:root.clone(),network:"tgrin".into(),mode:NetworkMode::NostrI2p{relay:"ws://relay.test.i2p".into(),socks:proxy,expiration_tag:false},logical_proxy:None,poll_secs:1,fetch_limit:200,ttl_secs:13*3600,history_days:0,tor_state:None,bridge_line:None,bridge_binary:None};
        let wb=Arc::new(WalletService::open(cfg,Zeroizing::new([32u8;32])).unwrap());wb.start_network();assert_eq!(wb.wait_ready(Duration::from_secs(15)).phase,"ready");
        let deadline=Instant::now()+Duration::from_secs(180);loop {let n=wb.history.list(a.address(),2000).unwrap().len();if n==1005 {break}assert!(Instant::now()<deadline,"only {n}/1005 messages persisted; status {:?}",wb.status().last_error);std::thread::sleep(Duration::from_millis(500));}
        wb.shutdown();stop.store(true,Ordering::Relaxed);worker.join().unwrap();drop(wb);let _=std::fs::remove_dir_all(root);
    }

    #[test]
    fn cursor_drains_multiple_service_batches_and_reopens() {
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();listener.set_nonblocking(true).unwrap();let proxy=listener.local_addr().unwrap();
        let events=Arc::new(Mutex::new(Vec::new()));let stop=Arc::new(AtomicBool::new(false));
        let lost=Arc::new(AtomicBool::new(false));let before=Arc::new(AtomicBool::new(false));
        let s=stop.clone();let e=events.clone();let l=lost.clone();let b=before.clone();
        let worker=std::thread::spawn(move||while !s.load(Ordering::Relaxed) {match listener.accept() {
            Ok((stream,_))=>{let (e,l,b)=(e.clone(),l.clone(),b.clone());std::thread::spawn(move||serve(stream,e,l,b));},
            Err(err) if err.kind()==std::io::ErrorKind::WouldBlock=>std::thread::sleep(Duration::from_millis(10)),Err(_)=>break,
        }});
        let sa=[31u8;32];let sb=[32u8;32];let a=Identity::from_seed(sa,"tgrin").unwrap();let b=Identity::from_seed(sb,"tgrin").unwrap();
        let ka=crate::identity::nostr_keys_from_messaging_seed(&sa,"tgrin").unwrap();let kb=crate::identity::nostr_keys_from_messaging_seed(&sb,"tgrin").unwrap();let now=unix_now();
        let ba=NostrBinding::create(&a,&ka.public_hex(),1,now,now+3600).unwrap();let bb=NostrBinding::create(&b,&kb.public_hex(),1,now,now+3600).unwrap();
        let root=std::env::temp_dir().join(format!("gs-cursor-service-{}-{}",std::process::id(),now));
        let config=|dir:PathBuf| ServiceConfig{data_dir:dir,network:"tgrin".into(),mode:NetworkMode::NostrI2p{relay:"ws://relay.test.i2p".into(),socks:proxy,expiration_tag:false},logical_proxy:None,poll_secs:1,fetch_limit:2,ttl_secs:13*3600,history_days:0,tor_state:None,bridge_line:None,bridge_binary:None};
        let wa=Arc::new(WalletService::open(config(root.join("a")),Zeroizing::new(sa)).unwrap());
        let wb=Arc::new(WalletService::open(config(root.join("b")),Zeroizing::new(sb)).unwrap());
        wa.add_nostr_binding(&bb,"B").unwrap();wb.add_nostr_binding(&ba,"A").unwrap();wa.start_network();assert_eq!(wa.wait_ready(Duration::from_secs(10)).phase,"ready");
        for i in 0..5 {wa.send_text(wb.address(),&format!("cursor-{i}"),None).unwrap();}
        wb.start_network();assert_eq!(wb.wait_ready(Duration::from_secs(10)).phase,"ready");
        let limit=Instant::now()+Duration::from_secs(15);loop {
            if wb.messages(0,100).messages.iter().filter(|m|m.direction=="incoming").count()==5 {break;}
            assert!(Instant::now()<limit,"cursor did not drain all 5 messages");std::thread::sleep(Duration::from_millis(50));
        }
        wb.shutdown();drop(wb);
        let reopened=Arc::new(WalletService::open(config(root.join("b")),Zeroizing::new(sb)).unwrap());reopened.start_network();assert_eq!(reopened.wait_ready(Duration::from_secs(10)).phase,"ready");
        assert_eq!(reopened.messages(0,100).messages.iter().filter(|m|m.direction=="incoming").count(),5);
        reopened.shutdown();wa.shutdown();stop.store(true,Ordering::Relaxed);worker.join().unwrap();let _=std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod live_i2p_wallet_tests {
    use super::*;
    #[test]
    #[ignore = "requires two explicitly started isolated I2P routers"]
    fn two_wallet_services_exchange_i2p_text_with_signed_contacts() {
        let a="127.0.0.1:17657".parse().unwrap(); let b="127.0.0.1:17658".parse().unwrap();
        let root=std::env::temp_dir().join(format!("gs-live-wallet-{}-{}",std::process::id(),unix_now()));
        let config=|dir:PathBuf,sam:SocketAddr| ServiceConfig {
            data_dir:dir, network:"tgrin".into(), mode:NetworkMode::I2p {sam},
            logical_proxy:None,poll_secs:1,fetch_limit:20,ttl_secs:13*60*60,history_days:0,tor_state:None,bridge_line:None,bridge_binary:None,
        };
        let wa=Arc::new(WalletService::open(config(root.join("a"),a),Zeroizing::new([51;32])).unwrap());
        let wb=Arc::new(WalletService::open(config(root.join("b"),b),Zeroizing::new([52;32])).unwrap());
        wa.start_network(); wb.start_network();
        let sa=wa.wait_ready(Duration::from_secs(150)); assert_eq!(sa.phase,"ready", "{:?}",sa.last_error);
        let sb=wb.wait_ready(Duration::from_secs(150)); assert_eq!(sb.phase,"ready", "{:?}",sb.last_error);
        wa.add_i2p_binding(&wb.i2p_binding().unwrap(),"Bob").unwrap();
        wb.add_i2p_binding(&wa.i2p_binding().unwrap(),"Alice").unwrap();
        // Only retry if no stream was established. An unknown result must not
        // be retried as a new message, because it may already be stored.
        let mut sent=false;
        for attempt in 1..=8 {
            match wa.send_text(wb.address(),"test I2P wallet",None) {
                Ok(_) => {sent=true;break;}
                Err(e) if e.contains("I2P connection unavailable") => {println!("waiting for route {attempt}/8"); std::thread::sleep(Duration::from_secs(15));}
                Err(e) => panic!("uncertain I2P result: {e}"),
            }
        }
        assert!(sent,"I2P route did not become available");
        let first=wa.send_slatepack(wb.address(),"synthetic encrypted S1",None).unwrap();
        let second=wa.send_slatepack(wb.address(),"synthetic encrypted S1",None).unwrap();
        assert_eq!(first.id,second.id,"retry should reuse the saved envelope");
        let deadline=Instant::now()+Duration::from_secs(15);
        loop {
            let items=wb.messages(0,50).messages;
            if items.iter().any(|m|m.text.as_deref()==Some("test I2P wallet") && m.verified)
                && items.iter().filter(|m|m.id==first.id && m.armor.as_deref()==Some("synthetic encrypted S1") && m.verified).count()==1 {break}
            assert!(Instant::now()<deadline,"recipient did not verify message");
            std::thread::sleep(Duration::from_millis(100));
        }
        wa.shutdown(); wb.shutdown();
    }
}



