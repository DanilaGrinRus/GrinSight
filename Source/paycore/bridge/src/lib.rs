//! Adapter between the payment core and everything outside it.
//!
//! * [`Bridge::call`] speaks JSON-RPC 2.0 with methods under `paycore.`; the
//!   host mounts it wherever the UI already talks to Rust (for the Flutter
//!   app: the local service's `/rpc`). It is transport-independent: one
//!   request string in, one response string out.
//! * [`ports`] are the traits the host implements for the outside world:
//!   broadcast, clock, chain view, slate text format, message transport.
//! * `paycore.delivery.*` moves slates through the message transport. What
//!   arrives from there is untrusted and bounded: a fixed number of messages
//!   per call and per sender, nothing parsed from a sender nobody waits
//!   for, and a sender who keeps sending invalid slates is muted.
//!
//! What never crosses this boundary: the seed, keys, signing contexts and
//! the journal key. The host opens the [`Core`] itself and hands it over;
//! no method takes or returns secret material. Chain facts are not fed
//! through JSON either: the chain layer calls `core_mut().chain_advance`.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    missing_docs
)]

/// The `Mailbox` port across a process boundary: the wallet's side is
/// [`pipe::PipeMailbox`], given to [`ports::Ports::mailbox`].
pub use fly_paycore_chain_pipe as chain_pipe;
pub use fly_paycore_chain_port as chain_port;
pub use fly_paycore_mailbox_pipe as pipe;
pub use fly_paycore_onion_pipe as onion_pipe;
mod onion;
pub mod ports;
pub use onion::{OnionFactory, ONION_HOLD, ONION_MAX_ASKS, ONION_MIN_AMOUNT, ONION_POST_WITHIN};
pub mod runner;

use fly_paycore_store::{Dir, Guard};
use fly_paycore_wallet::{
    slate_stage, Broadcast, Core, CoreError, DeliveryNote, DeliveryStatus, Envelope, Finalized,
    MessageState, SendStatus, SlateStage, MESSAGE_PREFIX,
};
use grin_keychain::Keychain;
use fly_paycore_chain_port::{ChainFeed, Step, Tip};
use fly_paycore_wallet::{Advance, OldPiece};
use ports::{Incoming, Ports, Published};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Version of the method set. Raised when a method changes incompatibly.
pub const API_VERSION: u32 = 1;
/// Largest request accepted, checked before parsing.
pub const MAX_REQUEST_LEN: usize = 256 * 1024;
/// Envelopes published by one `paycore.delivery.pump`.
pub const MAX_PUMP: usize = 16;
/// Steps of the chain taken in one call: blocks applied, steps back, new
/// starting points. More wait for the next call, so that a long catch-up
/// does not keep the interface waiting.
pub const MAX_CHAIN_STEPS: usize = 64;
/// Most pieces of the old outputs read in one `paycore.chain.sync`, and the
/// longest it goes on reading them: other requests wait meanwhile.
pub const MAX_OLD_PIECES: usize = 64;
/// See [`MAX_OLD_PIECES`].
pub const OLD_BUDGET: Duration = Duration::from_secs(1);
/// For this long after a piece of old outputs was read, the next piece is
/// taken to be on its way: `paycore.chain.sync` that meets a piece which is
/// not there yet still says `more`, and the next round follows without the
/// pause. The chain layer fetches pieces from several nodes and they come
/// out of order: the one that is next is often the last of a run to
/// arrive, and waiting the pause out for it leaves the rest lying. After
/// this long without a piece the chain layer has nothing to give - no
/// nodes, a new archive header - and is asked at the ordinary pace.
pub const OLD_COMING_FOR: Duration = Duration::from_secs(5);
/// How often a finished transaction that is not in the chain yet is handed
/// to the chain layer again by `paycore.send.pump`. Handing it over again
/// is how the wallet learns that nodes have it, and how it gets sent after
/// the chain layer was restarted; the chain layer sends nothing twice.
pub const BROADCAST_EVERY: Duration = Duration::from_secs(30);
/// Frames after which the journal is folded into a snapshot (5.5, K118).
/// Every block the wallet follows writes a frame: about three days of
/// blocks, after which the fold takes the journal back to its start.
pub const FOLD_AFTER: u64 = 4096;
/// Pause before an envelope that a relay did not accept is offered again.
/// It doubles with every attempt up to [`PUBLISH_RETRY_MAX`]: a relay that
/// refuses is not asked a thousand times, and the journal is not filled
/// with notes about it.
pub const PUBLISH_RETRY_FIRST: Duration = Duration::from_secs(2);
/// Longest pause between two publications of the same envelope.
pub const PUBLISH_RETRY_MAX: Duration = Duration::from_secs(300);
/// Messages taken from the transport by one `paycore.delivery.receive`.
pub const MAX_RECEIVE: usize = 16;
/// Messages of one sender handled by one `paycore.delivery.receive`; the
/// rest stay with the transport for a later call.
pub const MAX_PER_SENDER: u32 = 4;
/// Invalid messages after which a sender is ignored until the wallet is
/// reopened or a new payment to that contact is started.
pub const MAX_STRIKES: u32 = 8;
/// Senders whose invalid messages are counted; more are not tracked and
/// their messages are dropped unread.
pub const MAX_TRACKED_SENDERS: usize = 1024;
/// Largest text taken from the transport, checked before decoding.
pub const MAX_INCOMING_TEXT: usize = 96 * 1024;

/// An error on its way to the caller: code, stable kind, optional reason.
struct Fail {
    code: i64,
    kind: &'static str,
    reason: String,
}

fn fail(code: i64, kind: &'static str, reason: &str) -> Fail {
    Fail {
        code,
        kind,
        reason: reason.to_string(),
    }
}

/// The most confirmations the owner can ask for before "received" (K190).
pub const MAX_K_CONF: u64 = 1000;

fn bad_params(reason: &str) -> Fail {
    fail(-32602, "invalid_params", reason)
}

impl From<CoreError> for Fail {
    fn from(e: CoreError) -> Fail {
        match e {
            CoreError::BadSlate(r) => fail(-32010, "bad_slate", r),
            CoreError::Refused(r) => fail(-32011, "refused", r),
            CoreError::NotFound => fail(-32012, "not_found", ""),
            CoreError::Conflict => fail(-32013, "conflict", ""),
            CoreError::UnknownOutcome => fail(-32014, "unknown_outcome", ""),
            CoreError::InsufficientFunds => fail(-32015, "insufficient_funds", ""),
            CoreError::Commit(c) => fail(-32020, "storage", &format!("{c:?}")),
            CoreError::Open(_) => fail(-32021, "storage_open", ""),
            CoreError::Corrupt => fail(-32022, "corrupt", ""),
            CoreError::Rng => fail(-32023, "rng", ""),
            CoreError::Build => fail(-32024, "build", ""),
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let b = text.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => c.checked_sub(b'0'),
            b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
            b'A'..=b'F' => c.checked_sub(b'A').and_then(|v| v.checked_add(10)),
            _ => None,
        }
    };
    b.chunks(2)
        .map(|pair| match pair {
            [hi, lo] => Some(nibble(*hi)?.checked_mul(16)?.checked_add(nibble(*lo)?)?),
            _ => None,
        })
        .collect()
}

/// Typed access to the `params` object.
struct Params<'a>(&'a Map<String, Value>);

impl Params<'_> {
    fn text(&self, name: &str) -> Result<&str, Fail> {
        self.0
            .get(name)
            .and_then(Value::as_str)
            .ok_or_else(|| bad_params(name))
    }

    /// Nanogrin: a non-negative integer, or a decimal string (the form used
    /// in results, safe for 53-bit number platforms).
    fn amount(&self, name: &str) -> Result<u64, Fail> {
        match self.0.get(name) {
            Some(Value::Number(n)) => n.as_u64().ok_or_else(|| bad_params(name)),
            Some(Value::String(s)) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
                s.parse::<u64>().map_err(|_| bad_params(name))
            }
            _ => Err(bad_params(name)),
        }
    }

    fn amount_or(&self, name: &str, default: u64) -> Result<u64, Fail> {
        if self.0.contains_key(name) {
            self.amount(name)
        } else {
            Ok(default)
        }
    }

    fn flag(&self, name: &str) -> Result<bool, Fail> {
        match self.0.get(name) {
            None => Ok(false),
            Some(Value::Bool(b)) => Ok(*b),
            Some(_) => Err(bad_params(name)),
        }
    }

    fn bytes<const N: usize>(&self, name: &str) -> Result<[u8; N], Fail> {
        unhex(self.text(name)?)
            .and_then(|v| <[u8; N]>::try_from(v).ok())
            .ok_or_else(|| bad_params(name))
    }

    fn bytes_opt<const N: usize>(&self, name: &str) -> Result<Option<[u8; N]>, Fail> {
        match self.0.get(name) {
            None | Some(Value::Null) => Ok(None),
            Some(_) => self.bytes(name).map(Some),
        }
    }
}

fn delivery_name(s: DeliveryStatus) -> &'static str {
    match s {
        DeliveryStatus::Queued => "queued",
        DeliveryStatus::WaitingRelay => "waiting_relay",
        DeliveryStatus::RelayAccepted => "relay_accepted",
        DeliveryStatus::Expired => "expired",
        DeliveryStatus::QueueBusy => "queue_busy",
        DeliveryStatus::QueueFull => "queue_full",
    }
}

/// What became of an incoming message: its kind for the UI, whether the
/// transport may forget it, and extra fields of the event.
type Handled = (&'static str, bool, Vec<(&'static str, Value)>);

/// Slate bytes as the text that leaves the bridge.
fn encode_text(
    slatepack: bool,
    codec: &mut dyn ports::SlateCodec,
    slate: &[u8],
) -> Result<String, String> {
    if slatepack {
        fly_paycore_wallet::slatepack_encode(slate)
            .map_err(|_| "slate cannot be written as Slatepack text".to_string())
    } else {
        codec.encode(slate)
    }
}

fn message_state_name(state: MessageState) -> &'static str {
    match state {
        MessageState::Received => "received",
        MessageState::Waiting => "waiting",
        MessageState::RelayAccepted => "relay_accepted",
        MessageState::Expired => "expired",
    }
}

/// Seconds of this computer's clock, for the time shown with a message
/// only; nothing is decided on it.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn stage_name(stage: SlateStage) -> &'static str {
    match stage {
        SlateStage::S1 => "S1",
        SlateStage::S2 => "S2",
        SlateStage::S3 => "S3",
        SlateStage::I1 => "I1",
        SlateStage::I2 => "I2",
        SlateStage::I3 => "I3",
        SlateStage::Unknown => "unknown",
    }
}

fn no_mailbox() -> Fail {
    fail(-32031, "no_mailbox", "")
}

fn no_chain() -> Fail {
    fail(-32032, "no_chain", "")
}

fn outcome_name(outcome: Broadcast) -> &'static str {
    match outcome {
        Broadcast::Accepted => "accepted",
        Broadcast::Rejected => "rejected",
        Broadcast::Unknown => "unknown",
    }
}

fn status_name(s: SendStatus) -> &'static str {
    match s {
        SendStatus::Prepared => "prepared",
        SendStatus::Cancelled => "cancelled",
        SendStatus::Released => "released",
        SendStatus::Unknown => "unknown",
        SendStatus::Finalized => "finalized",
        SendStatus::Confirmed => "confirmed",
        SendStatus::Contested => "contested",
        SendStatus::Dead => "dead",
    }
}

/// The payment core together with its ports.
pub struct Bridge<D: Dir, G: Guard, K: Keychain> {
    core: Core<D, G, K>,
    ports: Ports,
    /// Sign held replies without asking, on the selected tip.
    auto_sign: bool,
    /// Smallest amount answered by unattended receive through the mailbox.
    min_auto_amount: u64,
    /// Invalid messages per sender, in memory only.
    strikes: BTreeMap<[u8; 32], u32>,
    /// Where the next pump starts, so a stuck envelope cannot starve others.
    pump_cursor: usize,
    /// First and longest pause between publications of one envelope.
    publish_retry: (Duration, Duration),
    /// When each waiting envelope may be offered again, and the pause that
    /// led there. In memory only: after a restart everything is due.
    publish_wait: BTreeMap<[u8; 16], (Instant, Duration)>,
    /// The same for text messages, by message id.
    message_wait: BTreeMap<[u8; 32], (Instant, Duration)>,
    /// Slates cross the bridge as Slatepack text instead of going through
    /// the `SlateCodec` port.
    slatepack: bool,
    /// Where verified blocks come from, if the host has a chain layer.
    feed: Option<Box<dyn ChainFeed>>,
    /// Starts the transport whenever the identity or the contacts change.
    factory: Option<ports::MailboxFactory>,
    /// Why the transport is not running, if the factory failed.
    transport_error: Option<String>,
    /// How long the chain layer was waited for; see `paycore.chain.timing`.
    asked: Asked,
    /// When a piece of old outputs was last read, and for how long after
    /// that the next one is taken to be on its way.
    old_read_at: Option<Instant>,
    old_coming_for: Duration,
    /// Whether the last `paycore.chain.sync` ended with the chain layer
    /// saying "nothing new": the wallet has every block the layer has.
    at_tip: bool,
    /// Confirmations after which an incoming payment is called received,
    /// if the owner chose a number (K190): at least 1. A word about the
    /// status only; it changes nothing about what can be spent.
    k_conf_owner: Option<u64>,
    /// When each finished transaction was last handed to the chain layer
    /// and what the answer was. In memory only.
    posted: BTreeMap<[u8; 16], (Instant, Broadcast)>,
    /// The same for the transactions of invoices this wallet issued, by slate.
    posted_invoices: BTreeMap<[u8; 16], (Instant, Broadcast)>,
    broadcast_every: Duration,
    fold_after: u64,
    /// Payments to and from an address through Tor.
    onion: onion::Side,
}

/// Counts and waits of following the chain layer since the bridge was
/// made. A measurement: nothing is decided by it.
#[derive(Default)]
struct Asked {
    rounds: u64,
    steps: u64,
    steps_took: Duration,
    pieces: u64,
    pieces_took: Duration,
    not_ready: u64,
}

impl<D: Dir, G: Guard, K: Keychain> Bridge<D, G, K> {
    /// Wrap a core the host has opened.
    pub fn new(core: Core<D, G, K>, ports: Ports) -> Self {
        Bridge {
            core,
            ports,
            auto_sign: false,
            min_auto_amount: 0,
            strikes: BTreeMap::new(),
            pump_cursor: 0,
            publish_retry: (PUBLISH_RETRY_FIRST, PUBLISH_RETRY_MAX),
            publish_wait: BTreeMap::new(),
            message_wait: BTreeMap::new(),
            slatepack: false,
            feed: None,
            factory: None,
            transport_error: None,
            asked: Asked::default(),
            old_read_at: None,
            old_coming_for: OLD_COMING_FOR,
            at_tip: false,
            k_conf_owner: None,
            posted: BTreeMap::new(),
            posted_invoices: BTreeMap::new(),
            broadcast_every: BROADCAST_EVERY,
            fold_after: FOLD_AFTER,
            onion: onion::Side::default(),
        }
    }

    /// Give the bridge the chain layer to take verified blocks from. Without
    /// one, chain facts reach the core only through [`Bridge::core_mut`].
    pub fn set_chain_feed(&mut self, feed: Box<dyn ChainFeed>) {
        self.feed = Some(feed);
    }

    /// Change for how long after a piece of old outputs the next one is
    /// taken to be on its way ([`OLD_COMING_FOR`]). Tests use zero.
    pub fn set_old_coming_for(&mut self, coming_for: Duration) {
        self.old_coming_for = coming_for;
    }

    /// Change how often a finished transaction is handed to the chain
    /// layer again ([`BROADCAST_EVERY`]). Tests use zero.
    pub fn set_broadcast_every(&mut self, every: Duration) {
        self.broadcast_every = every;
    }

    /// Change after how many frames the journal is folded ([`FOLD_AFTER`]).
    /// Tests use a few.
    pub fn set_fold_after(&mut self, frames: u64) {
        self.fold_after = frames.max(1);
    }

    /// Change the pauses between publications of one envelope (the first
    /// and the longest). Tests use zero.
    pub fn set_publish_retry(&mut self, first: Duration, longest: Duration) {
        self.publish_retry = (first, longest.max(first));
    }

    /// Let the bridge start the transport itself: now, and again whenever
    /// the transport identity or the set of contacts changes. While the
    /// wallet has no identity there is no transport. A transport given in
    /// [`Ports::mailbox`] is replaced.
    pub fn set_mailbox_factory(&mut self, factory: ports::MailboxFactory) {
        self.factory = Some(factory);
        self.restart_transport();
    }

    /// Stop the transport and start it again from what the journal says.
    fn restart_transport(&mut self) {
        let Some(factory) = self.factory.as_mut() else {
            return;
        };
        // the old one goes first: two transports must not answer for one identity
        self.ports.mailbox = None;
        self.transport_error = None;
        // a new transport has not been asked anything yet
        self.publish_wait.clear();
        let (Some(identity_secret), Some(store_key), Some(identity)) = (
            self.core.identity_secret(),
            self.core.transport_store_key(),
            self.core.identity(),
        ) else {
            return;
        };
        let spec = ports::TransportSpec {
            identity_secret,
            identity_public: identity.public,
            store_key,
            contacts: self.core.contacts().iter().map(|c| c.key).collect(),
        };
        match factory(&spec) {
            Ok(mailbox) => self.ports.mailbox = Some(mailbox),
            Err(why) => self.transport_error = Some(why.chars().take(200).collect()),
        }
    }

    fn contact_keys(&self) -> Vec<[u8; 32]> {
        self.core.contacts().iter().map(|c| c.key).collect()
    }

    fn identity_json(&self) -> Result<Value, Fail> {
        Ok(match self.core.identity() {
            None => json!({ "public": null }),
            Some(i) => json!({
                "public": hex(&i.public),
                "npub": fly_paycore_wallet::npub_encode(&i.public)?,
                "imported": i.imported,
                "previous": i
                    .previous
                    .iter()
                    .map(fly_paycore_wallet::npub_encode)
                    .collect::<Result<Vec<_>, _>>()?,
            }),
        })
    }

    /// Exchange slates as Slatepack text, the format other Grin wallets
    /// read and write, instead of using the `SlateCodec` port. Text coming
    /// in may be plain or encrypted for this wallet's address; text going
    /// out is plain, so it relies on the channel for privacy: the message
    /// transport encrypts it, a user pasting it by hand should know.
    pub fn set_slatepack(&mut self, on: bool) {
        self.slatepack = on;
    }

    fn decode_text(&mut self, text: &str) -> Result<Vec<u8>, String> {
        if self.slatepack {
            self.core
                .slatepack_decode(text)
                .map_err(|_| "not Slatepack text this wallet can read".to_string())
        } else {
            self.ports.codec.decode(text)
        }
    }

    /// Let replies that arrive through the mailbox be signed without asking
    /// the user. Off by default. It is a host decision and deliberately not
    /// a JSON method. Even when on, signing happens only while the chain
    /// layer reports a selected tip and the wallet state stands on it.
    pub fn set_auto_sign(&mut self, on: bool) {
        self.auto_sign = on;
    }

    /// Smallest amount unattended receive answers through the mailbox.
    pub fn set_min_auto_amount(&mut self, nanogrin: u64) {
        self.min_auto_amount = nanogrin;
    }

    /// The core, for reads by the host.
    pub fn core(&self) -> &Core<D, G, K> {
        &self.core
    }

    /// The core, for the chain layer (`chain_advance`, `chain_rollback`,
    /// `chain_reanchor`, `checkpoint`).
    pub fn core_mut(&mut self) -> &mut Core<D, G, K> {
        &mut self.core
    }

    /// Give the core back (closing the wallet).
    pub fn into_core(self) -> Core<D, G, K> {
        self.core
    }

    /// Handle one JSON-RPC 2.0 request and return the response text. Never
    /// panics on any input. A request without `id` (a notification) is
    /// executed and answered with an empty string. Batches are not supported.
    pub fn call(&mut self, request: &str) -> String {
        if request.len() > MAX_REQUEST_LEN {
            return respond(
                Value::Null,
                Err(fail(-32600, "invalid_request", "too large")),
            );
        }
        let parsed: Value = match serde_json::from_str(request) {
            Ok(v) => v,
            Err(_) => return respond(Value::Null, Err(fail(-32700, "parse_error", ""))),
        };
        let Some(obj) = parsed.as_object() else {
            return respond(Value::Null, Err(fail(-32600, "invalid_request", "")));
        };
        let id = obj.get("id").cloned();
        let valid_id = matches!(
            id,
            None | Some(Value::Null) | Some(Value::Number(_)) | Some(Value::String(_))
        );
        let method = obj.get("method").and_then(Value::as_str);
        let (Some(method), true, Some("2.0")) =
            (method, valid_id, obj.get("jsonrpc").and_then(Value::as_str))
        else {
            return respond(Value::Null, Err(fail(-32600, "invalid_request", "")));
        };
        let empty = Map::new();
        let params = match obj.get("params") {
            None | Some(Value::Null) => &empty,
            Some(Value::Object(m)) => m,
            Some(_) => {
                return respond(
                    id.unwrap_or(Value::Null),
                    Err(bad_params("params must be an object")),
                )
            }
        };
        let result = self.dispatch(method, &Params(params));
        match id {
            Some(id) => respond(id, result),
            None => String::new(),
        }
    }

    fn wallet_basis(&self) -> ports::PaymentBasis {
        let basis = self.ports.chain.payment_basis();
        let state = match basis.state {
            fly_paycore_wallet::ChainState::AtTip
                if basis.selected.is_none() || basis.selected != self.core.tip() =>
            {
                fly_paycore_wallet::ChainState::Behind
            }
            state => state,
        };
        // how many confirmations make an incoming payment "received" is the
        // owner's to say (K190); the chain layer's number stands until they do
        ports::PaymentBasis { state, k_conf: self.k_conf_owner.unwrap_or(basis.k_conf).max(1), ..basis }
    }

    fn slate_in(&mut self, p: &Params<'_>) -> Result<Vec<u8>, Fail> {
        let text = p.text("slate")?;
        self.decode_text(text)
            .map_err(|e| fail(-32030, "codec", &e))
    }

    fn slate_out(&mut self, slate: &[u8]) -> Result<Value, Fail> {
        encode_text(self.slatepack, self.ports.codec.as_mut(), slate)
            .map(Value::String)
            .map_err(|e| fail(-32030, "codec", &e))
    }

    fn finalized(&mut self, fin: &Finalized) -> Result<Value, Fail> {
        let proof = match &fin.payment_proof {
            None => Value::Null,
            Some(p) => json!({
                "amount": p.amount.to_string(),
                "excess": hex(&p.excess),
                "sender_address": hex(&p.sender_address),
                "receiver_address": hex(&p.receiver_address),
                "signature": hex(&p.signature),
            }),
        };
        Ok(json!({
            "tx": hex(&fin.tx),
            "slate": self.slate_out(&fin.s3)?,
            "excess": hex(&fin.excess),
            "payment_proof": proof,
        }))
    }

    fn balance_json(&self) -> Value {
        let b = self.core.balance();
        // While the search for old outputs is under way the sums
        // are what the wallet knows, not all the seed holds: an
        // output may yet be found, and one may yet prove spent.
        // The sums are given as they are, with that said.
        let incomplete = self.core.old_search().is_some_and(|search| search.next.is_some());
        json!({
            "spendable": b.spendable.to_string(),
            "reserved": b.reserved.to_string(),
            "immature": b.immature.to_string(),
            "incomplete": incomplete,
        })
    }

    fn dispatch(&mut self, method: &str, p: &Params<'_>) -> Result<Value, Fail> {
        match method {
            "paycore.info" => Ok(json!({
                "api_version": API_VERSION,
                "max_request_len": MAX_REQUEST_LEN,
                "max_slate_len": fly_paycore_wallet::MAX_SLATE_LEN,
                "max_open_drafts": fly_paycore_wallet::MAX_OPEN_DRAFTS,
                "draft_ttl_secs": fly_paycore_wallet::DRAFT_TTL_SECS,
                "r_undo": fly_paycore_wallet::R_UNDO,
                "tip_height": self.core.tip_height(),
                "auto_receive_since": self.core.auto_receive_since(),
            })),
            "paycore.balance" => Ok(self.balance_json()),
            "paycore.address" => Ok(json!({ "address": hex(&self.core.receive_address()?) })),
            "paycore.history" => {
                let sends: Vec<Value> = self
                    .core
                    .sends()
                    .into_iter()
                    .map(|(op, st, amount, fee)| {
                        json!({
                            "op": hex(&op),
                            "state": status_name(st),
                            "amount": amount.to_string(),
                            "fee": fee.to_string(),
                            "delivery": self.core.delivery_status(&op).map(delivery_name),
                            "reply_held": self.core.send_held(&op).is_some(),
                            "invoice": self.core.send_is_invoice(&op),
                            "locked": self.core.send_locked(&op),
                            "deliver_to": self.core.delivery_contact(&op).map(|key| hex(&key)),
                            "kernel_height": self.core.send_kernel_height(&op),
                            "signed": self.core.send_result(&op).is_some(),
                        })
                    })
                    .collect();
                let drafts = self.core.incomings();
                let basis = (!drafts.is_empty()).then(|| self.wallet_basis());
                let incoming: Vec<Value> = drafts.into_iter()
                    .map(|(id, value, abandoned)| {
                        let evidence = basis.as_ref().and_then(|b| self.core.observe_incoming(&id, b.state, b.k_conf));
                        json!({
                            "status": evidence.as_ref().map(|o| o.status),
                            "status_rule": evidence.as_ref().and_then(|o| o.status_rule).map(|r| format!("{r:?}")),
                            "slate_id": hex(&id),
                            "amount": value.to_string(),
                            "abandoned": abandoned,
                            "kernel_height": self.core.incoming_kernel_height(&id),
                            "reply_kept": self.core.incoming_reply(&id).is_some(),
                        })
                    })
                    .collect();
                let k_conf = self.wallet_basis().k_conf;
                Ok(json!({ "sends": sends, "incoming": incoming, "k_conf": k_conf, "tip_height": self.core.tip_height() }))
            }

            // ----- reading a slate before deciding (K119)
            "paycore.slate.read" => {
                let slate = self.slate_in(p)?;
                let sum = fly_paycore_wallet::slate_summary(&slate)?;
                Ok(json!({
                    "stage": stage_name(sum.stage),
                    "slate_id": hex(&sum.id),
                    // a reply in the compact form does not repeat them: null,
                    // never a zero a window could show as a real amount
                    "amount": (sum.amount > 0).then(|| sum.amount.to_string()),
                    "fee": (sum.fee > 0).then(|| sum.fee.to_string()),
                    "ttl_cutoff_height": sum.ttl_cutoff_height,
                    "sender_address": sum.sender.map(|a| hex(&a)),
                    "receiver_address": sum.receiver.map(|a| hex(&a)),
                }))
            }

            // ----- sending
            "paycore.send.prepare" => {
                let amount = p.amount("amount")?;
                let ttl = p.amount_or("ttl_cutoff_height", 0)?;
                let proof_to = p.bytes_opt::<32>("proof_to")?;
                let replaces = p.bytes_opt::<16>("replaces")?;
                let late = p.flag("late")?;
                let not_a_repeat = p.flag("not_a_repeat")?;
                if let Some(to) = p.bytes_opt::<32>("deliver_to")? {
                    if replaces.is_some() || not_a_repeat {
                        return Err(bad_params(
                            "deliver_to cannot be combined with replaces or not_a_repeat",
                        ));
                    }
                    let slatepack = self.slatepack;
                    let Ports { codec, mailbox, .. } = &mut self.ports;
                    let mailbox = mailbox.as_mut().ok_or_else(no_mailbox)?;
                    let mut seal = |s1: &[u8]| -> Result<Envelope, String> {
                        let text = encode_text(slatepack, codec.as_mut(), s1)?;
                        mailbox.seal(&to, &text)
                    };
                    let prepared = self
                        .core
                        .send_prepare_delivery(amount, ttl, proof_to, late, to, &mut seal)?;
                    // a new payment to a contact gives it a clean slate
                    self.strikes.remove(&to);
                    return Ok(json!({
                        "op": hex(&prepared.op),
                        "slate": self.slate_out(&prepared.s1)?,
                        "delivery": "queued",
                    }));
                }
                let prepared = match (late, proof_to, replaces) {
                    (true, _, None) => self.core.send_prepare_late(amount, ttl, proof_to)?,
                    (true, _, Some(_)) => {
                        return Err(bad_params("late lock cannot replace an operation"))
                    }
                    (false, Some(to), None) => {
                        if not_a_repeat {
                            return Err(bad_params(
                                "proof_to cannot be combined with not_a_repeat",
                            ));
                        }
                        self.core.send_prepare_with_proof(amount, ttl, to)?
                    }
                    (false, Some(_), Some(_)) => {
                        return Err(bad_params("proof_to cannot be combined with replaces"))
                    }
                    (false, None, _) => {
                        self.core
                            .send_prepare(amount, ttl, replaces, not_a_repeat)?
                    }
                };
                Ok(json!({
                    "op": hex(&prepared.op),
                    "slate": self.slate_out(&prepared.s1)?,
                }))
            }
            "paycore.send.finalize" => {
                let op = p.bytes::<16>("op")?;
                let s2 = self.slate_in(p)?;
                let fin = self.core.send_finalize(&op, &s2)?;
                self.finalized(&fin)
            }
            "paycore.send.cancel" => {
                // `release_locked`: the user was told that a payment locked
                // after a rollback may have been signed, and gives it up
                let op = p.bytes::<16>("op")?;
                if p.flag("release_locked")? {
                    self.core.send_release_locked(&op)?;
                } else {
                    self.core.send_cancel(&op)?;
                }
                Ok(json!({}))
            }
            "paycore.send.status" => {
                let op = p.bytes::<16>("op")?;
                let st = self.core.send_status(&op).ok_or(CoreError::NotFound)?;
                let (accepted, rejected, unknown) =
                    self.core.broadcast_attempts(&op).unwrap_or((0, 0, 0));
                let obs = self.core.observe_send(&op).ok_or(CoreError::NotFound)?;
                Ok(json!({
                    "state": status_name(st),
                    "reserve": obs.reserve,
                    "conflict": obs.conflict,
                    "broadcasts": { "accepted": accepted, "rejected": rejected, "unknown": unknown },
                    "delivery": self.core.delivery_status(&op).map(delivery_name),
                    "reply_held": self.core.send_held(&op).is_some(),
                }))
            }
            "paycore.send.finalize_held" => {
                // the user looked at the payment and confirmed it
                let op = p.bytes::<16>("op")?;
                let fin = self.core.send_finalize_held(&op)?;
                self.finalized(&fin)
            }

            // ----- transport identity and contacts
            "paycore.identity.get" => self.identity_json(),
            "paycore.identity.create" => {
                self.core.identity_create(p.flag("replace")?)?;
                self.restart_transport();
                self.identity_json()
            }
            "paycore.identity.import" => {
                let secret = fly_paycore_wallet::nsec_decode(p.text("nsec")?)
                    .map_err(|_| bad_params("nsec"))?;
                self.core.identity_import(&secret, p.flag("replace")?)?;
                self.restart_transport();
                self.identity_json()
            }
            "paycore.identity.export" => {
                // the backup of the identity; whoever reads it can speak as
                // this wallet on the transport, though not spend from it
                let secret = self.core.identity_secret().ok_or(CoreError::NotFound)?;
                let nsec = fly_paycore_wallet::nsec_encode(&secret)?;
                Ok(json!({ "nsec": nsec.as_str() }))
            }
            "paycore.contacts.list" => {
                let list = self
                    .core
                    .contacts()
                    .iter()
                    .map(|c| {
                        Ok(json!({
                            "key": hex(&c.key),
                            "npub": fly_paycore_wallet::npub_encode(&c.key)?,
                            "name": c.name,
                            "address": c.address.as_ref().map(|a| hex(a)),
                        }))
                    })
                    .collect::<Result<Vec<Value>, Fail>>()?;
                Ok(json!({ "contacts": list }))
            }
            "paycore.contacts.set" => {
                let key = match p.bytes_opt::<32>("key")? {
                    Some(k) => k,
                    None => fly_paycore_wallet::npub_decode(p.text("npub")?)
                        .map_err(|_| bad_params("npub"))?,
                };
                let before = self.contact_keys();
                self.core
                    .contact_set(key, p.text("name")?, p.bytes_opt::<32>("address")?)?;
                if before != self.contact_keys() {
                    self.restart_transport();
                }
                Ok(json!({}))
            }
            // ----- text messages to contacts (K120–K122)
            "paycore.messages.send" => {
                let to = p.bytes::<32>("key")?;
                let text = p.text("text")?.to_string();
                let at = unix_now();
                let Ports { mailbox, .. } = &mut self.ports;
                let mailbox = mailbox.as_mut().ok_or_else(no_mailbox)?;
                let mut seal = |wire: &str| mailbox.seal(&to, wire);
                let id = self.core.message_send(to, &text, at, &mut seal)?;
                Ok(json!({ "id": hex(&id), "state": "waiting" }))
            }
            "paycore.messages.list" => {
                let with = p.bytes::<32>("key")?;
                let list: Vec<Value> = self
                    .core
                    .messages(&with)
                    .into_iter()
                    .map(|m| {
                        json!({
                            "id": hex(&m.id),
                            "dir": if m.out { "out" } else { "in" },
                            "at": m.at,
                            "text": m.text,
                            "state": message_state_name(m.state),
                        })
                    })
                    .collect();
                Ok(json!({ "messages": list }))
            }
            "paycore.messages.summary" => {
                let list: Vec<Value> = self
                    .core
                    .conversations()
                    .into_iter()
                    .map(|(key, count, at, out)| {
                        json!({ "key": hex(&key), "count": count, "last_at": at, "last_dir": if out { "out" } else { "in" } })
                    })
                    .collect();
                Ok(json!({ "conversations": list }))
            }
            "paycore.contacts.remove" => {
                let key = p.bytes::<32>("key")?;
                self.core.contact_remove(&key)?;
                self.restart_transport();
                Ok(json!({}))
            }
            "paycore.transport.status" => Ok(json!({
                "identity": self.core.identity().is_some(),
                "running": self.ports.mailbox.is_some(),
                "error": self.transport_error,
            })),
            "paycore.transport.restart" => {
                self.restart_transport();
                Ok(json!({
                    "running": self.ports.mailbox.is_some(),
                    "error": self.transport_error,
                }))
            }

            // ----- delivery through the message transport
            "paycore.chain.sync" => self.chain_sync(),
            // what the core's decisions are made against, asked now
            "paycore.wallet.chain_status" => {
                let basis = self.wallet_basis();
                let balance = self.balance_json();
                Ok(json!({
                    "balance": balance,
                    "state": match basis.state {
                        fly_paycore_wallet::ChainState::AtTip => "at_tip",
                        fly_paycore_wallet::ChainState::Behind => "behind",
                        fly_paycore_wallet::ChainState::Unknown => "unknown",
                    },
                    "selected_height": basis.selected.map(|(height, _)| height),
                    "tip_height": self.core.tip_height(),
                }))
            }
            "paycore.chain.status" => Ok(json!({
                "state": match self.ports.chain.chain_state() {
                    fly_paycore_wallet::ChainState::AtTip => "at_tip",
                    fly_paycore_wallet::ChainState::Behind => "behind",
                    fly_paycore_wallet::ChainState::Unknown => "unknown",
                },
                "k_conf": self.ports.chain.k_conf(),
                "rangeproofs_authenticated": self.ports.chain.rangeproofs_authenticated(),
                "selected_height": self.ports.chain.selected_tip().map(|(height, _)| height),
                "confirmed_time": self.ports.clock.confirmed_time(),
                "tip_height": self.core.tip_height(),
            })),
            // K188: a starting point made by the chain layer from the chain
            // it verified; the reason there is none is the layer's own
            "paycore.chain.point" => {
                let feed = self.feed.as_mut().ok_or_else(no_chain)?;
                match feed.point().map(String::from_utf8) {
                    Ok(Ok(point)) if !point.is_empty() => Ok(json!({ "point": point })),
                    Ok(_) => Err(fail(-32033, "no_point", "the starting point made is not text")),
                    Err(why) => Err(fail(-32033, "no_point", &why)),
                }
            }
            // the search for outputs older than the wallet's blocks
            "paycore.search.start" => {
                self.core.old_search_start()?;
                Ok(self.search_json())
            }
            "paycore.search.status" => Ok(self.search_json()),
            // Where the time of following the chain went since the profile
            // was opened: a measurement for whoever tunes the program, with
            // nothing of the wallet's contents in it. Milliseconds.
            "paycore.chain.timing" => {
                let ms = |d: Duration| u64::try_from(d.as_millis()).unwrap_or(u64::MAX);
                let wallet = self.core.timing();
                Ok(json!({
                    "rounds": self.asked.rounds,
                    "blocks": { "asked": self.asked.steps, "ask_ms": ms(self.asked.steps_took) },
                    "pieces": { "read": self.asked.pieces, "not_ready": self.asked.not_ready, "ask_ms": ms(self.asked.pieces_took) },
                    "wallet": {
                        "events": wallet.events,
                        "keys_ms": ms(wallet.keys),
                        "check_ms": ms(wallet.check),
                        "write_ms": ms(wallet.write),
                        "apply_ms": ms(wallet.apply),
                    },
                }))
            }
            "paycore.delivery.pump" => self.delivery_pump(p.flag("now")?),
            "paycore.delivery.receive" => self.delivery_receive(),
            "paycore.delivery.reply" => {
                // the user approved an incoming payment by hand; the reply
                // goes back the way the payment came
                let id = p.bytes::<32>("id")?;
                let text = p.text("slate")?;
                let mailbox = self.ports.mailbox.as_mut().ok_or_else(no_mailbox)?;
                let outcome = match mailbox.resend_reply(&id) {
                    Some(o) => o,
                    None => mailbox.reply(&id, text),
                };
                let sent = outcome == Published::Accepted;
                if sent {
                    mailbox.done(&id);
                }
                Ok(json!({ "sent": sent }))
            }
            "paycore.delivery.ack" => {
                let id = p.bytes::<32>("id")?;
                self.ports
                    .mailbox
                    .as_mut()
                    .ok_or_else(no_mailbox)?
                    .done(&id);
                Ok(json!({}))
            }
            "paycore.send.review" => {
                let op = p.bytes::<16>("op")?;
                let review = self.core.prepared_slate(&op)?;
                // the stored S1 again, for a payment passed on by hand
                let s1 = self.core.prepared_s1(&op)?;
                Ok(json!({ "op": hex(&op), "amount": review.amount.to_string(), "fee": review.fee.to_string(),
                    "receiver_address": review.receiver.map(|key| hex(&key)),
                    "slate_id": hex(&review.id), "slate": self.slate_out(&s1)? }))
            }
            "paycore.send.result" => {
                let op = p.bytes::<16>("op")?;
                let fin = self.core.send_result(&op).ok_or(CoreError::NotFound)?;
                self.finalized(&fin)
            }
            "paycore.send.broadcast" => {
                let op = p.bytes::<16>("op")?;
                let fin = self.core.send_result(&op).ok_or(CoreError::NotFound)?;
                if fin.tx.is_empty() {
                    return Err(CoreError::Refused("the payee broadcasts a paid invoice").into());
                }
                // the same stored bytes every time; nothing is signed here.
                // `direct`: the owner agrees that this one payment may go out
                // from this computer's address if Tor fails to send it (K192)
                let outcome = if p.flag("direct")? {
                    self.ports.broadcaster.post_tx_direct(&fin.tx)
                } else {
                    self.ports.broadcaster.post_tx(&fin.tx)
                };
                self.core.send_broadcast_result(&op, outcome)?;
                self.posted.insert(op, (Instant::now(), outcome));
                Ok(json!({ "outcome": outcome_name(outcome) }))
            }
            "paycore.send.pump" => self.send_pump(),

            // ----- payments to and from an address through Tor (K151-K158)
            "paycore.onion.status" => Ok(self.onion_status()),
            "paycore.onion.send" => self.onion_send(&p.bytes::<16>("op")?),
            "paycore.onion.pump" => self.onion_pump(),
            "paycore.onion.accept" => self.onion_accept(p.amount("id")?),
            "paycore.onion.decline" => {
                self.onion_decline(p.amount("id")?);
                Ok(json!({}))
            }

            // ----- receiving
            "paycore.receive.draft" => {
                let s1 = self.slate_in(p)?;
                let now = self.ports.clock.confirmed_time();
                let s2 = self.core.receive_draft(&s1, now)?;
                Ok(json!({ "slate": self.slate_out(&s2)? }))
            }
            "paycore.receive.auto" => {
                let s1 = self.slate_in(p)?;
                let min = p.amount_or("min_amount", 0)?;
                let s2 = self.core.receive_stateless(&s1, min)?;
                Ok(json!({ "slate": self.slate_out(&s2)? }))
            }
            "paycore.receive.set_auto" => {
                let on = match p.0.get("on") {
                    Some(Value::Bool(b)) => *b,
                    _ => return Err(bad_params("on")),
                };
                let authenticated = self.ports.chain.rangeproofs_authenticated();
                self.core.set_auto_receive(on, authenticated)?;
                Ok(json!({ "auto_receive_since": self.core.auto_receive_since() }))
            }
            "paycore.receive.status" => {
                let id = p.bytes::<16>("slate_id")?;
                let ports::PaymentBasis { state, k_conf, .. } = self.wallet_basis();
                let obs = self
                    .core
                    .observe_incoming(&id, state, k_conf)
                    .ok_or(CoreError::NotFound)?;
                Ok(obs.to_json())
            }
            // K191: the reply made to an incoming payment, again, as it is kept
            "paycore.receive.reply" => {
                let id = p.bytes::<16>("slate_id")?;
                let s2 = self.core.incoming_reply(&id).ok_or(CoreError::NotFound)?;
                Ok(json!({ "slate": self.slate_out(&s2)? }))
            }
            // K190: how many confirmations make an incoming payment "received"
            "paycore.settings.confirmations" => {
                let count = p.amount("count")?;
                if !(1..=MAX_K_CONF).contains(&count) {
                    return Err(bad_params("count"));
                }
                self.k_conf_owner = Some(count);
                Ok(json!({ "k_conf": count }))
            }
            "paycore.receive.abandon" => {
                self.core.draft_abandon(&p.bytes::<16>("slate_id")?)?;
                Ok(json!({}))
            }
            "paycore.receive.expire" => {
                let now = self.ports.clock.confirmed_time();
                let closed = self.core.drafts_expire(now)?;
                Ok(json!({ "closed": closed }))
            }

            // ----- invoices
            "paycore.invoice.issue" => {
                let amount = p.amount("amount")?;
                let now = self.ports.clock.confirmed_time();
                let (id, i1) = self.core.invoice_issue(amount, now)?;
                Ok(json!({ "slate_id": hex(&id), "slate": self.slate_out(&i1)? }))
            }
            "paycore.invoice.finalize" => {
                let id = p.bytes::<16>("slate_id")?;
                let i2 = self.slate_in(p)?;
                let fin = self.core.invoice_finalize(&id, &i2)?;
                self.finalized(&fin)
            }
            "paycore.invoice.review" => {
                // the wallet's own numbers for the screen; reads only
                let i1 = self.slate_in(p)?;
                let review = self.core.invoice_review(&i1)?;
                Ok(json!({
                    "slate_id": hex(&review.id),
                    "amount": review.amount.to_string(),
                    "fee": review.fee.to_string(),
                    "ttl_cutoff_height": review.ttl_cutoff_height,
                    "paid_op": review.paid.map(|op| hex(&op)),
                }))
            }
            "paycore.invoice.pay" => {
                // `max_amount` and `max_fee` are what the user agreed to on
                // screen; without `max_fee` only the amount is held to
                let max = p.amount("max_amount")?;
                let max_fee = p.amount_or("max_fee", u64::MAX)?;
                let i1 = self.slate_in(p)?;
                let (op, i2) = self.core.invoice_pay_agreed(&i1, max, max_fee)?;
                Ok(json!({ "op": hex(&op), "slate": self.slate_out(&i2)? }))
            }
            _ => Err(fail(-32601, "method_not_found", "")),
        }
    }

    /// Follow the chain layer: tell it where the wallet stands and apply
    /// what it says comes next, until it has nothing new, cannot say, or
    /// [`MAX_CHAIN_STEPS`] steps were taken. The wallet's position is read
    /// from the journal before every step, so a step is never applied on
    /// top of anything but the block it was asked for.
    fn chain_sync(&mut self) -> Result<Value, Fail> {
        // until this call has run to "nothing new", the wallet may be behind
        self.at_tip = false;
        let feed = self.feed.as_mut().ok_or_else(no_chain)?;
        let (mut applied, mut rolled_back, mut reanchored, mut unknown) = (0u32, 0u32, false, false);
        let mut left = MAX_CHAIN_STEPS;
        let mut at_tip = false;
        self.asked.rounds = self.asked.rounds.saturating_add(1);
        let more = loop {
            if left == 0 {
                break true;
            }
            left = left.saturating_sub(1);
            let at = self.core.tip().map(|(height, hash)| Tip { height, hash });
            let asking = Instant::now();
            let step = feed.next(at);
            self.asked.steps = self.asked.steps.saturating_add(1);
            self.asked.steps_took = self.asked.steps_took.saturating_add(asking.elapsed());
            match step {
                Err(_) => {
                    // not "nothing new": the chain layer could not say
                    unknown = true;
                    break false;
                }
                Ok(Step::Nothing) => {
                    at_tip = true;
                    break false;
                }
                Ok(Step::Block(block)) => {
                    let mut advance = Advance {
                        height: block.height,
                        hash: block.hash,
                        v_delta: block.v_delta.clone(),
                        ..Advance::default()
                    };
                    for o in &block.outputs {
                        if !advance.push_output(&o.commit, &o.proof, o.pos, o.coinbase) {
                            return Err(CoreError::Refused("a block with a malformed range proof").into());
                        }
                    }
                    block.inputs.iter().for_each(|c| advance.push_input(c));
                    block.kernels.iter().for_each(|c| advance.push_kernel(c));
                    self.core.chain_advance(&advance)?;
                    applied = applied.saturating_add(1);
                }
                Ok(Step::Rollback { to }) => {
                    self.core.chain_rollback(to)?;
                    rolled_back = rolled_back.saturating_add(1);
                }
                Ok(Step::ReanchorExtending(tip)) => {
                    self.core.chain_reanchor_extending(tip.height, tip.hash)?;
                    reanchored = true;
                }
                Ok(Step::Reanchor(tip)) => {
                    self.core.chain_reanchor(tip.height, tip.hash)?;
                    reanchored = true;
                }
            }
        };
        // The old outputs are read only by a wallet that has every block
        // the chain layer has: a piece says what is unspent after the last
        // of them.
        let (mut read, mut more_old) = (0usize, false);
        if at_tip {
            let started = Instant::now();
            while let Some((next, since)) = self.core.old_search().and_then(|s| Some((s.next?, s.since))) {
                if read >= MAX_OLD_PIECES || started.elapsed() >= OLD_BUDGET {
                    more_old = true;
                    break;
                }
                // "cannot say" is not "an empty piece": the piece is asked for again.
                // The chain layer fetches pieces as they are read: while pieces
                // have been coming, the next one is on its way and is asked for
                // without the pause; once none has come for a while, it is not.
                let asking = Instant::now();
                // A wallet that knew its outputs up to a block says so:
                // what was there by that block may come without range
                // proofs, and is not fetched from anybody.
                let answer = match since {
                    Some((height, hash)) => feed.old_outputs_since(next, Tip { height, hash }),
                    None => feed.old_outputs(next),
                };
                self.asked.pieces_took = self.asked.pieces_took.saturating_add(asking.elapsed());
                let Ok(old) = answer else {
                    self.asked.not_ready = self.asked.not_ready.saturating_add(1);
                    more_old = self.old_read_at.is_some_and(|at| at.elapsed() < self.old_coming_for);
                    break;
                };
                self.asked.pieces = self.asked.pieces.saturating_add(1);
                if !(if since.is_some() { old.answers_since(next) } else { old.answers(next) }) {
                    break;
                }
                if self.core.tip() != Some((old.at.height, old.at.hash)) {
                    // the chain layer has a block the wallet has not: that first
                    more_old = true;
                    break;
                }
                let mut piece = OldPiece {
                    piece: next,
                    last: old.next.is_none(),
                    pieces: old.pieces,
                    before: old.before,
                    at: (old.at.height, old.at.hash),
                    outputs: Vec::new(),
                    bare: old.bare.then(|| old.outputs.iter().map(|o| (o.commit, o.pos)).collect()),
                };
                if !old.bare {
                    for o in &old.outputs {
                        if !piece.push_output(&o.commit, &o.proof, o.pos, o.coinbase) {
                            return Err(CoreError::Refused("an old output with a malformed range proof").into());
                        }
                    }
                }
                self.core.old_apply(&piece)?;
                read = read.saturating_add(1);
                self.old_read_at = Some(Instant::now());
            }
        }
        self.at_tip = at_tip;
        // The journal is folded as it grows (5.5, K118): every block writes
        // a frame, and a journal never folded would grow without end and in
        // the end be too long to open.
        if self.core.journal_frames() >= self.fold_after {
            self.core.checkpoint(None)?;
        }
        let tip_height = self.core.tip_height();
        let changed = applied > 0 || rolled_back > 0 || reanchored;
        let summary = json!({
            "applied": applied,
            "rolled_back": rolled_back,
            "reanchored": reanchored,
            "tip_height": tip_height,
        });
        let mut events = if changed { vec![summary] } else { Vec::new() };
        if read > 0 {
            events.push(json!({ "search": self.search_json() }));
        }
        Ok(json!({
            "chain": events,
            "tip_height": tip_height,
            "more": more || more_old,
            "unknown": unknown,
        }))
    }

    /// Where the search for old outputs stands.
    /// Hand one finished transaction that is not in the chain yet to the
    /// chain layer: the one that was handed over longest ago, if that was
    /// [`BROADCAST_EVERY`] ago or more. One at a time, because the answer
    /// is waited for and requests of the interface wait meanwhile.
    ///
    /// Only a wallet that has every block the chain layer has does this:
    /// a transaction whose block the wallet has not read yet is not in the
    /// chain as far as the wallet knows, and the chain layer - which
    /// forgets what it sent when it is restarted - would find its inputs
    /// spent and call it refused.
    ///
    /// The same stored bytes every time; nothing is signed here. The
    /// outcome is written to the journal only when it is not the one this
    /// handler got for that transaction last time, so that asking again
    /// and again does not fill the journal.
    fn send_pump(&mut self) -> Result<Value, Fail> {
        let nothing = || Ok(json!({ "broadcast": [] }));
        if !self.at_tip {
            return nothing();
        }
        let waiting: Vec<[u8; 16]> = self
            .core
            .sends()
            .into_iter()
            .filter(|(_, status, _, _)| *status == SendStatus::Finalized)
            .map(|(op, _, _, _)| op)
            .collect();
        // Invoices this wallet issued and completed: the transaction is
        // here and nowhere else - the payer signed first and never had it.
        let invoices = self.core.invoices_to_broadcast();
        self.posted.retain(|op, _| waiting.contains(op));
        self.posted_invoices.retain(|slate, _| invoices.iter().any(|(id, _)| id == slate));
        let now = Instant::now();
        let ready = |last: Option<&(Instant, Broadcast)>| last.is_none_or(|(at, _)| now.saturating_duration_since(*at) >= self.broadcast_every);
        // one transaction a call: the one handed over longest ago, of
        // either kind; one never handed over comes first
        let due_send = waiting
            .iter()
            .filter(|op| ready(self.posted.get(*op)))
            .min_by_key(|op| self.posted.get(*op).map(|(at, _)| *at))
            .copied();
        let due_invoice = invoices
            .iter()
            .filter(|(slate, _)| ready(self.posted_invoices.get(slate)))
            .min_by_key(|(slate, _)| self.posted_invoices.get(slate).map(|(at, _)| *at));
        let last_send = due_send.map(|op| self.posted.get(&op).map(|(at, _)| *at));
        let last_invoice = due_invoice.map(|(slate, _)| self.posted_invoices.get(slate).map(|(at, _)| *at));
        let invoice_first = match (last_send, last_invoice) {
            (_, None) => false,
            (None, Some(_)) => true,
            (Some(send), Some(invoice)) => invoice < send,
        };
        if invoice_first {
            let Some((slate, tx)) = due_invoice else {
                return nothing();
            };
            let before = self.posted_invoices.get(slate).map(|(_, outcome)| *outcome);
            let outcome = self.ports.broadcaster.post_tx(tx);
            self.posted_invoices.insert(*slate, (now, outcome));
            if before == Some(outcome) {
                return nothing();
            }
            // nothing of this is written: the invoice's record changes
            // when its kernel is in a block, not when it was handed over
            return Ok(json!({ "broadcast": [{ "invoice": hex(slate), "outcome": outcome_name(outcome) }] }));
        }
        let Some(op) = due_send else {
            return nothing();
        };
        let fin = self.core.send_result(&op).ok_or(CoreError::NotFound)?;
        let before = self.posted.get(&op).map(|(_, outcome)| *outcome);
        if fin.tx.is_empty() {
            // a paid invoice: the payee has the transaction, not this wallet
            self.posted.insert(op, (now, Broadcast::Unknown));
            return nothing();
        }
        let outcome = self.ports.broadcaster.post_tx(&fin.tx);
        self.posted.insert(op, (now, outcome));
        if before == Some(outcome) {
            return nothing();
        }
        self.core.send_broadcast_result(&op, outcome)?;
        Ok(json!({ "broadcast": [{ "op": hex(&op), "outcome": outcome_name(outcome) }] }))
    }

    fn search_json(&self) -> Value {
        match self.core.old_search() {
            None => json!({ "state": "none" }),
            Some(s) => {
                let mut view = json!({
                    "state": if s.next.is_some() { "reading" } else { "done" },
                    "next": s.next,
                    "pieces": s.pieces,
                    "found": s.found,
                    "gone": s.gone,
                });
                // a search that began with a block the wallet knew its
                // outputs up to says which: a height, nothing else
                if let (Some((height, _)), Some(map)) = (s.since, view.as_object_mut()) {
                    map.insert("since".to_string(), json!(height));
                }
                view
            }
        }
    }

    /// Publish the envelopes that still wait for a relay. Each envelope is
    /// read from the journal and published byte for byte; what the relay
    /// answers is noted and changes nothing about the payment. An envelope
    /// that was not accepted waits before it is offered again, longer each
    /// time; `now` (the user asked) offers every waiting envelope at once.
    fn delivery_pump(&mut self, now: bool) -> Result<Value, Fail> {
        let mailbox = self.ports.mailbox.as_mut().ok_or_else(no_mailbox)?;
        let confirmed = self.ports.clock.confirmed_time();
        let pending = self.core.delivery_pending();
        let at = Instant::now();
        self.publish_wait.retain(|op, _| pending.contains(op));
        let due: Vec<_> = pending
            .iter()
            .filter(|op| now || self.publish_wait.get(*op).is_none_or(|(until, _)| at >= *until))
            .copied()
            .collect();
        let turn = due.len().min(MAX_PUMP);
        let start = self.pump_cursor.checked_rem(due.len()).unwrap_or(0);
        self.pump_cursor = start.wrapping_add(turn);
        let (first, longest) = self.publish_retry;
        let mut out = Vec::new();
        for op in due.iter().cycle().skip(start).take(turn) {
            let Some(envelope) = self.core.delivery_envelope(op) else {
                continue;
            };
            let note = if confirmed.is_some_and(|t| t >= envelope.expires_at) {
                DeliveryNote::Expired
            } else {
                match mailbox.publish(&envelope) {
                    Published::Accepted => DeliveryNote::RelayAccepted,
                    Published::Unknown => DeliveryNote::RelayUnknown,
                    Published::Busy => DeliveryNote::QueueBusy,
                    Published::Full => DeliveryNote::QueueFull,
                    Published::Expired => DeliveryNote::Expired,
                }
            };
            let pause = match note {
                DeliveryNote::RelayAccepted | DeliveryNote::Expired => None,
                // the relay was asked and did not accept: longer each time
                DeliveryNote::RelayUnknown => Some(match self.publish_wait.get(op) {
                    Some((_, last)) => last.saturating_mul(2).min(longest),
                    None => first,
                }),
                // the transport did not get as far as a relay: soon again
                DeliveryNote::QueueBusy | DeliveryNote::QueueFull => Some(first),
            };
            match pause.and_then(|p| at.checked_add(p).map(|until| (until, p))) {
                Some(wait) => self.publish_wait.insert(*op, wait),
                None => self.publish_wait.remove(op),
            };
            self.core.delivery_note(op, note)?;
            out.push(json!({
                "op": hex(op),
                "delivery": self.core.delivery_status(op).map(delivery_name),
            }));
        }
        let mut sent = Vec::new();
        let messages = self.core.message_pending();
        self.message_wait.retain(|id, _| messages.contains(id));
        let due: Vec<[u8; 32]> = messages
            .iter()
            .filter(|id| now || self.message_wait.get(*id).is_none_or(|(until, _)| at >= *until))
            .take(MAX_PUMP)
            .copied()
            .collect();
        for id in &due {
            let Some(envelope) = self.core.message_envelope(id) else {
                continue;
            };
            let expired = confirmed.is_some_and(|t| t >= envelope.expires_at);
            let outcome = if expired { Published::Expired } else { mailbox.publish(&envelope) };
            let pause = match outcome {
                Published::Accepted | Published::Expired => None,
                Published::Unknown => Some(match self.message_wait.get(id) {
                    Some((_, last)) => last.saturating_mul(2).min(longest),
                    None => first,
                }),
                Published::Busy | Published::Full => Some(first),
            };
            match pause.and_then(|p| at.checked_add(p).map(|until| (until, p))) {
                Some(wait) => self.message_wait.insert(*id, wait),
                None => self.message_wait.remove(id),
            };
            // only what settles the message is written; retries are not
            match outcome {
                Published::Accepted => self.core.message_note(id, true)?,
                Published::Expired => self.core.message_note(id, false)?,
                _ => {}
            }
            sent.push(json!({
                "message": hex(id),
                "state": match outcome {
                    Published::Accepted => "relay_accepted",
                    Published::Expired => "expired",
                    _ => "waiting",
                },
            }));
        }
        let waiting = pending
            .len()
            .saturating_sub(out.len())
            .saturating_add(messages.len().saturating_sub(sent.len()));
        out.extend(sent);
        Ok(json!({ "published": out, "waiting": waiting }))
    }

    fn strike(&mut self, from: &[u8; 32]) {
        if let Some(n) = self.strikes.get_mut(from) {
            *n = n.saturating_add(1);
        } else if self.strikes.len() < MAX_TRACKED_SENDERS {
            self.strikes.insert(*from, 1);
        }
    }

    /// Take messages from the transport. Everything here is untrusted input
    /// from the network; see the limits at the top of this file.
    fn delivery_receive(&mut self) -> Result<Value, Fail> {
        if self.ports.mailbox.is_none() {
            return Err(no_mailbox());
        }
        let mut per_sender: BTreeMap<[u8; 32], u32> = BTreeMap::new();
        let mut events = Vec::new();
        // replies kept earlier are signed once the selected tip allows it
        if self.auto_sign {
            if let Some(sel) = self.ports.chain.selected_tip() {
                for op in self.core.held_ops() {
                    let kind = match self.core.send_finalize_held_at(&op, sel) {
                        Ok(_) => "reply_signed",
                        Err(CoreError::Refused(_)) => continue,
                        Err(CoreError::UnknownOutcome) => "unknown_outcome",
                        Err(e) => return Err(e.into()),
                    };
                    events.push(json!({ "kind": kind, "op": hex(&op) }));
                }
            }
        }
        for _ in 0..MAX_RECEIVE {
            let Some(msg) = self
                .ports
                .mailbox
                .as_mut()
                .and_then(|m| m.next_incoming())
            else {
                break;
            };
            let (kind, ack, extra) = self.handle_incoming(&msg, &mut per_sender)?;
            if ack {
                if let Some(m) = self.ports.mailbox.as_mut() {
                    m.done(&msg.id);
                }
            }
            let mut event = Map::new();
            event.insert("kind".into(), kind.into());
            event.insert("from".into(), hex(&msg.from).into());
            event.insert("id".into(), hex(&msg.id).into());
            for (k, v) in extra {
                event.insert(k.into(), v);
            }
            events.push(Value::Object(event));
        }
        Ok(json!({ "events": events }))
    }

    /// Decide what one incoming message is and act on it. Returns the kind
    /// for the UI, whether the transport may forget the message, and extra
    /// fields. Only a storage failure is an error; it leaves the message
    /// with the transport.
    fn handle_incoming(
        &mut self,
        msg: &Incoming,
        per_sender: &mut BTreeMap<[u8; 32], u32>,
    ) -> Result<Handled, Fail> {
        let dropped = |why: &'static str| Ok(("dropped", true, vec![("reason", why.into())]));
        let known = self.strikes.get(&msg.from).copied();
        if known.is_some_and(|n| n >= MAX_STRIKES) {
            return dropped("sender is muted");
        }
        if known.is_none() && self.strikes.len() >= MAX_TRACKED_SENDERS {
            return dropped("too many senders");
        }
        let seen = per_sender.entry(msg.from).or_insert(0);
        if *seen >= MAX_PER_SENDER {
            return Ok(("deferred", false, vec![]));
        }
        *seen = seen.saturating_add(1);
        if msg.text.len() > MAX_INCOMING_TEXT {
            self.strike(&msg.from);
            return dropped("too large");
        }
        // words for a person: kept, never parsed as a slate (K120)
        if let Some(body) = msg.text.strip_prefix(MESSAGE_PREFIX) {
            return match self.core.message_received(msg.from, msg.id, body, unix_now()) {
                Ok(_) => Ok(("message", true, vec![])),
                Err(CoreError::Refused("not a contact")) => dropped("not a contact"),
                Err(CoreError::Refused(r)) => {
                    self.strike(&msg.from);
                    dropped(r)
                }
                Err(e) => Err(e.into()),
            };
        }
        let auto_receive = self.core.auto_receive_since().is_some();
        let slate = match self.decode_text(&msg.text) {
            Ok(s) => s,
            Err(_) => {
                self.strike(&msg.from);
                return dropped("not a slate");
            }
        };
        let stage = match slate_stage(&slate) {
            Ok(s) => s,
            Err(_) => {
                self.strike(&msg.from);
                return dropped("not a slate");
            }
        };
        match stage {
            SlateStage::S2 => {
                let op = match self.core.send_find_for_reply(&slate, &msg.from) {
                    Ok(op) => op,
                    Err(CoreError::BadSlate(_)) | Err(CoreError::NotFound) => {
                        self.strike(&msg.from);
                        return dropped("reply to nothing we sent");
                    }
                    Err(CoreError::Refused(r)) => return dropped(r),
                    Err(CoreError::Conflict) => return dropped("another reply was already chosen"),
                    Err(e) => return Err(e.into()),
                };
                match self.core.send_hold_reply(&op, &slate) {
                    Ok(()) => {}
                    Err(CoreError::BadSlate(_)) => {
                        self.strike(&msg.from);
                        return dropped("reply does not match what was sent");
                    }
                    Err(CoreError::Refused(r)) => return dropped(r),
                    Err(CoreError::Conflict) => return dropped("another reply was already chosen"),
                    Err(e) => return Err(e.into()),
                }
                let op_field = ("op", Value::String(hex(&op)));
                if self.auto_sign {
                    if let Some(sel) = self.ports.chain.selected_tip() {
                        match self.core.send_finalize_held_at(&op, sel) {
                            Ok(_) => return Ok(("reply_signed", true, vec![op_field])),
                            // not on the selected tip, or closed meanwhile:
                            // the reply stays held for the user
                            Err(CoreError::Refused(_)) => {}
                            Err(CoreError::UnknownOutcome) => {
                                return Ok(("unknown_outcome", true, vec![op_field]))
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                Ok(("reply_held", true, vec![op_field]))
            }
            SlateStage::S1 => {
                if !auto_receive {
                    // the user decides; the host acknowledges afterwards
                    return Ok((
                        "needs_approval",
                        false,
                        vec![("slate", Value::String(msg.text.clone()))],
                    ));
                }
                let stored = self
                    .ports
                    .mailbox
                    .as_mut()
                    .and_then(|m| m.resend_reply(&msg.id));
                let outcome = match stored {
                    Some(o) => o,
                    None => {
                        let reply = match self.core.receive_stateless(&slate, self.min_auto_amount)
                        {
                            Ok(s2) => s2,
                            Err(CoreError::BadSlate(_)) => {
                                self.strike(&msg.from);
                                return dropped("not a payment we can receive");
                            }
                            Err(CoreError::Refused(r)) => return dropped(r),
                            Err(e) => return Err(e.into()),
                        };
                        let text = match encode_text(
                            self.slatepack,
                            self.ports.codec.as_mut(),
                            &reply,
                        ) {
                            Ok(t) => t,
                            Err(_) => return Ok(("reply_pending", false, vec![])),
                        };
                        match self.ports.mailbox.as_mut() {
                            Some(m) => m.reply(&msg.id, &text),
                            None => Published::Unknown,
                        }
                    }
                };
                match outcome {
                    Published::Accepted => Ok(("payment_answered", true, vec![])),
                    _ => Ok(("reply_pending", false, vec![])),
                }
            }
            _ => dropped("unsupported message"),
        }
    }
}

fn respond(id: Value, result: Result<Value, Fail>) -> String {
    let body = match result {
        Ok(v) => json!({ "jsonrpc": "2.0", "id": id, "result": v }),
        Err(f) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": f.code,
                "message": f.kind,
                "data": { "kind": f.kind, "reason": f.reason },
            },
        }),
    };
    body.to_string()
}
