//! Ports: what the payment core needs from the outside world. The host
//! (today the Rust service behind the Flutter app) implements them; the core
//! and the bridge never reach for the network, the clock or the screen
//! themselves.
use fly_paycore_wallet::{Broadcast, ChainState};
pub use fly_paycore_mailbox::{Envelope, Incoming, Mailbox, Published};

/// Hands a finalized transaction to the network.
pub trait Broadcaster {
    /// Post the serialized transaction. A timeout or a lost connection is
    /// `Broadcast::Unknown`, never `Rejected`.
    fn post_tx(&mut self, tx: &[u8]) -> Broadcast;
}

/// Time the wallet may rely on (specification 7.2: confirmed time).
pub trait Clock {
    /// Seconds of confirmed time, or `None` while the clock is not confirmed.
    fn confirmed_time(&self) -> Option<u64>;
}

/// Evidence for a payment observation, taken from a single chain snapshot.
pub struct PaymentBasis {
    /// Status allowed by the chain layer, including provisional selection.
    pub state: ChainState,
    /// Height and hash selected in this snapshot.
    pub selected: Option<(u64, [u8; 32])>,
    /// Number of confirmations required by this snapshot.
    pub k_conf: u64,
}

/// What the chain layer (the Fly core) currently knows.
pub trait ChainView {
    /// Until a provider implements a coherent snapshot it cannot confirm a receipt.
    fn payment_basis(&self) -> PaymentBasis {
        PaymentBasis { state: ChainState::Unknown, selected: None, k_conf: self.k_conf() }
    }
    /// The "state" axis of Level 5 for status rows.
    fn chain_state(&self) -> ChainState;
    /// Confirmations required for "confirmed".
    fn k_conf(&self) -> u64;
    /// True if range proofs are authenticated against the chain, which
    /// unattended receive requires.
    fn rangeproofs_authenticated(&self) -> bool;
    /// Tip (height, header hash) of the chain the chain layer has verified
    /// and selected, or `None` while it cannot vouch for one. Unattended
    /// signing happens only while the wallet state stands on this tip.
    fn selected_tip(&self) -> Option<(u64, [u8; 32])> {
        None
    }
}

/// What a transport needs from the wallet to start: who we are on the
/// transport and whom we talk to. Made by the bridge from the journal every
/// time the identity or the set of contacts changes.
pub struct TransportSpec {
    /// Secret key of the transport identity. It is not a wallet key.
    pub identity_secret: zeroize::Zeroizing<[u8; 32]>,
    /// The public key that belongs to it.
    pub identity_public: [u8; 32],
    /// Key for the transport's own files.
    pub store_key: zeroize::Zeroizing<[u8; 32]>,
    /// Transport keys of the contacts.
    pub contacts: Vec<[u8; 32]>,
}

/// Starts a transport for a [`TransportSpec`]. The host supplies the rest
/// (relay, data directory, timing) and, in the product, starts the
/// transport process with [`crate::pipe::PipeMailbox::spawn`].
pub type MailboxFactory = Box<dyn FnMut(&TransportSpec) -> Result<Box<dyn Mailbox>, String>>;

/// Converts between what the user pastes or scans and slate JSON.
/// Slatepack armor, encryption and transports (Nostr, Tor) plug in here.
pub trait SlateCodec {
    /// Text from outside to slate JSON bytes. The error text is shown to the
    /// user and must not contain secrets.
    fn decode(&mut self, text: &str) -> Result<Vec<u8>, String>;
    /// Slate JSON bytes to the text handed to the counterparty.
    fn encode(&mut self, slate: &[u8]) -> Result<String, String>;
}

/// Slate JSON passed through unchanged.
#[derive(Clone, Copy, Debug, Default)]
pub struct JsonCodec;

impl SlateCodec for JsonCodec {
    fn decode(&mut self, text: &str) -> Result<Vec<u8>, String> {
        Ok(text.as_bytes().to_vec())
    }
    fn encode(&mut self, slate: &[u8]) -> Result<String, String> {
        String::from_utf8(slate.to_vec()).map_err(|_| "slate is not text".to_string())
    }
}

/// The set of ports one bridge works with.
pub struct Ports {
    /// Network broadcast.
    pub broadcaster: Box<dyn Broadcaster>,
    /// Confirmed time.
    pub clock: Box<dyn Clock>,
    /// Chain layer.
    pub chain: Box<dyn ChainView>,
    /// Slate text format.
    pub codec: Box<dyn SlateCodec>,
    /// Message transport, if the host has one. Without it every delivery
    /// method answers `no_mailbox` and slates travel by hand.
    pub mailbox: Option<Box<dyn Mailbox>>,
}
