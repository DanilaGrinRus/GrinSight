//! The message-transport port of the payment core.
//!
//! This crate holds only the contract between the core and whatever carries
//! slates to a contact (today: gift-wrapped Nostr events over Tor). It has no
//! dependencies, so a transport can implement [`Mailbox`] without pulling in
//! the wallet, and the wallet can be built without any transport.
//!
//! The division of duties: the envelope of an outgoing payment is kept by the
//! core, in its journal, in the same frame as the payment itself; the mailbox
//! publishes exactly those bytes, however often it is asked. A reply to an
//! incoming payment is kept by the mailbox, because receiving without state
//! writes nothing to the journal.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// A sealed message for one contact. It is already encrypted; nothing in it
/// is secret from whoever stores it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// Identifier of the message; every retry carries the same one.
    pub event_id: [u8; 32],
    /// The encrypted message, published byte for byte.
    pub bytes: Vec<u8>,
    /// Unix seconds after which it is no longer published.
    pub expires_at: u64,
}

/// What became of one attempt to hand a message to the relays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Published {
    /// A relay acknowledged the message.
    Accepted,
    /// No definite answer; the message may or may not be stored.
    Unknown,
    /// The transport is busy; try again later.
    Busy,
    /// The transport's queue is full.
    Full,
    /// The envelope's delivery window has closed by the transport's clock;
    /// it was not sent and will not be.
    Expired,
}

/// A message the transport received and authenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    /// Identifier of the message, stable across redelivery.
    pub id: [u8; 32],
    /// Transport identity of the sender, verified by the transport.
    pub from: [u8; 32],
    /// The text it carried.
    pub text: String,
}

/// The message transport as the payment core sees it.
pub trait Mailbox {
    /// Seal `text` for `to`. Must not publish and must not touch the network.
    fn seal(&mut self, to: &[u8; 32], text: &str) -> Result<Envelope, String>;
    /// Publish a sealed envelope byte for byte.
    fn publish(&mut self, envelope: &Envelope) -> Published;
    /// The next received message that has not been marked done. A message
    /// that is not marked done is delivered again later.
    fn next_incoming(&mut self) -> Option<Incoming>;
    /// If a reply to this incoming message is already stored, publish the
    /// stored bytes again and say what happened; `None` if there is none.
    fn resend_reply(&mut self, incoming: &[u8; 32]) -> Option<Published>;
    /// Seal a reply to an incoming message, store it durably, then publish
    /// it. Repeating the call for the same incoming message must publish the
    /// stored reply, not a new one.
    fn reply(&mut self, incoming: &[u8; 32], text: &str) -> Published;
    /// The incoming message has been dealt with and need not come again.
    fn done(&mut self, incoming: &[u8; 32]);
    /// Why the transport is not getting through, in words for the user;
    /// `None` when nothing is known to be wrong. It is a description to
    /// show, never a fact about a payment: nothing may be decided on it.
    fn problem(&mut self) -> Option<String> {
        None
    }
}

/// Longest text a transport may report as its problem.
pub const MAX_PROBLEM_LEN: usize = 240;

/// A problem text made safe to show: plain printable characters only, cut
/// to [`MAX_PROBLEM_LEN`]. The text may quote a relay, which is anybody.
pub fn plain_problem(text: &str) -> String {
    text.chars()
        .take(MAX_PROBLEM_LEN)
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
        .collect()
}
