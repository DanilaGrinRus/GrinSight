//! What comes of asking a source: its answer, or why there is none.
//!
//! Apart from the asking itself, so that a program that cannot ask (a page
//! in a browser has no secure channel of its own making) still speaks of
//! answers and failures in the same words.
use crate::said::Said;
use std::fmt;
use std::net::SocketAddr;
use std::time::Instant;

/// What one source answered.
#[derive(Debug, Clone, Copy)]
pub struct Answer {
    /// The tip the node named.
    pub said: Said,
    /// The time the server wrote on the answer, in seconds since 1970.
    pub date: Option<u64>,
    /// The moment the question was written, after the secure channel was
    /// up. The server wrote its time after this.
    pub sent: Instant,
    /// The moment the answer was read to its end. The server wrote its
    /// time before this.
    pub got: Instant,
    /// The address that answered.
    pub peer: SocketAddr,
}

/// Why there is no answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The name has no address.
    Name,
    /// No address of the name took the connection.
    Connect,
    /// The server's certificate does not hold; the words say how. A clock
    /// of this computer that is far off shows up here.
    Certificate(&'static str),
    /// The secure channel failed otherwise.
    Secure,
    /// The connection broke.
    Broken,
    /// The allowed time ran out.
    Late,
    /// The server answered with another status than success.
    Status(u16),
    /// The answer is longer than is read from a stranger.
    TooLong,
    /// The answer is not what a Grin node writes; the words say where.
    Format(&'static str),
    /// The node answered that it will not or cannot say.
    Refused,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Name => write!(f, "the name has no address"),
            Failure::Connect => write!(f, "no connection"),
            Failure::Certificate(how) => write!(f, "the certificate {how}"),
            Failure::Secure => write!(f, "the secure channel failed"),
            Failure::Broken => write!(f, "the connection broke"),
            Failure::Late => write!(f, "no answer in time"),
            Failure::Status(code) => write!(f, "status {code}"),
            Failure::TooLong => write!(f, "the answer is too long"),
            Failure::Format(what) => write!(f, "not a node's answer: {what}"),
            Failure::Refused => write!(f, "the node would not say"),
        }
    }
}
