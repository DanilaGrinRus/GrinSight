//! Payments to and from a Grin address through Tor, as the payment core
//! sees them, and the conversation with the process that does it.
//!
//! A Grin address is the public half of a key; the same key names an onion
//! service of Tor. A wallet that listens there is asked, in the words every
//! Grin wallet uses between wallets, to take a payment, and answers in the
//! same connection. The process that speaks Tor holds the secret half of
//! that one key and nothing else of the wallet: it carries request bodies
//! in and answers out and decides nothing. What a request is, whether it is
//! answered and with what is the payment core's business
//! (`fly-paycore-bridge`).
//!
//! Whoever connects to an onion service is not known: a request says
//! nothing true about its sender. Everything that arrives is anybody's
//! text.
//!
//! No third-party code.
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

pub use fly_paycore_pipe_link::plain_text;
use fly_paycore_pipe_link::{wipe, Cut, Link};
use std::path::Path;
use std::time::Duration;

/// Version of what is said over the link.
pub const VERSION: u8 = 2;
/// Largest frame either side sends.
pub const MAX_FRAME: usize = 600 * 1024;
/// Largest body of a request or an answer, in bytes.
pub const MAX_BODY: usize = 256 * 1024;
/// How long the process may take to say it has started. It says so before
/// Tor is up; Tor comes up afterwards and its state is asked for.
pub const START: Duration = Duration::from_secs(20);

/// Ask for the state. Answer: [`STATE`].
pub const ASK_STATE: u8 = 0x20;
/// Post a body to the onion service of a key. Answer: [`TAKEN`].
pub const POST: u8 = 0x21;
/// Ask for the next event. Answer: [`EVENT`].
pub const NEXT: u8 = 0x22;
/// Answer a request that arrived. Answer: [`TAKEN`].
pub const ANSWER: u8 = 0x23;
/// The state.
pub const STATE: u8 = 0xA0;
/// One byte: 1 taken, 0 not.
pub const TAKEN: u8 = 0xA1;
/// An event, or none.
pub const EVENT: u8 = 0xA2;

/// What the process is told at its start.
pub struct Config {
    /// Secret key of the wallet's address (ed25519 seed). The address is
    /// its public half; the onion service is named by the same key.
    pub secret: [u8; 32],
    /// The address itself, the public half of that key. The process checks
    /// that the two belong together and does not start otherwise.
    pub public: [u8; 32],
    /// Directory for Tor's own files. One per wallet, used by one process.
    pub data_dir: String,
    /// Whether the onion service is run, so that payments can arrive.
    pub listen: bool,
    /// Tor bridges the user chose, one a line; empty for none. The process
    /// reads and checks them; with any, Tor is reached through them only.
    pub tor_bridges: String,
}

impl Drop for Config {
    fn drop(&mut self) {
        wipe(&mut self.secret);
    }
}

impl Config {
    /// The wire form. Holds the secret: wipe it once it is sent.
    pub fn encode(&self) -> Option<Vec<u8>> {
        let dir = self.data_dir.as_bytes();
        let len = u16::try_from(dir.len()).ok()?;
        let mut out = Vec::with_capacity(dir.len().checked_add(67)?);
        out.extend_from_slice(&self.secret);
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(dir);
        out.push(u8::from(self.listen));
        out.extend_from_slice(&u16::try_from(self.tor_bridges.len()).ok()?.to_le_bytes());
        out.extend_from_slice(self.tor_bridges.as_bytes());
        Some(out)
    }
    /// Read the wire form.
    pub fn decode(bytes: &[u8]) -> Option<Config> {
        let mut c = Cut(bytes);
        let secret = c.array::<32>()?;
        let public = c.array::<32>()?;
        let data_dir = c.short_text()?;
        let listen = match c.u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let tor_bridges = c.short_text()?;
        c.done().then_some(Config { secret, public, data_dir, listen, tor_bridges })
    }
}

/// How far Tor has come.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Phase {
    /// Nothing is known: there is no process, or it does not answer.
    #[default]
    None,
    /// Tor is coming up.
    Starting,
    /// Tor is up: payments can be sent. The onion service is not known to
    /// be reachable (or is not run).
    Up,
    /// Tor is up and the onion service is announced: payments can arrive.
    Listening,
    /// Tor did not come up or the service failed; the process tries again.
    Failed,
}

impl Phase {
    fn byte(self) -> u8 {
        match self {
            Phase::None => 0,
            Phase::Starting => 1,
            Phase::Up => 2,
            Phase::Listening => 3,
            Phase::Failed => 4,
        }
    }
    fn of(byte: u8) -> Option<Phase> {
        Some(match byte {
            0 => Phase::None,
            1 => Phase::Starting,
            2 => Phase::Up,
            3 => Phase::Listening,
            4 => Phase::Failed,
            _ => return None,
        })
    }
}

/// The state of the Tor process.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct State {
    /// How far Tor has come.
    pub phase: Phase,
    /// What is in its way, in plain words that name no address, or empty.
    pub problem: String,
}

/// Something that happened at the Tor process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A post ended: the answer's body, or why there is none. `Err` says
    /// the answer is not known, never that the other side did not act.
    Posted {
        /// The ticket the post was given.
        ticket: [u8; 16],
        /// The body of the answer, or plain words.
        result: Result<String, String>,
    },
    /// A request arrived at the onion service and waits for its answer.
    Request {
        /// Names the request for [`Onion::answer`].
        id: u64,
        /// The body, at most [`MAX_BODY`] bytes of text.
        body: String,
    },
}

/// The port: payments to and from an address through Tor.
pub trait Onion {
    /// Start posting `body` to the onion service of the address key `to`.
    /// `false`: not taken, nothing was sent. The outcome comes as
    /// [`Event::Posted`] with the same ticket.
    fn post(&mut self, ticket: &[u8; 16], to: &[u8; 32], body: &str) -> bool;
    /// The next event, if there is one.
    fn next(&mut self) -> Option<Event>;
    /// Answer a request. An answer to a request that no longer waits is
    /// dropped.
    fn answer(&mut self, id: u64, body: &str);
    /// The state of Tor.
    fn state(&mut self) -> State;
}

/// Wire form of a state.
pub fn encode_state(state: &State) -> Vec<u8> {
    let words: String = state.problem.chars().take(200).collect();
    let mut out = vec![state.phase.byte()];
    out.extend_from_slice(words.as_bytes());
    out
}

/// Read a state.
pub fn decode_state(bytes: &[u8]) -> Option<State> {
    let (phase, words) = bytes.split_first()?;
    Some(State {
        phase: Phase::of(*phase)?,
        problem: fly_paycore_pipe_link::plain_text(std::str::from_utf8(words).ok()?, 200),
    })
}

fn sized(out: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    if bytes.len() > MAX_BODY {
        return None;
    }
    out.extend_from_slice(&u32::try_from(bytes.len()).ok()?.to_le_bytes());
    out.extend_from_slice(bytes);
    Some(())
}

/// Wire form of a post.
pub fn encode_post(ticket: &[u8; 16], to: &[u8; 32], body: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(ticket);
    out.extend_from_slice(to);
    sized(&mut out, body.as_bytes())?;
    Some(out)
}

/// Read a post: ticket, key, body.
pub fn decode_post(bytes: &[u8]) -> Option<([u8; 16], [u8; 32], String)> {
    let mut c = Cut(bytes);
    let ticket = c.array::<16>()?;
    let to = c.array::<32>()?;
    let body = String::from_utf8(c.bytes(MAX_BODY)?.to_vec()).ok()?;
    c.done().then_some((ticket, to, body))
}

/// Wire form of an answer to a request.
pub fn encode_answer(id: u64, body: &str) -> Option<Vec<u8>> {
    let mut out = id.to_le_bytes().to_vec();
    sized(&mut out, body.as_bytes())?;
    Some(out)
}

/// Read an answer to a request.
pub fn decode_answer(bytes: &[u8]) -> Option<(u64, String)> {
    let mut c = Cut(bytes);
    let id = c.u64()?;
    let body = String::from_utf8(c.bytes(MAX_BODY)?.to_vec()).ok()?;
    c.done().then_some((id, body))
}

/// Wire form of an event, or of none.
pub fn encode_event(event: Option<&Event>) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match event {
        None => out.push(0),
        Some(Event::Posted { ticket, result }) => {
            out.push(1);
            out.extend_from_slice(ticket);
            let (ok, text) = match result {
                Ok(body) => (1u8, body.as_str()),
                Err(why) => (0u8, why.as_str()),
            };
            out.push(ok);
            sized(&mut out, text.as_bytes())?;
        }
        Some(Event::Request { id, body }) => {
            out.push(2);
            out.extend_from_slice(&id.to_le_bytes());
            sized(&mut out, body.as_bytes())?;
        }
    }
    Some(out)
}

/// Read an event. `Some(None)`: there is none.
pub fn decode_event(bytes: &[u8]) -> Option<Option<Event>> {
    let mut c = Cut(bytes);
    let event = match c.u8()? {
        0 => None,
        1 => {
            let ticket = c.array::<16>()?;
            let ok = c.u8()?;
            let text = String::from_utf8(c.bytes(MAX_BODY)?.to_vec()).ok()?;
            Some(Event::Posted {
                ticket,
                result: match ok {
                    1 => Ok(text),
                    0 => Err(fly_paycore_pipe_link::plain_text(&text, 200)),
                    _ => return None,
                },
            })
        }
        2 => {
            let id = c.u64()?;
            let body = String::from_utf8(c.bytes(MAX_BODY)?.to_vec()).ok()?;
            Some(Event::Request { id, body })
        }
        _ => return None,
    };
    c.done().then_some(event)
}

/// The core's end of the pipe.
pub struct PipeOnion {
    link: Link,
    timeout: Duration,
}

/// A Tor process that has been told its configuration and has not answered
/// yet. Dropping it ends the process.
pub struct Starting {
    inner: fly_paycore_pipe_link::Starting,
    timeout: Duration,
}

impl Starting {
    /// Has the process answered? `None`: not yet.
    pub fn poll(&mut self) -> Option<Result<PipeOnion, String>> {
        let timeout = self.timeout;
        self.inner.poll().map(|r| {
            r.map(|link| PipeOnion { link, timeout })
                .map_err(|why| why.replacen("it did not start", "the Tor process did not start", 1))
        })
    }
}

impl PipeOnion {
    /// Start `program` as the Tor process, tell it `config` and return
    /// without waiting for its answer. The process gets nothing on its
    /// command line or in its environment.
    pub fn spawn_begin(program: &Path, config: &Config, timeout: Duration) -> Result<Starting, String> {
        let mut hello = config.encode().ok_or("the configuration does not fit a frame")?;
        let inner = Link::spawn_begin(program, &mut hello, VERSION, START.max(timeout), MAX_FRAME);
        wipe(&mut hello);
        let inner = inner.map_err(|why| why.replacen("the process", "the Tor process", 1))?;
        Ok(Starting { inner, timeout })
    }

    /// The same over an existing pair of streams.
    pub fn connect_begin<R, W>(reader: R, writer: W, config: &Config, timeout: Duration) -> Result<Starting, String>
    where
        R: std::io::Read + Send + 'static,
        W: std::io::Write + Send + 'static,
    {
        let mut hello = config.encode().ok_or("the configuration does not fit a frame")?;
        let inner = Link::connect_begin(reader, writer, &mut hello, VERSION, START.max(timeout), MAX_FRAME);
        wipe(&mut hello);
        Ok(Starting { inner: inner?, timeout })
    }

    /// Whether the process can still be asked anything.
    pub fn alive(&self) -> bool {
        self.link.alive()
    }

    fn taken(&mut self, tag: u8, payload: &[u8]) -> bool {
        matches!(self.link.exchange(tag, payload, self.timeout), Some((TAKEN, body)) if body == [1])
    }
}

impl Onion for PipeOnion {
    fn post(&mut self, ticket: &[u8; 16], to: &[u8; 32], body: &str) -> bool {
        match encode_post(ticket, to, body) {
            Some(payload) => self.taken(POST, &payload),
            None => false,
        }
    }
    fn next(&mut self) -> Option<Event> {
        match self.link.exchange(NEXT, &[], self.timeout) {
            Some((EVENT, body)) => match decode_event(&body) {
                Some(event) => event,
                None => {
                    // nonsense: the conversation is over
                    self.link.hang_up();
                    None
                }
            },
            _ => None,
        }
    }
    fn answer(&mut self, id: u64, body: &str) {
        if let Some(payload) = encode_answer(id, body) {
            self.taken(ANSWER, &payload);
        }
    }
    fn state(&mut self) -> State {
        match self.link.exchange(ASK_STATE, &[], self.timeout) {
            Some((STATE, body)) => decode_state(&body).unwrap_or_default(),
            _ => State::default(),
        }
    }
}

/// A stand-in Tor process for tests of the process boundary (feature
/// "stub"). Not part of any product build.
#[cfg(feature = "stub")]
pub mod stub;

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn what_is_said_reads_back_the_same() {
        let lines = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=abc iat-mode=0\nsnowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72";
        let config = Config { secret: [7; 32], public: [8; 32], data_dir: "C:\\данные\\tor".into(), listen: true, tor_bridges: lines.into() };
        let wire = config.encode().unwrap();
        let back = Config::decode(&wire).unwrap();
        assert_eq!((back.secret, back.public, back.data_dir.as_str(), back.listen), ([7; 32], [8; 32], "C:\\данные\\tor", true));
        // the bridges cross as they were given; none is an empty text
        assert_eq!(back.tor_bridges, lines);
        let none = Config { secret: [7; 32], public: [8; 32], data_dir: "d".into(), listen: false, tor_bridges: String::new() };
        assert_eq!(Config::decode(&none.encode().unwrap()).unwrap().tor_bridges, "");
        // more than a start-up message carries does not cross at all
        let much = Config { secret: [7; 32], public: [8; 32], data_dir: "d".into(), listen: false, tor_bridges: "a".repeat(70_000) };
        assert!(much.encode().is_none());
        assert!(Config::decode(wire.split_last().unwrap().1).is_none());
        let mut longer = wire.clone();
        longer.push(0);
        assert!(Config::decode(&longer).is_none());

        let post = encode_post(&[1; 16], &[2; 32], "{}").unwrap();
        assert_eq!(decode_post(&post), Some(([1; 16], [2; 32], "{}".to_string())));
        assert!(encode_post(&[1; 16], &[2; 32], &"x".repeat(MAX_BODY.saturating_add(1))).is_none());

        let answer = encode_answer(9, "ok").unwrap();
        assert_eq!(decode_answer(&answer), Some((9, "ok".to_string())));

        for event in [
            None,
            Some(Event::Posted { ticket: [3; 16], result: Ok("body".into()) }),
            Some(Event::Posted { ticket: [3; 16], result: Err("no answer".into()) }),
            Some(Event::Request { id: 5, body: "{\"a\":1}".into() }),
        ] {
            let wire = encode_event(event.as_ref()).unwrap();
            assert_eq!(decode_event(&wire), Some(event));
        }
        assert!(decode_event(&[3]).is_none());
        assert!(decode_event(&[]).is_none());

        let state = State { phase: Phase::Listening, problem: "Tor is slow".into() };
        assert_eq!(decode_state(&encode_state(&state)), Some(state));
        assert!(decode_state(&[9]).is_none());
    }

    /// What the process reports may quote the network: it is shown only as
    /// plain printable characters.
    #[test]
    fn words_from_the_process_are_made_plain() {
        let wire = encode_event(Some(&Event::Posted { ticket: [0; 16], result: Err("bad\u{1b}[31m\nline".into()) })).unwrap();
        assert_eq!(decode_event(&wire), Some(Some(Event::Posted { ticket: [0; 16], result: Err("bad?[31m?line".into()) })));
        let state = decode_state(&[4, b'a', 0x07, b'b']).unwrap();
        assert_eq!(state.problem, "a?b");
    }
}
