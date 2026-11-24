//! The `Mailbox` port across a process boundary.
//!
//! The payment core and the message transport run as two processes: the one
//! that holds the wallet's keys contains no network code, and the one that
//! talks to relays through Tor never sees a wallet key. They speak over the
//! child's standard input and output with the frames defined here.
//!
//! * [`PipeMailbox`] is the core's side: a `Mailbox` whose every call is one
//!   request and one answer. It never blocks for longer than its timeout and
//!   never reports more than it knows: if the transport process is slow,
//!   dead or talking nonsense, a publication is "unknown", nothing has
//!   arrived, and a reply is "not sent" - never "there is no stored reply",
//!   which would make the core build a second one.
//! * [`serve`] is the transport's side: it reads the start-up [`Config`],
//!   builds the real mailbox and answers requests until the pipe closes.
//!
//! No third-party code: both sides can be built from either set of pinned
//! dependencies.
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

#[cfg(feature = "stub")]
pub mod stub;
mod wire;

pub use wire::{Config, MAX_FRAME, VERSION};

use fly_paycore_mailbox::{Envelope, Incoming, Mailbox, Published};
use fly_paycore_pipe_link::{read_frame, wipe, write_failed, write_frame, write_ready, Cut, Link, HELLO};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

fn code(p: Published) -> u8 {
    match p {
        Published::Accepted => 1,
        Published::Unknown => 2,
        Published::Busy => 3,
        Published::Full => 4,
        Published::Expired => 5,
    }
}

fn published(code: u8) -> Option<Published> {
    Some(match code {
        1 => Published::Accepted,
        2 => Published::Unknown,
        3 => Published::Busy,
        4 => Published::Full,
        5 => Published::Expired,
        _ => return None,
    })
}

/// A key: the next 32 bytes.
fn key(c: &mut Cut<'_>) -> Option<[u8; 32]> {
    c.array::<32>()
}

/// Everything that is left, as text.
fn rest_text(c: Cut<'_>) -> Option<String> {
    String::from_utf8(c.0.to_vec()).ok()
}

/// The core's end of the pipe. The conversation itself (frames, start-up,
/// one request and one answer within a time limit, the end of the process)
/// is the shared link's, [`fly_paycore_pipe_link`]; here is only what is
/// said over it.
pub struct PipeMailbox {
    link: Link,
    timeout: Duration,
}

/// A transport that has been told its configuration and has not answered
/// yet. Bringing up the network can take a while; the wallet does not have
/// to wait for it. Dropping it ends the process it started.
pub struct Starting {
    inner: fly_paycore_pipe_link::Starting,
    timeout: Duration,
}

impl Starting {
    /// Has the transport answered? `None`: not yet. `Some(Ok)`: it is
    /// ready. `Some(Err)`: it failed, went silent for longer than its start
    /// time or answered nonsense; its process, if any, has been ended.
    /// After `Some` this value is used up.
    pub fn poll(&mut self) -> Option<Result<PipeMailbox, String>> {
        let timeout = self.timeout;
        self.inner.poll().map(|r| named(r, timeout))
    }

    /// Wait for the answer, up to the start time of the configuration.
    pub fn wait(self) -> Result<PipeMailbox, String> {
        named(self.inner.wait(), self.timeout)
    }

    /// Process id of the transport, if a process was started.
    pub fn process_id(&self) -> Option<u32> {
        self.inner.process_id()
    }
}

fn named(r: Result<Link, String>, timeout: Duration) -> Result<PipeMailbox, String> {
    match r {
        Ok(link) => Ok(PipeMailbox { link, timeout }),
        Err(why) => Err(why.replacen("it did not start", "the transport did not start", 1)),
    }
}

impl PipeMailbox {
    fn start_time(config: &Config, timeout: Duration) -> Duration {
        Duration::from_secs(u64::from(config.start_timeout_secs)).max(timeout)
    }

    /// Speak the protocol over an existing pair of streams. Sends `config`,
    /// then waits up to the configured start time for the other side to
    /// report that it is ready.
    pub fn connect<R, W>(reader: R, writer: W, config: &Config, timeout: Duration) -> Result<PipeMailbox, String>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        Self::connect_begin(reader, writer, config, timeout)?.wait()
    }

    /// The first half of [`PipeMailbox::connect`]: send `config` and return
    /// without waiting for the answer. The configuration holds secrets; its
    /// wire form is wiped once it is sent.
    pub fn connect_begin<R, W>(reader: R, writer: W, config: &Config, timeout: Duration) -> Result<Starting, String>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let mut hello = config.encode().ok_or("the configuration does not fit a frame")?;
        let start = Self::start_time(config, timeout);
        let inner = Link::connect_begin(reader, writer, &mut hello, VERSION, start, MAX_FRAME);
        wipe(&mut hello);
        Ok(Starting { inner: inner?, timeout })
    }

    /// Start `program` as the transport process and speak to it over its
    /// standard input and output. The process gets nothing on its command
    /// line or in its environment; it ends when this mailbox is dropped.
    pub fn spawn(program: &Path, config: &Config, timeout: Duration) -> Result<PipeMailbox, String> {
        Self::spawn_begin(program, config, timeout)?.wait()
    }

    /// The first half of [`PipeMailbox::spawn`]: start the process, send
    /// `config` and return without waiting for the answer.
    pub fn spawn_begin(program: &Path, config: &Config, timeout: Duration) -> Result<Starting, String> {
        let mut hello = config.encode().ok_or("the configuration does not fit a frame")?;
        let start = Self::start_time(config, timeout);
        let inner = Link::spawn_begin(program, &mut hello, VERSION, start, MAX_FRAME);
        wipe(&mut hello);
        let inner = inner.map_err(|why| why.replacen("the process", "the transport process", 1))?;
        Ok(Starting { inner, timeout })
    }

    /// Process id of the transport, if this mailbox started it.
    pub fn process_id(&self) -> Option<u32> {
        self.link.process_id()
    }

    /// Whether the other side can still be asked anything.
    pub fn alive(&self) -> bool {
        self.link.alive()
    }

    fn ask(&mut self, tag: u8, payload: &[u8]) -> Option<(u8, Vec<u8>)> {
        self.link.exchange(tag, payload, self.timeout)
    }

    /// An answer that is not one of the expected ones ends the conversation.
    fn confused<T>(&mut self, fallback: T) -> T {
        self.link.hang_up();
        fallback
    }
}

impl Mailbox for PipeMailbox {
    fn seal(&mut self, to: &[u8; 32], text: &str) -> Result<Envelope, String> {
        let mut payload = to.to_vec();
        payload.extend_from_slice(text.as_bytes());
        match self.ask(wire::SEAL, &payload) {
            Some((wire::SEALED, body)) => {
                let mut c = Cut(&body);
                match (key(&mut c), c.u64()) {
                    (Some(event_id), Some(expires_at)) if !c.done() => Ok(Envelope {
                        event_id,
                        expires_at,
                        bytes: c.0.to_vec(),
                    }),
                    _ => self.confused(Err("the transport answered nonsense".to_string())),
                }
            }
            Some((wire::NOT_SEALED, _)) => Err("the transport could not seal the message".to_string()),
            Some(_) => self.confused(Err("the transport answered nonsense".to_string())),
            None => Err("the transport does not answer".to_string()),
        }
    }

    fn publish(&mut self, envelope: &Envelope) -> Published {
        let mut payload = envelope.event_id.to_vec();
        payload.extend_from_slice(&envelope.expires_at.to_le_bytes());
        payload.extend_from_slice(&envelope.bytes);
        match self.ask(wire::PUBLISH, &payload) {
            Some((wire::PUBLISHED, body)) => match body.as_slice() {
                [one] => published(*one).unwrap_or_else(|| self.confused(Published::Unknown)),
                _ => self.confused(Published::Unknown),
            },
            Some(_) => self.confused(Published::Unknown),
            None => Published::Unknown,
        }
    }

    fn next_incoming(&mut self) -> Option<Incoming> {
        match self.ask(wire::NEXT, &[]) {
            Some((wire::INCOMING, body)) => {
                let mut c = Cut(&body);
                match (key(&mut c), key(&mut c)) {
                    (Some(id), Some(from)) => match rest_text(c) {
                        Some(text) => Some(Incoming { id, from, text }),
                        None => self.confused(None),
                    },
                    _ => self.confused(None),
                }
            }
            Some((wire::NOTHING, _)) => None,
            Some(_) => self.confused(None),
            None => None,
        }
    }

    fn resend_reply(&mut self, incoming: &[u8; 32]) -> Option<Published> {
        // "no stored reply" must come from the transport itself; silence or
        // nonsense is "not sent", so that no second reply is ever built
        match self.ask(wire::RESEND, incoming) {
            Some((wire::NO_REPLY, body)) if body.is_empty() => None,
            Some((wire::PUBLISHED, body)) => match body.as_slice() {
                [one] => Some(published(*one).unwrap_or_else(|| self.confused(Published::Busy))),
                _ => self.confused(Some(Published::Busy)),
            },
            Some(_) => self.confused(Some(Published::Busy)),
            None => Some(Published::Busy),
        }
    }

    fn reply(&mut self, incoming: &[u8; 32], text: &str) -> Published {
        let mut payload = incoming.to_vec();
        payload.extend_from_slice(text.as_bytes());
        match self.ask(wire::REPLY, &payload) {
            Some((wire::PUBLISHED, body)) => match body.as_slice() {
                [one] => published(*one).unwrap_or_else(|| self.confused(Published::Unknown)),
                _ => self.confused(Published::Unknown),
            },
            Some(_) => self.confused(Published::Unknown),
            None => Published::Unknown,
        }
    }

    fn done(&mut self, incoming: &[u8; 32]) {
        match self.ask(wire::DONE, incoming) {
            Some((wire::OK, _)) | None => {}
            Some(_) => self.confused(()),
        }
    }

    fn problem(&mut self) -> Option<String> {
        match self.ask(wire::PROBLEM, &[]) {
            // whatever the other side wrote, only plain text is handed on
            Some((wire::TEXT, body)) => match std::str::from_utf8(&body) {
                Ok(text) if !text.is_empty() => Some(fly_paycore_mailbox::plain_problem(text)),
                Ok(_) => self.confused(None),
                Err(_) => self.confused(None),
            },
            Some((wire::NOTHING, _)) | None => None,
            Some(_) => self.confused(None),
        }
    }
}

/// The transport's end: read the start-up message, build the mailbox with
/// `make`, answer requests until the other side closes the pipe. A request
/// that is not understood ends the loop with an error: the other side is
/// the wallet, and a wallet that talks nonsense is not to be guessed at.
pub fn serve<M, F>(reader: &mut dyn Read, writer: &mut dyn Write, make: F) -> io::Result<()>
where
    M: Mailbox,
    F: FnOnce(Config) -> Result<M, String>,
{
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "request not understood");
    let Some((tag, mut body)) = read_frame(reader, MAX_FRAME)? else {
        return Ok(());
    };
    if tag != HELLO {
        return Err(bad());
    }
    let config = Config::decode(&body);
    wipe(&mut body);
    let Some(config) = config else {
        write_failed(writer, "configuration not understood", MAX_FRAME)?;
        return Err(bad());
    };
    let mut mailbox = match make(config) {
        Ok(m) => m,
        Err(why) => {
            write_failed(writer, &why, MAX_FRAME)?;
            return Ok(());
        }
    };
    write_ready(writer, VERSION, MAX_FRAME)?;
    while let Some((tag, body)) = read_frame(reader, MAX_FRAME)? {
        let mut c = Cut(&body);
        match tag {
            wire::SEAL => {
                let to = key(&mut c).ok_or_else(bad)?;
                let text = rest_text(c).ok_or_else(bad)?;
                match mailbox.seal(&to, &text) {
                    Ok(e) => {
                        let mut out = e.event_id.to_vec();
                        out.extend_from_slice(&e.expires_at.to_le_bytes());
                        out.extend_from_slice(&e.bytes);
                        write_frame(writer, wire::SEALED, &out, MAX_FRAME)?;
                    }
                    Err(_) => write_frame(writer, wire::NOT_SEALED, &[], MAX_FRAME)?,
                }
            }
            wire::PUBLISH => {
                let event_id = key(&mut c).ok_or_else(bad)?;
                let expires_at = c.u64().ok_or_else(bad)?;
                let envelope = Envelope {
                    event_id,
                    expires_at,
                    bytes: c.0.to_vec(),
                };
                write_frame(writer, wire::PUBLISHED, &[code(mailbox.publish(&envelope))], MAX_FRAME)?;
            }
            wire::NEXT => {
                if !c.done() {
                    return Err(bad());
                }
                match mailbox.next_incoming() {
                    Some(m) => {
                        let mut out = m.id.to_vec();
                        out.extend_from_slice(&m.from);
                        out.extend_from_slice(m.text.as_bytes());
                        // a message too large for a frame cannot be handed
                        // on; it is released so that it does not block
                        if out.len() >= MAX_FRAME {
                            mailbox.done(&m.id);
                            write_frame(writer, wire::NOTHING, &[], MAX_FRAME)?;
                        } else {
                            write_frame(writer, wire::INCOMING, &out, MAX_FRAME)?;
                        }
                    }
                    None => write_frame(writer, wire::NOTHING, &[], MAX_FRAME)?,
                }
            }
            wire::RESEND => {
                let incoming = key(&mut c).filter(|_| c.done()).ok_or_else(bad)?;
                match mailbox.resend_reply(&incoming) {
                    Some(p) => write_frame(writer, wire::PUBLISHED, &[code(p)], MAX_FRAME)?,
                    None => write_frame(writer, wire::NO_REPLY, &[], MAX_FRAME)?,
                }
            }
            wire::REPLY => {
                let incoming = key(&mut c).ok_or_else(bad)?;
                let text = rest_text(c).ok_or_else(bad)?;
                write_frame(writer, wire::PUBLISHED, &[code(mailbox.reply(&incoming, &text))], MAX_FRAME)?;
            }
            wire::DONE => {
                let incoming = key(&mut c).filter(|_| c.done()).ok_or_else(bad)?;
                mailbox.done(&incoming);
                write_frame(writer, wire::OK, &[], MAX_FRAME)?;
            }
            wire::PROBLEM => {
                if !c.done() {
                    return Err(bad());
                }
                match mailbox.problem().map(|p| fly_paycore_mailbox::plain_problem(&p)) {
                    Some(text) if !text.is_empty() => write_frame(writer, wire::TEXT, text.as_bytes(), MAX_FRAME)?,
                    _ => write_frame(writer, wire::NOTHING, &[], MAX_FRAME)?,
                }
            }
            _ => return Err(bad()),
        }
    }
    Ok(())
}
