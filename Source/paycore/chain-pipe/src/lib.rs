//! The chain port across a process boundary.
//!
//! The wallet process contains no network code. The chain layer - peers,
//! headers, proofs, blocks - runs as a process of its own, and the wallet
//! speaks to it over that process's standard input and output.
//!
//! * [`PipeChain`] is the wallet's side: a `ChainFeed` whose every call is
//!   one request and one answer within a time limit. It never says more
//!   than it knows: a chain process that is slow, dead or talking nonsense
//!   gives no status, an "unknown" next step and an "unknown" broadcast -
//!   never "nothing new", which the wallet would take for "I am at the
//!   tip". It also does not take the chain process's word for the shape of
//!   an answer: a block that does not sit right above the wallet's position
//!   or a step "back" that goes forward ends the conversation.
//! * [`serve`] is the chain process's side.
//!
//! The wallet tells the chain process its position (a height and a header
//! hash) and hands it finished transactions. Nothing else about the wallet
//! crosses this pipe.
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
pub mod wire;

pub use wire::{Config, MAX_FRAME, VERSION};

use fly_paycore_chain_port::{plain_problem, ChainFeed, OldOutputs, Posted, Status, Step, Tip, Unknown, MAX_POINT_LEN, MAX_TX_LEN};
use fly_paycore_pipe_link::{read_frame, read_hello, write_failed, write_frame, write_ready, Cut, Link};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

/// A chain process that has been told its configuration and has not
/// answered yet. Dropping it ends the process.
pub struct Starting {
    inner: fly_paycore_pipe_link::Starting,
    timeout: Duration,
}

impl Starting {
    /// Has the chain process answered? `None`: not yet.
    pub fn poll(&mut self) -> Option<Result<PipeChain, String>> {
        let timeout = self.timeout;
        self.inner.poll().map(|r| named(r, timeout))
    }
    /// Wait for the answer, up to the start time of the configuration.
    pub fn wait(self) -> Result<PipeChain, String> {
        named(self.inner.wait(), self.timeout)
    }
    /// Process id of the chain process, if a process was started.
    pub fn process_id(&self) -> Option<u32> {
        self.inner.process_id()
    }
}

fn named(r: Result<Link, String>, timeout: Duration) -> Result<PipeChain, String> {
    match r {
        Ok(link) => Ok(PipeChain { link, timeout }),
        Err(why) => Err(why.replacen("it did not start", "the chain process did not start", 1)),
    }
}

/// The wallet's side of the pipe.
pub struct PipeChain {
    link: Link,
    timeout: Duration,
}

impl PipeChain {
    fn start_time(config: &Config, timeout: Duration) -> Duration {
        Duration::from_secs(u64::from(config.start_timeout_secs)).max(timeout)
    }

    /// Speak the protocol over an existing pair of streams, without waiting
    /// for the other side to report ready.
    pub fn connect_begin<R, W>(reader: R, writer: W, config: &Config, timeout: Duration) -> Result<Starting, String>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let mut hello = config.encode().ok_or("the configuration does not fit a frame")?;
        let start = Self::start_time(config, timeout);
        let inner = Link::connect_begin(reader, writer, &mut hello, VERSION, start, MAX_FRAME)?;
        Ok(Starting { inner, timeout })
    }

    /// [`PipeChain::connect_begin`], then wait for "ready".
    pub fn connect<R, W>(reader: R, writer: W, config: &Config, timeout: Duration) -> Result<PipeChain, String>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        Self::connect_begin(reader, writer, config, timeout)?.wait()
    }

    /// Start `program` as the chain process, without waiting for it to
    /// report ready. It gets nothing on its command line or in its
    /// environment and ends when this value is dropped.
    pub fn spawn_begin(program: &Path, config: &Config, timeout: Duration) -> Result<Starting, String> {
        let mut hello = config.encode().ok_or("the configuration does not fit a frame")?;
        let start = Self::start_time(config, timeout);
        let inner = Link::spawn_begin(program, &mut hello, VERSION, start, MAX_FRAME)
            .map_err(|why| why.replacen("the process", "the chain process", 1))?;
        Ok(Starting { inner, timeout })
    }

    /// [`PipeChain::spawn_begin`], then wait for "ready".
    pub fn spawn(program: &Path, config: &Config, timeout: Duration) -> Result<PipeChain, String> {
        Self::spawn_begin(program, config, timeout)?.wait()
    }

    /// Process id of the chain process, if this value started it.
    pub fn process_id(&self) -> Option<u32> {
        self.link.process_id()
    }

    /// Whether the chain process can still be asked anything.
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

impl PipeChain {
    /// A finished transaction to the chain process: plainly, or with the
    /// owner's agreement to the direct way for this one (K192).
    fn hand_over(&mut self, how: u8, tx: &[u8]) -> Posted {
        if tx.is_empty() || tx.len() > MAX_TX_LEN {
            // nothing was sent; "rejected" would claim a node's verdict
            return Posted::Unknown;
        }
        match self.ask(how, tx) {
            Some((wire::POSTED, body)) => match wire::posted_from(&body) {
                Some(posted) => posted,
                None => self.confused(Posted::Unknown),
            },
            Some(_) => self.confused(Posted::Unknown),
            None => Posted::Unknown,
        }
    }
}

impl ChainFeed for PipeChain {
    fn status(&mut self) -> Option<Status> {
        match self.ask(wire::STATUS, &[]) {
            Some((wire::STATUS_IS, body)) => match wire::decode_status(&body) {
                Some(status) => Some(status),
                None => self.confused(None),
            },
            Some((wire::UNKNOWN, body)) if body.is_empty() => None,
            Some(_) => self.confused(None),
            None => None,
        }
    }

    fn next(&mut self, at: Option<Tip>) -> Result<Step, Unknown> {
        let Some((tag, body)) = self.ask(wire::NEXT, &wire::encode_tip(at)) else {
            return Err(Unknown);
        };
        // the answer must make sense for the position that was sent
        let step = match (tag, at) {
            (wire::NOTHING, Some(_)) if body.is_empty() => Some(Step::Nothing),
            (wire::BLOCK, Some(at)) => wire::decode_block(&body)
                .filter(|b| at.height.checked_add(1) == Some(b.height))
                .map(|b| Step::Block(Box::new(b))),
            (wire::ROLLBACK, Some(at)) => Cut(&body)
                .u64()
                .filter(|to| body.len() == 8 && *to < at.height)
                .map(|to| Step::Rollback { to }),
            (wire::REANCHOR_EXTENDING, Some(previous)) => wire::decode_tip(&body).flatten()
                .filter(|anchor| anchor.height > previous.height)
                .map(Step::ReanchorExtending),
            (wire::REANCHOR, _) => wire::decode_tip(&body).flatten().map(Step::Reanchor),
            (wire::UNKNOWN, _) if body.is_empty() => return Err(Unknown),
            _ => None,
        };
        match step {
            Some(step) => Ok(step),
            None => self.confused(Err(Unknown)),
        }
    }

    fn post(&mut self, tx: &[u8]) -> Posted {
        self.hand_over(wire::POST, tx)
    }

    fn post_direct(&mut self, tx: &[u8]) -> Posted {
        self.hand_over(wire::POST_DIRECT, tx)
    }

    fn problem(&mut self) -> Option<String> {
        match self.ask(wire::PROBLEM, &[]) {
            // whatever the other side wrote, only plain text is handed on
            Some((wire::TEXT, body)) => match std::str::from_utf8(&body) {
                Ok(text) if !text.is_empty() => Some(plain_problem(text)),
                _ => self.confused(None),
            },
            Some((wire::NO_PROBLEM, body)) if body.is_empty() => None,
            Some(_) => self.confused(None),
            None => None,
        }
    }

    fn old_outputs(&mut self, piece: u64) -> Result<OldOutputs, Unknown> {
        let answer = self.ask(wire::OLD, &piece.to_le_bytes());
        self.old_answer(answer, piece, false)
    }

    fn old_outputs_since(&mut self, piece: u64, since: Tip) -> Result<OldOutputs, Unknown> {
        let answer = self.ask(wire::OLD_SINCE, &wire::encode_old_since(piece, since));
        self.old_answer(answer, piece, true)
    }

    fn set_tor(&mut self, off: bool) -> bool {
        match self.ask(wire::TOR, &[u8::from(off)]) {
            Some((wire::DONE, body)) if body.is_empty() => true,
            // the layer on the other side has no such switch
            Some((wire::UNKNOWN, body)) if body.is_empty() => false,
            Some(_) => self.confused(false),
            None => false,
        }
    }
    fn point(&mut self) -> Result<Vec<u8>, String> {
        let silent = || NO_POINT_ANSWER.to_string();
        match self.ask(wire::POINT, &[]) {
            Some((wire::POINT_IS, body)) if !body.is_empty() && body.len() <= MAX_POINT_LEN => Ok(body),
            // whatever the other side wrote, only plain text is handed on
            Some((wire::TEXT, body)) => match std::str::from_utf8(&body) {
                Ok(text) if !text.is_empty() => Err(plain_problem(text)),
                _ => self.confused(Err(silent())),
            },
            Some(_) => self.confused(Err(silent())),
            None => Err(silent()),
        }
    }
}

/// Said when the chain process gave no answer about a starting point.
pub const NO_POINT_ANSWER: &str = "the chain process did not answer";
/// Said by the chain process when its layer made a record that cannot be
/// handed over.
pub const POINT_UNFIT: &str = "the starting point made cannot be handed over";

impl PipeChain {
    /// The answer to a request for a piece of the old outputs.
    fn old_answer(&mut self, answer: Option<(u8, Vec<u8>)>, piece: u64, since: bool) -> Result<OldOutputs, Unknown> {
        match answer {
            Some((wire::OLD_ARE, body)) => match wire::decode_old(&body, piece, since) {
                Some(old) => Ok(old),
                None => self.confused(Err(Unknown)),
            },
            Some((wire::UNKNOWN, body)) if body.is_empty() => Err(Unknown),
            Some(_) => self.confused(Err(Unknown)),
            None => Err(Unknown),
        }
    }
}

/// The chain process's end: read the start-up message, build the feed with
/// `make`, answer requests until the other side closes the pipe. A request
/// that is not understood ends the loop with an error.
pub fn serve<F, M>(reader: &mut dyn Read, writer: &mut dyn Write, make: M) -> io::Result<()>
where
    F: ChainFeed,
    M: FnOnce(Config) -> Result<F, String>,
{
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "request not understood");
    let hello = read_hello(reader, MAX_FRAME)?;
    let Some(config) = Config::decode(&hello) else {
        write_failed(writer, "configuration not understood", MAX_FRAME)?;
        return Err(bad());
    };
    let mut feed = match make(config) {
        Ok(feed) => feed,
        Err(why) => {
            write_failed(writer, &why, MAX_FRAME)?;
            return Ok(());
        }
    };
    write_ready(writer, VERSION, MAX_FRAME)?;
    while let Some((tag, body)) = read_frame(reader, MAX_FRAME)? {
        match tag {
            wire::STATUS if body.is_empty() => match feed.status() {
                Some(status) => write_frame(writer, wire::STATUS_IS, &wire::encode_status(&status), MAX_FRAME)?,
                None => write_frame(writer, wire::UNKNOWN, &[], MAX_FRAME)?,
            },
            wire::NEXT => {
                let at = wire::decode_tip(&body).ok_or_else(bad)?;
                match feed.next(at) {
                    Ok(Step::Nothing) => write_frame(writer, wire::NOTHING, &[], MAX_FRAME)?,
                    Ok(Step::Block(block)) => match wire::encode_block(&block) {
                        Some(bytes) => write_frame(writer, wire::BLOCK, &bytes, MAX_FRAME)?,
                        // a block that cannot be handed over is not "nothing"
                        None => write_frame(writer, wire::UNKNOWN, &[], MAX_FRAME)?,
                    },
                    Ok(Step::Rollback { to }) => write_frame(writer, wire::ROLLBACK, &to.to_le_bytes(), MAX_FRAME)?,
                    Ok(Step::ReanchorExtending(tip)) => {
                        write_frame(writer, wire::REANCHOR_EXTENDING, &wire::encode_tip(Some(tip)), MAX_FRAME)?
                    }
                    Ok(Step::Reanchor(tip)) => {
                        write_frame(writer, wire::REANCHOR, &wire::encode_tip(Some(tip)), MAX_FRAME)?
                    }
                    Err(Unknown) => write_frame(writer, wire::UNKNOWN, &[], MAX_FRAME)?,
                }
            }
            wire::POST => {
                if body.is_empty() || body.len() > MAX_TX_LEN {
                    return Err(bad());
                }
                write_frame(writer, wire::POSTED, &[wire::posted_code(feed.post(&body))], MAX_FRAME)?;
            }
            wire::POST_DIRECT => {
                if body.is_empty() || body.len() > MAX_TX_LEN {
                    return Err(bad());
                }
                write_frame(writer, wire::POSTED, &[wire::posted_code(feed.post_direct(&body))], MAX_FRAME)?;
            }
            wire::TOR => {
                let off = match body.as_slice() {
                    [0] => false,
                    [1] => true,
                    _ => return Err(bad()),
                };
                write_frame(writer, if feed.set_tor(off) { wire::DONE } else { wire::UNKNOWN }, &[], MAX_FRAME)?;
            }
            wire::PROBLEM if body.is_empty() => match feed.problem().map(|p| plain_problem(&p)) {
                Some(text) if !text.is_empty() => write_frame(writer, wire::TEXT, text.as_bytes(), MAX_FRAME)?,
                _ => write_frame(writer, wire::NO_PROBLEM, &[], MAX_FRAME)?,
            },
            wire::OLD => {
                let piece = <[u8; 8]>::try_from(body.as_slice()).map(u64::from_le_bytes).map_err(|_| bad())?;
                // a piece that cannot be handed over is not "no outputs"
                match feed.old_outputs(piece).ok().and_then(|old| wire::encode_old(&old, piece, false)) {
                    Some(bytes) => write_frame(writer, wire::OLD_ARE, &bytes, MAX_FRAME)?,
                    None => write_frame(writer, wire::UNKNOWN, &[], MAX_FRAME)?,
                }
            }
            wire::OLD_SINCE => {
                let (piece, since) = wire::decode_old_since(&body).ok_or_else(bad)?;
                match feed.old_outputs_since(piece, since).ok().and_then(|old| wire::encode_old(&old, piece, true)) {
                    Some(bytes) => write_frame(writer, wire::OLD_ARE, &bytes, MAX_FRAME)?,
                    None => write_frame(writer, wire::UNKNOWN, &[], MAX_FRAME)?,
                }
            }
            wire::POINT if body.is_empty() => {
                // a record or the reason there is none: never an empty answer
                let answer = feed.point().and_then(|record| {
                    if record.is_empty() || record.len() > MAX_POINT_LEN {
                        Err(POINT_UNFIT.to_string())
                    } else {
                        Ok(record)
                    }
                });
                match answer {
                    Ok(record) => write_frame(writer, wire::POINT_IS, &record, MAX_FRAME)?,
                    Err(why) => {
                        let text = plain_problem(&why);
                        let text = if text.is_empty() { POINT_UNFIT } else { text.as_str() };
                        write_frame(writer, wire::TEXT, text.as_bytes(), MAX_FRAME)?;
                    }
                }
            }
            _ => return Err(bad()),
        }
    }
    Ok(())
}
