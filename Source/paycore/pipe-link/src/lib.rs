//! The link between the wallet process and a helper process it starts.
//!
//! The wallet process holds the keys and contains no network code; whatever
//! needs the network runs in a process of its own and is spoken to over
//! that process's standard input and output. This crate is the part of that
//! conversation that does not depend on what is being said:
//!
//! * frames: `u32` little-endian length, one tag byte, payload; a frame
//!   larger than the agreed limit is refused before anything is allocated;
//! * start-up: the first frame (`HELLO`) carries the helper's configuration,
//!   the helper answers `READY` with the protocol version or `FAILED` with
//!   a reason. Nothing is passed on a command line or in the environment;
//! * [`Link::exchange`]: one request, one answer, within a time limit. Any
//!   trouble - silence, a closed pipe, a frame that is not a frame - ends
//!   the conversation for good and ends the helper process. The caller then
//!   answers its own callers with "unknown", never with a guess.
//!
//! No third-party code, so both sides of any link can use it whatever their
//! own pinned dependencies are.
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

use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

/// Tag of the first frame: the helper's configuration.
pub const HELLO: u8 = 0x10;
/// The helper is ready; the payload is the protocol version, one byte.
pub const READY: u8 = 0x90;
/// The helper could not start; the payload says why, in plain text.
pub const FAILED: u8 = 0x91;

type Frame = io::Result<Option<(u8, Vec<u8>)>>;

struct Outgoing {
    tag: u8,
    payload: Vec<u8>,
}

impl Drop for Outgoing {
    fn drop(&mut self) {
        wipe(&mut self.payload);
    }
}

fn within(completed: (Instant, Frame), until: Option<Instant>) -> Option<(u8, Vec<u8>)> {
    let (at, reply) = completed;
    if at > until? { return None; }
    reply.ok().flatten()
}

fn bad(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, what)
}

/// Write one frame: length, tag, payload.
pub fn write_frame(w: &mut dyn Write, tag: u8, payload: &[u8], max: usize) -> io::Result<()> {
    let len = payload
        .len()
        .checked_add(1)
        .filter(|n| *n <= max)
        .ok_or_else(|| bad("frame too large"))?;
    let len = u32::try_from(len).map_err(|_| bad("frame too large"))?;
    w.write_all(&len.to_le_bytes())?;
    w.write_all(&[tag])?;
    w.write_all(payload)?;
    w.flush()
}

/// Read one frame of at most `max` bytes. `Ok(None)` is a clean end of the
/// stream between frames.
pub fn read_frame(r: &mut dyn Read, max: usize) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut len = [0u8; 4];
    let mut got = 0usize;
    while got < len.len() {
        let slot = len.get_mut(got..).ok_or_else(|| bad("frame header"))?;
        match r.read(slot) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got = got.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let len = usize::try_from(u32::from_le_bytes(len)).map_err(|_| bad("frame length"))?;
    if len == 0 || len > max {
        return Err(bad("frame length"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    let tag = body.first().copied().ok_or_else(|| bad("frame length"))?;
    body.remove(0);
    Ok(Some((tag, body)))
}

/// Wipe a buffer that held something not meant to stay in memory.
pub fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    std::hint::black_box(&*buf);
}

/// Text made safe to show: plain printable characters only, cut to `max`.
/// What a helper reports may quote a peer on the network, which is anybody.
pub fn plain_text(text: &str, max: usize) -> String {
    text.chars()
        .take(max)
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
        .collect()
}

/// Cursor over a payload; every read is checked.
pub struct Cut<'a>(pub &'a [u8]);
impl<'a> Cut<'a> {
    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    /// The next `N` bytes as an array.
    pub fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        <[u8; N]>::try_from(self.take(N)?).ok()
    }
    /// One byte.
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1)?.first().copied()
    }
    /// A little-endian `u16`.
    pub fn u16(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }
    /// A little-endian `u32`.
    pub fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }
    /// A little-endian `u64`.
    pub fn u64(&mut self) -> Option<u64> {
        self.array().map(u64::from_le_bytes)
    }
    /// A text with a `u16` length in front.
    pub fn short_text(&mut self) -> Option<String> {
        let n = usize::from(self.u16()?);
        String::from_utf8(self.take(n)?.to_vec()).ok()
    }
    /// Bytes with a `u32` length in front, at most `max` of them.
    pub fn bytes(&mut self, max: usize) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u32()?).ok().filter(|n| *n <= max)?;
        self.take(n)
    }
    /// Whether everything has been read.
    pub fn done(&self) -> bool {
        self.0.is_empty()
    }
}

/// The wallet's end of a link to a helper that has reported ready.
pub struct Link {
    to_peer: Option<mpsc::SyncSender<Outgoing>>,
    frames: Receiver<(Instant, Frame)>,
    child: Option<Child>,
    max_frame: usize,
}

/// A helper that has been told its configuration and has not answered yet.
/// Dropping it ends the process it started.
pub struct Starting {
    link: Option<Link>,
    until: Option<Instant>,
    version: u8,
}

impl Starting {
    /// Has the helper answered? `None`: not yet. `Some(Ok)`: it is ready.
    /// `Some(Err)`: it failed, stayed silent past its start time or answered
    /// nonsense; its process, if any, has been ended. After `Some` this
    /// value is used up.
    pub fn poll(&mut self) -> Option<Result<Link, String>> {
        let Some(link) = self.link.as_mut() else {
            return Some(Err("it did not start".to_string()));
        };
        let frame = match link.frames.try_recv() {
            Ok(reply) => within(reply, self.until),
            Err(TryRecvError::Empty) if self.until.is_some_and(|until| Instant::now() < until) => return None,
            _ => None,
        };
        Some(self.judge(frame))
    }

    /// Wait for the answer, up to the start time.
    pub fn wait(mut self) -> Result<Link, String> {
        let left = self
            .until
            .map(|until| until.saturating_duration_since(Instant::now()))
            .unwrap_or_default();
        let frame = match self.link.as_mut().map(|l| l.frames.recv_timeout(left)) {
            Some(Ok(reply)) => within(reply, self.until),
            _ => None,
        };
        self.judge(frame)
    }

    /// Process id of the helper, if a process was started.
    pub fn process_id(&self) -> Option<u32> {
        self.link.as_ref().and_then(Link::process_id)
    }

    fn judge(&mut self, frame: Option<(u8, Vec<u8>)>) -> Result<Link, String> {
        let Some(mut link) = self.link.take() else {
            return Err("it did not start".to_string());
        };
        match frame {
            Some((READY, body)) if body == [self.version] => Ok(link),
            Some((FAILED, body)) => {
                link.hang_up();
                Err(format!("it did not start: {}", plain_text(&String::from_utf8_lossy(&body), 200)))
            }
            _ => {
                link.hang_up();
                Err("it did not start".to_string())
            }
        }
    }
}

impl Drop for Starting {
    fn drop(&mut self) {
        // a helper that never became ready has nothing to finish
        if let Some(link) = self.link.as_mut() {
            link.hang_up();
        }
    }
}

impl Link {
    /// Speak over an existing pair of streams: send `hello` (it is wiped
    /// afterwards) and return without waiting. The helper has `start` to
    /// report ready with exactly `version`.
    pub fn connect_begin<R, W>(
        reader: R,
        writer: W,
        hello: &mut [u8],
        version: u8,
        start: Duration,
        max_frame: usize,
    ) -> Result<Starting, String>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let until = Instant::now().checked_add(start);
        if hello.len().checked_add(1).is_none_or(|len| len > max_frame || u32::try_from(len).is_err()) {
            wipe(hello);
            return Err("configuration too large".into());
        }
        let first = Outgoing { tag: HELLO, payload: hello.to_vec() };
        wipe(hello);
        let (to_peer, requests) = mpsc::sync_channel::<Outgoing>(1);
        let (tx, frames) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("pipe-link-io".into())
            .spawn(move || {
                let (mut reader, mut writer) = (reader, writer);
                for request in requests {
                    let sent = write_frame(&mut writer, request.tag, &request.payload, max_frame);
                    drop(request);
                    let frame = sent.and_then(|()| read_frame(&mut reader, max_frame));
                    let closed = !matches!(frame, Ok(Some(_)));
                    if tx.send((Instant::now(), frame)).is_err() || closed { break; }
                }
            })
            .map_err(|_| "the I/O thread could not be started".to_string())?;
        to_peer.try_send(first).map_err(|_| "could not start the link".to_string())?;
        Ok(Starting {
            link: Some(Link { to_peer: Some(to_peer), frames, child: None, max_frame }),
            until,
            version,
        })
    }

    /// Start `program` and speak to it over its standard input and output.
    /// The process gets nothing on its command line or in its environment;
    /// it ends when the link is dropped.
    pub fn spawn_begin(
        program: &Path,
        hello: &mut [u8],
        version: u8,
        start: Duration,
        max_frame: usize,
    ) -> Result<Starting, String> {
        let mut command = Command::new(program);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear();
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // the helper needs these to find the system's libraries and its
            // temporary folder; nothing else is passed on
            for name in ["SystemRoot", "SYSTEMROOT", "windir", "TEMP", "TMP"] {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
            // CREATE_NO_WINDOW: no console window flashes up
            command.creation_flags(0x0800_0000);
        }
        let spawned = command.spawn();
        let mut child = match spawned {
            Ok(child) => child,
            Err(_) => {
                wipe(hello);
                return Err("the process could not be started".to_string());
            }
        };
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            wipe(hello);
            let _ = child.kill();
            let _ = child.wait();
            return Err("the process has no pipes".to_string());
        };
        match Self::connect_begin(stdout, stdin, hello, version, start, max_frame) {
            Ok(mut starting) => {
                match starting.link.as_mut() {
                    Some(link) if link.alive() => link.child = Some(child),
                    _ => {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                }
                Ok(starting)
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                Err(e)
            }
        }
    }

    /// Process id of the helper, if this link started it.
    pub fn process_id(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Whether the other side can still be asked anything.
    pub fn alive(&self) -> bool {
        self.to_peer.is_some()
    }

    /// Stop talking: close our end and, if we started the process, end it.
    pub fn hang_up(&mut self) {
        self.to_peer = None;
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// One request, one answer, within `wait`. Any trouble ends the
    /// conversation for good: later calls return `None` at once.
    pub fn exchange(&mut self, tag: u8, payload: &[u8], wait: Duration) -> Option<(u8, Vec<u8>)> {
        let until = Instant::now().checked_add(wait);
        if payload.len().checked_add(1).is_none_or(|n| n > self.max_frame || u32::try_from(n).is_err()) {
            self.hang_up();
            return None;
        }
        let request = Outgoing { tag, payload: payload.to_vec() };
        if self.to_peer.as_ref()?.try_send(request).is_err() {
            self.hang_up();
            return None;
        }
        let left = until.map(|end| end.saturating_duration_since(Instant::now())).unwrap_or_default();
        match self.frames.recv_timeout(left).ok().and_then(|reply| within(reply, until)) {
            Some(frame) => Some(frame),
            None => {
                self.hang_up();
                None
            }
        }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        // closing our end tells the helper to finish; then make sure
        self.to_peer = None;
        if let Some(mut child) = self.child.take() {
            for _ in 0..20 {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return;
                }
                thread::sleep(Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// The helper's side of the start-up: read the first frame and hand back
/// the configuration bytes. Anything but a `HELLO` is an error.
pub fn read_hello(reader: &mut dyn Read, max_frame: usize) -> io::Result<Vec<u8>> {
    match read_frame(reader, max_frame)? {
        Some((HELLO, body)) => Ok(body),
        _ => Err(bad("the first frame is not the configuration")),
    }
}

/// The helper's side: report ready.
pub fn write_ready(writer: &mut dyn Write, version: u8, max_frame: usize) -> io::Result<()> {
    write_frame(writer, READY, &[version], max_frame)
}

/// The helper's side: report why it cannot start.
pub fn write_failed(writer: &mut dyn Write, why: &str, max_frame: usize) -> io::Result<()> {
    write_frame(writer, FAILED, plain_text(why, 200).as_bytes(), max_frame)
}
