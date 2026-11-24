//! Talking to `fly-paycore-host`: JSON-RPC 2.0, one line per request and one
//! per answer, on the host's standard input and output (paycore/host/README.md).
//!
//! Answers are matched to requests by id. Lines without an id are
//! notifications (`paycore.event`, `host.events_dropped`) and go to a
//! callback. When the host goes away every waiting call ends with
//! [`CallError::Gone`]. A password is written straight into the request line
//! and the buffer is wiped after writing; no other copy is kept here.
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

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroize;

/// Longest line read from the host; longer lines are skipped (the host's
/// own limit for a request is 257 KB).
pub const MAX_LINE: usize = 1 << 20;

/// Why a call has no result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// The host answered with an error: its code, the name the host gives it
    /// (`wrong_password`, `locked`, …) and its message.
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// The host's name for it, or empty.
        name: String,
        /// The message, as the host wrote it.
        message: String,
    },
    /// No answer in time.
    Timeout,
    /// The host's output ended or the request could not be written.
    Gone,
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Rpc { name, message, .. } if !name.is_empty() => write!(f, "{name}: {message}"),
            CallError::Rpc { code, message, .. } => write!(f, "{code}: {message}"),
            CallError::Timeout => write!(f, "the wallet process did not answer in time"),
            CallError::Gone => write!(f, "the wallet process is not running"),
        }
    }
}

type Pending = Arc<Mutex<HashMap<u64, Sender<Result<Value, CallError>>>>>;

/// A connection to a JSON-RPC peer over a pair of byte streams.
pub struct Client {
    writer: Mutex<Box<dyn Write + Send>>,
    pending: Pending,
    next: AtomicU64,
}

impl Client {
    /// Starts reading answers from `reader` on a thread of its own.
    pub fn start(reader: Box<dyn Read + Send>, writer: Box<dyn Write + Send>, on_note: Box<dyn Fn(Value) + Send>) -> Arc<Client> {
        let client = Arc::new(Client { writer: Mutex::new(writer), pending: Arc::new(Mutex::new(HashMap::new())), next: AtomicU64::new(1) });
        let pending = client.pending.clone();
        std::thread::spawn(move || read_loop(reader, &pending, on_note.as_ref()));
        client
    }

    /// Calls `method` and waits up to `wait` for the answer.
    pub fn call(&self, method: &str, params: Value, wait: Duration) -> Result<Value, CallError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string().into_bytes();
        line.push(b'\n');
        self.send(id, line, wait)
    }

    /// Calls `method` with ordinary `params` (an object, or null) and one
    /// secret parameter `key` (a password). The request line is built here
    /// and wiped after it is written.
    pub fn call_secret(&self, method: &str, params: Value, key: &str, secret: &str, wait: Duration) -> Result<Value, CallError> {
        self.call_secrets(method, params, &[(key, secret)], wait)
    }

    /// Like [`Client::call_secret`] with several secret parameters (a
    /// password and the words of a wallet). Each is written straight into the
    /// request line, which is wiped after it is written.
    pub fn call_secrets(&self, method: &str, params: Value, secrets: &[(&str, &str)], wait: Duration) -> Result<Value, CallError> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let mut fields = match params {
            Value::Object(map) => map,
            Value::Null => serde_json::Map::new(),
            _ => return Err(CallError::Gone),
        };
        for (key, _) in secrets {
            fields.remove(*key);
        }
        let head = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": Value::Object(fields) }).to_string();
        // `head` ends with "}}": the params object and the request. Reopen
        // the params object and add the secrets as its last fields.
        let Some(open) = head.strip_suffix("}}") else {
            return Err(CallError::Gone);
        };
        let mut line = Vec::with_capacity(head.len().saturating_add(256));
        line.extend_from_slice(open.as_bytes());
        let mut first = open.ends_with('{');
        for (key, secret) in secrets {
            let quoted_key = serde_json::to_string(key).map_err(|_| CallError::Gone);
            let quoted = serde_json::to_string(secret).map_err(|_| CallError::Gone);
            let (mut quoted_key, mut quoted) = match (quoted_key, quoted) {
                (Ok(k), Ok(v)) => (k, v),
                (k, v) => {
                    if let Ok(mut v) = v {
                        v.zeroize();
                    }
                    drop(k);
                    line.zeroize();
                    return Err(CallError::Gone);
                }
            };
            if !first {
                line.push(b',');
            }
            first = false;
            line.extend_from_slice(quoted_key.as_bytes());
            line.push(b':');
            line.extend_from_slice(quoted.as_bytes());
            quoted.zeroize();
            quoted_key.zeroize();
        }
        line.extend_from_slice(b"}}\n");
        self.send(id, line, wait)
    }

    fn send(&self, id: u64, mut line: Vec<u8>, wait: Duration) -> Result<Value, CallError> {
        let (tx, rx) = channel();
        if let Ok(mut pending) = self.pending.lock() {
            pending.insert(id, tx);
        } else {
            line.zeroize();
            return Err(CallError::Gone);
        }
        let written = match self.writer.lock() {
            Ok(mut w) => w.write_all(&line).and_then(|()| w.flush()).is_ok(),
            Err(_) => false,
        };
        line.zeroize();
        if !written {
            self.forget(id);
            return Err(CallError::Gone);
        }
        let answer = rx.recv_timeout(wait).unwrap_or(Err(CallError::Timeout));
        if answer == Err(CallError::Timeout) {
            self.forget(id);
        }
        answer
    }

    fn forget(&self, id: u64) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.remove(&id);
        }
    }
}

fn read_loop(reader: Box<dyn Read + Send>, pending: &Pending, on_note: &(dyn Fn(Value) + Send)) {
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match read_line_bounded(&mut reader, &mut buf) {
            Ok(None) | Err(_) => break,
            Ok(Some(false)) => continue, // too long: skipped
            Ok(Some(true)) => {}
        }
        let Ok(message) = serde_json::from_slice::<Value>(&buf) else {
            continue;
        };
        match message.get("id").and_then(Value::as_u64) {
            Some(id) => {
                let waiter = pending.lock().ok().and_then(|mut p| p.remove(&id));
                if let Some(waiter) = waiter {
                    let _ = waiter.send(outcome(&message));
                }
            }
            None if message.get("method").is_some() => on_note(message),
            None => {}
        }
    }
    // The host is gone: wake everyone still waiting.
    if let Ok(mut pending) = pending.lock() {
        for (_, waiter) in pending.drain() {
            let _ = waiter.send(Err(CallError::Gone));
        }
    }
}

/// Reads one line into `buf` without the newline. `None` at the end of
/// input; `Some(false)` when the line was longer than [`MAX_LINE`] and was
/// skipped.
fn read_line_bounded(reader: &mut impl BufRead, buf: &mut Vec<u8>) -> std::io::Result<Option<bool>> {
    let mut too_long = false;
    let mut any = false;
    loop {
        let chunk = reader.fill_buf()?;
        if chunk.is_empty() {
            return Ok(if any { Some(!too_long) } else { None });
        }
        any = true;
        let (part, done) = match chunk.iter().position(|b| *b == b'\n') {
            Some(at) => (chunk.get(..at).unwrap_or_default(), Some(at)),
            None => (chunk, None),
        };
        if !too_long {
            if buf.len().saturating_add(part.len()) > MAX_LINE {
                too_long = true;
                buf.clear();
            } else {
                buf.extend_from_slice(part);
            }
        }
        let used = done.map_or(chunk.len(), |at| at.saturating_add(1));
        reader.consume(used);
        if done.is_some() {
            return Ok(Some(!too_long));
        }
    }
}

fn outcome(message: &Value) -> Result<Value, CallError> {
    if let Some(error) = message.get("error") {
        let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
        // the wallet's reason, where it gives one: fixed words of its own
        // that say why ("Tor is not ready yet"); otherwise the message
        let reason = error.get("data").and_then(|d| d.get("reason")).and_then(Value::as_str).filter(|r| !r.is_empty());
        let message = reason.or_else(|| error.get("message").and_then(Value::as_str)).unwrap_or("").to_string();
        let name = error
            .get("data")
            .and_then(|d| d.get("name").or_else(|| d.get("kind")))
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| host_error_name(code).to_string());
        return Err(CallError::Rpc { code, name, message });
    }
    Ok(message.get("result").cloned().unwrap_or(Value::Null))
}

/// Names of the host's own error codes (paycore/host/README.md).
pub fn host_error_name(code: i64) -> &'static str {
    match code {
        -32040 => "locked",
        -32041 => "no_profile",
        -32042 => "profile_exists",
        -32043 => "wrong_password",
        -32044 => "guard",
        -32045 => "already_unlocked",
        -32046 => "bad_mnemonic",
        -32047 => "no_journal",
        -32048 => "profile_damaged",
        -32049 => "profile_io",
        -32050 => "busy",
        _ => "",
    }
}

/// The host process with its client. Dropping it closes the host's input:
/// the host locks the profile and exits.
pub struct Host {
    client: Arc<Client>,
    /// The process, when this window started it.
    child: Option<Child>,
    stdin_closer: Arc<Mutex<Option<ChildStdin>>>,
    /// The connection, when another process keeps the host (Android's
    /// service); closing it leaves the host running.
    #[cfg(unix)]
    socket: Option<std::os::unix::net::UnixStream>,
}

struct SharedStdin(Arc<Mutex<Option<ChildStdin>>>);

impl Write for SharedStdin {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        match self.0.lock().map_err(|_| std::io::ErrorKind::BrokenPipe)?.as_mut() {
            Some(stdin) => stdin.write(data),
            None => Err(std::io::ErrorKind::BrokenPipe.into()),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self.0.lock().map_err(|_| std::io::ErrorKind::BrokenPipe)?.as_mut() {
            Some(stdin) => stdin.flush(),
            None => Ok(()),
        }
    }
}

// Keep the identity decision before constructing a JSON-RPC client.
#[cfg(any(test, target_os = "android"))]
fn with_service_peer<T>(
    peer_uid: std::io::Result<u32>,
    own_uid: u32,
    attach: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    if peer_uid? != own_uid {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    attach()
}

impl Host {
    /// Starts `program` with `args` (none of them secret).
    pub fn spawn(program: &std::path::Path, args: &[String], on_note: Box<dyn Fn(Value) + Send>) -> std::io::Result<Host> {
        let mut command = Command::new(program);
        command.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            command.creation_flags(CREATE_NO_WINDOW);
        }
        let mut child = command.spawn()?;
        let stdout = child.stdout.take().ok_or(std::io::ErrorKind::BrokenPipe)?;
        let stdin = child.stdin.take().ok_or(std::io::ErrorKind::BrokenPipe)?;
        let stdin_closer = Arc::new(Mutex::new(Some(stdin)));
        let client = Client::start(Box::new(stdout), Box::new(SharedStdin(stdin_closer.clone())), on_note);
        Ok(Host {
            client,
            child: Some(child),
            stdin_closer,
            #[cfg(unix)]
            socket: None,
        })
    }

    /// Talks to a host another process keeps, over a connected stream (the
    /// same lines as over a pipe). Dropping the `Host` closes the connection
    /// only; the host goes on.
    #[cfg(unix)]
    pub fn attach(stream: std::os::unix::net::UnixStream, on_note: Box<dyn Fn(Value) + Send>) -> std::io::Result<Host> {
        let reader = stream.try_clone()?;
        let writer = stream.try_clone()?;
        let client = Client::start(Box::new(reader), Box::new(writer), on_note);
        Ok(Host { client, child: None, stdin_closer: Arc::new(Mutex::new(None)), socket: Some(stream) })
    }

    /// Connects to the host the app's service keeps on Android: an abstract
    /// local socket that only this app's own processes are let through (the
    /// service checks the caller's uid).
    #[cfg(target_os = "android")]
    pub fn connect_service(name: &str, on_note: Box<dyn Fn(Value) + Send>) -> std::io::Result<Host> {
        use std::os::android::net::SocketAddrExt;
        let addr = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes())?;
        let stream = std::os::unix::net::UnixStream::connect_addr(&addr)?;
        let peer = rustix::net::sockopt::socket_peercred(&stream)
            .map(|cred| cred.uid.as_raw()).map_err(std::io::Error::from);
        with_service_peer(peer, rustix::process::getuid().as_raw(), || Host::attach(stream, on_note))
    }

    /// The JSON-RPC client.
    pub fn client(&self) -> Arc<Client> {
        self.client.clone()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(socket) = self.socket.take() {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        let Some(child) = self.child.as_mut() else { return };
        if let Ok(mut stdin) = self.stdin_closer.lock() {
            stdin.take();
        }
        for _ in 0..50 {
            if matches!(child.try_wait(), Ok(Some(_))) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
mod tests;
