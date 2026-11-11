// SPDX-License-Identifier: MIT OR Apache-2.0
//! unity-tor — automatic slatepack exchange for the Unity wallet
//! (RESEARCH / NOT VERIFIED).
//!
//! Two transports, one address book:
//!
//! * **grin-wallet Tor foreign API** (`POST http://<onion>/v2/foreign`,
//!   `check_version` / `receive_tx` / `finalize_tx`). The onion is derived from
//!   the wallet's slatepack address, exactly like grin-wallet and Grin++, so
//!   they can pay us and we can pay them. The sender is NOT authenticated here:
//!   only the address it claims in the payment-proof request is known.
//! * **GrinMessenger envelopes** (signed by the sender's messenger key, ACKed):
//!   direct to the peer's messenger onion over Arti, or through a
//!   store-and-forward relay when Tor is unavailable. The messenger identity is
//!   a separate key derived from the wallet seed.
//!
//! The wallet logic itself (receive, finalize, broadcast) is the Unity wallet
//! executable, called as a subprocess; this daemon only moves slatepacks and
//! applies the acceptance policy:
//!   auto_accept = off | contacts | all
//! Invoices (I1) are never paid automatically.

use flint_messenger_wallet::{NetworkMode, ServiceConfig, WalletService};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Address book + policy (user_dir/address-book.json)
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct Contact {
    /// Contact ID: the peer's slatepack address (grin1...). Its onion (grin-wallet
    /// Tor foreign API) is derived from it.
    id: String,
    #[serde(default)]
    name: String,
    /// The peer's GrinMessenger address, if it has one (separate key).
    #[serde(default)]
    messenger: Option<String>,
    /// Accept this contact's payments automatically (auto_accept = contacts).
    #[serde(default = "yes")]
    auto: bool,
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Book {
    #[serde(default = "default_policy")]
    auto_accept: String,
    #[serde(default)]
    contacts: Vec<Contact>,
}

fn default_policy() -> String {
    "contacts".into()
}

impl Default for Book {
    fn default() -> Self {
        Book { auto_accept: default_policy(), contacts: vec![] }
    }
}

fn book_path(user_dir: &Path) -> PathBuf {
    user_dir.join("address-book.json")
}

fn load_book(user_dir: &Path) -> Book {
    fs::read_to_string(book_path(user_dir)).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

fn save_book(user_dir: &Path, b: &Book) -> Result<(), String> {
    fs::create_dir_all(user_dir).map_err(|e| format!("{e}"))?;
    fs::write(book_path(user_dir), serde_json::to_string_pretty(b).unwrap()).map_err(|e| format!("address book: {e}"))
}

/// Who is paying us and how sure we are of it.
#[derive(Debug, Clone)]
struct Sender {
    /// Slatepack address the payment claims to come from (payment proof /
    /// slatepack sender field).
    claimed: Option<String>,
    /// Messenger address that signed the envelope (authenticated), if any.
    messenger: Option<String>,
}

/// Policy: Ok(description) = accept automatically; Err(reason) = do not.
fn decide(book: &Book, s: &Sender) -> Result<String, String> {
    // A signed envelope is matched ONLY by the key that signed it: an unknown
    // signer that merely claims a contact's slatepack address is a stranger.
    // Without a signature (Tor foreign API) only the claimed address exists.
    let find = || -> Option<&Contact> {
        match &s.messenger {
            Some(m) => book.contacts.iter().find(|c| c.messenger.as_deref() == Some(m.as_str()) || c.id == *m),
            None => s.claimed.as_ref().and_then(|a| book.contacts.iter().find(|c| c.id == *a)),
        }
    };
    let how = if s.messenger.is_some() { "signed envelope" } else { "claimed in the slate (not authenticated)" };
    match book.auto_accept.as_str() {
        "all" => Ok(match find() {
            Some(c) => format!("contact '{}' ({how})", c.name),
            None => format!("anyone ({})", s.claimed.clone().or(s.messenger.clone()).unwrap_or_else(|| "no address".into())),
        }),
        // Only a signed messenger envelope proves who sent it. A Tor foreign API
        // request only CLAIMS an address (saddr in the slate), so under
        // "contacts" it is never accepted automatically: it goes to the inbox
        // and is received by hand. "all" accepts anyone anyway.
        "contacts" => match find() {
            Some(c) if c.auto && s.messenger.is_none() => Err(format!(
                "sender claims to be contact '{}' but over the Tor foreign API that is not authenticated; \
                 receive it by hand (or the contact sends a signed messenger envelope)",
                c.name
            )),
            Some(c) if c.auto => Ok(format!("contact '{}' {} ({how})", c.name, c.id)),
            Some(c) => Err(format!("contact '{}' has automatic acceptance off", c.name)),
            None => Err(format!(
                "sender {} is not in the address book",
                s.messenger.clone().or(s.claimed.clone()).unwrap_or_else(|| "(no address)".into())
            )),
        },
        _ => Err("automatic acceptance is off".into()),
    }
}

// ---------------------------------------------------------------------------
// Daemon context: the wallet executable and the files it shares with scripts
// ---------------------------------------------------------------------------

struct Ctx {
    exe: PathBuf,
    seeds: PathBuf,
    /// `--seeds -`: the phrases came on our standard input (wallet service);
    /// every wallet exe call gets them on ITS standard input, never as a file.
    seed_text: Option<String>,
    wallet: usize,
    user_dir: PathBuf,
    mainnet: bool,
    work: PathBuf,
    /// grin1... -> http://127.0.0.1:PORT (bench: foreign API without Tor).
    overrides: BTreeMap<String, String>,
    tor: Mutex<Option<Arc<flint_tor_arti::TorHttpClient>>>,
    messenger: Mutex<Option<Arc<WalletService>>>,
    log: Mutex<()>,
    /// (minute, files saved in it) for `inbox_save`.
    inbox_rate: Mutex<(u64, u32)>,
}

/// Written into a run folder once its answer is finalized.
const FINALIZED_MARK: &str = "FINALIZED";

/// Exclusive per-slate lock (`<dir>/<slate_id>.lock`), released on drop.
/// File locks conflict between handles of the same process too, so this
/// serializes threads and processes alike.
fn slate_lock(dir: &Path, slate_id: &str) -> Result<fs::File, String> {
    if !valid_slate_id(slate_id) {
        return Err("bad slate id".into());
    }
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let p = dir.join(format!("{slate_id}.lock"));
    let f = fs::OpenOptions::new().create(true).truncate(false).write(true).open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    f.lock().map_err(|e| format!("lock {}: {e}", p.display()))?;
    Ok(f)
}

// ---- inbox quota (rejected requests are saved for manual handling) ----

/// At most this many files / bytes in inbox/, and this many new files per
/// minute: rejected requests cannot fill the disk. Over the limit a request
/// is refused and only logged.
const INBOX_MAX_FILES: usize = 200;
const INBOX_MAX_BYTES: u64 = 16 * 1024 * 1024;
const INBOX_MAX_ITEM: usize = 128 * 1024;
const INBOX_PER_MINUTE: u32 = 20;

/// Save `data` as `inbox/<name>` if the quota allows; never overwrites.
fn inbox_save(inbox: &Path, name: &str, data: &[u8], rate: &Mutex<(u64, u32)>, now_secs: u64) -> Result<PathBuf, String> {
    if data.len() > INBOX_MAX_ITEM {
        return Err(format!("too large for the inbox ({} bytes)", data.len()));
    }
    {
        let mut r = rate.lock().unwrap();
        let minute = now_secs / 60;
        if r.0 != minute {
            *r = (minute, 0);
        }
        if r.1 >= INBOX_PER_MINUTE {
            return Err("inbox rate limit reached".into());
        }
        r.1 += 1;
    }
    fs::create_dir_all(inbox).map_err(|e| format!("{e}"))?;
    let (mut n, mut bytes) = (0usize, 0u64);
    for e in fs::read_dir(inbox).map_err(|e| format!("{e}"))?.flatten() {
        if let Ok(m) = e.metadata() {
            if m.is_file() {
                n += 1;
                bytes += m.len();
            }
        }
    }
    if n >= INBOX_MAX_FILES || bytes + data.len() as u64 > INBOX_MAX_BYTES {
        return Err(format!("inbox full ({n} files, {bytes} bytes): handle or delete old requests"));
    }
    let p = inbox.join(name);
    write_new(&p, data)?;
    Ok(p)
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// Unique per process and call (time, pid, sequence number): parallel
/// requests in the same second never share a temporary file name.
fn stamp() -> String {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    format!("{}-{}-{}", now(), std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst))
}

/// Create a NEW file (fails if the name exists) and write `data`.
fn write_new(path: &Path, data: &[u8]) -> Result<(), String> {
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(data).map_err(|e| format!("{}: {e}", path.display()))
}

impl Ctx {
    fn log(&self, line: &str) {
        let _g = self.log.lock().unwrap();
        let l = format!("{} {line}", now());
        println!("{l}");
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(self.work.join("daemon.log")) {
            let _ = writeln!(f, "{l}");
        }
    }

    /// Run the wallet executable; returns (exit code, stdout).
    fn exe(&self, args: &[&str]) -> Result<(i32, String), String> {
        let mut c = Command::new(&self.exe);
        if self.mainnet {
            c.arg("--mainnet");
        }
        c.args(args).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        c.stdin(if self.seed_text.is_some() { std::process::Stdio::piped() } else { std::process::Stdio::null() });
        let mut child = c.spawn().map_err(|e| format!("wallet exe {}: {e}", self.exe.display()))?;
        if let (Some(t), Some(mut stdin)) = (&self.seed_text, child.stdin.take()) {
            // The child reads the phrases once; a closed pipe just means it did not need them.
            let _ = std::io::Write::write_all(&mut stdin, t.as_bytes());
        }
        let out = child.wait_with_output().map_err(|e| format!("wallet exe {}: {e}", self.exe.display()))?;
        Ok((out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).to_string()))
    }

    fn line<'a>(out: &'a str, key: &str) -> Option<&'a str> {
        out.lines().find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
    }

    fn wallet_file(&self) -> PathBuf {
        self.user_dir.join("wallet-outputs.jsonl")
    }

    fn pending_file(&self) -> PathBuf {
        self.user_dir.join("pending-receives.jsonl")
    }

    fn tip_height(&self) -> Option<String> {
        let t = fs::read_to_string(self.wallet_file()).ok()?;
        let first = t.lines().next()?;
        let i = first.find("\"tip_height\":")? + 13;
        Some(first[i..].chars().take_while(|c| c.is_ascii_digit()).collect())
    }

    /// Receive an S1 (slatepack or slate JSON) with this wallet; returns the
    /// answer (same format as the input).
    fn receive(&self, input: &str, who: &str) -> Result<String, String> {
        let dir = self.work.join("in");
        fs::create_dir_all(&dir).map_err(|e| format!("{e}"))?;
        let st = stamp();
        let ext = if input.trim_start().starts_with('{') { "json" } else { "txt" };
        let inp = dir.join(format!("s1-{st}.{ext}"));
        let outp = dir.join(format!("s2-{st}.{ext}"));
        write_new(&inp, input.as_bytes())?;
        let w = self.wallet.to_string();
        let mut args = vec![
            "--receive-slatepack".to_string(), inp.display().to_string(),
            "--seeds".into(), self.seeds.display().to_string(),
            "--wallet".into(), w,
            "--response-out".into(), outp.display().to_string(),
            "--pending".into(), self.pending_file().display().to_string(),
        ];
        if self.wallet_file().exists() {
            args.push("--known-outputs".into());
            args.push(self.wallet_file().display().to_string());
        }
        if let Some(t) = self.tip_height() {
            args.push("--tip-height".into());
            args.push(t);
        }
        let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let (code, out) = self.exe(&a)?;
        if code != 0 {
            return Err(Self::line(&out, "RECEIVE").unwrap_or("receive failed").to_string());
        }
        self.log(&format!(
            "RECEIVED amount={} slate={} from {who} -> answer sent back",
            Self::line(&out, "RECEIVE_AMOUNT").unwrap_or("?"),
            Self::line(&out, "RECEIVE_SLATE_ID").unwrap_or("?")
        ));
        fs::read_to_string(&outp).map_err(|e| format!("{e}"))
    }

    /// Kind of a slatepack / slate JSON as the wallet sees it.
    fn info(&self, text: &str) -> Result<(String, String, String), String> {
        let dir = self.work.join("in");
        fs::create_dir_all(&dir).map_err(|e| format!("{e}"))?;
        let ext = if text.trim_start().starts_with('{') { "json" } else { "txt" };
        let p = dir.join(format!("info-{}.{ext}", stamp()));
        write_new(&p, text.as_bytes())?;
        let w = self.wallet.to_string();
        let (code, out) = self.exe(&["--slatepack-info", &p.display().to_string(), "--seeds", &self.seeds.display().to_string(), "--wallet", &w])?;
        let _ = fs::remove_file(&p);
        if code != 0 {
            return Err(Self::line(&out, "SLATE_INFO").unwrap_or("not a slatepack for this wallet").to_string());
        }
        Ok((
            Self::line(&out, "SLATE_STATE").unwrap_or("").to_string(),
            Self::line(&out, "SLATE_ID").unwrap_or("").to_string(),
            Self::line(&out, "SLATE_SENDER").filter(|s| !s.is_empty()).or(Self::line(&out, "SLATE_PROOF_SENDER")).unwrap_or("").to_string(),
        ))
    }

    fn peers(&self) -> Vec<String> {
        fs::read_to_string(self.user_dir.join("peers.txt"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| l.split_whitespace().next().map(|s| s.to_string()))
            .filter(|s| s.contains(':'))
            .take(4)
            .collect()
    }

    /// Finalize the answer to one of our sends / invoices, write the
    /// transaction into its run folder and broadcast it.
    fn finish(&self, req: &SendRequest, answer: &str) -> Result<(), String> {
        // One finalization per slate: the Foreign API, the messenger and the
        // outgoing thread may deliver the same answer at the same time. The
        // file lock serializes them (also across processes); whoever comes
        // second sees the FINALIZED marker and does nothing.
        let _lock = slate_lock(&self.sends_dir(), &req.slate_id)?;
        let folder = PathBuf::from(&req.tx_folder);
        if folder.join(FINALIZED_MARK).exists() {
            self.log(&format!("slate={} already finalized: second answer ignored", req.slate_id));
            return Ok(());
        }
        let ext = if answer.trim_start().starts_with('{') { "json" } else { "txt" };
        let ans = folder.join(format!("slatepack-answer.{ext}"));
        fs::write(&ans, answer).map_err(|e| format!("{e}"))?;
        let tx = folder.join("spend-tx.hex");
        let (code, out) = if req.kind == "invoice" {
            self.exe(&[
                "--finalize-invoice", &ans.display().to_string(), "--seeds", &self.seeds.display().to_string(),
                "--invoice-context", &req.context, "--tx-out", &tx.display().to_string(),
            ])?
        } else {
            self.exe(&[
                "--finalize-slatepack", &ans.display().to_string(), "--seeds", &self.seeds.display().to_string(),
                "--send-context", &req.context, "--tx-out", &tx.display().to_string(),
                "--proof-out", &folder.join("payment-proof.json").display().to_string(),
            ])?
        };
        fs::write(folder.join("05-finalize-auto.log"), &out).ok();
        if code != 0 {
            return Err(Self::line(&out, "FINALIZE").unwrap_or("finalize failed").to_string());
        }
        // Finalized (context consumed): never again for this slate, even if
        // the broadcast below fails (-Broadcast resends the saved tx).
        fs::write(folder.join(FINALIZED_MARK), format!("{}\n", now())).map_err(|e| format!("finalized, marker not written: {e}"))?;
        // -Broadcast / -Confirm read the details from the run folder's log.
        let spend: String = out.lines().filter(|l| l.starts_with("GAP_SPEND_")).map(|l| format!("{l}\n")).collect();
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(folder.join("30-wallet.log")) {
            let _ = f.write_all(spend.as_bytes());
        }
        let peers = self.peers();
        if peers.is_empty() {
            return Err("finalized, but no peers known for broadcast (peers.txt): run -Broadcast".into());
        }
        let mut args = vec!["--broadcast-tx".to_string(), tx.display().to_string()];
        for p in &peers {
            args.push("--peer".into());
            args.push(p.clone());
        }
        args.push("--allow-mainnet-spend".into());
        let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let (bcode, bout) = self.exe(&a)?;
        fs::write(folder.join("40-broadcast-auto.log"), &bout).ok();
        let sent = bout.lines().filter(|l| l.starts_with("BROADCAST_TX=") && l.ends_with("SENT")).count();
        fs::write(
            folder.join("AUTO_RESULT.txt"),
            format!("finalized and broadcast: sent to {sent} peer(s), exit {bcode}\nkernel {}\n", Self::line(&out, "GAP_SPEND_KERNEL_EXCESS").unwrap_or("?")),
        )
        .ok();
        if sent == 0 {
            return Err("finalized, broadcast failed on every peer: run -Broadcast".into());
        }
        self.log(&format!("FINALIZED+BROADCAST slate={} peers={sent} kernel={}", req.slate_id, Self::line(&out, "GAP_SPEND_KERNEL_EXCESS").unwrap_or("?")));
        Ok(())
    }

    fn sends_dir(&self) -> PathBuf {
        self.work.join("sends")
    }

    fn find_send(&self, slate_id: &str) -> Option<SendRequest> {
        if !valid_slate_id(slate_id) {
            return None;
        }
        let t = fs::read_to_string(self.sends_dir().join(format!("{slate_id}.json"))).ok()?;
        serde_json::from_str(&t).ok()
    }

    fn mark_send(&self, req: &SendRequest, status: &str) {
        if !valid_slate_id(&req.slate_id) {
            return;
        }
        let dir = if req.kind == "reply" { self.work.join("replies") } else { self.sends_dir() };
        if let Err(e) = fs::create_dir_all(&dir).and_then(|_| fs::write(dir.join(format!("{}.status", req.slate_id)), format!("{} {status}\n", now()))) {
            self.log(&format!("status of slate={} not saved: {e}", req.slate_id));
        }
        if let Err(e) = fs::write(PathBuf::from(&req.tx_folder).join("AUTO_STATUS.txt"), format!("{status}\n")) {
            self.log(&format!("AUTO_STATUS for slate={} not written: {e}", req.slate_id));
        }
    }
}

// ---------------------------------------------------------------------------
// Requests the scripts put into the outbox
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SendRequest {
    /// "send" (we pay; S1 out, S2 back) or "invoice" (we invoice; I1 out, I2 back).
    kind: String,
    slate_id: String,
    to: String,
    /// Plain V4 slate JSON (grin-wallet Tor foreign API). Only for "send".
    #[serde(default)]
    slate_json: Option<String>,
    /// Encrypted slatepack (messenger envelope).
    armor: String,
    context: String,
    tx_folder: String,
    #[serde(default)]
    messenger: Option<String>,
    /// Skip the grin-wallet foreign API and go straight to the messenger
    /// (signed envelope: the receiver can authenticate the sender).
    #[serde(default)]
    messenger_only: bool,
}

// ---------------------------------------------------------------------------
// Minimal HTTP (loopback server for the onion; plain client for the bench)
// ---------------------------------------------------------------------------

const MAX_BODY: usize = 1024 * 1024;
/// Request line and each header line (bytes).
const MAX_LINE: usize = 8 * 1024;
/// All header lines together (bytes) and their number.
const MAX_HEADERS_BYTES: usize = 32 * 1024;
const MAX_HEADERS: usize = 64;
/// Connections served at the same time; more are refused at once.
const MAX_CONNECTIONS: usize = 16;
/// The whole request (line, headers, body) must arrive within this time; a
/// client trickling bytes cannot hold a connection slot longer.
const REQUEST_DEADLINE: Duration = Duration::from_secs(20);

/// A reader that fails once `deadline` has passed (each read gets only the
/// time that is left), so a slow trickle cannot keep a request open.
struct Deadline<R> {
    inner: R,
    deadline: std::time::Instant,
    set: Box<dyn FnMut(Duration) + Send>,
}

impl<R: Read> Read for Deadline<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "request deadline"));
        }
        (self.set)(left);
        self.inner.read(buf)
    }
}

/// A slate id is a UUID (8-4-4-4-12 hex). Ids from the network or from files
/// become file names (inbox, sends, outbox), so nothing else is accepted:
/// no separators, no "..", no drive letters, no absolute paths.
fn valid_slate_id(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// One line of at most `max` bytes (a longer one is an error, not a buffer).
fn read_line_limited<R: BufRead>(r: &mut R, max: usize) -> Result<String, String> {
    let mut buf = Vec::new();
    let n = r.by_ref().take(max as u64 + 1).read_until(b'\n', &mut buf).map_err(|e| format!("{e}"))?;
    if n > max || (n == max + 1 && buf.last() != Some(&b'\n')) {
        return Err("line too long".into());
    }
    String::from_utf8(buf).map_err(|_| "header is not UTF-8".to_string())
}

fn read_request(stream: &mut TcpStream) -> Result<(String, String, Vec<u8>), String> {
    read_request_within(stream, REQUEST_DEADLINE)
}

fn read_request_within(stream: &mut TcpStream, limit: Duration) -> Result<(String, String, Vec<u8>), String> {
    let s2 = stream.try_clone().map_err(|e| format!("{e}"))?;
    let ctl = stream.try_clone().map_err(|e| format!("{e}"))?;
    let mut r = BufReader::new(Deadline {
        inner: s2,
        deadline: std::time::Instant::now() + limit,
        set: Box::new(move |left| {
            ctl.set_read_timeout(Some(left.max(Duration::from_millis(1)))).ok();
        }),
    });
    parse_request(&mut r)
}

/// The HTTP request parser itself (no socket): request line, headers within
/// MAX_LINE / MAX_HEADERS / MAX_HEADERS_BYTES, body within MAX_BODY.
fn parse_request<R: BufRead>(r: &mut R) -> Result<(String, String, Vec<u8>), String> {
    let first = read_line_limited(r, MAX_LINE)?;
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut len = 0usize;
    let (mut count, mut total) = (0usize, 0usize);
    loop {
        let h = read_line_limited(r, MAX_LINE)?;
        if h.is_empty() {
            return Err("connection closed inside the headers".into());
        }
        count += 1;
        total += h.len();
        if count > MAX_HEADERS || total > MAX_HEADERS_BYTES {
            return Err("too many / too large headers".into());
        }
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                len = v.trim().parse().map_err(|_| "bad content-length".to_string())?;
            }
        }
    }
    if len > MAX_BODY {
        return Err("body too large".into());
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|e| format!("{e}"))?;
    Ok((method, path, body))
}

fn respond(stream: &mut TcpStream, code: u16, body: &str) {
    let reason = match code {
        200 => "OK",
        503 => "Service Unavailable",
        _ => "Error",
    };
    let _ = write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

/// Plain HTTP POST (bench overrides on 127.0.0.1 only).
fn plain_post(url: &str, body: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let rest = url.strip_prefix("http://").ok_or("only http:// URLs")?;
    let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    if !(host.starts_with("127.0.0.1:") || host.starts_with("localhost:")) {
        return Err("plain HTTP is for loopback bench URLs only".into());
    }
    let mut s = TcpStream::connect(host).map_err(|e| format!("connect {host}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(120))).ok();
    write!(s, "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
        .map_err(|e| format!("{e}"))?;
    s.write_all(body).map_err(|e| format!("{e}"))?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| format!("{e}"))?;
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, b) = text.split_once("\r\n\r\n").ok_or("bad HTTP answer")?;
    let code: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    Ok((code, b.as_bytes().to_vec()))
}

fn rpc_ok(id: &Value, v: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "result": {"Ok": v}}).to_string()
}

fn rpc_err(id: &Value, msg: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32000, "message": msg}}).to_string()
}

/// grin-wallet's foreign API, the part a sender uses over Tor.
fn handle_foreign(ctx: &Ctx, body: &[u8]) -> String {
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return rpc_err(&Value::Null, &format!("bad JSON-RPC: {e}")),
    };
    let id = req["id"].clone();
    match req["method"].as_str().unwrap_or("") {
        "check_version" => rpc_ok(&id, json!({"foreign_api_version": 2, "supported_slate_versions": ["V4"]})),
        "receive_tx" => {
            let slate = &req["params"][0];
            if slate["sta"].as_str() != Some("S1") {
                return rpc_err(&id, "receive_tx expects an S1 slate");
            }
            let hrp = if ctx.mainnet { "grin" } else { "tgrin" };
            let claimed = slate["proof"]["saddr"]
                .as_str()
                .and_then(|h| data_encoding::HEXLOWER_PERMISSIVE.decode(h.as_bytes()).ok())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .and_then(|k| flint_tor_arti::address_from_key(hrp, &k).ok());
            let sender = Sender { claimed: claimed.clone(), messenger: None };
            let sid = slate["id"].as_str().unwrap_or("").to_string();
            if !valid_slate_id(&sid) {
                return rpc_err(&id, "bad slate id (expected a UUID)");
            }
            match decide(&load_book(&ctx.user_dir), &sender) {
                Ok(who) => match ctx.receive(&slate.to_string(), &who) {
                    Ok(answer) => match serde_json::from_str::<Value>(&answer) {
                        Ok(v) => rpc_ok(&id, v),
                        Err(e) => rpc_err(&id, &format!("answer: {e}")),
                    },
                    Err(e) => {
                        ctx.log(&format!("RECEIVE FAILED slate={sid}: {e}"));
                        rpc_err(&id, &format!("receive failed: {e}"))
                    }
                },
                Err(reason) => {
                    let saved = match inbox_save(&ctx.work.join("inbox"), &format!("{sid}.json"), slate.to_string().as_bytes(), &ctx.inbox_rate, now()) {
                        Ok(_) => "saved in inbox; receive it by hand with -Receive".to_string(),
                        Err(e) => format!("NOT saved: {e}"),
                    };
                    ctx.log(&format!("NOT ACCEPTED slate={sid} from {}: {reason} ({saved})", claimed.unwrap_or_default()));
                    rpc_err(&id, &format!("not accepted automatically ({reason}); send a slatepack instead"))
                }
            }
        }
        "finalize_tx" => {
            // A payer returns our invoice (I2) over Tor.
            let slate = &req["params"][0];
            let sid = slate["id"].as_str().unwrap_or("").to_string();
            if !valid_slate_id(&sid) {
                return rpc_err(&id, "bad slate id (expected a UUID)");
            }
            match ctx.find_send(&sid) {
                Some(r) if r.kind == "invoice" => match ctx.finish(&r, &slate.to_string()) {
                    Ok(()) => {
                        ctx.mark_send(&r, "PAID_FINALIZED_BROADCAST");
                        rpc_ok(&id, slate.clone())
                    }
                    Err(e) => {
                        ctx.mark_send(&r, &format!("FAILED {e}"));
                        rpc_err(&id, &e)
                    }
                },
                _ => rpc_err(&id, "unknown invoice"),
            }
        }
        m => rpc_err(&id, &format!("method {m} not supported")),
    }
}

/// Counts live connections; the slot is given back when the guard drops.
struct ConnSlot(Arc<AtomicUsize>);
impl ConnSlot {
    fn take(active: &Arc<AtomicUsize>, max: usize) -> Option<ConnSlot> {
        let prev = active.fetch_add(1, Ordering::SeqCst);
        if prev >= max {
            active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(ConnSlot(active.clone()))
    }
}
impl Drop for ConnSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn serve_http(ctx: Arc<Ctx>, listener: TcpListener) {
    let active = Arc::new(AtomicUsize::new(0));
    for s in listener.incoming() {
        let Ok(mut stream) = s else { continue };
        let Some(slot) = ConnSlot::take(&active, MAX_CONNECTIONS) else {
            // Busy: refuse without a thread (a slow client cannot hold us).
            stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
            respond(&mut stream, 503, "{\"error\":\"busy\"}");
            continue;
        };
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _slot = slot;
            let (method, path, body) = match read_request(&mut stream) {
                Ok(r) => r,
                Err(_) => return,
            };
            if method == "POST" && path.trim_end_matches('/') == "/v2/foreign" {
                let ans = handle_foreign(&ctx, &body);
                respond(&mut stream, 200, &ans);
            } else {
                respond(&mut stream, 404, "{\"error\":\"not found\"}");
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Outgoing: deliver S1 / I1, collect the answer, finalize, broadcast
// ---------------------------------------------------------------------------

fn foreign_url(ctx: &Ctx, to: &str) -> Result<String, String> {
    if let Some(u) = ctx.overrides.get(to) {
        return Ok(format!("{}/v2/foreign", u.trim_end_matches('/')));
    }
    let onion = flint_tor_arti::onion_from_address(to).map_err(|e| format!("onion of {to}: {e}"))?;
    Ok(format!("http://{onion}.onion/v2/foreign"))
}

fn post(ctx: &Ctx, url: &str, body: &Value) -> Result<Value, String> {
    let bytes = body.to_string().into_bytes();
    let (code, ans) = if url.contains(".onion/") {
        let client = ctx.tor.lock().unwrap().clone().ok_or("Tor is not available")?;
        client.request("POST", url, &bytes).map_err(|e| format!("{e}"))?
    } else {
        plain_post(url, &bytes)?
    };
    if code != 200 {
        return Err(format!("HTTP {code}"));
    }
    let v: Value = serde_json::from_slice(&ans).map_err(|e| format!("answer: {e}"))?;
    if !v["error"].is_null() {
        return Err(format!("{}", v["error"]["message"]));
    }
    if !v["result"]["Err"].is_null() {
        return Err(format!("{}", v["result"]["Err"]));
    }
    Ok(v["result"]["Ok"].clone())
}

/// Standard path: the receiver's grin-wallet compatible onion answers S2 at once.
fn send_via_foreign_api(ctx: &Ctx, req: &SendRequest) -> Result<String, String> {
    let json_path = req.slate_json.as_ref().ok_or("no slate JSON")?;
    let slate: Value = serde_json::from_str(&fs::read_to_string(json_path).map_err(|e| format!("{e}"))?).map_err(|e| format!("{e}"))?;
    let url = foreign_url(ctx, &req.to)?;
    let v = post(ctx, &url, &json!({"jsonrpc": "2.0", "method": "check_version", "id": 1, "params": []}))?;
    if v["foreign_api_version"].as_u64().unwrap_or(0) < 2 {
        return Err("other wallet: unsupported foreign API".into());
    }
    let s2 = post(ctx, &url, &json!({"jsonrpc": "2.0", "method": "receive_tx", "id": 1, "params": [slate, null, null]}))?;
    Ok(s2.to_string())
}

/// Queue states (each a directory of `<slate_id>.json`):
///   outbox/  -> written by `queue`; picked up here
///   sends/   -> accepted: a send / invoice waiting for its answer (has a
///               `.status` once dispatched); replies go to `replies/`
/// A request leaves outbox/ only AFTER it is stored in sends/ or replies/
/// (write to a temporary name, then rename); a crash in between leaves it in
/// outbox/ and it is taken again. Requests stored but never dispatched (no
/// `.status`) are dispatched again when the daemon starts.
/// Result of taking one outbox file (see `accept_file`).
enum Accept {
    /// Stored now and removed from outbox/: dispatch it.
    Dispatch(SendRequest),
    /// The same request was already stored by an earlier pass (whose removal
    /// from outbox/ failed): outbox file removed now, NOT dispatched again.
    AlreadyStored,
    /// Nothing changed (read / store / remove failed): try again next pass.
    Retry(String),
    /// Not a valid request: set aside as `.bad`.
    Parked(String),
}

/// Take one outbox file. The request leaves outbox/ only AFTER it is stored
/// in sends/ or replies/ (temporary name + rename); a request already stored
/// there is never dispatched a second time from outbox/.
fn accept_file(p: &Path, sends: &Path, replies: &Path) -> Accept {
    let t = match fs::read_to_string(p) {
        Ok(t) => t,
        Err(e) => return Accept::Retry(format!("cannot read ({e})")),
    };
    let park = |why: String| {
        let bad = p.with_extension("bad");
        match fs::rename(p, &bad) {
            Ok(()) => Accept::Parked(format!("{why}; moved to {}", bad.display())),
            Err(e) => Accept::Parked(format!("{why}; could not set it aside: {e}")),
        }
    };
    let req = match serde_json::from_str::<SendRequest>(&t) {
        Ok(r) => r,
        Err(e) => return park(format!("not a request ({e})")),
    };
    if !valid_slate_id(&req.slate_id) {
        return park("bad slate id".into());
    }
    // "reply" = our answer to someone else's request (I2 to an invoice):
    // nothing comes back for it, so it is not a pending send.
    let dir = if req.kind == "reply" { replies } else { sends };
    let target = dir.join(format!("{}.json", req.slate_id));
    if let Ok(stored) = fs::read_to_string(&target) {
        // A reply (our I2) whose earlier delivery FAILED may be queued again
        // (same slate, new run folder): it replaces the failed one. Anything
        // else with the same slate id is refused.
        let failed_reply = req.kind == "reply"
            && fs::read_to_string(target.with_extension("status"))
                .map(|st| st.split_once(' ').map_or(false, |(_, s)| s.starts_with("FAILED")))
                .unwrap_or(false);
        if stored != t && failed_reply {
            if let Err(e) = fs::remove_file(&target) {
                return Accept::Retry(format!("failed reply not replaced ({e})"));
            }
            let _ = fs::remove_file(target.with_extension("status"));
            return accept_file(p, sends, replies);
        }
        if stored != t {
            return park(format!("another request for slate {} is already stored", req.slate_id));
        }
        return match fs::remove_file(p) {
            Ok(()) => Accept::AlreadyStored,
            Err(e) => Accept::Retry(format!("already stored, not removed ({e})")),
        };
    }
    let stored = (|| -> Result<(), String> {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let tmp = dir.join(format!("{}.json.tmp", req.slate_id));
        fs::write(&tmp, &t).map_err(|e| format!("{}: {e}", tmp.display()))?;
        fs::rename(&tmp, &target).map_err(|e| format!("store: {e}"))
    })();
    if let Err(e) = stored {
        return Accept::Retry(format!("not stored ({e})"));
    }
    match fs::remove_file(p) {
        Ok(()) => Accept::Dispatch(req),
        // Stored but still in outbox/: dispatched by this pass; the next pass
        // finds it stored and only removes the outbox file (AlreadyStored).
        Err(_) => Accept::Dispatch(req),
    }
}

fn accept_outbox_file(ctx: &Ctx, p: &Path) -> Option<SendRequest> {
    match accept_file(p, &ctx.sends_dir(), &ctx.work.join("replies")) {
        Accept::Dispatch(r) => Some(r),
        Accept::AlreadyStored => {
            ctx.log(&format!("outbox {}: already stored and dispatched; removed", p.display()));
            None
        }
        Accept::Retry(why) => {
            ctx.log(&format!("outbox {}: {why}; will retry", p.display()));
            None
        }
        Accept::Parked(why) => {
            ctx.log(&format!("outbox {}: {why}", p.display()));
            None
        }
    }
}

/// Requests stored in sends/ or replies/ that never got past "DISPATCHED"
/// (a stop between accepting and delivering): dispatch them again. A second
/// delivery is harmless: the receiver refuses a slate it already answered.
fn resume_undispatched(ctx: &Arc<Ctx>) {
    for dir in [ctx.sends_dir(), ctx.work.join("replies")] {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) != Some("json") {
                continue;
            }
            // Done (a final status) or waiting for an answer: nothing to resume.
            // "DISPATCHED" only means the attempt started before a stop.
            match fs::read_to_string(p.with_extension("status")) {
                Ok(st) if !st.trim_end().ends_with("DISPATCHED") => continue,
                _ => {}
            }
            let Some(req) = fs::read_to_string(&p).ok().and_then(|t| serde_json::from_str::<SendRequest>(&t).ok()) else { continue };
            if !valid_slate_id(&req.slate_id) {
                continue;
            }
            ctx.log(&format!("RESUME {} slate={} (stored, never dispatched)", req.kind, req.slate_id));
            dispatch(ctx, req);
        }
    }
}

fn process_outbox(ctx: &Arc<Ctx>) {
    let dir = ctx.work.join("outbox");
    let Ok(rd) = fs::read_dir(&dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        if let Some(req) = accept_outbox_file(ctx, &p) {
            dispatch(ctx, req);
        }
    }
}

fn dispatch(ctx: &Arc<Ctx>, req: SendRequest) {
    {
        ctx.mark_send(&req, "DISPATCHED");
        ctx.log(&format!("OUTGOING {} slate={} to {}", req.kind, req.slate_id, req.to));
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            // 1) grin-wallet Tor foreign API (payments only): synchronous answer.
            if req.kind == "send" && !req.messenger_only {
                match send_via_foreign_api(&ctx, &req) {
                    Ok(s2) => {
                        ctx.log(&format!("S2 received over the Tor foreign API for slate={}", req.slate_id));
                        match ctx.finish(&req, &s2) {
                            Ok(()) => ctx.mark_send(&req, "DONE via Tor foreign API: finalized and broadcast"),
                            Err(e) => ctx.mark_send(&req, &format!("FAILED after S2: {e}")),
                        }
                        return;
                    }
                    Err(e) => ctx.log(&format!("foreign API to {} failed: {e}; trying the messenger", req.to)),
                }
            }
            // 2) GrinMessenger envelope (direct onion or relay); the answer
            //    comes back as an event and is finished there.
            let book = load_book(&ctx.user_dir);
            let target = req
                .messenger
                .clone()
                .or_else(|| book.contacts.iter().find(|c| c.id == req.to).and_then(|c| c.messenger.clone()));
            let svc = ctx.messenger.lock().unwrap().clone();
            match (target, svc) {
                (Some(m), Some(svc)) => match svc.send_slatepack(&m, &fs::read_to_string(&req.armor).unwrap_or_default(), None) {
                    Ok(_) if req.kind == "reply" => {
                        ctx.mark_send(&req, &format!("DONE: answer sent via messenger to {m}; the issuer finalizes and broadcasts"));
                        ctx.log(&format!("answer for slate={} sent via messenger to {m}", req.slate_id));
                    }
                    Ok(_) => {
                        ctx.mark_send(&req, &format!("SENT via messenger to {m}; waiting for the answer"));
                        ctx.log(&format!("sent slate={} via messenger to {m}", req.slate_id));
                    }
                    Err(e) => ctx.mark_send(&req, &format!("FAILED: messenger send: {e}")),
                },
                (None, _) => ctx.mark_send(&req, "FAILED: receiver not reachable over Tor and has no messenger address in the address book"),
                (_, None) => ctx.mark_send(&req, "FAILED: messenger not running"),
            }
        });
    }
}

/// (id, peer, armor) of every incoming slatepack in the messenger history.
fn incoming_slatepacks(svc: &WalletService) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let mut after = 0u64;
    loop {
        let page = svc.messages(after, 1000);
        if page.messages.is_empty() {
            break;
        }
        for m in &page.messages {
            if m.direction == "incoming" && m.kind == "slatepack" {
                if let Some(a) = &m.armor {
                    out.push((m.id.clone(), m.peer.clone(), a.clone()));
                }
            }
        }
        if page.next <= after {
            break;
        }
        after = page.next;
    }
    out
}

/// One pass: every incoming slatepack (id, peer, armor) of the history that is
/// not in `done` is handed to `handle`, then marked. Returns errors to log.
fn process_unhandled(msgs: Vec<(String, String, String)>, done: &mut Processed, mut handle: impl FnMut(&str, &str)) -> Vec<String> {
    let mut errs = Vec::new();
    for (id, peer, armor) in msgs {
        if done.contains(&id) {
            continue;
        }
        handle(&peer, &armor);
        if let Err(e) = done.mark(&id) {
            errs.push(format!("processing list not updated for {id}: {e}"));
        }
    }
    errs
}

fn all_incoming_ids(svc: &WalletService) -> Vec<String> {
    incoming_slatepacks(svc).into_iter().map(|m| m.0).collect()
}

/// Durable set of messenger message ids already handed to the wallet (one
/// id per line, appended + fsynced after handling). When the file does not
/// exist yet (first start of this version) the messages already in the
/// history are taken as handled, so an upgrade does not replay old payments.
struct Processed {
    path: PathBuf,
    ids: std::collections::HashSet<String>,
    baselined: usize,
}

impl Processed {
    fn open(path: &Path, existing: impl FnOnce() -> Vec<String>) -> Processed {
        let mut p = Processed { path: path.to_path_buf(), ids: Default::default(), baselined: 0 };
        match fs::read_to_string(path) {
            Ok(t) => p.ids = t.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect(),
            Err(_) => {
                for id in existing() {
                    if p.mark(&id).is_ok() {
                        p.baselined += 1;
                    }
                }
                if p.baselined == 0 {
                    let _ = fs::write(path, "");
                }
            }
        }
        p
    }

    fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    fn mark(&mut self, id: &str) -> Result<(), String> {
        if id.is_empty() || id.len() > 256 || id.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err("unusable message id".into());
        }
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&self.path).map_err(|e| format!("{e}"))?;
        f.write_all(format!("{id}\n").as_bytes()).map_err(|e| format!("{e}"))?;
        f.sync_all().map_err(|e| format!("{e}"))?;
        self.ids.insert(id.to_string());
        Ok(())
    }
}

/// An envelope with a slatepack arrived (sender authenticated by signature).
fn handle_envelope(ctx: &Ctx, svc: &WalletService, peer: &str, armor: &str) {
    let (state, sid, sender) = match ctx.info(armor) {
        Ok(x) => x,
        Err(e) => {
            ctx.log(&format!("envelope from {peer}: not a slatepack for this wallet: {e}"));
            return;
        }
    };
    if !valid_slate_id(&sid) {
        ctx.log(&format!("envelope from {peer}: bad slate id, ignored"));
        return;
    }
    match state.as_str() {
        "S1" => {
            let s = Sender { claimed: Some(sender.clone()).filter(|x| !x.is_empty()), messenger: Some(peer.to_string()) };
            match decide(&load_book(&ctx.user_dir), &s) {
                Ok(who) => match ctx.receive(armor, &who) {
                    Ok(answer) => {
                        if let Err(e) = svc.send_slatepack(peer, &answer, None) {
                            ctx.log(&format!("answer to {peer} for slate={sid} not sent: {e}"));
                        }
                    }
                    Err(e) => ctx.log(&format!("RECEIVE FAILED slate={sid} from {peer}: {e}")),
                },
                Err(reason) => {
                    let saved = match inbox_save(&ctx.work.join("inbox"), &format!("{sid}.txt"), armor.as_bytes(), &ctx.inbox_rate, now()) {
                        Ok(_) => "saved in inbox; receive it by hand with -Receive".to_string(),
                        Err(e) => format!("NOT saved: {e}"),
                    };
                    ctx.log(&format!("NOT ACCEPTED slate={sid} from {peer}: {reason} ({saved})"));
                }
            }
        }
        "S2" | "I2" => match ctx.find_send(&sid) {
            Some(r) => match ctx.finish(&r, armor) {
                Ok(()) => ctx.mark_send(&r, &format!("DONE via messenger ({state}): finalized and broadcast")),
                Err(e) => ctx.mark_send(&r, &format!("FAILED after {state}: {e}")),
            },
            None => ctx.log(&format!("{state} from {peer} for unknown slate={sid}: ignored")),
        },
        "I1" => {
            let inbox = ctx.work.join("inbox");
            if inbox.join(format!("invoice-{sid}.txt")).exists() {
                ctx.log(&format!("INVOICE from {peer} slate={sid}: already in the inbox"));
                return;
            }
            match inbox_save(&inbox, &format!("invoice-{sid}.txt"), armor.as_bytes(), &ctx.inbox_rate, now()) {
                Ok(_) => {
                    // Whom to send the answer to (the signed envelope's sender).
                    let _ = fs::write(inbox.join(format!("invoice-{sid}.peer")), peer);
                    ctx.log(&format!("INVOICE from {peer} slate={sid}: never paid automatically; pay it with -PayInvoice inbox -Tor"));
                }
                Err(e) => ctx.log(&format!("INVOICE from {peer} slate={sid}: NOT saved: {e}")),
            }
        }
        other => ctx.log(&format!("{other} from {peer} slate={sid}: ignored")),
    }
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn hex32(s: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let b = data_encoding::HEXLOWER_PERMISSIVE.decode(s.trim().as_bytes()).map_err(|_| "hex".to_string())?;
    let mut out = Zeroizing::new([0u8; 32]);
    if b.len() != 32 {
        return Err("expected 32 bytes".into());
    }
    out.copy_from_slice(&b);
    Ok(out)
}

fn write_status(ctx: &Ctx, v: &Value) {
    let _ = fs::write(ctx.work.join("status.json"), serde_json::to_string_pretty(v).unwrap());
}

fn serve(args: &[String]) -> Result<(), String> {
    let exe = PathBuf::from(arg(args, "--exe").ok_or("--exe")?);
    let seeds = PathBuf::from(arg(args, "--seeds").ok_or("--seeds")?);
    let seed_text = if seeds.as_os_str() == "-" {
        let mut t = String::new();
        std::io::Read::read_to_string(&mut std::io::Read::take(std::io::stdin(), 64 * 1024), &mut t)
            .map_err(|e| format!("seeds on standard input: {e}"))?;
        Some(t)
    } else {
        None
    };
    let user_dir = PathBuf::from(arg(args, "--user-dir").ok_or("--user-dir")?);
    let wallet: usize = arg(args, "--wallet").and_then(|w| w.parse().ok()).unwrap_or(1);
    let mainnet = flag(args, "--mainnet");
    let no_tor = flag(args, "--no-tor");
    let port: u16 = arg(args, "--port").and_then(|p| p.parse().ok()).unwrap_or(0);
    let relay = arg(args, "--relay");
    let work = user_dir.join(format!("tor-wallet-{wallet}"));
    for d in ["outbox", "inbox", "sends", "in"] {
        fs::create_dir_all(work.join(d)).map_err(|e| format!("{e}"))?;
    }
    // One daemon per wallet: a second one would fight over the onion service
    // and hang in Arti; the OS drops the lock when the process dies.
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(work.join("daemon.lock"))
        .map_err(|e| format!("daemon.lock: {e}"))?;
    if lock.try_lock().is_err() {
        return Err(format!(
            "another unity-tor daemon of wallet {wallet} is already running (close its window; if none is visible: Get-Process unity-tor | Stop-Process -Force)"
        ));
    }
    let _lock = lock;
    let mut overrides = BTreeMap::new();
    for (i, a) in args.iter().enumerate() {
        if a == "--foreign-override" {
            if let Some((k, v)) = args.get(i + 1).and_then(|x| x.split_once('=')) {
                overrides.insert(k.to_string(), v.to_string());
            }
        }
    }
    let ctx = Arc::new(Ctx {
        exe,
        seeds,
        seed_text,
        wallet,
        user_dir: user_dir.clone(),
        mainnet,
        work: work.clone(),
        overrides,
        tor: Mutex::new(None),
        messenger: Mutex::new(None),
        log: Mutex::new(()),
        inbox_rate: Mutex::new((0, 0)),
    });
    // Keys from the wallet (stdout of the wallet exe only).
    let (code, out) = ctx.exe(&["--tor-keys", "--seeds", &ctx.seeds.display().to_string(), "--wallet", &wallet.to_string()])?;
    if code != 0 {
        return Err("wallet exe --tor-keys failed".into());
    }
    let address = Ctx::line(&out, "ADDRESS").ok_or("no ADDRESS")?.to_string();
    let addr_seed = hex32(Ctx::line(&out, "ADDRESS_SECRET_HEX").ok_or("no address secret")?)?;
    let msg_seed = hex32(Ctx::line(&out, "MESSAGING_SEED_HEX").ok_or("no messaging seed")?)?;
    let onion = flint_tor_arti::onion_address(&addr_seed);

    // grin-wallet foreign API on loopback; the onion forwards to it.
    let listener = TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("listen: {e}"))?;
    let local = listener.local_addr().map_err(|e| format!("{e}"))?.to_string();
    {
        let c = ctx.clone();
        std::thread::spawn(move || serve_http(c, listener));
    }
    ctx.log(&format!("wallet {wallet} address {address}; foreign API on http://{local}/v2/foreign; onion {onion}.onion"));
    let status = Arc::new(Mutex::new(json!({
        "wallet": wallet, "address": address, "onion": format!("{onion}.onion"), "foreign_api_local": format!("http://{local}/v2/foreign"),
        "tor": if no_tor { "off" } else { "starting" }, "messenger": "starting", "policy": load_book(&user_dir).auto_accept,
    })));
    write_status(&ctx, &status.lock().unwrap());

    // Tor: onion service for the foreign API + client for outgoing requests.
    let mut onion_service = None;
    if !no_tor {
        let cfg = flint_tor_arti::TorConfig::new(work.join("arti"));
        ctx.log("Tor: bootstrapping Arti (30-150 s the first time)...");
        match flint_tor_arti::OnionService::start(&addr_seed, &local, &cfg) {
            Ok(s) => {
                ctx.log(&format!("Tor: onion service published: {}", s.url()));
                onion_service = Some(s);
                match flint_tor_arti::TorHttpClient::bootstrap(&cfg) {
                    Ok(c) => *ctx.tor.lock().unwrap() = Some(Arc::new(c)),
                    Err(e) => ctx.log(&format!("Tor client: {e}")),
                }
                status.lock().unwrap()["tor"] = json!("ready");
            }
            Err(e) => {
                ctx.log(&format!("Tor FAILED: {e} (the messenger relay is used if configured)"));
                status.lock().unwrap()["tor"] = json!(format!("failed: {e}"));
            }
        }
        write_status(&ctx, &status.lock().unwrap());
    }

    // GrinMessenger: direct over Tor when it works, else the relay.
    let tor_ok = ctx.tor.lock().unwrap().is_some();
    let mode = match (&relay, tor_ok) {
        (_, true) => Some(NetworkMode::Direct),
        (Some(url), false) => Some(NetworkMode::Relay { url: url.clone(), plain: flag(args, "--relay-plain") }),
        (None, false) => None,
    };
    // GlauxNet = where messages wait for us: "local" is our own mailbox
    // (loopback gateway published as our onion), "remote" a configured relay.
    status.lock().unwrap()["glauxnet"] = json!(match &mode {
        Some(NetworkMode::Direct) => "local".to_string(),
        Some(NetworkMode::Relay { url, .. }) => format!("remote {url}"),
        None => "off".to_string(),
    });
    if let Some(mode) = mode {
        let label = mode.label();
        let cfg = ServiceConfig {
            data_dir: work.join("messenger"),
            network: if mainnet { "mainnet".into() } else { "testnet".into() },
            mode,
            poll_secs: 2,
            fetch_limit: 100,
            ttl_secs: 12 * 60 * 60,
            tor_state: Some(work.join("arti")),
        };
        match WalletService::open(cfg, msg_seed) {
            Ok(svc) => {
                let svc = Arc::new(svc);
                svc.start_network();
                let st = svc.wait_ready(Duration::from_secs(180));
                ctx.log(&format!("messenger ({label}): {} {} address {}", st.phase, st.detail, svc.address()));
                {
                    let mut s = status.lock().unwrap();
                    s["messenger"] = json!(format!("{} ({label})", st.phase));
                    s["messenger_address"] = json!(svc.address());
                }
                *ctx.messenger.lock().unwrap() = Some(svc.clone());
                let c = ctx.clone();
                std::thread::spawn(move || {
                    // The messenger ACKs an envelope once it is in its history,
                    // BEFORE we process it; its live event queue is empty after
                    // a restart. So the source of truth is the message HISTORY,
                    // and a durable list of message ids already handled here
                    // (written after handling: at least once; handling is
                    // idempotent: a received slate resends its saved answer, a
                    // finalized one is skipped, an invoice is kept once).
                    let mut done = Processed::open(&c.work.join("messenger-processed.txt"), || all_incoming_ids(&svc));
                    if done.baselined > 0 {
                        c.log(&format!("messenger: {} earlier messages marked as handled (first start with the processing list)", done.baselined));
                    }
                    let mut since = 0u64;
                    loop {
                        for e in process_unhandled(incoming_slatepacks(&svc), &mut done, |peer, armor| handle_envelope(&c, &svc, peer, armor)) {
                            c.log(&format!("messenger: {e}"));
                        }
                        // Wait for news (or 5 s), then scan the history again.
                        let page = svc.events(since, Duration::from_secs(5));
                        since = page.next;
                        for ev in page.events {
                            let v = serde_json::to_value(&ev).unwrap_or(Value::Null);
                            if v["type"] == "rejected" || v["type"] == "error" {
                                c.log(&format!("messenger event: {v}"));
                            }
                        }
                    }
                });
            }
            Err(e) => ctx.log(&format!("messenger: {e}")),
        }
    } else {
        ctx.log("messenger: off (no Tor and no --relay)");
        status.lock().unwrap()["messenger"] = json!("off");
    }
    write_status(&ctx, &status.lock().unwrap());
    ctx.log("ready: waiting for payments and for outgoing requests");
    let _keep = onion_service;
    resume_undispatched(&ctx);
    loop {
        process_outbox(&ctx);
        std::thread::sleep(Duration::from_secs(2));
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn book_cmd(args: &[String]) -> Result<(), String> {
    let user_dir = PathBuf::from(arg(args, "--user-dir").ok_or("--user-dir")?);
    let mut b = load_book(&user_dir);
    let sub = args.iter().skip(2).map(|s| s.as_str()).find(|a| ["add", "remove", "auto-accept", "list"].contains(a)).unwrap_or("list");
    match sub {
        "add" => {
            let id = arg(args, "--id").ok_or("--id grin1...")?;
            flint_tor_arti::onion_from_address(&id).map_err(|e| format!("--id {id}: {e}"))?;
            let messenger = arg(args, "--messenger");
            if let Some(m) = &messenger {
                flint_tor_arti::onion_from_address(m).map_err(|e| format!("--messenger {m}: {e}"))?;
            }
            let c = Contact {
                id: id.clone(),
                name: arg(args, "--name").unwrap_or_default(),
                messenger,
                auto: arg(args, "--auto").map_or(true, |a| a != "no"),
            };
            b.contacts.retain(|x| x.id != id);
            b.contacts.push(c);
            save_book(&user_dir, &b)?;
            println!("CONTACT_SAVED={id}");
        }
        "remove" => {
            let id = arg(args, "--id").ok_or("--id")?;
            let before = b.contacts.len();
            b.contacts.retain(|x| x.id != id);
            save_book(&user_dir, &b)?;
            println!("CONTACT_REMOVED={}", before != b.contacts.len());
        }
        "auto-accept" => {
            let i = args.iter().position(|a| a == "auto-accept").unwrap_or(0);
            let p = args.get(i + 1).ok_or("off|contacts|all")?;
            if !["off", "contacts", "all"].contains(&p.as_str()) {
                return Err("auto-accept: off | contacts | all".into());
            }
            b.auto_accept = p.clone();
            save_book(&user_dir, &b)?;
            println!("AUTO_ACCEPT={p}");
        }
        _ => {
            println!("AUTO_ACCEPT={}", b.auto_accept);
            for c in &b.contacts {
                let onion = flint_tor_arti::onion_from_address(&c.id).unwrap_or_default();
                println!(
                    "CONTACT id={} name={:?} auto={} messenger={} onion={onion}.onion",
                    c.id,
                    c.name,
                    if c.auto { "yes" } else { "no" },
                    c.messenger.clone().unwrap_or_else(|| "-".into())
                );
            }
        }
    }
    Ok(())
}

fn queue(args: &[String]) -> Result<(), String> {
    let user_dir = PathBuf::from(arg(args, "--user-dir").ok_or("--user-dir")?);
    let wallet: usize = arg(args, "--wallet").and_then(|w| w.parse().ok()).unwrap_or(1);
    let req = SendRequest {
        kind: arg(args, "--kind").unwrap_or_else(|| "send".into()),
        slate_id: arg(args, "--slate-id").ok_or("--slate-id")?,
        to: arg(args, "--to").ok_or("--to")?,
        slate_json: arg(args, "--slate-json"),
        armor: arg(args, "--armor").ok_or("--armor")?,
        context: arg(args, "--context").ok_or("--context")?,
        tx_folder: arg(args, "--tx-folder").ok_or("--tx-folder")?,
        messenger: arg(args, "--messenger"),
        messenger_only: args.iter().any(|a| a == "--messenger-only"),
    };
    if !valid_slate_id(&req.slate_id) {
        return Err(format!("bad slate id {} (expected a UUID)", req.slate_id));
    }
    let dir = user_dir.join(format!("tor-wallet-{wallet}")).join("outbox");
    fs::create_dir_all(&dir).map_err(|e| format!("{e}"))?;
    let tmp = dir.join(format!("{}.tmp", req.slate_id));
    fs::write(&tmp, serde_json::to_string_pretty(&req).unwrap()).map_err(|e| format!("{e}"))?;
    fs::rename(&tmp, dir.join(format!("{}.json", req.slate_id))).map_err(|e| format!("{e}"))?;
    println!("QUEUED={} (the Tor daemon of wallet {wallet} delivers it)", req.slate_id);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(|s| s.as_str()) {
        Some("serve") => serve(&args),
        Some("book") => book_cmd(&args),
        Some("queue") => queue(&args),
        Some("onion") => args
            .get(2)
            .ok_or_else(|| "onion <grin1 address>".to_string())
            .and_then(|a| flint_tor_arti::onion_from_address(a).map_err(|e| format!("{e}")))
            .map(|o| println!("ONION={o}.onion")),
        _ => Err("usage: unity-tor serve|book|queue|onion ...".into()),
    };
    if let Err(e) = r {
        eprintln!("UNITY_TOR=FAIL {e}");
        println!("UNITY_TOR=FAIL {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn book(policy: &str) -> Book {
        Book {
            auto_accept: policy.into(),
            contacts: vec![
                Contact { id: "grin1alice".into(), name: "Alice".into(), messenger: Some("grin1alicemsg".into()), auto: true },
                Contact { id: "grin1bob".into(), name: "Bob".into(), messenger: None, auto: false },
            ],
        }
    }

    #[test]
    fn policy_off_contacts_all() {
        let alice_env = Sender { claimed: Some("grin1x".into()), messenger: Some("grin1alicemsg".into()) };
        let alice_tor = Sender { claimed: Some("grin1alice".into()), messenger: None };
        let bob = Sender { claimed: Some("grin1bob".into()), messenger: None };
        let stranger = Sender { claimed: Some("grin1eve".into()), messenger: None };
        assert!(decide(&book("off"), &alice_env).is_err());
        assert!(decide(&book("contacts"), &alice_env).is_ok());
        // Tor foreign API: the address is only claimed -> never automatic under "contacts".
        assert!(decide(&book("contacts"), &alice_tor).unwrap_err().contains("not authenticated"));
        assert!(decide(&book("contacts"), &bob).is_err(), "contact with auto off");
        assert!(decide(&book("contacts"), &stranger).is_err());
        assert!(decide(&book("all"), &stranger).is_ok());
        assert!(decide(&book("all"), &alice_tor).unwrap().contains("not authenticated"));
        // Signed by an unknown key while claiming Alice's address: a stranger.
        let impostor = Sender { claimed: Some("grin1alice".into()), messenger: Some("grin1evilmsg".into()) };
        assert!(decide(&book("contacts"), &impostor).unwrap_err().contains("not in the address book"));
        assert!(!decide(&book("all"), &impostor).unwrap().contains("Alice"));
    }

    #[test]
    fn slate_id_must_be_a_uuid() {
        assert!(valid_slate_id("0436430c-2b02-624c-2032-570501212b00"));
        assert!(valid_slate_id("0436430C-2B02-624C-2032-570501212B00"));
        for bad in [
            "",
            "?",
            "../../evil",
            "..\\..\\evil",
            "/etc/passwd",
            "C:\\Windows\\x",
            "0436430c-2b02-624c-2032-570501212b0/",
            "0436430c/2b02-624c-2032-570501212b00",
            "0436430c-2b02-624c-2032-570501212b00.json",
            "0436430c-2b02-624c-2032-570501212b0",
            "0436430c-2b02-624c-2032-5705012..b00",
            "0436430c_2b02_624c_2032_570501212b00",
        ] {
            assert!(!valid_slate_id(bad), "{bad}");
        }
    }

    fn serve_one(raw: Vec<u8>) -> Result<(String, String, Vec<u8>), String> {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            let _ = c.write_all(&raw);
            let _ = c.shutdown(std::net::Shutdown::Write);
        });
        let (mut s, _) = l.accept().unwrap();
        let r = read_request(&mut s);
        t.join().unwrap();
        r
    }

    #[test]
    fn http_limits() {
        let ok = serve_one(b"POST /v2/foreign HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}".to_vec()).unwrap();
        assert_eq!((ok.0.as_str(), ok.1.as_str(), ok.2.as_slice()), ("POST", "/v2/foreign", &b"{}"[..]));
        // request line too long
        let mut long = b"POST /".to_vec();
        long.extend(vec![b'a'; MAX_LINE + 10]);
        long.extend(b" HTTP/1.1\r\n\r\n");
        assert!(serve_one(long).is_err());
        // one huge header
        let mut big = b"POST / HTTP/1.1\r\nX: ".to_vec();
        big.extend(vec![b'a'; MAX_LINE + 10]);
        big.extend(b"\r\n\r\n");
        assert!(serve_one(big).is_err());
        // too many headers
        let mut many = b"POST / HTTP/1.1\r\n".to_vec();
        for i in 0..(MAX_HEADERS + 5) {
            many.extend(format!("X-{i}: y\r\n").as_bytes());
        }
        many.extend(b"\r\n");
        assert!(serve_one(many).is_err());
        // body over the limit, bad length, headers never finished
        assert!(serve_one(format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1).into_bytes()).is_err());
        assert!(serve_one(b"POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n".to_vec()).is_err());
        assert!(serve_one(b"POST / HTTP/1.1\r\nHost: x\r\n".to_vec()).is_err());
    }

    #[test]
    fn slow_trickle_hits_the_request_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut c = TcpStream::connect(addr).unwrap();
            // one header byte every 100 ms: each single read is fast, the whole is not
            for b in b"POST / HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n" {
                if c.write_all(&[*b]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let (mut s, _) = l.accept().unwrap();
        let t0 = std::time::Instant::now();
        let r = read_request_within(&mut s, Duration::from_millis(800));
        assert!(r.is_err());
        assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
        drop(s);
        t.join().unwrap();
    }

    #[test]
    fn stamps_unique_across_threads() {
        let hs: Vec<_> = (0..8).map(|_| std::thread::spawn(|| (0..200).map(|_| stamp()).collect::<Vec<_>>())).collect();
        let mut all: Vec<String> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
        let n = all.len();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), n);
        let dir = std::env::temp_dir().join(format!("unity-tor-new-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.txt");
        write_new(&p, b"a").unwrap();
        assert!(write_new(&p, b"b").is_err(), "an existing file is never reused");
        assert_eq!(fs::read(&p).unwrap(), b"a");
        let _ = fs::remove_dir_all(&dir);
    }

    fn req_json(kind: &str, sid: &str) -> String {
        serde_json::to_string(&SendRequest {
            kind: kind.into(),
            slate_id: sid.into(),
            to: "grin1x".into(),
            slate_json: None,
            armor: "a".into(),
            context: "c".into(),
            tx_folder: "t".into(),
            messenger: None,
            messenger_only: false,
        })
        .unwrap()
    }

    /// Store happened, removal from outbox/ did not (simulated by putting the
    /// same file back), daemon restarts: the request is dispatched once.
    #[test]
    fn outbox_never_dispatches_a_stored_request_twice() {
        let dir = std::env::temp_dir().join(format!("unity-outbox-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (outbox, sends, replies) = (dir.join("outbox"), dir.join("sends"), dir.join("replies"));
        fs::create_dir_all(&outbox).unwrap();
        let sid = "0436430c-2b02-624c-2032-570501212b00";
        let p = outbox.join(format!("{sid}.json"));
        let t = req_json("send", sid);
        fs::write(&p, &t).unwrap();
        assert!(matches!(accept_file(&p, &sends, &replies), Accept::Dispatch(_)));
        assert!(!p.exists() && sends.join(format!("{sid}.json")).exists());
        // removal "failed": the outbox file is still there on the next pass
        fs::write(&p, &t).unwrap();
        assert!(matches!(accept_file(&p, &sends, &replies), Accept::AlreadyStored));
        assert!(!p.exists(), "only removed, not dispatched again");
        // a different request with the same slate id is not taken
        fs::write(&p, req_json("invoice", sid)).unwrap();
        assert!(matches!(accept_file(&p, &sends, &replies), Accept::Parked(_)));
        assert!(outbox.join(format!("{sid}.bad")).exists());
        // replies go to replies/, garbage and bad ids are set aside
        let sid2 = "1436430c-2b02-624c-2032-570501212b00";
        let p2 = outbox.join(format!("{sid2}.json"));
        fs::write(&p2, req_json("reply", sid2)).unwrap();
        assert!(matches!(accept_file(&p2, &sends, &replies), Accept::Dispatch(_)));
        assert!(replies.join(format!("{sid2}.json")).exists());
        let p3 = outbox.join("x.json");
        fs::write(&p3, "garbage").unwrap();
        assert!(matches!(accept_file(&p3, &sends, &replies), Accept::Parked(_)));
        fs::write(&p3, req_json("send", "../evil")).unwrap();
        assert!(matches!(accept_file(&p3, &sends, &replies), Accept::Parked(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_reply_can_be_queued_again_others_cannot() {
        let dir = std::env::temp_dir().join(format!("unity-reply-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (outbox, sends, replies) = (dir.join("outbox"), dir.join("sends"), dir.join("replies"));
        fs::create_dir_all(&outbox).unwrap();
        let sid = "2436430c-2b02-624c-2032-570501212b00";
        let p = outbox.join(format!("{sid}.json"));
        fs::write(&p, req_json("reply", sid)).unwrap();
        assert!(matches!(accept_file(&p, &sends, &replies), Accept::Dispatch(_)));
        let again = req_json("reply", sid).replace("\"t\"", "\"t2\""); // new run folder
        // still in flight (DISPATCHED): refused
        fs::write(replies.join(format!("{sid}.status")), "1 DISPATCHED\n").unwrap();
        fs::write(&p, &again).unwrap();
        assert!(matches!(accept_file(&p, &sends, &replies), Accept::Parked(_)));
        // delivery FAILED: the new request replaces it and is dispatched
        fs::write(replies.join(format!("{sid}.status")), "1 FAILED: messenger send: x\n").unwrap();
        fs::write(&p, &again).unwrap();
        assert!(matches!(accept_file(&p, &sends, &replies), Accept::Dispatch(_)));
        assert_eq!(fs::read_to_string(replies.join(format!("{sid}.json"))).unwrap(), again);
        // a FAILED send is never replaced this way
        let sid2 = "3436430c-2b02-624c-2032-570501212b00";
        let p2 = outbox.join(format!("{sid2}.json"));
        fs::write(&p2, req_json("send", sid2)).unwrap();
        assert!(matches!(accept_file(&p2, &sends, &replies), Accept::Dispatch(_)));
        fs::write(sends.join(format!("{sid2}.status")), "1 FAILED x\n").unwrap();
        fs::write(&p2, req_json("send", sid2).replace("\"t\"", "\"t2\"")).unwrap();
        assert!(matches!(accept_file(&p2, &sends, &replies), Accept::Parked(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn slate_lock_serializes_finishers() {
        let dir = std::env::temp_dir().join(format!("unity-slock-{}", std::process::id()));
        let sid = "4436430c-2b02-624c-2032-570501212b00";
        assert!(slate_lock(&dir, "../x").is_err());
        let held = slate_lock(&dir, sid).unwrap();
        let inside = Arc::new(AtomicUsize::new(0));
        let i2 = inside.clone();
        let d2 = dir.clone();
        let t = std::thread::spawn(move || {
            let _l = slate_lock(&d2, sid).unwrap();
            i2.store(1, Ordering::SeqCst);
        });
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(inside.load(Ordering::SeqCst), 0, "second finisher waits for the first");
        drop(held);
        t.join().unwrap();
        assert_eq!(inside.load(Ordering::SeqCst), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn inbox_quota_and_rate() {
        let dir = std::env::temp_dir().join(format!("unity-inbox-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let rate = Mutex::new((0u64, 0u32));
        let t0 = 6000u64;
        assert!(inbox_save(&dir, "big.json", &vec![b'x'; INBOX_MAX_ITEM + 1], &rate, t0).is_err());
        assert!(inbox_save(&dir, "a.json", b"1", &rate, t0).is_ok());
        assert!(inbox_save(&dir, "a.json", b"2", &rate, t0).is_err(), "never overwritten");
        for i in 2..INBOX_PER_MINUTE {
            inbox_save(&dir, &format!("r{i}.json"), b"1", &rate, t0).unwrap();
        }
        assert!(inbox_save(&dir, "late.json", b"1", &rate, t0).unwrap_err().contains("rate"));
        // next minute: allowed again, until the file count limit
        let mut t = t0 + 60;
        let mut n = fs::read_dir(&dir).unwrap().count();
        let err = loop {
            match inbox_save(&dir, &format!("f{n}.json"), b"1", &rate, t) {
                Ok(_) => n += 1,
                Err(e) if e.contains("rate") => t += 60,
                Err(e) => break e,
            }
        };
        assert!(err.contains("inbox full"), "{err}");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), INBOX_MAX_FILES);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn processed_messages_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("unity-processed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("messenger-processed.txt");
        // first start: what is already in the history counts as handled
        let p = Processed::open(&f, || vec!["old-1".into(), "old-2".into()]);
        assert_eq!(p.baselined, 2);
        assert!(p.contains("old-1"));
        drop(p);
        // later start: the file is the truth; history is NOT re-baselined, so a
        // message ACKed but not handled before the stop is handled now
        let mut p = Processed::open(&f, || vec!["acked-not-handled".into()]);
        assert_eq!(p.baselined, 0);
        assert!(!p.contains("acked-not-handled"));
        p.mark("acked-not-handled").unwrap();
        assert!(p.mark("bad\nid").is_err());
        drop(p);
        let p = Processed::open(&f, Vec::new);
        assert!(p.contains("acked-not-handled") && p.contains("old-2"));
        // empty history on first start still creates the file
        let g = dir.join("empty.txt");
        let _ = Processed::open(&g, Vec::new);
        assert!(g.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// ACCEPTANCE (restart after ACK): the messenger ACKed and stored m2, then
    /// the daemon stopped before handling it. After the restart m2 is handled
    /// exactly once; m1 (handled before) is not handled again; a further
    /// restart handles nothing.
    #[test]
    fn restart_after_ack_handles_the_stored_message_once() {
        let dir = std::env::temp_dir().join(format!("unity-ack-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("messenger-processed.txt");
        let msg = |id: &str| (id.to_string(), "peer".to_string(), format!("armor-{id}"));
        // run 1: history = [m1]; handled
        let mut done = Processed::open(&f, Vec::new);
        let mut seen = Vec::new();
        process_unhandled(vec![msg("m1")], &mut done, |_, a| seen.push(a.to_string()));
        assert_eq!(seen, vec!["armor-m1"]);
        // m2 arrives, is stored in the history and ACKed; the daemon stops
        // before the handler ran (nothing marked)
        drop(done);
        // run 2 (restart): live events are empty, the history has m1 + m2
        let mut done = Processed::open(&f, || vec!["m1".into(), "m2".into()]);
        let mut seen = Vec::new();
        process_unhandled(vec![msg("m1"), msg("m2")], &mut done, |_, a| seen.push(a.to_string()));
        assert_eq!(seen, vec!["armor-m2"], "only the ACKed but unhandled message");
        drop(done);
        // run 3: nothing left
        let mut done = Processed::open(&f, Vec::new);
        let mut seen = Vec::new();
        process_unhandled(vec![msg("m1"), msg("m2")], &mut done, |_, a| seen.push(a.to_string()));
        assert!(seen.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    /// ACCEPTANCE (two finalizers): the Foreign API, the messenger and the
    /// outgoing thread deliver the same answer at once. The real
    /// `Ctx::finish` runs the (stub) wallet executable to finalize exactly once.
    #[cfg(unix)]
    #[test]
    fn same_answer_from_three_paths_finalizes_once() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("unity-fin3-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (user, work, run) = (dir.join("user"), dir.join("work"), dir.join("run"));
        for d in [&user, &work, &run] {
            fs::create_dir_all(d).unwrap();
        }
        fs::write(user.join("peers.txt"), "192.0.2.1:3414\n").unwrap();
        // stub wallet: counts finalizations (slowly, to overlap), "broadcasts"
        let count = dir.join("finalized.count");
        let exe = dir.join("wallet-stub.sh");
        fs::write(
            &exe,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n --finalize-slatepack|--finalize-invoice) sleep 0.3; echo x >> {c}; echo FINALIZE=OK;;\n --broadcast-tx) echo BROADCAST_TX=192.0.2.1:3414 SENT;;\nesac\nexit 0\n",
                c = count.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        let ctx = Arc::new(Ctx {
            exe,
            seeds: dir.join("seeds"),
            seed_text: None,
            wallet: 1,
            user_dir: user,
            mainnet: false,
            work,
            overrides: BTreeMap::new(),
            tor: Mutex::new(None),
            messenger: Mutex::new(None),
            log: Mutex::new(()),
            inbox_rate: Mutex::new((0, 0)),
        });
        let req: SendRequest = serde_json::from_str(&req_json("send", "5436430c-2b02-624c-2032-570501212b00")).unwrap();
        let req = SendRequest { tx_folder: run.display().to_string(), ..req };
        let hs: Vec<_> = (0..3)
            .map(|_| {
                let (ctx, req) = (ctx.clone(), req.clone());
                std::thread::spawn(move || ctx.finish(&req, "SLATEPACK S2"))
            })
            .collect();
        for h in hs {
            assert!(h.join().unwrap().is_ok());
        }
        assert_eq!(fs::read_to_string(&count).unwrap().lines().count(), 1, "finalized exactly once");
        assert!(run.join(FINALIZED_MARK).exists());
        // a late fourth delivery is a no-op as well
        ctx.finish(&req, "SLATEPACK S2").unwrap();
        assert_eq!(fs::read_to_string(&count).unwrap().lines().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- robustness fuzzing of everything a stranger can send us ----------
    // Deterministic mutations of valid inputs; the property is: no panic.
    // Iterations: UNITY_FUZZ_ITERS (default 1000 per target).

    struct FRng(u64);
    impl FRng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            if n == 0 { 0 } else { (self.next() % n as u64) as usize }
        }
    }

    fn fmutate(r: &mut FRng, seeds: &[Vec<u8>]) -> Vec<u8> {
        const SP: &[u8] = b"\"{}[],:\\\n\r 0-9.eE+\x00\xff\xc3";
        let mut d = seeds[r.below(seeds.len())].clone();
        for _ in 0..1 + r.below(4) {
            let n = d.len();
            match r.below(7) {
                0 if n > 0 => { let i = r.below(n); d[i] ^= 1 << r.below(8); }
                1 if n > 0 => { let i = r.below(n); d.truncate(i); }
                2 if n > 0 => { let a = r.below(n); let b = (a + 1 + r.below(64)).min(n); d.drain(a..b); }
                3 => { let i = r.below(n + 1); for _ in 0..1 + r.below(16) { d.insert(i, r.next() as u8); } }
                4 => { let i = r.below(n + 1); d.insert(i, SP[r.below(SP.len())]); }
                5 if n > 0 => { let a = r.below(n); let b = (a + 1 + r.below(256)).min(n); let x = d[a..b].to_vec(); let i = r.below(d.len() + 1); d.splice(i..i, x); }
                _ if n > 0 => { let i = r.below(n); d[i] = r.next() as u8; }
                _ => {}
            }
        }
        d
    }

    fn fiters() -> usize {
        std::env::var("UNITY_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(1000)
    }

    fn ffuzz(name: &str, seed: u64, seeds: Vec<Vec<u8>>, mut f: impl FnMut(&[u8])) {
        let mut r = FRng(seed | 1);
        for i in 0..fiters() {
            let d = fmutate(&mut r, &seeds);
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&d))).is_err() {
                let p = std::env::temp_dir().join(format!("unity-tor-fuzz-{name}.bin"));
                let _ = fs::write(&p, &d);
                panic!("{name}: PANIC on mutation {i}; input saved to {}", p.display());
            }
        }
    }

    /// `--seeds -`: the phrases reach every wallet exe call on its stdin.
    #[cfg(unix)]
    #[test]
    fn seeds_from_stdin_reach_the_wallet_exe() {
        use std::os::unix::fs::PermissionsExt;
        let mut c = fuzz_ctx("stdin-seeds");
        let got = c.user_dir.join("got.txt");
        let exe = c.user_dir.join("fake-exe");
        fs::write(&exe, format!("#!/bin/sh\ncat > {}\necho ADDRESS=x\n", got.display())).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
        c.exe = exe;
        c.seed_text = Some("abandon ".repeat(23) + "art\n");
        let (code, out) = c.exe(&["--tor-keys", "--seeds", "-"]).unwrap();
        assert_eq!((code, out.trim()), (0, "ADDRESS=x"));
        assert_eq!(fs::read_to_string(&got).unwrap(), "abandon ".repeat(23) + "art\n");
        // Without seed text the child gets an empty stdin (never ours).
        c.seed_text = None;
        c.exe(&["--x"]).unwrap();
        assert_eq!(fs::read_to_string(&got).unwrap(), "");
    }

    fn fuzz_ctx(tag: &str) -> Ctx {
        let dir = std::env::temp_dir().join(format!("unity-tor-fuzz-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("user")).unwrap();
        Ctx {
            exe: dir.join("no-such-wallet-exe"),
            seeds: dir.join("seeds"),
            seed_text: None,
            wallet: 1,
            user_dir: dir.join("user"),
            mainnet: false,
            work: dir.join("work"),
            overrides: BTreeMap::new(),
            tor: Mutex::new(None),
            messenger: Mutex::new(None),
            log: Mutex::new(()),
            inbox_rate: Mutex::new((0, 0)),
        }
    }

    /// HTTP requests from the network (Tor foreign API listener).
    #[test]
    fn fuzz_http_request_parser() {
        let seeds = vec![
            b"POST /v2/foreign HTTP/1.1\r\nHost: x.onion\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
            b"GET / HTTP/1.0\r\n\r\n".to_vec(),
        ];
        // The parser directly on bytes: no socket per input (tens of
        // thousands of TCP connections exhaust the ephemeral ports on Windows,
        // and a failed connect would leave accept() waiting forever).
        ffuzz("http", 41, seeds, |d| {
            if let Ok((_, _, body)) = parse_request(&mut std::io::Cursor::new(d)) {
                assert!(body.len() <= MAX_BODY);
            }
        });
        // The socket path once, for the deadline wrapper around the parser.
        assert!(serve_one(b"GET / HTTP/1.0\r\n\r\n".to_vec()).is_ok());
    }

    /// JSON-RPC bodies of the foreign API (receive_tx / finalize_tx / ...).
    #[test]
    fn fuzz_foreign_api() {
        let ctx = fuzz_ctx("rpc");
        let sid = "6436430c-2b02-624c-2032-570501212b00";
        let seeds: Vec<Vec<u8>> = [
            json!({"jsonrpc": "2.0", "id": 1, "method": "check_version", "params": []}),
            json!({"jsonrpc": "2.0", "id": 1, "method": "receive_tx", "params": [{"ver": "4:3", "id": sid, "sta": "S1", "amt": "1000000000",
                "proof": {"saddr": "aa".repeat(32), "raddr": "bb".repeat(32)}, "sigs": [{"xs": "02aa", "nonce": "03bb"}]}, null, null]}),
            json!({"jsonrpc": "2.0", "id": 2, "method": "finalize_tx", "params": [{"id": sid, "sta": "I2"}]}),
        ]
        .iter()
        .map(|v| v.to_string().into_bytes())
        .collect();
        ffuzz("foreign-api", 42, seeds, |d| {
            let ans = handle_foreign(&ctx, d);
            assert!(serde_json::from_str::<Value>(&ans).is_ok(), "answer is always JSON");
        });
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    /// address-book.json (edited by hand or damaged) and the policy decision.
    #[test]
    fn fuzz_address_book() {
        let ctx = fuzz_ctx("book");
        let seed = json!({"auto_accept": "contacts", "contacts": [{"id": "grin1qqqq", "name": "x", "messenger": "grin1zzzz", "auto": true}]});
        ffuzz("address-book", 43, vec![seed.to_string().into_bytes()], |d| {
            fs::write(book_path(&ctx.user_dir), d).unwrap();
            let b = load_book(&ctx.user_dir);
            let _ = decide(&b, &Sender { claimed: Some("grin1qqqq".into()), messenger: Some("grin1zzzz".into()) });
            let _ = decide(&b, &Sender { claimed: None, messenger: None });
        });
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    /// GrinMessenger envelopes from the relay / onion: parse + open.
    #[test]
    fn fuzz_messenger_envelopes() {
        use flint_messenger::{Envelope, Identity, MessageKind};
        let alice = Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let bob = Identity::from_seed([9u8; 32], "tgrin").unwrap();
        let env = Envelope::seal_default(&alice, bob.address(), MessageKind::Slatepack { armor: "BEGINSLATEPACK. abc. ENDSLATEPACK.".into(), encrypted: true }).unwrap();
        let text = Envelope::seal_default(&alice, bob.address(), MessageKind::Text { text: "hi".into() }).unwrap();
        let seeds = vec![serde_json::to_vec(&env).unwrap(), serde_json::to_vec(&text).unwrap()];
        let now = flint_messenger::envelope::unix_now();
        assert!(env.open(&bob, now).is_ok(), "valid seed opens");
        ffuzz("envelope", 44, seeds, |d| {
            if let Ok(e) = serde_json::from_slice::<Envelope>(d) {
                let _ = e.open(&bob, now);
                let _ = e.verify_pow(1);
            }
            let _ = flint_messenger::Address::parse(&String::from_utf8_lossy(d));
        });
    }

    /// RUSTSEC-2026-0459: the SQLite built into the Tor client (arti's
    /// directory cache) must be 3.54.0 or newer (see tor/patches).
    #[test]
    fn bundled_sqlite_has_the_cve_fix() {
        let v = unsafe { libsqlite3_sys::sqlite3_libversion_number() };
        assert!(v >= 3_054_000, "SQLite {v}: needs >= 3.54.0 (RUSTSEC-2026-0459)");
    }

    #[test]
    fn connection_slots() {
        let active = Arc::new(AtomicUsize::new(0));
        let a = ConnSlot::take(&active, 2).unwrap();
        let b = ConnSlot::take(&active, 2).unwrap();
        assert!(ConnSlot::take(&active, 2).is_none());
        drop(a);
        let c = ConnSlot::take(&active, 2);
        assert!(c.is_some());
        drop((b, c));
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }
}
