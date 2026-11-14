// SPDX-License-Identifier: MIT OR Apache-2.0
//! grinsight-tor — automatic slatepack exchange for the GrinSight wallet.
//!
//! Two transports, one address book:
//!
//! * **grin-wallet Tor foreign API** (`POST http://<onion>/v2/foreign`,
//!   `check_version` / `receive_tx` / `finalize_tx`). The onion is derived from
//!   the wallet's slatepack address, exactly like grin-wallet and Grin++, so
//!   they can pay us and we can pay them. On this transport the sender is NOT
//!   authenticated: the address in the payment proof is only CLAIMED and is
//!   never used to identify a contact or to grant contact-based auto-accept.
//!   Invoices are never paid automatically.
//! * **GrinMessenger envelopes** (signed by the sender's messenger key, ACKed):
//!   direct to the peer's messenger onion over Arti, or through a
//!   store-and-forward relay when Tor is unavailable. The messenger identity is
//!   a separate key derived from the wallet seed.
//!
//! The wallet logic itself (receive, finalize, broadcast) is the GrinSight wallet
//! executable, called as a subprocess; this daemon only moves slatepacks and
//! applies the acceptance policy:
//!   auto_accept = off | ask | contacts | all
//! * `ask` (default, book v2): a payment from a stranger is held up to 40 s and
//!   the user answers in the app (`pending/` + `decisions/` files). 3 requests
//!   may wait at once, 10 new strangers per hour; over the limit the S1 goes
//!   to the inbox and the sender is told to hand over a slatepack.
//! * `contacts`: a contact with `auto` is accepted only for an authenticated
//!   messenger identity; other requests go to the inbox without a question.
//! * `all`: anyone is accepted. `off`: everything goes to the inbox.
//! A request that is not answered in time is sent to the sender as a slatepack
//! fallback by grin-wallet; the S1 stays in the inbox for a manual receive.

use glaux_messenger::channel_drain;

use glaux_messenger_wallet::{NetworkMode, ServiceConfig, WalletService};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
#[cfg(windows)]
mod managed_i2p;
use sha2::{Digest, Sha256};
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

/// Current address-book format: v2 added the "ask" mode. A file without
/// "version" is v1.
const BOOK_VERSION: u32 = 3;

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Book {
    #[serde(default)]
    version: u32,
    #[serde(default = "default_policy")]
    auto_accept: String,
    #[serde(default)]
    contacts: Vec<Contact>,
}

/// A new book asks about the first payment from a stranger.
fn default_policy() -> String {
    "ask_all".into()
}

impl Default for Book {
    fn default() -> Self {
        Book { version: BOOK_VERSION, auto_accept: default_policy(), contacts: vec![] }
    }
}

impl Book {
    /// On upgrade retain disabled mode; enabled legacy modes now ask for
    /// confirmation for every sender as requested by the wallet user.
    fn migrate(&mut self) -> bool {
        if self.version >= BOOK_VERSION { return false; }
        if self.auto_accept != "off" { self.auto_accept = "ask_all".into(); }
        self.version = BOOK_VERSION;
        true
    }
}

fn book_path(user_dir: &Path) -> PathBuf {
    user_dir.join("address-book.json")
}

/// Book writers in the daemon and the CLI are separate processes. The stable
/// lock file serializes each complete read-modify-write transaction.
fn lock_book(user_dir: &Path) -> Result<std::fs::File, String> {
    fs::create_dir_all(user_dir).map_err(|e| format!("address book directory: {e}"))?;
    let lock = fs::OpenOptions::new().read(true).write(true).create(true)
        .open(user_dir.join("address-book.lock")).map_err(|e| format!("address book lock: {e}"))?;
    lock.lock().map_err(|e| format!("address book lock: {e}"))?;
    Ok(lock)
}

/// Existing unreadable or malformed books must never be replaced by defaults.
fn load_book_checked(user_dir: &Path) -> Result<Book, String> {
    let text = match fs::read_to_string(book_path(user_dir)) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Book::default()),
        Err(e) => return Err(format!("address book cannot be read: {e}")),
    };
    let mut book: Book = serde_json::from_str(&text).map_err(|e| format!("address book is corrupt: {e}"))?;
    book.migrate();
    Ok(book)
}

/// Payment policy must fail closed when book metadata cannot be read.
fn load_book(user_dir: &Path) -> Book {
    load_book_checked(user_dir).unwrap_or_else(|_| Book { version: BOOK_VERSION, auto_accept: "off".into(), contacts: vec![] })
}

fn save_book(user_dir: &Path, b: &Book) -> Result<(), String> {
    fs::create_dir_all(user_dir).map_err(|e| format!("{e}"))?;
    let mut b = b.clone();
    b.version = BOOK_VERSION;
    let tmp = user_dir.join(format!("address-book.json.{}.tmp", stamp()));
    fs::write(&tmp, serde_json::to_string_pretty(&b).unwrap()).map_err(|e| format!("address book: {e}"))?;
    fs::rename(&tmp, book_path(user_dir)).map_err(|e| format!("address book: {e}"))
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

impl Sender {
    fn describe(&self) -> String {
        self.messenger.clone().or_else(|| self.claimed.clone()).unwrap_or_else(|| "(no address)".into())
    }
}

/// What to do with an incoming payment.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Accept it now; the string is the "who" written to the log/history.
    Accept(String),
    /// A stranger in mode "ask": hold the request and ask the user.
    Ask,
    /// Put it into the inbox without asking.
    Inbox(String),
}

/// Policy: accept / ask / inbox.
///
/// Only the key of a signed messenger envelope authenticates the sender.
/// A Tor foreign API request merely claims an address (`proof.saddr`), so it
/// cannot match an address-book contact or trigger contact-based auto-accept.
/// Invoices never come through here and are paid only by hand.
fn decide(book: &Book, s: &Sender) -> Decision {
    let find = || -> Option<&Contact> {
        s.messenger.as_ref().and_then(|m| {
            book.contacts.iter().find(|c| c.messenger.as_deref() == Some(m.as_str()) || c.id == *m)
        })
    };
    let how = if s.messenger.is_some() { "signed envelope" } else { "address claimed in the slate (Tor, not authenticated)" };
    match book.auto_accept.as_str() {
        "ask_all" => Decision::Ask,
        "all" => Decision::Accept(match find() {
            Some(c) => format!("contact '{}' ({how})", c.name),
            None => format!("anyone ({})", s.describe()),
        }),
        "ask" | "contacts" => match find() {
            Some(c) if c.auto => Decision::Accept(format!("contact '{}' ({how})", c.name)),
            Some(c) => Decision::Inbox(format!("contact '{}' has automatic acceptance off", c.name)),
            None if book.auto_accept == "ask" => Decision::Ask,
            None => Decision::Inbox(format!("sender {} is not in the address book", s.describe())),
        },
        _ => Decision::Inbox("automatic acceptance is off".into()),
    }
}

// ---------------------------------------------------------------------------
// Daemon context: the wallet executable and the files it shares with scripts
// ---------------------------------------------------------------------------

struct Ctx {
    channel_drain: channel_drain::ChannelDrain,
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
    tor: Mutex<Option<Arc<glaux_tor_arti::TorHttpClient>>>,
    messenger: Mutex<Option<Arc<WalletService>>>,
    /// Tag captured when the messaging session starts, never reinterpreted
    /// from mutable settings while that session is running.
    messenger_route: Mutex<Option<String>>,
    log: Mutex<()>,
    /// (minute, files saved in it) for `inbox_save`.
    inbox_rate: Mutex<(u64, u32)>,
    /// How long a stranger's `receive_tx` waits for the user (40 s normally;
    /// shorter in tests through GRINSIGHT_TOR_HOLD_SECS).
    hold: Duration,
    /// Arrival times of the last strangers' payments (rate limit, one hour).
    strangers: Mutex<Vec<u64>>,
    /// In tests: the fake wallet executable (no wallet binary needed).
    #[cfg(test)]
    receive_fn: Option<Arc<dyn Fn(&str, &str) -> Result<String, String> + Send + Sync>>,
    /// In tests: stand in for finalize + broadcast.
    #[cfg(test)]
    finish_fn: Option<Arc<dyn Fn(&SendRequest, &str) -> Result<(), String> + Send + Sync>>,
}

/// Written into a run folder once its answer is finalized.
const FINALIZED_MARK: &str = "FINALIZED";

#[derive(Debug, PartialEq, Eq)]
enum FinishOutcome {
    Broadcast,
    AlreadyFinalized,
}

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

/// Write a file atomically: a unique temporary name in the same directory,
/// then rename over the target (a reader never sees a partial file).
fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let base = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!(".{base}.{}.tmp", stamp()));
    fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
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
        #[cfg(test)]
        if let Some(f) = &self.receive_fn {
            return f(input, who);
        }
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
        args.push("--verified-profile-dir".into());
        args.push(self.user_dir.display().to_string());
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

    /// Kind of a slatepack / slate JSON as the wallet sees it:
    /// (state, slate id, sender, amount nanogrin, fee nanogrin).
    fn info(&self, text: &str) -> Result<(String, String, String, u64, u64), String> {
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
        let num = |k: &str| Self::line(&out, k).and_then(|x| x.parse().ok()).unwrap_or(0);
        Ok((
            Self::line(&out, "SLATE_STATE").unwrap_or("").to_string(),
            Self::line(&out, "SLATE_ID").unwrap_or("").to_string(),
            Self::line(&out, "SLATE_SENDER").filter(|s| !s.is_empty()).or(Self::line(&out, "SLATE_PROOF_SENDER")).unwrap_or("").to_string(),
            num("SLATE_AMOUNT"),
            num("SLATE_FEE"),
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
    fn finish(&self, req: &SendRequest, answer: &str) -> Result<FinishOutcome, String> {
        // One finalization per slate: the Foreign API, the messenger and the
        // outgoing thread may deliver the same answer at the same time. The
        // file lock serializes them (also across processes); whoever comes
        // second sees the FINALIZED marker and does nothing.
        let _lock = slate_lock(&self.sends_dir(), &req.slate_id)?;
        let folder = PathBuf::from(&req.tx_folder);
        if folder.join(FINALIZED_MARK).exists() {
            self.log(&format!("slate={} already finalized: second answer ignored", req.slate_id));
            return Ok(FinishOutcome::AlreadyFinalized);
        }
        check_payment_not_cancelled(req, req.expected_mode.as_deref().map_or(false, is_backup_mode))?;
        if req.expected_mode.as_deref().map_or(false, is_backup_mode) { check_payment_reservation(self, req)?; }
        #[cfg(test)]
        if let Some(f) = &self.finish_fn { return f(req, answer).map(|_| FinishOutcome::Broadcast); }
        let ext = if answer.trim_start().starts_with('{') { "json" } else { "txt" };
        let ans = folder.join(format!("slatepack-answer.{ext}"));
        fs::write(&ans, answer).map_err(|e| format!("{e}"))?;
        let tx = folder.join("spend-tx.hex");
        let (code, out) = if req.kind == "invoice" {
            let i3 = folder.join("invoice-i3.json");
            self.exe(&[
                "--finalize-invoice", &ans.display().to_string(), "--seeds", &self.seeds.display().to_string(),
                "--invoice-context", &req.context, "--tx-out", &tx.display().to_string(),
                "--slate-json-out", &i3.display().to_string(),
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
        // The service uses this record for chain confirmation. Keep the
        // complete finalize log as recovery evidence if this write fails.
        let spend_tmp = folder.join("spend-tor.tmp");
        fs::write(&spend_tmp, &spend).and_then(|_| fs::rename(&spend_tmp, folder.join("spend.txt")))
            .map_err(|e| format!("finalized, but spend record not written: {e}"))?;
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
            format!("finalized: sent to {sent} peer(s), exit {bcode}\nkernel {}\n", Self::line(&out, "GAP_SPEND_KERNEL_EXCESS").unwrap_or("?")),
        )
        .ok();
        if bcode != 0 || sent == 0 {
            return Err(format!("finalized, broadcast not confirmed (sent to {sent} peer(s), exit {bcode}): run -Broadcast"));
        }
        self.log(&format!("FINALIZED+BROADCAST slate={} peers={sent} kernel={}", req.slate_id, Self::line(&out, "GAP_SPEND_KERNEL_EXCESS").unwrap_or("?")));
        Ok(FinishOutcome::Broadcast)
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
// Manual acceptance (auto_accept = ask): pending requests + the user's decision
// ---------------------------------------------------------------------------

/// How many requests may wait for the user's answer at once.
const PENDING_MAX_HELD: usize = 3;
/// How many new strangers may send us a first payment per hour.
const STRANGERS_PER_HOUR: usize = 10;
/// An unanswered messenger request is kept this long (an envelope has no
/// connection to hold, so the answer may come much later).
const PENDING_MESSENGER_HOURS: u64 = 24;
/// Production hold time of a receive_tx (the sender waits 60 s in grin-wallet,
/// part of it is the Tor round trip).
const DEFAULT_HOLD_SECS: u64 = 40;
/// Polling step while a request is held.
const HOLD_POLL: Duration = Duration::from_millis(100);

/// One payment held for the user's answer (`pending/<slate_id>.json`), with its
/// S1 next to it (`<slate_id>.s1.json` for the Tor foreign API, `.s1.txt` for a
/// messenger envelope) and, once received, the answer in `.s2.txt`.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct Pending {
    slate_id: String,
    /// Nanogrin.
    amount: u64,
    fee: u64,
    /// Claimed slatepack address (Tor) or the sender of the armor.
    #[serde(default)]
    from: Option<String>,
    /// "tor-foreign" (HTTP request held) or "messenger" (answered by envelope).
    channel: String,
    received_at: u64,
    /// For tor-foreign: when the sender's HTTP request gives up.
    expires_at: u64,
    #[serde(default)]
    sender_verified: bool,
    /// Messenger address to answer to (channel "messenger").
    #[serde(default)]
    peer: Option<String>,
    /// Authenticated messenger route at receipt; absent only in legacy records.
    #[serde(default)]
    transport_mode: Option<String>,
    #[serde(default)]
    transport_route: Option<String>,
}

/// The user's answer, written by the app (`decisions/<slate_id>.json`).
#[derive(Serialize, Deserialize, Clone, Debug)]
struct DecisionFile {
    #[serde(default)]
    slate_id: String,
    accept: bool,
    #[serde(default = "yes")]
    add_contact: bool,
    #[serde(default)]
    name: String,
}

impl Ctx {
    fn pending_dir(&self) -> PathBuf {
        self.work.join("pending")
    }

    fn decisions_dir(&self) -> PathBuf {
        self.work.join("decisions")
    }

    fn pending_json(&self, sid: &str) -> PathBuf {
        self.pending_dir().join(format!("{sid}.json"))
    }

    /// Every readable pending request (never the companion S1/S2 files).
    fn pending(&self) -> Vec<Pending> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(self.pending_dir()) else { return out };
        for e in rd.flatten() {
            let p = e.path();
            let n = p.file_name().and_then(|x| x.to_str()).unwrap_or("");
            if !n.ends_with(".json") || n.ends_with(".s1.json") {
                continue;
            }
            if let Some(v) = fs::read_to_string(&p).ok().and_then(|t| serde_json::from_str::<Pending>(&t).ok()) {
                out.push(v);
            }
        }
        out
    }

    fn pending_count(&self) -> usize {
        self.pending().len()
    }

    /// Held requests whose sender is still waiting (the HTTP request is open).
    fn held_count(&self) -> usize {
        let t = now();
        self.pending().iter().filter(|p| p.channel == "tor-foreign" && p.expires_at > t).count()
    }

    fn find_pending(&self, sid: &str) -> Option<Pending> {
        if !valid_slate_id(sid) {
            return None;
        }
        fs::read_to_string(self.pending_json(sid)).ok().and_then(|t| serde_json::from_str(&t).ok())
    }

    /// Store the request + its S1.
    fn add_pending(&self, p: &Pending, s1: &[u8], s1_name: &str) -> Result<(), String> {
        fs::create_dir_all(self.pending_dir()).map_err(|e| format!("pending dir: {e}"))?;
        write_atomic(&self.pending_dir().join(s1_name), s1)?;
        write_atomic(&self.pending_json(&p.slate_id), serde_json::to_string_pretty(p).unwrap().as_bytes())
    }

    /// Remove the request, its S1/S2 and the decision (idempotent).
    fn remove_pending(&self, sid: &str) {
        if !valid_slate_id(sid) {
            return;
        }
        let d = self.pending_dir();
        for name in [format!("{sid}.json"), format!("{sid}.s1.json"), format!("{sid}.s1.txt"), format!("{sid}.s2.txt")] {
            let _ = fs::remove_file(d.join(name));
        }
        let _ = fs::remove_file(self.decisions_dir().join(format!("{sid}.json")));
    }

    /// Read the user's decision (the app writes it atomically).
    fn decision(&self, sid: &str) -> Option<DecisionFile> {
        if !valid_slate_id(sid) {
            return None;
        }
        let p = self.decisions_dir().join(format!("{sid}.json"));
        serde_json::from_str(&fs::read_to_string(p).ok()?).ok()
    }

    /// Wait up to `hold` for the decision; None when the time is out.
    fn wait_decision(&self, sid: &str, hold: Duration) -> Option<DecisionFile> {
        let deadline = std::time::Instant::now() + hold;
        loop {
            if let Some(d) = self.decision(sid) {
                return Some(d);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(HOLD_POLL);
        }
    }

    /// How many strangers arrived in the last hour (spam protection).
    fn strangers_recent(&self) -> usize {
        let cutoff = now().saturating_sub(3600);
        self.strangers.lock().unwrap().iter().filter(|t| **t >= cutoff).count()
    }

    /// Remember one more stranger (in memory, and in `strangers.log` so the
    /// limit survives a restart).
    fn record_stranger(&self) {
        let t = now();
        let mut s = self.strangers.lock().unwrap();
        s.retain(|x| *x >= t.saturating_sub(3600));
        s.push(t);
        drop(s);
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(self.work.join("strangers.log")) {
            let _ = writeln!(f, "{t}");
        }
    }

    /// Save an S1 that was not accepted into the inbox, with its metadata
    /// (`<stem>.meta.json`; the app lists the inbox by it).
    fn inbox_payment(&self, sid: &str, s1: &[u8], channel: &str, amount: u64, fee: u64, from: Option<&str>) -> Result<String, String> {
        let inbox = self.work.join("inbox");
        let name = if channel == "messenger" { format!("{sid}.txt") } else { format!("{sid}.json") };
        inbox_save(&inbox, &name, s1, &self.inbox_rate, now())?;
        self.inbox_meta(
            &name,
            &json!({
                "kind": "payment", "amount": amount, "fee": fee, "from": from,
                "channel": channel, "received_at": now(), "slate_id": sid, "file": name,
            }),
        );
        Ok(format!("saved in the inbox as {name}; receive it by hand"))
    }

    /// Metadata next to an inbox file (`<stem>.meta.json`).
    fn inbox_meta(&self, name: &str, meta: &Value) {
        let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
        let _ = write_atomic(&self.work.join("inbox").join(format!("{stem}.meta.json")), meta.to_string().as_bytes());
    }
}

/// Add a new accepted messenger contact without replacing or aliasing an
/// existing contact. The slate's claimed id is not authenticated by the
/// messenger signature, so it must never overwrite another entry.
fn book_add(user_dir: &Path, id: &str, name: &str, messenger: Option<&str>, auto: bool) -> Result<(), String> {
    let _guard = lock_book(user_dir)?;
    let mut b = load_book_checked(user_dir)?;
    if b.contacts.iter().any(|c| {
        c.id == id || c.messenger.as_deref() == Some(id) ||
            messenger.is_some_and(|m| c.id == m || c.messenger.as_deref() == Some(m))
    }) {
        return Err("contact id or messenger already belongs to an existing contact".into());
    }
    b.contacts.push(Contact { id: id.to_string(), name: name.to_string(), messenger: messenger.map(str::to_string), auto });
    save_book(user_dir, &b)
}

/// Called only while holding the book lock. A catalogue binding must not
/// replace a saved key or change the existing local name and trust policy.
fn bind_compatible(b: &mut Book, id: &str, messenger: &str, name: &str) -> Result<(), String> {
    if id.is_empty() || messenger.is_empty() { return Err("missing contact binding".into()); }
    if b.contacts.iter().any(|c| c.id != id && (c.id == messenger || c.messenger.as_deref() == Some(messenger) || c.messenger.as_deref() == Some(id))) {
        return Err("contact or messenger belongs to another contact".into());
    }
    if let Some(existing) = b.contacts.iter_mut().find(|c| c.id == id) {
        if existing.messenger.as_deref().is_some_and(|old| old != messenger) {
            return Err("existing contact has a different messenger".into());
        }
        existing.messenger = Some(messenger.to_string());
    } else {
        b.contacts.push(Contact { id: id.to_string(), name: name.to_string(), messenger: Some(messenger.to_string()), auto: false });
    }
    Ok(())
}

fn parse_amount(v: &Value) -> u64 {
    v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())).unwrap_or(0)
}

/// Slatepack address from the payment proof's `saddr` (hex pubkey), if any.
fn claimed_address(ctx: &Ctx, slate: &Value) -> Option<String> {
    let hrp = if ctx.mainnet { "grin" } else { "tgrin" };
    slate["proof"]["saddr"]
        .as_str()
        .and_then(|h| data_encoding::HEXLOWER_PERMISSIVE.decode(h.as_bytes()).ok())
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .and_then(|k| glaux_tor_arti::address_from_key(hrp, &k).ok())
}

/// Receive an accepted S1 and wrap the answer into a JSON-RPC response.
fn answer_received(ctx: &Ctx, id: &Value, s1: &str, who: &str, sid: &str) -> String {
    match ctx.receive(s1, who) {
        Ok(answer) => match serde_json::from_str::<Value>(&answer) {
            Ok(v) => rpc_ok(id, v),
            Err(e) => rpc_err(id, &format!("answer: {e}")),
        },
        Err(e) => {
            ctx.log(&format!("RECEIVE FAILED slate={sid}: {e}"));
            rpc_err(id, &format!("receive failed: {e}"))
        }
    }
}

/// Not accepted automatically: the S1 is kept in the inbox for a manual
/// receive, and the sender is told to hand over a slatepack.
fn answer_not_accepted(ctx: &Ctx, id: &Value, sid: &str, s1: &[u8], channel: &str, amount: u64, fee: u64, from: Option<&str>, reason: &str) -> String {
    let saved = ctx.inbox_payment(sid, s1, channel, amount, fee, from).unwrap_or_else(|e| e);
    ctx.log(&format!("NOT ACCEPTED slate={sid} from {}: {reason} ({saved})", from.unwrap_or("-")));
    rpc_err(id, &format!("not accepted automatically ({reason}); send a slatepack instead"))
}

/// Mode "ask" on the Tor foreign API: hold the request for up to `ctx.hold`
/// while the user decides in the app; the S2 goes back in the same HTTP answer.
fn ask_foreign(ctx: &Ctx, id: &Value, slate: &Value, sid: &str, claimed: Option<&str>) -> String {
    let amount = parse_amount(&slate["amt"]);
    let fee = parse_amount(&slate["fee"]);
    let s1 = slate.to_string();
    if ctx.held_count() >= PENDING_MAX_HELD || ctx.strangers_recent() >= STRANGERS_PER_HOUR {
        return answer_not_accepted(ctx, id, sid, s1.as_bytes(), "tor-foreign", amount, fee, claimed, "too many requests are waiting for confirmation");
    }
    let t0 = now();
    let p = Pending {
        slate_id: sid.to_string(),
        amount,
        fee,
        from: claimed.map(str::to_string),
        channel: "tor-foreign".into(),
        received_at: t0,
        expires_at: t0 + ctx.hold.as_secs().max(1),
        sender_verified: false,
        peer: None,
        transport_mode: None,
        transport_route: None,
    };
    if let Err(e) = ctx.add_pending(&p, s1.as_bytes(), &format!("{sid}.s1.json")) {
        return answer_not_accepted(ctx, id, sid, s1.as_bytes(), "tor-foreign", amount, fee, claimed, &format!("cannot keep the request ({e})"));
    }
    ctx.record_stranger();
    ctx.log(&format!(
        "ASK slate={sid} amount={amount} fee={fee} from {}: waiting up to {} s for the user",
        claimed.unwrap_or("-"),
        ctx.hold.as_secs()
    ));
    match ctx.wait_decision(sid, ctx.hold) {
        Some(d) if d.accept => {
            let s1 = fs::read_to_string(ctx.pending_dir().join(format!("{sid}.s1.json"))).unwrap_or(s1);
            let who = format!("{} (address claimed in the slate over Tor; accepted by the user)", claimed.unwrap_or("a stranger"));
            let ans = answer_received(ctx, id, &s1, &who, sid);
            // A claimed address is not authenticated: save only on explicit
            // request after successful receive, with auto-accept disabled.
            let received = serde_json::from_str::<Value>(&ans).is_ok_and(|v| v.get("error").is_none());
            if received && d.add_contact {
                if let Some(address) = claimed {
                    if book_add(&ctx.user_dir, address, &d.name, None, false).is_err() {
                        ctx.log("CONTACT NOT ADDED: existing entry or storage error");
                    }
                }
            }
            ctx.remove_pending(sid);
            ans
        }
        Some(_) => {
            ctx.remove_pending(sid);
            ctx.log(&format!("DECLINED slate={sid} by the user"));
            rpc_err(id, "declined by the receiver")
        }
        None => {
            let saved = ctx.inbox_payment(sid, s1.as_bytes(), "tor-foreign", amount, fee, claimed).unwrap_or_else(|e| e);
            ctx.remove_pending(sid);
            ctx.log(&format!("ASK TIMEOUT slate={sid}: {saved}; the sender gets a slatepack fallback"));
            rpc_err(id, "waiting for the receiver's confirmation; send a slatepack instead")
        }
    }
}

/// Mode "ask" for a messenger envelope: no connection is held; the answer goes
/// back as a signed envelope when the user accepts (`process_decisions`).
fn ask_messenger(ctx: &Ctx, peer: &str, armor: &str, sid: &str, from: Option<&str>, amount: u64, fee: u64, transport_mode: Option<&str>) -> Result<(), String> {
    if ctx.pending_count() >= PENDING_MAX_HELD || ctx.strangers_recent() >= STRANGERS_PER_HOUR {
        return Err("too many requests are waiting for confirmation".into());
    }
    let t0 = now();
    let p = Pending {
        slate_id: sid.to_string(),
        amount,
        fee,
        from: from.map(str::to_string),
        channel: "messenger".into(),
        received_at: t0,
        expires_at: t0 + PENDING_MESSENGER_HOURS * 3600,
        sender_verified: true,
        peer: Some(peer.to_string()),
        transport_mode: transport_mode.map(str::to_string),
        transport_route: ctx.messenger_route.lock().unwrap().clone(),
    };
    ctx.add_pending(&p, armor.as_bytes(), &format!("{sid}.s1.txt"))?;
    ctx.record_stranger();
    ctx.log(&format!("ASK (messenger) slate={sid} from {peer}: waiting for the user; the answer goes back as a signed envelope"));
    Ok(())
}

/// Accept a messenger pending request: receive once, keep the answer if the
/// envelope cannot be sent yet, then add the contact and drop the request.
fn accept_messenger_pending(ctx: &Ctx, p: &Pending, d: &DecisionFile) {
    let Some(peer) = p.peer.clone() else {
        ctx.log(&format!("pending slate={} has no messenger address; retained", p.slate_id));
        return;
    };
    let s2path = ctx.pending_dir().join(format!("{}.s2.txt", p.slate_id));
    let answer = if s2path.exists() {
        match fs::read_to_string(&s2path) {
            Ok(answer) if !answer.trim().is_empty() => answer,
            _ => { ctx.log(&format!("pending slate={} has an unreadable saved answer; retained", p.slate_id)); return; }
        }
    } else {
        let s1 = match fs::read_to_string(ctx.pending_dir().join(format!("{}.s1.txt", p.slate_id))) {
            Ok(t) => t,
            Err(e) => {
                ctx.log(&format!("pending slate={} has no readable S1; retained: {e}", p.slate_id));
                return;
            }
        };
        let who = format!("{} (signed messenger envelope; accepted by the user)", p.from.clone().unwrap_or_else(|| peer.clone()));
        match ctx.receive(&s1, &who) {
            Ok(a) => {
                if let Err(error) = write_atomic(&s2path, a.as_bytes()).and_then(|_| fs::OpenOptions::new().write(true).open(&s2path).and_then(|f| f.sync_all()).map_err(|e| format!("sync answer: {e}"))) {
                    ctx.log(&format!("pending slate={} answer could not be saved; retained: {error}", p.slate_id));
                    return;
                }
                a
            }
            Err(e) => {
                ctx.log(&format!("RECEIVE FAILED slate={} from {peer}: {e}", p.slate_id));
                return;
            }
        }
    };
    let svc = ctx.messenger.lock().unwrap().clone();
    let Some(svc) = svc else { ctx.log("answer waits: messenger is not running"); return; };
    let active_route = ctx.messenger_route.lock().unwrap().clone();
    let configured = match configured_backup_route(&ctx.user_dir) {
        Ok(route) => route,
        Err(error) => { ctx.log(&format!("pending route settings invalid: {error}")); return; }
    };
    let configured = configured.as_ref().map(|(m, t)| (m.as_str(), t.as_str()));
    if !pending_route_matches(p.transport_mode.as_deref(), p.transport_route.as_deref(), &svc.status().mode, active_route.as_deref(), configured) {
        ctx.log(&format!("pending slate={} waits: original messaging route is not active", p.slate_id));
        return;
    }
    if d.add_contact {
        let id = p.from.clone().unwrap_or_else(|| peer.clone());
        match book_add(&ctx.user_dir, &id, &d.name, Some(&peer), false) {
            Ok(()) => ctx.log(&format!("CONTACT ADDED {id} (messenger {peer}); saved without automatic acceptance")),
            Err(e) => ctx.log(&format!("CONTACT {id} not added: {e}")),
        }
    }
    match svc.send_slatepack(&peer, &answer, None) {
        Ok(_) => {
            if let Err(error) = mark_inbound_outcome(ctx, &p.slate_id, "accepted") {
                ctx.log(&format!("answer for slate={} was queued but outcome could not be saved: {error}", p.slate_id));
                return;
            }
            ctx.log(&format!("ANSWERED (messenger) slate={} to {peer}", p.slate_id));
            ctx.remove_pending(&p.slate_id);
        }
        Err(e) => ctx.log(&format!("answer for slate={} not sent to {peer} yet: {e}", p.slate_id)),
    }
}

/// One pass over pending requests: answer messenger ones whose decision came,
/// expire requests nobody can answer any more.
fn process_decisions(ctx: &Ctx) {
    let Some(_permit) = ctx.channel_drain.enter() else { return };
    let _ = fs::create_dir_all(ctx.pending_dir());
    let _ = fs::create_dir_all(ctx.decisions_dir());
    let t = now();
    for p in ctx.pending() {
        if p.channel == "tor-foreign" {
            // The HTTP holder is gone (daemon restarted, or a crash while
            // holding): the sender already has a slatepack fallback.
            if t > p.expires_at.saturating_add(30) {
                if let Ok(s1) = fs::read_to_string(ctx.pending_dir().join(format!("{}.s1.json", p.slate_id))) {
                    let _ = ctx.inbox_payment(&p.slate_id, s1.as_bytes(), "tor-foreign", p.amount, p.fee, p.from.as_deref());
                }
                ctx.remove_pending(&p.slate_id);
            }
            continue;
        }
        let _guard = match incoming_slate_lock(ctx, &p.slate_id) {
            Ok(guard) => guard, Err(error) => { ctx.log(&format!("pending lock failed: {error}")); continue; }
        };
        // The snapshot may be stale after waiting for the per-slate lock.
        let Some(p) = ctx.find_pending(&p.slate_id) else { continue; };
        let Some(peer) = p.peer.as_deref() else { ctx.log("pending request has no peer; retained"); continue; };
        let armor = match fs::read_to_string(ctx.pending_dir().join(format!("{}.s1.txt", p.slate_id))) {
            Ok(armor) => armor, Err(error) => { ctx.log(&format!("pending request has no readable S1: {error}")); continue; }
        };
        let active = ctx.messenger.lock().unwrap().clone().map(|svc| svc.status().mode);
        let mode = match (&p.transport_mode, active.as_deref()) {
            (Some(mode), _) => mode.as_str(),
            (None, Some("direct")) => "direct",
            (None, Some("relay")) => "relay",
            _ => { ctx.log("pending request has no known original route; retained"); continue; }
        };
        if let Err(error) = ensure_inbound_claim(ctx, &p.slate_id, peer, &armor, mode, p.transport_route.as_deref()) {
            ctx.log(&format!("pending request replay guard failed: {error}")); continue;
        }
        match ctx.decision(&p.slate_id) {
            Some(d) if d.accept => accept_messenger_pending(ctx, &p, &d),
            Some(_) => {
                if let Err(error) = mark_inbound_outcome(ctx, &p.slate_id, "declined") { ctx.log(&format!("cannot record declined request: {error}")); continue; }
                ctx.log(&format!("DECLINED (messenger) slate={} by the user", p.slate_id));
                ctx.remove_pending(&p.slate_id);
            }
            None if t > p.received_at + PENDING_MESSENGER_HOURS * 3600 => {
                let name = format!("{}.txt", p.slate_id);
                let meta = json!({"kind":"payment", "amount":p.amount, "fee":p.fee, "from":p.from, "channel":"messenger", "transport_mode":mode, "transport_route":p.transport_route, "received_at":now(), "slate_id":p.slate_id, "file":name});
                if let Err(error) = persist_messenger_inbox(ctx, &name, peer, &armor, &meta).and_then(|_| mark_inbound_outcome(ctx, &p.slate_id, "inbox")) {
                    ctx.log(&format!("cannot move expired pending request to inbox: {error}")); continue;
                }
                ctx.remove_pending(&p.slate_id);
            }
            None => {}
        }
    }
    // Decisions whose request is gone (answered by a holder, stale app file):
    // drop them so the app does not see a ghost request.
    if let Ok(rd) = fs::read_dir(ctx.decisions_dir()) {
        for e in rd.flatten() {
            let p = e.path();
            let sid = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let stale = fs::metadata(&p)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| m.elapsed().ok())
                .map_or(false, |d| d > Duration::from_secs(300));
            if stale || !ctx.pending_json(sid).exists() {
                let _ = fs::remove_file(&p);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Requests the scripts put into the outbox
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
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
    /// Exact route explicitly chosen when this operation was created.
    #[serde(default)]
    expected_mode: Option<String>,
    #[serde(default)]
    expected_route: Option<String>,
    /// Digest captured at first queueing, to prevent a retry from using a
    /// modified S1 while retaining the original slate and route.
    #[serde(default)]
    armor_sha256: Option<String>,
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
    let Some(_permit) = ctx.channel_drain.enter() else { return rpc_err(&id, "channel is switching; please retry"); };
    match req["method"].as_str().unwrap_or("") {
        "check_version" => rpc_ok(&id, json!({"foreign_api_version": 2, "supported_slate_versions": ["V4"]})),
        "receive_tx" => {
            let slate = &req["params"][0];
            if slate["sta"].as_str() != Some("S1") {
                return rpc_err(&id, "receive_tx expects an S1 slate (invoices are never paid automatically)");
            }
            let claimed = claimed_address(ctx, slate);
            let sender = Sender { claimed: claimed.clone(), messenger: None };
            let sid = slate["id"].as_str().unwrap_or("").to_string();
            if !valid_slate_id(&sid) {
                return rpc_err(&id, "bad slate id (expected a UUID)");
            }
            match decide(&load_book(&ctx.user_dir), &sender) {
                Decision::Accept(who) => answer_received(ctx, &id, &slate.to_string(), &who, &sid),
                Decision::Inbox(reason) => {
                    let amount = parse_amount(&slate["amt"]);
                    let fee = parse_amount(&slate["fee"]);
                    answer_not_accepted(ctx, &id, &sid, slate.to_string().as_bytes(), "tor-foreign", amount, fee, claimed.as_deref(), &reason)
                }
                Decision::Ask => ask_foreign(ctx, &id, slate, &sid, claimed.as_deref()),
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
                    Ok(outcome) => {
                        ctx.mark_send(&r, match outcome {
                            FinishOutcome::Broadcast => "PAID_FINALIZED_BROADCAST",
                            FinishOutcome::AlreadyFinalized => "PAID_ALREADY_FINALIZED: broadcast status unknown",
                        });
                        // Do not report the payer's I2 as a finalized I3 if
                        // the actual response was lost or is unreadable.
                        let i3 = fs::read_to_string(PathBuf::from(&r.tx_folder).join("invoice-i3.json"))
                            .ok()
                            .and_then(|t| serde_json::from_str::<Value>(&t).ok());
                        match i3 {
                            Some(i3) => rpc_ok(&id, i3),
                            None => rpc_err(&id, "invoice finalized but I3 response is unavailable"),
                        }
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
    let onion = glaux_tor_arti::onion_from_address(to).map_err(|e| format!("onion of {to}: {e}"))?;
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

/// An invoice answer (I2) delivered over the Tor foreign API: grin-wallet's
/// `finalize_tx` finishes the payment on the issuer's side and broadcasts it.
fn send_reply_via_foreign_api(ctx: &Ctx, req: &SendRequest) -> Result<String, String> {
    let json_path = req.slate_json.as_ref().ok_or("no I2 slate JSON")?;
    let slate: Value = serde_json::from_str(&fs::read_to_string(json_path).map_err(|e| format!("{e}"))?).map_err(|e| format!("{e}"))?;
    let url = foreign_url(ctx, &req.to)?;
    let v = post(ctx, &url, &json!({"jsonrpc": "2.0", "method": "check_version", "id": 1, "params": []}))?;
    if v["foreign_api_version"].as_u64().unwrap_or(0) < 2 {
        return Err("other wallet: unsupported foreign API".into());
    }
    let i3 = post(ctx, &url, &json!({"jsonrpc": "2.0", "method": "finalize_tx", "id": 1, "params": [slate]}))?;
    Ok(i3.to_string())
}

/// A slatepack address is `grin1...` (mainnet) or `tgrin1...` (floonet).
fn is_grin_address(a: &str) -> bool {
    a.starts_with("grin1") || a.starts_with("tgrin1")
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
        let original: SendRequest = match serde_json::from_str(&stored) {
            Ok(original) => original, Err(_) => return Accept::Retry("invalid stored payment request".into()),
        };
        let backup = req.expected_mode.as_deref().map_or(false, is_backup_mode)
            || original.expected_mode.as_deref().map_or(false, is_backup_mode);
        if backup && original != req { return park("conflicting backup request for slate id".into()); }
        let failed_reply = req.kind == "reply" && !backup
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
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let _guard = if valid_slate_id(stem) {
        match slate_lock(&ctx.sends_dir(), stem) { Ok(g) => Some(g), Err(e) => { ctx.log(&format!("outbox lock failed: {e}")); return None; } }
    } else { None };
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
    let Some(parent_permit) = ctx.channel_drain.enter() else { return };
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
            if ctx.work.join("outbox").join(retry_marker_name(&req, "retry-running")).exists() { continue; }
            ctx.log(&format!("RESUME {} slate={} (stored, never dispatched)", req.kind, req.slate_id));
            dispatch(ctx, req, &parent_permit);
        }
    }
}

fn process_outbox(ctx: &Arc<Ctx>) {
    let Some(parent_permit) = ctx.channel_drain.enter() else { return };
    let dir = ctx.work.join("outbox");
    let Ok(rd) = fs::read_dir(&dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("json") {
            continue;
        }
        if let Some(req) = accept_outbox_file(ctx, &p) {
            dispatch(ctx, req, &parent_permit);
        }
    }
}

fn is_backup_mode(mode: &str) -> bool { matches!(mode, "i2p_direct" | "nostr_i2p" | "nostr_direct") }
fn payment_route_tag(mode: &str, url: &str, proxy_identity: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"grinsight-payment-route-v1\0"); digest.update(mode.as_bytes()); digest.update(b"\0");
    digest.update(url.as_bytes()); digest.update(b"\0"); digest.update(proxy_identity.as_bytes());
    data_encoding::HEXLOWER.encode(&digest.finalize())
}
fn valid_route_tag(tag: &str) -> bool {
    tag.len() == 64 && tag.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn configured_backup_route(user_dir: &Path) -> Result<Option<(String, String)>, String> {
    let data = match fs::read_to_string(user_dir.join("settings.json")) {
        Ok(data) => data, Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot read messaging settings".into()),
    };
    let value: Value = serde_json::from_str(&data).map_err(|_| "invalid messaging settings")?;
    let mode = match value.get("messenger_nostr_mode").and_then(Value::as_str).unwrap_or("off") {
        "off" => return Ok(None), "i2p_direct" => "i2p_direct", "i2p" => "nostr_i2p", "direct" => "nostr_direct", _ => return Err("invalid messaging mode".into()),
    };
    let url = if mode == "i2p_direct" { "" } else { value.get("messenger_nostr_url").and_then(Value::as_str).ok_or("Nostr server required")?.trim() };
    if mode != "i2p_direct" && (url.is_empty() || url.len() > 2048 || url.chars().any(char::is_control)) { return Err("invalid Nostr server".into()); }
    if mode == "nostr_direct" && value.get("messenger_nostr_consent_url").and_then(Value::as_str) != Some(url) { return Err("direct Nostr consent missing for server".into()); }
    let proxy = if mode == "nostr_direct" { String::new() } else {
        let raw = value.get("messenger_nostr_proxy").and_then(Value::as_str).ok_or("I2P proxy required")?.trim();
        if raw == "bundled" { "bundled".to_string() } else {
            let addr: std::net::SocketAddr = raw.parse().map_err(|_| "invalid local I2P proxy")?;
            if !addr.ip().is_loopback() || addr.port() == 0 { return Err("I2P proxy must be local".into()); }
            addr.to_string()
        }
    };
    Ok(Some((mode.to_string(), payment_route_tag(mode, url, &proxy))))
}
/// `logical_proxy` is `Some("bundled")` only after an owned router guard is live.
fn active_backup_route(mode: &NetworkMode, logical_proxy: Option<&str>, configured: Option<(&str, &str)>) -> Result<Option<String>, String> {
    if logical_proxy.is_some() && logical_proxy != Some("bundled") { return Err("invalid logical proxy identity".into()); }
    let (label, tag) = match mode {
        NetworkMode::NostrDirect { relay, .. } => ("nostr_direct", payment_route_tag("nostr_direct", relay, "")),
        NetworkMode::NostrI2p { relay, socks, .. } => ("nostr_i2p", payment_route_tag("nostr_i2p", relay, &logical_proxy.map(str::to_string).unwrap_or_else(|| socks.to_string()))),
        NetworkMode::I2p { sam } => ("i2p_direct", payment_route_tag("i2p_direct", "", &logical_proxy.map(str::to_string).unwrap_or_else(|| sam.to_string()))),
        _ => return Ok(None),
    };
    if configured != Some((label, tag.as_str())) { return Err("messaging settings changed during startup".into()); }
    Ok(Some(tag))
}
fn validate_payment_route(req: &SendRequest, active_mode: Option<&str>, active_route: Option<&str>, configured: Option<(&str, &str)>) -> Result<(), String> {
    match req.expected_mode.as_deref() {
        Some("tor") => {
            if req.expected_route.is_some() { return Err("unexpected route tag for Tor".into()); }
            if req.messenger_only && active_mode != Some("direct") { return Err("Tor messenger is not active; no other route attempted".into()); }
        }
        Some(expected) if is_backup_mode(expected) => {
            let tag = req.expected_route.as_deref().ok_or("explicit messaging route tag required")?;
            if !valid_route_tag(tag) || !req.messenger_only || req.messenger.as_deref().map_or(true, |m| m.trim().is_empty()) { return Err("invalid explicitly selected messaging route".into()); }
            if active_mode != Some(expected) || active_route != Some(tag) || configured != Some((expected, tag)) { return Err("selected messaging route is not active; no other route attempted".into()); }
        }
        Some(_) => return Err("invalid explicitly selected messaging route".into()),
        None if req.expected_route.is_some() || active_mode.map_or(false, is_backup_mode) || configured.is_some() => return Err("messaging route must be selected explicitly; no other route attempted".into()),
        None => {},
    }
    Ok(())
}

/// Check cancellation while holding the same per-slate lock as wallet release.
fn check_payment_not_cancelled(req: &SendRequest, strict: bool) -> Result<(), String> {
    let meta_path = PathBuf::from(&req.tx_folder).join("meta.json");
    let text = match fs::read_to_string(&meta_path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && !strict => return Ok(()),
        Err(e) => return Err(format!("cannot verify payment state: {e}")),
    };
    let meta: Value = serde_json::from_str(&text).map_err(|_| "invalid payment metadata")?;
    if strict && meta.get("slate_id").and_then(Value::as_str) != Some(req.slate_id.as_str()) { return Err("payment slate identity mismatch".into()); }
    let stage = meta.get("stage").and_then(Value::as_str);
    if stage == Some("cancelled") { return Err("payment was cancelled; no delivery or finalization attempted".into()); }
    if strict {
        let kind = meta.get("kind").and_then(Value::as_str).ok_or("payment kind is missing")?;
        let valid = matches!((req.kind.as_str(), kind), ("send", "send") | ("invoice", "invoice") | ("reply", "pay_invoice") | ("reply", "receive"));
        if !valid { return Err("payment kind mismatch".into()); }
        if stage.is_none() && !matches!(kind, "invoice" | "receive") { return Err("payment stage is missing".into()); }
    }
    Ok(())
}
/// The reservation journal, not UI metadata, is authoritative after release.
/// Called under the shared wallet/daemon per-slate lock.
fn check_payment_reservation(ctx: &Ctx, req: &SendRequest) -> Result<(), String> {
    let meta: Value = serde_json::from_slice(&fs::read(PathBuf::from(&req.tx_folder).join("meta.json")).map_err(|e| format!("payment metadata unavailable: {e}"))?).map_err(|_| "invalid payment metadata")?;
    let kind = meta.get("kind").and_then(Value::as_str).ok_or("payment kind missing")?;
    let what = match (req.kind.as_str(), kind) { ("send", "send") => "send", ("reply", "pay_invoice") => "invoice", _ => return Ok(()) };
    let pending = ctx.pending_file();
    let mut lock_name = pending.as_os_str().to_os_string(); lock_name.push(".lock");
    let lock_path = PathBuf::from(lock_name);
    let lock = fs::OpenOptions::new().create(true).truncate(false).write(true).open(lock_path).map_err(|e| format!("reservation lock: {e}"))?;
    lock.lock().map_err(|e| format!("reservation lock: {e}"))?;
    const MAX_JOURNAL: u64 = 64 * 1024 * 1024;
    let file = fs::File::open(&pending).map_err(|e| format!("reservation journal unavailable: {e}"))?;
    if file.metadata().map_err(|e| format!("reservation journal metadata: {e}"))?.len() > MAX_JOURNAL { return Err("reservation journal exceeds safe read limit".into()); }
    let mut data = Vec::new();
    file.take(MAX_JOURNAL + 1).read_to_end(&mut data).map_err(|e| format!("reservation journal read: {e}"))?;
    if data.len() as u64 > MAX_JOURNAL { return Err("reservation journal exceeds safe read limit".into()); }
    let text = std::str::from_utf8(&data).map_err(|_| "reservation journal contains invalid UTF-8")?;
    if !text.is_empty() && !text.ends_with('\n') { return Err("reservation journal truncated".into()); }
    let mut reserved = false;
    let mut released = false;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).map_err(|_| "reservation journal corrupted")?;
        let row = row.as_object().ok_or("reservation journal corrupted")?;
        let row_kind = row.get("kind").and_then(Value::as_str);
        if row_kind == Some("release") {
            let sid = row.get("slate_id").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("invalid release record")?;
            if sid == req.slate_id { released = true; }
        }
        if matches!(row_kind, Some("inputs" | "payment")) {
            let sid = row.get("slate_id").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("invalid reservation record")?;
            let purpose = row.get("what").and_then(Value::as_str).filter(|w| matches!(*w,"send"|"invoice"|"self")).ok_or("invalid reservation record")?;
            let wallet = row.get("wallet").and_then(Value::as_u64).ok_or("invalid reservation record")?;
            row.get("tip_height").and_then(Value::as_u64).ok_or("invalid reservation record")?;
            let commits = row.get("commits").and_then(Value::as_str).ok_or("invalid reservation record")?;
            if commits.split(',').any(|c| c.len() != 66 || !c.bytes().all(|b| b.is_ascii_hexdigit())) { return Err("invalid reservation record".into()); }
            if sid == req.slate_id {
                if wallet != ctx.wallet as u64 || purpose != what { return Err("payment reservation identity mismatch".into()); }
                reserved = true;
            }
        }
    }
    if released { return Err("payment inputs were released; no delivery or finalization attempted".into()); }
    if !reserved { return Err("payment reservation could not be verified".into()); }
    if what == "send" && (req.context.is_empty() || !Path::new(&req.context).is_file()) { return Err("send context unavailable; no delivery or finalization attempted".into()); }
    Ok(())
}

/// Never hold this lock across the Tor foreign API path: that path may call
/// finish(), which takes the same lock. This helper is for backup envelopes.
fn with_backup_send_lock<T>(ctx: &Ctx, req: &SendRequest, send: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    if req.expected_mode.as_deref().map_or(false, is_backup_mode) {
        let _guard = slate_lock(&ctx.sends_dir(), &req.slate_id)?;
        check_payment_not_cancelled(req, true)?;
        check_payment_reservation(ctx, req)?;
        let folder = PathBuf::from(&req.tx_folder);
        if folder.join(FINALIZED_MARK).exists() || folder.join("spend-tx.hex").exists() {
            return Err("payment already finalized; no new delivery attempted".into());
        }
        send()
    } else { send() }
}

/// Do not overwrite a cancellation or a concurrently finalized payment with
/// stale DISPATCHED/SENT/FAILED state from an earlier network attempt.
fn mark_delivery_if_pending(ctx: &Ctx, req: &SendRequest, status: &str) -> bool {
    if req.expected_mode.as_deref().map_or(false, is_backup_mode) {
        let _guard = match slate_lock(&ctx.sends_dir(), &req.slate_id) { Ok(guard) => guard, Err(e) => { ctx.log(&format!("cannot lock payment status: {e}")); return false; } };
        if check_payment_not_cancelled(req, true).is_err() { return false; }
        let folder = PathBuf::from(&req.tx_folder);
        if folder.join(FINALIZED_MARK).exists() || folder.join("spend-tx.hex").exists() { return false; }
        ctx.mark_send(req, status);
        true
    } else { ctx.mark_send(req, status); true }
}

struct RetryCompletion(Option<PathBuf>);
impl Drop for RetryCompletion { fn drop(&mut self) { if let Some(path) = &self.0 { let _ = fs::remove_file(path); } } }
fn dispatch(ctx: &Arc<Ctx>, req: SendRequest, parent: &channel_drain::Permit) { dispatch_inner(ctx, req, None, parent) }
fn dispatch_inner(ctx: &Arc<Ctx>, req: SendRequest, retry_marker: Option<PathBuf>, parent: &channel_drain::Permit) {
    let permit = match parent.child() { Ok(p) => p, Err(e) => { ctx.log(e); return; } };
    {
        let completion = RetryCompletion(retry_marker);
        if !mark_delivery_if_pending(ctx, &req, "DISPATCHED") { return; }
        ctx.log(&format!("OUTGOING {} slate={} to {}", req.kind, req.slate_id, req.to));
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _permit = permit;
            let _completion = completion;
            let active = ctx.messenger.lock().unwrap().clone().map(|svc| svc.status().mode);
            let active_route = ctx.messenger_route.lock().unwrap().clone();
            let configured = match configured_backup_route(&ctx.user_dir) {
                Ok(route) => route,
                Err(error) => { mark_delivery_if_pending(&ctx, &req, &format!("FAILED: invalid messaging settings: {error}")); return; }
            };
            let configured = configured.as_ref().map(|(m, t)| (m.as_str(), t.as_str()));
            if let Err(error) = validate_payment_route(&req, active.as_deref(), active_route.as_deref(), configured) {
                mark_delivery_if_pending(&ctx, &req, &format!("FAILED: {error}"));
                return;
            }
            // 1) grin-wallet / Grin++ Tor foreign API: payments (S1 -> S2) and
            //    answers to our invoice (I2 -> finalize_tx). A synchronous answer.
            let tor_call = if req.messenger_only {
                None
            } else if req.kind == "send" {
                Some(send_via_foreign_api(&ctx, &req))
            } else if req.kind == "reply" && is_grin_address(&req.to) {
                Some(send_reply_via_foreign_api(&ctx, &req))
            } else {
                None
            };
            if let Some(result) = tor_call {
                match result {
                    Ok(answer) => {
                        if req.kind == "send" {
                            ctx.log(&format!("S2 received over the Tor foreign API for slate={}", req.slate_id));
                            match ctx.finish(&req, &answer) {
                                Ok(FinishOutcome::Broadcast) => ctx.mark_send(&req, "DONE via Tor foreign API: finalized and broadcast"),
                                Ok(FinishOutcome::AlreadyFinalized) => ctx.mark_send(&req, "ALREADY_FINALIZED: broadcast status unknown"),
                                Err(e) => ctx.mark_send(&req, &format!("FAILED after S2: {e}")),
                            }
                        } else {
                            ctx.mark_send(&req, "DONE via Tor foreign API: the issuer finalized the invoice and broadcasts");
                            ctx.log(&format!("invoice answer for slate={} delivered to the issuer over the Tor foreign API", req.slate_id));
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
                (Some(_), Some(svc)) if req.expected_mode.as_deref() == Some("tor") && svc.status().mode != "direct" => {
                    mark_delivery_if_pending(&ctx, &req, "FAILED: Tor messenger unavailable; no other messaging route attempted");
                },
                (Some(m), Some(svc)) => match with_backup_send_lock(&ctx, &req, || {
                    let armor = fs::read_to_string(&req.armor).map_err(|e| format!("cannot read saved slatepack: {e}"))?;
                    if req.expected_mode.as_deref().map_or(false, is_backup_mode) {
                        let digest = slatepack_digest(&armor)?;
                        if req.armor_sha256.as_deref() != Some(digest.as_str()) { return Err("saved slatepack changed; no delivery attempted".into()); }
                    }
                    svc.send_slatepack(&m, &armor, None).map_err(|e| format!("{e}"))
                }) {
                    Ok(_) if req.kind == "reply" => {
                        mark_delivery_if_pending(&ctx, &req, &format!("DONE: answer sent via messenger to {m}; the issuer finalizes and broadcasts"));
                        ctx.log(&format!("answer for slate={} sent via messenger to {m}", req.slate_id));
                    }
                    Ok(_) => {
                        mark_delivery_if_pending(&ctx, &req, &format!("SENT via messenger to {m}; waiting for the answer"));
                        ctx.log(&format!("sent slate={} via messenger to {m}", req.slate_id));
                    }
                    Err(e) => { mark_delivery_if_pending(&ctx, &req, &format!("FAILED: messenger send: {e}")); },
                },
                (None, _) => { mark_delivery_if_pending(&ctx, &req, "FAILED: receiver not reachable over Tor and has no messenger address in the address book"); },
                (_, None) => { mark_delivery_if_pending(&ctx, &req, "FAILED: messenger not running"); },
            }
        });
    }
}

type PaymentWatch=glaux_messenger_wallet::service::PaymentWatch;
use glaux_messenger_wallet::service::incremental_payment_events;

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
fn process_unhandled(msgs: Vec<(String, String, String)>, done: &mut Processed, mut handle: impl FnMut(&str, &str) -> Result<(), String>) -> Vec<String> {
    let mut errs = Vec::new();
    for (id, peer, armor) in msgs {
        if done.contains(&id) {
            continue;
        }
        if let Err(e) = handle(&peer, &armor) {
            errs.push(format!("processing failed for {id}: {e}"));
            continue;
        }
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

fn usable_message_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 256 && !id.chars().any(|c| c.is_control() || c.is_whitespace())
}

impl Processed {
    fn open(path: &Path, existing: impl FnOnce() -> Vec<String>) -> Result<Processed, String> {
        let mut p = Processed { path: path.to_path_buf(), ids: Default::default(), baselined: 0 };
        match fs::read_to_string(path) {
            Ok(t) => {
                if !t.is_empty() && !t.ends_with('\n') { return Err("truncated processed-message list".into()); }
                for id in t.lines() {
                    if !usable_message_id(id) { return Err("invalid processed-message record".into()); }
                    p.ids.insert(id.to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut data = String::new();
                for id in existing() {
                    if !usable_message_id(&id) { return Err("invalid earlier message id".into()); }
                    if p.ids.insert(id.clone()) { data.push_str(&id); data.push('\n'); }
                }
                let dir = path.parent().ok_or("processed-message path has no parent")?;
                fs::create_dir_all(dir).map_err(|e| format!("cannot create processed-message directory: {e}"))?;
                let tmp = dir.join(format!(".processed-init-{}.tmp", stamp()));
                let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)
                    .map_err(|e| format!("cannot create processed-message list: {e}"))?;
                file.write_all(data.as_bytes()).and_then(|_| file.sync_all())
                    .map_err(|e| format!("cannot persist processed-message list: {e}"))?;
                drop(file);
                fs::rename(&tmp, path).map_err(|e| format!("cannot install processed-message list: {e}"))?;
                p.baselined = p.ids.len();
            }
            Err(e) => return Err(format!("cannot read processed-message list: {e}")),
        }
        Ok(p)
    }

    fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }

    fn mark(&mut self, id: &str) -> Result<(), String> {
        if !usable_message_id(id) {
            return Err("unusable message id".into());
        }
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&self.path).map_err(|e| format!("{e}"))?;
        f.write_all(format!("{id}\n").as_bytes()).map_err(|e| format!("{e}"))?;
        f.sync_all().map_err(|e| format!("{e}"))?;
        self.ids.insert(id.to_string());
        Ok(())
    }
}

/// Persistent identity of an incoming S1, retained after user decisions so
/// an envelope replay cannot create another approval or change its peer/route.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug)]
struct InboundClaim { peer: String, armor: String, transport_mode: String, #[serde(default)] transport_route: Option<String> }

fn inbound_claim_dir(ctx: &Ctx) -> PathBuf { ctx.work.join("messenger-inbound") }
fn incoming_slate_lock(ctx: &Ctx, sid: &str) -> Result<fs::File, String> {
    slate_lock(&inbound_claim_dir(ctx).join("locks"), sid)
}
fn ensure_inbound_claim(ctx: &Ctx, sid: &str, peer: &str, armor: &str, mode: &str, route: Option<&str>) -> Result<(), String> {
    if !valid_slate_id(sid) || armor.len() > INBOX_MAX_ITEM { return Err("invalid incoming claim".into()); }
    let dir = inbound_claim_dir(ctx); fs::create_dir_all(&dir).map_err(|e| format!("claim directory: {e}"))?;
    let path = dir.join(format!("{sid}.json"));
    if is_backup_mode(mode) && !route.map_or(false, valid_route_tag) { return Err("missing original backup route".into()); }
    let claim = InboundClaim { peer: peer.into(), armor: armor.into(), transport_mode: mode.into(), transport_route: route.map(str::to_string) };
    match fs::read(&path) {
        Ok(bytes) => {
            let stored: InboundClaim = serde_json::from_slice(&bytes).map_err(|_| "corrupt incoming claim")?;
            if stored != claim { return Err("conflicting incoming slatepack, peer, or route".into()); }
            return Ok(());
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("cannot read incoming claim: {e}")),
    }
    // Bounded records protect disk space. Fail closed instead of evicting a
    // replay guard which could otherwise cause a second user approval.
    let mut count = 0usize; let mut total = 0u64;
    for entry in fs::read_dir(&dir).map_err(|e| format!("claim directory: {e}"))? {
        let entry = entry.map_err(|e| format!("claim directory: {e}"))?;
        let meta = entry.metadata().map_err(|e| format!("claim metadata: {e}"))?;
        if meta.is_file() { count += 1; total = total.saturating_add(meta.len()); }
    }
    if count >= 100_000 || total.saturating_add(armor.len() as u64) > 256 * 1024 * 1024 {
        return Err("incoming replay-protection storage is full".into());
    }
    let data = serde_json::to_vec(&claim).map_err(|e| format!("incoming claim: {e}"))?;
    let temp = dir.join(format!(".claim-{}.tmp", stamp()));
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&temp).map_err(|e| format!("claim create: {e}"))?;
    f.write_all(&data).and_then(|_| f.sync_all()).map_err(|e| format!("claim write: {e}"))?; drop(f);
    fs::rename(&temp, &path).map_err(|e| format!("claim install: {e}"))?;
    Ok(())
}
fn inbound_outcome(ctx: &Ctx, sid: &str) -> Result<Option<String>, String> {
    match fs::read_to_string(inbound_claim_dir(ctx).join(format!("{sid}.done"))) {
        Ok(s) if matches!(s.as_str(), "accepted" | "declined" | "inbox") => Ok(Some(s)),
        Ok(_) => Err("corrupt incoming outcome".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read incoming outcome: {e}")),
    }
}
fn mark_inbound_outcome(ctx: &Ctx, sid: &str, outcome: &str) -> Result<(), String> {
    if !valid_slate_id(sid) || !matches!(outcome, "accepted" | "declined" | "inbox") { return Err("invalid incoming outcome".into()); }
    if let Some(old) = inbound_outcome(ctx, sid)? {
        return if old == outcome { Ok(()) } else { Err("conflicting incoming outcome".into()) };
    }
    let dir = inbound_claim_dir(ctx); fs::create_dir_all(&dir).map_err(|e| format!("claim directory: {e}"))?;
    let claim = fs::read(dir.join(format!("{sid}.json"))).map_err(|e| format!("missing incoming claim: {e}"))?;
    let _: InboundClaim = serde_json::from_slice(&claim).map_err(|_| "corrupt incoming claim")?;
    let tmp = dir.join(format!(".outcome-{}.tmp", stamp()));
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp).map_err(|e| format!("outcome create: {e}"))?;
    f.write_all(outcome.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("outcome write: {e}"))?; drop(f);
    fs::rename(&tmp, dir.join(format!("{sid}.done"))).map_err(|e| format!("outcome install: {e}"))?;
    Ok(())
}
fn pending_route_matches(expected: Option<&str>, expected_route: Option<&str>, active: &str, active_route: Option<&str>, configured: Option<(&str, &str)>) -> bool {
    match expected {
        Some(mode) if is_backup_mode(mode) => {
            mode == active && expected_route.map_or(false, valid_route_tag) && expected_route == active_route
                && configured == expected_route.map(|tag| (mode, tag))
        }
        Some(mode) => mode == active && expected_route.is_none(),
        None => !is_backup_mode(active) && expected_route.is_none(),
    }
}

/// Persist a received item idempotently before marking its envelope processed.
fn persist_messenger_inbox(ctx: &Ctx, name: &str, peer: &str, armor: &str, meta: &Value) -> Result<(), String> {
    let inbox = ctx.work.join("inbox");
    let path = inbox.join(name);
    match fs::read(&path) {
        Ok(existing) if existing == armor.as_bytes() => {},
        Ok(_) => return Err("conflicting slatepack for this slate id".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => { inbox_save(&inbox, name, armor.as_bytes(), &ctx.inbox_rate, now())?; },
        Err(e) => return Err(format!("cannot read saved slatepack: {e}")),
    }
    fs::OpenOptions::new().write(true).open(&path).and_then(|f| f.sync_all()).map_err(|e| format!("cannot sync saved slatepack: {e}"))?;
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    let peer_path = inbox.join(format!("{stem}.peer"));
    match fs::read_to_string(&peer_path) {
        Ok(existing) if existing != peer => return Err("conflicting messenger peer for this slate id".into()),
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => write_atomic(&peer_path, peer.as_bytes())?,
        Err(e) => return Err(format!("cannot read saved peer: {e}")),
    }
    let meta_path = inbox.join(format!("{stem}.meta.json"));
    match fs::read(&meta_path) {
        Ok(old) => {
            let old: Value = serde_json::from_slice(&old).map_err(|_| "corrupt inbox metadata")?;
            if old.get("transport_mode").and_then(Value::as_str) != meta.get("transport_mode").and_then(Value::as_str)
                || old.get("transport_route").and_then(Value::as_str) != meta.get("transport_route").and_then(Value::as_str) {
                return Err("conflicting route for this slate id".into());
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("cannot read inbox metadata: {e}")),
    }
    write_atomic(&meta_path, meta.to_string().as_bytes())?;
    for p in [&peer_path, &meta_path] {
        fs::OpenOptions::new().write(true).open(p).and_then(|f| f.sync_all()).map_err(|e| format!("cannot sync inbox metadata: {e}"))?;
    }
    Ok(())
}

/// A reply may only finalize the payment when it arrived over the selected
/// route and, for backup channels, from the exact signed messenger peer.
fn validate_answer_route(ctx: &Ctx, req: &SendRequest, peer: &str, active_mode: &str, active_route: Option<&str>) -> Result<(), String> {
    if req.expected_mode.as_deref().map_or(false, is_backup_mode) && req.messenger.as_deref() != Some(peer) {
        return Err("answer from an unexpected signed messenger peer".into());
    }
    if req.expected_mode.as_deref() == Some("tor") && active_mode != "direct" {
        return Err("answer arrived over a different channel".into());
    }
    let configured = configured_backup_route(&ctx.user_dir)?;
    let configured = configured.as_ref().map(|(m, t)| (m.as_str(), t.as_str()));
    validate_payment_route(req, Some(active_mode), active_route, configured)
}

fn validate_incoming_slate_state(state:&str,sid:&str)->Result<(),String> {
    if !valid_slate_id(sid) {return Err("invalid slate id; retained for recovery".into());}
    if !matches!(state,"S1"|"S2"|"I1"|"I2") {return Err("unsupported slate state; retained for recovery".into());}
    Ok(())
}
fn sync_finalized_result(req:&SendRequest)->Result<(),String> {
    let folder=PathBuf::from(&req.tx_folder);
    for name in [FINALIZED_MARK,"spend-tx.hex"] {
        let path=folder.join(name);
        let f=fs::OpenOptions::new().write(true).open(&path).map_err(|e|format!("finalized result unavailable: {e}"))?;
        if f.metadata().map_err(|e|format!("finalized result metadata: {e}"))?.len()==0{return Err("finalized result is empty".into());}
        f.sync_all().map_err(|e|format!("finalized result sync: {e}"))?;
    }
    Ok(())
}

/// A signed Slatepack is marked processed only after its result is saved.
fn handle_envelope(ctx: &Ctx, svc: &WalletService, peer: &str, armor: &str) -> Result<(), String> {
    let _permit = ctx.channel_drain.enter().ok_or("channel is switching; retain for retry")?;
    let (state, sid, sender, amount, fee) = match ctx.info(armor) {
        Ok(x) => x,
        Err(e) => return Err(format!("slatepack inspection failed: {e}")),
    };
    validate_incoming_slate_state(&state,&sid)?;
    match state.as_str() {
        "S1" => {
            let mode = svc.status().mode;
            let route = ctx.messenger_route.lock().unwrap().clone();
            let _guard = incoming_slate_lock(ctx, &sid)?;
            ensure_inbound_claim(ctx, &sid, peer, armor, &mode, route.as_deref())?;
            if let Some(outcome) = inbound_outcome(ctx, &sid)? {
                if outcome == "accepted" {
                    let configured = configured_backup_route(&ctx.user_dir)?;
                    let configured = configured.as_ref().map(|(m, t)| (m.as_str(), t.as_str()));
                    if !pending_route_matches(Some(&mode), route.as_deref(), &mode, route.as_deref(), configured) { return Err("original messaging route is not active".into()); }
                    let answer = ctx.receive(armor, "previously accepted signed messenger envelope")?;
                    svc.send_slatepack(peer, &answer, None).map_err(|e| format!("answer redelivery failed: {e}"))?;
                }
                return Ok(());
            }
            let claimed = Some(sender.clone()).filter(|x| !x.is_empty());
            let sender = Sender { claimed: claimed.clone(), messenger: Some(peer.to_string()) };
            match decide(&load_book(&ctx.user_dir), &sender) {
                Decision::Accept(who) => {
                    let configured = configured_backup_route(&ctx.user_dir)?;
                    let configured = configured.as_ref().map(|(m, t)| (m.as_str(), t.as_str()));
                    if !pending_route_matches(Some(&mode), route.as_deref(), &mode, route.as_deref(), configured) { return Err("original messaging route is not active".into()); }
                    let answer = ctx.receive(armor, &who).map_err(|e| format!("receive failed: {e}"))?;
                    svc.send_slatepack(peer, &answer, None).map_err(|e| format!("answer delivery failed: {e}"))?;
                    mark_inbound_outcome(ctx, &sid, "accepted")?;
                }
                decision => {
                    if matches!(decision, Decision::Ask) {
                        let pending_file = ctx.pending_json(&sid);
                        match fs::read_to_string(&pending_file) {
                            Ok(text) => {
                                let pending: Pending = serde_json::from_str(&text).map_err(|_| "corrupt existing pending request")?;
                                let saved = fs::read(ctx.pending_dir().join(format!("{sid}.s1.txt"))).map_err(|e| format!("cannot read pending request: {e}"))?;
                                if pending.peer.as_deref() != Some(peer) || saved != armor.as_bytes() { return Err("conflicting pending slatepack".into()); }
                                for p in [&pending_file, &ctx.pending_dir().join(format!("{sid}.s1.txt"))] {
                                    fs::OpenOptions::new().write(true).open(p).and_then(|f| f.sync_all()).map_err(|e| format!("cannot sync pending request: {e}"))?;
                                }
                                return Ok(());
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                            Err(e) => return Err(format!("cannot read pending request: {e}")),
                        }
                        let orphan = ctx.pending_dir().join(format!("{sid}.s1.txt"));
                        match fs::read(&orphan) {
                            Ok(saved) if saved != armor.as_bytes() => return Err("conflicting incomplete pending slatepack".into()),
                            Ok(_) => {},
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                            Err(e) => return Err(format!("cannot read incomplete pending request: {e}")),
                        }
                        if ask_messenger(ctx, peer, armor, &sid, claimed.as_deref(), amount, fee, Some(&mode)).is_ok() {
                            for p in [&pending_file, &ctx.pending_dir().join(format!("{sid}.s1.txt"))] {
                                fs::OpenOptions::new().write(true).open(p).and_then(|f| f.sync_all()).map_err(|e| format!("cannot sync pending request: {e}"))?;
                            }
                            return Ok(());
                        }
                    }
                    let name = format!("{sid}.txt");
                    let meta = json!({"kind":"payment", "amount":amount, "fee":fee, "from":claimed, "channel":"messenger", "transport_mode":mode, "transport_route":route, "received_at":now(), "slate_id":sid, "file":name});
                    persist_messenger_inbox(ctx, &name, peer, armor, &meta)?;
                    mark_inbound_outcome(ctx, &sid, "inbox")?;
                    ctx.log(&format!("saved S1 for slate={sid} in the inbox"));
                }
            }
        }
        "S2" | "I2" => match ctx.find_send(&sid) {
            Some(r) => {
                let mode = svc.status().mode;
                let route = ctx.messenger_route.lock().unwrap().clone();
                validate_answer_route(ctx, &r, peer, &mode, route.as_deref())?;
                match ctx.finish(&r, armor) {
                Ok(FinishOutcome::Broadcast) => { sync_finalized_result(&r)?; ctx.mark_send(&r, &format!("DONE via messenger ({state}): finalized and broadcast")); },
                Ok(FinishOutcome::AlreadyFinalized) => { sync_finalized_result(&r)?; ctx.mark_send(&r, "ALREADY_FINALIZED: broadcast status unknown"); },
                Err(e) => { ctx.mark_send(&r, &format!("FAILED after {state}: {e}")); return Err(format!("finalization failed: {e}")); }
                }
            },
            None => { ctx.log(&format!("{state} for unknown slate={sid}: retained for retry")); return Err("pending transaction not found".into()); }
        },
        "I1" => {
            let name = format!("invoice-{sid}.txt");
            let from = Some(sender).filter(|x| !x.is_empty());
            let mode = svc.status().mode;
            let route = ctx.messenger_route.lock().unwrap().clone();
            if is_backup_mode(&mode) && !route.as_deref().map_or(false, valid_route_tag) { return Err("missing active messaging route".into()); }
            let meta = json!({"kind":"invoice", "amount":amount, "fee":fee, "from":from, "channel":"messenger", "transport_mode":mode, "transport_route":route, "received_at":now(), "slate_id":sid, "file":name});
            persist_messenger_inbox(ctx, &name, peer, armor, &meta)?;
            ctx.log(&format!("invoice slate={sid} saved for manual approval"));
        }
        _ => return Err("unsupported slate state; retained for recovery".into()),
    }
    Ok(())
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

fn select_messenger_mode(relay: Option<&str>, tor_ok: bool, bridge_configured: bool, plain: bool) -> Option<NetworkMode> {
    match (relay, tor_ok, bridge_configured) {
        (_, true, _) => Some(NetworkMode::Direct),
        (Some(url), false, false) => Some(NetworkMode::Relay { url: url.to_owned(), plain }),
        _ => None,
    }
}

/// Explicit profile choice. Direct mode requires consent bound to this exact
/// server URL; neither mode falls back to another network on error.
fn read_nostr_settings(user_dir: &Path) -> Result<Value, String> {
    let text = match fs::read_to_string(user_dir.join("settings.json")) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(json!({})),
        Err(_) => return Err("cannot read messenger settings".into()),
    };
    serde_json::from_str(&text).map_err(|_| "invalid messenger settings".into())
}
fn uses_bundled_i2p(value: &Value) -> bool {
    matches!(value.get("messenger_nostr_mode").and_then(Value::as_str), Some("i2p" | "i2p_direct"))
        && value.get("messenger_nostr_proxy").and_then(Value::as_str) == Some("bundled")
}
#[cfg(test)]
fn read_nostr_mode(user_dir: &Path) -> Result<Option<NetworkMode>, String> {
    parse_nostr_snapshot(&read_nostr_settings(user_dir)?, None)
}
fn parse_nostr_snapshot(value: &Value, bundled: Option<(std::net::SocketAddr, std::net::SocketAddr)>) -> Result<Option<NetworkMode>, String> {
    let mode = value.get("messenger_nostr_mode").and_then(Value::as_str).unwrap_or("off");
    if mode == "off" { return Ok(None); }
    if mode == "i2p_direct" {
        let raw = value.get("messenger_nostr_proxy").and_then(Value::as_str).ok_or("I2P SAM required")?;
        let sam: std::net::SocketAddr = if raw == "bundled" { bundled.ok_or("bundled I2P router unavailable")?.0 } else { raw.parse().map_err(|_| "invalid I2P SAM")? };
        if !sam.ip().is_loopback() || sam.port() == 0 { return Err("I2P SAM must be local".into()); }
        return Ok(Some(NetworkMode::I2p { sam }));
    }
    let relay = value.get("messenger_nostr_url").and_then(Value::as_str).ok_or("Nostr server required")?.trim();
    if relay.is_empty() || relay.len() > 2048 || relay.chars().any(char::is_control) { return Err("invalid Nostr server".into()); }
    let expiration_tag = value.get("messenger_nostr_expiry").and_then(Value::as_bool).unwrap_or(false);
    match mode {
        "i2p" => {
            let raw = value.get("messenger_nostr_proxy").and_then(Value::as_str).ok_or("I2P proxy required")?;
            let socks: std::net::SocketAddr = if raw == "bundled" { bundled.ok_or("bundled I2P router unavailable")?.1 } else { raw.parse().map_err(|_| "invalid I2P proxy")? };
            if !socks.ip().is_loopback() || socks.port() == 0 { return Err("I2P proxy must be local".into()); }
            Ok(Some(NetworkMode::NostrI2p { relay: relay.to_string(), socks, expiration_tag }))
        }
        "direct" => {
            let agreed = value.get("messenger_nostr_consent_url").and_then(Value::as_str) == Some(relay);
            if !agreed || !relay.starts_with("wss://") { return Err("direct Nostr requires WSS and explicit consent for this server".into()); }
            Ok(Some(NetworkMode::NostrDirect { relay: relay.to_string(), consent: true, expiration_tag }))
        }
        _ => Err("unsupported messenger mode".into()),
    }
}

#[derive(Clone)]
struct BridgeSpec { line: String, binary: PathBuf }

/// Start the Tor foreign API and outgoing client; used synchronously for Tor
/// mode and in the background when a separate messenger mode is selected.
fn bootstrap_wallet_tor(
    ctx: &Ctx, status: &Arc<Mutex<Value>>, seed: &[u8; 32], local: &str,
    cfg: &glaux_tor_arti::TorConfig, has_bridge: bool,
) -> Option<glaux_tor_arti::OnionService> {
    ctx.log("Tor: bootstrapping Arti (30-150 s the first time)...");
    let mut onion = None;
    match glaux_tor_arti::OnionService::start(seed, local, cfg) {
        Ok(s) => {
            ctx.log(&format!("Tor: onion service published: {}", s.url()));
            onion = Some(s);
            match glaux_tor_arti::TorHttpClient::bootstrap(cfg) {
                Ok(c) => { *ctx.tor.lock().unwrap() = Some(Arc::new(c)); status.lock().unwrap()["tor"] = json!("ready"); }
                Err(e) => {
                    if has_bridge { ctx.log("Tor bridge client failed"); } else { ctx.log(&format!("Tor client: {e}")); }
                    status.lock().unwrap()["tor"] = json!("failed: outgoing Tor client unavailable");
                }
            }
        }
        Err(e) => {
            if has_bridge { ctx.log("Tor bridge failed; no fallback was attempted"); status.lock().unwrap()["tor"] = json!("failed: bridge connection failed"); }
            else { ctx.log(&format!("Tor FAILED: {e} (the messenger relay is used if configured)")); status.lock().unwrap()["tor"] = json!(format!("failed: {e}")); }
        }
    }
    write_status(ctx, &status.lock().unwrap());
    onion
}

/// Reads private bridge configuration without putting it in logs or argv.
fn read_bridge_settings(user_dir: &Path) -> Result<Option<BridgeSpec>, String> {
    let text = match fs::read_to_string(user_dir.join("settings.json")) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot read Tor bridge settings".into()),
    };
    let v: Value = serde_json::from_str(&text).map_err(|_| "invalid Tor settings")?;
    let mode = match v.get("tor_bridge_mode") {
        None => "direct",
        Some(v) => v.as_str().ok_or("invalid Tor bridge mode")?,
    };
    if mode == "direct" { return Ok(None); }
    if !matches!(mode, "obfs4" | "snowflake") { return Err("unsupported Tor bridge mode".into()); }
    let raw_line = v["tor_bridge_line"].as_str().ok_or("missing bridge line")?.trim();
    let line = raw_line.strip_prefix("Bridge ").unwrap_or(raw_line);
    let binary = v["tor_bridge_binary"].as_str().ok_or("missing bridge program")?.trim();
    if line.len() > 2048 || line.contains(['\n', '\r']) || line.split_whitespace().next() != Some(mode) {
        return Err("invalid bridge line for selected transport".into());
    }
    let path = if binary == "bundled" {
        let exe = std::env::current_exe().map_err(|_| "cannot locate bundled Tor transport")?;
        let parent = exe.parent().ok_or("cannot locate bundled Tor transport")?;
        #[cfg(target_os = "windows")]
        let filename = "lyrebird.exe";
        #[cfg(target_os = "android")]
        let filename = "libgrinsight_pt.so";
        #[cfg(not(any(target_os = "windows", target_os = "android")))]
        let filename = "lyrebird";
        parent.join(filename)
    } else { PathBuf::from(binary) };
    if binary.len() > 1024 || !path.is_absolute() || !path.is_file() {
        return Err("transport program must be an existing absolute file path".into());
    }
    Ok(Some(BridgeSpec { line: line.to_owned(), binary: path }))
}

fn serve(args: &[String]) -> Result<(), String> {
    let exe = PathBuf::from(arg(args, "--exe").ok_or("--exe")?);
    let seeds = PathBuf::from(arg(args, "--seeds").ok_or("--seeds")?);
    // --watch-stdin: seeds come framed ("LEN <n>\n" + n bytes) and standard input
    // stays open afterwards as a lifeline. When the parent (grinsight-service)
    // exits for any reason - normal close, crash, killed - the OS closes the
    // pipe, the read returns EOF and this daemon exits instead of staying
    // orphaned with the wallet's Tor identity running.
    let watch_stdin = flag(args, "--watch-stdin");
    let seed_text = if seeds.as_os_str() == "-" && watch_stdin {
        let mut input = std::io::stdin().lock();
        let mut header = String::new();
        std::io::BufRead::read_line(&mut input, &mut header).map_err(|e| format!("seeds on standard input: {e}"))?;
        let n: usize = header
            .trim()
            .strip_prefix("LEN ")
            .and_then(|v| v.parse().ok())
            .filter(|n| *n <= 64 * 1024)
            .ok_or("seeds on standard input: bad length header")?;
        let mut buf = vec![0u8; n];
        std::io::Read::read_exact(&mut input, &mut buf).map_err(|e| format!("seeds on standard input: {e}"))?;
        Some(String::from_utf8(buf).map_err(|_| "seeds on standard input: not UTF-8")?)
    } else if seeds.as_os_str() == "-" {
        let mut t = String::new();
        std::io::Read::read_to_string(&mut std::io::Read::take(std::io::stdin(), 64 * 1024), &mut t)
            .map_err(|e| format!("seeds on standard input: {e}"))?;
        Some(t)
    } else {
        None
    };
    if watch_stdin {
        std::thread::spawn(|| {
            let mut sink = [0u8; 64];
            let mut input = std::io::stdin();
            loop {
                match std::io::Read::read(&mut input, &mut sink) {
                    Ok(0) | Err(_) => {
                        eprintln!("parent closed standard input: exiting");
                        std::process::exit(0);
                    }
                    Ok(_) => {}
                }
            }
        });
    }
    let user_dir = PathBuf::from(arg(args, "--user-dir").ok_or("--user-dir")?);
    let bridge = read_bridge_settings(&user_dir)?;
    let nostr_snapshot = read_nostr_settings(&user_dir)?;
    let bundled_selected = uses_bundled_i2p(&nostr_snapshot);
    let wallet: usize = arg(args, "--wallet").and_then(|w| w.parse().ok()).unwrap_or(1);
    let mainnet = flag(args, "--mainnet");
    let no_tor = flag(args, "--no-tor");
    let port: u16 = arg(args, "--port").and_then(|p| p.parse().ok()).unwrap_or(0);
    let relay = arg(args, "--relay");
    let work = user_dir.join(format!("tor-wallet-{wallet}"));
    for d in ["outbox", "inbox", "sends", "in", "pending", "decisions"] {
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
            "another grinsight-tor daemon of wallet {wallet} is already running (close its window; if none is visible: Get-Process grinsight-tor | Stop-Process -Force)"
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
    let hold_secs = std::env::var("GRINSIGHT_TOR_HOLD_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(DEFAULT_HOLD_SECS)
        .clamp(1, DEFAULT_HOLD_SECS);
    let strangers: Vec<u64> = fs::read_to_string(work.join("strangers.log"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().parse().ok())
        .collect();
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
        messenger_route: Mutex::new(None),
        channel_drain: channel_drain::ChannelDrain::default(),
        log: Mutex::new(()),
        inbox_rate: Mutex::new((0, 0)),
        hold: Duration::from_secs(hold_secs),
        strangers: Mutex::new(strangers),
        #[cfg(test)]
        receive_fn: None,
        #[cfg(test)]
        finish_fn: None,
    });
    // Keys from the wallet (stdout of the wallet exe only).
    let (code, out) = ctx.exe(&["--tor-keys", "--seeds", &ctx.seeds.display().to_string(), "--wallet", &wallet.to_string()])?;
    if code != 0 {
        return Err("wallet exe --tor-keys failed".into());
    }
    let address = Ctx::line(&out, "ADDRESS").ok_or("no ADDRESS")?.to_string();
    let addr_seed = hex32(Ctx::line(&out, "ADDRESS_SECRET_HEX").ok_or("no address secret")?)?;
    let msg_seed = hex32(Ctx::line(&out, "MESSAGING_SEED_HEX").ok_or("no messaging seed")?)?;
    let onion = glaux_tor_arti::onion_address(&addr_seed);

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
        "foreign_api": { "address": address, "onion": format!("{onion}.onion") }, "pending_count": 0,
        "tor": if no_tor { "off" } else { "starting" }, "messenger": "starting", "policy": load_book(&user_dir).auto_accept,
    })));
    write_status(&ctx, &status.lock().unwrap());

    #[cfg(windows)]
    let _managed_i2p = if bundled_selected {
        let exe = std::env::current_exe().map_err(|_| "cannot locate bundled I2P")?;
        let bundle = exe.parent().ok_or("cannot locate bundled I2P")?.join("i2p");
        Some(managed_i2p::windows::start(&bundle, &work.join("i2p-router"), Duration::from_secs(180))?)
    } else { None };
    #[cfg(not(windows))]
    if bundled_selected { return Err("bundled I2P is unavailable on this platform".into()); }
    #[cfg(windows)]
    let bundled_endpoints = _managed_i2p.as_ref().map(|g| (g.sam(), g.socks()));
    #[cfg(not(windows))]
    let bundled_endpoints = None;
    let nostr_mode = parse_nostr_snapshot(&nostr_snapshot, bundled_endpoints)?;

    // Keep Tor payments available while an explicitly chosen backup messenger
    // starts independently. Without a backup, preserve the existing synchronous
    // Tor selection behavior.
    let mut onion_service = None;
    if !no_tor {
        let mut cfg = glaux_tor_arti::TorConfig::new(work.join("arti"));
        if let Some(spec) = &bridge { cfg = cfg.with_bridge(spec.line.clone(), Some(spec.binary.clone())); }
        if nostr_mode.is_some() {
            let c = ctx.clone(); let st = status.clone(); let local_addr = local.clone();
            let key = zeroize::Zeroizing::new(addr_seed); let has_bridge = bridge.is_some();
            let bootstrap_permit = ctx.channel_drain.enter().ok_or("channel is switching")?;
            std::thread::spawn(move || {
                let service = bootstrap_wallet_tor(&c, &st, &key, &local_addr, &cfg, has_bridge);
                drop(bootstrap_permit);
                // The onion service must live for as long as the daemon does.
                if let Some(_service) = service { loop { std::thread::park(); } }
            });
        } else {
            onion_service = bootstrap_wallet_tor(&ctx, &status, &addr_seed, &local, &cfg, bridge.is_some());
        }
    }

    // GrinMessenger: direct over Tor when it works, else the relay.
    let tor_ok = ctx.tor.lock().unwrap().is_some();
    let mode = nostr_mode.or_else(|| select_messenger_mode(relay.as_deref(), tor_ok, bridge.is_some(), flag(args, "--relay-plain")));
    // GlauxNet = where messages wait for us: "local" is our own mailbox
    // (loopback gateway published as our onion), "remote" a configured relay.
    status.lock().unwrap()["glauxnet"] = json!(match &mode {
        Some(NetworkMode::Direct) => "local".to_string(),
        Some(NetworkMode::Relay { url, .. }) => format!("remote {url}"),
        Some(NetworkMode::NostrI2p { .. }) => "nostr_i2p".to_string(),
        Some(NetworkMode::NostrDirect { .. }) => "nostr_direct".to_string(),
        Some(NetworkMode::I2p { .. }) => "i2p_direct".to_string(),
        None => "off".to_string(),
    });
    if let Some(mode) = mode {
        let label = mode.label();
        let configured = configured_backup_route(&ctx.user_dir)?;
        let configured = configured.as_ref().map(|(m, t)| (m.as_str(), t.as_str()));
        // Integrator: pass Some("bundled") only with a live owned RouterGuard
        // created from the same immutable settings snapshot as `mode`.
        let logical_proxy = bundled_selected.then(|| "bundled".to_string());
        let active_route = active_backup_route(&mode, logical_proxy.as_deref(), configured)?;
        let ttl = if matches!(&mode, NetworkMode::NostrI2p { .. } | NetworkMode::NostrDirect { .. } | NetworkMode::I2p { .. }) { 13 * 60 * 60 } else { 12 * 60 * 60 };
        let cfg = ServiceConfig {
            data_dir: work.join("messenger"),
            network: if mainnet { "mainnet".into() } else { "testnet".into() },
            mode,
            logical_proxy,
            poll_secs: 2,
            fetch_limit: 100,
            ttl_secs: ttl,
            history_days: match nostr_snapshot.get("messenger_history_days") {
                None => 0,
                Some(v) => match v.as_u64() {Some(0)=>0,Some(30)=>30,_=>return Err("invalid local history retention".into())},
            },
            tor_state: Some(work.join("arti")),
            bridge_line: bridge.as_ref().map(|b| b.line.clone()),
            bridge_binary: bridge.as_ref().map(|b| b.binary.clone()),
        };
        match WalletService::open(cfg, msg_seed) {
            Ok(svc) => {
                *ctx.messenger_route.lock().unwrap() = active_route.clone();
                status.lock().unwrap()["glaux_route"] = active_route.map_or(Value::Null, Value::String);
                let svc = Arc::new(svc);
                // Private local control API: never expose this listener over the
                // onion. The owner-only token protects chat history and sends.
                match (glaux_messenger_wallet::server::bind("127.0.0.1:0"),
                    glaux_messenger_wallet::AuthToken::load_or_create(work.join("chat-api.token"))) {
                    (Ok((listener, addr)), Ok(token)) => {
                        let api = svc.clone();
                        let token = Arc::new(token);
                        let chat_gate = ctx.channel_drain.clone();
                        std::thread::spawn(move || {
                            let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                            let _ = glaux_messenger_wallet::server::serve_guarded(listener, api, token, stop, Some(chat_gate));
                        });
                        {
                            let mut s = status.lock().unwrap();
                            s["chat_port"] = json!(addr.port());
                            s["messenger_address"] = json!(svc.address());
                        }
                        write_status(&ctx, &status.lock().unwrap());
                    }
                    (Err(e), _) | (_, Err(e)) => ctx.log(&format!("chat API unavailable: {e}")),
                }
                svc.set_channel_gate(ctx.channel_drain.clone());
                svc.start_network();
                let st = svc.wait_ready(Duration::from_secs(180));
                ctx.log(&format!("messenger ({label}): {} {} address {}", st.phase, st.detail, svc.address()));
                {
                    let mut s = status.lock().unwrap();
                    s["messenger"] = json!(format!("{} ({label})", st.phase));
                    s["messenger_address"] = json!(svc.address());
                }
                *ctx.messenger.lock().unwrap() = Some(svc.clone());
                // Keep UI status current after slow bootstrap or recovery.
                let status_monitor = status.clone();
                let svc_monitor = svc.clone();
                let ctx_monitor = ctx.clone();
                std::thread::spawn(move || loop {
                    let state = svc_monitor.status();
                    let label = format!("{} ({})", state.phase, state.mode);
                    {
                        let mut current = status_monitor.lock().unwrap();
                        if current["messenger"].as_str() != Some(label.as_str()) {
                            current["messenger"] = json!(label);
                            write_status(&ctx_monitor, &current);
                        }
                    }
                    std::thread::sleep(Duration::from_secs(2));
                });
                let c = ctx.clone();
                std::thread::spawn(move || {
                    // The messenger ACKs an envelope once it is in its history,
                    // BEFORE we process it; its live event queue is empty after
                    // a restart. So the source of truth is the message HISTORY,
                    // and a durable list of message ids already handled here
                    // (written after handling: at least once; handling is
                    // idempotent: a received slate resends its saved answer, a
                    // finalized one is skipped, an invoice is kept once).
                    if let Err(error)=svc.initialize_payment_checkpoint() {c.log(&format!("payment recovery unavailable: {error}"));return;}
                    let mut since=0u64;
                    let mut cached:Option<glaux_messenger::history::PaymentScan>=None;
                    let mut completed:Option<PaymentWatch>=None;
                    let mut retry_watch:Option<PaymentWatch>=None;
                    let mut retry_after=std::time::Instant::now();
                    loop {
                        if cached.is_none() {
                            let before=match svc.payment_watch(){Ok(w)=>w,Err(error)=>{c.log(&format!("payment watch: {error}"));std::thread::sleep(Duration::from_secs(5));continue;}};
                            if retry_watch==Some(before) && std::time::Instant::now()<retry_after {std::thread::sleep(Duration::from_secs(5));continue;}
                            let mut scan=match svc.begin_payment_scan(){Ok(scan)=>scan,Err(error)=>{c.log(&format!("payment scan: {error}"));std::thread::sleep(Duration::from_secs(5));continue;}};
                            let mut good=true;
                            loop {
                                let (page,done)=match svc.next_payment_scan(&mut scan,1000){Ok(p)=>p,Err(error)=>{c.log(&format!("payment scan: {error}"));good=false;break;}};
                                for (message,review) in page {
                                    if review {continue;}
                                    let Some(armor)=message.armor.as_deref() else {good=false;continue;};
                                    if let Err(error)=handle_envelope(&c,&svc,&message.peer,armor) {c.log(&format!("payment processing failed: {error}"));good=false;continue;}
                                    if let Err(error)=svc.mark_payment_processed_after_durable_handler(&mut scan,&message.peer,&message.id) {c.log(&format!("payment checkpoint write failed: {error}"));good=false;break;}
                                }
                                if done || !good {break;}
                            }
                            if !good {retry_watch=svc.payment_watch().ok();retry_after=std::time::Instant::now()+Duration::from_secs(30);continue;}
                            // Capture an event cursor after the snapshot. A concurrent
                            // arrival changes generation and forces a fresh full scan.
                            let cursor=svc.events(0,Duration::ZERO).next;
                            match svc.payment_watch() {
                                Ok(after) if after.0==before.0=>{cached=Some(scan);completed=Some(after);since=cursor;retry_watch=None;},
                                _=>{cached=None;completed=None;}
                            }
                            continue;
                        }
                        let page=svc.events(since,Duration::from_secs(5));
                        let after=match svc.payment_watch(){Ok(w)=>w,Err(error)=>{c.log(&format!("payment watch: {error}"));cached=None;continue;}};
                        let Some(before)=completed else {cached=None;continue;};
                        let Some(messages)=incremental_payment_events(&page,since,&before,&after) else {cached=None;completed=None;continue;};
                        let mut good=true;
                        let scan=cached.as_mut().expect("scan present");
                        for event in messages {
                            let candidate=match svc.payment_event_candidate(scan,&event.peer,&event.id) {Ok(Some(m))=>m,Ok(None)=>{good=false;break;},Err(error)=>{c.log(&format!("payment event: {error}"));good=false;break;}};
                            let Some(armor)=candidate.armor.as_deref() else {good=false;break;};
                            if let Err(error)=handle_envelope(&c,&svc,&candidate.peer,armor) {c.log(&format!("payment processing failed: {error}"));good=false;break;}
                            if let Err(error)=svc.mark_payment_processed_after_durable_handler(scan,&candidate.peer,&candidate.id) {c.log(&format!("payment checkpoint write failed: {error}"));good=false;break;}
                        }
                        if !good {cached=None;completed=None;retry_watch=svc.payment_watch().ok();retry_after=std::time::Instant::now()+Duration::from_secs(30);continue;}
                        since=page.next;
                        match svc.payment_watch() {Ok(final_watch) if final_watch.0==after.0=>completed=Some(final_watch),_=>{cached=None;completed=None;}}
                    }
                });
            }
            Err(e) => {
                ctx.log(&format!("messenger: {e}"));
                if e.starts_with("Cannot load message history") || e.starts_with("read_state") {
                    let mut s = status.lock().unwrap();
                    s["last_error"] = json!("message_history_unavailable");
                    write_status(&ctx, &s);
                }
            },
        }
    } else {
        ctx.log("messenger: off (no Tor and no --relay)");
        status.lock().unwrap()["messenger"] = json!("off");
    }
    write_status(&ctx, &status.lock().unwrap());
    ctx.log("ready: waiting for payments and for outgoing requests");
    let _keep = onion_service;
    resume_undispatched(&ctx);
    process_backup_retries(&ctx, true);
    loop {
        process_outbox(&ctx);
        process_backup_retries(&ctx, false);
        process_decisions(&ctx);
        {
            let mut s = status.lock().unwrap();
            s["pending_count"] = json!(ctx.pending_count());
            s["policy"] = json!(load_book(&user_dir).auto_accept);
            write_status(&ctx, &s);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

fn book_cmd(args: &[String]) -> Result<(), String> {
    let user_dir = PathBuf::from(arg(args, "--user-dir").ok_or("--user-dir")?);
    let _guard = lock_book(&user_dir)?;
    let mut b = load_book_checked(&user_dir)?;
    let sub = args.iter().skip(2).map(|s| s.as_str()).find(|a| ["add", "remove", "auto-accept", "list"].contains(a)).unwrap_or("list");
    match sub {
        "add" => {
            let id = arg(args, "--id").ok_or("--id grin1...")?;
            glaux_tor_arti::onion_from_address(&id).map_err(|e| format!("--id {id}: {e}"))?;
            if args.iter().any(|a| a == "--insert-only") && b.contacts.iter().any(|c| c.id == id || c.messenger.as_deref() == Some(id.as_str())) {
                return Err("contact already exists".into());
            }
            let messenger = arg(args, "--messenger");
            if let Some(m) = &messenger {
                glaux_tor_arti::onion_from_address(m).map_err(|e| format!("--messenger {m}: {e}"))?;
            }
            if args.iter().any(|a| a == "--bind-if-compatible") {
                let peer = messenger.as_deref().ok_or("--messenger required for binding")?;
                let name = arg(args, "--name").unwrap_or_default();
                bind_compatible(&mut b, &id, peer, &name)?;
                save_book(&user_dir, &b)?;
                println!("CONTACT_SAVED={id}");
                return Ok(());
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
            let p = args.get(i + 1).ok_or("off|ask|ask_all|contacts|all")?;
            if !["off", "ask", "ask_all", "contacts", "all"].contains(&p.as_str()) {
                return Err("auto-accept: off | ask | ask_all | contacts | all".into());
            }
            b.auto_accept = p.clone();
            save_book(&user_dir, &b)?;
            println!("AUTO_ACCEPT={p}");
        }
        _ => {
            println!("AUTO_ACCEPT={}", b.auto_accept);
            for c in &b.contacts {
                let onion = glaux_tor_arti::onion_from_address(&c.id).unwrap_or_default();
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
    let mut req = SendRequest {
        kind: arg(args, "--kind").unwrap_or_else(|| "send".into()),
        slate_id: arg(args, "--slate-id").ok_or("--slate-id")?,
        to: arg(args, "--to").ok_or("--to")?,
        slate_json: arg(args, "--slate-json"),
        armor: arg(args, "--armor").ok_or("--armor")?,
        context: arg(args, "--context").ok_or("--context")?,
        tx_folder: arg(args, "--tx-folder").ok_or("--tx-folder")?,
        messenger: arg(args, "--messenger"),
        messenger_only: args.iter().any(|a| a == "--messenger-only"),
        expected_mode: arg(args, "--expected-mode"),
        expected_route: arg(args, "--expected-route"),
        armor_sha256: None,
    };
    match req.expected_mode.as_deref() {
        Some("tor") if req.expected_route.is_none() => {},
        Some(expected) if is_backup_mode(expected) && req.messenger_only && req.messenger.as_deref().map_or(false, |m| !m.trim().is_empty())
            && req.expected_route.as_deref().map_or(false, valid_route_tag) => {},
        None if req.expected_route.is_none() => {},
        _ => return Err("invalid explicitly selected messaging route".into()),
    }
    if !valid_slate_id(&req.slate_id) {
        return Err(format!("bad slate id {} (expected a UUID)", req.slate_id));
    }
    let work = user_dir.join(format!("tor-wallet-{wallet}"));
    if req.expected_mode.as_deref().map_or(false, is_backup_mode) {
        req.armor_sha256 = Some(backup_armor_digest(&req.armor)?);
    }
    if flag(args, "--retry") {
        queue_backup_retry(&work, &req)?;
        println!("RETRY=QUEUED (same saved slatepack and messaging route; delivery is not confirmed)");
        return Ok(());
    }
    if req.expected_mode.as_deref().map_or(false, is_backup_mode) {
        let _guard = slate_lock(&work.join("sends"), &req.slate_id)?;
        check_payment_not_cancelled(&req, true)?;
        verify_backup_intent(&req)?;
        enqueue_backup_initial_locked(&work, &req)?;
        println!("QUEUED={} (delivery is not confirmed)", req.slate_id);
        return Ok(());
    }
    let dir = work.join("outbox");
    fs::create_dir_all(&dir).map_err(|e| format!("{e}"))?;
    let tmp = dir.join(format!("{}.tmp", req.slate_id));
    fs::write(&tmp, serde_json::to_string_pretty(&req).unwrap()).map_err(|e| format!("{e}"))?;
    fs::rename(&tmp, dir.join(format!("{}.json", req.slate_id))).map_err(|e| format!("{e}"))?;
    println!("QUEUED={} (the Tor daemon of wallet {wallet} delivers it)", req.slate_id);
    Ok(())
}

fn slatepack_digest(armor: &str) -> Result<String, String> {
    let armor = armor.trim();
    if armor.is_empty() || armor.len() > 128 * 1024 { return Err("invalid saved slatepack".into()); }
    let mut hash = Sha256::new(); hash.update(armor.as_bytes());
    Ok(data_encoding::HEXLOWER.encode(&hash.finalize()))
}
fn backup_armor_digest(path: &str) -> Result<String, String> {
    let armor = fs::read_to_string(path).map_err(|e| format!("cannot read saved slatepack: {e}"))?;
    slatepack_digest(&armor)
}
/// Verify the saved route intent and original S1 before retry, or before a
/// first queue after a crash. The service writes it before exposing the result.
fn verify_backup_intent(req: &SendRequest) -> Result<(), String> {
    let intent: Value = serde_json::from_slice(&fs::read(PathBuf::from(&req.tx_folder).join("backup-route.json")).map_err(|_| "saved backup route not found")?).map_err(|_| "invalid saved backup route")?;
    if intent.get("peer").and_then(Value::as_str) != req.messenger.as_deref()
        || intent.get("mode").and_then(Value::as_str) != req.expected_mode.as_deref()
        || intent.get("route").and_then(Value::as_str) != req.expected_route.as_deref()
        || intent.get("armor_sha256").and_then(Value::as_str) != req.armor_sha256.as_deref() {
        return Err("saved backup route or slatepack digest does not match".into());
    }
    let digest = req.armor_sha256.as_deref().filter(|d| valid_route_tag(d)).ok_or("original slatepack digest is missing")?;
    if backup_armor_digest(&req.armor)? != digest { return Err("saved slatepack changed; retry refused".into()); }
    Ok(())
}
fn validate_retry_state(req: &SendRequest) -> Result<(), String> {
    if !matches!(req.kind.as_str(), "send" | "invoice" | "reply") || !req.expected_mode.as_deref().map_or(false, is_backup_mode) || !req.messenger_only {
        return Err("retry is available only for an existing backup-channel payment".into());
    }
    check_payment_not_cancelled(req, true)?;
    let folder = PathBuf::from(&req.tx_folder);
    if folder.join(FINALIZED_MARK).exists() || folder.join("spend-tx.hex").exists() { return Err("payment is already finalized".into()); }
    let meta: Value = serde_json::from_slice(&fs::read(folder.join("meta.json")).map_err(|_| "cannot read payment metadata")?).map_err(|_| "invalid payment metadata")?;
    let kind = meta.get("kind").and_then(Value::as_str).unwrap_or("");
    let stage = meta.get("stage").and_then(Value::as_str);
    let retryable = match (req.kind.as_str(), kind, stage) {
        ("send", "send", Some("waiting_answer")) => true,
        ("invoice", "invoice", None | Some("waiting_payer")) => true,
        ("reply", "pay_invoice", Some("waiting_issuer")) => true,
        ("reply", "receive", None | Some("waiting_sender")) => true,
        _ => false,
    };
    if !retryable { return Err("payment stage is not eligible for retry".into()); }
    verify_backup_intent(req)
}
fn same_saved_request(path: &Path, req: &SendRequest) -> Result<bool, String> {
    match fs::read(path) {
        Ok(data) => {
            let old: SendRequest = serde_json::from_slice(&data).map_err(|_| "invalid saved payment request")?;
            if old != *req { return Err("retry does not match the original payment and route".into()); }
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(format!("cannot read original payment request: {e}")),
    }
}
fn write_queue_entry(path: &Path, req: &SendRequest) -> Result<(), String> {
    let data = serde_json::to_vec_pretty(req).map_err(|e| format!("queue request: {e}"))?;
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|e| format!("queue create: {e}"))?;
    f.write_all(&data).and_then(|_| f.sync_all()).map_err(|e| format!("queue write: {e}"))
}
/// The caller holds the payment lock, so daemon acceptance cannot read a
/// partially written entry and cannot race a retry against cancellation.
fn saved_queue_dir(work: &Path, req: &SendRequest) -> PathBuf {
    work.join(if req.kind == "reply" { "replies" } else { "sends" })
}
fn retry_marker_name(req: &SendRequest, suffix: &str) -> String {
    if req.kind == "send" { format!("{}.{suffix}", req.slate_id) }
    else { format!("{}.{}.{suffix}", req.slate_id, req.kind) }
}
fn enqueue_backup_initial_locked(work: &Path, req: &SendRequest) -> Result<(), String> {
    let saved = saved_queue_dir(work, req); let dir = work.join("outbox");
    fs::create_dir_all(&dir).map_err(|e| format!("outbox directory: {e}"))?;
    if same_saved_request(&saved.join(format!("{}.json", req.slate_id)), req)? { return Err("payment was already queued; use retry".into()); }
    let target = dir.join(format!("{}.json", req.slate_id));
    if same_saved_request(&target, req)? { return Ok(()); }
    write_queue_entry(&target, req)
}
fn queue_backup_retry(work: &Path, req: &SendRequest) -> Result<(), String> {
    let _guard = slate_lock(&work.join("sends"), &req.slate_id)?;
    validate_retry_state(req)?;
    let dir = work.join("outbox"); fs::create_dir_all(&dir).map_err(|e| format!("retry queue directory: {e}"))?;
    let original = saved_queue_dir(work, req).join(format!("{}.json", req.slate_id));
    if !same_saved_request(&original, req)? {
        // The daemon never accepted the first request (or crashed before it
        // was written): queue the exact S1 from the durable intent instead.
        return enqueue_backup_initial_locked(work, req);
    }
    for suffix in ["retry", "retry-running"] {
        if same_saved_request(&dir.join(retry_marker_name(req, suffix)), req)? { return Ok(()); }
    }
    let target = dir.join(retry_marker_name(req, "retry"));
    let tmp = dir.join(format!(".retry-{}.tmp", stamp()));
    write_queue_entry(&tmp, req)?;
    fs::rename(&tmp, target).map_err(|e| format!("retry queue: {e}"))?;
    Ok(())
}
fn process_backup_retries(ctx: &Arc<Ctx>, recover_running: bool) {
    let Some(parent_permit) = ctx.channel_drain.enter() else { return };
    let dir = ctx.work.join("outbox");
    let Ok(entries) = fs::read_dir(&dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path(); let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        if ext != "retry" && !(recover_running && ext == "retry-running") { continue; }
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let sid = stem.split('.').next().unwrap_or("");
        if !valid_slate_id(sid) { continue; }
        let (req, running) = {
            let _guard = match slate_lock(&ctx.sends_dir(), sid) { Ok(g) => g, Err(e) => { ctx.log(&format!("retry lock failed: {e}")); continue; } };
            let req: SendRequest = match fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
                Some(req) => req, None => { ctx.log("invalid backup retry retained for inspection"); continue; }
            };
            if req.slate_id != sid || path.file_name().and_then(|s| s.to_str()) != Some(retry_marker_name(&req, ext).as_str()) {
                ctx.log("invalid backup retry identity; retained"); continue;
            }
            let original = saved_queue_dir(&ctx.work, &req).join(format!("{}.json", req.slate_id));
            let valid = validate_retry_state(&req).and_then(|_| if same_saved_request(&original, &req)? { Ok(()) } else { Err("original payment not found".into()) });
            if let Err(error) = valid {
                ctx.log(&format!("backup retry not dispatched: {error}"));
                continue;
            }
            let running = dir.join(retry_marker_name(&req, "retry-running"));
            if ext == "retry" {
                if running.exists() { continue; }
                if let Err(error) = fs::rename(&path, &running) { ctx.log(&format!("cannot claim backup retry: {error}")); continue; }
            }
            (req, running)
        };
        // Marker survives a crash. Re-dispatch uses the exact same immutable
        // envelope; only the completion guard removes this marker.
        dispatch_inner(ctx, req, Some(running), &parent_permit);
    }
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
            .and_then(|a| glaux_tor_arti::onion_from_address(a).map_err(|e| format!("{e}")))
            .map(|o| println!("ONION={o}.onion")),
        _ => Err("usage: grinsight-tor serve|book|queue|onion ...".into()),
    };
    if let Err(e) = r {
        eprintln!("GRINSIGHT_TOR=FAIL {e}");
        println!("GRINSIGHT_TOR=FAIL {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("grinsight-tor-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    /// A daemon context without a wallet executable: the tests supply
    /// `receive_fn`/`finish_fn` where the real daemon would call the wallet.
    fn test_ctx(tag: &str) -> Ctx {
        let dir = temp_dir(tag);
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
            messenger_route: Mutex::new(None),
        channel_drain: channel_drain::ChannelDrain::default(),
            log: Mutex::new(()),
            inbox_rate: Mutex::new((0, 0)),
            hold: Duration::from_secs(1),
            strangers: Mutex::new(Vec::new()),
            receive_fn: None,
            finish_fn: None,
        }
    }

    #[test]
    fn duplicate_answer_is_not_reported_as_new_broadcast() {
        let ctx = test_ctx("duplicate-outcome");
        let folder = ctx.user_dir.join("payment");
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join(FINALIZED_MARK), "already finalized").unwrap();
        let req: SendRequest = serde_json::from_str(&req_json("send", "5436430c-2b02-624c-2032-570501212b00")).unwrap();
        let req = SendRequest { tx_folder: folder.display().to_string(), ..req };
        assert_eq!(ctx.finish(&req, "duplicate"), Ok(FinishOutcome::AlreadyFinalized));
    }

    fn book(policy: &str) -> Book {
        Book {
            version: BOOK_VERSION,
            auto_accept: policy.into(),
            contacts: vec![
                Contact { id: "grin1alice".into(), name: "Alice".into(), messenger: Some("grin1alicemsg".into()), auto: true },
                Contact { id: "grin1bob".into(), name: "Bob".into(), messenger: None, auto: false },
            ],
        }
    }

    fn write_book(ctx: &Ctx, policy: &str) {
        fs::create_dir_all(&ctx.user_dir).unwrap();
        fs::write(book_path(&ctx.user_dir), serde_json::to_string(&book(policy)).unwrap()).unwrap();
    }

    fn accepted(d: &Decision) -> bool {
        matches!(d, Decision::Accept(_))
    }
    fn asks(d: &Decision) -> bool {
        matches!(d, Decision::Ask)
    }
    fn inboxed(d: &Decision) -> bool {
        matches!(d, Decision::Inbox(_))
    }

    /// The whole table from the task: mode x (contact auto, contact auto=no,
    /// stranger, stranger without any address).
    #[test]
    fn policy_table() {
        let alice_env = Sender { claimed: Some("grin1x".into()), messenger: Some("grin1alicemsg".into()) };
        let alice_tor = Sender { claimed: Some("grin1alice".into()), messenger: None };
        let bob_env = Sender { claimed: None, messenger: Some("grin1bob".into()) };
        let bob = Sender { claimed: Some("grin1bob".into()), messenger: None };
        let stranger = Sender { claimed: Some("grin1eve".into()), messenger: None };
        let no_addr = Sender { claimed: None, messenger: None };

        // off: everything to the inbox, a contact's payment too.
        for s in [&alice_env, &alice_tor, &bob, &stranger, &no_addr] {
            assert!(inboxed(&decide(&book("off"), s)), "off {s:?}");
        }
        // ask_all must ask for every sender, including saved contacts.
        for s in [&alice_env, &alice_tor, &bob_env, &bob, &stranger, &no_addr] {
            assert!(asks(&decide(&book("ask_all"), s)), "ask_all {s:?}");
        }
        // ask: only the authenticated contact with auto is accepted; a Tor
        // sender is asked even when it claims the address of a known contact.
        assert!(accepted(&decide(&book("ask"), &alice_env)));
        assert!(inboxed(&decide(&book("ask"), &bob_env)), "authenticated contact with auto disabled stays in inbox");
        assert!(asks(&decide(&book("ask"), &alice_tor)), "a claimed contact address is not authenticated");
        assert!(asks(&decide(&book("ask"), &bob)), "a claimed address cannot identify even a disabled contact");
        assert!(asks(&decide(&book("ask"), &stranger)));
        assert!(asks(&decide(&book("ask"), &no_addr)), "no address: still a stranger");
        // contacts: the same automatic contact acceptance, strangers to the inbox.
        assert!(accepted(&decide(&book("contacts"), &alice_env)));
        assert!(inboxed(&decide(&book("contacts"), &alice_tor)));
        assert!(inboxed(&decide(&book("contacts"), &stranger)));
        assert!(inboxed(&decide(&book("contacts"), &no_addr)));
        assert!(inboxed(&decide(&book("contacts"), &bob)));
        // all: anyone, including a sender with no address at all.
        for s in [&alice_env, &alice_tor, &bob, &stranger, &no_addr] {
            assert!(accepted(&decide(&book("all"), s)), "all {s:?}");
        }
        let who = match decide(&book("all"), &alice_tor) {
            Decision::Accept(w) => w,
            other => panic!("{other:?}"),
        };
        assert!(!who.contains("Alice"), "unverified Tor sender labeled as contact: {who}");
        // A signed envelope from an unknown messenger key stays a stranger even
        // if it claims a contact's slatepack address.
        let impostor = Sender { claimed: Some("grin1alice".into()), messenger: Some("grin1evilmsg".into()) };
        assert!(asks(&decide(&book("ask"), &impostor)));
        assert!(inboxed(&decide(&book("contacts"), &impostor)));
        let who = match decide(&book("all"), &impostor) {
            Decision::Accept(w) => w,
            other => panic!("{other:?}"),
        };
        assert!(!who.contains("Alice"), "{who}");
    }

    #[test]
    fn corrupted_book_is_not_replaced_and_policy_fails_closed() {
        let dir = temp_dir("corrupt-book-preserved");
        fs::create_dir_all(&dir).unwrap();
        let bad = b"{ corrupt";
        fs::write(book_path(&dir), bad).unwrap();
        assert_eq!(load_book(&dir).auto_accept, "off");
        assert!(book_add(&dir, "grin1new", "New", None, false).is_err());
        assert_eq!(fs::read(book_path(&dir)).unwrap(), bad);
    }

    #[test]
    fn concurrent_book_inserts_do_not_lose_or_replace_entries() {
        let dir = temp_dir("book-concurrent-insert");
        fs::create_dir_all(&dir).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
        let mut threads = Vec::new();
        for i in 0..12 {
            let dir = dir.clone(); let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                book_add(&dir, &format!("grin1{i}"), "Test", None, false)
            }));
        }
        for t in threads { t.join().unwrap().unwrap(); }
        let b = load_book_checked(&dir).unwrap();
        assert_eq!(b.contacts.len(), 12);
        assert!(b.contacts.iter().all(|c| !c.auto));
        assert!(book_add(&dir, "grin10", "Replacement", None, false).is_err());
    }

    #[test]
    fn cli_insert_only_is_atomic_and_disables_auto_accept() {
        let dir = temp_dir("book-cli-insert-only");
        fs::create_dir_all(&dir).unwrap();
        let id = glaux_tor_arti::address_from_key("tgrin", &[7; 32]).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for name in ["Alice", "Other"] {
            let dir = dir.clone(); let id = id.clone(); let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let args = vec!["grinsight-tor".into(), "book".into(), "add".into(), "--user-dir".into(), dir.to_string_lossy().into_owned(), "--id".into(), id, "--name".into(), name.into(), "--auto".into(), "no".into(), "--insert-only".into()];
                barrier.wait();
                book_cmd(&args)
            }));
        }
        let successes = threads.into_iter().map(|t| t.join().unwrap()).filter(Result::is_ok).count();
        assert_eq!(successes, 1);
        let book = load_book_checked(&dir).unwrap();
        assert_eq!(book.contacts.len(), 1);
        assert!(!book.contacts[0].auto);
    }

    #[test]
    fn catalogue_bind_race_preserves_name_and_trust_and_rejects_conflicts() {
        let dir = temp_dir("book-bind-race");
        fs::create_dir_all(&dir).unwrap();
        let id = glaux_tor_arti::address_from_key("tgrin", &[7; 32]).unwrap();
        let peer_a = glaux_tor_arti::address_from_key("tgrin", &[8; 32]).unwrap();
        let peer_b = glaux_tor_arti::address_from_key("tgrin", &[9; 32]).unwrap();
        book_add(&dir, &id, "Local name", None, true).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let mut threads = Vec::new();
        for peer in [peer_a.clone(), peer_b.clone()] {
            let dir = dir.clone(); let id = id.clone(); let barrier = barrier.clone();
            threads.push(std::thread::spawn(move || {
                let args = vec!["grinsight-tor".into(), "book".into(), "add".into(), "--user-dir".into(), dir.to_string_lossy().into_owned(), "--id".into(), id, "--name".into(), "Remote name".into(), "--messenger".into(), peer, "--bind-if-compatible".into()];
                barrier.wait();
                book_cmd(&args)
            }));
        }
        let successes = threads.into_iter().map(|t| t.join().unwrap()).filter(Result::is_ok).count();
        assert_eq!(successes, 1);
        let book = load_book_checked(&dir).unwrap();
        assert_eq!(book.contacts.len(), 1);
        assert_eq!(book.contacts[0].name, "Local name");
        assert!(book.contacts[0].auto);
        assert!(matches!(book.contacts[0].messenger.as_deref(), Some(x) if x == peer_a.as_str() || x == peer_b.as_str()));
    }

    #[test]
    fn accepted_messenger_cannot_overwrite_or_alias_existing_contact() {
        let dir = temp_dir("contact-collision");
        fs::create_dir_all(&dir).unwrap();
        save_book(&dir, &book("ask")).unwrap();
        let before = fs::read_to_string(book_path(&dir)).unwrap();
        // Attacker signs with their own key while claiming Alice's slate address.
        assert!(book_add(&dir, "grin1alice", "Attacker", Some("grin1evilmsg"), true).is_err());
        assert!(book_add(&dir, "grin1new", "Attacker", Some("grin1alicemsg"), true).is_err());
        assert!(book_add(&dir, "grin1alicemsg", "Attacker", Some("grin1evilmsg"), true).is_err());
        assert!(book_add(&dir, "grin1new", "Attacker", Some("grin1alice"), true).is_err());
        assert_eq!(before, fs::read_to_string(book_path(&dir)).unwrap());
        assert!(book_add(&dir, "grin1new", "New", Some("grin1newmsg"), true).is_ok());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn manually_saved_foreign_contact_is_not_auto_trusted() {
        let dir = temp_dir("unverified-contact");
        fs::create_dir_all(&dir).unwrap();
        save_book(&dir, &book("ask_all")).unwrap();
        assert!(book_add(&dir, "grin1foreign", "New", None, false).is_ok());
        let b = load_book(&dir);
        let c = b.contacts.iter().find(|c| c.id == "grin1foreign").unwrap();
        assert!(!c.auto);
        assert!(c.messenger.is_none());
        assert!(book_add(&dir, "grin1alice", "Replacement", None, false).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nostr_mode_requires_local_proxy_or_explicit_consent_for_exact_url() {
        let dir = temp_dir("nostr-settings"); fs::create_dir_all(&dir).unwrap();
        let path = dir.join("settings.json");
        assert!(read_nostr_mode(&dir).unwrap().is_none());
        fs::write(&path, json!({"messenger_nostr_mode":"i2p","messenger_nostr_url":"ws://relay.test.i2p","messenger_nostr_proxy":"127.0.0.1:7656"}).to_string()).unwrap();
        assert!(matches!(read_nostr_mode(&dir).unwrap(), Some(NetworkMode::NostrI2p { .. })));
        fs::write(&path, json!({"messenger_nostr_mode":"i2p","messenger_nostr_url":"ws://relay.test.i2p","messenger_nostr_proxy":"192.0.2.5:7656"}).to_string()).unwrap();
        assert!(read_nostr_mode(&dir).is_err());
        fs::write(&path, json!({"messenger_nostr_mode":"direct","messenger_nostr_url":"wss://relay.test","messenger_nostr_consent_url":"wss://another.test"}).to_string()).unwrap();
        assert!(read_nostr_mode(&dir).is_err());
        fs::write(&path, json!({"messenger_nostr_mode":"direct","messenger_nostr_url":"wss://relay.test","messenger_nostr_consent_url":"wss://relay.test"}).to_string()).unwrap();
        assert!(matches!(read_nostr_mode(&dir).unwrap(), Some(NetworkMode::NostrDirect { consent: true, .. })));
        fs::write(&path, json!({"messenger_nostr_mode":"i2p_direct","messenger_nostr_proxy":"127.0.0.1:7656"}).to_string()).unwrap();
        assert!(matches!(read_nostr_mode(&dir).unwrap(), Some(NetworkMode::I2p { .. })));
        fs::write(&path, json!({"messenger_nostr_mode":"i2p_direct","messenger_nostr_proxy":"192.0.2.5:7656"}).to_string()).unwrap();
        assert!(read_nostr_mode(&dir).is_err());
        let _ = fs::remove_file(path); let _ = fs::remove_dir(dir);
    }

    #[test]
    fn bridge_selection_fails_closed_and_does_not_expose_configuration() {
        let dir = temp_dir("bridge-settings");
        fs::create_dir_all(&dir).unwrap();
        assert!(read_bridge_settings(&dir).unwrap().is_none());
        let program = dir.join("transport-test");
        fs::write(&program, "test").unwrap();
        let path = dir.join("settings.json");
        let cfg = json!({"tor_bridge_mode":"obfs4", "tor_bridge_line":"obfs4 example:443 secret", "tor_bridge_binary":program});
        fs::write(&path, cfg.to_string()).unwrap();
        let selected = read_bridge_settings(&dir).unwrap().unwrap();
        assert_eq!(selected.line, "obfs4 example:443 secret");
        let snowflake = json!({"tor_bridge_mode":"snowflake", "tor_bridge_line":"Bridge snowflake example:443 token", "tor_bridge_binary":program});
        fs::write(&path, snowflake.to_string()).unwrap();
        assert_eq!(read_bridge_settings(&dir).unwrap().unwrap().line, "snowflake example:443 token");
        assert!(matches!(select_messenger_mode(Some("http://relay"), false, true, true), None));
        let broken = json!({"tor_bridge_mode":"snowflake", "tor_bridge_line":"obfs4 bad secret", "tor_bridge_binary":program});
        fs::write(&path, broken.to_string()).unwrap();
        let err = match read_bridge_settings(&dir) { Err(e) => e, _ => panic!("invalid config accepted") };
        assert!(!err.contains("secret"));
        fs::write(&path, "{").unwrap();
        assert!(read_bridge_settings(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn book_v1_migration_and_default() {
        let dir = temp_dir("book-migrate");
        fs::create_dir_all(&dir).unwrap();
        let p = book_path(&dir);
        for old in ["ask", "contacts", "all", "off"] {
            fs::write(&p, format!(r#"{{"version":2,"auto_accept":"{old}","contacts":[]}}"#)).unwrap();
            let b = load_book(&dir);
            assert_eq!(b.version, BOOK_VERSION);
            assert_eq!(b.auto_accept, if old == "off" { "off" } else { "ask_all" });
        }
        assert_eq!(default_policy(), "ask_all");
        let _ = fs::remove_dir_all(&dir);
    }



    const GW: &str = include_str!("../tests/fixtures/grin_wallet_5_5_1_foreign.json");
    fn gw() -> Value { serde_json::from_str(GW).unwrap() }

    /// The request and the expected answer are the doctest of
    /// `api/src/foreign_rpc.rs` of grin-wallet 5.5.1: our handler answers it
    /// with exactly the VersionedSlate JSON grin-wallet expects.
    #[test]
    fn grin_wallet_5_5_1_check_version() {
        let f = gw();
        let ctx = test_ctx("gw-version");
        let ans: Value = serde_json::from_str(&handle_foreign(&ctx, f["blocks"]["check_version_request"].to_string().as_bytes())).unwrap();
        assert_eq!(ans, f["blocks"]["check_version_response"]);
    }

    #[test]
    fn grin_wallet_5_5_1_receive_tx() {
        let f = gw();
        let mut ctx = test_ctx("gw-receive");
        write_book(&ctx, "all");
        let s2 = f["blocks"]["receive_tx_response"]["result"]["Ok"].to_string();
        ctx.receive_fn = Some(Arc::new(move |_input, _who| Ok(s2.clone())));
        let ans: Value = serde_json::from_str(&handle_foreign(&ctx, f["blocks"]["receive_tx_request"].to_string().as_bytes())).unwrap();
        assert_eq!(ans, f["blocks"]["receive_tx_response"], "our answer is exactly grin-wallet's expected response");
        // The claimed address is really the sender of the doctest payment proof.
        let claimed = claimed_address(&ctx, &f["blocks"]["receive_tx_request"]["params"][0]).expect("doctest saddr is a valid key");
        assert!(claimed.starts_with("tgrin1"), "{claimed}");
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn grin_wallet_5_5_1_finalize_tx() {
        let f = gw();
        let mut ctx = test_ctx("gw-finalize");
        write_book(&ctx, "all");
        let i2 = f["blocks"]["finalize_tx_request"]["params"][0].clone();
        let sid = i2["id"].as_str().unwrap().to_string();
        let folder = ctx.sends_dir().join(&sid);
        fs::create_dir_all(&folder).unwrap();
        let req = SendRequest {
            kind: "invoice".into(),
            slate_id: sid.clone(),
            to: "grin1x".into(),
            slate_json: None,
            armor: "a".into(),
            context: "c".into(),
            tx_folder: folder.display().to_string(),
            messenger: None,
            messenger_only: false,
            expected_mode: None,
            expected_route: None,
            armor_sha256: None,
        };
        fs::write(ctx.sends_dir().join(format!("{sid}.json")), serde_json::to_string(&req).unwrap()).unwrap();
        // The real wallet writes the finalized I3 slate next to the tx; the
        // stand-in writes the doctest's I3.
        let i3 = f["blocks"]["finalize_tx_response"]["result"]["Ok"].to_string();
        let folder2 = folder.clone();
        ctx.finish_fn = Some(Arc::new(move |_r, _a| fs::write(folder2.join("invoice-i3.json"), &i3).map_err(|e| e.to_string())));
        let ans: Value = serde_json::from_str(&handle_foreign(&ctx, f["blocks"]["finalize_tx_request"].to_string().as_bytes())).unwrap();
        assert_eq!(ans, f["blocks"]["finalize_tx_response"], "finalize_tx answers with the finalized I3 slate");
        fs::remove_file(folder.join("invoice-i3.json")).unwrap();
        ctx.finish_fn = Some(Arc::new(|_, _| Ok(())));
        let missing: Value = serde_json::from_str(&handle_foreign(&ctx, f["blocks"]["finalize_tx_request"].to_string().as_bytes())).unwrap();
        assert!(missing["error"]["message"].as_str().unwrap().contains("I3"));
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn invoice_is_never_received_automatically() {
        let f = gw();
        let ctx = test_ctx("invoice-not-auto");
        write_book(&ctx, "all");
        let mut req = f["blocks"]["receive_tx_request"].clone();
        req["params"][0]["sta"] = json!("I1");
        let ans: Value = serde_json::from_str(&handle_foreign(&ctx, req.to_string().as_bytes())).unwrap();
        assert!(ans["error"]["message"].as_str().unwrap().contains("S1"), "{ans}");
        assert_eq!(ctx.pending_count(), 0, "an invoice is never held for acceptance");
        let inbox = fs::read_dir(ctx.work.join("inbox")).map(|rd| rd.flatten().count()).unwrap_or(0);
        assert_eq!(inbox, 0, "an invoice is never received over the Tor foreign API (only paid by hand)");
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    fn request_json(f: &Value, sid: &str) -> String {
        let mut req = f["blocks"]["receive_tx_request"].clone();
        req["params"][0]["id"] = json!(sid);
        req.to_string()
    }

    #[test]
    fn ask_accept_within_the_hold_returns_s2_without_trusting_claimed_contact() {
        let f = gw();
        let mut ctx = test_ctx("ask-accept");
        write_book(&ctx, "ask");
        ctx.hold = Duration::from_secs(5);
        let s2 = f["blocks"]["receive_tx_response"]["result"]["Ok"].to_string();
        ctx.receive_fn = Some(Arc::new(move |_input, _who| Ok(s2.clone())));
        let sid = f["blocks"]["receive_tx_request"]["params"][0]["id"].as_str().unwrap().to_string();
        let claimed = claimed_address(&ctx, &f["blocks"]["receive_tx_request"]["params"][0]).unwrap();
        let dec = ctx.decisions_dir();
        let sid2 = sid.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let d = json!({"slate_id": sid2.clone(), "accept": true, "add_contact": true, "name": "Alice"});
            write_atomic(&dec.join(format!("{sid2}.json")), d.to_string().as_bytes()).unwrap();
        });
        let ans: Value = serde_json::from_str(&handle_foreign(&ctx, request_json(&f, &sid).as_bytes())).unwrap();
        t.join().unwrap();
        assert_eq!(ans, f["blocks"]["receive_tx_response"], "S2 in the same answer");
        let b = load_book(&ctx.user_dir);
        let contact = b.contacts.iter().find(|c| c.id == claimed).expect("requested contact");
        assert!(!contact.auto, "unverified contact must not be auto-trusted");
        assert!(contact.messenger.is_none(), "unverified contact must not have a trusted messenger binding");
        assert!(!ctx.pending_json(&sid).exists(), "cleaned up");
        assert_eq!(ctx.pending_count(), 0);
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn ask_declined_by_the_user() {
        let f = gw();
        let mut ctx = test_ctx("ask-decline");
        write_book(&ctx, "ask");
        ctx.hold = Duration::from_secs(5);
        let sid = "1436430c-2b02-624c-2032-570501212b00".to_string();
        let dec = ctx.decisions_dir();
        let sid2 = sid.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let d = json!({"slate_id": sid2, "accept": false});
            write_atomic(&dec.join(format!("{sid2}.json")), d.to_string().as_bytes()).unwrap();
        });
        let ans: Value = serde_json::from_str(&handle_foreign(&ctx, request_json(&f, &sid).as_bytes())).unwrap();
        t.join().unwrap();
        assert!(ans["error"]["message"].as_str().unwrap().contains("declined by the receiver"), "{ans}");
        assert!(!ctx.pending_json(&sid).exists());
        let claimed = claimed_address(&ctx, &f["blocks"]["receive_tx_request"]["params"][0]).unwrap();
        assert!(load_book(&ctx.user_dir).contacts.iter().all(|c| c.id != claimed), "a declined payment adds no contact");
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn ask_timeout_keeps_the_payment_in_the_inbox() {
        let f = gw();
        let mut ctx = test_ctx("ask-timeout");
        write_book(&ctx, "ask");
        ctx.hold = Duration::from_secs(1);
        let sid = "2436430c-2b02-624c-2032-570501212b00".to_string();
        let ans: Value = serde_json::from_str(&handle_foreign(&ctx, request_json(&f, &sid).as_bytes())).unwrap();
        assert!(ans["error"]["message"].as_str().unwrap().contains("waiting for the receiver's confirmation"), "{ans}");
        assert!(!ctx.pending_json(&sid).exists(), "nothing is waiting any more");
        let inbox = ctx.work.join("inbox");
        assert!(inbox.join(format!("{sid}.json")).exists(), "S1 kept for a manual receive");
        let meta: Value = serde_json::from_str(&fs::read_to_string(inbox.join(format!("{sid}.meta.json"))).unwrap()).unwrap();
        assert_eq!((meta["kind"].as_str(), meta["channel"].as_str()), (Some("payment"), Some("tor-foreign")));
        assert_eq!(meta["amount"], 6000000000u64);
        assert_eq!(meta["fee"], 23500000u64);
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn ask_limits_stop_spam() {
        let f = gw();
        // 3 requests already wait: a new one goes to the inbox at once.
        let ctx = test_ctx("ask-limit-held");
        write_book(&ctx, "ask");
        fs::create_dir_all(ctx.pending_dir()).unwrap();
        for i in 0..PENDING_MAX_HELD {
            let sid = format!("3436430c-2b02-624c-2032-570501212b{:02}", i);
            let p = Pending {
                slate_id: sid.clone(), amount: 1, fee: 0, from: None, channel: "tor-foreign".into(),
                received_at: now(), expires_at: now() + 40, sender_verified: false, peer: None, transport_mode: None, transport_route: None,
            };
            write_atomic(&ctx.pending_json(&sid), serde_json::to_string(&p).unwrap().as_bytes()).unwrap();
        }
        let sid = "4436430c-2b02-624c-2032-570501212b00";
        let ans: Value = serde_json::from_str(&handle_foreign(&ctx, request_json(&f, sid).as_bytes())).unwrap();
        assert!(ans["error"]["message"].as_str().unwrap().contains("too many requests"), "{ans}");
        assert!(ctx.work.join("inbox").join(format!("{sid}.json")).exists());
        assert_eq!(ctx.pending_count(), PENDING_MAX_HELD);

        // 10 new strangers in the hour: the next one is not asked about.
        let ctx = test_ctx("ask-limit-hour");
        write_book(&ctx, "ask");
        *ctx.strangers.lock().unwrap() = vec![now(); STRANGERS_PER_HOUR];
        let sid = "5436430c-2b02-624c-2032-570501212b00";
        let ans: Value = serde_json::from_str(&handle_foreign(&ctx, request_json(&f, sid).as_bytes())).unwrap();
        assert!(ans["error"]["message"].as_str().unwrap().contains("too many requests"), "{ans}");
        assert!(ctx.work.join("inbox").join(format!("{sid}.json")).exists());
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn messenger_ask_receives_once_and_keeps_the_answer() {
        let mut ctx = test_ctx("msg-ask");
        write_book(&ctx, "ask");
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = calls.clone();
        ctx.receive_fn = Some(Arc::new(move |_input, _who| {
            c2.fetch_add(1, Ordering::SeqCst);
            Ok("{\"sta\":\"S2\"}".into())
        }));
        let sid = "6436430c-2b02-624c-2032-570501212b00";
        let armor = "BEGINSLATEPACK. x. ENDSLATEPACK.";
        ask_messenger(&ctx, "grinmsg1peer", armor, sid, Some("tgrin1sender"), 25_000_000_000, 10_000_000, None).unwrap();
        assert_eq!(ctx.pending_count(), 1);
        let p = ctx.find_pending(sid).expect("pending");
        assert_eq!((p.channel.as_str(), p.sender_verified, p.peer.as_deref()), ("messenger", true, Some("grinmsg1peer")));
        let d = DecisionFile { slate_id: sid.into(), accept: true, add_contact: false, name: String::new() };
        accept_messenger_pending(&ctx, &p, &d);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(ctx.pending_dir().join(format!("{sid}.s2.txt")).exists(), "the answer is kept until the envelope is sent");
        assert_eq!(ctx.pending_count(), 1, "not delivered: the messenger is not running");
        accept_messenger_pending(&ctx, &p, &d);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "received only once");
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
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
        let dir = std::env::temp_dir().join(format!("grinsight-tor-new-{}", std::process::id()));
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
            expected_mode: None,
            expected_route: None,
            armor_sha256: None,
        })
        .unwrap()
    }

    /// Store happened, removal from outbox/ did not (simulated by putting the
    /// same file back), daemon restarts: the request is dispatched once.
    #[test]
    fn outbox_never_dispatches_a_stored_request_twice() {
        let dir = std::env::temp_dir().join(format!("grinsight-outbox-{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("grinsight-reply-{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("grinsight-slock-{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("grinsight-inbox-{}", std::process::id()));
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
        let dir = std::env::temp_dir().join(format!("grinsight-processed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("messenger-processed.txt");
        // first start: what is already in the history counts as handled
        let p = Processed::open(&f, || vec!["old-1".into(), "old-2".into()]).unwrap();
        assert_eq!(p.baselined, 2);
        assert!(p.contains("old-1"));
        drop(p);
        // later start: the file is the truth; history is NOT re-baselined, so a
        // message ACKed but not handled before the stop is handled now
        let mut p = Processed::open(&f, || vec!["acked-not-handled".into()]).unwrap();
        assert_eq!(p.baselined, 0);
        assert!(!p.contains("acked-not-handled"));
        p.mark("acked-not-handled").unwrap();
        assert!(p.mark("bad\nid").is_err());
        drop(p);
        let p = Processed::open(&f, Vec::new).unwrap();
        assert!(p.contains("acked-not-handled") && p.contains("old-2"));
        // empty history on first start still creates the file
        let g = dir.join("empty.txt");
        let _ = Processed::open(&g, Vec::new).unwrap();
        assert!(g.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// ACCEPTANCE (restart after ACK): the messenger ACKed and stored m2, then
    /// the daemon stopped before handling it. After the restart m2 is handled
    /// exactly once; m1 (handled before) is not handled again; a further
    /// restart handles nothing.
    #[test]
    fn restart_after_ack_handles_the_stored_message_once() {
        let dir = std::env::temp_dir().join(format!("grinsight-ack-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("messenger-processed.txt");
        let msg = |id: &str| (id.to_string(), "peer".to_string(), format!("armor-{id}"));
        // run 1: history = [m1]; handled
        let mut done = Processed::open(&f, Vec::new).unwrap();
        let mut seen = Vec::new();
        process_unhandled(vec![msg("m1")], &mut done, |_, a| { seen.push(a.to_string()); Ok(()) });
        assert_eq!(seen, vec!["armor-m1"]);
        // m2 arrives, is stored in the history and ACKed; the daemon stops
        // before the handler ran (nothing marked)
        drop(done);
        // run 2 (restart): live events are empty, the history has m1 + m2
        let mut done = Processed::open(&f, || vec!["m1".into(), "m2".into()]).unwrap();
        let mut seen = Vec::new();
        process_unhandled(vec![msg("m1"), msg("m2")], &mut done, |_, a| { seen.push(a.to_string()); Ok(()) });
        assert_eq!(seen, vec!["armor-m2"], "only the ACKed but unhandled message");
        drop(done);
        // run 3: nothing left
        let mut done = Processed::open(&f, Vec::new).unwrap();
        let mut seen = Vec::new();
        process_unhandled(vec![msg("m1"), msg("m2")], &mut done, |_, a| { seen.push(a.to_string()); Ok(()) });
        assert!(seen.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn processed_message_list_read_error_does_not_rebaseline() {
        let dir = std::env::temp_dir().join(format!("grinsight-processed-unreadable-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let called = std::cell::Cell::new(false);
        let result = Processed::open(&dir, || { called.set(true); vec!["must-not-be-marked".into()] });
        assert!(result.is_err());
        assert!(!called.get());
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn corrupt_processed_message_list_fails_closed() {
        let dir = std::env::temp_dir().join(format!("grinsight-processed-corrupt-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("processed.txt");
        fs::write(&file, "ok\nbad id\n").unwrap();
        assert!(Processed::open(&file, Vec::new).is_err());
        fs::write(&file, "partial-record").unwrap();
        assert!(Processed::open(&file, Vec::new).is_err());
        let _ = fs::remove_file(&file); let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn explicit_payment_route_rejects_fallback_and_legacy_backup_send() {
        let mut req: SendRequest = serde_json::from_str(&req_json("send", "5436430c-2b02-624c-2032-570501212b00")).unwrap();
        let a = "a".repeat(64); let b = "b".repeat(64);
        assert!(validate_payment_route(&req, Some("direct"), None, None).is_ok());
        assert!(validate_payment_route(&req, None, None, Some(("nostr_direct", &a))).is_err());
        assert!(validate_payment_route(&req, Some("nostr_direct"), Some(&a), Some(("nostr_direct", &a))).is_err());
        req.expected_mode = Some("nostr_direct".into()); req.expected_route = Some(a.clone());
        assert!(validate_payment_route(&req, Some("nostr_direct"), Some(&a), Some(("nostr_direct", &a))).is_err());
        req.messenger_only = true; req.messenger = Some("grinmsg1test".into());
        assert!(validate_payment_route(&req, Some("nostr_direct"), Some(&a), Some(("nostr_direct", &a))).is_ok());
        assert!(validate_payment_route(&req, Some("nostr_direct"), Some(&b), Some(("nostr_direct", &a))).is_err());
        assert!(validate_payment_route(&req, Some("nostr_direct"), Some(&a), Some(("nostr_direct", &b))).is_err());
        assert!(validate_payment_route(&req, Some("i2p_direct"), Some(&a), Some(("nostr_direct", &a))).is_err());
        assert!(validate_payment_route(&req, Some("nostr_direct"), Some(&a), None).is_err());
        assert!(validate_payment_route(&req, None, None, Some(("nostr_direct", &a))).is_err());
        req.expected_mode = Some("tor".into()); req.expected_route = None; req.messenger_only = false;
        assert!(validate_payment_route(&req, Some("nostr_direct"), Some(&a), Some(("nostr_direct", &a))).is_ok());
        req.messenger_only = true;
        assert!(validate_payment_route(&req, Some("nostr_direct"), Some(&a), Some(("nostr_direct", &a))).is_err());
        assert!(validate_payment_route(&req, Some("direct"), None, None).is_ok());
        assert!(validate_payment_route(&req, Some("relay"), None, None).is_err());
        req.expected_mode = Some("bad".into());
        assert!(validate_payment_route(&req, Some("direct"), None, None).is_err());
    }

    #[test]
    fn route_hash_agrees_with_service_vectors_and_normalizes_local_proxy() {
        assert_eq!(payment_route_tag("nostr_direct", "wss://relay.example", ""), "a17d971cda8df9b709f186a50812bc7831a508eaa3598e966ab9521a1563594f");
        assert_eq!(payment_route_tag("i2p_direct", "", "bundled"), "ab3b2b6387d0c99825b3bbd4e58d428bde07de872aed03c0e318ee951c29b4ab");
        let dir = temp_dir("route-tag-settings"); fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("settings.json"), json!({"messenger_nostr_mode":"i2p", "messenger_nostr_url":"ws://relay.example.i2p", "messenger_nostr_proxy":"127.0.0.1:4447"}).to_string()).unwrap();
        assert_eq!(configured_backup_route(&dir).unwrap().unwrap().1, "264d0e20ae47ca5547f468b6a392e8b8238740746a00fe71dcbbd7be10a4e7fb");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn processing_failure_is_not_marked_and_can_be_retried_after_restart() {
        let dir = std::env::temp_dir().join(format!("grinsight-process-retry-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("processed.txt");
        let msg = || ("m1".to_string(), "peer".to_string(), "armor".to_string());
        let mut done = Processed::open(&path, Vec::new).unwrap();
        let errors = process_unhandled(vec![msg()], &mut done, |_, _| Err("synthetic write failure".into()));
        assert_eq!(errors.len(), 1); assert!(!done.contains("m1")); drop(done);
        let mut done = Processed::open(&path, Vec::new).unwrap();
        assert!(process_unhandled(vec![msg()], &mut done, |_, _| Ok(())).is_empty());
        assert!(done.contains("m1")); drop(done);
        assert!(Processed::open(&path, Vec::new).unwrap().contains("m1"));
        let _ = fs::remove_file(&path); let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn recovery_real_invoice_child() {
        let Ok(root)=std::env::var("GS_REAL_RECOVERY_CHILD") else{return;};
        let mut ctx=test_ctx("v2-real-child");ctx.user_dir=Path::new(&root).join("user");ctx.work=Path::new(&root).join("work");
        ctx.exe=std::env::var_os("GS_REAL_CORE").expect("GS_REAL_CORE").into();ctx.seeds=Path::new(&std::env::var("GS_REAL_I1_DIR").unwrap()).join("seed.txt");
        let mut cfg=ServiceConfig::default();cfg.data_dir=ctx.work.join("messenger");cfg.network="tgrin".into();
        let svc=WalletService::open(cfg,zeroize::Zeroizing::new([37;32])).unwrap();let mut scan=svc.begin_payment_scan().unwrap();let (page,_)=svc.next_payment_scan(&mut scan,10).unwrap();
        assert_eq!(page.len(),1);assert!(!page[0].1);let m=&page[0].0;
        handle_envelope(&ctx,&svc,&m.peer,m.armor.as_deref().unwrap()).unwrap();
        let mut signal=fs::OpenOptions::new().create_new(true).write(true).open(Path::new(&root).join("result-synced")).unwrap();signal.write_all(b"ok").unwrap();signal.sync_all().unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    #[ignore = "requires synthetic I1 fixture and GS_REAL_CORE"]
    fn real_daemon_handler_kill_after_durable_invoice_before_journal_mark() {
        use glaux_messenger::history::{History,MessageRecord,Direction};use glaux_messenger::envelope::MessageKind;
        use std::process::{Command,Stdio};use std::time::Instant;
        let fixture=std::env::var("GS_REAL_I1_DIR").expect("fixture");let mut ctx=test_ctx("v2-real-parent");let root=ctx.user_dir.parent().unwrap().to_path_buf();
        ctx.exe=std::env::var_os("GS_REAL_CORE").expect("GS_REAL_CORE").into();ctx.seeds=Path::new(&fixture).join("seed.txt");
        let armor=fs::read_to_string(Path::new(&fixture).join("i1.txt")).unwrap();let (state,sid,_,_,_)=ctx.info(&armor).unwrap();assert_eq!(state,"I1");
        let seed=[37u8;32];let mut cfg=ServiceConfig::default();cfg.data_dir=ctx.work.join("messenger");cfg.network="tgrin".into();
        let svc=WalletService::open(cfg.clone(),zeroize::Zeroizing::new(seed)).unwrap();svc.initialize_payment_checkpoint().unwrap();
        let peer=glaux_messenger::Identity::from_seed([38;32],"tgrin").unwrap().address().clone();let r=MessageRecord{id:"00000000-0000-4000-8000-000000000078".into(),direction:Direction::Incoming,signature_verified:true,kind:MessageKind::Slatepack{armor:armor.clone(),encrypted:true},created_at:1,expires_at:None,local_expiry_opt_in:false};
        let h=History::open(cfg.data_dir.join("history"),glaux_messenger_wallet::identity::storage_key(&seed,"tgrin")).unwrap();h.record(&peer,&r).unwrap();drop(h);drop(svc);
        let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","tests::recovery_real_invoice_child","--nocapture"]).env("GS_REAL_RECOVERY_CHILD",&root).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        let deadline=Instant::now()+Duration::from_secs(10);while !root.join("result-synced").exists()&&Instant::now()<deadline{std::thread::sleep(Duration::from_millis(20));}
        if !root.join("result-synced").exists(){let _=child.kill();let _=child.wait();panic!("child did not persist result");}child.kill().unwrap();child.wait().unwrap();
        assert_eq!(fs::read_to_string(ctx.work.join("inbox").join(format!("invoice-{sid}.txt"))).unwrap(),armor);
        let svc=WalletService::open(cfg,zeroize::Zeroizing::new(seed)).unwrap();let mut scan=svc.begin_payment_scan().unwrap();let (page,_)=svc.next_payment_scan(&mut scan,10).unwrap();assert_eq!(page.len(),1);let m=&page[0].0;
        handle_envelope(&ctx,&svc,&m.peer,m.armor.as_deref().unwrap()).unwrap();svc.mark_payment_processed_after_durable_handler(&mut scan,&m.peer,&m.id).unwrap();drop(svc);
        let mut cfg=ServiceConfig::default();cfg.data_dir=ctx.work.join("messenger");cfg.network="tgrin".into();let svc=WalletService::open(cfg,zeroize::Zeroizing::new(seed)).unwrap();let mut scan=svc.begin_payment_scan().unwrap();let (page,done)=svc.next_payment_scan(&mut scan,10).unwrap();assert!(done&&page.is_empty());
        let _=fs::remove_dir_all(root);
    }

    #[test]
    fn incremental_stream_requires_contiguous_events_and_exact_generation() {
        use glaux_messenger_wallet::service::{EventKind,EventsPage,WalletEvent,MessageView};
        let view=MessageView{seq:0,id:"id".into(),peer:"peer".into(),direction:"incoming".into(),verified:true,kind:"slatepack".into(),text:None,armor:Some("s1".into()),encrypted:Some(true),created_at:1,expires_at:None};
        let mut before:PaymentWatch=(0,32,[0;32],32,[0;32]);let start=std::time::Instant::now();
        for n in 1..=1000u64 {
            let page=EventsPage{epoch:"e".into(),next:n,events:vec![WalletEvent{seq:n,event:EventKind::Message{message:view.clone()}}]};
            let mut after=before;after.0+=1;assert_eq!(incremental_payment_events(&page,n-1,&before,&after).unwrap().len(),1);before=after;
        }
        eprintln!("INCREMENTAL_EVENTS_1000_MS={}",start.elapsed().as_millis());
        let gap=EventsPage{epoch:"e".into(),next:1002,events:vec![WalletEvent{seq:1002,event:EventKind::Message{message:view.clone()}}]};let mut after=before;after.0+=1;
        assert!(incremental_payment_events(&gap,1000,&before,&after).is_none());
        let missing=EventsPage{epoch:"e".into(),next:1001,events:vec![]};assert!(incremental_payment_events(&missing,1000,&before,&after).is_none());
        let valid=EventsPage{epoch:"e".into(),next:1001,events:vec![WalletEvent{seq:1001,event:EventKind::Message{message:view}}]};
        assert!(incremental_payment_events(&valid,1000,&before,&before).is_none());
        after.2=[1;32];assert!(incremental_payment_events(&valid,1000,&before,&after).is_none());
    }

    #[test]
    fn unsupported_states_and_missing_finalized_data_are_never_terminal() {
        let ctx=test_ctx("missing-terminal");let sid="5436430c-2b02-624c-2032-570501212b00";
        assert!(validate_incoming_slate_state("unknown",sid).is_err());assert!(validate_incoming_slate_state("S1","bad").is_err());
        let folder=ctx.user_dir.join("tx");fs::create_dir_all(&folder).unwrap();let mut req:SendRequest=serde_json::from_str(&req_json("send",sid)).unwrap();req.tx_folder=folder.display().to_string();
        fs::write(folder.join(FINALIZED_MARK),"done").unwrap();assert!(sync_finalized_result(&req).is_err());
        fs::write(folder.join("spend-tx.hex"),"valid-synthetic").unwrap();assert!(sync_finalized_result(&req).is_ok());
        let _=fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn inbox_retry_is_idempotent_and_rejects_conflicting_message_or_peer() {
        let ctx = test_ctx("retry-inbox");
        let meta = json!({"kind":"invoice"});
        let name = "invoice-test.txt";
        persist_messenger_inbox(&ctx, name, "peer-a", "armor-a", &meta).unwrap();
        persist_messenger_inbox(&ctx, name, "peer-a", "armor-a", &meta).unwrap();
        assert!(persist_messenger_inbox(&ctx, name, "peer-b", "armor-a", &meta).is_err());
        assert!(persist_messenger_inbox(&ctx, name, "peer-a", "armor-b", &meta).is_err());
        assert_eq!(fs::read(ctx.work.join("inbox").join(name)).unwrap(), b"armor-a");
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn failed_inbox_metadata_can_be_retried_without_replacing_slatepack() {
        let ctx = test_ctx("retry-inbox-metadata");
        let dir = ctx.work.join("inbox"); fs::create_dir_all(&dir).unwrap();
        let blocked = dir.join("invoice-test.meta.json"); fs::create_dir(&blocked).unwrap();
        assert!(persist_messenger_inbox(&ctx, "invoice-test.txt", "peer-a", "armor-a", &json!({})).is_err());
        fs::remove_dir(&blocked).unwrap();
        persist_messenger_inbox(&ctx, "invoice-test.txt", "peer-a", "armor-a", &json!({})).unwrap();
        assert_eq!(fs::read(dir.join("invoice-test.txt")).unwrap(), b"armor-a");
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn incoming_claim_prevents_peer_route_and_content_equivocation_after_restart() {
        let ctx = test_ctx("incoming-claim");
        let sid = "5436430c-2b02-624c-2032-570501212b00";
        {
            let _guard = incoming_slate_lock(&ctx, sid).unwrap();
            ensure_inbound_claim(&ctx, sid, "peer-a", "armor-a", "nostr_direct", Some(&"a".repeat(64))).unwrap();
            ensure_inbound_claim(&ctx, sid, "peer-a", "armor-a", "nostr_direct", Some(&"a".repeat(64))).unwrap();
            assert!(ensure_inbound_claim(&ctx, sid, "peer-b", "armor-a", "nostr_direct", Some(&"a".repeat(64))).is_err());
            assert!(ensure_inbound_claim(&ctx, sid, "peer-a", "armor-b", "nostr_direct", Some(&"a".repeat(64))).is_err());
            assert!(ensure_inbound_claim(&ctx, sid, "peer-a", "armor-a", "i2p_direct", Some(&"b".repeat(64))).is_err());
            mark_inbound_outcome(&ctx, sid, "accepted").unwrap();
        }
        assert_eq!(inbound_outcome(&ctx, sid).unwrap().as_deref(), Some("accepted"));
        assert!(mark_inbound_outcome(&ctx, sid, "declined").is_err());
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn pending_answer_stays_on_original_route_and_legacy_backup_is_rejected() {
        let a = "a".repeat(64); let b = "b".repeat(64);
        assert!(pending_route_matches(Some("i2p_direct"), Some(&a), "i2p_direct", Some(&a), Some(("i2p_direct", &a))));
        assert!(!pending_route_matches(Some("i2p_direct"), Some(&a), "i2p_direct", Some(&b), Some(("i2p_direct", &b))));
        assert!(!pending_route_matches(Some("i2p_direct"), Some(&a), "nostr_direct", Some(&a), Some(("i2p_direct", &a))));
        assert!(!pending_route_matches(Some("nostr_direct"), Some(&a), "direct", None, None));
        assert!(!pending_route_matches(None, None, "nostr_direct", Some(&a), Some(("nostr_direct", &a))));
        assert!(pending_route_matches(None, None, "direct", None, None));
    }

    #[test]
    fn inbox_refuses_replay_over_a_different_channel() {
        let ctx = test_ctx("retry-inbox-route");
        let a = json!({"transport_mode":"nostr_i2p"});
        let b = json!({"transport_mode":"nostr_direct"});
        persist_messenger_inbox(&ctx, "invoice-test.txt", "peer-a", "armor-a", &a).unwrap();
        assert!(persist_messenger_inbox(&ctx, "invoice-test.txt", "peer-a", "armor-a", &b).is_err());
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn released_journal_blocks_s1_and_i2_before_metadata_updates() {
        let mut ctx = test_ctx("release-before-meta");
        let folder=ctx.user_dir.join("tx"); fs::create_dir_all(&folder).unwrap();
        let sid="5436430c-2b02-624c-2032-570501212b00";
        let mut req:SendRequest=serde_json::from_str(&req_json("send",sid)).unwrap();
        req.tx_folder=folder.display().to_string(); req.expected_mode=Some("nostr_direct".into());
        req.context=folder.join("send-context.json").display().to_string(); fs::write(&req.context,"{}").unwrap();
        fs::write(folder.join("meta.json"),json!({"slate_id":sid,"kind":"send","stage":"waiting_answer"}).to_string()).unwrap();
        let journal=ctx.pending_file();
        fs::write(&journal,format!("{}\n",json!({"kind":"payment","what":"send","slate_id":sid,"wallet":1,"tip_height":1,"commits":"a".repeat(66)}))).unwrap();
        assert!(with_backup_send_lock(&ctx,&req,||Ok(())).is_ok());
        fs::remove_file(&req.context).unwrap(); assert!(with_backup_send_lock(&ctx,&req,||Ok(())).is_err()); fs::write(&req.context,"{}").unwrap();
        fs::write(&journal,format!("{}\n{}\n",json!({"kind":"payment","what":"send","slate_id":sid,"wallet":1,"tip_height":1,"commits":"a".repeat(66)}),json!({"kind":"release","slate_id":sid}))).unwrap();
        assert!(with_backup_send_lock(&ctx,&req,||Ok(())).is_err());
        let finalized=Arc::new(std::sync::atomic::AtomicBool::new(false)); let flag=finalized.clone();
        ctx.finish_fn=Some(Arc::new(move |_,_| { flag.store(true,Ordering::SeqCst); Ok(()) }));
        assert!(ctx.finish(&req,"late S2").is_err()); assert!(!finalized.load(Ordering::SeqCst));
        req.kind="reply".into(); fs::write(folder.join("meta.json"),json!({"slate_id":sid,"kind":"pay_invoice","stage":"waiting_answer"}).to_string()).unwrap();
        fs::write(&journal,format!("{}\n",json!({"kind":"payment","what":"invoice","slate_id":sid,"wallet":1,"tip_height":1,"commits":"a".repeat(66)}))).unwrap();
        assert!(with_backup_send_lock(&ctx,&req,||Ok(())).is_ok());
        fs::write(&journal,format!("{}\n{}\n",json!({"kind":"payment","what":"invoice","slate_id":sid,"wallet":1,"tip_height":1,"commits":"a".repeat(66)}),json!({"kind":"release","slate_id":sid}))).unwrap();
        assert!(with_backup_send_lock(&ctx,&req,||Ok(())).is_err());
        fs::write(&journal,format!("{}\n{}\n",json!({"kind":"payment","what":"invoice","slate_id":sid,"wallet":1,"tip_height":1,"commits":"a".repeat(66)}),json!({"kind":"inputs","what":"send","wallet":1}))).unwrap();
        assert!(with_backup_send_lock(&ctx,&req,||Ok(())).is_err());
        fs::write(&journal,"{broken").unwrap(); assert!(with_backup_send_lock(&ctx,&req,||Ok(())).is_err());
        let mut name=journal.as_os_str().to_os_string(); name.push(".lock");
        let lock=fs::OpenOptions::new().write(true).open(PathBuf::from(name)).unwrap(); assert!(lock.try_lock().is_ok()); drop(lock);
        fs::remove_file(&journal).unwrap(); assert!(with_backup_send_lock(&ctx,&req,||Ok(())).is_err());
        fs::File::create(&journal).unwrap().set_len(64 * 1024 * 1024 + 1).unwrap(); assert!(with_backup_send_lock(&ctx,&req,||Ok(())).is_err());
        let _=fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn backup_send_and_s2_refuse_a_cancelled_payment() {
        let mut ctx = test_ctx("backup-cancel-before");
        let folder = ctx.user_dir.join("tx"); fs::create_dir_all(&folder).unwrap();
        let sid = "5436430c-2b02-624c-2032-570501212b00";
        fs::write(folder.join("meta.json"), json!({"slate_id":sid,"kind":"send","stage":"cancelled"}).to_string()).unwrap();
        let mut req: SendRequest = serde_json::from_str(&req_json("send", sid)).unwrap();
        req.tx_folder = folder.display().to_string(); req.expected_mode = Some("nostr_direct".into());
        let called = std::sync::atomic::AtomicBool::new(false);
        assert!(with_backup_send_lock(&ctx, &req, || { called.store(true, Ordering::SeqCst); Ok(()) }).is_err());
        assert!(!called.load(Ordering::SeqCst));
        let finalized = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = finalized.clone(); ctx.finish_fn = Some(Arc::new(move |_, _| { flag.store(true, Ordering::SeqCst); Ok(()) }));
        assert!(ctx.finish(&req, "synthetic S2").is_err());
        assert!(!finalized.load(Ordering::SeqCst));
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn backup_reply_and_invoice_allow_only_expected_stage_less_metadata() {
        let ctx = test_ctx("backup-stage-less");
        let folder = ctx.user_dir.join("tx"); fs::create_dir_all(&folder).unwrap();
        let sid = "7436430c-2b02-624c-2032-570501212b00";
        let mut req: SendRequest = serde_json::from_str(&req_json("invoice", sid)).unwrap();
        req.tx_folder = folder.display().to_string(); req.expected_mode = Some("nostr_direct".into());
        fs::write(folder.join("meta.json"), json!({"slate_id":sid,"kind":"invoice"}).to_string()).unwrap();
        assert!(with_backup_send_lock(&ctx, &req, || Ok(())).is_ok());
        req.kind = "reply".into();
        assert!(with_backup_send_lock(&ctx, &req, || Ok(())).is_err());
        fs::write(folder.join("meta.json"), json!({"slate_id":sid,"kind":"receive"}).to_string()).unwrap();
        assert!(with_backup_send_lock(&ctx, &req, || Ok(())).is_ok());
        fs::write(folder.join("meta.json"), json!({"slate_id":sid,"kind":"pay_invoice"}).to_string()).unwrap();
        assert!(with_backup_send_lock(&ctx, &req, || Ok(())).is_err());
        fs::write(folder.join("meta.json"), json!({"slate_id":sid,"kind":"pay_invoice","stage":"waiting_issuer"}).to_string()).unwrap();
        fs::write(ctx.pending_file(),format!("{}\n",json!({"kind":"payment","what":"invoice","slate_id":sid,"wallet":1,"tip_height":1,"commits":"a".repeat(66)}))).unwrap();
        assert!(with_backup_send_lock(&ctx, &req, || Ok(())).is_ok());
        fs::write(folder.join("meta.json"), json!({"slate_id":sid,"kind":"receive","stage":"cancelled"}).to_string()).unwrap();
        assert!(with_backup_send_lock(&ctx, &req, || Ok(())).is_err());
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn cancellation_waits_until_backup_send_releases_slate_lock() {
        let ctx = Arc::new(test_ctx("backup-cancel-during"));
        let folder = ctx.user_dir.join("tx"); fs::create_dir_all(&folder).unwrap();
        let sid = "6436430c-2b02-624c-2032-570501212b00";
        fs::write(folder.join("meta.json"), json!({"slate_id":sid,"kind":"send","stage":"waiting_answer"}).to_string()).unwrap();
        let mut req: SendRequest = serde_json::from_str(&req_json("send", sid)).unwrap();
        req.tx_folder = folder.display().to_string(); req.expected_mode = Some("nostr_direct".into());
        req.context=folder.join("send-context.json").display().to_string();fs::write(&req.context,"{}").unwrap();
        fs::write(ctx.pending_file(),format!("{}\n",json!({"kind":"payment","what":"send","slate_id":sid,"wallet":1,"tip_height":1,"commits":"a".repeat(66)}))).unwrap();
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let send_ctx = ctx.clone(); let send_req = req.clone();
        let sender = std::thread::spawn(move || with_backup_send_lock(&send_ctx, &send_req, || { entered_tx.send(()).unwrap(); release_rx.recv().unwrap(); Ok(()) }));
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let cancel_ctx = ctx.clone(); let cancel_folder = folder.clone();
        let (cancel_tx, cancel_rx) = std::sync::mpsc::channel();
        let cancel = std::thread::spawn(move || { let _guard = slate_lock(&cancel_ctx.sends_dir(), sid).unwrap(); fs::write(cancel_folder.join("meta.json"), json!({"slate_id":sid,"kind":"send","stage":"cancelled"}).to_string()).unwrap(); cancel_tx.send(()).unwrap(); });
        assert!(cancel_rx.recv_timeout(Duration::from_millis(150)).is_err());
        release_tx.send(()).unwrap(); sender.join().unwrap().unwrap();
        cancel_rx.recv_timeout(Duration::from_secs(3)).unwrap(); cancel.join().unwrap();
        assert!(with_backup_send_lock(&ctx, &req, || Ok(())).is_err());
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    fn backup_retry_fixture(tag: &str) -> (Ctx, SendRequest) {
        let ctx = test_ctx(tag); let sid = "8436430c-2b02-624c-2032-570501212b00";
        let folder = ctx.user_dir.join("tx"); fs::create_dir_all(&folder).unwrap();
        let armor = folder.join("s1.txt"); fs::write(&armor, "synthetic encrypted S1\n").unwrap();
        fs::write(folder.join("meta.json"), json!({"slate_id":sid,"kind":"send","stage":"waiting_answer"}).to_string()).unwrap();
        let mut req: SendRequest = serde_json::from_str(&req_json("send", sid)).unwrap();
        req.tx_folder = folder.display().to_string(); req.armor = armor.display().to_string();
        req.messenger_only = true; req.messenger = Some("grinmsg1test".into());
        req.expected_mode = Some("nostr_direct".into()); req.expected_route = Some("a".repeat(64));
        req.armor_sha256 = Some(backup_armor_digest(&req.armor).unwrap());
        fs::write(folder.join("backup-route.json"), json!({"peer":req.messenger,"mode":req.expected_mode,"route":req.expected_route,"armor_sha256":req.armor_sha256}).to_string()).unwrap();
        (ctx, req)
    }

    #[test]
    fn manual_retry_reuses_exact_stored_request_and_survives_restart_marker() {
        let (ctx, req) = backup_retry_fixture("retry-original");
        fs::create_dir_all(ctx.sends_dir()).unwrap();
        fs::write(ctx.sends_dir().join(format!("{}.json", req.slate_id)), serde_json::to_vec(&req).unwrap()).unwrap();
        queue_backup_retry(&ctx.work, &req).unwrap();
        let marker = ctx.work.join("outbox").join(format!("{}.retry", req.slate_id));
        let saved: SendRequest = serde_json::from_slice(&fs::read(&marker).unwrap()).unwrap(); assert_eq!(saved, req);
        queue_backup_retry(&ctx.work, &req).unwrap();
        let running = ctx.work.join("outbox").join(format!("{}.retry-running", req.slate_id)); fs::rename(&marker, &running).unwrap();
        queue_backup_retry(&ctx.work, &req).unwrap();
        assert!(running.exists()); assert!(!marker.exists());
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn manual_retry_before_first_queue_uses_original_s1_and_does_not_duplicate() {
        let (ctx, req) = backup_retry_fixture("retry-before-queue");
        queue_backup_retry(&ctx.work, &req).unwrap();
        let queued = ctx.work.join("outbox").join(format!("{}.json", req.slate_id));
        let saved: SendRequest = serde_json::from_slice(&fs::read(&queued).unwrap()).unwrap(); assert_eq!(saved, req);
        queue_backup_retry(&ctx.work, &req).unwrap();
        assert_eq!(fs::read_dir(ctx.work.join("outbox")).unwrap().count(), 1);
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn manual_retry_rejects_changed_s1_route_peer_and_cancellation() {
        let (ctx, req) = backup_retry_fixture("retry-reject");
        let mut altered = req.clone(); altered.expected_route = Some("b".repeat(64));
        assert!(queue_backup_retry(&ctx.work, &altered).is_err());
        altered = req.clone(); altered.messenger = Some("other-peer".into());
        assert!(queue_backup_retry(&ctx.work, &altered).is_err());
        fs::write(&req.armor, "different synthetic S1").unwrap();
        let mut changed = req.clone(); changed.armor_sha256 = Some(backup_armor_digest(&changed.armor).unwrap());
        assert!(queue_backup_retry(&ctx.work, &changed).is_err());
        fs::write(&req.armor, "synthetic encrypted S1\n").unwrap();
        fs::write(PathBuf::from(&req.tx_folder).join("meta.json"), json!({"slate_id":req.slate_id,"kind":"send","stage":"cancelled"}).to_string()).unwrap();
        assert!(queue_backup_retry(&ctx.work, &req).is_err());
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn retry_accepts_original_i1_i2_and_s2_without_allowing_route_changes() {
        for (tag, wire_kind, meta_kind, stage) in [
            ("retry-i1", "invoice", "invoice", None),
            ("retry-i2", "reply", "pay_invoice", Some("waiting_issuer")),
            ("retry-s2", "reply", "receive", None),
        ] {
            let (ctx, mut req) = backup_retry_fixture(tag);
            req.kind = wire_kind.into();
            let folder = PathBuf::from(&req.tx_folder);
            let mut meta = json!({"slate_id":req.slate_id,"kind":meta_kind});
            if let Some(stage) = stage { meta["stage"] = json!(stage); }
            fs::write(folder.join("meta.json"), meta.to_string()).unwrap();
            let saved = saved_queue_dir(&ctx.work, &req); fs::create_dir_all(&saved).unwrap();
            fs::write(saved.join(format!("{}.json", req.slate_id)), serde_json::to_vec(&req).unwrap()).unwrap();
            queue_backup_retry(&ctx.work, &req).unwrap();
            let marker = ctx.work.join("outbox").join(retry_marker_name(&req, "retry"));
            assert!(marker.exists(), "{tag}");
            let mut other_route = req.clone(); other_route.expected_route = Some("b".repeat(64));
            assert!(queue_backup_retry(&ctx.work, &other_route).is_err(), "{tag}");
            meta["stage"] = json!("cancelled"); fs::write(folder.join("meta.json"), meta.to_string()).unwrap();
            assert!(queue_backup_retry(&ctx.work, &req).is_err(), "{tag}");
            let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
        }
    }

    #[test]
    fn retry_before_first_i1_i2_and_s2_queue_preserves_exact_request() {
        for (tag, wire_kind, meta_kind, stage) in [
            ("retry-first-i1", "invoice", "invoice", None),
            ("retry-first-i2", "reply", "pay_invoice", Some("waiting_issuer")),
            ("retry-first-s2", "reply", "receive", None),
        ] {
            let (ctx, mut req) = backup_retry_fixture(tag); req.kind = wire_kind.into();
            let mut meta = json!({"slate_id":req.slate_id,"kind":meta_kind});
            if let Some(stage) = stage { meta["stage"] = json!(stage); }
            fs::write(PathBuf::from(&req.tx_folder).join("meta.json"), meta.to_string()).unwrap();
            queue_backup_retry(&ctx.work, &req).unwrap();
            let path = ctx.work.join("outbox").join(format!("{}.json", req.slate_id));
            let queued: SendRequest = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            assert_eq!(queued, req, "{tag}");
            let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
        }
    }

    #[test]
    fn retry_markers_separate_send_invoice_and_reply_for_same_slate() {
        let (ctx, mut req) = backup_retry_fixture("retry-marker-names");
        let send = retry_marker_name(&req, "retry-running"); req.kind = "invoice".into();
        let invoice = retry_marker_name(&req, "retry-running"); req.kind = "reply".into();
        let reply = retry_marker_name(&req, "retry-running");
        assert_ne!(send, invoice); assert_ne!(send, reply); assert_ne!(invoice, reply);
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn running_retry_marker_recovers_without_sending_over_an_unselected_route() {
        let (raw, req) = backup_retry_fixture("recover-running-retry"); let ctx = Arc::new(raw);
        fs::create_dir_all(ctx.sends_dir()).unwrap(); fs::create_dir_all(ctx.work.join("outbox")).unwrap();
        fs::write(ctx.sends_dir().join(format!("{}.json", req.slate_id)), serde_json::to_vec(&req).unwrap()).unwrap();
        let marker = ctx.work.join("outbox").join(retry_marker_name(&req, "retry-running"));
        fs::write(&marker, serde_json::to_vec(&req).unwrap()).unwrap();
        process_backup_retries(&ctx, true);
        let until = std::time::Instant::now() + Duration::from_secs(3);
        while marker.exists() && std::time::Instant::now() < until { std::thread::sleep(Duration::from_millis(10)); }
        assert!(!marker.exists());
        let status = fs::read_to_string(ctx.sends_dir().join(format!("{}.status", req.slate_id))).unwrap();
        assert!(status.contains("FAILED"));
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn cancelled_retry_marker_is_never_dispatched_during_recovery() {
        let (raw, req) = backup_retry_fixture("cancelled-running-retry"); let ctx = Arc::new(raw);
        fs::create_dir_all(ctx.sends_dir()).unwrap(); fs::create_dir_all(ctx.work.join("outbox")).unwrap();
        fs::write(ctx.sends_dir().join(format!("{}.json", req.slate_id)), serde_json::to_vec(&req).unwrap()).unwrap();
        let marker = ctx.work.join("outbox").join(retry_marker_name(&req, "retry-running"));
        fs::write(&marker, serde_json::to_vec(&req).unwrap()).unwrap();
        fs::write(PathBuf::from(&req.tx_folder).join("meta.json"), json!({"slate_id":req.slate_id,"kind":"send","stage":"cancelled"}).to_string()).unwrap();
        process_backup_retries(&ctx, true);
        assert!(marker.exists());
        assert!(!ctx.sends_dir().join(format!("{}.status", req.slate_id)).exists());
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn stale_network_result_cannot_replace_cancelled_or_finalized_status() {
        let (ctx, req) = backup_retry_fixture("retry-terminal");
        let folder = PathBuf::from(&req.tx_folder);
        fs::write(folder.join("meta.json"), json!({"slate_id":req.slate_id,"kind":"send","stage":"cancelled"}).to_string()).unwrap();
        assert!(!mark_delivery_if_pending(&ctx, &req, "SENT"));
        fs::write(folder.join("meta.json"), json!({"slate_id":req.slate_id,"kind":"send","stage":"waiting_answer"}).to_string()).unwrap();
        fs::write(folder.join(FINALIZED_MARK), b"done").unwrap();
        assert!(!mark_delivery_if_pending(&ctx, &req, "FAILED"));
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    #[test]
    fn answer_requires_original_signed_peer_and_exact_route() {
        let ctx = test_ctx("answer-route");
        let url = "wss://relay.example";
        fs::write(ctx.user_dir.join("settings.json"), json!({"messenger_nostr_mode":"direct","messenger_nostr_url":url,"messenger_nostr_consent_url":url}).to_string()).unwrap();
        let tag = payment_route_tag("nostr_direct", url, "");
        let mut req: SendRequest = serde_json::from_str(&req_json("send", "5436430c-2b02-624c-2032-570501212b00")).unwrap();
        req.expected_mode = Some("nostr_direct".into()); req.expected_route = Some(tag.clone());
        req.messenger_only = true; req.messenger = Some("peer-a".into());
        assert!(validate_answer_route(&ctx, &req, "peer-a", "nostr_direct", Some(&tag)).is_ok());
        assert!(validate_answer_route(&ctx, &req, "peer-b", "nostr_direct", Some(&tag)).is_err());
        assert!(validate_answer_route(&ctx, &req, "peer-a", "nostr_direct", Some(&"a".repeat(64))).is_err());
        assert!(validate_answer_route(&ctx, &req, "peer-a", "i2p_direct", Some(&tag)).is_err());
        req.expected_mode = Some("tor".into()); req.expected_route = None; req.messenger_only = false;
        assert!(validate_answer_route(&ctx, &req, "peer-a", "nostr_direct", Some(&tag)).is_err());
        assert!(validate_answer_route(&ctx, &req, "peer-a", "direct", None).is_ok());
        let _ = fs::remove_dir_all(ctx.user_dir.parent().unwrap());
    }

    /// ACCEPTANCE (two finalizers): the Foreign API, the messenger and the
    /// outgoing thread deliver the same answer at once. The real
    /// `Ctx::finish` runs the (stub) wallet executable to finalize exactly once.
    #[cfg(unix)]
    #[test]
    fn same_answer_from_three_paths_finalizes_once() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("grinsight-fin3-{}", std::process::id()));
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
            messenger_route: Mutex::new(None),
        channel_drain: channel_drain::ChannelDrain::default(),
            log: Mutex::new(()),
            inbox_rate: Mutex::new((0, 0)),
            hold: Duration::from_secs(1),
            strangers: Mutex::new(Vec::new()),
            receive_fn: None,
            finish_fn: None,
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
    // Iterations: GRINSIGHT_FUZZ_ITERS (default 1000 per target).

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
        std::env::var("GRINSIGHT_FUZZ_ITERS").ok().and_then(|v| v.parse().ok()).unwrap_or(1000)
    }

    fn ffuzz(name: &str, seed: u64, seeds: Vec<Vec<u8>>, mut f: impl FnMut(&[u8])) {
        let mut r = FRng(seed | 1);
        for i in 0..fiters() {
            let d = fmutate(&mut r, &seeds);
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&d))).is_err() {
                let p = std::env::temp_dir().join(format!("grinsight-tor-fuzz-{name}.bin"));
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
        let mut c = test_ctx(&format!("fuzz-{tag}"));
        // A fuzzed stranger must not really wait 40 s.
        c.hold = Duration::from_millis(1);
        c
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
        use glaux_messenger::{Envelope, Identity, MessageKind};
        let alice = Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let bob = Identity::from_seed([9u8; 32], "tgrin").unwrap();
        let env = Envelope::seal_default(&alice, bob.address(), MessageKind::Slatepack { armor: "BEGINSLATEPACK. abc. ENDSLATEPACK.".into(), encrypted: true }).unwrap();
        let text = Envelope::seal_default(&alice, bob.address(), MessageKind::Text { text: "hi".into() }).unwrap();
        let seeds = vec![serde_json::to_vec(&env).unwrap(), serde_json::to_vec(&text).unwrap()];
        let now = glaux_messenger::envelope::unix_now();
        assert!(env.open(&bob, now).is_ok(), "valid seed opens");
        ffuzz("envelope", 44, seeds, |d| {
            if let Ok(e) = serde_json::from_slice::<Envelope>(d) {
                let _ = e.open(&bob, now);
                let _ = e.verify_pow(1);
            }
            let _ = glaux_messenger::Address::parse(&String::from_utf8_lossy(d));
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
