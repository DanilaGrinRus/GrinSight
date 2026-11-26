//! The wallet process of GrinSight.
//!
//! One process serves one profile directory. The interface starts it and
//! talks to it over its standard input and output: one JSON-RPC 2.0 request
//! per line in, one answer per line out, plus `paycore.event` notifications
//! about delivery. Nothing secret is taken from the command line or the
//! environment, and nothing is logged.
//!
//! * `host.*` methods are answered here: creating or restoring a profile,
//!   unlocking it with the password, locking it, changing the password.
//! * `paycore.*` methods go to the payment core of the unlocked profile,
//!   which lives on one worker thread (`fly_paycore_bridge::runner`).
//!   While the profile is locked they are refused.
//!
//! This process contains no network code. Messages travel through a second
//! process, the transport, which the host starts for the unlocked profile
//! and ends when the profile is locked ([`transport`]). The chain is a port
//! ([`ChainPorts`]); until the chain layer is connected the product program
//! runs with "nothing is known about the chain".
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

pub mod chain;
pub mod inline;
pub mod onion;
pub mod profile;
mod session;
pub mod tor_bridges;
pub mod transport;

pub use session::{HostBridge, HostCore};

use fly_paycore_bridge::ports::{Broadcaster, ChainView, Clock};
use fly_paycore_bridge::runner::{Runner, RunnerError};
use fly_paycore_bridge::MAX_REQUEST_LEN;
use fly_paycore_guard_os::Origin;
use fly_paycore_store::GuardCheck;
use fly_paycore_wallet::{Broadcast, ChainState};
use grin_keychain::ExtKeychain;
use profile::{Network, ProfileError, Secrets};
use serde::Deserialize;
use serde_json::{json, Value};
use session::{Fail, Opened, Places};
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use transport::{Launcher, Phase, Report, SharedReport};
use zeroize::{Zeroize, Zeroizing};

/// Version of the `host.*` methods.
pub const HOST_API_VERSION: u32 = 1;
/// Answers and notifications waiting to be written; notifications beyond
/// that are dropped and counted.
const MAX_WAITING_OUTPUT: usize = 256;

/// The three ports through which the core sees the chain.
pub struct ChainPorts {
    /// Hands a finalized transaction to the network.
    pub broadcaster: Box<dyn Broadcaster>,
    /// Confirmed time.
    pub clock: Box<dyn Clock>,
    /// What is known about the chain.
    pub chain: Box<dyn ChainView>,
}

/// Runs once on a newly created journal; see [`Setup::after_create`].
pub type AfterCreate = fn(&mut HostCore, &ExtKeychain, &Value) -> Result<(), String>;

/// What differs between the product program and a test program.
#[derive(Clone, Copy)]
pub struct Setup {
    /// Makes the chain ports, on the worker thread.
    pub ports: fn() -> ChainPorts,
    /// Runs once on a newly created journal with the `test` parameter of
    /// the request. The product has none.
    pub after_create: Option<AfterCreate>,
    /// Whether profiles on the chain of automated tests are accepted.
    pub allow_automated: bool,
    /// Cost of the password key derivation for new profile files.
    pub kdf_log_n: u8,
    /// Profile files that ask for less are refused.
    pub kdf_min_log_n: u8,
    /// Pause between two rounds of delivery.
    pub tick: Duration,
    /// Pause before a transport that is down is started again.
    pub transport_retry: Duration,
}

struct NoChain;
impl Broadcaster for NoChain {
    fn post_tx(&mut self, _tx: &[u8]) -> Broadcast {
        Broadcast::Unknown
    }
}
impl Clock for NoChain {
    fn confirmed_time(&self) -> Option<u64> {
        None
    }
}
impl ChainView for NoChain {
    fn chain_state(&self) -> ChainState {
        ChainState::Unknown
    }
    fn k_conf(&self) -> u64 {
        10
    }
    fn rangeproofs_authenticated(&self) -> bool {
        false
    }
}

impl Setup {
    /// The product: no chain layer is connected yet, so nothing is known
    /// about the chain, nothing is broadcast and no time is confirmed.
    pub fn product() -> Setup {
        Setup {
            ports: || ChainPorts {
                broadcaster: Box::new(NoChain),
                clock: Box::new(NoChain),
                chain: Box::new(NoChain),
            },
            after_create: None,
            allow_automated: false,
            // 2^17 blocks of 1 KB: 128 MB and a good part of a second
            kdf_log_n: 17,
            kdf_min_log_n: 15,
            tick: Duration::from_secs(2),
            transport_retry: Duration::from_secs(30),
        }
    }
}

/// A text that is wiped when dropped. The JSON parser may still have held
/// it in a buffer of its own; that copy is not ours to wipe.
struct Secret(Zeroizing<String>);
impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d).map(|s| Secret(Zeroizing::new(s)))
    }
}

#[derive(Deserialize)]
struct Head {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    id: Option<Value>,
}

#[derive(Deserialize, Default)]
struct HostParams {
    #[serde(default)]
    password: Option<Secret>,
    #[serde(default)]
    new_password: Option<Secret>,
    #[serde(default)]
    mnemonic: Option<Secret>,
    #[serde(default)]
    network: Option<String>,
    #[serde(default)]
    words: Option<Secret>,
    #[serde(default)]
    reset_guard: Option<bool>,
    /// `host.tor`: Tor off (`true`) or on.
    #[serde(default)]
    off: Option<bool>,
    #[serde(default)]
    test: Option<Value>,
}

#[derive(Deserialize)]
struct HostRequest {
    #[serde(default)]
    params: Option<HostParams>,
}

struct HostFail {
    code: i32,
    kind: &'static str,
    reason: String,
}

fn fail(code: i32, kind: &'static str, reason: &str) -> HostFail {
    HostFail {
        code,
        kind,
        reason: reason.to_string(),
    }
}

fn bad_params(reason: &str) -> HostFail {
    fail(-32602, "invalid_params", reason)
}

impl From<ProfileError> for HostFail {
    fn from(e: ProfileError) -> Self {
        match e {
            ProfileError::Missing => fail(-32041, "no_profile", ""),
            ProfileError::Exists => fail(-32042, "profile_exists", ""),
            ProfileError::WrongPassword => fail(-32043, "wrong_password", ""),
            ProfileError::Damaged(what) => fail(-32048, "profile_damaged", what),
            ProfileError::BadInput(what) => bad_params(what),
            ProfileError::Io(kind) => fail(-32049, "profile_io", &format!("{kind:?}")),
            ProfileError::Rng => fail(-32049, "profile_io", "no randomness"),
        }
    }
}

impl From<Fail> for HostFail {
    fn from(e: Fail) -> Self {
        match e {
            Fail::GuardForeign => fail(-32044, "guard", "foreign"),
            Fail::GuardDamaged => fail(-32044, "guard", "damaged"),
            Fail::NoJournal => fail(-32047, "no_journal", ""),
            Fail::Other(why) => fail(-32049, "profile_io", &why),
        }
    }
}

fn answer(id: &Value, result: Result<Value, HostFail>) -> Zeroizing<String> {
    let body = match result {
        Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Err(f) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": f.code,
                "message": f.kind,
                "data": {"kind": f.kind, "reason": f.reason},
            },
        }),
    };
    Zeroizing::new(body.to_string())
}

/// The writer of everything that leaves the process. Answers wait for
/// room; notifications never wait, so the worker is never held up by an
/// interface that has stopped reading.
#[derive(Clone)]
struct Out {
    lines: SyncSender<Zeroizing<String>>,
    dropped: Arc<AtomicU64>,
}

impl Out {
    fn answer(&self, line: Zeroizing<String>) {
        if !line.is_empty() {
            let _ = self.lines.send(line);
        }
    }
    fn event(&self, line: &str) {
        match self.lines.try_send(Zeroizing::new(line.to_string())) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

enum Line {
    End,
    Text,
    TooLong,
}

/// Read one line of at most `max` bytes into `buf`. A longer line is read
/// to its end and thrown away.
fn read_line<R: BufRead>(input: &mut R, buf: &mut Vec<u8>, max: usize) -> std::io::Result<Line> {
    buf.zeroize();
    let mut too_long = false;
    let mut any = false;
    loop {
        let chunk = input.fill_buf()?;
        if chunk.is_empty() {
            return Ok(match (any, too_long) {
                (false, _) => Line::End,
                (true, true) => Line::TooLong,
                (true, false) => Line::Text,
            });
        }
        any = true;
        let (part, used, ended) = match chunk.iter().position(|b| *b == b'\n') {
            Some(at) => (chunk.get(..at).unwrap_or_default(), at.saturating_add(1), true),
            None => (chunk, chunk.len(), false),
        };
        if !too_long {
            if buf.len().saturating_add(part.len()) > max {
                too_long = true;
                buf.zeroize();
            } else {
                buf.extend_from_slice(part);
            }
        }
        input.consume(used);
        if ended {
            return Ok(if too_long { Line::TooLong } else { Line::Text });
        }
    }
}

struct Args {
    profile: PathBuf,
    guard_root: PathBuf,
    launcher: Option<(PathBuf, String)>,
    chain: Option<(PathBuf, Vec<String>)>,
    /// `--onion`: the Tor program for payments to and from the address.
    onion: Option<PathBuf>,
    /// `--tor-bridges`: the file of Tor bridges the user chose.
    tor_bridges: Option<PathBuf>,
    /// `--chain-direct-post`: the user agreed that a transaction may be
    /// sent from this computer's address when Tor fails.
    direct_post: bool,
    /// `--chain-no-tor`: the user switched Tor off.
    tor_off: bool,
    /// `--device-key-stdin`: the first line of the input is not a request
    /// but the device's key for the tail guard (see [`device_key_line`]).
    device_key_first: bool,
}

fn default_guard_root() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA")
            .filter(|v| !v.is_empty())
            .map(|v| PathBuf::from(v).join("GrinSightLight").join("guard"))
    }
    #[cfg(not(windows))]
    {
        let state = std::env::var_os("XDG_STATE_HOME")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .filter(|v| !v.is_empty())
                    .map(|v| PathBuf::from(v).join(".local").join("state"))
            })?;
        Some(state.join("grinsight-light").join("guard"))
    }
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let (mut profile, mut guard, mut program, mut relay, mut chain) = (None, None, None, None, None);
    let mut onion = None;
    let mut tor_bridges = None;
    let mut peers = Vec::new();
    let mut direct_post = false;
    let mut tor_off = false;
    let mut device_key_first = false;
    let mut it = args.iter();
    while let Some(name) = it.next() {
        if name == "--chain-direct-post" {
            direct_post = true;
            continue;
        }
        if name == "--chain-no-tor" {
            tor_off = true;
            continue;
        }
        if name == "--device-key-stdin" {
            if cfg!(windows) {
                // Windows binds the guard to the user and the machine itself
                return Err(format!("{name} is not used on Windows"));
            }
            device_key_first = true;
            continue;
        }
        if name == "--chain-peer" {
            // may be given several times
            let value = it.next().ok_or_else(|| format!("{name} needs a value"))?;
            if value.is_empty() || value.len() > 512 || peers.len() >= 32 {
                return Err(format!("{name}: not usable"));
            }
            peers.push(value.clone());
            continue;
        }
        let slot = match name.as_str() {
            "--chain" => &mut chain,
            "--onion" => &mut onion,
            "--tor-bridges" => &mut tor_bridges,
            "--profile" => &mut profile,
            "--guard-dir" => &mut guard,
            "--transport" => &mut program,
            "--relay" => &mut relay,
            _ => return Err(format!("unknown argument {name}")),
        };
        let value = it.next().ok_or_else(|| format!("{name} needs a value"))?;
        if slot.replace(value.clone()).is_some() {
            return Err(format!("{name} is given twice"));
        }
    }
    let profile = PathBuf::from(profile.ok_or("--profile <directory> is required")?);
    let guard_root = match guard {
        Some(dir) => PathBuf::from(dir),
        None => default_guard_root().ok_or("no place for the tail guard; pass --guard-dir")?,
    };
    let launcher = match (program, relay) {
        (Some(program), Some(relay)) if !relay.is_empty() && relay.len() <= 512 => {
            Some((PathBuf::from(program), relay))
        }
        (None, None) => None,
        _ => return Err("--transport and --relay go together".to_string()),
    };
    let chain = match chain {
        Some(program) => Some((PathBuf::from(program), peers)),
        None if peers.is_empty() => None,
        None => return Err("--chain-peer needs --chain".to_string()),
    };
    if direct_post && chain.is_none() {
        return Err("--chain-direct-post needs --chain".to_string());
    }
    if tor_off && chain.is_none() {
        return Err("--chain-no-tor needs --chain".to_string());
    }
    Ok(Args {
        profile,
        guard_root,
        launcher,
        chain,
        onion: onion.map(PathBuf::from),
        tor_bridges: tor_bridges.map(PathBuf::from),
        direct_post,
        tor_off,
        device_key_first,
    })
}

/// The one line a host started with `--device-key-stdin` is given before
/// any request: `{"jsonrpc":"2.0","method":"host.device_key","params":{"key":"<64 hex digits>"}}`,
/// exactly so. The key is 32 bytes that whoever starts the host keeps under
/// a key of the device (on Android: the service, under a key of the Android
/// Keystore). An empty `key` says the device has no such keeper: the guard
/// is then bound to the password alone, and the status says so. Anything
/// else is a wrong start. The line is read without a JSON tree, so that no
/// copy of the key outlives the buffer it came in.
fn device_key_line(line: &[u8]) -> Result<Option<Zeroizing<[u8; 32]>>, &'static str> {
    const HEAD: &[u8] = br#"{"jsonrpc":"2.0","method":"host.device_key","params":{"key":""#;
    const TAIL: &[u8] = br#""}}"#;
    let wrong = "the first line must be the device key";
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let digits = line.strip_prefix(HEAD).and_then(|rest| rest.strip_suffix(TAIL)).ok_or(wrong)?;
    if digits.is_empty() {
        return Ok(None);
    }
    let mut key = Zeroizing::new([0u8; 32]);
    if digits.len() != 64 {
        return Err(wrong);
    }
    for (byte, pair) in key.iter_mut().zip(digits.chunks_exact(2)) {
        let nibble = |c: &u8| match c {
            b'0'..=b'9' => c.checked_sub(b'0'),
            b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
            _ => None,
        };
        let (Some(high), Some(low)) = (pair.first().and_then(nibble), pair.get(1).and_then(nibble)) else {
            return Err(wrong);
        };
        *byte = high.checked_mul(16).and_then(|h| h.checked_add(low)).ok_or(wrong)?;
    }
    Ok(Some(key))
}

fn private_dir(path: &Path) -> std::io::Result<PathBuf> {
    if !path.is_dir() {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(path)?;
    }
    // made absolute, not resolved: on Windows a resolved path gets a prefix
    // that not every program understands, and the transport is given one
    std::path::absolute(path)
}

fn places(args: Args, setup: &Setup, device_key: Option<Zeroizing<[u8; 32]>>) -> Result<Places, String> {
    let profile = private_dir(&args.profile).map_err(|_| "the profile directory cannot be used")?;
    let guard_root = private_dir(&args.guard_root).map_err(|_| "the guard directory cannot be used")?;
    // the guard is worth something only where a copy of the profile does
    // not take it along; compared as resolved paths too, so that another
    // spelling of the profile (letter case, a link) is not taken for elsewhere
    let resolved = match (guard_root.canonicalize(), profile.canonicalize()) {
        (Ok(guard), Ok(profile)) => guard.starts_with(profile),
        _ => return Err("the guard or profile directory cannot be resolved".to_string()),
    };
    if resolved || guard_root.starts_with(&profile) {
        return Err("the guard directory must lie outside the profile directory".to_string());
    }
    if profile.to_str().is_none() {
        return Err("the profile path is not text".to_string());
    }
    // one switch for everything that uses Tor (K189, K193)
    let tor = chain::tor_switch(args.tor_off);
    let launcher = args.launcher.map(|(program, relay)| Launcher {
        program,
        relay,
        data_dir: String::new(),
        retry: setup.transport_retry,
        off: tor.clone(),
    });
    let direct_post = args.direct_post;
    let tor_off = tor.clone();
    let chain = args.chain.map(|(program, peers)| chain::ChainProgram {
        inside: None,
        program,
        peers,
        retry: setup.transport_retry,
        direct_post,
        tor_off,
    });
    if let Some(file) = args.tor_bridges {
        tor_bridges::set_file(file);
    }
    let onion = args.onion.map(|program| onion::OnionProgram {
        program,
        data_dir: String::new(),
        retry: setup.transport_retry,
        off: tor.clone(),
    });
    Ok(Places {
        profile,
        guard_root,
        launcher,
        chain,
        onion,
        device_key,
        tor,
    })
}

struct OpenWallet {
    runner: Runner,
    network: Network,
    instance: [u8; 16],
}

struct Host {
    setup: Setup,
    places: Places,
    out: Out,
    runner: Option<OpenWallet>,
    report: SharedReport,
    chain_report: chain::SharedChainReport,
}

fn guard_name(check: GuardCheck) -> &'static str {
    match check {
        GuardCheck::Match => "match",
        GuardCheck::CaughtUp => "caught_up",
        GuardCheck::RolledBack => "rolled_back",
        GuardCheck::Missing => "missing",
    }
}

fn origin_name(origin: Origin) -> &'static str {
    match origin {
        Origin::Existing => "existing",
        Origin::Created => "created",
        Origin::Reset => "reset",
    }
}

fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>, HostFail> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::getrandom(bytes.as_mut()).map_err(|_| HostFail::from(ProfileError::Rng))?;
    Ok(bytes)
}

fn password(p: &Option<Secret>, name: &str) -> Result<Zeroizing<Vec<u8>>, HostFail> {
    match p {
        Some(Secret(text)) if !text.is_empty() && text.len() <= profile::MAX_PASSWORD_LEN => {
            Ok(Zeroizing::new(text.as_bytes().to_vec()))
        }
        Some(_) => Err(bad_params(&format!("{name}: length"))),
        None => Err(bad_params(&format!("{name}: missing"))),
    }
}

/// The answer that carries the recovery phrase, put together without a
/// JSON tree so that no copy of the phrase outlives the line itself.
fn phrase_answer(id: &Value, seed: &[u8]) -> Result<Zeroizing<String>, HostFail> {
    let phrase = Zeroizing::new(
        grin_keychain::mnemonic::from_entropy(seed).map_err(|_| fail(-32049, "profile_io", "seed"))?,
    );
    if !phrase.bytes().all(|b| b.is_ascii_lowercase() || b == b' ') {
        return Err(fail(-32049, "profile_io", "seed"));
    }
    Ok(Zeroizing::new(format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"mnemonic\":\"{}\"}}}}",
        phrase.as_str()
    )))
}

/// How many numbered words have to be typed to delete a wallet.
pub const DELETE_WORDS: usize = 2;

/// Whether the numbered words a person typed are the wallet's own: `said`
/// is "7 apple 19 river" - a place (1 to 24) and the word at it, twice, the
/// places different. Anything else is a malformed request; right form with
/// a wrong word is `false`.
pub(crate) fn words_match(seed: &[u8], said: &str) -> Result<bool, HostFail> {
    let phrase = Zeroizing::new(grin_keychain::mnemonic::from_entropy(seed).map_err(|_| fail(-32049, "profile_io", "seed"))?);
    let own: Vec<&str> = phrase.split(' ').collect();
    let parts: Vec<&str> = said.split(' ').filter(|part| !part.is_empty()).collect();
    if parts.len() != DELETE_WORDS.saturating_mul(2) {
        return Err(bad_params("words: two numbered words"));
    }
    let mut places: Vec<usize> = Vec::with_capacity(DELETE_WORDS);
    let mut all = true;
    for pair in parts.chunks_exact(2) {
        let (Some(place), Some(word)) = (pair.first().and_then(|n| n.parse::<usize>().ok()), pair.get(1)) else {
            return Err(bad_params("words: a place and a word"));
        };
        if place == 0 || place > own.len() || places.contains(&place) {
            return Err(bad_params("words: two different places"));
        }
        places.push(place);
        // every pair is looked at, right or wrong: the answer does not say which one failed
        all &= own.get(place.saturating_sub(1)).is_some_and(|mine| mine == &word.to_lowercase().as_str());
    }
    Ok(all)
}

impl Host {
    fn status(&self) -> Value {
        let state = if self.runner.is_some() {
            "unlocked"
        } else if profile::exists(&self.places.profile) {
            "locked"
        } else {
            "none"
        };
        // Only the open worker identifies the active wallet. The on-disk
        // network is an unauthenticated hint for the locked login screen.
        let network = match &self.runner {
            Some(wallet) => Some(wallet.network),
            None => profile::network(&self.places.profile).ok(),
        }.map(Network::name);
        let report: Report = match self.report.lock() {
            Ok(r) => r.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let chain: chain::ChainReport = match self.chain_report.lock() {
            Ok(r) => r.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let phase = |p: Phase| match p {
            Phase::None => "none",
            Phase::Starting => "starting",
            Phase::Ready => "ready",
            Phase::Down => "down",
        };
        json!({
            "api_version": HOST_API_VERSION,
            "profile": state,
            "network": network,
            // what a copy of the profile and its guard would have to come
            // with to pass for the original
            "guard_binding": session::guard_binding(&self.places),
            // where the rollback guards are kept, for the window to show: a
            // place on this computer, not a secret
            "guard_dir": self.places.guard_root.to_string_lossy(),
            "transport": {
                "configured": self.places.launcher.is_some(),
                "phase": phase(report.phase),
                "error": report.error,
                "problem": report.problem,
                "starts": report.starts,
            },
            // its state is the wallet's to ask: `paycore.onion.status`
            "onion": { "configured": self.places.onion.is_some() },
            // the owner's switch: with it set nothing here uses Tor
            "tor_off": chain::tor_is_off(&self.places.tor),
            // how many Tor bridges the helper processes are given when they start
            "tor_bridges": { "lines": tor_bridges::count(&tor_bridges::text()), "usable": tor_bridges::text() != tor_bridges::UNUSABLE },
            "chain": {
                "configured": self.places.chain.is_some(),
                "phase": phase(chain.phase),
                "error": chain.error,
                "problem": chain.problem,
                "starts": chain.starts,
            },
        })
    }

    fn network(&self, p: &HostParams) -> Result<Network, HostFail> {
        let name = p.network.as_deref().ok_or_else(|| bad_params("network: missing"))?;
        match Network::from_name(name) {
            Some(Network::Automated) if !self.setup.allow_automated => Err(bad_params("network: unknown")),
            Some(network) => Ok(network),
            None => Err(bad_params("network: unknown")),
        }
    }

    /// Make the journal and then the profile file of a new profile around
    /// `seed`. The profile stays locked. `restored`: the seed was brought
    /// by the user and may have a history.
    fn make_profile(&mut self, p: &HostParams, seed: Zeroizing<Vec<u8>>, restored: bool) -> Result<(), HostFail> {
        if profile::exists(&self.places.profile) {
            return Err(ProfileError::Exists.into());
        }
        let pass = password(&p.password, "password")?;
        let secrets = Secrets {
            network: self.network(p)?,
            seed,
            root: random::<32>()?,
            guard_wrap: random::<32>()?,
            instance: *random::<16>()?,
            account: 0,
        };
        // sealed first: a password or seed that cannot be sealed leaves nothing behind
        let text = Zeroizing::new(profile::seal(&secrets, &pass, self.setup.kdf_log_n)?);
        let (places, setup) = (self.places.clone(), self.setup);
        let extra = match self.setup.after_create {
            Some(_) => p.test.clone().unwrap_or(Value::Null),
            None => Value::Null,
        };
        // on a thread of its own: the chain selection of that thread and
        // the keychain end with it
        let made = thread::Builder::new()
            .name("paycore-create".into())
            .spawn(move || session::create(&secrets, &places, &setup, &extra, restored))
            .map_err(|_| fail(-32049, "profile_io", "no thread"))?
            .join()
            .map_err(|_| fail(-32049, "profile_io", "creation failed"))?;
        made?;
        profile::write_new(&self.places.profile, &text)?;
        Ok(())
    }

    fn unlock(&mut self, p: &HostParams) -> Result<Value, HostFail> {
        if self.runner.is_some() {
            return Err(fail(-32045, "already_unlocked", ""));
        }
        let pass = password(&p.password, "password")?;
        let secrets = profile::open(&self.places.profile, &pass, self.setup.kdf_min_log_n)?;
        if secrets.network == Network::Automated && !self.setup.allow_automated {
            return Err(ProfileError::Damaged("network").into());
        }
        let network = secrets.network;
        let instance = secrets.instance;
        let reset = p.reset_guard.unwrap_or(false);
        let (places, setup, report, out) = (self.places.clone(), self.setup, self.report.clone(), self.out.clone());
        let chain_report = self.chain_report.clone();
        let slot: Arc<Mutex<Option<Result<Opened, Fail>>>> = Arc::new(Mutex::new(None));
        let told = slot.clone();
        let started = Runner::start(
            move || {
                let (bridge, outcome) = match session::open(&secrets, &places, &setup, reset, &report, &chain_report) {
                    Ok((bridge, opened)) => (Ok(bridge), Ok(opened)),
                    Err(why) => (Err(String::new()), Err(why)),
                };
                if let Ok(mut slot) = told.lock() {
                    *slot = Some(outcome);
                }
                bridge
            },
            self.setup.tick,
            Box::new(move |note| out.event(note)),
        );
        let outcome = slot.lock().ok().and_then(|mut s| s.take());
        match (started, outcome) {
            (Ok(runner), Some(Ok(opened))) => {
                self.runner = Some(OpenWallet { runner, network, instance });
                Ok(json!({
                    "guard": guard_name(opened.guard),
                    "guard_key": origin_name(opened.guard_key),
                    "recovered": opened.recovered,
                }))
            }
            (_, Some(Err(why))) => Err(why.into()),
            _ => Err(fail(-32049, "profile_io", "the profile could not be opened")),
        }
    }

    fn lock(&mut self) {
        if let Some(wallet) = self.runner.take() {
            // returns when the worker, the core and the transport are gone
            wallet.runner.stop();
        }
    }

    fn host_call(&mut self, method: &str, id: &Value, line: &str) -> Zeroizing<String> {
        let request: HostRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => return answer(id, Err(bad_params("params"))),
        };
        let p = request.params.unwrap_or_default();
        let result = match method {
            "host.status" => Ok(self.status()),
            "host.profile.create" => match random::<32>() {
                Ok(seed) => {
                    let made = self.make_profile(&p, Zeroizing::new(seed.to_vec()), false);
                    match made.and_then(|()| phrase_answer(id, seed.as_ref())) {
                        Ok(line) => return line,
                        Err(e) => Err(e),
                    }
                }
                Err(e) => Err(e),
            },
            "host.profile.restore" => self.restore(&p).map(|()| json!({})),
            "host.profile.mnemonic" => {
                let shown = password(&p.password, "password")
                    .and_then(|pass| self.profile_for_session(&pass))
                    .and_then(|secrets: Secrets| phrase_answer(id, &secrets.seed));
                match shown {
                    Ok(line) => return line,
                    Err(e) => Err(e),
                }
            }
            "host.profile.change_password" => self.change_password(&p).map(|()| json!({})),
            "host.profile.delete" => self.delete(&p).map(|()| json!({})),
            "host.unlock" => self.unlock(&p),
            "host.lock" => {
                self.lock();
                Ok(json!({}))
            }
            // K193: the owner's Tor switch, locked or open, without a restart
            "host.tor" => match (p.off, self.places.chain.is_some()) {
                (Some(off), true) => {
                    self.places.tor.store(off, std::sync::atomic::Ordering::SeqCst);
                    Ok(json!({ "off": off }))
                }
                (Some(_), false) => Err(bad_params("off: there is no chain program to send without Tor")),
                (None, _) => Err(bad_params("off: missing")),
            },
            // K201: the owner changed the bridges - locked or open, without
            // a restart of the wallet. The host is told nothing but "now":
            // the lines are in the file it was named at its start, and each
            // process that uses Tor is started anew with them.
            "host.tor.bridges" => {
                chain::bridges_changed(&self.places.tor);
                let text = tor_bridges::text();
                Ok(json!({ "lines": tor_bridges::count(&text), "usable": text != tor_bridges::UNUSABLE }))
            }
            _ => Err(fail(-32601, "method_not_found", "")),
        };
        answer(id, result)
    }

    fn restore(&mut self, p: &HostParams) -> Result<(), HostFail> {
        let Some(Secret(phrase)) = &p.mnemonic else {
            return Err(bad_params("mnemonic: missing"));
        };
        if phrase.len() > 1024 {
            return Err(fail(-32046, "bad_mnemonic", ""));
        }
        let words = Zeroizing::new(phrase.to_lowercase());
        let seed = Zeroizing::new(
            grin_keychain::mnemonic::to_entropy(&words).map_err(|_| fail(-32046, "bad_mnemonic", ""))?,
        );
        self.make_profile(p, seed, true)
    }

    fn profile_for_session(&self, pass: &[u8]) -> Result<Secrets, HostFail> {
        let secrets = profile::open(&self.places.profile, pass, self.setup.kdf_min_log_n)?;
        if self.runner.as_ref().is_some_and(|wallet|
            wallet.instance != secrets.instance || wallet.network != secrets.network
        ) {
            return Err(fail(-32049, "profile_io", "the open wallet and the profile file differ"));
        }
        Ok(secrets)
    }

    fn change_password(&mut self, p: &HostParams) -> Result<(), HostFail> {
        let old = password(&p.password, "password")?;
        let new = password(&p.new_password, "new_password")?;
        let secrets = self.profile_for_session(&old)?;
        let text = Zeroizing::new(profile::seal(&secrets, &new, self.setup.kdf_log_n)?);
        profile::replace(&self.places.profile, &text)?;
        Ok(())
    }

    /// Delete the wallet from this computer: for its password and two of
    /// its 24 words by number - whoever asks has to have the words, because
    /// after this only the words bring the money back. The wallet is closed,
    /// its own directories go, the profile's file goes last.
    fn delete(&mut self, p: &HostParams) -> Result<(), HostFail> {
        let pass = password(&p.password, "password")?;
        let Some(Secret(said)) = &p.words else {
            return Err(bad_params("words: missing"));
        };
        let secrets = self.profile_for_session(&pass)?;
        if !words_match(&secrets.seed, said)? {
            return Err(fail(-32051, "wrong_words", ""));
        }
        self.lock();
        session::forget(&self.places, &secrets.instance).map_err(|e| fail(-32049, "profile_io", &format!("{:?}", e.kind())))?;
        profile::remove(&self.places.profile)?;
        Ok(())
    }

    /// One request line in, one answer line out (empty for a notification).
    fn handle(&mut self, line: &str) -> Zeroizing<String> {
        let head: Head = match serde_json::from_str(line) {
            Ok(h) => h,
            Err(e) if e.is_data() => return answer(&Value::Null, Err(fail(-32600, "invalid_request", ""))),
            Err(_) => return answer(&Value::Null, Err(fail(-32700, "parse_error", ""))),
        };
        let id = head.id.unwrap_or(Value::Null);
        let valid_id = matches!(id, Value::Null | Value::Number(_) | Value::String(_));
        let (Some(method), true, Some("2.0")) = (head.method.as_deref(), valid_id, head.jsonrpc.as_deref()) else {
            return answer(&Value::Null, Err(fail(-32600, "invalid_request", "")));
        };
        if method.starts_with("host.") {
            return self.host_call(method, &id, line);
        }
        match &self.runner {
            None => answer(&id, Err(fail(-32040, "locked", ""))),
            Some(wallet) => match wallet.runner.call(line) {
                Ok(text) => Zeroizing::new(text),
                Err(RunnerError::Busy) => answer(&id, Err(fail(-32050, "busy", ""))),
                Err(RunnerError::Stopped) => answer(&id, Err(fail(-32040, "locked", ""))),
            },
        }
    }
}

/// Run the host: read requests from `input` until it ends, write answers
/// and notifications to `output`. `args` are the command-line arguments
/// after the program name. Returns the exit code of the process.
pub fn run<R, W>(setup: Setup, args: &[String], mut input: R, output: W) -> u8
where
    R: BufRead,
    W: Write + Send + 'static,
{
    let mut buf = Vec::new();
    let started = parse_args(args).and_then(|a| {
        let device_key = if a.device_key_first {
            let read = match read_line(&mut input, &mut buf, 512) {
                Ok(Line::Text) => device_key_line(&buf).map_err(str::to_string),
                _ => Err("the first line must be the device key".to_string()),
            };
            buf.zeroize();
            read?
        } else {
            None
        };
        places(a, &setup, device_key)
    });
    let places = match started {
        Ok(p) => p,
        Err(why) => {
            // the only thing ever written to standard error: a wrong start
            eprintln!("fly-paycore-host: {why}");
            return 2;
        }
    };
    let (lines, waiting) = mpsc::sync_channel::<Zeroizing<String>>(MAX_WAITING_OUTPUT);
    let dropped = Arc::new(AtomicU64::new(0));
    let missed = dropped.clone();
    let Ok(writer) = thread::Builder::new().name("host-output".into()).spawn(move || {
        let mut output = output;
        for line in waiting {
            let n = missed.swap(0, Ordering::SeqCst);
            if n > 0 {
                let note = json!({"jsonrpc": "2.0", "method": "host.events_dropped", "params": {"count": n}});
                if writeln!(output, "{note}").is_err() {
                    return;
                }
            }
            if writeln!(output, "{}", line.as_str()).is_err() || output.flush().is_err() {
                return;
            }
        }
    }) else {
        return 2;
    };
    let mut host = Host {
        setup,
        places,
        out: Out { lines, dropped },
        runner: None,
        report: Arc::new(Mutex::new(Report::default())),
        chain_report: Arc::new(Mutex::new(chain::ChainReport::default())),
    };
    // a little room beyond the largest request the core accepts
    let max = MAX_REQUEST_LEN.saturating_add(1024);
    let mut code = 0;
    loop {
        match read_line(&mut input, &mut buf, max) {
            Ok(Line::End) => break,
            Ok(Line::TooLong) => host
                .out
                .answer(answer(&Value::Null, Err(fail(-32600, "invalid_request", "too large")))),
            Ok(Line::Text) => {
                let reply = match std::str::from_utf8(&buf) {
                    Ok(text) if text.trim().is_empty() => Zeroizing::new(String::new()),
                    Ok(text) => host.handle(text),
                    Err(_) => answer(&Value::Null, Err(fail(-32700, "parse_error", ""))),
                };
                host.out.answer(reply);
            }
            Err(_) => {
                code = 1;
                break;
            }
        }
    }
    buf.zeroize();
    // the interface is gone: lock, let the last lines out, and end
    host.lock();
    drop(host);
    let _ = writer.join();
    code
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod device_key_tests {
    use super::device_key_line;

    fn line(key: &str) -> Vec<u8> {
        format!(r#"{{"jsonrpc":"2.0","method":"host.device_key","params":{{"key":"{key}"}}}}"#).into_bytes()
    }

    /// The first line of a host told to expect the device's key is that
    /// line and nothing else: 64 lower-case hex digits, or an empty key for
    /// a device that keeps none. A request, a key of another length or in
    /// other letters, a line with anything added - a wrong start. Read the
    /// same way on every system, though only Android gives the line.
    #[test]
    fn the_device_key_line_is_exactly_that_line() {
        let digits: String = (0u8..32).map(|byte| format!("{:02x}", byte.wrapping_mul(9).wrapping_add(1))).collect();
        let key = device_key_line(&line(&digits)).unwrap().unwrap();
        let expected: Vec<u8> = (0u8..32).map(|byte| byte.wrapping_mul(9).wrapping_add(1)).collect();
        assert_eq!(key.as_slice(), expected.as_slice());
        // a line ending the Windows way is the same line
        let mut windows = line(&digits);
        windows.push(b'\r');
        assert_eq!(device_key_line(&windows).unwrap().unwrap().as_slice(), expected.as_slice());
        assert!(device_key_line(&line("")).unwrap().is_none(), "a device with no key of its own");

        let spaced = String::from_utf8(line(&digits)).unwrap().replace("\"params\":", "\"params\": ").into_bytes();
        let mut trailing = line(&digits);
        trailing.extend_from_slice(b" ");
        let mut twice = line(&digits);
        twice.extend_from_slice(&line(&digits));
        let wrong: Vec<Vec<u8>> = vec![
            line(&digits[..62]),
            line(&format!("{digits}00")),
            line(&digits.to_uppercase().replace('0', "A")),
            line(&digits.replace('1', "g")),
            line(&format!("{}\\u0030", &digits[..58])),
            spaced,
            trailing,
            twice,
            br#"{"jsonrpc":"2.0","id":1,"method":"host.status","params":{}}"#.to_vec(),
            Vec::new(),
        ];
        for bad in wrong {
            assert!(device_key_line(&bad).is_err(), "{}", String::from_utf8_lossy(&bad));
        }
    }
}
