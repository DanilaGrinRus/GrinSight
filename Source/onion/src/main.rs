//! The Tor process of the wallet: payments to and from a Grin address.
//!
//! It is started by the wallet process and spoken to over its standard
//! input and output (`fly-paycore-onion-pipe`). It holds one secret, the
//! key of the wallet's address, because the onion service of that address
//! cannot be announced without it; the key is kept in memory only and is
//! never written to Tor's files. It carries bodies: a post to the onion
//! service of another address and its answer, and requests that arrive at
//! its own service with the answers the wallet gives. It reads none of
//! them and decides nothing.
//!
//! Tor's own files live in the directory it is given, one per wallet, so
//! two wallets on one computer do not touch each other's Tor. It opens no
//! port on this computer.
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

mod http;

use arti_client::config::{CfgPath, TorClientConfigBuilder};
use arti_client::{HasKind, TorClient};
use fly_paycore_onion_pipe as pipe;
use fly_paycore_onion_pipe::{Config, Event, Phase, State};
use fly_paycore_pipe_link::{read_frame, read_hello, write_failed, write_frame, write_ready};
use futures::StreamExt;
use safelog::DisplayRedacted;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tor_rtcompat::PreferredRuntime;

/// Longest wait for Tor to come up, once.
const BOOTSTRAP: Duration = Duration::from_secs(180);
/// Pause before Tor is tried again.
const RETRY: Duration = Duration::from_secs(30);
/// Longest a post may take, from the connection to the whole answer.
const POST_WITHIN: Duration = Duration::from_secs(120);
/// Longest wait for a request to arrive whole.
const REQUEST_WITHIN: Duration = Duration::from_secs(30);
/// Longest wait for the wallet's answer to a request.
const ANSWER_WITHIN: Duration = Duration::from_secs(75);
/// Posts under way at once.
const MAX_POSTS: usize = 4;
/// Connections to the service served at once.
const MAX_SERVED: usize = 8;
/// Requests waiting for the wallet at once.
const MAX_WAITING: usize = 8;
/// Outcomes of posts kept for the wallet to fetch.
const MAX_OUTCOMES: usize = 64;
/// Requests served over one connection: the version, the payment, and a spare.
const MAX_TURNS: usize = 4;

type Client = Arc<TorClient<PreferredRuntime>>;

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    events: Mutex<VecDeque<Event>>,
    waiting: Mutex<HashMap<u64, oneshot::Sender<String>>>,
    client: Mutex<Option<Client>>,
    next_id: AtomicU64,
    posts: AtomicUsize,
    served: AtomicUsize,
    seen: Mutex<Seen>,
}

/// What came to the wallet's address since the process started: counts
/// only, and the last port that was not the wallet's. Nothing of what a
/// request said is kept.
#[derive(Default, Clone, PartialEq, Eq, Debug)]
struct Seen {
    /// Requests handed to the wallet.
    taken: u32,
    /// Connections to another port than the wallet's, and the last such port.
    other_port: u32,
    last_port: u16,
    /// Connections that came and said nothing at all.
    silent: u32,
    /// The first line of the last request that was not a wallet's, cut short.
    last_line: String,
    /// Requests that were not a wallet's request, by what was wrong.
    not_wallet: u32,
    malformed: u32,
    too_large: u32,
    /// Connections that ended, or went silent, before a whole request came.
    cut_short: u32,
    /// Requests the wallet did not answer in time.
    unanswered: u32,
}

impl Seen {
    /// One line for the window; empty when nothing came.
    fn words(&self) -> String {
        let mut parts = Vec::new();
        fn say(parts: &mut Vec<String>, n: u32, what: &str) {
            if n > 0 {
                parts.push(format!("{n} {what}"));
            }
        }
        say(&mut parts, self.taken, "handed to the wallet");
        say(&mut parts, self.unanswered, "left without the wallet's answer");
        say(&mut parts, self.not_wallet, "not a wallet's request");
        if self.not_wallet > 0 && !self.last_line.is_empty() {
            parts.push(format!("the last of them began: {}", self.last_line));
        }
        say(&mut parts, self.silent, "silent");
        say(&mut parts, self.malformed, "malformed");
        say(&mut parts, self.too_large, "too large");
        say(&mut parts, self.cut_short, "cut short");
        if self.other_port > 0 {
            parts.push(format!("{} to another port (last: {})", self.other_port, self.last_port));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("came to the address: {}", parts.join(", "))
        }
    }
}

fn held<T>(slot: &Mutex<T>) -> MutexGuard<'_, T> {
    match slot.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl Shared {
    fn set(&self, phase: Phase, problem: &str) {
        *held(&self.state) = State { phase, problem: problem.to_string() };
    }
}

/// Counts something under way and gives the count back when it ends.
struct Slot<'a>(&'a AtomicUsize);
impl<'a> Slot<'a> {
    fn take(count: &'a AtomicUsize, max: usize) -> Option<Slot<'a>> {
        let mut seen = count.load(Ordering::SeqCst);
        loop {
            if seen >= max {
                return None;
            }
            let more = seen.checked_add(1)?;
            match count.compare_exchange(seen, more, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(Slot(count)),
                Err(now) => seen = now,
            }
        }
    }
}
impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut seen = self.0.load(Ordering::SeqCst);
        while let Some(less) = seen.checked_sub(1) {
            match self.0.compare_exchange(seen, less, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return,
                Err(now) => seen = now,
            }
        }
    }
}

fn not_a_link(path: &Path) -> Option<()> {
    let meta = std::fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return None;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return None;
        }
    }
    Some(())
}

fn child(parent: &Path, name: &str) -> Option<PathBuf> {
    let path = parent.join(name);
    match std::fs::create_dir(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return None,
    }
    not_a_link(&path)?;
    Some(path)
}

/// `tor/cache` and `tor/state` under the data directory, which has to
/// exist. Nothing here is a link to somewhere else.
fn storage(data_dir: &str) -> Option<(PathBuf, PathBuf)> {
    let given = Path::new(data_dir);
    not_a_link(given)?;
    let root = std::fs::canonicalize(given).ok()?;
    let tor = child(&root, "tor")?;
    Some((child(&tor, "cache")?, child(&tor, "state")?))
}

/// Drop what an earlier run of the onion service left in Tor's state: the
/// list of its introduction points. Their keys lived in that run's memory
/// and are gone with it; a service started over that list waits for keys
/// that will never come and is not announced. Every run starts the
/// service afresh.
fn forget_service(state: &Path) {
    let kept = state.join("hss");
    if not_a_link(&kept).is_some() {
        let _ = std::fs::remove_dir_all(&kept);
    }
}

/// The key of the address in the form the onion service is run with.
fn service_key(secret: &[u8; 32]) -> tor_hscrypto::pk::HsIdKeypair {
    let pair = tor_llcrypto::pk::ed25519::Keypair::from_bytes(secret);
    tor_hscrypto::pk::HsIdKeypair::from(tor_llcrypto::pk::ed25519::ExpandedKeypair::from(&pair))
}

/// The name of the onion service of an address key, `<56 characters>.onion`.
fn onion_name(key: &[u8; 32]) -> String {
    tor_hscrypto::pk::HsId::from(*key).display_unredacted().to_string()
}

/// What Tor is said to have failed with when the chosen bridges cannot be used.
const BRIDGES_UNUSABLE: &str = "the Tor bridges cannot be used";

async fn bring_up(cache: &Path, state: &Path, bridges: &str) -> Result<Client, &'static str> {
    // Tor bridges the user chose: with any, Tor is reached through them only, and
    // lines that cannot be used stop it here rather than let it go directly
    let chosen = fly_tor_bridges::TorBridges::parse(bridges).map_err(|_| BRIDGES_UNUSABLE)?;
    let mut config = TorClientConfigBuilder::default();
    // paths are taken as they are, never as Arti's variables
    config.storage().cache_dir(CfgPath::new_literal(cache)).state_dir(CfgPath::new_literal(state));
    // the keys of the onion service are kept in memory, not in a file
    config
        .storage()
        .keystore()
        .enabled(tor_config::BoolOrAuto::Explicit(true))
        .primary()
        .kind(tor_config::ExplicitOrAuto::Explicit(tor_keymgr::config::ArtiKeystoreKind::Ephemeral));
    chosen.apply(&mut config, &fly_tor_bridges::own_program()).map_err(|_| BRIDGES_UNUSABLE)?;
    let config = config.build().map_err(|_| if chosen.is_empty() { "Tor could not be set up" } else { BRIDGES_UNUSABLE })?;
    match tokio::time::timeout(BOOTSTRAP, TorClient::builder().config(config).create_bootstrapped()).await {
        Err(_) => Err("Tor took too long to come up"),
        Ok(Err(_)) => Err("Tor did not come up"),
        Ok(Ok(client)) => Ok(client),
    }
}

async fn post(client: Client, to: [u8; 32], body: String) -> Result<String, String> {
    let host = onion_name(&to);
    let work = async {
        let mut stream = client
            .connect((host.as_str(), 80))
            .await
            .map_err(|e| format!("Tor did not reach the wallet at this address ({})", e.kind()))?;
        let lost = |_| "the connection to the wallet was lost".to_string();
        stream.write_all(&http::request(&host, &body)).await.map_err(lost)?;
        stream.flush().await.map_err(lost)?;
        let mut data = Vec::new();
        let mut piece = vec![0u8; 16 * 1024];
        loop {
            let n = stream.read(&mut piece).await.map_err(lost)?;
            data.extend_from_slice(piece.get(..n).unwrap_or_default());
            match http::answer_body(&data, pipe::MAX_BODY, n == 0) {
                Ok(answer) => return Ok(answer),
                Err(http::Bad::Short) => {}
                Err(http::Bad::Other) => return Err("the wallet at this address refused the request".to_string()),
                Err(http::Bad::Large | http::Bad::Form) => return Err("the answer is not a wallet's answer".to_string()),
            }
        }
    };
    match tokio::time::timeout(POST_WITHIN, work).await {
        Ok(outcome) => outcome,
        Err(_) => Err("the wallet at this address did not answer in time".to_string()),
    }
}

async fn serve_one(shared: Arc<Shared>, request: tor_hsservice::StreamRequest) {
    use tor_proto::stream::IncomingStreamRequest;
    let port = match request.request() {
        IncomingStreamRequest::Begin(begin) => Some(begin.port()),
        _ => None,
    };
    let Some(_slot) = Slot::take(&shared.served, MAX_SERVED) else {
        return;
    };
    if port != Some(80) {
        let mut seen = held(&shared.seen);
        seen.other_port = seen.other_port.saturating_add(1);
        seen.last_port = port.unwrap_or(0);
        return;
    }
    let Ok(stream) = request.accept(tor_cell::relaycell::msg::Connected::new_empty()).await else {
        return;
    };
    talk(&shared, stream).await;
}

/// One connection to the wallet's port: requests read and answered one
/// after another, a bounded number of them.
async fn talk<S>(shared: &Shared, mut stream: S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let count = |pick: fn(&mut Seen) -> &mut u32| {
        let mut seen = held(&shared.seen);
        let n = pick(&mut seen);
        *n = n.saturating_add(1);
    };
    // a wallet may ask for the version and send the payment over one connection
    for turn in 0..MAX_TURNS {
        let read = async {
            let mut data = Vec::new();
            let mut piece = vec![0u8; 16 * 1024];
            loop {
                match http::request_body(&data, pipe::MAX_BODY) {
                    Ok(body) => return Ok(body),
                    Err(http::Bad::Short) => {}
                    Err(bad) => return Err((Some(bad), http::first_line(&data))),
                }
                match stream.read(&mut piece).await {
                    // the other side is done
                    Ok(0) | Err(_) => return Err((if data.is_empty() { None } else { Some(http::Bad::Short) }, String::new())),
                    Ok(n) => data.extend_from_slice(piece.get(..n).unwrap_or_default()),
                }
            }
        };
        let body = match tokio::time::timeout(REQUEST_WITHIN, read).await {
            Ok(Ok(body)) => body,
            // a connection that says nothing: after a served request that is its ordinary end
            Ok(Err((None, _))) => {
                if turn == 0 {
                    count(|s| &mut s.silent);
                }
                return;
            }
            Err(_) if turn > 0 => return,
            Ok(Err((Some(http::Bad::Short), _))) | Err(_) => {
                count(|s| &mut s.cut_short);
                return;
            }
            Ok(Err((Some(bad), line))) => {
                count(match bad {
                    http::Bad::Large => |s| &mut s.too_large,
                    http::Bad::Other => |s| &mut s.not_wallet,
                    _ => |s| &mut s.malformed,
                });
                if bad == http::Bad::Other {
                    held(&shared.seen).last_line = line;
                }
                let _ = stream.write_all(&http::refusal(bad)).await;
                let _ = stream.flush().await;
                return;
            }
        };
        let id = shared.next_id.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        let full = {
            let mut waiting = held(&shared.waiting);
            let full = waiting.len() >= MAX_WAITING;
            if !full {
                waiting.insert(id, tx);
            }
            full
        };
        if full {
            count(|s| &mut s.too_large);
            let _ = stream.write_all(&http::refusal(http::Bad::Large)).await;
            let _ = stream.flush().await;
            return;
        }
        count(|s| &mut s.taken);
        held(&shared.events).push_back(Event::Request { id, body });
        let answer = tokio::time::timeout(ANSWER_WITHIN, rx).await;
        held(&shared.waiting).remove(&id);
        let Ok(Ok(answer)) = answer else {
            // without an answer the connection just ends: the sender learns
            // nothing of why
            count(|s| &mut s.unanswered);
            return;
        };
        if stream.write_all(&http::answer(&answer)).await.is_err() || stream.flush().await.is_err() {
            return;
        }
    }
}

async fn listen(shared: Arc<Shared>, client: Client, key: tor_hscrypto::pk::HsIdKeypair) -> &'static str {
    use tor_hsservice::status::State as Service;
    let Ok(nickname) = tor_hsservice::HsNickname::new("wallet".to_string()) else {
        return "the onion service could not be set up";
    };
    let Ok(config) = tor_hsservice::config::OnionServiceConfigBuilder::default().nickname(nickname).build() else {
        return "the onion service could not be set up";
    };
    let Ok(Some((service, requests))) = client.launch_onion_service_with_hsid(config, key) else {
        return "the onion service could not be started";
    };
    let mut status = service.status_events();
    let mut requests = Box::pin(tor_hsservice::handle_rend_requests(requests));
    loop {
        tokio::select! {
            seen = status.next() => match seen.map(|s| s.state()) {
                Some(Service::Running | Service::DegradedReachable) => shared.set(Phase::Listening, ""),
                // "not launched" is also what a service says of itself
                // before its first step; its end is the end of the requests
                Some(Service::Bootstrapping | Service::Shutdown) => shared.set(Phase::Up, "the address is being announced in Tor"),
                None => return "the onion service stopped",
                Some(_) => shared.set(Phase::Up, "the address cannot be reached through Tor now"),
            },
            request = requests.next() => match request {
                Some(request) => {
                    tokio::spawn(serve_one(shared.clone(), request));
                }
                None => return "the onion service stopped",
            },
        }
    }
}

async fn run(shared: Arc<Shared>, mut config: Config) {
    let Some((cache, state)) = storage(&config.data_dir) else {
        shared.set(Phase::Failed, "the directory for Tor cannot be used");
        return;
    };
    // the key it is given must be the key of the address it is told
    let public = tor_llcrypto::pk::ed25519::Keypair::from_bytes(&config.secret).verifying_key().to_bytes();
    if public != config.public {
        fly_paycore_pipe_link::wipe(&mut config.secret);
        shared.set(Phase::Failed, "the key is not the key of the address");
        return;
    }
    let key = config.listen.then(|| service_key(&config.secret));
    fly_paycore_pipe_link::wipe(&mut config.secret);
    forget_service(&state);
    let mut key = key;
    loop {
        shared.set(Phase::Starting, "");
        match bring_up(&cache, &state, &config.tor_bridges).await {
            Err(why) => shared.set(Phase::Failed, why),
            Ok(client) => {
                *held(&shared.client) = Some(client.clone());
                shared.set(Phase::Up, "");
                match key.take() {
                    // payments are only sent: nothing more to do here
                    None => return std::future::pending().await,
                    Some(key) => {
                        let why = listen(shared.clone(), client, key).await;
                        // the key went into that service; a new process is
                        // started by the wallet for a new try
                        shared.set(Phase::Failed, why);
                        return;
                    }
                }
            }
        }
        tokio::time::sleep(RETRY).await;
    }
}

fn handle(shared: &Arc<Shared>, runtime: &tokio::runtime::Runtime, tag: u8, body: &[u8]) -> Option<(u8, Vec<u8>)> {
    let taken = |yes: bool| Some((pipe::TAKEN, vec![u8::from(yes)]));
    match tag {
        pipe::ASK_STATE => {
            let mut state = held(&shared.state).clone();
            // while the address listens there is no problem to tell: the place is used
            // for the count of what came to it
            if state.phase == Phase::Listening {
                state.problem = held(&shared.seen).words();
            }
            Some((pipe::STATE, pipe::encode_state(&state)))
        }
        pipe::POST => {
            let (ticket, to, text) = pipe::decode_post(body)?;
            let Some(client) = held(&shared.client).clone() else {
                return taken(false);
            };
            if shared.posts.load(Ordering::SeqCst) >= MAX_POSTS || held(&shared.events).len() >= MAX_OUTCOMES {
                return taken(false);
            }
            let shared = shared.clone();
            runtime.spawn(async move {
                let slot = Slot::take(&shared.posts, usize::MAX);
                let result = post(client, to, text).await;
                held(&shared.events).push_back(Event::Posted { ticket, result });
                drop(slot);
            });
            taken(true)
        }
        pipe::NEXT => {
            let event = held(&shared.events).pop_front();
            Some((pipe::EVENT, pipe::encode_event(event.as_ref())?))
        }
        pipe::ANSWER => {
            let (id, text) = pipe::decode_answer(body)?;
            let sent = match held(&shared.waiting).remove(&id) {
                Some(waiter) => waiter.send(text).is_ok(),
                None => false,
            };
            taken(sent)
        }
        _ => None,
    }
}

fn main() -> std::process::ExitCode {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let Ok(mut hello) = read_hello(&mut input, pipe::MAX_FRAME) else {
        return std::process::ExitCode::from(2);
    };
    let config = Config::decode(&hello);
    fly_paycore_pipe_link::wipe(&mut hello);
    let start = || -> Result<(Config, tokio::runtime::Runtime), &'static str> {
        let config = config.ok_or("the configuration is not one")?;
        // rustls has one provider for the whole process; Tor needs one
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            return Err("Tor could not be set up");
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("fly-onion")
            .enable_all()
            .build()
            .map_err(|_| "Tor could not be set up")?;
        Ok((config, runtime))
    };
    let (config, runtime) = match start() {
        Ok(started) => started,
        Err(why) => {
            let _ = write_failed(&mut output, why, pipe::MAX_FRAME);
            return std::process::ExitCode::from(2);
        }
    };
    if write_ready(&mut output, pipe::VERSION, pipe::MAX_FRAME).is_err() {
        return std::process::ExitCode::from(2);
    }
    let shared = Arc::new(Shared::default());
    shared.set(Phase::Starting, "");
    runtime.spawn(run(shared.clone(), config));
    // one request, one answer, until the wallet process is gone
    while let Ok(Some((tag, body))) = read_frame(&mut input, pipe::MAX_FRAME) {
        let Some((tag, answer)) = handle(&shared, &runtime, tag, &body) else {
            break;
        };
        if write_frame(&mut output, tag, &answer, pipe::MAX_FRAME).is_err() {
            break;
        }
    }
    // nothing of Tor outlives the conversation
    runtime.shutdown_timeout(Duration::from_secs(2));
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The onion service of an address is named by the address key alone:
    /// the example of the Tor specification (rend-spec-v3, appendix).
    #[test]
    fn the_onion_name_of_a_key() {
        let key: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3,
            0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];
        assert_eq!(onion_name(&key), "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion");
    }

    /// The service is run with the very key of the address: its public
    /// half is the address.
    #[test]
    fn the_service_key_is_the_address_key() {
        // RFC 8032, test 1
        let secret: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69,
            0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ];
        let public: [u8; 32] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3,
            0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
        ];
        let key = service_key(&secret);
        let id = tor_hscrypto::pk::HsId::from(tor_hscrypto::pk::HsIdKey::from(&key));
        assert_eq!(id, tor_hscrypto::pk::HsId::from(public));
    }

    #[test]
    fn what_is_under_way_is_counted_and_given_back() {
        let count = AtomicUsize::new(0);
        let a = Slot::take(&count, 2).unwrap();
        let b = Slot::take(&count, 2).unwrap();
        assert!(Slot::take(&count, 2).is_none());
        drop(a);
        assert!(Slot::take(&count, 2).is_some());
        drop(b);
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn tor_keeps_its_files_under_the_directory_it_is_given() {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let root = std::env::temp_dir().join(format!("fly-onion-{}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(&root).unwrap();
        let (cache, state) = storage(root.to_str().unwrap()).unwrap();
        let real = std::fs::canonicalize(&root).unwrap();
        assert_eq!((cache, state), (real.join("tor").join("cache"), real.join("tor").join("state")));
        assert!(storage(root.join("missing").to_str().unwrap()).is_none());
        let other = root.join("other");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("tor"), b"a file").unwrap();
        assert!(storage(other.to_str().unwrap()).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// One run of the process's inside: bring Tor up in `root`, announce
    /// the service of `secret`, post a question to it through the network
    /// and answer it. Returns how long the announcing took.
    /// With Tor bridges chosen, Tor is never reached round them: what
    /// cannot be used as bridges fails the start, and the reason is said.
    #[test]
    fn bridges_that_cannot_be_used_stop_tor_and_the_reason_is_said() {
        let obfs4 = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        // the third case holds where no program for bridges stands next to the test
        // program (the live run puts one there)
        let cases: &[&str] = if fly_tor_bridges::own_program().is_file() { &["not a bridge line", "unusable"] } else { &["not a bridge line", "unusable", obfs4] };
        for &chosen in cases {
            let root = std::env::temp_dir().join(format!("fly-onion-bridges-{}-{}", std::process::id(), chosen.len()));
            std::fs::create_dir_all(&root).unwrap();
            let began = std::time::Instant::now();
            let got = runtime.block_on(bring_up(&root.join("cache"), &root.join("state"), chosen));
            assert_eq!(got.err(), Some("the Tor bridges cannot be used"), "{chosen}");
            assert!(began.elapsed() < Duration::from_secs(5));
            assert!(!root.join("cache").join("dir.sqlite3").exists());
        }
    }

    fn live_run(root: &Path, secret: [u8; 32], public: [u8; 32]) -> Duration {
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let shared = Arc::new(Shared::default());
        // `FLY_LIVE_BRIDGES` names a file of bridge lines: then the whole run goes through
        // them. The program for them is looked for next to this one, as in a package;
        // `FLY_LIVE_PT` names the program to put there for the run.
        let tor_bridges = std::env::var("FLY_LIVE_BRIDGES").map(|file| std::fs::read_to_string(file).unwrap()).unwrap_or_default();
        if let Ok(program) = std::env::var("FLY_LIVE_PT") {
            let beside = fly_tor_bridges::own_program();
            if !beside.is_file() {
                std::fs::copy(program, &beside).unwrap();
            }
        }
        println!("bridges given: {}", fly_tor_bridges::TorBridges::parse(&tor_bridges).unwrap().len());
        runtime.spawn(run(shared.clone(), Config { secret, public, data_dir: root.to_str().unwrap().to_string(), listen: true, tor_bridges }));
        let started = std::time::Instant::now();
        while held(&shared.state).phase != Phase::Listening {
            assert!(started.elapsed() < Duration::from_secs(400), "{:?}", held(&shared.state));
            std::thread::sleep(Duration::from_secs(1));
        }
        let announced = started.elapsed();
        eprintln!("listening after {announced:?}");
        // a freshly announced service can take a moment to be found
        let mut answer = None;
        for attempt in 0..6 {
            let post = encode(&[9; 16], &public, "{\"question\":1}");
            assert_eq!(handle(&shared, &runtime, pipe::POST, &post), Some((pipe::TAKEN, vec![1])));
            let until = std::time::Instant::now().checked_add(Duration::from_secs(150)).unwrap();
            let mut outcome = None;
            while outcome.is_none() && std::time::Instant::now() < until {
                std::thread::sleep(Duration::from_millis(300));
                let (_, wire) = handle(&shared, &runtime, pipe::NEXT, &[]).unwrap();
                match pipe::decode_event(&wire).unwrap() {
                    Some(Event::Request { id, body }) => {
                        assert_eq!(body, "{\"question\":1}");
                        let wire = pipe::encode_answer(id, "{\"answer\":2}").unwrap();
                        assert_eq!(handle(&shared, &runtime, pipe::ANSWER, &wire), Some((pipe::TAKEN, vec![1])));
                    }
                    Some(Event::Posted { ticket, result }) => {
                        assert_eq!(ticket, [9; 16]);
                        outcome = Some(result);
                    }
                    None => {}
                }
            }
            eprintln!("attempt {attempt}: {outcome:?} after {:?}", started.elapsed());
            if let Some(Ok(body)) = outcome {
                answer = Some(body);
                break;
            }
        }
        assert_eq!(answer.as_deref(), Some("{\"answer\":2}"));
        runtime.shutdown_timeout(Duration::from_secs(5));
        announced
    }

    /// The wallet is opened, closed and opened again: the second run finds
    /// the Tor directory of the first and has to announce the address
    /// just the same.
    /// What came to the address is told in counts, and only when something came.
    #[test]
    fn what_came_to_the_address_is_counted_and_said_in_one_line() {
        assert_eq!(Seen::default().words(), "");
        let seen = Seen { taken: 2, other_port: 3, last_port: 443, not_wallet: 1, cut_short: 4, ..Seen::default() };
        assert_eq!(seen.words(), "came to the address: 2 handed to the wallet, 1 not a wallet's request, 4 cut short, 3 to another port (last: 443)");
        let knocked = Seen { not_wallet: 2, silent: 5, last_line: "GET / HTTP/1.1".into(), ..Seen::default() };
        assert_eq!(knocked.words(), "came to the address: 2 not a wallet's request, the last of them began: GET / HTTP/1.1, 5 silent");
        let quiet = Seen { unanswered: 1, malformed: 1, too_large: 1, ..Seen::default() };
        assert_eq!(quiet.words(), "came to the address: 1 left without the wallet's answer, 1 malformed, 1 too large");
    }

    /// A sender may ask for the version and send the payment over one
    /// connection: each request is handed to the wallet and answered in
    /// its turn, and the connection is not served without end.
    #[test]
    fn requests_over_one_connection_are_answered_in_turn_and_not_without_end() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
        let Ok(runtime) = runtime else {
            assert!(runtime.is_ok());
            return;
        };
        runtime.block_on(async {
            let shared = Arc::new(Shared::default());
            let (mut sender, ours) = tokio::io::duplex(64 * 1024);
            let serving = tokio::spawn({
                let shared = shared.clone();
                async move { talk(&shared, ours).await }
            });
            // the wallet: answers every request with its own body turned round
            let wallet = tokio::spawn({
                let shared = shared.clone();
                async move {
                    loop {
                        let event = held(&shared.events).pop_front();
                        if let Some(Event::Request { id, body }) = event {
                            if let Some(tx) = held(&shared.waiting).remove(&id) {
                                let _ = tx.send(format!("answer to {body}"));
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                }
            });
            let mut answered = 0usize;
            for n in 0..MAX_TURNS.saturating_add(2) {
                let body = format!("{{\"n\":{n}}}");
                if sender.write_all(&http::request("abc.onion", &body)).await.is_err() {
                    break;
                }
                let expected = http::answer(&format!("answer to {body}"));
                let mut got = vec![0u8; expected.len()];
                match tokio::time::timeout(Duration::from_secs(5), sender.read_exact(&mut got)).await {
                    Ok(Ok(_)) => {
                        assert_eq!(got, expected, "{n}");
                        answered = answered.saturating_add(1);
                    }
                    _ => break,
                }
            }
            // every one up to the bound, and none after it
            assert_eq!(answered, MAX_TURNS);
            assert!(tokio::time::timeout(Duration::from_secs(5), serving).await.is_ok());
            wallet.abort();
            let seen = held(&shared.seen).clone();
            assert_eq!(seen, Seen { taken: 4, ..Seen::default() });
        });
    }

    /// What is not a wallet's request is refused, counted, and ends the
    /// connection; only its first line is kept, and nothing reaches the wallet.
    #[test]
    fn what_is_not_a_wallets_request_is_refused_counted_and_goes_no_further() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build();
        let Ok(runtime) = runtime else {
            assert!(runtime.is_ok());
            return;
        };
        runtime.block_on(async {
            let shared = Arc::new(Shared::default());
            let (mut sender, ours) = tokio::io::duplex(64 * 1024);
            let serving = tokio::spawn({
                let shared = shared.clone();
                async move { talk(&shared, ours).await }
            });
            let knock = b"GET /secret-looking/path HTTP/1.1\r\nHost: x\r\nCookie: do-not-keep\r\nContent-Length: 0\r\n\r\n";
            assert!(sender.write_all(knock).await.is_ok());
            let mut got = Vec::new();
            let read = tokio::time::timeout(Duration::from_secs(5), sender.read_to_end(&mut got)).await;
            assert!(matches!(read, Ok(Ok(_))));
            assert_eq!(got, http::refusal(http::Bad::Other));
            assert!(tokio::time::timeout(Duration::from_secs(5), serving).await.is_ok());
            assert!(held(&shared.events).is_empty());
            let seen = held(&shared.seen).clone();
            assert_eq!(seen, Seen { not_wallet: 1, last_line: "GET /secret-looking/path HTTP/1.1".into(), ..Seen::default() });
            assert!(!seen.words().contains("do-not-keep"));
            // and a connection that says nothing is counted as silent
            let (sender, ours) = tokio::io::duplex(1024);
            drop(sender);
            talk(&shared, ours).await;
            assert_eq!(held(&shared.seen).silent, 1);
        });
    }

    /// The count takes the place of the problem only while the address
    /// listens: a failure keeps its own words.
    #[test]
    fn the_count_is_said_only_while_the_address_listens() {
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread().build() else {
            return;
        };
        let shared = Arc::new(Shared::default());
        held(&shared.seen).taken = 3;
        let state = |shared: &Arc<Shared>| handle(shared, &runtime, pipe::ASK_STATE, &[]).and_then(|(_, wire)| pipe::decode_state(&wire));
        shared.set(Phase::Failed, "Tor did not come up");
        assert_eq!(state(&shared).map(|s| s.problem), Some("Tor did not come up".to_string()));
        shared.set(Phase::Listening, "");
        assert_eq!(state(&shared).map(|s| s.problem), Some("came to the address: 3 handed to the wallet".to_string()));
    }

    /// Asks the wallet whose address key is `FLY_ASK_KEY` (64 hex digits)
    /// for its version through Tor, from a Tor of this test's own: whether
    /// an open wallet can be reached from outside its own process.
    #[test]
    #[ignore = "uses the Tor network"]
    fn ask_a_wallet_for_its_version_through_tor() {
        assert_eq!(std::env::var("FLY_ALLOW_TOR").as_deref(), Ok("1"));
        let hex = std::env::var("FLY_ASK_KEY").unwrap();
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        println!("asking {}", onion_name(&key));
        let root = std::env::temp_dir().join(format!("fly-onion-ask-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let runtime = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        let client = runtime.block_on(bring_up(&root.join("cache"), &root.join("state"), "")).unwrap();
        let body = r#"{"jsonrpc":"2.0","method":"check_version","id":1,"params":[]}"#;
        let mut reached = false;
        for attempt in 0..4 {
            let started = std::time::Instant::now();
            let outcome = runtime.block_on(post(client.clone(), key, body.to_string()));
            println!("ask {attempt}: {outcome:?} after {:?}", started.elapsed());
            if outcome.is_ok() {
                reached = true;
                break;
            }
        }
        assert!(reached, "the wallet was not reached");
    }

    #[test]
    #[ignore = "uses the Tor network"]
    fn live_a_wallet_answers_itself_through_tor() {
        assert_eq!(std::env::var("FLY_ALLOW_TOR").as_deref(), Ok("1"));
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).unwrap();
        let public = tor_llcrypto::pk::ed25519::Keypair::from_bytes(&secret).verifying_key().to_bytes();
        let root = std::env::temp_dir().join(format!("fly-onion-live-{}", u64::from_le_bytes(secret.first_chunk::<8>().copied().unwrap())));
        std::fs::create_dir_all(&root).unwrap();
        let first = live_run(&root, secret, public);
        eprintln!("--- the same directory again");
        let second = live_run(&root, secret, public);
        eprintln!("announced in {first:?}, then in {second:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn what_an_earlier_run_left_of_the_service_is_dropped() {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let state = std::env::temp_dir().join(format!("fly-onion-forget-{}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(state.join("hss").join("wallet")).unwrap();
        std::fs::write(state.join("hss").join("wallet").join("ipts.json"), b"{}").unwrap();
        std::fs::write(state.join("guards.json"), b"{}").unwrap();
        forget_service(&state);
        assert!(!state.join("hss").exists());
        // the rest of Tor's state stays
        assert!(state.join("guards.json").exists());
        // nothing to drop is no trouble
        forget_service(&state);
        let _ = std::fs::remove_dir_all(&state);
    }

    fn encode(ticket: &[u8; 16], to: &[u8; 32], body: &str) -> Vec<u8> {
        pipe::encode_post(ticket, to, body).unwrap()
    }
}
