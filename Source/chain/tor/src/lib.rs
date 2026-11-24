//! Tor for the chain process.
//!
//! The chain process sends the wallet's transactions through Tor, so that
//! the node that takes a transaction first does not see the address of the
//! computer it came from. Everything else the chain process does - headers,
//! state, blocks, the question to public nodes - goes on as before.
//!
//! The code that speaks to a node - TLS for a public node's API, the
//! node's own network code for a stem transaction - works on an ordinary
//! TCP connection. A [`Bridge`] gives it one: the stream through Tor is
//! opened first, then a listener on this computer's loopback address takes
//! exactly one connection and passes bytes both ways between the two.
//!
//! What the bridge does not hide:
//!
//! * another program on this computer can connect to the listener in the
//!   moment between it being opened and the caller connecting. It then
//!   holds a stream to the node the caller meant, and the caller's own
//!   connection fails. Nothing the caller would have sent reaches it: the
//!   bytes go nowhere until the caller writes them. TLS to a public node
//!   is end to end; the node's own network code is not encrypted, but a
//!   stem transaction is meant for the network anyway.
//! * the exit relay of Tor sees what goes to the node, as the node does;
//!   for TLS that is only the name of the server.
//!
//! There is no fallback: if Tor cannot be brought up or cannot reach a
//! node, the caller is told so and nothing is sent any other way.
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

use arti_client::config::{CfgPath, TorClientConfigBuilder};
use arti_client::{ErrorKind, HasKind, TorClient};
pub use fly_tor_bridges::{own_program, TorBridges};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::Runtime;
use tor_rtcompat::PreferredRuntime;

/// The longest any one wait may be.
pub const MAX_WAIT: Duration = Duration::from_secs(300);
/// How long a bridge waits for the caller to connect.
pub const ACCEPT_WITHIN: Duration = Duration::from_secs(10);
/// Name of the directory Tor keeps its state in, inside the data directory.
pub const DIR: &str = "tor";

/// Why Tor did not do what was asked. The words name no host, address or
/// path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TorError {
    /// The directory for Tor's state cannot be used.
    Storage,
    /// The destination is not a name or address Tor may be asked for.
    Destination,
    /// A wait of zero or longer than [`MAX_WAIT`].
    Wait,
    /// Tor or its runtime could not be set up.
    Setup,
    /// Tor did not come up.
    Bootstrap,
    /// Tor did not reach the destination; what Tor said, in its own
    /// words, which name nothing of the destination.
    Connect(ErrorKind),
    /// The time ran out.
    Late,
    /// The listener on this computer could not be opened.
    Local,
    /// Tor bridges are asked for and cannot be used: a line is not a
    /// bridge line, or the program for them is not next to this one.
    Bridges,
}

impl fmt::Display for TorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let words = match self {
            TorError::Storage => "the directory for Tor cannot be used",
            TorError::Destination => "not a destination Tor is asked for",
            TorError::Wait => "a wait out of bounds",
            TorError::Setup => "Tor could not be set up",
            TorError::Bootstrap => "Tor did not come up",
            TorError::Connect(kind) => return write!(f, "Tor did not reach the node ({kind})"),
            TorError::Late => "Tor took too long",
            TorError::Local => "no listener could be opened on this computer",
            TorError::Bridges => "the Tor bridges cannot be used",
        };
        f.write_str(words)
    }
}

impl std::error::Error for TorError {}

fn bounded(wait: Duration) -> Result<Duration, TorError> {
    if wait.is_zero() || wait > MAX_WAIT {
        Err(TorError::Wait)
    } else {
        Ok(wait)
    }
}

fn not_a_link(meta: &std::fs::Metadata) -> Result<(), TorError> {
    // a file in the place of a directory fails as soon as something is
    // made inside it
    if meta.file_type().is_symlink() {
        return Err(TorError::Storage);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // a reparse point: a junction or a link
        if meta.file_attributes() & 0x400 != 0 {
            return Err(TorError::Storage);
        }
    }
    Ok(())
}

fn child(parent: &Path, name: &str) -> Result<PathBuf, TorError> {
    let path = parent.join(name);
    match std::fs::create_dir(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(TorError::Storage),
    }
    not_a_link(&std::fs::symlink_metadata(&path).map_err(|_| TorError::Storage)?)?;
    Ok(path)
}

/// The directories Tor keeps its cache and its state in: `tor/cache` and
/// `tor/state` under `data_dir`, which has to exist and be a directory.
pub fn storage(data_dir: &Path) -> Result<(PathBuf, PathBuf), TorError> {
    not_a_link(&std::fs::symlink_metadata(data_dir).map_err(|_| TorError::Storage)?)?;
    let root = std::fs::canonicalize(data_dir).map_err(|_| TorError::Storage)?;
    let tor = child(&root, DIR)?;
    Ok((child(&tor, "cache")?, child(&tor, "state")?))
}

/// What Tor is asked to connect to: a domain name, which Tor resolves, or
/// a public address. Nothing else: no address of this computer or of a
/// home network, no URL, no port inside the name.
pub fn destination(host: &str, port: u16) -> Result<String, TorError> {
    if port == 0 || host.is_empty() || host.len() > 253 {
        return Err(TorError::Destination);
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return if public(ip) { Ok(ip.to_string()) } else { Err(TorError::Destination) };
    }
    // the parser of hosts refuses what a name cannot hold: '/', ':', '@',
    // '#', '?', '\\', brackets, spaces, control characters
    match url::Host::parse(host).map_err(|_| TorError::Destination)? {
        url::Host::Domain(name) if !name.is_empty() && name != "localhost" && !name.ends_with(".localhost") => Ok(name),
        _ => Err(TorError::Destination),
    }
}

/// Whether an address is one a node on the internet can have.
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_multicast()
                || a == 0
                // shared address space and the space for benchmarks
                || (a == 100 && (64..128).contains(&b))
                || (a == 198 && (b == 18 || b == 19))
                || a >= 240)
        }
        IpAddr::V6(v6) => {
            let [first, second, ..] = v6.segments();
            !(v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                // unique local and link local
                || (first & 0xfe00) == 0xfc00
                || (first & 0xffc0) == 0xfe80
                // documentation
                || (first == 0x2001 && second == 0x0db8)
                || v6.to_ipv4_mapped().is_some())
        }
    }
}

/// One embedded Tor client with a runtime of its own. Made once per data
/// directory; whoever makes it makes sure there is only one.
pub struct Tor {
    runtime: Runtime,
    client: Arc<TorClient<PreferredRuntime>>,
}

impl fmt::Debug for Tor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tor")
    }
}

impl Tor {
    /// Bring Tor up, keeping its state under `data_dir`, and wait for it no
    /// longer than `within`. Blocks; not to be called from inside a Tokio
    /// runtime.
    pub fn start(data_dir: &Path, within: Duration) -> Result<Tor, TorError> {
        Tor::start_through(data_dir, within, &TorBridges::none(), Path::new(""))
    }

    /// As [`Tor::start`], reaching Tor through `bridges` when there are
    /// any: through them only, never directly. `program` is the pluggable
    /// transport program the bridges may need.
    pub fn start_through(data_dir: &Path, within: Duration, bridges: &TorBridges, program: &Path) -> Result<Tor, TorError> {
        let within = bounded(within)?;
        // rustls has one provider for the whole process; Tor needs one
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            return Err(TorError::Setup);
        }
        let (cache, state) = storage(data_dir)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("fly-chain-tor")
            .enable_all()
            .build()
            .map_err(|_| TorError::Setup)?;
        let mut config = TorClientConfigBuilder::default();
        // paths are taken as they are, never as Arti's variables
        config.storage().cache_dir(CfgPath::new_literal(cache)).state_dir(CfgPath::new_literal(state));
        bridges.apply(&mut config, program).map_err(|_| TorError::Bridges)?;
        let config = config.build().map_err(|_| if bridges.is_empty() { TorError::Setup } else { TorError::Bridges })?;
        let client = runtime.block_on(async {
            tokio::time::timeout(within, TorClient::builder().config(config).create_bootstrapped())
                .await
                .map_err(|_| TorError::Late)?
                .map_err(|_| TorError::Bootstrap)
        })?;
        Ok(Tor {
            runtime,
            client,
        })
    }

    /// Open a stream through Tor to `host` at `port`, waiting no longer
    /// than `within`, and a listener on this computer for it. See
    /// [`Bridge`].
    pub fn bridge(&self, host: &str, port: u16, within: Duration) -> Result<Bridge, TorError> {
        let within = bounded(within)?;
        let target = destination(host, port)?;
        let client = self.client.clone();
        let stream = self.runtime.block_on(async move {
            tokio::time::timeout(within, client.connect((target.as_str(), port)))
                .await
                .map_err(|_| TorError::Late)?
                .map_err(|e| TorError::Connect(e.kind()))
        })?;
        let listener = self.runtime.block_on(tokio::net::TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0)));
        let listener = listener.map_err(|_| TorError::Local)?;
        let at = listener.local_addr().map_err(|_| TorError::Local)?;
        self.runtime.spawn(async move {
            // one connection, and only for so long
            let Ok(Ok((mut local, _))) = tokio::time::timeout(ACCEPT_WITHIN, listener.accept()).await else {
                return;
            };
            drop(listener);
            let mut stream = stream;
            let _ = tokio::io::copy_bidirectional(&mut local, &mut stream).await;
        });
        Ok(Bridge { at })
    }
}

/// A listener on this computer's loopback address that takes one
/// connection, within [`ACCEPT_WITHIN`], and passes it on through Tor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bridge {
    /// Where to connect.
    pub at: SocketAddr,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn what_tor_is_asked_for() {
        assert_eq!(destination("api.grin.money", 443), Ok("api.grin.money".into()));
        assert_eq!(destination("Main.Grin.Raubritter.org", 443), Ok("main.grin.raubritter.org".into()));
        assert_eq!(destination("5.9.10.11", 3414), Ok("5.9.10.11".into()));
        assert_eq!(destination("2a01:4f8::1", 3414), Ok("2a01:4f8::1".into()));
        for bad in [
            "", "localhost", "node.localhost", "127.0.0.1", "10.0.0.5", "192.168.1.5", "172.16.0.1", "169.254.1.1",
            "100.64.0.1", "0.1.2.3", "224.0.0.1", "255.255.255.255", "198.18.0.1", "203.0.113.5", "::1", "fe80::1",
            "fd00::1", "::ffff:10.0.0.1", "2001:db8::1", "[2a01:4f8::1]", "host:443", "https://api.grin.money",
            "user@host", "host/path", "a b", "host\\bad", "host?x", "line\nbreak",
        ] {
            assert_eq!(destination(bad, 443), Err(TorError::Destination), "{bad}");
        }
        assert_eq!(destination("api.grin.money", 0), Err(TorError::Destination));
        assert_eq!(destination(&"a".repeat(254), 443), Err(TorError::Destination));
    }

    #[test]
    fn waits_are_bounded() {
        assert_eq!(bounded(Duration::ZERO), Err(TorError::Wait));
        assert_eq!(bounded(MAX_WAIT + Duration::from_secs(1)), Err(TorError::Wait));
        assert_eq!(bounded(MAX_WAIT), Ok(MAX_WAIT));
    }

    fn temp(tag: &str) -> PathBuf {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let p = std::env::temp_dir().join(format!("fly-chain-tor-{tag}-{}", u64::from_le_bytes(r)));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn tor_keeps_its_state_under_the_data_directory() {
        let root = temp("storage");
        let (cache, state) = storage(&root).unwrap();
        let real = std::fs::canonicalize(&root).unwrap();
        assert_eq!((cache.clone(), state.clone()), (real.join(DIR).join("cache"), real.join(DIR).join("state")));
        // again: the same, nothing changes
        assert_eq!(storage(&root).unwrap(), (cache, state));
        // a file where the directory should be
        let other = temp("file");
        std::fs::write(other.join(DIR), b"not a directory").unwrap();
        assert_eq!(storage(&other), Err(TorError::Storage));
        // a data directory that is not there
        assert_eq!(storage(&other.join("missing")), Err(TorError::Storage));
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&other);
    }

    #[test]
    fn the_words_name_nothing_of_the_destination() {
        for e in [
            TorError::Storage, TorError::Destination, TorError::Wait, TorError::Setup, TorError::Bootstrap,
            TorError::Connect(ErrorKind::ExitPolicyRejected), TorError::Connect(ErrorKind::RemoteConnectionRefused),
            TorError::Late, TorError::Local, TorError::Bridges,
        ] {
            let words = e.to_string();
            assert!(!words.is_empty() && !words.contains('.') && !words.contains(':'), "{words}");
        }
        // what Tor said is passed on: the reason a node is not reached
        assert_eq!(TorError::Connect(ErrorKind::ExitPolicyRejected).to_string(), "Tor did not reach the node (rejected by exit policy)");
    }

    /// Only with `FLY_ALLOW_TOR=1`: Tor relays see this computer's address.
    #[test]
    #[ignore = "uses the Tor network"]
    fn live_a_bridge_through_tor() {
        use std::io::{Read, Write};
        assert_eq!(std::env::var("FLY_ALLOW_TOR").as_deref(), Ok("1"));
        let root = temp("live");
        let tor = Tor::start(&root, Duration::from_secs(120)).unwrap();
        let bridge = tor.bridge("example.com", 80, Duration::from_secs(60)).unwrap();
        let mut local = std::net::TcpStream::connect(bridge.at).unwrap();
        local.write_all(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").unwrap();
        let mut answer = Vec::new();
        local.read_to_end(&mut answer).unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 "));
        // one connection only
        assert!(std::net::TcpStream::connect_timeout(&bridge.at, Duration::from_secs(1)).is_err());
    }

    #[test]
    fn bridges_that_cannot_be_used_stop_tor_before_it_starts() {
        let line = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";
        let bridges = TorBridges::parse(line).unwrap();
        let root = temp("no-program");
        // the program for the transport is not there: nothing connects,
        // and Tor is not reached directly instead
        let started = std::time::Instant::now();
        let got = Tor::start_through(&root, Duration::from_secs(60), &bridges, &root.join("missing").join("lyrebird"));
        assert_eq!(got.err(), Some(TorError::Bridges));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!root.join(DIR).join("cache").join("dir.sqlite3").exists());
    }

    /// Only with `FLY_ALLOW_TOR=1`. `FLY_LIVE_BRIDGES` names a file of
    /// bridge lines, `FLY_LIVE_PT` the pluggable transport program.
    #[test]
    #[ignore = "uses the Tor network through bridges"]
    fn live_tor_comes_up_through_bridges() {
        use std::io::{Read, Write};
        assert_eq!(std::env::var("FLY_ALLOW_TOR").as_deref(), Ok("1"));
        let lines = std::fs::read_to_string(std::env::var("FLY_LIVE_BRIDGES").unwrap()).unwrap();
        let bridges = TorBridges::parse(&lines).unwrap();
        assert!(!bridges.is_empty());
        let program = PathBuf::from(std::env::var("FLY_LIVE_PT").unwrap());
        let root = temp("live-bridges");
        let started = std::time::Instant::now();
        let tor = Tor::start_through(&root, Duration::from_secs(280), &bridges, &program).unwrap();
        println!("Tor came up through {} bridges ({:?}) in {} s", bridges.len(), bridges.transports(), started.elapsed().as_secs());
        let bridge = tor.bridge("example.com", 80, Duration::from_secs(90)).unwrap();
        let mut local = std::net::TcpStream::connect(bridge.at).unwrap();
        local.write_all(b"HEAD / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").unwrap();
        let mut answer = Vec::new();
        local.read_to_end(&mut answer).unwrap();
        assert!(answer.starts_with(b"HTTP/1.1 "));
        println!("a page came back through the bridges after {} s", started.elapsed().as_secs());
    }
}
