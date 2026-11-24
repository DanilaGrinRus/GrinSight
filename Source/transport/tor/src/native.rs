use arti_client::config::{CfgPath, TorClientConfigBuilder};
use arti_client::{DataStream, TorClient};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tor_rtcompat::PreferredRuntime;
use url::Host;

/// Coarse errors intentionally omit hostnames, paths, proxy details and keys.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TorError {
    InvalidStorage,
    InvalidDestination,
    InvalidTimeout,
    Config,
    Bootstrap,
    Connect,
    Deadline,
    /// Tor bridges are asked for and cannot be used.
    Bridges,
}

impl std::fmt::Display for TorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Tor operation failed: {self:?}")
    }
}

impl std::error::Error for TorError {}

/// An explicitly owned client which can be cloned by Nostr, HTTP and wallet
/// components. Each clone uses the same TorClient; this type never opens a
/// direct socket. The application must create only one instance per storage.
#[derive(Clone)]
pub struct SharedTor {
    client: Arc<TorClient<PreferredRuntime>>,
}

impl std::fmt::Debug for SharedTor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedTor { redacted }")
    }
}

const MAX_WAIT: Duration = Duration::from_secs(300);

fn checked_timeout(timeout: Duration) -> Result<Duration, TorError> {
    if timeout.is_zero() || timeout > MAX_WAIT {
        Err(TorError::InvalidTimeout)
    } else {
        Ok(timeout)
    }
}

fn reject_link(meta: &std::fs::Metadata) -> Result<(), TorError> {
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(TorError::InvalidStorage);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(TorError::InvalidStorage);
        }
    }
    Ok(())
}

fn checked_child(parent: &Path, name: &str) -> Result<PathBuf, TorError> {
    let child = parent.join(name);
    match std::fs::create_dir(&child) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(_) => return Err(TorError::InvalidStorage),
    }
    reject_link(&std::fs::symlink_metadata(&child).map_err(|_| TorError::InvalidStorage)?)?;
    Ok(child)
}

/// Only these directories are created beneath the caller's existing Fly data
/// root. Parent replacement and ancestor reparse points are not prevented; the
/// caller must supply a trusted stable path. Never pass a user wallet path.
fn storage_paths(root: &Path) -> Result<(PathBuf, PathBuf), TorError> {
    reject_link(&std::fs::symlink_metadata(root).map_err(|_| TorError::InvalidStorage)?)?;
    let root = std::fs::canonicalize(root).map_err(|_| TorError::InvalidStorage)?;
    let tor = checked_child(&root, "tor")?;
    Ok((checked_child(&tor, "cache")?, checked_child(&tor, "state")?))
}

// A literal PathBuf must never be interpreted as an Arti variable or shell
// expression. This also avoids losing non-UTF-8 paths during configuration.
fn literal_storage_paths(cache: &Path, state: &Path) -> (CfgPath, CfgPath) {
    (CfgPath::new_literal(cache), CfgPath::new_literal(state))
}

/// Destination parsing does not resolve DNS locally. IP literals, credentials,
/// ports embedded in host, URLs, whitespace and invalid names are refused.
fn domain(host: &str, port: u16) -> Result<String, TorError> {
    if port == 0
        || host.is_empty()
        || host.len() > 253
        || host.bytes().any(|b| b.is_ascii_whitespace())
        || host
            .chars()
            .any(|c| matches!(c, '/' | ':' | '@' | '#' | '?' | '\\'))
    {
        return Err(TorError::InvalidDestination);
    }
    match Host::parse(host).map_err(|_| TorError::InvalidDestination)? {
        Host::Domain(name) if !name.is_empty() => Ok(name),
        _ => Err(TorError::InvalidDestination),
    }
}

impl SharedTor {
    /// Bootstrap one embedded Arti client. Failure or timeout is returned; no
    /// fallback connection is attempted. Must run inside a Tokio runtime.
    pub async fn bootstrap(fly_data_root: &Path, timeout: Duration) -> Result<Self, TorError> {
        Self::bootstrap_through(fly_data_root, timeout, "").await
    }

    /// As [`SharedTor::bootstrap`], reaching Tor through the bridges of
    /// `bridges` (bridge lines, one a line) when there are any: through
    /// them only, never directly. Lines that cannot be used, or a transport
    /// whose program is not next to this one, stop Tor before it connects.
    pub async fn bootstrap_through(fly_data_root: &Path, timeout: Duration, bridges: &str) -> Result<Self, TorError> {
        let chosen = fly_tor_bridges::TorBridges::parse(bridges).map_err(|_| TorError::Bridges)?;
        let timeout = checked_timeout(timeout)?;
        // Rustls has a process-wide provider. Install ring explicitly if the
        // application has not selected one; another initializer may win the
        // race, in which case the installed provider is used. This prevents
        // Arti's TLS setup from panicking when no provider was configured.
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            return Err(TorError::Config);
        }
        let (cache, state) = storage_paths(fly_data_root)?;
        let (cache, state) = literal_storage_paths(&cache, &state);
        let mut builder = TorClientConfigBuilder::default();
        builder.address_filter().allow_onion_addrs(true);
        builder.storage().cache_dir(cache).state_dir(state);
        chosen.apply(&mut builder, &fly_tor_bridges::own_program()).map_err(|_| TorError::Bridges)?;
        let config = builder.build().map_err(|_| if chosen.is_empty() { TorError::Config } else { TorError::Bridges })?;
        let client = tokio::time::timeout(
            timeout,
            TorClient::builder().config(config).create_bootstrapped(),
        )
        .await
        .map_err(|_| TorError::Deadline)?
        .map_err(|_| TorError::Bootstrap)?;
        Ok(Self { client })
    }

    /// Connect by hostname using Arti only. DNS resolution is delegated to Tor;
    /// direct TCP, local resolver, external SOCKS and fallback paths do not exist
    /// here. TLS, WebSocket and application-level authentication are callers'
    /// separate responsibilities.
    pub async fn connect_domain(
        &self,
        host: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<DataStream, TorError> {
        let timeout = checked_timeout(timeout)?;
        let host = domain(host, port)?;
        tokio::time::timeout(timeout, self.client.connect((host.as_str(), port)))
            .await
            .map_err(|_| TorError::Deadline)?
            .map_err(|_| TorError::Connect)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destination_does_not_accept_urls_addresses_or_credentials() {
        assert_eq!(domain("example.org", 443), Ok("example.org".into()));
        assert!(domain("service.onion", 80).is_ok());
        for bad in [
            "",
            "127.0.0.1",
            "[::1]",
            "host:443",
            "https://example.org",
            "user@host",
            "host/path",
            "a b",
            "host\\bad",
        ] {
            assert_eq!(domain(bad, 443), Err(TorError::InvalidDestination));
        }
        assert_eq!(domain("example.org", 0), Err(TorError::InvalidDestination));
    }

    #[test]
    fn deadlines_are_bounded() {
        assert_eq!(
            checked_timeout(Duration::ZERO),
            Err(TorError::InvalidTimeout)
        );
        assert_eq!(
            checked_timeout(Duration::from_secs(301)),
            Err(TorError::InvalidTimeout)
        );
        assert_eq!(
            checked_timeout(Duration::from_secs(30)),
            Ok(Duration::from_secs(30))
        );
    }

    #[test]
    fn storage_is_beneath_existing_root_and_refuses_non_directories() {
        // TEMP must be configured inside Fly by tools/env.ps1 when running.
        let root = tempfile::Builder::new()
            .prefix("fly-tor-synthetic-")
            .tempdir()
            .unwrap()
            .keep();
        let (cache, state) = storage_paths(&root).unwrap();
        assert_eq!(
            cache,
            std::fs::canonicalize(&root)
                .unwrap()
                .join("tor")
                .join("cache")
        );
        assert_eq!(
            state,
            std::fs::canonicalize(&root)
                .unwrap()
                .join("tor")
                .join("state")
        );
        assert_eq!(storage_paths(&root).unwrap(), (cache, state));
        let other = tempfile::Builder::new()
            .prefix("fly-tor-file-")
            .tempdir()
            .unwrap()
            .keep();
        std::fs::write(other.join("tor"), b"synthetic").unwrap();
        assert_eq!(storage_paths(&other), Err(TorError::InvalidStorage));
    }

    #[test]
    fn storage_configuration_preserves_literal_dollar_paths() {
        use arti_client::config::CfgPathResolver;
        let root = tempfile::Builder::new()
            .prefix("fly-$ARTI_CACHE-$HOME-")
            .tempdir()
            .unwrap()
            .keep();
        let (cache, state) = storage_paths(&root).unwrap();
        let (cfg_cache, cfg_state) = literal_storage_paths(&cache, &state);
        let resolver = CfgPathResolver::default();
        assert_eq!(cfg_cache.path(&resolver).unwrap(), cache);
        assert_eq!(cfg_state.path(&resolver).unwrap(), state);
        assert_eq!(cfg_cache.as_literal_path(), Some(cache.as_path()));
        assert_eq!(cfg_state.as_literal_path(), Some(state.as_path()));
    }

    /// With Tor bridges chosen, Tor is never reached round them: what
    /// cannot be used as bridges stops it before anything connects.
    #[test]
    fn bridges_that_cannot_be_used_stop_tor_before_it_connects() {
        let obfs4 = "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0";
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let cases: &[&str] = if fly_tor_bridges::own_program().is_file() { &["not a bridge line", "unusable"] } else { &["not a bridge line", "unusable", obfs4] };
        for &chosen in cases {
            let root = tempfile::Builder::new().prefix("fly-tor-bridges-").tempdir().unwrap().keep();
            let began = std::time::Instant::now();
            let got = rt.block_on(SharedTor::bootstrap_through(&root, Duration::from_secs(60), chosen));
            assert_eq!(got.err(), Some(TorError::Bridges), "{chosen}");
            assert!(began.elapsed() < Duration::from_secs(5));
            assert!(!root.join("tor").join("cache").join("dir.sqlite3").exists());
        }
    }

    #[test]
    #[ignore = "opt-in network test: Tor relays see the connecting IP"]
    fn live_bootstrap_and_connection() {
        assert_eq!(std::env::var("FLY_ALLOW_TOR_BOOTSTRAP").as_deref(), Ok("1"));
        let fly_root = PathBuf::from(std::env::var_os("FLY_ROOT").expect("FLY_ROOT required"));
        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let expected = std::fs::canonicalize(fly_root.join(".tmp")).unwrap();
        assert_eq!(temp, expected, "test TEMP must be the isolated Fly directory");
        let root = tempfile::Builder::new().prefix("fly-tor-live-").tempdir_in(temp).unwrap().keep();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2).enable_all().build().unwrap();
        runtime.block_on(async {
            let tor = SharedTor::bootstrap(&root, Duration::from_secs(120)).await.expect("Tor bootstrap failed");
            let _stream = tor.connect_domain("example.com", 443, Duration::from_secs(45))
                .await.expect("Tor connection failed");
        });
    }
}
