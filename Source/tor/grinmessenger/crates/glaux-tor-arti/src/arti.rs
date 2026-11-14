// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Adapted from grin-wallet's Tor integration (`impls/src/tor/arti.rs`), which is
// Apache-2.0 (https://github.com/mimblewimble/grin-wallet), originally adapted
// for Glaux. Glaux-authored wrapping follows `crates/core/src/onion.rs`.
// The grin-specific types (TorConfig, secp SecretKey, wallet Error) were
// replaced with local equivalents so this crate stands alone.

//! In-process Tor: Arti client, onion service publishing and HTTP-over-Tor.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, TorClientConfigBuilder};
use arti_client::{TorClient, TorClientConfig};
use bytes::Bytes;
use fslock_guard::LockFileGuard;
use futures::Stream;
use http_body_util::{BodyExt, Full, Limited};

/// Largest HTTP response body read from a remote onion (a peer cannot make
/// us buffer more than this; a JSON-RPC answer is a few kB).
pub const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
use hyper::client::conn::http1;
use hyper::{Method, Request, Uri};
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_hsrproxy::config::{
    Encapsulation, ProxyAction, ProxyConfigBuilder, ProxyPattern, ProxyRule, TargetAddr,
};
use tor_hsrproxy::OnionServiceReverseProxy;
use tor_hsservice::config::OnionServiceConfigBuilder;
use tor_hsservice::{
    HsIdKeypairSpecifier, HsIdPublicKeySpecifier, HsNickname, RendRequest, RunningOnionService,
};
use tor_keymgr::config::CfgPath;
use tor_keymgr::{ArtiNativeKeystore, KeyMgrBuilder, KeystoreSelector};
use tor_llcrypto::pk::ed25519::ExpandedKeypair;
#[cfg(all(feature = "native-tls", feature = "rustls"))]
compile_error!("glaux-tor-arti: enable exactly one of the features `native-tls` and `rustls`");
#[cfg(not(any(feature = "native-tls", feature = "rustls")))]
compile_error!("glaux-tor-arti: enable one of the features `native-tls` (default) or `rustls`");
#[cfg(feature = "native-tls")]
use tor_rtcompat::tokio::TokioNativeTlsRuntime as ArtiRuntime;
#[cfg(feature = "rustls")]
use tor_rtcompat::tokio::TokioRustlsRuntime as ArtiRuntime;
use tor_rtcompat::{SleepProviderExt, ToplevelBlockOn};

use crate::error::{Result, TorError};
use crate::keys::{exp_sec_key_bytes, expanded_from_seed};
use crate::onion::onion_address;
use crate::{DEFAULT_BOOTSTRAP_TIMEOUT_SECS, DEFAULT_REQUEST_TIMEOUT_SECS};

/// Configuration for the in-process Tor client and onion service.
///
/// The state directory holds Arti's state, cache and keystore. Bridge settings
/// are optional; without them Arti uses the public Tor network.
pub struct TorConfig {
    /// Root directory for Arti state/cache/keystore.
    pub state_dir: PathBuf,
    /// Maximum time allowed for the initial Tor bootstrap.
    pub bootstrap_timeout: Duration,
    /// Maximum time allowed for one HTTP request through Tor.
    pub request_timeout: Duration,
    /// Optional bridge line, e.g. `obfs4 192.0.2.10:443 ABCD cert=… iat-mode=0`.
    pub bridge_line: Option<String>,
    /// Optional path to the pluggable-transport binary for the bridge.
    pub bridge_bin_path: Option<PathBuf>,
    mistrust: fs_mistrust::Mistrust,
}

impl TorConfig {
    /// Create a configuration rooted at `state_dir` with default timeouts.
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            bootstrap_timeout: Duration::from_secs(DEFAULT_BOOTSTRAP_TIMEOUT_SECS),
            request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
            bridge_line: None,
            bridge_bin_path: None,
            mistrust: fs_mistrust::Mistrust::new(),
        }
    }

    /// Attach an optional pluggable-transport bridge.
    pub fn with_bridge(
        mut self,
        bridge_line: impl Into<String>,
        bridge_bin_path: Option<PathBuf>,
    ) -> Self {
        self.bridge_line = Some(bridge_line.into());
        self.bridge_bin_path = bridge_bin_path;
        self
    }

    fn mistrust(&self) -> &fs_mistrust::Mistrust {
        &self.mistrust
    }

    fn state_cache_paths(&self) -> (PathBuf, PathBuf) {
        let root = self.state_dir.join("arti");
        (root.join("state"), root.join("cache"))
    }
}

struct TorService {
    service: Arc<RunningOnionService>,
    proxy: Arc<OnionServiceReverseProxy>,
    worker: JoinHandle<()>,
    state_lock: PathBuf,
}

/// One Tokio runtime shared by all Arti clients in this process.
#[derive(Clone)]
struct ArtiRuntimeWrapper {
    runtime: ArtiRuntime,
}

impl ArtiRuntimeWrapper {
    fn create() -> std::io::Result<Self> {
        // rustls needs a process-wide crypto provider before the first TLS
        // config is built; installing it again is a harmless no-op (Err).
        #[cfg(feature = "rustls")]
        let _ = rustls::crypto::ring::default_provider().install_default();
        Ok(Self {
            runtime: ArtiRuntime::create()?,
        })
    }
}

static ARTI_RUNTIME: LazyLock<Mutex<Option<ArtiRuntimeWrapper>>> =
    LazyLock::new(|| Mutex::new(ArtiRuntimeWrapper::create().ok()));

type CachedArtiClient = Arc<TorClient<ArtiRuntime>>;
type ArtiClientCache = Mutex<Option<(CachedArtiClient, TorClientConfig)>>;

static ARTI_CLIENT_CONFIG: LazyLock<ArtiClientCache> = LazyLock::new(|| Mutex::new(None));

static ARTI_PROXY_SERVICES: LazyLock<Mutex<HashMap<String, TorService>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn runtime() -> Result<ArtiRuntime> {
    let mut runtime = ARTI_RUNTIME
        .lock()
        .map_err(|_| TorError::Tor("Arti runtime lock poisoned".into()))?;
    let wrapper = match runtime.as_ref() {
        None => runtime.insert(ArtiRuntimeWrapper::create().map_err(TorError::Io)?),
        Some(wrapper) => wrapper,
    };
    Ok(wrapper.runtime.clone())
}

/// A running Tor onion service forwarding `onion:80` to a local loopback address.
///
/// Dropping the value stops the service; [`OnionService::stop`] does it
/// explicitly.
pub struct OnionService {
    onion: Option<String>,
}

impl OnionService {
    /// Publish `local_addr` (e.g. `127.0.0.1:34567`) under the onion derived from
    /// `seed`. Blocks while Arti bootstraps and the service is launched.
    ///
    /// The onion is derived from the same ed25519 seed as the messenger
    /// identity, so peers can compute it from the bech32 address alone.
    pub fn start(seed: &[u8; 32], local_addr: &str, config: &TorConfig) -> Result<Self> {
        let onion = onion_address(seed);
        start_tor_service(seed, local_addr, config)?;
        info!("onion service published: {onion}.onion");
        Ok(Self { onion: Some(onion) })
    }

    /// Onion id (56 base32 chars, no `.onion`).
    pub fn onion(&self) -> &str {
        self.onion.as_deref().unwrap_or_default()
    }

    /// `http://<onion>.onion` URL peers can deliver to.
    pub fn url(&self) -> String {
        format!("http://{}.onion", self.onion())
    }

    /// Stop the service now.
    pub fn stop(mut self) {
        if let Some(onion) = self.onion.take() {
            let _ = stop_tor_service(onion);
        }
    }
}

impl Drop for OnionService {
    fn drop(&mut self) {
        if let Some(onion) = self.onion.take() {
            let _ = stop_tor_service(onion);
        }
    }
}

/// Blocking HTTP/1.1 client that routes requests through Tor/Arti.
///
/// The underlying Arti client is process-wide and cached per configuration, so
/// bootstrapping is paid once even when both an [`OnionService`] and a
/// [`TorHttpClient`] are used.
pub struct TorHttpClient {
    client: Arc<TorClient<ArtiRuntime>>,
    timeout: Duration,
}

impl TorHttpClient {
    /// Create the client and block until Tor is bootstrapped.
    pub fn bootstrap(config: &TorConfig) -> Result<Self> {
        let (client, _) = init_client(config)?;
        Ok(Self {
            client,
            timeout: config.request_timeout,
        })
    }

    /// Perform one HTTP request against an absolute `http://` URL (`.onion` and
    /// clearnet are both supported) and return `(status, body)`.
    pub fn request(&self, method: &str, url: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let uri: Uri = url
            .parse()
            .map_err(|e| TorError::Config(format!("URL {url}: {e}")))?;
        let host = uri
            .host()
            .ok_or_else(|| TorError::Config(format!("URL {url}: нет host")))?
            .to_string();
        let port = uri.port_u16().unwrap_or(80);
        // Send an origin-form request target (`/path?query`) with an explicit
        // Host header. Passing the absolute URI to hyper makes it emit
        // absolute-form (`GET http://host/path`), which is only meant for
        // proxies and confuses minimal origin servers such as our gateway.
        let authority = uri
            .authority()
            .map(|authority| authority.as_str().to_string())
            .ok_or_else(|| TorError::Config(format!("URL {url}: нет authority")))?;
        let host_header = hyper::header::HeaderValue::from_str(&authority)
            .map_err(|e| TorError::Config(format!("URL {url}: bad host header: {e}")))?;
        let request_uri: Uri = uri
            .path_and_query()
            .map(|path| path.as_str())
            .unwrap_or("/")
            .parse()
            .map_err(|e| TorError::Config(format!("URL {url}: bad path: {e}")))?;
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|e| TorError::Config(format!("HTTP method: {e}")))?;
        let body = body.to_vec();
        let client = self.client.clone();
        let timeout = self.timeout;
        let target = format!("{host}:{port}");

        let worker = thread::spawn(move || -> Result<(u16, Vec<u8>)> {
            let runtime = client.runtime().clone();
            runtime.clone().block_on(async move {
                let request = async move {
                    let stream = client
                        .connect((host, port))
                        .await
                        .map_err(|e| TorError::Tor(format!("connect {target}: {e}")))?;
                    let (mut sender, connection) =
                        http1::handshake::<_, Full<Bytes>>(TokioIo::new(stream))
                            .await
                            .map_err(|e| TorError::Tor(format!("HTTP handshake: {e}")))?;
                    tokio::spawn(async move {
                        if let Err(e) = connection.await {
                            error!("Tor connection error: {e}");
                        }
                    });
                    let request = Request::builder()
                        .method(method)
                        .uri(request_uri)
                        .header(hyper::header::HOST, host_header)
                        .body(Full::from(Bytes::from(body)))
                        .map_err(|e| TorError::Tor(format!("request: {e}")))?;
                    let response = sender
                        .send_request(request)
                        .await
                        .map_err(|e| TorError::Tor(format!("send: {e}")))?;
                    let status = response.status().as_u16();
                    let declared = response
                        .headers()
                        .get(hyper::header::CONTENT_LENGTH)
                        .and_then(|v| v.to_str().ok())
                        .and_then(|v| v.parse::<u64>().ok());
                    if declared.is_some_and(|n| n > MAX_RESPONSE_BYTES as u64) {
                        return Err(TorError::Tor(format!("response body over {MAX_RESPONSE_BYTES} bytes")));
                    }
                    let bytes = Limited::new(response.into_body(), MAX_RESPONSE_BYTES)
                        .collect()
                        .await
                        .map_err(|e| TorError::Tor(format!("response body (limit {MAX_RESPONSE_BYTES} bytes): {e}")))?
                        .to_bytes()
                        .to_vec();
                    Ok((status, bytes))
                };
                runtime
                    .timeout(timeout, request)
                    .await
                    .map_err(|_| TorError::Tor(format!("request timeout ({timeout:?})")))?
            })
        });
        worker
            .join()
            .map_err(|_| TorError::Tor("Tor worker thread panicked".into()))?
    }
}

// ---------- onion service internals ----------

fn build_client_config(config: &TorConfig) -> Result<TorClientConfig> {
    let (state_path, cache_path) = config.state_cache_paths();
    // Arti's fs-mistrust wants 0700 on every directory from its state root
    // down. create_dir_all alone leaves the umask default (0755) on a fresh
    // Linux profile, so create the chain and tighten it here. Running this on
    // every start also repairs profiles created before the fix.
    let root = state_path.parent().map(Path::to_path_buf).unwrap_or_else(|| state_path.clone());
    let dirs: [&Path; 4] = [&config.state_dir, &root, &state_path, &cache_path];
    for dir in dirs {
        std::fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in dirs {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }

    let mut builder = TorClientConfigBuilder::from_directories(&state_path, &cache_path);
    builder.address_filter().allow_onion_addrs(true);

    if let Some(bridge_line) = config.bridge_line.as_ref() {
        let bridge: BridgeConfigBuilder = bridge_line
            .parse()
            .map_err(|_| TorError::Config("invalid bridge configuration".into()))?;
        builder.bridges().bridges().push(bridge.clone());
        let Some(transport_name) = bridge.get_transport() else {
            return Err(TorError::Config("bridge transport is missing".into()));
        };
        let bin_path = config
            .bridge_bin_path
            .as_ref()
            .map(|path| path.to_string_lossy().to_string())
            .unwrap_or_else(|| transport_name.to_string());
        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec![transport_name.parse().map_err(|e| {
                TorError::Config(format!("bridge transport {transport_name:?}: {e}"))
            })?])
            .path(CfgPath::new(bin_path))
            .run_on_startup(true);
        builder.bridges().transports().push(transport);
    }

    builder
        .build()
        .map_err(|e| if config.bridge_line.is_some() {
            TorError::Config("invalid Tor bridge configuration".into())
        } else { TorError::Config(format!("Tor client config: {e:?}")) })
}

/// Build (or reuse) the process-wide Arti client and bootstrap it.
fn init_client(
    config: &TorConfig,
) -> Result<(Arc<TorClient<ArtiRuntime>>, TorClientConfig)> {
    let client_config = build_client_config(config)?;
    let mut cached = ARTI_CLIENT_CONFIG
        .lock()
        .map_err(|_| TorError::Tor("Arti client cache poisoned".into()))?;
    if let Some((client, cached_config)) = cached.as_ref() {
        if cached_config == &client_config {
            debug!("Reusing bootstrapped Arti Tor client");
            return Ok((client.clone(), cached_config.clone()));
        }
        debug!("Tor client config changed; rebuilding Arti client");
        *cached = None;
    }
    let client = launch_client(client_config.clone(), config)?;
    cached.replace((client.clone(), client_config.clone()));
    Ok((client, client_config))
}

fn launch_client(
    client_config: TorClientConfig,
    config: &TorConfig,
) -> Result<Arc<TorClient<ArtiRuntime>>> {
    let runtime = runtime()?;
    let client = TorClient::with_runtime(runtime)
        .config(client_config)
        .create_unbootstrapped()
        .map_err(|e| TorError::Tor(format!("create Arti client: {e}")))?;
    let timeout = config.bootstrap_timeout;
    info!("Bootstrapping Tor/Arti (timeout {timeout:?})");
    let runtime = client.runtime().clone();
    let c = client.clone();
    runtime.clone().block_on(async move {
        match runtime.timeout(timeout, c.bootstrap()).await {
            Ok(Ok(())) => {
                let percent = c.bootstrap_status().as_frac();
                info!("Tor client bootstrapped: {:.0}%", percent * 100.0);
                Ok(c.clone())
            }
            Ok(Err(e)) => Err(TorError::Tor(format!("bootstrap: {e}"))),
            Err(_) => Err(TorError::Tor(format!(
                "bootstrap timeout ({timeout:?}); проверьте сеть/Tor"
            ))),
        }
    })
}

fn start_tor_service(seed: &[u8; 32], local_addr: &str, config: &TorConfig) -> Result<()> {
    let onion = onion_address(seed);
    let (client, _) = init_client(config)?;

    let hs = HsNickname::new(onion.clone())
        .map_err(|e| TorError::Config(format!("onion nickname {onion}: {e}")))?;
    let (state_path, _) = config.state_cache_paths();
    let keystore_path = state_path.join("keystore");
    // Arti 0.44-style per-service lock: the service cannot restart before the
    // previous instance has finished stopping.
    let state_lock = state_path.join("hss").join(format!("{onion}.lock"));
    add_service_key(config.mistrust(), seed, &hs, keystore_path)?;

    let service_config = OnionServiceConfigBuilder::default()
        .nickname(hs.clone())
        .build()
        .map_err(|e| TorError::Config(format!("onion service config: {e:?}")))?;

    let (service, proxy, worker) = match client.launch_onion_service(service_config) {
        Ok(Some((service, mut requests))) => {
            let addr: SocketAddr = local_addr
                .parse()
                .map_err(|e| TorError::Config(format!("локальный адрес {local_addr:?}: {e}")))?;
            let proxy = create_service_proxy(addr)?;
            let client = client.clone();
            let worker_proxy = proxy.clone();
            let worker = thread::spawn(move || {
                client.runtime().block_on(async move {
                    loop {
                        match run_service_proxy(worker_proxy.clone(), &mut requests, hs.clone())
                            .await
                        {
                            Ok(()) => {
                                info!("Tor onion proxy stopped");
                                break;
                            }
                            Err(e) => {
                                error!("Tor onion proxy error: {e}; перезапуск");
                                tokio::time::sleep(Duration::from_millis(1000)).await;
                            }
                        }
                    }
                })
            });
            (service, proxy, worker)
        }
        Ok(None) => {
            return Err(TorError::Tor(
                "onion service отключён в конфигурации Arti".into(),
            ))
        }
        Err(e) => return Err(TorError::Tor(format!("launch onion service: {e}"))),
    };

    ARTI_PROXY_SERVICES
        .lock()
        .map_err(|_| TorError::Tor("onion service registry poisoned".into()))?
        .insert(
            onion,
            TorService {
                service,
                proxy,
                worker,
                state_lock,
            },
        );
    Ok(())
}

fn stop_tor_service(onion: String) -> Result<()> {
    let service = ARTI_PROXY_SERVICES
        .lock()
        .map_err(|_| TorError::Tor("onion service registry poisoned".into()))?
        .remove(&onion);
    let Some(TorService {
        service,
        proxy,
        worker,
        state_lock,
    }) = service
    else {
        debug!("Stop: onion service {onion} is not running");
        return Ok(());
    };
    proxy.shutdown();
    worker
        .join()
        .map_err(|_| TorError::Tor("Tor onion worker thread panicked".into()))?;
    drop(service);
    drop(
        LockFileGuard::lock(state_lock)
            .map_err(|e| TorError::Tor(format!("cannot release onion lock: {e}")))?,
    );
    Ok(())
}

fn create_service_proxy(addr: SocketAddr) -> Result<Arc<OnionServiceReverseProxy>> {
    let rule = ProxyRule::new(
        ProxyPattern::one_port(80).map_err(|e| TorError::Config(format!("proxy pattern: {e}")))?,
        ProxyAction::Forward(Encapsulation::Simple, TargetAddr::Inet(addr)),
    );
    let mut builder = ProxyConfigBuilder::default();
    builder.set_proxy_ports(vec![rule]);
    let config = builder
        .build()
        .map_err(|e| TorError::Config(format!("proxy config: {e}")))?;
    Ok(OnionServiceReverseProxy::new(config))
}

async fn run_service_proxy<S>(
    proxy: Arc<OnionServiceReverseProxy>,
    requests: &mut S,
    nickname: HsNickname,
) -> Result<()>
where
    S: Stream<Item = RendRequest> + Unpin + Send + 'static,
{
    let runtime = runtime()?;
    proxy
        .handle_requests(runtime, nickname, requests)
        .await
        .map_err(|e| TorError::Tor(format!("onion proxy: {e}")))?;
    Ok(())
}

fn add_service_key(
    mistrust: &fs_mistrust::Mistrust,
    seed: &[u8; 32],
    hs_nickname: &HsNickname,
    keystore_path: PathBuf,
) -> Result<()> {
    let arti_store = ArtiNativeKeystore::from_path_and_mistrust(&keystore_path, mistrust)
        .map_err(|e| TorError::Tor(format!("keystore {}: {e}", keystore_path.display())))?;
    let key_manager = KeyMgrBuilder::default()
        .primary_store(Box::new(arti_store))
        .build()
        .map_err(|e| TorError::Tor(format!("key manager: {e}")))?;

    let expanded_sk = expanded_from_seed(seed);
    let sk_bytes = exp_sec_key_bytes(expanded_sk);
    match ExpandedKeypair::from_secret_key_bytes(sk_bytes) {
        None => Err(TorError::Tor("hidden service key cannot be created".into())),
        Some(expanded) => {
            key_manager
                .insert(
                    HsIdKey::from(*expanded.public()),
                    &HsIdPublicKeySpecifier::new(hs_nickname.clone()),
                    KeystoreSelector::Primary,
                    true,
                )
                .map_err(|e| TorError::Tor(format!("insert onion public key: {e}")))?;
            key_manager
                .insert(
                    HsIdKeypair::from(expanded),
                    &HsIdKeypairSpecifier::new(hs_nickname.clone()),
                    KeystoreSelector::Primary,
                    true,
                )
                .map_err(|e| TorError::Tor(format!("insert onion keypair: {e}")))?;
            Ok(())
        }
    }
}

/// The Tor executable/`torrc` path is intentionally absent: this crate always
/// runs Tor in-process through Arti.
#[allow(dead_code)]
fn _no_external_tor(_path: &Path) {}

#[cfg(test)]
mod runtime_tests {
    #[test]
    fn bridge_configuration_is_not_silently_direct_and_errors_are_redacted() {
        let dir = std::env::temp_dir().join(format!("gs-bridge-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("transport-test");
        std::fs::write(&bin, "test").unwrap();
        let direct = super::TorConfig::new(&dir);
        let bridge = super::TorConfig::new(&dir).with_bridge(
            "obfs4 192.0.2.55:38114 316E643333645F6D79216558614D3931657A5F5F cert=YXJlIGZyZXF1ZW50bHkgZnVsbCBvZiBsaXR0bGUgbWVzc2FnZXMgeW91IGNhbiBmaW5kLg iat-mode=0", Some(bin));
        let a = super::build_client_config(&direct).unwrap();
        let b = super::build_client_config(&bridge).unwrap();
        assert_ne!(a, b, "bridge configuration must differ from direct Tor");
        let invalid = super::TorConfig::new(&dir).with_bridge("invalid private-token", None);
        let err = match super::build_client_config(&invalid) { Err(e) => e.to_string(), Ok(_) => panic!("bad bridge accepted") };
        assert!(!err.contains("private-token"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The Tokio/TLS runtime Arti runs on can be created (with `rustls` this
    /// needs the crypto provider installed first, otherwise Arti panics).
    #[test]
    fn arti_runtime_creates() {
        let rt = super::runtime().expect("Arti runtime");
        drop(rt);
        #[cfg(feature = "rustls")]
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
}
