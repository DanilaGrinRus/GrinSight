use super::*;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::sync::Weak;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub(super) struct AutoState {
    wallet: Weak<Wallet>,
    generation: u64,
    pub(super) phrase: Option<String>,
    pub(super) code: Option<String>,
    pub(super) publication: &'static str,
}

pub(super) struct Snapshot {
    pub(super) port: u16,
    pub(super) token: Zeroizing<String>,
    pub(super) route: String,
    pub(super) address: String,
}

impl Snapshot {
    fn request(&self, path: &str, value: &Value) -> Result<Value, String> {
        self.request_with_timeout(path, value, Duration::from_secs(10))
    }
    fn request_with_timeout(&self, path: &str, value: &Value, timeout: Duration) -> Result<Value, String> {
        let deadline = Instant::now() + timeout;
        let payload = value.to_string();
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port);
        let connect_limit = timeout.min(Duration::from_secs(3));
        let mut stream = TcpStream::connect_timeout(&addr.into(), connect_limit).map_err(|_| "messenger unavailable")?;
        let request = Zeroizing::new(format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}", self.token.as_str(), payload.len()));
        let mut remaining = request.as_bytes();
        while !remaining.is_empty() {
            let left = deadline.checked_duration_since(Instant::now()).ok_or("messenger request timed out")?;
            stream.set_write_timeout(Some(left.max(Duration::from_millis(1)))).map_err(|_| "messenger timeout unavailable")?;
            let written = stream.write(remaining).map_err(|_| "messenger request failed")?;
            if written == 0 { return Err("messenger request failed".into()); }
            remaining = &remaining[written..];
        }
        let mut response = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let left = deadline.checked_duration_since(Instant::now()).ok_or("messenger request timed out")?;
            stream.set_read_timeout(Some(left.max(Duration::from_millis(1)))).map_err(|_| "messenger timeout unavailable")?;
            let n = stream.read(&mut chunk).map_err(|_| "messenger response failed")?;
            if n == 0 { break; }
            if response.len().saturating_add(n) > 2 * 1024 * 1024 { return Err("messenger response too large".into()); }
            response.extend_from_slice(&chunk[..n]);
        }
        let split = response.windows(4).position(|x| x == b"\r\n\r\n").ok_or("invalid messenger response")?;
        let header = std::str::from_utf8(&response[..split]).map_err(|_| "invalid messenger response")?;
        if !header.starts_with("HTTP/1.1 200 ") { return Err("messenger request rejected".into()); }
        serde_json::from_slice(&response[split + 4..]).map_err(|_| "invalid messenger response".into())
    }
}

/// Recompute the public index locally rather than trusting the daemon draft.
/// Keep this fixed list/domain synchronized with glaux-messenger::nostr::catalog.
pub(super) fn public_phrase(address: &str) -> String {
    use sha2::{Digest, Sha256};
    const WORDS: [&str; 64] = [
        "ant", "ash", "bay", "bee", "cafe", "cold", "crab", "crow",
        "dew", "dive", "dusk", "elk", "elm", "fern", "fin", "flea",
        "flit", "gull", "halo", "hare", "harp", "haze", "herb", "hive",
        "iris", "jade", "lamb", "lily", "lobe", "loom", "lynx", "mare",
        "mint", "mist", "mole", "moss", "moth", "neon", "owl", "pine",
        "plum", "reef", "reed", "rill", "ruby", "seal", "sky", "slug",
        "soil", "star", "swan", "teal", "toad", "twig", "vase", "vine",
        "wax", "wind", "wren", "yarn", "zest", "zoom", "ibis", "orca",
    ];
    let mut hash = Sha256::new();
    hash.update(b"grinsight-public-lookup-phrase-v1\0");
    hash.update(address.as_bytes());
    let digest = hash.finalize();
    digest[..6].iter().map(|b| WORDS[(b & 63) as usize]).collect::<Vec<_>>().join("-")
}

/// Derive and validate against the unlocked wallet without network access.
/// Encode the derived public key with the wallet's network HRP explicitly,
/// without reading or mutating the process-global chain type.
pub(super) fn verified_wallet_address(w: &Wallet) -> Result<String, String> {
    use grin_keychain::{ExtKeychain, Keychain};
    use bech32::ToBase32;
    let entropy = Zeroizing::new(grin_keychain::mnemonic::to_entropy(&w.phrase).map_err(|_| "invalid wallet phrase")?);
    let key = ExtKeychain::from_seed(&entropy, !w.mainnet()).map_err(|_| "cannot derive wallet key")?;
    let parent = ExtKeychain::derive_key_id(2, 0, 0, 0, 0);
    let secret = grin_wallet_libwallet::address::address_from_derivation_path(&key, &parent, 0).map_err(|_| "cannot derive address")?;
    let public = ed25519_dalek::SigningKey::from_bytes(&secret.0).verifying_key().to_bytes();
    let prefix = if w.mainnet() { "grin" } else { "tgrin" };
    let canonical = bech32::encode(prefix, public.to_base32()).map_err(|_| "invalid wallet address")?;
    match std::fs::read_to_string(w.p("address.txt")) {
        Ok(saved) if saved.trim() != canonical => return Err("saved address differs from wallet".into()),
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(_) => return Err("saved address unavailable".into()),
    }
    Ok(canonical)
}

fn publication_due(last: Option<(Instant, &str)>, route: &str, now: Instant) -> bool {
    last.is_none_or(|(when, previous)| previous != route || now.saturating_duration_since(when) >= Duration::from_secs(12 * 3600))
}

impl Service {
    /// Starts at most one worker for this unlocked Wallet. The status is scoped
    /// to the Arc identity, not just the profile name, to distinguish relogins.
    pub fn chat_catalog_identity(self: &Arc<Self>) -> Result<Value, String> {
        let w = self.wallet()?;
        let mut state = self.catalogue_auto.lock().map_err(|_| "catalogue state unavailable")?;
        let same = state.wallet.upgrade().is_some_and(|previous| Arc::ptr_eq(&previous, &w));
        if !same {
            state.generation = state.generation.wrapping_add(1);
            state.wallet = Arc::downgrade(&w);
            // Offline display is derived from the currently unlocked wallet,
            // not an unchecked saved address or the daemon's response.
            state.phrase = verified_wallet_address(&w).ok().map(|a| public_phrase(&a));
            state.code = None;
            state.publication = "pending";
            let generation = state.generation;
            let service = Arc::downgrade(self);
            let wallet = Arc::downgrade(&w);
            std::thread::spawn(move || auto_worker(service, wallet, generation));
        }
        Ok(json!({"search_phrase": state.phrase, "comparison_code": state.code, "publication": if state.publication.is_empty() { "pending" } else { state.publication }}))
    }
}

fn update(svc: &Service, generation: u64, w: &Arc<Wallet>, status: &'static str, phrase: Option<&str>, code: Option<&str>) {
    if let Ok(mut state) = svc.catalogue_auto.lock() {
        if state.generation != generation || !state.wallet.upgrade().is_some_and(|old| Arc::ptr_eq(&old, w)) { return; }
        state.publication = status;
        if let Some(p) = phrase { state.phrase = Some(p.to_string()); }
        if let Some(c) = code { state.code = Some(c.to_string()); }
    }
}

/// Fail closed if a previously saved opt-out cannot be read or parsed.
fn parse_auto_setting(bytes: &[u8]) -> Result<bool, String> {
    let settings: Value = serde_json::from_slice(bytes).map_err(|_| "catalogue settings unavailable")?;
    let obj = settings.as_object().ok_or("catalogue settings unavailable")?;
    match obj.get("catalogue_auto_publish") {
        None => Ok(true),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err("catalogue settings unavailable".into()),
    }
}
fn read_auto_setting(path: &std::path::Path) -> Result<bool, String> {
    let file = std::fs::File::open(path).map_err(|_| "catalogue settings unavailable")?;
    let mut bytes = Vec::new();
    file.take(1_048_577).read_to_end(&mut bytes).map_err(|_| "catalogue settings unavailable")?;
    if bytes.len() > 1_048_576 { return Err("catalogue settings unavailable".into()); }
    parse_auto_setting(&bytes)
}
fn auto_enabled(w: &Wallet) -> Result<bool, String> {
    read_auto_setting(&w.p("settings.json"))
}

/// Hold lifecycle only while reading the currently unlocked wallet and daemon
/// identity. Network requests are made later with this wallet's own token.
fn capture(svc: &Service, w: &Arc<Wallet>) -> Result<Snapshot, String> {
    let _lock = svc.rpc_lifecycle.read().map_err(|_| "wallet lifecycle unavailable")?;
    capture_locked(svc, w)
}

/// Caller must hold lifecycle read lock.
fn capture_locked(svc: &Service, w: &Arc<Wallet>) -> Result<Snapshot, String> {
    let current = svc.wallet()?;
    if !Arc::ptr_eq(&current, w) { return Err("wallet changed".into()); }
    if !auto_enabled(w)? { return Err("disabled".into()); }
    let brief = svc.tor_status_brief(w);
    if brief["running"] != true { return Err("messenger unavailable".into()); }
    let status = &brief["status"];
    let mode = status["glauxnet"].as_str().unwrap_or("");
    if mode != "nostr_direct" && mode != "nostr_i2p" { return Err("Nostr unavailable".into()); }
    let port = status["chat_port"].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0).ok_or("messenger unavailable")?;
    let route = status["glaux_route"].as_str().filter(|r| r.len() == 64 && r.bytes().all(|c| c.is_ascii_hexdigit())).ok_or("route unavailable")?.to_owned();
    let token = Zeroizing::new(std::fs::read_to_string(w.p("tor-wallet-1/chat-api.token")).map_err(|_| "messenger unavailable")?.trim().to_owned());
    if token.len() < 32 || !token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') { return Err("messenger unavailable".into()); }
    let address = std::fs::read_to_string(w.p("address.txt")).map_err(|_| "address unavailable")?.trim().to_owned();
    let prefix = if w.mainnet() { "grin1" } else { "tgrin1" };
    if !address.starts_with(prefix) || address.len() > 120 || !address.bytes().all(|b| b.is_ascii_alphanumeric()) { return Err("address unavailable".into()); }
    Ok(Snapshot {port, token, route, address})
}

/// Calculate the displayed verification code locally from the exact keys in
/// the signed claims. A daemon-supplied arbitrary code is never trusted.
fn comparison_code_for_claims(claims: &Value) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let wallet = claims["wallet_address"].as_str().ok_or("invalid profile")?;
    let owner = claims["binding"]["owner"].as_str().ok_or("invalid profile")?;
    let transport = claims["binding"]["transport_key"].as_str().ok_or("invalid profile")?;
    if wallet.len() > 128 || owner.len() > 128 || transport.len() != 64 || !transport.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err("invalid profile".into()); }
    if !(wallet.starts_with("grin1") && owner.starts_with("grin1") || wallet.starts_with("tgrin1") && owner.starts_with("tgrin1")) { return Err("profile network mismatch".into()); }
    let mut hash = Sha256::new();
    hash.update(b"grinsight-contact-code-v1\0");
    for part in [wallet, owner, transport] {
        hash.update((part.len() as u32).to_be_bytes());
        hash.update(part.as_bytes());
    }
    let raw = hash.finalize();
    let text: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{}-{}-{}", &text[..4], &text[4..8], &text[8..12]))
}

/// Network draft uses only the public address and captured daemon credentials;
/// no Arc<Wallet> or signing secret remains held while awaiting the daemon.
fn fetch_draft(snapshot: &Snapshot) -> Result<(Value, Vec<u8>, String, String), String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| "clock unavailable")?.as_secs();
    let lookup = snapshot.request("/v1/catalog/draft", &json!({"name":"viewer","wallet_address":snapshot.address,"sequence":now,"revoked":false}))?;
    let phrase = public_phrase(&snapshot.address);
    if lookup["search_phrase"] != phrase { return Err("invalid contact phrase".into()); }
    let draft = snapshot.request("/v1/catalog/draft", &json!({"name":phrase,"wallet_address":snapshot.address,"sequence":now,"revoked":false}))?;
    let claims = draft.get("claims").ok_or("invalid profile")?;
    if draft["route"] != snapshot.route || draft["search_phrase"] != phrase || claims["name"] != phrase || claims["wallet_address"] != snapshot.address || claims["sequence"] != now || claims["version"] != 1 || claims["revoked"] != false { return Err("profile changed".into()); }
    let code = comparison_code_for_claims(claims)?;
    if draft["comparison_code"] != code { return Err("comparison code mismatch".into()); }
    let encoded = draft["transcript_hex"].as_str().ok_or("invalid profile transcript")?;
    if encoded.len() > 16_384 || encoded.len() % 2 != 0 || !encoded.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) { return Err("invalid profile transcript".into()); }
    let transcript: Vec<u8> = encoded.as_bytes().chunks_exact(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(),16).unwrap()).collect();
    let prefix = b"grinsight-public-contact-v1\0";
    if !transcript.starts_with(prefix) || serde_json::from_slice::<Value>(&transcript[prefix.len()..]).ok().as_ref() != Some(claims) { return Err("profile transcript mismatch".into()); }
    Ok((claims.clone(), transcript, phrase, code))
}

/// Sign only if the exact captured wallet, route and opt-in are still active.
/// The lock covers only local key derivation/signing, never network I/O.
pub(super) fn sign_guarded(svc: &Service, wallet: &Weak<Wallet>, snapshot: &Snapshot, claims: Value, transcript: &[u8]) -> Result<Value, String> {
    use grin_keychain::{ExtKeychain, Keychain};
    let _guard = svc.rpc_lifecycle.read().map_err(|_| "wallet lifecycle unavailable")?;
    let current = svc.wallet()?;
    if !Weak::ptr_eq(wallet, &Arc::downgrade(&current)) { return Err("wallet changed".into()); }
    let now = capture_locked(svc, &current)?;
    if now.port != snapshot.port || now.route != snapshot.route || now.address != snapshot.address || now.token.as_str() != snapshot.token.as_str() { return Err("route changed".into()); }
    if verified_wallet_address(&current)? != snapshot.address { return Err("wallet address changed".into()); }
    let entropy = Zeroizing::new(grin_keychain::mnemonic::to_entropy(&current.phrase).map_err(|_| "invalid wallet phrase")?);
    let key = ExtKeychain::from_seed(&entropy, !current.mainnet()).map_err(|_| "cannot derive wallet key")?;
    let sig = grinsight_state::receive::sign_public_contact(&key, transcript)?;
    let signature: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    Ok(json!({"consent_public":true,"expected_route":snapshot.route,"profile":{"claims":claims,"wallet_signature":signature}}))
}

fn same_snapshot(svc: &Service, w: &Arc<Wallet>, snapshot: &Snapshot) -> bool {
    let Ok(now) = capture(svc, w) else { return false; };
    now.port == snapshot.port && now.route == snapshot.route && now.address == snapshot.address && now.token.as_str() == snapshot.token.as_str()
}

/// Serializes the final snapshot check and bounded POST with wallet logout,
/// channel changes, and opt-out. After a successful logout/opt-out no new POST
/// can begin for this wallet. Already accepted relay data cannot be recalled.
pub(super) fn publish_bounded(svc: &Service, wallet: &Weak<Wallet>, snapshot: &Snapshot, profile: &Value) -> bool {
    let Ok(_guard) = svc.rpc_lifecycle.read() else { return false; };
    let Ok(current) = svc.wallet() else { return false; };
    if !Weak::ptr_eq(wallet, &Arc::downgrade(&current)) { return false; }
    let Ok(now) = capture_locked(svc, &current) else { return false; };
    if now.port != snapshot.port || now.route != snapshot.route || now.address != snapshot.address || now.token.as_str() != snapshot.token.as_str() { return false; }
    // Do not keep an extra Arc<Wallet> (and thus the seed) during network I/O.
    drop(current);
    snapshot.request("/v1/catalog/publish", profile).is_ok()
}

fn auto_worker(service: Weak<Service>, wallet: Weak<Wallet>, generation: u64) {
    let mut last: Option<(Instant, String)> = None;
    loop {
        let (Some(svc), Some(w)) = (service.upgrade(), wallet.upgrade()) else { return; };
        let active = svc.catalogue_auto.lock().ok().is_some_and(|s| s.generation == generation && s.wallet.upgrade().is_some_and(|p| Arc::ptr_eq(&p, &w)));
        if !active { return; }
        match capture(&svc, &w) {
            Err(error) => update(&svc, generation, &w, if error == "disabled" { "disabled" } else { "pending" }, None, None),
            Ok(snapshot) => {
                if publication_due(last.as_ref().map(|(t,r)| (*t,r.as_str())), &snapshot.route, Instant::now()) {
                    let captured = Arc::downgrade(&w);
                    // Release the only background strong wallet reference
                    // before starting either of the network draft requests.
                    drop(w);
                    if let Ok((claims, transcript, phrase, code)) = fetch_draft(&snapshot) {
                        if let Ok(profile) = sign_guarded(&svc, &captured, &snapshot, claims, &transcript) {
                            if let Some(current) = captured.upgrade() {
                                update(&svc, generation, &current, "pending", Some(&phrase), Some(&code));
                                drop(current);
                            }
                            let accepted = publish_bounded(&svc, &captured, &snapshot, &profile);
                            if let Some(current) = captured.upgrade() {
                                if same_snapshot(&svc, &current, &snapshot) {
                                    if accepted { last = Some((Instant::now(), snapshot.route.clone())); }
                                    update(&svc, generation, &current, if accepted { "published" } else { "pending" }, Some(&phrase), Some(&code));
                                }
                            }
                        }
                    }
                    drop(svc);
                    std::thread::sleep(RETRY_DELAY);
                    continue;
                }
            }
        }
        drop(w); drop(svc);
        std::thread::sleep(RETRY_DELAY);
    }
}

#[cfg(test)]
mod integration_tests;

#[cfg(test)]
const RETRY_DELAY: Duration = Duration::from_millis(100);
#[cfg(not(test))]
const RETRY_DELAY: Duration = Duration::from_secs(30);

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn slow_server_cannot_extend_total_request_deadline() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for _ in 0..10 {
                if stream.write_all(b"x").is_err() { break; }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let snapshot = Snapshot { port, token: Zeroizing::new("a".repeat(32)), route:"0".repeat(64), address:"unused".into() };
        let started = Instant::now();
        assert!(snapshot.request_with_timeout("/", &json!({}), Duration::from_millis(200)).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        worker.join().unwrap();
    }
    #[test] fn phrase_is_stable_and_separated_by_network() {
        assert_eq!(public_phrase("grin1example"), public_phrase("grin1example"));
        assert_ne!(public_phrase("grin1example"), public_phrase("tgrin1example"));
        assert_eq!(public_phrase("grin1example").split('-').count(), 6);
    }
    #[test] fn saved_opt_out_or_bad_settings_never_enables_publication() {
        assert_eq!(parse_auto_setting(br#"{"catalogue_auto_publish":false}"#).unwrap(), false);
        assert_eq!(parse_auto_setting(br#"{"catalogue_auto_publish":true}"#).unwrap(), true);
        assert!(parse_auto_setting(br#"{"catalogue_auto_publish":"false"}"#).is_err());
        assert!(parse_auto_setting(b"broken json").is_err());
    }
    #[test] fn opt_out_then_missing_file_is_fail_closed() {
        let path = std::env::temp_dir().join(format!("gs-auto-optout-{}-{}.json", std::process::id(), SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::write(&path, br#"{"catalogue_auto_publish":false}"#).unwrap();
        assert_eq!(read_auto_setting(&path).unwrap(), false);
        std::fs::remove_file(&path).unwrap();
        assert!(read_auto_setting(&path).is_err());
    }
    #[test] fn comparison_code_is_derived_from_all_public_claims() {
        let mut claims = json!({"wallet_address":"tgrin1wallet","binding":{"owner":"tgrin1owner","transport_key":"a".repeat(64)}});
        let first = comparison_code_for_claims(&claims).unwrap();
        assert_eq!(first.len(), 14);
        claims["binding"]["transport_key"] = json!("b".repeat(64));
        assert_ne!(first, comparison_code_for_claims(&claims).unwrap());
        claims["binding"]["owner"] = json!("grin1wrongnetwork");
        assert!(comparison_code_for_claims(&claims).is_err());
    }
    #[test] fn retries_failed_and_renews_for_route_change() {
        let now=Instant::now();
        assert!(publication_due(None, "a", now));
        assert!(!publication_due(Some((now, "a")), "a", now));
        assert!(publication_due(Some((now, "a")), "b", now));
        assert!(publication_due(Some((now - Duration::from_secs(12*3600), "a")), "a", now));
    }
}
