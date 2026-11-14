//! End-to-end tests against a local mock control daemon and a synthetic wallet.
//! No user profile, funds, or external network are used.
use super::*;
use bech32::FromBase32;
use ed25519_dalek::Verifier;
use sha2::{Digest, Sha256};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::mpsc;

#[test]
#[ignore = "helper subprocess used by local integration test"]
fn fake_daemon_child() {
    std::thread::sleep(Duration::from_secs(60));
}

fn request(stream: &mut TcpStream) -> Value {
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 2048];
    let body = loop {
        let count = stream.read(&mut chunk).unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(pos) = bytes.windows(4).position(|x| x == b"\r\n\r\n") { break pos + 4; }
    };
    let header = std::str::from_utf8(&bytes[..body]).unwrap();
    let length: usize = header.lines().find_map(|line| line.strip_prefix("Content-Length: ")).unwrap().trim().parse().unwrap();
    while bytes.len() < body + length {
        let count = stream.read(&mut chunk).unwrap();
        assert!(count > 0);
        bytes.extend_from_slice(&chunk[..count]);
    }
    serde_json::from_slice(&bytes[body..body + length]).unwrap()
}

fn reply(stream: &mut TcpStream, status: &str, body: &Value) {
    let data = body.to_string();
    write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{data}", data.len()).unwrap();
}

fn test_service() -> (Arc<Service>, Arc<Wallet>, TcpListener, PathBuf, String, String) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let root = std::env::temp_dir().join(format!("gs-auto-canonical-{}-{now}", std::process::id()));
    std::fs::create_dir_all(root.join("tor-wallet-1")).unwrap();
    std::fs::write(root.join("settings.json"), br#"{"catalogue_auto_publish":true}"#).unwrap();
    std::fs::write(root.join("tor-wallet-1/chat-api.token"), "z".repeat(32)).unwrap();
    let phrase = grin_keychain::mnemonic::from_entropy(&[9u8; 16]).unwrap();
    let wallet = Arc::new(Wallet { name: "synthetic".into(), network: Network::Floonet, dir: root.clone(), phrase: Zeroizing::new(phrase) });
    let address = verified_wallet_address(&wallet).unwrap();
    std::fs::write(root.join("address.txt"), &address).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let route = "0".repeat(64);
    let status = json!({"glauxnet":"nostr_direct", "chat_port":port, "glaux_route":route});
    std::fs::write(root.join("tor-wallet-1/status.json"), status.to_string()).unwrap();
    let service = Arc::new(Service::new(Config { data_dir: root.clone(), bin_dir: root.clone(), checkpoints_dir: root.clone() }));
    *service.open.lock().unwrap() = Some(wallet.clone());
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "wallet::catalogue_auto::integration_tests::fake_daemon_child", "--ignored", "--nocapture"])
        .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    *service.tor.lock().unwrap() = Some(child);
    (service, wallet, listener, root, address, route)
}

fn teardown(service: &Service, root: &Path) {
    service.tor_stop();
    *service.open.lock().unwrap() = None;
    for name in ["settings.json", "address.txt", "tor-wallet-1/chat-api.token", "tor-wallet-1/status.json"] {
        std::fs::remove_file(root.join(name)).unwrap();
    }
    std::fs::remove_dir(root.join("tor-wallet-1")).unwrap();
    std::fs::remove_dir(root).unwrap();
}

fn draft_response(body: &Value, address: &str, route: &str, phrase: &str) -> Value {
    let claims = json!({"version":1, "name":phrase, "wallet_address":address,
        "binding":{"owner":address, "transport_key":"a".repeat(64)},
        "sequence":body["sequence"], "revoked":false});
    let mut h = Sha256::new(); h.update(b"grinsight-contact-code-v1\0");
    for part in [address, address, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] {
        h.update((part.len() as u32).to_be_bytes()); h.update(part.as_bytes());
    }
    let hex: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    let code = format!("{}-{}-{}", &hex[..4], &hex[4..8], &hex[8..12]);
    let mut transcript = b"grinsight-public-contact-v1\0".to_vec();
    transcript.extend(serde_json::to_vec(&claims).unwrap());
    let encoded: String = transcript.iter().map(|b| format!("{b:02x}")).collect();
    json!({"claims":claims, "transcript_hex":encoded, "comparison_code":code, "search_phrase":phrase, "route":route})
}

#[test]
fn automatic_publish_retries_and_signs_current_wallet_only() {
    let (svc, wallet, listener, root, address, route) = test_service();
    if let Err(error) = capture(&svc, &wallet) { panic!("initial synthetic snapshot: {error}"); }
    let phrase = public_phrase(&address);
    let expected_phrase = phrase.clone();
    let expected_address = address.clone();
    let (sent_tx, sent_rx) = mpsc::channel();
    let (stage_tx, stage_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        // Fail the first request; the actual background worker must retry.
        let (mut stream, _) = listener.accept().unwrap(); let _ = request(&mut stream);
        stage_tx.send(0).unwrap();
        reply(&mut stream, "503 Unavailable", &json!({"error":"offline"}));
        drop(stream);
        for stage in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let body = request(&mut stream);
            stage_tx.send(stage + 1).unwrap();
            if stage == 0 { reply(&mut stream, "200 OK", &json!({"search_phrase":phrase})); }
            else if stage == 1 { reply(&mut stream, "200 OK", &draft_response(&body, &address, &route, &phrase)); }
            else { sent_tx.send(body).unwrap(); reply(&mut stream, "200 OK", &json!({"ok":true})); }
        }
    });
    let first = svc.chat_catalog_identity().unwrap();
    assert_eq!(first["search_phrase"], expected_phrase);
    let published = sent_rx.recv_timeout(Duration::from_secs(8)).unwrap_or_else(|e| panic!("publication was not retried: {e}; stages={:?}", stage_rx.try_iter().collect::<Vec<_>>()));
    let claims = &published["profile"]["claims"];
    assert_eq!(claims["wallet_address"], expected_address);
    assert_eq!(claims["name"], expected_phrase);
    let mut transcript = b"grinsight-public-contact-v1\0".to_vec();
    transcript.extend(serde_json::to_vec(claims).unwrap());
    let (_, words) = bech32::decode(&expected_address).unwrap();
    let key: [u8; 32] = Vec::<u8>::from_base32(&words).unwrap().try_into().unwrap();
    let text = published["profile"]["wallet_signature"].as_str().unwrap();
    let bytes: Vec<u8> = text.as_bytes().chunks_exact(2).map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16).unwrap()).collect();
    let signature = ed25519_dalek::Signature::from_slice(&bytes).unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap().verify(&transcript, &signature).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if svc.chat_catalog_identity().unwrap()["publication"] == "published" { break; }
        assert!(Instant::now() < deadline, "server acceptance was not reported");
        std::thread::sleep(Duration::from_millis(10));
    }
    server.join().unwrap();
    teardown(&svc, &root);
    drop(wallet);
}

fn interruption_during_draft_prevents_signing_and_publication(switch_profile: bool) {
    let (svc, wallet, listener, root, address, route) = test_service();
    if let Err(error) = capture(&svc, &wallet) { panic!("initial synthetic snapshot: {error}"); }
    let phrase = public_phrase(&address);
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (count_tx, count_rx) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap(); let _ = request(&mut stream);
        started_tx.send(()).unwrap(); release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        reply(&mut stream, "200 OK", &json!({"search_phrase":phrase}));
        drop(stream);
        let (mut stream, _) = listener.accept().unwrap(); let body = request(&mut stream);
        reply(&mut stream, "200 OK", &draft_response(&body, &address, &route, &phrase));
        listener.set_nonblocking(true).unwrap();
        let until = Instant::now() + Duration::from_millis(500);
        let mut third = false;
        while Instant::now() < until { if listener.accept().is_ok() { third = true; break; } std::thread::sleep(Duration::from_millis(10)); }
        count_tx.send(third).unwrap();
    });
    svc.chat_catalog_identity().unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    {
        let _guard = svc.rpc_lifecycle.write().unwrap();
        *svc.open.lock().unwrap() = if switch_profile {
            Some(Arc::new(Wallet { name: "another-synthetic".into(), network: Network::Floonet, dir: root.clone(), phrase: Zeroizing::new(grin_keychain::mnemonic::from_entropy(&[10u8; 16]).unwrap()) }))
        } else { None };
    }
    release_tx.send(()).unwrap();
    assert!(!count_rx.recv_timeout(Duration::from_secs(5)).unwrap(), "publication happened after logout");
    server.join().unwrap();
    teardown(&svc, &root);
    drop(wallet);
}

#[test]
fn logout_during_draft_prevents_signing_and_publication() {
    interruption_during_draft_prevents_signing_and_publication(false);
}

#[test]
fn profile_switch_during_draft_prevents_cross_wallet_publication() {
    interruption_during_draft_prevents_signing_and_publication(true);
}
