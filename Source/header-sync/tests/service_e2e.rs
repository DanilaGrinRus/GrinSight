//! End to end: the app's calls against a real `grinsight-service` process.
//!
//! The core binary is replaced by a copy of THIS test program (it acts as the
//! core when started under that name): network modes (peer probe, header
//! sync, gap proof, broadcast) are simulated, every offline mode (slatepack
//! address, building S1, receiving, finalizing, invoices) runs the REAL core
//! with the phrase on stdin. So the money logic, the seed vault and the RPC
//! are real; only the chain is not.
//!
//! Flow: create two wallets (A, B) -> A opens -> A pays B (S1) -> B receives
//! (S2) -> A finalizes + broadcasts -> A confirms (kernel in a block) ->
//! B issues an invoice -> history, balances, refusals (wrong password, bad
//! token, browser origin, locked wallet, wrong network address).

use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CORE: &str = "reverse-wtema-header-sync";
const TOR: &str = "unity-tor";

fn main() {
    let me = std::env::current_exe().unwrap();
    if me.file_stem().and_then(|s| s.to_str()) == Some(CORE) {
        fake_core();
        return;
    }
    if me.file_stem().and_then(|s| s.to_str()) == Some(TOR) {
        fake_tor();
        return;
    }
    scenario();
    println!("test service_e2e ... ok");
}

// ---------------------------------------------------------------------------
// Simulated core (network modes only)
// ---------------------------------------------------------------------------

fn header(height: u64, ts: i64) -> Vec<u8> {
    let mut h = 5u16.to_be_bytes().to_vec();
    h.extend(height.to_be_bytes());
    h.extend(ts.to_be_bytes());
    h.extend([0u8; 16]);
    h
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

fn fake_core() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let real = std::env::var("GS_REAL_CORE").expect("GS_REAL_CORE");
    let has = |k: &str| args.iter().any(|a| a == k);
    let val = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let vals = |k: &str| args.windows(2).filter(|w| w[0] == k).map(|w| w[1].clone()).collect::<Vec<_>>();
    if has("--probe-peer") {
        for p in vals("--probe-peer") {
            println!("PROBE_PEER={p} OK agent=\"fake\" version=3 caps=0x1 pibd=yes block_hist=1 total_difficulty=100");
        }
        println!("PROBE_ANY_PIBD=yes");
        return;
    }
    if has("--checkpoint-file") {
        let dir = PathBuf::from(val("--state-dir").unwrap());
        let hs: Vec<Vec<u8>> = (6400..=10010u64).map(|h| header(h, now() - (10010 - h as i64) * 60)).collect();
        let mut t = (hs.len() as u32).to_le_bytes().to_vec();
        for h in &hs {
            t.extend((h.len() as u32).to_le_bytes());
            t.extend(h);
        }
        std::fs::write(dir.join("verified-headers.bin"), t).unwrap();
        let hex: String = hs.last().unwrap().iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(dir.join("checkpoint.rwm"), format!("version 1\nheader {hex}\n")).unwrap();
        println!("HEADER_SYNC=PASS\nHEADER_SYNC_PEERS_OK=2/2\nHEADER_SYNC_NETWORK_DIFFICULTY_UNCHECKED_NO_HISTORY=0\nHEADER_SYNC_COMMON_HEADERS=AGREE_FULL_BYTES\nHEADER_SYNC_INDEPENDENT_NETS=2 (a,b)\nHEADER_SYNC_CAUGHT_UP_PEERS=2\nHEADER_SYNC_LAST_HEIGHT=10010\nHEADER_SYNC_CHAIN_SUPPORT=2/2");
        return;
    }
    if has("--gap-headers") {
        // The gap proof is simulated; a payment is built by the REAL core
        // (testnet bench mode) with the phrase from our stdin.
        let mut seeds = String::new();
        if has("--gap-send-to") {
            std::io::stdin().read_to_string(&mut seeds).unwrap();
            let mut c = Command::new(&real)
                .args([
                    "--bench-build-send", "--seeds", "-", "--wallet", "1",
                    "--to", &val("--gap-send-to").unwrap(), "--amount", &val("--gap-send-amount").unwrap(),
                    "--slatepack-out", &val("--gap-slatepack-out").unwrap(), "--context-out", &val("--gap-context-out").unwrap(),
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            c.stdin.take().unwrap().write_all(seeds.as_bytes()).unwrap();
            let out = c.wait_with_output().unwrap();
            print!("{}", String::from_utf8_lossy(&out.stdout));
            assert!(out.status.success(), "bench send failed");
        }
        for k in vals("--gap-kernel") {
            println!("GAP_KERNEL={k} FOUND height=10005 hash={} (bound to kernel_root)", "ab".repeat(32));
        }
        for b in vals("--gap-check-block") {
            println!("GAP_BLOCK_CHECK={b} ON_VERIFIED_CHAIN depth=6");
        }
        println!("GAP_ARCHIVE_HEIGHT=0\nGAP_TIP_HEIGHT=10010\nGAP_WALLET=wallet=1 outputs=0 unspent_at_tip=0 balance_nanogrin=0\nGAP_PROVE_VERDICT=MULTI worst_exit=0");
        return;
    }
    if has("--broadcast-tx") {
        assert!(std::path::Path::new(&val("--broadcast-tx").unwrap()).exists());
        for p in vals("--peer") {
            println!("BROADCAST_TX={p} SENT");
        }
        return;
    }
    // Offline modes: the real core, same arguments, our stdin passed on.
    let st = Command::new(&real).args(&args).status().unwrap();
    std::process::exit(st.code().unwrap_or(1));
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

struct Svc {
    child: std::process::Child,
    port: u16,
    token: String,
}

impl Svc {
    fn raw(&self, body: &str, token: &str, extra: &str) -> (u16, Value) {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        // The service must end every reply itself (also on Windows, where a
        // child started meanwhile holds a copy of the socket): never hang.
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let req = format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {token}\r\n{extra}Content-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            self.port,
            body.len()
        );
        s.write_all(req.as_bytes()).unwrap();
        let mut resp = String::new();
        s.read_to_string(&mut resp).unwrap();
        let code: u16 = resp.split(' ').nth(1).unwrap().parse().unwrap();
        let body = resp.split("\r\n\r\n").nth(1).unwrap_or("");
        (code, serde_json::from_str(body).unwrap_or(Value::Null))
    }

    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }).to_string();
        let (code, v) = self.raw(&body, &self.token, "");
        assert_eq!(code, 200, "{method}: {v}");
        match v.get("error") {
            Some(e) => Err(e["message"].as_str().unwrap_or("").to_string()),
            None => Ok(v["result"].clone()),
        }
    }

    fn ok(&self, method: &str, params: Value) -> Value {
        self.call(method, params.clone()).unwrap_or_else(|e| panic!("{method} {params}: {e}"))
    }

    /// Starts a job method and waits for it.
    fn job(&self, method: &str, params: Value) -> Value {
        let id = self.ok(method, params)["job"].as_str().unwrap().to_string();
        let t0 = Instant::now();
        loop {
            let j = self.ok("job.status", json!({ "id": id, "all": true }));
            match j["state"].as_str().unwrap() {
                "running" => {}
                "done" => return j["result"].clone(),
                other => panic!("{method} job {other}: {} lines={}", j["error"], j["lines"]),
            }
            assert!(t0.elapsed() < Duration::from_secs(300), "{method} job too slow");
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

fn copy_core(bin: &Path) {
    let me = std::env::current_exe().unwrap();
    for name in [CORE, TOR] {
        std::fs::copy(&me, bin.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))).unwrap();
    }
}

/// Simulated unity-tor daemon: takes the phrase on stdin, reports a local
/// GlauxNet (or the remote one when --relay is given, as when Tor fails),
/// then idles until the service kills it (at most 5 minutes).
fn fake_tor() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let val = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    assert_eq!(args.first().map(String::as_str), Some("serve"), "{args:?}");
    assert_eq!(val("--seeds").as_deref(), Some("-"));
    let mut phrase = String::new();
    std::io::stdin().read_to_string(&mut phrase).unwrap();
    assert!(phrase.split_whitespace().count() >= 12, "phrase must arrive on stdin");
    let work = PathBuf::from(val("--user-dir").unwrap()).join("tor-wallet-1");
    std::fs::create_dir_all(&work).unwrap();
    let glaux = match val("--relay") {
        Some(r) => format!("remote {r}"),
        None => "local".into(),
    };
    std::fs::write(
        work.join("status.json"),
        json!({ "onion": "fakefakefake.onion", "messenger_address": "grinmsg1fake", "tor": "ready", "glauxnet": glaux }).to_string(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_secs(300));
}

fn start(root: &Path) -> Svc {
    let mut child = Command::new(env!("CARGO_BIN_EXE_grinsight-service"))
        .args(["serve", "--data-dir"])
        .arg(root.join("data"))
        .arg("--bin-dir")
        .arg(root.join("bin"))
        .arg("--checkpoints")
        .arg(root.join("cp"))
        .env("GS_REAL_CORE", env!("CARGO_BIN_EXE_reverse-wtema-header-sync"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let mut text = String::new();
    let mut b = [0u8; 1];
    while text.matches('\n').count() < 2 {
        out.read_exact(&mut b).unwrap();
        text.push(b[0] as char);
    }
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).unwrap().to_string();
    Svc { port: get("GRINSIGHT_SERVICE_PORT=").parse().unwrap(), token: get("GRINSIGHT_SERVICE_TOKEN="), child }
}

fn scenario() {
    let root = std::env::temp_dir().join(format!("gs-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for d in ["bin", "cp/floonet", "data"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    copy_core(&root.join("bin"));
    // Shipped checkpoint (content irrelevant to the simulated sync) + pins.
    let cp = b"version 1\nheight 900\n";
    let hi = b"history";
    std::fs::write(root.join("cp/floonet/checkpoint.rwm"), cp).unwrap();
    std::fs::write(root.join("cp/floonet/recent-headers.bin"), hi).unwrap();
    std::fs::write(
        root.join("cp/floonet/pin.txt"),
        format!("checkpoint_sha256={}\nhistory_sha256={}\n", unity_state::session::sha256_hex(cp), unity_state::session::sha256_hex(hi)),
    )
    .unwrap();

    let svc = start(&root);

    // Refusals before anything else: token, browser origin, locked wallet.
    let info_body = r#"{"jsonrpc":"2.0","id":1,"method":"service.info"}"#;
    assert_eq!(svc.raw(info_body, "wrong", "").0, 401);
    assert_eq!(svc.raw(info_body, &svc.token, "Origin: http://evil.example\r\n").0, 403);
    assert_eq!(svc.ok("service.info", json!({}))["profiles"], json!([]));
    assert!(svc.call("wallet.status", json!({})).unwrap_err().contains("locked"));

    // Two new wallets (phrases made by the service).
    let pa = svc.ok("wallet.new_phrase", json!({}))["phrase"].as_str().unwrap().to_string();
    let pb = svc.ok("wallet.new_phrase", json!({}))["phrase"].as_str().unwrap().to_string();
    assert_eq!(pa.split(' ').count(), 24);
    assert_eq!(svc.ok("wallet.create", json!({ "name": "alice", "network": "floonet", "phrase": pa, "password": "alice-pass-1" }))["origin"], "new");
    assert_eq!(svc.ok("wallet.create", json!({ "name": "bob", "network": "floonet", "phrase": pb, "password": "bob-pass-12" }))["origin"], "new");
    // A phrase the service did not make is a restore (scan before keys).
    assert_eq!(svc.ok("wallet.create", json!({ "name": "carol", "network": "floonet", "phrase": pa, "password": "carol-pass" }))["origin"], "restored");
    assert!(svc.call("wallet.create", json!({ "name": "alice", "network": "floonet", "phrase": pb, "password": "xxxxxxxxx" })).is_err(), "exists");
    assert!(svc.call("wallet.unlock", json!({ "name": "alice", "network": "floonet", "password": "nope-nope" })).unwrap_err().contains("wrong password"));
    // The vault never holds the phrase in clear.
    let vault = std::fs::read_to_string(root.join("data/profiles/floonet/alice/vault.json")).unwrap();
    assert!(!vault.contains(pa.split(' ').next().unwrap()) || pa.split(' ').next().unwrap().len() < 4);

    // Bob: address (real core, phrase on stdin).
    svc.ok("wallet.unlock", json!({ "name": "bob", "network": "floonet", "password": "bob-pass-12" }));
    let addr_b = svc.ok("wallet.address", json!({}))["address"].as_str().unwrap().to_string();
    assert!(addr_b.starts_with("tgrin1"), "{addr_b}");

    // GlauxNet: on by default, started with the wallet, can be turned off
    // and on; a remote GlauxNet is only a fallback URL.
    let glaux = |want: &str| {
        let t = Instant::now();
        loop {
            let g = svc.ok("glauxnet.status", json!({}));
            if g["state"] == want {
                return g;
            }
            assert!(t.elapsed() < Duration::from_secs(20), "GlauxNet state {g} (want {want})");
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    assert_eq!(svc.ok("wallet.settings", json!({}))["glauxnet"], true);
    let g = glaux("local");
    assert_eq!(g["onion"], "fakefakefake.onion");
    assert_eq!(g["messenger_address"], "grinmsg1fake");
    assert_eq!(svc.ok("glauxnet.enable", json!({ "enabled": false }))["state"], "off");
    assert_eq!(svc.ok("wallet.settings", json!({}))["glauxnet"], false);
    assert!(svc.call("wallet.set_settings", json!({ "glauxnet_relay": "ftp://x" })).unwrap_err().contains("http"));
    svc.ok("wallet.set_settings", json!({ "glauxnet_relay": "http://127.0.0.1:9" }));
    assert_eq!(glaux("off")["running"], false);
    svc.ok("glauxnet.enable", json!({ "enabled": true }));
    assert_eq!(glaux("remote")["relay"], "http://127.0.0.1:9");
    svc.ok("wallet.set_settings", json!({ "glauxnet_relay": "" }));
    // Off survives a lock/unlock (no daemon at all), on comes back with it.
    svc.ok("glauxnet.enable", json!({ "enabled": false }));
    let u = svc.ok("wallet.unlock", json!({ "name": "bob", "network": "floonet", "password": "bob-pass-12" }));
    assert_eq!(u["glauxnet"]["state"], "off");
    svc.ok("glauxnet.enable", json!({ "enabled": true }));
    glaux("local");

    // Carol (restored, never opened): may not hand out keys yet.
    svc.ok("wallet.unlock", json!({ "name": "carol", "network": "floonet", "password": "carol-pass" }));
    assert!(svc.call("wallet.invoice", json!({ "amount": 5 })).unwrap_err().contains("open the wallet once"));

    // Alice: open (checkpoint -> peers -> sync -> proven update).
    svc.ok("wallet.unlock", json!({ "name": "alice", "network": "floonet", "password": "alice-pass-1" }));
    svc.ok("wallet.set_settings", json!({ "extra_peers": ["192.0.2.1:13414", "198.51.100.7:13414"], "auto_broadcast": true }));
    let opened = svc.job("wallet.open", json!({}));
    assert_eq!(opened["last_open"]["tip_height"], 10010);
    assert_eq!(opened["last_open"]["current_tip_state"], "AT_VERIFIED_TIP_ONLY");
    let st = svc.ok("wallet.status", json!({}));
    assert_eq!(st["proof"]["session"]["can_spend"], true, "{st}");
    assert_eq!(st["proof"]["session"]["sync_status"], "PASS");
    assert!(svc.call("wallet.send", json!({ "to": "grin1mainnetaddress", "amount": 1 })).unwrap_err().contains("tgrin1"));

    // Alice pays Bob 2 GRIN: S1 built by the real core.
    let sent = svc.job("wallet.send", json!({ "to": addr_b, "amount": 2_000_000_000u64 }));
    let tx_a = sent["tx_id"].as_str().unwrap().to_string();
    let s1 = sent["slatepack"].as_str().unwrap().to_string();
    assert!(s1.contains("BEGINSLATEPACK"));
    let pay = svc.ok("wallet.payments", json!({}));
    assert_eq!(pay["payments"][0]["stage"], "waiting_answer", "{pay}");

    // Bob receives (real core): S2 + incoming in his balance.
    svc.ok("wallet.unlock", json!({ "name": "bob", "network": "floonet", "password": "bob-pass-12" }));
    let got = svc.ok("wallet.receive", json!({ "slatepack": s1 }));
    assert_eq!(got["amount"], 2_000_000_000u64);
    let s2 = got["answer"].as_str().unwrap().to_string();
    let sb = svc.ok("wallet.status", json!({}));
    assert_eq!(sb["balance"]["incoming_nanogrin"], 2_000_000_000u64, "{sb}");
    assert_eq!(svc.ok("wallet.payments", json!({}))["payments"][0]["stage"], "waiting_sender");
    // The same S1 again: the same answer (no second key).
    let again = svc.ok("wallet.receive", json!({ "slatepack": s1 }));
    assert_eq!(again["answer"], got["answer"]);
    assert_eq!((again["tx_id"].clone(), again["resent"].clone()), (got["tx_id"].clone(), json!(true)));

    // Alice finalizes (real core validates the transaction) and broadcasts.
    svc.ok("wallet.unlock", json!({ "name": "alice", "network": "floonet", "password": "alice-pass-1" }));
    let fin = svc.job("wallet.finalize", json!({ "tx_id": tx_a, "answer": s2 }));
    assert_eq!(fin["kernel"].as_str().unwrap().len(), 66, "{fin}");
    assert!(fin["broadcast"]["peers_sent"].as_u64().unwrap() >= 1);
    assert!(svc.call("wallet.finalize", json!({ "tx_id": tx_a, "answer": s2 })).unwrap_err().contains("already finalized"));
    let after = svc.ok("wallet.payments", json!({}));
    assert_eq!(after["payments"][0]["stage"], "broadcast");
    assert_eq!(after["payments"][0]["payment_proof"], true, "receiver signature kept by finalize");

    // Confirm: kernel in block 10005 of a tip at 10010 -> depth 6 (in block).
    let c = svc.job("wallet.confirm", json!({ "tx_id": tx_a }));
    assert_eq!((c["state"].as_str(), c["height"].as_u64(), c["depth"].as_u64()), (Some("in_block"), Some(10005), Some(6)), "{c}");
    // Again: the earlier block is re-checked on the chain verified now.
    let c2 = svc.job("wallet.confirm", json!({ "tx_id": tx_a }));
    assert_eq!(c2["state"], "in_block", "{c2}");
    assert_eq!(svc.ok("wallet.payments", json!({}))["payments"][0]["stage"], "in_block");

    // Bob asks Alice for 1 GRIN: invoice I1 by the real core.
    svc.ok("wallet.unlock", json!({ "name": "bob", "network": "floonet", "password": "bob-pass-12" }));
    let inv = svc.ok("wallet.invoice", json!({ "amount": "1000000000" }));
    assert!(inv["slatepack"].as_str().unwrap().contains("BEGINSLATEPACK"));
    let tx_inv = inv["tx_id"].as_str().unwrap();
    assert_eq!(svc.ok("wallet.slatepack", json!({ "tx_id": tx_inv }))["file"], "invoice-i1.txt");
    let pb_list = svc.ok("wallet.payments", json!({}));
    assert_eq!(pb_list["payments"].as_array().unwrap().len(), 2);
    assert!(svc.call("wallet.slatepack", json!({ "tx_id": "../../alice" })).is_err(), "path escape");

    // Locked again: nothing works without the password.
    svc.ok("wallet.lock", json!({}));
    assert!(svc.call("wallet.payments", json!({})).unwrap_err().contains("locked"));
    assert_eq!(svc.ok("service.info", json!({}))["profiles"].as_array().unwrap().len(), 3);

    // Closing stdin (the app exited) stops the service.
    let Svc { mut child, .. } = svc;
    drop(child.stdin.take());
    let t0 = Instant::now();
    while child.try_wait().unwrap().is_none() {
        assert!(t0.elapsed() < Duration::from_secs(10), "service did not stop");
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = std::fs::remove_dir_all(&root);
}
