//! grinsight-service: the wallet core for the GrinSight app (replaces
//! run_user.ps1 and grinsight.py; no Python, no PowerShell).
//!
//! The app starts it and reads two lines from its stdout:
//!   GRINSIGHT_SERVICE_PORT=<port>
//!   GRINSIGHT_SERVICE_TOKEN=<token>
//! then calls JSON-RPC 2.0 on http://127.0.0.1:<port>/rpc with
//! `Authorization: Bearer <token>`. The service stops when its stdin closes
//! (the app exited) or on `service.shutdown`.
//!
//!   grinsight-service serve  [--data-dir D] [--bin-dir D] [--checkpoints D]
//!
//! Command line (test bench / support; same code as the RPC methods):
//!   grinsight-service import-seed-file --file F --index N --name X --network floonet|mainnet
//!   grinsight-service open   --name X --network floonet|mainnet      (sync + proven wallet update)
//!   grinsight-service status --name X --network floonet|mainnet
//!   grinsight-service address --name X --network floonet|mainnet
//!   grinsight-service payments --name X --network floonet|mainnet
//!   grinsight-service new-phrase [--words 12|18|24]   (prints a new phrase; for interop checks, see check_phrases.ps1)
//! The password comes from GRINSIGHT_PASSWORD or is read from stdin.
//!
//! Defaults: data dir = %APPDATA%\GrinSight (Windows) or ~/.grinsight;
//! bin dir = folder of this program; checkpoints = <bin dir>\checkpoints.

#[path = "../../helper_p2p.rs"]
mod helper_p2p;
mod http;
mod jobs;
mod vault;
mod wallet;

use grin_core::core::Transaction;
use grin_core::ser;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use wallet::{network_from, Config, Service};

fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("hex: {e}")))
        .collect()
}

fn relay_tx(hex: &str) -> Result<Value, String> {
    let bytes = hex_to_bytes(hex)?;
    let tx: Transaction = ser::deserialize_default(&mut &bytes[..])
        .map_err(|e| format!("transaction decode: {e:?}"))?;
    crate::helper_p2p::relay_transaction(&tx)?;
    Ok(json!({"relayed": true}))
}
fn arg(v: &[String], k: &str) -> Option<String> {
    v.iter().position(|a| a == k).and_then(|i| v.get(i + 1)).cloned()
}

fn default_data_dir() -> PathBuf {
    if let Some(a) = std::env::var_os("APPDATA") {
        return PathBuf::from(a).join("GrinSight");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
    home.join(".grinsight")
}

fn config(v: &[String]) -> Config {
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|x| x.to_path_buf())).unwrap_or_else(|| PathBuf::from("."));
    let bin_dir = arg(v, "--bin-dir").map(PathBuf::from).unwrap_or(exe_dir);
    Config {
        // Absolute: paths saved in the profile must not depend on the current folder.
        data_dir: grinsight_state::session::resolve_path(&arg(v, "--data-dir").map(PathBuf::from).unwrap_or_else(default_data_dir))
            .unwrap_or_else(|_| default_data_dir()),
        checkpoints_dir: arg(v, "--checkpoints").map(PathBuf::from).unwrap_or_else(|| bin_dir.join("checkpoints")),
        bin_dir,
    }
}

fn random_token() -> Result<String, String> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| e.to_string())?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

fn p_str<'a>(p: &'a Value, k: &str) -> Result<&'a str, String> {
    p.get(k).and_then(Value::as_str).ok_or_else(|| format!("parameter {k} is required"))
}

fn p_u64(p: &Value, k: &str) -> Result<u64, String> {
    match p.get(k) {
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| format!("{k}: whole nanogrin")),
        Some(Value::String(s)) => s.parse().map_err(|_| format!("{k}: whole nanogrin")),
        _ => Err(format!("parameter {k} is required")),
    }
}

/// Every RPC method. Amounts are nanogrin (1 GRIN = 1e9).
pub fn dispatch(svc: &Arc<Service>, method: &str, p: &Value) -> Result<Value, String> {
    // Serialize channel switches and wallet lifecycle against all RPC work.
    let exclusive = matches!(method, "wallet.set_settings" | "wallet.create" | "wallet.restore" | "wallet.unlock" | "wallet.unlock_bound" | "wallet.verify_password_bound" | "wallet.change_password" | "wallet.lock" | "wallet.rename" | "tor.start" | "tor.stop" | "glauxnet.enable");
    let _write = if exclusive { Some(svc.rpc_lifecycle.write().map_err(|_| "wallet lifecycle lock poisoned")?) } else { None };
    let _read = if exclusive { None } else { Some(svc.rpc_lifecycle.read().map_err(|_| "wallet lifecycle lock poisoned")?) };
    match method {
        "service.info" => Ok(json!({
            "version": env!("CARGO_PKG_VERSION"), "schema_version": 1,
            "profiles": svc.profiles(),
            "unlocked": svc.wallet().ok().map(|w| json!({ "name": w.name, "network": if w.network == grinsight_state::session::Network::Mainnet { "mainnet" } else { "floonet" } })),
        })),
        "wallet.new_phrase" => {
            // words: 12 | 18 | 24 (default 24)
            let words = match p.get("words") {
                None | Some(Value::Null) => 24,
                Some(v) => v.as_u64().ok_or("words: 12, 18 or 24")? as usize,
            };
            Ok(json!({ "phrase": *svc.new_phrase(words)?, "words": words }))
        }
        "wallet.check_phrase" => vault::normalize_phrase(p_str(p, "phrase")?).map(|_| json!({ "ok": true })),
        "wallet.create" | "wallet.restore" => {
            let net = network_from(p_str(p, "network")?)?;
            svc.create(p_str(p, "name")?, net, p_str(p, "phrase")?, p_str(p, "password")?, method == "wallet.restore")
        }
        "wallet.unlock" => svc.unlock(p_str(p, "name")?, network_from(p_str(p, "network")?)?, p_str(p, "password")?),
        "wallet.unlock_bound" => svc.unlock_bound(p_str(p, "name")?, network_from(p_str(p, "network")?)?, p_str(p, "password")?, p_str(p, "vault_digest")?),
        "wallet.show_phrase" => svc.show_phrase(p_str(p, "password")?),
        "wallet.change_password" => svc.change_password(p_str(p, "old")?, p_str(p, "new")?),
        "wallet.mutation_identity" => svc.mutation_identity(),
        "wallet.verify_password_bound" => svc.verify_password_bound(p_str(p, "name")?, network_from(p_str(p, "network")?)?, p_str(p, "password")?),
        "wallet.rename" => svc.rename_profile(p_str(p, "name")?),
        "wallet.lock" => {
            svc.lock();
            Ok(json!({ "locked": true }))
        }
        "wallet.status" => svc.status(),
        "wallet.settings" => svc.settings(),
        "wallet.set_settings" => svc.set_settings(p),
        "wallet.address" => svc.address(),
        "wallet.open" => svc.start_open(),
        "wallet.checkpoint_info" => svc.checkpoint_info(p),
        "wallet.own_checkpoint" => svc.start_own_checkpoint(p),
        "experiment.header_proof_peers" => svc.header_proof_peers(p),
        "experiment.header_proof_sample" => svc.header_proof_sample(p),
        "wallet.receive" => match p.get("inbox_file").and_then(Value::as_str) {
            Some(f) => svc.receive_inbox(f),
            None => svc.receive(p_str(p, "slatepack")?),
        },
        "wallet.send" => svc.start_send(p_str(p, "to")?, p_u64(p, "amount")?, p.get("backup_intent")),
        "wallet.finalize" => svc.start_finalize(p_str(p, "tx_id")?, p_str(p, "answer")?, p.get("broadcast").and_then(Value::as_bool)),
        "helper.relay" => relay_tx(p_str(p, "tx")?),
        "wallet.broadcast" => svc.start_broadcast(p_str(p, "tx_id")?),
        "wallet.confirm" => svc.start_confirm(p_str(p, "tx_id")?),
        "wallet.release" => svc.release(p_str(p, "tx_id")?, p.get("force").and_then(Value::as_bool).unwrap_or(false)),
        "wallet.invoice" => svc.invoice_create(p_u64(p, "amount")?, p.get("payer").and_then(Value::as_str), p.get("backup_intent")),
        "wallet.pay_invoice" => {
            let (text, intent) = match p.get("inbox_file").and_then(Value::as_str) {
                Some(f) => (svc.inbox_invoice(f)?, svc.backup_inbox_invoice_intent(f)?),
                None => (p_str(p, "slatepack")?.to_string(), None),
            };
            svc.start_pay_invoice(&text, intent.as_ref())
        }
        "wallet.hide_cancelled" => svc.hide_cancelled(p_str(p, "tx_id")?),
        "wallet.payments" => svc.payments(),
        "wallet.slatepack" => svc.slatepack(p_str(p, "tx_id")?),
        "wallet.slatepacks" => svc.slatepacks(p_str(p, "tx_id")?),
        "job.status" => svc.jobs.get(p_str(p, "id")?).map(|j| j.json(p.get("all").and_then(Value::as_bool).unwrap_or(false))).ok_or_else(|| "no such job".into()),
        "job.list" => Ok(json!({ "jobs": svc.jobs.list() })),
        "job.cancel" => svc.jobs.cancel(p_str(p, "id")?).map(|_| json!({ "cancelling": true })),
        "tor.start" => svc.tor_start(p.get("relay").and_then(Value::as_str)),
        "tor.stop" => {
            svc.tor_stop();
            Ok(json!({ "running": false }))
        }
        "tor.status" => svc.tor_status(),
        "tor.pending" => svc.tor_pending(),
        "tor.decide" => svc.tor_decide(
            p_str(p, "slate_id")?,
            p.get("accept").and_then(Value::as_bool).ok_or("accept: true/false is required")?,
            p.get("add_contact").and_then(Value::as_bool).unwrap_or(true),
            p.get("name").and_then(Value::as_str),
        ),
        "tor.inbox" => svc.tor_inbox(),
        "chat.info" => svc.chat_info(),
        "chat.status" => svc.chat_status(),
        "chat.quarantine_invalid_export" => svc.chat_quarantine_invalid_export(p_str(p, "name_token")?),
        "chat.quarantine_invalid_discard" => {
            if p.get("confirm").and_then(Value::as_bool) != Some(true) { return Err("confirmation required".into()); }
            svc.chat_quarantine_invalid_discard(p_str(p, "name_token")?)
        },
        "chat.quarantine_list" => svc.chat_quarantine_list(),
        "chat.quarantine_export" => svc.chat_quarantine_export(p_str(p, "id")?, p_str(p, "digest")?),
        "chat.quarantine_discard" => {
            if p.get("confirm").and_then(Value::as_bool) != Some(true) { return Err("confirmation required".into()); }
            svc.chat_quarantine_discard(p_str(p, "id")?, p_str(p, "digest")?, p.get("confirm_corrupt").and_then(Value::as_bool) == Some(true))
        },
        "chat.quarantine_cleanup" => {
            if p.get("confirm").and_then(Value::as_bool) != Some(true) { return Err("confirmation required".into()); }
            svc.chat_quarantine_cleanup()
        },
        "chat.deferred_list" => svc.chat_deferred_list(),
        "chat.deferred_retry" => svc.chat_deferred_retry(p_str(p, "route")?),
        "chat.deferred_discard" => {
            if p.get("confirm").and_then(Value::as_bool) != Some(true) { return Err("confirmation required".into()); }
            svc.chat_deferred_discard(p_str(p, "id")?, p_str(p, "route")?)
        },
        "chat.payment_contacts" => svc.backup_payment_contacts(),
        "chat.payment_deliver" => svc.backup_payment_deliver(p_str(p, "tx_id")?, p_str(p, "peer")?, p_str(p, "mode")?, p_str(p, "route")?),
        "chat.payment_retry_info" => svc.backup_payment_retry_info(p_str(p, "tx_id")?),
        "chat.payment_retry" => svc.backup_payment_retry(p_str(p, "tx_id")?),
        "chat.inbox_invoice_validate" => svc.backup_inbox_invoice_validate(p_str(p, "file")?),
        "chat.inbox_invoice_deliver" => svc.backup_inbox_invoice_deliver(p_str(p, "file")?, p_str(p, "tx_id")?),
        "chat.nostr_binding" => svc.chat_nostr_binding(),
        "chat.catalog_search" => svc.chat_catalog_search(p_str(p, "name")?),
        "chat.catalog_own_code" => svc.chat_catalog_own_code(),
        "chat.catalog_identity" => svc.chat_catalog_identity(),
        "chat.catalog_add" => svc.chat_catalog_add(p.get("profile").ok_or("profile required")?, p_str(p, "name")?, p.get("identity_checked").and_then(Value::as_bool)==Some(true)),
        "chat.catalog_publish" => {
            if p.get("consent_public").and_then(Value::as_bool) != Some(true) { return Err("explicit consent to a public profile is required".into()); }
            svc.chat_catalog_publish(p_str(p, "name")?, p.get("revoked").and_then(Value::as_bool).unwrap_or(false))
        },
        "chat.nostr_add" => svc.chat_nostr_add(p.get("binding").ok_or("binding required")?, p_str(p, "name")?),
        "chat.i2p_binding" => svc.chat_i2p_binding(),
        "chat.i2p_add" => svc.chat_i2p_add(p.get("binding").ok_or("binding required")?, p_str(p, "name")?),
        "chat.messages" => svc.chat_messages(p.get("after").and_then(Value::as_u64).unwrap_or(0)),
        "chat.send" => svc.chat_send(p_str(p, "to")?, p_str(p, "text")?),
        "glauxnet.status" => svc.glauxnet_status(),
        "glauxnet.enable" => svc.glauxnet_enable(p.get("enabled").and_then(Value::as_bool).ok_or("enabled: true/false")?),
        "tor.deliver" => svc.tor_deliver(p_str(p, "tx_id")?, p.get("messenger").and_then(Value::as_str), p.get("messenger_only").and_then(Value::as_bool).unwrap_or(false)),
        "contacts.list" => svc.contacts("list", p),
        "contacts.add" => svc.contacts("add", p),
        "contacts.insert" => svc.contacts("insert", p),
        "contacts.remove" => svc.contacts("remove", p),
        "contacts.auto_accept" => svc.contacts("auto_accept", p),
        _ => Err(format!("unknown method {method}")),
    }
}

fn serve(v: &[String]) -> Result<(), String> {
    let svc = Arc::new(Service::new(config(v)));
    std::fs::create_dir_all(&svc.cfg.data_dir).map_err(|e| format!("{}: {e}", svc.cfg.data_dir.display()))?;
    // Only the owner may read the wallet files (Windows: %APPDATA% is per user).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&svc.cfg.data_dir, std::fs::Permissions::from_mode(0o700));
    }
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let token = Arc::new(random_token()?);
    println!("GRINSIGHT_SERVICE_PORT={port}\nGRINSIGHT_SERVICE_TOKEN={token}");
    let _ = std::io::stdout().flush();
    // The parent closes our stdin when it exits: stop then (no orphan).
    {
        let svc = svc.clone();
        std::thread::spawn(move || {
            let mut sink = String::new();
            let stdin = std::io::stdin();
            let mut l = stdin.lock();
            while matches!(l.read_line(&mut sink), Ok(n) if n > 0) {
                sink.clear();
            }
            // The app is gone: stop Tor first, without waiting for in-flight
            // calls, so the daemon never outlives the app.
            svc.tor_stop();
            if let Ok(_lifecycle) = svc.rpc_lifecycle.write() { svc.lock(); }
            std::process::exit(0);
        });
    }
    for s in listener.incoming().flatten() {
        let svc = svc.clone();
        let token = token.clone();
        std::thread::spawn(move || {
            http::serve_one(s, &token, |m, p| {
                if m == "service.shutdown" {
                    let _lifecycle = svc.rpc_lifecycle.write().map_err(|_| "wallet lifecycle lock poisoned")?;
                    svc.lock();
                    std::thread::spawn(|| {
                        std::thread::sleep(std::time::Duration::from_millis(200));
                        std::process::exit(0);
                    });
                    return Ok(json!({ "stopping": true }));
                }
                dispatch(&svc, m, p)
            });
        });
    }
    Ok(())
}

fn password() -> Result<String, String> {
    if let Ok(p) = std::env::var("GRINSIGHT_PASSWORD") {
        return Ok(p);
    }
    eprint!("password: ");
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).map_err(|e| e.to_string())?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

/// Command line: the same calls as the app makes, printed as JSON.
fn cli(mode: &str, v: &[String]) -> Result<Value, String> {
    let svc = Arc::new(Service::new(config(v)));
    let name = arg(v, "--name").ok_or("--name is required")?;
    let net = network_from(&arg(v, "--network").ok_or("--network floonet|mainnet is required")?)?;
    if mode == "import-seed-file" {
        let file = arg(v, "--file").ok_or("--file is required")?;
        let index: usize = arg(v, "--index").and_then(|x| x.parse().ok()).ok_or("--index N is required")?;
        return svc.import_seed_file(std::path::Path::new(&file), index, &name, net, &password()?);
    }
    svc.unlock(&name, net, &password()?)?;
    match mode {
        "status" => svc.status(),
        "address" => svc.address(),
        "payments" => svc.payments(),
        "open" => {
            let id = svc.start_open()?["job"].as_str().unwrap().to_string();
            let job = svc.jobs.get(&id).unwrap();
            let mut shown = 0usize;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                let lines = job.lines.lock().unwrap().clone();
                for l in lines.iter().skip(shown) {
                    eprintln!("  {l}");
                }
                shown = lines.len().max(shown);
                if *job.state.lock().unwrap() != "running" {
                    break;
                }
            }
            let j = job.json(false);
            if j["state"] != "done" {
                return Err(format!("{}: {}", j["state"], j["error"]));
            }
            svc.status()
        }
        _ => Err(format!("unknown mode {mode}")),
    }
}


fn node_cli(v: &[String]) -> Result<Value, String> {
    let sub = v.first().map(String::as_str).unwrap_or("");
    if sub == "serve" {
        grin_core::global::init_global_chain_type(grin_core::global::ChainTypes::Mainnet);
        let data_dir = arg(v, "--data-dir").map(PathBuf::from).unwrap_or_else(default_data_dir);
        let port: u16 = arg(v, "--p2p-port").and_then(|x| x.parse().ok()).unwrap_or(3414);
        let host: std::net::IpAddr = arg(v, "--p2p-host")
            .and_then(|x| x.parse().ok())
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        let state_path = data_dir.join("helper").join("helper.ust2");
        let (state, legacy) = grinsight_state::helper::HelperState::load(
            state_path.to_str().ok_or("bad helper state path")?,
        )?;
        if legacy {
            return Err("helper.ust2 is legacy UST1; run node bootstrap first".into());
        }
        let chain = std::sync::Arc::new(std::sync::Mutex::new(
            grinsight_state::helper::HelperChain::new(state, 10080),
        ));
        eprintln!("HELPER_P2P_START host={host} port={port}");
        return crate::helper_p2p::serve(chain, &data_dir, host, port).map(|_| serde_json::Value::Null);
    }
    if sub != "bootstrap" {
        return Err(format!("unknown node command {sub}"));
    }
    let data_dir = arg(v, "--data-dir").map(PathBuf::from).unwrap_or_else(default_data_dir);
    let headers = arg(v, "--headers").ok_or("--headers FILE is required (validated header transcript)")?;
    let bin_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|x| x.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."));
    let exe = bin_dir.join(if cfg!(windows) { "reverse-wtema-header-sync.exe" } else { "reverse-wtema-header-sync" });
    if !exe.exists() {
        return Err(format!("bootstrap binary not found: {}", exe.display()));
    }
    let helper_dir = data_dir.join("helper");
    std::fs::create_dir_all(&helper_dir).map_err(|e| format!("helper dir: {e}"))?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("--mainnet")
        .arg("--gap-headers")
        .arg(&headers)
        .arg("--gap-bootstrap")
        .arg("--gap-state")
        .arg(&helper_dir);
    let mut i = 0usize;
    while i < v.len() {
        if v[i] == "--peer" {
            if let Some(p) = v.get(i + 1) {
                cmd.arg("--peer").arg(p);
                i += 1;
            }
        } else if v[i] == "--helper-output-segments" {
            cmd.arg("--helper-output-segments");
        } else if v[i] == "--max-msgs-per-min" || v[i] == "--segment-height" || v[i] == "--gap-archive" {
            if let Some(x) = v.get(i + 1) {
                cmd.arg(&v[i]).arg(x);
                i += 1;
            }
        }
        i += 1;
    }
    let out = cmd.output().map_err(|e| format!("run bootstrap: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    print!("{stdout}");
    eprint!("{stderr}");
    if !out.status.success() {
        return Err(format!("bootstrap failed with {}", out.status));
    }
    Ok(serde_json::json!({"helper_state": helper_dir.join("helper.ust2"), "ok": true}))
}
fn main() {
    let v: Vec<String> = std::env::args().skip(1).collect();
    let mode = v.first().cloned().unwrap_or_default();
    let r = match mode.as_str() {
        "serve" => serve(&v[1..]).map(|_| Value::Null),
        "new-phrase" => {
            let words = arg(&v[1..], "--words").and_then(|x| x.parse::<usize>().ok()).unwrap_or(24);
            vault::new_phrase(words).map(|p| {
                println!("{}", *p);
                Value::Null
            })
        }
        "import-seed-file" | "open" | "status" | "address" | "payments" => cli(&mode, &v[1..]),
        "node" => node_cli(&v[1..]),
        _ => {
            eprintln!("usage: grinsight-service serve|import-seed-file|open|status|address|payments|node bootstrap [options] (see the top of main.rs)");
            std::process::exit(2);
        }
    };
    match r {
        Ok(Value::Null) => {}
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(e) => {
            eprintln!("GRINSIGHT=FAIL {e}");
            std::process::exit(1);
        }
    }
}
