//! GrinSight data gateway.
//!
//! Untrusted transport/source only: it serves checkpoint/recent-header data.
//! The browser verifies everything; this process never sees seed/keys and never
//! performs chain validation. Production WSS/TLS is terminated by a reverse
//! proxy in front of this plain-WS listener.

mod ws;
mod peer;
mod discovery;
mod full_pibd;

use grin_core::core::hash::{Hash, Hashed};
use grin_core::core::{BlockHeader, SegmentIdentifier};
use grin_core::ser::{self, ProtocolVersion};
use grin_util::ToHex;
use serde_json::{json, Value};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

#[derive(Clone)]
struct HeaderInfo {
    height: u64,
    hash: String,
    raw: String,
}

#[derive(Clone)]
struct Data {
    network: String,
    checkpoint_height: u64,
    checkpoint_text: String,
    headers: Vec<HeaderInfo>,
    checkpoint_hash: String,
    peers: std::sync::Arc<std::sync::RwLock<Vec<String>>>,
    manual_peers: bool,
    no_discovery: bool,
    static_release: bool,
    mainnet: bool,
    max_peers: usize,
    locator: Option<String>,
    max_requests: u64,
    bundle: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

fn load(release_dir: &str) -> Result<Data, String> {
    let cp_path = format!("{release_dir}/checkpoint.rwm");
    let text = std::fs::read_to_string(&cp_path).map_err(|e| format!("{cp_path}: {e}"))?;
    let mut checkpoint_height = 0u64;
    let mut checkpoint_hash = String::new();
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("height ") {
            checkpoint_height = v.trim().parse().map_err(|_| "checkpoint height".to_string())?;
        }
        if let Some(v) = line.strip_prefix("hash ") { checkpoint_hash = v.trim().to_string(); }
    }
    let recent_path = format!("{release_dir}/recent-headers.bin");
    let raw = std::fs::read(&recent_path).map_err(|e| format!("{recent_path}: {e}"))?;
    let parsed = grinsight_state::headers::parse_state_headers(&raw)
        .map_err(|e| format!("recent headers: {e}"))?;
    let headers = parsed
        .into_iter()
        .map(|h| {
            let raw = ser::ser_vec(&h, ProtocolVersion::local())
                .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>())
                .unwrap_or_default();
            HeaderInfo { height: h.height, hash: h.hash().to_hex(), raw }
        })
        .collect();
    Ok(Data {
        network: "floonet".into(),
        checkpoint_height,
        checkpoint_text: text,
        headers,
        checkpoint_hash,
        peers: std::sync::Arc::new(std::sync::RwLock::new(Vec::new())),
        manual_peers: false,
        no_discovery: false,
        static_release: false,
        mainnet: false,
        max_peers: 5,
        locator: None,
        max_requests: 128,
        bundle: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
    })
}

fn reply(stream: &mut TcpStream, id: Value, ok: bool, payload: Value) -> std::io::Result<()> {
    let msg = if ok {
        json!({"id": id, "ok": true, "result": payload})
    } else {
        json!({"id": id, "ok": false, "error": payload})
    };
    ws::write_text(stream, &msg.to_string())
}

fn handle(mut stream: TcpStream, data: Arc<Data>) {
    let mut requests = 0u64;
    // A client that connects and stays silent (or drips bytes) must not hold
    // one of the limited slots: bounded handshake, idle wait and frame time.
    let _ = stream.set_read_timeout(Some(ws::HANDSHAKE_DEADLINE));
    let _ = stream.set_write_timeout(Some(ws::IDLE_TIMEOUT));
    if !matches!(ws::handshake(&mut stream), Ok(true)) { return; }
    loop {
        let _ = stream.set_read_timeout(Some(ws::IDLE_TIMEOUT));
        let mut timed = ws::Deadline { inner: &mut stream, until: std::time::Instant::now() + ws::IDLE_TIMEOUT + ws::FRAME_DEADLINE };
        let text = match ws::read_text(&mut timed) {
            Ok(Some(t)) => t,
            _ => break,
        };
        if text.is_empty() { continue; }
        let req: Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(_) => { let _ = reply(&mut stream, Value::Null, false, json!({"code":"bad_json","message":"invalid JSON"})); continue; }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        requests += 1;
        if requests > data.max_requests {
            let _ = reply(&mut stream, id, false,
                json!({"code":"rate_limited","message":"too many requests on this connection"}));
            break;
        }
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let result = match method {
            "hello" => Ok(json!({
                "protocol": 1,
                "network": data.network,
                "capabilities": ["checkpoint", "headers"],
                "source": "shipped-release",
                "verified_by": "browser",
            })),
            "checkpoint" => Ok(json!({
                "height": data.checkpoint_height,
                "text": data.checkpoint_text,
            })),
            "headers" => {
                let from = req.get("params").and_then(|p| p.get("from")).and_then(|v| v.as_u64()).unwrap_or(0);
                let count = req.get("params").and_then(|p| p.get("count")).and_then(|v| v.as_u64()).unwrap_or(64).min(512);
                let peers = data.peers.read().map(|p| p.clone()).unwrap_or_default();
                let hs: Vec<Value> = if peers.is_empty() && data.static_release {
                    data.headers.iter()
                        .filter(|h| h.height >= from)
                        .take(count as usize)
                        .map(|h| json!({"height": h.height, "hash": h.hash, "header": h.raw}))
                        .collect()
                } else {
                    let locator_hex = req.get("params").and_then(|p| p.get("locator")).and_then(|v| v.as_str())
                        .or(data.locator.as_deref()).unwrap_or(&data.checkpoint_hash);
                    let locator = match Hash::from_hex(locator_hex) {
                        Ok(h) => h,
                        Err(_) => {
                            let _ = reply(&mut stream, id.clone(), false,
                                json!({"code":"bad_checkpoint","message":"checkpoint hash"}));
                            continue;
                        }
                    };
                    if peers.is_empty() {
                        let _ = reply(&mut stream, id.clone(), false,
                            json!({"code":"peers_not_found","message":"no PIBD peers discovered; use --peer or retry"}));
                        continue;
                    }
                    let mut got = None;
                    let mut errors = Vec::new();
                    for peer_arg in &peers {
                        match peer::fetch_headers(peer_arg, locator, std::time::Duration::from_secs(20)) {
                            Ok(headers) => { got = Some((peer_arg.clone(), headers)); break; }
                            Err(e) => errors.push(format!("{peer_arg}: {e}")),
                        }
                    }
                    match got {
                        Some((_peer, headers)) => headers.iter().take(count as usize)
                            .map(|h| {
                                let raw = ser::ser_vec(h, ProtocolVersion::local())
                                    .map(|b| b.iter().map(|x| format!("{x:02x}")).collect::<String>())
                                    .unwrap_or_default();
                                json!({"height": h.height, "hash": h.hash().to_hex(), "header": raw})
                            })
                            .collect(),
                        None => {
                            let _ = reply(&mut stream, id.clone(), false,
                                json!({"code":"peer","message": errors.join("; ")}));
                            continue;
                        }
                    }
                };
                Ok(json!({"headers": hs, "more": false, "source": if peers.is_empty() {"shipped-release"} else {"live-peer"}}))
            }
            "blocks_bundle_hashes" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let arr = params.get("hashes").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let mut hashes = Vec::new();
                for h in arr { if let Some(s) = h.as_str() { if let Ok(hh) = Hash::from_hex(s) { hashes.push(hh); } } }
                if hashes.is_empty() { let _ = reply(&mut stream, id, false, json!({"code":"bad_hashes","message":"hashes"})); continue; }
                let peers = data.peers.read().map(|p| p.clone()).unwrap_or_default();
                let mut got = None; let mut errors = Vec::new();
                for peer_arg in &peers {
                    match peer::fetch_blocks(peer_arg, &hashes, std::time::Duration::from_secs(900)) {
                        Ok(v) => { got = Some(v); break; }
                        Err(e) => errors.push(format!("{peer_arg}: {e}")),
                    }
                }
                match got {
                    Some(blocks) => {
                        let mut out = b"BLK1".to_vec();
                        out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
                        for b in &blocks {
                            let raw = ser::ser_vec(b, ProtocolVersion::local()).unwrap_or_default();
                            out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
                            out.extend_from_slice(&raw);
                        }
                        let n = out.len();
                        if let Ok(mut w) = data.bundle.lock() { *w = out; }
                        Ok(json!({"size": n, "blocks": blocks.len()}))
                    }
                    None => { let _ = reply(&mut stream, id, false, json!({"code":"peer","message": errors.join("; ")})); continue; }
                }
            }
            "blocks_bundle" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let archive_hex = params.get("archive").and_then(|v| v.as_str()).unwrap_or("");
                let archive = match Hash::from_hex(archive_hex) {
                    Ok(h) => h,
                    Err(_) => { let _ = reply(&mut stream, id, false, json!({"code":"bad_archive","message":"archive hash"})); continue; }
                };
                let peers = data.peers.read().map(|p| p.clone()).unwrap_or_default();
                let mut got = None; let mut errors = Vec::new();
                for peer_arg in &peers {
                    match peer::fetch_block_bundle(peer_arg, archive, std::time::Duration::from_secs(60)) {
                        Ok(v) => { got = Some(v); break; }
                        Err(e) => errors.push(format!("{peer_arg}: {e}")),
                    }
                }
                match got {
                    Some(bundle) => {
                        let n = bundle.len();
                        if let Ok(mut w) = data.bundle.lock() { *w = bundle; }
                        Ok(json!({"size": n, "source": "block_bundle"}))
                    }
                    None => { let _ = reply(&mut stream, id, false, json!({"code":"peer","message": errors.join("; ")})); continue; }
                }
            }
            "blocks" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let hashes_json = params.get("hashes").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let mut hashes = Vec::new();
                for h in hashes_json {
                    if let Some(s) = h.as_str() { if let Ok(hh) = Hash::from_hex(s) { hashes.push(hh); } }
                }
                if hashes.is_empty() { let _ = reply(&mut stream, id, false, json!({"code":"bad_hashes","message":"hashes"})); continue; }
                let peers = data.peers.read().map(|p| p.clone()).unwrap_or_default();
                let mut got = None;
                let mut errors = Vec::new();
                for peer_arg in &peers {
                    match peer::fetch_blocks(peer_arg, &hashes, std::time::Duration::from_secs(60)) {
                        Ok(b) => { got = Some(b); break; }
                        Err(e) => errors.push(format!("{peer_arg}: {e}")),
                    }
                }
                match got {
                    Some(blocks) => {
                        let mut out = Vec::new();
                        for b in blocks {
                            let raw = ser::ser_vec(&b, ProtocolVersion::local()).unwrap_or_default();
                            out.push(json!({"height": b.header.height, "hash": b.header.hash().to_hex(), "size": raw.len(), "block": raw.iter().map(|x| format!("{x:02x}")).collect::<String>()}));
                        }
                        Ok(json!({"blocks": out}))
                    }
                    None => { let _ = reply(&mut stream, id, false, json!({"code":"peer","message": errors.join("; ")})); continue; }
                }
            }
            "block" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let hash_hex = params.get("hash").and_then(|v| v.as_str()).unwrap_or("");
                let hash = match Hash::from_hex(hash_hex) {
                    Ok(h) => h,
                    Err(_) => { let _ = reply(&mut stream, id, false, json!({"code":"bad_hash","message":"block hash"})); continue; }
                };
                let peers = data.peers.read().map(|p| p.clone()).unwrap_or_default();
                let mut got = None;
                let mut errors = Vec::new();
                for peer_arg in &peers {
                    match peer::fetch_block(peer_arg, hash, std::time::Duration::from_secs(30)) {
                        Ok(b) => { got = Some(b); break; }
                        Err(e) => errors.push(format!("{peer_arg}: {e}")),
                    }
                }
                match got {
                    Some(b) => match ser::ser_vec(&b, ProtocolVersion::local()) {
                        Ok(raw) => Ok(json!({"height": b.header.height, "hash": b.header.hash().to_hex(), "size": raw.len(), "block": raw.iter().map(|x| format!("{x:02x}")).collect::<String>()})),
                        Err(e) => Err(json!({"code":"serialize","message": format!("{e:?}")})),
                    }
                    None => { let _ = reply(&mut stream, id, false, json!({"code":"peer","message": errors.join("; ")})); continue; }
                }
            }
            "pibd_full" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let archive_hex = params.get("archive").and_then(|v| v.as_str()).unwrap_or("");
                let header_hex = params.get("header").and_then(|v| v.as_str()).unwrap_or("");
                let archive = match Hash::from_hex(archive_hex) {
                    Ok(h) => h,
                    Err(_) => { let _ = reply(&mut stream, id, false, json!({"code":"bad_archive","message":"archive hash"})); continue; }
                };
                let hbytes: Vec<u8> = match (0..header_hex.len()).step_by(2)
                    .map(|i| u8::from_str_radix(&header_hex[i..i+2], 16).ok()).collect::<Option<Vec<u8>>>() {
                    Some(v) if v.len() > 100 => v,
                    _ => { let _ = reply(&mut stream, id, false, json!({"code":"bad_header","message":"header hex"})); continue; }
                };
                let header: BlockHeader = match ser::deserialize_default(&mut &hbytes[..]) {
                    Ok(h) => h,
                    Err(_) => { let _ = reply(&mut stream, id, false, json!({"code":"bad_header","message":"header decode"})); continue; }
                };
                let peers = data.peers.read().map(|p| p.clone()).unwrap_or_default();
                if peers.is_empty() {
                    let _ = reply(&mut stream, id, false, json!({"code":"peers_not_found","message":"no PIBD peers"}));
                    continue;
                }
                let nout = grin_core::core::pmmr::n_leaves(header.output_mmr_size);
                let bc = (nout + 1024 * 512 - 1) / (1024 * 512);
                let oc = SegmentIdentifier::count_segments_required(header.output_mmr_size, 11) as u64;
                let rc = 0u64; // rangeproof/kernel are fetched after the UTXO root passes
                let kc = 0u64;
                let mut got = None;
                let mut errors = Vec::new();
                for peer_arg in &peers {
                    match full_pibd::fetch_full(peer_arg, archive, &header, bc, oc, rc, kc) {
                        Ok(v) => { got = Some(v); break; }
                        Err(e) => errors.push(format!("{peer_arg}: {e}")),
                    }
                }
                match got {
                    Some(bundle) => {
                        let n = bundle.len();
                        if let Ok(mut w) = data.bundle.lock() { *w = bundle; }
                        Ok(json!({"size": n, "bitmap_count": bc, "output_count": oc, "rangeproof_count": rc, "kernel_count": kc}))
                    }
                    None => { let _ = reply(&mut stream, id, false, json!({"code":"peer","message": errors.join("; ")})); continue; }
                }
            }
            "pibd_rproof" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let archive_hex = params.get("archive").and_then(|v| v.as_str()).unwrap_or("");
                let header_hex = params.get("header").and_then(|v| v.as_str()).unwrap_or("");
                let archive = match Hash::from_hex(archive_hex) {
                    Ok(h) => h,
                    Err(_) => { let _ = reply(&mut stream, id, false, json!({"code":"bad_archive","message":"archive hash"})); continue; }
                };
                let hbytes: Vec<u8> = match (0..header_hex.len()).step_by(2)
                    .map(|i| u8::from_str_radix(&header_hex[i..i+2], 16).ok()).collect::<Option<Vec<u8>>>() {
                    Some(v) if v.len() > 100 => v,
                    _ => { let _ = reply(&mut stream, id, false, json!({"code":"bad_header","message":"header hex"})); continue; }
                };
                let header: BlockHeader = match ser::deserialize_default(&mut &hbytes[..]) {
                    Ok(h) => h,
                    Err(_) => { let _ = reply(&mut stream, id, false, json!({"code":"bad_header","message":"header decode"})); continue; }
                };
                let peers = data.peers.read().map(|p| p.clone()).unwrap_or_default();
                if peers.is_empty() {
                    let _ = reply(&mut stream, id, false, json!({"code":"peers_not_found","message":"no PIBD peers"}));
                    continue;
                }
                let oc = SegmentIdentifier::count_segments_required(header.output_mmr_size, 11) as u64;
                let rc = oc;
                let mut got = None;
                let mut errors = Vec::new();
                for peer_arg in &peers {
                    match full_pibd::fetch_full(peer_arg, archive, &header, 0, 0, rc, 0) {
                        Ok(v) => { got = Some(v); break; }
                        Err(e) => errors.push(format!("{peer_arg}: {e}")),
                    }
                }
                match got {
                    Some(bundle) => {
                        let n = bundle.len();
                        if let Ok(mut w) = data.bundle.lock() { *w = bundle; }
                        Ok(json!({"size": n, "bitmap_count": 0, "output_count": 0, "rangeproof_count": rc, "kernel_count": 0}))
                    }
                    None => { let _ = reply(&mut stream, id, false, json!({"code":"peer","message": errors.join("; ")})); continue; }
                }
            }
            "bundle_info" => {
                let b = match data.bundle.lock() { Ok(b) => b, Err(_) => { let _ = reply(&mut stream, id, false, json!({"code":"bundle","message":"lock"})); continue; } };
                Ok(json!({"size": b.len(), "ready": !b.is_empty()}))
            }
            "pibd_chunk" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let off = params.get("offset").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
                let len = params.get("length").and_then(|v| v.as_u64()).unwrap_or(262144).min(262144) as usize;
                let b = match data.bundle.lock() { Ok(b) => b, Err(_) => { let _ = reply(&mut stream, id, false, json!({"code":"bundle","message":"lock"})); continue; } };
                let end = off.saturating_add(len).min(b.len());
                if off > b.len() { let _ = reply(&mut stream, id, false, json!({"code":"range","message":"offset"})); continue; }
                let hex: String = b[off..end].iter().map(|x| format!("{x:02x}")).collect();
                Ok(json!({"offset": off, "length": end - off, "total": b.len(), "data": hex}))
            }
            "pibd" => {
                let params = req.get("params").cloned().unwrap_or(Value::Null);
                let archive_hex = params.get("archive").and_then(|v| v.as_str()).unwrap_or("");
                let leaf = params.get("leaf").and_then(|v| v.as_u64()).unwrap_or(0);
                let archive = match Hash::from_hex(archive_hex) {
                    Ok(h) => h,
                    Err(_) => { let _ = reply(&mut stream, id, false,
                        json!({"code":"bad_archive","message":"archive hash"})); continue; }
                };
                let peers = data.peers.read().map(|p| p.clone()).unwrap_or_default();
                if peers.is_empty() {
                    let _ = reply(&mut stream, id, false,
                        json!({"code":"peers_not_found","message":"no PIBD peers discovered; use --peer or retry"}));
                    continue;
                }
                let mut got = None;
                let mut errors = Vec::new();
                for peer_arg in &peers {
                    match peer::fetch_pibd(peer_arg, archive, leaf) {
                        Ok(b) => { got = Some(b); break; }
                        Err(e) => errors.push(format!("{peer_arg}: {e}")),
                    }
                }
                match got {
                    Some(bundle) => Ok(json!({
                        "archive": archive.to_hex(),
                        "leaf": leaf,
                        "bundle": bundle.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    })),
                    None => { let _ = reply(&mut stream, id, false,
                        json!({"code":"peer","message": errors.join("; ")})); continue; }
                }
            }
            "peers" => Ok(json!({"peers": data.peers.read().map(|p| p.clone()).unwrap_or_default(), "note": "untrusted data sources; browser verifies"})),
            _ => Err(json!({"code":"unsupported","message": format!("unknown method {method}")})),
        };
        match result {
            Ok(r) => { if reply(&mut stream, id, true, r).is_err() { break; } }
            Err(e) => { if reply(&mut stream, id, false, e).is_err() { break; } }
        }
    }
}

fn main() {
    let mut bind = "127.0.0.1:8787".to_string();
    let mut release_dir = "release".to_string();
    let mut peer_args: Vec<String> = Vec::new();
    let mut locator_arg: Option<String> = None;
    let mut max_requests = 128u64;
    let mut max_connections = 64usize;
    let mut no_discovery = false;
    let mut static_release = false;
    let mut discovery_interval = 300u64;
    let mut max_peers = 5usize;
    let mut args_mainnet = false;
    let mut bundle_file_arg: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--mainnet" => args_mainnet = true,
            "--bind" => bind = args.next().unwrap_or(bind),
            "--release-dir" => release_dir = args.next().unwrap_or(release_dir),
            "--peer" => { if let Some(p) = args.next() { peer_args.push(p); } },
            "--locator" => locator_arg = args.next(),
            "--bundle-file" => bundle_file_arg = args.next(),
            "--max-requests-per-conn" => max_requests = args.next().and_then(|v| v.parse().ok()).unwrap_or(max_requests),
            "--max-connections" => max_connections = args.next().and_then(|v| v.parse().ok()).unwrap_or(max_connections),
            "--no-discovery" => no_discovery = true,
            "--static-release" => static_release = true,
            "--discovery-interval" => discovery_interval = args.next().and_then(|v| v.parse().ok()).unwrap_or(discovery_interval),
            "--max-peers" => max_peers = args.next().and_then(|v| v.parse().ok()).unwrap_or(max_peers),
            "--help" | "-h" => {
                println!("grinsight-gateway --bind 127.0.0.1:8787 --release-dir release [--mainnet] [--peer IP:PORT ...] [--no-discovery] [--static-release] [--discovery-interval SECS] [--max-peers N] [--locator genesis|HASH]");
                println!("Plain WS; put a TLS reverse proxy in front for WSS. No keys, no verification.");
                return;
            }
            other => { eprintln!("unknown argument {other}"); std::process::exit(2); }
        }
    }
    grin_core::global::set_global_chain_type(grin_core::global::ChainTypes::Testnet);
    grin_core::global::set_global_chain_type(if args_mainnet { grin_core::global::ChainTypes::Mainnet } else { grin_core::global::ChainTypes::Testnet });
    let data = match load(&release_dir) {
        Ok(mut d) => {
            d.peers = std::sync::Arc::new(std::sync::RwLock::new(peer_args.clone()));
            d.manual_peers = !peer_args.is_empty();
            d.no_discovery = no_discovery;
            d.static_release = static_release;
            d.mainnet = args_mainnet;
            d.max_peers = max_peers;
            d.max_requests = max_requests;
            d.network = if args_mainnet { "mainnet".into() } else { "floonet".into() };
            if let Some(path) = bundle_file_arg.as_deref() {
                d.bundle = std::sync::Arc::new(std::sync::Mutex::new(std::fs::read(path).map_err(|e| format!("{path}: {e}")).unwrap_or_default()));
            }
            d.locator = match locator_arg.as_deref() {
                Some("genesis") => Some(grin_core::global::get_genesis_block().header.hash().to_hex()),
                Some(h) => Some(h.to_string()),
                None => None,
            };
            Arc::new(d)
        },
        Err(e) => { eprintln!("gateway load failed: {e}"); std::process::exit(1); }
    };
    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => { eprintln!("bind {bind}: {e}"); std::process::exit(1); }
    };
    eprintln!(
        "GATEWAY_READY bind={bind} checkpoint_height={} headers={} peer={:?} (plain WS; WSS via TLS proxy)",
        data.checkpoint_height, data.headers.len(), data.peers.read().map(|p| p.clone()).unwrap_or_default()
    );
    if !data.manual_peers && !data.no_discovery {
        let d = data.clone();
        std::thread::spawn(move || loop {
            let pool = discovery::discover(d.mainnet, d.max_peers);
            if !pool.is_empty() {
                if let Ok(mut w) = d.peers.write() { *w = pool; }
                eprintln!("GATEWAY_PEERS_REFRESHED={:?}", d.peers.read().map(|p| p.clone()).unwrap_or_default());
            } else {
                eprintln!("GATEWAY_PEERS_EMPTY discovery returned none");
            }
            std::thread::sleep(std::time::Duration::from_secs(discovery_interval));
        });
    } else if data.peers.read().map(|p| p.is_empty()).unwrap_or(true) {
        eprintln!("GATEWAY_PEERS=NONE (manual/no-discovery mode; WS will return peers_not_found)");
    }
    let active = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for conn in listener.incoming() {
        match conn {
            Ok(s) => {
                if active.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= max_connections {
                    active.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    eprintln!("connection limit reached");
                    drop(s);
                    continue;
                }
                let d = data.clone();
                let a = active.clone();
                std::thread::spawn(move || { handle(s, d); a.fetch_sub(1, std::sync::atomic::Ordering::SeqCst); });
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
}




