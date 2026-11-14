// SPDX-License-Identifier: MIT OR Apache-2.0
//! Standalone store-and-forward relay for opaque messenger envelopes.
//!
//! This is the relay half of the Glaux messenger, extracted from the wallet
//! core: there is no wallet, no payment RPC proxy and no external HTTP client.
//! It serves only `/glaux/v1/msg*` (store/fetch/ack) and `/glaux/v1/health`, so
//! recipients can be reached while offline, for example through a Tor onion
//! service in front of the loopback listener.
//!
//! Messenger payloads are **opaque signed+encrypted envelopes** produced by
//! `glaux-messenger`. The gateway deliberately does not receive the sender
//! address: it stores `to`, the opaque payload, size and timestamps only. It
//! cannot verify the sender signature (that is the recipient's job) and must not
//! be trusted for authenticity.
//!
//! Hardening rules:
//! * message ids are UUIDs; ack requires the same recipient address;
//! * public relays require a signed recipient proof bound to the message id;
//! * per-recipient and global queue quotas;
//! * TTL clamped to the gateway maximum; expired records purged.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use glaux_messenger::transport::{HttpConnector, TcpConnector};
use glaux_messenger::{ack::MAX_SKEW_SECS, AckProof, Address};

use crate::error::{Error, Result};

/// Current wall-clock time in Unix milliseconds (the store wire unit).
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

const MAX_REQUEST: usize = 160 * 1024;
const MAX_PAYLOAD: usize = 64 * 1024;
const DEFAULT_TTL_SECS: u64 = 26 * 60 * 60;
const MAX_PER_RECIPIENT: usize = 100;
const MAX_TOTAL: usize = 10_000;
const MAX_CONNECTIONS: usize = 64;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,
    pub to: String,
    /// Opaque `glaux-messenger` envelope JSON (base64 fields inside).
    pub payload: String,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct GatewayConfig {
    /// Loopback address to bind. A public relay normally binds loopback behind
    /// Tor; a reverse proxy may choose another address.
    pub bind: SocketAddr,

    /// Directory for message files; empty = memory only.
    pub store_dir: Option<PathBuf>,
    /// Public relays should require a signed recipient ack, otherwise anyone
    /// knowing an address can delete its mail.
    pub require_signed_ack: bool,
    pub require_v2_ack: bool,
    /// Reject envelopes without a valid proof of work. The P2P listener and
    /// public relays set this; the default keeps internal tests/legacy simple.
    pub require_pow: bool,
    /// Require a signed recipient proof on `GET /glaux/v1/msg` (address +
    /// timestamp + ed25519 signature). Without it anyone who learns an address
    /// can read its mailbox metadata (count, sizes, timestamps, ids). Public
    /// relays should enable this; the default keeps tests/legacy simple.
    pub require_fetch_proof: bool,
    pub ttl_secs: u64,
    pub max_per_recipient: usize,
    pub max_total: usize,
    pub max_payload: usize,
    pub max_posts_per_minute: u32,
    /// Enforce the post-rate limiter. Relay mode keeps it on. The direct-mode
    /// loopback gateway turns it off: every Tor sender arrives from 127.0.0.1,
    /// so a shared per-recipient rate bucket lets one cheap attacker (PoW is
    /// only 18 bits) hold the bucket full and block legitimate incoming
    /// messages. Direct mode instead uses a larger queue and relies on the
    /// recipient's poll/ack loop plus proof of work to drain spam.
    pub enforce_post_rate: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("gateway bind"),
            store_dir: None,
            require_signed_ack: false,
            require_v2_ack: false,
            require_pow: false,
            require_fetch_proof: false,
            ttl_secs: DEFAULT_TTL_SECS,
            max_per_recipient: MAX_PER_RECIPIENT,
            max_total: MAX_TOTAL,
            max_payload: MAX_PAYLOAD,
            max_posts_per_minute: 120,
            enforce_post_rate: true,
        }
    }
}

struct State {
    config: GatewayConfig,
    messages: Mutex<HashMap<String, Message>>,
    /// Per-recipient POST budget for the current minute. This is deliberately
    /// independent from the message-count quota: a flood of tiny messages must
    /// not be able to churn the queue faster than normal delivery.
    posts: Mutex<HashMap<String, (Instant, u32)>>,
    active: AtomicUsize,
}

/// A running gateway. Dropping it stops accepting new connections.
pub struct Gateway {
    addr: SocketAddr,
    running: Arc<AtomicBool>,
}

impl Gateway {
    pub fn start(config: GatewayConfig) -> Result<Self> { Self::start_guarded(config, None) }

    pub fn start_guarded(config: GatewayConfig, gate: Option<glaux_messenger::channel_drain::ChannelDrain>) -> Result<Self> {
        let listener = TcpListener::bind(config.bind).map_err(Error::Io)?;
        let addr = listener.local_addr().map_err(Error::Io)?;
        listener.set_nonblocking(true).map_err(Error::Io)?;

        // A relay restart must not forget persisted messages: POST quotas are
        // checked against this map before the first GET. Loading lazily made a
        // restarted relay accept over-quota posts (audit PT-03).
        let mut messages = HashMap::new();
        if let Some(dir) = &config.store_dir {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    let Ok(bytes) = std::fs::read(&path) else {
                        continue;
                    };
                    if let Ok(message) = serde_json::from_slice::<Message>(&bytes) {
                        messages.insert(message.id.clone(), message);
                    }
                }
            }
        }
        let state = Arc::new(State {
            config,
            messages: Mutex::new(messages),
            posts: Mutex::new(HashMap::new()),
            active: AtomicUsize::new(0),
        });
        let running = Arc::new(AtomicBool::new(true));

        let state_thread = state.clone();
        let running_thread = running.clone();
        std::thread::spawn(move || {
            while running_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let permit = match &gate { Some(g) => match g.enter() { Some(p) => Some(p), None => { let _ = write_response(&mut stream, 503, "application/json", b"{\"error\":\"channel switching\"}"); continue; } }, None => None };
                        // On Windows an accepted socket inherits the listener's
                        // nonblocking flag. Under Tor the request headers may
                        // arrive in a later packet, so a nonblocking first read
                        // would fail with WouldBlock and close without a reply.
                        let _ = stream.set_nonblocking(false);
                        if state_thread.active.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
                            state_thread.active.fetch_sub(1, Ordering::Relaxed);
                            let mut rejected = stream;
                            let _ = write_response(
                                &mut rejected,
                                503,
                                "application/json",
                                b"{\"error\":\"too many connections\"}",
                            );
                            continue;
                        }
                        let state = state_thread.clone();
                        std::thread::spawn(move || {
                            let _permit = permit;
                            let _ = handle(stream, state.clone());
                            state.active.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self { addr, running })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug)]
enum PutError {
    Quota,
    Invalid(String),
    Io(String),
}

fn handle(mut stream: TcpStream, state: Arc<State>) -> Result<()> {
    let peer = stream
        .peer_addr()
        .ok()
        .map(|addr| addr.ip())
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .map_err(Error::Io)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(15)))
        .map_err(Error::Io)?;

    let (method, path, body) = read_request(&mut stream)?;
    let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
    let route = path.split('?').next().unwrap_or("").to_string();

    match (method.as_str(), route.as_str()) {
        ("POST", "/glaux/v1/msg") => {
            if body.len() > state.config.max_payload {
                return write_response(
                    &mut stream,
                    413,
                    "application/json",
                    b"{\"error\":\"payload too large\"}",
                );
            }
            let value: Value = match serde_json::from_slice(&body) {
                Ok(value) => value,
                Err(_) => {
                    return write_response(
                        &mut stream,
                        400,
                        "application/json",
                        b"{\"error\":\"bad json\"}",
                    )
                }
            };
            let to = value.get("to").and_then(Value::as_str).unwrap_or("");
            let id = value.get("id").and_then(Value::as_str).unwrap_or("");
            let payload = value.get("payload").and_then(Value::as_str).unwrap_or("");
            if Address::parse(to).is_err() {
                return write_response(
                    &mut stream,
                    400,
                    "application/json",
                    b"{\"error\":\"bad recipient\"}",
                );
            }
            let id = match canonical_message_id(id) {
                Some(id) => id,
                None => {
                    return write_response(
                        &mut stream,
                        400,
                        "application/json",
                        b"{\"error\":\"bad id\"}",
                    )
                }
            };
            if payload.is_empty() || payload.len() > state.config.max_payload {
                return write_response(
                    &mut stream,
                    400,
                    "application/json",
                    b"{\"error\":\"bad payload\"}",
                );
            }
            if state.config.require_pow {
                let envelope: glaux_messenger::Envelope = match serde_json::from_str(payload) {
                    Ok(envelope) => envelope,
                    Err(_) => {
                        return write_response(
                            &mut stream,
                            400,
                            "application/json",
                            b"{\"error\":\"pow required\"}",
                        )
                    }
                };
                if envelope.pow_bits == 0
                    || envelope.recipient != to
                    || !same_uuid(&envelope.id, &id)
                    || envelope
                        .verify_pow(glaux_messenger::envelope::POW_MIN_BITS)
                        .is_err()
                {
                    return write_response(
                        &mut stream,
                        400,
                        "application/json",
                        b"{\"error\":\"pow required\"}",
                    );
                }
            }
            let requested = value
                .get("ttl_secs")
                .and_then(Value::as_u64)
                .unwrap_or(state.config.ttl_secs);
            let ttl = requested.clamp(1, state.config.ttl_secs.max(1));
            match store(&state, &id, to, payload, ttl, peer) {
                Ok(message) => {
                    let body = serde_json::to_vec(
                        &json!({"id": message.id, "expires_at": message.expires_at}),
                    )
                    .unwrap_or_default();
                    write_response(&mut stream, 200, "application/json", &body)
                }
                Err(PutError::Quota) => write_response(
                    &mut stream,
                    429,
                    "application/json",
                    b"{\"error\":\"quota\"}",
                ),
                Err(PutError::Invalid(e)) => {
                    let body = format!("{{\"error\":\"{e}\"}}");
                    write_response(&mut stream, 400, "application/json", body.as_bytes())
                }
                Err(PutError::Io(e)) => {
                    let body = format!("{{\"error\":\"store: {e}\"}}");
                    write_response(&mut stream, 500, "application/json", body.as_bytes())
                }
            }
        }
        ("GET", "/glaux/v1/msg") => {
            let to = query_param(query, "to").unwrap_or_default();
            let address = match Address::parse(&to) {
                Ok(address) => address,
                Err(_) => {
                    return write_response(
                        &mut stream,
                        400,
                        "application/json",
                        b"{\"error\":\"bad recipient\"}",
                    )
                }
            };
            if state.config.require_fetch_proof {
                let now = glaux_messenger::envelope::unix_now();
                let ts = query_param(query, "ts").and_then(|value| value.parse::<u64>().ok());
                let signature = query_param(query, "sig").and_then(|value| {
                    data_encoding::HEXLOWER
                        .decode(value.to_ascii_lowercase().as_bytes())
                        .ok()
                        .and_then(|bytes| <[u8; 64]>::try_from(bytes.as_slice()).ok())
                });
                let proof_ok = match (ts, signature) {
                    (Some(ts), Some(signature)) => {
                        ts.abs_diff(now) <= MAX_SKEW_SECS
                            && address.verify_bytes(
                                &glaux_messenger::address::fetch_proof_transcript(&address, ts),
                                &signature,
                            )
                    }
                    _ => false,
                };
                if !proof_ok {
                    return write_response(
                        &mut stream,
                        401,
                        "application/json",
                        b"{\"error\":\"fetch proof required\"}",
                    );
                }
            }
            let limit = query_param(query, "limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(100)
                .clamp(1, 500);
            match list(&state, &to, limit) {
                Ok(items) => {
                    let body = serde_json::to_vec(&json!({"messages": items})).unwrap_or_default();
                    write_response(&mut stream, 200, "application/json", &body)
                }
                Err(PutError::Io(e)) => {
                    let body = format!("{{\"error\":\"store: {e}\"}}");
                    write_response(&mut stream, 500, "application/json", body.as_bytes())
                }
                Err(_) => write_response(
                    &mut stream,
                    400,
                    "application/json",
                    b"{\"error\":\"bad request\"}",
                ),
            }
        }
        ("POST", _) if route.starts_with("/glaux/v1/raw-reject/") => {
            let raw=route.trim_start_matches("/glaux/v1/raw-reject/").trim_end_matches('/');
            let Some(id)=canonical_message_id(raw) else {return write_response(&mut stream,400,"application/json",b"{\"error\":\"bad id\"}")};
            let proof: glaux_messenger::ack::RawRejectProof=match serde_json::from_slice(&body) {
                Ok(p)=>p, Err(_)=>return write_response(&mut stream,400,"application/json",b"{\"error\":\"bad reject proof\"}"),
            };
            let now=glaux_messenger::envelope::unix_now();
            if !same_uuid(&proof.id,&id) || proof.ts.abs_diff(now)>MAX_SKEW_SECS || proof.verify().map(|a|a.to_string()!=proof.to).unwrap_or(true) {
                return write_response(&mut stream,401,"application/json",b"{\"error\":\"bad reject proof\"}");
            }
            match reject_raw(&state,&id,&proof.to,&proof.digest) {
                Ok(true)=>write_response(&mut stream,200,"application/json",b"{\"ok\":true}"),
                Ok(false)=>write_response(&mut stream,409,"application/json",b"{\"error\":\"not rejected\"}"),
                Err(_)=>write_response(&mut stream,500,"application/json",b"{\"error\":\"storage error\"}"),
            }
        }
        ("POST", _) if route.starts_with("/glaux/v2/msg/") && route.ends_with("/ack") => {
            let raw = route.trim_start_matches("/glaux/v2/msg/").trim_end_matches("/ack").trim_end_matches('/');
            let Some(id) = canonical_message_id(raw) else { return write_response(&mut stream, 400, "application/json", b"{\"error\":\"bad id\"}"); };
            let proof: glaux_messenger::ack::AckProofV2 = match serde_json::from_slice(&body) {
                Ok(p) => p,
                Err(_) => return write_response(&mut stream, 400, "application/json", b"{\"error\":\"bad v2 proof\"}"),
            };
            let now = glaux_messenger::envelope::unix_now();
            if !same_uuid(&proof.id, &id) || proof.ts.abs_diff(now) > MAX_SKEW_SECS || proof.verify().is_err() {
                return write_response(&mut stream, 401, "application/json", b"{\"error\":\"invalid v2 proof\"}");
            }
            match ack_v2(&state, &id, &proof.to, &proof.digest) {
                Ok(true) => write_response(&mut stream, 200, "application/json", b"{\"removed\":true}"),
                Ok(false) => write_response(&mut stream, 409, "application/json", b"{\"error\":\"not found or content changed\"}"),
                Err(_) => write_response(&mut stream, 500, "application/json", b"{\"error\":\"store failure\"}"),
            }
        }
        ("POST", _) if route.starts_with("/glaux/v1/msg/") && route.ends_with("/ack") => {
            if state.config.require_v2_ack {
                return write_response(&mut stream, 426, "application/json", b"{\"error\":\"v2 ack required\"}");
            }
            let id = route
                .trim_start_matches("/glaux/v1/msg/")
                .trim_end_matches("/ack")
                .trim_end_matches('/');
            let id = match canonical_message_id(id) {
                Some(id) => id,
                None => {
                    return write_response(
                        &mut stream,
                        400,
                        "application/json",
                        b"{\"error\":\"bad id\"}",
                    )
                }
            };
            let value: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let to = value.get("to").and_then(Value::as_str).unwrap_or("");
            if Address::parse(to).is_err() {
                return write_response(
                    &mut stream,
                    400,
                    "application/json",
                    b"{\"error\":\"bad recipient\"}",
                );
            }
            let proof: Option<AckProof> = serde_json::from_value(value.clone()).ok();
            if state.config.require_signed_ack && proof.is_none() {
                return write_response(
                    &mut stream,
                    401,
                    "application/json",
                    b"{\"error\":\"signed ack required\"}",
                );
            }
            if let Some(proof) = proof.as_ref() {
                let now = glaux_messenger::envelope::unix_now();
                let valid = proof.to == to
                    && same_uuid(&proof.id, &id)
                    && proof.ts.abs_diff(now) <= MAX_SKEW_SECS
                    && proof
                        .verify()
                        .map(|address| address.to_string() == to)
                        .unwrap_or(false);
                if !valid {
                    return write_response(
                        &mut stream,
                        401,
                        "application/json",
                        b"{\"error\":\"bad ack proof\"}",
                    );
                }
            }
            match ack(&state, &id, to) {
                Ok(true) => write_response(&mut stream, 200, "application/json", b"{\"ok\":true}"),
                Ok(false) => write_response(
                    &mut stream,
                    404,
                    "application/json",
                    b"{\"error\":\"not found\"}",
                ),
                Err(PutError::Io(e)) => {
                    let body = format!("{{\"error\":\"store: {e}\"}}");
                    write_response(&mut stream, 500, "application/json", body.as_bytes())
                }
                Err(_) => write_response(
                    &mut stream,
                    400,
                    "application/json",
                    b"{\"error\":\"bad request\"}",
                ),
            }
        }
        ("GET", "/glaux/v1/health") => {
            write_response(&mut stream, 200, "application/json", b"{\"ok\":true}")
        }
        _ => write_response(
            &mut stream,
            404,
            "application/json",
            b"{\"error\":\"not found\"}",
        ),
    }
}

fn store(
    state: &State,
    id: &str,
    to: &str,
    payload: &str,
    ttl_secs: u64,
    peer: std::net::IpAddr,
) -> std::result::Result<Message, PutError> {
    // Per-recipient alone lets one sender burn another user's budget. A public
    // relay gets a per-source-IP budget; on loopback (Tor forwards every
    // connection from 127.0.0.1) that bucket would be shared by all senders and
    // is therefore skipped. Per-recipient and global queue quotas still apply.
    // Direct-mode gateways disable this limiter entirely: with all Tor senders
    // behind 127.0.0.1 a shared bucket means one attacker blocks every peer;
    // queue capacity + PoW + the recipient's ack/drain loop are used instead.
    if state.config.enforce_post_rate {
        if !peer.is_loopback()
            && !allow_post_with(
                state,
                &format!("ip:{peer}"),
                state.config.max_posts_per_minute,
            )
        {
            return Err(PutError::Quota);
        }
        if !allow_post_with(state, to, state.config.max_posts_per_minute) {
            return Err(PutError::Quota);
        }
    }
    let now = now_millis();
    let mut guard = state
        .messages
        .lock()
        .map_err(|_| PutError::Io("store busy".into()))?;
    purge(&state.config, &mut guard, now);

    if let Some(existing) = guard.get(id) {
        if existing.to != to {
            return Err(PutError::Invalid("id belongs to another recipient".into()));
        }
        if existing.payload != payload {
            return Err(PutError::Invalid("conflicting envelope id".into()));
        }
        return Ok(existing.clone());
    }
    let per_recipient = guard.values().filter(|m| m.to == to).count();
    if per_recipient >= state.config.max_per_recipient || guard.len() >= state.config.max_total {
        return Err(PutError::Quota);
    }

    let message = Message {
        id: id.to_string(),
        to: to.to_string(),
        payload: payload.to_string(),
        created_at: now,
        expires_at: now + (ttl_secs as i64) * 1000,
    };
    if let Some(dir) = &state.config.store_dir {
        std::fs::create_dir_all(dir).map_err(|e| PutError::Io(e.to_string()))?;
        let bytes =
            serde_json::to_vec(&message).map_err(|e| PutError::Invalid(format!("msg: {e}")))?;
        std::fs::write(dir.join(format!("{}.json", message.id)), bytes)
            .map_err(|e| PutError::Io(e.to_string()))?;
    }
    guard.insert(message.id.clone(), message.clone());
    Ok(message)
}

const MAX_LIST_BYTES: usize = 2 * 1024 * 1024;

fn list(state: &State, to: &str, limit: usize) -> std::result::Result<Vec<Message>, PutError> {
    let now = now_millis();
    let mut guard = state
        .messages
        .lock()
        .map_err(|_| PutError::Io("store busy".into()))?;

    // Disk is the source of truth after a restart; merge it lazily.
    if let Some(dir) = &state.config.store_dir {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                if uuid::Uuid::parse_str(stem).is_err() {
                    continue;
                }
                if let Ok(bytes) = std::fs::read(&path) {
                    if let Ok(message) = serde_json::from_slice::<Message>(&bytes) {
                        guard.entry(message.id.clone()).or_insert(message);
                    }
                }
            }
        }
    }

    let mut items: Vec<Message> = guard
        .values()
        .filter(|m| m.to == to && m.expires_at > now)
        .cloned()
        .collect();
    items.sort_by_key(|m| m.created_at);
    purge(&state.config, &mut guard, now);
    // Bound the wire response, not just each message. A queue of legal
    // 64 KiB envelopes must not exceed the client's 4 MiB read limit.
    let mut selected = Vec::new();
    let mut bytes = 0usize;
    for item in items {
        let size = item.payload.len().saturating_add(256);
        if selected.len() >= limit.max(1) || bytes.saturating_add(size) > MAX_LIST_BYTES {
            break;
        }
        bytes = bytes.saturating_add(size);
        selected.push(item);
    }
    Ok(selected)
}

/// Fixed one-minute window per recipient. The default is high enough for
/// legitimate retries but bounded; P2P listeners lower it explicitly.
fn allow_post_with(state: &State, to: &str, limit: u32) -> bool {
    let mut guard = match state.posts.lock() {
        Ok(guard) => guard,
        Err(_) => return false,
    };
    let now = Instant::now();
    let entry = guard.entry(to.to_string()).or_insert((now, 0));
    if now.duration_since(entry.0) >= Duration::from_secs(60) {
        *entry = (now, 0);
    }
    if entry.1 >= limit {
        return false;
    }
    entry.1 += 1;
    // Keep the map bounded on relays that see many one-off recipients.
    if guard.len() > 4096 {
        guard.retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(120));
    }
    true
}

fn purge(config: &GatewayConfig, guard: &mut HashMap<String, Message>, now: i64) {
    let expired: Vec<String> = guard
        .values()
        .filter(|m| m.expires_at <= now)
        .map(|m| m.id.clone())
        .collect();
    for id in expired {
        guard.remove(&id);
        if let Some(dir) = &config.store_dir {
            let _ = std::fs::remove_file(dir.join(format!("{id}.json")));
        }
    }
}

fn ack(state: &State, id: &str, to: &str) -> std::result::Result<bool, PutError> {
    let mut guard = state
        .messages
        .lock()
        .map_err(|_| PutError::Io("store busy".into()))?;
    let matches = guard.get(id).is_some_and(|message| message.to == to);
    if !matches {
        return Ok(false);
    }
    guard.remove(id);
    if let Some(dir) = &state.config.store_dir {
        std::fs::remove_file(dir.join(format!("{id}.json")))
            .map_err(|e| PutError::Io(e.to_string()))?;
    }
    Ok(true)
}

/// The digest and recipient are rechecked while holding the message lock; the
/// disk entry is removed before memory to fail closed on I/O failure.
fn reject_raw(state: &State, id: &str, to: &str, digest: &str) -> std::result::Result<bool, PutError> {
    let mut guard=state.messages.lock().map_err(|_|PutError::Io("store busy".into()))?;
    let Some(message)=guard.get(id) else {return Ok(false)};
    if message.to != to || glaux_messenger::ack::raw_payload_digest(&message.payload) != digest || !glaux_messenger::ack::definitely_malformed_raw(&message.payload) {return Ok(false)}
    if let Some(dir)=&state.config.store_dir {
        std::fs::remove_file(dir.join(format!("{id}.json"))).map_err(|e|PutError::Io(e.to_string()))?;
    }
    guard.remove(id);
    Ok(true)
}

fn ack_v2(state: &State, id: &str, to: &str, digest: &str) -> std::result::Result<bool, PutError> {
    let mut guard = state.messages.lock().map_err(|_| PutError::Io("store busy".into()))?;
    let Some(message) = guard.get(id) else { return Ok(false) };
    if message.to != to { return Ok(false); }
    let envelope: glaux_messenger::Envelope = serde_json::from_str(&message.payload).map_err(|_| PutError::Invalid("invalid stored envelope".into()))?;
    if glaux_messenger::ack::envelope_digest(&envelope).map_err(|_| PutError::Invalid("invalid stored envelope".into()))? != digest { return Ok(false); }
    if let Some(dir) = &state.config.store_dir {
        std::fs::remove_file(dir.join(format!("{id}.json"))).map_err(|e| PutError::Io(e.to_string()))?;
    }
    guard.remove(id);
    Ok(true)
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.replace("%40", "@").replace("%20", " "))
    })
}

/// Canonical UUID form (lowercase, hyphenated). Message ids are compared and
/// stored only in this form, so `AABB…` and `aabb…` cannot address two entries
/// or bypass a lookup differently on case-sensitive and case-insensitive
/// filesystems.
fn canonical_message_id(raw: &str) -> Option<String> {
    uuid::Uuid::parse_str(raw.trim())
        .ok()
        .map(|id| id.hyphenated().to_string())
}

fn same_uuid(left: &str, right: &str) -> bool {
    match (
        uuid::Uuid::parse_str(left.trim()),
        uuid::Uuid::parse_str(right.trim()),
    ) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Reduce an absolute-form request target (`http://host:port/path?query`) to the
/// origin-form path used by the gateway router. Origin-form targets pass through
/// unchanged.
fn normalize_request_target(target: &str) -> String {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"));
    match rest {
        Some(rest) => match rest.find('/') {
            Some(index) => rest[index..].to_string(),
            None => "/".to_string(),
        },
        None => target.to_string(),
    }
}

fn read_request(stream: &mut TcpStream) -> Result<(String, String, Vec<u8>)> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end;
    loop {
        let read = stream.read(&mut chunk).map_err(Error::Io)?;
        if read == 0 {
            return Err(Error::Invalid("gateway: пустой запрос".into()));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_REQUEST {
            return Err(Error::Invalid("gateway: запрос слишком большой".into()));
        }
        if let Some(pos) = find(&buffer, b"\r\n\r\n") {
            header_end = pos + 4;
            break;
        }
    }

    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    // Some HTTP clients (hyper sends absolute-form when the request URI carries a
    // scheme+authority) put the whole URL into the request target. Accept both
    // origin-form and absolute-form so middleware/proxies cannot turn a valid
    // `/glaux/v1/*` call into a bogus 404.
    let path = normalize_request_target(&path);
    let length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if length > MAX_REQUEST {
        return Err(Error::Invalid("gateway: тело слишком большое".into()));
    }

    let mut body = buffer[header_end..].to_vec();
    while body.len() < length {
        let read = stream.read(&mut chunk).map_err(Error::Io)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > MAX_REQUEST {
            return Err(Error::Invalid("gateway: тело слишком большое".into()));
        }
    }
    body.truncate(length);
    Ok((method, path, body))
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        400 => "Bad Request",
        404 => "Not Found",
        413 => "Payload Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(Error::Io)?;
    stream.write_all(body).map_err(Error::Io)?;
    stream.flush().map_err(Error::Io)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Wait until the gateway answers on its own health endpoint.
pub fn wait_ready(gateway: &Gateway, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let url = format!("{}/glaux/v1/health", gateway.url());
    let connector = TcpConnector::new();
    while Instant::now() < deadline {
        if let Ok((status, _)) = connector.request("GET", &url, b"") {
            if (200..300).contains(&status) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use glaux_messenger::transport::GatewayTransport;
    use glaux_messenger::{Envelope, Identity, MessageKind, Transport, DEFAULT_TTL_SECS};

    fn addr(seed: u8) -> String {
        Address::from_key("tgrin", [seed; 32])
            .expect("address")
            .to_string()
    }

    #[test]
    fn mixed_gateway_page_drains_bounded_poison_after_encrypted_quarantine() {
        let config=GatewayConfig {require_signed_ack:true,require_v2_ack:true,require_fetch_proof:true,..GatewayConfig::default()};
        let (gateway,url)=start_gateway(config);
        let a=Identity::from_seed([5;32],"tgrin").unwrap();let b=Identity::from_seed([6;32],"tgrin").unwrap();
        let to=b.address().to_string();
        for n in 1..=70 {
            let id=format!("00000000-0000-4000-8000-{n:012}");
            let body=json!({"id":id,"to":to,"payload":"{damaged","ttl_secs":900}).to_string();
            assert_eq!(post(&format!("{url}/glaux/v1/msg"),&body).0,200);
        }
        let valid=Envelope::seal_now(&a,b.address(),MessageKind::Text{text:"deliver".into()},900).unwrap();
        let client=GatewayTransport::new(&url).unwrap();client.deliver(&valid).unwrap();
        let dir=std::env::temp_dir().join(format!("gs-poison-gateway-{}",uuid::Uuid::new_v4()));
        let quarantine=glaux_messenger::raw_quarantine::RawQuarantine::open(&dir,b.address().clone(),[8;32]).unwrap();
        let first=client.fetch_signed_mixed(&b,glaux_messenger::envelope::unix_now(),100).unwrap();
        assert_eq!(first.envelopes.len(),1);assert_eq!(first.malformed.len(),32);assert_eq!(first.omitted_malformed,38);
        for item in first.malformed {let saved=quarantine.save(&item.id,&item.payload).unwrap();client.reject_saved_raw(&b,&quarantine,&saved).unwrap();}
        let second=client.fetch_signed_mixed(&b,glaux_messenger::envelope::unix_now(),100).unwrap();
        assert_eq!(second.envelopes.len(),1);assert_eq!(second.malformed.len(),32);assert_eq!(second.omitted_malformed,6);
        for item in second.malformed {let saved=quarantine.save(&item.id,&item.payload).unwrap();client.reject_saved_raw(&b,&quarantine,&saved).unwrap();}
        let third=client.fetch_signed_mixed(&b,glaux_messenger::envelope::unix_now(),100).unwrap();
        assert_eq!(third.malformed.len(),6);assert_eq!(third.envelopes.len(),1,"valid message is not acknowledged by raw rejects");
        assert_eq!(std::fs::read_dir(&dir).unwrap().filter(|e|e.as_ref().unwrap().path().extension().and_then(|x|x.to_str())==Some("raw")).count(),64);
        drop(gateway);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn raw_reject_is_authenticated_content_specific_and_preserves_unknown_versions() {
        let config=GatewayConfig { require_signed_ack:true, require_v2_ack:true, ..GatewayConfig::default() };
        let (gateway,url)=start_gateway(config);
        let owner=Identity::from_seed([2;32],"tgrin").unwrap();
        let stranger=Identity::from_seed([3;32],"tgrin").unwrap();
        let id="11111111-2222-4333-8444-555555555555";
        let payload="{not valid json";
        let body=json!({"to":owner.address().to_string(),"id":id,"payload":payload,"ttl_secs":900}).to_string();
        assert_eq!(post(&format!("{url}/glaux/v1/msg"),&body).0,200);
        let digest=glaux_messenger::ack::raw_payload_digest(payload);
        let now=glaux_messenger::envelope::unix_now();
        let wrong=glaux_messenger::ack::RawRejectProof::sign(&stranger,id,&digest,now);
        assert_ne!(post(&format!("{url}/glaux/v1/raw-reject/{id}"),&serde_json::to_string(&wrong).unwrap()).0,200);
        let mut forged=glaux_messenger::ack::RawRejectProof::sign(&owner,id,&digest,now);
        forged.digest="00".repeat(32);
        assert_eq!(post(&format!("{url}/glaux/v1/raw-reject/{id}"),&serde_json::to_string(&forged).unwrap()).0,401);
        let v2=glaux_messenger::ack::AckProofV2::sign(&owner,id,&digest,now);
        assert_eq!(post(&format!("{url}/glaux/v1/raw-reject/{id}"),&serde_json::to_string(&v2).unwrap()).0,401,"v2 ACK proof must not authorize raw rejection");
        let proof=glaux_messenger::ack::RawRejectProof::sign(&owner,id,&digest,now);
        assert_eq!(post(&format!("{url}/glaux/v1/raw-reject/{id}"),&serde_json::to_string(&proof).unwrap()).0,200);
        let future=r#"{"version":99,"future":"format"}"#;
        let body=json!({"to":owner.address().to_string(),"id":id,"payload":future,"ttl_secs":900}).to_string();
        assert_eq!(post(&format!("{url}/glaux/v1/msg"),&body).0,200);
        assert_ne!(post(&format!("{url}/glaux/v1/raw-reject/{id}"),&serde_json::to_string(&proof).unwrap()).0,200,"old digest must not delete replacement");
        let proof2=glaux_messenger::ack::RawRejectProof::sign(&owner,id,&glaux_messenger::ack::raw_payload_digest(future),now);
        assert_ne!(post(&format!("{url}/glaux/v1/raw-reject/{id}"),&serde_json::to_string(&proof2).unwrap()).0,200,"unknown version remains untouched");
        assert!(!glaux_messenger::ack::definitely_malformed_raw(r#"{"other":"future"}"#));
        assert!(glaux_messenger::ack::definitely_malformed_raw(r#"{"version":2,"invalid":true}"#));
        drop(gateway);
    }

    #[test]
    fn v2_ack_never_deletes_replacement_and_conflicting_store_fails_closed() {
        let state = State { config: GatewayConfig::default(), messages: Mutex::new(HashMap::new()), posts: Mutex::new(HashMap::new()), active: AtomicUsize::new(0) };
        let a=Identity::from_seed([1;32],"tgrin").unwrap(); let b=Identity::from_seed([2;32],"tgrin").unwrap();
        let first=Envelope::seal_now(&a,b.address(),MessageKind::Text{text:"one".into()},900).unwrap();
        let mut replacement=first.clone(); replacement.ciphertext.push(7);
        let one=serde_json::to_string(&first).unwrap();let two=serde_json::to_string(&replacement).unwrap();
        let ip="127.0.0.1".parse().unwrap();let to=b.address().to_string();
        store(&state,&first.id,&to,&one,900,ip).unwrap();
        assert!(store(&state,&first.id,&to,&two,900,ip).is_err());
        let digest=glaux_messenger::ack::envelope_digest(&first).unwrap();
        assert!(ack_v2(&state,&first.id,&to,&digest).unwrap());
        store(&state,&first.id,&to,&two,900,ip).unwrap();
        assert!(!ack_v2(&state,&first.id,&to,&digest).unwrap());
        assert_eq!(list(&state,&to,10).unwrap().len(),1);
    }

    #[test]
    fn http_v2_ack_requires_valid_exact_proof_and_rejects_legacy() {
        let config=GatewayConfig { require_signed_ack:true, require_v2_ack:true, ..GatewayConfig::default() };
        let (gateway,url)=start_gateway(config);
        let a=Identity::from_seed([1;32],"tgrin").unwrap();let b=Identity::from_seed([2;32],"tgrin").unwrap();
        let e=Envelope::seal_now(&a,b.address(),MessageKind::Text{text:"v2".into()},900).unwrap();
        let client=GatewayTransport::new(&url).unwrap();client.deliver(&e).unwrap();
        let page=client.fetch_signed_tagged(&b,glaux_messenger::envelope::unix_now(),10).unwrap();
        assert_eq!(page.len(),1); let token=page[0].1.clone().unwrap();
        let (id,digest)=token.split_once(':').unwrap();
        let wrong=glaux_messenger::ack::AckProofV2::sign(&a,id,digest,glaux_messenger::envelope::unix_now());
        let (status,_)=post(&format!("{url}/glaux/v2/msg/{id}/ack"),&serde_json::to_string(&wrong).unwrap());
        assert_eq!(status,409);
        let mut forged=glaux_messenger::ack::AckProofV2::sign(&b,id,digest,glaux_messenger::envelope::unix_now());
        forged.digest="00".repeat(32);
        let (status,_)=post(&format!("{url}/glaux/v2/msg/{id}/ack"),&serde_json::to_string(&forged).unwrap());
        assert_eq!(status,401);
        let old=glaux_messenger::AckProof::sign(&b,id,glaux_messenger::envelope::unix_now());
        let (status,_)=post(&format!("{url}/glaux/v1/msg/{id}/ack"),&serde_json::to_string(&old).unwrap());
        assert_eq!(status,426);
        assert_eq!(client.ack_signed(&b,&[token]).unwrap(),1);
        assert!(client.fetch_signed(&b,glaux_messenger::envelope::unix_now(),10).unwrap().is_empty());
        drop(gateway);
    }

    #[test]
    fn per_recipient_post_rate_is_bounded() {
        let state = State {
            config: GatewayConfig::default(),
            messages: Mutex::new(HashMap::new()),
            posts: Mutex::new(HashMap::new()),
            active: AtomicUsize::new(0),
        };
        let limit = state.config.max_posts_per_minute;
        for _ in 0..limit {
            assert!(allow_post_with(&state, "tgrin1recipient", limit));
        }
        assert!(!allow_post_with(&state, "tgrin1recipient", limit));
        assert!(
            allow_post_with(&state, "tgrin1other", limit),
            "budget is per recipient"
        );
    }

    #[test]
    fn per_ip_post_rate_is_bounded_and_independent() {
        let state = State {
            config: GatewayConfig::default(),
            messages: Mutex::new(HashMap::new()),
            posts: Mutex::new(HashMap::new()),
            active: AtomicUsize::new(0),
        };
        let limit = state.config.max_posts_per_minute;
        for _ in 0..limit {
            assert!(allow_post_with(&state, "ip:198.51.100.7", limit));
        }
        assert!(!allow_post_with(&state, "ip:198.51.100.7", limit));
        assert!(
            allow_post_with(&state, "ip:198.51.100.8", limit),
            "per-IP budget leaked to another peer"
        );
    }

    fn start_gateway(config: GatewayConfig) -> (Gateway, String) {
        let gateway = Gateway::start(config).expect("gateway");
        assert!(wait_ready(&gateway, Duration::from_secs(5)));
        let url = gateway.url();
        (gateway, url)
    }

    fn post(url: &str, body: &str) -> (u16, String) {
        let (status, response) = TcpConnector::new()
            .request("POST", url, body.as_bytes())
            .expect("post");
        (status, String::from_utf8_lossy(&response).to_string())
    }

    fn get(url: &str) -> (u16, String) {
        let (status, response) = TcpConnector::new().request("GET", url, b"").expect("get");
        (status, String::from_utf8_lossy(&response).to_string())
    }

    fn put(url: &str, to: &str, payload: &str) -> (u16, String) {
        post(
            &format!("{url}/glaux/v1/msg"),
            &serde_json::to_string(
                &json!({"id": uuid::Uuid::new_v4().to_string(), "to": to, "payload": payload}),
            )
            .unwrap(),
        )
    }

    fn messages(body: &str) -> Vec<Value> {
        let value: Value = serde_json::from_str(body).expect("json");
        value
            .get("messages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }

    /// Minimal SOCKS5 relay that forwards everything to one local port and
    /// records the requested host names. Lets tests exercise onion routing
    /// without a real Tor network.
    fn fake_socks(upstream: u16) -> (String, Arc<AtomicBool>, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        listener.set_nonblocking(true).unwrap();
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let hosts = Arc::new(Mutex::new(Vec::new()));
        let hosts_thread = hosts.clone();
        std::thread::spawn(move || {
            while flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut client, _)) => {
                        let _ = client.set_nonblocking(false);
                        let hosts = hosts_thread.clone();
                        std::thread::spawn(move || {
                            let mut greeting = [0u8; 3];
                            if client.read_exact(&mut greeting).is_err() {
                                return;
                            }
                            if client.write_all(&[5, 0]).is_err() {
                                return;
                            }
                            let mut head = [0u8; 4];
                            if client.read_exact(&mut head).is_err() || head[3] != 3 {
                                return;
                            }
                            let mut len = [0u8; 1];
                            if client.read_exact(&mut len).is_err() {
                                return;
                            }
                            let mut host = vec![0u8; len[0] as usize];
                            if client.read_exact(&mut host).is_err() {
                                return;
                            }
                            let host = String::from_utf8_lossy(&host).to_string();
                            if let Ok(mut log) = hosts.lock() {
                                log.push(host);
                            }
                            let mut port = [0u8; 2];
                            if client.read_exact(&mut port).is_err() {
                                return;
                            }
                            let Ok(mut upstream_stream) =
                                TcpStream::connect(("127.0.0.1", upstream))
                            else {
                                return;
                            };
                            if client.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).is_err() {
                                return;
                            }
                            let Ok(mut to_upstream) = client.try_clone() else {
                                return;
                            };
                            let Ok(mut upstream_writer) = upstream_stream.try_clone() else {
                                return;
                            };
                            let t = std::thread::spawn(move || {
                                let _ = std::io::copy(&mut to_upstream, &mut upstream_writer);
                            });
                            let _ = std::io::copy(&mut upstream_stream, &mut client);
                            let _ = client.shutdown(std::net::Shutdown::Write);
                            let _ = t.join();
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        (addr, running, hosts)
    }

    #[test]
    fn relay_sees_only_recipient_and_opaque_payload() {
        let (_gateway, url) = start_gateway(GatewayConfig::default());
        let alice = Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let bob = Identity::from_seed([9u8; 32], "tgrin").unwrap();
        let envelope = Envelope::seal_now(
            &alice,
            bob.address(),
            MessageKind::Text {
                text: "private".into(),
            },
            DEFAULT_TTL_SECS,
        )
        .unwrap();
        let payload = serde_json::to_string(&envelope).unwrap();

        let (status, body) = put(&url, &bob.address().to_string(), &payload);
        assert_eq!(status, 200, "{body}");
        let value: Value = serde_json::from_str(&body).unwrap();
        let id = value.get("id").and_then(Value::as_str).unwrap().to_string();

        let (status, body) = get(&format!("{url}/glaux/v1/msg?to={}", bob.address()));
        assert_eq!(status, 200);
        assert!(!body.contains(&alice.address().to_string()), "{body}");
        assert!(!body.contains("private"), "{body}");
        let items = messages(&body);
        assert_eq!(items.len(), 1);
        let stored: Envelope =
            serde_json::from_str(items[0].get("payload").and_then(Value::as_str).unwrap()).unwrap();
        let opened = stored
            .open(&bob, glaux_messenger::envelope::unix_now())
            .unwrap();
        assert_eq!(opened.sender, *alice.address());

        let (status, _) = post(
            &format!("{url}/glaux/v1/msg/{id}/ack"),
            &serde_json::to_string(&json!({"to": bob.address().to_string()})).unwrap(),
        );
        assert_eq!(status, 200);
        assert!(messages(&get(&format!("{url}/glaux/v1/msg?to={}", bob.address())).1).is_empty());
    }

    #[test]
    fn require_pow_rejects_an_envelope_without_a_proof() {
        let (_gateway, url) = start_gateway(GatewayConfig {
            require_pow: true,
            ..GatewayConfig::default()
        });
        let alice = Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let bob = Identity::from_seed([9u8; 32], "tgrin").unwrap();
        let envelope = Envelope::seal_now(
            &alice,
            bob.address(),
            MessageKind::Text { text: "pow".into() },
            DEFAULT_TTL_SECS,
        )
        .unwrap();
        let payload = serde_json::to_string(&envelope).unwrap();
        let body = serde_json::to_string(&json!({
            "id": envelope.id,
            "to": bob.address().to_string(),
            "payload": payload,
        }))
        .unwrap();
        let (status, body) = post(&format!("{url}/glaux/v1/msg"), &body);
        assert_eq!(status, 200, "{body}");

        let mut stripped = serde_json::to_value(&envelope).unwrap();
        stripped["pow_bits"] = json!(0);
        stripped["pow_nonce"] = json!(0);
        let stripped = serde_json::to_string(&stripped).unwrap();
        let body = serde_json::to_string(&json!({
            "id": envelope.id,
            "to": bob.address().to_string(),
            "payload": stripped,
        }))
        .unwrap();
        let (status, _) = post(&format!("{url}/glaux/v1/msg"), &body);
        assert_eq!(status, 400, "gateway must reject a proof-less envelope");
    }

    #[test]
    fn sdk_transport_exchanges_messages_through_gateway() {
        use glaux_messenger::Transport;

        let (_gateway, url) = start_gateway(GatewayConfig::default());
        let alice = Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let bob = Identity::from_seed([9u8; 32], "tgrin").unwrap();
        let transport = glaux_messenger::GatewayTransport::new(&url).unwrap();

        let envelope = Envelope::seal_now(
            &alice,
            bob.address(),
            MessageKind::Text {
                text: "via sdk".into(),
            },
            DEFAULT_TTL_SECS,
        )
        .unwrap();
        transport.deliver(&envelope).expect("deliver");

        let now = glaux_messenger::envelope::unix_now();
        let fetched = transport.fetch(bob.address(), now, 10).expect("fetch");
        assert_eq!(fetched.len(), 1);
        let opened = fetched[0].open(&bob, now).expect("open");
        assert_eq!(opened.sender, *alice.address());

        assert_eq!(
            transport
                .ack(bob.address(), std::slice::from_ref(&envelope.id))
                .expect("ack"),
            1
        );
        assert!(transport
            .fetch(bob.address(), now, 10)
            .expect("fetch after ack")
            .is_empty());
    }

    #[test]
    fn sdk_transport_works_through_a_socks_proxy() {
        use glaux_messenger::Transport;

        let (_gateway, _url) = start_gateway(GatewayConfig::default());
        let gateway_port = _gateway.addr().port();
        let (socks, running, _hosts) = fake_socks(gateway_port);
        let transport =
            glaux_messenger::GatewayTransport::with_socks("http://relay.onion", &socks).unwrap();
        assert!(transport.is_onion());
        let alice = Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let bob = Identity::from_seed([9u8; 32], "tgrin").unwrap();
        let envelope = Envelope::seal_now(
            &alice,
            bob.address(),
            MessageKind::Text {
                text: "via tor".into(),
            },
            DEFAULT_TTL_SECS,
        )
        .unwrap();
        transport.deliver(&envelope).expect("deliver via socks");
        let fetched = transport
            .fetch(bob.address(), glaux_messenger::envelope::unix_now(), 10)
            .expect("fetch via socks");
        assert_eq!(fetched.len(), 1);
        running.store(false, Ordering::Relaxed);
    }

    #[test]
    fn gateway_waits_for_a_request_split_across_packets() {
        let (gateway, _url) = start_gateway(GatewayConfig::default());
        let mut stream = TcpStream::connect(gateway.addr()).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .write_all(b"POST /glaux/v1/msg HTTP/1.1\r\nHost: 127.0.0.1\r\n")
            .unwrap();
        stream.flush().unwrap();
        std::thread::sleep(Duration::from_millis(150));
        stream
            .write_all(b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}")
            .unwrap();
        stream.flush().unwrap();

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).expect("response");
        let response = String::from_utf8_lossy(&raw);
        assert!(
            response.starts_with("HTTP/1.1 400"),
            "gateway must answer even when the request arrives in chunks: {response}"
        );
    }

    #[test]
    fn absolute_form_request_target_is_routed_correctly() {
        let (gateway, _url) = start_gateway(GatewayConfig::default());

        let raw_request = |method: &str, target: &str, body: &str| -> String {
            let mut stream = TcpStream::connect(gateway.addr()).expect("connect");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = format!(
                "{method} {target} HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(request.as_bytes()).unwrap();
            stream.flush().unwrap();
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).expect("response");
            String::from_utf8_lossy(&raw).to_string()
        };

        let health = raw_request("GET", "http://example.test/glaux/v1/health", "");
        assert!(
            health.starts_with("HTTP/1.1 200"),
            "absolute-form health request must be routed: {health}"
        );
        assert!(health.contains("\"ok\":true"), "health body: {health}");

        let message = raw_request("POST", "http://example.test/glaux/v1/msg", "{}");
        assert!(
            message.starts_with("HTTP/1.1 400"),
            "absolute-form POST must reach the route (bad recipient => 400, not 404): {message}"
        );
        assert!(
            message.contains("bad recipient"),
            "unexpected body: {message}"
        );
    }

    #[test]
    fn relay_mode_has_no_wallet_and_requires_signed_acks() {
        use glaux_messenger::Transport;

        let (_gateway, url) = start_gateway(GatewayConfig {
            require_signed_ack: true,
            ..GatewayConfig::default()
        });
        assert_eq!(get(&format!("{url}/glaux/v1/health")).0, 200);
        assert_eq!(post(&format!("{url}/v2/foreign"), "{}").0, 404);

        let transport = glaux_messenger::GatewayTransport::new(&url).unwrap();
        let alice = Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let bob = Identity::from_seed([9u8; 32], "tgrin").unwrap();
        let envelope = Envelope::seal_now(
            &alice,
            bob.address(),
            MessageKind::Text {
                text: "offline relay".into(),
            },
            DEFAULT_TTL_SECS,
        )
        .unwrap();
        transport.deliver(&envelope).expect("deliver");
        assert_eq!(
            transport
                .fetch(bob.address(), glaux_messenger::envelope::unix_now(), 10)
                .unwrap()
                .len(),
            1,
            "relay must store the envelope for an offline recipient"
        );

        // Old capability ack without the proof must not delete anything.
        let (status, body) = post(
            &format!("{url}/glaux/v1/msg/{}/ack", envelope.id),
            &serde_json::to_string(&json!({"to": bob.address().to_string()})).unwrap(),
        );
        assert_eq!(status, 401, "{body}");

        let token = format!("{}:{}", envelope.id, glaux_messenger::ack::envelope_digest(&envelope).unwrap());
        let signed = transport
            .ack_signed(&bob, std::slice::from_ref(&token))
            .expect("signed ack");
        assert_eq!(signed, 1);
        assert!(transport
            .fetch(bob.address(), glaux_messenger::envelope::unix_now(), 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn relay_store_survives_a_process_restart() {
        use glaux_messenger::Transport;

        let dir = std::env::temp_dir().join(format!("glaux-relay-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let make = || {
            start_gateway(GatewayConfig {
                require_signed_ack: true,
                store_dir: Some(dir.clone()),
                ..GatewayConfig::default()
            })
        };
        let alice = Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let bob = Identity::from_seed([9u8; 32], "tgrin").unwrap();
        let envelope = Envelope::seal_now(
            &alice,
            bob.address(),
            MessageKind::Text {
                text: "survive restart".into(),
            },
            DEFAULT_TTL_SECS,
        )
        .unwrap();

        {
            let (_gateway, url) = make();
            glaux_messenger::GatewayTransport::new(&url)
                .unwrap()
                .deliver(&envelope)
                .expect("deliver");
        }

        let (_gateway, url) = make();
        let transport = glaux_messenger::GatewayTransport::new(&url).unwrap();
        let fetched = transport
            .fetch(bob.address(), glaux_messenger::envelope::unix_now(), 10)
            .unwrap();
        assert_eq!(fetched.len(), 1);
        let token = format!("{}:{}", envelope.id, glaux_messenger::ack::envelope_digest(&envelope).unwrap());
        assert_eq!(transport.ack_signed(&bob, &[token]).unwrap(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_keeps_the_persisted_post_quota() {
        let dir = std::env::temp_dir().join(format!("glaux-relay-quota-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let config = || GatewayConfig {
            store_dir: Some(dir.clone()),
            max_per_recipient: 1,
            ..GatewayConfig::default()
        };
        let to = addr(3);
        {
            let (_gateway, url) = start_gateway(config());
            assert_eq!(put(&url, &to, "first").0, 200);
        }
        let (_gateway, url) = start_gateway(config());
        assert_eq!(
            put(&url, &to, "second").0,
            429,
            "restart forgot persisted quota"
        );
        assert_eq!(
            messages(&get(&format!("{url}/glaux/v1/msg?to={to}")).1).len(),
            1
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn direct_transport_derives_recipient_onion_and_uses_local_mailbox() {
        use glaux_messenger::{DirectOnionTransport, GatewayTransport, Transport};

        let (_alice_gateway, alice_url) = start_gateway(GatewayConfig::default());
        let (bob_gateway, bob_url) = start_gateway(GatewayConfig::default());
        let (socks, running, hosts) = fake_socks(bob_gateway.addr().port());

        let alice = Identity::from_seed([7u8; 32], "tgrin").unwrap();
        let bob = Identity::from_seed([9u8; 32], "tgrin").unwrap();

        // Alice's transport keeps her own mailbox locally, but delivery is
        // addressed to Bob's address-derived onion.
        let alice_transport = DirectOnionTransport::new(&alice_url, &socks).unwrap();
        let alice_messenger = glaux_messenger::Messenger::new(alice_transport);
        alice_messenger
            .send(
                &alice,
                bob.address(),
                MessageKind::Text {
                    text: "direct onion".into(),
                },
                DEFAULT_TTL_SECS,
            )
            .expect("direct send");

        let requested = hosts.lock().unwrap().clone();
        assert_eq!(
            requested,
            vec![format!("{}.onion", bob.address().onion())],
            "delivery must go to the recipient onion derived from the address"
        );

        let alice_inbox = GatewayTransport::new(&alice_url)
            .unwrap()
            .fetch(alice.address(), glaux_messenger::envelope::unix_now(), 10)
            .unwrap();
        assert!(alice_inbox.is_empty(), "Alice must not receive Bob's mail");

        // Bob receives and acks through his own local gateway.
        let bob_transport = DirectOnionTransport::new(&bob_url, &socks).unwrap();
        let bob_messenger = glaux_messenger::Messenger::new(bob_transport);
        let inbox = bob_messenger.receive(&bob, 10).expect("Bob receives");
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].sender, *alice.address());
        assert!(matches!(
            inbox[0].kind,
            MessageKind::Text { ref text } if text == "direct onion"
        ));
        assert!(GatewayTransport::new(&bob_url)
            .unwrap()
            .fetch(bob.address(), glaux_messenger::envelope::unix_now(), 10)
            .unwrap()
            .is_empty());

        running.store(false, Ordering::Relaxed);
    }

    #[test]
    fn ack_requires_the_same_recipient() {
        let (_gateway, url) = start_gateway(GatewayConfig::default());
        let to = addr(1);
        let (status, body) = put(&url, &to, "opaque");
        assert_eq!(status, 200, "{body}");
        let id: Value = serde_json::from_str(&body).unwrap();
        let id = id.get("id").and_then(Value::as_str).unwrap();

        let (status, _) = post(
            &format!("{url}/glaux/v1/msg/{id}/ack"),
            &serde_json::to_string(&json!({"to": addr(2)})).unwrap(),
        );
        assert_eq!(status, 404);
        let (_, body) = get(&format!("{url}/glaux/v1/msg?to={to}"));
        assert_eq!(messages(&body).len(), 1);

        let (status, _) = post(
            &format!("{url}/glaux/v1/msg/{id}/ack"),
            &serde_json::to_string(&json!({"to": to})).unwrap(),
        );
        assert_eq!(status, 200);
    }

    #[test]
    fn ack_rejects_non_uuid_and_traversal_ids() {
        let (_gateway, url) = start_gateway(GatewayConfig::default());
        for bad in [
            "nope",
            "../../settings",
            "00000000-0000-0000-0000-000000000000",
        ] {
            let (status, _) = post(
                &format!("{url}/glaux/v1/msg/{bad}/ack"),
                &serde_json::to_string(&json!({"to": addr(3)})).unwrap(),
            );
            assert!(status == 400 || status == 404, "{bad} -> {status}");
        }
    }

    #[test]
    fn junk_addresses_and_oversized_payloads_are_rejected() {
        let (_gateway, url) = start_gateway(GatewayConfig::default());
        assert_eq!(put(&url, "not-an-address", "x").0, 400);
        let long = "x".repeat(MAX_PAYLOAD + 1);
        assert_eq!(put(&url, &addr(5), &long).0, 413);
        assert_eq!(get(&format!("{url}/glaux/v1/msg?to=nope")).0, 400);
    }

    #[test]
    fn quotas_are_enforced_per_recipient() {
        let (_gateway, url) = start_gateway(GatewayConfig {
            max_per_recipient: 1,
            ..GatewayConfig::default()
        });
        let to = addr(6);
        assert_eq!(put(&url, &to, "first").0, 200);
        assert_eq!(put(&url, &to, "second").0, 429);
        // One recipient's full mailbox must not consume another recipient's
        // quota: the limit is per recipient, not global.
        assert_eq!(
            put(&url, &addr(7), "other").0,
            200,
            "one recipient blocked another"
        );
    }

    #[test]
    fn a_full_queue_response_stays_below_the_client_limit() {
        let (_gateway, url) = start_gateway(GatewayConfig {
            max_per_recipient: 100,
            ..GatewayConfig::default()
        });
        let to = addr(4);
        let payload = "x".repeat(60 * 1024);
        for _ in 0..40 {
            assert_eq!(put(&url, &to, &payload).0, 200);
        }
        let (status, body) = get(&format!("{url}/glaux/v1/msg?to={to}"));
        assert_eq!(status, 200);
        assert!(
            body.len() < 4 * 1024 * 1024,
            "relay response exceeded client limit: {}",
            body.len()
        );
        assert!(!messages(&body).is_empty(), "page must contain messages");
    }

    #[test]
    fn expired_messages_are_not_delivered() {
        let (_gateway, url) = start_gateway(GatewayConfig::default());
        let to = addr(3);
        let (status, body) = post(
            &format!("{url}/glaux/v1/msg"),
            &serde_json::to_string(&json!({
                "id": uuid::Uuid::new_v4().to_string(), "to": to, "payload": "x", "ttl_secs": 1
            }))
            .unwrap(),
        );
        assert_eq!(status, 200, "{body}");
        std::thread::sleep(Duration::from_millis(1100));
        let (_, body) = get(&format!("{url}/glaux/v1/msg?to={to}"));
        assert!(messages(&body).is_empty());
    }

    #[test]
    fn connection_flood_is_shed_with_503() {
        let (gateway, _url) = start_gateway(GatewayConfig::default());
        let mut idle = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            idle.push(TcpStream::connect(gateway.addr()).expect("idle connect"));
        }
        // Let the accept loop consume all idle sockets; each worker blocks in
        // read_request, so the connection budget is genuinely exhausted.
        std::thread::sleep(Duration::from_millis(300));

        let mut extra = TcpStream::connect(gateway.addr()).expect("extra connect");
        extra
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        extra
            .write_all(b"GET /glaux/v1/msg?to=x HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            .unwrap();
        let mut raw = Vec::new();
        let _ = extra.read_to_end(&mut raw);
        let response = String::from_utf8_lossy(&raw);
        assert!(
            response.starts_with("HTTP/1.1 503"),
            "flood was not shed with 503: {response}"
        );
        drop(idle);
    }

    #[test]
    fn degraded_storage_returns_500_and_keeps_the_message_invisible() {
        let dir = std::env::temp_dir().join(format!("glaux-relay-broken-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        // A regular file where the store directory should be makes every write
        // fail without touching any real storage.
        let broken = dir.join("store");
        std::fs::write(&broken, b"not a directory").unwrap();
        let (_gateway, url) = start_gateway(GatewayConfig {
            store_dir: Some(broken),
            ..GatewayConfig::default()
        });
        let to = addr(11);
        let (status, body) = put(&url, &to, "payload");
        assert_eq!(status, 500, "storage failure was not reported: {body}");
        let (status, body) = get(&format!("{url}/glaux/v1/msg?to={to}"));
        assert_eq!(status, 200);
        assert!(
            messages(&body).is_empty(),
            "failed write leaked into memory: {body}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn direct_mode_queue_does_not_share_the_relay_post_rate() {
        // Direct-mode gateways see every Tor sender as 127.0.0.1. A shared
        // per-recipient rate limiter there let one cheap attacker (18-bit PoW)
        // hold the bucket and block legitimate traffic. The direct config
        // disables the limiter and uses a larger queue instead.
        let (_gateway, url) = start_gateway(GatewayConfig {
            enforce_post_rate: false,
            max_per_recipient: 500,
            max_total: 5_000,
            ..GatewayConfig::default()
        });
        let to = addr(21);
        for n in 0..60 {
            let (status, body) = put(&url, &to, &format!("burst-{n}"));
            assert_eq!(status, 200, "burst message {n} was rate-limited: {body}");
        }
        // A legitimate message after the burst is still accepted.
        let (status, body) = put(&url, &to, "legitimate-after-burst");
        assert_eq!(
            status, 200,
            "legitimate message blocked after burst: {body}"
        );
    }

    #[test]
    fn mixed_case_message_ids_address_the_same_relay_entry() {
        let (_gateway, url) = start_gateway(GatewayConfig::default());
        let bob = Identity::generate("tgrin").expect("bob");
        let to = bob.address().to_string();
        let id = uuid::Uuid::new_v4().to_string();
        let upper = id.to_uppercase();
        let body = |id: &str| {
            serde_json::to_string(&json!({
                "id": id, "to": to, "payload": "ciphertext", "ttl_secs": 60
            }))
            .unwrap()
        };
        let (status, response) = post(&format!("{url}/glaux/v1/msg"), &body(&upper));
        assert_eq!(status, 200, "uppercase post: {response}");
        let (status, response) = post(&format!("{url}/glaux/v1/msg"), &body(&id));
        assert_eq!(status, 200, "lowercase post: {response}");

        let (_, listed) = get(&format!("{url}/glaux/v1/msg?to={to}"));
        let items = messages(&listed);
        assert_eq!(items.len(), 1, "one canonical entry, not two: {listed}");
        assert_eq!(items[0]["id"], id, "ids are returned canonical/lowercase");

        let (status, response) = post(
            &format!("{url}/glaux/v1/msg/{upper}/ack"),
            &serde_json::to_string(&json!({"to": to})).unwrap(),
        );
        assert_eq!(status, 200, "uppercase ack: {response}");
        let (_, listed) = get(&format!("{url}/glaux/v1/msg?to={to}"));
        assert!(
            messages(&listed).is_empty(),
            "uppercase ack must delete the lowercase entry: {listed}"
        );
    }

    #[test]
    fn fetch_requires_a_signed_address_proof_when_enabled() {
        let (_gateway, url) = start_gateway(GatewayConfig {
            require_fetch_proof: true,
            ..GatewayConfig::default()
        });
        let alice = Identity::generate("tgrin").expect("alice");
        let bob = Identity::generate("tgrin").expect("bob");
        let envelope = Envelope::seal_now(
            &alice,
            bob.address(),
            MessageKind::Text {
                text: "signed fetch".into(),
            },
            DEFAULT_TTL_SECS,
        )
        .expect("seal");
        let payload = serde_json::to_string(&envelope).unwrap();
        let to = bob.address().to_string();
        let (status, response) = post(
            &format!("{url}/glaux/v1/msg"),
            &serde_json::to_string(&json!({
                "id": envelope.id, "to": to, "payload": payload, "ttl_secs": 60
            }))
            .unwrap(),
        );
        assert_eq!(status, 200, "{response}");

        // Anonymous fetch: no address proof -> no mailbox metadata leak.
        let (status, response) = get(&format!("{url}/glaux/v1/msg?to={to}"));
        assert_eq!(status, 401, "unsigned fetch must be rejected: {response}");
        // Wrong signature is rejected too.
        let now = glaux_messenger::envelope::unix_now();
        let (status, response) = get(&format!(
            "{url}/glaux/v1/msg?to={to}&ts={now}&sig={}",
            "00".repeat(64)
        ));
        assert_eq!(status, 401, "forged proof must be rejected: {response}");

        // The address holder signs and the mailbox content is returned.
        let transport = GatewayTransport::new(&url).expect("transport");
        let fetched = transport
            .fetch_signed(&bob, glaux_messenger::envelope::unix_now(), 10)
            .expect("signed fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].id, envelope.id);
    }
}
