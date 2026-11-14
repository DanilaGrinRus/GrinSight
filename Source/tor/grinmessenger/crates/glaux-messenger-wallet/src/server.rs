// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loopback HTTP API used by the `glauxmsg-walletd` sidecar.
//!
//! Security stance: bind loopback only (the daemon refuses non-loopback
//! listeners), require a bearer token for every `/v1` endpoint except
//! `/v1/health`, no CORS headers, no TLS (localhost only), `Cache-Control:
//! no-store`. The token is generated on first start and stored in a `0600` file
//! (Unix) so the wallet can read it from its own process.

use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use crate::identity::write_secret_file;
use crate::service::{capabilities, WalletService, API_VERSION};

const MAX_HEADER: usize = 64 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const TOKEN_ENV: &str = "GLAUXMSG_WALLETD_TOKEN";

/// Bearer token used by the sidecar API.
pub struct AuthToken {
    path: PathBuf,
    token: String,
}

impl AuthToken {
    /// Load a token from `path`, or create a new random one. An existing token
    /// is never overwritten, so a wallet can provision the file itself.
    pub fn load_or_create(path: impl Into<PathBuf>) -> Result<Self, String> {
        let path = path.into();
        if path.exists() {
            let token = fs::read_to_string(&path)
                .map_err(|e| format!("token {}: {e}", path.display()))?
                .trim()
                .to_string();
            if token.len() < 32 {
                return Err(format!(
                    "token {} is too short (expected at least 32 chars)",
                    path.display()
                ));
            }
            return Ok(Self { path, token });
        }
        let token = crate::identity::generate_token()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("token dir: {e}"))?;
        }
        write_secret_file(&path, format!("{token}\n").as_bytes())?;
        Ok(Self { path, token })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Environment-variable override for tests/supervisors. The token file is
    /// still required; this only lets a launcher inject the value without
    /// parsing the file.
    #[allow(dead_code)]
    pub fn from_env(token: String, path: PathBuf) -> Self {
        Self { path, token }
    }

    pub fn verify(&self, provided: &str) -> bool {
        constant_time_eq(provided.as_bytes(), self.token.as_bytes())
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Serve the API until the process exits (or `stop` is set after a connection).
pub fn serve(
    listener: TcpListener,
    service: Arc<WalletService>,
    token: Arc<AuthToken>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    serve_guarded(listener, service, token, stop, None)
}

pub fn serve_guarded(listener: TcpListener, service: Arc<WalletService>, token: Arc<AuthToken>, stop: Arc<AtomicBool>, gate: Option<glaux_messenger::channel_drain::ChannelDrain>) -> Result<(), String> {
    let hold: Arc<std::sync::Mutex<Option<glaux_messenger::channel_drain::Drained>>> = Arc::new(std::sync::Mutex::new(None));
    let control_busy = Arc::new(AtomicBool::new(false));
    for incoming in listener.incoming() {
        if stop.load(Ordering::Relaxed) { return Ok(()); }
        match incoming {
            Ok(stream) => {
                let service=service.clone(); let token=token.clone(); let gate=gate.clone(); let hold=hold.clone(); let busy=control_busy.clone();
                std::thread::spawn(move || handle_guarded_connection(stream, service, token, gate, hold, busy));
            }
            Err(error) => return Err(format!("accept: {error}")),
        }
    }
    Ok(())
}

/// Bind helper that refuses non-loopback addresses. Returns the listener and
/// the concrete bound address.
pub fn bind(listen: &str) -> Result<(TcpListener, SocketAddr), String> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|_| format!("--listen {listen:?}: expected host:port"))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "--listen {addr}: refusing a non-loopback bind; the wallet API must stay local"
        ));
    }
    let listener = TcpListener::bind(addr).map_err(|e| format!("bind {addr}: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    Ok((listener, local))
}

fn handle_guarded_connection(mut stream: TcpStream, service: Arc<WalletService>, token: Arc<AuthToken>, gate: Option<glaux_messenger::channel_drain::ChannelDrain>, hold: Arc<std::sync::Mutex<Option<glaux_messenger::channel_drain::Drained>>>, busy: Arc<AtomicBool>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let response = match read_request(&mut stream) {
        Err(error) => (400, json!({"error":error})),
        Ok(request) if request.method == "POST" && request.path == "/v1/channel/drain" => {
            if !authorized(&request, &token) { (401,json!({"error":"missing or invalid bearer token"})) }
            else if busy.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() { (503,json!({"error":"channel switch already in progress"})) }
            else if let Some(gate) = gate {
                match gate.drain(Duration::from_secs(35)) {
                    Err(error) => { busy.store(false, Ordering::Release); (503,json!({"error":error})) },
                    Ok(drained) => match service.shutdown_and_wait(Duration::from_secs(20)) {
                        Err(error) => { drop(drained); let recovery=service.clone(); let recovering=busy.clone(); std::thread::spawn(move || { if recovery.shutdown_and_wait(Duration::from_secs(180)).is_ok() { recovery.restart_network_after_shutdown(); recovering.store(false, Ordering::Release); } }); (503,json!({"error":error})) },
                        Ok(()) => {
                            *hold.lock().unwrap_or_else(|p| p.into_inner())=Some(drained);
                            let lease=hold.clone(); let recovery=service.clone(); let recovering=busy.clone(); std::thread::spawn(move || { std::thread::sleep(Duration::from_secs(30)); if let Some(drained) = lease.lock().unwrap_or_else(|p| p.into_inner()).take() { recovery.restart_network_after_shutdown(); drop(drained); recovering.store(false, Ordering::Release); } });
                            (200,json!({"drained":true}))
                        }
                    }
                }
            } else { busy.store(false, Ordering::Release); (503,json!({"error":"drain unavailable"})) }
        }
        Ok(request) => {
            let permit=match &gate { Some(g) => match g.enter() { Some(p) => Some(p), None => { let _=write_response(&mut stream,503,&json!({"error":"channel is switching"})); return; } }, None => None };
            let response=route(&service,&token,&request); drop(permit); response
        }
    };
    let _=stream.set_read_timeout(None); let _=write_response(&mut stream,response.0,&response.1);
}

struct Request {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end;
    loop {
        let read = stream.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
        if read == 0 {
            return Err("empty request".into());
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > MAX_HEADER {
            return Err("request headers are too large".into());
        }
        if let Some(position) = find_bytes(&buffer, b"\r\n\r\n") {
            header_end = position + 4;
            break;
        }
    }
    let head = String::from_utf8_lossy(&buffer[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() {
        return Err("malformed request line".into());
    }
    let (path, query) = match target.split_once('?') {
        Some((path, query)) => (path.to_string(), query.to_string()),
        None => (target.clone(), String::new()),
    };
    let mut headers = Vec::new();
    let mut length = 0usize;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name_lower = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if name_lower == "content-length" {
            length = value
                .parse::<usize>()
                .map_err(|_| "bad Content-Length".to_string())?;
        }
        headers.push((name_lower, value));
    }
    if length > MAX_BODY {
        return Err("request body is too large".into());
    }
    let mut body = buffer[header_end..].to_vec();
    while body.len() < length {
        let read = stream
            .read(&mut chunk)
            .map_err(|e| format!("read body: {e}"))?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
        if body.len() > MAX_BODY {
            return Err("request body is too large".into());
        }
    }
    body.truncate(length);
    Ok(Request {
        method,
        path,
        query,
        headers,
        body,
    })
}

fn route(service: &WalletService, token: &AuthToken, request: &Request) -> (u16, Value) {
    // Health is the only unauthenticated endpoint: it exposes no identity data.
    if request.method == "GET" && request.path == "/v1/health" {
        let status = service.status();
        return (
            200,
            json!({
                "ok": true,
                "phase": status.phase,
                "api_version": API_VERSION,
            }),
        );
    }
    if !authorized(request, token) {
        return (401, json!({"error": "missing or invalid bearer token"}));
    }
    let result = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/v1/capabilities") => Ok(json!(capabilities())),
        ("GET", "/v1/status") => Ok(json!(service.status())),
        ("GET", "/v1/nostr/deferred") => service.deferred_status().map(|(items,more)|json!({"items":items.into_iter().map(|(id,received_at,route)|json!({"id":id,"received_at":received_at,"route":route})).collect::<Vec<_>>(),"limit":1000,"more":more})).map_err(ApiError::internal),
        ("POST", "/v1/nostr/deferred/retry") => {
            let body=match body_json(request){Ok(v)=>v,Err(e)=>return (e.status,json!({"error":e.message}))};
            match body.get("route").and_then(Value::as_str) {Some(route)=>service.retry_deferred(route).map(|_|json!({"ok":true})).map_err(ApiError::bad),None=>Err(ApiError::bad("route required"))}
        },
        ("POST", "/v1/nostr/deferred/discard") => {
            let body=match body_json(request){Ok(v)=>v,Err(e)=>return (e.status,json!({"error":e.message}))};
            match (body.get("id").and_then(Value::as_str),body.get("route").and_then(Value::as_str)) {(Some(id),Some(route))=>service.discard_deferred(id,route,body.get("confirm_permanent_deletion").and_then(Value::as_bool)==Some(true)).map(|_|json!({"ok":true})).map_err(ApiError::bad),_=>Err(ApiError::bad("event id and route required"))}
        },
        ("GET", "/v1/quarantine/envelopes") => service.quarantined_envelopes().map(|items|json!({"items":items.into_iter().map(|(id,digest,kind,corrupt,name_token)|json!({"id":id,"digest":digest,"kind":kind,"corrupt":corrupt,"name_token":name_token})).collect::<Vec<_>>()})).map_err(ApiError::internal),
        ("POST", "/v1/quarantine/envelopes/export") => {
            let body=match body_json(request){Ok(v)=>v,Err(e)=>return (e.status,json!({"error":e.message}))};
            match (body.get("id").and_then(Value::as_str),body.get("digest").and_then(Value::as_str)) {
                (Some(id),Some(digest))=>service.export_quarantined_envelope(id,digest).map(|envelope|json!({"envelope":envelope})).map_err(ApiError::bad),
                _=>Err(ApiError::bad("id and digest required")),
            }
        },
        ("POST", "/v1/quarantine/envelopes/discard") => {
            let body=match body_json(request){Ok(v)=>v,Err(e)=>return (e.status,json!({"error":e.message}))};
            match (body.get("id").and_then(Value::as_str),body.get("digest").and_then(Value::as_str)) {
                (Some(id),Some(digest))=>service.discard_quarantined_envelope(id,digest,body.get("confirm_permanent_deletion").and_then(Value::as_bool)==Some(true),body.get("confirm_corrupt").and_then(Value::as_bool)==Some(true)).map(|_|json!({"ok":true})).map_err(ApiError::bad),
                _=>Err(ApiError::bad("id and digest required")),
            }
        },
        ("POST", "/v1/quarantine/invalid-name/export") => {
            let body=match body_json(request){Ok(v)=>v,Err(e)=>return (e.status,json!({"error":e.message}))};
            match body.get("name_token").and_then(Value::as_str) {Some(token)=>service.export_quarantined_invalid_envelope(token).map(|envelope|json!({"envelope":envelope})).map_err(ApiError::bad),_=>Err(ApiError::bad("name token required"))}
        },
        ("POST", "/v1/quarantine/invalid-name/discard") => {
            let body=match body_json(request){Ok(v)=>v,Err(e)=>return (e.status,json!({"error":e.message}))};
            match body.get("name_token").and_then(Value::as_str) {Some(token)=>service.discard_quarantined_invalid_name(token,body.get("confirm_permanent_deletion").and_then(Value::as_bool)==Some(true)).map(|_|json!({"ok":true})).map_err(ApiError::bad),_=>Err(ApiError::bad("name token required"))}
        },
        ("POST", "/v1/quarantine/cleanup-temps") => {
            let body=match body_json(request){Ok(v)=>v,Err(e)=>return (e.status,json!({"error":e.message}))};
            service.cleanup_quarantine_temps(body.get("confirm_cleanup").and_then(Value::as_bool)==Some(true)).map(|removed|json!({"removed":removed})).map_err(ApiError::bad)
        },
        ("GET", "/v1/nostr/binding") => service.nostr_binding().map(|binding| json!({"binding": binding})).map_err(ApiError::internal),
        ("POST", "/v1/catalog/draft") => {
            let body = match body_json(request) { Ok(value) => value, Err(error) => return (error.status, json!({"error":error.message})) };
            match (body.get("name").and_then(Value::as_str), body.get("wallet_address").and_then(Value::as_str), body.get("sequence").and_then(Value::as_u64), body.get("revoked").and_then(Value::as_bool)) {
                (Some(name), Some(wallet), Some(sequence), Some(revoked)) => service.catalogue_draft(name, wallet, sequence, revoked).map_err(ApiError::bad),
                _ => Err(ApiError::bad("name, wallet_address, sequence and revoked are required")),
            }
        },
        ("POST", "/v1/catalog/publish") => {
            let body = match body_json(request) { Ok(value) => value, Err(error) => return (error.status, json!({"error":error.message})) };
            if body.get("consent_public").and_then(Value::as_bool) != Some(true) { return (400, json!({"error":"explicit consent to a public profile is required"})); }
            match (body.get("profile").cloned().and_then(|v| serde_json::from_value(v).ok()), body.get("expected_route").and_then(Value::as_str)) {
                (Some(profile), Some(route)) => service.catalogue_publish(&profile,route).map(|code| json!({"ok":true,"comparison_code":code})).map_err(ApiError::bad),
                _ => Err(ApiError::bad("profile and expected route required")),
            }
        },
        ("POST", "/v1/catalog/search") => {
            let body = match body_json(request) { Ok(value) => value, Err(error) => return (error.status, json!({"error":error.message})) };
            match (body.get("name").and_then(Value::as_str),body.get("expected_route").and_then(Value::as_str)) {
                (Some(name),Some(route)) => service.catalogue_search(name,route).map(|results| json!({"results":results,"complete":false})).map_err(ApiError::bad),
                _ => Err(ApiError::bad("name and expected route required")),
            }
        },
        ("POST", "/v1/catalog/add") => {
            let body = match body_json(request) { Ok(value) => value, Err(error) => return (error.status, json!({"error":error.message})) };
            let profile = body.get("profile").cloned().and_then(|v| serde_json::from_value(v).ok());
            match (profile, body.get("name").and_then(Value::as_str)) {
                (Some(profile), Some(name)) => service.catalogue_add(&profile,name,body.get("identity_checked").and_then(Value::as_bool)==Some(true)).map(|contact| json!({"contact":contact})).map_err(ApiError::bad),
                _ => Err(ApiError::bad("profile and name required")),
            }
        },
        ("GET", "/v1/i2p/binding") => service.i2p_binding().map(|binding| json!({"binding": binding})).map_err(ApiError::bad),
        ("POST", "/v1/i2p/contact") => {
            let body = match body_json(request) { Ok(value) => value, Err(error) => return (error.status, json!({"error":error.message})) };
            let binding = body.get("binding").cloned().and_then(|v| serde_json::from_value(v).ok());
            let name = body.get("name").and_then(Value::as_str);
            match (binding, name) {
                (Some(binding), Some(name)) => service.add_i2p_binding(&binding, name).map(|contact| json!({"contact":contact})).map_err(ApiError::bad),
                _ => Err(ApiError::bad("binding and name are required")),
            }
        },
        ("POST", "/v1/nostr/contact") => {
            let body = match body_json(request) { Ok(value) => value, Err(error) => return (error.status, json!({"error":error.message})) };
            let binding = body.get("binding").cloned().and_then(|v| serde_json::from_value(v).ok());
            let name = body.get("name").and_then(Value::as_str);
            match (binding, name) {
                (Some(binding), Some(name)) => service.add_nostr_binding(&binding, name).map(|contact| json!({"contact":contact})).map_err(ApiError::bad),
                _ => Err(ApiError::bad("binding and name are required")),
            }
        },
        ("GET", "/v1/identity") => {
            let status = service.status();
            Ok(json!({
                "address": status.address,
                "onion": status.onion,
                "onion_url": status.onion_url,
                "network": status.network,
                "mode": status.mode,
                "api_version": status.api_version,
            }))
        }
        ("GET", "/v1/contacts") => service
            .contacts()
            .map(|contacts| json!({"contacts": contacts}))
            .map_err(ApiError::internal),
        ("POST", "/v1/contacts") => handle_add_contact(service, request),
        ("DELETE", path) if path.starts_with("/v1/contacts/") => {
            let address = path.trim_start_matches("/v1/contacts/");
            if address.is_empty() {
                Err(ApiError::bad("contact address is missing"))
            } else {
                service
                    .remove_contact(address)
                    .map(|removed| json!({"address": address, "removed": removed}))
                    .map_err(ApiError::bad)
            }
        }
        ("GET", "/v1/payment-recovery") => {
            let offset=query_u64(&request.query,"offset").unwrap_or(0).min(usize::MAX as u64) as usize;
            let limit=query_u64(&request.query,"limit").unwrap_or(50).min(100) as usize;
            service.recovery_page(offset,limit).map(|(items,next,more)|json!({
                "items":items.into_iter().map(|m|json!({"peer":m.peer,"id":m.id,"armor":m.armor,"created_at":m.created_at,"status":"review_required","sender_cancellation":"unknown","payment_status":"unknown"})).collect::<Vec<_>>(),
                "next_offset":next,"has_more":more
            })).map_err(ApiError::internal)
        },
        ("GET", "/v1/messages") => {
            let after = query_u64(&request.query, "after").unwrap_or(0);
            let limit = query_u64(&request.query, "limit").unwrap_or(100) as usize;
            Ok(json!(service.messages(after, limit)))
        }
        ("GET", "/v1/events") => {
            let since = query_u64(&request.query, "since").unwrap_or(0);
            let wait_secs = query_u64(&request.query, "wait").unwrap_or(0).min(30);
            Ok(json!(service.events(since, Duration::from_secs(wait_secs))))
        }
        ("GET", "/v1/unread") => {
            let (peers, total) = service.unread();
            Ok(json!({"total": total, "peers": peers}))
        }
        ("POST", "/v1/read") => handle_mark_read(service, request),
        ("POST", "/v1/send") => handle_send(service, request),
        _ => Err(ApiError::not_found()),
    };
    match result {
        Ok(value) => (200, value),
        Err(error) => (error.status, json!({"error": error.message})),
    }
}

fn authorized(request: &Request, token: &AuthToken) -> bool {
    request
        .headers
        .iter()
        .find(|(name, _)| name == "authorization")
        .map(|(_, value)| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
                .map(|provided| token.verify(provided.trim()))
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

struct ApiError {
    status: u16,
    message: String,
}

impl ApiError {
    fn bad(message: impl Into<String>) -> Self {
        Self {
            status: 400,
            message: message.into(),
        }
    }
    fn not_found() -> Self {
        Self {
            status: 404,
            message: "not found".into(),
        }
    }
    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: 500,
            message: message.into(),
        }
    }
}

fn body_json(request: &Request) -> Result<Value, ApiError> {
    serde_json::from_slice(&request.body).map_err(|e| ApiError::bad(format!("invalid JSON: {e}")))
}

fn handle_add_contact(service: &WalletService, request: &Request) -> Result<Value, ApiError> {
    let body = body_json(request)?;
    let address = body
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("field 'address' is required"))?;
    let name = body
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("field 'name' is required"))?;
    service
        .add_contact(address, name)
        .map(|contact| json!({"contact": contact}))
        .map_err(ApiError::bad)
}

fn handle_mark_read(service: &WalletService, request: &Request) -> Result<Value, ApiError> {
    let body = body_json(request)?;
    let peer = body
        .get("peer")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("field 'peer' is required"))?;
    service
        .mark_read(peer)
        .map(|read_at| json!({"peer": peer, "read_at": read_at}))
        .map_err(ApiError::bad)
}

fn handle_send(service: &WalletService, request: &Request) -> Result<Value, ApiError> {
    let body = body_json(request)?;
    let to = body
        .get("to")
        .and_then(Value::as_str)
        .ok_or_else(|| ApiError::bad("field 'to' is required"))?;
    let kind = body.get("kind").and_then(Value::as_str).unwrap_or("text");
    let ttl = body.get("ttl_secs").and_then(Value::as_u64);
    let message = match kind {
        "text" => {
            let text = body
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::bad("field 'text' is required for kind=text"))?;
            service.send_text(to, text, ttl)
        }
        "slatepack" => {
            let armor = body
                .get("armor")
                .and_then(Value::as_str)
                .ok_or_else(|| ApiError::bad("field 'armor' is required for kind=slatepack"))?;
            service.send_slatepack(to, armor, ttl)
        }
        other => return Err(ApiError::bad(format!("unknown kind {other:?}"))),
    };
    message
        .map(|message| json!({"message": message}))
        .map_err(ApiError::bad)
}

fn query_u64(query: &str, key: &str) -> Option<u64> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key {
            v.parse::<u64>().ok()
        } else {
            None
        }
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn write_response(stream: &mut TcpStream, status: u16, body: &Value) -> std::io::Result<()> {
    let payload = serde_json::to_vec(body).unwrap_or_else(|_| b"{\"error\":\"json\"}".to_vec());
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        500 => "Internal Server Error",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()
}

/// Host part of a token path, for diagnostics (never the token value).
pub fn token_path_label(token: &AuthToken) -> String {
    token.path().display().to_string()
}

/// The daemon prints the URL on startup; this helper keeps the format stable.
pub fn startup_json(addr: SocketAddr, token: &AuthToken, status: &crate::ServiceStatus) -> Value {
    json!({
        "event": "ready",
        "api": format!("http://{addr}"),
        "token_file": token_path_label(token),
        "address": status.address,
        "network": status.network,
        "mode": status.mode,
        "phase": status.phase,
        "api_version": API_VERSION,
        "pid": std::process::id(),
        "token_env": TOKEN_ENV,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_compare_works() {
        assert!(constant_time_eq(b"abcd", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abce"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }

    #[test]
    fn chat_api_requires_bearer_token() {
        let token = AuthToken::from_env("0123456789abcdef0123456789abcdef".into(), PathBuf::new());
        let mut request = Request { method: "GET".into(), path: "/v1/messages".into(), query: "".into(), headers: vec![], body: vec![] };
        assert!(!authorized(&request, &token));
        request.headers.push(("authorization".into(), "Bearer wrong".into()));
        assert!(!authorized(&request, &token));
        request.headers[0].1 = "Bearer 0123456789abcdef0123456789abcdef".into();
        assert!(authorized(&request, &token));
    }

    #[test]
    fn nostr_binding_api_requires_bearer_and_rejects_tampering() {
        use crate::{NetworkMode, ServiceConfig};
        use zeroize::Zeroizing;
        let dir=std::env::temp_dir().join(format!("gs-nostr-api-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let cfg=ServiceConfig {data_dir:dir,network:"tgrin".into(),mode:NetworkMode::Direct,..ServiceConfig::default()};
        let service=WalletService::open(cfg,Zeroizing::new([9;32])).unwrap();
        let token=AuthToken::from_env("0123456789abcdef0123456789abcdef".into(),PathBuf::new());
        let mut request=Request {method:"GET".into(),path:"/v1/nostr/binding".into(),query:"".into(),headers:vec![],body:vec![]};
        assert_eq!(route(&service,&token,&request).0,401);
        request.headers.push(("authorization".into(),"Bearer 0123456789abcdef0123456789abcdef".into()));
        let (status,value)=route(&service,&token,&request); assert_eq!(status,200);
        request.path="/v1/i2p/binding".into();
        assert_eq!(route(&service,&token,&request).0,400);
        let mut binding=value["binding"].clone(); binding["signature_hex"]=json!("00");
        request.method="POST".into(); request.path="/v1/nostr/contact".into();
        request.body=serde_json::to_vec(&json!({"binding":binding,"name":"test"})).unwrap();
        assert_eq!(route(&service,&token,&request).0,400);
    }

    #[test]
    fn quarantine_export_requires_auth_and_exact_item() {
        use crate::{NetworkMode,ServiceConfig};use zeroize::Zeroizing;
        let dir=std::env::temp_dir().join(format!("gs-quarantine-api-{}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let service=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),mode:NetworkMode::Direct,..Default::default()},Zeroizing::new([9;32])).unwrap();
        let token=AuthToken::from_env("0123456789abcdef0123456789abcdef".into(),PathBuf::new());
        let mut req=Request{method:"GET".into(),path:"/v1/quarantine/envelopes".into(),query:"".into(),headers:vec![],body:vec![]};
        assert_eq!(route(&service,&token,&req).0,401);req.headers.push(("authorization".into(),"Bearer 0123456789abcdef0123456789abcdef".into()));
        assert_eq!(route(&service,&token,&req).0,200);req.method="POST".into();req.path="/v1/quarantine/envelopes/export".into();
        req.body=serde_json::to_vec(&json!({"id":"missing","digest":"00"})).unwrap();assert_eq!(route(&service,&token,&req).0,400);
        drop(service);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn deferred_api_requires_bearer_and_explicit_discard_consent() {
        use crate::{NetworkMode,ServiceConfig};use zeroize::Zeroizing;
        let dir=std::env::temp_dir().join(format!("gs-deferred-api-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let service=WalletService::open(ServiceConfig{data_dir:dir.clone(),network:"tgrin".into(),mode:NetworkMode::Direct,..Default::default()},Zeroizing::new([9;32])).unwrap();
        service.test_enable_nostr();
        let token=AuthToken::from_env("0123456789abcdef0123456789abcdef".into(),PathBuf::new());
        let mut req=Request{method:"GET".into(),path:"/v1/nostr/deferred".into(),query:"".into(),headers:vec![],body:vec![]};
        assert_eq!(route(&service,&token,&req).0,401);req.headers.push(("authorization".into(),"Bearer 0123456789abcdef0123456789abcdef".into()));
        let (status,body)=route(&service,&token,&req);assert_eq!(status,200);assert_eq!(body["limit"],1000);
        req.method="POST".into();req.path="/v1/nostr/deferred/discard".into();req.body=serde_json::to_vec(&json!({"id":"a".repeat(64)})).unwrap();
        assert_eq!(route(&service,&token,&req).0,400);
        drop(service);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn drain_control_requires_token_and_closes_admission() {
        use crate::{NetworkMode, ServiceConfig};
        use zeroize::Zeroizing;
        use std::io::{Read, Write};
        let dir=std::env::temp_dir().join(format!("gs-drain-api-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let cfg=ServiceConfig {data_dir:dir,network:"tgrin".into(),mode:NetworkMode::Direct,..ServiceConfig::default()};
        let service=Arc::new(WalletService::open(cfg,Zeroizing::new([9;32])).unwrap());
        let token=Arc::new(AuthToken::from_env("0123456789abcdef0123456789abcdef".into(),PathBuf::new()));
        let gate=glaux_messenger::channel_drain::ChannelDrain::default();
        let hold=Arc::new(std::sync::Mutex::new(None));
        let busy=Arc::new(AtomicBool::new(false));
        let run = |auth: &str| {
            let listener=TcpListener::bind("127.0.0.1:0").unwrap(); let addr=listener.local_addr().unwrap();
            let svc=service.clone(); let tok=token.clone(); let gate=gate.clone(); let hold=hold.clone(); let busy=busy.clone();
            let thread=std::thread::spawn(move || {let (s,_)=listener.accept().unwrap();handle_guarded_connection(s,svc,tok,Some(gate),hold,busy);});
            let mut stream=TcpStream::connect(addr).unwrap();
            write!(stream,"POST /v1/channel/drain HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: 0\r\n\r\n",auth).unwrap();
            let mut response=String::new(); stream.read_to_string(&mut response).unwrap(); thread.join().unwrap(); response
        };
        assert!(run("wrong").starts_with("HTTP/1.1 401"));
        assert!(gate.enter().is_some());
        assert!(run("0123456789abcdef0123456789abcdef").starts_with("HTTP/1.1 200"));
        assert!(gate.enter().is_none());
        assert!(run("0123456789abcdef0123456789abcdef").starts_with("HTTP/1.1 503"));
        hold.lock().unwrap().take();
        assert!(gate.enter().is_some());
    }

    #[test]
    fn non_loopback_bind_is_refused() {
        assert!(bind("0.0.0.0:0").is_err());
        assert!(bind("[::]:0").is_err());
    }
}

