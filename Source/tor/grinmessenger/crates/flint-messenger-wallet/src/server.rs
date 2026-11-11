// SPDX-License-Identifier: MIT OR Apache-2.0
//! Loopback HTTP API used by the `flintmsg-walletd` sidecar.
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
const TOKEN_ENV: &str = "FLINTMSG_WALLETD_TOKEN";

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
    for incoming in listener.incoming() {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        match incoming {
            Ok(stream) => {
                let service = service.clone();
                let token = token.clone();
                std::thread::spawn(move || handle_connection(stream, service, token));
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

fn handle_connection(mut stream: TcpStream, service: Arc<WalletService>, token: Arc<AuthToken>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
    let response = match read_request(&mut stream) {
        Ok(request) => route(&service, &token, &request),
        Err(error) => (400, json!({"error": error})),
    };
    let _ = stream.set_read_timeout(None);
    let _ = write_response(&mut stream, response.0, &response.1);
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
    fn non_loopback_bind_is_refused() {
        assert!(bind("0.0.0.0:0").is_err());
        assert!(bind("[::]:0").is_err());
    }
}
