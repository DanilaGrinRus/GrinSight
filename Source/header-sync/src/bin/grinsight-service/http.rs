//! Loopback HTTP for JSON-RPC 2.0 (`POST /rpc`).
//!
//! Only the app that started the service may talk to it:
//! * it listens on 127.0.0.1 only;
//! * every request carries `Authorization: Bearer <token>` (random, printed
//!   once on the service's stdout, which only the parent process reads);
//! * the Host header must be a loopback name (no DNS rebinding) and a request
//!   with an `Origin` header (a web page) is refused.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

pub fn parse<R: BufRead>(r: &mut R) -> Result<Request, String> {
    let mut seen = 0usize;
    let mut line = String::new();
    let mut read_line = |line: &mut String, r: &mut R| -> Result<(), String> {
        line.clear();
        let n = r.take((MAX_HEADERS - seen.min(MAX_HEADERS)) as u64 + 1).read_line(line).map_err(|e| e.to_string())?;
        seen += n;
        if seen > MAX_HEADERS {
            return Err("headers too large".into());
        }
        if n == 0 {
            return Err("connection closed".into());
        }
        Ok(())
    };
    read_line(&mut line, r)?;
    let mut parts = line.trim_end().splitn(3, ' ');
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().ok_or("bad request line")?.to_string();
    if !parts.next().unwrap_or("").starts_with("HTTP/1.") {
        return Err("bad request line".into());
    }
    let mut headers = Vec::new();
    loop {
        read_line(&mut line, r)?;
        let l = line.trim_end_matches(['\r', '\n']);
        if l.is_empty() {
            break;
        }
        let (k, v) = l.split_once(':').ok_or("bad header")?;
        headers.push((k.trim().to_string(), v.trim().to_string()));
        if headers.len() > 64 {
            return Err("too many headers".into());
        }
    }
    let req = Request { method, path, headers, body: Vec::new() };
    if req.header("transfer-encoding").is_some() {
        return Err("chunked bodies are not accepted".into());
    }
    let len: usize = match req.header("content-length") {
        Some(v) => v.parse().map_err(|_| "bad content-length")?,
        None => 0,
    };
    if len > MAX_BODY {
        return Err("body too large".into());
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).map_err(|e| format!("body: {e}"))?;
    Ok(Request { body, ..req })
}

fn respond(s: &mut TcpStream, status: &str, body: &[u8]) {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = s.write_all(head.as_bytes());
    let _ = s.write_all(body);
    // End the reply on the wire (FIN) now. Dropping the socket is not
    // enough on Windows: a child started while this request was served (the
    // GlauxNet daemon, a core job) inherits a copy of the socket and keeps
    // the connection open for as long as it lives.
    let _ = s.flush();
    let _ = s.shutdown(std::net::Shutdown::Write);
}

fn loopback_host(h: &str) -> bool {
    let host = if let Some(rest) = h.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        h.rsplit_once(':').map_or(h, |(a, _)| a)
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// Checks the request (path, auth, host, origin) and returns the JSON-RPC
/// call, or the HTTP status and message to send instead.
pub fn check(req: &Request, token: &str) -> Result<Value, (&'static str, String)> {
    if req.method != "POST" || req.path != "/rpc" {
        return Err(("404 Not Found", "POST /rpc only".into()));
    }
    let want = format!("Bearer {token}");
    let got = req.header("authorization").unwrap_or("");
    // Constant-time compare of equal-length strings.
    let same = got.len() == want.len() && got.bytes().zip(want.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0;
    if !same {
        return Err(("401 Unauthorized", "bad or missing token".into()));
    }
    if !req.header("host").is_some_and(loopback_host) {
        return Err(("403 Forbidden", "host must be loopback".into()));
    }
    if req.header("origin").is_some() {
        return Err(("403 Forbidden", "browser requests are refused".into()));
    }
    serde_json::from_slice(&req.body).map_err(|e| ("400 Bad Request", format!("json: {e}")))
}

/// One connection: parse, check, dispatch, answer (JSON-RPC 2.0).
pub fn serve_one<F>(mut s: TcpStream, token: &str, dispatch: F)
where
    F: FnOnce(&str, &Value) -> Result<Value, String>,
{
    let _ = s.set_read_timeout(Some(Duration::from_secs(30)));
    let mut r = BufReader::new(match s.try_clone() {
        Ok(c) => c,
        Err(_) => return,
    });
    let req = match parse(&mut r) {
        Ok(q) => q,
        Err(e) => return respond(&mut s, "400 Bad Request", json!({ "error": e }).to_string().as_bytes()),
    };
    let call = match check(&req, token) {
        Ok(c) => c,
        Err((status, msg)) => return respond(&mut s, status, json!({ "error": msg }).to_string().as_bytes()),
    };
    let id = call.get("id").cloned().unwrap_or(Value::Null);
    let method = call.get("method").and_then(Value::as_str).unwrap_or("");
    let params = call.get("params").cloned().unwrap_or(json!({}));
    let reply = match dispatch(method, &params) {
        Ok(v) => json!({ "jsonrpc": "2.0", "id": id, "result": v }),
        Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": e } }),
    };
    respond(&mut s, "200 OK", reply.to_string().as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(raw: &str) -> Result<Request, String> {
        parse(&mut std::io::Cursor::new(raw.as_bytes().to_vec()))
    }

    #[test]
    fn parse_and_check() {
        let body = r#"{"jsonrpc":"2.0","id":1,"method":"service.info"}"#;
        let ok = format!(
            "POST /rpc HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nAuthorization: Bearer abc\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let q = req(&ok).unwrap();
        assert_eq!(check(&q, "abc").unwrap()["method"], "service.info");
        assert_eq!(check(&q, "abd").unwrap_err().0, "401 Unauthorized");
        assert_eq!(check(&q, "ab").unwrap_err().0, "401 Unauthorized");
        let evil = ok.replace("127.0.0.1:5000", "evil.example:5000");
        assert_eq!(check(&req(&evil).unwrap(), "abc").unwrap_err().0, "403 Forbidden");
        let page = ok.replace("Host:", "Origin: http://x\r\nHost:");
        assert_eq!(check(&req(&page).unwrap(), "abc").unwrap_err().0, "403 Forbidden");
        let get = ok.replace("POST", "GET");
        assert_eq!(check(&req(&get).unwrap(), "abc").unwrap_err().0, "404 Not Found");
        assert!(loopback_host("[::1]:80") && loopback_host("localhost") && !loopback_host("127.0.0.2:1"));
    }

    #[test]
    fn limits() {
        assert!(req("POST /rpc HTTP/1.1\r\nContent-Length: 99999999\r\n\r\n").is_err());
        assert!(req("POST /rpc HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        assert!(req(&format!("POST /rpc HTTP/1.1\r\nX: {}\r\n\r\n", "a".repeat(20000))).is_err());
        assert!(req("garbage\r\n\r\n").is_err());
        assert!(req("POST /rpc HTTP/1.1\r\nContent-Length: 5\r\n\r\nab").is_err(), "short body");
    }
}
