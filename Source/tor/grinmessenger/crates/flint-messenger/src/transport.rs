// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal HTTP transport for the loopback/Tor gateway (`/flint/v1/msg*`).
//!
//! Deliberately dependency-free: a small blocking HTTP/1.1 client over
//! `TcpStream`. The gateway is loopback behind the onion, so no TLS layer here;
//! Tor provides transport confidentiality. The envelope itself is the
//! signed/encrypted unit.
//!
//! The wire layer is pluggable through [`HttpConnector`]: [`TcpConnector`] is
//! the built-in direct/SOCKS5 implementation, and embedding applications may
//! supply their own connector (for example an in-process Arti client) via
//! [`GatewayTransport::with_connector`] or
//! [`DirectOnionTransport::with_connector`]. The URL grammar, request shape and
//! response handling stay in this module; a connector only performs the I/O.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::ack::AckProof;
use crate::address::{fetch_proof_transcript, Address};
use crate::envelope::{unix_now, Envelope, Identity};
use crate::error::{Error, Result};
use crate::store::Transport;

const TIMEOUT: Duration = Duration::from_secs(15);
/// The first circuit to an onion can take noticeably longer than a clearnet
/// request: descriptor lookup and the rendezvous handshake happen before the
/// hidden service opens its local HTTP connection.
const ONION_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESPONSE: usize = 4 * 1024 * 1024;
/// Bound relay cleanup work per fetch; a hostile queue cannot make one inbox
/// call ack an unbounded number of ids.
const MAX_BAD_ACKS: usize = 32;

/// Blocking HTTP/1.1 backend used by [`GatewayTransport`] and
/// [`DirectOnionTransport`].
///
/// Implementations must perform exactly one request against the absolute
/// `http://` URL they are given and return the status code together with the
/// complete response body. Redirects, TLS and proxying are the connector's
/// concern; request layout and size limits stay in this module.
pub trait HttpConnector: Send + Sync {
    fn request(&self, method: &str, url: &str, body: &[u8]) -> Result<(u16, Vec<u8>)>;
}

/// Built-in [`HttpConnector`]: HTTP/1.1 over a plain `TcpStream`, optionally
/// tunnelled through a Tor SOCKS5 proxy for `.onion` destinations.
pub struct TcpConnector {
    /// Optional Tor SOCKS5 proxy (`host:port`). Required for `.onion` hosts.
    socks: Option<String>,
}

impl TcpConnector {
    pub fn new() -> Self {
        Self { socks: None }
    }

    /// Route through a Tor SOCKS5 proxy. `socks` is e.g. `127.0.0.1:9050`.
    pub fn with_socks(socks: &str) -> Result<Self> {
        let socks = socks.trim();
        if socks.is_empty() {
            return Err(Error::Store("gateway: пустой SOCKS-адрес".into()));
        }
        Ok(Self {
            socks: Some(socks.to_string()),
        })
    }

    fn connect(&self, host: &str, port: u16, is_onion: bool) -> Result<TcpStream> {
        let timeout = if is_onion { ONION_TIMEOUT } else { TIMEOUT };
        if let Some(socks) = &self.socks {
            return socks5_connect(socks, host, port, timeout);
        }
        if is_onion {
            return Err(Error::Store(
                "gateway: для .onion нужен Tor SOCKS (with_socks)".into(),
            ));
        }
        let addr = format!("{host}:{port}");
        let sock = addr
            .to_socket_addrs()
            .map_err(|e| Error::Store(format!("gateway: {e}")))?
            .next()
            .ok_or_else(|| Error::Store("gateway: адрес не разрешился".into()))?;
        TcpStream::connect_timeout(&sock, timeout)
            .map_err(|e| Error::Store(format!("gateway: connect: {e}")))
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpConnector for TcpConnector {
    fn request(&self, method: &str, url: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let (host, port, path) = split_http_url(url)?;
        let is_onion = host.ends_with(".onion");
        let timeout = if is_onion { ONION_TIMEOUT } else { TIMEOUT };
        let mut stream = self.connect(&host, port, is_onion)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| Error::Store(format!("gateway: timeout: {e}")))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| Error::Store(format!("gateway: timeout: {e}")))?;

        let host_header = if port == 80 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|e| Error::Store(format!("gateway: write: {e}")))?;
        stream
            .write_all(body)
            .map_err(|e| Error::Store(format!("gateway: write: {e}")))?;

        let mut raw = Vec::new();
        stream
            .take(MAX_RESPONSE as u64 + 1)
            .read_to_end(&mut raw)
            .map_err(|e| Error::Store(format!("gateway: read: {e}")))?;
        if raw.len() > MAX_RESPONSE {
            return Err(Error::Store("gateway: ответ слишком большой".into()));
        }
        let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
            return Err(Error::Store("gateway: нет заголовков ответа".into()));
        };
        let head = String::from_utf8_lossy(&raw[..pos]).to_string();
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| Error::Store("gateway: нет статуса".into()))?;
        Ok((status, raw[pos + 4..].to_vec()))
    }
}

/// Split an absolute `http://` URL into host, port (80 by default) and the
/// request-target (path plus query, always starting with `/`).
fn split_http_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .trim()
        .strip_prefix("http://")
        .ok_or_else(|| Error::Store("gateway: нужен http:// URL".into()))?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => {
            (host.to_string(), port.parse::<u16>().unwrap())
        }
        _ => (authority.to_string(), 80),
    };
    if host.is_empty() {
        return Err(Error::Store("gateway: пустой host".into()));
    }
    Ok((host, port, path))
}

fn socks5_connect(socks: &str, target: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let addr = socks
        .to_socket_addrs()
        .map_err(|e| Error::Store(format!("socks: {e}")))?
        .next()
        .ok_or_else(|| Error::Store("socks: адрес не разрешился".into()))?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| Error::Store(format!("socks: connect: {e}")))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|e| Error::Store(format!("socks: timeout: {e}")))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|e| Error::Store(format!("socks: timeout: {e}")))?;

    // Greeting: SOCKS5, no authentication.
    stream
        .write_all(&[5, 1, 0])
        .map_err(|e| Error::Store(format!("socks: write: {e}")))?;
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .map_err(|e| Error::Store(format!("socks: read: {e}")))?;
    if greeting != [5, 0] {
        return Err(Error::Store("socks: прокси требует авторизацию".into()));
    }

    let target_bytes = target.as_bytes();
    if target_bytes.len() > 255 {
        return Err(Error::Store("socks: слишком длинный host".into()));
    }
    let mut request = Vec::with_capacity(7 + target_bytes.len());
    request.extend_from_slice(&[5, 1, 0, 3, target_bytes.len() as u8]);
    request.extend_from_slice(target_bytes);
    request.extend_from_slice(&port.to_be_bytes());
    stream
        .write_all(&request)
        .map_err(|e| Error::Store(format!("socks: write: {e}")))?;

    let mut reply = [0u8; 2];
    stream
        .read_exact(&mut reply)
        .map_err(|e| Error::Store(format!("socks: read: {e}")))?;
    if reply != [5, 0] {
        return Err(Error::Store(format!(
            "socks: CONNECT отклонён ({:#04x})",
            reply[1]
        )));
    }
    let mut reserved = [0u8; 1];
    stream
        .read_exact(&mut reserved)
        .map_err(|e| Error::Store(format!("socks: read: {e}")))?;
    let mut atyp = [0u8; 1];
    stream
        .read_exact(&mut atyp)
        .map_err(|e| Error::Store(format!("socks: read: {e}")))?;
    let skip = match atyp[0] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            stream
                .read_exact(&mut len)
                .map_err(|e| Error::Store(format!("socks: read: {e}")))?;
            len[0] as usize + 2
        }
        other => {
            return Err(Error::Store(format!(
                "socks: неизвестный ATYP {other:#04x}"
            )))
        }
    };
    let mut rest = vec![0u8; skip];
    stream
        .read_exact(&mut rest)
        .map_err(|e| Error::Store(format!("socks: read: {e}")))?;
    Ok(stream)
}

pub struct GatewayTransport {
    /// Normalized gateway base URL: no trailing slash, `http://` only.
    base_url: String,
    connector: Arc<dyn HttpConnector>,
    is_onion: bool,
}

impl GatewayTransport {
    pub fn new(base_url: &str) -> Result<Self> {
        Self::with_connector(base_url, Arc::new(TcpConnector::new()))
    }

    /// Route through a Tor SOCKS5 proxy. `socks` is e.g. `127.0.0.1:9050`.
    pub fn with_socks(base_url: &str, socks: &str) -> Result<Self> {
        // Validate the gateway URL first, exactly like `new`, then the proxy.
        let transport = Self::new(base_url)?;
        let connector = TcpConnector::with_socks(socks)?;
        Ok(Self {
            connector: Arc::new(connector),
            ..transport
        })
    }

    /// Use an external HTTP backend for every request. The URL grammar and the
    /// request/response handling are unchanged; only the I/O is delegated.
    pub fn with_connector(base_url: &str, connector: Arc<dyn HttpConnector>) -> Result<Self> {
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        let (host, _, _) = split_http_url(&base_url)?;
        Ok(Self {
            base_url,
            connector,
            is_onion: host.ends_with(".onion"),
        })
    }

    pub fn is_onion(&self) -> bool {
        self.is_onion
    }

    fn request(&self, method: &str, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
        let url = format!("{}{}", self.base_url, path);
        self.connector.request(method, &url, body)
    }

    fn expect_ok(&self, status: u16, body: &[u8]) -> Result<()> {
        if (200..300).contains(&status) {
            return Ok(());
        }
        let text = String::from_utf8_lossy(body);
        Err(Error::Store(format!("gateway: HTTP {status}: {text}")))
    }
}

/// Direct peer-to-peer delivery over Tor.
///
/// Sending derives the recipient's v3 onion from the slatepack address and POSTs
/// the envelope to that onion. Fetching and acking use the wallet's own local
/// gateway, because the mailbox for this identity lives on this machine. No
/// third-party relay is involved; an offline recipient simply does not receive
/// the message (its gateway was not reachable).
pub struct DirectOnionTransport {
    local: String,
    /// Backend used for delivery to the recipient's onion. Fetch/ack always use
    /// a direct local TCP connection to the loopback mailbox.
    connector: Arc<dyn HttpConnector>,
}

impl DirectOnionTransport {
    /// `local` is the loopback gateway URL (`http://127.0.0.1:PORT`) that stores
    /// this identity's inbox; `socks` is the local Tor SOCKS5 endpoint.
    pub fn new(local: &str, socks: &str) -> Result<Self> {
        let local = local.trim().trim_end_matches('/').to_string();
        GatewayTransport::new(&local)?;
        let socks = socks.trim();
        if socks.is_empty() {
            return Err(Error::Store("direct onion: пустой SOCKS-адрес".into()));
        }
        Ok(Self {
            local,
            connector: Arc::new(TcpConnector::with_socks(socks)?),
        })
    }

    /// Use an external HTTP backend (for example an in-process Arti client) for
    /// delivery to the recipient's onion. Fetch and ack still go to the local
    /// loopback mailbox over plain TCP, as with [`Self::new`].
    pub fn with_connector(local: &str, connector: Arc<dyn HttpConnector>) -> Result<Self> {
        let local = local.trim().trim_end_matches('/').to_string();
        GatewayTransport::new(&local)?;
        Ok(Self { local, connector })
    }

    fn local_transport(&self) -> Result<GatewayTransport> {
        GatewayTransport::new(&self.local)
    }
}

impl Transport for DirectOnionTransport {
    fn deliver(&self, envelope: &Envelope) -> Result<()> {
        let recipient = Address::parse(&envelope.recipient)?;
        let remote =
            GatewayTransport::with_connector(&recipient.onion_url(), self.connector.clone())?;
        remote.deliver(envelope)
    }

    fn fetch(&self, recipient: &Address, now: u64, limit: usize) -> Result<Vec<Envelope>> {
        self.local_transport()?.fetch(recipient, now, limit)
    }

    fn ack(&self, recipient: &Address, ids: &[String]) -> Result<usize> {
        self.local_transport()?.ack(recipient, ids)
    }

    fn ack_signed(&self, recipient: &Identity, ids: &[String]) -> Result<usize> {
        self.local_transport()?.ack_signed(recipient, ids)
    }
}

impl Transport for GatewayTransport {
    fn deliver(&self, envelope: &Envelope) -> Result<()> {
        let recipient: Address = envelope.recipient.parse()?;
        let payload = serde_json::to_string(envelope)
            .map_err(|e| Error::Envelope(format!("payload: {e}")))?;
        let body = serde_json::to_vec(&serde_json::json!({
            "id": envelope.id,
            "to": recipient.to_string(),
            "payload": payload,
            "ttl_secs": envelope.ttl,
        }))
        .map_err(|e| Error::Envelope(format!("json: {e}")))?;
        let (status, response) = self.request("POST", "/flint/v1/msg", &body)?;
        self.expect_ok(status, &response)
    }

    fn fetch(&self, recipient: &Address, now: u64, limit: usize) -> Result<Vec<Envelope>> {
        let to = recipient.to_string();
        let page = limit.clamp(1, 100);
        let (status, response) =
            self.request("GET", &format!("/flint/v1/msg?to={to}&limit={page}"), b"")?;
        self.parse_fetch(recipient, now, limit, status, &response)
    }

    /// Authenticated fetch: signs the address + timestamp so a hardened relay
    /// only returns the mailbox metadata to the address holder.
    fn fetch_signed(&self, recipient: &Identity, now: u64, limit: usize) -> Result<Vec<Envelope>> {
        let address = recipient.address();
        let to = address.to_string();
        let page = limit.clamp(1, 100);
        let signature = recipient.sign_bytes(&fetch_proof_transcript(address, now));
        let sig = data_encoding::HEXLOWER.encode(&signature);
        let (status, response) = self.request(
            "GET",
            &format!("/flint/v1/msg?to={to}&limit={page}&ts={now}&sig={sig}"),
            b"",
        )?;
        self.parse_fetch(address, now, limit, status, &response)
    }

    fn ack(&self, recipient: &Address, ids: &[String]) -> Result<usize> {
        let to = recipient.to_string();
        let body = serde_json::to_vec(&serde_json::json!({ "to": to }))
            .map_err(|e| Error::Store(format!("json: {e}")))?;
        self.ack_with_body(&body, ids)
    }

    fn ack_signed(&self, recipient: &Identity, ids: &[String]) -> Result<usize> {
        let mut acked = 0;
        for id in ids {
            let proof = AckProof::sign(recipient, id, unix_now());
            let body =
                serde_json::to_vec(&proof).map_err(|e| Error::Store(format!("ack proof: {e}")))?;
            acked += self.ack_one(id, &body)?;
        }
        Ok(acked)
    }
}

impl GatewayTransport {
    fn parse_fetch(
        &self,
        recipient: &Address,
        now: u64,
        limit: usize,
        status: u16,
        response: &[u8],
    ) -> Result<Vec<Envelope>> {
        self.expect_ok(status, response)?;
        let value: Value = serde_json::from_slice(response)
            .map_err(|e| Error::Store(format!("gateway JSON: {e}")))?;
        let items = value
            .get("messages")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        let mut rejected = Vec::new();
        // One malformed payload must not poison the whole batch. Parse every
        // item, skip only the bad one, and keep scanning until the requested
        // number of valid envelopes is reached; otherwise the first 20 broken
        // envelopes would hide good messages behind them forever. A bounded
        // number of malformed relay ids is acked as quarantine so they do not
        // occupy the queue until TTL.
        for item in items {
            let Some(payload) = item.get("payload").and_then(Value::as_str) else {
                if let Some(id) = item.get("id").and_then(Value::as_str) {
                    if rejected.len() < MAX_BAD_ACKS {
                        rejected.push(id.to_string());
                    }
                }
                continue;
            };
            let Ok(envelope) = serde_json::from_str::<Envelope>(payload) else {
                if let Some(id) = item.get("id").and_then(Value::as_str) {
                    if rejected.len() < MAX_BAD_ACKS {
                        rejected.push(id.to_string());
                    }
                }
                continue;
            };
            out.push(envelope);
            if out.len() >= limit.max(1) {
                break;
            }
        }
        // This is not a sender-authenticated ack: only malformed items are
        // removed and a relay that requires a signed ack rejects it harmlessly.
        if !rejected.is_empty() {
            let _ = self.ack(recipient, &rejected);
        }
        // `now` is the caller's clock; envelope TTL is enforced by `open`.
        let _ = now;
        Ok(out)
    }

    fn ack_with_body(&self, body: &[u8], ids: &[String]) -> Result<usize> {
        let mut acked = 0;
        for id in ids {
            acked += self.ack_one(id, body)?;
        }
        Ok(acked)
    }

    fn ack_one(&self, id: &str, body: &[u8]) -> Result<usize> {
        let (status, response) = self.request("POST", &format!("/flint/v1/msg/{id}/ack"), body)?;
        if status == 404 {
            return Ok(0);
        }
        self.expect_ok(status, &response)?;
        Ok(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::MessageKind;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingConnector {
        requests: Mutex<Vec<(String, String, Vec<u8>)>>,
        response: Mutex<Option<(u16, Vec<u8>)>>,
    }

    impl RecordingConnector {
        fn take_requests(&self) -> Vec<(String, String, Vec<u8>)> {
            std::mem::take(&mut *self.requests.lock().expect("requests"))
        }
    }

    impl HttpConnector for RecordingConnector {
        fn request(&self, method: &str, url: &str, body: &[u8]) -> Result<(u16, Vec<u8>)> {
            self.requests.lock().expect("requests").push((
                method.to_string(),
                url.to_string(),
                body.to_vec(),
            ));
            Ok(self
                .response
                .lock()
                .expect("response")
                .clone()
                .unwrap_or_else(|| (200, b"{}".to_vec())))
        }
    }

    fn parties() -> (Identity, Identity) {
        (
            Identity::from_seed([7u8; 32], "tgrin").expect("alice"),
            Identity::from_seed([9u8; 32], "tgrin").expect("bob"),
        )
    }

    #[test]
    fn gateway_transport_delegates_absolute_urls_to_the_connector() {
        let connector = Arc::new(RecordingConnector::default());
        let transport =
            GatewayTransport::with_connector("http://relay.example:8080/", connector.clone())
                .expect("transport");
        assert!(!transport.is_onion());

        let (alice, bob) = parties();
        let envelope = Envelope::seal_now(
            &alice,
            bob.address(),
            MessageKind::Text { text: "via".into() },
            crate::DEFAULT_TTL_SECS,
        )
        .expect("envelope");
        transport.deliver(&envelope).expect("deliver");

        let requests = connector.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, "POST");
        assert_eq!(requests[0].1, "http://relay.example:8080/flint/v1/msg");
        assert!(!requests[0].2.is_empty());
    }

    #[test]
    fn gateway_transport_fetch_parses_the_connector_response() {
        let connector = Arc::new(RecordingConnector::default());
        let transport = GatewayTransport::with_connector("http://relay.onion", connector.clone())
            .expect("transport");
        assert!(transport.is_onion());

        let (alice, bob) = parties();
        let envelope = Envelope::seal_now(
            &alice,
            bob.address(),
            MessageKind::Text {
                text: "fetched".into(),
            },
            crate::DEFAULT_TTL_SECS,
        )
        .expect("envelope");
        let payload = serde_json::to_string(&envelope).expect("payload json");
        let body = serde_json::json!({"messages": [{"id": envelope.id, "payload": payload}]});
        *connector.response.lock().expect("response") =
            Some((200, serde_json::to_vec(&body).expect("body json")));

        let fetched = transport
            .fetch(bob.address(), unix_now(), 10)
            .expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].id, envelope.id);

        let requests = connector.take_requests();
        assert_eq!(requests.len(), 1);
        assert!(requests[0]
            .1
            .starts_with("http://relay.onion/flint/v1/msg?to="));
    }

    #[test]
    fn gateway_transport_signed_ack_goes_through_the_connector() {
        let connector = Arc::new(RecordingConnector::default());
        let transport = GatewayTransport::with_connector("http://relay.onion", connector.clone())
            .expect("transport");
        let (_alice, bob) = parties();
        let id = "11111111-1111-4111-8111-111111111111".to_string();
        assert_eq!(
            transport
                .ack_signed(&bob, std::slice::from_ref(&id))
                .expect("ack"),
            1
        );

        let requests = connector.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, "POST");
        assert_eq!(
            requests[0].1,
            format!("http://relay.onion/flint/v1/msg/{id}/ack")
        );
        let proof: Value = serde_json::from_slice(&requests[0].2).expect("proof json");
        assert_eq!(
            proof.get("to").and_then(Value::as_str),
            Some(bob.address().to_string().as_str())
        );
        assert_eq!(proof.get("id").and_then(Value::as_str), Some(id.as_str()));
    }

    #[test]
    fn direct_onion_delivery_uses_the_configured_connector() {
        let connector = Arc::new(RecordingConnector::default());
        let transport =
            DirectOnionTransport::with_connector("http://127.0.0.1:1", connector.clone())
                .expect("transport");
        let (alice, bob) = parties();
        let envelope = Envelope::seal_now(
            &alice,
            bob.address(),
            MessageKind::Text {
                text: "direct".into(),
            },
            crate::DEFAULT_TTL_SECS,
        )
        .expect("envelope");
        transport.deliver(&envelope).expect("deliver");

        let requests = connector.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].1,
            format!("{}/flint/v1/msg", bob.address().onion_url())
        );
    }

    #[test]
    fn url_and_proxy_validation_keeps_the_old_contract() {
        assert!(GatewayTransport::new("https://relay.example").is_err());
        assert!(GatewayTransport::new("http://").is_err());
        assert!(GatewayTransport::with_socks("http://relay.onion", "   ").is_err());
        assert!(TcpConnector::with_socks("").is_err());
        assert!(DirectOnionTransport::new("http://127.0.0.1:1", "").is_err());
        assert!(DirectOnionTransport::new("relay.onion", "127.0.0.1:9050").is_err());
    }
}
