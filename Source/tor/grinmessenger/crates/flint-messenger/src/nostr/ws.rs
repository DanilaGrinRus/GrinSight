// SPDX-License-Identifier: MIT OR Apache-2.0
//! Blocking WebSocket relay client for the Nostr transport (NIP-01 + NIP-42).
//!
//! The transport contract allows one `wss://` relay; plain `ws://` is accepted
//! only for loopback tests. Publishing waits for the relay's `OK` for the exact
//! event id, and a query stops at `EOSE` or on the read timeout — an absent EOSE
//! never turns into an infinite wait.
//!
//! When a relay asks for authentication (`["AUTH", challenge]`) the client signs
//! a kind-22242 event with the transport key, answers with `["AUTH", event]`,
//! waits for its `OK`, and re-sends the pending `EVENT`/`REQ`. Relays that never
//! ask need no extra round trip.

use std::collections::HashSet;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{client_tls_with_config, Message, WebSocket};
use url::{Host, Url};

use super::event::Event;
use super::keys::NostrKeys;
use super::relay::{Relay, RelayFilter};
use crate::error::{Error, Result};

/// Budget for DNS, TCP and the WebSocket/TLS handshake together.
#[allow(dead_code)] // only referenced by the non-test branch of connect_budget`r
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Production uses ten seconds; tests use a short budget so a stalled relay can
/// be exercised without slowing the suite.
fn connect_budget() -> Duration {
    #[cfg(test)]
    {
        Duration::from_millis(300)
    }
    #[cfg(not(test))]
    {
        CONNECT_TIMEOUT
    }
}
/// Read/write budget for one relay operation after the handshake.
const IO_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a publish waits for the matching `OK`.
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a query waits for `EOSE` after the last event.
const QUERY_TIMEOUT: Duration = Duration::from_secs(20);
/// A relay may ask for authentication at most this many times per operation.
const MAX_AUTH_ATTEMPTS: u8 = 2;
/// One relay message above this is a protocol/resource violation, not an event.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Frame cap keeps a single fragmented message from allocating unbounded memory.
const MAX_FRAME_BYTES: usize = 256 * 1024;
/// A query asks for at most a handful of events; anything beyond these caps is a
/// flood, and the query fails instead of silently truncating or growing memory.
const MAX_QUERY_EVENTS: usize = 4096;
const MAX_QUERY_BYTES: usize = 8 * 1024 * 1024;

fn store(message: impl Into<String>) -> Error {
    Error::Store(format!("nostr/ws: {}", message.into()))
}

/// One relay endpoint. Connections are opened per operation and never pooled.
pub struct WsRelay {
    url: String,
    keys: NostrKeys,
}

impl WsRelay {
    /// Parse and enforce the relay URL policy. The host is compared as a parsed
    /// host, not as a string prefix: `ws://localhost.attacker.invalid` is remote.
    fn parse_url(url: &str) -> Result<Url> {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return Err(store("empty relay URL"));
        }
        let parsed =
            Url::parse(trimmed).map_err(|error| store(format!("invalid relay URL: {error}")))?;
        match parsed.scheme() {
            "wss" => {}
            "ws" => {
                let loopback = matches!(parsed.host(), Some(Host::Domain(host)) if host.eq_ignore_ascii_case("localhost"))
                    || matches!(parsed.host(), Some(Host::Ipv4(ip)) if ip.is_loopback())
                    || matches!(parsed.host(), Some(Host::Ipv6(ip)) if ip.is_loopback());
                if !loopback {
                    return Err(store("relay URL must be wss:// (ws:// only for loopback)"));
                }
            }
            _ => return Err(store("relay URL must be wss:// (ws:// only for loopback)")),
        }
        Ok(parsed)
    }

    /// Validate a relay URL without creating a client (settings, tests).
    pub fn validate_url(url: &str) -> Result<()> {
        Self::parse_url(url).map(|_| ())
    }

    /// Accept `wss://`; `ws://` only for loopback (unit tests, local drills).
    pub fn new(url: &str, keys: NostrKeys) -> Result<Self> {
        Self::validate_url(url)?;
        Ok(Self {
            url: url.trim().to_string(),
            keys,
        })
    }

    /// Signed NIP-42 authentication event for one challenge.
    pub(crate) fn auth_event(&self, challenge: &str) -> Result<Event> {
        let tags = vec![
            vec!["relay".to_string(), self.relay_tag()],
            vec!["challenge".to_string(), challenge.to_string()],
        ];
        Event::unsigned(
            self.keys.public_hex(),
            super::unix_now_secs(),
            22242,
            tags,
            String::new(),
        )
        .sign(self.keys.secret())
    }

    /// Relay URL as used by the NIP-42 `relay` tag (no trailing slash).
    fn relay_tag(&self) -> String {
        self.url.trim_end_matches('/').to_string()
    }

    /// Resolve with the caller's deadline. The OS resolver is blocking, so the
    /// lookup runs on a helper thread; the connection attempt itself still fails
    /// when the budget expires instead of pinning the transport worker.
    fn resolve_with_budget(host: &str, port: u16, deadline: Instant) -> Result<Vec<SocketAddr>> {
        let host = host.to_string();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = (host.as_str(), port)
                .to_socket_addrs()
                .map(|addrs| addrs.collect::<Vec<_>>());
            let _ = tx.send(result);
        });
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(store("resolve deadline exceeded"));
        }
        match rx.recv_timeout(remaining) {
            Ok(Ok(addrs)) if !addrs.is_empty() => Ok(addrs),
            Ok(Ok(_)) => Err(store("relay host has no address")),
            Ok(Err(error)) => Err(store(format!("resolve: {error}"))),
            Err(_) => Err(store("resolve deadline exceeded")),
        }
    }

    fn open(&self) -> Result<WebSocket<MaybeTlsStream<TcpStream>>> {
        install_crypto_provider();
        let parsed = Self::parse_url(&self.url)?;
        let host = match parsed.host() {
            Some(Host::Domain(host)) => host.to_string(),
            Some(Host::Ipv4(ip)) => ip.to_string(),
            Some(Host::Ipv6(ip)) => ip.to_string(),
            None => return Err(store("relay URL has no host")),
        };
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| store("relay URL has no port"))?;
        let deadline = Instant::now() + connect_budget();
        let addrs = Self::resolve_with_budget(&host, port, deadline)?;
        let mut last_error = None;
        let mut socket = None;
        for addr in addrs {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match TcpStream::connect_timeout(&addr, remaining) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    // Bound TLS and WebSocket handshake I/O by the same budget.
                    let _ = stream.set_read_timeout(Some(connect_budget()));
                    let _ = stream.set_write_timeout(Some(connect_budget()));
                    let mut config = WebSocketConfig::default();
                    config.max_message_size = Some(MAX_MESSAGE_BYTES);
                    config.max_frame_size = Some(MAX_FRAME_BYTES);
                    match client_tls_with_config(self.url.as_str(), stream, Some(config), None) {
                        Ok((ws, _response)) => {
                            socket = Some(ws);
                            break;
                        }
                        Err(error) => {
                            return Err(store(format!("handshake: {error}")));
                        }
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }
        let socket = socket.ok_or_else(|| {
            store(format!(
                "connect deadline exceeded: {}",
                last_error
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "no address".into())
            ))
        })?;
        match socket.get_ref() {
            MaybeTlsStream::Plain(stream) => {
                let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
            }
            MaybeTlsStream::Rustls(stream) => {
                let _ = stream.sock.set_read_timeout(Some(IO_TIMEOUT));
                let _ = stream.sock.set_write_timeout(Some(IO_TIMEOUT));
            }
            _ => {}
        }
        Ok(socket)
    }

    fn send(&self, socket: &mut WebSocket<MaybeTlsStream<TcpStream>>, text: String) -> Result<()> {
        socket
            .send(Message::Text(text.into()))
            .map_err(|error| store(format!("send: {error}")))?;
        socket
            .flush()
            .map_err(|error| store(format!("flush: {error}")))
    }

    fn close(mut socket: WebSocket<MaybeTlsStream<TcpStream>>) {
        let _ = socket.close(None);
        let _ = socket.flush();
    }

    /// Answer one challenge and register the pending `AUTH` event id.
    fn answer_auth(
        &self,
        socket: &mut WebSocket<MaybeTlsStream<TcpStream>>,
        challenge: &str,
    ) -> Result<String> {
        let event = self.auth_event(challenge)?;
        let id = event.id.clone();
        self.send(socket, auth_payload(&event))?;
        Ok(id)
    }
}

impl Relay for WsRelay {
    fn publish(&self, event: &Event) -> Result<()> {
        let mut socket = self.open()?;
        self.send(&mut socket, publish_payload(event))?;
        let deadline = Instant::now() + PUBLISH_TIMEOUT;
        let mut auth_attempts = 0u8;
        let mut pending_auth: Option<String> = None;
        let outcome = loop {
            if Instant::now() > deadline {
                break Err(store("timeout waiting for OK"));
            }
            let message = match socket.read() {
                Ok(message) => message,
                Err(error) => break Err(store(format!("read: {error}"))),
            };
            let text = match message {
                Message::Text(text) => text.to_string(),
                Message::Close(_) => break Err(store("relay closed the connection")),
                _ => continue,
            };
            match parse_message(&text) {
                Ok(RelayMessage::Auth(challenge)) => {
                    if auth_attempts >= MAX_AUTH_ATTEMPTS {
                        break Err(store("relay asked for authentication too many times"));
                    }
                    auth_attempts += 1;
                    match self.answer_auth(&mut socket, &challenge) {
                        Ok(id) => pending_auth = Some(id),
                        Err(error) => break Err(error),
                    }
                }
                Ok(RelayMessage::Ok {
                    id,
                    accepted,
                    message,
                }) => {
                    if pending_auth.as_deref() == Some(id.as_str()) {
                        if !accepted {
                            break Err(store(format!("relay rejected AUTH: {message}")));
                        }
                        pending_auth = None;
                        // The relay may have dropped the event while it wanted
                        // authentication; one resend after a successful AUTH is
                        // the NIP-42 pattern.
                        if let Err(error) = self.send(&mut socket, publish_payload(event)) {
                            break Err(error);
                        }
                        continue;
                    }
                    if id != event.id {
                        continue;
                    }
                    if accepted {
                        break Ok(());
                    }
                    break Err(store(format!("relay rejected the event: {message}")));
                }
                Ok(RelayMessage::Notice(message)) => {
                    // A NOTICE is advisory; keep waiting for the matching OK.
                    let _ = message;
                }
                Ok(RelayMessage::Closed { message, .. }) => {
                    if pending_auth.is_some() {
                        // Wait for the AUTH OK, then the resend decides.
                        continue;
                    }
                    break Err(store(format!("relay closed the subscription: {message}")));
                }
                Ok(_) => continue,
                Err(error) => break Err(error),
            }
        };
        Self::close(socket);
        outcome
    }

    fn query(&self, filter: &RelayFilter) -> Result<Vec<Event>> {
        let mut socket = self.open()?;
        let subscription = format!("flint-{}", std::process::id());
        self.send(&mut socket, req_payload(filter, &subscription))?;
        let mut events = Vec::new();
        let mut seen = HashSet::new();
        let mut received = 0usize;
        let mut received_bytes = 0usize;
        let mut auth_attempts = 0u8;
        let mut pending_auth: Option<String> = None;
        let deadline = Instant::now() + QUERY_TIMEOUT;
        loop {
            if Instant::now() > deadline {
                break;
            }
            let message = match socket.read() {
                Ok(message) => message,
                Err(error) => {
                    Self::close(socket);
                    return Err(store(format!("read: {error}")));
                }
            };
            let text = match message {
                Message::Text(text) => text.to_string(),
                Message::Close(_) => break,
                _ => continue,
            };
            received += 1;
            received_bytes = received_bytes.saturating_add(text.len());
            if received > MAX_QUERY_EVENTS || received_bytes > MAX_QUERY_BYTES {
                Self::close(socket);
                return Err(store("query budget exceeded: relay sent too many messages"));
            }
            match parse_message(&text) {
                Ok(RelayMessage::Auth(challenge)) => {
                    if auth_attempts >= MAX_AUTH_ATTEMPTS {
                        Self::close(socket);
                        return Err(store("relay asked for authentication too many times"));
                    }
                    auth_attempts += 1;
                    match self.answer_auth(&mut socket, &challenge) {
                        Ok(id) => pending_auth = Some(id),
                        Err(error) => {
                            Self::close(socket);
                            return Err(error);
                        }
                    }
                }
                Ok(RelayMessage::Ok {
                    id,
                    accepted,
                    message,
                }) if pending_auth.as_deref() == Some(id.as_str()) => {
                    if !accepted {
                        Self::close(socket);
                        return Err(store(format!("relay rejected AUTH: {message}")));
                    }
                    pending_auth = None;
                    // Re-issue the subscription now that the relay knows us.
                    if let Err(error) = self.send(&mut socket, req_payload(filter, &subscription)) {
                        Self::close(socket);
                        return Err(error);
                    }
                }
                Ok(RelayMessage::Event(event)) => {
                    if seen.insert(event.id.clone()) && events.len() < filter.limit.max(1) {
                        events.push(event);
                    }
                }
                Ok(RelayMessage::Eose(id)) if id == subscription => break,
                Ok(RelayMessage::Closed {
                    subscription: id,
                    message,
                }) if id == subscription => {
                    if pending_auth.is_some() {
                        continue;
                    }
                    Self::close(socket);
                    if message.contains("auth-required") && auth_attempts == 0 {
                        return Err(store(
                            "relay requires NIP-42 authentication but sent no AUTH challenge",
                        ));
                    }
                    return Err(store(format!("relay closed the subscription: {message}")));
                }
                Ok(_) => continue,
                Err(error) => {
                    Self::close(socket);
                    return Err(error);
                }
            }
        }
        let _ = self.send(&mut socket, json!(["CLOSE", subscription]).to_string());
        Self::close(socket);
        Ok(events)
    }
}

/// `rustls` cannot infer a provider from crate features here (the vendor tree
/// enables neither `aws-lc-rs` nor `ring` by default), so install `ring` once.
fn install_crypto_provider() {
    use std::sync::Once;
    static INSTALL: Once = Once::new();
    INSTALL.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// `["EVENT", event]` as sent by a client.
fn publish_payload(event: &Event) -> String {
    json!(["EVENT", event]).to_string()
}

/// `["AUTH", event]` as sent by a client (NIP-42).
fn auth_payload(event: &Event) -> String {
    json!(["AUTH", event]).to_string()
}

/// `["REQ", subscription, filter]` with only the fields in use.
fn req_payload(filter: &RelayFilter, subscription: &str) -> String {
    let mut object = serde_json::Map::new();
    if !filter.kinds.is_empty() {
        object.insert("kinds".into(), json!(filter.kinds));
    }
    if let Some(recipient) = &filter.recipient {
        object.insert("#p".into(), json!([recipient]));
    }
    object.insert("since".into(), json!(filter.since));
    if filter.limit > 0 {
        object.insert("limit".into(), json!(filter.limit));
    }
    json!(["REQ", subscription, Value::Object(object)]).to_string()
}

/// Parsed relay-to-client message (the subset this transport uses).
#[derive(Debug, PartialEq)]
pub(crate) enum RelayMessage {
    Ok {
        id: String,
        accepted: bool,
        message: String,
    },
    Event(Event),
    Eose(String),
    Notice(String),
    Closed {
        subscription: String,
        message: String,
    },
    /// NIP-42 challenge: the relay wants the client to authenticate.
    Auth(String),
    Other,
}

fn parse_message(text: &str) -> Result<RelayMessage> {
    let value: Value =
        serde_json::from_str(text).map_err(|error| store(format!("json: {error}")))?;
    let array = value
        .as_array()
        .ok_or_else(|| store("relay message is not an array"))?;
    let kind = array.first().and_then(Value::as_str).unwrap_or_default();
    let string_at = |index: usize| {
        array
            .get(index)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    Ok(match kind {
        "OK" => RelayMessage::Ok {
            id: string_at(1),
            accepted: array.get(2).and_then(Value::as_bool).unwrap_or(false),
            message: string_at(3),
        },
        "EVENT" => {
            let raw = array
                .get(2)
                .cloned()
                .ok_or_else(|| store("EVENT without payload"))?;
            let event: Event =
                serde_json::from_value(raw).map_err(|error| store(format!("event: {error}")))?;
            RelayMessage::Event(event)
        }
        "EOSE" => RelayMessage::Eose(string_at(1)),
        "NOTICE" => RelayMessage::Notice(string_at(1)),
        "CLOSED" => RelayMessage::Closed {
            subscription: string_at(1),
            message: string_at(2),
        },
        "AUTH" => RelayMessage::Auth(string_at(1)),
        _ => RelayMessage::Other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex};

    fn test_keys() -> NostrKeys {
        NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
            .expect("keys")
    }

    #[test]
    fn url_policy() {
        let keys = test_keys;
        assert!(WsRelay::new("wss://relay.example.com", keys()).is_ok());
        assert!(WsRelay::new("ws://127.0.0.1:8080", keys()).is_ok());
        assert!(WsRelay::new("ws://localhost:7777", keys()).is_ok());
        assert!(WsRelay::new("ws://relay.example.com", keys()).is_err());
        assert!(WsRelay::new("https://relay.example.com", keys()).is_err());
        assert!(WsRelay::new("", keys()).is_err());
        // Prefix tricks must not pass as loopback.
        assert!(WsRelay::new("ws://localhost.attacker.invalid", keys()).is_err());
        assert!(WsRelay::new("ws://127.0.0.1.attacker.invalid", keys()).is_err());
        assert!(WsRelay::new("ws://localhostattacker.invalid", keys()).is_err());
        assert!(WsRelay::new("ws://127.0.0.1@attacker.invalid", keys()).is_err());
        assert!(WsRelay::validate_url("ws://localhost.attacker.invalid").is_err());
        assert!(WsRelay::validate_url("ws://localhost:7777").is_ok());
        assert!(WsRelay::validate_url("wss://localhost.attacker.invalid").is_ok());
    }

    #[test]
    fn auth_event_carries_relay_and_challenge() {
        let relay = WsRelay::new("wss://relay.example.com/", test_keys()).expect("relay");
        let event = relay.auth_event("challenge-1").expect("auth event");
        assert_eq!(event.kind, 22242);
        assert_eq!(event.content, "");
        assert_eq!(event.tags[0], vec!["relay", "wss://relay.example.com"]);
        assert_eq!(event.tags[1], vec!["challenge", "challenge-1"]);
        let public = event.verify().expect("auth event signature");
        assert_eq!(public, relay.keys.public());
    }

    #[test]
    fn payloads_and_messages() {
        let event = Event::unsigned(
            "ab".repeat(32),
            1_700_000_000,
            1059,
            vec![vec!["p".into(), "cd".repeat(32)]],
            "payload".into(),
        )
        .sign(
            &secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .expect("secret"),
        )
        .expect("sign");

        let published: Value = serde_json::from_str(&publish_payload(&event)).expect("json");
        assert_eq!(published[0], "EVENT");
        assert_eq!(published[1]["id"], event.id);

        let filter = RelayFilter {
            kinds: vec![1059],
            recipient: Some("cd".repeat(32)),
            since: 5,
            limit: 7,
        };
        let request: Value = serde_json::from_str(&req_payload(&filter, "sub")).expect("json");
        assert_eq!(request[0], "REQ");
        assert_eq!(request[1], "sub");
        assert_eq!(request[2]["kinds"][0], 1059);
        assert_eq!(request[2]["#p"][0], "cd".repeat(32));
        assert_eq!(request[2]["limit"], 7);

        assert!(matches!(
            parse_message(r#"["OK","id",true,"saved"]"#).expect("ok"),
            RelayMessage::Ok { accepted: true, .. }
        ));
        assert!(matches!(
            parse_message(r#"["EOSE","sub"]"#).expect("eose"),
            RelayMessage::Eose(id) if id == "sub"
        ));
        assert!(matches!(
            parse_message(r#"["CLOSED","sub","error: not found"]"#).expect("closed"),
            RelayMessage::Closed { .. }
        ));
        assert!(matches!(
            parse_message(r#"["NOTICE","slow down"]"#).expect("notice"),
            RelayMessage::Notice(_)
        ));
        assert!(matches!(
            parse_message(r#"["AUTH","challenge"]"#).expect("auth"),
            RelayMessage::Auth(challenge) if challenge == "challenge"
        ));
        let wrapped = json!(["EVENT", "sub", serde_json::to_value(&event).expect("value")]);
        assert!(matches!(
            parse_message(&wrapped.to_string()).expect("event"),
            RelayMessage::Event(parsed) if parsed.id == event.id
        ));
        assert!(parse_message("not json").is_err());
        assert!(parse_message("{}").is_err());
    }

    /// Loopback relay that demands NIP-42: the query must authenticate first,
    /// then the re-issued REQ gets EOSE.
    #[test]
    fn query_answers_auth_challenge_and_retries() {
        use std::net::TcpListener;
        use tungstenite::accept;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let server_seen = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let Ok(mut socket) = accept(stream) else {
                    break;
                };
                let _ = socket.send(tungstenite::Message::Text(
                    r#"["AUTH","chal-loopback"]"#.to_string().into(),
                ));
                let mut authed = false;
                loop {
                    let Ok(message) = socket.read() else { break };
                    let tungstenite::Message::Text(text) = message else {
                        continue;
                    };
                    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                        continue;
                    };
                    let Some(array) = value.as_array() else {
                        continue;
                    };
                    match array.first().and_then(|v| v.as_str()) {
                        Some("AUTH") => {
                            let Some(raw) = array.get(1).cloned() else {
                                continue;
                            };
                            let Ok(event) = serde_json::from_value::<Event>(raw) else {
                                continue;
                            };
                            let tags = event.tags.clone();
                            let challenge_ok = tags.iter().any(|tag| {
                                tag == &vec!["challenge".to_string(), "chal-loopback".to_string()]
                            });
                            let relay_ok = tags.iter().any(|tag| {
                                tag.first().map(String::as_str) == Some("relay")
                                    && tag.get(1).map(String::as_str)
                                        == Some(&format!("ws://{address}"))
                            });
                            let signed = event.verify().is_ok();
                            server_seen
                                .lock()
                                .expect("seen")
                                .push(format!("AUTH kind={} challenge={challenge_ok} relay={relay_ok} signed={signed}", event.kind));
                            if signed && challenge_ok && relay_ok {
                                authed = true;
                                let _ = socket.send(tungstenite::Message::Text(
                                    json!(["OK", event.id, true, ""]).to_string().into(),
                                ));
                            } else {
                                let _ = socket.send(tungstenite::Message::Text(
                                    json!(["OK", event.id, false, "invalid auth"])
                                        .to_string()
                                        .into(),
                                ));
                            }
                        }
                        Some("REQ") => {
                            let subscription = array
                                .get(1)
                                .and_then(|v| v.as_str())
                                .unwrap_or("sub")
                                .to_string();
                            server_seen
                                .lock()
                                .expect("seen")
                                .push(format!("REQ authed={authed}"));
                            if authed {
                                let _ = socket.send(tungstenite::Message::Text(
                                    json!(["EOSE", subscription]).to_string().into(),
                                ));
                            } else {
                                let _ = socket.send(tungstenite::Message::Text(
                                    json!(["CLOSED", subscription, "auth-required"])
                                        .to_string()
                                        .into(),
                                ));
                            }
                        }
                        Some("CLOSE") => break,
                        _ => {}
                    }
                }
            }
        });

        let url = format!("ws://{address}");
        let relay = WsRelay::new(&url, test_keys()).expect("relay");
        let filter = RelayFilter {
            kinds: vec![1],
            recipient: None,
            since: super::super::unix_now_secs().saturating_sub(60),
            limit: 2,
        };
        let events = relay.query(&filter).expect("query after auth");
        assert!(events.is_empty());
        let seen = seen.lock().expect("seen").clone();
        assert!(
            seen.iter().any(|line| line.starts_with("AUTH kind=22242",)
                && line.contains("challenge=true")
                && line.contains("signed=true")),
            "relay must receive a valid AUTH event: {seen:?}"
        );
        assert!(
            seen.iter().any(|line| line == "REQ authed=true"),
            "the request must be retried after authentication: {seen:?}"
        );
    }

    /// A server that completes TCP but never answers the WebSocket handshake
    /// must fail within the connect budget, not pin the worker.
    #[test]
    fn handshake_is_bounded_by_the_connect_budget() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_secs(3));
                drop(stream);
            }
        });

        let relay = WsRelay::new(&format!("ws://{address}"), test_keys()).expect("relay");
        let filter = RelayFilter {
            kinds: vec![1],
            recipient: None,
            since: super::super::unix_now_secs().saturating_sub(60),
            limit: 2,
        };
        let started = Instant::now();
        assert!(relay.query(&filter).is_err());
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "handshake must respect the connect budget, took {:?}",
            started.elapsed()
        );
    }

    /// A relay that ignores `REQ` and floods NOTICEs must hit the query budget
    /// instead of growing memory until the deadline.
    #[test]
    fn query_stops_a_message_flood() {
        use std::net::TcpListener;
        use tungstenite::accept;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let Ok(mut socket) = accept(stream) else {
                return;
            };
            let mut sent = false;
            for _ in 0..5000 {
                if socket
                    .send(tungstenite::Message::Text(
                        r#"["NOTICE","flood"]"#.to_string().into(),
                    ))
                    .is_err()
                {
                    break;
                }
                sent = true;
            }
            // Keep the connection open so the client observes its own budget
            // error instead of a reset caused by our socket dropping.
            if sent {
                std::thread::sleep(Duration::from_secs(5));
            }
        });

        let relay = WsRelay::new(&format!("ws://{address}"), test_keys()).expect("relay");
        let filter = RelayFilter {
            kinds: vec![1],
            recipient: None,
            since: super::super::unix_now_secs().saturating_sub(60),
            limit: 2,
        };
        let error = relay.query(&filter).expect_err("flood must fail the query");
        assert!(
            error.to_string().contains("budget exceeded"),
            "unexpected error: {error}"
        );
    }

    /// A message above the configured WebSocket cap is a protocol violation.
    #[test]
    fn query_rejects_an_oversized_message() {
        use std::net::TcpListener;
        use tungstenite::accept;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let Ok(mut socket) = accept(stream) else {
                return;
            };
            let _ = socket.send(tungstenite::Message::Text(
                "x".repeat(2 * 1024 * 1024).into(),
            ));
        });

        let relay = WsRelay::new(&format!("ws://{address}"), test_keys()).expect("relay");
        let filter = RelayFilter {
            kinds: vec![1],
            recipient: None,
            since: super::super::unix_now_secs().saturating_sub(60),
            limit: 2,
        };
        assert!(relay.query(&filter).is_err());
    }

    /// Read-only network probe: REQ → EOSE on a live relay. Not run by default.
    /// Set `FLINT_NOSTR_LIVE_RELAY=wss://…` and run with `--ignored`.
    #[test]
    #[ignore = "network: requires FLINT_NOSTR_LIVE_RELAY"]
    fn live_relay_req_returns_eose() {
        let Ok(url) = std::env::var("FLINT_NOSTR_LIVE_RELAY") else {
            panic!("FLINT_NOSTR_LIVE_RELAY must be set for the live relay probe");
        };
        // The probe verifies TLS, WebSocket, AUTH (when asked), REQ and EOSE.
        // Kind 1 is the default; kind 1059 now also works on relays that gate DM
        // filters behind NIP-42.
        let kind = std::env::var("FLINT_NOSTR_LIVE_RELAY_KIND")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1u32);
        let relay = WsRelay::new(&url, NostrKeys::generate().expect("keys")).expect("relay url");
        let recipient = std::env::var("FLINT_NOSTR_LIVE_RECIPIENT")
            .ok()
            .filter(|value| !value.is_empty());
        let filter = RelayFilter {
            kinds: vec![kind],
            recipient,
            since: super::super::unix_now_secs().saturating_sub(600),
            limit: 3,
        };
        let events = relay.query(&filter).expect("query");
        assert!(events.len() <= 3);
        assert!(events.iter().all(|event| event.kind == kind));
        for event in &events {
            event.verify().expect("relay event must verify");
        }
    }
}
