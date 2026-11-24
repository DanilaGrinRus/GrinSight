//! Native Tor-only WebSocket transport for the Nostr SDK.
//! The caller owns and shares one bootstrapped Fly Tor client. This module
//! doesn't implement contact trust, retry queues, onion hosting or PWA.
use std::{fmt, pin::Pin, task::{Context, Poll}, time::Duration};
use async_wsocket::{ConnectionMode, Message};
use fly_tor::SharedTor;
use futures_util::{Sink, StreamExt};
use nostr_sdk::{nostr::util::BoxedFuture, pool::transport::{error::TransportError, websocket::{WebSocketSink, WebSocketStream, WebSocketTransport}}, Client, ClientBuilder, Keys, Url};
use tokio_tungstenite::{client_async_tls_with_config, tungstenite::{protocol::{Message as WireMessage, WebSocketConfig}, Error as WireError}};
use tokio_util::compat::FuturesAsyncReadCompatExt;

const MAX_MESSAGE: usize = 256 * 1024;
const MAX_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct TorWebSocketTransport { tor: SharedTor }

impl fmt::Debug for TorWebSocketTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("TorWebSocketTransport { redacted }") }
}

fn error() -> TransportError {
    TransportError::backend(std::io::Error::new(std::io::ErrorKind::Other, "Tor WebSocket transport failed"))
}

fn stage_error(stage: &'static str) -> TransportError {
    TransportError::backend(std::io::Error::new(std::io::ErrorKind::Other, stage))
}

fn handshake_error(err: WireError) -> TransportError {
    let stage = match err {
        WireError::Io(ref io) if io.kind() == std::io::ErrorKind::UnexpectedEof => "WSS connection ended during handshake",
        WireError::Io(ref io) if io.kind() == std::io::ErrorKind::ConnectionReset => "WSS connection reset during handshake",
        WireError::Io(_) => "WSS I/O failed during handshake",
        WireError::Tls(_) => "WSS TLS validation or handshake failed",
        WireError::Http(ref response) if response.status().is_client_error() => "WSS relay rejected handshake (4xx)",
        WireError::Http(ref response) if response.status().is_server_error() => "WSS relay failed handshake (5xx)",
        WireError::Http(_) => "WSS relay rejected handshake",
        WireError::Protocol(_) => "WSS protocol handshake failed",
        _ => "WSS handshake failed",
    };
    stage_error(stage)
}

pub(crate) fn destination(url: &Url, timeout: Duration) -> Result<(&str, u16), TransportError> {
    if timeout.is_zero() || timeout > MAX_TIMEOUT || url.scheme() != "wss"
        || !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() || url.query().is_some()
    { return Err(error()); }
    let host = url.host_str().ok_or_else(error)?;
    // Never resolve locally; reject numeric IP destinations and URL edge cases.
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') || host.len() > 253 {
        return Err(error());
    }
    let port = url.port_or_known_default().filter(|p| *p != 0).ok_or_else(error)?;
    Ok((host, port))
}

/// Build the client with the Tor-only transport installed before any relay
/// is added. Keep SDK default builders away from network-capable app code.
pub fn client(tor: SharedTor, keys: Keys) -> Client {
    ClientBuilder::new().signer(keys).websocket_transport(TorWebSocketTransport { tor }).build()
}

impl WebSocketTransport for TorWebSocketTransport {
    fn support_ping(&self) -> bool { true }
    fn connect<'a>(&'a self, url: &'a Url, _mode: &'a ConnectionMode, timeout: Duration)
        -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), TransportError>> {
        Box::pin(async move {
            let (host, port) = destination(url, timeout)?;
            // ConnectionMode from the SDK is deliberately ignored: *all*
            // relays pass through our owned Arti client, with no fallback.
            let connect = async {
                let stream = self.tor.connect_domain(host, port, timeout).await
                    .map_err(|_| stage_error("Tor connection failed"))?;
                let config = WebSocketConfig::default().max_message_size(Some(MAX_MESSAGE))
                    .max_frame_size(Some(MAX_MESSAGE)).max_write_buffer_size(MAX_MESSAGE * 2);
                // WSS only; rustls verifies the certificate and DNS name using
                // webpki roots. client_async_tls never opens a socket itself.
                let (ws, _) = client_async_tls_with_config(url.as_str(), stream.compat(), Some(config), None)
                    .await.map_err(handshake_error)?;
                let (sink, stream) = ws.split();
                let sink: WebSocketSink = Box::new(TorSink(sink));
                let stream: WebSocketStream = Box::pin(stream.map(|item| item.map_err(|_| error()).and_then(from_wire)));
                Ok((sink, stream))
            };
            tokio::time::timeout(timeout, connect).await.map_err(|_| stage_error("Tor WebSocket connection timed out"))?
        })
    }
}

fn from_wire(message: WireMessage) -> Result<Message, TransportError> {
    Ok(match message {
        WireMessage::Text(value) => Message::Text(value.to_string()),
        WireMessage::Binary(value) => Message::Binary(value.to_vec()),
        WireMessage::Ping(value) => Message::Ping(value.to_vec()),
        WireMessage::Pong(value) => Message::Pong(value.to_vec()),
        WireMessage::Close(value) => Message::Close(value.map(|v| async_wsocket::message::CloseFrame { code: v.code.into(), reason: v.reason.to_string() })),
        WireMessage::Frame(_) => return Err(error()),
    })
}

struct TorSink<S>(S);
impl<S> Sink<Message> for TorSink<S>
where S: Sink<WireMessage, Error = WireError> + Unpin {
    type Error = TransportError;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_ready(cx).map_err(|_| error())
    }
    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        if item.len() > MAX_MESSAGE { return Err(error()); }
        Pin::new(&mut self.0).start_send(item.into()).map_err(|_| error())
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_flush(cx).map_err(|_| error())
    }
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0).poll_close(cx).map_err(|_| error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn destination_rejects_plaintext_credentials_ip_and_bad_timeouts() {
        let good = Url::parse("wss://relay.example/path").unwrap();
        assert_eq!(destination(&good, Duration::from_secs(5)).unwrap(), ("relay.example", 443));
        for raw in ["ws://relay.example/", "wss://name:pass@relay.example/", "wss://127.0.0.1/", "wss://[::1]/", "wss://relay.example/#fragment", "wss://relay.example/?token=synthetic"] {
            assert!(destination(&Url::parse(raw).unwrap(), Duration::from_secs(5)).is_err());
        }
        assert!(destination(&good, Duration::ZERO).is_err());
        assert!(destination(&good, Duration::from_secs(301)).is_err());
    }
    #[test]
    fn wire_conversion_roundtrips_and_redacts_errors() {
        assert_eq!(from_wire(WireMessage::Text("synthetic".into())).unwrap(), Message::Text("synthetic".into()));
        assert_eq!(from_wire(WireMessage::Ping(vec![1, 2].into())).unwrap(), Message::Ping(vec![1, 2]));
        assert_eq!(error().to_string(), "Tor WebSocket transport failed");
        let synthetic = WireError::Io(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "secret-marker"));
        assert_eq!(handshake_error(synthetic).to_string(), "WSS connection reset during handshake");
    }

    #[test]
    #[ignore = "opt-in network test; Tor guards see the client IP"]
    fn live_wss_handshake_through_tor_without_publishing() {
        assert_eq!(std::env::var("FLY_ALLOW_TOR_NOSTR_TEST").as_deref(), Ok("1"));
        let fly_root = std::path::PathBuf::from(std::env::var_os("FLY_ROOT").expect("FLY_ROOT required"));
        let temp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        assert_eq!(temp, std::fs::canonicalize(fly_root.join(".tmp")).unwrap());
        let name = format!("fly-nostr-live-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        let root = temp.join(name);
        std::fs::create_dir(&root).unwrap();
        let url = Url::parse(&std::env::var("FLY_TEST_NOSTR_RELAY").expect("test relay required")).unwrap();
        assert!(destination(&url, Duration::from_secs(90)).is_ok());
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            let tor = SharedTor::bootstrap(&root, Duration::from_secs(120)).await.expect("Tor bootstrap failed");
            let transport = TorWebSocketTransport { tor };
            let (_sink, _stream) = transport.connect(&url, &ConnectionMode::direct(), Duration::from_secs(90))
                .await.expect("Tor WSS handshake failed");
        });
    }
}
