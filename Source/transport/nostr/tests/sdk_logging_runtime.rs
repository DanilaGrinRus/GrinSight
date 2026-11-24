//! Synthetic SDK relay: no sockets, keys, or real messages are used.
#![cfg(not(target_arch = "wasm32"))]
use std::{fmt, pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll}, time::Duration};
use async_wsocket::{ConnectionMode, Message};
use futures_util::{Sink, StreamExt};
use nostr_sdk::{ClientBuilder, ClientMessage, SubscriptionId, Url, nostr::util::BoxedFuture,
    pool::transport::{error::TransportError, websocket::{WebSocketSink, WebSocketStream, WebSocketTransport}}};
use tracing::{Event, Metadata, Subscriber, field::{Field, Visit}, span::{Attributes, Id, Record}};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<String>>);
struct Visitor<'a>(&'a mut String);
impl Visit for Visitor<'_> {
    fn record_debug(&mut self, _: &Field, value: &dyn fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, "{value:?}");
    }
}
impl Subscriber for Capture {
    fn enabled(&self, _: &Metadata<'_>) -> bool { true }
    fn new_span(&self, _: &Attributes<'_>) -> Id { Id::from_u64(1) }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut log = self.0.lock().unwrap();
        event.record(&mut Visitor(&mut log));
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

#[derive(Debug, Clone, Default)]
struct FakeRelay(Arc<Mutex<Vec<String>>>);
struct FakeSink(Arc<Mutex<Vec<String>>>);
impl Sink<Message> for FakeSink {
    type Error = TransportError;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { Poll::Ready(Ok(())) }
    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        if let Message::Text(text) = item { self.0.lock().unwrap().push(text); }
        Ok(())
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { Poll::Ready(Ok(())) }
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { Poll::Ready(Ok(())) }
}
impl WebSocketTransport for FakeRelay {
    fn support_ping(&self) -> bool { false }
    fn connect<'a>(&'a self, _: &'a Url, _: &'a ConnectionMode, _: Duration)
        -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), TransportError>> {
        Box::pin(async move {
            let sink: WebSocketSink = Box::new(FakeSink(self.0.clone()));
            let incoming = futures_util::stream::once(async {
                Ok(Message::Text(r#"["NOTICE","FLY_INBOUND_SECRET_MARKER"]"#.to_owned()))
            }).chain(futures_util::stream::pending());
            let stream: WebSocketStream = Box::pin(incoming);
            Ok((sink, stream))
        })
    }
}

#[test]
fn sdk_does_not_log_synthetic_incoming_or_outgoing_payload() {
    let capture = Capture::default();
    tracing::subscriber::set_global_default(capture.clone()).unwrap();
    tracing::debug!("FLY_LOG_CAPTURE_CONTROL");
    let fake = FakeRelay::default();
    let sent = fake.0.clone();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        let client = ClientBuilder::new().websocket_transport(fake).build();
        let url = "wss://relay.example";
        let mut notifications = client.notifications();
        client.add_relay(url).await.unwrap();
        client.try_connect_relay(url, Duration::from_secs(3)).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let message = notifications.recv().await.unwrap();
                if format!("{message:?}").contains("FLY_INBOUND_SECRET_MARKER") { break; }
            }
        }).await;
        assert!(received.is_ok(), "synthetic input must be received by the SDK");
        client.send_msg_to([url], ClientMessage::close(SubscriptionId::new("FLY_OUTBOUND_SECRET_MARKER"))).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while !sent.lock().unwrap().iter().any(|s| s.contains("FLY_OUTBOUND_SECRET_MARKER")) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.expect("synthetic output must reach the fake relay");
        client.disconnect().await;
    });
    let log = capture.0.lock().unwrap();
    assert!(log.contains("FLY_LOG_CAPTURE_CONTROL"), "logging capture must be active");
    assert!(!log.contains("FLY_INBOUND_SECRET_MARKER"));
    assert!(!log.contains("FLY_OUTBOUND_SECRET_MARKER"));
}
