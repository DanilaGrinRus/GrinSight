//! In-memory relay experiment: no sockets, production keys or payment actions.
#![cfg(not(target_arch = "wasm32"))]
use std::{fmt, pin::Pin, sync::{Arc, Mutex}, task::{Context, Poll}, time::Duration};
use async_wsocket::{ConnectionMode, Message};
use futures_util::Sink;
use fly_nostr_research::nostr::{verified_unwrap::unwrap_from_contact, wrapv3};
use nostr_sdk::{ClientBuilder, ClientMessage, Event, EventBuilder, JsonUtil, Keys, Kind, RelayMessage, Tag, Url,
    nostr::util::BoxedFuture, pool::{RelayPoolNotification, transport::{error::TransportError,
    websocket::{WebSocketSink, WebSocketStream, WebSocketTransport}}}};
use tokio::sync::mpsc::{self, UnboundedSender};

#[derive(Clone, Default)]
struct FakeRelay { receivers: Arc<Mutex<Vec<UnboundedSender<Message>>>>, wire: Arc<Mutex<Vec<String>>> }
impl fmt::Debug for FakeRelay { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("FakeRelay") } }
struct FakeSink(FakeRelay);
impl Sink<Message> for FakeSink {
    type Error = TransportError;
    fn poll_ready(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> { Poll::Ready(Ok(())) }
    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        if let Message::Text(text) = item {
            self.0.wire.lock().unwrap().push(text.clone());
            if let Ok(ClientMessage::Event(event)) = ClientMessage::from_json(&text) {
                let incoming = Message::Text(format!("[\"EVENT\",\"test-subscription\",{}]", event.as_json()));
                for receiver in self.0.receivers.lock().unwrap().iter() { let _ = receiver.send(incoming.clone()); }
            }
        }
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
            let (tx, rx) = mpsc::unbounded_channel();
            self.receivers.lock().unwrap().push(tx);
            let sink: WebSocketSink = Box::new(FakeSink(self.clone()));
            let stream: WebSocketStream = Box::pin(futures_util::stream::unfold(rx, |mut rx| async {
                rx.recv().await.map(|msg| (Ok(msg), rx))
            }));
            Ok((sink, stream))
        })
    }
}

async fn exercise_delivery(v3: bool) {
    let relay = FakeRelay::default();
    let sender = ClientBuilder::new().websocket_transport(relay.clone()).build();
    let recipient = ClientBuilder::new().websocket_transport(relay.clone()).build();
    let alice = Keys::generate(); let bob = Keys::generate(); let mallory = Keys::generate();
    let url = "wss://relay.example";
    let mut notifications = recipient.notifications();
    for client in [&sender, &recipient] {
        client.add_relay(url).await.unwrap();
        client.try_connect_relay(url, Duration::from_secs(3)).await.unwrap();
    }
    let message = "FLY_SYNTHETIC_SECRET_MESSAGE";
    let event = if v3 {
        wrapv3::wrap(&alice, &bob.public_key(), message.to_owned(), vec![]).unwrap()
    } else {
        let rumor = EventBuilder::new(Kind::PrivateDirectMessage, message)
            .tag(Tag::public_key(bob.public_key())).build(alice.public_key());
        EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor, []).await.unwrap()
    };
    sender.send_msg_to([url], ClientMessage::event(event)).await.unwrap();
    let received: Event = tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let RelayPoolNotification::Message { message: RelayMessage::Event { event, .. }, .. } = notifications.recv().await.unwrap() {
                break event.into_owned();
            }
        }
    }).await.expect("the second SDK must receive the event");
    let unwrapped = unwrap_from_contact(&bob, &received, &alice.public_key()).await.unwrap();
    assert_eq!(unwrapped.rumor.content, message);
    assert!(unwrap_from_contact(&bob, &received, &mallory.public_key()).await.is_err());
    assert!(unwrap_from_contact(&mallory, &received, &alice.public_key()).await.is_err());
    let wire = relay.wire.lock().unwrap().join("");
    assert!(!wire.contains(message));
    sender.disconnect().await;
    recipient.disconnect().await;
}

#[tokio::test]
async fn two_sdk_clients_deliver_v3_and_authenticate_contact() { exercise_delivery(true).await; }

#[tokio::test]
async fn two_sdk_clients_deliver_v2_and_authenticate_contact() { exercise_delivery(false).await; }
