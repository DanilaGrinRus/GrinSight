// SPDX-License-Identifier: MIT OR Apache-2.0
//! `Transport` implementation over Nostr gift wraps (kind 1059).
//!
//! The recipient's Nostr key is resolved through [`Directory`]; the transport
//! never guesses a key from an address, because the address is an ed25519
//! slatepack key and the transport key is unrelated secp256k1 material.

use std::collections::HashMap;

use secp256k1::XOnlyPublicKey;

use super::event::KIND_GIFT_WRAP;
use super::event::Event;
use super::{gift_wrap, unwrap, NostrKeys, Relay, RelayFilter};
use crate::address::Address;
use crate::contacts::Contact;
use crate::envelope::Envelope;
use crate::error::{Error, Result};
use crate::store::Transport;
use crate::{DEFAULT_TTL_SECS, MAX_TTL_SECS};
use super::cursor::{Cursor, CursorStore, Lane, PendingPage};

fn query_window(ttl: u64) -> u64 { ttl.saturating_add(172_800).saturating_add(300) }

/// Resolve the transport key of a peer by their Glaux address.
pub trait Directory: Send + Sync {
    fn nostr_pubkey(&self, address: &Address) -> Option<XOnlyPublicKey>;
}

/// Durable preservation is required before an unsupported signed event may be skipped.
pub trait DeferredNostrEvent: Send + Sync {
    fn preserve(&self, event:&Event, now:u64)->Result<()>;
}

/// Nostr delivery for Glaux envelopes with an explicit transport directory.
pub struct NostrTransport<R: Relay, D: Directory> {
    relay: R,
    keys: NostrKeys,
    directory: D,
    ttl: u64,
    publish_expiration: bool,
    warning: std::sync::Mutex<Option<String>>,
    paging: std::sync::Mutex<Option<Paging>>,
    deferred: Option<std::sync::Arc<dyn DeferredNostrEvent>>,
}

struct BufferedPage { tracker:PendingPage, items:Vec<(Envelope,Option<String>)>, blocked:bool, floor:u64, deferred:Vec<(Event,u64)> }
struct Paging { store:CursorStore, cursor:Cursor, pending:Option<BufferedPage>, lane:Lane }

/// Directory assembled from the encrypted contact book: the peer's address maps
/// to the Nostr transport key stored with that contact.
#[derive(Clone, Debug, Default)]
pub struct ContactDirectory {
    entries: HashMap<String, XOnlyPublicKey>,
}

impl ContactDirectory {
    /// Build from contacts; entries with an invalid or absent key are skipped.
    pub fn from_contacts(contacts: &[Contact]) -> Self {
        let mut entries = HashMap::new();
        for contact in contacts {
            let Some(hex) = contact.nostr.as_deref() else {
                continue;
            };
            if let Ok(key) = super::parse_public_hex(hex) {
                entries.insert(contact.address.clone(), key);
            }
        }
        Self { entries }
    }

    /// Add or replace one entry, validating the key.
    pub fn insert_hex(&mut self, address: &str, hex: &str) -> Result<()> {
        let key = super::parse_public_hex(hex)?;
        self.entries.insert(address.to_string(), key);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Directory for ContactDirectory {
    fn nostr_pubkey(&self, address: &Address) -> Option<XOnlyPublicKey> {
        self.entries.get(&address.to_string()).copied()
    }
}

impl<R: Relay, D: Directory> NostrTransport<R, D> {
    pub fn new(relay: R, keys: NostrKeys, directory: D) -> Self {
        Self {
            relay,
            keys,
            directory,
            ttl: DEFAULT_TTL_SECS,
            publish_expiration: false,
            warning: std::sync::Mutex::new(None),
            paging: std::sync::Mutex::new(None),
            deferred: None,
        }
    }

    pub fn with_deferred(mut self, sink:std::sync::Arc<dyn DeferredNostrEvent>)->Self { self.deferred=Some(sink); self }

    pub fn with_ttl(mut self, ttl: u64) -> Self {
        self.ttl = ttl.min(MAX_TTL_SECS);
        self
    }

    /// Request NIP-40 expiry on new events. Relays may ignore it or retain
    /// copies. The timestamp also reveals timing metadata to the relay.
    pub fn with_expiration_tag(mut self, enabled: bool) -> Self {
        self.publish_expiration = enabled;
        self
    }

    pub fn with_cursor(self, store:CursorStore)->Result<Self> {
        let cursor=store.load()?;
        let lane=if cursor.next_backfill {Lane::Backfill} else {Lane::Live};
        *self.paging.lock().map_err(|_|Error::Store("nostr cursor lock poisoned".into()))?=Some(Paging{store,cursor,pending:None,lane});
        Ok(self)
    }

    fn paged_fetch(&self, recipient:&crate::Identity, now:u64, limit:usize, paging:&mut Paging)->Result<Vec<(Envelope,Option<String>)>> {
        if let Some(page)=&paging.pending {return Ok(page.items.clone());}
        let window_floor=now.saturating_sub(query_window(self.ttl));
        if paging.cursor.backfill_done {paging.lane=Lane::Live;}
        let since=match paging.lane {Lane::Live=>if paging.cursor.live_floor==0 {window_floor} else {paging.cursor.live_floor.max(window_floor)},Lane::Backfill=>window_floor};
        let until=match paging.lane {Lane::Live=>paging.cursor.live_until.unwrap_or(now),Lane::Backfill=>paging.cursor.backfill_until.unwrap_or(now)};
        let filter=RelayFilter{kinds:vec![KIND_GIFT_WRAP],recipient:Some(self.keys.public_hex()),topic:None,since,until:Some(until),limit};
        let mut events=self.relay.query(&filter)?;
        if events.len()>limit {return Err(Error::Store("nostr relay exceeded requested limit".into()));}
        let full=events.len()==limit;
        let mut boundary_verified=!full;
        if full {
            if let Some(oldest)=events.iter().map(|e|e.created_at).min() {
                let boundary=RelayFilter{kinds:vec![KIND_GIFT_WRAP],recipient:Some(self.keys.public_hex()),topic:None,since:oldest,until:Some(oldest),limit};
                let extra=self.relay.query(&boundary)?;
                boundary_verified=extra.len()<limit && extra.iter().all(|e|e.created_at==oldest);
                let mut present:std::collections::HashSet<String>=events.iter().map(|e|e.id.clone()).collect();
                for event in extra {if present.insert(event.id.clone()) {events.push(event);}}
            }
        }
        let mut blocked=false;let mut opened=Vec::new();let mut ids=Vec::new();let mut saved=Vec::new();let mut staged=Vec::new();
        for event in events {
            if event.created_at<since || event.created_at>until || event.verify().is_err() {blocked=true;continue;}
            let envelope=unwrap(&event,self.keys.secret()).ok().and_then(|(_,rumor)|serde_json::from_str::<Envelope>(&rumor.content).ok());
            // Expired events cannot be delivered; do not fill the deferred
            // quota with dead ciphertext. Count them in page boundary/ACK.
            if envelope.as_ref().is_some_and(|e|e.ttl>0 && e.ttl<=MAX_TTL_SECS && e.created_at.saturating_add(e.ttl.min(self.ttl))<=now) {
                ids.push((event.id.clone(),event.created_at));saved.push(event.id);continue;
            }
            let valid=envelope.as_ref().is_some_and(|e|e.recipient==recipient.address().to_string() && e.ttl>0 && e.ttl<=MAX_TTL_SECS && e.created_at<=now.saturating_add(300) && e.open(recipient,now).is_ok());
            if !valid {
                // Stage the signed event in memory. The event and page cursor
                // are committed in the same authenticated atomic file replace.
                let mut candidate=paging.cursor.clone();
                let valid = staged.iter().try_for_each(|(e,t)|candidate.preserve(e,*t)).and_then(|_|candidate.preserve(&event,now));
                if valid.is_ok() {ids.push((event.id.clone(),event.created_at));saved.push(event.id.clone());staged.push((event,now));}
                else {blocked=true;}
                continue;
            }
            let envelope=envelope.expect("validated envelope");
            if envelope.created_at.saturating_add(envelope.ttl.min(self.ttl))<=now {continue;}
            ids.push((event.id.clone(),event.created_at));opened.push((envelope,Some(event.id)));
        }
        if full && ids.is_empty() {blocked=true;}
        if !staged.is_empty() { *self.warning.lock().map_err(|_|Error::Store("nostr warning state poisoned".into()))?=Some("Nostr events preserved for future processing".into()); }
        if blocked { *self.warning.lock().map_err(|_|Error::Store("nostr warning state poisoned".into()))?=Some("Nostr receive page contains unhandled events; delivery may be incomplete".into()); }
        if full && !boundary_verified { *self.warning.lock().map_err(|_|Error::Store("nostr warning state poisoned".into()))?=Some("Nostr receive page is full; delivery may be incomplete".into()); }
        // Maintain full/partial information even when expired events were filtered.
        let effective_limit=if full {ids.len().max(1)} else {limit};
        let mut tracker=PendingPage::new(paging.lane,&ids,effective_limit,true,boundary_verified)?;
        for id in saved {tracker.ack(&id)?;}
        if tracker.ready() {
            if !blocked && !tracker.incomplete() {
                let mut next=tracker.commit(&paging.cursor)?;for (event,time) in &staged {next.preserve(event,*time)?;}if paging.lane==Lane::Live && next.live_until.is_none(){next.live_floor=window_floor;}next.next_backfill=paging.lane==Lane::Live;
                if let Err(error)=paging.store.save_if(&paging.cursor,&next) {paging.cursor=paging.store.load()?;return Err(error);}paging.cursor=next;paging.lane=match paging.lane {Lane::Live=>Lane::Backfill,Lane::Backfill=>Lane::Live};
            }
            return Ok(opened);
        }
        paging.pending=Some(BufferedPage{tracker,items:opened.clone(),blocked,floor:window_floor,deferred:staged});
        Ok(opened)
    }

    /// Transport identity other peers need to address this wallet.
    pub fn public_hex(&self) -> String {
        self.keys.public_hex()
    }
}

impl<R: Relay, D: Directory> Transport for NostrTransport<R, D> {
    fn take_warning(&self) -> Option<String> { self.warning.lock().ok().and_then(|mut w| w.take()) }
    fn fetch_signed_tagged(&self, recipient: &crate::Identity, now: u64, limit: usize) -> Result<Vec<(Envelope, Option<String>)>> {
        if limit == 0 { return Ok(Vec::new()); }
        let mut paging=self.paging.lock().map_err(|_|Error::Store("nostr cursor lock poisoned".into()))?;
        if let Some(ref mut state)=*paging {return self.paged_fetch(recipient,now,limit,state);}
        let filter = RelayFilter { kinds: vec![KIND_GIFT_WRAP], recipient: Some(self.keys.public_hex()), topic: None, since: now.saturating_sub(query_window(self.ttl)), until: None, limit };
        let events = self.relay.query(&filter)?;
        if events.len() >= limit {
            *self.warning.lock().map_err(|_|Error::Store("nostr warning state poisoned".into()))? = Some("Nostr receive page is full; delivery may be incomplete".into());
        }
        let mut out = Vec::new();
        for event in events {
            if event.verify().is_err() { continue; }
            let Ok((_, rumor)) = unwrap(&event, self.keys.secret()) else { continue; };
            let Ok(envelope) = serde_json::from_str::<Envelope>(&rumor.content) else { continue; };
            if envelope.recipient != recipient.address().to_string() || envelope.ttl == 0 || envelope.ttl > MAX_TTL_SECS { continue; }
            let lifetime = envelope.ttl.min(self.ttl);
            if envelope.created_at > now.saturating_add(300) || envelope.created_at.saturating_add(lifetime) <= now { continue; }
            out.push((envelope, Some(event.id)));
        }
        Ok(out)
    }
    fn deliver(&self, envelope: &Envelope) -> Result<()> {
        let recipient = Address::parse(&envelope.recipient)?;
        let peer = self.directory.nostr_pubkey(&recipient).ok_or_else(|| {
            Error::Store("nostr: неизвестный транспортный ключ получателя".into())
        })?;
        let content = serde_json::to_string(envelope)
            .map_err(|error| Error::Envelope(format!("nostr: envelope: {error}")))?;
        let now = super::unix_now_secs();
        let event = if self.publish_expiration {
            let expires = envelope.created_at.checked_add(envelope.ttl).ok_or(Error::BadTtl(envelope.ttl))?;
            super::wrap::gift_wrap_with_expiration(self.keys.secret(), &peer, content, now, Some(expires))?
        } else {
            gift_wrap(self.keys.secret(), &peer, content, now)?
        };
        self.relay.publish(&event)
    }

    fn fetch(&self, recipient: &Address, now: u64, limit: usize) -> Result<Vec<Envelope>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        // NIP-59 randomizes the wrap timestamp by up to two days into the past,
        // so the subscription window must cover that jitter on top of the TTL.
        let window = query_window(self.ttl);
        let filter = RelayFilter {
            kinds: vec![KIND_GIFT_WRAP],
            recipient: Some(self.keys.public_hex()), topic: None,
            since: now.saturating_sub(window), until: None,
            limit,
        };
        let events = self.relay.query(&filter)?;
        let mut out = Vec::new();
        for event in events {
            // A wrap we cannot open (foreign key, corrupt payload) is skipped:
            // one poison message must not lose the rest of the batch.
            let Ok((_sender, rumor)) = unwrap(&event, self.keys.secret()) else {
                continue;
            };
            let Ok(envelope) = serde_json::from_str::<Envelope>(&rumor.content) else {
                continue;
            };
            if envelope.recipient != recipient.to_string() {
                continue;
            }
            if envelope.ttl == 0 || envelope.ttl > MAX_TTL_SECS {
                continue;
            }
            let lifetime = envelope.ttl.min(self.ttl);
            if envelope.created_at > now.saturating_add(300) || envelope.created_at.saturating_add(lifetime) <= now {
                continue;
            }
            out.push(envelope);
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    fn ack(&self, _recipient: &Address, ids: &[String]) -> Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut paging=self.paging.lock().map_err(|_|Error::Store("nostr cursor lock poisoned".into()))?;
        if let Some(state)=paging.as_mut() {
            let page=state.pending.as_ref().ok_or_else(||Error::Store("nostr ACK without pending page".into()))?;
            let mut tracker=page.tracker.clone();
            for id in ids {tracker.ack(id)?;}
            if tracker.ready() {
                if !page.blocked && !tracker.incomplete() {
                    let mut next=tracker.commit(&state.cursor)?;
                    for (event,time) in &page.deferred {next.preserve(event,*time)?;}
                    if state.lane==Lane::Live && next.live_until.is_none() {next.live_floor=page.floor;}
                    next.next_backfill=state.lane==Lane::Live;
                    if let Err(error)=state.store.save_if(&state.cursor,&next) {state.cursor=state.store.load()?;state.pending=None;return Err(error);}state.cursor=next;
                    state.lane=match state.lane {Lane::Live=>Lane::Backfill,Lane::Backfill=>Lane::Live};
                } else {
                    *self.warning.lock().map_err(|_|Error::Store("nostr warning state poisoned".into()))?=Some("Nostr receive page is full; delivery may be incomplete".into());
                }
                state.pending=None;
            } else {
                let page=state.pending.as_mut().unwrap();page.tracker=tracker;
                page.items.retain(|(_,token)|token.as_ref().is_none_or(|t|!ids.contains(t)));
            }
            return Ok(ids.len());
        }
        // Gift wraps are signed by an ephemeral sender key. The recipient
        // cannot validly issue a NIP-09 deletion for them. This ACK only
        // confirms local handling; relay storage is outside our control.
        Ok(ids.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Identity, MessageKind};
    use crate::nostr::MemoryRelay;
    use crate::nostr::WsRelay;
    use std::str::FromStr;
    use std::sync::Arc;

    struct SharedRelay(Arc<MemoryRelay>);
    impl Relay for SharedRelay {
        fn publish(&self, event: &Event) -> Result<()> {
            self.0.publish(event)
        }
        fn query(&self, filter: &RelayFilter) -> Result<Vec<Event>> {
            self.0.query(filter)
        }
    }

    #[derive(Clone, Default)]
    struct MapDirectory(HashMap<String, XOnlyPublicKey>);
    impl Directory for MapDirectory {
        fn nostr_pubkey(&self, address: &Address) -> Option<XOnlyPublicKey> {
            self.0.get(&address.to_string()).copied()
        }
    }

    fn keys(hex: &str) -> NostrKeys {
        NostrKeys::from_hex(hex).expect("keys")
    }

    fn peer(keys: &NostrKeys) -> XOnlyPublicKey {
        keys.public()
    }

    #[test]
    fn signed_collision_from_relay_is_not_acked_as_saved_after_restart() {
        use crate::history::{Direction, History, MessageRecord};
        use crate::store::Messenger;
        let relay = Arc::new(MemoryRelay::new());
        let akeys = keys("0000000000000000000000000000000000000000000000000000000000000001");
        let bkeys = keys("0000000000000000000000000000000000000000000000000000000000000002");
        let alice = Identity::from_seed([11; 32], "tgrin").unwrap();
        let bob = Identity::from_seed([22; 32], "tgrin").unwrap();
        let mut directory = MapDirectory::default();
        directory.0.insert(bob.address().to_string(), bkeys.public());
        let sender = NostrTransport::new(SharedRelay(relay.clone()), akeys, directory.clone());
        let id = uuid::Uuid::new_v4().to_string(); let now = crate::envelope::unix_now();
        for value in ["one", "two"] {
            let envelope = Envelope::seal_with_id(&alice, bob.address(), MessageKind::Text { text: value.into() }, 900, now, id.clone()).unwrap();
            sender.deliver(&envelope).unwrap();
        }
        let receiver = NostrTransport::new(SharedRelay(relay.clone()), bkeys, directory);
        let batch = Messenger::new(receiver).fetch_open(&bob, 10).unwrap();
        assert_eq!(batch.opened.len(), 2);
        assert_ne!(batch.opened[0].transport_token, batch.opened[1].transport_token);
        let to_record = |m: &crate::Opened| MessageRecord { id: m.id.clone(), direction: Direction::Incoming, signature_verified: true, kind: m.kind.clone(), created_at: m.created_at, expires_at: None, local_expiry_opt_in: false };
        let first = to_record(&batch.opened[0]); let second = to_record(&batch.opened[1]);
        let dir = std::env::temp_dir().join(format!("gs-v2-relay-collision-{}", uuid::Uuid::new_v4()));
        let history = History::open(&dir, [7;32]).unwrap();
        history.record(&alice.address(), &first).unwrap();
        history.delete(&alice.address(), &id).unwrap();
        drop(history);
        let history = History::open(&dir, [7;32]).unwrap();
        assert!(history.contains_record(alice.address(), &first).unwrap());
        assert!(history.contains_record(alice.address(), &second).is_err());
        drop(history); let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn full_receive_page_is_reported_as_incomplete() {
        let relay=Arc::new(MemoryRelay::new());
        let ak=keys("0000000000000000000000000000000000000000000000000000000000000001");
        let bk=keys("0000000000000000000000000000000000000000000000000000000000000002");
        let a=Identity::from_seed([11;32],"tgrin").unwrap();let b=Identity::from_seed([22;32],"tgrin").unwrap();
        let mut directory=MapDirectory::default();directory.0.insert(b.address().to_string(),bk.public());
        let sender=NostrTransport::new(SharedRelay(relay.clone()),ak,directory.clone());
        let e=Envelope::seal_now(&a,b.address(),MessageKind::Text{text:"x".into()},900).unwrap();
        sender.deliver(&e).unwrap();sender.deliver(&e).unwrap();
        let receiver=NostrTransport::new(SharedRelay(relay),bk,directory);
        let received=receiver.fetch_signed_tagged(&b,e.created_at,2).unwrap();
        assert_eq!(received.len(),2);
        assert!(receiver.take_warning().unwrap().contains("delivery may be incomplete"));
    }

    #[test]
    fn cursor_buffers_pages_and_replays_uncommitted_after_restart() {
        use crate::store::Messenger;
        let relay=Arc::new(MemoryRelay::new());
        let ak=keys("0000000000000000000000000000000000000000000000000000000000000001");
        let bk=keys("0000000000000000000000000000000000000000000000000000000000000002");
        let a=Identity::from_seed([11;32],"tgrin").unwrap();let b=Identity::from_seed([22;32],"tgrin").unwrap();
        let mut directory=MapDirectory::default();directory.0.insert(b.address().to_string(),bk.public());
        let sender=NostrTransport::new(SharedRelay(relay.clone()),ak,directory.clone());
        for i in 0..5 {let e=Envelope::seal_now(&a,b.address(),MessageKind::Text{text:format!("item-{i}")},900).unwrap();sender.deliver(&e).unwrap();}
        let dir=std::env::temp_dir().join(format!("gs-page-e2e-{}",uuid::Uuid::new_v4()));let path=dir.join("cursor.enc");
        let store=||CursorStore::new(path.clone(),[7;32],"profile","relay").unwrap();
        store().initialize(&Cursor::default()).unwrap();
        let first=Messenger::new(NostrTransport::new(SharedRelay(relay.clone()),bk.clone(),directory.clone()).with_cursor(store()).unwrap());
        let batch=first.fetch_open(&b,2).unwrap();assert_eq!(batch.opened.len(),2);
        let ids:Vec<_>=batch.opened.iter().map(|m|m.transport_token.clone().unwrap()).collect();first.ack_signed(&b,&ids).unwrap();
        assert_eq!(store().load().unwrap(),Cursor::default());drop(first);
        let receiver=Messenger::new(NostrTransport::new(SharedRelay(relay),bk,directory).with_cursor(store()).unwrap());
        let mut seen=std::collections::HashSet::new();
        for expected in [2,2,1] {
            let batch=receiver.fetch_open(&b,2).unwrap();assert_eq!(batch.opened.len(),expected);
            let ids:Vec<_>=batch.opened.iter().map(|m|m.transport_token.clone().unwrap()).collect();
            for id in &ids {assert!(seen.insert(id.clone()));}receiver.ack_signed(&b,&ids).unwrap();
        }
        assert_eq!(seen.len(),5);assert!(store().load().unwrap().next_backfill);
        drop(receiver);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_cursor_commit_keeps_pending_event_for_retry() {
        use crate::store::Messenger;
        let relay=Arc::new(MemoryRelay::new());let ak=keys("0000000000000000000000000000000000000000000000000000000000000001");
        let bk=keys("0000000000000000000000000000000000000000000000000000000000000002");
        let a=Identity::from_seed([11;32],"tgrin").unwrap();let b=Identity::from_seed([22;32],"tgrin").unwrap();
        let mut directory=MapDirectory::default();directory.0.insert(b.address().to_string(),bk.public());
        let sender=NostrTransport::new(SharedRelay(relay.clone()),ak,directory.clone());
        sender.deliver(&Envelope::seal_now(&a,b.address(),MessageKind::Text{text:"x".into()},900).unwrap()).unwrap();
        let dir=std::env::temp_dir().join(format!("gs-page-fail-{}",uuid::Uuid::new_v4()));let path=dir.join("cursor.enc");
        let store=CursorStore::new(path.clone(),[7;32],"profile","relay").unwrap();store.initialize(&Cursor::default()).unwrap();
        let good=std::fs::read(&path).unwrap();let receiver=Messenger::new(NostrTransport::new(SharedRelay(relay),bk,directory).with_cursor(store).unwrap());
        let page=receiver.fetch_open(&b,10).unwrap();let token=page.opened[0].transport_token.clone().unwrap();
        std::fs::write(&path,b"corrupt").unwrap();assert!(receiver.ack_signed(&b,&[token.clone()]).is_err());
        assert_eq!(receiver.fetch_open(&b,10).unwrap().opened[0].transport_token.as_ref(),Some(&token));
        std::fs::write(&path,good).unwrap();assert_eq!(receiver.ack_signed(&b,&[token]).unwrap(),1);
        drop(receiver);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn signed_poison_is_preserved_before_cursor_and_valid_survives_restart() {
        struct Sink(std::path::PathBuf);
        impl DeferredNostrEvent for Sink {fn preserve(&self,e:&Event,_:u64)->Result<()> {
            use std::io::Write;
            let mut f=std::fs::OpenOptions::new().write(true).create(true).truncate(true).open(&self.0).map_err(|e|Error::Store(e.to_string()))?;
            f.write_all(serde_json::to_string(e).unwrap().as_bytes()).and_then(|_|f.sync_all()).map_err(|e|Error::Store(e.to_string()))
        }}
        let relay=Arc::new(MemoryRelay::new());let ak=keys("0000000000000000000000000000000000000000000000000000000000000001");
        let bk=keys("0000000000000000000000000000000000000000000000000000000000000002");
        let a=Identity::from_seed([11;32],"tgrin").unwrap();let b=Identity::from_seed([22;32],"tgrin").unwrap();let now=crate::envelope::unix_now();
        let poison=Event::unsigned(ak.public_hex(),now,KIND_GIFT_WRAP,vec![vec!["p".into(),bk.public_hex()]],"invalid ciphertext".into()).sign(ak.secret()).unwrap();
        relay.publish(&poison).unwrap();let valid=Envelope::seal(&a,b.address(),MessageKind::Text{text:"after poison".into()},900,now).unwrap();
        relay.publish(&super::super::gift_wrap(ak.secret(),&bk.public(),serde_json::to_string(&valid).unwrap(),now).unwrap()).unwrap();
        let dir=std::env::temp_dir().join(format!("gs-poison-restart-{}",uuid::Uuid::new_v4()));std::fs::create_dir_all(&dir).unwrap();
        let path=dir.join("cursor.enc");let raw=dir.join("saved.json");let store=||CursorStore::new(path.clone(),[7;32],"profile","relay").unwrap();store().initialize(&Cursor::default()).unwrap();
        let receiver=NostrTransport::new(SharedRelay(relay.clone()),bk.clone(),MapDirectory::default()).with_deferred(Arc::new(Sink(raw.clone()))).with_cursor(store()).unwrap();
        let page=receiver.fetch_signed_tagged(&b,now,10).unwrap();assert_eq!(page.len(),1);assert!(store().load().unwrap().deferred.is_empty());
        drop(receiver);
        let receiver=NostrTransport::new(SharedRelay(relay),bk,MapDirectory::default()).with_deferred(Arc::new(Sink(raw.clone()))).with_cursor(store()).unwrap();
        let page=receiver.fetch_signed_tagged(&b,now,10).unwrap();assert_eq!(page.len(),1);let token=page[0].1.clone().unwrap();receiver.ack(b.address(),&[token]).unwrap();
        let committed=store().load().unwrap();assert_eq!(committed.deferred.len(),1);assert_eq!(committed.deferred[0].id,poison.id);assert_ne!(committed,Cursor::default());
        drop(receiver);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn full_page_of_expired_events_advances_without_filling_deferred() {
        let relay=Arc::new(MemoryRelay::new());let ak=keys("0000000000000000000000000000000000000000000000000000000000000001");
        let bk=keys("0000000000000000000000000000000000000000000000000000000000000002");
        let a=Identity::from_seed([11;32],"tgrin").unwrap();let b=Identity::from_seed([22;32],"tgrin").unwrap();let now=crate::envelope::unix_now();
        for jitter in [1,2] {let envelope=Envelope::seal(&a,b.address(),MessageKind::Text{text:"expired".into()},900,now-901).unwrap();
            relay.publish(&super::super::wrap::gift_wrap_with_test_jitter(ak.secret(),&bk.public(),serde_json::to_string(&envelope).unwrap(),now,jitter).unwrap()).unwrap();}
        let dir=std::env::temp_dir().join(format!("gs-expired-page-{}",uuid::Uuid::new_v4()));let path=dir.join("cursor.enc");
        let store=||CursorStore::new(path.clone(),[7;32],"profile","route").unwrap();store().initialize(&Cursor::default()).unwrap();
        let transport=NostrTransport::new(SharedRelay(relay),bk,MapDirectory::default()).with_cursor(store()).unwrap();
        assert!(transport.fetch_signed_tagged(&b,now,2).unwrap().is_empty());let state=store().load().unwrap();assert!(state.deferred.is_empty());assert_ne!(state,Cursor::default());
        drop(transport);let _=std::fs::remove_dir_all(dir);
    }
    #[test]
    fn cursor_traverses_relay_pages_with_verified_boundaries() {
        let relay=Arc::new(MemoryRelay::new());let ak=keys("0000000000000000000000000000000000000000000000000000000000000001");
        let bk=keys("0000000000000000000000000000000000000000000000000000000000000002");
        let a=Identity::from_seed([11;32],"tgrin").unwrap();let b=Identity::from_seed([22;32],"tgrin").unwrap();let now=crate::envelope::unix_now();
        for jitter in 1..=5 {let e=Envelope::seal(&a,b.address(),MessageKind::Text{text:format!("{jitter}")},900,now).unwrap();
            relay.publish(&super::super::wrap::gift_wrap_with_test_jitter(ak.secret(),&bk.public(),serde_json::to_string(&e).unwrap(),now,jitter).unwrap()).unwrap();}
        let dir=std::env::temp_dir().join(format!("gs-cursor-pages-{}",uuid::Uuid::new_v4()));let path=dir.join("cursor.enc");
        let store=CursorStore::new(path,[7;32],"profile","relay").unwrap();store.initialize(&Cursor::default()).unwrap();
        let receiver=NostrTransport::new(SharedRelay(relay),bk,MapDirectory::default()).with_cursor(store).unwrap();
        let mut seen=std::collections::HashSet::new();
        for _ in 0..8 {let page=receiver.fetch_signed_tagged(&b,now,2).unwrap();let ids:Vec<_>=page.iter().map(|(_,id)|id.clone().unwrap()).collect();
            for id in &ids {seen.insert(id.clone());}if !ids.is_empty(){receiver.ack(b.address(),&ids).unwrap();}if seen.len()==5 {break;}}
        assert_eq!(seen.len(),5);drop(receiver);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn saturated_second_processes_available_but_never_advances() {
        let relay=Arc::new(MemoryRelay::new());let ak=keys("0000000000000000000000000000000000000000000000000000000000000001");
        let bk=keys("0000000000000000000000000000000000000000000000000000000000000002");
        let a=Identity::from_seed([11;32],"tgrin").unwrap();let b=Identity::from_seed([22;32],"tgrin").unwrap();let now=crate::envelope::unix_now();
        for i in 0..3 {let e=Envelope::seal(&a,b.address(),MessageKind::Text{text:format!("{i}")},900,now).unwrap();
            relay.publish(&super::super::wrap::gift_wrap_with_test_jitter(ak.secret(),&bk.public(),serde_json::to_string(&e).unwrap(),now,1).unwrap()).unwrap();}
        let dir=std::env::temp_dir().join(format!("gs-cursor-saturated-{}",uuid::Uuid::new_v4()));let path=dir.join("cursor.enc");
        let store=||CursorStore::new(path.clone(),[7;32],"profile","relay").unwrap();store().initialize(&Cursor::default()).unwrap();
        let receiver=NostrTransport::new(SharedRelay(relay),bk,MapDirectory::default()).with_cursor(store()).unwrap();
        let page=receiver.fetch_signed_tagged(&b,now,2).unwrap();assert_eq!(page.len(),2);
        let ids:Vec<_>=page.iter().map(|(_,id)|id.clone().unwrap()).collect();receiver.ack(b.address(),&ids).unwrap();
        assert_eq!(store().load().unwrap(),Cursor::default());assert!(receiver.take_warning().unwrap().contains("incomplete"));
        drop(receiver);let _=std::fs::remove_dir_all(dir);
    }

    #[test]
    fn deliver_fetch_ack() {
        let relay = Arc::new(MemoryRelay::new());
        let alice_keys = keys("0000000000000000000000000000000000000000000000000000000000000001");
        let bob_keys = keys("0000000000000000000000000000000000000000000000000000000000000002");

        let alice = Identity::from_seed([11u8; 32], "tgrin").expect("alice");
        let bob = Identity::from_seed([22u8; 32], "tgrin").expect("bob");

        let mut directory = MapDirectory::default();
        directory
            .0
            .insert(bob.address().to_string(), peer(&bob_keys));
        directory
            .0
            .insert(alice.address().to_string(), peer(&alice_keys));

        let alice_transport =
            NostrTransport::new(SharedRelay(relay.clone()), alice_keys, directory.clone());
        let bob_transport = NostrTransport::new(SharedRelay(relay.clone()), bob_keys, directory);

        assert_eq!(alice_transport.public_hex().len(), 64);

        let envelope = Envelope::seal_default(
            &alice,
            bob.address(),
            MessageKind::Text { text: "hi".into() },
        )
        .expect("seal");
        alice_transport.deliver(&envelope).expect("deliver");

        let now = envelope.created_at;
        let fetched = bob_transport.fetch(bob.address(), now, 10).expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].id, envelope.id);

        // Until persisted and acknowledged the caller can retry the message.
        assert_eq!(bob_transport.fetch(bob.address(), now, 10).unwrap().len(), 1);

        // This only clears local bookkeeping; the relay can retain its copy.
        assert_eq!(
            bob_transport
                .ack(bob.address(), std::slice::from_ref(&envelope.id))
                .expect("ack"),
            1
        );
        assert!(relay.stored().iter().any(|event| event.kind == KIND_GIFT_WRAP));
    }

    /// The transport only wraps the Glaux envelope: slatepack armor must come
    /// back byte-for-byte so the inbox automation can recognize it regardless
    /// of whether the envelope arrived over relay, direct onion or Nostr.
    #[test]
    fn opt_in_expiry_uses_envelope_deadline_without_extending_it() {
        let relay = Arc::new(MemoryRelay::new());
        let keys_a = keys("0000000000000000000000000000000000000000000000000000000000000001");
        let keys_b = keys("0000000000000000000000000000000000000000000000000000000000000002");
        let alice = Identity::from_seed([11;32], "tgrin").unwrap();
        let bob = Identity::from_seed([22;32], "tgrin").unwrap();
        let mut directory = MapDirectory::default();
        directory.0.insert(bob.address().to_string(), keys_b.public());
        let sender = NostrTransport::new(SharedRelay(relay.clone()), keys_a, directory).with_expiration_tag(true);
        let envelope = Envelope::seal_now(&alice, bob.address(), MessageKind::Text { text: "deadline".into() }, 900).unwrap();
        sender.deliver(&envelope).unwrap(); sender.deliver(&envelope).unwrap();
        let events=relay.stored(); assert_eq!(events.len(), 2);
        for e in events {
            e.verify().unwrap();
            assert!(e.tags.contains(&vec!["expiration".into(), (envelope.created_at + envelope.ttl).to_string()]));
        }
    }

    #[test]
    fn previous_13h_envelope_remains_fetchable_after_15_minutes() {
        let relay=Arc::new(MemoryRelay::new());
        let ka=keys("0000000000000000000000000000000000000000000000000000000000000001");
        let kb=keys("0000000000000000000000000000000000000000000000000000000000000002");
        let alice=Identity::from_seed([11;32],"tgrin").unwrap();let bob=Identity::from_seed([22;32],"tgrin").unwrap();
        let mut directory=MapDirectory::default();directory.0.insert(bob.address().to_string(),kb.public());
        let sender=NostrTransport::new(SharedRelay(relay.clone()),ka,directory.clone());
        let receiver=NostrTransport::new(SharedRelay(relay),kb,directory).with_ttl(13*3600);
        let legacy=Envelope::seal_now(&alice,bob.address(),MessageKind::Text{text:"legacy".into()},13*3600).unwrap();
        sender.deliver(&legacy).unwrap();
        assert_eq!(query_window(13*3600),61*3600+300);
        assert_eq!(receiver.fetch(bob.address(),legacy.created_at+4*3600,10).unwrap().len(),1);
        assert_eq!(receiver.fetch(bob.address(),legacy.created_at+13*3600-1,10).unwrap().len(),1);
        assert!(receiver.fetch(bob.address(),legacy.created_at+13*3600,10).unwrap().is_empty());
    }

    #[test]
    fn legacy_envelope_with_max_jitter_remains_available_until_expiry() {
        let relay=Arc::new(MemoryRelay::new());
        let ka=keys("0000000000000000000000000000000000000000000000000000000000000001");
        let kb=keys("0000000000000000000000000000000000000000000000000000000000000002");
        let a=Identity::from_seed([11;32],"tgrin").unwrap();let b=Identity::from_seed([22;32],"tgrin").unwrap();
        let now=crate::envelope::unix_now();let created=now-13*3600+1;
        let envelope=Envelope::seal(&a,b.address(),MessageKind::Text{text:"legacy".into()},13*3600,created).unwrap();
        let wrap=super::super::wrap::gift_wrap_with_test_jitter(ka.secret(),&kb.public(),serde_json::to_string(&envelope).unwrap(),created,172_799).unwrap();
        relay.publish(&wrap).unwrap();let receiver=NostrTransport::new(SharedRelay(relay),kb,MapDirectory::default()).with_ttl(13*3600);
        let batch=receiver.fetch_signed_tagged(&b,now,10).unwrap();assert_eq!(batch.len(),1);assert_eq!(batch[0].0.id,envelope.id);
        assert!(receiver.fetch_signed_tagged(&b,now+1,10).unwrap().is_empty());
    }

    #[test]
    fn fetch_rejects_an_envelope_at_its_exact_expiry() {
        let relay = Arc::new(MemoryRelay::new());
        let keys_a = keys("0000000000000000000000000000000000000000000000000000000000000001");
        let keys_b = keys("0000000000000000000000000000000000000000000000000000000000000002");
        let alice = Identity::from_seed([11;32], "tgrin").unwrap();
        let bob = Identity::from_seed([22;32], "tgrin").unwrap();
        let mut directory = MapDirectory::default();
        directory.0.insert(bob.address().to_string(), keys_b.public());
        let sender = NostrTransport::new(SharedRelay(relay.clone()), keys_a, directory.clone());
        let receiver = NostrTransport::new(SharedRelay(relay), keys_b, directory).with_ttl(900);
        let envelope = Envelope::seal_now(&alice, bob.address(), MessageKind::Text { text: "deadline".into() }, 900).unwrap();
        sender.deliver(&envelope).unwrap();
        assert!(receiver.fetch(bob.address(), envelope.created_at + envelope.ttl, 10).unwrap().is_empty());
    }

    #[test]
    fn slatepack_armor_survives_over_nostr() {
        let relay = Arc::new(MemoryRelay::new());
        let alice_keys = keys("0000000000000000000000000000000000000000000000000000000000000001");
        let bob_keys = keys("0000000000000000000000000000000000000000000000000000000000000002");

        let alice = Identity::from_seed([11u8; 32], "tgrin").expect("alice");
        let bob = Identity::from_seed([22u8; 32], "tgrin").expect("bob");

        let mut directory = MapDirectory::default();
        directory
            .0
            .insert(bob.address().to_string(), peer(&bob_keys));
        directory
            .0
            .insert(alice.address().to_string(), peer(&alice_keys));

        let alice_transport =
            NostrTransport::new(SharedRelay(relay.clone()), alice_keys, directory.clone());
        let bob_transport = NostrTransport::new(SharedRelay(relay), bob_keys, directory);

        let armor = "BEGINSLATEPACK. AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ENDSLATEPACK.";
        let envelope = Envelope::seal_default(
            &alice,
            bob.address(),
            MessageKind::Text {
                text: armor.to_string(),
            },
        )
        .expect("seal");
        alice_transport.deliver(&envelope).expect("deliver");

        let fetched = bob_transport
            .fetch(bob.address(), envelope.created_at, 10)
            .expect("fetch");
        assert_eq!(fetched.len(), 1);
        let opened = fetched[0]
            .open(&bob, envelope.created_at)
            .expect("open envelope");
        assert_eq!(
            opened.kind,
            MessageKind::Text {
                text: armor.to_string()
            }
        );
    }

    #[test]
    fn contact_directory_maps_saved_keys() {
        use crate::envelope::Identity;
        let keys =
            NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .expect("keys");
        let identity = Identity::from_seed([22u8; 32], "tgrin").expect("identity");
        let address = identity.address().to_string();
        let mut contact = Contact {
            address: address.clone(),
            name: "bob".into(),
            created_at: 0,
            updated_at: 0,
            nostr: Some(keys.public_hex()),
            nostr_binding: None,
            i2p_binding: None,
            catalog_profile: None,
            identity_verified_fingerprint: None,
        };
        let directory = ContactDirectory::from_contacts(&[contact.clone()]);
        assert_eq!(directory.len(), 1);
        assert!(directory
            .nostr_pubkey(&address.parse().expect("address"))
            .is_some());

        contact.nostr = Some("zz".into());
        assert!(ContactDirectory::from_contacts(&[contact]).is_empty());
    }

    #[test]
    fn unknown_recipient_is_explicit() {
        let relay = Arc::new(MemoryRelay::new());
        let alice_keys =
            NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .expect("keys");
        let alice = Identity::from_seed([11u8; 32], "tgrin").expect("alice");
        let bob = Identity::from_seed([22u8; 32], "tgrin").expect("bob");
        let transport =
            NostrTransport::new(SharedRelay(relay), alice_keys, MapDirectory::default());
        let envelope = Envelope::seal_default(
            &alice,
            bob.address(),
            MessageKind::Text { text: "hi".into() },
        )
        .expect("seal");
        let error = transport.deliver(&envelope).expect_err("must fail");
        assert!(matches!(error, Error::Store(_)));
    }

    #[test]
    fn foreign_wrap_is_skipped() {
        let relay = Arc::new(MemoryRelay::new());
        let alice_keys =
            NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .expect("keys");
        let eve_keys =
            NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000003")
                .expect("keys");
        let alice = Identity::from_seed([11u8; 32], "tgrin").expect("alice");

        // A wrap addressed to Eve, delivered into Alice's subscription window.
        let event = gift_wrap(
            &secp256k1::SecretKey::from_str(
                "0000000000000000000000000000000000000000000000000000000000000002",
            )
            .expect("secret"),
            &eve_keys.public(),
            "{}".into(),
            super::super::unix_now_secs(),
        )
        .expect("wrap");
        relay.publish(&event).expect("publish");

        let transport =
            NostrTransport::new(SharedRelay(relay), alice_keys, MapDirectory::default());
        let fetched = transport
            .fetch(alice.address(), super::super::unix_now_secs(), 10)
            .expect("fetch");
        assert!(fetched.is_empty());
    }

    /// End-to-end drill over a real socket: a minimal in-process relay accepts
    /// the gift wrap, answers OK, then serves it back on REQ and sends EOSE.
    /// Loopback only; no public relay is touched.
    #[test]
    fn transport_roundtrip_over_loopback_relay() {
        use std::net::TcpListener;
        use std::sync::Mutex as StdMutex;
        use tungstenite::accept;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("addr");
        let store: Arc<StdMutex<Vec<Event>>> = Arc::new(StdMutex::new(Vec::new()));
        let server_store = store.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let Ok(mut socket) = accept(stream) else {
                    break;
                };
                loop {
                    let Ok(message) = socket.read() else { break };
                    let text = match message {
                        tungstenite::Message::Text(text) => text.to_string(),
                        tungstenite::Message::Close(_) => break,
                        _ => continue,
                    };
                    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                        continue;
                    };
                    let Some(array) = value.as_array() else {
                        continue;
                    };
                    match array.first().and_then(|v| v.as_str()) {
                        Some("EVENT") => {
                            let Some(raw) = array.get(1).cloned() else {
                                continue;
                            };
                            let Ok(event) = serde_json::from_value::<Event>(raw) else {
                                continue;
                            };
                            server_store.lock().expect("store").push(event.clone());
                            let _ = socket.send(tungstenite::Message::Text(
                                serde_json::json!(["OK", event.id, true, ""])
                                    .to_string()
                                    .into(),
                            ));
                        }
                        Some("REQ") => {
                            let subscription = array
                                .get(1)
                                .and_then(|v| v.as_str())
                                .unwrap_or("s")
                                .to_string();
                            let filter = array.get(2).cloned().unwrap_or_default();
                            let events = server_store.lock().expect("store").clone();
                            for event in events {
                                if !event.kind.to_string().is_empty()
                                    && filter["kinds"]
                                        .as_array()
                                        .map(|kinds| {
                                            kinds
                                                .iter()
                                                .any(|k| k.as_u64() == Some(event.kind as u64))
                                        })
                                        .unwrap_or(true)
                                    && filter["#p"]
                                        .as_array()
                                        .map(|tags| {
                                            tags.iter().any(|tag| {
                                                event
                                                    .p_tags()
                                                    .iter()
                                                    .any(|p| Some(p.as_str()) == tag.as_str())
                                            })
                                        })
                                        .unwrap_or(true)
                                    && filter["since"]
                                        .as_u64()
                                        .map(|since| event.created_at >= since)
                                        .unwrap_or(true)
                                {
                                    let _ = socket.send(tungstenite::Message::Text(
                                        serde_json::json!(["EVENT", subscription, event])
                                            .to_string()
                                            .into(),
                                    ));
                                }
                            }
                            let _ = socket.send(tungstenite::Message::Text(
                                serde_json::json!(["EOSE", subscription]).to_string().into(),
                            ));
                        }
                        _ => {}
                    }
                }
            }
        });

        let alice_keys =
            NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
                .expect("alice");
        let bob_keys =
            NostrKeys::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
                .expect("bob");
        let alice = Identity::from_seed([11u8; 32], "tgrin").expect("alice id");
        let bob = Identity::from_seed([22u8; 32], "tgrin").expect("bob id");
        let mut directory = ContactDirectory::default();
        directory
            .insert_hex(&bob.address().to_string(), &bob_keys.public_hex())
            .expect("bob key");
        directory
            .insert_hex(&alice.address().to_string(), &alice_keys.public_hex())
            .expect("alice key");

        let url = format!("ws://{}", address);
        let alice_transport = NostrTransport::new(
            WsRelay::new(&url, alice_keys.clone()).expect("relay"),
            alice_keys,
            directory.clone(),
        );
        let bob_transport = NostrTransport::new(
            WsRelay::new(&url, bob_keys.clone()).expect("relay"),
            bob_keys,
            directory,
        );

        let envelope = Envelope::seal_default(
            &alice,
            bob.address(),
            MessageKind::Text {
                text: "over loopback".into(),
            },
        )
        .expect("seal");
        alice_transport.deliver(&envelope).expect("deliver");

        // The relay's wrap timestamp is randomized; query from "now" minus the
        // subscription window the transport builds.
        let now = super::super::unix_now_secs();
        let fetched = bob_transport.fetch(bob.address(), now, 10).expect("fetch");
        assert_eq!(fetched.len(), 1, "delivered envelope must come back");
        assert_eq!(fetched[0].id, envelope.id);
        assert_eq!(
            bob_transport
                .ack(bob.address(), std::slice::from_ref(&envelope.id))
                .expect("ack"),
            1
        );
    }
}
