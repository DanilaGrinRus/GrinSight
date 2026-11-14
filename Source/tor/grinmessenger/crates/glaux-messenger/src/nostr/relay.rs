// SPDX-License-Identifier: MIT OR Apache-2.0
//! Relay boundary for the Nostr transport.
//!
//! A real relay speaks WebSocket; the transport only needs publish/query, so the
//! protocol client stays outside this crate's cryptography and can be tested
//! with [`MemoryRelay`].

use std::sync::Mutex;

use super::event::{Event, KIND_DELETE};
use crate::error::{Error, Result};

/// One subscription query (NIP-01 filter subset used by this transport).
#[derive(Clone, Debug, Default)]
pub struct RelayFilter {
    /// Event kinds to match; empty means any kind.
    pub kinds: Vec<u32>,
    /// `p` tag value to match (the recipient's transport key).
    pub recipient: Option<String>,
    /// Exact NIP-01 #t tag, used for opt-in profile lookup.
    pub topic: Option<String>,
    /// Lower bound for `created_at`, inclusive.
    pub since: u64,
    /// Upper timestamp bound, inclusive.
    pub until: Option<u64>,
    /// Upper bound for returned events; `0` means no explicit limit.
    pub limit: usize,
}

/// Publish/query boundary. Implementations decide transport security.
pub trait Relay: Send + Sync {
    fn publish(&self, event: &Event) -> Result<()>;
    fn query(&self, filter: &RelayFilter) -> Result<Vec<Event>>;
}

/// In-memory relay used by unit tests and local drills.
#[derive(Default)]
pub struct MemoryRelay {
    events: Mutex<Vec<Event>>,
}

impl MemoryRelay {
    pub fn new() -> Self {
        Self::default()
    }

    /// Events still stored (deletions are applied at query time).
    pub fn stored(&self) -> Vec<Event> {
        self.events
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }
}

impl Relay for MemoryRelay {
    fn publish(&self, event: &Event) -> Result<()> {
        event.verify()?;
        let mut events = self
            .events
            .lock()
            .map_err(|_| Error::Store("nostr: relay lock poisoned".into()))?;
        if events.iter().any(|stored| stored.id == event.id) {
            return Ok(());
        }
        events.push(event.clone());
        Ok(())
    }

    fn query(&self, filter: &RelayFilter) -> Result<Vec<Event>> {
        let events = self
            .events
            .lock()
            .map_err(|_| Error::Store("nostr: relay lock poisoned".into()))?;
        // NIP-09 deletion is only valid for events by the same author.
        let deleted: Vec<(String, String)> = events
            .iter()
            .filter(|event| event.kind == KIND_DELETE)
            .flat_map(|event| event.e_tags().into_iter().map(move |id| (event.pubkey.clone(), id)))
            .collect();
        let mut matched: Vec<Event> = events
            .iter()
            .filter(|event| event.kind != KIND_DELETE)
            .filter(|event| deleted.iter().all(|(author, id)| author != &event.pubkey || id != &event.id))
            .filter(|event| filter.kinds.is_empty() || filter.kinds.contains(&event.kind))
            .filter(|event| match &filter.recipient {
                Some(recipient) => event.p_tags().iter().any(|tag| tag == recipient),
                None => true,
            })
            .filter(|event| filter.topic.as_ref().is_none_or(|topic| event.tags.iter().any(|t| t.len() >= 2 && t[0] == "t" && t[1] == *topic)))
            .filter(|event| event.created_at >= filter.since)
            .filter(|event| filter.until.is_none_or(|until| event.created_at <= until))
            .cloned()
            .collect();
        matched.sort_by_key(|event| std::cmp::Reverse(event.created_at));
        if filter.limit > 0 {
            matched.truncate(filter.limit);
        }
        Ok(matched)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::{hex_encode, wrap::xonly_hex};
    use secp256k1::{PublicKey, SecretKey};
    use std::str::FromStr;

    fn secret(hex: &str) -> SecretKey {
        SecretKey::from_str(hex).expect("secret")
    }

    #[test]
    fn until_is_inclusive_and_order_is_newest_first() {
        let key=secret("0000000000000000000000000000000000000000000000000000000000000001");
        let relay=MemoryRelay::new();
        for (ts,text) in [(100,"old"),(101,"one"),(101,"two"),(102,"new")] {
            relay.publish(&Event::unsigned(xonly_hex(&key),ts,14,vec![],text.into()).sign(&key).unwrap()).unwrap();
        }
        let filter=RelayFilter{kinds:vec![14],recipient:None,topic:None,since:0,until:Some(101),limit:10};
        let found=relay.query(&filter).unwrap();
        assert_eq!(found.iter().map(|e|e.created_at).collect::<Vec<_>>(),vec![101,101,100]);
    }

    #[test]
    fn legacy_61_hour_window_includes_boundary() {
        let key=secret("0000000000000000000000000000000000000000000000000000000000000001");
        let relay=MemoryRelay::new();let now=300_000u64;let boundary=now-(61*3600+300);
        for ts in [boundary-1,boundary,boundary+1] {
            relay.publish(&Event::unsigned(xonly_hex(&key),ts,14,vec![],ts.to_string()).sign(&key).unwrap()).unwrap();
        }
        let filter=RelayFilter{kinds:vec![14],recipient:None,topic:None,since:boundary,until:None,limit:10};
        assert_eq!(relay.query(&filter).unwrap().iter().map(|e|e.created_at).collect::<Vec<_>>(),vec![boundary+1,boundary]);
    }

    #[test]
    fn publish_query_and_delete() {
        let keys = secret("0000000000000000000000000000000000000000000000000000000000000001");
        let recipient = hex_encode(
            &PublicKey::from_secret_key(&keys)
                .x_only_public_key()
                .0
                .to_byte_array(),
        );
        let relay = MemoryRelay::new();
        let event = Event::unsigned(
            xonly_hex(&keys),
            100,
            14,
            vec![vec!["p".to_string(), recipient.clone()]],
            "hello".into(),
        )
        .sign(&keys)
        .expect("sign");
        relay.publish(&event).expect("publish");
        // Duplicate publish is idempotent.
        relay.publish(&event).expect("publish again");

        let filter = RelayFilter {
            kinds: vec![14],
            recipient: Some(recipient), topic: None,
            since: 0, until: None,
            limit: 10,
        };
        assert_eq!(relay.query(&filter).expect("query").len(), 1);

        let attacker = secret("0000000000000000000000000000000000000000000000000000000000000002");
        let forged = Event::unsigned(xonly_hex(&attacker), 101, KIND_DELETE,
            vec![vec!["e".to_string(), event.id.clone()]], String::new())
            .sign(&attacker).unwrap();
        relay.publish(&forged).unwrap();
        assert_eq!(relay.query(&filter).unwrap().len(), 1);

        let deletion = Event::unsigned(
            xonly_hex(&keys),
            101,
            KIND_DELETE,
            vec![vec!["e".to_string(), event.id.clone()]],
            String::new(),
        )
        .sign(&keys)
        .expect("delete");
        relay.publish(&deletion).expect("publish deletion");
        assert!(relay.query(&filter).expect("query").is_empty());
    }
}
