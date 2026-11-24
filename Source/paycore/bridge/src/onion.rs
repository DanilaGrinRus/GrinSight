//! Payments to and from a Grin address through Tor (specification 7.25,
//! K151-K158).
//!
//! A payment is sent to the onion service of the address it names, in the
//! words every Grin wallet uses between wallets (`receive_tx` of the
//! "foreign API"); the answer comes back in the same connection and is
//! kept for the user to look at and sign, exactly like a reply that came
//! any other way.
//!
//! What arrives at this wallet's own onion service is anybody's text: who
//! sent it is not known and cannot be. It is read with every limit of
//! this file, never trusted, and answered with a signature only by the
//! rules of unattended receive or after the user said yes in the window.
use crate::{fail, hex, Bridge, Fail};
use fly_paycore_onion_pipe::{plain_text, Event, Onion, Phase};
use fly_paycore_store::{Dir, Guard};
use fly_paycore_wallet::{slate_summary, CoreError, SlateStage};
use grin_keychain::Keychain;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// Smallest payment taken through Tor, in nanogrin (0.001 GRIN). An output
/// worth less costs about as much to spend as it holds; whoever sends such
/// amounts fills the wallet with outputs, not with money.
pub const ONION_MIN_AMOUNT: u64 = 1_000_000;
/// Payments from senders the wallet does not answer by itself that may
/// wait for the user's word at once. More are refused.
pub const ONION_MAX_ASKS: usize = 3;
/// How long such a payment waits for the user. The sender's wallet waits
/// for the answer in an open connection and gives up on its own; after
/// this long the answer would reach nobody.
pub const ONION_HOLD: Duration = Duration::from_secs(40);
/// How long the outcome of a post is waited for before it is taken to be
/// unknown.
pub const ONION_POST_WITHIN: Duration = Duration::from_secs(180);
/// Events of the Tor process handled by one `paycore.onion.pump`.
const MAX_EVENTS: usize = 16;
/// Largest request body read, checked before parsing.
const MAX_REQUEST: usize = 96 * 1024;
/// Failed sends remembered for showing, in memory only.
const MAX_FAILED: usize = 64;

/// Starts the Tor process for the address key it is given: the secret
/// half, which is the only secret that leaves the payment core for it,
/// and the address itself.
pub type OnionFactory = Box<dyn FnMut(&zeroize::Zeroizing<[u8; 32]>, &[u8; 32]) -> Result<Box<dyn Onion>, String>>;

enum Sending {
    /// Posted, no outcome yet.
    Posted(Instant),
    /// It did not get through; the words say why. The payment itself is
    /// as it was: prepared, the money reserved.
    Failed(String),
}

/// A payment that waits for the user's word.
struct Ask {
    id: u64,
    rpc_id: Value,
    slate: Vec<u8>,
    slate_id: [u8; 16],
    amount: u64,
    sender: Option<[u8; 32]>,
    since: Instant,
}

/// The bridge's side of the Onion port.
pub(crate) struct Side {
    port: Option<Box<dyn Onion>>,
    factory: Option<OnionFactory>,
    error: Option<String>,
    sends: BTreeMap<[u8; 16], Sending>,
    asks: Vec<Ask>,
    min_amount: u64,
    hold: Duration,
    post_within: Duration,
}

impl Default for Side {
    fn default() -> Self {
        Side {
            port: None,
            factory: None,
            error: None,
            sends: BTreeMap::new(),
            asks: Vec::new(),
            min_amount: ONION_MIN_AMOUNT,
            hold: ONION_HOLD,
            post_within: ONION_POST_WITHIN,
        }
    }
}

fn no_onion() -> Fail {
    fail(-32032, "no_onion", "")
}

/// The id of a request as it may be given back: a number, a short plain
/// word or nothing. It is the one thing of a request an answer repeats.
fn rpc_id(request: &Value) -> Value {
    match request.get("id") {
        Some(Value::Number(n)) => Value::Number(n.clone()),
        Some(Value::String(s)) if s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') => {
            Value::String(s.clone())
        }
        _ => Value::Null,
    }
}

fn rpc_ok(id: &Value, result: Value) -> String {
    json!({"id": id, "jsonrpc": "2.0", "result": {"Ok": result}}).to_string()
}

/// A refusal. The words are fixed ones of this file: nothing of the
/// wallet's state and nothing the request said goes back.
fn rpc_err(id: &Value, words: &str) -> String {
    json!({"id": id, "jsonrpc": "2.0", "error": {"code": -32000, "message": words}}).to_string()
}

/// What a wallet answered to a post: the slate it gave, or why not. What
/// the other side says is quoted as plain characters, and little of it.
fn posted_slate(body: &str) -> Result<Vec<u8>, String> {
    let not_wallet = || "the answer is not a wallet's answer".to_string();
    let quoted = |said: &Value| {
        let said = match said {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        };
        format!("the wallet at this address refused: {}", plain_text(&said, 120))
    };
    let answer: Value = serde_json::from_str(body).map_err(|_| not_wallet())?;
    if let Some(error) = answer.get("error").filter(|e| !e.is_null()) {
        return Err(quoted(error.get("message").unwrap_or(&Value::Null)));
    }
    let result = answer.get("result").ok_or_else(not_wallet)?;
    if let Some(error) = result.get("Err").filter(|e| !e.is_null()) {
        return Err(quoted(error));
    }
    match result.get("Ok") {
        Some(slate @ Value::Object(_)) => serde_json::to_vec(slate).map_err(|_| not_wallet()),
        _ => Err(not_wallet()),
    }
}

impl<D: Dir, G: Guard, K: Keychain> Bridge<D, G, K> {
    /// Use this Onion port. For hosts that start the Tor process
    /// themselves and for tests.
    pub fn set_onion(&mut self, port: Box<dyn Onion>) {
        self.onion.port = Some(port);
        self.onion.error = None;
    }

    /// Let the bridge start the Tor process itself, now, with the key of
    /// the wallet's address.
    pub fn set_onion_factory(&mut self, factory: OnionFactory) {
        self.onion.factory = Some(factory);
        self.onion.port = None;
        self.onion.error = None;
        let Some(factory) = self.onion.factory.as_mut() else {
            return;
        };
        match (self.core.address_secret_for_onion(), self.core.receive_address()) {
            (Ok(secret), Ok(public)) => match factory(&secret, &public) {
                Ok(port) => self.onion.port = Some(port),
                Err(why) => self.onion.error = Some(why.chars().take(200).collect()),
            },
            _ => self.onion.error = Some("the address key could not be made".to_string()),
        }
    }

    /// Change the smallest payment taken through Tor ([`ONION_MIN_AMOUNT`]).
    pub fn set_onion_min_amount(&mut self, nanogrin: u64) {
        self.onion.min_amount = nanogrin;
    }

    /// Change how long a payment waits for the user ([`ONION_HOLD`]) and
    /// the outcome of a post is waited for ([`ONION_POST_WITHIN`]). Tests
    /// use zero.
    pub fn set_onion_waits(&mut self, hold: Duration, post_within: Duration) {
        self.onion.hold = hold;
        self.onion.post_within = post_within;
    }

    fn is_contact_address(&self, address: &[u8; 32]) -> bool {
        self.core.contacts().iter().any(|c| c.address.as_ref() == Some(address))
    }

    pub(crate) fn onion_status(&mut self) -> Value {
        let state = self.onion.port.as_mut().map(|port| port.state()).unwrap_or_default();
        let phase = match (self.onion.port.is_some(), state.phase) {
            (false, _) | (true, Phase::None) => "none",
            (true, Phase::Starting) => "starting",
            (true, Phase::Up) => "up",
            (true, Phase::Listening) => "listening",
            (true, Phase::Failed) => "failed",
        };
        let problem = match &self.onion.error {
            Some(error) => error.clone(),
            None => state.problem,
        };
        let sends: Vec<Value> = self
            .onion
            .sends
            .iter()
            .map(|(op, sending)| match sending {
                Sending::Posted(_) => json!({ "op": hex(op), "state": "posted" }),
                Sending::Failed(why) => json!({ "op": hex(op), "state": "failed", "reason": why }),
            })
            .collect();
        let slatepack = self.slatepack;
        let hold = self.onion.hold;
        let mut asks = Vec::new();
        for ask in &self.onion.asks {
            let text = crate::encode_text(slatepack, self.ports.codec.as_mut(), &ask.slate).unwrap_or_default();
            asks.push(json!({
                "id": ask.id,
                "slate": text,
                "slate_id": hex(&ask.slate_id),
                "amount": ask.amount.to_string(),
                // what the payment says about its sender; nobody vouches for it
                "claimed_sender": ask.sender.map(|a| hex(&a)),
                "known_sender": ask.sender.is_some_and(|a| self.is_contact_address(&a)),
                "left_secs": hold.saturating_sub(ask.since.elapsed()).as_secs(),
            }));
        }
        json!({
            "phase": phase,
            "problem": problem,
            "min_amount": self.onion.min_amount.to_string(),
            "sends": sends,
            "asks": asks,
        })
    }

    /// Send a prepared payment to the onion service of the address it
    /// names (K151). Signs nothing and writes nothing: the payment stays
    /// prepared whatever becomes of the post.
    pub(crate) fn onion_send(&mut self, op: &[u8; 16]) -> Result<Value, Fail> {
        if self.onion.port.is_none() {
            return Err(no_onion());
        }
        let review = self.core.prepared_slate(op)?;
        let Some(to) = review.receiver else {
            return Err(CoreError::Refused("the payment names no address").into());
        };
        if self.core.delivery_contact(op).is_some() {
            return Err(CoreError::Refused("the payment goes to a contact").into());
        }
        if self.core.send_held(op).is_some() {
            return Err(CoreError::Refused("a reply is already here").into());
        }
        if matches!(self.onion.sends.get(op), Some(Sending::Posted(_))) {
            // the same request again: nothing is posted twice
            return Ok(json!({ "op": hex(op), "state": "posted" }));
        }
        let s1 = self.core.prepared_s1(op)?;
        let slate: Value = serde_json::from_slice(&s1).map_err(|_| CoreError::Build)?;
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "receive_tx", "params": [slate, null, null]}).to_string();
        let taken = self.onion.port.as_mut().is_some_and(|port| port.post(op, &to, &body));
        if !taken {
            return Err(CoreError::Refused("Tor is not ready yet").into());
        }
        if self.onion.sends.len() >= MAX_FAILED {
            self.onion.sends.retain(|_, sending| matches!(sending, Sending::Posted(_)));
        }
        self.onion.sends.insert(*op, Sending::Posted(Instant::now()));
        Ok(json!({ "op": hex(op), "state": "posted" }))
    }

    /// One round: take what the Tor process has and let what waited too
    /// long go.
    pub(crate) fn onion_pump(&mut self) -> Result<Value, Fail> {
        if self.onion.port.is_none() {
            return Err(no_onion());
        }
        let mut events = Vec::new();
        for _ in 0..MAX_EVENTS {
            let Some(event) = self.onion.port.as_mut().and_then(|port| port.next()) else {
                break;
            };
            match event {
                Event::Posted { ticket, result } => {
                    if let Some(note) = self.onion_posted(&ticket, result)? {
                        events.push(note);
                    }
                }
                Event::Request { id, body } => {
                    let (answer, note) = self.onion_request(id, &body);
                    if let (Some(answer), Some(port)) = (answer, self.onion.port.as_mut()) {
                        port.answer(id, &answer);
                    }
                    events.push(note);
                }
            }
        }
        // a payment nobody answered in time: the sender has stopped waiting
        let hold = self.onion.hold;
        let (late, waiting): (Vec<Ask>, Vec<Ask>) =
            std::mem::take(&mut self.onion.asks).into_iter().partition(|ask| ask.since.elapsed() >= hold);
        self.onion.asks = waiting;
        for ask in late {
            if let Some(port) = self.onion.port.as_mut() {
                port.answer(ask.id, &rpc_err(&ask.rpc_id, "the owner of the wallet did not answer in time"));
            }
            events.push(json!({ "kind": "ask_expired", "id": ask.id, "slate_id": hex(&ask.slate_id) }));
        }
        // a post whose outcome never came
        let within = self.onion.post_within;
        for (op, sending) in self.onion.sends.iter_mut() {
            if matches!(sending, Sending::Posted(at) if at.elapsed() >= within) {
                *sending = Sending::Failed("Tor gave no outcome; whether the wallet at this address got the payment is not known".to_string());
                events.push(json!({ "kind": "tor_failed", "op": hex(op) }));
            }
        }
        Ok(json!({ "onion": events }))
    }

    /// The outcome of a post: the reply is held for the user (K152), or
    /// the words of the failure are kept for showing.
    fn onion_posted(&mut self, op: &[u8; 16], result: Result<String, String>) -> Result<Option<Value>, Fail> {
        if !matches!(self.onion.sends.get(op), Some(Sending::Posted(_))) {
            // an outcome nobody waits for
            return Ok(None);
        }
        let held = match result.and_then(|body| posted_slate(&body)) {
            Err(why) => Err(why),
            Ok(s2) => match fly_paycore_wallet::slate_stage(&s2) {
                Ok(SlateStage::S2) => match self.core.send_hold_reply(op, &s2) {
                    Ok(()) => Ok(()),
                    Err(CoreError::BadSlate(_)) => Err("the reply does not match the payment".to_string()),
                    Err(CoreError::Refused(r)) => Err(r.to_string()),
                    Err(CoreError::Conflict) => Err("another reply was already chosen".to_string()),
                    Err(CoreError::NotFound) => Err("the payment is no longer there".to_string()),
                    Err(e) => return Err(e.into()),
                },
                _ => Err("the answer is not a reply to a payment".to_string()),
            },
        };
        match held {
            Err(why) => {
                self.onion.sends.insert(*op, Sending::Failed(why));
                Ok(Some(json!({ "kind": "tor_failed", "op": hex(op) })))
            }
            Ok(()) => {
                self.onion.sends.remove(op);
                if self.auto_sign {
                    if let Some(sel) = self.ports.chain.selected_tip() {
                        match self.core.send_finalize_held_at(op, sel) {
                            Ok(_) => return Ok(Some(json!({ "kind": "reply_signed", "op": hex(op) }))),
                            Err(CoreError::Refused(_)) => {}
                            Err(CoreError::UnknownOutcome) => return Ok(Some(json!({ "kind": "unknown_outcome", "op": hex(op) }))),
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                Ok(Some(json!({ "kind": "reply_held", "op": hex(op) })))
            }
        }
    }

    /// Decide what a request that arrived at the onion service is. Returns
    /// the answer to give now, if any, and a note for the interface.
    /// Nothing here is an error of the wallet: a request is answered,
    /// refused or kept.
    fn onion_request(&mut self, id: u64, body: &str) -> (Option<String>, Value) {
        let refuse = |rpc: &Value, words: &'static str| {
            (Some(rpc_err(rpc, words)), json!({ "kind": "dropped", "reason": words }))
        };
        if body.len() > MAX_REQUEST {
            return refuse(&Value::Null, "the request is too large");
        }
        let Ok(request) = serde_json::from_str::<Value>(body) else {
            return refuse(&Value::Null, "the request is not one");
        };
        let rpc = rpc_id(&request);
        match request.get("method").and_then(Value::as_str) {
            Some("check_version") => {
                let answer = rpc_ok(&rpc, json!({"foreign_api_version": 2, "supported_slate_versions": ["V4"]}));
                return (Some(answer), json!({ "kind": "asked_version" }));
            }
            Some("receive_tx") => {}
            _ => return refuse(&rpc, "this wallet takes payments only"),
        }
        let Some(slate @ Value::Object(_)) = request.get("params").and_then(|p| p.get(0)) else {
            return refuse(&rpc, "the request holds no payment");
        };
        let Ok(slate) = serde_json::to_vec(slate) else {
            return refuse(&rpc, "the request holds no payment");
        };
        let Ok(summary) = slate_summary(&slate) else {
            return refuse(&rpc, "not a payment this wallet can read");
        };
        if summary.stage != SlateStage::S1 {
            // an invoice asks this wallet to pay: never through here
            return refuse(&rpc, "this wallet takes payments only");
        }
        // K155: dust is refused before anything else is done with it
        if summary.amount < self.onion.min_amount {
            return refuse(&rpc, "the amount is too small for this wallet");
        }
        if self.onion.asks.iter().any(|ask| ask.slate_id == summary.id) {
            return refuse(&rpc, "this payment already waits for the owner of the wallet");
        }
        // K153: answered at once only where unattended receive is on and
        // the payment names a sender the user has added
        let known = summary.sender.is_some_and(|a| self.is_contact_address(&a));
        if known && self.core.auto_receive_since().is_some() {
            match self.core.receive_stateless(&slate, self.onion.min_amount) {
                Ok(s2) => match serde_json::from_slice::<Value>(&s2) {
                    Ok(reply) => {
                        return (
                            Some(rpc_ok(&rpc, reply)),
                            json!({ "kind": "payment_answered", "slate_id": hex(&summary.id) }),
                        )
                    }
                    Err(_) => return refuse(&rpc, "the wallet could not answer"),
                },
                Err(CoreError::BadSlate(_)) => return refuse(&rpc, "not a payment this wallet can take"),
                // unattended receive says no (the chain is behind, ...):
                // the user is asked instead
                Err(_) => {}
            }
        }
        // K154: everybody else waits for the user, three at most
        if self.onion.asks.len() >= ONION_MAX_ASKS {
            return refuse(&rpc, "the wallet is busy, try again later");
        }
        self.onion.asks.push(Ask {
            id,
            rpc_id: rpc,
            slate,
            slate_id: summary.id,
            amount: summary.amount,
            sender: summary.sender,
            since: Instant::now(),
        });
        (None, json!({ "kind": "needs_approval", "via": "tor", "id": id, "slate_id": hex(&summary.id) }))
    }

    /// The user said yes to a payment that waits (K154): sign the reply
    /// and give it to the sender, who is still connected.
    pub(crate) fn onion_accept(&mut self, id: u64) -> Result<Value, Fail> {
        let Some(at) = self.onion.asks.iter().position(|ask| ask.id == id) else {
            return Err(CoreError::Refused("the sender no longer waits").into());
        };
        let ask = self.onion.asks.remove(at);
        if ask.since.elapsed() >= self.onion.hold {
            if let Some(port) = self.onion.port.as_mut() {
                port.answer(ask.id, &rpc_err(&ask.rpc_id, "the owner of the wallet did not answer in time"));
            }
            return Err(CoreError::Refused("the sender no longer waits").into());
        }
        let now = self.ports.clock.confirmed_time();
        let s2 = match self.core.receive_draft(&ask.slate, now) {
            Ok(s2) => s2,
            Err(e) => {
                if let Some(port) = self.onion.port.as_mut() {
                    port.answer(ask.id, &rpc_err(&ask.rpc_id, "the wallet could not take this payment"));
                }
                return Err(e.into());
            }
        };
        let reply: Value = serde_json::from_slice(&s2).map_err(|_| CoreError::Build)?;
        if let Some(port) = self.onion.port.as_mut() {
            port.answer(ask.id, &rpc_ok(&ask.rpc_id, reply));
        }
        Ok(json!({ "slate": self.slate_out(&s2)?, "slate_id": hex(&ask.slate_id) }))
    }

    /// The user said no.
    pub(crate) fn onion_decline(&mut self, id: u64) {
        if let Some(at) = self.onion.asks.iter().position(|ask| ask.id == id) {
            let ask = self.onion.asks.remove(at);
            if let Some(port) = self.onion.port.as_mut() {
                port.answer(ask.id, &rpc_err(&ask.rpc_id, "the owner of the wallet declined the payment"));
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn what_a_wallet_answered_is_a_slate_or_plain_words() {
        assert_eq!(posted_slate(r#"{"id":1,"jsonrpc":"2.0","result":{"Ok":{"a":1}}}"#), Ok(br#"{"a":1}"#.to_vec()));
        let not = Err("the answer is not a wallet's answer".to_string());
        for body in ["", "[]", "{}", r#"{"result":{}}"#, r#"{"result":{"Ok":"text"}}"#, r#"{"result":{"Ok":null}}"#, "<html>"] {
            assert_eq!(posted_slate(body), not, "{body}");
        }
        assert_eq!(
            posted_slate(r#"{"error":{"code":-32000,"message":"busy"}}"#),
            Err("the wallet at this address refused: busy".to_string())
        );
        assert_eq!(
            posted_slate(r#"{"result":{"Err":{"GenericError":"no"}}}"#),
            Err(r#"the wallet at this address refused: {"GenericError":"no"}"#.to_string())
        );
        // what the other side says is anybody's text: plain and short
        let long = format!(r#"{{"error":{{"message":"{}\u001b[31m\n"}}}}"#, "x".repeat(500));
        let words = posted_slate(&long).unwrap_err();
        assert_eq!(words.len(), "the wallet at this address refused: ".len().saturating_add(120));
        assert!(words.chars().all(|c| c.is_ascii_graphic() || c == ' '));
        // an error wins over a result given with it
        assert!(posted_slate(r#"{"error":{"message":"no"},"result":{"Ok":{"a":1}}}"#).is_err());
    }

    #[test]
    fn the_id_of_a_request_is_given_back_only_if_it_is_small() {
        assert_eq!(rpc_id(&json!({"id": 7})), json!(7));
        assert_eq!(rpc_id(&json!({"id": "abc"})), json!("abc"));
        assert_eq!(rpc_id(&json!({"id": "x".repeat(65)})), Value::Null);
        assert_eq!(rpc_id(&json!({"id": "two words"})), Value::Null);
        assert_eq!(rpc_id(&json!({"id": "<b>"})), Value::Null);
        assert_eq!(rpc_id(&json!({"id": {"a": [1, 2, 3]}})), Value::Null);
        assert_eq!(rpc_id(&json!({})), Value::Null);
    }
}
