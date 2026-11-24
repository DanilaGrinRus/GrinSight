//! Wallet state and the single function that changes it.
use crate::{Balance, CoreError, OpId, SlateId, R_UNDO};
use fly_paycore_keys::ledger::BranchState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

pub(crate) fn arr33(b: &[u8]) -> Result<[u8; 33], CoreError> {
    b.try_into().map_err(|_| CoreError::Corrupt)
}

fn arr16(b: &[u8]) -> Result<[u8; 16], CoreError> {
    b.try_into().map_err(|_| CoreError::Corrupt)
}

/// An output of this wallet seen in a verified block.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OutputRec {
    pub commit: Vec<u8>,
    pub key_id: Vec<u8>,
    pub value: u64,
    pub coinbase: bool,
    pub height: u64,
    pub pos: u64,
    /// Bound to a local record by joint inclusion with its kernel (`Create`).
    pub bound: bool,
    /// Height of the block that spent it.
    pub spent: Option<u64>,
    /// Found by the search for old outputs, not in a block: `height` is
    /// then a height by which it existed, not the one it was created at.
    #[serde(default)]
    pub old: bool,
}

/// The search for the wallet's outputs that are older than its blocks
/// (specification 7.19). The chain layer hands over what is unspent piece
/// by piece; the wallet keeps what its seed opens and, once every piece has
/// been read, knows which of the outputs it had are gone.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OldSearch {
    /// The piece to read next; `None` once all have been read.
    pub next: Option<u64>,
    /// How many pieces there were when the last one was read.
    pub pieces: u64,
    /// The lowest and the highest height up to which a piece read so far
    /// was complete.
    pub floor: Option<u64>,
    pub ceiling: u64,
    /// Own outputs the pieces have shown to be unspent.
    pub seen: BTreeSet<String>,
    /// The heights the wallet stood at while it read, each with the first
    /// piece read there. What was read above a block that is taken back
    /// is read again.
    pub runs: Vec<(u64, u64)>,
    /// Reading again after the search was over: outputs are added, none is
    /// given up.
    pub again: bool,
    /// How many outputs the search added, and how many it found gone.
    pub found: u64,
    pub gone: u64,
    /// The block up to which the wallet knew every output of its own when
    /// this search began: the block it stood at before the gap. Up to
    /// there the search has nothing to find, only to learn what is still
    /// unspent. `None`: the search is for everything.
    pub since: Option<(u64, Vec<u8>)>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FoundOut {
    pub commit: Vec<u8>,
    pub key_id: Vec<u8>,
    pub value: u64,
    pub coinbase: bool,
    pub pos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinalRec {
    pub tx: Vec<u8>,
    pub excess: Vec<u8>,
    pub s3: Vec<u8>,
    #[serde(default)]
    pub proof: Option<crate::slates::PaymentProof>,
}

/// A send operation. `ctx` holds the signing context (secret).
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SendRec {
    pub op: OpId,
    pub slate_id: SlateId,
    pub s1: Vec<u8>,
    pub ctx: Vec<u8>,
    pub inputs: Vec<Vec<u8>>,
    /// Change output: key id, value, commitment.
    pub change: Option<(Vec<u8>, u64, Vec<u8>)>,
    pub amount: u64,
    pub fee: u64,
    pub r_height: u64,
    #[serde(default)]
    pub binding_interrupted: bool,
    pub replaces: Option<OpId>,
    pub branch: u32,
    pub index: u32,
    pub locked: bool,
    pub cancelled: bool,
    pub armed: Option<Vec<u8>>,
    pub fin: Option<FinalRec>,
    pub kernel_height: Option<u64>,
    pub conflict_height: Option<u64>,
    pub dead: bool,
    /// Broadcast attempts: (accepted, rejected, unknown outcome).
    #[serde(default)]
    pub broadcasts: (u32, u32, u32),
    /// This operation pays an invoice (signed when created).
    #[serde(default)]
    pub invoice: bool,
    /// Late lock: inputs, change and the change path are chosen and made
    /// durable in the arming frame, not when S1 is built.
    #[serde(default)]
    pub late: bool,
    /// Automatic delivery of S1: the sealed envelope and what became of it.
    #[serde(default)]
    pub delivery: Option<DeliveryRec>,
    /// Tip of the verified chain when the reply was chosen for signing.
    #[serde(default)]
    pub armed_sel: Option<(u64, Vec<u8>)>,
    /// A verified reply that waits for the decision to sign. Holding it
    /// gives no right to sign and reserves nothing.
    #[serde(default)]
    pub held: Option<Vec<u8>>,
    /// `kernel_height` was not read from a block: the search for old
    /// outputs found this operation's change output on the chain, and the
    /// height is one by which the operation was in it.
    #[serde(default)]
    pub by_search: bool,
    /// Cancelled while locked after a detected rollback: the reserve was
    /// released at the user's word, but the journal that was lost may have
    /// held a signature of this payment. It is not called cancelled.
    #[serde(default)]
    pub released: bool,
}

/// The envelope that carries S1 to the recipient and its delivery history.
/// Nothing here is secret: the envelope is already encrypted for the contact.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeliveryRec {
    /// Who the envelope is for (transport identity, 32 bytes).
    pub contact: Vec<u8>,
    /// Identifier of the envelope; every retry carries the same one.
    pub event_id: Vec<u8>,
    /// The sealed envelope, sent again byte for byte on retry.
    pub envelope: Vec<u8>,
    /// Unix seconds after which the envelope is no longer published.
    pub expires_at: u64,
    /// Publications without a definite answer.
    pub unknown: u32,
    /// Publications a relay acknowledged.
    pub accepted: u32,
    /// The transport reported the delivery window closed.
    pub expired: bool,
    /// Last note: 0 none, 1 unknown, 2 accepted, 3 expired, 4 busy, 5 full.
    pub last: u8,
}

/// A receive draft (Level 5, 5.1).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct DraftRec {
    pub slate_id: SlateId,
    pub s1_fp: Vec<u8>,
    pub s2: Vec<u8>,
    pub key_id: Vec<u8>,
    pub commit: Vec<u8>,
    pub value: u64,
    pub excess: Vec<u8>,
    pub r_height: u64,
    #[serde(default)]
    pub binding_interrupted: bool,
    pub created: Option<u64>,
    pub branch: u32,
    pub index: u32,
    pub abandoned: bool,
    pub kernel_height: Option<u64>,
    pub bound: bool,
    /// Spend of the bound output instance, retained if a new instance
    /// takes its commitment's place in the live index.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bound_spent: Option<u64>,
    /// For an invoice we issued: the I1 handed out.
    #[serde(default)]
    pub invoice: Option<Vec<u8>>,
    /// Its signing context (secret).
    #[serde(default)]
    pub ctx: Vec<u8>,
    /// The I2 chosen for signing.
    #[serde(default)]
    pub armed: Option<Vec<u8>>,
    /// The result.
    #[serde(default)]
    pub fin: Option<FinalRec>,
}

/// Everything that can happen to a wallet. Each event is one journal frame.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum Event {
    Init {
        account: u32,
        branch: u32,
    },
    Recovery {
        branch: u32,
    },
    Prepared(Box<SendRec>),
    Cancelled {
        op: OpId,
    },
    Armed {
        op: OpId,
        s2: Vec<u8>,
        #[serde(default)]
        sel: Option<(u64, Vec<u8>)>,
    },
    /// A note about the delivery of S1. Never touches reserves or signing.
    Delivery {
        op: OpId,
        what: u8,
    },
    /// A verified reply is kept until the decision to sign.
    ReplyHeld {
        op: OpId,
        s2: Vec<u8>,
    },
    /// The transport identity is created, imported or replaced.
    IdentitySet {
        secret: Secret,
        public: Vec<u8>,
        imported: bool,
    },
    /// A contact is added or changed.
    ContactSet {
        key: Vec<u8>,
        name: String,
        address: Option<Vec<u8>>,
    },
    /// A contact is removed.
    ContactRemoved {
        key: Vec<u8>,
    },
    /// A text message to a contact, sealed, with its envelope (K121).
    MessageOut {
        id: Vec<u8>,
        to: Vec<u8>,
        at: u64,
        text: String,
        envelope: Vec<u8>,
        expires_at: u64,
    },
    /// A text message from a contact, stored before the transport forgets
    /// it (K120).
    MessageIn {
        id: Vec<u8>,
        from: Vec<u8>,
        at: u64,
        text: String,
    },
    /// What became of an outgoing message: 1 a relay accepted it, 2 its
    /// delivery window closed. Either way its envelope is dropped (K121).
    MessageNote {
        id: Vec<u8>,
        what: u8,
    },
    /// Arming of a late-locked send: the reserve and the change path become
    /// durable in the same frame as the choice of S2.
    ArmedLate {
        op: OpId,
        s2: Vec<u8>,
        inputs: Vec<Vec<u8>>,
        change: Option<(Vec<u8>, u64, Vec<u8>)>,
        branch: u32,
        index: u32,
        #[serde(default)]
        sel: Option<(u64, Vec<u8>)>,
    },
    Final {
        op: OpId,
        tx: Vec<u8>,
        excess: Vec<u8>,
        s3: Vec<u8>,
        proof: Option<crate::slates::PaymentProof>,
    },
    Draft(Box<DraftRec>),
    Broadcast {
        op: OpId,
        outcome: u8,
    },
    InvoicePaid(Box<SendRec>),
    InvoiceArmed {
        slate_id: SlateId,
        i2: Vec<u8>,
    },
    InvoiceFinal {
        slate_id: SlateId,
        tx: Vec<u8>,
        excess: Vec<u8>,
        s3: Vec<u8>,
    },
    DraftAbandon {
        slate_id: SlateId,
    },
    Advance {
        height: u64,
        hash: Vec<u8>,
        found: Vec<FoundOut>,
        spent: Vec<Vec<u8>>,
        kernels: Vec<Vec<u8>>,
        v_delta: Vec<u8>,
    },
    Rollback {
        height: u64,
    },
    Reanchor {
        height: u64,
        hash: Vec<u8>,
        /// The block up to which the wallet knew every output of its own,
        /// as it found when the gap opened; the search that follows does
        /// not look for unknown outputs below it.
        since: Option<(u64, Vec<u8>)>,
        /// Absent in older journals, before the chain layer attested ancestry.
        #[serde(default)]
        extends: Option<bool>,
    },
    ResetLegacyChainEvidence,
    /// Start the search for old outputs, from the first piece.
    OldSearch {},
    /// One piece of the old outputs, read while the wallet stood at the
    /// block `at_height`, `at_hash`.
    Old {
        piece: u64,
        last: bool,
        pieces: u64,
        before: u64,
        at_height: u64,
        at_hash: Vec<u8>,
        found: Vec<FoundOut>,
    },
    AutoReceive {
        on: bool,
    },
}

impl Event {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, CoreError> {
        serde_json::to_vec(self).map_err(|_| CoreError::Corrupt)
    }
    pub(crate) fn decode(b: &[u8]) -> Result<Event, CoreError> {
        serde_json::from_slice(b).map_err(|_| CoreError::Corrupt)
    }
}

/// What one block changed, kept for `R_UNDO` blocks.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Undo {
    height: u64,
    prev_tip: Option<(u64, Vec<u8>)>,
    created: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    replaced_outputs: Vec<OutputRec>,
    spent: Vec<String>,
    send_kernels: Vec<String>,
    draft_kernels: Vec<String>,
    draft_bound: Vec<String>,
    conflicts: Vec<String>,
    died: Vec<String>,
}

/// State of a send operation as shown to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendStatus {
    /// S1 handed out, inputs reserved, nothing signed.
    Prepared,
    /// Cancelled before signing; inputs released.
    Cancelled,
    /// Locked by a detected rollback and then given up by the user: inputs
    /// released, but a signature may exist in the journal that was lost, so
    /// the payment may still reach the chain.
    Released,
    /// An S2 was chosen but no result is recorded. Whether a signature exists
    /// is unknown; inputs stay reserved.
    Unknown,
    /// Signed; the transaction may be broadcast.
    Finalized,
    /// The kernel is in the chain.
    Confirmed,
    /// One of the inputs was spent by another transaction less than `R_UNDO`
    /// blocks ago; a reorg could still revive this payment.
    Contested,
    /// The conflicting spend is `R_UNDO` deep; inputs are released.
    Dead,
}

/// The "state" axis of Level 5, supplied by the chain layer when asking for
/// a status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainState {
    /// No verified state for the current chain.
    Unknown,
    /// Verified up to a height below the tip.
    Behind,
    /// Verified at the tip.
    AtTip,
}

/// Rows of the Level 5 status table (section 7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    /// State unknown: preliminary.
    S1,
    /// State behind the tip: preliminary.
    S2,
    /// No local deal record: preliminary.
    S3,
    /// Kernel inclusion not proven: not confirmed.
    S4,
    /// Too few confirmations: preliminary.
    S6,
    /// Kernel proven, output bound but neither alive nor spent: not confirmed.
    S7,
    /// Kernel proven, output not bound to the record: preliminary.
    S7a,
    /// Confirmed.
    S8,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    #[serde(with = "branch_serde")]
    pub branch: BranchState,
    pub account: u32,
    pub outputs: BTreeMap<String, OutputRec>,
    pub sends: BTreeMap<String, SendRec>,
    pub drafts: BTreeMap<String, DraftRec>,
    pub tip: Option<(u64, Vec<u8>)>,
    /// Height from which the verified state advanced without a gap.
    pub continuous_since: u64,
    undo: Vec<Undo>,
    /// Old snapshots did not record whether a gap preserved the wallet's chain.
    #[serde(default = "legacy_snapshot")]
    pub legacy_chain_evidence: bool,
    pub auto_receive: Option<u64>,
    /// Opaque snapshot of the verified state V taken at the last checkpoint,
    /// with the height it describes.
    pub v_base: Option<(u64, Vec<u8>)>,
    /// Opaque per-block changes of V since `v_base`, with their heights.
    pub v_deltas: Vec<(u64, Vec<u8>)>,
    /// The transport identity under which contacts see this wallet.
    #[serde(default)]
    pub identity: Option<IdentityRec>,
    /// Contacts by transport key (hex).
    #[serde(default)]
    pub contacts: BTreeMap<String, ContactRec>,
    /// The search for old outputs: asked for, under way or over.
    #[serde(default)]
    pub old: Option<OldSearch>,
    /// Text messages by contact key (hex), oldest first (K120–K122).
    #[serde(default)]
    pub conversations: Conversations,
}

/// One text message of a conversation.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MessageRec {
    pub id: Vec<u8>,
    pub out: bool,
    pub at: u64,
    pub text: String,
    /// Outgoing: the sealed envelope, kept until a relay accepted it or its
    /// window closed.
    #[serde(default)]
    pub envelope: Option<Vec<u8>>,
    #[serde(default)]
    pub expires_at: u64,
    /// Outgoing: 0 waiting for a relay, 1 a relay accepted it, 2 expired.
    #[serde(default)]
    pub state: u8,
}

/// K122 (ред. 0.41): a conversation keeps `MAX_MESSAGES_PER_CONTACT`
/// messages besides own messages still waiting for a relay (they are the
/// delivery queue and never go here); the oldest of the others go.
fn trim_conversation(list: &mut Vec<MessageRec>) {
    let waiting = list.iter().filter(|r| r.waiting()).count();
    while list.len() > crate::MAX_MESSAGES_PER_CONTACT.saturating_add(waiting) {
        let Some(i) = list.iter().position(|r| !r.waiting()) else { break };
        list.remove(i);
    }
}

impl MessageRec {
    /// An own message no relay has accepted yet and whose window is open.
    pub(crate) fn waiting(&self) -> bool {
        self.out && self.state == 0
    }
}

/// The conversations behind a shared pointer: every event is checked on a
/// copy of the state, and the conversations are copied only when an event
/// changes them, not for every block.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct Conversations(pub std::sync::Arc<BTreeMap<String, Vec<MessageRec>>>);

impl Serialize for Conversations {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.as_ref().serialize(s)
    }
}

impl<'de> Deserialize<'de> for Conversations {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Conversations(std::sync::Arc::new(BTreeMap::deserialize(d)?)))
    }
}

impl Conversations {
    pub(crate) fn find(&self, id: &[u8]) -> Option<(&String, &MessageRec)> {
        self.0.iter().find_map(|(k, list)| list.iter().find(|m| m.id == id).map(|m| (k, m)))
    }
}

/// Bytes that are wiped when dropped and never printed.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub(crate) struct Secret(pub Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// The transport identity: a key of its own, not derived from the wallet
/// seed. The seed cannot bring it back; its backup is the key itself.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityRec {
    pub secret: Secret,
    pub public: Vec<u8>,
    pub imported: bool,
    /// Public keys of earlier identities, oldest first.
    pub previous: Vec<Vec<u8>>,
}

/// Someone payments can be delivered to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ContactRec {
    pub key: Vec<u8>,
    pub name: String,
    /// Slatepack address (payment-proof key) of the contact, if known.
    pub address: Option<Vec<u8>>,
}

mod branch_serde {
    use fly_paycore_keys::ledger::BranchState;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &BranchState, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&b.encode())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<BranchState, D::Error> {
        let bytes = Vec::<u8>::deserialize(d)?;
        BranchState::decode(&bytes).map_err(|_| serde::de::Error::custom("branch state"))
    }
}

impl OldSearch {
    /// A search for everything that has read nothing yet.
    pub(crate) fn start() -> OldSearch {
        OldSearch::start_since(None)
    }

    /// A search that has read nothing yet, by a wallet that knew every
    /// output of its own up to the block `since`.
    pub(crate) fn start_since(since: Option<(u64, Vec<u8>)>) -> OldSearch {
        OldSearch {
            next: Some(0),
            since,
            ..OldSearch::default()
        }
    }
}

fn legacy_snapshot() -> bool { true }

/// Inputs chosen for a send.
pub(crate) struct Picked {
    pub inputs: Vec<OutputRec>,
    pub fee: u64,
    pub change: u64,
}

impl State {
    pub(crate) fn new(account: u32) -> State {
        State {
            branch: BranchState::default(),
            account,
            outputs: BTreeMap::new(),
            sends: BTreeMap::new(),
            drafts: BTreeMap::new(),
            tip: None,
            continuous_since: 0,
            undo: Vec::new(),
            legacy_chain_evidence: false,
            auto_receive: None,
            v_base: None,
            v_deltas: Vec::new(),
            identity: None,
            contacts: BTreeMap::new(),
            old: None,
            conversations: Conversations::default(),
        }
    }

    /// An operation whose S1 went out by itself and can still be answered.
    fn delivery_open(&self, s: &SendRec) -> bool {
        s.delivery.is_some() && self.send_status(&s.op) == Some(SendStatus::Prepared)
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, CoreError> {
        serde_json::to_vec(self).map_err(|_| CoreError::Corrupt)
    }

    pub(crate) fn decode(b: &[u8]) -> Result<State, CoreError> {
        serde_json::from_slice(b).map_err(|_| CoreError::Corrupt)
    }

    /// Adds a message to a contact's conversation: only a contact, a text
    /// of 1 to `MAX_MESSAGE_LEN` bytes, an id seen once; when there are more
    /// than `MAX_MESSAGES_PER_CONTACT` besides own messages still waiting for
    /// a relay, the oldest of the others goes (K122).
    fn message_push(&mut self, contact: &[u8], m: MessageRec) -> Result<(), CoreError> {
        let k = hex(contact);
        if contact.len() != 32 || !self.contacts.contains_key(&k) {
            return Err(CoreError::Refused("not a contact"));
        }
        if m.text.is_empty() || m.text.len() > crate::MAX_MESSAGE_LEN {
            return Err(CoreError::Refused("message is not usable"));
        }
        if self.conversations.find(&m.id).is_some() {
            return Err(CoreError::Conflict);
        }
        let list = std::sync::Arc::make_mut(&mut self.conversations.0).entry(k).or_default();
        list.push(m);
        trim_conversation(list);
        Ok(())
    }

    /// Whether `ev` is acceptable in this state, without changing it.
    pub(crate) fn clone_check(&self, ev: &Event) -> Result<(), CoreError> {
        self.clone().apply(ev)
    }

    fn in_flight(s: &SendRec) -> bool {
        !s.cancelled && !s.dead && s.kernel_height.is_none()
    }

    /// Operation holding `commit` in reserve, if any.
    fn reserved_by(&self, commit: &[u8]) -> Option<&SendRec> {
        self.sends
            .values()
            .find(|s| Self::in_flight(s) && s.inputs.iter().any(|c| c == commit))
    }

    pub(crate) fn send_status(&self, op: &OpId) -> Option<SendStatus> {
        let s = self.sends.get(&hex(op))?;
        Some(if s.cancelled && s.released {
            SendStatus::Released
        } else if s.cancelled {
            SendStatus::Cancelled
        } else if s.kernel_height.is_some() {
            SendStatus::Confirmed
        } else if s.dead {
            SendStatus::Dead
        } else if s.conflict_height.is_some() {
            SendStatus::Contested
        } else if s.fin.is_some() {
            SendStatus::Finalized
        } else if s.armed.is_some() {
            SendStatus::Unknown
        } else {
            SendStatus::Prepared
        })
    }

    pub(crate) fn any_contested(&self) -> bool {
        self.sends
            .values()
            .any(|s| Self::in_flight(s) && s.conflict_height.is_some())
    }

    pub(crate) fn open_drafts(&self) -> usize {
        self.drafts
            .values()
            .filter(|d| !d.abandoned && !d.bound)
            .count()
    }

    pub(crate) fn expired_drafts(&self, now: u64, ttl: u64) -> Vec<SlateId> {
        self.drafts
            .values()
            // A chosen invoice response survives until settlement or review.
            // It cannot be abandoned and must not interrupt other expirations.
            .filter(|d| !d.abandoned && !d.bound && d.armed.is_none())
            .filter(|d| {
                d.created
                    .map(|c| now.saturating_sub(c) >= ttl)
                    .unwrap_or(false)
            })
            .map(|d| d.slate_id)
            .collect()
    }

    fn mature(&self, o: &OutputRec, maturity: u64) -> bool {
        if !o.coinbase {
            return true;
        }
        match (&self.tip, o.height.checked_add(maturity)) {
            (Some((tip, _)), Some(at)) => *tip >= at,
            _ => false,
        }
    }

    pub(crate) fn balance(&self, maturity: u64) -> Balance {
        let mut b = Balance::default();
        for o in self.outputs.values().filter(|o| o.spent.is_none()) {
            let slot = if self.reserved_by(&o.commit).is_some() {
                &mut b.reserved
            } else if !self.mature(o, maturity) {
                &mut b.immature
            } else {
                &mut b.spendable
            };
            *slot = slot.saturating_add(o.value);
        }
        b
    }

    pub(crate) fn unspent(&self) -> Vec<([u8; 33], u64)> {
        self.outputs
            .values()
            .filter(|o| o.spent.is_none())
            .filter_map(|o| Some((arr33(&o.commit).ok()?, o.value)))
            .collect()
    }

    /// Choose inputs for `amount`. A replacement must spend an input of the
    /// operation it replaces, so that the two transactions exclude each other.
    pub(crate) fn select_inputs(
        &self,
        amount: u64,
        replaces: Option<&OpId>,
        maturity: u64,
    ) -> Result<Picked, CoreError> {
        let old = match replaces {
            Some(op) => Some(self.sends.get(&hex(op)).ok_or(CoreError::NotFound)?),
            None => None,
        };
        let usable = |o: &OutputRec| -> bool {
            if o.spent.is_some() || !self.mature(o, maturity) {
                return false;
            }
            match self.reserved_by(&o.commit) {
                None => true,
                Some(holder) => old.map(|x| x.op == holder.op).unwrap_or(false),
            }
        };
        let mut pool: Vec<&OutputRec> = self.outputs.values().filter(|o| usable(o)).collect();
        pool.sort_by(|a, b| b.value.cmp(&a.value).then(a.commit.cmp(&b.commit)));
        let mut chosen: Vec<OutputRec> = Vec::new();
        if let Some(x) = old {
            let shared =
                pool.iter()
                    .find(|o| x.inputs.contains(&o.commit))
                    .ok_or(CoreError::Refused(
                        "the replaced operation has no unspent input left",
                    ))?;
            chosen.push((*shared).clone());
        }
        let fee_for = |inputs: usize, outputs: usize| grin_core::libtx::tx_fee(inputs, outputs, 1);
        let forced = chosen.first().map(|c| c.commit.clone());
        let mut rest = pool
            .into_iter()
            .filter(|o| forced.as_ref() != Some(&o.commit));
        loop {
            let total = chosen
                .iter()
                .try_fold(0u64, |acc, o| acc.checked_add(o.value))
                .ok_or(CoreError::Build)?;
            if !chosen.is_empty() {
                // recipient output plus change
                let fee = fee_for(chosen.len(), 2);
                let need = amount.checked_add(fee).ok_or(CoreError::Build)?;
                if total > need {
                    return Ok(Picked {
                        fee,
                        change: total.checked_sub(need).ok_or(CoreError::Build)?,
                        inputs: chosen,
                    });
                }
                // no change output
                let fee1 = fee_for(chosen.len(), 1);
                if amount.checked_add(fee1) == Some(total) {
                    return Ok(Picked {
                        fee: fee1,
                        change: 0,
                        inputs: chosen,
                    });
                }
            }
            match rest.next() {
                Some(o) => chosen.push(o.clone()),
                None => return Err(CoreError::InsufficientFunds),
            }
        }
    }

    /// Choose inputs for a late-locked send whose fee was fixed in S1.
    /// Refuses if that fee no longer pays for the transaction.
    pub(crate) fn select_inputs_fixed_fee(
        &self,
        amount: u64,
        fee: u64,
        maturity: u64,
    ) -> Result<Picked, CoreError> {
        let need = amount.checked_add(fee).ok_or(CoreError::Build)?;
        let mut pool: Vec<&OutputRec> = self
            .outputs
            .values()
            .filter(|o| {
                o.spent.is_none()
                    && self.mature(o, maturity)
                    && self.reserved_by(&o.commit).is_none()
            })
            .collect();
        pool.sort_by(|a, b| b.value.cmp(&a.value).then(a.commit.cmp(&b.commit)));
        let mut chosen: Vec<OutputRec> = Vec::new();
        let mut total = 0u64;
        for o in pool {
            if total >= need {
                break;
            }
            total = total.checked_add(o.value).ok_or(CoreError::Build)?;
            chosen.push(o.clone());
        }
        if total < need {
            return Err(CoreError::InsufficientFunds);
        }
        let change = total.checked_sub(need).ok_or(CoreError::Build)?;
        let outputs = if change > 0 { 2 } else { 1 };
        if fee < grin_core::libtx::tx_fee(chosen.len(), outputs, 1) {
            return Err(CoreError::Refused(
                "the fee fixed in S1 no longer pays for the transaction",
            ));
        }
        Ok(Picked {
            inputs: chosen,
            fee,
            change,
        })
    }

    fn retain_bound_spend(drafts: &mut BTreeMap<String, DraftRec>, previous: &OutputRec) {
        if !previous.bound || previous.spent.is_none() { return; }
        for draft in drafts.values_mut() {
            if draft.bound && draft.commit == previous.commit && draft.kernel_height == Some(previous.height) {
                draft.bound_spent = previous.spent;
            }
        }
    }

    /// State of the exact instance bound by joint inclusion.
    pub(crate) fn bound_spent(&self, draft: &DraftRec) -> Option<bool> {
        if !draft.bound { return None; }
        if let Some(output) = self.outputs.get(&hex(&draft.commit)) {
            if output.bound && draft.kernel_height == Some(output.height) {
                return Some(output.spent.is_some());
            }
        }
        draft.bound_spent.map(|_| true)
    }

    pub(crate) fn incoming_row(
        &self,
        slate_id: &SlateId,
        chain: ChainState,
        k_conf: u64,
    ) -> Option<Row> {
        let d = self.drafts.get(&hex(slate_id))?;
        Some(match chain {
            ChainState::Unknown => Row::S1,
            ChainState::Behind => Row::S2,
            ChainState::AtTip => {
                let (tip, kh) = match (&self.tip, d.kernel_height) {
                    (Some((tip, _)), Some(kh)) => (*tip, kh),
                    _ => return Some(Row::S4),
                };
                let confirmations = tip.saturating_sub(kh).saturating_add(1);
                if confirmations < k_conf {
                    Row::S6
                } else if !d.bound {
                    Row::S7a
                } else if self.bound_spent(d).is_some() {
                    // alive, or spent by a recorded spend
                    Row::S8
                } else {
                    Row::S7
                }
            }
        })
    }

    pub(crate) fn unrecorded_row(&self, commit: &[u8; 33], chain: ChainState) -> Option<Row> {
        let o = self.outputs.get(&hex(commit))?;
        if o.bound {
            return None;
        }
        Some(match chain {
            ChainState::Unknown => Row::S1,
            ChainState::Behind => Row::S2,
            ChainState::AtTip => Row::S3,
        })
    }

    /// The only function that changes wallet state. Used both when an event
    /// has just been committed and when the journal is replayed.
    pub(crate) fn apply(&mut self, ev: &Event) -> Result<(), CoreError> {
        match ev {
            Event::Init { account, branch } => {
                if self.branch.current().is_some() {
                    return Err(CoreError::Corrupt);
                }
                self.account = *account;
                self.branch
                    .note_branch(*branch)
                    .map_err(|_| CoreError::Corrupt)
            }
            Event::Recovery { branch } => {
                self.branch
                    .note_branch(*branch)
                    .map_err(|_| CoreError::Corrupt)?;
                // K15: nothing prepared before the rollback may be signed
                for s in self.sends.values_mut() {
                    s.locked = true;
                }
                // an issued invoice that was not armed can no longer be signed
                for d in self.drafts.values_mut() {
                    if d.invoice.is_some() && d.armed.is_none() {
                        d.ctx.clear();
                    }
                }
                Ok(())
            }
            Event::Prepared(rec) => {
                let key = hex(&rec.op);
                if self.sends.contains_key(&key)
                    || rec.armed.is_some()
                    || rec.fin.is_some()
                    || rec.cancelled
                    || rec.locked
                    || rec.armed_sel.is_some()
                    || rec.held.is_some()
                {
                    return Err(CoreError::Corrupt);
                }
                if let Some(d) = &rec.delivery {
                    if self.identity.is_none() {
                        return Err(CoreError::Refused("the wallet has no transport identity"));
                    }
                    if !self.contacts.contains_key(&hex(&d.contact)) {
                        return Err(CoreError::Refused("the recipient is not a contact"));
                    }
                    let clean = d.contact.len() == 32
                        && d.event_id.len() == 32
                        && !d.envelope.is_empty()
                        && d.envelope.len() <= crate::MAX_ENVELOPE_LEN
                        && d.unknown == 0
                        && d.accepted == 0
                        && !d.expired
                        && d.last == 0;
                    if !clean {
                        return Err(CoreError::Corrupt);
                    }
                    if self.sends.values().any(|x| {
                        x.delivery
                            .as_ref()
                            .is_some_and(|y| y.event_id == d.event_id)
                    }) {
                        return Err(CoreError::Conflict);
                    }
                }
                if rec.late {
                    // nothing is reserved and no path is issued yet
                    if !rec.inputs.is_empty() || rec.change.is_some() || rec.replaces.is_some() {
                        return Err(CoreError::Corrupt);
                    }
                    self.sends.insert(key, (**rec).clone());
                    return Ok(());
                }
                for c in &rec.inputs {
                    let o = self.outputs.get(&hex(c)).ok_or(CoreError::Corrupt)?;
                    let free = match self.reserved_by(c) {
                        None => true,
                        Some(holder) => rec.replaces == Some(holder.op),
                    };
                    if o.spent.is_some() || !free {
                        return Err(CoreError::Refused("input not available"));
                    }
                }
                self.branch
                    .note_issued(rec.branch, rec.index)
                    .map_err(|_| CoreError::Corrupt)?;
                self.sends.insert(key, (**rec).clone());
                Ok(())
            }
            Event::Cancelled { op } => {
                let s = self.sends.get_mut(&hex(op)).ok_or(CoreError::NotFound)?;
                if s.armed.is_some() {
                    return Err(CoreError::Refused("an S2 was already chosen for signing"));
                }
                if s.cancelled {
                    return Err(CoreError::Refused("already cancelled"));
                }
                s.cancelled = true;
                // what a rollback locked may have been signed in the part
                // of the journal that was lost: said so from here on
                s.released = s.locked;
                s.ctx.clear();
                Ok(())
            }
            Event::Armed { op, s2, sel } => {
                let s = self.sends.get_mut(&hex(op)).ok_or(CoreError::NotFound)?;
                if s.armed.is_some() || s.cancelled || s.locked || s.late {
                    return Err(CoreError::Refused("operation cannot be armed"));
                }
                if s.conflict_height.is_some() || s.dead {
                    return Err(CoreError::Refused(
                        "an input was spent by another transaction",
                    ));
                }
                s.armed = Some(s2.clone());
                s.armed_sel = sel.clone();
                Ok(())
            }
            Event::ReplyHeld { op, s2 } => {
                let s = self.sends.get_mut(&hex(op)).ok_or(CoreError::NotFound)?;
                if s.armed.is_some()
                    || s.cancelled
                    || s.locked
                    || s.dead
                    || s.conflict_height.is_some()
                {
                    return Err(CoreError::Refused("operation takes no reply"));
                }
                if s.held.is_some() {
                    return Err(CoreError::Conflict);
                }
                if s2.is_empty() || s2.len() > crate::MAX_SLATE_LEN {
                    return Err(CoreError::Corrupt);
                }
                s.held = Some(s2.clone());
                Ok(())
            }
            Event::IdentitySet {
                secret,
                public,
                imported,
            } => {
                if secret.0.len() != 32 || public.len() != 32 {
                    return Err(CoreError::Corrupt);
                }
                // replies to what is on its way are addressed to the present
                // identity; changing it now would leave them unanswered
                if self.sends.values().any(|s| self.delivery_open(s)) {
                    return Err(CoreError::Refused(
                        "a delivered payment still waits for its reply",
                    ));
                }
                if self.contacts.contains_key(&hex(public)) {
                    return Err(CoreError::Refused("that key belongs to a contact"));
                }
                let mut previous = Vec::new();
                if let Some(old) = &self.identity {
                    if old.public == *public {
                        return Err(CoreError::Conflict);
                    }
                    previous.clone_from(&old.previous);
                    previous.push(old.public.clone());
                    if previous.len() > crate::MAX_PREVIOUS_IDENTITIES {
                        previous.remove(0);
                    }
                }
                self.identity = Some(IdentityRec {
                    secret: secret.clone(),
                    public: public.clone(),
                    imported: *imported,
                    previous,
                });
                Ok(())
            }
            Event::ContactSet { key, name, address } => {
                let name_ok = !name.is_empty()
                    && name.len() <= crate::MAX_CONTACT_NAME
                    && !name.chars().any(char::is_control)
                    && name.trim() == name;
                if key.len() != 32 || !name_ok || address.as_ref().is_some_and(|a| a.len() != 32) {
                    return Err(CoreError::Refused("contact is not usable"));
                }
                if self.identity.as_ref().is_some_and(|i| i.public == *key) {
                    return Err(CoreError::Refused("that is this wallet's own key"));
                }
                let k = hex(key);
                if !self.contacts.contains_key(&k) && self.contacts.len() >= crate::MAX_CONTACTS {
                    return Err(CoreError::Refused("too many contacts"));
                }
                self.contacts.insert(
                    k,
                    ContactRec {
                        key: key.clone(),
                        name: name.clone(),
                        address: address.clone(),
                    },
                );
                Ok(())
            }
            Event::ContactRemoved { key } => {
                let k = hex(key);
                if !self.contacts.contains_key(&k) {
                    return Err(CoreError::NotFound);
                }
                let waiting = self.sends.values().any(|s| {
                    self.delivery_open(s) && s.delivery.as_ref().is_some_and(|d| d.contact == *key)
                });
                if waiting {
                    return Err(CoreError::Refused(
                        "a payment to this contact still waits for its reply",
                    ));
                }
                self.contacts.remove(&k);
                // the conversation goes with the contact (K122)
                if self.conversations.0.contains_key(&k) {
                    std::sync::Arc::make_mut(&mut self.conversations.0).remove(&k);
                }
                Ok(())
            }
            Event::MessageOut { id, to, at, text, envelope, expires_at } => {
                if self.identity.is_none() {
                    return Err(CoreError::Refused("the wallet has no transport identity"));
                }
                if id.len() != 32 || envelope.is_empty() || envelope.len() > crate::MAX_ENVELOPE_LEN {
                    return Err(CoreError::Refused("message is not usable"));
                }
                self.message_push(to, MessageRec {
                    id: id.clone(),
                    out: true,
                    at: *at,
                    text: text.clone(),
                    envelope: Some(envelope.clone()),
                    expires_at: *expires_at,
                    state: 0,
                })
            }
            Event::MessageIn { id, from, at, text } => {
                if id.len() != 32 {
                    return Err(CoreError::Refused("message is not usable"));
                }
                self.message_push(from, MessageRec {
                    id: id.clone(),
                    out: false,
                    at: *at,
                    text: text.clone(),
                    envelope: None,
                    expires_at: 0,
                    state: 0,
                })
            }
            Event::MessageNote { id, what } => {
                if !matches!(*what, 1 | 2) {
                    return Err(CoreError::Corrupt);
                }
                let key = match self.conversations.find(id) {
                    Some((k, m)) if m.out && m.state == 0 => k.clone(),
                    Some(_) => return Err(CoreError::Conflict),
                    None => return Err(CoreError::NotFound),
                };
                let list = std::sync::Arc::make_mut(&mut self.conversations.0)
                    .get_mut(&key)
                    .ok_or(CoreError::NotFound)?;
                if let Some(m) = list.iter_mut().find(|m| m.id == *id) {
                    m.state = *what;
                    m.envelope = None;
                }
                trim_conversation(list);
                Ok(())
            }
            Event::Delivery { op, what } => {
                let s = self.sends.get_mut(&hex(op)).ok_or(CoreError::NotFound)?;
                let d = s
                    .delivery
                    .as_mut()
                    .ok_or(CoreError::Refused("operation has no delivery"))?;
                match what {
                    1 => d.unknown = d.unknown.saturating_add(1),
                    2 => d.accepted = d.accepted.saturating_add(1),
                    3 => d.expired = true,
                    4 | 5 => {}
                    _ => return Err(CoreError::Corrupt),
                }
                d.last = *what;
                Ok(())
            }
            Event::ArmedLate {
                op,
                s2,
                inputs,
                change,
                branch,
                index,
                sel,
            } => {
                let key = hex(op);
                let s = self.sends.get(&key).ok_or(CoreError::NotFound)?;
                if s.armed.is_some() || s.cancelled || s.locked || !s.late || inputs.is_empty() {
                    return Err(CoreError::Refused("operation cannot be armed"));
                }
                let mut total = 0u64;
                for (n, c) in inputs.iter().enumerate() {
                    let o = self.outputs.get(&hex(c)).ok_or(CoreError::Corrupt)?;
                    if o.spent.is_some()
                        || self.reserved_by(c).is_some()
                        || inputs.iter().take(n).any(|d| d == c)
                    {
                        return Err(CoreError::Refused("input not available"));
                    }
                    total = total.checked_add(o.value).ok_or(CoreError::Corrupt)?;
                }
                // the frame must balance exactly against the S1 already sent
                let out = s
                    .amount
                    .checked_add(s.fee)
                    .and_then(|x| x.checked_add(change.as_ref().map(|c| c.1).unwrap_or(0)));
                if out != Some(total) {
                    return Err(CoreError::Corrupt);
                }
                self.branch
                    .note_issued(*branch, *index)
                    .map_err(|_| CoreError::Corrupt)?;
                let s = self.sends.get_mut(&key).ok_or(CoreError::NotFound)?;
                s.inputs = inputs.clone();
                s.change = change.clone();
                s.branch = *branch;
                s.index = *index;
                s.armed = Some(s2.clone());
                s.armed_sel = sel.clone();
                Ok(())
            }
            Event::Final {
                op,
                tx,
                excess,
                s3,
                proof,
            } => {
                let s = self.sends.get_mut(&hex(op)).ok_or(CoreError::NotFound)?;
                if s.armed.is_none() || s.fin.is_some() {
                    return Err(CoreError::Corrupt);
                }
                s.fin = Some(FinalRec {
                    tx: tx.clone(),
                    excess: excess.clone(),
                    s3: s3.clone(),
                    proof: proof.clone(),
                });
                // the signing context is retired together with the result
                s.ctx.clear();
                Ok(())
            }
            Event::Broadcast { op, outcome } => {
                let s = self.sends.get_mut(&hex(op)).ok_or(CoreError::NotFound)?;
                if s.fin.is_none() {
                    return Err(CoreError::Refused("nothing to broadcast"));
                }
                let slot = match outcome {
                    0 => &mut s.broadcasts.0,
                    1 => &mut s.broadcasts.1,
                    _ => &mut s.broadcasts.2,
                };
                *slot = slot.saturating_add(1);
                Ok(())
            }
            Event::InvoicePaid(rec) => {
                let key = hex(&rec.op);
                if self.sends.contains_key(&key)
                    || !rec.invoice
                    || rec.armed.is_none()
                    || rec.fin.is_none()
                {
                    return Err(CoreError::Corrupt);
                }
                if self.sends.values().any(|s| s.slate_id == rec.slate_id) {
                    return Err(CoreError::Conflict);
                }
                for c in &rec.inputs {
                    let o = self.outputs.get(&hex(c)).ok_or(CoreError::Corrupt)?;
                    if o.spent.is_some() || self.reserved_by(c).is_some() {
                        return Err(CoreError::Refused("input not available"));
                    }
                }
                self.branch
                    .note_issued(rec.branch, rec.index)
                    .map_err(|_| CoreError::Corrupt)?;
                self.sends.insert(key, (**rec).clone());
                Ok(())
            }
            Event::InvoiceArmed { slate_id, i2 } => {
                let d = self
                    .drafts
                    .get_mut(&hex(slate_id))
                    .ok_or(CoreError::NotFound)?;
                if d.invoice.is_none() || d.armed.is_some() || d.abandoned || d.ctx.is_empty() {
                    return Err(CoreError::Refused("invoice cannot be armed"));
                }
                d.armed = Some(i2.clone());
                Ok(())
            }
            Event::InvoiceFinal {
                slate_id,
                tx,
                excess,
                s3,
            } => {
                let d = self
                    .drafts
                    .get_mut(&hex(slate_id))
                    .ok_or(CoreError::NotFound)?;
                if d.armed.is_none() || d.fin.is_some() {
                    return Err(CoreError::Corrupt);
                }
                d.excess = excess.clone();
                d.fin = Some(FinalRec {
                    tx: tx.clone(),
                    excess: excess.clone(),
                    s3: s3.clone(),
                    proof: None,
                });
                d.ctx.clear();
                Ok(())
            }
            Event::Draft(rec) => {
                let key = hex(&rec.slate_id);
                if self.drafts.contains_key(&key) {
                    return Err(CoreError::Conflict);
                }
                self.branch
                    .note_issued(rec.branch, rec.index)
                    .map_err(|_| CoreError::Corrupt)?;
                self.drafts.insert(key, (**rec).clone());
                Ok(())
            }
            Event::DraftAbandon { slate_id } => {
                let d = self
                    .drafts
                    .get_mut(&hex(slate_id))
                    .ok_or(CoreError::NotFound)?;
                if d.bound {
                    return Err(CoreError::Refused("draft is already bound"));
                }
                if d.armed.is_some() {
                    return Err(CoreError::Refused("an I2 was already chosen for signing"));
                }
                d.abandoned = true;
                d.ctx.clear();
                Ok(())
            }
            Event::AutoReceive { on } => {
                self.auto_receive = if *on {
                    Some(self.tip.as_ref().map(|t| t.0).unwrap_or(0))
                } else {
                    None
                };
                Ok(())
            }
            Event::ResetLegacyChainEvidence => {
                self.discard_chain_evidence();
                self.legacy_chain_evidence = false;
                self.tip = None;
                self.old = Some(OldSearch::start());
                self.undo.clear();
                self.v_base = None;
                self.v_deltas.clear();
                Ok(())
            }
            Event::Reanchor { height, hash, since, extends } => {
                // Blocks the wallet never saw lie between its position and
                // the new one: what it holds may have been spent there and
                // what it was paid there it does not know. The search for
                // old outputs settles both. A wallet without a position
                // has missed nothing it knew about.
                if self.tip.is_some() {
                    match extends {
                        Some(false) => {
                            self.discard_chain_evidence();
                            self.legacy_chain_evidence = false;
                            self.old = Some(OldSearch::start());
                        }
                        Some(true) => self.old = Some(OldSearch::start_since(since.clone())),
                        None => {
                            // Replay the original transition before migrating at open.
                            self.old = Some(OldSearch::start_since(since.clone()));
                            self.legacy_chain_evidence = true;
                        }
                    }
                }
                self.tip = Some((*height, hash.clone()));
                self.continuous_since = *height;
                self.undo.clear();
                self.v_base = None;
                self.v_deltas.clear();
                // completeness by scanning does not survive a gap
                if self.auto_receive.is_some() {
                    self.auto_receive = Some(*height);
                }
                Ok(())
            }
            Event::Advance {
                height,
                hash,
                found,
                spent,
                kernels,
                v_delta,
            } => self.advance(*height, hash, found, spent, kernels, v_delta),
            Event::Rollback { height } => self.rollback(*height),
            Event::OldSearch {} => {
                self.old = Some(OldSearch::start());
                Ok(())
            }
            Event::Old {
                piece,
                last,
                pieces,
                before,
                at_height,
                at_hash,
                found,
            } => self.old_piece(*piece, *last, *pieces, *before, *at_height, at_hash, found),
        }
    }

    /// Signatures, exposed paths, in-flight operations and the association
    /// with their inputs survive. Only claims about a particular chain go.
    fn discard_chain_evidence(&mut self) {
        self.outputs.clear();
        for s in self.sends.values_mut() {
            s.kernel_height = None;
            s.by_search = false;
            s.binding_interrupted = true;
            s.conflict_height = None;
            s.dead = false;
        }
        for d in self.drafts.values_mut() {
            d.kernel_height = None;
            d.bound = false;
            d.bound_spent = None;
            d.binding_interrupted = true;
        }
    }

    /// The block up to which the wallet knows every output of its own, if
    /// a gap opened now: the block it stands at, when it has all it ever
    /// had - no search was ever needed, or the last one has read every
    /// piece. A wallet in the middle of a search knows no more than that
    /// search was begun with.
    pub(crate) fn known_up_to(&self) -> Option<(u64, Vec<u8>)> {
        let tip = self.tip.clone()?;
        match &self.old {
            None => Some(tip),
            Some(search) if search.next.is_none() && !search.again => Some(tip),
            Some(search) => search.since.clone(),
        }
    }

    /// An output the wallet has a record of, spent or not.
    pub(crate) fn known_output(&self, commit: &[u8]) -> Option<&OutputRec> {
        self.outputs.get(&hex(commit))
    }

    /// Take one piece of the old outputs (specification 7.19).
    #[allow(clippy::too_many_arguments)]
    fn old_piece(
        &mut self,
        piece: u64,
        last: bool,
        pieces: u64,
        before: u64,
        at_height: u64,
        at_hash: &[u8],
        found: &[FoundOut],
    ) -> Result<(), CoreError> {
        let Some(search) = self.old.as_mut() else {
            return Err(CoreError::Refused("no search for old outputs is under way"));
        };
        if search.next != Some(piece) {
            return Err(CoreError::Refused("not the piece that is next"));
        }
        // The piece says what is unspent after one block. Only a wallet
        // that stands at that very block has seen every spend up to it and
        // none after it.
        if self.tip.as_ref().map(|(height, hash)| (*height, hash.as_slice())) != Some((at_height, at_hash)) {
            return Err(CoreError::Refused("the piece is for another block"));
        }
        // An output younger than `before` may be missing from the piece;
        // the wallet must have it from its blocks.
        if before > at_height || self.continuous_since > before {
            return Err(CoreError::Refused("the piece does not reach the wallet's blocks"));
        }
        if piece.checked_add(1).map(|after| if last { after == pieces } else { after < pieces }) != Some(true) {
            return Err(CoreError::Refused("the piece does not fit the number of pieces"));
        }
        for f in found {
            let key = hex(&f.commit);
            if !search.again {
                search.seen.insert(key.clone());
            }
            if self.outputs.get(&key).is_some_and(|o| o.spent.is_none()) {
                continue;
            }
            if let Some(previous) = self.outputs.get(&key) {
                Self::retain_bound_spend(&mut self.drafts, previous);
            }
            // unknown, or known as spent before the blocks the wallet missed
            self.outputs.insert(
                key,
                OutputRec {
                    commit: f.commit.clone(),
                    key_id: f.key_id.clone(),
                    value: f.value,
                    coinbase: f.coinbase,
                    height: before,
                    pos: f.pos,
                    bound: false,
                    spent: None,
                    old: true,
                },
            );
            search.found = search.found.saturating_add(1);
        }
        // A change output that is on the chain was put there by its
        // operation: no other transaction was ever signed with that
        // output. Its kernel lies in blocks the wallet did not see; the
        // operation was in the chain by `before`, and is not contested
        // when its inputs prove spent.
        // And an input that is unspent says the opposite of what an
        // earlier search concluded: the operation is not in this chain.
        for s in self.sends.values_mut() {
            if s.by_search && s.inputs.iter().any(|input| found.iter().any(|f| f.commit == *input)) {
                s.kernel_height = None;
                s.by_search = false;
            }
        }
        for s in self.sends.values_mut() {
            let evidence = s.change.as_ref().is_some_and(|(_, _, change)| found.iter().any(|f| f.commit == *change));
            if evidence && Self::in_flight(s) && s.fin.is_some() {
                s.kernel_height = Some(before);
                s.by_search = true;
            }
        }
        if search.runs.last().map(|(height, _)| *height) != Some(at_height) {
            search.runs.push((at_height, piece));
        }
        search.floor = Some(search.floor.map_or(before, |floor| floor.min(before)));
        search.ceiling = search.ceiling.max(before);
        search.pieces = pieces;
        search.next = if last { None } else { piece.checked_add(1) };
        if !last {
            return Ok(());
        }
        // Every piece has been read. An output the wallet holds that
        // existed by the time each piece was complete, and that none of
        // them showed, was spent in blocks the wallet did not see.
        let floor = search.floor.unwrap_or(before);
        let again = std::mem::take(&mut search.again);
        let seen = std::mem::take(&mut search.seen);
        if again {
            return Ok(());
        }
        let mut gone = Vec::new();
        for (key, o) in self.outputs.iter_mut() {
            if o.spent.is_none() && o.height <= floor && !seen.contains(key) {
                o.spent = Some(at_height);
                gone.push(o.commit.clone());
            }
        }
        // an operation in flight that counted on one of them is contested
        for s in self.sends.values_mut() {
            if Self::in_flight(s) && s.conflict_height.is_none() && s.inputs.iter().any(|i| gone.contains(i) || !self.outputs.contains_key(&hex(i))) {
                s.conflict_height = Some(at_height);
            }
        }
        if let Some(search) = self.old.as_mut() {
            search.gone = search.gone.saturating_add(u64::try_from(gone.len()).unwrap_or(u64::MAX));
        }
        Ok(())
    }

    fn advance(
        &mut self,
        height: u64,
        hash: &[u8],
        found: &[FoundOut],
        spent: &[Vec<u8>],
        kernels: &[Vec<u8>],
        v_delta: &[u8],
    ) -> Result<(), CoreError> {
        if let Some((tip, _)) = &self.tip {
            if tip.checked_add(1) != Some(height) {
                return Err(CoreError::Refused("block does not extend the tip"));
            }
        } else {
            self.continuous_since = height;
        }
        let mut u = Undo {
            height,
            prev_tip: self.tip.clone(),
            ..Undo::default()
        };
        let has_kernel = |excess: &[u8]| kernels.iter().any(|k| k == excess);

        // kernels of own operations
        for (key, s) in self.sends.iter_mut() {
            if let Some(f) = &s.fin {
                if s.kernel_height.is_none() && has_kernel(&f.excess) {
                    s.kernel_height = Some(height);
                    u.send_kernels.push(key.clone());
                }
            }
        }
        for (key, d) in self.drafts.iter_mut() {
            if d.kernel_height.is_none() && has_kernel(&d.excess) {
                d.kernel_height = Some(height);
                u.draft_kernels.push(key.clone());
            }
        }

        // own outputs created by this block
        for f in found {
            let key = hex(&f.commit);
            if self
                .outputs
                .get(&key)
                .map(|o| o.spent.is_none())
                .unwrap_or(false)
            {
                return Err(CoreError::Refused("output already alive"));
            }
            // Automatic binding (Level 5, section 3 step 2): the record was
            // made before the output was disclosed, its kernel is in this
            // very block, the state advanced without a gap since the record's
            // R, and this is the first such inclusion.
            let mut bound = false;
            for (dkey, d) in self.drafts.iter_mut() {
                if d.commit == f.commit
                    && !d.bound
                    && !d.abandoned
                    && !d.binding_interrupted
                    && d.kernel_height == Some(height)
                    && d.r_height < height
                    && self.continuous_since <= d.r_height
                {
                    d.bound = true;
                    bound = true;
                    u.draft_bound.push(dkey.clone());
                }
            }
            for s in self.sends.values() {
                if let Some((_, _, c)) = &s.change {
                    if *c == f.commit
                        && !s.binding_interrupted
                        && s.kernel_height == Some(height)
                        && s.r_height < height
                        && self.continuous_since <= s.r_height
                    {
                        bound = true;
                    }
                }
            }
            let previous = self.outputs.insert(
                key.clone(),
                OutputRec {
                    commit: f.commit.clone(),
                    key_id: f.key_id.clone(),
                    value: f.value,
                    coinbase: f.coinbase,
                    height,
                    pos: f.pos,
                    bound,
                    spent: None,
                    old: false,
                },
            );
            u.created.push(key);
            if let Some(previous) = previous {
                Self::retain_bound_spend(&mut self.drafts, &previous);
                u.replaced_outputs.push(previous);
            }
        }

        // own outputs spent by this block
        for c in spent {
            let key = hex(c);
            let hit = match self.outputs.get_mut(&key) {
                Some(o) if o.spent.is_none() && o.height < height => {
                    o.spent = Some(height);
                    true
                }
                _ => false,
            };
            if !hit {
                continue;
            }
            u.spent.push(key);
            // spent by someone else's transaction: every operation in flight
            // that counted on this input is contested
            for (skey, s) in self.sends.iter_mut() {
                if Self::in_flight(s)
                    && s.conflict_height.is_none()
                    && s.inputs.iter().any(|i| i == c)
                {
                    s.conflict_height = Some(height);
                    u.conflicts.push(skey.clone());
                }
            }
        }

        // a conflict R_UNDO deep kills the operation and frees its inputs
        for (skey, s) in self.sends.iter_mut() {
            if let Some(h) = s.conflict_height {
                if Self::in_flight(s) && height.saturating_sub(h).saturating_add(1) >= R_UNDO {
                    s.dead = true;
                    u.died.push(skey.clone());
                }
            }
        }

        self.tip = Some((height, hash.to_vec()));
        if !v_delta.is_empty() {
            self.v_deltas.push((height, v_delta.to_vec()));
        }
        self.undo.push(u);
        let max = usize::try_from(R_UNDO).unwrap_or(usize::MAX);
        if self.undo.len() > max {
            let cut = self.undo.len().saturating_sub(max);
            self.undo.drain(..cut);
        }
        Ok(())
    }

    fn rollback(&mut self, to: u64) -> Result<(), CoreError> {
        let (tip, _) = self.tip.clone().ok_or(CoreError::Refused("no tip"))?;
        if to >= tip {
            return Err(CoreError::Refused("nothing to roll back"));
        }
        let depth =
            usize::try_from(tip.saturating_sub(to)).map_err(|_| CoreError::Refused("too deep"))?;
        if depth > self.undo.len() {
            return Err(CoreError::Refused("deeper than the undo log: re-anchor"));
        }
        if self.v_base.as_ref().map(|(h, _)| *h > to).unwrap_or(false) {
            return Err(CoreError::Refused("below the snapshot of V: re-anchor"));
        }
        for draft in self.drafts.values_mut() {
            if draft.bound_spent.is_some_and(|height| height > to) {
                draft.bound_spent = None;
            }
        }
        self.v_deltas.retain(|(h, _)| *h <= to);
        for _ in 0..depth {
            let u = self.undo.pop().ok_or(CoreError::Corrupt)?;
            for k in &u.died {
                if let Some(s) = self.sends.get_mut(k) {
                    s.dead = false;
                }
            }
            // K3: the reserve returns in the same event that removes the conflict
            for k in &u.conflicts {
                if let Some(s) = self.sends.get_mut(k) {
                    s.conflict_height = None;
                }
            }
            for k in &u.spent {
                if let Some(o) = self.outputs.get_mut(k) {
                    o.spent = None;
                }
            }
            for k in &u.created {
                self.outputs.remove(k);
            }
            for previous in u.replaced_outputs {
                self.outputs.insert(hex(&previous.commit), previous);
            }
            for k in &u.draft_bound {
                if let Some(d) = self.drafts.get_mut(k) {
                    d.bound = false;
                }
            }
            for k in &u.draft_kernels {
                if let Some(d) = self.drafts.get_mut(k) {
                    d.kernel_height = None;
                }
            }
            for k in &u.send_kernels {
                if let Some(s) = self.sends.get_mut(k) {
                    s.kernel_height = None;
                }
            }
            self.tip = u.prev_tip;
        }
        if let Some(search) = self.old.as_mut() {
            if search.ceiling > to {
                // Outputs the search added may be younger than the block
                // the wallet is back at, and not exist on the other
                // branch. They go, and the search starts over.
                self.outputs.retain(|_, o| !(o.old && o.height > to));
                // and with them what they said about operations: a
                // kernel height above this block that the undo records
                // did not take back was not read from a block
                for s in self.sends.values_mut() {
                    if s.kernel_height.is_some_and(|height| height > to) {
                        s.kernel_height = None;
                        s.by_search = false;
                    }
                }
                // what the wallet knew before the gap it still knows
                *search = OldSearch::start_since(search.since.take());
            } else if let Some(first) = search.runs.iter().position(|(read_at, _)| *read_at > to) {
                // What was read above that block said what was unspent on
                // the branch that is gone: an output spent there, and so
                // not shown, may be alive on the other one.
                let piece = search.runs.get(first).map(|(_, piece)| *piece);
                search.runs.truncate(first);
                if search.next.is_none() {
                    search.again = true;
                }
                search.next = piece;
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn slate_of(&self, op: &OpId) -> Option<SlateId> {
        self.sends.get(&hex(op)).map(|s| s.slate_id)
    }

    #[allow(dead_code)]
    pub(crate) fn op16(b: &[u8]) -> Result<OpId, CoreError> {
        arr16(b)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    /// The block the wallet knew its outputs up to travels in the event
    /// that opens the gap and comes back from the journal with it.
    #[test]
    fn the_known_block_is_written_with_the_gap() {
        let ev = Event::Reanchor {
            height: 7,
            hash: vec![1],
            since: Some((5, vec![9; 32])),
            extends: Some(true),
        };
        let back = Event::decode(&ev.encode().unwrap()).unwrap();
        assert!(matches!(back, Event::Reanchor { height: 7, since: Some((5, hash)), .. } if hash == vec![9; 32]));
        // applied to a wallet that has a position, the event starts the
        // search with that block; to one that has none, no search
        let mut st = State::new(0);
        st.apply(&ev).unwrap();
        assert_eq!(st.old, None);
        st.apply(&ev).unwrap();
        assert_eq!(st.old.as_ref().unwrap().since, Some((5, vec![9; 32])));
        assert_eq!(st.old.as_ref().unwrap().next, Some(0));
    }

    #[test]
    fn undo_restores_the_previous_wallet_output_instance() -> Result<(), CoreError> {
        let mut st = State::new(0);
        let mut found = FoundOut { commit: vec![1; 33], key_id: vec![2; 17],
            value: 10, coinbase: false, pos: 1 };
        st.advance(1, &[1; 32], std::slice::from_ref(&found), &[], &[], &[])?;
        let initial = st.outputs.clone();
        st.advance(2, &[2; 32], &[], std::slice::from_ref(&found.commit), &[], &[])?;
        let spent = st.outputs.clone();
        found.pos = 5;
        st.advance(3, &[3; 32], std::slice::from_ref(&found), &[], &[], &[])?;
        st.rollback(2)?;
        assert_eq!(st.outputs, spent);
        st.rollback(1)?;
        assert_eq!(st.outputs, initial);
        Ok(())
    }
    fn out(n: u8, value: u64) -> OutputRec {
        OutputRec {
            commit: vec![n; 33],
            key_id: vec![n; 17],
            value,
            coinbase: false,
            height: 1,
            pos: u64::from(n),
            bound: false,
            spent: None,
            old: false,
        }
    }

    fn send(op: u8, late: bool, inputs: Vec<Vec<u8>>, amount: u64, fee: u64) -> SendRec {
        SendRec {
            op: [op; 16],
            slate_id: [op; 16],
            s1: Vec::new(),
            ctx: vec![1],
            inputs,
            change: None,
            amount,
            fee,
            r_height: 1,
            binding_interrupted: false,
            replaces: None,
            branch: 0,
            index: 0,
            locked: false,
            cancelled: false,
            armed: None,
            fin: None,
            kernel_height: None,
            conflict_height: None,
            dead: false,
            broadcasts: (0, 0, 0),
            invoice: false,
            late,
            delivery: None,
            armed_sel: None,
            held: None,
            by_search: false,
            released: false,
        }
    }

    /// K20: the arming frame of a late-locked send is checked on replay as
    /// strictly as when it is written. A frame that does not balance against
    /// S1, repeats an input, takes a reserved or spent input, or arms an
    /// ordinary send, is refused and changes nothing.
    #[test]
    fn late_arming_frame_is_validated() {
        let mut st = State::new(0);
        st.apply(&Event::Init {
            account: 0,
            branch: 7,
        })
        .unwrap();
        for (n, v) in [(1u8, 60u64), (2, 50), (3, 40), (4, 30)] {
            st.outputs.insert(hex(&[n; 33]), out(n, v));
        }
        st.outputs.get_mut(&hex(&[4u8; 33])).unwrap().spent = Some(2);
        // an ordinary send holds output 3
        let mut ordinary = send(9, false, vec![vec![3; 33]], 30, 10);
        (ordinary.branch, ordinary.index) = st.branch.peek().unwrap();
        st.apply(&Event::Prepared(Box::new(ordinary))).unwrap();
        // a late send for 90 + fee 10
        st.apply(&Event::Prepared(Box::new(send(8, true, vec![], 90, 10))))
            .unwrap();
        // a late record that already carries a reserve is not a late record
        assert!(st
            .clone()
            .apply(&Event::Prepared(Box::new(send(
                7,
                true,
                vec![vec![1; 33]],
                5,
                1
            ))))
            .is_err());
        let (branch, index) = st.branch.peek().unwrap();
        let arm = |inputs: Vec<u8>, change: Option<u64>, op: u8| Event::ArmedLate {
            op: [op; 16],
            s2: vec![0],
            inputs: inputs.into_iter().map(|n| vec![n; 33]).collect(),
            change: change.map(|v| (vec![5; 17], v, vec![5; 33])),
            branch,
            index,
            sel: None,
        };
        let before = st.clone();
        for (what, ev) in [
            ("does not balance", arm(vec![1, 2], None, 8)),
            ("change too large", arm(vec![1, 2], Some(11), 8)),
            ("too little", arm(vec![1], None, 8)),
            ("repeated input", arm(vec![2, 2], None, 8)),
            ("reserved input", arm(vec![1, 3], None, 8)),
            ("spent input", arm(vec![1, 2, 4], Some(40), 8)),
            ("unknown input", arm(vec![1, 6], None, 8)),
            ("no inputs", arm(vec![], None, 8)),
            ("ordinary send", arm(vec![1, 2], Some(10), 9)),
        ] {
            assert!(st.apply(&ev).is_err(), "{what}");
            assert!(st == before, "{what}: state changed");
        }
        // 60 + 50 = 90 + 10 + 10
        st.apply(&arm(vec![1, 2], Some(10), 8)).unwrap();
        let s = st.sends.get(&hex(&[8u8; 16])).unwrap();
        assert_eq!((s.inputs.len(), s.branch, s.index), (2, branch, index));
        assert_ne!(
            st.branch.peek(),
            Some((branch, index)),
            "the path is issued"
        );
        // armed once only, and never by the ordinary arming event
        assert!(st.clone().apply(&arm(vec![1, 2], Some(10), 8)).is_err());
        let mut fresh = before.clone();
        assert!(fresh
            .apply(&Event::Armed {
                op: [8; 16],
                s2: vec![0],
                sel: None,
            })
            .is_err());
        // the reserve now blocks an ordinary send
        let mut blocked = send(6, false, vec![vec![1; 33]], 5, 1);
        (blocked.branch, blocked.index) = st.branch.peek().unwrap();
        assert!(st.apply(&Event::Prepared(Box::new(blocked))).is_err());
    }
}
