//! Send and receive automata of the payment core (specification rev. 0.4,
//! sections 6-9; stages E3, E4, E5 and the status table of E7).
//!
//! Every change of state is an [`Event`] that is first committed to the
//! journal and only then applied to memory by the one function [`State::apply`];
//! opening a wallet replays the same events through the same function. What a
//! caller may show to the outside world (S1, S2, the signed transaction) is
//! returned only after the journal confirmed that the event is durable and
//! covered by the tail guard, and the signing code can only be reached with
//! that confirmation in hand.
//!
//! Chain facts (`chain_advance`, `chain_rollback`) are taken as already
//! verified by the caller (Level 5); this crate does not talk to any network.
//! The Grin chain type and fee base are process-wide settings of `grin_core`
//! and must be set by the application before use.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

pub mod migrate;
mod slates;
mod state;
pub mod trace;

pub use slates::{PaymentProof, MAX_SLATEPACK_LEN};
pub use state::{ChainState, Row, SendStatus};

use fly_paycore_keys::ledger::BranchState;
use fly_paycore_keys::path::KeyPath;
use fly_paycore_keys::scan;
use fly_paycore_store::{
    CommitError, Dir, Guard, GuardCheck, Identity, OpenError, RootKey, Sealed, Store, KIND_RECOVERY,
};
use grin_keychain::{ExtKeychain, Identifier, Keychain, SwitchCommitmentType};
use grin_util::secp::pedersen::{Commitment, RangeProof};
use sha2::{Digest, Sha256};
use state::{DraftRec, Event, FoundOut, SendRec, State};
use zeroize::Zeroizing;

/// Frame kind used for every event of this layer.
pub const KIND_EVENT: u8 = 0x20;
/// Reorg depth beyond which the wallet re-anchors (specification: `R_undo`).
pub const R_UNDO: u64 = 720;
/// Open receive drafts allowed at once.
pub const MAX_OPEN_DRAFTS: usize = 16;
/// Words in the check code of a contact (K199): 66 bits.
pub const CHECK_WORDS: usize = 6;
/// Lifetime of a receive draft in seconds of confirmed time (7 days).
pub const DRAFT_TTL_SECS: u64 = 7 * 24 * 3600;
/// Largest slate accepted, checked before parsing.
pub const MAX_SLATE_LEN: usize = 64 * 1024;
/// Contacts a wallet keeps; each has its own connection in the transport.
pub const MAX_CONTACTS: usize = 64;
/// Longest contact name, in bytes of UTF-8.
pub const MAX_CONTACT_NAME: usize = 64;
/// Public keys of replaced transport identities that are remembered.
pub const MAX_PREVIOUS_IDENTITIES: usize = 16;
/// Largest sealed delivery envelope kept with an operation.
pub const MAX_ENVELOPE_LEN: usize = 128 * 1024;
/// The first line of a text message in the mailbox: what follows is words
/// for a person, never a slate (K120).
pub const MESSAGE_PREFIX: &str = "GSTEXT1\n";
/// Longest text message, in bytes of UTF-8 (K122).
pub const MAX_MESSAGE_LEN: usize = 2000;
/// Messages kept per contact; the oldest goes first (K122).
pub const MAX_MESSAGES_PER_CONTACT: usize = 100;
/// Own messages to one contact that may wait for the relay at once (K121).
pub const MAX_WAITING_MESSAGES: usize = 100;

/// Identifier of a send operation (random, local).
pub type OpId = [u8; 16];
/// Slate UUID bytes.
pub type SlateId = [u8; 16];

/// Why the core refused. No variant carries key material.
#[derive(Debug, PartialEq, Eq)]
pub enum CoreError {
    /// The journal could not be opened or created.
    Open(String),
    /// A journal commit failed; see [`CommitError`].
    Commit(CommitError),
    /// Journal content does not follow the rules of this layer.
    Corrupt,
    /// The random generator of the operating system failed.
    Rng,
    /// A slate could not be parsed or does not pass validation.
    BadSlate(&'static str),
    /// The request is not allowed in the current state.
    Refused(&'static str),
    /// No such operation or draft.
    NotFound,
    /// A different S2 was already chosen for this operation, or a different
    /// S1 was already answered under this slate id.
    Conflict,
    /// The operation was armed for signing but no result was recorded: it is
    /// unknown whether a signature exists. Nothing is signed again.
    UnknownOutcome,
    /// Not enough spendable funds.
    InsufficientFunds,
    /// A cryptographic or transaction-building step failed.
    Build,
}

impl From<CommitError> for CoreError {
    fn from(e: CommitError) -> Self {
        CoreError::Commit(e)
    }
}
impl From<OpenError> for CoreError {
    fn from(e: OpenError) -> Self {
        CoreError::Open(format!("{:?}", e))
    }
}

/// What happened while opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenReport {
    /// Outcome of the tail-guard check.
    pub guard: GuardCheck,
    /// A rollback or move was detected: a new branch was opened and every
    /// operation that existed is locked against signing.
    pub recovered: bool,
}

/// One block's worth of verified facts.
#[derive(Clone, Debug, Default)]
pub struct Advance {
    /// Height of the block; must be the tip height plus one.
    pub height: u64,
    /// Hash of the block header.
    pub hash: [u8; 32],
    /// Every output the block adds, with its range proof, MMR position and
    /// whether it is a coinbase output.
    pub outputs: Vec<(Commitment, RangeProof, u64, bool)>,
    /// Every commitment the block spends.
    pub inputs: Vec<Commitment>,
    /// Excess of every kernel in the block.
    pub kernels: Vec<Commitment>,
    /// Opaque change of the verified state V for this block, stored in the
    /// same frame (specification 5.6).
    pub v_delta: Vec<u8>,
}

impl Advance {
    /// Add an output from plain bytes, as a chain layer outside this
    /// process hands them over. `false` if the range proof has no valid
    /// length; nothing is added then.
    pub fn push_output(&mut self, commit: &[u8; 33], proof: &[u8], pos: u64, coinbase: bool) -> bool {
        let mut bytes = [0u8; grin_util::secp::constants::MAX_PROOF_SIZE];
        let Some(slot) = bytes.get_mut(..proof.len()).filter(|_| !proof.is_empty()) else {
            return false;
        };
        slot.copy_from_slice(proof);
        let proof = RangeProof {
            proof: bytes,
            plen: proof.len(),
        };
        self.outputs.push((Commitment(*commit), proof, pos, coinbase));
        true
    }
    /// Add a spent commitment.
    pub fn push_input(&mut self, commit: &[u8; 33]) {
        self.inputs.push(Commitment(*commit));
    }
    /// Add the excess of a kernel.
    pub fn push_kernel(&mut self, excess: &[u8; 33]) {
        self.kernels.push(Commitment(*excess));
    }
}

/// One piece of the outputs that are older than the wallet's blocks, as the
/// chain layer handed it over (specification 7.19).
#[derive(Clone, Debug, Default)]
pub struct OldPiece {
    /// Number of the piece.
    pub piece: u64,
    /// Whether it is the last one.
    pub last: bool,
    /// How many pieces there are.
    pub pieces: u64,
    /// The height up to which the piece is complete.
    pub before: u64,
    /// The block after which the outputs of the piece are unspent: height
    /// and header hash.
    pub at: (u64, [u8; 32]),
    /// The outputs: commitment, range proof, MMR position, coinbase.
    pub outputs: Vec<(Commitment, RangeProof, u64, bool)>,
    /// For a piece that came without range proofs: what is unspent in it,
    /// commitment and MMR position. `outputs` is empty then. Only a
    /// search that began with a block the wallet knew its outputs up to
    /// takes such a piece.
    pub bare: Option<Vec<([u8; 33], u64)>>,
}

impl OldPiece {
    /// Add an output from plain bytes. `false` if the range proof has no
    /// valid length; nothing is added then.
    pub fn push_output(&mut self, commit: &[u8; 33], proof: &[u8], pos: u64, coinbase: bool) -> bool {
        let mut carrier = Advance::default();
        let pushed = carrier.push_output(commit, proof, pos, coinbase);
        self.outputs.append(&mut carrier.outputs);
        pushed
    }
}

/// Where the search for old outputs stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OldProgress {
    /// The piece to read next; `None` once every piece has been read.
    pub next: Option<u64>,
    /// How many pieces there were when the last one was read; 0 before
    /// the first.
    pub pieces: u64,
    /// Outputs the search has added to the wallet.
    pub found: u64,
    /// Outputs the wallet held that the search found spent.
    pub gone: u64,
    /// The block up to which the wallet knew every output of its own when
    /// the search began, if it did: height and header hash. The chain
    /// layer is asked with it, and may then give pieces without range
    /// proofs for what was there by that block.
    pub since: Option<(u64, [u8; 32])>,
}

/// An own output that no record of a payment stands for (K194).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unrecorded {
    /// Its commitment.
    pub commit: Vec<u8>,
    /// Its value, in nanogrin.
    pub value: u64,
    /// The block it was seen in; for one found by the search for old
    /// outputs (`old`), a block by which it existed.
    pub height: u64,
    /// Found by the search for old outputs, not in a block.
    pub old: bool,
    /// A block reward.
    pub coinbase: bool,
    /// The block that spent it, if it is spent.
    pub spent: Option<u64>,
}

/// Balance by category, in nanogrin.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Balance {
    /// Unspent, mature, not reserved.
    pub spendable: u64,
    /// Unspent but held by an operation in flight.
    pub reserved: u64,
    /// Unspent coinbase not yet mature.
    pub immature: u64,
    /// Unspent and marked "not to be spent" by the owner (K195): the
    /// wallet's own choice of inputs passes it by.
    pub kept: u64,
}


/// What seals a slate for a contact: gives the envelope, or says why not.
pub type Seal<'a> = &'a mut dyn FnMut(&[u8]) -> Result<Envelope, String>;
/// One unspent output of the wallet (K195).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnOutput {
    /// Its commitment.
    pub commit: Vec<u8>,
    /// Its value, in nanogrin.
    pub value: u64,
    /// The block it was seen in; found by the search for old outputs
    /// (`old`), a block by which it existed.
    pub height: u64,
    /// Found by the search for old outputs.
    pub old: bool,
    /// A block reward.
    pub coinbase: bool,
    /// Held by a payment under way.
    pub reserved: bool,
    /// A block reward that cannot be spent yet.
    pub immature: bool,
    /// Marked "not to be spent" by the owner.
    pub kept: bool,
}

/// Prepared send: what to hand to the recipient.
#[derive(Debug)]
pub struct Prepared {
    /// Local identifier of the operation.
    pub op: OpId,
    /// S1 as slate JSON (version 4).
    pub s1: Vec<u8>,
    /// Proof that the reservation and the signing context are durable.
    pub sealed: Sealed,
}

/// Finalized send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finalized {
    /// The transaction, Grin binary serialization.
    pub tx: Vec<u8>,
    /// S3 as slate JSON.
    pub s3: Vec<u8>,
    /// Kernel excess.
    pub excess: [u8; 33],
    /// The recipient's signed acknowledgement, if one was requested.
    pub payment_proof: Option<PaymentProof>,
}

/// The payment core of one wallet account.
pub struct Core<D: Dir, G: Guard, K: Keychain> {
    store: Store<D, G>,
    keychain: K,
    st: State,
    maturity: u64,
    signs: u64,
    timing: Timing,
    /// K196: how many of its smallest outputs a payment takes along on
    /// the owner's standing word; 0: none. In memory only.
    gather: usize,
}

/// Where the time of following the chain went since the journal was
/// opened. A measurement and nothing else: no decision reads it, it is not
/// written anywhere, and it says nothing about what the wallet holds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timing {
    /// Trying the wallet's keys on the range proofs of blocks and of pieces
    /// of old outputs.
    pub keys: std::time::Duration,
    /// Checking a chain event against the state before it is written.
    pub check: std::time::Duration,
    /// Writing chain events to the journal, the wait for the disk included.
    pub write: std::time::Duration,
    /// Taking a written chain event into the state.
    pub apply: std::time::Duration,
    /// Chain events written.
    pub events: u64,
}

fn random16() -> Result<[u8; 16], CoreError> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).map_err(|_| CoreError::Rng)?;
    Ok(b)
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

impl<D: Dir, G: Guard, K: Keychain> Core<D, G, K> {
    /// Create a wallet journal for `account` and open its first branch.
    /// `coinbase_maturity` is the network's value (mainnet 1440).
    pub fn create(
        dir: D,
        guard: G,
        root: &RootKey,
        id: Identity,
        keychain: K,
        account: u32,
        coinbase_maturity: u64,
    ) -> Result<Self, CoreError> {
        let store = Store::create(dir, guard, root, id)?;
        let mut core = Core {
            store,
            keychain,
            st: State::new(account),
            maturity: coinbase_maturity,
            signs: 0,
            timing: Timing::default(),
            gather: 0,
        };
        let branch = core.st.branch.fresh_branch().map_err(|_| CoreError::Rng)?;
        core.commit_sealed(Event::Init { account, branch })?;
        Ok(core)
    }

    /// Open a wallet journal and replay it.
    pub fn open(
        dir: D,
        guard: G,
        root: &RootKey,
        id: Identity,
        keychain: K,
        coinbase_maturity: u64,
    ) -> Result<(Self, OpenReport), CoreError> {
        let opened = Store::open(dir, guard, root, id)?;
        let mut st = match opened.snapshot {
            Some(s) => State::decode(&s)?,
            None => State::new(0),
        };
        for f in &opened.frames {
            if f.kind != KIND_EVENT && f.kind != KIND_RECOVERY {
                return Err(CoreError::Corrupt);
            }
            let ev = Event::decode(&f.body)?;
            st.apply(&ev)?;
        }
        let mut core = Core {
            store: opened.store,
            keychain,
            st,
            maturity: coinbase_maturity,
            signs: 0,
            timing: Timing::default(),
            gather: 0,
        };
        let recovered = opened.guard.recovery_required();
        if recovered {
            let branch = core.st.branch.fresh_branch().map_err(|_| CoreError::Rng)?;
            let ev = Event::Recovery { branch };
            let body = ev.encode()?;
            core.store.commit_recovery(&body)?;
            core.st.apply(&ev)?;
        } else if core.st.branch.current().is_none() {
            // creation did not get as far as its first frame
            let branch = core.st.branch.fresh_branch().map_err(|_| CoreError::Rng)?;
            let account = core.st.account;
            core.commit_sealed(Event::Init { account, branch })?;
        }
        if core.st.legacy_chain_evidence && core.st.old.is_some() && core.st.tip.is_some() {
            core.commit_plain(Event::ResetLegacyChainEvidence)?;
        }
        Ok((
            core,
            OpenReport {
                guard: opened.guard,
                recovered,
            },
        ))
    }

    /// Commit an event that unlocks a disclosure, then apply it.
    fn commit_sealed(&mut self, ev: Event) -> Result<Sealed, CoreError> {
        // reject before writing anything the state machine would not accept
        self.st.clone_check(&ev)?;
        let body = ev.encode()?;
        let sealed = self.store.commit_sealed(KIND_EVENT, &body)?;
        self.st.apply(&ev)?;
        Ok(sealed)
    }

    /// Commit an event that unlocks nothing, then apply it.
    fn commit_plain(&mut self, ev: Event) -> Result<(), CoreError> {
        let began = std::time::Instant::now();
        self.st.clone_check(&ev)?;
        let checked = std::time::Instant::now();
        let body = ev.encode()?;
        self.store.commit(KIND_EVENT, &body)?;
        let written = std::time::Instant::now();
        self.st.apply(&ev)?;
        let t = &mut self.timing;
        t.check = t.check.saturating_add(checked.saturating_duration_since(began));
        t.write = t.write.saturating_add(written.saturating_duration_since(checked));
        t.apply = t.apply.saturating_add(written.elapsed());
        t.events = t.events.saturating_add(1);
        Ok(())
    }

    /// Where the time of following the chain went; see [`Timing`].
    pub fn timing(&self) -> Timing {
        self.timing
    }

    /// Frames written since the last fold of the journal (5.5).
    pub fn journal_frames(&self) -> u64 {
        self.store.frames_in_generation()
    }

    /// Fold the journal into a snapshot. `v_snapshot` is the caller's opaque
    /// snapshot of the verified state V at the current tip; with it, the
    /// per-block changes of V kept so far are dropped. It is written in the
    /// same atomic step as the wallet state.
    pub fn checkpoint(&mut self, v_snapshot: Option<Vec<u8>>) -> Result<(), CoreError> {
        let mut next = self.st.clone();
        if let Some(v) = v_snapshot {
            let tip = next
                .tip
                .as_ref()
                .map(|t| t.0)
                .ok_or(CoreError::Refused("chain state unknown"))?;
            next.v_base = Some((tip, v));
            next.v_deltas.clear();
        }
        let snap = Zeroizing::new(next.encode()?);
        self.store.checkpoint(&snap)?;
        self.st = next;
        Ok(())
    }

    /// The stored snapshot of V (with its height) and the per-block changes
    /// recorded after it, oldest first.
    #[allow(clippy::type_complexity)]
    pub fn v_state(&self) -> (Option<(u64, &[u8])>, Vec<(u64, &[u8])>) {
        (
            self.st.v_base.as_ref().map(|(h, v)| (*h, v.as_slice())),
            self.st
                .v_deltas
                .iter()
                .map(|(h, d)| (*h, d.as_slice()))
                .collect(),
        )
    }

    fn account_id(&self) -> Identifier {
        ExtKeychain::derive_key_id(2, self.st.account, 0, 0, 0)
    }

    /// The x-only public key of a transport secret, if the secret is usable.
    fn transport_public(&self, secret: &[u8; 32]) -> Result<[u8; 32], CoreError> {
        use grin_util::secp::key::{PublicKey, SecretKey};
        let bad = CoreError::BadSlate("not a usable key");
        let secp = self.keychain.secp();
        let sk = SecretKey::from_slice(secp, secret).map_err(|_| CoreError::BadSlate("not a usable key"))?;
        let pk = PublicKey::from_secret_key(secp, &sk).map_err(|_| CoreError::BadSlate("not a usable key"))?;
        let bytes = pk.serialize_vec(secp, true);
        let x = bytes.get(1..33).ok_or(bad)?;
        <[u8; 32]>::try_from(x).map_err(|_| CoreError::BadSlate("not a usable key"))
    }

    /// Whether 32 bytes are the x-only form of a point on the curve.
    fn transport_key_valid(&self, key: &[u8; 32]) -> bool {
        let mut full = [2u8; 33];
        if let Some(tail) = full.get_mut(1..) {
            tail.copy_from_slice(key);
        }
        grin_util::secp::key::PublicKey::from_slice(self.keychain.secp(), &full).is_ok()
    }

    fn identity_set(&mut self, secret: &[u8; 32], imported: bool, replace: bool) -> Result<[u8; 32], CoreError> {
        let public = self.transport_public(secret)?;
        if self.st.identity.is_some() && !replace {
            return Err(CoreError::Refused("the wallet already has a transport identity"));
        }
        self.commit_plain(Event::IdentitySet {
            secret: state::Secret(secret.to_vec()),
            public: public.to_vec(),
            imported,
        })?;
        Ok(public)
    }

    /// Make a new transport identity: a random key that has nothing to do
    /// with the wallet seed. The seed cannot bring it back; its backup is
    /// [`Core::identity_secret`]. With `replace`, an existing identity is
    /// retired (its public key is remembered); without, it is an error to
    /// have one already. Refused while a delivered payment waits for its
    /// reply.
    pub fn identity_create(&mut self, replace: bool) -> Result<[u8; 32], CoreError> {
        let mut secret = Zeroizing::new([0u8; 32]);
        // a random 32-byte string is a valid key except with negligible odds
        for _ in 0..8 {
            getrandom::getrandom(secret.as_mut()).map_err(|_| CoreError::Rng)?;
            if self.transport_public(&secret).is_ok() {
                return self.identity_set(&secret, false, replace);
            }
        }
        Err(CoreError::Rng)
    }

    /// Take a transport identity the user brought (a backup, or one used in
    /// another wallet). Same rules as [`Core::identity_create`].
    pub fn identity_import(&mut self, secret: &[u8; 32], replace: bool) -> Result<[u8; 32], CoreError> {
        self.identity_set(secret, true, replace)
    }

    /// The transport identity, without its secret.
    pub fn identity(&self) -> Option<TransportIdentity> {
        let i = self.st.identity.as_ref()?;
        Some(TransportIdentity {
            public: <[u8; 32]>::try_from(i.public.as_slice()).ok()?,
            imported: i.imported,
            previous: i
                .previous
                .iter()
                .filter_map(|p| <[u8; 32]>::try_from(p.as_slice()).ok())
                .collect(),
        })
    }

    /// The secret of the transport identity: for the transport process, and
    /// for the user's backup. Whoever has it can read and send messages as
    /// this wallet; it moves no money.
    pub fn identity_secret(&self) -> Option<Zeroizing<[u8; 32]>> {
        let i = self.st.identity.as_ref()?;
        <[u8; 32]>::try_from(i.secret.0.as_slice()).ok().map(Zeroizing::new)
    }

    /// Key under which the transport keeps its own files. Follows the
    /// identity: a new identity cannot read what the old one stored.
    pub fn transport_store_key(&self) -> Option<Zeroizing<[u8; 32]>> {
        use sha2::{Digest, Sha256};
        let secret = self.identity_secret()?;
        let mut h = Sha256::new();
        h.update(b"GrinSight Fly transport store key v1");
        h.update(secret.as_ref());
        Some(Zeroizing::new(h.finalize().into()))
    }

    /// Add a contact or change its name and address.
    pub fn contact_set(&mut self, key: [u8; 32], name: &str, address: Option<[u8; 32]>) -> Result<(), CoreError> {
        if !self.transport_key_valid(&key) {
            return Err(CoreError::Refused("contact is not usable"));
        }
        if let Some(a) = &address {
            if ed25519_dalek::VerifyingKey::from_bytes(a).is_err() {
                return Err(CoreError::Refused("contact is not usable"));
            }
        }
        self.commit_plain(Event::ContactSet {
            key: key.to_vec(),
            name: name.to_string(),
            address: address.map(|a| a.to_vec()),
        })
    }

    /// K199: the check code of this wallet and a contact - six words that
    /// are the same in both wallets when each has the other's message key
    /// and address right, and differ when anything of the four was
    /// swapped on the way. Made from public keys only; it is no secret
    /// and proves nothing by itself: the two compare it over a channel
    /// of their own. Reads only.
    pub fn contact_code(&self, key: &[u8; 32]) -> Result<Vec<String>, CoreError> {
        use sha2::Digest;
        let own = self.st.identity.as_ref().ok_or(CoreError::Refused("the wallet has no transport identity"))?;
        let c = self.st.contacts.get(&state::hex(key)).ok_or(CoreError::NotFound)?;
        let theirs = c.address.as_ref().ok_or(CoreError::Refused("the contact has no address to check"))?;
        let mine = self.receive_address()?;
        // each side: its message key, then its address; the two sides in
        // one order whoever computes, so that both get the same words
        let mut sides = [[own.public.as_slice(), mine.as_slice()].concat(), [c.key.as_slice(), theirs.as_slice()].concat()];
        sides.sort();
        let mut hash = sha2::Sha256::new();
        hash.update(b"GrinSight contact check v1");
        for side in &sides {
            hash.update(side);
        }
        let digest = hash.finalize();
        // six words of eleven bits each, from the first 66 bits
        let mut bits = digest.iter().flat_map(|byte| (0..8u32).rev().map(move |bit| (byte >> bit) & 1));
        let mut words = Vec::with_capacity(CHECK_WORDS);
        for _ in 0..CHECK_WORDS {
            let mut index = 0usize;
            for _ in 0..11 {
                index = (index << 1) | usize::from(bits.next().ok_or(CoreError::Build)?);
            }
            words.push(grin_keychain::mnemonic::WORDS.get(index).ok_or(CoreError::Build)?.clone());
        }
        Ok(words)
    }

    /// K199: set or take off the owner's mark that the check code of a
    /// contact was compared and was the same. Durable. It is taken off by
    /// the wallet itself when the contact's address is changed.
    pub fn contact_check(&mut self, key: &[u8; 32], on: bool) -> Result<(), CoreError> {
        let now = self.st.contacts.get(&state::hex(key)).ok_or(CoreError::NotFound)?.checked;
        if now == on {
            return Ok(());
        }
        self.commit_plain(Event::ContactChecked { key: key.to_vec(), on })
    }

    /// Remove a contact. Refused while a payment delivered to it waits for
    /// its reply.
    pub fn contact_remove(&mut self, key: &[u8; 32]) -> Result<(), CoreError> {
        self.commit_plain(Event::ContactRemoved { key: key.to_vec() })
    }

    /// The contacts, by name.
    pub fn contacts(&self) -> Vec<Contact> {
        let mut out: Vec<Contact> = self
            .st
            .contacts
            .values()
            .filter_map(|c| {
                Some(Contact {
                    key: <[u8; 32]>::try_from(c.key.as_slice()).ok()?,
                    name: c.name.clone(),
                    address: match &c.address {
                        None => None,
                        Some(a) => Some(<[u8; 32]>::try_from(a.as_slice()).ok()?),
                    },
                    checked: c.checked,
                })
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name).then(a.key.cmp(&b.key)));
        out
    }

    /// Send a text message to a contact (K121): the text is sealed for the
    /// contact without the network and written to the journal with its
    /// envelope in one frame; the delivery round publishes it. Returns the
    /// message id. `at` is the sender's clock, for showing only.
    pub fn message_send(
        &mut self,
        to: [u8; 32],
        text: &str,
        at: u64,
        seal: &mut dyn FnMut(&str) -> Result<Envelope, String>,
    ) -> Result<[u8; 32], CoreError> {
        if self.st.identity.is_none() {
            return Err(CoreError::Refused("the wallet has no transport identity"));
        }
        if !self.st.contacts.contains_key(&state::hex(&to)) {
            return Err(CoreError::Refused("not a contact"));
        }
        if text.is_empty() || text.len() > MAX_MESSAGE_LEN {
            return Err(CoreError::Refused("message is not usable"));
        }
        let waiting = self
            .st
            .conversations
            .0
            .get(&state::hex(&to))
            .map_or(0, |list| list.iter().filter(|m| m.waiting()).count());
        if waiting >= MAX_WAITING_MESSAGES {
            return Err(CoreError::Refused("too many messages are waiting for this contact"));
        }
        let wire = format!("{MESSAGE_PREFIX}{text}");
        let envelope = seal(&wire).map_err(|_| CoreError::Refused("the transport cannot seal now"))?;
        self.commit_plain(Event::MessageOut {
            id: envelope.event_id.to_vec(),
            to: to.to_vec(),
            at,
            text: text.to_string(),
            envelope: envelope.bytes,
            expires_at: envelope.expires_at,
        })?;
        Ok(envelope.event_id)
    }

    /// Keep a text message that came from a contact (K120). `text` is the
    /// message without [`MESSAGE_PREFIX`]. `Ok(false)`: it is kept already
    /// (the transport offered it again). Written before the transport may
    /// forget it.
    pub fn message_received(&mut self, from: [u8; 32], id: [u8; 32], text: &str, at: u64) -> Result<bool, CoreError> {
        match self.commit_plain(Event::MessageIn {
            id: id.to_vec(),
            from: from.to_vec(),
            at,
            text: text.to_string(),
        }) {
            Ok(()) => Ok(true),
            Err(CoreError::Conflict) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Outgoing messages whose envelope still waits for a relay.
    pub fn message_pending(&self) -> Vec<[u8; 32]> {
        self.st
            .conversations
            .0
            .values()
            .flatten()
            .filter(|m| m.out && m.state == 0 && m.envelope.is_some())
            .filter_map(|m| <[u8; 32]>::try_from(m.id.as_slice()).ok())
            .collect()
    }

    /// The stored envelope of an outgoing message, to publish byte for byte.
    pub fn message_envelope(&self, id: &[u8; 32]) -> Option<Envelope> {
        let (_, m) = self.st.conversations.find(id)?;
        Some(Envelope {
            event_id: *id,
            bytes: m.envelope.clone()?,
            expires_at: m.expires_at,
        })
    }

    /// A relay accepted the message (`accepted`), or its window closed.
    /// Written once; the envelope is dropped.
    pub fn message_note(&mut self, id: &[u8; 32], accepted: bool) -> Result<(), CoreError> {
        self.commit_plain(Event::MessageNote {
            id: id.to_vec(),
            what: if accepted { 1 } else { 2 },
        })
    }

    /// The conversation with a contact, oldest first.
    pub fn messages(&self, with: &[u8; 32]) -> Vec<Message> {
        self.st
            .conversations
            .0
            .get(&state::hex(with))
            .map(|list| {
                list.iter()
                    .filter_map(|m| {
                        Some(Message {
                            id: <[u8; 32]>::try_from(m.id.as_slice()).ok()?,
                            out: m.out,
                            at: m.at,
                            text: m.text.clone(),
                            state: match (m.out, m.state) {
                                (false, _) => MessageState::Received,
                                (true, 1) => MessageState::RelayAccepted,
                                (true, 2) => MessageState::Expired,
                                (true, _) => MessageState::Waiting,
                            },
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// For each contact with a conversation: how many messages, and the
    /// newest one's time and direction.
    pub fn conversations(&self) -> Vec<([u8; 32], usize, u64, bool)> {
        self.st
            .conversations
            .0
            .iter()
            .filter_map(|(k, list)| {
                let key = <[u8; 32]>::try_from(self.st.contacts.get(k)?.key.as_slice()).ok()?;
                let last = list.last()?;
                Some((key, list.len(), last.at, last.out))
            })
            .collect()
    }

    /// The secret behind the receive address. Lives only for one call.
    fn address_secret(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, CoreError> {
        let sec = grin_wallet_libwallet::address::address_from_derivation_path(
            &self.keychain,
            &self.account_id(),
            0,
        )
        .map_err(|_| CoreError::Build)?;
        Ok(zeroize::Zeroizing::new(sec.0))
    }

    /// Secret key of the receive address, for the one process that runs the
    /// onion service of that address: Tor announces a service only with
    /// the key that names it. Whoever holds it can also read Slatepack text
    /// encrypted for the address and sign as the address in a payment
    /// proof; it cannot spend. The host passes it to that process and
    /// nowhere else.
    pub fn address_secret_for_onion(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, CoreError> {
        self.address_secret()
    }

    /// Slatepack text as slate JSON. Plain packs and packs encrypted for
    /// this wallet's address are read; anything else is refused. Signs
    /// nothing and writes nothing.
    pub fn slatepack_decode(&self, text: &str) -> Result<Vec<u8>, CoreError> {
        if text.len() > MAX_SLATEPACK_LEN.saturating_mul(2) {
            return Err(CoreError::BadSlate("too large"));
        }
        let secret = self.address_secret()?;
        let key = ed25519_dalek::SigningKey::from_bytes(&secret);
        slates::slatepack_decode(text, Some(&key))
    }

    /// Slate JSON as Slatepack text encrypted for `address`, naming this
    /// wallet's address as the sender.
    pub fn slatepack_encode_for(
        &self,
        slate: &[u8],
        address: [u8; 32],
    ) -> Result<String, CoreError> {
        slates::slatepack_encode(slate, Some(self.receive_address()?), Some(address))
    }

    /// Public key of the account's receive address (index 0), as used in
    /// Slatepack addresses and payment proofs.
    pub fn receive_address(&self) -> Result<[u8; 32], CoreError> {
        let sec = grin_wallet_libwallet::address::address_from_derivation_path(
            &self.keychain,
            &self.account_id(),
            0,
        )
        .map_err(|_| CoreError::Build)?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&sec.0)
            .verifying_key()
            .to_bytes())
    }

    /// Number of signatures made by this process (for tests of invariant K1).
    pub fn signatures_made(&self) -> u64 {
        self.signs
    }

    /// Journal tail (for tests of invariant K8).
    pub fn journal_tail(&self) -> fly_paycore_store::GuardValue {
        self.store.tail()
    }

    /// Branch state.
    pub fn branches(&self) -> &BranchState {
        &self.st.branch
    }

    /// Current tip height known to the wallet.
    pub fn tip_height(&self) -> Option<u64> {
        self.st.tip.as_ref().map(|t| t.0)
    }

    /// The block the wallet stands at: height and header hash.
    pub fn tip(&self) -> Option<(u64, [u8; 32])> {
        let (height, hash) = self.st.tip.as_ref()?;
        Some((*height, <[u8; 32]>::try_from(hash.as_slice()).ok()?))
    }

    // ----- chain facts ---------------------------------------------------

    /// Apply one verified block. Own outputs are found by rewinding every
    /// range proof with the wallet seed.
    pub fn chain_advance(&mut self, a: &Advance) -> Result<(), CoreError> {
        let began = std::time::Instant::now();
        let mut found = Vec::new();
        for (commit, proof, pos, coinbase) in &a.outputs {
            if let Some(f) =
                scan::rewind(&self.keychain, *commit, *proof).map_err(|_| CoreError::Build)?
            {
                found.push(FoundOut {
                    commit: commit.0.to_vec(),
                    key_id: f.key_id.to_bytes().to_vec(),
                    value: f.amount,
                    coinbase: *coinbase,
                    pos: *pos,
                });
            }
        }
        self.timing.keys = self.timing.keys.saturating_add(began.elapsed());
        self.commit_plain(Event::Advance {
            height: a.height,
            hash: a.hash.to_vec(),
            found,
            spent: a.inputs.iter().map(|c| c.0.to_vec()).collect(),
            kernels: a.kernels.iter().map(|c| c.0.to_vec()).collect(),
            v_delta: a.v_delta.clone(),
        })
    }

    /// Undo every block above `height` (a reorg of at most [`R_UNDO`] blocks).
    pub fn chain_rollback(&mut self, height: u64) -> Result<(), CoreError> {
        self.commit_plain(Event::Rollback { height })
    }

    /// Start over from a new anchor after a reorg deeper than [`R_UNDO`] or a
    /// gap in the verified bodies. Automatic binding of records made before
    /// `height` is no longer possible.
    ///
    /// With no proof that the old position is on this chain, restart
    /// the complete search. Local signatures and input reservations survive.
    pub fn chain_reanchor(&mut self, height: u64, hash: [u8; 32]) -> Result<(), CoreError> {
        self.commit_plain(Event::Reanchor {
            height, hash: hash.to_vec(), since: None, extends: Some(false),
        })
    }

    /// Re-anchor after the chain layer proved the previous wallet (height,
    /// hash) is an ancestor of this strictly newer archive header.
    pub fn chain_reanchor_extending(&mut self, height: u64, hash: [u8; 32]) -> Result<(), CoreError> {
        if !self.st.tip.as_ref().is_some_and(|(old, _)| *old < height) {
            return Err(CoreError::Refused("archive does not extend the previous position"));
        }
        self.commit_plain(Event::Reanchor {
            height, hash: hash.to_vec(), since: self.st.known_up_to(), extends: Some(true),
        })
    }

    // ----- old outputs --------------------------------------------------

    /// Start the search for outputs older than the wallet's blocks, from
    /// the first piece: for a wallet made from an existing seed, and
    /// whenever the user asks.
    pub fn old_search_start(&mut self) -> Result<(), CoreError> {
        self.commit_plain(Event::OldSearch {})
    }

    /// Where the search stands; `None` if none was ever asked for.
    pub fn old_search(&self) -> Option<OldProgress> {
        self.st.old.as_ref().map(|s| OldProgress {
            next: s.next,
            pieces: s.pieces,
            found: s.found,
            gone: s.gone,
            since: s.since.as_ref().and_then(|(height, hash)| Some((*height, <[u8; 32]>::try_from(hash.as_slice()).ok()?))),
        })
    }

    /// Take one piece of the old outputs. Own outputs are found by
    /// rewinding every range proof with the wallet seed. Returns how many
    /// of the outputs in the piece are the wallet's.
    ///
    /// In a piece without range proofs nothing can be found that way: the
    /// wallet looks its known outputs up in it. Such a piece is refused
    /// by a search for everything - it would read as "nothing of mine
    /// here" where nothing was looked for.
    pub fn old_apply(&mut self, p: &OldPiece) -> Result<usize, CoreError> {
        let began = std::time::Instant::now();
        let mut found = Vec::new();
        if let Some(bare) = &p.bare {
            if !p.outputs.is_empty() {
                return Err(CoreError::Refused("a piece without range proofs that has some"));
            }
            if !self.st.old.as_ref().is_some_and(|search| search.since.is_some()) {
                return Err(CoreError::Refused("a piece without range proofs in a search for everything"));
            }
            for (commit, pos) in bare {
                if let Some(known) = self.st.known_output(commit) {
                    found.push(FoundOut {
                        commit: commit.to_vec(),
                        key_id: known.key_id.clone(),
                        value: known.value,
                        coinbase: known.coinbase,
                        pos: *pos,
                    });
                }
            }
        }
        for (commit, proof, pos, coinbase) in &p.outputs {
            if let Some(f) = scan::rewind(&self.keychain, *commit, *proof).map_err(|_| CoreError::Build)? {
                found.push(FoundOut {
                    commit: commit.0.to_vec(),
                    key_id: f.key_id.to_bytes().to_vec(),
                    value: f.amount,
                    coinbase: *coinbase,
                    pos: *pos,
                });
            }
        }
        let own = found.len();
        self.timing.keys = self.timing.keys.saturating_add(began.elapsed());
        self.commit_plain(Event::Old {
            piece: p.piece,
            last: p.last,
            pieces: p.pieces,
            before: p.before,
            at_height: p.at.0,
            at_hash: p.at.1.to_vec(),
            found,
        })?;
        Ok(own)
    }

    /// Balance by category.
    pub fn balance(&self) -> Balance {
        self.st.balance(self.maturity)
    }

    // ----- sending -------------------------------------------------------

    /// Reserve inputs, build S1 and make both durable. `replaces` names a
    /// contested operation this payment repeats; the new transaction then
    /// spends one of its inputs so that at most one of the two can execute.
    /// While a contested operation exists, an unrelated send needs
    /// `not_a_repeat = true` (the user's explicit confirmation).
    pub fn send_prepare(
        &mut self,
        amount: u64,
        ttl_cutoff_height: u64,
        replaces: Option<OpId>,
        not_a_repeat: bool,
    ) -> Result<Prepared, CoreError> {
        self.prepare(
            amount,
            ttl_cutoff_height,
            How {
                replaces,
                not_a_repeat,
                ..How::default()
            },
        )
    }

    /// K195: like [`Core::send_prepare`] for a new payment, paid with
    /// exactly the outputs the owner chose - by hand, or to the contact
    /// `to` when `seal` is given, with a payment proof asked of
    /// `proof_to` if one is named. `spend_kept`: the owner's separate word
    /// that an output marked "not to be spent" among them is spent this once.
    pub fn send_prepare_chosen(
        &mut self,
        amount: u64,
        ttl_cutoff_height: u64,
        chosen: Vec<[u8; 33]>,
        spend_kept: bool,
        proof_to: Option<[u8; 32]>,
        delivery: Option<([u8; 32], Seal<'_>)>,
    ) -> Result<Prepared, CoreError> {
        if self.st.any_contested() {
            return Err(CoreError::Refused("a contested operation exists: replace it or confirm this is not a repeat"));
        }
        let seal = match delivery {
            Some((contact, seal)) => {
                if self.st.identity.is_none() {
                    return Err(CoreError::Refused("the wallet has no transport identity"));
                }
                if !self.st.contacts.contains_key(&state::hex(&contact)) {
                    return Err(CoreError::Refused("the recipient is not a contact"));
                }
                Some((contact, seal))
            }
            None => None,
        };
        self.prepare(amount, ttl_cutoff_height, How { chosen: Some((chosen, spend_kept)), proof_to, seal, ..How::default() })
    }

    /// K196: what collecting would come to - the amount of the one output,
    /// the fee and how many outputs are spent. Reads only.
    pub fn collect_plan(&self, chosen: Option<&[[u8; 33]]>, most: usize) -> Result<(u64, u64, usize), CoreError> {
        let (commits, amount, fee) = self.st.collect_plan(chosen, self.maturity, most)?;
        Ok((amount, fee, commits.len()))
    }

    /// K196: prepare the payment to this wallet itself that turns several
    /// of its outputs into one: the outputs named, or - with none named -
    /// those the wallet could spend by its own choice, the smallest first,
    /// `most` at most. The amount is all they hold less the fee, so there
    /// is no change. The wallet answers it itself (`receive_draft`) and
    /// signs it as any payment. Gives the prepared payment, its amount,
    /// its fee and how many outputs it spends.
    pub fn collect_prepare(&mut self, chosen: Option<Vec<[u8; 33]>>, spend_kept: bool, most: usize) -> Result<(Prepared, u64, u64, usize), CoreError> {
        if self.st.any_contested() {
            return Err(CoreError::Refused("a contested operation exists: replace it or confirm this is not a repeat"));
        }
        let (commits, amount, fee) = self.st.collect_plan(chosen.as_deref(), self.maturity, most)?;
        let count = commits.len();
        let prepared = self.prepare(amount, 0, How { chosen: Some((commits, spend_kept)), ..How::default() })?;
        Ok((prepared, amount, fee, count))
    }

    /// K197: what taking a signed payment back would come to: the amount
    /// that returns in one output, the fee, how many outputs are spent.
    /// Reads only.
    pub fn take_back_plan(&self, op: &OpId) -> Result<(u64, u64, usize), CoreError> {
        let (commits, amount, fee) = self.st.take_back_plan(op)?;
        Ok((amount, fee, commits.len()))
    }

    /// K197: prepare the taking back of a signed payment that is in no
    /// block: a payment of the wallet to itself that spends every input
    /// of that payment, so that only one of the two can be in a block.
    /// The wallet answers and signs it as any payment. Nothing is sure:
    /// the first payment may reach a block all the same.
    pub fn take_back_prepare(&mut self, op: &OpId) -> Result<(Prepared, u64, u64, usize), CoreError> {
        let (commits, amount, fee) = self.st.take_back_plan(op)?;
        let count = commits.len();
        // what the payment holds is spent whatever its marks say
        let prepared = self.prepare(amount, 0, How { chosen: Some((commits, true)), replaces: Some(*op), take_back: true, ..How::default() })?;
        Ok((prepared, amount, fee, count))
    }

    /// K198: the owner agrees that this one signed payment may go to the
    /// network from this device's own address when Tor fails to send it.
    /// Written with the payment: it outlives a restart. Said again, it
    /// writes nothing.
    pub fn send_agree_direct(&mut self, op: &OpId) -> Result<(), CoreError> {
        if self.send_direct(op) {
            return Ok(());
        }
        self.commit_plain(Event::Direct { op: *op })
    }

    /// K198: whether the owner agreed to the direct way for this payment.
    pub fn send_direct(&self, op: &OpId) -> bool {
        self.st.sends.get(&state::hex(op)).is_some_and(|s| s.direct)
    }

    /// K197: the payment under way that replaces this one.
    pub fn send_replaced_by(&self, op: &OpId) -> Option<OpId> {
        self.st.replaced_by(op)
    }

    /// The payment this one replaces.
    pub fn send_replaces(&self, op: &OpId) -> Option<OpId> {
        self.st.sends.get(&state::hex(op))?.replaces
    }

    /// K196: the owner's standing word that a payment takes up to `most`
    /// of the wallet's smallest outputs along (0: none). Not written: the
    /// one who starts the wallet says it again.
    pub fn set_gather(&mut self, most: usize) {
        self.gather = most;
    }

    /// K196: whether payments take small outputs along now.
    pub fn gathers(&self) -> bool {
        self.gather > 0
    }

    /// K195: the wallet's unspent outputs, the largest first. Reads only.
    pub fn outputs(&self) -> Vec<OwnOutput> {
        self.st
            .unspent_outputs(self.maturity)
            .into_iter()
            .map(|(o, reserved, immature, kept)| OwnOutput { commit: o.commit.clone(), value: o.value, height: o.height, old: o.old, coinbase: o.coinbase, reserved, immature, kept })
            .collect()
    }

    /// K195: set or take off the owner's mark "not to be spent" on an
    /// unspent output of this wallet. Durable: it outlives a restart.
    pub fn output_keep(&mut self, commit: &[u8; 33], on: bool) -> Result<(), CoreError> {
        if self.st.is_kept(commit) == on {
            return Ok(());
        }
        // whether the output is there to be marked is decided where the
        // event is applied; a refusal there writes nothing
        self.commit_plain(Event::Keep { commit: commit.to_vec(), on })
    }

    /// Late lock: build S1 without reserving anything. Inputs, change and the
    /// change path are chosen when the reply is finalized and become durable
    /// in the arming frame, before the signature. The fee is fixed now; if it
    /// no longer pays for the transaction then, finalizing is refused and
    /// nothing is signed. Not available while a contested operation exists.
    pub fn send_prepare_late(
        &mut self,
        amount: u64,
        ttl_cutoff_height: u64,
        recipient_address: Option<[u8; 32]>,
    ) -> Result<Prepared, CoreError> {
        if self.st.any_contested() {
            return Err(CoreError::Refused("a contested operation exists"));
        }
        self.prepare(
            amount,
            ttl_cutoff_height,
            How {
                proof_to: recipient_address,
                late: true,
                ..How::default()
            },
        )
    }

    /// Like [`Core::send_prepare`], and ask the recipient at `recipient_address`
    /// (ed25519 key of its Slatepack address) for a signed payment proof. The
    /// proof is verified before anything is signed and returned with the result.
    pub fn send_prepare_with_proof(
        &mut self,
        amount: u64,
        ttl_cutoff_height: u64,
        recipient_address: [u8; 32],
    ) -> Result<Prepared, CoreError> {
        self.prepare(
            amount,
            ttl_cutoff_height,
            How {
                proof_to: Some(recipient_address),
                ..How::default()
            },
        )
    }

    /// A gap in the wallet search may hide a spend of an otherwise selectable output.
    fn require_complete_for_spend(&self) -> Result<(), CoreError> {
        if self.st.old.as_ref().is_some_and(|search| search.next.is_some()) {
            return Err(CoreError::Refused("the search for old outputs is not over"));
        }
        Ok(())
    }

    fn prepare(
        &mut self,
        amount: u64,
        ttl_cutoff_height: u64,
        how: How<'_>,
    ) -> Result<Prepared, CoreError> {
        let How {
            chosen,
            replaces,
            take_back,
            not_a_repeat,
            proof_to,
            late,
            seal,
        } = how;
        if amount == 0 {
            return Err(CoreError::Refused("amount must be positive"));
        }
        let (tip, _) = self
            .st
            .tip
            .clone()
            .ok_or(CoreError::Refused("chain state unknown"))?;
        self.require_complete_for_spend()?;
        if ttl_cutoff_height != 0 && tip >= ttl_cutoff_height {
            return Err(CoreError::Refused("time-to-live already passed"));
        }
        match replaces {
            // taking back has made its own checks (`take_back_plan`)
            Some(_) if take_back => {}
            Some(old) => {
                if self.st.send_status(&old) != Some(SendStatus::Contested) {
                    return Err(CoreError::Refused(
                        "only a contested operation can be replaced",
                    ));
                }
            }
            None => {
                if self.st.any_contested() && !not_a_repeat {
                    return Err(CoreError::Refused(
                        "a contested operation exists: replace it or confirm this is not a repeat",
                    ));
                }
            }
        }
        let (branch, index) = self
            .st
            .branch
            .peek()
            .ok_or(CoreError::Refused("branch exhausted"))?;
        let change_path = KeyPath::Branch {
            account: self.st.account,
            branch,
            index,
        };
        let mut picked = match &chosen {
            Some((commits, spend_kept)) => self.st.select_chosen(amount, commits, *spend_kept, self.maturity, replaces.as_ref().filter(|_| take_back))?,
            None => self.st.select_inputs(amount, replaces.as_ref(), self.maturity)?,
        };
        // K196: only the wallet's own choice for a new, ordinary payment
        // takes small outputs along - not the owner's choice, not a late
        // lock, not the replacement of a contested payment
        if chosen.is_none() && !late && replaces.is_none() {
            self.st.gather_small(&mut picked, amount, self.maturity, self.gather)?;
        }
        if late {
            // only the fee estimate is kept; nothing is reserved
            picked.inputs.clear();
            picked.change = 0;
        }
        let (branch, index) = if late { (0, 0) } else { (branch, index) };
        let op = random16()?;
        let built = slates::build_s1(
            &self.keychain,
            &self.account_id(),
            amount,
            ttl_cutoff_height,
            &picked,
            &change_path.to_identifier(),
            tip,
            proof_to,
        )?;
        // the envelope is sealed from the S1 in memory and becomes durable in
        // the same frame as the operation and its reserve
        let delivery = match seal {
            None => None,
            Some((contact, seal)) => {
                let env = seal(&built.s1).map_err(|_| {
                    CoreError::Refused("the transport could not seal the envelope")
                })?;
                if env.bytes.is_empty() || env.bytes.len() > MAX_ENVELOPE_LEN {
                    return Err(CoreError::Refused("envelope size is out of range"));
                }
                Some(state::DeliveryRec {
                    contact: contact.to_vec(),
                    event_id: env.event_id.to_vec(),
                    envelope: env.bytes,
                    expires_at: env.expires_at,
                    unknown: 0,
                    accepted: 0,
                    expired: false,
                    last: 0,
                })
            }
        };
        let rec = SendRec {
            op,
            slate_id: built.slate_id,
            s1: built.s1.clone(),
            ctx: built.context.to_vec(),
            inputs: picked.inputs.iter().map(|i| i.commit.clone()).collect(),
            change: built.change,
            amount,
            fee: picked.fee,
            r_height: tip,
            binding_interrupted: false,
            replaces,
            branch,
            index,
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
            delivery,
            armed_sel: None,
            held: None,
            by_search: false,
            released: false,
            direct: false,
        };
        let sealed = self.commit_sealed(Event::Prepared(Box::new(rec)))?;
        Ok(Prepared {
            op,
            s1: built.s1,
            sealed,
        })
    }

    /// Prepare a send whose S1 travels by itself (automatic delivery).
    /// `seal` turns the S1 into the envelope for `contact`; the envelope is
    /// written in the same frame as the operation and its reserve, and can be
    /// read back with [`Core::delivery_envelope`] only after that frame is
    /// durable. Nothing may be published from the closure itself.
    pub fn send_prepare_delivery(
        &mut self,
        amount: u64,
        ttl_cutoff_height: u64,
        proof_to: Option<[u8; 32]>,
        late: bool,
        contact: [u8; 32],
        seal: &mut dyn FnMut(&[u8]) -> Result<Envelope, String>,
    ) -> Result<Prepared, CoreError> {
        if late && self.st.any_contested() {
            return Err(CoreError::Refused("a contested operation exists"));
        }
        // before a slate exists or the transport is asked for anything
        if self.st.identity.is_none() {
            return Err(CoreError::Refused("the wallet has no transport identity"));
        }
        if !self.st.contacts.contains_key(&state::hex(&contact)) {
            return Err(CoreError::Refused("the recipient is not a contact"));
        }
        self.prepare(
            amount,
            ttl_cutoff_height,
            How {
                proof_to,
                late,
                seal: Some((contact, seal)),
                ..How::default()
            },
        )
    }

    /// The envelope to publish for an operation, exactly as stored. `None`
    /// once the operation is cancelled, locked, answered, or its delivery
    /// window is closed: nothing more may be published for it.
    pub fn delivery_envelope(&self, op: &OpId) -> Option<Envelope> {
        let s = self.st.sends.get(&state::hex(op))?;
        let d = s.delivery.as_ref()?;
        if self.st.send_status(op)? != SendStatus::Prepared
            || s.locked
            || d.expired
            || s.held.is_some()
        {
            return None;
        }
        // from the cut-off height on, a reply could not be signed any more
        let ttl = slates::s1_ttl(&s.s1).ok()?;
        if ttl > 0 && self.st.tip.as_ref().is_some_and(|(tip, _)| *tip >= ttl) {
            return None;
        }
        Some(Envelope {
            event_id: <[u8; 32]>::try_from(d.event_id.as_slice()).ok()?,
            bytes: d.envelope.clone(),
            expires_at: d.expires_at,
        })
    }

    /// Operations whose envelope still waits for a relay to accept it.
    pub fn delivery_pending(&self) -> Vec<OpId> {
        self.st
            .sends
            .values()
            .filter(|s| s.delivery.as_ref().is_some_and(|d| d.accepted == 0))
            .filter(|s| self.delivery_envelope(&s.op).is_some())
            .map(|s| s.op)
            .collect()
    }

    /// Record what happened to a publication. Changes no reserve and no
    /// signing right; a relay's answer says nothing about the payment.
    pub fn delivery_note(&mut self, op: &OpId, note: DeliveryNote) -> Result<(), CoreError> {
        let what = match note {
            DeliveryNote::RelayUnknown => 1,
            DeliveryNote::RelayAccepted => 2,
            DeliveryNote::Expired => 3,
            DeliveryNote::QueueBusy => 4,
            DeliveryNote::QueueFull => 5,
        };
        let d = self
            .st
            .sends
            .get(&state::hex(op))
            .ok_or(CoreError::NotFound)?
            .delivery
            .as_ref()
            .ok_or(CoreError::Refused("operation has no delivery"))?;
        // a note that changes nothing is not worth a frame
        let idle = match what {
            3 => d.expired,
            1 | 4 | 5 => d.last == what,
            _ => false,
        };
        if idle {
            return Ok(());
        }
        self.commit_plain(Event::Delivery { op: *op, what })
    }

    /// Delivery state of an operation, if it has automatic delivery.
    pub fn delivery_status(&self, op: &OpId) -> Option<DeliveryStatus> {
        let d = self.st.sends.get(&state::hex(op))?.delivery.as_ref()?;
        Some(if d.expired {
            DeliveryStatus::Expired
        } else if d.accepted > 0 {
            DeliveryStatus::RelayAccepted
        } else if d.last == 4 {
            DeliveryStatus::QueueBusy
        } else if d.last == 5 {
            DeliveryStatus::QueueFull
        } else if d.unknown > 0 {
            DeliveryStatus::WaitingRelay
        } else {
            DeliveryStatus::Queued
        })
    }

    /// Find the open operation an incoming S2 answers. The reply must carry
    /// the slate id of an operation that is still open and, for a delivered
    /// operation, come from the contact it was sent to. Reads only.
    pub fn send_find_for_reply(&self, s2: &[u8], from: &[u8; 32]) -> Result<OpId, CoreError> {
        let slate_id = slates::slate_id_of(s2)?;
        let s = self
            .st
            .sends
            .values()
            .find(|s| s.slate_id == slate_id && !s.invoice)
            .ok_or(CoreError::NotFound)?;
        if let Some(d) = &s.delivery {
            if d.contact.as_slice() != from.as_slice() {
                return Err(CoreError::Refused(
                    "reply does not come from the recipient",
                ));
            }
        }
        match self.st.send_status(&s.op) {
            Some(SendStatus::Prepared) if !s.locked => Ok(s.op),
            Some(SendStatus::Cancelled | SendStatus::Released) => {
                Err(CoreError::Refused("operation was cancelled"))
            }
            Some(SendStatus::Prepared) => Err(CoreError::Refused(
                "operation is locked after a detected rollback",
            )),
            Some(_) => match &s.armed {
                Some(chosen) if sha(chosen) == sha(s2) => Ok(s.op),
                _ => Err(CoreError::Conflict),
            },
            None => Err(CoreError::NotFound),
        }
    }

    /// [`Core::send_finalize`] bound to the selected chain: `sel` is the tip
    /// (height, header hash) the chain layer has verified. Signing is refused
    /// unless the wallet's state stands on exactly that tip; the tip is
    /// recorded in the arming frame. Unattended signing must use this call.
    pub fn send_finalize_at(
        &mut self,
        op: &OpId,
        s2: &[u8],
        sel: (u64, [u8; 32]),
    ) -> Result<Finalized, CoreError> {
        let same = self
            .st
            .tip
            .as_ref()
            .is_some_and(|(h, hash)| *h == sel.0 && hash.as_slice() == sel.1.as_slice());
        let already = self
            .st
            .sends
            .get(&state::hex(op))
            .is_some_and(|s| s.armed.is_some());
        if !same && !already {
            return Err(CoreError::Refused(
                "wallet state is not on the selected chain tip",
            ));
        }
        self.send_finalize(op, s2)
    }

    /// Tip recorded when the reply of an operation was chosen for signing.
    pub fn armed_at(&self, op: &OpId) -> Option<(u64, Vec<u8>)> {
        self.st.sends.get(&state::hex(op))?.armed_sel.clone()
    }

    /// Cancel a prepared operation and release its inputs. Refused once an
    /// S2 has been chosen for signing, and for an operation locked after a
    /// detected rollback: whether that one was signed is not known, so it
    /// is not cancelled but given up ([`Core::send_release_locked`]).
    pub fn send_cancel(&mut self, op: &OpId) -> Result<(), CoreError> {
        // Chain evidence can change the displayed status of a locked send.
        // Only an explicit release may give up that lock.
        if self.st.sends.get(&state::hex(op)).is_some_and(|s| s.locked) {
            return Err(CoreError::Refused(
                "operation is locked after a detected rollback",
            ));
        }
        self.commit_sealed(Event::Cancelled { op: *op })?;
        Ok(())
    }

    /// Whether the operation is prepared and locked after a detected
    /// rollback: it cannot be signed, and its reserve stays until the user
    /// gives it up.
    pub fn send_locked(&self, op: &OpId) -> bool {
        self.st.sends.get(&state::hex(op)).is_some_and(|s| s.locked)
            && self.st.send_status(op) == Some(SendStatus::Prepared)
    }

    /// Give up an operation locked after a detected rollback: its inputs
    /// are released and its context is closed. The journal that was lost
    /// may have held a signature of this payment, so it may still reach the
    /// chain; its status says so (`Released`) and is never "cancelled".
    /// Only for the user's explicit word, and only for a locked operation.
    pub fn send_release_locked(&mut self, op: &OpId) -> Result<(), CoreError> {
        if !self.st.sends.contains_key(&state::hex(op)) {
            return Err(CoreError::NotFound);
        }
        if !self.send_locked(op) {
            return Err(CoreError::Refused("operation is not locked"));
        }
        self.commit_sealed(Event::Cancelled { op: *op })?;
        Ok(())
    }

    /// The contact an operation's S1 was sent to, if it has automatic
    /// delivery.
    pub fn delivery_contact(&self, op: &OpId) -> Option<[u8; 32]> {
        let d = self.st.sends.get(&state::hex(op))?.delivery.as_ref()?;
        <[u8; 32]>::try_from(d.contact.as_slice()).ok()
    }

    /// The S1 of a prepared operation, exactly as stored: for passing it on
    /// by hand again. Nothing once the operation is no longer prepared.
    pub fn prepared_s1(&self, op: &OpId) -> Result<Vec<u8>, CoreError> {
        let record = self.st.sends.get(&state::hex(op)).ok_or(CoreError::NotFound)?;
        if self.st.send_status(op) != Some(SendStatus::Prepared) {
            return Err(CoreError::Refused("payment is not prepared"));
        }
        Ok(record.s1.clone())
    }

    /// Status of a send operation.
    pub fn send_status(&self, op: &OpId) -> Option<SendStatus> {
        self.st.send_status(op)
    }

    /// Whether an operation that has no chosen reply may still get one.
    fn may_take_reply(&self, rec: &SendRec) -> Result<(), CoreError> {
        if rec.cancelled {
            return Err(CoreError::Refused("operation was cancelled"));
        }
        if rec.locked {
            return Err(CoreError::Refused(
                "operation is locked after a detected rollback",
            ));
        }
        if rec.conflict_height.is_some() || rec.dead {
            return Err(CoreError::Refused(
                "an input was spent by another transaction",
            ));
        }
        if let Some((tip, _)) = &self.st.tip {
            let ttl = slates::s1_ttl(&rec.s1)?;
            if ttl != 0 && *tip >= ttl {
                return Err(CoreError::Refused("time-to-live passed"));
            }
        }
        Ok(())
    }

    /// Keep a reply that arrived by itself until the decision to sign. The
    /// reply passes every check made before signing; holding it signs
    /// nothing, reserves nothing and can still be followed by a cancel. The
    /// first valid reply is kept; the same reply again changes nothing and a
    /// different one is refused.
    pub fn send_hold_reply(&mut self, op: &OpId, s2: &[u8]) -> Result<(), CoreError> {
        if s2.len() > MAX_SLATE_LEN {
            return Err(CoreError::BadSlate("too large"));
        }
        let rec = self
            .st
            .sends
            .get(&state::hex(op))
            .ok_or(CoreError::NotFound)?
            .clone();
        if let Some(kept) = rec.armed.as_ref().or(rec.held.as_ref()) {
            return if sha(kept) == sha(s2) {
                Ok(())
            } else {
                Err(CoreError::Conflict)
            };
        }
        self.may_take_reply(&rec)?;
        slates::check_s2(&self.keychain, &rec.s1, s2)?;
        self.commit_plain(Event::ReplyHeld {
            op: *op,
            s2: s2.to_vec(),
        })
    }

    /// The reply held for an operation that can still be signed.
    pub fn send_held(&self, op: &OpId) -> Option<Vec<u8>> {
        let s = self.st.sends.get(&state::hex(op))?;
        if self.st.send_status(op)? != SendStatus::Prepared || s.locked {
            return None;
        }
        s.held.clone()
    }

    /// Sign with the held reply: the user confirmed the payment.
    pub fn send_finalize_held(&mut self, op: &OpId) -> Result<Finalized, CoreError> {
        let s2 = self.held_or_chosen(op)?;
        self.send_finalize(op, &s2)
    }

    /// Sign with the held reply on the selected chain tip, unattended.
    pub fn send_finalize_held_at(
        &mut self,
        op: &OpId,
        sel: (u64, [u8; 32]),
    ) -> Result<Finalized, CoreError> {
        let s2 = self.held_or_chosen(op)?;
        self.send_finalize_at(op, &s2, sel)
    }

    fn held_or_chosen(&self, op: &OpId) -> Result<Vec<u8>, CoreError> {
        let s = self
            .st
            .sends
            .get(&state::hex(op))
            .ok_or(CoreError::NotFound)?;
        s.armed
            .clone()
            .or_else(|| s.held.clone())
            .ok_or(CoreError::Refused("no reply is held for this operation"))
    }

    /// Operations that hold a reply and can still be signed.
    pub fn held_ops(&self) -> Vec<OpId> {
        self.st
            .sends
            .values()
            .filter(|s| s.held.is_some())
            .filter(|s| self.send_held(&s.op).is_some())
            .map(|s| s.op)
            .collect()
    }

    /// Contacts whose reply is still awaited. A message from anyone else
    /// cannot be a reply and need not be parsed.
    pub fn delivery_contacts(&self) -> Vec<[u8; 32]> {
        let mut out: Vec<[u8; 32]> = self
            .st
            .sends
            .values()
            .filter(|s| s.held.is_none() && !s.locked)
            .filter(|s| self.st.send_status(&s.op) == Some(SendStatus::Prepared))
            .filter_map(|s| s.delivery.as_ref())
            .filter_map(|d| <[u8; 32]>::try_from(d.contact.as_slice()).ok())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Accept the recipient's S2, sign once and return the transaction.
    ///
    /// A repeat of the very same S2 after success returns the stored result
    /// without signing. A different S2 is refused. If an earlier attempt
    /// stopped between choosing S2 and recording a result, the outcome is
    /// unknown and nothing is signed.
    pub fn send_finalize(&mut self, op: &OpId, s2: &[u8]) -> Result<Finalized, CoreError> {
        if s2.len() > MAX_SLATE_LEN {
            return Err(CoreError::BadSlate("too large"));
        }
        let rec = self
            .st
            .sends
            .get(&state::hex(op))
            .ok_or(CoreError::NotFound)?
            .clone();
        if let Some(chosen) = &rec.armed {
            if sha(chosen) != sha(s2) {
                return Err(CoreError::Conflict);
            }
            return match &rec.fin {
                Some(f) => Ok(Finalized {
                    tx: f.tx.clone(),
                    s3: f.s3.clone(),
                    excess: state::arr33(&f.excess)?,
                    payment_proof: f.proof.clone(),
                }),
                None => Err(CoreError::UnknownOutcome),
            };
        }
        self.require_complete_for_spend()?;
        self.may_take_reply(&rec)?;
        // everything that can be checked without the nonce, before arming
        let proof = slates::check_s2(&self.keychain, &rec.s1, s2)?;
        let (sealed, rec) = if rec.late {
            self.arm_late(op, &rec, s2)?
        } else {
            let sealed = self.commit_sealed(Event::Armed {
                op: *op,
                s2: s2.to_vec(),
                sel: self.st.tip.clone(),
            })?;
            (sealed, rec)
        };
        let mut fin = self.sign(&sealed, &rec, s2)?;
        fin.payment_proof = proof.clone();
        self.commit_sealed(Event::Final {
            op: *op,
            tx: fin.tx.clone(),
            excess: fin.excess.to_vec(),
            s3: fin.s3.clone(),
            proof,
        })?;
        Ok(fin)
    }

    /// Late lock: choose the reserve and the change path and make them
    /// durable together with the choice of S2.
    fn arm_late(
        &mut self,
        op: &OpId,
        rec: &SendRec,
        s2: &[u8],
    ) -> Result<(Sealed, SendRec), CoreError> {
        if self.st.any_contested() {
            return Err(CoreError::Refused("a contested operation exists"));
        }
        let picked = self
            .st
            .select_inputs_fixed_fee(rec.amount, rec.fee, self.maturity)?;
        let (branch, index) = self
            .st
            .branch
            .peek()
            .ok_or(CoreError::Refused("branch exhausted"))?;
        let change = if picked.change > 0 {
            let id = KeyPath::Branch {
                account: self.st.account,
                branch,
                index,
            }
            .to_identifier();
            let commit = self
                .keychain
                .commit(picked.change, &id, SwitchCommitmentType::Regular)
                .map_err(|_| CoreError::Build)?;
            Some((id.to_bytes().to_vec(), picked.change, commit.0.to_vec()))
        } else {
            None
        };
        let sealed = self.commit_sealed(Event::ArmedLate {
            op: *op,
            s2: s2.to_vec(),
            inputs: picked.inputs.iter().map(|i| i.commit.clone()).collect(),
            change,
            branch,
            index,
            sel: self.st.tip.clone(),
        })?;
        let rec = self
            .st
            .sends
            .get(&state::hex(op))
            .ok_or(CoreError::Corrupt)?
            .clone();
        Ok((sealed, rec))
    }

    /// The only place a sender signature is made. It cannot be called without
    /// the receipt of the durable, guarded `Armed` event.
    fn sign(&mut self, _armed: &Sealed, rec: &SendRec, s2: &[u8]) -> Result<Finalized, CoreError> {
        self.signs = self.signs.saturating_add(1);
        let ctx = Zeroizing::new(rec.ctx.clone());
        let inputs = rec
            .inputs
            .iter()
            .map(|c| {
                self.st
                    .outputs
                    .get(&state::hex(c))
                    .cloned()
                    .ok_or(CoreError::Corrupt)
            })
            .collect::<Result<Vec<_>, _>>()?;
        slates::finalize(
            &self.keychain,
            &ctx,
            &inputs,
            rec.change.as_ref(),
            s2,
            rec.late,
        )
    }

    // ----- receiving -----------------------------------------------------

    /// Receive with a draft (the user approved this payment): the record,
    /// the height R and a fresh branch path are durable before S2 is returned.
    /// `confirmed_time` is seconds of confirmed time, if the clock is confirmed.
    pub fn receive_draft(
        &mut self,
        s1: &[u8],
        confirmed_time: Option<u64>,
    ) -> Result<Vec<u8>, CoreError> {
        let parsed = slates::parse_s1(s1, self.st.tip.as_ref().map(|t| t.0))?;
        let key = state::hex(&parsed.slate_id);
        if let Some(d) = self.st.drafts.get(&key) {
            // same request again: the same bytes, no new signature
            return if d.s1_fp == sha(s1).to_vec() {
                Ok(d.s2.clone())
            } else {
                Err(CoreError::Conflict)
            };
        }
        let (tip, _) = self
            .st
            .tip
            .clone()
            .ok_or(CoreError::Refused("chain state unknown"))?;
        if self.st.open_drafts() >= MAX_OPEN_DRAFTS {
            return Err(CoreError::Refused("too many open drafts"));
        }
        let (branch, index) = self
            .st
            .branch
            .peek()
            .ok_or(CoreError::Refused("branch exhausted"))?;
        let path = KeyPath::Branch {
            account: self.st.account,
            branch,
            index,
        };
        let key_id = path.to_identifier();
        let built = slates::build_s2(&self.keychain, &self.account_id(), &parsed, &key_id)?;
        let rec = DraftRec {
            slate_id: parsed.slate_id,
            s1_fp: sha(s1).to_vec(),
            s1: s1.to_vec(),
            s2: built.s2.clone(),
            key_id: key_id.to_bytes().to_vec(),
            commit: built.commit.to_vec(),
            value: parsed.amount,
            excess: built.excess.to_vec(),
            r_height: tip,
            binding_interrupted: false,
            created: confirmed_time,
            branch,
            index,
            abandoned: false,
            kernel_height: None,
            bound: false,
            bound_spent: None,
            invoice: None,
            ctx: Vec::new(),
            armed: None,
            fin: None,
        };
        // S2 exists only in memory until this returns
        self.commit_sealed(Event::Draft(Box::new(rec)))?;
        Ok(built.s2)
    }

    /// Abandon a draft. Its path stays used; a payment that still arrives is
    /// found by the scan without automatic binding.
    pub fn draft_abandon(&mut self, slate_id: &SlateId) -> Result<(), CoreError> {
        self.commit_plain(Event::DraftAbandon {
            slate_id: *slate_id,
        })
    }

    /// Abandon drafts older than seven days of confirmed time. Without a
    /// confirmed clock nothing expires.
    pub fn drafts_expire(&mut self, confirmed_time: Option<u64>) -> Result<usize, CoreError> {
        let now = match confirmed_time {
            Some(t) => t,
            None => return Ok(0),
        };
        let old = self.st.expired_drafts(now, DRAFT_TTL_SECS);
        for id in &old {
            self.commit_plain(Event::DraftAbandon { slate_id: *id })?;
        }
        Ok(old.len())
    }

    /// Receive without state (unattended receive, grin-wallet issue 844).
    /// Writes nothing. Only available while unattended receive is switched on.
    pub fn receive_stateless(&self, s1: &[u8], min_amount: u64) -> Result<Vec<u8>, CoreError> {
        if self.st.auto_receive.is_none() {
            return Err(CoreError::Refused("unattended receive is off"));
        }
        let parsed = slates::parse_s1(s1, self.st.tip.as_ref().map(|t| t.0))?;
        if parsed.amount < min_amount {
            return Err(CoreError::Refused("amount below the configured minimum"));
        }
        let path = KeyPath::stateless_random(self.st.account).map_err(|_| CoreError::Rng)?;
        Ok(slates::build_s2(
            &self.keychain,
            &self.account_id(),
            &parsed,
            &path.to_identifier(),
        )?
        .s2)
    }

    /// Switch unattended receive on or off. Switching on records the height
    /// from which wallet completeness rests on scanning (`LocalThenScan`).
    /// `rp_authenticated` must be true: without authenticated range proofs
    /// the outputs could not be found.
    pub fn set_auto_receive(&mut self, on: bool, rp_authenticated: bool) -> Result<(), CoreError> {
        if on && !rp_authenticated {
            return Err(CoreError::Refused(
                "unattended receive needs authenticated range proofs",
            ));
        }
        self.commit_plain(Event::AutoReceive { on })
    }

    /// Height from which completeness rests on scanning, if unattended
    /// receive is on.
    pub fn auto_receive_since(&self) -> Option<u64> {
        self.st.auto_receive
    }

    // ----- statuses ------------------------------------------------------

    /// Row of the Level 5 table for an incoming payment received with a draft.
    pub fn incoming_row(&self, slate_id: &SlateId, chain: ChainState, k_conf: u64) -> Option<Row> {
        self.st.incoming_row(slate_id, chain, k_conf)
    }

    /// The original S1 of a prepared operation, for review before signing.
    pub fn prepared_slate(&self, op: &OpId) -> Result<SlateSummary, CoreError> {
        let record = self.st.sends.get(&state::hex(op)).ok_or(CoreError::NotFound)?;
        if self.st.send_status(op) != Some(SendStatus::Prepared) {
            return Err(CoreError::Refused("payment is not prepared"));
        }
        let mut review = slates::summary(&record.s1)?;
        review.amount = record.amount;
        review.fee = record.fee;
        Ok(review)
    }

    /// Stored result of a finalized send (or a paid invoice, where `tx` is
    /// empty and `s3` holds the I2). Reads only; never signs.
    pub fn send_result(&self, op: &OpId) -> Option<Finalized> {
        let s = self.st.sends.get(&state::hex(op))?;
        let f = s.fin.as_ref()?;
        Some(Finalized {
            tx: f.tx.clone(),
            s3: f.s3.clone(),
            excess: state::arr33(&f.excess).ok()?,
            payment_proof: f.proof.clone(),
        })
    }

    /// Outgoing operations: id, state, amount, fee.
    pub fn sends(&self) -> Vec<(OpId, SendStatus, u64, u64)> {
        self.st
            .sends
            .values()
            .filter_map(|s| Some((s.op, self.st.send_status(&s.op)?, s.amount, s.fee)))
            .collect()
    }

    /// Whether the outgoing operation is the payment of an invoice: its
    /// transaction is completed and sent to the network by whoever issued
    /// the invoice, not by this wallet.
    pub fn send_is_invoice(&self, op: &OpId) -> bool {
        self.st.sends.get(&state::hex(op)).is_some_and(|s| s.invoice)
    }

    /// K194: own outputs no record of a payment stands for, newest first.
    /// Reads only.
    pub fn unrecorded_outputs(&self) -> Vec<Unrecorded> {
        self.st
            .unrecorded()
            .into_iter()
            .map(|o| Unrecorded { commit: o.commit.clone(), value: o.value, height: o.height, old: o.old, coinbase: o.coinbase, spent: o.spent })
            .collect()
    }

    /// The block the wallet stood at when an outgoing payment was
    /// prepared: its place in time among the operations.
    pub fn send_made_height(&self, op: &OpId) -> Option<u64> {
        Some(self.st.sends.get(&state::hex(op))?.r_height)
    }

    /// The same for an incoming payment the wallet has a record of.
    pub fn incoming_made_height(&self, slate_id: &SlateId) -> Option<u64> {
        Some(self.st.drafts.get(&state::hex(slate_id))?.r_height)
    }

    /// The number of an outgoing payment's slate.
    pub fn send_slate_id(&self, op: &OpId) -> Option<SlateId> {
        Some(self.st.sends.get(&state::hex(op))?.slate_id)
    }

    /// The block an outgoing payment's kernel was seen in, if it was (K190).
    pub fn send_kernel_height(&self, op: &OpId) -> Option<u64> {
        self.st.sends.get(&state::hex(op))?.kernel_height
    }

    /// The block an incoming payment's kernel was seen in, if it was (K190).
    pub fn incoming_kernel_height(&self, slate_id: &SlateId) -> Option<u64> {
        self.st.drafts.get(&state::hex(slate_id))?.kernel_height
    }

    /// K200: the sender's request of an incoming payment this wallet
    /// answered, as it came. Kept with the payment's record; gone when the
    /// payment is abandoned. A payment taken by unattended receive has no
    /// record and so no text. Reads only.
    pub fn incoming_request(&self, slate_id: &SlateId) -> Option<Vec<u8>> {
        let d = self.st.drafts.get(&state::hex(slate_id))?;
        (!d.s1.is_empty()).then(|| d.s1.clone())
    }

    /// The reply this wallet made to an incoming payment (S2), as it is
    /// kept: to be handed to the sender again (K191). Reads only.
    pub fn incoming_reply(&self, slate_id: &SlateId) -> Option<Vec<u8>> {
        let d = self.st.drafts.get(&state::hex(slate_id))?;
        (!d.s2.is_empty()).then(|| d.s2.clone())
    }

    /// Receive drafts and issued invoices: slate id, value, abandoned.
    pub fn incomings(&self) -> Vec<(SlateId, u64, bool)> {
        self.st
            .drafts
            .values()
            .map(|d| (d.slate_id, d.value, d.abandoned))
            .collect()
    }

    /// What the core shows about an outgoing operation, for trace export.
    pub fn observe_send(&self, op: &OpId) -> Option<trace::Observation> {
        let status = self.st.send_status(op)?;
        let s = self.st.sends.get(&state::hex(op))?;
        let held = !s.inputs.is_empty()
            && matches!(
                status,
                SendStatus::Prepared
                    | SendStatus::Unknown
                    | SendStatus::Finalized
                    | SendStatus::Contested
            );
        Some(trace::Observation {
            status: if status == SendStatus::Confirmed {
                "confirmed"
            } else {
                "not_confirmed"
            },
            status_rule: None,
            known: true,
            spent: status == SendStatus::Confirmed,
            reserve: held,
            conflict: matches!(status, SendStatus::Contested | SendStatus::Dead),
            send_state: Some(status),
        })
    }

    /// What the core shows about an incoming payment received with a draft.
    pub fn observe_incoming(
        &self,
        slate_id: &SlateId,
        chain: ChainState,
        k_conf: u64,
    ) -> Option<trace::Observation> {
        let row = self.st.incoming_row(slate_id, chain, k_conf)?;
        let d = self.st.drafts.get(&state::hex(slate_id))?;
        let spent = self.st.bound_spent(d).unwrap_or(false);
        Some(trace::Observation {
            status: trace::status_word(row),
            status_rule: Some(row),
            known: true,
            spent,
            reserve: false,
            conflict: false,
            send_state: None,
        })
    }

    /// Row for an own output that has no deal record (stateless receive,
    /// restore): never above S3.
    pub fn unrecorded_output_row(&self, commit: &[u8; 33], chain: ChainState) -> Option<Row> {
        self.st.unrecorded_row(commit, chain)
    }

    /// Commitments of unspent own outputs with their values.
    pub fn unspent(&self) -> Vec<([u8; 33], u64)> {
        self.st.unspent()
    }

    // ----- broadcast bookkeeping ----------------------------------------

    /// The transactions of the invoices this wallet issued and completed
    /// whose kernel it has not seen in a block: slate id and transaction.
    /// The payer signs an invoice first and never has the transaction; the
    /// one who issued the invoice completes it, and it is theirs to hand
    /// to the network. An invoice that was given up is not among them.
    pub fn invoices_to_broadcast(&self) -> Vec<(SlateId, Vec<u8>)> {
        self.st
            .drafts
            .values()
            .filter(|d| d.invoice.is_some() && !d.abandoned && d.kernel_height.is_none())
            .filter_map(|d| Some((d.slate_id, d.fin.as_ref().map(|fin| fin.tx.clone()).filter(|tx| !tx.is_empty())?)))
            .collect()
    }

    /// Record the outcome of handing the finalized transaction to a node. An
    /// unknown outcome (timeout, dropped connection) is not a failure: the
    /// same bytes may be sent again, nothing is ever signed again.
    pub fn send_broadcast_result(
        &mut self,
        op: &OpId,
        outcome: Broadcast,
    ) -> Result<(), CoreError> {
        let outcome = match outcome {
            Broadcast::Accepted => 0,
            Broadcast::Rejected => 1,
            Broadcast::Unknown => 2,
        };
        self.commit_plain(Event::Broadcast { op: *op, outcome })
    }

    /// Broadcast attempts so far: accepted, rejected, unknown outcome.
    pub fn broadcast_attempts(&self, op: &OpId) -> Option<(u32, u32, u32)> {
        self.st.sends.get(&state::hex(op)).map(|s| s.broadcasts)
    }

    // ----- invoices -----------------------------------------------------

    /// Issue an invoice for `amount`: our output on a fresh branch path, the
    /// height R and the signing context are durable before I1 is returned.
    pub fn invoice_issue(
        &mut self,
        amount: u64,
        confirmed_time: Option<u64>,
    ) -> Result<(SlateId, Vec<u8>), CoreError> {
        if amount == 0 {
            return Err(CoreError::Refused("amount must be positive"));
        }
        let (tip, _) = self
            .st
            .tip
            .clone()
            .ok_or(CoreError::Refused("chain state unknown"))?;
        if self.st.open_drafts() >= MAX_OPEN_DRAFTS {
            return Err(CoreError::Refused("too many open drafts"));
        }
        let (branch, index) = self
            .st
            .branch
            .peek()
            .ok_or(CoreError::Refused("branch exhausted"))?;
        let key_id = KeyPath::Branch {
            account: self.st.account,
            branch,
            index,
        }
        .to_identifier();
        let built = slates::build_i1(&self.keychain, &self.account_id(), amount, &key_id, tip)?;
        let rec = DraftRec {
            slate_id: built.slate_id,
            s1_fp: sha(&built.i1).to_vec(),
            s1: Vec::new(),
            s2: Vec::new(),
            key_id: key_id.to_bytes().to_vec(),
            commit: built.commit.to_vec(),
            value: amount,
            excess: Vec::new(),
            r_height: tip,
            binding_interrupted: false,
            created: confirmed_time,
            branch,
            index,
            abandoned: false,
            kernel_height: None,
            bound: false,
            bound_spent: None,
            invoice: Some(built.i1.clone()),
            ctx: built.context.to_vec(),
            armed: None,
            fin: None,
        };
        self.commit_sealed(Event::Draft(Box::new(rec)))?;
        Ok((built.slate_id, built.i1))
    }

    /// Complete an invoice we issued with the payer's I2: check it, sign once,
    /// return the transaction. Repeats and conflicts behave as in
    /// [`Core::send_finalize`].
    pub fn invoice_finalize(
        &mut self,
        slate_id: &SlateId,
        i2: &[u8],
    ) -> Result<Finalized, CoreError> {
        if i2.len() > MAX_SLATE_LEN {
            return Err(CoreError::BadSlate("too large"));
        }
        let rec = self
            .st
            .drafts
            .get(&state::hex(slate_id))
            .ok_or(CoreError::NotFound)?
            .clone();
        let i1 = rec.invoice.clone().ok_or(CoreError::NotFound)?;
        if let Some(chosen) = &rec.armed {
            if sha(chosen) != sha(i2) {
                return Err(CoreError::Conflict);
            }
            return match &rec.fin {
                Some(f) => Ok(Finalized {
                    tx: f.tx.clone(),
                    s3: f.s3.clone(),
                    excess: state::arr33(&f.excess)?,
                    payment_proof: None,
                }),
                None => Err(CoreError::UnknownOutcome),
            };
        }
        if rec.abandoned {
            return Err(CoreError::Refused("invoice was abandoned"));
        }
        if rec.ctx.is_empty() {
            return Err(CoreError::Refused(
                "invoice is locked after a detected rollback",
            ));
        }
        slates::check_i2(&self.keychain, &i1, i2, self.tip_height())?;
        let sealed = self.commit_sealed(Event::InvoiceArmed {
            slate_id: *slate_id,
            i2: i2.to_vec(),
        })?;
        let fin = self.sign_invoice(&sealed, &rec, i2)?;
        self.commit_sealed(Event::InvoiceFinal {
            slate_id: *slate_id,
            tx: fin.tx.clone(),
            excess: fin.excess.to_vec(),
            s3: fin.s3.clone(),
        })?;
        Ok(fin)
    }

    /// The only place a payee signature for an invoice is made; needs the
    /// receipt of the durable, guarded `InvoiceArmed` event.
    fn sign_invoice(
        &mut self,
        _armed: &Sealed,
        rec: &DraftRec,
        i2: &[u8],
    ) -> Result<Finalized, CoreError> {
        self.signs = self.signs.saturating_add(1);
        let ctx = Zeroizing::new(rec.ctx.clone());
        slates::finalize_i2(&self.keychain, &ctx, (&rec.key_id, rec.value), i2)
    }

    /// What paying the invoice `i1` would take, by this wallet's own
    /// count: the amount it asks for and the fee of the inputs that would
    /// be spent now. Reads only: nothing is reserved, nothing is signed,
    /// nothing is written. It refuses whatever [`Core::invoice_pay`] would
    /// refuse before signing. For an invoice this wallet has paid already
    /// it gives the stored numbers and the operation.
    pub fn invoice_review(&self, i1: &[u8]) -> Result<InvoiceReview, CoreError> {
        let parsed = slates::parse_i1(i1)?;
        if let Some(s) = self
            .st
            .sends
            .values()
            .find(|s| s.slate_id == parsed.slate_id)
        {
            return match &s.armed {
                Some(seen) if s.invoice && s.fin.is_some() && sha(seen) == sha(i1) => {
                    Ok(InvoiceReview {
                        id: parsed.slate_id,
                        amount: s.amount,
                        fee: s.fee,
                        ttl_cutoff_height: parsed.slate.ttl_cutoff_height,
                        paid: Some(s.op),
                    })
                }
                _ => Err(CoreError::Conflict),
            };
        }
        slates::check_ttl(parsed.slate.ttl_cutoff_height, self.tip_height())?;
        self.require_complete_for_spend()?;
        if self.st.any_contested() {
            return Err(CoreError::Refused("a contested operation exists"));
        }
        if self.st.tip.is_none() {
            return Err(CoreError::Refused("chain state unknown"));
        }
        let picked = self.st.select_inputs(parsed.amount, None, self.maturity)?;
        Ok(InvoiceReview {
            id: parsed.slate_id,
            amount: parsed.amount,
            fee: picked.fee,
            ttl_cutoff_height: parsed.slate.ttl_cutoff_height,
            paid: None,
        })
    }

    /// Pay an invoice: reserve inputs, sign, and make everything durable
    /// before I2 is returned. Paying is the payer's one signature, so the
    /// same I1 again returns the stored I2 and never a second payment.
    /// `max_amount` is the most the user agreed to pay.
    pub fn invoice_pay(
        &mut self,
        i1: &[u8],
        max_amount: u64,
    ) -> Result<(OpId, Vec<u8>), CoreError> {
        self.invoice_pay_agreed(i1, max_amount, u64::MAX)
    }

    /// [`Core::invoice_pay`] with the fee the user agreed to as well: the
    /// inputs are chosen at the moment of paying, and if their fee has
    /// become higher than `max_fee` since the numbers were shown, nothing
    /// is signed.
    pub fn invoice_pay_agreed(
        &mut self,
        i1: &[u8],
        max_amount: u64,
        max_fee: u64,
    ) -> Result<(OpId, Vec<u8>), CoreError> {
        let parsed = slates::parse_i1(i1)?;
        if let Some(s) = self
            .st
            .sends
            .values()
            .find(|s| s.slate_id == parsed.slate_id)
        {
            return match (&s.armed, &s.fin) {
                (Some(seen), Some(f)) if s.invoice && sha(seen) == sha(i1) => {
                    Ok((s.op, f.s3.clone()))
                }
                _ => Err(CoreError::Conflict),
            };
        }
        slates::check_ttl(parsed.slate.ttl_cutoff_height, self.tip_height())?;
        self.require_complete_for_spend()?;
        if parsed.amount > max_amount {
            return Err(CoreError::Refused("invoice asks for more than agreed"));
        }
        if self.st.any_contested() {
            return Err(CoreError::Refused("a contested operation exists"));
        }
        let (tip, _) = self
            .st
            .tip
            .clone()
            .ok_or(CoreError::Refused("chain state unknown"))?;
        let (branch, index) = self
            .st
            .branch
            .peek()
            .ok_or(CoreError::Refused("branch exhausted"))?;
        let change_id = KeyPath::Branch {
            account: self.st.account,
            branch,
            index,
        }
        .to_identifier();
        let picked = self.st.select_inputs(parsed.amount, None, self.maturity)?;
        if picked.fee > max_fee {
            return Err(CoreError::Refused("the fee is higher than agreed"));
        }
        let built = slates::build_i2(
            &self.keychain,
            &self.account_id(),
            &parsed,
            &picked,
            &change_id,
        )?;
        self.signs = self.signs.saturating_add(1);
        let op = random16()?;
        let rec = SendRec {
            op,
            slate_id: parsed.slate_id,
            s1: Vec::new(),
            ctx: Vec::new(),
            inputs: picked.inputs.iter().map(|i| i.commit.clone()).collect(),
            change: built.change,
            amount: parsed.amount,
            fee: picked.fee,
            r_height: tip,
            binding_interrupted: false,
            replaces: None,
            branch,
            index,
            locked: false,
            cancelled: false,
            armed: Some(i1.to_vec()),
            fin: Some(state::FinalRec {
                tx: Vec::new(),
                excess: built.excess.to_vec(),
                s3: built.i2.clone(),
                proof: None,
            }),
            kernel_height: None,
            conflict_height: None,
            dead: false,
            broadcasts: (0, 0, 0),
            invoice: true,
            late: false,
            delivery: None,
            armed_sel: None,
            held: None,
            by_search: false,
            released: false,
            direct: false,
        };
        // the signed I2 exists only in memory until this returns
        self.commit_sealed(Event::InvoicePaid(Box::new(rec)))?;
        Ok((op, built.i2))
    }
}

/// What paying an invoice would take ([`Core::invoice_review`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvoiceReview {
    pub id: SlateId,
    /// What the invoice asks for.
    pub amount: u64,
    /// The fee of the inputs this wallet would spend now, or spent.
    pub fee: u64,
    /// The height from which the invoice cannot be paid; 0 if it names none.
    pub ttl_cutoff_height: u64,
    /// The operation, if this wallet has paid this very invoice already.
    pub paid: Option<OpId>,
}

/// Which message of the exchange a slate is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlateStage {
    /// The sender's first message of an ordinary payment.
    S1,
    /// The recipient's reply.
    S2,
    /// The finished ordinary payment.
    S3,
    /// The payee's invoice.
    I1,
    /// The payer's reply to an invoice.
    I2,
    /// The finished invoice payment.
    I3,
    /// None of the above.
    Unknown,
}

/// One text message of a conversation (K120–K122).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// Identifier of the message on the transport.
    pub id: [u8; 32],
    /// Sent by this wallet.
    pub out: bool,
    /// Unix seconds by the clock of whoever kept it; for showing only.
    pub at: u64,
    /// The words, as written; showing them is the interface's care (О1–О5, О9).
    pub text: String,
    /// What is known about its delivery.
    pub state: MessageState,
}

/// What is known about a message. «A relay accepted» is not «read» (О10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageState {
    /// It came from the contact.
    Received,
    /// Sent; no relay has accepted it yet.
    Waiting,
    /// A relay accepted it.
    RelayAccepted,
    /// Its delivery window closed before a relay accepted it.
    Expired,
}

/// The wallet's transport identity, without its secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportIdentity {
    /// Public key contacts know this wallet by.
    pub public: [u8; 32],
    /// Brought in by the user rather than made here.
    pub imported: bool,
    /// Public keys of earlier identities, oldest first.
    pub previous: Vec<[u8; 32]>,
}

/// Someone payments can be delivered to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// Transport key of the contact.
    pub key: [u8; 32],
    /// Name the user gave.
    pub name: String,
    /// Slatepack address of the contact, if known.
    pub address: Option<[u8; 32]>,
    /// K199: the owner compared the check code with the contact.
    pub checked: bool,
}

fn bech32_encode(hrp: &str, key: &[u8; 32]) -> Result<String, CoreError> {
    use bech32::ToBase32;
    bech32::encode(hrp, key.to_base32()).map_err(|_| CoreError::Build)
}

fn bech32_decode(hrp: &str, text: &str) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    use bech32::FromBase32;
    let bad = CoreError::BadSlate("not a key in that form");
    let text = text.trim();
    if text.len() > 100 {
        return Err(bad);
    }
    let (got, data) = bech32::decode(text).map_err(|_| CoreError::BadSlate("not a key in that form"))?;
    let bytes = Zeroizing::new(Vec::<u8>::from_base32(&data).map_err(|_| CoreError::BadSlate("not a key in that form"))?);
    if got != hrp {
        return Err(bad);
    }
    let key = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| CoreError::BadSlate("not a key in that form"))?;
    Ok(Zeroizing::new(key))
}

/// A transport public key in the form users pass around (`npub1вЂ¦`).
pub fn npub_encode(key: &[u8; 32]) -> Result<String, CoreError> {
    bech32_encode("npub", key)
}

/// Read a transport public key from its `npub1вЂ¦` form.
pub fn npub_decode(text: &str) -> Result<[u8; 32], CoreError> {
    bech32_decode("npub", text).map(|k| *k)
}

/// A transport secret key in its backup form (`nsec1вЂ¦`).
pub fn nsec_encode(secret: &[u8; 32]) -> Result<Zeroizing<String>, CoreError> {
    bech32_encode("nsec", secret).map(Zeroizing::new)
}

/// Read a transport secret key from its `nsec1вЂ¦` form.
pub fn nsec_decode(text: &str) -> Result<Zeroizing<[u8; 32]>, CoreError> {
    bech32_decode("nsec", text)
}

/// Slate JSON as Slatepack text, readable by anyone who sees it. Use it when
/// the channel itself is private (the message transport) or the user will
/// hand the text over personally.
pub fn slatepack_encode(slate: &[u8]) -> Result<String, CoreError> {
    slates::slatepack_encode(slate, None, None)
}

/// What a slate says about itself (K119): read for showing before the user
/// decides, never signed, stored or compared with the wallet. The amount and
/// fee are the other side's words until the wallet's own checks accept the
/// slate in `receive_*`, `send_finalize` or `invoice_*`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlateSummary {
    pub stage: SlateStage,
    pub id: SlateId,
    pub amount: u64,
    pub fee: u64,
    pub ttl_cutoff_height: u64,
    /// Payment proof addresses, when the slate asks for a proof.
    pub sender: Option<[u8; 32]>,
    pub receiver: Option<[u8; 32]>,
}

/// Read a slate for showing; checks the format only and changes nothing.
pub fn slate_summary(slate: &[u8]) -> Result<SlateSummary, CoreError> {
    slates::summary(slate)
}

/// Tell which message of the exchange a slate is. Checks the format only.
pub fn slate_stage(slate: &[u8]) -> Result<SlateStage, CoreError> {
    slates::stage_of(slate)
}

pub use fly_paycore_mailbox::Envelope;

type Sealer<'a> = (
    [u8; 32],
    &'a mut dyn FnMut(&[u8]) -> Result<Envelope, String>,
);

/// The variations of preparing a send.
#[derive(Default)]
struct How<'a> {
    /// K195: the outputs the owner chose to pay with, and whether one
    /// marked "not to be spent" among them may be spent this once.
    chosen: Option<(Vec<[u8; 33]>, bool)>,
    replaces: Option<OpId>,
    /// K197: `replaces` names a signed payment the owner takes back, and
    /// `chosen` are its inputs.
    take_back: bool,
    not_a_repeat: bool,
    proof_to: Option<[u8; 32]>,
    late: bool,
    seal: Option<Sealer<'a>>,
}

/// What happened to one publication of an envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryNote {
    /// No definite answer from the relay.
    RelayUnknown,
    /// A relay acknowledged the message.
    RelayAccepted,
    /// The delivery window closed.
    Expired,
    /// The transport queue is busy; try later.
    QueueBusy,
    /// The transport queue is full.
    QueueFull,
}

/// Delivery state shown next to an operation. It says nothing about the
/// payment itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveryStatus {
    /// Stored, not published yet.
    Queued,
    /// Published without a definite answer.
    WaitingRelay,
    /// A relay acknowledged the message.
    RelayAccepted,
    /// The delivery window closed.
    Expired,
    /// The transport queue is busy.
    QueueBusy,
    /// The transport queue is full.
    QueueFull,
}

/// Outcome of handing a transaction to a node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Broadcast {
    /// The node accepted it into its pool.
    Accepted,
    /// The node refused it.
    Rejected,
    /// No answer: it may or may not have been accepted.
    Unknown,
}
