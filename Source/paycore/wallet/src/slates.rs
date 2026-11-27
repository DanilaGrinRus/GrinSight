//! Slate construction with Grin's own types. The steps mirror
//! `grin_wallet_libwallet` 5.5.1 (`init_send_tx`, `receive_tx`,
//! `finalize_tx`) so that the result is interchangeable with it; only the
//! storage around them is ours.
use crate::state::{OutputRec, Picked};
use crate::{CoreError, Finalized, SlateId, MAX_SLATE_LEN};
use byteorder::{BigEndian, WriteBytesExt};
use ed25519_dalek::{Signer, SigningKey};
use grin_core::core::transaction::Weighting;
use grin_core::core::FeeFields;
use grin_core::libtx::proof::ProofBuilder;
use grin_core::libtx::{aggsig, build};
use grin_core::ser;
use grin_keychain::{Identifier, Keychain, SwitchCommitmentType};
use grin_wallet_libwallet::{address, Context, Slate, SlateState, SlateVersion, VersionedSlate};
use zeroize::Zeroize;

fn bad(_: grin_wallet_libwallet::Error) -> CoreError {
    CoreError::Build
}

fn to_json(slate: &Slate) -> Result<Vec<u8>, CoreError> {
    let v = VersionedSlate::into_version(slate.clone(), SlateVersion::V4).map_err(bad)?;
    serde_json::to_vec(&v).map_err(|_| CoreError::Build)
}

fn from_json(bytes: &[u8]) -> Result<Slate, CoreError> {
    if bytes.len() > MAX_SLATE_LEN {
        return Err(CoreError::BadSlate("too large"));
    }
    let text = std::str::from_utf8(bytes).map_err(|_| CoreError::BadSlate("not text"))?;
    // Grin's parser panics on a kernel offset that is not hex
    // (`BlindingFactor::from_hex` unwraps), so that field is checked first.
    // The check reads the JSON strictly: with a repeated key Grin's parser
    // would look at one occurrence and this check at another.
    let Strict(probe) =
        serde_json::from_str(text).map_err(|_| CoreError::BadSlate("cannot be parsed"))?;
    if let Some(off) = probe.get("off") {
        let ok = off
            .as_str()
            .map(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .unwrap_or(false);
        if !ok {
            return Err(CoreError::BadSlate("kernel offset is not 32 bytes of hex"));
        }
    }
    Slate::deserialize_upgrade(text).map_err(|_| CoreError::BadSlate("cannot be parsed"))
}

/// A JSON value in which no object repeats a key, at any depth.
struct Strict(serde_json::Value);

impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use serde::de::{Error, MapAccess, SeqAccess, Visitor};
        use serde_json::Value;
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without repeated keys")
            }
            fn visit_bool<E: Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E: Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_u64<E: Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_f64<E: Error>(self, v: f64) -> Result<Strict, E> {
                Ok(Strict(Value::from(v)))
            }
            fn visit_str<E: Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_unit<E: Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(Strict(v)) = seq.next_element()? {
                    out.push(v);
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let Strict(v) = map.next_value()?;
                    if out.insert(key, v).is_some() {
                        return Err(A::Error::custom("repeated key"));
                    }
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}

fn key_id(bytes: &[u8]) -> Identifier {
    Identifier::from_bytes(bytes)
}

/// The live signer is deliberately neither serializable nor cloneable. Both
/// signing entry points consume it and only this module can access its nonce.
pub(crate) struct SigningContext(Context);

impl Drop for SigningContext {
    fn drop(&mut self) {
        self.0.sec_nonce.0.zeroize();
        self.0.initial_sec_nonce.0.zeroize();
        self.0.sec_key.0.zeroize();
        self.0.initial_sec_key.0.zeroize();
    }
}

pub(crate) struct BuiltS1 {
    pub slate_id: SlateId,
    pub s1: Vec<u8>,
    pub context: SigningContext,
    pub change: Option<(Vec<u8>, u64, Vec<u8>)>,
}

/// Sender, round 1: inputs, change, public nonce and excess.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_s1<K: Keychain>(
    keychain: &K,
    parent: &Identifier,
    amount: u64,
    ttl_cutoff_height: u64,
    picked: &Picked,
    change_id: &Identifier,
    tip_height: u64,
    proof_to: Option<[u8; 32]>,
) -> Result<BuiltS1, CoreError> {
    let mut slate = Slate::blank(2, false);
    slate.amount = amount;
    slate.ttl_cutoff_height = ttl_cutoff_height;
    slate.version_info.block_header_version = grin_core::consensus::header_version(tip_height).0;
    slate.kernel_features = 0;
    slate.fee_fields = FeeFields::new(0, picked.fee).map_err(|_| CoreError::Build)?;

    let mut context = Context::new(keychain.secp(), parent, false, true);
    context.fee = Some(slate.fee_fields);
    context.amount = amount;
    let mut parts = Vec::new();
    for i in &picked.inputs {
        let id = key_id(&i.key_id);
        parts.push(if i.coinbase {
            build::coinbase_input(i.value, id.clone())
        } else {
            build::input(i.value, id.clone())
        });
        context.add_input(&id, &None, i.value);
    }
    let change = if picked.change > 0 {
        parts.push(build::output(picked.change, change_id.clone()));
        context.add_output(change_id, &None, picked.change);
        let commit = keychain
            .commit(picked.change, change_id, SwitchCommitmentType::Regular)
            .map_err(|_| CoreError::Build)?;
        Some((
            change_id.to_bytes().to_vec(),
            picked.change,
            commit.0.to_vec(),
        ))
    } else {
        None
    };
    slate
        .add_transaction_elements(keychain, &ProofBuilder::new(keychain), parts)
        .map_err(bad)?;
    slate.fill_round_1(keychain, &mut context).map_err(bad)?;
    context.initial_sec_key = context.sec_key.clone();
    slate.compact().map_err(bad)?;
    if let Some(to) = proof_to {
        // ask the recipient to sign for the payment with its address key
        let ours = SigningKey::from_bytes(
            &address::address_from_derivation_path(keychain, parent, 0)
                .map_err(bad)?
                .0,
        );
        let mut v = serde_json::to_value(
            VersionedSlate::into_version(slate.clone(), SlateVersion::V4).map_err(bad)?,
        )
        .map_err(|_| CoreError::Build)?;
        let obj = v.as_object_mut().ok_or(CoreError::Build)?;
        obj.insert("proof".into(), serde_json::json!({ "saddr": hex(&ours.verifying_key().to_bytes()), "raddr": hex(&to) }));
        slate = Slate::deserialize_upgrade(&v.to_string()).map_err(|_| CoreError::Build)?;
        context.payment_proof_derivation_index = Some(0);
    }

    Ok(BuiltS1 {
        slate_id: *slate.id.as_bytes(),
        s1: to_json(&slate)?,
        context: SigningContext(context),
        change,
    })
}

/// Which message of the exchange a slate is.
pub(crate) fn stage_of(slate: &[u8]) -> Result<crate::SlateStage, CoreError> {
    Ok(stage_from(&from_json(slate)?.state))
}

fn stage_from(state: &SlateState) -> crate::SlateStage {
    use crate::SlateStage as S;
    match state {
        SlateState::Standard1 => S::S1,
        SlateState::Standard2 => S::S2,
        SlateState::Standard3 => S::S3,
        SlateState::Invoice1 => S::I1,
        SlateState::Invoice2 => S::I2,
        SlateState::Invoice3 => S::I3,
        SlateState::Unknown => S::Unknown,
    }
}

/// K119: the slate's own words, read the same strict way as every parse.
pub(crate) fn summary(slate: &[u8]) -> Result<crate::SlateSummary, CoreError> {
    let s = from_json(slate)?;
    let proof = s.payment_proof.as_ref();
    Ok(crate::SlateSummary {
        stage: stage_from(&s.state),
        id: *s.id.as_bytes(),
        amount: s.amount,
        fee: s.fee_fields.fee(),
        ttl_cutoff_height: s.ttl_cutoff_height,
        sender: proof.map(|p| p.sender_address.to_bytes()),
        receiver: proof.map(|p| p.receiver_address.to_bytes()),
    })
}

/// Slate id of any slate, after the same checks every parse goes through.
pub(crate) fn slate_id_of(slate: &[u8]) -> Result<SlateId, CoreError> {
    Ok(*from_json(slate)?.id.as_bytes())
}

pub(crate) fn s1_ttl(s1: &[u8]) -> Result<u64, CoreError> {
    Ok(from_json(s1)?.ttl_cutoff_height)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn proof_message(amount: u64, excess: &[u8; 33], sender: &[u8; 32]) -> Result<Vec<u8>, CoreError> {
    let mut msg = Vec::new();
    msg.write_u64::<BigEndian>(amount)
        .map_err(|_| CoreError::Build)?;
    msg.extend_from_slice(excess);
    msg.extend_from_slice(sender);
    Ok(msg)
}

/// The recipient's signed acknowledgement of a payment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PaymentProof {
    /// Amount paid.
    pub amount: u64,
    /// Kernel excess of the transaction.
    pub excess: Vec<u8>,
    /// Sender address (ed25519 public key).
    pub sender_address: Vec<u8>,
    /// Recipient address (ed25519 public key).
    pub receiver_address: Vec<u8>,
    /// Recipient's signature over amount, excess and sender address.
    pub signature: Vec<u8>,
}

impl PaymentProof {
    /// Verify the signature. It proves the recipient acknowledged the
    /// payment; whether the kernel is in the chain is a separate question.
    pub fn verify(&self) -> bool {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let parts = (
            <[u8; 33]>::try_from(self.excess.as_slice()),
            <[u8; 32]>::try_from(self.sender_address.as_slice()),
            <[u8; 32]>::try_from(self.receiver_address.as_slice()),
            <[u8; 64]>::try_from(self.signature.as_slice()),
        );
        let (Ok(excess), Ok(sender), Ok(receiver), Ok(sig)) = parts else {
            return false;
        };
        let (Ok(key), Ok(msg)) = (
            VerifyingKey::from_bytes(&receiver),
            proof_message(self.amount, &excess, &sender),
        ) else {
            return false;
        };
        key.verify(&msg, &Signature::from_bytes(&sig)).is_ok()
    }
}

/// The counterparty's half of the transaction, checked with public data
/// only: every output carries a valid range proof and is a plain output,
/// every input is plain, and its commitments, the agreed value and its
/// kernel offset add up to exactly the public excess it signed with:
/// `outputs - inputs + value*H - offset*G == P`. After this and the partial
/// signature check nothing the counterparty supplied can make the final
/// transaction invalid, so a failure can no longer strand an armed operation.
fn check_counterparty_half<K: Keychain>(
    keychain: &K,
    reply: &Slate,
    public_excess: &grin_util::secp::key::PublicKey,
    add_value: u64,
    sub_value: u64,
) -> Result<(), CoreError> {
    use grin_core::core::OutputFeatures;
    let secp = keychain.secp();
    let wrong = || CoreError::BadSlate("counterparty transaction data is inconsistent");
    let tx = reply.tx.as_ref().ok_or(wrong())?;
    let mut plus = Vec::new();
    let mut minus = Vec::new();
    for o in tx.outputs() {
        if o.features() != OutputFeatures::Plain {
            return Err(wrong());
        }
        o.verify_proof()
            .map_err(|_| CoreError::BadSlate("range proof does not verify"))?;
        plus.push(o.commitment());
    }
    let inputs: Vec<grin_core::core::transaction::CommitWrapper> = tx.inputs().into();
    for i in &inputs {
        minus.push(i.commitment());
    }
    if add_value > 0 {
        plus.push(secp.commit_value(add_value).map_err(|_| wrong())?);
    }
    if sub_value > 0 {
        minus.push(secp.commit_value(sub_value).map_err(|_| wrong())?);
    }
    if reply.offset != grin_keychain::BlindingFactor::zero() {
        let key = reply.offset.secret_key(secp).map_err(|_| wrong())?;
        minus.push(secp.commit(0, key).map_err(|_| wrong())?);
    }
    let sum = secp.commit_sum(plus, minus).map_err(|_| wrong())?;
    let derived = sum.to_pubkey(secp).map_err(|_| wrong())?;
    if &derived != public_excess {
        return Err(wrong());
    }
    Ok(())
}

/// Everything about an S2 that can be checked against the stored S1 without
/// the sender's secret nonce: shape, identity of the deal, the recipient's
/// partial signature and, if one was requested, the payment proof.
pub(crate) fn check_s2<K: Keychain>(
    keychain: &K,
    s1: &[u8],
    s2: &[u8],
) -> Result<Option<PaymentProof>, CoreError> {
    let s1 = from_json(s1)?;
    let mut reply = from_json(s2)?;
    let shape_ok = s1.state == SlateState::Standard1
        && reply.state == SlateState::Standard2
        && s1.id == reply.id
        && s1.version_info.version == reply.version_info.version
        && s1.version_info.block_header_version == reply.version_info.block_header_version
        && s1.num_participants == 2
        && reply.num_participants == 2
        && s1.ttl_cutoff_height == reply.ttl_cutoff_height
        && reply.kernel_features == 0
        && reply.kernel_features_args.is_none()
        && reply.payment_proof.is_some() == s1.payment_proof.is_some()
        && reply.amount == 0
        && reply.fee_fields == FeeFields::zero()
        && s1.participant_data.len() == 1
        && reply.participant_data.len() == 1;
    if !shape_ok {
        return Err(CoreError::BadSlate("S2 does not match the stored S1"));
    }
    let (sender, receiver) = match (s1.participant_data.first(), reply.participant_data.first()) {
        (Some(a), Some(b)) => (a.clone(), b.clone()),
        _ => return Err(CoreError::BadSlate("participants")),
    };
    let sig = receiver
        .part_sig
        .ok_or(CoreError::BadSlate("no recipient signature"))?;
    if sender.public_blind_excess == receiver.public_blind_excess
        || sender.public_nonce == receiver.public_nonce
    {
        return Err(CoreError::BadSlate("recipient reused sender keys"));
    }
    // exactly one output from the recipient, nothing else
    let outputs = reply
        .tx
        .as_ref()
        .map(|t| (t.inputs().len(), t.outputs().len(), t.kernels().len()));
    if outputs != Some((0, 1, 1)) && outputs != Some((0, 1, 0)) {
        return Err(CoreError::BadSlate("unexpected transaction content in S2"));
    }
    reply.amount = s1.amount;
    reply.fee_fields = s1.fee_fields;
    reply.participant_data.push(sender);
    let secp = keychain.secp();
    let nonces = reply
        .pub_nonce_sum(secp)
        .map_err(|_| CoreError::BadSlate("nonces"))?;
    let keys = reply
        .pub_blind_sum(secp)
        .map_err(|_| CoreError::BadSlate("keys"))?;
    let msg = reply
        .msg_to_sign()
        .map_err(|_| CoreError::BadSlate("message"))?;
    aggsig::verify_partial_sig(
        secp,
        &sig,
        &nonces,
        &receiver.public_blind_excess,
        Some(&keys),
        &msg,
    )
    .map_err(|_| CoreError::BadSlate("recipient signature does not verify"))?;
    check_counterparty_half(
        keychain,
        &reply,
        &receiver.public_blind_excess,
        0,
        s1.amount,
    )?;
    let (asked, got) = match (s1.payment_proof.as_ref(), reply.payment_proof.as_ref()) {
        (Some(a), Some(b)) => (a, b),
        _ => return Ok(None),
    };
    if asked.sender_address != got.sender_address || asked.receiver_address != got.receiver_address
    {
        return Err(CoreError::BadSlate("payment proof addresses were changed"));
    }
    let signature = got
        .receiver_signature
        .ok_or(CoreError::BadSlate("payment proof is not signed"))?;
    let excess = reply
        .calc_excess(secp)
        .map_err(|_| CoreError::BadSlate("excess"))?;
    let proof = PaymentProof {
        amount: s1.amount,
        excess: excess.0.to_vec(),
        sender_address: asked.sender_address.to_bytes().to_vec(),
        receiver_address: asked.receiver_address.to_bytes().to_vec(),
        signature: signature.to_bytes().to_vec(),
    };
    if !proof.verify() {
        return Err(CoreError::BadSlate(
            "payment proof signature does not verify",
        ));
    }
    Ok(Some(proof))
}

/// Sender, round 2: the one signature. Called only from `Core::sign`.
pub(crate) fn finalize<K: Keychain>(
    keychain: &K,
    mut signer: SigningContext,
    inputs: &[OutputRec],
    change: Option<&(Vec<u8>, u64, Vec<u8>)>,
    s2: &[u8],
    late: bool,
) -> Result<Finalized, CoreError> {
    let context = &mut signer.0;
    if late {
        // late lock: the context was made before inputs were chosen
        if !context.input_ids.is_empty() || !context.output_ids.is_empty() {
            return Err(CoreError::Corrupt);
        }
        for i in inputs {
            context.add_input(&key_id(&i.key_id), &None, i.value);
        }
        if let Some((id, value, _)) = change {
            context.add_output(&key_id(id), &None, *value);
        }
    }
    let mut slate = from_json(s2)?;
    slate.adjust_offset(keychain, &context).map_err(bad)?;
    // restore amount, fee and our side of the transaction (the compact S2
    // carries only the recipient's)
    slate.amount = context.amount;
    slate.fee_fields = context.fee.ok_or(CoreError::Corrupt)?;
    slate
        .add_participant_info(keychain, &context, None)
        .map_err(bad)?;
    let mut parts = Vec::new();
    for i in inputs {
        let id = key_id(&i.key_id);
        parts.push(if i.coinbase {
            build::coinbase_input(i.value, id)
        } else {
            build::input(i.value, id)
        });
    }
    if let Some((id, value, _)) = change {
        parts.push(build::output(*value, key_id(id)));
    }
    slate
        .add_transaction_elements(keychain, &ProofBuilder::new(keychain), parts)
        .map_err(bad)?;
    slate.tx_or_err_mut().map_err(bad)?.offset = slate.offset.clone();

    slate
        .fill_round_2(keychain, &context.sec_key, &context.sec_nonce)
        .map_err(bad)?;
    slate.finalize(keychain).map_err(bad)?;

    let tx = slate.tx_or_err().map_err(bad)?.clone();
    // never hand out a transaction the network would reject
    tx.validate(Weighting::AsTransaction)
        .map_err(|_| CoreError::Build)?;
    let excess = tx
        .kernels()
        .first()
        .map(|k| k.excess.0)
        .ok_or(CoreError::Build)?;
    slate.state = SlateState::Standard3;
    Ok(Finalized {
        tx: ser::ser_vec(&tx, ser::ProtocolVersion::local()).map_err(|_| CoreError::Build)?,
        s3: to_json(&slate)?,
        excess,
        payment_proof: None,
    })
}

pub(crate) struct ParsedS1 {
    pub slate: Slate,
    pub slate_id: SlateId,
    pub amount: u64,
}

/// A zero cutoff is unlimited. The cutoff block itself is already too late.
pub(crate) fn check_ttl(cutoff: u64, tip_height: Option<u64>) -> Result<(), CoreError> {
    match (cutoff, tip_height) {
        (0, _) => Ok(()),
        (_, Some(tip)) if tip < cutoff => Ok(()),
        (_, Some(_)) => Err(CoreError::BadSlate("time-to-live passed")),
        (_, None) => Err(CoreError::BadSlate("time-to-live cannot be checked")),
    }
}

/// Checks every receive performs before building anything.
pub(crate) fn parse_s1(s1: &[u8], tip_height: Option<u64>) -> Result<ParsedS1, CoreError> {
    let slate = from_json(s1)?;
    if slate.state != SlateState::Standard1 {
        return Err(CoreError::BadSlate("not a Standard1 slate"));
    }
    if slate.amount == 0 {
        return Err(CoreError::BadSlate("zero amount"));
    }
    if slate.num_participants != 2 || slate.participant_data.len() != 1 {
        return Err(CoreError::BadSlate("participants"));
    }
    if slate.kernel_features != 0 || slate.kernel_features_args.is_some() {
        return Err(CoreError::BadSlate("only plain kernels are supported"));
    }
    check_ttl(slate.ttl_cutoff_height, tip_height)?;
    Ok(ParsedS1 {
        slate_id: *slate.id.as_bytes(),
        amount: slate.amount,
        slate,
    })
}

pub(crate) struct BuiltS2 {
    pub s2: Vec<u8>,
    pub commit: [u8; 33],
    pub excess: [u8; 33],
}

/// Recipient: add the output at `output_id`, sign, and answer a payment
/// proof request. The recipient's signing context lives only in this call.
pub(crate) fn build_s2<K: Keychain>(
    keychain: &K,
    parent: &Identifier,
    s1: &ParsedS1,
    output_id: &Identifier,
) -> Result<BuiltS2, CoreError> {
    let mut slate = s1.slate.clone();
    slate.tx = Some(Slate::empty_transaction());
    slate
        .add_transaction_elements(
            keychain,
            &ProofBuilder::new(keychain),
            vec![build::output(s1.amount, output_id.clone())],
        )
        .map_err(bad)?;
    let mut context = Context::new(keychain.secp(), parent, false, false);
    context.add_output(output_id, &None, s1.amount);
    context.amount = s1.amount;
    context.fee = slate.fee_fields.as_opt();
    slate.fill_round_1(keychain, &mut context).map_err(bad)?;
    context.initial_sec_key = context.sec_key.clone();
    slate
        .fill_round_2(keychain, &context.sec_key, &context.sec_nonce)
        .map_err(bad)?;
    slate.adjust_offset(keychain, &context).map_err(bad)?;
    let excess = slate.calc_excess(keychain.secp()).map_err(bad)?;

    if let Some(p) = slate.payment_proof.as_mut() {
        // amount (big endian) | kernel excess | sender address, signed with
        // the account's address key 0, as grin-wallet does
        let msg = proof_message(s1.amount, &excess.0, &p.sender_address.to_bytes())?;
        let sec = address::address_from_derivation_path(keychain, parent, 0).map_err(bad)?;
        let signing = SigningKey::from_bytes(&sec.0);
        if signing.verifying_key() != p.receiver_address {
            return Err(CoreError::BadSlate(
                "payment proof names another recipient address",
            ));
        }
        p.receiver_signature = Some(signing.sign(&msg));
    }

    slate.amount = 0;
    slate.fee_fields = FeeFields::zero();
    slate
        .remove_other_sigdata(keychain, &context.sec_nonce, &context.sec_key)
        .map_err(bad)?;
    slate.state = SlateState::Standard2;
    let commit = keychain
        .commit(s1.amount, output_id, SwitchCommitmentType::Regular)
        .map_err(|_| CoreError::Build)?;
    Ok(BuiltS2 {
        s2: to_json(&slate)?,
        commit: commit.0,
        excess: excess.0,
    })
}

// ----- invoice flow ---------------------------------------------------------

pub(crate) struct BuiltI1 {
    pub slate_id: SlateId,
    pub i1: Vec<u8>,
    pub context: SigningContext,
    pub commit: [u8; 33],
}

/// Payee, step 1: an invoice with our output and public keys.
pub(crate) fn build_i1<K: Keychain>(
    keychain: &K,
    parent: &Identifier,
    amount: u64,
    output_id: &Identifier,
    tip_height: u64,
) -> Result<BuiltI1, CoreError> {
    let mut slate = Slate::blank(2, true);
    slate.amount = amount;
    slate.version_info.block_header_version = grin_core::consensus::header_version(tip_height).0;
    slate.kernel_features = 0;
    slate
        .add_transaction_elements(
            keychain,
            &ProofBuilder::new(keychain),
            vec![build::output(amount, output_id.clone())],
        )
        .map_err(bad)?;
    let mut context = Context::new(keychain.secp(), parent, false, true);
    context.add_output(output_id, &None, amount);
    context.amount = amount;
    slate.fill_round_1(keychain, &mut context).map_err(bad)?;
    context.initial_sec_key = context.sec_key.clone();
    slate.compact().map_err(bad)?;
    let commit = keychain
        .commit(amount, output_id, SwitchCommitmentType::Regular)
        .map_err(|_| CoreError::Build)?;
    Ok(BuiltI1 {
        slate_id: *slate.id.as_bytes(),
        i1: to_json(&slate)?,
        context: SigningContext(context),
        commit: commit.0,
    })
}

pub(crate) struct ParsedI1 {
    pub slate: Slate,
    pub slate_id: SlateId,
    pub amount: u64,
}

pub(crate) fn parse_i1(i1: &[u8]) -> Result<ParsedI1, CoreError> {
    let slate = from_json(i1)?;
    if slate.state != SlateState::Invoice1
        || slate.amount == 0
        || slate.num_participants != 2
        || slate.participant_data.len() != 1
    {
        return Err(CoreError::BadSlate("not a payable invoice"));
    }
    if slate.kernel_features != 0
        || slate.kernel_features_args.is_some()
        || slate.payment_proof.is_some()
    {
        return Err(CoreError::BadSlate("unsupported invoice features"));
    }
    Ok(ParsedI1 {
        slate_id: *slate.id.as_bytes(),
        amount: slate.amount,
        slate,
    })
}

pub(crate) struct BuiltI2 {
    pub i2: Vec<u8>,
    pub excess: [u8; 33],
    pub change: Option<(Vec<u8>, u64, Vec<u8>)>,
}

/// Payer: pay an invoice. This is the payer's one signature.
pub(crate) fn build_i2<K: Keychain>(
    keychain: &K,
    parent: &Identifier,
    i1: &ParsedI1,
    picked: &Picked,
    change_id: &Identifier,
) -> Result<BuiltI2, CoreError> {
    let mut slate = i1.slate.clone();
    slate.tx = Some(Slate::empty_transaction());
    slate.fee_fields = FeeFields::new(0, picked.fee).map_err(|_| CoreError::Build)?;
    let mut context = Context::new(keychain.secp(), parent, false, false);
    context.fee = Some(slate.fee_fields);
    context.amount = i1.amount;
    let mut parts = Vec::new();
    for i in &picked.inputs {
        let id = key_id(&i.key_id);
        parts.push(if i.coinbase {
            build::coinbase_input(i.value, id.clone())
        } else {
            build::input(i.value, id.clone())
        });
        context.add_input(&id, &None, i.value);
    }
    let change = if picked.change > 0 {
        parts.push(build::output(picked.change, change_id.clone()));
        context.add_output(change_id, &None, picked.change);
        let commit = keychain
            .commit(picked.change, change_id, SwitchCommitmentType::Regular)
            .map_err(|_| CoreError::Build)?;
        Some((
            change_id.to_bytes().to_vec(),
            picked.change,
            commit.0.to_vec(),
        ))
    } else {
        None
    };
    slate
        .add_transaction_elements(keychain, &ProofBuilder::new(keychain), parts)
        .map_err(bad)?;
    slate.fill_round_1(keychain, &mut context).map_err(bad)?;
    context.initial_sec_key = context.sec_key.clone();
    slate
        .fill_round_2(keychain, &context.sec_key, &context.sec_nonce)
        .map_err(bad)?;
    slate.adjust_offset(keychain, &context).map_err(bad)?;
    slate.tx_or_err_mut().map_err(bad)?.offset = slate.offset.clone();
    let excess = slate.calc_excess(keychain.secp()).map_err(bad)?;
    slate.amount = 0;
    slate
        .remove_other_sigdata(keychain, &context.sec_nonce, &context.sec_key)
        .map_err(bad)?;
    slate.state = SlateState::Invoice2;
    Ok(BuiltI2 {
        i2: to_json(&slate)?,
        excess: excess.0,
        change,
    })
}

/// Payee: what can be checked about I2 before the payee's nonce is touched.
pub(crate) fn check_i2<K: Keychain>(
    keychain: &K, i1: &[u8], i2: &[u8], tip_height: Option<u64>,
) -> Result<(), CoreError> {
    let i1 = from_json(i1)?;
    let mut reply = from_json(i2)?;
    check_ttl(reply.ttl_cutoff_height, tip_height)?;
    let ok = i1.state == SlateState::Invoice1
        && reply.state == SlateState::Invoice2
        && i1.id == reply.id
        && reply.num_participants == 2
        && reply.kernel_features == 0
        && reply.kernel_features_args.is_none()
        && reply.payment_proof.is_none()
        && reply.amount == 0
        && reply.fee_fields != FeeFields::zero()
        && i1.participant_data.len() == 1
        && reply.participant_data.len() == 1;
    if !ok {
        return Err(CoreError::BadSlate("I2 does not match the issued invoice"));
    }
    let (payee, payer) = match (i1.participant_data.first(), reply.participant_data.first()) {
        (Some(a), Some(b)) => (a.clone(), b.clone()),
        _ => return Err(CoreError::BadSlate("participants")),
    };
    let sig = payer
        .part_sig
        .ok_or(CoreError::BadSlate("no payer signature"))?;
    if payee.public_blind_excess == payer.public_blind_excess
        || payee.public_nonce == payer.public_nonce
    {
        return Err(CoreError::BadSlate("payer reused payee keys"));
    }
    reply.amount = i1.amount;
    reply.participant_data.push(payee);
    let secp = keychain.secp();
    let nonces = reply
        .pub_nonce_sum(secp)
        .map_err(|_| CoreError::BadSlate("nonces"))?;
    let keys = reply
        .pub_blind_sum(secp)
        .map_err(|_| CoreError::BadSlate("keys"))?;
    let msg = reply
        .msg_to_sign()
        .map_err(|_| CoreError::BadSlate("message"))?;
    aggsig::verify_partial_sig(
        secp,
        &sig,
        &nonces,
        &payer.public_blind_excess,
        Some(&keys),
        &msg,
    )
    .map_err(|_| CoreError::BadSlate("payer signature does not verify"))?;
    let paid = i1
        .amount
        .checked_add(reply.fee_fields.fee())
        .ok_or(CoreError::BadSlate("amounts"))?;
    check_counterparty_half(keychain, &reply, &payer.public_blind_excess, paid, 0)
}

/// Payee: the one signature that completes an invoice. Called only from
/// `Core::sign_invoice`.
pub(crate) fn finalize_i2<K: Keychain>(
    keychain: &K,
    signer: SigningContext,
    output: (&[u8], u64),
    i2: &[u8],
) -> Result<Finalized, CoreError> {
    let context = &signer.0;
    let mut slate = from_json(i2)?;
    slate.adjust_offset(keychain, &context).map_err(bad)?;
    slate.amount = context.amount;
    slate
        .add_participant_info(keychain, &context, None)
        .map_err(bad)?;
    slate
        .add_transaction_elements(
            keychain,
            &ProofBuilder::new(keychain),
            vec![build::output(output.1, key_id(output.0))],
        )
        .map_err(bad)?;
    slate.tx_or_err_mut().map_err(bad)?.offset = slate.offset.clone();
    slate
        .fill_round_2(keychain, &context.sec_key, &context.sec_nonce)
        .map_err(bad)?;
    slate.finalize(keychain).map_err(bad)?;
    let tx = slate.tx_or_err().map_err(bad)?.clone();
    tx.validate(Weighting::AsTransaction)
        .map_err(|_| CoreError::Build)?;
    let excess = tx
        .kernels()
        .first()
        .map(|k| k.excess.0)
        .ok_or(CoreError::Build)?;
    slate.state = SlateState::Invoice3;
    Ok(Finalized {
        tx: ser::ser_vec(&tx, ser::ProtocolVersion::local()).map_err(|_| CoreError::Build)?,
        s3: to_json(&slate)?,
        excess,
        payment_proof: None,
    })
}

// ----- Slatepack text ---------------------------------------------------------

/// Largest Slatepack text accepted, checked before anything is decoded.
pub const MAX_SLATEPACK_LEN: usize = 64 * 1024;

fn slatepack_address(key: &[u8; 32]) -> Result<grin_wallet_libwallet::SlatepackAddress, CoreError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(key)
        .map_err(|_| CoreError::BadSlate("not an address key"))?;
    Ok(grin_wallet_libwallet::SlatepackAddress::new(&key))
}

/// Slate JSON as Slatepack text. Without `encrypt_to` the text is readable
/// by anyone who sees it; with it, only by the holder of that address.
pub(crate) fn slatepack_encode(
    slate: &[u8],
    sender: Option<[u8; 32]>,
    encrypt_to: Option<[u8; 32]>,
) -> Result<String, CoreError> {
    use grin_wallet_libwallet::{Slatepacker, SlatepackerArgs};
    let slate = from_json(slate)?;
    let sender = match (&sender, &encrypt_to) {
        // a sender is named only inside an encrypted pack
        (Some(s), Some(_)) => Some(slatepack_address(s)?),
        _ => None,
    };
    let recipients = match &encrypt_to {
        Some(r) => vec![slatepack_address(r)?],
        None => vec![],
    };
    let packer = Slatepacker::new(SlatepackerArgs {
        sender,
        recipients,
        dec_key: None,
    });
    let pack = packer.create_slatepack(&slate).map_err(bad)?;
    let text = packer.armor_slatepack(&pack).map_err(bad)?;
    if text.len() > MAX_SLATEPACK_LEN {
        return Err(CoreError::BadSlate("too large"));
    }
    Ok(text)
}

/// Slatepack text as slate JSON. A pack encrypted for the address behind
/// `secret` is opened; one encrypted for someone else is refused. The result
/// has passed the same checks as any slate JSON handed to the core.
pub(crate) fn slatepack_decode(
    text: &str,
    secret: Option<&SigningKey>,
) -> Result<Vec<u8>, CoreError> {
    use grin_wallet_libwallet::{Slatepacker, SlatepackerArgs};
    let text = text.trim();
    if text.len() > MAX_SLATEPACK_LEN {
        return Err(CoreError::BadSlate("too large"));
    }
    // only the armored form is taken: no bare binary and no JSON pack
    if !text.starts_with("BEGINSLATEPACK.") || !text.ends_with("ENDSLATEPACK.") || !text.is_ascii()
    {
        return Err(CoreError::BadSlate("not Slatepack text"));
    }
    let packer = Slatepacker::new(SlatepackerArgs {
        sender: None,
        recipients: vec![],
        dec_key: secret,
    });
    let pack = packer
        .deser_slatepack(text.as_bytes(), true)
        .map_err(|_| CoreError::BadSlate("Slatepack cannot be read"))?;
    let slate = packer
        .get_slate(&pack)
        .map_err(|_| CoreError::BadSlate("Slatepack holds no slate"))?;
    let json = to_json(&slate).map_err(|_| CoreError::BadSlate("Slatepack holds no slate"))?;
    from_json(&json)?;
    Ok(json)
}
