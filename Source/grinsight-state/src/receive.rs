//! Receive a Grin payment sent as a slatepack (RESEARCH / NOT VERIFIED).
//!
//! The sender's wallet makes an S1 slatepack (amount, fee, its public excess
//! and nonce; usually encrypted to our slatepack address). We add one output
//! of `amount` with the next unused key of the account, sign our part and
//! return an S2 slatepack (encrypted to the sender's address when it gave one).
//! The sender finalizes and broadcasts; the new output is then found by the
//! usual scan of new blocks (it is ours by rangeproof rewind).
//!
//! The slatepack, slate and signature logic is grin-wallet's own
//! (`grin_wallet_libwallet`, vendored); this module only replaces its wallet
//! database: the steps follow `api_impl::foreign::receive_tx`.

use crate::wallet::Wallets;
use grin_core::core::{Committed, FeeFields};
use grin_core::libtx::{build, ProofBuilder};
use grin_keychain::{ExtKeychain, ExtKeychainPath, Identifier, Keychain};
use grin_util::secp::key::SecretKey;
use grin_util::secp::pedersen::Commitment;
use grin_util::ToHex;
use grin_wallet_libwallet::{address, Context, Slate, SlateState, SlatepackAddress, Slatepacker, SlatepackerArgs};
use std::convert::TryFrom;

/// grin-wallet's default account: m/0/0, outputs m/0/0/n.
pub fn parent_key_id() -> Identifier {
    ExtKeychain::derive_key_id(2, 0, 0, 0, 0)
}

fn address_secret(k: &ExtKeychain) -> Result<SecretKey, String> {
    address::address_from_derivation_path(k, &parent_key_id(), 0).map_err(|e| format!("address key: {e}"))
}

/// The wallet's slatepack address (grin1... / tgrin1...), as grin-wallet shows it.
pub fn slatepack_address(k: &ExtKeychain) -> Result<String, String> {
    let sec = address_secret(k)?;
    let a = SlatepackAddress::try_from(&sec).map_err(|e| format!("address: {e}"))?;
    Ok(a.to_string())
}

/// Domain-separated proof that this wallet controls its published address.
/// Callers must validate all profile claims and the user's publication consent.
pub fn sign_public_contact(k: &ExtKeychain, transcript: &[u8]) -> Result<[u8; 64], String> {
    use ed25519_dalek::Signer;
    if transcript.len() > 8192 || !transcript.starts_with(b"grinsight-public-contact-v1\0") {
        return Err("invalid contact profile transcript".into());
    }
    let sec = address_secret(k)?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&sec.0).sign(transcript).to_bytes())
}

/// Next output key m/0/0/n: one above every index already used (known own
/// outputs and outputs promised in earlier, not yet confirmed receives).
pub fn next_key_id(used: &[Identifier]) -> Identifier {
    let parent = ExtKeychainPath::from_identifier(&parent_key_id());
    let n = used
        .iter()
        .map(ExtKeychainPath::from_identifier)
        .filter(|p| p.depth == 3 && p.path[0] == parent.path[0] && p.path[1] == parent.path[1])
        .map(|p| u32::from(p.path[2]))
        .max()
        .map_or(0, |m| m + 1);
    ExtKeychain::derive_key_id(3, 0, 0, n, 0)
}

pub struct Received {
    /// Armored S2 slatepack to give back to the sender.
    pub response: String,
    pub amount: u64,
    pub fee: u64,
    pub key_id: Identifier,
    pub commit: Commitment,
    pub slate_id: String,
    pub sender: Option<String>,
    /// Sender address came from the slatepack itself (false: only claimed
    /// in a JSON slate's payment proof request).
    pub sender_verified: bool,
    pub encrypted_in: bool,
    pub payment_proof: bool,
    /// Input and answer are plain V4 slate JSON (Tor foreign API).
    pub json: bool,
}

pub fn is_json(text: &str) -> bool {
    text.trim_start().starts_with('{')
}

/// A V4 slate as grin-wallet puts it on the wire (JSON).
pub fn slate_from_json(text: &str) -> Result<Slate, String> {
    let v: grin_wallet_libwallet::VersionedSlate = serde_json::from_str(text.trim()).map_err(|e| format!("slate JSON: {e}"))?;
    Slate::upgrade(v).map_err(|e| format!("slate JSON: {e}"))
}

pub fn slate_to_json(slate: &Slate) -> Result<String, String> {
    let v = grin_wallet_libwallet::VersionedSlate::into_version(slate.clone(), grin_wallet_libwallet::SlateVersion::V4).map_err(|e| format!("slate JSON: {e}"))?;
    serde_json::to_string(&v).map_err(|e| format!("slate JSON: {e}"))
}

/// Decode an S1 slatepack (armored text, encrypted to our address or plain)
/// and build the S2 answer. `tip_height` must be a verified, fresh tip for TTL checks.
/// Request identity is recorded beside the reservation, before an answer is handed out.
fn request_hash(text: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(text.trim().as_bytes()))
}

fn validate_saved_request(path: &str, sid: &str, wallet: usize, kind: &str, text: &str, cutoff: u64) -> Result<(), String> {
    let records = journal(path)?;
    let mut found = records.iter().filter(|r| rkind(r) == Some(kind) && rs(r, "slate_id") == Some(sid) && r.get("wallet").and_then(|v|v.as_u64()) == Some(wallet as u64));
    let saved = found.next().ok_or("original request identity unavailable; use manual recovery")?;
    if found.next().is_some() { return Err("duplicate original request identity; manual recovery required".into()); }
    if rs(saved, "request_hash") != Some(request_hash(text).as_str()) || saved.get("cutoff_height").and_then(|v|v.as_u64()) != Some(cutoff) {
        return Err("original request changed or predates request identity protection; manual recovery required".into());
    }
    Ok(())
}

fn check_slate_cutoff(cutoff: u64, tip: Option<u64>, kind: &str) -> Result<(), String> {
    if cutoff == 0 { return Ok(()); }
    let tip = tip.ok_or_else(|| format!("{kind} has a cutoff at height {cutoff}; a fresh verified chain tip is required"))?;
    if tip >= cutoff { return Err(format!("{kind} expired at height {cutoff} (tip {tip})")); }
    Ok(())
}

pub fn receive(w: &Wallets, wallet: usize, used: &[Identifier], armored: &str, tip_height: Option<u64>) -> Result<Received, String> {
    let k = w.keychain(wallet).ok_or("no such wallet")?;
    let parent = parent_key_id();
    let sec = address_secret(k)?;
    let dec_key = ed25519_dalek::SigningKey::from_bytes(&sec.0);
    let json_mode = is_json(armored);
    let (slate, sender_addr, encrypted_in) = if json_mode {
        // grin-wallet's Tor foreign API (receive_tx) carries the plain V4 slate
        // as JSON; the sender's address is only the one claimed in the payment
        // proof request (not authenticated).
        let slate = slate_from_json(armored)?;
        let claimed = slate.payment_proof.as_ref().map(|p| SlatepackAddress::new(&p.sender_address));
        (slate, claimed, false)
    } else {
        let packer = Slatepacker::new(SlatepackerArgs { sender: None, recipients: vec![], dec_key: Some(&dec_key) });
        // Mode as sent (decryption resets it): 1 = encrypted to our address.
        let raw = packer.deser_slatepack(armored.trim().as_bytes(), false).map_err(|e| format!("slatepack: {e}"))?;
        let encrypted_in = raw.mode == 1;
        let sp = packer
            .deser_slatepack(armored.trim().as_bytes(), true)
            .map_err(|e| format!("slatepack (is it addressed to this wallet's slatepack address?): {e}"))?;
        let slate = packer.get_slate(&sp).map_err(|e| format!("slate: {e}"))?;
        (slate, sp.sender, encrypted_in)
    };

    // Same checks as grin-wallet's receive_tx.
    if slate.state != SlateState::Standard1 {
        return Err(format!("not a payment to receive (slate state {:?}, expected Standard1 / S1)", slate.state));
    }
    if slate.amount == 0 {
        return Err("slate amount is 0".into());
    }
    check_slate_cutoff(slate.ttl_cutoff_height, tip_height, "slate")?;
    let our_addr = SlatepackAddress::try_from(&sec).map_err(|e| format!("address: {e}"))?;
    if let Some(p) = &slate.payment_proof {
        if p.receiver_address != our_addr.pub_key {
            return Err("payment proof is addressed to another slatepack address".into());
        }
    }

    let amount = slate.amount;
    let fee = slate.fee_fields.fee();
    let key_id = next_key_id(used);
    let mut ret = slate.clone();
    ret.tx = Some(Slate::empty_transaction());
    // selection::build_recipient_output
    ret.add_transaction_elements(k, &ProofBuilder::new(k), vec![build::output(amount, key_id.clone())])
        .map_err(|e| format!("add output: {e}"))?;
    let mut ctx = Context::new(k.secp(), &parent, false, false);
    ctx.add_output(&key_id, &None, amount);
    ctx.amount = amount;
    ctx.fee = ret.fee_fields.as_opt();
    // tx::add_output_to_slate (not initiator)
    ret.fill_round_1(k, &mut ctx).map_err(|e| format!("round 1: {e}"))?;
    ctx.initial_sec_key = ctx.sec_key.clone();
    ret.fill_round_2(k, &ctx.sec_key, &ctx.sec_nonce).map_err(|e| format!("round 2: {e}"))?;
    // foreign::receive_tx
    ret.adjust_offset(k, &ctx).map_err(|e| format!("offset: {e}"))?;
    let excess = ret.calc_excess(k.secp()).map_err(|e| format!("excess: {e}"))?;
    let mut payment_proof = false;
    if let Some(p) = ret.payment_proof.as_mut() {
        // tx::create_payment_proof_signature
        use ed25519_dalek::Signer;
        let mut msg = Vec::with_capacity(8 + 33 + 32);
        msg.extend_from_slice(&amount.to_be_bytes());
        msg.extend_from_slice(&excess.0);
        msg.extend_from_slice(p.sender_address.as_bytes());
        p.receiver_signature = Some(dec_key.sign(&msg));
        payment_proof = true;
    }
    ret.amount = 0;
    ret.fee_fields = FeeFields::zero();
    ret.remove_other_sigdata(k, &ctx.sec_nonce, &ctx.sec_key).map_err(|e| format!("sigdata: {e}"))?;
    ret.state = SlateState::Standard2;

    let commit = ret.tx_or_err().map_err(|e| format!("{e}"))?.outputs()[0].commitment();
    if k.commit(amount, &key_id, grin_keychain::SwitchCommitmentType::Regular).map_err(|e| format!("{e:?}"))? != commit {
        return Err("new output commitment mismatch".into());
    }
    // Answer: JSON for JSON (Tor foreign API); otherwise a slatepack from our
    // address, encrypted to the sender when it gave its address.
    let response = if json_mode {
        slate_to_json(&ret)?
    } else {
        let recipients: Vec<SlatepackAddress> = sender_addr.clone().into_iter().collect();
        let out = Slatepacker::new(SlatepackerArgs { sender: Some(our_addr), recipients, dec_key: None });
        let pack = out.create_slatepack(&ret).map_err(|e| format!("pack: {e}"))?;
        out.armor_slatepack(&pack).map_err(|e| format!("armor: {e}"))?
    };
    Ok(Received {
        response,
        amount,
        fee,
        key_id,
        commit,
        slate_id: slate.id.to_string(),
        sender: sender_addr.map(|a| a.to_string()),
        sender_verified: !json_mode,
        encrypted_in,
        payment_proof,
        json: json_mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use grin_core::core::{Transaction, Weighting};
    use grin_core::global::{self, ChainTypes};
    use grin_wallet_libwallet::{SlateVersion, VersionedSlate};

    #[test]
    fn cutoff_requires_tip_and_expires_at_boundary() {
        assert!(check_slate_cutoff(0, None, "slate").is_ok());
        assert!(check_slate_cutoff(100, None, "slate").unwrap_err().contains("fresh verified chain tip"));
        assert!(check_slate_cutoff(100, Some(99), "slate").is_ok());
        assert!(check_slate_cutoff(100, Some(100), "slate").unwrap_err().contains("expired"));
        assert!(check_slate_cutoff(100, Some(101), "invoice").unwrap_err().contains("expired"));
    }

    fn keychain(seed: u8) -> ExtKeychain {
        ExtKeychain::from_seed(&[seed; 32], true).unwrap()
    }

    /// Sender side as grin-wallet does it (init_send_tx + finalize_tx),
    /// receiver side = `receive` above; the final transaction must validate.
    fn round_trip(encrypt: bool, with_proof: bool) {
        global::set_local_chain_type(ChainTypes::Testnet);
        let ks = keychain(7);
        let w = Wallets::from_keychains(vec![keychain(9)]);
        let kr = w.keychain(0).unwrap();
        let our_addr_str = slatepack_address(kr).unwrap();
        assert!(our_addr_str.starts_with("tgrin1"), "{our_addr_str}");

        // --- sender: S1 ---
        let parent = parent_key_id();
        let in_id = ExtKeychain::derive_key_id(3, 0, 0, 5, 0);
        let change_id = ExtKeychain::derive_key_id(3, 0, 0, 6, 0);
        let in_amount = 10_000_000_000u64;
        let amount = 3_000_000_000u64;
        let fee = Transaction::weight_by_iok(1, 2, 1) * global::get_accept_fee_base();
        let change = in_amount - amount - fee;
        let mut s1 = Slate::blank(2, false);
        s1.amount = amount;
        s1.ttl_cutoff_height = 101;
        s1.kernel_features = 0;
        s1.fee_fields = FeeFields::new(0, fee).unwrap();
        s1.add_transaction_elements(&ks, &ProofBuilder::new(&ks), vec![build::input(in_amount, in_id.clone()), build::output(change, change_id.clone())])
            .unwrap();
        let mut sctx = Context::new(ks.secp(), &parent, false, true);
        sctx.fee = Some(s1.fee_fields);
        sctx.amount = amount;
        sctx.add_input(&in_id, &None, in_amount);
        sctx.add_output(&change_id, &None, change);
        s1.fill_round_1(&ks, &mut sctx).unwrap();
        sctx.initial_sec_key = sctx.sec_key.clone();
        let sender_sec = address::address_from_derivation_path(&ks, &parent, 0).unwrap();
        let sender_addr = SlatepackAddress::try_from(&sender_sec).unwrap();
        let our_addr = SlatepackAddress::try_from(&address_secret(kr).unwrap()).unwrap();
        if with_proof {
            // PaymentInfo is private in libwallet: add the proof through the V4 JSON form.
            let mut v = serde_json::to_value(VersionedSlate::into_version(s1.clone(), SlateVersion::V4).unwrap()).unwrap();
            v["proof"] = serde_json::json!({
                "saddr": sender_addr.pub_key.to_bytes().to_hex(),
                "raddr": our_addr.pub_key.to_bytes().to_hex(),
            });
            let vs: VersionedSlate = serde_json::from_value(v).unwrap();
            let upgraded = Slate::upgrade(vs).unwrap();
            assert!(upgraded.payment_proof.is_some());
            s1.payment_proof = upgraded.payment_proof;
        }
        let packer = Slatepacker::new(SlatepackerArgs {
            sender: Some(sender_addr.clone()),
            recipients: if encrypt { vec![our_addr.clone()] } else { vec![] },
            dec_key: None,
        });
        let armored_s1 = packer.armor_slatepack(&packer.create_slatepack(&s1).unwrap()).unwrap();

        // --- receiver ---
        let used = vec![ExtKeychain::derive_key_id(3, 0, 0, 0, 0), ExtKeychain::derive_key_id(3, 0, 0, 3, 0)];
        assert!(receive(&w, 0, &used, &armored_s1, None).err().unwrap().contains("fresh verified chain tip"));
        assert!(receive(&w, 0, &used, &armored_s1, Some(101)).err().unwrap().contains("expired"));
        let r = receive(&w, 0, &used, &armored_s1, Some(100)).unwrap();
        assert_eq!(r.amount, amount);
        assert_eq!(r.encrypted_in, encrypt);
        assert_eq!(r.payment_proof, with_proof);
        assert_eq!(r.key_id, ExtKeychain::derive_key_id(3, 0, 0, 4, 0));
        assert_eq!(r.sender.as_deref(), Some(sender_addr.to_string().as_str()));

        // --- sender: finalize S2 (decrypt with its own address key) ---
        let sdec = ed25519_dalek::SigningKey::from_bytes(&sender_sec.0);
        let sp = Slatepacker::new(SlatepackerArgs { sender: None, recipients: vec![], dec_key: Some(&sdec) });
        assert_eq!(sp.deser_slatepack(r.response.as_bytes(), false).unwrap().mode, 1, "answer is encrypted to the sender");
        let pack2 = sp.deser_slatepack(r.response.as_bytes(), true).unwrap();
        let mut s2 = sp.get_slate(&pack2).unwrap();
        assert_eq!(s2.state, SlateState::Standard2);
        let proof = s2.payment_proof.clone();
        if with_proof {
            assert!(proof.as_ref().unwrap().receiver_signature.is_some());
        }
        // foreign::finalize_tx (Standard2)
        s2.adjust_offset(&ks, &sctx).unwrap();
        s2.amount = sctx.amount;
        s2.fee_fields = sctx.fee.unwrap();
        s2.add_participant_info(&ks, &sctx, None).unwrap();
        s2.add_transaction_elements(&ks, &ProofBuilder::new(&ks), vec![build::input(in_amount, in_id.clone()), build::output(change, change_id.clone())])
            .unwrap();
        s2.tx_or_err_mut().unwrap().offset = s2.offset.clone();
        s2.fill_round_2(&ks, &sctx.sec_key, &sctx.sec_nonce).unwrap();
        s2.finalize(&ks).unwrap();
        let tx = s2.tx_or_err().unwrap().clone();
        tx.validate(Weighting::AsTransaction).unwrap();
        assert_eq!(tx.inputs().len(), 1);
        assert_eq!(tx.outputs().len(), 2);
        assert!(tx.outputs().iter().any(|o| o.commitment() == r.commit));
        if let Some(p) = proof {
            // What the sender checks (tx::verify_slate_payment_proof): our
            // address signed amount || kernel excess || sender address.
            use ed25519_dalek::Verifier;
            let mut msg = Vec::new();
            msg.extend_from_slice(&amount.to_be_bytes());
            msg.extend_from_slice(&tx.kernels()[0].excess.0);
            msg.extend_from_slice(sender_addr.pub_key.as_bytes());
            our_addr.pub_key.verify(&msg, p.receiver_signature.as_ref().unwrap()).expect("payment proof signature");
        }
        // Our output is found by the normal rewind scan.
        let rows: Vec<_> = tx.outputs().iter().map(|o| (u64::MAX, o.identifier, o.proof)).collect();
        let found = w.discover(&rows).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].amount, amount);
        assert_eq!(found[0].commit, r.commit);
    }

    #[test]
    fn receive_encrypted_slatepack_round_trip() {
        round_trip(true, false);
    }

    #[test]
    fn receive_plain_slatepack_with_payment_proof() {
        round_trip(false, true);
    }

    /// Regression: a compact S2 may already carry our inputs and change
    /// (Grin++ 2.0.0 echoes the whole slate; grin-wallet returns only the
    /// receiver's output). Re-adding them made a duplicate change output and the
    /// fee check failed with "Fee Dispute Error" (Grin++ 2.0.0, live 2026-11-12).
    /// `finalize` now adds only what is missing; this checks the detection on a
    /// real slate body and on a receiver-only body.
    #[test]
    fn compact_s2_elements_are_detected_not_readded() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let ks = keychain(7);
        let in_id = ExtKeychain::derive_key_id(3, 0, 0, 5, 0);
        let change_id = ExtKeychain::derive_key_id(3, 0, 0, 6, 0);
        let in_amount = 10_000_000_000u64;
        let amount = 3_000_000_000u64;
        let fee = Transaction::weight_by_iok(1, 2, 1) * global::get_accept_fee_base();
        let change = in_amount - amount - fee;
        let in_commit = ks.commit(in_amount, &in_id, grin_keychain::SwitchCommitmentType::Regular).unwrap();
        let change_commit = ks.commit(change, &change_id, grin_keychain::SwitchCommitmentType::Regular).unwrap();
        let mut s1 = Slate::blank(2, false);
        s1.amount = amount;
        s1.fee_fields = FeeFields::new(0, fee).unwrap();
        s1.add_transaction_elements(&ks, &ProofBuilder::new(&ks), vec![build::input(in_amount, in_id.clone()), build::output(change, change_id.clone())])
            .unwrap();
        let tx = s1.tx_or_err().unwrap().clone();
        let inputs = vec![InputSel { key_id: in_id.to_hex(), amount: in_amount, coinbase: false, commit: in_commit.0.to_hex() }];
        assert_eq!(send_elements_present(&tx, &inputs, &change_commit), (true, true), "an echoed body already has our side");
        let empty = Slate::empty_transaction();
        assert_eq!(send_elements_present(&empty, &inputs, &change_commit), (false, false), "a receiver-only S2 needs our side added");
    }

    #[test]
    fn next_key_skips_used_indexes() {
        assert_eq!(next_key_id(&[]), ExtKeychain::derive_key_id(3, 0, 0, 0, 0));
        let used = vec![ExtKeychain::derive_key_id(3, 0, 0, 7, 0), ExtKeychain::derive_key_id(3, 1, 0, 50, 0)];
        assert_eq!(next_key_id(&used), ExtKeychain::derive_key_id(3, 0, 0, 8, 0));
    }

    #[test]
    fn rejects_garbage_and_wrong_state() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let w = Wallets::from_keychains(vec![keychain(9)]);
        assert!(receive(&w, 0, &[], "BEGINSLATEPACK. xyz. ENDSLATEPACK.", None).is_err());
    }

    #[test]
    fn hex_of_commit_is_33_bytes() {
        let c = Commitment::from_vec(vec![8u8; 33]);
        assert_eq!(c.0.to_hex().len(), 66);
    }
}

// ---------------------------------------------------------------------------
// Sending to a slatepack address: S1 (initiator) and finalize (S2 -> S3);
// invoices: I1 (issuer), I2 (payer), finalize (I2 -> I3)
// ---------------------------------------------------------------------------

/// One own output used as an input.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InputSel {
    pub key_id: String,
    pub amount: u64,
    pub coinbase: bool,
    pub commit: String,
}

impl InputSel {
    pub fn new(key: &Identifier, amount: u64, coinbase: bool, commit: &Commitment) -> Self {
        InputSel { key_id: key.to_hex(), amount, coinbase, commit: commit.0.to_hex() }
    }
    fn id(&self) -> Result<Identifier, String> {
        key_id_from_hex(&self.key_id).ok_or_else(|| "input key id hex".to_string())
    }
    fn element(&self) -> Result<Box<build::Append<ExtKeychain, ProofBuilder<ExtKeychain>>>, String> {
        let id = self.id()?;
        Ok(if self.coinbase { build::coinbase_input(self.amount, id) } else { build::input(self.amount, id) })
    }
}

/// grin-wallet's fee: `n_in` inputs, 2 outputs (change + receiver), 1 kernel.
pub fn send_fee_for(n_in: usize) -> u64 {
    grin_core::core::Transaction::weight_by_iok(n_in as u64, 2, 1) * grin_core::global::get_accept_fee_base()
}

pub fn send_fee() -> u64 {
    send_fee_for(1)
}

/// Largest outputs first until they cover `amount` + the fee for that many
/// inputs, with change left over. `candidates` = spendable own outputs.
pub fn select_inputs(candidates: &[InputSel], amount: u64) -> Result<Vec<InputSel>, String> {
    let mut c = candidates.to_vec();
    c.sort_by(|a, b| b.amount.cmp(&a.amount));
    // u128 sums: an amount from an incoming invoice (or many large inputs)
    // cannot overflow; an impossible amount is an error, not a panic.
    if amount as u128 + send_fee_for(candidates.len().max(1)) as u128 > u64::MAX as u128 {
        return Err(format!("amount {amount} is too large (amount + fee does not fit in 64 bits)"));
    }
    let mut picked = Vec::new();
    let mut sum = 0u128;
    for x in c {
        sum += x.amount as u128;
        picked.push(x);
        if sum > amount as u128 + send_fee_for(picked.len()) as u128 {
            return Ok(picked);
        }
    }
    let total: u128 = candidates.iter().map(|x| x.amount as u128).sum();
    Err(format!(
        "not enough spendable funds: {total} nanogrin in {} outputs, need {amount} + fee {} (and some change)",
        candidates.len(),
        send_fee_for(candidates.len().max(1))
    ))
}

/// What the sender (or invoice issuer) keeps between its two steps. It holds
/// the signing secrets (excess key + nonce) of this one transaction: written
/// next to the run, deleted by the finishing step. Never sent anywhere.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct SendContext {
    pub wallet: usize,
    pub slate_id: String,
    /// Receiver (send) or payer (invoice), when known.
    pub dest: String,
    pub inputs: Vec<InputSel>,
    /// Our own new output: change (send) or the invoiced amount (invoice).
    pub own_output: String,
    pub own_output_amount: u64,
    pub payment_proof: bool,
    pub ctx: Context,
}

pub struct SendBuilt {
    pub s1: String,
    /// The same S1 as plain V4 JSON (for grin-wallet's Tor foreign API).
    pub s1_json: String,
    pub context: SendContext,
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    pub change_key: Identifier,
}

fn our_address(k: &ExtKeychain) -> Result<(SecretKey, SlatepackAddress), String> {
    let sec = address_secret(k)?;
    let a = SlatepackAddress::try_from(&sec).map_err(|e| format!("address: {e}"))?;
    Ok((sec, a))
}

fn parse_dest(dest: &str) -> Result<SlatepackAddress, String> {
    let a = SlatepackAddress::try_from(dest.trim()).map_err(|e| format!("address {dest}: {e}"))?;
    if !a.valid_network() {
        return Err(format!("{dest} is an address of the other network"));
    }
    Ok(a)
}

fn armor(sender: Option<SlatepackAddress>, to: Option<SlatepackAddress>, slate: &Slate) -> Result<String, String> {
    let packer = Slatepacker::new(SlatepackerArgs { sender, recipients: to.into_iter().collect(), dec_key: None });
    packer.armor_slatepack(&packer.create_slatepack(slate).map_err(|e| format!("pack: {e}"))?).map_err(|e| format!("armor: {e}"))
}

/// Decrypt with our address key; returns the slate and the sender's address.
fn unarmor(k: &ExtKeychain, text: &str) -> Result<(Slate, Option<SlatepackAddress>), String> {
    if is_json(text) {
        return Ok((slate_from_json(text)?, None));
    }
    let (sec, _) = our_address(k)?;
    let dec_key = ed25519_dalek::SigningKey::from_bytes(&sec.0);
    let packer = Slatepacker::new(SlatepackerArgs { sender: None, recipients: vec![], dec_key: Some(&dec_key) });
    let sp = packer.deser_slatepack(text.trim().as_bytes(), true).map_err(|e| format!("slatepack: {e}"))?;
    let slate = packer.get_slate(&sp).map_err(|e| format!("slate: {e}"))?;
    Ok((slate, sp.sender))
}

/// Initiator side of a payment (grin-wallet `init_send_tx`, no late lock):
/// the given inputs, a change output with the next unused key, a payment
/// proof request, S1 encrypted to `dest`. `wallet` is 0-based.
pub fn build_send(w: &Wallets, wallet: usize, inputs: &[InputSel], used: &[Identifier], amount: u64, dest: &str) -> Result<SendBuilt, String> {
    let k = w.keychain(wallet).ok_or("no such wallet")?;
    if inputs.is_empty() {
        return Err("no inputs".into());
    }
    let dest_addr = parse_dest(dest)?;
    let fee = send_fee_for(inputs.len());
    let in_sum: u64 = inputs.iter().try_fold(0u64, |a, x| a.checked_add(x.amount)).ok_or("input amounts overflow")?;
    let change = in_sum
        .checked_sub(amount)
        .and_then(|x| x.checked_sub(fee))
        .ok_or(format!("inputs {in_sum} do not cover amount {amount} + fee {fee}"))?;
    if change == 0 {
        return Err("no change left: pick another amount (zero-value change output not supported)".into());
    }
    let parent = parent_key_id();
    let change_key = next_key_id(used);
    let mut elems = Vec::new();
    for i in inputs {
        elems.push(i.element()?);
    }
    elems.push(build::output(change, change_key.clone()));
    let mut s1 = Slate::blank(2, false);
    s1.amount = amount;
    s1.kernel_features = 0;
    s1.fee_fields = FeeFields::new(0, fee).map_err(|e| format!("fee: {e:?}"))?;
    s1.add_transaction_elements(k, &ProofBuilder::new(k), elems).map_err(|e| format!("add inputs: {e}"))?;
    let mut ctx = Context::new(k.secp(), &parent, false, true);
    ctx.fee = Some(s1.fee_fields);
    ctx.amount = amount;
    for i in inputs {
        ctx.add_input(&i.id()?, &None, i.amount);
    }
    ctx.add_output(&change_key, &None, change);
    s1.fill_round_1(k, &mut ctx).map_err(|e| format!("round 1: {e}"))?;
    ctx.initial_sec_key = ctx.sec_key.clone();
    let (_, our_addr) = our_address(k)?;
    // Payment proof: the receiver signs (amount, kernel excess, our address).
    s1.payment_proof = Some(grin_wallet_libwallet::PaymentInfo {
        sender_address: our_addr.pub_key,
        receiver_address: dest_addr.pub_key,
        receiver_signature: None,
    });
    ctx.payment_proof_derivation_index = Some(0);
    let change_commit = k.commit(change, &change_key, grin_keychain::SwitchCommitmentType::Regular).map_err(|e| format!("{e:?}"))?;
    let s1_text = armor(Some(our_addr), Some(dest_addr), &s1)?;
    let s1_json = slate_to_json(&s1)?;
    Ok(SendBuilt {
        s1: s1_text,
        s1_json,
        context: SendContext {
            wallet: wallet + 1,
            slate_id: s1.id.to_string(),
            dest: dest.trim().to_string(),
            inputs: inputs.to_vec(),
            own_output: change_commit.0.to_hex(),
            own_output_amount: change,
            payment_proof: true,
            ctx,
        },
        amount,
        fee,
        change,
        change_key,
    })
}

fn proof_message(amount: u64, excess: &Commitment, sender: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    let mut msg = Vec::with_capacity(8 + 33 + 32);
    msg.extend_from_slice(&amount.to_be_bytes());
    msg.extend_from_slice(&excess.0);
    msg.extend_from_slice(sender.as_bytes());
    msg
}

/// Which of our side a compact S2 already carries: (all inputs, our change).
/// grin-wallet returns an S2 with only the receiver's output; Grin++ 2.0.0
/// echoes the whole slate, so nothing on our side may be added twice.
fn send_elements_present(tx: &grin_core::core::Transaction, inputs: &[InputSel], change: &Commitment) -> (bool, bool) {
    let all_inputs = inputs.iter().all(|i| tx.inputs_committed().iter().any(|c| c.0.to_hex() == i.commit));
    let change_present = tx.outputs().iter().any(|o| o.commitment() == *change);
    (all_inputs, change_present)
}

/// Sender finalizes the receiver's S2 (grin-wallet `finalize_tx`, Standard2):
/// the complete, validated transaction; the receiver's payment proof
/// signature is checked and the proof (grin-wallet format) returned.
pub fn finalize(w: &Wallets, sc: &SendContext, s2_text: &str) -> Result<(grin_core::core::Transaction, Commitment, Option<String>), String> {
    let k = w.keychain(sc.wallet - 1).ok_or("no such wallet")?;
    let (mut s2, _) = unarmor(k, s2_text)?;
    if s2.state != SlateState::Standard2 {
        return Err(format!("not a receiver's answer (state {:?}, expected Standard2 / S2)", s2.state));
    }
    if s2.id.to_string() != sc.slate_id {
        return Err(format!("answer is for slate {}, this payment is {}", s2.id, sc.slate_id));
    }
    let ctx = &sc.ctx;
    let (ch_id, _, ch_amount) = ctx.output_ids.first().cloned().ok_or("context has no change")?;
    s2.adjust_offset(k, ctx).map_err(|e| format!("offset: {e}"))?;
    // selection::repopulate_tx
    s2.amount = ctx.amount;
    s2.fee_fields = ctx.fee.ok_or("context has no fee")?;
    // The answer may carry fee 0 (grin-wallet's receiver zeroes it); the kernel
    // must reflect OUR fee even when there is nothing to add below.
    s2.update_kernel().map_err(|e| format!("kernel: {e}"))?;
    s2.add_participant_info(k, ctx, None).map_err(|e| format!("participant: {e}"))?;
    // A V4 slate crosses the wire compact (`coms`): `tx` is rebuilt from it and
    // already carries our inputs and change. Add only what is missing. Do not
    // rely on the dedup inside `Transaction::with_output`: another wallet's
    // `coms` (Grin++ 2.0.0) are not in grin's Output order, its binary search
    // misses our change and the tx gets a second copy -> "Fee Dispute Error".
    let own_change = Commitment::from_vec(grin_util::from_hex(&sc.own_output).map_err(|_| "change commit hex")?);
    let (inputs_present, change_present) = s2
        .tx_or_err()
        .map(|tx| send_elements_present(tx, &sc.inputs, &own_change))
        .unwrap_or((false, false));
    let mut elems = Vec::new();
    if !inputs_present {
        for i in &sc.inputs {
            elems.push(i.element()?);
        }
    }
    if !change_present {
        elems.push(build::output(ch_amount, ch_id.clone()));
    }
    if !elems.is_empty() {
        s2.add_transaction_elements(k, &ProofBuilder::new(k), elems).map_err(|e| format!("add inputs: {e}"))?;
    }
    // A compact slate from another wallet may list its outputs in its own
    // order; keep the transaction body canonical (and deduplicated).
    {
        let tx = s2.tx_or_err_mut().map_err(|e| format!("{e}"))?;
        let mut outs = tx.outputs().to_vec();
        outs.sort();
        outs.dedup();
        tx.body = tx.body.clone().replace_outputs(&outs);
    }
    let off = s2.offset.clone();
    s2.tx_or_err_mut().map_err(|e| format!("{e}"))?.offset = off;
    // tx::complete_tx
    s2.fill_round_2(k, &ctx.sec_key, &ctx.sec_nonce).map_err(|e| format!("round 2: {e}"))?;
    s2.finalize(k).map_err(|e| format!("finalize: {e}"))?;
    let tx = s2.tx_or_err().map_err(|e| format!("{e}"))?.clone();
    tx.validate(grin_core::core::Weighting::AsTransaction).map_err(|e| format!("transaction does not validate: {e:?}"))?;
    if tx.inputs().len() != sc.inputs.len() || tx.outputs().len() != 2 || tx.kernels().len() != 1 {
        return Err("unexpected transaction shape".into());
    }
    if tx.fee() != ctx.fee.map(|f| f.fee()).unwrap_or(0) {
        return Err("fee changed".into());
    }
    let own = own_change;
    if !tx.outputs().iter().any(|o| o.commitment() == own) {
        return Err("our change output is missing".into());
    }
    let theirs = tx.outputs().iter().map(|o| o.commitment()).find(|c| *c != own).ok_or("receiver output missing")?;
    // tx::verify_slate_payment_proof
    let mut proof_json = None;
    if sc.payment_proof {
        let p = s2.payment_proof.as_ref().ok_or("payment proof requested but missing in the answer")?;
        let sig = p.receiver_signature.ok_or("receiver did not sign the payment proof")?;
        // Both addresses come from the answer: they must be the ones of THIS
        // payment (our address, the receiver we sent to), or the proof would
        // name / be signed by someone else (grin-wallet compares them with the
        // stored tx log entry in verify_slate_payment_proof).
        let (sec, ours) = our_address(k)?;
        let dest = parse_dest(&sc.dest).map_err(|e| format!("payment context: {e}"))?;
        check_proof_addresses(&p.sender_address, &p.receiver_address, &ours.pub_key, &dest.pub_key)?;
        let excess = tx.kernels()[0].excess;
        let msg = proof_message(ctx.amount, &excess, &ours.pub_key);
        use ed25519_dalek::{Signer, Verifier};
        dest.pub_key.verify(&msg, &sig).map_err(|_| "receiver's payment proof signature is invalid")?;
        let sender_sig = ed25519_dalek::SigningKey::from_bytes(&sec.0).sign(&msg);
        let proof = grin_wallet_libwallet::PaymentProof {
            amount: ctx.amount,
            excess,
            recipient_address: dest.clone(),
            recipient_sig: sig,
            sender_address: ours,
            sender_sig,
        };
        proof_json = Some(serde_json::to_string_pretty(&proof).map_err(|e| format!("proof: {e}"))?);
    }
    Ok((tx, theirs, proof_json))
}

/// The payment proof in an answer must name us as sender and the receiver we
/// paid as receiver; a substituted address on either side is refused.
pub fn check_proof_addresses(
    sender_in_answer: &ed25519_dalek::VerifyingKey,
    receiver_in_answer: &ed25519_dalek::VerifyingKey,
    ours: &ed25519_dalek::VerifyingKey,
    dest: &ed25519_dalek::VerifyingKey,
) -> Result<(), String> {
    if sender_in_answer != ours {
        return Err("payment proof: sender address in the answer is not ours".into());
    }
    if receiver_in_answer != dest {
        return Err("payment proof: receiver address in the answer is not the one we paid".into());
    }
    Ok(())
}

/// Invoice step 1 (grin-wallet `issue_invoice_tx`): we ask for `amount`; our
/// output with the next unused key; I1 (encrypted to the payer if known).
pub fn issue_invoice(w: &Wallets, wallet: usize, used: &[Identifier], amount: u64, payer: Option<&str>) -> Result<(String, SendContext, Identifier), String> {
    let k = w.keychain(wallet).ok_or("no such wallet")?;
    if amount == 0 {
        return Err("invoice amount is 0".into());
    }
    let payer_addr = match payer {
        Some(p) => Some(parse_dest(p)?),
        None => None,
    };
    let parent = parent_key_id();
    let key_id = next_key_id(used);
    let mut slate = Slate::blank(2, true);
    slate.amount = amount;
    slate.kernel_features = 0;
    // selection::build_recipient_output + tx::add_output_to_slate (initiator)
    slate.add_transaction_elements(k, &ProofBuilder::new(k), vec![build::output(amount, key_id.clone())]).map_err(|e| format!("add output: {e}"))?;
    let mut ctx = Context::new(k.secp(), &parent, false, true);
    ctx.add_output(&key_id, &None, amount);
    ctx.amount = amount;
    ctx.fee = slate.fee_fields.as_opt();
    slate.fill_round_1(k, &mut ctx).map_err(|e| format!("round 1: {e}"))?;
    ctx.initial_sec_key = ctx.sec_key.clone();
    let commit = k.commit(amount, &key_id, grin_keychain::SwitchCommitmentType::Regular).map_err(|e| format!("{e:?}"))?;
    let id = slate.id.to_string();
    slate.compact().map_err(|e| format!("{e}"))?;
    let (_, ours) = our_address(k)?;
    let text = armor(Some(ours), payer_addr, &slate)?;
    Ok((
        text,
        SendContext {
            wallet: wallet + 1,
            slate_id: id,
            dest: payer.unwrap_or("").to_string(),
            inputs: vec![],
            own_output: commit.0.to_hex(),
            own_output_amount: amount,
            payment_proof: false,
            ctx,
        },
        key_id,
    ))
}

pub struct InvoicePaid {
    pub i2: String,
    /// The same I2 as plain V4 slate JSON (grin-wallet Tor foreign API
    /// `finalize_tx`; no secrets in it).
    pub i2_json: String,
    pub slate_id: String,
    pub amount: u64,
    pub fee: u64,
    pub change: u64,
    pub change_key: Identifier,
    pub change_commit: Commitment,
    pub issuer: Option<String>,
    pub inputs: Vec<InputSel>,
}

/// Invoice step 2, payer side (grin-wallet `process_invoice_tx`): read I1,
/// pick inputs from `candidates`, add change, sign; I2 back to the issuer.
pub fn pay_invoice(w: &Wallets, wallet: usize, candidates: &[InputSel], used: &[Identifier], i1_text: &str, tip_height: Option<u64>) -> Result<InvoicePaid, String> {
    let k = w.keychain(wallet).ok_or("no such wallet")?;
    let (slate, issuer) = unarmor(k, i1_text)?;
    if slate.state != SlateState::Invoice1 {
        return Err(format!("not an invoice (slate state {:?}, expected Invoice1 / I1)", slate.state));
    }
    if slate.amount == 0 {
        return Err("invoice amount is 0".into());
    }
    check_slate_cutoff(slate.ttl_cutoff_height, tip_height, "invoice")?;
    let amount = slate.amount;
    let inputs = select_inputs(candidates, amount)?;
    let fee = send_fee_for(inputs.len());
    let in_sum: u64 = inputs.iter().try_fold(0u64, |a, x| a.checked_add(x.amount)).ok_or("input amounts overflow")?;
    let change = in_sum
        .checked_sub(amount)
        .and_then(|x| x.checked_sub(fee))
        .ok_or(format!("inputs {in_sum} do not cover amount {amount} + fee {fee}"))?;
    let parent = parent_key_id();
    let change_key = next_key_id(used);
    let mut ret = slate.clone();
    ret.tx = Some(Slate::empty_transaction());
    // selection::build_send_tx (not initiator)
    ret.fee_fields = FeeFields::new(0, fee).map_err(|e| format!("fee: {e:?}"))?;
    let mut elems = Vec::new();
    for i in &inputs {
        elems.push(i.element()?);
    }
    elems.push(build::output(change, change_key.clone()));
    ret.add_transaction_elements(k, &ProofBuilder::new(k), elems).map_err(|e| format!("add inputs: {e}"))?;
    let mut ctx = Context::new(k.secp(), &parent, false, false);
    ctx.fee = Some(ret.fee_fields);
    ctx.amount = amount;
    for i in &inputs {
        ctx.add_input(&i.id()?, &None, i.amount);
    }
    ctx.add_output(&change_key, &None, change);
    // tx::add_inputs_to_slate (not initiator): round 1 + round 2
    ret.fill_round_1(k, &mut ctx).map_err(|e| format!("round 1: {e}"))?;
    ctx.initial_sec_key = ctx.sec_key.clone();
    ret.fill_round_2(k, &ctx.sec_key, &ctx.sec_nonce).map_err(|e| format!("round 2: {e}"))?;
    ret.adjust_offset(k, &ctx).map_err(|e| format!("offset: {e}"))?;
    let off = ret.offset.clone();
    ret.tx_or_err_mut().map_err(|e| format!("{e}"))?.offset = off;
    ret.amount = 0;
    ret.remove_other_sigdata(k, &ctx.sec_nonce, &ctx.sec_key).map_err(|e| format!("sigdata: {e}"))?;
    ret.state = SlateState::Invoice2;
    let change_commit = k.commit(change, &change_key, grin_keychain::SwitchCommitmentType::Regular).map_err(|e| format!("{e:?}"))?;
    let (_, ours) = our_address(k)?;
    // Plain JSON next to the encrypted answer: the issuer's grin-wallet /
    // Grin++ Tor foreign API takes the I2 as a V4 slate (finalize_tx).
    let i2_json = slate_to_json(&ret)?;
    let i2 = armor(Some(ours), issuer.clone(), &ret)?;
    Ok(InvoicePaid {
        i2,
        i2_json,
        slate_id: slate.id.to_string(),
        amount,
        fee,
        change,
        change_key,
        change_commit,
        issuer: issuer.map(|a| a.to_string()),
        inputs,
    })
}

/// Invoice step 3, issuer side (grin-wallet `finalize_tx`, Invoice2):
/// the finished transaction, the payer's outputs, and the finalized I3 slate
/// as plain JSON (grin-wallet's foreign API answers with it).
pub fn finalize_invoice_state(w: &Wallets, sc: &SendContext, i2_text: &str) -> Result<(grin_core::core::Transaction, Vec<Commitment>, String), String> {
    let k = w.keychain(sc.wallet - 1).ok_or("no such wallet")?;
    let (mut sl, _) = unarmor(k, i2_text)?;
    if sl.state != SlateState::Invoice2 {
        return Err(format!("not a paid invoice (state {:?}, expected Invoice2 / I2)", sl.state));
    }
    if sl.id.to_string() != sc.slate_id {
        return Err(format!("answer is for slate {}, this invoice is {}", sl.id, sc.slate_id));
    }
    let ctx = &sc.ctx;
    let (out_id, _, out_amount) = ctx.output_ids.first().cloned().ok_or("context has no output")?;
    sl.adjust_offset(k, ctx).map_err(|e| format!("offset: {e}"))?;
    let mut temp = ctx.clone();
    temp.sec_key = ctx.initial_sec_key.clone();
    temp.sec_nonce = ctx.initial_sec_nonce.clone();
    // selection::repopulate_tx (update_fee = false)
    sl.amount = temp.amount;
    sl.add_participant_info(k, &temp, None).map_err(|e| format!("participant: {e}"))?;
    // The payer's I2 normally carries only its own side (grin-wallet), but
    // Grin++ 2.0.0 echoes the whole slate. Adding our output again would make a
    // second copy of it (the same class of bug as the S2 fee dispute), so add it
    // only when it is really absent.
    let own = Commitment::from_vec(grin_util::from_hex(&sc.own_output).map_err(|_| "output commit hex")?);
    let have_output = sl.tx_or_err().map(|tx| tx.outputs().iter().any(|o| o.commitment() == own)).unwrap_or(false);
    if !have_output {
        sl.add_transaction_elements(k, &ProofBuilder::new(k), vec![build::output(out_amount, out_id)]).map_err(|e| format!("add output: {e}"))?;
    }
    let off = sl.offset.clone();
    sl.tx_or_err_mut().map_err(|e| format!("{e}"))?.offset = off;
    // tx::complete_tx
    sl.fill_round_2(k, &ctx.sec_key, &ctx.sec_nonce).map_err(|e| format!("round 2: {e}"))?;
    sl.finalize(k).map_err(|e| format!("finalize: {e}"))?;
    // grin-wallet's foreign::finalize_tx: the answer is the finalized I3 slate.
    sl.state = SlateState::Invoice3;
    sl.amount = 0;
    let i3_json = slate_to_json(&sl)?;
    let tx = sl.tx_or_err().map_err(|e| format!("{e}"))?.clone();
    tx.validate(grin_core::core::Weighting::AsTransaction).map_err(|e| format!("transaction does not validate: {e:?}"))?;
    if !tx.outputs().iter().any(|o| o.commitment() == own) {
        return Err("our invoiced output is missing".into());
    }
    if tx.kernels().len() != 1 {
        return Err("unexpected kernel count".into());
    }
    let others: Vec<Commitment> = tx.outputs().iter().map(|o| o.commitment()).filter(|c| *c != own).collect();
    Ok((tx, others, i3_json))
}

/// `finalize_invoice` without the I3 slate (callers that only need the tx).
pub fn finalize_invoice(w: &Wallets, sc: &SendContext, i2_text: &str) -> Result<(grin_core::core::Transaction, Vec<Commitment>), String> {
    finalize_invoice_state(w, sc, i2_text).map(|(tx, others, _)| (tx, others))
}

/// `--send-slatepack`: S1 + context file (keys in the context: keep local).
/// Test hook: stop as a crash would right after this step of a payment.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CrashAt {
    /// send: context written, nothing reserved, no S1.
    AfterContext,
    /// send: context + reservation, no S1. invoice: saved answer + reservation, no answer file.
    AfterReservation,
    /// invoice: saved answer, nothing reserved, no answer file.
    AfterSavedAnswer,
}

/// A send, the caller holding `lock_pending` and `cands` already free of
/// reserved inputs: select -> build -> context -> ONE reservation record
/// (inputs + change) -> S1. Used by `gap --gap-send-to`.
#[allow(clippy::too_many_arguments)]
pub fn start_send(
    w: &Wallets,
    wallet: usize,
    cands: &[InputSel],
    used: &[Identifier],
    amount: u64,
    dest: &str,
    pending: &str,
    s1_out: &str,
    ctx_out: &str,
    tip_height: u64,
    crash: Option<CrashAt>,
) -> Result<SendBuilt, String> {
    let inputs = select_inputs(cands, amount)?;
    let built = build_send(w, wallet, &inputs, used, amount, dest)?;
    write_send_context(&built, ctx_out)?;
    if crash == Some(CrashAt::AfterContext) {
        return Err("CRASH (test) after the context".into());
    }
    let in_commits: Vec<String> = built.context.inputs.iter().map(|i| i.commit.clone()).collect();
    reserve_payment(pending, wallet + 1, &built.context.slate_id, "send", &in_commits, tip_height, built.change, &built.change_key, &built.context.own_output, dest)?;
    if crash == Some(CrashAt::AfterReservation) {
        return Err("CRASH (test) after the reservation".into());
    }
    publish_send(&built, s1_out)?;
    Ok(built)
}

/// Invoice already paid by this wallet: write the SAME saved answer to `out`
/// and return its slate id; None if it was not paid yet.
pub fn resend_paid_invoice(w: &Wallets, wallet: usize, pending: &str, i1: &str, out: &str, tip_height: Option<u64>) -> Result<Option<String>, String> {
    let k = w.keychain(wallet).ok_or("wallet unavailable")?;
    let (slate, _) = unarmor(k, i1)?;
    if slate.state != SlateState::Invoice1 { return Err("not an invoice (expected I1)".into()); }
    check_slate_cutoff(slate.ttl_cutoff_height, tip_height, "invoice")?;
    let Some(sid) = invoice_slate_id(w, wallet, i1) else { return Ok(None) };
    if journal(pending)?.iter().any(|r| rkind(r) == Some("release") && rs(r, "slate_id") == Some(sid.as_str())) {
        return Err(format!("invoice {sid} was cancelled; do not resend its signed answer"));
    }
    if !pending_has_change(pending, &sid)? {
        return Ok(None);
    }
    validate_saved_request(pending, &sid, wallet + 1, "invoice_request", i1, slate.ttl_cutoff_height)?;
    let saved = saved_answer(pending, &sid).ok_or(format!(
        "invoice {sid} is already paid by this wallet but its saved answer is missing; \
         do not pay it again (that would spend the same coins twice)"
    ))?;
    std::fs::write(out, &saved).map_err(|e| format!("answer out: {e}"))?;
    println!("PAY_INVOICE_SLATE_ID={sid}\nPAY_INVOICE_ANSWER={out}\nPAY_INVOICE=I2_RESENT (already paid; the same answer again)");
    Ok(Some(sid))
}

/// Pay an invoice, the caller holding `lock_pending` and `cands` already free
/// of reserved inputs. Order: saved answer -> ONE reservation record -> answer
/// file. A crash before the reservation leaves nothing handed out; after it,
/// a retry resends the saved answer (`resend_paid_invoice`).
#[allow(clippy::too_many_arguments)]
pub fn start_invoice_payment(
    w: &Wallets,
    wallet: usize,
    cands: &[InputSel],
    used: &[Identifier],
    i1: &str,
    pending: &str,
    out: &str,
    tip_height: u64,
    crash: Option<CrashAt>,
) -> Result<InvoicePaid, String> {
    // (the caller tried `resend_paid_invoice` first)
    let paid = pay_invoice(w, wallet, cands, used, i1, Some(tip_height))?;
    if pending_has_change(pending, &paid.slate_id)? {
        return Err(format!("invoice {} is already paid by this wallet", paid.slate_id));
    }
    let issuer = paid.issuer.clone().unwrap_or_else(|| "(no address given)".into());
    let (input_slate, _) = unarmor(w.keychain(wallet).ok_or("wallet unavailable")?, i1)?;
    let has_claim = journal(pending)?.iter().any(|r| rkind(r) == Some("invoice_request") && rs(r, "slate_id") == Some(paid.slate_id.as_str()) && r.get("wallet").and_then(|v|v.as_u64()) == Some((wallet + 1) as u64));
    if has_claim {
        validate_saved_request(pending, &paid.slate_id, wallet + 1, "invoice_request", i1, input_slate.ttl_cutoff_height)?;
    } else {
        // A prior reservation without a claim is a legacy operation; never
        // invent its original identity. Existing reservations were rejected above.
        append_record(pending, format!("{{\"kind\":\"invoice_request\",\"wallet\":{},\"slate_id\":{},\"request_hash\":{},\"cutoff_height\":{}}}", wallet + 1, q(&paid.slate_id), q(&request_hash(i1)), input_slate.ttl_cutoff_height))?;
    }
    save_answer(pending, &paid.slate_id, &format!("{}\n", paid.i2))?;
    // The plain I2 JSON goes out with the answer (the issuer's Tor foreign API
    // takes JSON, not an armor). Written BEFORE the reservation: a crash later
    // leaves both the saved answer and its JSON on disk.
    let json_out = format!("{}.json", out.trim_end_matches(".txt"));
    write_atomic(&json_out, paid.i2_json.as_bytes()).map_err(|e| format!("slate json out: {e}"))?;
    if crash == Some(CrashAt::AfterSavedAnswer) {
        return Err("CRASH (test) after the saved answer".into());
    }
    let in_commits: Vec<String> = paid.inputs.iter().map(|i| i.commit.clone()).collect();
    reserve_payment(pending, wallet + 1, &paid.slate_id, "invoice", &in_commits, tip_height, paid.change, &paid.change_key, &paid.change_commit.0.to_hex(), &issuer)?;
    if crash == Some(CrashAt::AfterReservation) {
        return Err("CRASH (test) after the reservation".into());
    }
    std::fs::write(out, format!("{}\n", paid.i2)).map_err(|e| format!("answer out: {e}"))?;
    Ok(paid)
}

pub fn send_file(built: &SendBuilt, s1_out: &str, ctx_out: &str) -> Result<(), String> {
    write_send_context(built, ctx_out)?;
    publish_send(built, s1_out)
}

/// Step 1 of a send: the signing context (atomically). Written BEFORE the
/// input reservation, so a reserved send always has its context and can be
/// cancelled safely with `--release-inputs --send-context` (deleting the
/// context makes the S1 unfinalizable). A crash before the reservation leaves
/// only an unused context (no S1 ever left).
pub fn write_send_context(built: &SendBuilt, ctx_out: &str) -> Result<(), String> {
    let j = serde_json::to_string(&built.context).map_err(|e| format!("context: {e}"))?;
    write_atomic(ctx_out, j.as_bytes()).map_err(|e| format!("context out: {e}"))
}

/// Step 3 of a send (after the reservation): the S1 itself.
pub fn publish_send(built: &SendBuilt, s1_out: &str) -> Result<(), String> {
    // Plain JSON next to it, for the Tor foreign API (no secrets in it).
    let json_out = format!("{}.json", s1_out.trim_end_matches(".txt"));
    write_atomic(&json_out, built.s1_json.as_bytes()).map_err(|e| format!("slate json out: {e}"))?;
    write_atomic(s1_out, format!("{}\n", built.s1).as_bytes()).map_err(|e| format!("slatepack out: {e}"))?;
    println!(
        "SEND_SLATE_ID={}\nSEND_TO={}\nSEND_AMOUNT={}\nSEND_FEE={}\nSEND_CHANGE={}\nSEND_INPUTS={}\nSEND_INPUT={}\nSEND_CHANGE_OUTPUT={}\nSEND_CHANGE_KEY_ID={}\nSEND_PAYMENT_PROOF=requested\nSEND_SLATEPACK={s1_out}\nSEND=S1_READY (give the slatepack to the receiver, then finalize its answer)",
        built.context.slate_id,
        built.context.dest,
        built.amount,
        built.fee,
        built.change,
        built.context.inputs.len(),
        built.context.inputs.iter().map(|i| i.commit.clone()).collect::<Vec<_>>().join(","),
        built.context.own_output,
        built.change_key.to_hex()
    );
    Ok(())
}

/// Delete a context with signing secrets; the result line says whether it
/// really is gone (the transaction is complete either way).
fn delete_context(ctx_path: &str) -> String {
    match std::fs::remove_file(ctx_path) {
        Ok(()) => "FINALIZE=OK (context with signing secrets deleted)".into(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => "FINALIZE=OK (context already deleted)".into(),
        Err(e) => format!("FINALIZE=OK_CONTEXT_NOT_DELETED {ctx_path}: {e} (it holds signing secrets: delete it by hand)"),
    }
}

fn read_context(ctx_path: &str) -> Result<SendContext, String> {
    serde_json::from_str(&std::fs::read_to_string(ctx_path).map_err(|e| format!("context: {e}"))?).map_err(|e| format!("context: {e}"))
}

fn write_tx(tx: &grin_core::core::Transaction, tx_out: &str) -> Result<(), String> {
    let b = grin_core::ser::ser_vec(tx, grin_core::ser::ProtocolVersion::local()).map_err(|e| format!("{e:?}"))?;
    std::fs::write(tx_out, b.to_hex()).map_err(|e| format!("tx out: {e}"))
}

/// Lines the scripts read (-Broadcast shows them, -Confirm checks them).
fn print_spend_lines(wallet: usize, inputs: &[InputSel], own: &str, others: &[Commitment], amount: u64, to: &str, tx: &grin_core::core::Transaction, tx_out: &str) {
    println!("GAP_SPEND_WALLET={wallet}");
    if let Some(first) = inputs.first() {
        println!("GAP_SPEND_INPUT={}\nGAP_SPEND_INPUT_AMOUNT={}", first.commit, first.amount);
    }
    for i in inputs.iter().skip(1) {
        println!("GAP_SPEND_EXTRA_INPUT={}", i.commit);
    }
    println!("GAP_SPEND_NEW_OUTPUT={own}");
    for c in others {
        println!("GAP_SPEND_RECEIVER_OUTPUT={}", c.0.to_hex());
    }
    println!(
        "GAP_SPEND_AMOUNT_SENT={amount}\nGAP_SPEND_TO={to}\nGAP_SPEND_FEE={}\nGAP_SPEND_KERNEL_EXCESS={}\nGAP_SPEND_TX_VALIDATED=true\nGAP_SPEND_TX_OUT={tx_out}",
        tx.fee(),
        tx.kernels()[0].excess.0.to_hex()
    );
}

/// `--finalize-slatepack S2 --send-context FILE --tx-out FILE [--proof-out FILE]`.
pub fn finalize_file(seeds: &str, ctx_path: &str, s2_path: &str, tx_out: &str, proof_out: Option<&str>) -> Result<(), String> {
    let w = Wallets::from_file(seeds)?;
    let sc = read_context(ctx_path)?;
    let s2 = std::fs::read_to_string(s2_path).map_err(|e| format!("answer file: {e}"))?;
    let (tx, theirs, proof) = finalize(&w, &sc, &s2)?;
    write_tx(&tx, tx_out)?;
    // Everything that needs the context is written before it is deleted: a
    // failed proof write can be repeated from the context.
    if let (Some(p), Some(path)) = (&proof, proof_out) {
        write_atomic(path, p.as_bytes()).map_err(|e| format!("proof out: {e}"))?;
    }
    print_spend_lines(sc.wallet, &sc.inputs, &sc.own_output, &[theirs], sc.ctx.amount, &sc.dest, &tx, tx_out);
    if let (Some(_), Some(path)) = (&proof, proof_out) {
        println!("PAYMENT_PROOF=VERIFIED (receiver signature checked) file={path}");
    }
    println!("{}", delete_context(ctx_path));
    Ok(())
}

/// `--issue-invoice AMOUNT --wallet N ...`: I1 + context.
#[allow(clippy::too_many_arguments)]
pub fn issue_invoice_file(seeds: &str, wallet: usize, amount: u64, payer: Option<&str>, known: Option<&str>, pending: &str, i1_out: &str, ctx_out: &str) -> Result<(), String> {
    let w = Wallets::from_file(seeds)?;
    if wallet == 0 || wallet > w.len() {
        return Err(format!("wallet {wallet} not in the seed file (1..={})", w.len()));
    }
    let _lock = lock_pending(pending)?;
    let mut used = read_key_ids(pending, wallet)?;
    if let Some(k) = known {
        used.extend(read_known_key_ids(&w, k, wallet)?);
    }
    let (i1, sc, key) = issue_invoice(&w, wallet - 1, &used, amount, payer)?;
    // Reserve the key first: an interruption after this point leaves at most an
    // unused reservation, never a handed-out key that is not reserved.
    append_record(
        pending,
        format!(
            "{{\"kind\":\"invoice\",\"wallet\":{wallet},\"slate_id\":{},\"amount\":{amount},\"key_id\":{},\"commit\":{},\"to\":{},\"received_at\":{}}}",
            q(&sc.slate_id), q(&key.to_hex()), q(&sc.own_output), q(&sc.dest), q(&stamp_now())
        ),
    )?;
    std::fs::write(ctx_out, serde_json::to_string(&sc).map_err(|e| format!("context: {e}"))?).map_err(|e| format!("context out: {e}"))?;
    std::fs::write(i1_out, format!("{i1}\n")).map_err(|e| format!("invoice out: {e}"))?;
    println!(
        "INVOICE_SLATE_ID={}\nINVOICE_AMOUNT={amount}\nINVOICE_OUTPUT={}\nINVOICE_KEY_ID={}\nINVOICE_SLATEPACK={i1_out}\nINVOICE=I1_READY (give it to the payer, then finalize its answer)",
        sc.slate_id,
        sc.own_output,
        key.to_hex()
    );
    Ok(())
}

/// `--finalize-invoice I2 --invoice-context FILE --tx-out FILE [--slate-json-out F]`.
pub fn finalize_invoice_file(seeds: &str, ctx_path: &str, i2_path: &str, tx_out: &str, slate_json_out: Option<&str>) -> Result<(), String> {
    let w = Wallets::from_file(seeds)?;
    let sc = read_context(ctx_path)?;
    let i2 = std::fs::read_to_string(i2_path).map_err(|e| format!("answer file: {e}"))?;
    let (tx, others, i3_json) = finalize_invoice_state(&w, &sc, &i2)?;
    write_tx(&tx, tx_out)?;
    if let Some(p) = slate_json_out {
        write_atomic(p, i3_json.as_bytes()).map_err(|e| format!("slate json out: {e}"))?;
    }
    println!("{}", delete_context(ctx_path));
    // For -Confirm: the payer's inputs are spent; list them as "extra" inputs.
    println!("GAP_SPEND_WALLET={}", sc.wallet);
    use grin_core::core::Committed;
    for (n, i) in tx.inputs_committed().iter().enumerate() {
        if n == 0 {
            println!("GAP_SPEND_INPUT={}\nGAP_SPEND_INPUT_AMOUNT=0", i.0.to_hex());
        } else {
            println!("GAP_SPEND_EXTRA_INPUT={}", i.0.to_hex());
        }
    }
    println!("GAP_SPEND_NEW_OUTPUT={}", sc.own_output);
    for c in &others {
        println!("GAP_SPEND_RECEIVER_OUTPUT={}", c.0.to_hex());
    }
    println!(
        "GAP_SPEND_AMOUNT_SENT={}\nGAP_SPEND_TO=(invoice paid to wallet {})\nGAP_SPEND_FEE={}\nGAP_SPEND_KERNEL_EXCESS={}\nGAP_SPEND_TX_VALIDATED=true\nGAP_SPEND_TX_OUT={tx_out}\nFINALIZE=OK invoice (context with signing secrets deleted)",
        sc.own_output_amount,
        sc.wallet,
        tx.fee(),
        tx.kernels()[0].excess.0.to_hex()
    );
    if let Some(p) = slate_json_out {
        println!("FINALIZE_SLATE_JSON={p}");
    }
    Ok(())
}

#[cfg(test)]
mod send_tests {
    use super::*;
    use grin_core::global::{self, ChainTypes};

    fn wallets() -> Wallets {
        Wallets::from_keychains(vec![ExtKeychain::from_seed(&[3; 32], true).unwrap(), ExtKeychain::from_seed(&[4; 32], true).unwrap()])
    }

    fn input(w: &Wallets, wallet: usize, n: u32, amount: u64) -> InputSel {
        let id = ExtKeychain::derive_key_id(3, 0, 0, n, 0);
        let c = w.keychain(wallet).unwrap().commit(amount, &id, grin_keychain::SwitchCommitmentType::Regular).unwrap();
        InputSel::new(&id, amount, false, &c)
    }

    /// Wallet A sends to wallet B's address with two inputs: build_send ->
    /// receive -> finalize; the transaction validates, the payment proof
    /// verifies, B finds its output and A its change.
    #[test]
    fn send_receive_finalize_two_inputs_with_proof() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let w = wallets();
        let b_addr = slatepack_address(w.keychain(1).unwrap()).unwrap();
        let cands = vec![input(&w, 0, 1, 600_000_000), input(&w, 0, 2, 4_500_000_000), input(&w, 0, 3, 700_000_000)];
        let picked = select_inputs(&cands, 5_000_000_000).unwrap();
        assert_eq!(picked.iter().map(|x| x.amount).collect::<Vec<_>>(), vec![4_500_000_000, 700_000_000]);
        let used: Vec<Identifier> = cands.iter().map(|c| c.id().unwrap()).collect();
        let built = build_send(&w, 0, &picked, &used, 5_000_000_000, &b_addr).unwrap();
        assert_eq!(built.change_key, ExtKeychain::derive_key_id(3, 0, 0, 4, 0));
        assert_eq!(built.change, 5_200_000_000 - 5_000_000_000 - send_fee_for(2));
        let sc: SendContext = serde_json::from_str(&serde_json::to_string(&built.context).unwrap()).unwrap();
        let r = receive(&w, 1, &[], &built.s1, None).unwrap();
        assert!(r.payment_proof);
        let (tx, theirs, proof) = finalize(&w, &sc, &r.response).unwrap();
        assert_eq!(theirs, r.commit);
        assert_eq!(tx.inputs().len(), 2);
        let proof: grin_wallet_libwallet::PaymentProof = serde_json::from_str(&proof.unwrap()).unwrap();
        assert_eq!(proof.amount, 5_000_000_000);
        assert_eq!(proof.recipient_address.to_string(), b_addr);
        // both signatures check out the way grin-wallet's verify_payment_proof does
        use ed25519_dalek::Verifier;
        let msg = proof_message(proof.amount, &proof.excess, &proof.sender_address.pub_key);
        proof.recipient_address.pub_key.verify(&msg, &proof.recipient_sig).unwrap();
        proof.sender_address.pub_key.verify(&msg, &proof.sender_sig).unwrap();
        let rows: Vec<_> = tx.outputs().iter().map(|o| (u64::MAX, o.identifier, o.proof)).collect();
        let mut found = w.discover(&rows).unwrap();
        found.sort_by_key(|f| f.wallet);
        assert_eq!((found[0].wallet, found[0].amount), (0, built.change));
        assert_eq!((found[1].wallet, found[1].amount), (1, 5_000_000_000));
        assert!(finalize(&w, &sc, &built.s1).is_err());
        assert!(select_inputs(&cands, 10_000_000_000).is_err());
        // The genuine answer of B is refused when the payment was to someone
        // else (context dest C): the proof must name the receiver we paid.
        let c_addr = slatepack_address(&ExtKeychain::from_seed(&[5; 32], true).unwrap()).unwrap();
        let mut sc_c: SendContext = serde_json::from_str(&serde_json::to_string(&built.context).unwrap()).unwrap();
        sc_c.dest = c_addr;
        assert!(finalize(&w, &sc_c, &r.response).unwrap_err().contains("receiver address"));
    }

    #[test]
    fn proof_address_substitution_refused() {
        let key = |n: u8| ed25519_dalek::SigningKey::from_bytes(&[n; 32]).verifying_key();
        let (ours, dest, evil) = (key(1), key(2), key(3));
        assert!(check_proof_addresses(&ours, &dest, &ours, &dest).is_ok());
        assert!(check_proof_addresses(&evil, &dest, &ours, &dest).unwrap_err().contains("sender"));
        assert!(check_proof_addresses(&ours, &evil, &ours, &dest).unwrap_err().contains("receiver"));
        assert!(check_proof_addresses(&dest, &ours, &ours, &dest).is_err());
    }

    /// A cancelled send cannot complete late: releasing its inputs deletes the
    /// context, so the receiver's (late) answer can no longer be finalized;
    /// without a release the reservation never lapses.
    #[test]
    fn released_send_cannot_be_finalized_late() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let w = wallets();
        let b_addr = slatepack_address(w.keychain(1).unwrap()).unwrap();
        let cands = vec![input(&w, 0, 1, 4_000_000_000)];
        let built = build_send(&w, 0, &cands, &[cands[0].id().unwrap()], 1_000_000_000, &b_addr).unwrap();
        let dir = std::env::temp_dir().join(format!("grinsight-late-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
        let (pend, s1, ctx) = (p("pending.jsonl"), p("s1.txt"), p("ctx.json"));
        send_file(&built, &s1, &ctx).unwrap();
        let ins: Vec<String> = built.context.inputs.iter().map(|i| i.commit.clone()).collect();
        reserve_inputs(&pend, 1, &built.context.slate_id, "send", &ins, 100).unwrap();
        assert_eq!(reserved_inputs(&pend).unwrap().len(), 1, "held with no time-out");
        // the receiver answers, but only after we cancelled
        let late = receive(&w, 1, &[], &built.s1, None).unwrap();
        std::fs::write(p("s2.txt"), &late.response).unwrap();
        assert!(release_inputs(&pend, &built.context.slate_id, None, false).is_err(), "send needs its context");
        let other = p("other.json");
        let mut sc2: SendContext = serde_json::from_str(&std::fs::read_to_string(&ctx).unwrap()).unwrap();
        sc2.slate_id = "00000000-0000-0000-0000-000000000000".into();
        std::fs::write(&other, serde_json::to_string(&sc2).unwrap()).unwrap();
        assert!(release_inputs(&pend, &built.context.slate_id, Some(&other), false).is_err(), "wrong context refused");
        release_inputs(&pend, &built.context.slate_id, Some(&ctx), false).unwrap();
        assert!(reserved_inputs(&pend).unwrap().is_empty());
        // seeds for finalize_file are only needed after the context is read
        assert!(finalize_file("/nonexistent-seeds", &ctx, &p("s2.txt"), &p("tx.hex"), None).is_err());
        assert!(!std::path::Path::new(&ctx).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("grinsight-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// ACCEPTANCE (payment failures): a send interrupted between the context
    /// and the reservation, and between the reservation and the S1.
    #[test]
    fn send_crash_points_leave_a_safe_state() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let w = wallets();
        let b = slatepack_address(w.keychain(1).unwrap()).unwrap();
        let cands = vec![input(&w, 0, 1, 4_000_000_000)];
        let used = vec![cands[0].id().unwrap()];
        let dir = tmpdir("crash-send");
        let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
        let pend = p("pending.jsonl");
        // 1) crash after the context: nothing reserved, no S1 left the process
        let e = start_send(&w, 0, &cands, &used, 1_000_000_000, &b, &pend, &p("s1a.txt"), &p("ctxa.json"), 100, Some(CrashAt::AfterContext)).err().unwrap();
        assert!(e.contains("CRASH"));
        assert!(std::path::Path::new(&p("ctxa.json")).exists() && !std::path::Path::new(&p("s1a.txt")).exists());
        assert!(reserved_inputs(&pend).unwrap().is_empty(), "the input is still free");
        // 2) the retry works; then crash after the reservation: context and
        //    reservation exist together, no S1
        let e = start_send(&w, 0, &cands, &used, 1_000_000_000, &b, &pend, &p("s1b.txt"), &p("ctxb.json"), 100, Some(CrashAt::AfterReservation)).err().unwrap();
        assert!(e.contains("CRASH"));
        let sid_b: SendContext = serde_json::from_str(&std::fs::read_to_string(p("ctxb.json")).unwrap()).unwrap();
        assert!(!std::path::Path::new(&p("s1b.txt")).exists());
        let r = reserved_inputs(&pend).unwrap();
        assert_eq!(r.get(&cands[0].commit).map(|s| s.as_str()), Some(sid_b.slate_id.as_str()));
        assert!(pending_has_change(&pend, &sid_b.slate_id).unwrap(), "change key recorded in the same record");
        assert_eq!(read_key_ids(&pend, 1).unwrap().len(), 1);
        // the reserved input cannot be picked again ...
        let free: Vec<InputSel> = cands.iter().filter(|c| !r.contains_key(&c.commit)).cloned().collect();
        assert!(start_send(&w, 0, &free, &used, 1_000_000_000, &b, &pend, &p("s1c.txt"), &p("ctxc.json"), 100, None).is_err());
        // ... and the normal safe cancel works (its context exists)
        release_inputs(&pend, &sid_b.slate_id, Some(&p("ctxb.json")), false).unwrap();
        assert!(reserved_inputs(&pend).unwrap().is_empty());
        // 3) full run: S1 written, reserved once
        let built = start_send(&w, 0, &cands, &used, 1_000_000_000, &b, &pend, &p("s1d.txt"), &p("ctxd.json"), 100, None).unwrap();
        assert!(std::path::Path::new(&p("s1d.txt")).exists());
        assert_eq!(reserved_inputs(&pend).unwrap().len(), 1);
        // the receiver's answer finalizes with the context of THIS attempt
        let ans = receive(&w, 1, &[], &built.s1, None).unwrap();
        assert!(finalize(&w, &built.context, &ans.response).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ACCEPTANCE (payment failures): invoice payment interrupted at each step,
    /// and a lost I2 answered again with the SAME answer (never a second payment).
    #[test]
    fn invoice_crash_points_and_lost_answer() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let w = wallets();
        let a = slatepack_address(w.keychain(0).unwrap()).unwrap();
        let (i1, _isc, _) = issue_invoice(&w, 1, &[], 1_000_000_000, Some(&a)).unwrap();
        let cands = vec![input(&w, 0, 1, 3_000_000_000)];
        let used = vec![cands[0].id().unwrap()];
        let dir = tmpdir("crash-inv");
        let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
        let pend = p("pending.jsonl");
        // crash after the saved answer: nothing reserved, nothing handed out
        assert!(start_invoice_payment(&w, 0, &cands, &used, &i1, &pend, &p("i2a.txt"), 100, Some(CrashAt::AfterSavedAnswer)).is_err());
        assert!(reserved_inputs(&pend).unwrap().is_empty());
        assert!(resend_paid_invoice(&w, 0, &pend, &i1, &p("x.txt"), Some(100)).unwrap().is_none(), "not paid yet");
        // retry, crash after the reservation: no answer file yet
        assert!(start_invoice_payment(&w, 0, &cands, &used, &i1, &pend, &p("i2b.txt"), 100, Some(CrashAt::AfterReservation)).is_err());
        assert!(!std::path::Path::new(&p("i2b.txt")).exists());
        assert_eq!(reserved_inputs(&pend).unwrap().len(), 1);
        // the retry recognises the payment and hands out the saved answer
        let sid = resend_paid_invoice(&w, 0, &pend, &i1, &p("i2c.txt"), Some(100)).unwrap().expect("already paid");
        let saved = std::fs::read_to_string(p("i2c.txt")).unwrap();
        assert_eq!(saved_answer(&pend, &sid).unwrap(), saved);
        // the answer is lost again: still the same text, still one reservation
        resend_paid_invoice(&w, 0, &pend, &i1, &p("i2d.txt"), Some(100)).unwrap();
        assert_eq!(std::fs::read_to_string(p("i2d.txt")).unwrap(), saved);
        assert_eq!(reserved_inputs(&pend).unwrap().len(), 1);
        let (mut changed_invoice, issuer_addr) = unarmor(w.keychain(0).unwrap(), &i1).unwrap();
        changed_invoice.ttl_cutoff_height = 200;
        let payer_addr = SlatepackAddress::try_from(&address_secret(w.keychain(0).unwrap()).unwrap()).unwrap();
        let changed_i1 = armor(issuer_addr, Some(payer_addr), &changed_invoice).unwrap();
        assert!(resend_paid_invoice(&w, 0, &pend, &changed_i1, &p("changed-i2.txt"), Some(100)).unwrap_err().contains("original request changed"));
        assert!(!std::path::Path::new(&p("changed-i2.txt")).exists());
        release_inputs(&pend, &sid, None, true).unwrap();
        assert!(resend_paid_invoice(&w, 0, &pend, &i1, &p("cancelled-i2.txt"), Some(100)).unwrap_err().contains("cancelled"));
        assert!(!std::path::Path::new(&p("cancelled-i2.txt")).exists());
        let legacy = std::fs::read_to_string(&pend).unwrap().lines().filter(|line| !line.contains("invoice_request") && !line.contains("\"kind\":\"release\"")).collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(p("legacy-pending.jsonl"), legacy).unwrap();
        assert!(resend_paid_invoice(&w, 0, &p("legacy-pending.jsonl"), &i1, &p("legacy-i2.txt"), Some(100)).unwrap_err().contains("manual recovery"));
        assert!(!std::path::Path::new(&p("legacy-i2.txt")).exists());
        // and a direct second payment attempt is refused
        assert!(start_invoice_payment(&w, 0, &cands, &used, &i1, &pend, &p("i2e.txt"), 100, None).err().unwrap().contains("already paid"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expired_duplicate_never_returns_cached_s2() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let w = wallets();
        let dir = tmpdir("cutoff-s2-retry");
        let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
        let phrases = format!("{}\n{}\n", grin_keychain::mnemonic::from_entropy(&[3;32]).unwrap(), grin_keychain::mnemonic::from_entropy(&[4;32]).unwrap());
        std::fs::write(p("seeds.txt"), phrases).unwrap();
        let address = slatepack_address(w.keychain(1).unwrap()).unwrap();
        let cands = vec![input(&w, 0, 1, 4_000_000_000)];
        let built = build_send(&w, 0, &cands, &[cands[0].id().unwrap()], 1_000_000_000, &address).unwrap();
        let (mut slate, sender) = unarmor(w.keychain(1).unwrap(), &built.s1).unwrap();
        slate.ttl_cutoff_height = 101;
        let receiver = SlatepackAddress::try_from(&address_secret(w.keychain(1).unwrap()).unwrap()).unwrap();
        std::fs::write(p("s1.txt"), armor(sender, Some(receiver), &slate).unwrap()).unwrap();
        let pending = p("pending.jsonl");
        receive_file(&p("seeds.txt"), 2, &p("s1.txt"), &p("s2.txt"), None, &pending, Some(100), None).unwrap();
        assert!(receive_file(&p("seeds.txt"), 2, &p("s1.txt"), &p("missing.txt"), None, &pending, None, None).unwrap_err().contains("fresh verified chain tip"));
        assert!(receive_file(&p("seeds.txt"), 2, &p("s1.txt"), &p("expired.txt"), None, &pending, Some(101), None).unwrap_err().contains("expired"));
        assert!(!std::path::Path::new(&p("expired.txt")).exists());
        assert_eq!(read_key_ids(&pending, 2).unwrap().len(), 1);
        let (mut changed, sender) = unarmor(w.keychain(1).unwrap(), &std::fs::read_to_string(p("s1.txt")).unwrap()).unwrap();
        changed.ttl_cutoff_height = 0;
        let receiver = SlatepackAddress::try_from(&address_secret(w.keychain(1).unwrap()).unwrap()).unwrap();
        std::fs::write(p("changed.txt"), armor(sender, Some(receiver), &changed).unwrap()).unwrap();
        assert!(receive_file(&p("seeds.txt"), 2, &p("changed.txt"), &p("changed-s2.txt"), None, &pending, Some(100), None).unwrap_err().contains("original request changed"));
        assert!(!std::path::Path::new(&p("changed-s2.txt")).exists());
        let lines = std::fs::read_to_string(&pending).unwrap();
        let legacy = lines.lines().map(|line| {
            let mut v: serde_json::Value = serde_json::from_str(line).unwrap();
            v.as_object_mut().unwrap().remove("request_hash");
            serde_json::to_string(&v).unwrap()
        }).collect::<Vec<_>>().join("\n") + "\n";
        std::fs::write(&pending, legacy).unwrap();
        assert!(receive_file(&p("seeds.txt"), 2, &p("s1.txt"), &p("legacy-s2.txt"), None, &pending, Some(100), None).unwrap_err().contains("manual recovery"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ACCEPTANCE (payment failures): the receiver's answer (S2) is lost; the
    /// sender delivers the S1 again (e.g. after a restart) and gets the SAME
    /// answer back, with no second key reserved.
    #[test]
    fn lost_receive_answer_is_resent_identically() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let w = wallets();
        let dir = tmpdir("lost-s2");
        let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
        let phrases = format!(
            "{}\n{}\n",
            grin_keychain::mnemonic::from_entropy(&[3; 32]).unwrap(),
            grin_keychain::mnemonic::from_entropy(&[4; 32]).unwrap()
        );
        std::fs::write(p("seeds.txt"), phrases).unwrap();
        let b = slatepack_address(w.keychain(1).unwrap()).unwrap();
        let cands = vec![input(&w, 0, 1, 4_000_000_000)];
        let built = build_send(&w, 0, &cands, &[cands[0].id().unwrap()], 1_000_000_000, &b).unwrap();
        std::fs::write(p("s1.txt"), &built.s1).unwrap();
        let pend = p("pending.jsonl");
        receive_file(&p("seeds.txt"), 2, &p("s1.txt"), &p("s2-first.txt"), None, &pend, Some(10), None).unwrap();
        let first = std::fs::read_to_string(p("s2-first.txt")).unwrap();
        receive_file(&p("seeds.txt"), 2, &p("s1.txt"), &p("s2-again.txt"), None, &pend, Some(10), None).unwrap();
        assert_eq!(std::fs::read_to_string(p("s2-again.txt")).unwrap(), first, "the same answer");
        assert_eq!(read_key_ids(&pend, 2).unwrap().len(), 1, "one key, not two");
        // the resent answer finalizes the payment
        assert!(finalize(&w, &built.context, &first).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ACCEPTANCE (payment failures): two payments started at the same time
    /// with the same single input. Under the pending lock exactly one gets it;
    /// the other finds it reserved and fails (no double spend is built).
    #[test]
    fn two_concurrent_payments_with_one_input() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let dir = tmpdir("race");
        let pend = dir.join("pending.jsonl").to_str().unwrap().to_string();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|t| {
                let (pend, dir, barrier) = (pend.clone(), dir.clone(), barrier.clone());
                std::thread::spawn(move || {
                    global::set_local_chain_type(ChainTypes::Testnet);
                    let w = wallets();
                    let b = slatepack_address(w.keychain(1).unwrap()).unwrap();
                    let all = vec![input(&w, 0, 1, 4_000_000_000)];
                    let used = vec![all[0].id().unwrap()];
                    barrier.wait();
                    // the same sequence gap.rs runs: lock -> reserved -> select -> reserve
                    let _lock = lock_pending(&pend).unwrap();
                    let reserved = reserved_inputs(&pend).unwrap();
                    let free: Vec<InputSel> = all.iter().filter(|c| !reserved.contains_key(&c.commit)).cloned().collect();
                    let p = |n: &str| dir.join(format!("{n}{t}")).to_str().unwrap().to_string();
                    start_send(&w, 0, &free, &used, 1_000_000_000, &b, &pend, &p("s1-"), &p("ctx-"), 100, None).map(|x| x.context.slate_id)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1, "{results:?}");
        assert_eq!(reserved_inputs(&pend).unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Impossible amounts (e.g. from a hostile invoice) are errors, not panics.
    #[test]
    fn huge_amounts_do_not_overflow() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let w = wallets();
        let max = vec![input(&w, 0, 1, u64::MAX)];
        // amount + fee beyond 64 bits: refused, no panic
        assert!(select_inputs(&max, u64::MAX).unwrap_err().contains("too large"));
        // the largest input covers amount + fee with change 10
        assert_eq!(select_inputs(&max, u64::MAX - send_fee_for(1) - 10).unwrap().len(), 1);
        // two inputs of 2^63 each: neither alone covers it, their sum is 2^64
        let half = 1u64 << 63;
        let cands = vec![input(&w, 0, 2, half), input(&w, 0, 3, half)];
        let picked = select_inputs(&cands, u64::MAX - send_fee_for(2) - 10).unwrap();
        assert_eq!(picked.len(), 2, "compared in 128 bits, no overflow");
        // building the payment from them: the input sum does not fit -> error
        let b_addr = slatepack_address(w.keychain(1).unwrap()).unwrap();
        match build_send(&w, 0, &picked, &[], u64::MAX - send_fee_for(2) - 10, &b_addr) {
            Err(e) => assert!(e.contains("overflow"), "{e}"),
            Ok(_) => panic!("overflowing inputs accepted"),
        }
    }

    #[test]
    #[ignore = "synthetic two-wallet transport fixture"]
    fn synthetic_two_wallet_transport_fixture() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let w=wallets(); let dir=std::path::PathBuf::from(std::env::var("GS_CHAIN_FIXTURE").expect("fixture dir"));
        std::fs::create_dir_all(&dir).unwrap(); let file=|name:&str| dir.join(name);
        if std::env::var("GS_CHAIN_PHASE").unwrap()=="generate" {
            let b=slatepack_address(w.keychain(1).unwrap()).unwrap();
            let in1=input(&w,0,10,4_000_000_000);
            let built=build_send(&w,0,&[in1.clone()],&[in1.id().unwrap()],1_000_000_000,&b).unwrap();
            let response=receive(&w,1,&[],&built.s1,None).unwrap();
            let a=slatepack_address(w.keychain(0).unwrap()).unwrap();
            let (i1,ictx,_)=issue_invoice(&w,1,&[],1_000_000_000,Some(&a)).unwrap();
            let in2=input(&w,0,11,4_000_000_000);
            let i2=pay_invoice(&w,0,&[in2.clone()],&[in2.id().unwrap()],&i1,Some(10)).unwrap().i2;
            for (name,text) in [("s1.txt",built.s1),("s2.txt",response.response),("i1.txt",i1),("i2.txt",i2),("send-context.json",serde_json::to_string(&built.context).unwrap()),("invoice-context.json",serde_json::to_string(&ictx).unwrap())] {std::fs::write(file(name),text).unwrap();}
        } else if std::env::var("GS_CHAIN_PHASE").unwrap()=="respond" {
            let s1=std::fs::read_to_string(file("delivered-s1.txt")).unwrap();
            let i1=std::fs::read_to_string(file("delivered-i1.txt")).unwrap();
            let response=receive(&w,1,&[],&s1,None).unwrap();
            let in2=input(&w,0,11,4_000_000_000);
            let i2=pay_invoice(&w,0,&[in2.clone()],&[in2.id().unwrap()],&i1,Some(10)).unwrap().i2;
            std::fs::write(file("s2.txt"),response.response).unwrap();
            std::fs::write(file("i2.txt"),i2).unwrap();
        } else {
            let sc:SendContext=serde_json::from_slice(&std::fs::read(file("send-context.json")).unwrap()).unwrap();
            let ic:SendContext=serde_json::from_slice(&std::fs::read(file("invoice-context.json")).unwrap()).unwrap();
            let s2=std::fs::read_to_string(file("delivered-s2.txt")).unwrap();let i2=std::fs::read_to_string(file("delivered-i2.txt")).unwrap();
            let (tx,_,proof)=finalize(&w,&sc,&s2).unwrap();assert_eq!(tx.inputs().len(),1);assert!(proof.is_some());
            let (tx,_)=finalize_invoice(&w,&ic,&i2).unwrap();assert_eq!(tx.inputs().len(),1);
        }
    }

    /// Wallet B invoices wallet A: issue -> pay (two inputs) -> finalize.
    #[test]
    fn invoice_issue_pay_finalize() {
        global::set_local_chain_type(ChainTypes::Testnet);
        let w = wallets();
        let a_addr = slatepack_address(w.keychain(0).unwrap()).unwrap();
        let (i1, isc, key) = issue_invoice(&w, 1, &[], 2_000_000_000, Some(&a_addr)).unwrap();
        assert_eq!(key, ExtKeychain::derive_key_id(3, 0, 0, 0, 0));
        let isc: SendContext = serde_json::from_str(&serde_json::to_string(&isc).unwrap()).unwrap();
        let cands = vec![input(&w, 0, 1, 1_500_000_000), input(&w, 0, 2, 1_000_000_000)];
        let paid = pay_invoice(&w, 0, &cands, &[cands[0].id().unwrap(), cands[1].id().unwrap()], &i1, Some(10)).unwrap();
        assert_eq!(paid.inputs.len(), 2);
        assert_eq!(paid.change, 2_500_000_000 - 2_000_000_000 - send_fee_for(2));
        assert_eq!(paid.issuer.as_deref(), Some(slatepack_address(w.keychain(1).unwrap()).unwrap().as_str()));
        // a payer cannot pay a normal S1 as an invoice, and vice versa
        assert!(receive(&w, 0, &[], &i1, None).is_err());
        let (tx, others) = finalize_invoice(&w, &isc, &paid.i2).unwrap();
        assert_eq!(tx.inputs().len(), 2);
        assert_eq!(others, vec![paid.change_commit]);
        let rows: Vec<_> = tx.outputs().iter().map(|o| (u64::MAX, o.identifier, o.proof)).collect();
        let mut found = w.discover(&rows).unwrap();
        found.sort_by_key(|f| f.wallet);
        assert_eq!((found[0].wallet, found[0].amount), (0, paid.change));
        assert_eq!((found[1].wallet, found[1].amount), (1, 2_000_000_000));
    }
}

// ---------------------------------------------------------------------------
// Files: key ids already used, pending receives, CLI entry points
// ---------------------------------------------------------------------------

/// `"name":"value"` or `"name":123` from one JSON line written by this tool.
type Rec = serde_json::Map<String, serde_json::Value>;

/// Strict reader of the pending journal: every non-empty line must be ONE
/// complete JSON object. A damaged line anywhere is an error (fail closed:
/// silently skipping a reservation could free inputs or hand out a used key).
/// The only damage that can be repaired automatically is an incomplete LAST
/// line (an interrupted append); see `repair_pending`.
fn journal(path: &str) -> Result<Vec<Rec>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{path}: {e}")),
    };
    journal_text(&text, path)
}

pub(crate) fn journal_text(text: &str, path: &str) -> Result<Vec<Rec>, String> {
    if !text.is_empty() && !text.ends_with('\n') {
        return Err(format!("{path}: the last line is incomplete (interrupted write); run --repair-pending {path}"));
    }
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(t) {
            Ok(serde_json::Value::Object(m)) => out.push(m),
            _ => return Err(format!("{path} line {}: not a complete JSON record; the journal is damaged (restore it from a backup)", n + 1)),
        }
    }
    Ok(out)
}

fn rs<'a>(r: &'a Rec, k: &str) -> Option<&'a str> {
    r.get(k).and_then(|v| v.as_str())
}

fn rkind(r: &Rec) -> Option<&str> {
    rs(r, "kind")
}

/// `--repair-pending FILE`: an incomplete LAST line is the only damage an
/// interrupted append can cause (every record is written with one write and
/// fsync, BEFORE anything that depends on it leaves the process), so that
/// fragment is moved to `FILE.torn-<time>` and the file is cut back to the last
/// complete line. Damage anywhere else is refused (restore from a backup).
pub fn repair_pending(path: &str) -> Result<String, String> {
    let _lock = lock_pending(path)?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    if text.is_empty() || text.ends_with('\n') {
        journal_text(&text, path)?;
        return Ok("PENDING_REPAIR=NOTHING_TO_DO".into());
    }
    let cut = text.rfind('\n').map_or(0, |i| i + 1);
    let (good, torn) = text.split_at(cut);
    journal_text(good, path)?;
    let saved = format!("{path}.torn-{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%.f"));
    std::fs::write(&saved, torn).map_err(|e| format!("{saved}: {e}"))?;
    write_atomic(path, good.as_bytes())?;
    Ok(format!("PENDING_REPAIR=TORN_LAST_LINE_REMOVED saved={saved} bytes={}", torn.len()))
}

fn json_field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let key = format!("\"{name}\":");
    let rest = &line[line.find(&key)? + key.len()..];
    if let Some(r) = rest.strip_prefix('"') {
        r.split('"').next()
    } else {
        rest.split([',', '}']).next().map(|x| x.trim())
    }
}

/// Key ids of wallet `wallet` (1-based) listed in a wallet-outputs or a
/// pending file. A missing file means none; an unreadable file or a record
/// without a valid wallet number and key id is an ERROR, because silently
/// skipping it could hand out a key that is already reserved.
pub fn read_key_ids(path: &str, wallet: usize) -> Result<Vec<Identifier>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{path}: {e}")),
    };
    key_ids_in_text(&text, path, wallet)
}

/// Key ids from a wallet-outputs (known) file, ONLY after its MAC (keyed with
/// all seeds, see `Wallets::file_mac`) matches: a file with a dropped record
/// could otherwise make `next_key_id` hand out a key that is already used.
/// A missing file means none (first run). A file without a mac line, with a
/// wrong mac or with data after the mac line is an error (run a full scan to
/// rewrite it). Rolling back to an OLDER correctly signed copy is not detected
/// here; keys handed out by receive / invoice are also kept in the pending
/// file, which is append-only and checked as well.
pub fn read_known_key_ids(w: &Wallets, path: &str, wallet: usize) -> Result<Vec<Identifier>, String> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{path}: {e}")),
    };
    let mut body = String::new();
    let mut mac: Option<&str> = None;
    for (n, raw) in text.split_inclusive('\n').enumerate() {
        let line = raw.trim();
        if mac.is_some() {
            if !line.is_empty() {
                return Err(format!("{path} line {}: data after the mac line", n + 1));
            }
            continue;
        }
        if line.starts_with("{\"mac\":") {
            mac = Some(json_field(line, "mac").ok_or(format!("{path}: bad mac line"))?);
            continue;
        }
        body.push_str(raw);
    }
    let mac = mac.ok_or(format!("{path}: no mac line; run a full wallet scan to rewrite the file"))?;
    if w.file_mac(body.as_bytes()) != mac {
        return Err(format!("{path}: mac mismatch (file changed, shortened or written with other seeds); run a full wallet scan"));
    }
    key_ids_in_text(&body, path, wallet)
}

fn key_ids_in_text(text: &str, path: &str, wallet: usize) -> Result<Vec<Identifier>, String> {
    let mut out = Vec::new();
    for (n, r) in journal_text(text, path)?.iter().enumerate() {
        if r.contains_key("meta") || r.contains_key("mac") {
            continue;
        }
        // Input reservations / releases carry no key (see reserve_inputs).
        if matches!(rkind(r), Some("inputs") | Some("release")) {
            continue;
        }
        let bad = || format!("{path} record {}: record without a valid wallet / key_id", n + 1);
        let wl = r.get("wallet").and_then(|v| v.as_u64()).ok_or_else(bad)? as usize;
        let id = rs(r, "key_id").and_then(key_id_from_hex).ok_or_else(bad)?;
        if wl == wallet {
            out.push(id);
        }
    }
    Ok(out)
}

/// `Identifier::from_hex` in grin panics on malformed hex; check the text
/// first (17 bytes = 34 hex digits) so a bad record is an error, not a crash.
pub fn key_id_from_hex(h: &str) -> Option<Identifier> {
    if h.len() != 34 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Identifier::from_hex(h).ok()
}

/// Reserve the inputs a payment spends (kind "inputs", `what` = send /
/// invoice / self). There is NO time-out: an outstanding S1 (we can still
/// finalize it) or I2 (the issuer can finalize it at any time) may reach the
/// chain later, and a second payment with the same coins would conflict. A
/// reservation ends when its inputs are spent on chain, or by
/// `--release-inputs` (see `release_inputs` for when that is safe).
pub fn reserve_inputs(pending: &str, wallet: usize, slate_id: &str, what: &str, commits: &[String], tip_height: u64) -> Result<(), String> {
    if commits.is_empty() {
        return Ok(());
    }
    append_record(
        pending,
        format!(
            "{{\"kind\":\"inputs\",\"what\":{},\"wallet\":{wallet},\"slate_id\":{},\"commits\":{},\"tip_height\":{tip_height},\"received_at\":{}}}",
            q(what), q(slate_id), q(&commits.join(",")), q(&stamp_now())
        ),
    )
}

/// ONE record for a payment: its input reservation AND its change key (kind
/// "payment"). Written with a single append + fsync, so a crash leaves either
/// nothing (the payment never existed) or both; never reserved inputs without
/// the change record that a retry uses to recognise an already-made payment.
#[allow(clippy::too_many_arguments)]
pub fn reserve_payment(
    pending: &str,
    wallet: usize,
    slate_id: &str,
    what: &str,
    commits: &[String],
    tip_height: u64,
    change: u64,
    change_key: &Identifier,
    change_commit: &str,
    to: &str,
) -> Result<(), String> {
    if commits.is_empty() {
        return Err("a payment without inputs".into());
    }
    append_record(
        pending,
        format!(
            "{{\"kind\":\"payment\",\"what\":{},\"wallet\":{wallet},\"slate_id\":{},\"commits\":{},\"tip_height\":{tip_height},\"amount\":{change},\"key_id\":{},\"commit\":{},\"to\":{},\"received_at\":{}}}",
            q(what), q(slate_id), q(&commits.join(",")), q(&change_key.to_hex()), q(change_commit), q(to), q(&stamp_now())
        ),
    )
}

/// A JSON string literal (quotes + escaping): records keep a fixed key order
/// (scripts look for e.g. `"kind":"payment","what":"invoice","wallet":N`) and
/// a value can never break the line's JSON.
fn q(v: &str) -> String {
    serde_json::Value::from(v).to_string()
}

fn stamp_now() -> String {
    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Append one record (one JSON line). Refuses to append behind an incomplete
/// last line (that would glue two records into one damaged line).
fn append_record(pending: &str, rec: String) -> Result<(), String> {
    debug_assert!(serde_json::from_str::<serde_json::Value>(&rec).is_ok(), "{rec}");
    if let Ok(t) = std::fs::read(pending) {
        if !t.is_empty() && t.last() != Some(&b'\n') {
            return Err(format!("{pending}: the last line is incomplete (interrupted write); run --repair-pending {pending}"));
        }
    }
    append_line(pending, &format!("{rec}\n"))
}

/// `--release-inputs SLATE_ID`: cancel an unfinished payment so its inputs
/// can be selected again. Safe only if that payment can NEVER complete:
/// * send: give its `send_context` -> the context (the only way to finalize
///   the S1) is deleted first; a late S2 can then not be finalized;
/// * invoice payment / self-spend: the I2 / transaction is already out of our
///   hands; release only with `force` (the user accepts that a late
///   completion and a new payment with the same coins conflict on chain).
pub fn release_inputs(pending: &str, slate_id: &str, send_context: Option<&str>, force: bool) -> Result<String, String> {
    let _lock = lock_pending(pending)?;
    let recs = journal(pending)?;
    let what = recs
        .iter()
        .filter(|r| matches!(rkind(r), Some("inputs") | Some("payment")) && rs(r, "slate_id") == Some(slate_id))
        .filter_map(|r| rs(r, "what"))
        .next_back()
        .ok_or(format!("no input reservation for slate {slate_id} in {pending}"))?
        .to_string();
    let how = match (what.as_str(), send_context, force) {
        ("send", Some(ctx), _) => {
            let sc = read_context(ctx)?;
            if sc.slate_id != slate_id {
                return Err(format!("{ctx} is the context of slate {}, not {slate_id}", sc.slate_id));
            }
            std::fs::remove_file(ctx).map_err(|e| format!("delete {ctx}: {e} (not released)"))?;
            "send context deleted: the S1 can no longer be finalized".to_string()
        }
        (_, _, true) => format!("FORCED ({what}): a late completion would conflict with a new payment using the same coins"),
        ("send", None, false) => return Err("give --send-context FILE of this payment (it is deleted, so the S1 can never be finalized), or --force".into()),
        (w, _, false) => {
            return Err(format!(
                "a {w} reservation cannot be released safely (the other side can still complete it); \
                 only with --force, accepting a conflict if it is completed later"
            ))
        }
    };
    append_record(pending, format!("{{\"kind\":\"release\",\"slate_id\":{},\"received_at\":{}}}", q(slate_id), q(&stamp_now())))?;
    Ok(how)
}

/// Inputs still reserved (not released): commitment (hex) -> slate id. Inputs
/// already spent on chain are no candidates anyway.
pub fn reserved_inputs(pending: &str) -> Result<std::collections::HashMap<String, String>, String> {
    let recs = journal(pending)?;
    let released: std::collections::HashSet<&str> =
        recs.iter().filter(|r| rkind(r) == Some("release")).filter_map(|r| rs(r, "slate_id")).collect();
    let mut out = std::collections::HashMap::new();
    for (n, r) in recs.iter().enumerate() {
        if !matches!(rkind(r), Some("inputs") | Some("payment")) {
            continue;
        }
        // Every field of a reservation must be present and well formed;
        // a partial record is an error, never "fewer reserved inputs".
        let bad = || format!("{pending} record {}: bad input reservation", n + 1);
        let sid = rs(r, "slate_id").filter(|x| !x.is_empty()).ok_or_else(bad)?;
        rs(r, "what").filter(|w| matches!(*w, "send" | "invoice" | "self")).ok_or_else(bad)?;
        r.get("wallet").and_then(|v| v.as_u64()).ok_or_else(bad)?;
        r.get("tip_height").and_then(|v| v.as_u64()).ok_or_else(bad)?;
        let commits: Vec<&str> = rs(r, "commits").ok_or_else(bad)?.split(',').collect();
        if commits.is_empty() || commits.iter().any(|c| c.len() != 66 || !c.chars().all(|x| x.is_ascii_hexdigit())) {
            return Err(bad());
        }
        if released.contains(sid) {
            continue;
        }
        for c in commits {
            out.insert(c.to_string(), sid.to_string());
        }
    }
    Ok(out)
}

/// Slate id of an invoice (I1) addressed to `wallet` (None if it does not decode).
pub fn invoice_slate_id(w: &Wallets, wallet: usize, i1_text: &str) -> Option<String> {
    let k = w.keychain(wallet)?;
    unarmor(k, i1_text).ok().map(|(s, _)| s.id.to_string())
}

fn answers_dir(pending: &str) -> String {
    format!("{pending}.answers")
}

/// Keep the answer to an invoice next to the pending file BEFORE its change is
/// reserved, so a retry after an interruption can hand out the same answer.
pub fn save_answer(pending: &str, slate_id: &str, answer: &str) -> Result<(), String> {
    if slate_id.is_empty() || !slate_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err(format!("bad slate id {slate_id}"));
    }
    let dir = answers_dir(pending);
    std::fs::create_dir_all(&dir).map_err(|e| format!("answers dir {dir}: {e}"))?;
    write_atomic(&format!("{dir}/{slate_id}.txt"), answer.as_bytes())
}

/// The answer saved by `save_answer` for this slate, if any.
pub fn saved_answer(pending: &str, slate_id: &str) -> Option<String> {
    if !slate_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return None;
    }
    std::fs::read_to_string(format!("{}/{slate_id}.txt", answers_dir(pending))).ok().filter(|t| !t.trim().is_empty())
}

fn pending_has_slate(path: &str, slate_id: &str) -> Result<bool, String> {
    Ok(journal(path)?.iter().any(|r| rs(r, "slate_id") == Some(slate_id) && rkind(r).map_or(true, |k| k == "receive")))
}

/// A payment (or invoice payment) of this slate already reserved its change.
pub fn pending_has_change(path: &str, slate_id: &str) -> Result<bool, String> {
    Ok(journal(path)?.iter().any(|r| rs(r, "slate_id") == Some(slate_id) && matches!(rkind(r), Some("change") | Some("payment"))))
}

fn append_line(path: &str, line: &str) -> Result<(), String> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).open(path).map_err(|e| format!("pending: {e}"))?;
    f.write_all(line.as_bytes()).map_err(|e| format!("pending: {e}"))?;
    // On disk before any slatepack that uses the key leaves this process.
    f.sync_all().map_err(|e| format!("pending: {e}"))
}

/// Exclusive lock for one read-keys / reserve / hand-out sequence on a pending
/// file (`<pending>.lock`). A second operation on the same wallet files waits
/// instead of picking the same fresh key. Released when the handle drops.
pub fn lock_pending(pending: &str) -> Result<std::fs::File, String> {
    let lock = format!("{pending}.lock");
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock)
        .map_err(|e| format!("pending lock {lock}: {e}"))?;
    f.lock().map_err(|e| format!("pending lock {lock}: {e}"))?;
    Ok(f)
}

/// Replace `path` with `data` so that a crash leaves either the old or the
/// new file, never a half-written one (temporary file, flush, rename).
pub fn write_atomic(path: &str, data: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let tmp = format!("{path}.tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| format!("write {tmp}: {e}"))?;
        f.write_all(data).map_err(|e| format!("write {tmp}: {e}"))?;
        f.sync_all().map_err(|e| format!("write {tmp}: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("rename {tmp} -> {path}: {e}"))
}

/// Reserve the change key of a payment (kind "change") in the pending file.
pub fn reserve_change(pending: &str, wallet: usize, slate_id: &str, amount: u64, key: &Identifier, commit: &str, to: &str) -> Result<(), String> {
    append_record(
        pending,
        format!(
            "{{\"kind\":\"change\",\"wallet\":{wallet},\"slate_id\":{},\"amount\":{amount},\"key_id\":{},\"commit\":{},\"to\":{},\"received_at\":{}}}",
            q(slate_id), q(&key.to_hex()), q(commit), q(to), q(&stamp_now())
        ),
    )
}

/// `--slatepack-address --seeds FILE`: the address of every wallet in the file.
pub fn print_addresses(seeds: &str) -> Result<(), String> {
    let w = Wallets::from_file(seeds)?;
    for i in 0..w.len() {
        println!("SLATEPACK_ADDRESS=wallet={} {}", i + 1, slatepack_address(w.keychain(i).unwrap())?);
    }
    Ok(())
}

/// Armored form of a JSON S2/I2 answer: what a person can hand to
/// `grin-wallet finalize` / `grin-wallet pay` (the Tor foreign API itself takes
/// JSON). Encrypted to the sender address from the payment proof when present,
/// else unencrypted (grin-wallet accepts both).
pub fn armor_answer(w: &Wallets, wallet: usize, response_json: &str, fallback_sender: Option<&str>) -> Result<String, String> {
    let k = w.keychain(wallet.checked_sub(1).ok_or("wallet is 1-based")?).ok_or("no such wallet")?;
    let slate = slate_from_json(response_json)?;
    let sec = address_secret(k)?;
    let our_addr = SlatepackAddress::try_from(&sec).map_err(|e| format!("address: {e}"))?;
    let sender: Option<SlatepackAddress> = slate
        .payment_proof
        .as_ref()
        .map(|p| SlatepackAddress::new(&p.sender_address))
        .or_else(|| fallback_sender.and_then(|s| SlatepackAddress::try_from(s.trim()).ok()));
    let recipients: Vec<SlatepackAddress> = sender.into_iter().collect();
    let packer = Slatepacker::new(SlatepackerArgs { sender: Some(our_addr), recipients, dec_key: None });
    let pack = packer.create_slatepack(&slate).map_err(|e| format!("pack: {e}"))?;
    packer.armor_slatepack(&pack).map_err(|e| format!("armor: {e}"))
}

/// `--armor-out`: write the armored form of the answer (an already armored
/// answer is copied as is).
fn write_armor_out(w: &Wallets, wallet: usize, answer: &str, sender: Option<&str>, path: &str) -> Result<(), String> {
    let text = if is_json(answer) { armor_answer(w, wallet, answer, sender)? } else { answer.trim().to_string() };
    std::fs::write(path, format!("{text}\n")).map_err(|e| format!("armor out: {e}"))
}

/// `--receive-slatepack FILE`: read S1, write the S2 answer, remember the
/// promised output in the pending file (its key is not handed out twice).
/// `armor_out` gets the answer as a slatepack even when the input was JSON
/// (Tor foreign API): a person can hand it to `grin-wallet finalize`.
pub fn receive_file(
    seeds: &str,
    wallet: usize,
    input: &str,
    response_out: &str,
    known: Option<&str>,
    pending: &str,
    tip_height: Option<u64>,
    armor_out: Option<&str>,
) -> Result<(), String> {
    let w = Wallets::from_file(seeds)?;
    if wallet == 0 || wallet > w.len() {
        return Err(format!("wallet {wallet} not in the seed file (1..={})", w.len()));
    }
    let text = std::fs::read_to_string(input).map_err(|e| format!("slatepack file: {e}"))?;
    // Validate expiry even when returning a cached S2 after a previous receive.
    // Do this before any write or journal mutation.
    let k = w.keychain(wallet - 1).ok_or("wallet unavailable")?;
    let (slate, _) = unarmor(k, &text)?;
    if slate.state != SlateState::Standard1 { return Err("not a payment to receive (expected S1)".into()); }
    check_slate_cutoff(slate.ttl_cutoff_height, tip_height, "slate")?;
    let _lock = lock_pending(pending)?;
    let mut used = read_key_ids(pending, wallet)?;
    if let Some(k) = known {
        used.extend(read_known_key_ids(&w, k, wallet)?);
    }
    // Already received: hand out the SAME answer again (saved next to the
    // pending file), never a second one with another key.
    if let Some(sid) = w.keychain(wallet - 1).and_then(|k| unarmor(k, &text).ok()).map(|(s, _)| s.id.to_string()) {
        if pending_has_slate(pending, &sid)? {
            validate_saved_request(pending, &sid, wallet, "receive", &text, slate.ttl_cutoff_height)?;
            let saved = saved_answer(pending, &sid).ok_or(format!(
                "slate {sid} was already received (see {pending}) but its saved answer is missing; give the sender the answer made then"
            ))?;
            std::fs::write(response_out, &saved).map_err(|e| format!("response out: {e}"))?;
            if let Some(ao) = armor_out {
                write_armor_out(&w, wallet, &saved, None, ao)?;
            }
            println!("RECEIVE_SLATE_ID={sid}\nRECEIVE_RESPONSE={response_out}\nRECEIVE=RESENT (already received; the same answer again)");
            return Ok(());
        }
    }
    let r = receive(&w, wallet - 1, &used, &text, tip_height)?;
    if pending_has_slate(pending, &r.slate_id)? {
        return Err(format!("slate {} was already received (see {pending}); give the sender the answer made then", r.slate_id));
    }
    // Order: saved answer -> key record -> answer file. A lost answer (or a
    // crash after the record) is answered again with the SAME saved answer;
    // a crash before the record leaves nothing handed out.
    save_answer(pending, &r.slate_id, &format!("{}\n", r.response))?;
    append_record(
        pending,
        format!(
            "{{\"kind\":\"receive\",\"wallet\":{wallet},\"slate_id\":{},\"amount\":{},\"fee\":{},\"key_id\":{},\"commit\":{},\"sender\":{},\"received_at\":{},\"tip_height\":{},\"request_hash\":{},\"cutoff_height\":{}}}",
            q(&r.slate_id), r.amount, r.fee, q(&r.key_id.to_hex()), q(&r.commit.0.to_hex()),
            q(&r.sender.clone().unwrap_or_default()), q(&stamp_now()), tip_height.map_or("null".to_string(), |h| h.to_string()), q(&request_hash(&text)), slate.ttl_cutoff_height
        ),
    )?;
    std::fs::write(response_out, format!("{}\n", r.response)).map_err(|e| format!("response out: {e}"))?;
    if let Some(ao) = armor_out {
        write_armor_out(&w, wallet, &r.response, r.sender.as_deref(), ao)?;
    }
    println!(
        "RECEIVE_SLATE_ID={}\nRECEIVE_AMOUNT={}\nRECEIVE_FEE_PAID_BY_SENDER={}\nRECEIVE_FROM={}\nRECEIVE_SENDER_VERIFIED={}\nRECEIVE_ENCRYPTED_TO_US={}\nRECEIVE_PAYMENT_PROOF={}\nRECEIVE_NEW_OUTPUT={}\nRECEIVE_KEY_ID={}\nRECEIVE_RESPONSE={response_out}\nRECEIVE=OK (give the response to the sender; the coins arrive when the sender finalizes and the transaction is mined)",
        r.slate_id,
        r.amount,
        r.fee,
        r.sender.unwrap_or_else(|| "(no address given)".into()),
        r.sender_verified,
        r.encrypted_in,
        r.payment_proof,
        r.commit.0.to_hex(),
        r.key_id.to_hex()
    );
    Ok(())
}

/// `--slatepack-info FILE --seeds F --wallet N`: what a slatepack (or slate
/// JSON) is, without acting on it: state, id, amount, sender.
pub fn print_slatepack_info(seeds: &str, wallet: usize, path: &str) -> Result<(), String> {
    let w = Wallets::from_file(seeds)?;
    let k = w.keychain(wallet.checked_sub(1).ok_or("wallet is 1-based")?).ok_or("no such wallet")?;
    let text = std::fs::read_to_string(path).map_err(|e| format!("slatepack file: {e}"))?;
    let (slate, sender) = unarmor(k, &text)?;
    let state = match slate.state {
        SlateState::Standard1 => "S1",
        SlateState::Standard2 => "S2",
        SlateState::Standard3 => "S3",
        SlateState::Invoice1 => "I1",
        SlateState::Invoice2 => "I2",
        SlateState::Invoice3 => "I3",
        _ => "UNKNOWN",
    };
    let claimed = slate.payment_proof.as_ref().map(|p| SlatepackAddress::new(&p.sender_address).to_string());
    println!(
        "SLATE_STATE={state}\nSLATE_ID={}\nSLATE_AMOUNT={}\nSLATE_FEE={}\nSLATE_SENDER={}\nSLATE_PROOF_SENDER={}",
        slate.id,
        slate.amount,
        slate.fee_fields.fee(),
        sender.map(|a| a.to_string()).unwrap_or_default(),
        claimed.unwrap_or_default()
    );
    Ok(())
}

/// Messenger seed for wallet `wallet` (1-based): GrinMessenger's
/// `derive_messaging_seed` (HKDF-SHA256, same salt) over the phrase entropy,
/// so the messenger identity is separate from the payment address.
pub fn messaging_seed(w: &Wallets, wallet: usize) -> Result<[u8; 32], String> {
    let ent = w.entropy(wallet - 1).ok_or("no such wallet")?;
    let net = if grin_core::global::is_testnet() { "testnet" } else { "mainnet" };
    let label = format!("grinsight/{net}/wallet-{wallet}/messenger");
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"glaux-messenger/wallet-integration/v1"), ent);
    let mut out = [0u8; 32];
    hk.expand(label.as_bytes(), &mut out).map_err(|_| "hkdf")?;
    Ok(out)
}

/// `--tor-keys --seeds FILE --wallet N`: the two ed25519 seeds the Tor
/// daemon needs (payment address -> grin-wallet compatible onion; messenger
/// identity). Printed to stdout for the calling process only.
pub fn print_tor_keys(seeds: &str, wallet: usize) -> Result<(), String> {
    let w = Wallets::from_file(seeds)?;
    let k = w.keychain(wallet.checked_sub(1).ok_or("wallet is 1-based")?).ok_or("no such wallet")?;
    let (sec, addr) = our_address(k)?;
    let ms = messaging_seed(&w, wallet)?;
    println!("ADDRESS={addr}\nADDRESS_SECRET_HEX={}\nMESSAGING_SEED_HEX={}", sec.0.to_hex(), ms.to_hex());
    Ok(())
}

#[cfg(test)]
mod file_tests {
    use super::*;

    #[test]
    fn key_ids_from_wallet_and_pending_lines() {
        let dir = std::env::temp_dir().join(format!("grinsight-recv-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("w.jsonl");
        let a = ExtKeychain::derive_key_id(3, 0, 0, 4, 0).to_hex();
        let b = ExtKeychain::derive_key_id(3, 0, 0, 9, 0).to_hex();
        std::fs::write(
            &p,
            format!("{{\"meta\":\"grinsight-wallet\",\"tip_height\":5}}\n{{\"wallet\":4,\"commit\":\"08aa\",\"amount\":1,\"key_id\":\"{a}\"}}\n{{\"wallet\":1,\"key_id\":\"{b}\"}}\n"),
        )
        .unwrap();
        let ids = read_key_ids(p.to_str().unwrap(), 4).unwrap();
        assert_eq!(ids, vec![Identifier::from_hex(&a).unwrap()]);
        assert_eq!(next_key_id(&ids), ExtKeychain::derive_key_id(3, 0, 0, 5, 0));
        assert!(read_key_ids("/nonexistent/x", 4).unwrap().is_empty());
        // A record without a valid key id is an error, not a silent skip.
        std::fs::write(&p, "{\"wallet\":4,\"key_id\":\"zz\"}\n").unwrap();
        assert!(read_key_ids(p.to_str().unwrap(), 4).is_err());
        std::fs::write(&p, "garbage\n").unwrap();
        assert!(read_key_ids(p.to_str().unwrap(), 1).is_err());
        // meta and mac lines are not records
        std::fs::write(&p, format!("{{\"meta\":\"grinsight-wallet\",\"tip_height\":5}}\n{{\"wallet\":4,\"key_id\":\"{a}\"}}\n{{\"mac\":\"00\",\"records\":1}}\n")).unwrap();
        assert_eq!(read_key_ids(p.to_str().unwrap(), 4).unwrap().len(), 1);
        // saved invoice answers
        let pend = dir.join("pending.jsonl");
        let pend = pend.to_str().unwrap();
        assert!(saved_answer(pend, "abc-1").is_none());
        save_answer(pend, "abc-1", "ANSWER\n").unwrap();
        assert_eq!(saved_answer(pend, "abc-1").as_deref(), Some("ANSWER\n"));
        assert!(save_answer(pend, "../x", "y").is_err());
        // Input reservations: no time-out; release rules; not key records.
        let (c_aa, c_bb, c_cc) = (format!("08{}", "aa".repeat(32)), format!("08{}", "bb".repeat(32)), format!("09{}", "cc".repeat(32)));
        reserve_inputs(pend, 1, "s-1", "invoice", &[c_aa.clone(), c_bb.clone()], 100).unwrap();
        reserve_inputs(pend, 1, "s-2", "invoice", &[c_cc.clone()], 100).unwrap();
        let r = reserved_inputs(pend).unwrap();
        assert_eq!((r.get(&c_aa).map(|s| s.as_str()), r.len()), (Some("s-1"), 3));
        assert!(release_inputs(pend, "s-2", None, false).unwrap_err().contains("--force"), "an I2 is out of our hands");
        assert!(reserved_inputs(pend).unwrap().contains_key(&c_cc));
        assert!(release_inputs(pend, "s-2", None, true).unwrap().contains("FORCED"));
        assert!(!reserved_inputs(pend).unwrap().contains_key(&c_cc));
        assert!(release_inputs(pend, "no-such", None, true).is_err());
        assert!(read_key_ids(pend, 1).is_ok(), "reservation lines are not key records");
        assert_eq!(json_field("{\"slate_id\":\"abc\",\"x\":1}", "slate_id"), Some("abc"));
        assert_eq!(json_field("{\"wallet\":12,\"x\":1}", "wallet"), Some("12"));
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Journal: a damaged record is never read as "fewer reservations"; an
    /// interrupted last append is repaired by --repair-pending, other damage
    /// is refused. A payment record (inputs + change) is one line.
    #[test]
    fn pending_journal_is_strict_and_repairable() {
        let dir = std::env::temp_dir().join(format!("grinsight-journal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pend = dir.join("pending.jsonl");
        let pend = pend.to_str().unwrap();
        let c1 = format!("08{}", "11".repeat(32));
        let c2 = format!("09{}", "22".repeat(32));
        let key = ExtKeychain::derive_key_id(3, 0, 0, 7, 0);
        reserve_payment(pend, 1, "pay-1", "send", &[c1.clone(), c2.clone()], 50, 10, &key, &c1, "grin1x").unwrap();
        assert_eq!(reserved_inputs(pend).unwrap().len(), 2);
        assert!(pending_has_change(pend, "pay-1").unwrap(), "the payment record is recognised by a retry");
        // run_user.ps1 looks for this exact text
        assert!(std::fs::read_to_string(pend).unwrap().contains("\"kind\":\"payment\",\"what\":\"send\",\"wallet\":1,\"slate_id\":\"pay-1\""));
        assert_eq!(read_key_ids(pend, 1).unwrap(), vec![key.clone()], "its change key is a used key");
        let good = std::fs::read_to_string(pend).unwrap();
        // 1) Truncated reservation (crash in the middle of the append): every
        //    reader refuses, nothing is treated as free; repair cuts it off.
        let torn = format!("{good}{}", &good[..good.len() / 2]);
        std::fs::write(pend, &torn).unwrap();
        assert!(reserved_inputs(pend).unwrap_err().contains("--repair-pending"));
        assert!(read_key_ids(pend, 1).is_err());
        assert!(pending_has_change(pend, "pay-1").is_err());
        assert!(reserve_inputs(pend, 1, "x", "send", &[c1.clone()], 1).is_err(), "no append behind a torn line");
        let r = repair_pending(pend).unwrap();
        assert!(r.contains("TORN_LAST_LINE_REMOVED"), "{r}");
        assert_eq!(std::fs::read_to_string(pend).unwrap(), good);
        assert_eq!(reserved_inputs(pend).unwrap().len(), 2, "the complete records survive");
        assert!(repair_pending(pend).unwrap().contains("NOTHING_TO_DO"));
        // 2) A complete line that cut a reservation's field list short (valid
        //    JSON, commits missing): error, not "no inputs reserved".
        std::fs::write(pend, format!("{good}{{\"kind\":\"inputs\",\"what\":\"send\",\"wallet\":1,\"slate_id\":\"s9\"}}\n")).unwrap();
        assert!(reserved_inputs(pend).unwrap_err().contains("bad input reservation"));
        // ...and a commits list cut in the middle of a commitment.
        std::fs::write(pend, format!("{good}{{\"kind\":\"inputs\",\"what\":\"send\",\"wallet\":1,\"slate_id\":\"s9\",\"tip_height\":1,\"commits\":\"{c1},09ab\"}}\n")).unwrap();
        assert!(reserved_inputs(pend).is_err());
        // 3) Damage in the middle is not "repaired" automatically.
        std::fs::write(pend, format!("{{\"kind\":\"inp\n{good}")).unwrap();
        assert!(reserved_inputs(pend).unwrap_err().contains("damaged"));
        assert!(repair_pending(pend).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Item: receive / issue-invoice take used keys from the known-outputs
    /// file only after its MAC matches.
    #[test]
    fn known_outputs_need_a_valid_mac_before_keys_are_handed_out() {
        let dir = std::env::temp_dir().join(format!("grinsight-knownmac-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("wallet-outputs.jsonl");
        let ps = p.to_str().unwrap();
        let w = Wallets::from_keychains(vec![ExtKeychain::from_seed(&[5; 32], true).unwrap()]);
        let k0 = ExtKeychain::derive_key_id(3, 0, 0, 0, 0).to_hex();
        let k1 = ExtKeychain::derive_key_id(3, 0, 0, 1, 0).to_hex();
        let body = format!(
            "{{\"meta\":\"grinsight-wallet\",\"tip_height\":5,\"tip_hash\":\"00\"}}\n{{\"wallet\":1,\"key_id\":\"{k0}\"}}\n{{\"wallet\":1,\"key_id\":\"{k1}\"}}\n"
        );
        let signed = format!("{body}{{\"mac\":\"{}\",\"records\":2}}\n", w.file_mac(body.as_bytes()));
        std::fs::write(&p, &signed).unwrap();
        let ids = read_known_key_ids(&w, ps, 1).unwrap();
        assert_eq!(next_key_id(&ids), ExtKeychain::derive_key_id(3, 0, 0, 2, 0));
        // The last record removed, old mac kept: refused (would re-issue key 1).
        let mut lines: Vec<&str> = signed.lines().collect();
        lines.remove(2);
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        assert!(read_known_key_ids(&w, ps, 1).unwrap_err().contains("mac mismatch"));
        // No mac line at all, or a mac made with other seeds: refused.
        std::fs::write(&p, &body).unwrap();
        assert!(read_known_key_ids(&w, ps, 1).unwrap_err().contains("no mac"));
        let other = Wallets::from_keychains(vec![ExtKeychain::from_seed(&[5; 32], true).unwrap(), ExtKeychain::from_seed(&[6; 32], true).unwrap()]);
        std::fs::write(&p, &signed).unwrap();
        assert!(read_known_key_ids(&other, ps, 1).is_err());
        // Data after the mac line: refused. Missing file: first run, none.
        std::fs::write(&p, format!("{signed}{{\"wallet\":1,\"key_id\":\"{k1}\"}}\n")).unwrap();
        assert!(read_known_key_ids(&w, ps, 1).is_err());
        assert!(read_known_key_ids(&w, dir.join("none").to_str().unwrap(), 1).unwrap().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn write_atomic_and_pending_lock() {
        let dir = std::env::temp_dir().join(format!("grinsight-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("w.jsonl");
        let ps = p.to_str().unwrap();
        write_atomic(ps, b"one\n").unwrap();
        write_atomic(ps, b"two\n").unwrap();
        assert_eq!(std::fs::read_to_string(ps).unwrap(), "two\n");
        assert!(!std::path::Path::new(&format!("{ps}.tmp")).exists());
        // Second holder must wait: try_lock fails while the first lock lives.
        let pend = dir.join("pending.jsonl");
        let pend = pend.to_str().unwrap();
        let held = lock_pending(pend).unwrap();
        let again = std::fs::OpenOptions::new().write(true).open(format!("{pend}.lock")).unwrap();
        assert!(again.try_lock().is_err());
        drop(held);
        assert!(again.try_lock().is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

